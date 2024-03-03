const std = @import("std");
const zig_builtin = @import("builtin");
const Ast = std.zig.Ast;

const offsets = @import("../offsets.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("../lsp.zig");

pub const TokenType = enum(u32) {
    namespace,
    type,
    class,
    @"enum",
    interface,
    @"struct",
    typeParameter,
    parameter,
    variable,
    property,
    enumMember,
    event,
    function,
    method,
    macro,
    keyword,
    modifier,
    comment,
    string,
    number,
    regexp,
    operator,
    decorator,
    // non standard token types
    errorTag,
    builtin,
    label,
    keywordLiteral,
    @"union",
    @"opaque",
};

pub const TokenModifiers = packed struct(u16) {
    declaration: bool = false,
    definition: bool = false,
    readonly: bool = false,
    static: bool = false,
    deprecated: bool = false,
    abstract: bool = false,
    @"async": bool = false,
    modification: bool = false,
    documentation: bool = false,
    defaultLibrary: bool = false,
    // non standard token modifiers
    generic: bool = false,
    _: u5 = 0,
};

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    previous_source_index: usize = 0,
    source_index: usize = 0,
    token_buffer: std.ArrayListUnmanaged(u32) = .{},
    encoding: offsets.Encoding,
    limited: bool,

    fn add(self: *Builder, token: Ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) error{OutOfMemory}!void {
        const tree = self.handle.tree;
        const starts = tree.tokens.items(.start);

        try self.handleComments(self.previous_source_index, starts[token]);
        try self.addDirect(token_type, token_modifiers, offsets.tokenToLoc(tree, token));
    }

    fn finish(self: *Builder) error{OutOfMemory}!types.SemanticTokens {
        try self.handleComments(self.previous_source_index, self.handle.tree.source.len);
        return .{ .data = try self.token_buffer.toOwnedSlice(self.arena) };
    }

    /// Highlight normal comments and doc comments.
    fn handleComments(self: *Builder, from: usize, to: usize) error{OutOfMemory}!void {
        if (from >= to) return;

        const source = self.handle.tree.source;

        var i: usize = from;
        while (i < to) : (i += 1) {
            // Skip multi-line string literals
            if (source[i] == '\\' and source[i + 1] == '\\') {
                while (i < to and source[i] != '\n') : (i += 1) {}
                continue;
            }
            // Skip normal string literals
            if (source[i] == '"') {
                i += 1;
                while (i < to and
                    source[i] != '\n' and
                    !(source[i] == '"' and source[i - 1] != '\\')) : (i += 1)
                {}
                continue;
            }
            // Skip char literals
            if (source[i] == '\'') {
                i += 1;
                while (i < to and
                    source[i] != '\n' and
                    !(source[i] == '\'' and source[i - 1] != '\\')) : (i += 1)
                {}
                continue;
            }

            if (source[i] != '/' or source[i + 1] != '/')
                continue;

            const comment_start = i;
            var mods = TokenModifiers{};
            if (i + 2 < to and (source[i + 2] == '!' or source[i + 2] == '/'))
                mods.documentation = true;

            while (i < to and source[i] != '\n') : (i += 1) {}

            try self.addDirect(.comment, mods, .{ .start = comment_start, .end = i });
        }
    }

    fn addDirect(self: *Builder, param_token_type: TokenType, token_modifiers: TokenModifiers, loc: offsets.Loc) error{OutOfMemory}!void {
        std.debug.assert(loc.start <= loc.end);
        std.debug.assert(self.previous_source_index <= self.source_index);
        if (loc.start < self.previous_source_index) return;
        if (loc.start < self.source_index) return;
        var token_type = param_token_type;
        switch (token_type) {
            .namespace,
            .type,
            .class,
            .@"enum",
            .interface,
            .@"struct",
            .typeParameter,
            .variable,
            .property,
            .enumMember,
            .event,
            .function,
            .method,
            .macro,
            .modifier,
            .regexp,
            .decorator,
            .errorTag,
            => {},

            .@"union",
            .@"opaque",
            => token_type = .type,

            .parameter,
            .keyword,
            .comment,
            .string,
            .number,
            .operator,
            .builtin,
            .label,
            .keywordLiteral,
            => if (self.limited) return,
        }

        const source = self.handle.tree.source;
        const delta_text = source[self.previous_source_index..loc.start];
        const delta = offsets.indexToPosition(delta_text, delta_text.len, self.encoding);
        const length = offsets.locLength(source, loc, self.encoding);

        // assert that the `@intCast(length)` below is safe
        comptime std.debug.assert(DocumentStore.max_document_size == std.math.maxInt(u32));

        try self.token_buffer.appendSlice(self.arena, &.{
            delta.line,
            delta.character,
            @intCast(length),
            @intFromEnum(token_type),
            @as(u16, @bitCast(token_modifiers)),
        });
        self.previous_source_index = loc.start;
        self.source_index = loc.end;
    }
};

inline fn writeToken(builder: *Builder, token_idx: ?Ast.TokenIndex, tok_type: TokenType) !void {
    return try writeTokenMod(builder, token_idx, tok_type, .{});
}

inline fn writeTokenMod(builder: *Builder, token_idx: ?Ast.TokenIndex, tok_type: TokenType, tok_mod: TokenModifiers) !void {
    if (token_idx) |ti| {
        try builder.add(ti, tok_type, tok_mod);
    }
}

fn fieldTokenType(
    container_decl: Ast.Node.Index,
    handle: *DocumentStore.Handle,
    is_static_access: bool,
) ?TokenType {
    if (!ast.isContainer(handle.tree, container_decl))
        return null;
    if (container_decl == 0)
        return .property;
    if (is_static_access and ast.isTaggedUnion(handle.tree, container_decl))
        return .enumMember;
    const main_token = handle.tree.nodes.items(.main_token)[container_decl];
    if (main_token > handle.tree.tokens.len) return null;
    return @as(?TokenType, switch (handle.tree.tokens.items(.tag)[main_token]) {
        .keyword_struct, .keyword_union => .property,
        .keyword_enum => .enumMember,
        .keyword_error => .errorTag,
        else => null,
    });
}

fn colorIdentifierBasedOnType(
    builder: *Builder,
    type_node: Analyser.Type,
    target_tok: Ast.TokenIndex,
    is_parameter: bool,
    tok_mod: TokenModifiers,
) !void {
    if (type_node.is_type_val) {
        const token_type: TokenType =
            if (try type_node.isNamespace())
            .namespace
        else if (try type_node.isStructType())
            .@"struct"
        else if (try type_node.isEnumType())
            .@"enum"
        else if (try type_node.isUnionType())
            .@"union"
        else if (try type_node.isOpaqueType())
            .@"opaque"
        else if (is_parameter)
            .typeParameter
        else
            .type;

        try writeTokenMod(builder, target_tok, token_type, tok_mod);
    } else if (type_node.isTypeFunc()) {
        try writeTokenMod(builder, target_tok, .type, tok_mod);
    } else if (type_node.isFunc()) {
        var new_tok_mod = tok_mod;
        if (type_node.isGenericFunc()) {
            new_tok_mod.generic = true;
        }

        const has_self_param = try builder.analyser.hasSelfParam(type_node);

        try writeTokenMod(builder, target_tok, if (has_self_param) .method else .function, new_tok_mod);
    } else {
        var new_tok_mod = tok_mod;
        if (type_node.data == .compile_error) {
            new_tok_mod.deprecated = true;
        }
        try writeTokenMod(builder, target_tok, if (is_parameter) .parameter else .variable, new_tok_mod);
    }
}

fn writeNodeTokens(builder: *Builder, node: Ast.Node.Index) error{OutOfMemory}!void {
    if (node == 0) return;

    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    const tag = node_tags[node];
    const main_token = main_tokens[node];

    switch (tag) {
        .root => unreachable,
        .container_field,
        .container_field_align,
        .container_field_init,
        => try writeContainerField(builder, node, 0),
        .@"errdefer" => {
            try writeToken(builder, main_token, .keyword);

            if (node_data[node].lhs != 0) {
                try writeTokenMod(builder, node_data[node].lhs, .variable, .{ .declaration = true });
            }

            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            if (token_tags[main_token - 1] == .colon and token_tags[main_token - 2] == .identifier) {
                try writeTokenMod(builder, main_token - 2, .label, .{ .declaration = true });
            }

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node, &buffer).?;

            for (statements) |child| {
                try writeNodeTokens(builder, child);
            }
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?;
            try writeToken(builder, var_decl.visib_token, .keyword);
            try writeToken(builder, var_decl.extern_export_token, .keyword);
            try writeToken(builder, var_decl.threadlocal_token, .keyword);
            try writeToken(builder, var_decl.comptime_token, .keyword);
            try writeToken(builder, var_decl.ast.mut_token, .keyword);

            if (try builder.analyser.resolveTypeOfNode(.{ .node = node, .handle = handle })) |decl_type| {
                try colorIdentifierBasedOnType(builder, decl_type, var_decl.ast.mut_token + 1, false, .{ .declaration = true });
            } else {
                try writeTokenMod(builder, var_decl.ast.mut_token + 1, .variable, .{ .declaration = true });
            }

            try writeNodeTokens(builder, var_decl.ast.type_node);
            try writeNodeTokens(builder, var_decl.ast.align_node);
            try writeNodeTokens(builder, var_decl.ast.section_node);

            if (var_decl.ast.init_node != 0) {
                const equal_token = tree.firstToken(var_decl.ast.init_node) - 1;
                if (token_tags[equal_token] == .equal) {
                    try writeToken(builder, equal_token, .operator);
                }
            }

            try writeNodeTokens(builder, var_decl.ast.init_node);
        },
        .@"usingnamespace" => {
            const first_token = tree.firstToken(node);
            if (token_tags[first_token] == .keyword_pub) {
                try writeToken(builder, first_token, .keyword);
            }
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, node_data[node].lhs);
        },
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const decl: Ast.full.ContainerDecl = tree.fullContainerDecl(&buf, node).?;

            try writeToken(builder, decl.layout_token, .keyword);
            try writeToken(builder, decl.ast.main_token, .keyword);
            if (decl.ast.enum_token) |enum_token| {
                try writeToken(builder, enum_token, .keyword);
                if (decl.ast.arg != 0) {
                    try writeNodeTokens(builder, decl.ast.arg);
                }
            } else try writeNodeTokens(builder, decl.ast.arg);

            for (decl.ast.members) |child| {
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, child, node);
                } else {
                    try writeNodeTokens(builder, child);
                }
            }
        },
        .error_set_decl => {
            try writeToken(builder, main_token, .keyword);

            var tok_i = main_tokens[node] + 2;
            while (tok_i < node_data[node].rhs) : (tok_i += 1) {
                switch (token_tags[tok_i]) {
                    .doc_comment, .comma => {},
                    .identifier => try writeTokenMod(builder, tok_i, .errorTag, .{ .declaration = true }),
                    else => {},
                }
            }
        },
        .error_value => {
            if (node_data[node].lhs != 0) {
                try writeToken(builder, node_data[node].lhs - 1, .keyword);
            }
            try writeToken(builder, node_data[node].rhs, .errorTag);
        },
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto: Ast.full.FnProto = tree.fullFnProto(&buf, node).?;

            try writeToken(builder, fn_proto.visib_token, .keyword);
            try writeToken(builder, fn_proto.extern_export_inline_token, .keyword);
            try writeToken(builder, fn_proto.lib_name, .string);
            try writeToken(builder, fn_proto.ast.fn_token, .keyword);

            const func_ty = Analyser.Type{
                .data = .{ .other = .{ .node = node, .handle = handle } }, // this assumes that function types can only be Ast nodes
                .is_type_val = true,
            };

            const func_name_tok_type: TokenType = if (Analyser.isTypeFunction(tree, fn_proto))
                .type
            else if (try builder.analyser.hasSelfParam(func_ty))
                .method
            else
                .function;

            const tok_mod = TokenModifiers{
                .declaration = true,
                .generic = Analyser.isGenericFunction(tree, fn_proto),
            };

            try writeTokenMod(builder, fn_proto.name_token, func_name_tok_type, tok_mod);

            var it = fn_proto.iterate(&tree);
            while (ast.nextFnParam(&it)) |param_decl| {
                try writeToken(builder, param_decl.comptime_noalias, .keyword);

                const token_type: TokenType = if (Analyser.isMetaType(tree, param_decl.type_expr)) .typeParameter else .parameter;
                try writeTokenMod(builder, param_decl.name_token, token_type, .{ .declaration = true });

                if (param_decl.anytype_ellipsis3) |any_token| {
                    try writeToken(builder, any_token, .type);
                } else try writeNodeTokens(builder, param_decl.type_expr);
            }

            if (fn_proto.ast.align_expr != 0) {
                try writeToken(builder, tree.firstToken(fn_proto.ast.align_expr) - 2, .keyword);
            }
            try writeNodeTokens(builder, fn_proto.ast.align_expr);

            try writeNodeTokens(builder, fn_proto.ast.section_expr);

            if (fn_proto.ast.callconv_expr != 0) {
                try writeToken(builder, tree.firstToken(fn_proto.ast.callconv_expr) - 2, .keyword);
            }
            try writeNodeTokens(builder, fn_proto.ast.callconv_expr);

            try writeNodeTokens(builder, fn_proto.ast.return_type);

            if (tag == .fn_decl)
                try writeNodeTokens(builder, node_data[node].rhs);
        },
        .anyframe_type, .@"defer" => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .@"switch",
        .switch_comma,
        => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, node_data[node].lhs);
            const extra = tree.extraData(node_data[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases) |case_node| {
                try writeNodeTokens(builder, case_node);
            }
        },
        .switch_case_one,
        .switch_case,
        .switch_case_inline_one,
        .switch_case_inline,
        => {
            const switch_case = tree.fullSwitchCase(node).?;
            try writeToken(builder, switch_case.inline_token, .keyword);
            for (switch_case.ast.values) |item_node| try writeNodeTokens(builder, item_node);
            // check it it's 'else'
            if (switch_case.ast.values.len == 0) try writeToken(builder, switch_case.ast.arrow_token - 1, .keyword);
            if (switch_case.payload_token) |payload_token| {
                const actual_payload = payload_token + @intFromBool(token_tags[payload_token] == .asterisk);
                try writeTokenMod(builder, actual_payload, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, switch_case.ast.target_expr);
        },
        .@"while",
        .while_simple,
        .while_cont,
        => {
            const while_node = ast.fullWhile(tree, node).?;
            try writeTokenMod(builder, while_node.label_token, .label, .{ .declaration = true });
            try writeToken(builder, while_node.inline_token, .keyword);
            try writeToken(builder, while_node.ast.while_token, .keyword);
            try writeNodeTokens(builder, while_node.ast.cond_expr);
            if (while_node.payload_token) |payload| {
                const capture_is_ref = token_tags[payload] == .asterisk;
                const name_token = payload + @intFromBool(capture_is_ref);
                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, while_node.ast.cont_expr);

            try writeNodeTokens(builder, while_node.ast.then_expr);

            if (while_node.ast.else_expr != 0) {
                try writeToken(builder, while_node.else_token, .keyword);

                if (while_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try writeNodeTokens(builder, while_node.ast.else_expr);
            }
        },
        .for_simple,
        .@"for",
        => {
            const for_node = ast.fullFor(tree, node).?;
            try writeTokenMod(builder, for_node.label_token, .label, .{ .declaration = true });
            try writeToken(builder, for_node.inline_token, .keyword);
            try writeToken(builder, for_node.ast.for_token, .keyword);

            for (for_node.ast.inputs) |input_node| {
                try writeNodeTokens(builder, input_node);
            }

            var capture_token = for_node.payload_token;
            for (for_node.ast.inputs) |_| {
                if (capture_token >= tree.tokens.len - 1) break;
                const capture_is_ref = token_tags[capture_token] == .asterisk;
                const name_token = capture_token + @intFromBool(capture_is_ref);
                capture_token = name_token + 2;

                if (token_tags[name_token] != .identifier) continue;
                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, for_node.ast.then_expr);

            if (for_node.ast.else_expr != 0) {
                try writeToken(builder, for_node.else_token, .keyword);
                try writeNodeTokens(builder, for_node.ast.else_expr);
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node).?;

            try writeToken(builder, if_node.ast.if_token, .keyword);
            try writeNodeTokens(builder, if_node.ast.cond_expr);

            if (if_node.payload_token) |payload_token| {
                const capture_is_ref = token_tags[payload_token] == .asterisk;
                const actual_payload = payload_token + @intFromBool(capture_is_ref);
                try writeTokenMod(builder, actual_payload, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, if_node.ast.then_expr);

            if (if_node.ast.else_expr != 0) {
                try writeToken(builder, if_node.else_token, .keyword);
                if (if_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try writeNodeTokens(builder, if_node.ast.else_expr);
            }
        },
        .array_init,
        .array_init_comma,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const array_init: Ast.full.ArrayInit = tree.fullArrayInit(&buf, node).?;

            try writeNodeTokens(builder, array_init.ast.type_expr);
            for (array_init.ast.elements) |elem| try writeNodeTokens(builder, elem);
        },
        .struct_init,
        .struct_init_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = tree.fullStructInit(&buf, node).?;

            var field_token_type: ?TokenType = null;

            if (struct_init.ast.type_expr != 0) {
                try writeNodeTokens(builder, struct_init.ast.type_expr);

                field_token_type = if (try builder.analyser.resolveTypeOfNode(
                    .{ .node = struct_init.ast.type_expr, .handle = handle },
                )) |struct_type| switch (struct_type.data) {
                    .container => |scope_handle| fieldTokenType(try scope_handle.toNode(), scope_handle.handle, false),
                    else => null,
                } else null;
            }

            for (struct_init.ast.fields) |field_init| {
                const init_token = tree.firstToken(field_init);
                try writeToken(builder, init_token - 3, field_token_type orelse .property); // '.'
                try writeToken(builder, init_token - 2, field_token_type orelse .property); // name
                try writeToken(builder, init_token - 1, .operator); // '='
                try writeNodeTokens(builder, field_init);
            }
        },
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            var params: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&params, node).?;

            try writeToken(builder, call.async_token, .keyword);
            try writeNodeTokens(builder, call.ast.fn_expr);

            for (call.ast.params) |param| try writeNodeTokens(builder, param);
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = tree.fullSlice(node).?;

            try writeNodeTokens(builder, slice.ast.sliced);
            try writeNodeTokens(builder, slice.ast.start);
            try writeNodeTokens(builder, slice.ast.end);
            try writeNodeTokens(builder, slice.ast.sentinel);
        },
        .deref => {
            try writeNodeTokens(builder, node_data[node].lhs);
            try writeToken(builder, main_token, .operator);
        },
        .unwrap_optional => {
            try writeNodeTokens(builder, node_data[node].lhs);
            try writeToken(builder, main_token + 1, .operator);
        },
        .grouped_expression => {
            try writeNodeTokens(builder, node_data[node].lhs);
        },
        .@"break" => {
            try writeToken(builder, main_token, .keyword);
            if (node_data[node].lhs != 0)
                try writeToken(builder, node_data[node].lhs, .label);
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .@"continue" => {
            try writeToken(builder, main_token, .keyword);
            if (node_data[node].lhs != 0)
                try writeToken(builder, node_data[node].lhs, .label);
        },
        .@"comptime", .@"nosuspend", .@"suspend", .@"return" => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, node_data[node].lhs);
        },
        .number_literal => {
            try writeToken(builder, main_token, .number);
        },
        .enum_literal => {
            try writeToken(builder, main_token, .enumMember);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            try writeToken(builder, main_token, .builtin);
            for (params) |param|
                try writeNodeTokens(builder, param);
        },
        .string_literal,
        .char_literal,
        => {
            try writeToken(builder, main_token, .string);
        },
        .multiline_string_literal => {
            var cur_tok = main_token;
            const last_tok = node_data[node].rhs;

            while (cur_tok <= last_tok) : (cur_tok += 1) try writeToken(builder, cur_tok, .string);
        },
        .unreachable_literal => {
            try writeToken(builder, main_token, .keywordLiteral);
        },
        .@"asm",
        .asm_simple,
        => {
            const asm_node: Ast.full.Asm = ast.fullAsm(tree, node).?;

            try writeToken(builder, main_token, .keyword);
            try writeToken(builder, asm_node.volatile_token, .keyword);
            try writeNodeTokens(builder, asm_node.ast.template);

            for (asm_node.outputs) |output_node| {
                try writeToken(builder, main_tokens[output_node], .variable);
                try writeToken(builder, main_tokens[output_node] + 2, .string);
                const has_arrow = token_tags[main_tokens[output_node] + 4] == .arrow;
                if (has_arrow) {
                    try writeNodeTokens(builder, node_data[output_node].lhs);
                } else {
                    try writeToken(builder, main_tokens[output_node] + 4, .variable);
                }
            }

            for (asm_node.inputs) |input_node| {
                try writeToken(builder, main_tokens[input_node], .variable);
                try writeToken(builder, main_tokens[input_node] + 2, .string);
                try writeNodeTokens(builder, node_data[input_node].lhs);
            }

            if (asm_node.first_clobber) |first_clobber| clobbers: {
                var tok_i = first_clobber;
                while (true) : (tok_i += 1) {
                    try writeToken(builder, tok_i, .string);
                    tok_i += 1;
                    switch (token_tags[tok_i]) {
                        .r_paren => break :clobbers,
                        .comma => {
                            if (token_tags[tok_i + 1] == .r_paren) {
                                break :clobbers;
                            } else {
                                continue;
                            }
                        },
                        else => break :clobbers,
                    }
                }
            }
        },
        .asm_output,
        .asm_input,
        => unreachable,
        .test_decl => {
            try writeToken(builder, main_token, .keyword);
            switch (token_tags[node_data[node].lhs]) {
                .string_literal => try writeToken(builder, node_data[node].lhs, .string),
                .identifier => try writeIdentifier(builder, node_data[node].lhs),
                else => {},
            }

            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .@"catch" => {
            try writeNodeTokens(builder, node_data[node].lhs);
            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .pipe) {
                try writeTokenMod(builder, main_token + 2, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .add,
        .add_wrap,
        .add_sat,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        .bang_equal,
        .bit_and,
        .bit_or,
        .shl,
        .shl_sat,
        .shr,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .mul_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .@"orelse",
        => {
            try writeNodeTokens(builder, node_data[node].lhs);
            const token_type: TokenType = switch (tag) {
                .bool_and, .bool_or, .@"orelse" => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .assign_destructure => {
            const lhs_count = tree.extra_data[node_data[node].lhs];
            const lhs_exprs = tree.extra_data[node_data[node].lhs + 1 ..][0..lhs_count];

            for (lhs_exprs) |lhs_node| {
                try writeNodeTokens(builder, lhs_node);
            }

            try writeToken(builder, main_token, .operator);
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .array_access,
        .error_union,
        .switch_range,
        .for_range,
        => {
            try writeNodeTokens(builder, node_data[node].lhs);
            try writeNodeTokens(builder, node_data[node].rhs);
        },
        .identifier => {
            if (tree.tokens.items(.tag)[main_token] != .identifier) return; // why parser? why?
            try writeIdentifier(builder, main_token);
        },
        .field_access => {
            const data = node_data[node];
            if (data.rhs == 0) return;

            const symbol_name = offsets.identifierTokenToNameSlice(tree, data.rhs);

            try writeNodeTokens(builder, data.lhs);

            // TODO This is basically exactly the same as what is done in analysis.resolveTypeOfNode, with the added
            //      writeToken code.
            // Maybe we can hook into it instead? Also applies to Identifier and VarDecl
            const lhs = try builder.analyser.resolveTypeOfNode(.{ .node = data.lhs, .handle = handle }) orelse {
                try writeTokenMod(builder, data.rhs, .variable, .{});
                return;
            };
            const lhs_type = try builder.analyser.resolveDerefType(lhs) orelse lhs;
            if (try lhs_type.lookupSymbol(builder.analyser, symbol_name)) |decl_type| {
                switch (decl_type.decl) {
                    .ast_node => |decl_node| {
                        if (decl_type.handle.tree.nodes.items(.tag)[decl_node].isContainerField()) {
                            const tok_type = switch (lhs_type.data) {
                                .container => |scope_handle| fieldTokenType(try scope_handle.toNode(), scope_handle.handle, lhs_type.is_type_val),
                                else => null,
                            };

                            if (tok_type) |tt| {
                                try writeToken(builder, data.rhs, tt);
                                return;
                            }
                        }
                    },
                    .error_token => {
                        try writeToken(builder, data.rhs, .errorTag);
                        return;
                    },
                    else => {},
                }

                if (try decl_type.resolveType(builder.analyser)) |resolved_type| {
                    try colorIdentifierBasedOnType(builder, resolved_type, data.rhs, false, .{});
                    return;
                }
            }

            try writeTokenMod(builder, data.rhs, .variable, .{});
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.fullPtrType(tree, node).?;

            if (ptr_type.ast.sentinel != 0) {
                try writeNodeTokens(builder, ptr_type.ast.sentinel);
            }

            try writeToken(builder, ptr_type.allowzero_token, .keyword);

            if (ptr_type.ast.align_node != 0) {
                const first_tok = tree.firstToken(ptr_type.ast.align_node);
                try writeToken(builder, first_tok - 2, .keyword);
                try writeNodeTokens(builder, ptr_type.ast.align_node);

                if (ptr_type.ast.bit_range_start != 0) {
                    try writeNodeTokens(builder, ptr_type.ast.bit_range_start);
                    try writeNodeTokens(builder, ptr_type.ast.bit_range_end);
                }
            }

            try writeToken(builder, ptr_type.const_token, .keyword);
            try writeToken(builder, ptr_type.volatile_token, .keyword);

            try writeNodeTokens(builder, ptr_type.ast.child_type);
        },
        .array_type,
        .array_type_sentinel,
        => {
            const array_type: Ast.full.ArrayType = tree.fullArrayType(node).?;

            try writeNodeTokens(builder, array_type.ast.elem_count);
            try writeNodeTokens(builder, array_type.ast.sentinel);
            try writeNodeTokens(builder, array_type.ast.elem_type);
        },
        .address_of,
        .bit_not,
        .bool_not,
        .optional_type,
        .negation,
        .negation_wrap,
        => {
            try writeToken(builder, main_token, .operator);
            try writeNodeTokens(builder, node_data[node].lhs);
        },
        .@"try",
        .@"resume",
        .@"await",
        => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, node_data[node].lhs);
        },
        .anyframe_literal => try writeToken(builder, main_token, .type),
    }
}

fn writeContainerField(builder: *Builder, node: Ast.Node.Index, container_decl: Ast.Node.Index) !void {
    const tree = builder.handle.tree;

    var container_field = tree.fullContainerField(node).?;
    const field_token_type = fieldTokenType(container_decl, builder.handle, false) orelse .property;

    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    if (container_decl != 0 and token_tags[main_tokens[container_decl]] != .keyword_struct) {
        container_field.convertToNonTupleLike(tree.nodes);
    }

    try writeToken(builder, container_field.comptime_token, .keyword);
    if (!container_field.ast.tuple_like) {
        try writeTokenMod(builder, container_field.ast.main_token, field_token_type, .{ .declaration = true });
    }

    if (container_field.ast.type_expr != 0) {
        try writeNodeTokens(builder, container_field.ast.type_expr);
        if (container_field.ast.align_expr != 0) {
            try writeToken(builder, tree.firstToken(container_field.ast.align_expr) - 2, .keyword);
            try writeNodeTokens(builder, container_field.ast.align_expr);
        }
    }

    if (container_field.ast.value_expr != 0) {
        const equal_token = tree.firstToken(container_field.ast.value_expr) - 1;
        if (token_tags[equal_token] == .equal) {
            try writeToken(builder, equal_token, .operator);
        }
        try writeNodeTokens(builder, container_field.ast.value_expr);
    }
}

fn writeIdentifier(builder: *Builder, name_token: Ast.Node.Index) error{OutOfMemory}!void {
    const handle = builder.handle;
    const tree = handle.tree;

    const name = offsets.identifierTokenToNameSlice(tree, name_token);
    const is_escaped_identifier = tree.source[tree.tokens.items(.start)[name_token]] == '@';

    if (!is_escaped_identifier) {
        if (std.mem.eql(u8, name, "_")) return;
        if (try builder.analyser.resolvePrimitive(name)) |primitive| {
            const is_type = builder.analyser.ip.typeOf(primitive) == .type_type;
            return try writeToken(builder, name_token, if (is_type) .type else .keywordLiteral);
        }
    }

    if (try builder.analyser.lookupSymbolGlobal(
        handle,
        name,
        tree.tokens.items(.start)[name_token],
    )) |child| {
        const is_param = child.decl == .function_parameter;

        if (try child.resolveType(builder.analyser)) |decl_type| {
            return try colorIdentifierBasedOnType(builder, decl_type, name_token, is_param, .{});
        } else {
            try writeTokenMod(builder, name_token, if (is_param) .parameter else .variable, .{});
        }
    } else {
        try writeTokenMod(builder, name_token, .variable, .{});
    }
}

/// If `loc` is `null`, semantic tokens will be computed for the entire source range
/// Otherwise only tokens in the give source range will be returned
/// TODO edit version.
pub fn writeSemanticTokens(
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    loc: ?offsets.Loc,
    encoding: offsets.Encoding,
    limited: bool,
) error{OutOfMemory}!types.SemanticTokens {
    var builder = Builder{
        .arena = arena,
        .analyser = analyser,
        .handle = handle,
        .encoding = encoding,
        .limited = limited,
    };

    const nodes = if (loc) |l| try ast.nodesAtLoc(arena, handle.tree, l) else handle.tree.rootDecls();

    // reverse the ast from the root declarations
    for (nodes) |child| {
        try writeNodeTokens(&builder, child);
    }

    return try builder.finish();
}
