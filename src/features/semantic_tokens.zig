const std = @import("std");
const zig_builtin = @import("builtin");
const Ast = std.zig.Ast;

const offsets = @import("../offsets.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("../lsp.zig");

pub const TokenType = enum(u32) {
    type,
    parameter,
    variable,
    enumMember,
    property,
    errorTag,
    function,
    keyword,
    comment,
    string,
    number,
    operator,
    builtin,
    label,
    keywordLiteral,
    namespace,
    @"struct",
    @"enum",
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

    generic: bool = false,
    _: u5 = 0,
};

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    previous_source_index: usize = 0,
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

    fn addDirect(self: *Builder, token_type: TokenType, token_modifiers: TokenModifiers, loc: offsets.Loc) error{OutOfMemory}!void {
        std.debug.assert(loc.start <= loc.end);
        if (loc.start < self.previous_source_index) return;
        switch (token_type) {
            .type,
            .enumMember,
            .property,
            .errorTag,
            .function,
            .namespace,
            .@"struct",
            .@"enum",
            .@"union",
            .@"opaque",
            => {},

            .parameter,
            .variable,
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

        const delta_text = self.handle.tree.source[self.previous_source_index..loc.start];
        const delta = offsets.indexToPosition(delta_text, delta_text.len, self.encoding);
        const length = offsets.locLength(self.handle.tree.source, loc, self.encoding);

        try self.token_buffer.appendSlice(self.arena, &.{
            @truncate(u32, delta.line),
            @truncate(u32, delta.character),
            @truncate(u32, length),
            @enumToInt(token_type),
            @bitCast(u16, token_modifiers),
        });
        self.previous_source_index = loc.start;
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

fn writeDocComments(builder: *Builder, tree: Ast, doc: Ast.TokenIndex) !void {
    const token_tags = tree.tokens.items(.tag);
    var tok_idx = doc;
    while (token_tags[tok_idx] == .doc_comment or
        token_tags[tok_idx] == .container_doc_comment) : (tok_idx += 1)
    {
        try builder.add(tok_idx, .comment, .{ .documentation = true });
    }
}

fn fieldTokenType(container_decl: Ast.Node.Index, handle: *const DocumentStore.Handle) ?TokenType {
    const main_token = handle.tree.nodes.items(.main_token)[container_decl];
    if (main_token > handle.tree.tokens.len) return null;
    return @as(?TokenType, switch (handle.tree.tokens.items(.tag)[main_token]) {
        .keyword_struct, .keyword_union => .property,
        .keyword_enum => .enumMember,
        .keyword_error => .errorTag,
        else => null,
    });
}

fn colorIdentifierBasedOnType(builder: *Builder, type_node: Analyser.TypeWithHandle, target_tok: Ast.TokenIndex, tok_mod: TokenModifiers) !void {
    if (type_node.type.is_type_val) {
        var new_tok_mod = tok_mod;

        const token_type: TokenType =
            if (type_node.isNamespace())
            .namespace
        else if (type_node.isStructType())
            .@"struct"
        else if (type_node.isEnumType())
            .@"enum"
        else if (type_node.isUnionType())
            .@"union"
        else if (type_node.isOpaqueType())
            .@"opaque"
        else
            .type;

        try writeTokenMod(builder, target_tok, token_type, new_tok_mod);
    } else if (type_node.isTypeFunc()) {
        try writeTokenMod(builder, target_tok, .type, tok_mod);
    } else if (type_node.isFunc()) {
        var new_tok_mod = tok_mod;
        if (type_node.isGenericFunc()) {
            new_tok_mod.generic = true;
        }
        try writeTokenMod(builder, target_tok, .function, new_tok_mod);
    } else {
        try writeTokenMod(builder, target_tok, .variable, tok_mod);
    }
}

/// HACK self-hosted has not implemented async yet
inline fn callWriteNodeTokens(allocator: std.mem.Allocator, args: anytype) error{OutOfMemory}!void {
    if (zig_builtin.zig_backend == .other or zig_builtin.zig_backend == .stage1) {
        const FrameSize = @sizeOf(@Frame(writeNodeTokens));
        var child_frame = try allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
        // defer allocator.free(child_frame); allocator is a arena allocator

        return await @asyncCall(child_frame, {}, writeNodeTokens, args);
    } else {
        // TODO find a non recursive solution
        return @call(.auto, writeNodeTokens, args);
    }
}

fn writeNodeTokens(builder: *Builder, node: Ast.Node.Index) error{OutOfMemory}!void {
    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    if (node == 0 or node >= node_data.len) return;

    var allocator = builder.arena;

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

            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
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
                try callWriteNodeTokens(allocator, .{ builder, child });
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
                try colorIdentifierBasedOnType(builder, decl_type, var_decl.ast.mut_token + 1, .{ .declaration = true });
            } else {
                try writeTokenMod(builder, var_decl.ast.mut_token + 1, .variable, .{ .declaration = true });
            }

            try callWriteNodeTokens(allocator, .{ builder, var_decl.ast.type_node });
            try callWriteNodeTokens(allocator, .{ builder, var_decl.ast.align_node });
            try callWriteNodeTokens(allocator, .{ builder, var_decl.ast.section_node });

            if (var_decl.ast.init_node != 0) {
                const equal_token = tree.firstToken(var_decl.ast.init_node) - 1;
                if (token_tags[equal_token] == .equal) {
                    try writeToken(builder, equal_token, .operator);
                }
            }

            try callWriteNodeTokens(allocator, .{ builder, var_decl.ast.init_node });
        },
        .@"usingnamespace" => {
            const first_tok = tree.firstToken(node);
            if (first_tok > 0 and token_tags[first_tok - 1] == .doc_comment)
                try writeDocComments(builder, tree, first_tok - 1);
            try writeToken(builder, if (token_tags[first_tok] == .keyword_pub) first_tok else null, .keyword);
            try writeToken(builder, main_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
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
                if (decl.ast.arg != 0)
                    try callWriteNodeTokens(allocator, .{ builder, decl.ast.arg })
                else
                    try writeToken(builder, enum_token, .keyword);
            } else try callWriteNodeTokens(allocator, .{ builder, decl.ast.arg });

            for (decl.ast.members) |child| {
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, child, node);
                } else {
                    try callWriteNodeTokens(allocator, .{ builder, child });
                }
            }
        },
        .error_set_decl => {
            try writeToken(builder, main_token, .keyword);

            var tok_i = main_tokens[node] + 2;
            while (tok_i < node_data[node].rhs) : (tok_i += 1) {
                switch (token_tags[tok_i]) {
                    .doc_comment, .comma => {},
                    .identifier => try writeToken(builder, tok_i, .errorTag),
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
        .identifier => {
            const name = offsets.nodeToSlice(tree, node);

            if (std.mem.eql(u8, name, "_")) {
                return;
            } else if (Analyser.isValueIdent(name)) {
                return try writeToken(builder, main_token, .keywordLiteral);
            } else if (Analyser.isTypeIdent(name)) {
                return try writeToken(builder, main_token, .type);
            }

            if (try builder.analyser.lookupSymbolGlobal(
                handle,
                name,
                tree.tokens.items(.start)[main_token],
            )) |child| {
                if (child.decl.* == .param_payload) {
                    return try writeToken(builder, main_token, .parameter);
                }
                if (try child.resolveType(builder.analyser)) |decl_type| {
                    return try colorIdentifierBasedOnType(builder, decl_type, main_token, .{});
                }
            }
            try writeTokenMod(builder, main_token, .variable, .{});
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

            const func_name_tok_type: TokenType = if (Analyser.isTypeFunction(tree, fn_proto))
                .type
            else
                .function;

            const tok_mod = TokenModifiers{
                .declaration = true,
                .generic = Analyser.isGenericFunction(tree, fn_proto),
            };

            try writeTokenMod(builder, fn_proto.name_token, func_name_tok_type, tok_mod);

            var it = fn_proto.iterate(&tree);
            while (ast.nextFnParam(&it)) |param_decl| {
                if (param_decl.first_doc_comment) |docs| try writeDocComments(builder, tree, docs);

                try writeToken(builder, param_decl.comptime_noalias, .keyword);
                try writeTokenMod(builder, param_decl.name_token, .parameter, .{ .declaration = true });
                if (param_decl.anytype_ellipsis3) |any_token| {
                    try writeToken(builder, any_token, .type);
                } else try callWriteNodeTokens(allocator, .{ builder, param_decl.type_expr });
            }

            try callWriteNodeTokens(allocator, .{ builder, fn_proto.ast.align_expr });
            try callWriteNodeTokens(allocator, .{ builder, fn_proto.ast.section_expr });
            try callWriteNodeTokens(allocator, .{ builder, fn_proto.ast.callconv_expr });

            try callWriteNodeTokens(allocator, .{ builder, fn_proto.ast.return_type });

            if (tag == .fn_decl)
                try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .anyframe_type, .@"defer" => {
            try writeToken(builder, main_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .@"switch",
        .switch_comma,
        => {
            try writeToken(builder, main_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            const extra = tree.extraData(node_data[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases) |case_node| {
                try callWriteNodeTokens(allocator, .{ builder, case_node });
            }
        },
        .switch_case_one,
        .switch_case,
        .switch_case_inline_one,
        .switch_case_inline,
        => {
            const switch_case = tree.fullSwitchCase(node).?;
            try writeToken(builder, switch_case.inline_token, .keyword);
            for (switch_case.ast.values) |item_node| try callWriteNodeTokens(allocator, .{ builder, item_node });
            // check it it's 'else'
            if (switch_case.ast.values.len == 0) try writeToken(builder, switch_case.ast.arrow_token - 1, .keyword);
            if (switch_case.payload_token) |payload_token| {
                const actual_payload = payload_token + @boolToInt(token_tags[payload_token] == .asterisk);
                try writeTokenMod(builder, actual_payload, .variable, .{ .declaration = true });
            }
            try callWriteNodeTokens(allocator, .{ builder, switch_case.ast.target_expr });
        },
        .@"while",
        .while_simple,
        .while_cont,
        => {
            const while_node = ast.fullWhile(tree, node).?;
            try writeToken(builder, while_node.label_token, .label);
            try writeToken(builder, while_node.inline_token, .keyword);
            try writeToken(builder, while_node.ast.while_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, while_node.ast.cond_expr });
            if (while_node.payload_token) |payload| {
                const capture_is_ref = token_tags[payload] == .asterisk;
                const name_token = payload + @boolToInt(capture_is_ref);
                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            try callWriteNodeTokens(allocator, .{ builder, while_node.ast.cont_expr });

            try callWriteNodeTokens(allocator, .{ builder, while_node.ast.then_expr });

            if (while_node.ast.else_expr != 0) {
                try writeToken(builder, while_node.else_token, .keyword);

                if (while_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try callWriteNodeTokens(allocator, .{ builder, while_node.ast.else_expr });
            }
        },
        .for_simple,
        .@"for",
        => {
            const for_node = ast.fullFor(tree, node).?;
            try writeToken(builder, for_node.label_token, .label);
            try writeToken(builder, for_node.inline_token, .keyword);
            try writeToken(builder, for_node.ast.for_token, .keyword);

            for (for_node.ast.inputs) |input_node| {
                try callWriteNodeTokens(allocator, .{ builder, input_node });
            }

            var capture_token = for_node.payload_token;
            for (for_node.ast.inputs) |_| {
                const capture_is_ref = token_tags[capture_token] == .asterisk;
                const name_token = capture_token + @boolToInt(capture_is_ref);
                capture_token = name_token + 2;

                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            try callWriteNodeTokens(allocator, .{ builder, for_node.ast.then_expr });

            if (for_node.ast.else_expr != 0) {
                try writeToken(builder, for_node.else_token, .keyword);
                try callWriteNodeTokens(allocator, .{ builder, for_node.ast.else_expr });
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node).?;

            try writeToken(builder, if_node.ast.if_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, if_node.ast.cond_expr });

            if (if_node.payload_token) |payload_token| {
                const capture_is_ref = token_tags[payload_token] == .asterisk;
                const actual_payload = payload_token + @boolToInt(capture_is_ref);
                try writeTokenMod(builder, actual_payload, .variable, .{ .declaration = true });
            }
            try callWriteNodeTokens(allocator, .{ builder, if_node.ast.then_expr });

            if (if_node.ast.else_expr != 0) {
                try writeToken(builder, if_node.else_token, .keyword);
                if (if_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try callWriteNodeTokens(allocator, .{ builder, if_node.ast.else_expr });
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

            try callWriteNodeTokens(allocator, .{ builder, array_init.ast.type_expr });
            for (array_init.ast.elements) |elem| try callWriteNodeTokens(allocator, .{ builder, elem });
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
                try callWriteNodeTokens(allocator, .{ builder, struct_init.ast.type_expr });

                field_token_type = if (try builder.analyser.resolveTypeOfNode(
                    .{ .node = struct_init.ast.type_expr, .handle = handle },
                )) |struct_type| switch (struct_type.type.data) {
                    .other => |type_node| if (ast.isContainer(struct_type.handle.tree, type_node))
                        fieldTokenType(type_node, struct_type.handle)
                    else
                        null,
                    else => null,
                } else null;
            }

            for (struct_init.ast.fields) |field_init| {
                const init_token = tree.firstToken(field_init);
                try writeToken(builder, init_token - 3, field_token_type orelse .property); // '.'
                try writeToken(builder, init_token - 2, field_token_type orelse .property); // name
                try writeToken(builder, init_token - 1, .operator); // '='
                try callWriteNodeTokens(allocator, .{ builder, field_init });
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
            try callWriteNodeTokens(allocator, .{ builder, call.ast.fn_expr });

            for (call.ast.params) |param| try callWriteNodeTokens(allocator, .{ builder, param });
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = tree.fullSlice(node).?;

            try callWriteNodeTokens(allocator, .{ builder, slice.ast.sliced });
            try callWriteNodeTokens(allocator, .{ builder, slice.ast.start });
            try callWriteNodeTokens(allocator, .{ builder, slice.ast.end });
            try callWriteNodeTokens(allocator, .{ builder, slice.ast.sentinel });
        },
        .deref => {
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            try writeToken(builder, main_token, .operator);
        },
        .unwrap_optional => {
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            try writeToken(builder, main_token + 1, .operator);
        },
        .grouped_expression => {
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
        },
        .@"break" => {
            try writeToken(builder, main_token, .keyword);
            if (node_data[node].lhs != 0)
                try writeToken(builder, node_data[node].lhs, .label);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .@"continue" => {
            try writeToken(builder, main_token, .keyword);
            if (node_data[node].lhs != 0)
                try writeToken(builder, node_data[node].lhs, .label);
        },
        .@"comptime", .@"nosuspend", .@"suspend", .@"return" => {
            try writeToken(builder, main_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
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
                try callWriteNodeTokens(allocator, .{ builder, param });
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
            const asm_node: Ast.full.Asm = tree.fullAsm(node).?;

            try writeToken(builder, main_token, .keyword);
            try writeToken(builder, asm_node.volatile_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, asm_node.ast.template });

            for (asm_node.outputs) |output_node| {
                try writeToken(builder, main_tokens[output_node], .variable);
                try writeToken(builder, main_tokens[output_node] + 2, .string);
                const has_arrow = token_tags[main_tokens[output_node] + 4] == .arrow;
                if (has_arrow) {
                    try callWriteNodeTokens(allocator, .{ builder, node_data[output_node].lhs });
                } else {
                    try writeToken(builder, main_tokens[output_node] + 4, .variable);
                }
            }

            for (asm_node.inputs) |input_node| {
                try writeToken(builder, main_tokens[input_node], .variable);
                try writeToken(builder, main_tokens[input_node] + 2, .string);
                try callWriteNodeTokens(allocator, .{ builder, node_data[input_node].lhs });
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
                .identifier => try writeToken(builder, node_data[node].lhs, .variable),
                else => {},
            }

            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .@"catch" => {
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .pipe) {
                try writeTokenMod(builder, main_token + 2, .variable, .{ .declaration = true });
            }
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
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
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            const token_type: TokenType = switch (tag) {
                .bool_and, .bool_or, .@"orelse" => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .array_access,
        .error_union,
        .switch_range,
        .for_range,
        => {
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].rhs });
        },
        .field_access => {
            const data = node_data[node];
            if (data.rhs == 0) return;

            try callWriteNodeTokens(allocator, .{ builder, data.lhs });

            // TODO This is basically exactly the same as what is done in analysis.resolveTypeOfNode, with the added
            //      writeToken code.
            // Maybe we can hook into it instead? Also applies to Identifier and VarDecl
            const lhs_type = try builder.analyser.resolveFieldAccessLhsType(
                (try builder.analyser.resolveTypeOfNode(.{ .node = data.lhs, .handle = handle })) orelse return,
            );
            const left_type_node = switch (lhs_type.type.data) {
                .other => |n| n,
                else => return,
            };
            if (try builder.analyser.lookupSymbolContainer(
                .{ .node = left_type_node, .handle = lhs_type.handle },
                tree.tokenSlice(data.rhs),
                !lhs_type.type.is_type_val,
            )) |decl_type| {
                switch (decl_type.decl.*) {
                    .ast_node => |decl_node| {
                        if (decl_type.handle.tree.nodes.items(.tag)[decl_node].isContainerField()) {
                            const tok_type: ?TokenType = if (ast.isContainer(lhs_type.handle.tree, left_type_node))
                                fieldTokenType(decl_node, lhs_type.handle)
                            else if (left_type_node == 0)
                                .property
                            else
                                null;

                            if (tok_type) |tt| try writeToken(builder, data.rhs, tt);
                            return;
                        } else if (decl_type.handle.tree.nodes.items(.tag)[decl_node] == .error_value) {
                            try writeToken(builder, data.rhs, .errorTag);
                        }
                    },
                    else => {},
                }

                if (try decl_type.resolveType(builder.analyser)) |resolved_type| {
                    try colorIdentifierBasedOnType(builder, resolved_type, data.rhs, .{});
                }
            }
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.fullPtrType(tree, node).?;

            if (ptr_type.size == .One and token_tags[main_token] == .asterisk_asterisk and
                main_token == main_tokens[ptr_type.ast.child_type])
            {
                return try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.child_type });
            }

            if (ptr_type.size == .One) try writeToken(builder, main_token, .operator);
            if (ptr_type.ast.sentinel != 0) {
                try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.sentinel });
            }

            try writeToken(builder, ptr_type.allowzero_token, .keyword);

            if (ptr_type.ast.align_node != 0) {
                const first_tok = tree.firstToken(ptr_type.ast.align_node);
                try writeToken(builder, first_tok - 2, .keyword);
                try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.align_node });

                if (ptr_type.ast.bit_range_start != 0) {
                    try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.bit_range_start });
                    try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.bit_range_end });
                }
            }

            try writeToken(builder, ptr_type.const_token, .keyword);
            try writeToken(builder, ptr_type.volatile_token, .keyword);

            try callWriteNodeTokens(allocator, .{ builder, ptr_type.ast.child_type });
        },
        .array_type,
        .array_type_sentinel,
        => {
            const array_type: Ast.full.ArrayType = tree.fullArrayType(node).?;

            try callWriteNodeTokens(allocator, .{ builder, array_type.ast.elem_count });
            try callWriteNodeTokens(allocator, .{ builder, array_type.ast.sentinel });
            try callWriteNodeTokens(allocator, .{ builder, array_type.ast.elem_type });
        },
        .address_of,
        .bit_not,
        .bool_not,
        .optional_type,
        .negation,
        .negation_wrap,
        => {
            try writeToken(builder, main_token, .operator);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
        },
        .@"try",
        .@"resume",
        .@"await",
        => {
            try writeToken(builder, main_token, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, node_data[node].lhs });
        },
        .anyframe_literal => try writeToken(builder, main_token, .keyword),
    }
}

fn writeContainerField(builder: *Builder, node: Ast.Node.Index, container_decl: Ast.Node.Index) !void {
    const tree = builder.handle.tree;
    var allocator = builder.arena;

    var container_field = tree.fullContainerField(node).?;
    const field_token_type = fieldTokenType(container_decl, builder.handle) orelse .property;

    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    if (container_decl != 0 and token_tags[main_tokens[container_decl]] != .keyword_struct) {
        container_field.convertToNonTupleLike(tree.nodes);
    }

    try writeToken(builder, container_field.comptime_token, .keyword);
    if (!container_field.ast.tuple_like) {
        try writeToken(builder, container_field.ast.main_token, field_token_type);
    }

    if (container_field.ast.type_expr != 0) {
        try callWriteNodeTokens(allocator, .{ builder, container_field.ast.type_expr });
        if (container_field.ast.align_expr != 0) {
            try writeToken(builder, tree.firstToken(container_field.ast.align_expr) - 2, .keyword);
            try callWriteNodeTokens(allocator, .{ builder, container_field.ast.align_expr });
        }
    }

    if (container_field.ast.value_expr != 0) {
        const eq_tok: Ast.TokenIndex = if (container_field.ast.align_expr != 0)
            ast.lastToken(tree, container_field.ast.align_expr) + 2
        else if (container_field.ast.type_expr != 0)
            ast.lastToken(tree, container_field.ast.type_expr) + 1
        else
            container_field.ast.main_token + 1;

        try writeToken(builder, eq_tok, .operator);
        try callWriteNodeTokens(allocator, .{ builder, container_field.ast.value_expr });
    }
}

/// If `loc` is `null`, semantic tokens will be computed for the entire source range
/// Otherwise only tokens in the give source range will be returned
/// TODO edit version.
pub fn writeSemanticTokens(
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
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
