//! Implementation of [`textDocument/semanticTokens/*`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_semanticTokens)

const std = @import("std");
const Ast = std.zig.Ast;

const offsets = @import("../offsets.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;

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
    escapeSequence,
    number,
    regexp,
    operator,
    decorator,
    /// non standard token type
    errorTag,
    /// non standard token type
    builtin,
    /// non standard token type
    label,
    /// non standard token type
    keywordLiteral,
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
    mutable: bool = false,
    _: u4 = 0,

    pub fn format(
        modifiers: TokenModifiers,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, modifiers);
        _ = options;

        try writer.writeAll(".{");
        var i: usize = 0;
        inline for (std.meta.fields(TokenModifiers)) |field| {
            if ((comptime !std.mem.eql(u8, field.name, "_")) and @field(modifiers, field.name)) {
                if (i == 0) {
                    try writer.writeAll(" .");
                } else {
                    try writer.writeAll(", .");
                }
                try writer.writeAll(field.name);
                try writer.writeAll(" = true");
                i += 1;
            }
        }
        try writer.writeAll(" }");
    }
};

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    previous_source_index: usize = 0,
    source_index: usize = 0,
    token_buffer: std.ArrayListUnmanaged(u32) = .empty,
    encoding: offsets.Encoding,
    limited: bool,
    overlappingTokenSupport: bool,

    fn add(self: *Builder, token: Ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) error{OutOfMemory}!void {
        const tree = self.handle.tree;

        try self.handleComments(self.previous_source_index, tree.tokenStart(token));
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
        std.debug.assert(self.previous_source_index <= self.source_index);
        if (loc.start < self.previous_source_index) return;
        if (!self.overlappingTokenSupport and loc.start < self.source_index) return;
        switch (token_type) {
            .namespace,
            .type,
            .class,
            .@"enum",
            .interface,
            .@"struct",
            .typeParameter,
            .parameter,
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

            .keyword,
            .comment,
            .string,
            .escapeSequence,
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

fn writeToken(builder: *Builder, token_idx: ?Ast.TokenIndex, tok_type: TokenType) !void {
    return try writeTokenMod(builder, token_idx, tok_type, .{});
}

fn writeTokenMod(builder: *Builder, token_idx: ?Ast.TokenIndex, tok_type: TokenType, tok_mod: TokenModifiers) !void {
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
    if (handle.tree.nodeTag(container_decl) == .root) return .property;
    if (is_static_access and ast.isTaggedUnion(handle.tree, container_decl))
        return .enumMember;
    const main_token = handle.tree.nodeMainToken(container_decl);
    if (main_token > handle.tree.tokens.len) return null;
    return switch (handle.tree.tokenTag(main_token)) {
        .keyword_struct, .keyword_union => .property,
        .keyword_enum => .enumMember,
        .keyword_error => .errorTag,
        else => null,
    };
}

fn colorIdentifierBasedOnType(
    builder: *Builder,
    type_node: Analyser.Type,
    target_tok: Ast.TokenIndex,
    is_parameter: bool,
    tok_mod: TokenModifiers,
) !void {
    if (type_node.is_type_val) {
        const token_type: TokenType = if (type_node.isNamespace())
            .namespace
        else if (type_node.isStructType())
            .@"struct"
        else if (type_node.isEnumType())
            .@"enum"
        else if (type_node.isUnionType())
            .type // There is no token type for a union type
        else if (type_node.isOpaqueType())
            .type // There is no token type for an opaque
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

        const has_self_param = builder.analyser.hasSelfParam(type_node);

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
    const handle = builder.handle;
    const tree = handle.tree;

    const main_token = tree.nodeMainToken(node);

    switch (tree.nodeTag(node)) {
        .root => unreachable,
        .container_field,
        .container_field_align,
        .container_field_init,
        => try writeContainerField(builder, node, .root),
        .@"errdefer" => {
            try writeToken(builder, main_token, .keyword);

            const opt_payload, const rhs = tree.nodeData(node).opt_token_and_node;

            if (opt_payload.unwrap()) |payload| {
                try writeTokenMod(builder, payload, .variable, .{ .declaration = true });
            }

            try writeNodeTokens(builder, rhs);
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            if (ast.blockLabel(tree, node)) |label_token| {
                try writeTokenMod(builder, label_token, .label, .{ .declaration = true });
            }

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buffer, node).?;

            for (statements) |child| {
                try writeNodeTokens(builder, child);
            }
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const resolved_type = try builder.analyser.resolveTypeOfNode(.of(node, handle));
            try writeVarDecl(builder, node, resolved_type);
        },
        .@"usingnamespace" => {
            const first_token = tree.firstToken(node);
            if (tree.tokenTag(first_token) == .keyword_pub) {
                try writeToken(builder, first_token, .keyword);
            }
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, tree.nodeData(node).node);
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
            }
            if (decl.ast.arg.unwrap()) |arg| {
                try writeNodeTokens(builder, arg);
            }

            for (decl.ast.members) |child| {
                if (tree.nodeTag(child).isContainerField()) {
                    try writeContainerField(builder, child, node);
                } else {
                    try writeNodeTokens(builder, child);
                }
            }
        },
        .error_set_decl => {
            try writeToken(builder, main_token, .keyword);

            const lbrace, const rbrace = tree.nodeData(node).token_and_token;
            for (lbrace + 1..rbrace) |tok_i| {
                switch (tree.tokenTag(@intCast(tok_i))) {
                    .doc_comment, .comma => {},
                    .identifier => try writeTokenMod(builder, @intCast(tok_i), .errorTag, .{ .declaration = true }),
                    else => {},
                }
            }
        },
        .error_value => {
            const error_token = tree.nodeMainToken(node);
            try writeToken(builder, error_token, .keyword);
            const name_token = error_token + 2;
            if (name_token < tree.tokens.len and tree.tokenTag(name_token) == .identifier) {
                try writeToken(builder, name_token, .errorTag);
            } else {
                // parser error
            }
        },
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => |tag| {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto: Ast.full.FnProto = tree.fullFnProto(&buf, node).?;

            try writeToken(builder, fn_proto.visib_token, .keyword);
            try writeToken(builder, fn_proto.extern_export_inline_token, .keyword);
            try writeToken(builder, fn_proto.lib_name, .string);
            try writeToken(builder, fn_proto.ast.fn_token, .keyword);

            var is_generic = false;
            var func_name_tok_type: TokenType = .function;
            if (try builder.analyser.resolveTypeOfNode(.of(node, handle))) |func_ty| {
                is_generic = func_ty.isGenericFunc();
                if (func_ty.isTypeFunc()) {
                    func_name_tok_type = .type;
                } else {
                    const container_ty = try builder.analyser.innermostContainer(handle, tree.tokenStart(fn_proto.ast.fn_token));
                    if (container_ty.data.container.scope_handle.scope != .root and
                        Analyser.firstParamIs(func_ty, container_ty))
                    {
                        func_name_tok_type = .method;
                    }
                }
            }

            const tok_mod: TokenModifiers = .{
                .declaration = true,
                .generic = is_generic,
            };

            try writeTokenMod(builder, fn_proto.name_token, func_name_tok_type, tok_mod);

            var it = fn_proto.iterate(&tree);
            while (ast.nextFnParam(&it)) |param_decl| {
                try writeToken(builder, param_decl.comptime_noalias, .keyword);

                const token_type: TokenType = if (param_decl.type_expr) |type_expr|
                    if (Analyser.isMetaType(tree, type_expr))
                        .typeParameter
                    else
                        .parameter
                else
                    .parameter;
                try writeTokenMod(builder, param_decl.name_token, token_type, .{ .declaration = true });

                if (param_decl.anytype_ellipsis3) |any_token| {
                    try writeToken(builder, any_token, .type);
                } else try writeNodeTokens(builder, param_decl.type_expr.?);
            }

            if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
                try writeToken(builder, tree.firstToken(align_expr) - 2, .keyword);
                try writeNodeTokens(builder, align_expr);
            }

            if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
                try writeNodeTokens(builder, section_expr);
            }
            if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
                try writeToken(builder, tree.firstToken(callconv_expr) - 2, .keyword);
            }
            if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
                try writeNodeTokens(builder, callconv_expr);
            }
            if (fn_proto.ast.return_type.unwrap()) |return_type| {
                try writeNodeTokens(builder, return_type);
            }

            if (tag == .fn_decl) {
                try writeNodeTokens(builder, tree.nodeData(node).node_and_node[1]);
            }
        },
        .anyframe_type => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, tree.nodeData(node).token_and_node[1]);
        },
        .@"defer" => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, tree.nodeData(node).node);
        },
        .@"switch",
        .switch_comma,
        => {
            const switch_node = tree.fullSwitch(node).?;
            try writeTokenMod(builder, switch_node.label_token, .label, .{ .declaration = true });
            try writeToken(builder, switch_node.ast.switch_token, .keyword);
            try writeNodeTokens(builder, switch_node.ast.condition);
            for (switch_node.ast.cases) |case_node| {
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
                const actual_payload = payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk);
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
                const capture_is_ref = tree.tokenTag(payload) == .asterisk;
                const name_token = payload + @intFromBool(capture_is_ref);
                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            if (while_node.ast.cont_expr.unwrap()) |cont_expr| try writeNodeTokens(builder, cont_expr);
            try writeNodeTokens(builder, while_node.ast.then_expr);

            if (while_node.ast.else_expr.unwrap()) |else_expr| {
                try writeToken(builder, while_node.else_token, .keyword);

                if (while_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try writeNodeTokens(builder, else_expr);
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
                const capture_is_ref = tree.tokenTag(capture_token) == .asterisk;
                const name_token = capture_token + @intFromBool(capture_is_ref);
                capture_token = name_token + 2;

                if (tree.tokenTag(name_token) != .identifier) continue;
                try writeTokenMod(builder, name_token, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, for_node.ast.then_expr);

            if (for_node.ast.else_expr.unwrap()) |else_expr| {
                try writeToken(builder, for_node.else_token, .keyword);
                try writeNodeTokens(builder, else_expr);
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node).?;

            try writeToken(builder, if_node.ast.if_token, .keyword);
            try writeNodeTokens(builder, if_node.ast.cond_expr);

            if (if_node.payload_token) |payload_token| {
                const capture_is_ref = tree.tokenTag(payload_token) == .asterisk;
                const actual_payload = payload_token + @intFromBool(capture_is_ref);
                try writeTokenMod(builder, actual_payload, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, if_node.ast.then_expr);

            if (if_node.ast.else_expr.unwrap()) |else_expr| {
                try writeToken(builder, if_node.else_token, .keyword);
                if (if_node.error_token) |err_token| {
                    try writeTokenMod(builder, err_token, .variable, .{ .declaration = true });
                }
                try writeNodeTokens(builder, else_expr);
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

            if (array_init.ast.type_expr.unwrap()) |type_expr| {
                try writeNodeTokens(builder, type_expr);
            }
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

            if (struct_init.ast.type_expr.unwrap()) |type_expr| {
                try writeNodeTokens(builder, type_expr);

                if (try builder.analyser.resolveTypeOfNode(.of(type_expr, handle))) |struct_type| {
                    switch (struct_type.data) {
                        .container => |info| {
                            const scope_handle = info.scope_handle;
                            field_token_type = fieldTokenType(scope_handle.toNode(), scope_handle.handle, false);
                        },
                        else => {},
                    }
                }
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
            if (tree.nodeTag(call.ast.fn_expr) == .enum_literal) {
                // TODO actually try to resolve the decl literal
                try writeToken(builder, tree.nodeMainToken(call.ast.fn_expr), .function);
            } else {
                try writeNodeTokens(builder, call.ast.fn_expr);
            }

            for (call.ast.params) |param| try writeNodeTokens(builder, param);
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = tree.fullSlice(node).?;

            try writeNodeTokens(builder, slice.ast.sliced);
            try writeNodeTokens(builder, slice.ast.start);
            if (slice.ast.end.unwrap()) |end| {
                try writeNodeTokens(builder, end);
            }
            if (slice.ast.sentinel.unwrap()) |sentinel| {
                try writeNodeTokens(builder, sentinel);
            }
        },
        .deref => {
            try writeNodeTokens(builder, tree.nodeData(node).node);
            try writeToken(builder, main_token, .operator);
        },
        .unwrap_optional => {
            const lhs, const question_mark_token = tree.nodeData(node).node_and_token;
            try writeNodeTokens(builder, lhs);
            try writeToken(builder, question_mark_token, .operator);
        },
        .grouped_expression => {
            try writeNodeTokens(builder, tree.nodeData(node).node_and_token[0]);
        },
        .@"break", .@"continue" => {
            const opt_target, const opt_rhs = tree.nodeData(node).opt_token_and_opt_node;
            try writeToken(builder, main_token, .keyword);
            if (opt_target.unwrap()) |target| {
                try writeToken(builder, target, .label);
            }
            if (opt_rhs.unwrap()) |rhs| {
                try writeNodeTokens(builder, rhs);
            }
        },
        .@"comptime", .@"nosuspend", .@"suspend" => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, tree.nodeData(node).node);
        },
        .@"return" => {
            try writeToken(builder, main_token, .keyword);
            if (tree.nodeData(node).opt_node.unwrap()) |lhs| {
                try writeNodeTokens(builder, lhs);
            }
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
            const params = tree.builtinCallParams(&buffer, node).?;

            try writeToken(builder, main_token, .builtin);
            for (params) |param|
                try writeNodeTokens(builder, param);
        },
        .string_literal,
        .char_literal,
        => {
            try writeToken(builder, main_token, .string);
            if (!builder.limited and builder.overlappingTokenSupport) {
                const string_start = tree.tokenStart(main_token);
                const string = offsets.nodeToSlice(tree, node);
                var offset: usize = 0;
                while (offset < string.len) {
                    const slash_index = std.mem.indexOfScalarPos(u8, string, offset, '\\') orelse break;
                    offset = slash_index;
                    _ = std.zig.string_literal.parseEscapeSequence(string, &offset);
                    try builder.addDirect(.escapeSequence, .{}, .{
                        .start = slash_index + string_start,
                        .end = offset + string_start,
                    });
                }
            }
        },
        .multiline_string_literal => {
            const first_token, const last_token = tree.nodeData(node).token_and_token;
            for (first_token..last_token + 1) |cur_tok| {
                try writeToken(builder, @intCast(cur_tok), .string);
            }
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
                try writeToken(builder, tree.nodeMainToken(output_node), .variable);
                try writeToken(builder, tree.nodeMainToken(output_node) + 2, .string);
                const has_arrow = tree.tokenTag(tree.nodeMainToken(output_node) + 4) == .arrow;
                if (has_arrow) {
                    if (tree.nodeData(output_node).opt_node_and_token[0].unwrap()) |lhs| {
                        try writeNodeTokens(builder, lhs);
                    }
                } else {
                    try writeToken(builder, tree.nodeMainToken(output_node) + 4, .variable);
                }
            }

            for (asm_node.inputs) |input_node| {
                try writeToken(builder, tree.nodeMainToken(input_node), .variable);
                try writeToken(builder, tree.nodeMainToken(input_node) + 2, .string);
                try writeNodeTokens(builder, tree.nodeData(input_node).node_and_token[0]);
            }

            if (asm_node.first_clobber) |first_clobber| clobbers: {
                var tok_i = first_clobber;
                while (true) : (tok_i += 1) {
                    try writeToken(builder, tok_i, .string);
                    tok_i += 1;
                    switch (tree.tokenTag(tok_i)) {
                        .r_paren => break :clobbers,
                        .comma => {
                            if (tree.tokenTag(tok_i + 1) == .r_paren) {
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
            const opt_name_token, const block = tree.nodeData(node).opt_token_and_node;
            try writeToken(builder, main_token, .keyword);
            if (opt_name_token.unwrap()) |name_token| {
                switch (tree.tokenTag(name_token)) {
                    .string_literal => try writeToken(builder, name_token, .string),
                    .identifier => try writeIdentifier(builder, name_token),
                    else => {},
                }
            }

            try writeNodeTokens(builder, block);
        },
        .@"catch" => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try writeNodeTokens(builder, lhs);
            try writeToken(builder, main_token, .keyword);
            if (tree.tokenTag(main_token + 1) == .pipe) {
                try writeTokenMod(builder, main_token + 2, .variable, .{ .declaration = true });
            }
            try writeNodeTokens(builder, rhs);
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
        => |tag| {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try writeNodeTokens(builder, lhs);
            const token_type: TokenType = switch (tag) {
                .bool_and, .bool_or, .@"orelse" => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            try writeNodeTokens(builder, rhs);
        },
        .assign_destructure => {
            const data = tree.assignDestructure(node);

            const resolved_type = try builder.analyser.resolveTypeOfNode(.of(data.ast.value_expr, handle));

            for (data.ast.variables, 0..) |lhs_node, index| {
                switch (tree.nodeTag(lhs_node)) {
                    .global_var_decl,
                    .local_var_decl,
                    .aligned_var_decl,
                    .simple_var_decl,
                    => {
                        const field_type = if (resolved_type) |ty| try builder.analyser.resolveBracketAccessType(ty, .{ .single = index }) else null;
                        try writeVarDecl(builder, lhs_node, field_type);
                    },
                    .identifier => {
                        const name_token = tree.nodeMainToken(lhs_node);
                        try writeIdentifier(builder, name_token);
                    },
                    else => {},
                }
            }

            try writeToken(builder, main_token, .operator);
            try writeNodeTokens(builder, data.ast.value_expr);
        },
        .array_access,
        .error_union,
        .switch_range,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try writeNodeTokens(builder, lhs);
            try writeNodeTokens(builder, rhs);
        },
        .for_range => {
            const start, const opt_end = tree.nodeData(node).node_and_opt_node;
            try writeNodeTokens(builder, start);
            if (opt_end.unwrap()) |end| try writeNodeTokens(builder, end);
        },
        .identifier => {
            std.debug.assert(main_token == ast.identifierTokenFromIdentifierNode(tree, node) orelse return);
            try writeIdentifier(builder, main_token);
        },
        .field_access => {
            try writeFieldAccess(builder, node);
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.fullPtrType(tree, node).?;

            if (ptr_type.ast.sentinel.unwrap()) |sentinel| {
                try writeNodeTokens(builder, sentinel);
            }

            try writeToken(builder, ptr_type.allowzero_token, .keyword);

            if (ptr_type.ast.align_node.unwrap()) |align_node| {
                const first_tok = tree.firstToken(align_node);
                try writeToken(builder, first_tok - 2, .keyword);
                try writeNodeTokens(builder, align_node);

                if (ptr_type.ast.bit_range_start.unwrap()) |bit_range_start| {
                    const bit_range_end = ptr_type.ast.bit_range_end.unwrap().?;
                    try writeNodeTokens(builder, bit_range_start);
                    try writeNodeTokens(builder, bit_range_end);
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
            if (array_type.ast.sentinel.unwrap()) |sentinel| try writeNodeTokens(builder, sentinel);
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
            try writeNodeTokens(builder, tree.nodeData(node).node);
        },
        .@"try",
        .@"resume",
        .@"await",
        => {
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, tree.nodeData(node).node);
        },
        .anyframe_literal => try writeToken(builder, main_token, .type),
    }
}

fn writeContainerField(builder: *Builder, node: Ast.Node.Index, container_decl: Ast.Node.Index) !void {
    const tree = builder.handle.tree;

    var container_field = tree.fullContainerField(node).?;
    const field_token_type = fieldTokenType(container_decl, builder.handle, false) orelse .property;

    if (container_decl != .root and tree.tokenTag(tree.nodeMainToken(container_decl)) != .keyword_struct) {
        container_field.convertToNonTupleLike(&tree);
    }

    try writeToken(builder, container_field.comptime_token, .keyword);
    if (!container_field.ast.tuple_like) {
        try writeTokenMod(builder, container_field.ast.main_token, field_token_type, .{ .declaration = true });
    }

    if (container_field.ast.type_expr.unwrap()) |type_expr| {
        try writeNodeTokens(builder, type_expr);
        if (container_field.ast.align_expr.unwrap()) |align_expr| {
            try writeToken(builder, tree.firstToken(align_expr) - 2, .keyword);
            try writeNodeTokens(builder, align_expr);
        }
    }

    if (container_field.ast.value_expr.unwrap()) |value_expr| {
        const equal_token = tree.firstToken(value_expr) - 1;
        if (tree.tokenTag(equal_token) == .equal) {
            try writeToken(builder, equal_token, .operator);
        }
        try writeNodeTokens(builder, value_expr);
    }
}

fn writeVarDecl(builder: *Builder, var_decl_node: Ast.Node.Index, resolved_type: ?Analyser.Type) error{OutOfMemory}!void {
    const tree = builder.handle.tree;

    const var_decl = tree.fullVarDecl(var_decl_node).?;
    try writeToken(builder, var_decl.visib_token, .keyword);
    try writeToken(builder, var_decl.extern_export_token, .keyword);
    try writeToken(builder, var_decl.threadlocal_token, .keyword);
    try writeToken(builder, var_decl.comptime_token, .keyword);
    try writeToken(builder, var_decl.ast.mut_token, .keyword);

    const decl: Analyser.DeclWithHandle = .{
        .decl = .{ .ast_node = var_decl_node },
        .handle = builder.handle,
    };

    const mutable = tree.tokenTag(var_decl.ast.mut_token) == .keyword_var;
    if (resolved_type) |decl_type| {
        try colorIdentifierBasedOnType(
            builder,
            decl_type,
            var_decl.ast.mut_token + 1,
            false,
            .{
                .declaration = true,
                .static = !(decl_type.is_type_val or decl_type.isFunc()) and try decl.isStatic(),
                .mutable = mutable,
            },
        );
    } else {
        try writeTokenMod(
            builder,
            var_decl.ast.mut_token + 1,
            .variable,
            .{
                .declaration = true,
                .static = try decl.isStatic(),
                .mutable = mutable,
            },
        );
    }

    if (var_decl.ast.type_node.unwrap()) |type_node| try writeNodeTokens(builder, type_node);
    if (var_decl.ast.align_node.unwrap()) |align_node| try writeNodeTokens(builder, align_node);
    if (var_decl.ast.section_node.unwrap()) |section_node| try writeNodeTokens(builder, section_node);

    if (var_decl.ast.init_node.unwrap()) |init_node| {
        const equal_token = tree.firstToken(init_node) - 1;
        if (tree.tokenTag(equal_token) == .equal) {
            try writeToken(builder, equal_token, .operator);
        }
        try writeNodeTokens(builder, init_node);
    }
}

fn writeIdentifier(builder: *Builder, name_token: Ast.TokenIndex) error{OutOfMemory}!void {
    const handle = builder.handle;
    const tree = handle.tree;

    const name = offsets.identifierTokenToNameSlice(tree, name_token);
    const is_escaped_identifier = tree.source[tree.tokenStart(name_token)] == '@';

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
        tree.tokenStart(name_token),
    )) |child| {
        const is_param = child.decl == .function_parameter;
        const mutable = !child.isConst();
        if (try child.resolveType(builder.analyser)) |decl_type| {
            return try colorIdentifierBasedOnType(
                builder,
                decl_type,
                name_token,
                is_param,
                .{
                    .static = !(decl_type.is_type_val or decl_type.isFunc()) and try child.isStatic(),
                    .mutable = mutable,
                },
            );
        } else {
            try writeTokenMod(
                builder,
                name_token,
                if (is_param) .parameter else .variable,
                .{
                    .static = try child.isStatic(),
                    .mutable = mutable,
                },
            );
        }
    } else {
        try writeToken(builder, name_token, .variable);
    }
}

fn writeFieldAccess(builder: *Builder, node: Ast.Node.Index) error{OutOfMemory}!void {
    const handle = builder.handle;
    const tree = builder.handle.tree;
    const lhs_node, const field_name_token = tree.nodeData(node).node_and_token;

    const symbol_name = offsets.identifierTokenToNameSlice(tree, field_name_token);

    try writeNodeTokens(builder, lhs_node);

    const lhs = try builder.analyser.resolveTypeOfNode(.of(lhs_node, handle)) orelse {
        try writeToken(builder, field_name_token, .variable);
        return;
    };

    const lhs_type = try builder.analyser.resolveDerefType(lhs) orelse lhs;
    if (lhs_type.isErrorSetType(builder.analyser)) {
        try writeToken(builder, field_name_token, .errorTag);
        return;
    }

    if (try lhs_type.lookupSymbol(builder.analyser, symbol_name)) |decl_type| decl_blk: {
        field_blk: {
            if (decl_type.decl != .ast_node) break :field_blk;
            const decl_node = decl_type.decl.ast_node;
            if (!decl_type.handle.tree.nodeTag(decl_node).isContainerField()) break :field_blk;
            if (lhs_type.data != .container) break :field_blk;
            const scope_handle = lhs_type.data.container.scope_handle;
            const tt = fieldTokenType(
                scope_handle.toNode(),
                scope_handle.handle,
                lhs_type.is_type_val,
            ).?;
            switch (tt) {
                //These are the only token types returned by fieldTokenType
                .property, .enumMember, .errorTag => {},
                else => unreachable,
            }

            try writeTokenMod(builder, field_name_token, tt, .{});
            return;
        }

        const resolved_type = try decl_type.resolveType(builder.analyser) orelse break :decl_blk;
        try colorIdentifierBasedOnType(
            builder,
            resolved_type,
            field_name_token,
            false,
            .{
                .mutable = !decl_type.isConst(),
                .static = !(resolved_type.is_type_val or resolved_type.isFunc()) and try decl_type.isStatic(),
            },
        );
        return;
    }

    try writeTokenMod(
        builder,
        field_name_token,
        .variable,
        .{},
    );
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
    overlappingTokenSupport: bool,
) error{OutOfMemory}!types.SemanticTokens {
    var builder = Builder{
        .arena = arena,
        .analyser = analyser,
        .handle = handle,
        .encoding = encoding,
        .limited = limited,
        .overlappingTokenSupport = overlappingTokenSupport,
    };

    var nodes = if (loc) |l| try ast.nodesAtLoc(arena, handle.tree, l) else handle.tree.rootDecls();
    if (nodes.len == 1 and nodes[0] == .root) {
        nodes = handle.tree.rootDecls();
    }

    // reverse the ast from the root declarations
    for (nodes) |child| {
        try writeNodeTokens(&builder, child);
    }

    return try builder.finish();
}
