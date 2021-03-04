const std = @import("std");
const offsets = @import("offsets.zig");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const ast = std.zig.ast;

pub const TokenType = enum(u32) {
    type,
    parameter,
    variable,
    enumMember,
    field,
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
};

pub const TokenModifiers = packed struct {
    namespace: bool = false,
    @"struct": bool = false,
    @"enum": bool = false,
    @"union": bool = false,
    @"opaque": bool = false,
    declaration: bool = false,
    @"async": bool = false,
    documentation: bool = false,
    generic: bool = false,

    fn toInt(self: TokenModifiers) u32 {
        var res: u32 = 0;
        inline for (std.meta.fields(TokenModifiers)) |field, i| {
            if (@field(self, field.name)) {
                res |= 1 << i;
            }
        }
        return res;
    }

    fn set(self: *TokenModifiers, comptime field: []const u8) callconv(.Inline) void {
        @field(self, field) = true;
    }
};

const Builder = struct {
    handle: *DocumentStore.Handle,
    current_token: ?ast.TokenIndex,
    arr: std.ArrayList(u32),
    encoding: offsets.Encoding,

    fn init(allocator: *std.mem.Allocator, handle: *DocumentStore.Handle, encoding: offsets.Encoding) Builder {
        return Builder{
            .handle = handle,
            .current_token = null,
            .arr = std.ArrayList(u32).init(allocator),
            .encoding = encoding,
        };
    }

    fn add(self: *Builder, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const start_idx = if (self.current_token) |current_token|
            self.handle.tree.tokenLocation[current_token].line_start
        else
            0;

        if (start_idx > self.handle.tree.tokenLocation[token].line_start)
            return;

        const delta_loc = offsets.tokenRelativeLocation(self.handle.tree, start_idx, token, self.encoding) catch return;
        try self.arr.appendSlice(&[_]u32{
            @truncate(u32, delta_loc.line),
            @truncate(u32, delta_loc.column),
            @truncate(u32, offsets.tokenLength(self.handle.tree, token, self.encoding)),
            @enumToInt(token_type),
            token_modifiers.toInt(),
        });
        self.current_token = token;
    }

    fn toOwnedSlice(self: *Builder) []u32 {
        return self.arr.toOwnedSlice();
    }
};

fn writeToken(
    builder: *Builder,
    token_idx: ?ast.TokenIndex,
    tok_type: TokenType,
) callconv(.Inline) !void {
    return try writeTokenMod(builder, token_idx, tok_type, .{});
}

fn writeTokenMod(
    builder: *Builder,
    token_idx: ?ast.TokenIndex,
    tok_type: TokenType,
    tok_mod: TokenModifiers,
) callconv(.Inline) !void {
    if (token_idx) |ti| {
        try builder.add(ti, tok_type, tok_mod);
    }
}

fn writeDocComments(builder: *Builder, tree: *ast.Tree, doc: *ast.TokenIndex) !void {
    const token_tags = tree.tokens.items(.tag);
    var tok_idx = doc;
    while (token_tags[tok_idx] == .doc_comment or
        token_tags[tok_idx] == .container_doc_comment) : (tok_idx += 1)
    {
        var tok_mod = TokenModifiers{};
        tok_mod.set("documentation");

        try builder.add(tok_idx, .comment, tok_mod);
    }
}

fn fieldTokenType(container_decl: *ast.full.ContainerDecl, handle: *DocumentStore.Handle) ?TokenType {
    if (container_decl.ast.main_token > handle.tree.tokens.len) return null;
    return @as(?TokenType, switch (handle.tree.tokens.items(.tag)[container_decl.ast.main_token]) {
        .keyword_Struct => .field,
        .keyword_union, .keyword_enum => .enumMember,
        else => null,
    });
}

/// This is used to highlight gaps between AST nodes.
/// These gaps can be just gaps between statements/declarations with comments inside them
/// Or malformed code.
const GapHighlighter = struct {
    builder: *Builder,
    current_idx: ast.TokenIndex,

    // TODO More highlighting here
    fn handleTok(self: *GapHighlighter, tok: ast.TokenIndex) !void {
        const tok_id = self.builder.handle.tree.tokens.items(.tag)[tok];
        if (tok_id == .container_doc_comment or tok_id == .doc_comment) {
            try writeTokenMod(self.builder, tok, .comment, .{ .documentation = true });
        } else if (@enumToInt(tok_id) >= @enumToInt(std.zig.Token.Tag.keyword_align) and
            @enumToInt(tok_id) <= @enumToInt(std.zig.Token.Tag.keyword_while))
        {
            const tok_type: TokenType = switch (tok_id) {
                .keyword_true,
                .keyword_false,
                .keyword_null,
                .keyword_undefined,
                .keyword_unreachable,
                => .keywordLiteral,
                else => .keyword,
            };

            try writeToken(self.builder, tok, tok_type);
        } else if (@enumToInt(tok_id) >= @enumToInt(std.zig.Token.Tag.bang) and
            @enumToInt(tok_id) <= @enumToInt(std.zig.Token.Tag.tilde) and
            tok_id != .period and tok_id != .comma and tok_id != .r_paren and
            tok_id != .l_paren and tok_id != .r_bracce and tok_id != .l_brace and
            tok_id != .semicolon and tok_id != .colon)
        {
            try writeToken(self.builder, tok, .operator);
        } else if (tok_id == .integer_literal or tok_id == .float_literal) {
            try writeToken(self.builder, tok, .number);
        } else if (tok_id == .string_literal or tok_id == .multiline_string_literal_line or tok_id == .char_literal) {
            try writeToken(self.builder, tok, .string);
        }
    }

    fn init(builder: *Builder, start: ast.TokenIndex) GapHighlighter {
        return .{ .builder = builder, .current_idx = start };
    }

    fn next(self: *GapHighlighter, node: *ast.Node) !void {
        if (self.current_idx > 0 and self.builder.handle.tree.token_ids[self.current_idx - 1] == .container_doc_comment) {
            try self.handleTok(self.current_idx - 1);
        }

        var i = self.current_idx;
        while (i < node.firstToken()) : (i += 1) {
            try self.handleTok(i);
        }
        self.current_idx = node.lastToken() + 1;
    }

    fn end(self: *GapHighlighter, last: ast.TokenIndex) !void {
        var i = self.current_idx;
        while (i < last) : (i += 1) {
            try self.handleTok(i);
        }
    }
};

fn colorIdentifierBasedOnType(builder: *Builder, type_node: analysis.TypeWithHandle, target_tok: ast.TokenIndex, tok_mod: TokenModifiers) !void {
    if (type_node.type.is_type_val) {
        var new_tok_mod = tok_mod;
        if (type_node.isNamespace())
            new_tok_mod.set("namespace")
        else if (type_node.isStructType())
            new_tok_mod.set("struct")
        else if (type_node.isEnumType())
            new_tok_mod.set("enum")
        else if (type_node.isUnionType())
            new_tok_mod.set("union")
        else if (type_node.isOpaqueType())
            new_tok_mod.set("opaque");

        try writeTokenMod(builder, target_tok, .type, new_tok_mod);
    } else if (type_node.isTypeFunc()) {
        try writeTokenMod(builder, target_tok, .type, tok_mod);
    } else if (type_node.isFunc()) {
        var new_tok_mod = tok_mod;
        if (type_node.isGenericFunc()) {
            new_tok_mod.set("generic");
        }
        try writeTokenMod(builder, target_tok, .function, new_tok_mod);
    } else {
        try writeTokenMod(builder, target_tok, .variable, tok_mod);
    }
}

fn writeContainerField(
    builder: *Builder,
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    container_field: *ast.Node.ContainerField,
    field_token_type: ?TokenType,
    child_frame: anytype,
) !void {
    if (container_field.doc_comments) |docs| try writeDocComments(builder, builder.handle.tree, docs);
    try writeToken(builder, container_field.comptime_token, .keyword);
    if (field_token_type) |tok_type| try writeToken(builder, container_field.name_token, tok_type);
    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.type_expr });
    if (container_field.align_expr) |n| {
        try writeToken(builder, n.firstToken() - 2, .keyword);
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, n });
    }

    if (container_field.value_expr) |value_expr| block: {
        const eq_tok: ast.TokenIndex = if (container_field.type_expr) |type_expr|
            type_expr.lastToken() + 1
        else if (container_field.align_expr) |align_expr|
            align_expr.lastToken() + 1
        else
            break :block; // Check this, I believe it is correct.

        try writeToken(builder, eq_tok, .operator);
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, value_expr });
    }
}

// TODO This is very slow and does a lot of extra work, improve in the future.
fn writeNodeTokens(
    builder: *Builder,
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    maybe_node: ?ast.Node.Index,
    tree: ast.Tree,
) error{OutOfMemory}!void {
    if (maybe_node == null) return;

    const node = maybe_node.?;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const tag = node_tags[node];
    const main_token = main_tokens[node];
    const handle = builder.handle;

    const FrameSize = @sizeOf(@Frame(writeNodeTokens));
    var child_frame = try arena.child_allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
    defer arena.child_allocator.free(child_frame);

    switch (tag) {
        .root => {
            var gap_highlighter = GapHighlighter.init(builder, 0);
            var buf: [2]ast.Node.Index = undefined;
            for (analysis.declMembers(tree, .root, 0, &buf)) |child| {
                try gap_highlighter.next(child);
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, arena, store, analysis.containerField(tree, child), .field, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
            try gap_highlighter.end(handle.tree.tokens.len - 1);
        },
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            const first_tok = if (token_tags[main_token - 1] == .colon and token_tags[main_token - 2] == identifier) block: {
                try writeToken(builder, main_token - 2, .label);
                break :block main_token + 1;
            } else 0;

            var gap_highlighter = GapHighlighter.init(builder, first_tok);
            const statements: []const ast.Node.Index = switch (tag) {
                .block, .block_semicolon => tree.extra_data[datas[node].lhs..datas[node].rhs],
                .block_two, .block_two_semicolon => blk: {
                    const statements = &[_]ast.Node.Index{ datas[node].lhs, datas[node].rhs };
                    const len: usize = if (datas[node].lhs == 0)
                        @as(usize, 0)
                    else if (datas[node].rhs == 0)
                        @as(usize, 1)
                    else
                        @as(usize, 2);
                    break :blk statements[0..len];
                },
                else => unreachable,
            };

            for (statements) |child| {
                try gap_highlighter.next(child);
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, arena, store, analysis.containerField(tree, child), .field, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }

            try gap_highlighter.end(tree.lastToken(node));
        },
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const var_decl = analysis.varDecl(tree, node).?;
            if (analysis.getDocCommentTokenIndex(tree, node)) |comment_idx|
                try writeDocComments(builder, handle.tree, comment_idx);

            try writeToken(builder, var_decl.visib_token, .keyword);
            try writeToken(builder, var_decl.extern_export_token, .keyword);
            try writeToken(builder, var_decl.threadlocal_token, .keyword);
            try writeToken(builder, var_decl.comptime_token, .keyword);
            try writeToken(builder, var_decl.ast.mut_token, .keyword);
            if (try analysis.resolveTypeOfNode(store, arena, .{ .node = node, .handle = handle })) |decl_type| {
                try colorIdentifierBasedOnType(builder, decl_type, var_decl.ast.mut_token + 1, .{ .declaration = true });
            } else {
                try writeTokenMod(builder, var_decl.ast.mut_token + 1, .variable, .{ .declaration = true });
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.type_node });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.align_node });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.section_node });
            try writeToken(builder, var_decl.ast.mut_token + 2, .operator);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.init_node });
        },
        .@"usingnamespace" => {
            const first_tok = tree.firstToken(node);
            if (first_tok > 0 and token_tags[first_tok - 1] == .doc_comment)
                try writeDocComments(builder, builder.handle.tree, first_tok - 1);
            try writeToken(builder, if (token_tags[first_tok] == .keyword_pub) first_tok else null, .keyword);
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .error_set_decl => {
            // @TODO: Semantic highlighting for error set decl
        },
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        => {
            var buf: [2]ast.Node.Index = undefined;
            const decl: ast.full.ContainerDecl = switch (tag) {
                .container_decl, .container_decl_trailing => tree.containerDecl(node),
                .container_decl_two, .container_decl_two_trailing => tree.containerDeclTwo(&buf, node),
                .container_decl_arg, .container_decl_arg_trailing => tree.containerDeclArg(node),
                else => unreachable,
            };

            try writeToken(builder, decl.layout_token, .keyword);
            try writeToken(builder, decl.ast.main_token, .keyword);
            if (decl.enum_token) |enum_token| {
                if (decl.ast.arg != 0)
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl.ast.arg })
                else
                    try writeToken(builder, enum_token, .keyword);
            } else if (decl.ast.arg != 0) try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl.ast.arg });

            var gap_highlighter = GapHighlighter.init(builder, main_token + 1);
            const field_token_type = fieldTokenType(decl, handle);
            for (decl.ast.members) |child| {
                try gap_highlighter.next(child);
                if (node_tags[node].isContainerField()) {
                    try writeContainerField(builder, arena, store, analysis.containerField(tree, node), field_token_type, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
            try gap_highlighter.end(tree.lastToken(node));
        },
        .error_value => {
            // if (error_tag.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, datas[node].rhs, .errorTag);
        },
        .identifier => {
            if (analysis.isTypeIdent(handle.tree, main_token)) {
                return try writeToken(builder, main_token, .type);
            }

            if (try analysis.lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.items(.start)[main_token])) |child| {
                if (child.decl.* == .param_decl) {
                    return try writeToken(builder, main_token, .parameter);
                }
                var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
                if (try child.resolveType(store, arena, &bound_type_params)) |decl_type| {
                    try colorIdentifierBasedOnType(builder, decl_type, main_token, .{});
                } else {
                    try writeTokenMod(builder, main_token, .variable, .{});
                }
            }
        },
        .fn_proto, .fn_proto_one, .fn_proto_simple, .fn_proto_multiple, .fn_decl => {
            var buf: [1]ast.Node.Index = undefined;
            const fn_proto: ast.full.FnProto = analysis.fnProto(tree, node, &buf).?;
            if (analysis.getDocCommentTokenIndex(tree, node)) |cocs|
                try writeDocComments(builder, handle.tree, docs);

            try writeToken(builder, fn_proto.visib_token, .keyword);
            try writeToken(builder, fn_proto.extern_export_token, .keyword);
            try writeToken(builder, fn_proto.lib_name, .string);
            try writeToken(builder, fn_proto.ast.fn_token, .keyword);

            const func_name_tok_type: TokenType = if (analysis.isTypeFunction(handle.tree, fn_proto))
                .type
            else
                .function;

            const tok_mod = if (analysis.isGenericFunction(handle.tree, fn_proto))
                TokenModifiers{ .generic = true }
            else
                TokenModifiers{};

            try writeTokenMod(builder, fn_proto.name_token, func_name_tok_type, tok_mod);

            var it = fn_proto.iterate(tree);
            while (it.next()) |param_decl| {
                if (param_decl.first_doc_comment) |docs| try writeDocComments(builder, handle.tree, docs);

                try writeToken(builder, param_decl.comptime_noalias, .keyword);
                try writeTokenMod(builder, param_decl.name_token, .parameter, .{ .declaration = true });
                if (param_decl.anytype_ellipsis3) |any_token| {
                    try writeToken(builder, var_node.firstToken(), .type);
                } else if (param_decl.type_expr != 0) try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param_decl.type_expr });
            }

            if (fn_proto.ast.align_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.align_expr != 0 });
            if (fn_proto.ast.section_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.section_expr != 0 });
            if (fn_proto.ast.callconv_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.callconv_expr != 0 });

            if (fn_proto.ast.return_type != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.return_type });

            if (tag == .fn_decl)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .anyframe_type => {
            try writeToken(builder, main_token, .type);
            if (datas[node].rhs != 0) {
                try writeToken(builder, datas[node].lhs, .type);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
            }
        },
        .@"defer" => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .@"comptime", @"nosuspend" => {
            if (analysis.getDocCommentTokenIndex(tree, node)) |doc|
                try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .@"switch", .switch_comma => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            const extra = tree.extraData(datas[node].rhs, ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            var gap_highlighter = GapHighlighter.init(builder, switch_node.expr.lastToken() + 3);
            for (cases) |case_node| {
                try gap_highlighter.next(case_node);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, case_node });
            }
            try gap_highlighter.end(node.lastToken());
        },
        .switch_case_one, .switch_case => {
            const switch_case = if (tag == .switch_case) tree.switchCase(node) else tree.switchCaseOne(node);
            for (switch_case.ast.values) |item_node| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, item_node });
            // check it it's 'else'
            if (switch_case.ast.values.len == 0) try writeToken(builder, switch_case.ast.arrow_token - 1, .keyword);
            try writeToken(builder, switch_case.ast.arrow_token, .operator);
            if (switch_case.payload_token) |payload_token| {
                const p_token = @boolToInt(token_tags[payload_token] == .asterisk);
                try writeToken(builder, p_token, .variable);
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, switch_case.ast.target_expr });
        },
        .@"while", .while_simple, .while_cont, .for_simple, .@"for" => {
            const while_node: ast.full.While = switch (node) {
                .@"while" => tree.whileFull(node_idx),
                .while_simple => tree.whileSimple(node_idx),
                .while_cont => tree.whileCont(node_idx),
                .@"for" => tree.forFull(node_idx),
                .for_simple => tree.forSimple(node_idx),
                else => unreachable,
            };

            try writeToken(builder, while_node.label_token, .label);
            try writeToken(builder, while_node.inline_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.condition });
            try writeToken(builder, while_node.payload_token, .variable);
            if (while_node.ast.cont_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.ast.cont_expr});
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.body });
            if (while_node.@"else") |else_node|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, &else_node.base });
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            try writeToken(builder, for_node.label, .label);
            try writeToken(builder, for_node.inline_token, .keyword);
            try writeToken(builder, for_node.for_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, for_node.array_expr });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, for_node.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, for_node.body });
            if (for_node.@"else") |else_node|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, &else_node.base });
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            try writeToken(builder, if_node.if_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.condition });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.body });
            if (if_node.@"else") |else_node|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, &else_node.base });
        },
        .ArrayInitializer => {
            const array_initializer = node.cast(ast.Node.ArrayInitializer).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_initializer.lhs });
            for (array_initializer.listConst()) |elem| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, elem });
        },
        .ArrayInitializerDot => {
            const array_initializer = node.cast(ast.Node.ArrayInitializerDot).?;
            for (array_initializer.listConst()) |elem| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, elem });
        },
        .StructInitializer => {
            const struct_initializer = node.cast(ast.Node.StructInitializer).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, struct_initializer.lhs });
            const field_token_type = if (try analysis.resolveTypeOfNode(store, arena, .{ .node = struct_initializer.lhs, .handle = handle })) |struct_type| switch (struct_type.type.data) {
                .other => |type_node| if (type_node.cast(ast.Node.ContainerDecl)) |container_decl|
                    fieldTokenType(container_decl, handle)
                else
                    null,
                else => null,
            } else null;

            var gap_highlighter = GapHighlighter.init(builder, struct_initializer.lhs.lastToken() + 1);
            for (struct_initializer.listConst()) |field_init_node| {
                try gap_highlighter.next(field_init_node);
                std.debug.assert(field_init_node.tag == .FieldInitializer);
                const field_init = field_init_node.cast(ast.Node.FieldInitializer).?;
                if (field_token_type) |tok_type| {
                    try writeToken(builder, field_init.period_token, tok_type);
                    try writeToken(builder, field_init.name_token, tok_type);
                }
                try writeToken(builder, field_init.name_token + 1, .operator);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, field_init.expr });
            }
            try gap_highlighter.end(struct_initializer.rtoken);
        },
        .StructInitializerDot => {
            const struct_initializer = node.castTag(.StructInitializerDot).?;

            var gap_highlighter = GapHighlighter.init(builder, struct_initializer.dot + 1);
            for (struct_initializer.listConst()) |field_init_node| {
                try gap_highlighter.next(field_init_node);
                std.debug.assert(field_init_node.tag == .FieldInitializer);
                const field_init = field_init_node.castTag(.FieldInitializer).?;
                try writeToken(builder, field_init.period_token, .field);
                try writeToken(builder, field_init.name_token, .field);
                try writeToken(builder, field_init.name_token + 1, .operator);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, field_init.expr });
            }
            try gap_highlighter.end(struct_initializer.rtoken);
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            try writeToken(builder, call.async_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, call.lhs });
            if (builder.current_token) |curr_tok| {
                if (curr_tok != call.lhs.lastToken() and handle.tree.token_ids[call.lhs.lastToken()] == .Identifier) {
                    try writeToken(builder, call.lhs.lastToken(), .function);
                }
            }
            for (call.paramsConst()) |param| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param });
        },
        .Slice => {
            const slice = node.castTag(.Slice).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.lhs });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.start });
            try writeToken(builder, slice.start.lastToken() + 1, .operator);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.end });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.sentinel });
        },
        .ArrayAccess => {
            const arr_acc = node.castTag(.ArrayAccess).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, arr_acc.lhs });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, arr_acc.index_expr });
        },
        .Deref, .UnwrapOptional => {
            const suffix = node.cast(ast.Node.SimpleSuffixOp).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, suffix.lhs });
            try writeToken(builder, suffix.rtoken, .operator);
        },
        .GroupedExpression => {
            const grouped_expr = node.cast(ast.Node.GroupedExpression).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, grouped_expr.expr });
        },
        .Return, .Break, .Continue => {
            const cfe = node.cast(ast.Node.ControlFlowExpression).?;
            try writeToken(builder, cfe.ltoken, .keyword);
            switch (node.tag) {
                .Break => if (cfe.getLabel()) |n| try writeToken(builder, n, .label),
                .Continue => if (cfe.getLabel()) |n| try writeToken(builder, n, .label),
                else => {},
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, cfe.getRHS() });
        },
        .Suspend => {
            const suspend_node = node.cast(ast.Node.Suspend).?;
            try writeToken(builder, suspend_node.suspend_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, suspend_node.body });
        },
        .IntegerLiteral => {
            try writeToken(builder, node.firstToken(), .number);
        },
        .EnumLiteral => {
            const enum_literal = node.cast(ast.Node.EnumLiteral).?;
            try writeToken(builder, enum_literal.dot, .enumMember);
            try writeToken(builder, enum_literal.name, .enumMember);
        },
        .FloatLiteral => {
            try writeToken(builder, node.firstToken(), .number);
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            try writeToken(builder, builtin_call.builtin_token, .builtin);
            for (builtin_call.paramsConst()) |param|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param });
        },
        .StringLiteral, .CharLiteral => {
            try writeToken(builder, node.firstToken(), .string);
        },
        .MultilineStringLiteral => {
            const multi_line = node.cast(ast.Node.MultilineStringLiteral).?;
            for (multi_line.linesConst()) |line| try writeToken(builder, line, .string);
        },
        .BoolLiteral, .NullLiteral, .UndefinedLiteral, .Unreachable => {
            try writeToken(builder, node.firstToken(), .keywordLiteral);
        },
        .ErrorType => {
            try writeToken(builder, node.firstToken(), .keyword);
        },
        .Asm => {
            const asm_expr = node.cast(ast.Node.Asm).?;
            try writeToken(builder, asm_expr.asm_token, .keyword);
            try writeToken(builder, asm_expr.volatile_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, asm_expr.template });
            // TODO Inputs, outputs.
        },
        .AnyType => {
            try writeToken(builder, node.firstToken(), .type);
        },
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            if (test_decl.doc_comments) |doc| try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, test_decl.test_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, test_decl.name });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, test_decl.body_node });
        },
        .Catch => {
            const catch_expr = node.cast(ast.Node.Catch).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, catch_expr.lhs });
            try writeToken(builder, catch_expr.op_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, catch_expr.rhs });
        },
        .Add, .AddWrap, .ArrayCat, .ArrayMult, .Assign, .AssignBitAnd, .AssignBitOr, .AssignBitShiftLeft, .AssignBitShiftRight, .AssignBitXor, .AssignDiv, .AssignSub, .AssignSubWrap, .AssignMod, .AssignAdd, .AssignAddWrap, .AssignMul, .AssignMulWrap, .BangEqual, .BitAnd, .BitOr, .BitShiftLeft, .BitShiftRight, .BitXor, .BoolAnd, .BoolOr, .Div, .EqualEqual, .ErrorUnion, .GreaterOrEqual, .GreaterThan, .LessOrEqual, .LessThan, .MergeErrorSets, .Mod, .Mul, .MulWrap, .Period, .Range, .Sub, .SubWrap, .OrElse => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.lhs });
            if (node.tag != .Period) {
                const token_type: TokenType = switch (node.tag) {
                    .BoolAnd, .BoolOr, .OrElse => .keyword,
                    else => .operator,
                };

                try writeToken(builder, infix_op.op_token, token_type);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.rhs });
            }
            switch (node.tag) {
                .Period => {
                    const rhs_str = handle.tree.tokenSlice(infix_op.rhs.firstToken());

                    // TODO This is basically exactly the same as what is done in analysis.resolveTypeOfNode, with the added
                    //      writeToken code.
                    // Maybe we can hook into it insead? Also applies to Identifier and VarDecl
                    var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
                    const lhs_type = try analysis.resolveFieldAccessLhsType(
                        store,
                        arena,
                        (try analysis.resolveTypeOfNodeInternal(store, arena, .{
                            .node = infix_op.lhs,
                            .handle = handle,
                        }, &bound_type_params)) orelse return,
                        &bound_type_params,
                    );
                    const left_type_node = switch (lhs_type.type.data) {
                        .other => |n| n,
                        else => return,
                    };
                    if (try analysis.lookupSymbolContainer(store, arena, .{ .node = left_type_node, .handle = lhs_type.handle }, rhs_str, !lhs_type.type.is_type_val)) |decl_type| {
                        switch (decl_type.decl.*) {
                            .ast_node => |decl_node| {
                                if (decl_node.tag == .ContainerField) {
                                    const tok_type: ?TokenType = if (left_type_node.cast(ast.Node.ContainerDecl)) |container_decl|
                                        fieldTokenType(container_decl, lhs_type.handle)
                                    else if (left_type_node.tag == .Root)
                                        TokenType.field
                                    else
                                        null;

                                    if (tok_type) |tt| try writeToken(builder, infix_op.rhs.firstToken(), tt);
                                    return;
                                } else if (decl_node.tag == .ErrorTag) {
                                    try writeToken(builder, infix_op.rhs.firstToken(), .errorTag);
                                }
                            },
                            else => {},
                        }

                        if (try decl_type.resolveType(store, arena, &bound_type_params)) |resolved_type| {
                            try colorIdentifierBasedOnType(builder, resolved_type, infix_op.rhs.firstToken(), .{});
                        }
                    }
                },
                else => {},
            }
        },
        .SliceType => {
            const slice_type = node.castTag(.SliceType).?;
            const ptr_info = slice_type.ptr_info;
            if (ptr_info.align_info) |align_info| {
                try writeToken(builder, slice_type.op_token + 2, .keyword);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, align_info.node });
            }
            try writeToken(builder, ptr_info.const_token, .keyword);
            try writeToken(builder, ptr_info.volatile_token, .keyword);
            try writeToken(builder, ptr_info.allowzero_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice_type.rhs });
        },
        .PtrType => {
            const pointer_type = node.castTag(.PtrType).?;
            const tok_ids = builder.handle.tree.token_ids;

            const ptr_info = switch (tok_ids[pointer_type.op_token]) {
                .AsteriskAsterisk => pointer_type.rhs.castTag(.PtrType).?.ptr_info,
                else => pointer_type.ptr_info,
            };
            const rhs = switch (tok_ids[pointer_type.op_token]) {
                .AsteriskAsterisk => pointer_type.rhs.castTag(.PtrType).?.rhs,
                else => pointer_type.rhs,
            };

            const off = switch (tok_ids[pointer_type.op_token]) {
                .Asterisk, .AsteriskAsterisk => blk: {
                    try writeToken(builder, pointer_type.op_token, .operator);
                    break :blk pointer_type.op_token + 1;
                },
                .LBracket => blk: {
                    try writeToken(builder, pointer_type.op_token + 1, .operator);
                    const is_c_ptr = tok_ids[pointer_type.op_token + 2] == .Identifier;

                    if (is_c_ptr) {
                        try writeToken(builder, pointer_type.op_token + 2, .operator);
                    }

                    if (ptr_info.sentinel) |sentinel| {
                        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, sentinel });
                        break :blk sentinel.lastToken() + 2;
                    }

                    break :blk pointer_type.op_token + 3 + @boolToInt(is_c_ptr);
                },
                else => 0,
            };

            if (ptr_info.align_info) |align_info| {
                try writeToken(builder, off, .keyword);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, align_info.node });
            }
            try writeToken(builder, ptr_info.const_token, .keyword);
            try writeToken(builder, ptr_info.volatile_token, .keyword);
            try writeToken(builder, ptr_info.allowzero_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, rhs });
        },
        .ArrayType => {
            const array_type = node.castTag(.ArrayType).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.len_expr });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.rhs });
        },
        .ArrayTypeSentinel => {
            const array_type = node.castTag(.ArrayTypeSentinel).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.len_expr });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.sentinel });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.rhs });
        },
        .AddressOf, .Await, .BitNot, .BoolNot, .OptionalType, .Negation, .NegationWrap, .Resume, .Try => {
            const prefix_op = node.cast(ast.Node.SimplePrefixOp).?;
            const tok_type: TokenType = switch (node.tag) {
                .Try, .Await, .Resume => .keyword,
                else => .operator,
            };
            try writeToken(builder, prefix_op.op_token, tok_type);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, prefix_op.rhs });
        },
        else => {},
    }
}

// TODO Range version, edit version.
pub fn writeAllSemanticTokens(arena: *std.heap.ArenaAllocator, store: *DocumentStore, handle: *DocumentStore.Handle, encoding: offsets.Encoding) ![]u32 {
    var builder = Builder.init(arena.child_allocator, handle, encoding);
    // pass root node, which always has index '0'
    try writeNodeTokens(&builder, arena, store, 0, handle.tree);
    return builder.toOwnedSlice();
}
