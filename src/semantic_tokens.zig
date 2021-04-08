const std = @import("std");
const offsets = @import("offsets.zig");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const ast = std.zig.ast;
usingnamespace @import("ast.zig");

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

const Comment = struct {
    /// Length of the comment
    length: u32,
    /// Source index of the comment
    start: u32,
};

const CommentList = std.ArrayList(Comment);

const Builder = struct {
    handle: *DocumentStore.Handle,
    current_token: ?ast.TokenIndex,
    arr: std.ArrayList(u32),
    encoding: offsets.Encoding,
    comments: CommentList,

    fn init(allocator: *std.mem.Allocator, handle: *DocumentStore.Handle, encoding: offsets.Encoding) Builder {
        return Builder{
            .handle = handle,
            .current_token = null,
            .arr = std.ArrayList(u32).init(allocator),
            .encoding = encoding,
            .comments = CommentList.init(allocator),
        };
    }

    fn highlightComment(
        self: *Builder,
        prev_end: usize,
        comment_start: usize,
        comment_end: usize,
        token_modifiers: TokenModifiers,
    ) !void {
        const comment_delta = offsets.tokenRelativeLocation(
            self.handle.tree,
            prev_end,
            comment_start,
            self.encoding,
        ) catch return;

        const comment_length = offsets.lineSectionLength(
            self.handle.tree,
            comment_start,
            comment_end,
            self.encoding,
        ) catch return;

        try self.arr.appendSlice(&.{
            @truncate(u32, comment_delta.line),
            @truncate(u32, comment_delta.column),
            @truncate(u32, comment_length),
            @enumToInt(TokenType.comment),
            token_modifiers.toInt(),
        });
    }

    fn add(self: *Builder, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const starts = self.handle.tree.tokens.items(.start);
        var start_idx = if (self.current_token) |current_token|
            starts[current_token]
        else
            0;

        if (start_idx > starts[token])
            return;

        var comments_end: usize = start_idx;
        var comments_start: usize = start_idx;
        // Highlight comments in the gap
        {
            const source = self.handle.tree.source;
            var state: enum { none, comment, doc_comment, comment_start } = .none;
            var prev_byte = source[start_idx];
            var i: usize = start_idx + 1;
            while (i < starts[token]) : ({
                prev_byte = source[i];
                i += 1;
            }) {
                if (prev_byte == '/' and source[i] == '/') {
                    switch (state) {
                        .none => {
                            comments_start = i - 1;
                            state = .comment_start;
                        },
                        .comment_start => state = .doc_comment,
                        else => {},
                    }
                    continue;
                } else if (prev_byte == '/' and source[i] == '!' and state == .comment_start) {
                    state = .doc_comment;
                    continue;
                }

                if (source[i] == '\n' and state != .none) {
                    try self.highlightComment(comments_end, comments_start, i, switch (state) {
                        .comment, .comment_start => .{},
                        .doc_comment => .{ .documentation = true },
                        else => unreachable,
                    });
                    comments_end = i;
                    state = .none;
                } else if (state == .comment_start) {
                    state = .comment;
                }
            }
            if (state != .none) {
                try self.highlightComment(comments_end, comments_start, i, switch (state) {
                    .comment, .comment_start => .{},
                    .doc_comment => .{ .documentation = true },
                    else => unreachable,
                });
            }
        }

        const delta = offsets.tokenRelativeLocation(
            self.handle.tree,
            comments_start,
            starts[token],
            self.encoding,
        ) catch return;

        try self.arr.appendSlice(&.{
            @truncate(u32, delta.line),
            @truncate(u32, delta.column),
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

fn writeDocComments(builder: *Builder, tree: ast.Tree, doc: ast.TokenIndex) !void {
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

fn fieldTokenType(container_decl: ast.Node.Index, handle: *DocumentStore.Handle) ?TokenType {
    const main_token = handle.tree.nodes.items(.main_token)[container_decl];
    if (main_token > handle.tree.tokens.len) return null;
    return @as(?TokenType, switch (handle.tree.tokens.items(.tag)[main_token]) {
        .keyword_struct => .field,
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
            tok_id != .l_paren and tok_id != .r_brace and tok_id != .l_brace and
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

    fn next(self: *GapHighlighter, node: ast.Node.Index) !void {
        const tree = self.builder.handle.tree;
        if (self.current_idx > 0 and tree.tokens.items(.tag)[self.current_idx - 1] == .container_doc_comment) {
            try self.handleTok(self.current_idx - 1);
        }

        var i = self.current_idx;
        while (i < tree.firstToken(node)) : (i += 1) {
            try self.handleTok(i);
        }
        self.current_idx = lastToken(tree, node) + 1;
    }

    fn end(self: *GapHighlighter, last: ast.TokenIndex) !void {
        var i = self.current_idx;
        while (i < last) : (i += 1) {
            try self.handleTok(i);
        }
    }
};

fn colorIdentifierBasedOnType(builder: *Builder, type_node: analysis.TypeWithHandle, target_tok: ast.TokenIndex, tok_mod: TokenModifiers) !void {
    const tree = builder.handle.tree;
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
    node: ast.Node.Index,
    field_token_type: ?TokenType,
    child_frame: anytype,
) !void {
    const tree = builder.handle.tree;
    const container_field = containerField(tree, node).?;
    const base = tree.nodes.items(.main_token)[node];
    const tokens = tree.tokens.items(.tag);

    if (analysis.getDocCommentTokenIndex(tokens, base)) |docs|
        try writeDocComments(builder, tree, docs);

    try writeToken(builder, container_field.comptime_token, .keyword);
    if (field_token_type) |tok_type| try writeToken(builder, container_field.ast.name_token, tok_type);

    if (container_field.ast.type_expr != 0) {
        if (container_field.ast.align_expr != 0) {
            try writeToken(builder, tree.firstToken(container_field.ast.align_expr) - 2, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.align_expr });
        }
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.type_expr });
    }

    if (container_field.ast.value_expr != 0) block: {
        const eq_tok: ast.TokenIndex = if (container_field.ast.type_expr != 0)
            lastToken(tree, container_field.ast.type_expr) + 1
        else if (container_field.ast.align_expr != 0)
            lastToken(tree, container_field.ast.align_expr) + 1
        else
            break :block; // Check this, I believe it is correct.

        try writeToken(builder, eq_tok, .operator);
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.value_expr });
    }
}

// TODO This is very slow and does a lot of extra work, improve in the future.
fn writeNodeTokens(
    builder: *Builder,
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    maybe_node: ?ast.Node.Index,
) error{OutOfMemory}!void {
    if (maybe_node == null) return;
    const node = maybe_node.?;
    if (node == 0) return;

    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    if (node > datas.len) return;

    const tag = node_tags[node];
    const main_token = main_tokens[node];

    const FrameSize = @sizeOf(@Frame(writeNodeTokens));
    var child_frame = try arena.child_allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
    defer arena.child_allocator.free(child_frame);

    switch (tag) {
        .root => unreachable,
        .container_field,
        .container_field_align,
        .container_field_init,
        => try writeContainerField(builder, arena, store, node, .field, child_frame),
        .@"errdefer" => {
            try writeToken(builder, main_token, .keyword);

            if (datas[node].lhs != 0) {
                const payload_tok = datas[node].lhs;
                try writeToken(builder, payload_tok - 1, .operator);
                try writeToken(builder, payload_tok, .variable);
                try writeToken(builder, payload_tok + 1, .operator);
            }

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            const first_tok = if (token_tags[main_token - 1] == .colon and token_tags[main_token - 2] == .identifier) block: {
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
                    try writeContainerField(builder, arena, store, child, .field, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }

            try gap_highlighter.end(lastToken(tree, node));
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = varDecl(tree, node).?;
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |comment_idx|
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

            if (var_decl.ast.type_node != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.type_node });
            if (var_decl.ast.align_node != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.align_node });
            if (var_decl.ast.section_node != 0)
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
            var buf: [2]ast.Node.Index = undefined;
            const decl: ast.full.ContainerDecl = switch (tag) {
                .container_decl, .container_decl_trailing => tree.containerDecl(node),
                .container_decl_two, .container_decl_two_trailing => tree.containerDeclTwo(&buf, node),
                .container_decl_arg, .container_decl_arg_trailing => tree.containerDeclArg(node),
                .tagged_union, .tagged_union_trailing => tree.taggedUnion(node),
                .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => tree.taggedUnionEnumTag(node),
                .tagged_union_two, .tagged_union_two_trailing => tree.taggedUnionTwo(&buf, node),
                else => unreachable,
            };

            try writeToken(builder, decl.layout_token, .keyword);
            try writeToken(builder, decl.ast.main_token, .keyword);
            if (decl.ast.enum_token) |enum_token| {
                if (decl.ast.arg != 0)
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl.ast.arg })
                else
                    try writeToken(builder, enum_token, .keyword);
            } else if (decl.ast.arg != 0) try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl.ast.arg });

            var gap_highlighter = GapHighlighter.init(builder, main_token + 1);
            const field_token_type = fieldTokenType(node, handle);
            for (decl.ast.members) |child| {
                try gap_highlighter.next(child);
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, arena, store, child, field_token_type, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
            try gap_highlighter.end(lastToken(tree, node));
        },
        .error_value => {
            if (datas[node].lhs != 0) {
                try writeToken(builder, datas[node].lhs - 1, .keyword);
            }
            try writeToken(builder, datas[node].rhs, .errorTag);
        },
        .identifier => {
            if (analysis.isTypeIdent(handle.tree, main_token)) {
                return try writeToken(builder, main_token, .type);
            }

            if (try analysis.lookupSymbolGlobal(
                store,
                arena,
                handle,
                handle.tree.getNodeSource(node),
                handle.tree.tokens.items(.start)[main_token],
            )) |child| {
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
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => {
            var buf: [1]ast.Node.Index = undefined;
            const fn_proto: ast.full.FnProto = fnProto(tree, node, &buf).?;
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |docs|
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
                    try writeToken(builder, any_token, .type);
                } else if (param_decl.type_expr != 0) try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param_decl.type_expr });
            }

            if (fn_proto.ast.align_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.align_expr });
            if (fn_proto.ast.section_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.section_expr });
            if (fn_proto.ast.callconv_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.callconv_expr });

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
        .@"comptime",
        .@"nosuspend",
        => {
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |doc|
                try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .@"switch",
        .switch_comma,
        => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            const extra = tree.extraData(datas[node].rhs, ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            var gap_highlighter = GapHighlighter.init(builder, lastToken(tree, datas[node].lhs) + 1);
            for (cases) |case_node| {
                try gap_highlighter.next(case_node);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, case_node });
            }
            try gap_highlighter.end(lastToken(tree, node));
        },
        .switch_case_one,
        .switch_case,
        => {
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
        .@"while",
        .while_simple,
        .while_cont,
        .for_simple,
        .@"for",
        => {
            const while_node = whileAst(tree, node).?;
            try writeToken(builder, while_node.label_token, .label);
            try writeToken(builder, while_node.inline_token, .keyword);
            try writeToken(builder, while_node.ast.while_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.ast.cond_expr });
            if (while_node.payload_token) |payload| {
                try writeToken(builder, payload - 1, .operator);
                try writeToken(builder, payload, .variable);
                var r_pipe = payload + 1;
                if (token_tags[r_pipe] == .comma) {
                    r_pipe += 1;
                    try writeToken(builder, r_pipe, .variable);
                    r_pipe += 1;
                }
                try writeToken(builder, r_pipe, .operator);
            }
            if (while_node.ast.cont_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.ast.cont_expr });

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.ast.then_expr });

            if (while_node.ast.else_expr != 0) {
                try writeToken(builder, while_node.else_token, .keyword);

                if (while_node.error_token) |err_token| {
                    try writeToken(builder, err_token - 1, .operator);
                    try writeToken(builder, err_token, .variable);
                    try writeToken(builder, err_token + 1, .operator);
                }
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.ast.else_expr });
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ifFull(tree, node);

            try writeToken(builder, if_node.ast.if_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.ast.cond_expr });

            if (if_node.payload_token) |payload| {
                // if (?x) |x|
                try writeToken(builder, payload - 1, .operator); // |
                try writeToken(builder, payload, .variable); // 	x
                try writeToken(builder, payload + 1, .operator); // |
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.ast.then_expr });

            if (if_node.ast.else_expr != 0) {
                try writeToken(builder, if_node.else_token, .keyword);
                if (if_node.error_token) |err_token| {
                    // else |err|
                    try writeToken(builder, err_token - 1, .operator); // |
                    try writeToken(builder, err_token, .variable); // 	  err
                    try writeToken(builder, err_token + 1, .operator); // |
                }
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, if_node.ast.else_expr });
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
            var buf: [2]ast.Node.Index = undefined;
            const array_init: ast.full.ArrayInit = switch (tag) {
                .array_init, .array_init_comma => tree.arrayInit(node),
                .array_init_one, .array_init_one_comma => tree.arrayInitOne(buf[0..1], node),
                .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
                .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(&buf, node),
                else => unreachable,
            };

            if (array_init.ast.type_expr != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_init.ast.type_expr });
            for (array_init.ast.elements) |elem| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, elem });
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
            var buf: [2]ast.Node.Index = undefined;
            const struct_init: ast.full.StructInit = switch (tag) {
                .struct_init, .struct_init_comma => tree.structInit(node),
                .struct_init_dot, .struct_init_dot_comma => tree.structInitDot(node),
                .struct_init_one, .struct_init_one_comma => tree.structInitOne(buf[0..1], node),
                .struct_init_dot_two, .struct_init_dot_two_comma => tree.structInitDotTwo(&buf, node),
                else => unreachable,
            };

            var field_token_type: ?TokenType = null;

            if (struct_init.ast.type_expr != 0) {
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, struct_init.ast.type_expr });

                field_token_type = if (try analysis.resolveTypeOfNode(store, arena, .{
                    .node = struct_init.ast.type_expr,
                    .handle = handle,
                })) |struct_type| switch (struct_type.type.data) {
                    .other => |type_node| if (isContainer(struct_type.handle.tree, type_node))
                        fieldTokenType(type_node, struct_type.handle)
                    else
                        null,
                    else => null,
                } else null;
            }

            var gap_highlighter = GapHighlighter.init(builder, struct_init.ast.lbrace);
            for (struct_init.ast.fields) |field_init| {
                try gap_highlighter.next(field_init);

                const init_token = tree.firstToken(field_init);
                try writeToken(builder, init_token - 3, field_token_type orelse .field); // '.'
                try writeToken(builder, init_token - 2, field_token_type orelse .field); // name
                try writeToken(builder, init_token - 1, .operator); // '='
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, field_init });
            }
            try gap_highlighter.end(lastToken(tree, node));
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
            var params: [1]ast.Node.Index = undefined;
            const call: ast.full.Call = switch (tag) {
                .call, .call_comma, .async_call, .async_call_comma => tree.callFull(node),
                .call_one, .call_one_comma, .async_call_one, .async_call_one_comma => tree.callOne(&params, node),
                else => unreachable,
            };

            try writeToken(builder, call.async_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, call.ast.fn_expr });

            if (builder.current_token) |curr_tok| {
                if (curr_tok != lastToken(tree, call.ast.fn_expr) and token_tags[lastToken(tree, call.ast.fn_expr)] == .identifier) {
                    try writeToken(builder, lastToken(tree, call.ast.fn_expr), .function);
                }
            }
            for (call.ast.params) |param| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param });
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: ast.full.Slice = switch (tag) {
                .slice => tree.slice(node),
                .slice_open => tree.sliceOpen(node),
                .slice_sentinel => tree.sliceSentinel(node),
                else => unreachable,
            };

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.sliced });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.start });
            try writeToken(builder, lastToken(tree, slice.ast.start) + 1, .operator);

            if (slice.ast.end != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.end });
            if (slice.ast.sentinel != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.sentinel });
        },
        .array_access => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .deref => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            try writeToken(builder, main_token, .operator);
        },
        .unwrap_optional => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            try writeToken(builder, main_token + 1, .operator);
        },
        .grouped_expression => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .@"break",
        .@"continue",
        => {
            try writeToken(builder, main_token, .keyword);
            if (datas[node].lhs != 0)
                try writeToken(builder, datas[node].lhs, .label);
            if (datas[node].rhs != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .@"suspend", .@"return" => {
            try writeToken(builder, main_token, .keyword);
            if (datas[node].lhs != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .integer_literal,
        .float_literal,
        => {
            try writeToken(builder, main_token, .number);
        },
        .enum_literal => {
            try writeToken(builder, main_token - 1, .enumMember);
            try writeToken(builder, main_token, .enumMember);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const data = datas[node];
            const params = switch (tag) {
                .builtin_call, .builtin_call_comma => tree.extra_data[data.lhs..data.rhs],
                .builtin_call_two, .builtin_call_two_comma => if (data.lhs == 0)
                    &[_]ast.Node.Index{}
                else if (data.rhs == 0)
                    &[_]ast.Node.Index{data.lhs}
                else
                    &[_]ast.Node.Index{ data.lhs, data.rhs },
                else => unreachable,
            };

            try writeToken(builder, main_token, .builtin);
            for (params) |param|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param });
        },
        .string_literal,
        .char_literal,
        => {
            try writeToken(builder, main_token, .string);
        },
        .multiline_string_literal => {
            var cur_tok = main_token;
            const last_tok = datas[node].rhs;

            while (cur_tok <= last_tok) : (cur_tok += 1) try writeToken(builder, cur_tok, .string);
        },
        .true_literal,
        .false_literal,
        .null_literal,
        .undefined_literal,
        .unreachable_literal,
        => {
            try writeToken(builder, main_token, .keywordLiteral);
        },
        .error_set_decl => {
            try writeToken(builder, main_token, .keyword);
        },
        .@"asm",
        .asm_output,
        .asm_input,
        .asm_simple,
        => {
            const asm_node: ast.full.Asm = switch (tag) {
                .@"asm" => tree.asmFull(node),
                .asm_simple => tree.asmSimple(node),
                else => return, // TODO Inputs, outputs
            };

            try writeToken(builder, main_token, .keyword);
            try writeToken(builder, asm_node.volatile_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, asm_node.ast.template });
            // TODO Inputs, outputs.
        },
        .@"anytype" => {
            try writeToken(builder, main_token, .type);
        },
        .test_decl => {
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |doc|
                try writeDocComments(builder, handle.tree, doc);

            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .string_literal)
                try writeToken(builder, main_token + 1, .string);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .@"catch" => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .pipe)
                try writeToken(builder, main_token + 1, .variable);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .add,
        .add_wrap,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_bit_shift_left,
        .assign_bit_shift_right,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_mul,
        .assign_mul_wrap,
        .bang_equal,
        .bit_and,
        .bit_or,
        .bit_shift_left,
        .bit_shift_right,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .error_union,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .switch_range,
        .sub,
        .sub_wrap,
        .@"orelse",
        => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
            const token_type: TokenType = switch (tag) {
                .bool_and, .bool_or => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            if (datas[node].rhs != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].rhs });
        },
        .field_access => {
            const data = datas[node];
            if (data.rhs == 0) return;
            const rhs_str = tree.tokenSlice(data.rhs);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, data.lhs });

            // TODO This is basically exactly the same as what is done in analysis.resolveTypeOfNode, with the added
            //      writeToken code.
            // Maybe we can hook into it insead? Also applies to Identifier and VarDecl
            var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
            const lhs_type = try analysis.resolveFieldAccessLhsType(
                store,
                arena,
                (try analysis.resolveTypeOfNodeInternal(store, arena, .{
                    .node = data.lhs,
                    .handle = handle,
                }, &bound_type_params)) orelse return,
                &bound_type_params,
            );
            const left_type_node = switch (lhs_type.type.data) {
                .other => |n| n,
                else => return,
            };
            if (try analysis.lookupSymbolContainer(store, arena, .{
                .node = left_type_node,
                .handle = lhs_type.handle,
            }, rhs_str, !lhs_type.type.is_type_val)) |decl_type| {
                switch (decl_type.decl.*) {
                    .ast_node => |decl_node| {
                        if (decl_type.handle.tree.nodes.items(.tag)[decl_node].isContainerField()) {
                            const tok_type: ?TokenType = if (isContainer(lhs_type.handle.tree, left_type_node))
                                fieldTokenType(decl_node, lhs_type.handle)
                            else if (left_type_node == 0)
                                TokenType.field
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

                if (try decl_type.resolveType(store, arena, &bound_type_params)) |resolved_type| {
                    try colorIdentifierBasedOnType(builder, resolved_type, data.rhs, .{});
                }
            }
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ptrType(tree, node).?;

            if (ptr_type.size == .One and token_tags[main_token] == .asterisk_asterisk and
                main_token == main_tokens[ptr_type.ast.child_type])
            {
                return try await @asyncCall(child_frame, {}, writeNodeTokens, .{
                    builder,
                    arena,
                    store,
                    ptr_type.ast.child_type,
                });
            }

            if (ptr_type.size == .One) try writeToken(builder, main_token, .operator);
            if (ptr_type.ast.sentinel != 0) {
                return try await @asyncCall(child_frame, {}, writeNodeTokens, .{
                    builder,
                    arena,
                    store,
                    ptr_type.ast.sentinel,
                });
            }

            try writeToken(builder, ptr_type.allowzero_token, .keyword);

            if (ptr_type.ast.align_node != 0) {
                const first_tok = tree.firstToken(ptr_type.ast.align_node);
                try writeToken(builder, first_tok - 2, .keyword);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.align_node });

                if (ptr_type.ast.bit_range_start != 0) {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.bit_range_start });
                    try writeToken(builder, tree.firstToken(ptr_type.ast.bit_range_end - 1), .operator);
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.bit_range_end });
                }
            }

            try writeToken(builder, ptr_type.const_token, .keyword);
            try writeToken(builder, ptr_type.volatile_token, .keyword);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.child_type });
        },
        .array_type,
        .array_type_sentinel,
        => {
            const array_type: ast.full.ArrayType = if (tag == .array_type)
                tree.arrayType(node)
            else
                tree.arrayTypeSentinel(node);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.ast.elem_count });
            if (array_type.ast.sentinel != 0)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.ast.sentinel });

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.ast.elem_type });
        },
        .address_of,
        .bit_not,
        .bool_not,
        .optional_type,
        .negation,
        .negation_wrap,
        => {
            try writeToken(builder, main_token, .operator);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .@"try",
        .@"resume",
        .@"await",
        => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, datas[node].lhs });
        },
        .anyframe_literal => try writeToken(builder, main_token, .keyword),
    }
}

// TODO Range version, edit version.
pub fn writeAllSemanticTokens(arena: *std.heap.ArenaAllocator, store: *DocumentStore, handle: *DocumentStore.Handle, encoding: offsets.Encoding) ![]u32 {
    var builder = Builder.init(arena.child_allocator, handle, encoding);

    // reverse the ast from the root declarations
    var gap_highlighter = GapHighlighter.init(&builder, 0);

    var buf: [2]ast.Node.Index = undefined;
    for (declMembers(handle.tree, 0, &buf)) |child| {
        try gap_highlighter.next(child);
        try writeNodeTokens(&builder, arena, store, child);
    }

    try gap_highlighter.end(@truncate(u32, handle.tree.tokens.len) - 1);

    return builder.toOwnedSlice();
}
