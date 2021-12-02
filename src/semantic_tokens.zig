const std = @import("std");
const offsets = @import("./offsets.zig");
const DocumentStore = @import("./DocumentStore.zig");
const analysis = @import("./analysis.zig");
const Ast = std.zig.Ast;
const log = std.log.scoped(.semantic_tokens);
const ast = @import("./ast.zig");

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

    inline fn set(self: *TokenModifiers, comptime field: []const u8) void {
        @field(self, field) = true;
    }
};

const Builder = struct {
    handle: *DocumentStore.Handle,
    previous_position: usize = 0,
    previous_token: ?Ast.TokenIndex = null,
    arr: std.ArrayList(u32),
    encoding: offsets.Encoding,

    fn init(allocator: std.mem.Allocator, handle: *DocumentStore.Handle, encoding: offsets.Encoding) Builder {
        return Builder{
            .handle = handle,
            .arr = std.ArrayList(u32).init(allocator),
            .encoding = encoding,
        };
    }

    fn add(self: *Builder, token: Ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const tree = self.handle.tree;
        const starts = tree.tokens.items(.start);
        const next_start = starts[token];

        if (next_start < self.previous_position) {
            return error.MovedBackwards;
        }

        if (self.previous_token) |prev| {
            // Highlight gaps between AST nodes. These can contain comments or malformed code.
            var i = prev + 1;
            while (i < token) : (i += 1) {
                try handleComments(self, starts[i - 1], starts[i]);
                try handleToken(self, i);
            }
        }
        self.previous_token = token;
        try self.handleComments(if (token > 0) starts[token - 1] else 0, next_start);

        const length = offsets.tokenLength(tree, token, self.encoding);
        try self.addDirect(token_type, token_modifiers, next_start, length);
    }

    fn finish(self: *Builder) !void {
        const starts = self.handle.tree.tokens.items(.start);

        const last_token = self.previous_token orelse 0;
        var i = last_token + 1;
        while (i < starts.len) : (i += 1) {
            try handleComments(self, starts[i - 1], starts[i]);
            try handleToken(self, i);
        }
        try self.handleComments(starts[starts.len - 1], self.handle.tree.source.len);
    }

    /// Highlight a token without semantic context.
    fn handleToken(self: *Builder, tok: Ast.TokenIndex) !void {
        const tree = self.handle.tree;
        // TODO More highlighting here
        const tok_id = tree.tokens.items(.tag)[tok];
        const tok_type: TokenType = switch (tok_id) {
            .keyword_unreachable => .keywordLiteral,
            .integer_literal, .float_literal => .number,
            .string_literal, .multiline_string_literal_line, .char_literal => .string,
            .period, .comma, .r_paren, .l_paren, .r_brace, .l_brace, .semicolon, .colon => return,

            else => blk: {
                const id = @enumToInt(tok_id);
                if (id >= @enumToInt(std.zig.Token.Tag.keyword_align) and
                    id <= @enumToInt(std.zig.Token.Tag.keyword_while))
                    break :blk TokenType.keyword;
                if (id >= @enumToInt(std.zig.Token.Tag.bang) and
                    id <= @enumToInt(std.zig.Token.Tag.tilde))
                    break :blk TokenType.operator;

                return;
            },
        };
        const start = tree.tokens.items(.start)[tok];
        const length = offsets.tokenLength(tree, tok, self.encoding);
        try self.addDirect(tok_type, .{}, start, length);
    }

    /// Highlight normal comments and doc comments.
    fn handleComments(self: *Builder, from: usize, to: usize) !void {
        if (from == to) return;
        std.debug.assert(from < to);

        const source = self.handle.tree.source;

        var i: usize = from;
        while (i < to - 1) : (i += 1) {
            if (source[i] != '/' or source[i + 1] != '/')
                continue;

            const comment_start = i;
            var mods = TokenModifiers{};
            if (i + 2 < to and (source[i + 2] == '!' or source[i + 2] == '/'))
                mods.documentation = true;

            while (i < to - 1 and source[i] != '\n') : (i += 1) {}

            const length = try offsets.lineSectionLength(self.handle.tree, comment_start, i, self.encoding);
            try self.addDirect(TokenType.comment, mods, comment_start, length);
        }
    }

    fn addDirect(self: *Builder, tok_type: TokenType, tok_mod: TokenModifiers, start: usize, length: usize) !void {
        const delta = offsets.tokenRelativeLocation(
            self.handle.tree,
            self.previous_position,
            start,
            self.encoding,
        ) catch return;

        try self.arr.appendSlice(&.{
            @truncate(u32, delta.line),
            @truncate(u32, delta.column),
            @truncate(u32, length),
            @enumToInt(tok_type),
            tok_mod.toInt(),
        });
        self.previous_position = start;
    }

    fn toOwnedSlice(self: *Builder) []u32 {
        return self.arr.toOwnedSlice();
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
        var tok_mod = TokenModifiers{};
        tok_mod.set("documentation");

        try builder.add(tok_idx, .comment, tok_mod);
    }
}

fn fieldTokenType(container_decl: Ast.Node.Index, handle: *DocumentStore.Handle) ?TokenType {
    const main_token = handle.tree.nodes.items(.main_token)[container_decl];
    if (main_token > handle.tree.tokens.len) return null;
    return @as(?TokenType, switch (handle.tree.tokens.items(.tag)[main_token]) {
        .keyword_struct => .field,
        .keyword_union, .keyword_enum => .enumMember,
        else => null,
    });
}

fn colorIdentifierBasedOnType(builder: *Builder, type_node: analysis.TypeWithHandle, target_tok: Ast.TokenIndex, tok_mod: TokenModifiers) !void {
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

const WriteTokensError = error{
    OutOfMemory,
    Utf8InvalidStartByte,
    CodepointTooLong,
    Utf8ExpectedContinuation,
    Utf8OverlongEncoding,
    Utf8EncodesSurrogateHalf,
    Utf8CodepointTooLarge,
    MovedBackwards,
};

fn writeNodeTokens(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, maybe_node: ?Ast.Node.Index) WriteTokensError!void {
    const node = maybe_node orelse return;

    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    if (node == 0 or node > node_data.len) return;

    const FrameSize = @sizeOf(@Frame(writeNodeTokens));
    var child_frame = try arena.child_allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
    defer arena.child_allocator.free(child_frame);

    const tag = node_tags[node];
    const main_token = main_tokens[node];

    switch (tag) {
        .root => unreachable,
        .container_field,
        .container_field_align,
        .container_field_init,
        => try writeContainerField(builder, arena, store, node, .field, child_frame),
        .@"errdefer" => {
            try writeToken(builder, main_token, .keyword);

            if (node_data[node].lhs != 0) {
                const payload_tok = node_data[node].lhs;
                try writeToken(builder, payload_tok - 1, .operator);
                try writeToken(builder, payload_tok, .variable);
                try writeToken(builder, payload_tok + 1, .operator);
            }

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            if (token_tags[main_token - 1] == .colon and token_tags[main_token - 2] == .identifier) {
                try writeToken(builder, main_token - 2, .label);
            }

            const statements: []const Ast.Node.Index = switch (tag) {
                .block, .block_semicolon => tree.extra_data[node_data[node].lhs..node_data[node].rhs],
                .block_two, .block_two_semicolon => blk: {
                    const statements = &[_]Ast.Node.Index{ node_data[node].lhs, node_data[node].rhs };
                    const len: usize = if (node_data[node].lhs == 0)
                        @as(usize, 0)
                    else if (node_data[node].rhs == 0)
                        @as(usize, 1)
                    else
                        @as(usize, 2);
                    break :blk statements[0..len];
                },
                else => unreachable,
            };

            for (statements) |child| {
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, arena, store, child, .field, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.varDecl(tree, node).?;
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |comment_idx|
                try writeDocComments(builder, tree, comment_idx);

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
            try writeToken(builder, var_decl.ast.mut_token + 2, .operator);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.type_node });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.align_node });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.section_node });

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.ast.init_node });
        },
        .@"usingnamespace" => {
            const first_tok = tree.firstToken(node);
            if (first_tok > 0 and token_tags[first_tok - 1] == .doc_comment)
                try writeDocComments(builder, tree, first_tok - 1);
            try writeToken(builder, if (token_tags[first_tok] == .keyword_pub) first_tok else null, .keyword);
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
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
            const decl: Ast.full.ContainerDecl = switch (tag) {
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
            } else try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl.ast.arg });

            const field_token_type = fieldTokenType(node, handle);
            for (decl.ast.members) |child| {
                if (node_tags[child].isContainerField()) {
                    try writeContainerField(builder, arena, store, child, field_token_type, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
        },
        .error_value => {
            if (node_data[node].lhs > 0) {
                try writeToken(builder, node_data[node].lhs - 1, .keyword);
            }
            try writeToken(builder, node_data[node].rhs, .errorTag);
        },
        .identifier => {
            if (analysis.isTypeIdent(tree, main_token)) {
                return try writeToken(builder, main_token, .type);
            }

            if (try analysis.lookupSymbolGlobal(
                store,
                arena,
                handle,
                tree.getNodeSource(node),
                tree.tokens.items(.start)[main_token],
            )) |child| {
                if (child.decl.* == .param_decl) {
                    return try writeToken(builder, main_token, .parameter);
                }
                var bound_type_params = analysis.BoundTypeParams.init(arena.allocator());
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
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto: Ast.full.FnProto = ast.fnProto(tree, node, &buf).?;
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |docs|
                try writeDocComments(builder, tree, docs);

            try writeToken(builder, fn_proto.visib_token, .keyword);
            try writeToken(builder, fn_proto.extern_export_inline_token, .keyword);
            try writeToken(builder, fn_proto.lib_name, .string);
            try writeToken(builder, fn_proto.ast.fn_token, .keyword);

            const func_name_tok_type: TokenType = if (analysis.isTypeFunction(tree, fn_proto))
                .type
            else
                .function;

            const tok_mod = if (analysis.isGenericFunction(tree, fn_proto))
                TokenModifiers{ .generic = true }
            else
                TokenModifiers{};

            try writeTokenMod(builder, fn_proto.name_token, func_name_tok_type, tok_mod);

            var it = fn_proto.iterate(tree);
            while (it.next()) |param_decl| {
                if (param_decl.first_doc_comment) |docs| try writeDocComments(builder, tree, docs);

                try writeToken(builder, param_decl.comptime_noalias, .keyword);
                try writeTokenMod(builder, param_decl.name_token, .parameter, .{ .declaration = true });
                if (param_decl.anytype_ellipsis3) |any_token| {
                    try writeToken(builder, any_token, .type);
                } else try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param_decl.type_expr });
            }

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.align_expr });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.section_expr });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.callconv_expr });

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.ast.return_type });

            if (tag == .fn_decl)
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .anyframe_type => {
            try writeToken(builder, main_token, .type);
            if (node_data[node].rhs != 0) {
                try writeToken(builder, node_data[node].lhs, .type);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
            }
        },
        .@"defer" => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .@"comptime",
        .@"nosuspend",
        => {
            if (analysis.getDocCommentTokenIndex(token_tags, main_token)) |doc|
                try writeDocComments(builder, tree, doc);
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
        },
        .@"switch",
        .switch_comma,
        => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            const extra = tree.extraData(node_data[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases) |case_node| {
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, case_node });
            }
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
                const actual_payload = payload_token + @boolToInt(token_tags[payload_token] == .asterisk);
                try writeToken(builder, actual_payload, .variable);
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, switch_case.ast.target_expr });
        },
        .@"while",
        .while_simple,
        .while_cont,
        .for_simple,
        .@"for",
        => {
            const while_node = ast.whileAst(tree, node).?;
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
            const if_node = ast.ifFull(tree, node);

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
            var buf: [2]Ast.Node.Index = undefined;
            const array_init: Ast.full.ArrayInit = switch (tag) {
                .array_init, .array_init_comma => tree.arrayInit(node),
                .array_init_one, .array_init_one_comma => tree.arrayInitOne(buf[0..1], node),
                .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
                .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(&buf, node),
                else => unreachable,
            };

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
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = switch (tag) {
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
                    .other => |type_node| if (ast.isContainer(struct_type.handle.tree, type_node))
                        fieldTokenType(type_node, struct_type.handle)
                    else
                        null,
                    else => null,
                } else null;
            }

            for (struct_init.ast.fields) |field_init| {
                const init_token = tree.firstToken(field_init);
                try writeToken(builder, init_token - 3, field_token_type orelse .field); // '.'
                try writeToken(builder, init_token - 2, field_token_type orelse .field); // name
                try writeToken(builder, init_token - 1, .operator); // '='
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, field_init });
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
            const call: Ast.full.Call = switch (tag) {
                .call, .call_comma, .async_call, .async_call_comma => tree.callFull(node),
                .call_one, .call_one_comma, .async_call_one, .async_call_one_comma => tree.callOne(&params, node),
                else => unreachable,
            };

            try writeToken(builder, call.async_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, call.ast.fn_expr });

            if (builder.previous_token) |prev| {
                if (prev != ast.lastToken(tree, call.ast.fn_expr) and token_tags[ast.lastToken(tree, call.ast.fn_expr)] == .identifier) {
                    try writeToken(builder, ast.lastToken(tree, call.ast.fn_expr), .function);
                }
            }
            for (call.ast.params) |param| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, param });
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = switch (tag) {
                .slice => tree.slice(node),
                .slice_open => tree.sliceOpen(node),
                .slice_sentinel => tree.sliceSentinel(node),
                else => unreachable,
            };

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.sliced });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.start });
            try writeToken(builder, ast.lastToken(tree, slice.ast.start) + 1, .operator);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.end });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, slice.ast.sentinel });
        },
        .array_access => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .deref => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            try writeToken(builder, main_token, .operator);
        },
        .unwrap_optional => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            try writeToken(builder, main_token + 1, .operator);
        },
        .grouped_expression => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
        },
        .@"break",
        .@"continue",
        => {
            try writeToken(builder, main_token, .keyword);
            if (node_data[node].lhs != 0)
                try writeToken(builder, node_data[node].lhs, .label);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .@"suspend", .@"return" => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
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
            const data = node_data[node];
            const params = switch (tag) {
                .builtin_call, .builtin_call_comma => tree.extra_data[data.lhs..data.rhs],
                .builtin_call_two, .builtin_call_two_comma => if (data.lhs == 0)
                    &[_]Ast.Node.Index{}
                else if (data.rhs == 0)
                    &[_]Ast.Node.Index{data.lhs}
                else
                    &[_]Ast.Node.Index{ data.lhs, data.rhs },
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
            const last_tok = node_data[node].rhs;

            while (cur_tok <= last_tok) : (cur_tok += 1) try writeToken(builder, cur_tok, .string);
        },
        .unreachable_literal => {
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
            const asm_node: Ast.full.Asm = switch (tag) {
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
                try writeDocComments(builder, tree, doc);

            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .string_literal)
                try writeToken(builder, main_token + 1, .string);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .@"catch" => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            try writeToken(builder, main_token, .keyword);
            if (token_tags[main_token + 1] == .pipe)
                try writeToken(builder, main_token + 1, .variable);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
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
        .error_union,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .mul_sat,
        .switch_range,
        .sub,
        .sub_wrap,
        .sub_sat,
        .@"orelse",
        => {
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
            const token_type: TokenType = switch (tag) {
                .bool_and, .bool_or => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].rhs });
        },
        .field_access => {
            const data = node_data[node];
            if (data.rhs == 0) return;
            const rhs_str = tree.tokenSlice(data.rhs);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, data.lhs });

            // TODO This is basically exactly the same as what is done in analysis.resolveTypeOfNode, with the added
            //      writeToken code.
            // Maybe we can hook into it insead? Also applies to Identifier and VarDecl
            var bound_type_params = analysis.BoundTypeParams.init(arena.allocator());
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
                            const tok_type: ?TokenType = if (ast.isContainer(lhs_type.handle.tree, left_type_node))
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
            const ptr_type = ast.ptrType(tree, node).?;

            if (ptr_type.size == .One and token_tags[main_token] == .asterisk_asterisk and
                main_token == main_tokens[ptr_type.ast.child_type])
            {
                return try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.child_type });
            }

            if (ptr_type.size == .One) try writeToken(builder, main_token, .operator);
            if (ptr_type.ast.sentinel != 0) {
                return try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, ptr_type.ast.sentinel });
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
            const array_type: Ast.full.ArrayType = if (tag == .array_type)
                tree.arrayType(node)
            else
                tree.arrayTypeSentinel(node);

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, array_type.ast.elem_count });
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
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
        },
        .@"try",
        .@"resume",
        .@"await",
        => {
            try writeToken(builder, main_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, node_data[node].lhs });
        },
        .anyframe_literal => try writeToken(builder, main_token, .keyword),
    }
}

fn writeContainerField(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, node: Ast.Node.Index, field_token_type: ?TokenType, child_frame: anytype) !void {
    const tree = builder.handle.tree;
    const container_field = ast.containerField(tree, node).?;
    const base = tree.nodes.items(.main_token)[node];
    const tokens = tree.tokens.items(.tag);

    if (analysis.getDocCommentTokenIndex(tokens, base)) |docs|
        try writeDocComments(builder, tree, docs);

    try writeToken(builder, container_field.comptime_token, .keyword);
    if (field_token_type) |tok_type| try writeToken(builder, container_field.ast.name_token, tok_type);

    if (container_field.ast.type_expr != 0) {
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.type_expr });
        if (container_field.ast.align_expr != 0) {
            try writeToken(builder, tree.firstToken(container_field.ast.align_expr) - 2, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.align_expr });
        }
    }

    if (container_field.ast.value_expr != 0) block: {
        const eq_tok: Ast.TokenIndex = if (container_field.ast.align_expr != 0)
            ast.lastToken(tree, container_field.ast.align_expr) + 2
        else if (container_field.ast.type_expr != 0)
            ast.lastToken(tree, container_field.ast.type_expr) + 1
        else
            break :block;

        try writeToken(builder, eq_tok, .operator);
        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, container_field.ast.value_expr });
    }
}

// TODO Range version, edit version.
pub fn writeAllSemanticTokens(arena: *std.heap.ArenaAllocator, store: *DocumentStore, handle: *DocumentStore.Handle, encoding: offsets.Encoding) ![]u32 {
    var builder = Builder.init(arena.child_allocator, handle, encoding);
    errdefer builder.arr.deinit();

    // reverse the ast from the root declarations
    var buf: [2]Ast.Node.Index = undefined;
    for (ast.declMembers(handle.tree, 0, &buf)) |child| {
        writeNodeTokens(&builder, arena, store, child) catch |err| switch (err) {
            error.MovedBackwards => break,
            else => |e| return e,
        };
    }
    try builder.finish();
    return builder.toOwnedSlice();
}
