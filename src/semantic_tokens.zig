const std = @import("std");
const offsets = @import("offsets.zig");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const ast = std.zig.ast;

const TokenType = enum(u32) {
    namespace,
    type,
    @"struct",
    @"enum",
    @"union",
    parameter,
    variable,
    tagField,
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
};

const TokenModifiers = packed struct {
    definition: bool = false,
    @"async": bool = false,
    documentation: bool = false,
    generic: bool = false,

    fn toInt(self: TokenModifiers) u32 {
        return @as(u32, @bitCast(u4, self));
    }

    inline fn set(self: *TokenModifiers, comptime field: []const u8) void {
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
            self.handle.tree.token_locs[current_token].start
        else
            0;
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

inline fn writeToken(builder: *Builder, token_idx: ?ast.TokenIndex, tok_type: TokenType) !void {
    return try writeTokenMod(builder, token_idx, tok_type, .{});
}

inline fn writeTokenMod(builder: *Builder, token_idx: ?ast.TokenIndex, tok_type: TokenType, tok_mod: TokenModifiers) !void {
    if (token_idx) |ti| {
        try builder.add(ti, tok_type, tok_mod);
    }
}

fn writeDocComments(builder: *Builder, tree: *ast.Tree, doc: *ast.Node.DocComment) !void {
    var tok_idx = doc.first_line;
    while (tree.token_ids[tok_idx] == .DocComment or
        tree.token_ids[tok_idx] == .ContainerDocComment or
        tree.token_ids[tok_idx] == .LineComment) : (tok_idx += 1)
    {
        var tok_mod = TokenModifiers{};
        if (tree.token_ids[tok_idx] == .DocComment or tree.token_ids[tok_idx] == .ContainerDocComment)
            tok_mod.set("documentation");

        try builder.add(tok_idx, .comment, tok_mod);
    }
}

fn fieldTokenType(container_decl: *ast.Node.ContainerDecl, handle: *DocumentStore.Handle) ?TokenType {
    if (container_decl.kind_token > handle.tree.token_ids.len) return null;
    return @as(?TokenType, switch (handle.tree.token_ids[container_decl.kind_token]) {
        .Keyword_struct => .field,
        .Keyword_union, .Keyword_enum => .tagField,
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
        const tok_id = self.builder.handle.tree.token_ids[tok];
        if (tok_id == .LineComment) {
            try writeToken(self.builder, tok, .comment);
        } else if (tok_id == .ContainerDocComment) {
            try writeTokenMod(self.builder, tok, .comment, TokenModifiers{ .documentation = true });
        } else if (@enumToInt(tok_id) >= @enumToInt(std.zig.Token.Id.Keyword_align) and
            @enumToInt(tok_id) <= @enumToInt(std.zig.Token.Id.Keyword_while))
        {
            try writeToken(self.builder, tok, .keyword);
        } else if (@enumToInt(tok_id) >= @enumToInt(std.zig.Token.Id.Bang) and
            @enumToInt(tok_id) <= @enumToInt(std.zig.Token.Id.Tilde) and
            tok_id != .Period and tok_id != .Comma and tok_id != .RParen and
            tok_id != .LParen and tok_id != .RBrace and tok_id != .LBrace and
            tok_id != .Semicolon and tok_id != .Colon)
        {
            try writeToken(self.builder, tok, .operator);
        } else if (tok_id == .IntegerLiteral or tok_id == .FloatLiteral) {
            try writeToken(self.builder, tok, .number);
        } else if (tok_id == .StringLiteral or tok_id == .MultilineStringLiteralLine or tok_id == .CharLiteral) {
            try writeToken(self.builder, tok, .string);
        }
    }

    fn init(builder: *Builder, start: ast.TokenIndex) GapHighlighter {
        return .{ .builder = builder, .current_idx = start };
    }

    fn next(self: *GapHighlighter, node: *ast.Node) !void {
        if (self.current_idx > 0 and self.builder.handle.tree.token_ids[self.current_idx - 1] == .ContainerDocComment) {
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
        const tok_type = if (type_node.isNamespace())
            .namespace
        else if (type_node.isStructType())
            .@"struct"
        else if (type_node.isEnumType())
            .@"enum"
        else if (type_node.isUnionType())
            .@"union"
        else
            TokenType.type;

        try writeTokenMod(builder, target_tok, tok_type, tok_mod);
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
fn writeNodeTokens(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, maybe_node: ?*ast.Node) error{OutOfMemory}!void {
    if (maybe_node == null) return;
    const node = maybe_node.?;
    const handle = builder.handle;

    const FrameSize = @sizeOf(@Frame(writeNodeTokens));
    var child_frame = try arena.child_allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
    defer arena.child_allocator.free(child_frame);

    switch (node.tag) {
        .Root, .Block, .LabeledBlock => {
            const first_tok = if (node.castTag(.LabeledBlock)) |block_node| block: {
                try writeToken(builder, block_node.label, .label);
                break :block block_node.lbrace + 1;
            } else if (node.castTag(.Block)) |block_node|
                block_node.lbrace + 1
            else
                0;

            var gap_highlighter = GapHighlighter.init(builder, first_tok);
            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child| : (child_idx += 1) {
                try gap_highlighter.next(child);
                if (child.cast(ast.Node.ContainerField)) |container_field| {
                    try writeContainerField(builder, arena, store, container_field, .field, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
            try gap_highlighter.end(node.lastToken());
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.getTrailer("doc_comments")) |doc| try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, var_decl.getTrailer("visib_token"), .keyword);
            try writeToken(builder, var_decl.getTrailer("extern_export_token"), .keyword);
            try writeToken(builder, var_decl.getTrailer("thread_local_token"), .keyword);
            try writeToken(builder, var_decl.getTrailer("comptime_token"), .keyword);
            try writeToken(builder, var_decl.mut_token, .keyword);
            if (try analysis.resolveTypeOfNode(store, arena, .{ .node = node, .handle = handle })) |decl_type| {
                try colorIdentifierBasedOnType(builder, decl_type, var_decl.name_token, .{ .definition = true });
            } else {
                try writeTokenMod(builder, var_decl.name_token, .variable, .{ .definition = true });
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.getTrailer("type_node") });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.getTrailer("align_node") });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.getTrailer("section_node") });
            try writeToken(builder, var_decl.getTrailer("eq_token"), .operator);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, var_decl.getTrailer("init_node") });
        },
        .Use => {
            const use = node.cast(ast.Node.Use).?;
            if (use.doc_comments) |docs| try writeDocComments(builder, builder.handle.tree, docs);
            try writeToken(builder, use.visib_token, .keyword);
            try writeToken(builder, use.use_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, use.expr });
        },
        .ErrorSetDecl => {
            const error_set = node.cast(ast.Node.ErrorSetDecl).?;
            try writeToken(builder, error_set.error_token, .keyword);
            for (error_set.declsConst()) |decl|
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, decl });
        },
        .ContainerDecl => {
            const container_decl = node.cast(ast.Node.ContainerDecl).?;
            try writeToken(builder, container_decl.layout_token, .keyword);
            try writeToken(builder, container_decl.kind_token, .keyword);
            switch (container_decl.init_arg_expr) {
                .None => {},
                .Enum => |enum_expr| if (enum_expr) |expr|
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, expr })
                else
                    try writeToken(builder, container_decl.kind_token + 2, .keyword),
                .Type => |type_node| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, type_node }),
            }

            var gap_highlighter = GapHighlighter.init(builder, container_decl.lbrace_token + 1);
            const field_token_type = fieldTokenType(container_decl, handle);
            for (container_decl.fieldsAndDeclsConst()) |child| {
                try gap_highlighter.next(child);
                if (child.cast(ast.Node.ContainerField)) |container_field| {
                    try writeContainerField(builder, arena, store, container_field, field_token_type, child_frame);
                } else {
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, child });
                }
            }
            try gap_highlighter.end(node.lastToken());
        },
        .ErrorTag => {
            const error_tag = node.cast(ast.Node.ErrorTag).?;
            if (error_tag.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, error_tag.firstToken(), .errorTag);
        },
        .Identifier => {
            if (analysis.isTypeIdent(handle.tree, node.firstToken())) {
                return try writeToken(builder, node.firstToken(), .type);
            }

            if (try analysis.lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.token_locs[node.firstToken()].start)) |child| {
                if (child.decl.* == .param_decl) {
                    return try writeToken(builder, node.firstToken(), .parameter);
                }
                var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
                if (try child.resolveType(store, arena, &bound_type_params)) |decl_type| {
                    try colorIdentifierBasedOnType(builder, decl_type, node.firstToken(), .{});
                } else {
                    try writeTokenMod(builder, node.firstToken(), .variable, .{});
                }
            }
        },
        .FnProto => {
            const fn_proto = node.cast(ast.Node.FnProto).?;
            if (fn_proto.getTrailer("doc_comments")) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, fn_proto.getTrailer("visib_token"), .keyword);
            try writeToken(builder, fn_proto.getTrailer("extern_export_inline_token"), .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.getTrailer("lib_name") });
            try writeToken(builder, fn_proto.fn_token, .keyword);

            const func_name_tok_type: TokenType = if (analysis.isTypeFunction(handle.tree, fn_proto))
                .type
            else
                .function;

            const tok_mod = if (analysis.isGenericFunction(handle.tree, fn_proto))
                TokenModifiers{ .generic = true }
            else
                TokenModifiers{};

            try writeTokenMod(builder, fn_proto.getTrailer("name_token"), func_name_tok_type, tok_mod);

            for (fn_proto.paramsConst()) |param_decl| {
                if (param_decl.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
                try writeToken(builder, param_decl.noalias_token, .keyword);
                try writeToken(builder, param_decl.comptime_token, .keyword);
                try writeTokenMod(builder, param_decl.name_token, .parameter, .{ .definition = true });
                switch (param_decl.param_type) {
                    .any_type => |var_node| try writeToken(builder, var_node.firstToken(), .type),
                    .type_expr => |type_expr| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, type_expr }),
                }
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.getTrailer("align_expr") });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.getTrailer("section_expr") });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.getTrailer("callconv_expr") });

            switch (fn_proto.return_type) {
                .Explicit => |type_expr| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, type_expr }),
                .InferErrorSet => |type_expr| {
                    try writeToken(builder, type_expr.firstToken() - 1, .operator);
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, type_expr });
                },
                .Invalid => {},
            }
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, fn_proto.getTrailer("body_node") });
        },
        .AnyFrameType => {
            const any_frame_type = node.cast(ast.Node.AnyFrameType).?;
            try writeToken(builder, any_frame_type.anyframe_token, .type);
            if (any_frame_type.result) |any_frame_result| {
                try writeToken(builder, any_frame_result.arrow_token, .type);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, any_frame_result.return_type });
            }
        },
        .Defer => {
            const defer_node = node.cast(ast.Node.Defer).?;
            try writeToken(builder, defer_node.defer_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, defer_node.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, defer_node.expr });
        },
        .Comptime => {
            const comptime_node = node.cast(ast.Node.Comptime).?;
            if (comptime_node.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, comptime_node.comptime_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, comptime_node.expr });
        },
        .Nosuspend => {
            const nosuspend_node = node.cast(ast.Node.Nosuspend).?;
            try writeToken(builder, nosuspend_node.nosuspend_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, nosuspend_node.expr });
        },
        .Payload => {
            const payload = node.cast(ast.Node.Payload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.error_symbol.firstToken(), .variable);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .PointerPayload => {
            const payload = node.cast(ast.Node.PointerPayload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.ptr_token, .operator);
            try writeToken(builder, payload.value_symbol.firstToken(), .variable);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .PointerIndexPayload => {
            const payload = node.cast(ast.Node.PointerIndexPayload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.ptr_token, .operator);
            try writeToken(builder, payload.value_symbol.firstToken(), .variable);
            if (payload.index_symbol) |index_symbol| try writeToken(builder, index_symbol.firstToken(), .variable);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .Else => {
            const else_node = node.cast(ast.Node.Else).?;
            try writeToken(builder, else_node.else_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, else_node.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, else_node.body });
        },
        .Switch => {
            const switch_node = node.cast(ast.Node.Switch).?;
            try writeToken(builder, switch_node.switch_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, switch_node.expr });

            var gap_highlighter = GapHighlighter.init(builder, switch_node.expr.lastToken() + 3);
            for (switch_node.casesConst()) |case_node| {
                try gap_highlighter.next(case_node);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, case_node });
            }
            try gap_highlighter.end(node.lastToken());
        },
        .SwitchCase => {
            const switch_case = node.cast(ast.Node.SwitchCase).?;
            for (switch_case.itemsConst()) |item_node| try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, item_node });
            try writeToken(builder, switch_case.arrow_token, .operator);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, switch_case.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, switch_case.expr });
        },
        .SwitchElse => {
            const switch_else = node.cast(ast.Node.SwitchElse).?;
            try writeToken(builder, switch_else.token, .keyword);
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            try writeToken(builder, while_node.label, .label);
            try writeToken(builder, while_node.inline_token, .keyword);
            try writeToken(builder, while_node.while_token, .keyword);
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.condition });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.payload });
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, while_node.continue_expr });
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
            try writeToken(builder, enum_literal.dot, .tagField);
            try writeToken(builder, enum_literal.name, .tagField);
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
        .BoolLiteral, .NullLiteral, .UndefinedLiteral, .Unreachable, .ErrorType => {
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
        .Add, .AddWrap, .ArrayCat, .ArrayMult, .Assign, .AssignBitAnd, .AssignBitOr, .AssignBitShiftLeft, .AssignBitShiftRight, .AssignBitXor, .AssignDiv, .AssignSub, .AssignSubWrap, .AssignMod, .AssignAdd, .AssignAddWrap, .AssignMul, .AssignMulWrap, .BangEqual, .BitAnd, .BitOr, .BitShiftLeft, .BitShiftRight, .BitXor, .BoolAnd, .BoolOr, .Div, .EqualEqual, .ErrorUnion, .GreaterOrEqual, .GreaterThan, .LessOrEqual, .LessThan, .MergeErrorSets, .Mod, .Mul, .MulWrap, .Period, .Range, .Sub, .SubWrap, .OrElse => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;
            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.lhs });
            if (node.tag != .Period and node.tag != .Catch) {
                const token_type: TokenType = switch (node.tag) {
                    .BoolAnd, .BoolOr, .OrElse => .keyword,
                    else => .operator,
                };

                try writeToken(builder, infix_op.op_token, token_type);
                try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.rhs });
            }
            switch (node.tag) {
                .Catch => {
                    try writeToken(builder, infix_op.op_token, .keyword);
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.lhs });
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, infix_op.rhs });
                },
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
        .AddressOf, .Await, .BitNot, .BoolNot, .OptionalType, .Negation, .NegationWrap, .Resume, .Try => {
            const prefix_op = node.cast(ast.Node.SimplePrefixOp).?;
            const tok_type: TokenType = switch (node.tag) {
                .Try, .Await, .Resume => .keyword,
                else => .operator,
            };

            switch (node.tag) {
                .ArrayType => {
                    const info = node.castTag(.ArrayType).?;
                    try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, info.len_expr });
                },
                .SliceType, .PtrType => {
                    const info = switch (node.tag) {
                        .PtrType => node.castTag(.PtrType).?.ptr_info,
                        .SliceType => node.castTag(.SliceType).?.ptr_info,
                        else => return,
                    };

                    if (node.tag == .PtrType) try writeToken(builder, prefix_op.op_token, tok_type);

                    if (info.align_info) |align_info| {
                        if (node.tag == .PtrType) {
                            try writeToken(builder, prefix_op.op_token + 1, .keyword);
                        } else {
                            try writeToken(builder, prefix_op.op_token + 2, .keyword);
                        }
                        try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, align_info.node });
                    }
                    try writeToken(builder, info.const_token, .keyword);
                    try writeToken(builder, info.volatile_token, .keyword);
                    try writeToken(builder, info.allowzero_token, .keyword);
                },
                else => try writeToken(builder, prefix_op.op_token, tok_type),
            }

            try await @asyncCall(child_frame, {}, writeNodeTokens, .{ builder, arena, store, prefix_op.rhs });
        },
        else => {},
    }
}

// TODO Range version, edit version.
pub fn writeAllSemanticTokens(arena: *std.heap.ArenaAllocator, store: *DocumentStore, handle: *DocumentStore.Handle, encoding: offsets.Encoding) ![]u32 {
    var builder = Builder.init(arena.child_allocator, handle, encoding);
    try writeNodeTokens(&builder, arena, store, &handle.tree.root_node.base);
    return builder.toOwnedSlice();
}
