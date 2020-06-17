const std = @import("std");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const ast = std.zig.ast;

const TokenType = enum(u32) {
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
    modifier,
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

    fn init(allocator: *std.mem.Allocator, handle: *DocumentStore.Handle) Builder {
        return Builder{
            .handle = handle,
            .current_token = null,
            .arr = std.ArrayList(u32).init(allocator),
        };
    }

    fn add(self: *Builder, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const start_idx = if (self.current_token) |current_token|
            self.handle.tree.token_locs[current_token].start
        else
            0;

        const token_loc = self.handle.tree.token_locs[token];
        const delta_loc = self.handle.tree.tokenLocationLoc(start_idx, token_loc);
        try self.arr.appendSlice(&[_]u32{
            @truncate(u32, delta_loc.line),
            @truncate(u32, delta_loc.column),
            @truncate(u32, token_loc.end - token_loc.start),
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

fn writeTokenResolveType(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, type_node: *ast.Node, tok: ast.TokenIndex, tok_mod: TokenModifiers) !void {
    // Resolve the type of the declaration
    if (try analysis.resolveTypeOfNode(store, arena, .{ .node = type_node, .handle = builder.handle })) |decl_type| {
        if (decl_type.type.is_type_val) {
            const tok_type = if (decl_type.isStructType())
                .@"struct"
            else if (decl_type.isEnumType())
                .@"enum"
            else if (decl_type.isUnionType())
                .@"union"
            else
                TokenType.type;

            try writeTokenMod(builder, tok, tok_type, tok_mod);
        }
    }
}

fn fieldTokenType(container_decl: *ast.Node.ContainerDecl, handle: *DocumentStore.Handle) ?TokenType {
    return @as(?TokenType, switch (handle.tree.token_ids[container_decl.kind_token]) {
        .Keyword_struct => .field,
        .Keyword_union, .Keyword_enum => .tagField,
        else => null,
    });
}

fn writeNodeTokens(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, maybe_node: ?*ast.Node) error{OutOfMemory}!void {
    if (maybe_node == null) return;
    const node = maybe_node.?;
    const handle = builder.handle;

    switch (node.id) {
        .Root, .Block => {
            if (node.cast(ast.Node.Block)) |block_node| {
                try writeToken(builder, block_node.label, .label);
            }

            var previous_end = if (node.id == .Root) 0 else node.firstToken();
            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child| : (child_idx += 1) {
                var i = previous_end;
                while (i < child.firstToken()) : (i += 1) {
                    if (handle.tree.token_ids[i] == .LineComment) {
                        try writeToken(builder, i, .comment);
                    }
                }
                try writeNodeTokens(builder, arena, store, child);
                previous_end = child.lastToken();
            }

            var i = previous_end;
            while (i < node.lastToken()) : (i += 1) {
                if (handle.tree.token_ids[i] == .LineComment) {
                    try writeToken(builder, i, .comment);
                }
            }
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.doc_comments) |doc| try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, var_decl.visib_token, .keyword);
            try writeToken(builder, var_decl.extern_export_token, .keyword);
            try writeToken(builder, var_decl.thread_local_token, .keyword);
            try writeToken(builder, var_decl.comptime_token, .keyword);
            try writeToken(builder, var_decl.mut_token, .keyword);
            try writeTokenResolveType(builder, arena, store, node, var_decl.name_token, .{ .definition = true });
            try writeNodeTokens(builder, arena, store, var_decl.type_node);
            try writeNodeTokens(builder, arena, store, var_decl.align_node);
            try writeNodeTokens(builder, arena, store, var_decl.section_node);
            try writeToken(builder, var_decl.eq_token, .operator);
            try writeNodeTokens(builder, arena, store, var_decl.init_node);
        },
        .Use => {
            const use = node.cast(ast.Node.Use).?;
            if (use.doc_comments) |docs| try writeDocComments(builder, builder.handle.tree, docs);
            try writeToken(builder, use.visib_token, .keyword);
            try writeToken(builder, use.use_token, .keyword);
            try writeNodeTokens(builder, arena, store, use.expr);
        },
        .ErrorSetDecl => {
            const error_set = node.cast(ast.Node.ErrorSetDecl).?;
            try writeToken(builder, error_set.error_token, .keyword);
            for (error_set.declsConst()) |decl| try writeNodeTokens(builder, arena, store, decl);
        },
        .ContainerDecl => {
            const container_decl = node.cast(ast.Node.ContainerDecl).?;
            try writeToken(builder, container_decl.layout_token, .keyword);
            try writeToken(builder, container_decl.kind_token, .keyword);
            switch (container_decl.init_arg_expr) {
                .None => {},
                .Enum => |enum_expr| if (enum_expr) |expr|
                    try writeNodeTokens(builder, arena, store, expr)
                else
                    try writeToken(builder, container_decl.kind_token + 2, .keyword),
                .Type => |type_node| try writeNodeTokens(builder, arena, store, type_node),
            }

            const field_token_type = fieldTokenType(container_decl, handle);
            var previous_end = container_decl.firstToken();
            for (container_decl.fieldsAndDeclsConst()) |child| {
                var i = previous_end;
                while (i < child.firstToken()) : (i += 1) {
                    if (handle.tree.token_ids[i] == .LineComment) {
                        try writeToken(builder, i, .comment);
                    }
                }
                previous_end = child.lastToken();

                if (child.cast(ast.Node.ContainerField)) |container_field| {
                    if (container_field.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
                    try writeToken(builder, container_field.comptime_token, .keyword);
                    if (field_token_type) |tok_type| try writeToken(builder, container_field.name_token, tok_type);
                    try writeNodeTokens(builder, arena, store, container_field.align_expr);
                    try writeNodeTokens(builder, arena, store, container_field.type_expr);

                    if (container_field.value_expr) |value_expr| {
                        const eq_tok: ast.TokenIndex = if (container_field.type_expr) |type_expr|
                            type_expr.lastToken() + 1
                        else if (container_field.align_expr) |align_expr|
                            align_expr.lastToken() + 1
                        else
                            unreachable; // Check this, I believe it is correct.

                        try writeToken(builder, eq_tok, .operator);
                        try writeNodeTokens(builder, arena, store, value_expr);
                    }
                } else {
                    try writeNodeTokens(builder, arena, store, child);
                }
            }

            var i = previous_end;
            while (i < node.lastToken()) : (i += 1) {
                if (handle.tree.token_ids[i] == .LineComment) {
                    try writeToken(builder, i, .comment);
                }
            }
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
                // TODO: Clean this up.
                var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
                if (try child.resolveType(store, arena, &bound_type_params)) |decl_type| {
                    if (decl_type.type.is_type_val) {
                        const tok_type = if (decl_type.isStructType())
                            .@"struct"
                        else if (decl_type.isEnumType())
                            .@"enum"
                        else if (decl_type.isUnionType())
                            .@"union"
                        else
                            TokenType.type;
                        return try writeTokenMod(builder, node.firstToken(), tok_type, .{});
                    }
                }
            }
        },
        .FnProto => {
            const fn_proto = node.cast(ast.Node.FnProto).?;
            if (fn_proto.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, fn_proto.visib_token, .keyword);
            try writeToken(builder, fn_proto.extern_export_inline_token, .keyword);
            try writeNodeTokens(builder, arena, store, fn_proto.lib_name);
            try writeToken(builder, fn_proto.fn_token, .keyword);

            const func_name_tok_type: TokenType = if (analysis.isTypeFunction(handle.tree, fn_proto))
                .type
            else
                .function;
            try writeToken(builder, fn_proto.name_token, func_name_tok_type);

            for (fn_proto.paramsConst()) |param_decl| {
                if (param_decl.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
                try writeToken(builder, param_decl.noalias_token, .keyword);
                try writeToken(builder, param_decl.comptime_token, .keyword);
                try writeTokenMod(builder, param_decl.name_token, .parameter, .{ .definition = true });
                switch (param_decl.param_type) {
                    .var_type => |var_node| try writeToken(builder, var_node.firstToken(), .type),
                    .var_args => |var_args_tok| try writeToken(builder, var_args_tok, .operator),
                    .type_expr => |type_expr| try writeNodeTokens(builder, arena, store, type_expr),
                }
            }
            try writeNodeTokens(builder, arena, store, fn_proto.align_expr);
            try writeNodeTokens(builder, arena, store, fn_proto.section_expr);
            try writeNodeTokens(builder, arena, store, fn_proto.callconv_expr);

            switch (fn_proto.return_type) {
                .Explicit => |type_expr| try writeNodeTokens(builder, arena, store, type_expr),
                .InferErrorSet => |type_expr| {
                    try writeToken(builder, type_expr.firstToken() - 1, .operator);
                    try writeNodeTokens(builder, arena, store, type_expr);
                },
                .Invalid => {},
            }
            try writeNodeTokens(builder, arena, store, fn_proto.body_node);
        },
        .AnyFrameType => {
            const any_frame_type = node.cast(ast.Node.AnyFrameType).?;
            try writeToken(builder, any_frame_type.anyframe_token, .type);
            if (any_frame_type.result) |result| {
                try writeToken(builder, result.arrow_token, .type);
                try writeNodeTokens(builder, arena, store, result.return_type);
            }
        },
        .Defer => {
            const defer_node = node.cast(ast.Node.Defer).?;
            try writeToken(builder, defer_node.defer_token, .keyword);
            try writeNodeTokens(builder, arena, store, defer_node.payload);
            try writeNodeTokens(builder, arena, store, defer_node.expr);
        },
        .Comptime => {
            const comptime_node = node.cast(ast.Node.Comptime).?;
            if (comptime_node.doc_comments) |docs| try writeDocComments(builder, handle.tree, docs);
            try writeToken(builder, comptime_node.comptime_token, .keyword);
            try writeNodeTokens(builder, arena, store, comptime_node.expr);
        },
        .Nosuspend => {
            const nosuspend_node = node.cast(ast.Node.Nosuspend).?;
            try writeToken(builder, nosuspend_node.nosuspend_token, .keyword);
            try writeNodeTokens(builder, arena, store, nosuspend_node.expr);
        },
        .Payload => {
            const payload = node.cast(ast.Node.Payload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .PointerPayload => {
            const payload = node.cast(ast.Node.PointerPayload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.ptr_token, .operator);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .PointerIndexPayload => {
            const payload = node.cast(ast.Node.PointerIndexPayload).?;
            try writeToken(builder, payload.lpipe, .operator);
            try writeToken(builder, payload.ptr_token, .operator);
            try writeToken(builder, payload.rpipe, .operator);
        },
        .Else => {
            const else_node = node.cast(ast.Node.Else).?;
            try writeToken(builder, else_node.else_token, .keyword);
            try writeNodeTokens(builder, arena, store, else_node.payload);
            try writeNodeTokens(builder, arena, store, else_node.body);
        },
        .Switch => {
            const switch_node = node.cast(ast.Node.Switch).?;
            try writeToken(builder, switch_node.switch_token, .keyword);
            try writeNodeTokens(builder, arena, store, switch_node.expr);

            var previous_end = switch_node.firstToken();
            for (switch_node.casesConst()) |case_node| {
                var i = previous_end;
                while (i < case_node.firstToken()) : (i += 1) {
                    if (handle.tree.token_ids[i] == .LineComment) {
                        try writeToken(builder, i, .comment);
                    }
                }
                previous_end = case_node.lastToken();

                try writeNodeTokens(builder, arena, store, case_node);
            }

            var i = previous_end;
            while (i < node.lastToken()) : (i += 1) {
                if (handle.tree.token_ids[i] == .LineComment) {
                    try writeToken(builder, i, .comment);
                }
            }
        },
        .SwitchCase => {
            const switch_case = node.cast(ast.Node.SwitchCase).?;
            for (switch_case.itemsConst()) |item_node| try writeNodeTokens(builder, arena, store, item_node);
            try writeToken(builder, switch_case.arrow_token, .operator);
            try writeNodeTokens(builder, arena, store, switch_case.payload);
            try writeNodeTokens(builder, arena, store, switch_case.expr);
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
            try writeNodeTokens(builder, arena, store, while_node.condition);
            try writeNodeTokens(builder, arena, store, while_node.payload);
            try writeNodeTokens(builder, arena, store, while_node.continue_expr);
            try writeNodeTokens(builder, arena, store, while_node.body);
            if (while_node.@"else") |else_node| try writeNodeTokens(builder, arena, store, &else_node.base);
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            try writeToken(builder, for_node.label, .label);
            try writeToken(builder, for_node.inline_token, .keyword);
            try writeToken(builder, for_node.for_token, .keyword);
            try writeNodeTokens(builder, arena, store, for_node.array_expr);
            try writeNodeTokens(builder, arena, store, for_node.payload);
            try writeNodeTokens(builder, arena, store, for_node.body);
            if (for_node.@"else") |else_node| try writeNodeTokens(builder, arena, store, &else_node.base);
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            try writeToken(builder, if_node.if_token, .keyword);
            try writeNodeTokens(builder, arena, store, if_node.condition);
            try writeNodeTokens(builder, arena, store, if_node.payload);
            try writeNodeTokens(builder, arena, store, if_node.body);
            if (if_node.@"else") |else_node| try writeNodeTokens(builder, arena, store, &else_node.base);
        },
        .InfixOp => {
            const infix_op = node.cast(ast.Node.InfixOp).?;
            // @TODO Im blowing up my stack!
            // try writeNodeTokens(builder, arena, store, infix_op.lhs);
            if (infix_op.op != .Period and infix_op.op != .Catch) {
                const token_type: TokenType = switch (infix_op.op) {
                    .BoolAnd, .BoolOr => .keyword,
                    else => .operator,
                };

                try writeToken(builder, infix_op.op_token, token_type);
                try writeNodeTokens(builder, arena, store, infix_op.rhs);
            }
            if (infix_op.op == .Period) {
                // @TODO Special case for dot access.
                const rhs_str = handle.tree.tokenSlice(infix_op.rhs.firstToken());
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            const tok_type: TokenType = switch (prefix_op.op) {
                .Try, .Await, .Resume => .keyword,
                else => .operator,
            };

            try writeToken(builder, prefix_op.op_token, tok_type);
            switch (prefix_op.op) {
                .ArrayType => |info| {
                    try writeNodeTokens(builder, arena, store, info.len_expr);
                    try writeToken(builder, info.len_expr.lastToken() + 1, tok_type);
                },
                .SliceType, .PtrType => |info| {
                    if (prefix_op.op == .SliceType)
                        try writeToken(builder, prefix_op.op_token + 1, tok_type);

                    if (info.align_info) |align_info| {
                        try writeToken(builder, align_info.node.firstToken() - 2, .keyword);
                    }
                    try writeToken(builder, info.const_token, .keyword);
                    try writeToken(builder, info.volatile_token, .keyword);
                    try writeToken(builder, info.allowzero_token, .keyword);
                },
                else => {},
            }

            try writeNodeTokens(builder, arena, store, prefix_op.rhs);
        },
        .ArrayInitializer => {
            const array_initializer = node.cast(ast.Node.ArrayInitializer).?;
            try writeNodeTokens(builder, arena, store, array_initializer.lhs);
            for (array_initializer.listConst()) |elem| try writeNodeTokens(builder, arena, store, elem);
        },
        .ArrayInitializerDot => {
            const array_initializer = node.cast(ast.Node.ArrayInitializerDot).?;
            for (array_initializer.listConst()) |elem| try writeNodeTokens(builder, arena, store, elem);
        },
        .StructInitializer => {
            const struct_initializer = node.cast(ast.Node.StructInitializer).?;
            try writeNodeTokens(builder, arena, store, struct_initializer.lhs);
            const field_token_type = if (try analysis.resolveTypeOfNode(store, arena, .{ .node = struct_initializer.lhs, .handle = handle })) |struct_type| switch (struct_type.type.data) {
                .other => |type_node| if (type_node.cast(ast.Node.ContainerDecl)) |container_decl|
                    fieldTokenType(container_decl, handle)
                else
                    null,
                else => null,
            } else null;

            for (struct_initializer.listConst()) |field_init_node| {
                std.debug.assert(field_init_node.id == .FieldInitializer);
                const field_init = field_init_node.cast(ast.Node.FieldInitializer).?;
                if (field_token_type) |tok_type| {
                    try writeToken(builder, field_init.period_token, tok_type);
                    try writeToken(builder, field_init.name_token, tok_type);
                }
                try writeToken(builder, field_init.name_token + 1, .operator);
                try writeNodeTokens(builder, arena, store, field_init.expr);
            }
        },
        .StructInitializerDot => {
            const struct_initializer = node.cast(ast.Node.StructInitializerDot).?;
            for (struct_initializer.listConst()) |field_init_node| {
                std.debug.assert(field_init_node.id == .FieldInitializer);
                const field_init = field_init_node.cast(ast.Node.FieldInitializer).?;
                try writeToken(builder, field_init.name_token + 1, .operator);
                try writeNodeTokens(builder, arena, store, field_init.expr);
            }
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            try writeToken(builder, call.async_token, .keyword);
            try writeNodeTokens(builder, arena, store, call.lhs);
            for (call.paramsConst()) |param| try writeNodeTokens(builder, arena, store, param);
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            // @TODO We blow up the stack here as well T_T
            switch (suffix_op.op) {
                // .ArrayAccess => |n| try writeNodeTokens(builder, arena, store, n),
                // .Slice => |s| {
                //     try writeNodeTokens(builder, arena, store, s.start);
                //     try writeToken(builder, s.start.lastToken() + 1, .operator);
                //     try writeNodeTokens(builder, arena, store, s.end);
                //     try writeNodeTokens(builder, arena, store, s.sentinel);
                // },
                else => try writeToken(builder, suffix_op.rtoken, .operator),
            }
        },
        .GroupedExpression => {
            const grouped_expr = node.cast(ast.Node.GroupedExpression).?;
            try writeNodeTokens(builder, arena, store, grouped_expr.expr);
        },
        .ControlFlowExpression => {
            const cfe = node.cast(ast.Node.ControlFlowExpression).?;
            try writeToken(builder, cfe.ltoken, .keyword);
            switch (cfe.kind) {
                .Break => |label| if (label) |n| try writeToken(builder, n.firstToken(), .label),
                .Continue => |label| if (label) |n| try writeToken(builder, n.firstToken(), .label),
                else => {},
            }
            try writeNodeTokens(builder, arena, store, cfe.rhs);
        },
        .Suspend => {
            const suspend_node = node.cast(ast.Node.Suspend).?;
            try writeToken(builder, suspend_node.suspend_token, .keyword);
            try writeNodeTokens(builder, arena, store, suspend_node.body);
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
            for (builtin_call.paramsConst()) |param| try writeNodeTokens(builder, arena, store, param);
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
            try writeNodeTokens(builder, arena, store, asm_expr.template);
            // TODO Inputs, outputs.
        },
        .VarType => {
            try writeToken(builder, node.firstToken(), .type);
        },
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            if (test_decl.doc_comments) |doc| try writeDocComments(builder, handle.tree, doc);
            try writeToken(builder, test_decl.test_token, .keyword);
            try writeNodeTokens(builder, arena, store, test_decl.name);
            try writeNodeTokens(builder, arena, store, test_decl.body_node);
        },
        // TODO Remove this when we handle all nodes.
        else => {},
    }

    // TODO Where we are handling comments, also handle keywords etc.
    // TODO While editing, the current AST node will be invalid and thus will not exist in the tree at all.
    // Scan over the tokens we are not covering at all and color the keywords etc.
}

// TODO Range version, edit version.
pub fn writeAllSemanticTokens(allocator: *std.mem.Allocator, store: *DocumentStore, handle: *DocumentStore.Handle) ![]u32 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var builder = Builder.init(allocator, handle);
    try writeNodeTokens(&builder, &arena, store, &handle.tree.root_node.base);
    return builder.toOwnedSlice();
}
