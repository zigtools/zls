const std = @import("std");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.references);

const ast = std.zig.ast;

fn tokenReference(
    handle: *DocumentStore.Handle,
    tok: ast.TokenIndex,
    encoding: offsets.Encoding,
    context: anytype,
    comptime handler: anytype,
) !void {
    const loc = offsets.tokenRelativeLocation(handle.tree, 0, tok, encoding) catch return;
    try handler(context, types.Location{
        .uri = handle.uri(),
        .range = .{
            .start = .{
                .line = @intCast(types.Integer, loc.line),
                .character = @intCast(types.Integer, loc.column),
            },
            .end = .{
                .line = @intCast(types.Integer, loc.line),
                .character = @intCast(types.Integer, loc.column + offsets.tokenLength(handle.tree, tok, encoding)),
            },
        },
    });
}

pub fn labelReferences(
    arena: *std.heap.ArenaAllocator,
    decl: analysis.DeclWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
    context: anytype,
    comptime handler: anytype,
) !void {
    std.debug.assert(decl.decl.* == .label_decl);
    const handle = decl.handle;

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.decl.label_decl.firstToken();
    const last_tok = decl.decl.label_decl.lastToken();

    if (include_decl) {
        // The first token is always going to be the label
        try tokenReference(handle, first_tok, encoding, context, handler);
    }

    var curr_tok = first_tok + 1;
    while (curr_tok < last_tok - 2) : (curr_tok += 1) {
        const curr_id = handle.tree.token_ids[curr_tok];
        if ((curr_id == .Keyword_break or curr_id == .Keyword_continue) and handle.tree.token_ids[curr_tok + 1] == .Colon and
            handle.tree.token_ids[curr_tok + 2] == .Identifier)
        {
            if (std.mem.eql(u8, handle.tree.tokenSlice(curr_tok + 2), handle.tree.tokenSlice(first_tok))) {
                try tokenReference(handle, first_tok, encoding, context, handler);
            }
        }
    }
}

fn symbolReferencesInternal(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    node_handle: analysis.NodeWithHandle,
    decl: analysis.DeclWithHandle,
    encoding: offsets.Encoding,
    context: anytype,
    comptime handler: anytype,
) error{OutOfMemory}!void {
    const node = node_handle.node;
    const handle = node_handle.handle;

    switch (node.tag) {
        .ContainerDecl, .Root, .Block => {
            var idx: usize = 0;
            while (node.iterate(idx)) |child| : (idx += 1) {
                try symbolReferencesInternal(arena, store, .{ .node = child, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.getTrailer("type_node")) |type_node| {
                try symbolReferencesInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, encoding, context, handler);
            }
            if (var_decl.getTrailer("init_node")) |init_node| {
                try symbolReferencesInternal(arena, store, .{ .node = init_node, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Use => {
            const use = node.cast(ast.Node.Use).?;
            try symbolReferencesInternal(arena, store, .{ .node = use.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            if (field.type_expr) |type_node| {
                try symbolReferencesInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, encoding, context, handler);
            }
            if (field.value_expr) |init_node| {
                try symbolReferencesInternal(arena, store, .{ .node = init_node, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Identifier => {
            if (try analysis.lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.token_locs[node.firstToken()].start)) |child| {
                if (std.meta.eql(decl, child)) {
                    try tokenReference(handle, node.firstToken(), encoding, context, handler);
                }
            }
        },
        .FnProto => {
            const fn_proto = node.cast(ast.Node.FnProto).?;
            for (fn_proto.paramsConst()) |param| {
                switch (param.param_type) {
                    .type_expr => |type_node| {
                        try symbolReferencesInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, encoding, context, handler);
                    },
                    else => {},
                }
            }
            switch (fn_proto.return_type) {
                .Explicit, .InferErrorSet => |type_node| {
                    try symbolReferencesInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, encoding, context, handler);
                },
                else => {},
            }
            if (fn_proto.getTrailer("align_expr")) |align_expr| {
                try symbolReferencesInternal(arena, store, .{ .node = align_expr, .handle = handle }, decl, encoding, context, handler);
            }
            if (fn_proto.getTrailer("section_expr")) |section_expr| {
                try symbolReferencesInternal(arena, store, .{ .node = section_expr, .handle = handle }, decl, encoding, context, handler);
            }
            if (fn_proto.getTrailer("callconv_expr")) |callconv_expr| {
                try symbolReferencesInternal(arena, store, .{ .node = callconv_expr, .handle = handle }, decl, encoding, context, handler);
            }
            if (fn_proto.getTrailer("body_node")) |body| {
                try symbolReferencesInternal(arena, store, .{ .node = body, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .AnyFrameType => {
            const anyframe_type = node.cast(ast.Node.AnyFrameType).?;
            if (anyframe_type.result) |result| {
                try symbolReferencesInternal(arena, store, .{ .node = result.return_type, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Defer => {
            const defer_node = node.cast(ast.Node.Defer).?;
            try symbolReferencesInternal(arena, store, .{ .node = defer_node.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .Comptime => {
            const comptime_node = node.cast(ast.Node.Comptime).?;
            try symbolReferencesInternal(arena, store, .{ .node = comptime_node.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .Nosuspend => {
            const nosuspend_node = node.cast(ast.Node.Nosuspend).?;
            try symbolReferencesInternal(arena, store, .{ .node = nosuspend_node.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .Switch => {
            // TODO When renaming a union(enum) field, also rename switch items that refer to it.
            const switch_node = node.cast(ast.Node.Switch).?;
            try symbolReferencesInternal(arena, store, .{ .node = switch_node.expr, .handle = handle }, decl, encoding, context, handler);
            for (switch_node.casesConst()) |case| {
                if (case.*.cast(ast.Node.SwitchCase)) |case_node| {
                    try symbolReferencesInternal(arena, store, .{ .node = case_node.expr, .handle = handle }, decl, encoding, context, handler);
                }
            }
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            try symbolReferencesInternal(arena, store, .{ .node = while_node.condition, .handle = handle }, decl, encoding, context, handler);
            if (while_node.continue_expr) |cont_expr| {
                try symbolReferencesInternal(arena, store, .{ .node = cont_expr, .handle = handle }, decl, encoding, context, handler);
            }
            try symbolReferencesInternal(arena, store, .{ .node = while_node.body, .handle = handle }, decl, encoding, context, handler);
            if (while_node.@"else") |else_node| {
                try symbolReferencesInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            try symbolReferencesInternal(arena, store, .{ .node = for_node.array_expr, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = for_node.body, .handle = handle }, decl, encoding, context, handler);
            if (for_node.@"else") |else_node| {
                try symbolReferencesInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            try symbolReferencesInternal(arena, store, .{ .node = if_node.condition, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = if_node.body, .handle = handle }, decl, encoding, context, handler);
            if (if_node.@"else") |else_node| {
                try symbolReferencesInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .ArrayType => {
            const info = node.castTag(.ArrayType).?;
            try symbolReferencesInternal(arena, store, .{ .node = info.len_expr, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = info.rhs, .handle = handle }, decl, encoding, context, handler);
        },
        .ArrayTypeSentinel => {
            const info = node.castTag(.ArrayTypeSentinel).?;
            try symbolReferencesInternal(arena, store, .{ .node = info.len_expr, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = info.sentinel, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = info.rhs, .handle = handle }, decl, encoding, context, handler);
        },
        .PtrType, .SliceType => {
            const info = switch (node.tag) {
                .PtrType => node.castTag(.PtrType).?.ptr_info,
                .SliceType => node.castTag(.SliceType).?.ptr_info,
                else => unreachable,
            };

            if (info.align_info) |align_info| {
                try symbolReferencesInternal(arena, store, .{ .node = align_info.node, .handle = handle }, decl, encoding, context, handler);
                if (align_info.bit_range) |range| {
                    try symbolReferencesInternal(arena, store, .{ .node = range.start, .handle = handle }, decl, encoding, context, handler);
                    try symbolReferencesInternal(arena, store, .{ .node = range.end, .handle = handle }, decl, encoding, context, handler);
                }
            }
            if (info.sentinel) |sentinel| {
                try symbolReferencesInternal(arena, store, .{ .node = sentinel, .handle = handle }, decl, encoding, context, handler);
            }
            switch (node.tag) {
                .PtrType => try symbolReferencesInternal(arena, store, .{ .node = node.castTag(.PtrType).?.rhs, .handle = handle }, decl, encoding, context, handler),
                .SliceType => try symbolReferencesInternal(arena, store, .{ .node = node.castTag(.SliceType).?.rhs, .handle = handle }, decl, encoding, context, handler),
                else => unreachable,
            }
        },
        .AddressOf, .Await, .BitNot, .BoolNot, .OptionalType, .Negation, .NegationWrap, .Resume, .Try => {
            const prefix_op = node.cast(ast.Node.SimplePrefixOp).?;
            try symbolReferencesInternal(arena, store, .{ .node = prefix_op.rhs, .handle = handle }, decl, encoding, context, handler);
        },
        .FieldInitializer => {
            // TODO Rename field initializer names when needed
            const field_init = node.cast(ast.Node.FieldInitializer).?;
            try symbolReferencesInternal(arena, store, .{ .node = field_init.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .ArrayInitializer => {
            const array_init = node.cast(ast.Node.ArrayInitializer).?;
            try symbolReferencesInternal(arena, store, .{ .node = array_init.lhs, .handle = handle }, decl, encoding, context, handler);
            for (array_init.listConst()) |child| {
                try symbolReferencesInternal(arena, store, .{ .node = child, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .ArrayInitializerDot => {
            const array_init = node.cast(ast.Node.ArrayInitializerDot).?;
            for (array_init.listConst()) |child| {
                try symbolReferencesInternal(arena, store, .{ .node = child, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .StructInitializer => {
            // TODO Rename field initializer names when needed
            const struct_init = node.cast(ast.Node.StructInitializer).?;
            try symbolReferencesInternal(arena, store, .{ .node = struct_init.lhs, .handle = handle }, decl, encoding, context, handler);
            for (struct_init.listConst()) |child| {
                try symbolReferencesInternal(arena, store, .{ .node = child, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .StructInitializerDot => {
            const struct_init = node.cast(ast.Node.StructInitializerDot).?;
            for (struct_init.listConst()) |child| {
                try symbolReferencesInternal(arena, store, .{ .node = child, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            try symbolReferencesInternal(arena, store, .{ .node = call.lhs, .handle = handle }, decl, encoding, context, handler);
            for (call.paramsConst()) |param| {
                try symbolReferencesInternal(arena, store, .{ .node = param, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Slice => {
            const slice = node.castTag(.Slice).?;
            try symbolReferencesInternal(arena, store, .{ .node = slice.lhs, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = slice.start, .handle = handle }, decl, encoding, context, handler);
            if (slice.end) |end| {
                try symbolReferencesInternal(arena, store, .{ .node = end, .handle = handle }, decl, encoding, context, handler);
            }
            if (slice.sentinel) |sentinel| {
                try symbolReferencesInternal(arena, store, .{ .node = sentinel, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .ArrayAccess => {
            const arr_acc = node.castTag(.ArrayAccess).?;
            try symbolReferencesInternal(arena, store, .{ .node = arr_acc.lhs, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = arr_acc.index_expr, .handle = handle }, decl, encoding, context, handler);
        },
        .Deref, .UnwrapOptional => {
            const suffix = node.cast(ast.Node.SimpleSuffixOp).?;
            try symbolReferencesInternal(arena, store, .{ .node = suffix.lhs, .handle = handle }, decl, encoding, context, handler);
        },
        .GroupedExpression => {
            const grouped = node.cast(ast.Node.GroupedExpression).?;
            try symbolReferencesInternal(arena, store, .{ .node = grouped.expr, .handle = handle }, decl, encoding, context, handler);
        },
        .Return, .Break, .Continue => {
            const cfe = node.cast(ast.Node.ControlFlowExpression).?;
            if (cfe.getRHS()) |rhs| {
                try symbolReferencesInternal(arena, store, .{ .node = rhs, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .Suspend => {
            const suspend_node = node.cast(ast.Node.Suspend).?;
            if (suspend_node.body) |body| {
                try symbolReferencesInternal(arena, store, .{ .node = body, .handle = handle }, decl, encoding, context, handler);
            }
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            for (builtin_call.paramsConst()) |param| {
                try symbolReferencesInternal(arena, store, .{ .node = param, .handle = handle }, decl, encoding, context, handler);
            }
        },
        // TODO Inline asm expr
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            try symbolReferencesInternal(arena, store, .{ .node = test_decl.body_node, .handle = handle }, decl, encoding, context, handler);
        },
        .Period => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;

            try symbolReferencesInternal(arena, store, .{ .node = infix_op.lhs, .handle = handle }, decl, encoding, context, handler);

            const rhs_str = analysis.nodeToString(handle.tree, infix_op.rhs) orelse return;
            var bound_type_params = analysis.BoundTypeParams.init(&arena.allocator);
            const left_type = try analysis.resolveFieldAccessLhsType(
                store,
                arena,
                (try analysis.resolveTypeOfNodeInternal(store, arena, .{
                    .node = infix_op.lhs,
                    .handle = handle,
                }, &bound_type_params)) orelse return,
                &bound_type_params,
            );

            const left_type_node = switch (left_type.type.data) {
                .other => |n| n,
                else => return,
            };

            if (try analysis.lookupSymbolContainer(
                store,
                arena,
                .{ .node = left_type_node, .handle = left_type.handle },
                rhs_str,
                !left_type.type.is_type_val,
            )) |child| {
                if (std.meta.eql(child, decl)) {
                    try tokenReference(handle, infix_op.rhs.firstToken(), encoding, context, handler);
                }
            }
        },
        .Add, .AddWrap, .ArrayCat, .ArrayMult, .Assign, .AssignBitAnd, .AssignBitOr, .AssignBitShiftLeft, .AssignBitShiftRight, .AssignBitXor, .AssignDiv, .AssignSub, .AssignSubWrap, .AssignMod, .AssignAdd, .AssignAddWrap, .AssignMul, .AssignMulWrap, .BangEqual, .BitAnd, .BitOr, .BitShiftLeft, .BitShiftRight, .BitXor, .BoolOr, .Div, .EqualEqual, .ErrorUnion, .GreaterOrEqual, .GreaterThan, .LessOrEqual, .LessThan, .MergeErrorSets, .Mod, .Mul, .MulWrap, .Range, .Sub, .SubWrap, .OrElse => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;

            try symbolReferencesInternal(arena, store, .{ .node = infix_op.lhs, .handle = handle }, decl, encoding, context, handler);
            try symbolReferencesInternal(arena, store, .{ .node = infix_op.rhs, .handle = handle }, decl, encoding, context, handler);
        },
        else => {},
    }
}

pub fn symbolReferences(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    decl_handle: analysis.DeclWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
    context: anytype,
    comptime handler: anytype,
) !void {
    std.debug.assert(decl_handle.decl.* != .label_decl);
    const curr_handle = decl_handle.handle;

    switch (decl_handle.decl.*) {
        .ast_node => |decl_node| {
            var handles = std.ArrayList(*DocumentStore.Handle).init(&arena.allocator);
            var handle_it = store.handles.iterator();
            while (handle_it.next()) |entry| {
                try handles.append(entry.value);
            }
            for (handles.items) |handle| {
                if (include_decl and handle == curr_handle) {
                    try tokenReference(curr_handle, decl_handle.nameToken(), encoding, context, handler);
                }

                try symbolReferencesInternal(arena, store, .{ .node = &handle.tree.root_node.base, .handle = handle }, decl_handle, encoding, context, handler);
            }
        },
        .param_decl => |param| {
            // Rename the param tok.
            if (include_decl) {
                try tokenReference(curr_handle, decl_handle.nameToken(), encoding, context, handler);
            }
            const fn_node = loop: for (curr_handle.document_scope.scopes) |scope| {
                switch (scope.data) {
                    .function => |proto| {
                        const fn_proto = proto.cast(std.zig.ast.Node.FnProto).?;
                        for (fn_proto.paramsConst()) |*candidate| {
                            if (candidate == param)
                                break :loop fn_proto;
                        }
                    },
                    else => {},
                }
            } else {
                log.warn("Could not find param decl's function", .{});
                return;
            };
            if (fn_node.getTrailer("body_node")) |body| {
                try symbolReferencesInternal(arena, store, .{ .node = body, .handle = curr_handle }, decl_handle, encoding, context, handler);
            }
        },
        .pointer_payload, .array_payload, .switch_payload => {
            if (include_decl) {
                try tokenReference(curr_handle, decl_handle.nameToken(), encoding, context, handler);
            }
            try symbolReferencesInternal(arena, store, .{ .node = &curr_handle.tree.root_node.base, .handle = curr_handle }, decl_handle, encoding, context, handler);
        },
        .label_decl => unreachable,
    }
}
