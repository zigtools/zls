const std = @import("std");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");

const ast = std.zig.ast;

fn renameToken(handle: *DocumentStore.Handle, tok: ast.TokenIndex, new_name: []const u8, edits: *std.ArrayList(types.TextEdit), encoding: offsets.Encoding) !void {
    const loc = offsets.tokenRelativeLocation(handle.tree, 0, tok, encoding) catch return;
    (try edits.addOne()).* = .{
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
        .newText = new_name,
    };
}

pub fn renameLabel(arena: *std.heap.ArenaAllocator, decl: analysis.DeclWithHandle, new_name: []const u8, edits: *std.StringHashMap([]types.TextEdit), encoding: offsets.Encoding) !void {
    std.debug.assert(decl.decl.* == .label_decl);
    const handle = decl.handle;

    var text_edits = std.ArrayList(types.TextEdit).init(&arena.allocator);

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.decl.label_decl.firstToken();
    const last_tok = decl.decl.label_decl.lastToken();

    // The first token is always going to be the label
    try renameToken(handle, first_tok, new_name, &text_edits, encoding);

    var curr_tok = first_tok + 1;
    while (curr_tok < last_tok - 2) : (curr_tok += 1) {
        const curr_id = handle.tree.token_ids[curr_tok];
        if ((curr_id == .Keyword_break or curr_id == .Keyword_continue) and handle.tree.token_ids[curr_tok + 1] == .Colon and
            handle.tree.token_ids[curr_tok + 2] == .Identifier)
        {
            if (std.mem.eql(u8, handle.tree.tokenSlice(curr_tok + 2), handle.tree.tokenSlice(first_tok))) {
                try renameToken(handle, curr_tok + 2, new_name, &text_edits, encoding);
            }
        }
    }

    try edits.putNoClobber(handle.uri(), text_edits.items);
}

fn renameSymbolInternal(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    node_handle: analysis.NodeWithHandle,
    decl: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.ArrayList(types.TextEdit),
    encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const node = node_handle.node;
    const handle = node_handle.handle;

    switch (node.id) {
        .ContainerDecl, .Root, .Block => {
            var idx: usize = 0;
            while (node.iterate(idx)) |child| : (idx += 1) {
                try renameSymbolInternal(arena, store, .{ .node = child, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.type_node) |type_node| {
                try renameSymbolInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, new_name, edits, encoding);
            }
            if (var_decl.init_node) |init_node| {
                try renameSymbolInternal(arena, store, .{ .node = init_node, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .Use => {
            const use = node.cast(ast.Node.Use).?;
            try renameSymbolInternal(arena, store, .{ .node = use.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            if (field.type_expr) |type_node| {
                try renameSymbolInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, new_name, edits, encoding);
            }
            if (field.value_expr) |init_node| {
                try renameSymbolInternal(arena, store, .{ .node = init_node, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .Identifier => {
            if (try analysis.lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.token_locs[node.firstToken()].start)) |child| {
                if (std.meta.eql(decl, child)) {
                    try renameToken(handle, node.firstToken(), new_name, edits, encoding);
                }
            }
        },
        .FnProto => {
            const fn_proto = node.cast(ast.Node.FnProto).?;
            for (fn_proto.paramsConst()) |param| {
                switch (param.param_type) {
                    .type_expr => |type_node| {
                        try renameSymbolInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, new_name, edits, encoding);
                    },
                    else => {},
                }
            }
            switch (fn_proto.return_type) {
                .Explicit, .InferErrorSet => |type_node| {
                    try renameSymbolInternal(arena, store, .{ .node = type_node, .handle = handle }, decl, new_name, edits, encoding);
                },
                else => {},
            }
            if (fn_proto.align_expr) |align_expr| {
                try renameSymbolInternal(arena, store, .{ .node = align_expr, .handle = handle }, decl, new_name, edits, encoding);
            }
            if (fn_proto.section_expr) |section_expr| {
                try renameSymbolInternal(arena, store, .{ .node = section_expr, .handle = handle }, decl, new_name, edits, encoding);
            }
            if (fn_proto.callconv_expr) |callconv_expr| {
                try renameSymbolInternal(arena, store, .{ .node = callconv_expr, .handle = handle }, decl, new_name, edits, encoding);
            }
            if (fn_proto.body_node) |body| {
                try renameSymbolInternal(arena, store, .{ .node = body, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .AnyFrameType => {
            const anyframe_type = node.cast(ast.Node.AnyFrameType).?;
            if (anyframe_type.result) |result| {
                try renameSymbolInternal(arena, store, .{ .node = result.return_type, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .Defer => {
            const defer_node = node.cast(ast.Node.Defer).?;
            try renameSymbolInternal(arena, store, .{ .node = defer_node.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .Comptime => {
            const comptime_node = node.cast(ast.Node.Comptime).?;
            try renameSymbolInternal(arena, store, .{ .node = comptime_node.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .Nosuspend => {
            const nosuspend_node = node.cast(ast.Node.Nosuspend).?;
            try renameSymbolInternal(arena, store, .{ .node = nosuspend_node.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .Switch => {
            // TODO When renaming a union(enum) field, also rename switch items that refer to it.
            const switch_node = node.cast(ast.Node.Switch).?;
            try renameSymbolInternal(arena, store, .{ .node = switch_node.expr, .handle = handle }, decl, new_name, edits, encoding);
            for (switch_node.casesConst()) |case| {
                if (case.*.cast(ast.Node.SwitchCase)) |case_node| {
                    try renameSymbolInternal(arena, store, .{ .node = case_node.expr, .handle = handle }, decl, new_name, edits, encoding);
                }
            }
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            try renameSymbolInternal(arena, store, .{ .node = while_node.condition, .handle = handle }, decl, new_name, edits, encoding);
            if (while_node.continue_expr) |cont_expr| {
                try renameSymbolInternal(arena, store, .{ .node = cont_expr, .handle = handle }, decl, new_name, edits, encoding);
            }
            try renameSymbolInternal(arena, store, .{ .node = while_node.body, .handle = handle }, decl, new_name, edits, encoding);
            if (while_node.@"else") |else_node| {
                try renameSymbolInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            try renameSymbolInternal(arena, store, .{ .node = for_node.array_expr, .handle = handle }, decl, new_name, edits, encoding);
            try renameSymbolInternal(arena, store, .{ .node = for_node.body, .handle = handle }, decl, new_name, edits, encoding);
            if (for_node.@"else") |else_node| {
                try renameSymbolInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            try renameSymbolInternal(arena, store, .{ .node = if_node.condition, .handle = handle }, decl, new_name, edits, encoding);
            try renameSymbolInternal(arena, store, .{ .node = if_node.body, .handle = handle }, decl, new_name, edits, encoding);
            if (if_node.@"else") |else_node| {
                try renameSymbolInternal(arena, store, .{ .node = else_node.body, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .InfixOp => {
            const infix_op = node.cast(ast.Node.InfixOp).?;
            switch (infix_op.op) {
                .Period => {
                    try renameSymbolInternal(arena, store, .{ .node = infix_op.lhs, .handle = handle }, decl, new_name, edits, encoding);

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
                            try renameToken(handle, infix_op.rhs.firstToken(), new_name, edits, encoding);
                        }
                    }
                },
                else => {
                    try renameSymbolInternal(arena, store, .{ .node = infix_op.lhs, .handle = handle }, decl, new_name, edits, encoding);
                    try renameSymbolInternal(arena, store, .{ .node = infix_op.rhs, .handle = handle }, decl, new_name, edits, encoding);
                },
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .ArrayType => |info| {
                    try renameSymbolInternal(arena, store, .{ .node = info.len_expr, .handle = handle }, decl, new_name, edits, encoding);
                    if (info.sentinel) |sentinel| {
                        try renameSymbolInternal(arena, store, .{ .node = sentinel, .handle = handle }, decl, new_name, edits, encoding);
                    }
                },
                .PtrType, .SliceType => |info| {
                    if (info.align_info) |align_info| {
                        try renameSymbolInternal(arena, store, .{ .node = align_info.node, .handle = handle }, decl, new_name, edits, encoding);
                        if (align_info.bit_range) |range| {
                            try renameSymbolInternal(arena, store, .{ .node = range.start, .handle = handle }, decl, new_name, edits, encoding);
                            try renameSymbolInternal(arena, store, .{ .node = range.end, .handle = handle }, decl, new_name, edits, encoding);
                        }
                    }
                    if (info.sentinel) |sentinel| {
                        try renameSymbolInternal(arena, store, .{ .node = sentinel, .handle = handle }, decl, new_name, edits, encoding);
                    }
                },
                else => {},
            }
            try renameSymbolInternal(arena, store, .{ .node = prefix_op.rhs, .handle = handle }, decl, new_name, edits, encoding);
        },
        .FieldInitializer => {
            // TODO Rename field initializer names when needed
            const field_init = node.cast(ast.Node.FieldInitializer).?;
            try renameSymbolInternal(arena, store, .{ .node = field_init.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .ArrayInitializer => {
            const array_init = node.cast(ast.Node.ArrayInitializer).?;
            try renameSymbolInternal(arena, store, .{ .node = array_init.lhs, .handle = handle }, decl, new_name, edits, encoding);
            for (array_init.listConst()) |child| {
                try renameSymbolInternal(arena, store, .{ .node = child, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .ArrayInitializerDot => {
            const array_init = node.cast(ast.Node.ArrayInitializerDot).?;
            for (array_init.listConst()) |child| {
                try renameSymbolInternal(arena, store, .{ .node = child, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .StructInitializer => {
            // TODO Rename field initializer names when needed
            const struct_init = node.cast(ast.Node.StructInitializer).?;
            try renameSymbolInternal(arena, store, .{ .node = struct_init.lhs, .handle = handle }, decl, new_name, edits, encoding);
            for (struct_init.listConst()) |child| {
                try renameSymbolInternal(arena, store, .{ .node = child, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .StructInitializerDot => {
            const struct_init = node.cast(ast.Node.StructInitializerDot).?;
            for (struct_init.listConst()) |child| {
                try renameSymbolInternal(arena, store, .{ .node = child, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            try renameSymbolInternal(arena, store, .{ .node = call.lhs, .handle = handle }, decl, new_name, edits, encoding);
            for (call.paramsConst()) |param| {
                try renameSymbolInternal(arena, store, .{ .node = param, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            try renameSymbolInternal(arena, store, .{ .node = suffix_op.lhs, .handle = handle }, decl, new_name, edits, encoding);
            switch (suffix_op.op) {
                .ArrayAccess => |acc| try renameSymbolInternal(arena, store, .{ .node = acc, .handle = handle }, decl, new_name, edits, encoding),
                .Slice => |sl| {
                    try renameSymbolInternal(arena, store, .{ .node = sl.start, .handle = handle }, decl, new_name, edits, encoding);
                    if (sl.end) |end| {
                        try renameSymbolInternal(arena, store, .{ .node = end, .handle = handle }, decl, new_name, edits, encoding);
                    }
                    if (sl.sentinel) |sentinel| {
                        try renameSymbolInternal(arena, store, .{ .node = sentinel, .handle = handle }, decl, new_name, edits, encoding);
                    }
                },
                else => {},
            }
        },
        .GroupedExpression => {
            const grouped = node.cast(ast.Node.GroupedExpression).?;
            try renameSymbolInternal(arena, store, .{ .node = grouped.expr, .handle = handle }, decl, new_name, edits, encoding);
        },
        .ControlFlowExpression => {
            const cfe = node.cast(ast.Node.ControlFlowExpression).?;
            if (cfe.rhs) |rhs| {
                try renameSymbolInternal(arena, store, .{ .node = rhs, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .Suspend => {
            const suspend_node = node.cast(ast.Node.Suspend).?;
            if (suspend_node.body) |body| {
                try renameSymbolInternal(arena, store, .{ .node = body, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            for (builtin_call.paramsConst()) |param| {
                try renameSymbolInternal(arena, store, .{ .node = param, .handle = handle }, decl, new_name, edits, encoding);
            }
        },
        // TODO Inline asm expr
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            try renameSymbolInternal(arena, store, .{ .node = test_decl.body_node, .handle = handle }, decl, new_name, edits, encoding);
        },
        else => {},
    }
}

pub fn renameSymbol(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    decl_handle: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.StringHashMap([]types.TextEdit),
    encoding: offsets.Encoding,
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
                var text_edits = std.ArrayList(types.TextEdit).init(&arena.allocator);
                if (handle == curr_handle) {
                    try renameToken(curr_handle, decl_handle.nameToken(), new_name, &text_edits, encoding);
                }

                try renameSymbolInternal(arena, store, .{ .node = &handle.tree.root_node.base, .handle = handle }, decl_handle, new_name, &text_edits, encoding);
                if (text_edits.items.len > 0) {
                    try edits.putNoClobber(handle.uri(), text_edits.items);
                }
            }
        },
        .param_decl => |param| {
            var curr_doc_text_edits = std.ArrayList(types.TextEdit).init(&arena.allocator);
            // Rename the param tok.
            try renameToken(curr_handle, decl_handle.nameToken(), new_name, &curr_doc_text_edits, encoding);
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
                std.log.warn(.rename, "Could not find param decl's function", .{});
                return;
            };
            if (fn_node.body_node) |body| {
                try renameSymbolInternal(arena, store, .{ .node = body, .handle = curr_handle }, decl_handle, new_name, &curr_doc_text_edits, encoding);
            }
            try edits.putNoClobber(curr_handle.uri(), curr_doc_text_edits.items);
        },
        .pointer_payload, .array_payload, .switch_payload => {
            var curr_doc_text_edits = std.ArrayList(types.TextEdit).init(&arena.allocator);
            try renameToken(curr_handle, decl_handle.nameToken(), new_name, &curr_doc_text_edits, encoding);
            try renameSymbolInternal(arena, store, .{ .node = &curr_handle.tree.root_node.base, .handle = curr_handle }, decl_handle, new_name, &curr_doc_text_edits, encoding);
            try edits.putNoClobber(curr_handle.uri(), curr_doc_text_edits.items);
        },
        .label_decl => unreachable,
    }
}
