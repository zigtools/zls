const std = @import("std");
const Ast = std.zig.Ast;
const DocumentStore = @import("DocumentStore.zig");
const analysis = @import("analysis.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.references);
const ast = @import("ast.zig");

pub fn labelReferences(
    allocator: std.mem.Allocator,
    decl: analysis.DeclWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
) error{OutOfMemory}!std.ArrayListUnmanaged(types.Location) {
    std.debug.assert(decl.decl.* == .label_decl);
    const handle = decl.handle;
    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = tree.firstToken(decl.decl.label_decl);
    const last_tok = tree.lastToken(decl.decl.label_decl);

    var locations = std.ArrayListUnmanaged(types.Location){};
    errdefer locations.deinit(allocator);

    if (include_decl) {
        // The first token is always going to be the label
        try locations.append(allocator, .{
            .uri = handle.uri(),
            .range = offsets.tokenToRange(handle.tree, first_tok, encoding),
        });
    }

    var curr_tok = first_tok + 1;
    while (curr_tok < last_tok - 2) : (curr_tok += 1) {
        const curr_id = token_tags[curr_tok];

        if (curr_id != .keyword_break and curr_id != .keyword_continue) continue;
        if (token_tags[curr_tok + 1] != .colon) continue;
        if (token_tags[curr_tok + 2] != .identifier) continue;

        if (!std.mem.eql(u8, tree.tokenSlice(curr_tok + 2), tree.tokenSlice(first_tok))) continue;

        try locations.append(allocator, .{
            .uri = handle.uri(),
            .range = offsets.tokenToRange(handle.tree, curr_tok + 2, encoding),
        });
    }

    return locations;
}

fn symbolReferencesInternal(
    arena: *std.heap.ArenaAllocator,
    locations: *std.ArrayListUnmanaged(types.Location),
    store: *DocumentStore,
    node_handle: analysis.NodeWithHandle,
    decl: analysis.DeclWithHandle,
    encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    if (node > tree.nodes.len) return;
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const starts = tree.tokens.items(.start);

    switch (node_tags[node]) {
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node, &buffer).?;

            for (statements) |stmt|
                try symbolReferencesInternal(arena, locations, store, .{ .node = stmt, .handle = handle }, decl, encoding);
        },
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .root,
        .error_set_decl,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            for (ast.declMembers(tree, node, &buf)) |member|
                try symbolReferencesInternal(arena, locations, store, .{ .node = member, .handle = handle }, decl, encoding);
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.varDecl(tree, node).?;
            if (var_decl.ast.type_node != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = var_decl.ast.type_node, .handle = handle }, decl, encoding);
            }
            if (var_decl.ast.init_node != 0) {
                try symbolReferencesInternal(
                    arena,
                    locations,
                    store,
                    .{ .node = var_decl.ast.init_node, .handle = handle },
                    decl,
                    encoding,
                );
            }
        },
        .@"usingnamespace" => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = ast.containerField(tree, node).?;
            if (field.ast.type_expr != 0) {
                try symbolReferencesInternal(
                    arena,
                    locations,
                    store,
                    .{ .node = field.ast.type_expr, .handle = handle },
                    decl,
                    encoding,
                );
            }
            if (field.ast.value_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = field.ast.value_expr, .handle = handle }, decl, encoding);
            }
        },
        .identifier => blk: {
            const child = (try analysis.lookupSymbolGlobal(store, arena, handle, offsets.nodeToSlice(tree, node), starts[main_tokens[node]])) orelse break :blk;
            if (!std.meta.eql(decl, child)) break :blk;
            try locations.append(arena.allocator(), .{
                .uri = handle.uri(),
                .range = offsets.tokenToRange(handle.tree, main_tokens[node], encoding) catch break :blk,
            });
        },
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = ast.fnProto(tree, node, &buf).?;
            var it = fn_proto.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| {
                if (param.type_expr == 0) continue;

                try symbolReferencesInternal(arena, locations, store, .{ .node = param.type_expr, .handle = handle }, decl, encoding);
            }

            if (fn_proto.ast.return_type != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = fn_proto.ast.return_type, .handle = handle }, decl, encoding);
            }
            if (fn_proto.ast.align_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = fn_proto.ast.align_expr, .handle = handle }, decl, encoding);
            }
            if (fn_proto.ast.section_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = fn_proto.ast.section_expr, .handle = handle }, decl, encoding);
            }
            if (fn_proto.ast.callconv_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = fn_proto.ast.callconv_expr, .handle = handle }, decl, encoding);
            }
            if (node_tags[node] == .fn_decl) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
            }
        },
        .anyframe_type => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
        },
        .@"defer" => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
        },
        .@"comptime" => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .@"nosuspend" => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .@"switch",
        .switch_comma,
        => {
            // TODO When renaming a union(enum) field, also rename switch items that refer to it.
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            const extra = tree.extraData(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];
            for (cases) |case| {
                try symbolReferencesInternal(arena, locations, store, .{ .node = case, .handle = handle }, decl, encoding);
            }
        },
        .switch_case_one => {
            const case_one = tree.switchCaseOne(node);
            if (case_one.ast.target_expr != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = case_one.ast.target_expr, .handle = handle }, decl, encoding);
            for (case_one.ast.values) |val|
                try symbolReferencesInternal(arena, locations, store, .{ .node = val, .handle = handle }, decl, encoding);
        },
        .switch_case => {
            const case = tree.switchCase(node);
            if (case.ast.target_expr != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = case.ast.target_expr, .handle = handle }, decl, encoding);
            for (case.ast.values) |val|
                try symbolReferencesInternal(arena, locations, store, .{ .node = val, .handle = handle }, decl, encoding);
        },
        .@"while",
        .while_simple,
        .while_cont,
        .for_simple,
        .@"for",
        => {
            const loop = ast.whileAst(tree, node).?;
            try symbolReferencesInternal(arena, locations, store, .{ .node = loop.ast.cond_expr, .handle = handle }, decl, encoding);
            if (loop.ast.cont_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = loop.ast.cont_expr, .handle = handle }, decl, encoding);
            }
            try symbolReferencesInternal(arena, locations, store, .{ .node = loop.ast.then_expr, .handle = handle }, decl, encoding);
            if (loop.ast.else_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = loop.ast.else_expr, .handle = handle }, decl, encoding);
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.ifFull(tree, node);

            try symbolReferencesInternal(arena, locations, store, .{ .node = if_node.ast.cond_expr, .handle = handle }, decl, encoding);
            try symbolReferencesInternal(arena, locations, store, .{ .node = if_node.ast.then_expr, .handle = handle }, decl, encoding);
            if (if_node.ast.else_expr != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = if_node.ast.else_expr, .handle = handle }, decl, encoding);
            }
        },
        .array_type,
        .array_type_sentinel,
        => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.ptrType(tree, node).?;

            if (ptr_type.ast.align_node != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = ptr_type.ast.align_node, .handle = handle }, decl, encoding);
                if (node_tags[node] == .ptr_type_bit_range) {
                    try symbolReferencesInternal(arena, locations, store, .{ .node = ptr_type.ast.bit_range_start, .handle = handle }, decl, encoding);
                    try symbolReferencesInternal(arena, locations, store, .{ .node = ptr_type.ast.bit_range_end, .handle = handle }, decl, encoding);
                }
            }
            if (ptr_type.ast.sentinel != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = ptr_type.ast.sentinel, .handle = handle }, decl, encoding);
            }

            try symbolReferencesInternal(arena, locations, store, .{ .node = ptr_type.ast.child_type, .handle = handle }, decl, encoding);
        },
        .address_of, .@"await", .bit_not, .bool_not, .optional_type, .negation, .negation_wrap, .@"resume", .@"try" => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .array_init,
        .array_init_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        => |n| {
            var buf: [2]Ast.Node.Index = undefined;
            const array_init = switch (n) {
                .array_init, .array_init_comma => tree.arrayInit(node),
                .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
                .array_init_one, .array_init_one_comma => tree.arrayInitOne(buf[0..1], node),
                .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(&buf, node),
                else => unreachable,
            };
            if (array_init.ast.type_expr != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = array_init.ast.type_expr, .handle = handle }, decl, encoding);
            for (array_init.ast.elements) |e|
                try symbolReferencesInternal(arena, locations, store, .{ .node = e, .handle = handle }, decl, encoding);
        },
        .struct_init,
        .struct_init_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => |n| {
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = switch (n) {
                .struct_init, .struct_init_comma => tree.structInit(node),
                .struct_init_dot, .struct_init_dot_comma => tree.structInitDot(node),
                .struct_init_one, .struct_init_one_comma => tree.structInitOne(buf[0..1], node),
                .struct_init_dot_two, .struct_init_dot_two_comma => tree.structInitDotTwo(&buf, node),
                else => unreachable,
            };
            if (struct_init.ast.type_expr != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = struct_init.ast.type_expr, .handle = handle }, decl, encoding);
            for (struct_init.ast.fields) |field|
                try symbolReferencesInternal(arena, locations, store, .{ .node = field, .handle = handle }, decl, encoding);
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        .async_call,
        .async_call_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const call = ast.callFull(tree, node, &buf).?;

            if (call.ast.fn_expr != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = call.ast.fn_expr, .handle = handle }, decl, encoding);

            for (call.ast.params) |param| {
                try symbolReferencesInternal(arena, locations, store, .{ .node = param, .handle = handle }, decl, encoding);
            }
        },
        .slice,
        .slice_sentinel,
        .slice_open,
        => |s| {
            const slice: Ast.full.Slice = switch (s) {
                .slice => tree.slice(node),
                .slice_open => tree.sliceOpen(node),
                .slice_sentinel => tree.sliceSentinel(node),
                else => unreachable,
            };

            try symbolReferencesInternal(arena, locations, store, .{ .node = slice.ast.sliced, .handle = handle }, decl, encoding);
            try symbolReferencesInternal(arena, locations, store, .{ .node = slice.ast.start, .handle = handle }, decl, encoding);
            if (slice.ast.end != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = slice.ast.end, .handle = handle }, decl, encoding);
            if (slice.ast.sentinel != 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = slice.ast.sentinel, .handle = handle }, decl, encoding);
        },
        .array_access => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
        },
        .deref,
        .unwrap_optional,
        => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .grouped_expression => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
        },
        .@"return",
        .@"break",
        .@"continue",
        => {
            if (datas[node].lhs != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            }
        },
        .@"suspend" => {
            if (datas[node].lhs != 0) {
                try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            }
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            for (params) |param|
                try symbolReferencesInternal(arena, locations, store, .{ .node = param, .handle = handle }, decl, encoding);
        },
        .@"asm",
        .asm_simple,
        => |a| {
            const _asm: Ast.full.Asm = if (a == .@"asm") tree.asmFull(node) else tree.asmSimple(node);
            if (_asm.ast.items.len == 0)
                try symbolReferencesInternal(arena, locations, store, .{ .node = _asm.ast.template, .handle = handle }, decl, encoding);

            for (_asm.inputs) |input|
                try symbolReferencesInternal(arena, locations, store, .{ .node = input, .handle = handle }, decl, encoding);

            for (_asm.outputs) |output|
                try symbolReferencesInternal(arena, locations, store, .{ .node = output, .handle = handle }, decl, encoding);
        },
        .test_decl => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
        },
        .field_access => {
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);

            const rhs_str = ast.tokenSlice(tree, datas[node].rhs) catch return;
            var bound_type_params = analysis.BoundTypeParams{};
            const left_type = try analysis.resolveFieldAccessLhsType(
                store,
                arena,
                (try analysis.resolveTypeOfNodeInternal(store, arena, .{
                    .node = datas[node].lhs,
                    .handle = handle,
                }, &bound_type_params)) orelse return,
                &bound_type_params,
            );

            const left_type_node = switch (left_type.type.data) {
                .other => |n| n,
                else => return,
            };

            const child = (try analysis.lookupSymbolContainer(
                store,
                arena,
                .{ .node = left_type_node, .handle = left_type.handle },
                rhs_str,
                !left_type.type.is_type_val,
            )) orelse return;

            if (!std.meta.eql(child, decl)) return;

            try locations.append(arena.allocator(), .{
                .uri = handle.uri(),
                .range = offsets.tokenToRange(handle.tree, datas[node].rhs, encoding) catch return,
            });
        },
        .add,
        .add_wrap,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shr,
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
        .shl,
        .shr,
        .bit_xor,
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
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].lhs, .handle = handle }, decl, encoding);
            try symbolReferencesInternal(arena, locations, store, .{ .node = datas[node].rhs, .handle = handle }, decl, encoding);
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
    skip_std_references: bool,
    workspace: bool,
) error{OutOfMemory}!std.ArrayListUnmanaged(types.Location) {
    var locations = std.ArrayListUnmanaged(types.Location){};
    errdefer locations.deinit(arena.allocator());

    std.debug.assert(decl_handle.decl.* != .label_decl);
    const curr_handle = decl_handle.handle;
    if (include_decl) {
        try locations.append(arena.allocator(), .{
            .uri = curr_handle.uri(),
            .range = offsets.tokenToRange(curr_handle.tree, decl_handle.nameToken(), encoding) catch return locations,
        });
    }

    switch (decl_handle.decl.*) {
        .ast_node => {
            try symbolReferencesInternal(arena, &locations, store, .{ .node = 0, .handle = curr_handle }, decl_handle, encoding);

            if (!workspace) return locations;

            var imports = std.ArrayListUnmanaged(*DocumentStore.Handle){};

            var handle_it = store.handles.iterator();
            while (handle_it.next()) |entry| {
                if (skip_std_references and std.mem.indexOf(u8, entry.key_ptr.*, "std") != null) {
                    if (!include_decl or entry.value_ptr.* != curr_handle)
                        continue;
                }

                // Check entry's transitive imports
                try imports.append(arena.allocator(), entry.value_ptr.*);
                var i: usize = 0;
                blk: while (i < imports.items.len) : (i += 1) {
                    const import = imports.items[i];
                    for (import.imports_used.items) |uri| {
                        const h = store.getHandle(uri) orelse break;

                        if (h == curr_handle) {
                            // entry does import curr_handle
                            try symbolReferencesInternal(arena, &locations, store, .{ .node = 0, .handle = entry.value_ptr.* }, decl_handle, encoding);
                            break :blk;
                        }

                        select: {
                            for (imports.items) |item| {
                                if (item == h) {
                                    // already checked this import
                                    break :select;
                                }
                            }
                            try imports.append(arena.allocator(), h);
                        }
                    }
                }
                try imports.resize(arena.allocator(), 0);
            }
        },
        .param_decl => |param| {
            // Rename the param tok.
            for (curr_handle.document_scope.scopes.items) |scope| {
                if (scope.data != .function) continue;

                const proto = scope.data.function;

                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = ast.fnProto(curr_handle.tree, proto, &buf).?;

                var it = fn_proto.iterate(&curr_handle.tree);
                while (ast.nextFnParam(&it)) |candidate| {
                    if (!std.meta.eql(candidate, param)) continue;

                    if (curr_handle.tree.nodes.items(.tag)[proto] != .fn_decl) break;
                    try symbolReferencesInternal(
                        arena,
                        &locations,
                        store,
                        .{ .node = curr_handle.tree.nodes.items(.data)[proto].rhs, .handle = curr_handle },
                        decl_handle,
                        encoding,
                    );
                    break;
                }
            }
            log.warn("Could not find param decl's function", .{});
        },
        .pointer_payload, .switch_payload, .array_payload, .array_index => {
            try symbolReferencesInternal(arena, &locations, store, .{ .node = 0, .handle = curr_handle }, decl_handle, encoding);
        },
        .label_decl => unreachable,
    }

    return locations;
}
