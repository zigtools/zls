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
    const last_tok = ast.lastToken(tree, decl.decl.label_decl);

    var locations = std.ArrayListUnmanaged(types.Location){};
    errdefer locations.deinit(allocator);

    if (include_decl) {
        // The first token is always going to be the label
        try locations.append(allocator, .{
            .uri = handle.uri,
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
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, curr_tok + 2, encoding),
        });
    }

    return locations;
}

const Builder = struct {
    arena: *std.heap.ArenaAllocator,
    locations: std.ArrayListUnmanaged(types.Location),
    store: *DocumentStore,
    decl: analysis.DeclWithHandle,
    encoding: offsets.Encoding,

    pub fn init(arena: *std.heap.ArenaAllocator, store: *DocumentStore, decl: analysis.DeclWithHandle, encoding: offsets.Encoding) Builder {
        return Builder{
            .arena = arena,
            .locations = .{},
            .store = store,
            .decl = decl,
            .encoding = encoding,
        };
    }

    pub fn add(self: *Builder, handle: *const DocumentStore.Handle, token_index: Ast.TokenIndex) !void {
        try self.locations.append(self.arena.allocator(), .{
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, token_index, self.encoding),
        });
    }
};

fn symbolReferencesInternal(
    builder: *Builder,
    node: Ast.Node.Index,
    handle: *const DocumentStore.Handle,
    is_root: bool,
) error{OutOfMemory}!void {
    const tree = handle.tree;

    if (!is_root and node == 0 or node > tree.nodes.len) return;

    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const starts = tree.tokens.items(.start);

    switch (node_tags[node]) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node, &buffer).?;

            for (statements) |stmt|
                try symbolReferencesInternal(builder, stmt, handle, false);
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
                try symbolReferencesInternal(builder, member, handle, false);
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.varDecl(tree, node).?;
            try symbolReferencesInternal(builder, var_decl.ast.type_node, handle, false);
            try symbolReferencesInternal(builder, var_decl.ast.init_node, handle, false);
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = ast.containerField(tree, node).?;
            try symbolReferencesInternal(builder, field.ast.type_expr, handle, false);
            try symbolReferencesInternal(builder, field.ast.value_expr, handle, false);
        },
        .identifier => {
            const child = (try analysis.lookupSymbolGlobal(builder.store, builder.arena, handle, tree.getNodeSource(node), starts[main_tokens[node]])) orelse return;
            if (std.meta.eql(builder.decl, child)) try builder.add(handle, main_tokens[node]);
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
                try symbolReferencesInternal(builder, param.type_expr, handle, false);
            }

            try symbolReferencesInternal(builder, fn_proto.ast.return_type, handle, false);
            try symbolReferencesInternal(builder, fn_proto.ast.align_expr, handle, false);
            try symbolReferencesInternal(builder, fn_proto.ast.section_expr, handle, false);
            try symbolReferencesInternal(builder, fn_proto.ast.callconv_expr, handle, false);
            if (node_tags[node] == .fn_decl) {
                try symbolReferencesInternal(builder, datas[node].rhs, handle, false);
            }
        },
        .@"switch",
        .switch_comma,
        => {
            // TODO When renaming a union(enum) field, also rename switch items that refer to it.
            try symbolReferencesInternal(builder, datas[node].lhs, handle, false);
            const extra = tree.extraData(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];
            for (cases) |case| {
                try symbolReferencesInternal(builder, case, handle, false);
            }
        },
        .switch_case_one,
        .switch_case_inline_one,
        => {
            const case_one = tree.switchCaseOne(node);
            try symbolReferencesInternal(builder, case_one.ast.target_expr, handle, false);
            for (case_one.ast.values) |val|
                try symbolReferencesInternal(builder, val, handle, false);
        },
        .switch_case,
        .switch_case_inline,
        => {
            const case = tree.switchCase(node);
            try symbolReferencesInternal(builder, case.ast.target_expr, handle, false);
            for (case.ast.values) |val|
                try symbolReferencesInternal(builder, val, handle, false);
        },
        .@"while",
        .while_simple,
        .while_cont,
        .for_simple,
        .@"for",
        => {
            const loop = ast.whileAst(tree, node).?;
            try symbolReferencesInternal(builder, loop.ast.cond_expr, handle, false);
            try symbolReferencesInternal(builder, loop.ast.then_expr, handle, false);
            try symbolReferencesInternal(builder, loop.ast.else_expr, handle, false);
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.ifFull(tree, node);
            try symbolReferencesInternal(builder, if_node.ast.cond_expr, handle, false);
            try symbolReferencesInternal(builder, if_node.ast.then_expr, handle, false);
            try symbolReferencesInternal(builder, if_node.ast.else_expr, handle, false);
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.ptrType(tree, node).?;

            if (ptr_type.ast.align_node != 0) {
                try symbolReferencesInternal(builder, ptr_type.ast.align_node, handle, false);
                if (node_tags[node] == .ptr_type_bit_range) {
                    try symbolReferencesInternal(builder, ptr_type.ast.bit_range_start, handle, false);
                    try symbolReferencesInternal(builder, ptr_type.ast.bit_range_end, handle, false);
                }
            }

            try symbolReferencesInternal(builder, ptr_type.ast.sentinel, handle, false);
            try symbolReferencesInternal(builder, ptr_type.ast.child_type, handle, false);
        },
        .array_init,
        .array_init_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        => |tag| {
            var buf: [2]Ast.Node.Index = undefined;
            const array_init = switch (tag) {
                .array_init, .array_init_comma => tree.arrayInit(node),
                .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
                .array_init_one, .array_init_one_comma => tree.arrayInitOne(buf[0..1], node),
                .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(&buf, node),
                else => unreachable,
            };
            try symbolReferencesInternal(builder, array_init.ast.type_expr, handle, false);
            for (array_init.ast.elements) |e|
                try symbolReferencesInternal(builder, e, handle, false);
        },
        .struct_init,
        .struct_init_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => |tag| {
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = switch (tag) {
                .struct_init, .struct_init_comma => tree.structInit(node),
                .struct_init_dot, .struct_init_dot_comma => tree.structInitDot(node),
                .struct_init_one, .struct_init_one_comma => tree.structInitOne(buf[0..1], node),
                .struct_init_dot_two, .struct_init_dot_two_comma => tree.structInitDotTwo(&buf, node),
                else => unreachable,
            };
            try symbolReferencesInternal(builder, struct_init.ast.type_expr, handle, false);
            for (struct_init.ast.fields) |field|
                try symbolReferencesInternal(builder, field, handle, false);
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

            try symbolReferencesInternal(builder, call.ast.fn_expr, handle, false);

            for (call.ast.params) |param| {
                try symbolReferencesInternal(builder, param, handle, false);
            }
        },
        .slice,
        .slice_sentinel,
        .slice_open,
        => |tag| {
            const slice: Ast.full.Slice = switch (tag) {
                .slice => tree.slice(node),
                .slice_open => tree.sliceOpen(node),
                .slice_sentinel => tree.sliceSentinel(node),
                else => unreachable,
            };

            try symbolReferencesInternal(builder, slice.ast.sliced, handle, false);
            try symbolReferencesInternal(builder, slice.ast.start, handle, false);
            try symbolReferencesInternal(builder, slice.ast.end, handle, false);
            try symbolReferencesInternal(builder, slice.ast.sentinel, handle, false);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            for (params) |param|
                try symbolReferencesInternal(builder, param, handle, false);
        },
        .@"asm",
        .asm_simple,
        => |tag| {
            const full_asm: Ast.full.Asm = if (tag == .@"asm") tree.asmFull(node) else tree.asmSimple(node);
            if (full_asm.ast.items.len == 0)
                try symbolReferencesInternal(builder, full_asm.ast.template, handle, false);

            for (full_asm.inputs) |input|
                try symbolReferencesInternal(builder, input, handle, false);

            for (full_asm.outputs) |output|
                try symbolReferencesInternal(builder, output, handle, false);
        },
        // TODO implement references for asm
        .asm_output => {},
        .asm_input => {},
        .field_access => {
            try symbolReferencesInternal(builder, datas[node].lhs, handle, false);

            const rhs_str = ast.tokenSlice(tree, datas[node].rhs) catch return;
            var bound_type_params = analysis.BoundTypeParams{};
            const left_type = try analysis.resolveFieldAccessLhsType(
                builder.store,
                builder.arena,
                (try analysis.resolveTypeOfNodeInternal(builder.store, builder.arena, .{
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
                builder.store,
                builder.arena,
                .{ .node = left_type_node, .handle = left_type.handle },
                rhs_str,
                !left_type.type.is_type_val,
            )) orelse return;

            if (std.meta.eql(child, builder.decl)) try builder.add(handle, datas[node].rhs);
        },
        .@"usingnamespace",
        .unwrap_optional,
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .deref,
        .@"suspend",
        .@"resume",
        .@"continue",
        .@"break",
        .@"return",
        .grouped_expression,
        .@"comptime",
        .@"nosuspend",
        => try symbolReferencesInternal(builder, datas[node].lhs, handle, false),
        .test_decl,
        .@"errdefer",
        .@"defer",
        .anyframe_type,
        => try symbolReferencesInternal(builder, datas[node].rhs, handle, false),
        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .add_sat,
        .sub_sat,
        .shl,
        .shl_sat,
        .shr,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .array_type,
        .array_type_sentinel,
        .array_access,
        .@"catch",
        .switch_range,
        .error_union,
        => {
            try symbolReferencesInternal(builder, datas[node].lhs, handle, false);
            try symbolReferencesInternal(builder, datas[node].rhs, handle, false);
        },
        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .enum_literal,
        .string_literal,
        .multiline_string_literal,
        .error_value,
        => {},
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
    std.debug.assert(decl_handle.decl.* != .label_decl);

    var builder = Builder.init(arena, store, decl_handle, encoding);

    const curr_handle = decl_handle.handle;
    if (include_decl) try builder.add(curr_handle, decl_handle.nameToken());

    switch (decl_handle.decl.*) {
        .ast_node => {
            try symbolReferencesInternal(&builder, 0, curr_handle, true);

            if (!workspace) return builder.locations;

            var dependencies = std.StringArrayHashMapUnmanaged(void){};

            for (store.handles.values()) |handle| {
                if (skip_std_references and std.mem.indexOf(u8, handle.uri, "std") != null) {
                    if (!include_decl or !std.mem.eql(u8, handle.uri, curr_handle.uri))
                        continue;
                }

                var handle_dependencies = std.ArrayListUnmanaged([]const u8){};
                try store.collectDependencies(store.allocator, handle.*, &handle_dependencies);

                for (handle_dependencies.items) |uri| {
                    try dependencies.put(arena.allocator(), uri, {});
                }
            }

            for (dependencies.keys()) |uri| {
                const handle = store.getHandle(uri) orelse continue;
                try symbolReferencesInternal(&builder, 0, handle, true);
            }
        },
        .pointer_payload,
        .switch_payload,
        .array_payload,
        .array_index,
        => {
            try symbolReferencesInternal(&builder, 0, curr_handle, true);

            return builder.locations;
        },
        .param_payload => |pay| blk: {
            // Rename the param tok.
            const param = pay.param;
            for (curr_handle.document_scope.scopes.items) |scope| {
                if (scope.data != .function) continue;

                const proto = scope.data.function;

                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = ast.fnProto(curr_handle.tree, proto, &buf).?;

                var it = fn_proto.iterate(&curr_handle.tree);
                while (ast.nextFnParam(&it)) |candidate| {
                    if (!std.meta.eql(candidate, param)) continue;

                    if (curr_handle.tree.nodes.items(.tag)[proto] != .fn_decl) break :blk;
                    try symbolReferencesInternal(&builder, curr_handle.tree.nodes.items(.data)[proto].rhs, curr_handle, false);
                    break :blk;
                }
            }
            log.warn("Could not find param decl's function", .{});
        },
        .label_decl => unreachable, // handled separately by labelReferences
    }

    return builder.locations;
}
