const std = @import("std");
const zig_builtin = @import("builtin");
const DocumentStore = @import("DocumentStore.zig");
const analysis = @import("analysis.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");
const Ast = std.zig.Ast;
const log = std.log.scoped(.inlay_hint);
const ast = @import("ast.zig");
const data = @import("data/data.zig");
const Config = @import("Config.zig");

/// don't show inlay hints for the given builtin functions
/// builtins with one parameter are skipped automatically
/// this option is rare and is therefore build-only and
/// non-configurable at runtime
pub const inlay_hints_exclude_builtins: []const u8 = &.{};

/// max number of children in a declaration/array-init/struct-init or similar
/// that will not get a visibility check
pub const inlay_hints_max_inline_children = 12;

/// checks whether node is inside the range
fn isNodeInRange(tree: Ast, node: Ast.Node.Index, range: types.Range) bool {
    const endLocation = tree.tokenLocation(0, tree.lastToken(node));
    if (endLocation.line < range.start.line) return false;

    const beginLocation = tree.tokenLocation(0, tree.firstToken(node));
    if (beginLocation.line > range.end.line) return false;

    return true;
}

const Builder = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    handle: *const DocumentStore.Handle,
    hints: std.ArrayListUnmanaged(types.InlayHint),
    hover_kind: types.MarkupContent.Kind,
    encoding: offsets.Encoding,

    fn deinit(self: *Builder) void {
        for (self.hints.items) |hint| {
            self.allocator.free(hint.tooltip.value);
        }
        self.hints.deinit(self.allocator);
    }

    fn appendParameterHint(self: *Builder, position: types.Position, label: []const u8, tooltip: []const u8, tooltip_noalias: bool, tooltip_comptime: bool) !void {
        // TODO allocation could be avoided by extending InlayHint.jsonStringify
        // adding tooltip_noalias & tooltip_comptime to InlayHint should be enough
        const tooltip_text = blk: {
            if (tooltip.len == 0) break :blk "";
            const prefix = if (tooltip_noalias) if (tooltip_comptime) "noalias comptime " else "noalias " else if (tooltip_comptime) "comptime " else "";

            if (self.hover_kind == .Markdown) {
                break :blk try std.fmt.allocPrint(self.allocator, "```zig\n{s}{s}\n```", .{ prefix, tooltip });
            }

            break :blk try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ prefix, tooltip });
        };

        try self.hints.append(self.allocator, .{
            .position = position,
            .label = label,
            .kind = types.InlayHintKind.Parameter,
            .tooltip = .{
                .kind = self.hover_kind,
                .value = tooltip_text,
            },
            .paddingLeft = false,
            .paddingRight = true,
        });
    }

    fn toOwnedSlice(self: *Builder) error{OutOfMemory}![]types.InlayHint {
        return self.hints.toOwnedSlice(self.allocator);
    }
};

/// `call` is the function call
/// `decl_handle` should be a function protototype
/// writes parameter hints into `builder.hints`
fn writeCallHint(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, call: Ast.full.Call, decl_handle: analysis.DeclWithHandle) !void {
    const handle = builder.handle;
    const tree = handle.tree;

    const decl = decl_handle.decl;
    const decl_tree = decl_handle.handle.tree;

    switch (decl.*) {
        .ast_node => |fn_node| {
            var buffer: [1]Ast.Node.Index = undefined;
            if (ast.fnProto(decl_tree, fn_node, &buffer)) |fn_proto| {
                var i: usize = 0;
                var it = fn_proto.iterate(&decl_tree);

                if (try analysis.hasSelfParam(arena, store, decl_handle.handle, fn_proto)) {
                    _ = ast.nextFnParam(&it);
                }

                while (ast.nextFnParam(&it)) |param| : (i += 1) {
                    if (i >= call.ast.params.len) break;
                    const name_token = param.name_token orelse continue;
                    const name = decl_tree.tokenSlice(name_token);

                    if (builder.config.inlay_hints_hide_redundant_param_names or builder.config.inlay_hints_hide_redundant_param_names_last_token) {
                        const last_param_token = tree.lastToken(call.ast.params[i]);
                        const param_name = tree.tokenSlice(last_param_token);

                        if (std.mem.eql(u8, param_name, name)) {
                            if (tree.firstToken(call.ast.params[i]) == last_param_token) {
                                if (builder.config.inlay_hints_hide_redundant_param_names)
                                    continue;
                            } else {
                                if (builder.config.inlay_hints_hide_redundant_param_names_last_token)
                                    continue;
                            }
                        }
                    }

                    const token_tags = decl_tree.tokens.items(.tag);

                    const no_alias = if (param.comptime_noalias) |t| token_tags[t] == .keyword_noalias or token_tags[t - 1] == .keyword_noalias else false;
                    const comp_time = if (param.comptime_noalias) |t| token_tags[t] == .keyword_comptime or token_tags[t - 1] == .keyword_comptime else false;

                    const tooltip = if (param.anytype_ellipsis3) |token|
                        if (token_tags[token] == .keyword_anytype) "anytype" else ""
                    else
                        offsets.nodeToSlice(decl_tree, param.type_expr);

                    try builder.appendParameterHint(
                        offsets.tokenToPosition(tree, tree.firstToken(call.ast.params[i]), builder.encoding),
                        name,
                        tooltip,
                        no_alias,
                        comp_time,
                    );
                }
            }
        },
        else => {},
    }
}

/// takes parameter nodes from the ast and function parameter names from `Builtin.arguments` and writes parameter hints into `builder.hints`
fn writeBuiltinHint(builder: *Builder, parameters: []const Ast.Node.Index, arguments: []const []const u8) !void {
    if (parameters.len == 0) return;

    const handle = builder.handle;
    const tree = handle.tree;

    for (arguments) |arg, i| {
        if (i >= parameters.len) break;
        if (arg.len == 0) continue;

        const colonIndex = std.mem.indexOfScalar(u8, arg, ':');
        const type_expr: []const u8 = if (colonIndex) |index| arg[index + 1 ..] else &.{};

        var label: ?[]const u8 = null;
        var no_alias = false;
        var comp_time = false;

        var it = std.mem.split(u8, arg[0 .. colonIndex orelse arg.len], " ");
        while (it.next()) |item| {
            if (item.len == 0) continue;
            label = item;

            no_alias = no_alias or std.mem.eql(u8, item, "noalias");
            comp_time = comp_time or std.mem.eql(u8, item, "comptime");
        }

        try builder.appendParameterHint(
            offsets.tokenToPosition(tree, tree.firstToken(parameters[i]), builder.encoding),
            label orelse "",
            std.mem.trim(u8, type_expr, " \t\n"),
            no_alias,
            comp_time,
        );
    }
}

/// takes a Ast.full.Call (a function call), analysis its function expression, finds its declaration and writes parameter hints into `builder.hints`
fn writeCallNodeHint(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, call: Ast.full.Call) !void {
    if (call.ast.params.len == 0) return;
    if (builder.config.inlay_hints_exclude_single_argument and call.ast.params.len == 1) return;

    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    switch (node_tags[call.ast.fn_expr]) {
        .identifier => {
            const location = tree.tokenLocation(0, main_tokens[call.ast.fn_expr]);

            const absolute_index = location.line_start + location.column;

            const name = tree.tokenSlice(main_tokens[call.ast.fn_expr]);

            if (try analysis.lookupSymbolGlobal(store, arena, handle, name, absolute_index)) |decl_handle| {
                try writeCallHint(builder, arena, store, call, decl_handle);
            }
        },
        .field_access => {
            const lhsToken = tree.firstToken(call.ast.fn_expr);
            const rhsToken = node_data[call.ast.fn_expr].rhs;
            std.debug.assert(token_tags[rhsToken] == .identifier);

            const start = offsets.tokenToIndex(tree, lhsToken);
            const rhs_loc = offsets.tokenToLoc(tree, rhsToken);

            var held_range = try arena.allocator().dupeZ(u8, handle.text[start..rhs_loc.end]);
            var tokenizer = std.zig.Tokenizer.init(held_range);

            // note: we have the ast node, traversing it would probably yield better results
            // than trying to re-tokenize and re-parse it
            if (try analysis.getFieldAccessType(store, arena, handle, rhs_loc.end, &tokenizer)) |result| {
                const container_handle = result.unwrapped orelse result.original;
                switch (container_handle.type.data) {
                    .other => |container_handle_node| {
                        if (try analysis.lookupSymbolContainer(
                            store,
                            arena,
                            .{ .node = container_handle_node, .handle = container_handle.handle },
                            tree.tokenSlice(rhsToken),
                            true,
                        )) |decl_handle| {
                            try writeCallHint(builder, arena, store, call, decl_handle);
                        }
                    },
                    else => {},
                }
            }
        },
        else => {
            log.debug("cannot deduce fn expression with tag '{}'", .{node_tags[call.ast.fn_expr]});
        },
    }
}

/// HACK self-hosted has not implemented async yet
fn callWriteNodeInlayHint(allocator: std.mem.Allocator, args: anytype) error{OutOfMemory}!void {
    if (zig_builtin.zig_backend == .other or zig_builtin.zig_backend == .stage1) {
        const FrameSize = @sizeOf(@Frame(writeNodeInlayHint));
        var child_frame = try allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
        defer allocator.free(child_frame);

        return await @asyncCall(child_frame, {}, writeNodeInlayHint, args);
    } else {
        // TODO find a non recursive solution
        return @call(.{}, writeNodeInlayHint, args);
    }
}

/// iterates over the ast and writes parameter hints into `builder.hints` for every function call and builtin call
/// nodes outside the given range are excluded
fn writeNodeInlayHint(builder: *Builder, arena: *std.heap.ArenaAllocator, store: *DocumentStore, maybe_node: ?Ast.Node.Index, range: types.Range) error{OutOfMemory}!void {
    const node = maybe_node orelse return;

    const handle = builder.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    if (node == 0 or node > node_data.len) return;

    var allocator = arena.allocator();

    const tag = node_tags[node];

    // NOTE traversing the ast instead of iterating over all nodes allows using visibility
    // checks based on the given range which reduce runtimes by orders of magnitude for large files
    switch (tag) {
        .root => unreachable,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => {
            var params: [1]Ast.Node.Index = undefined;
            const call = ast.callFull(tree, node, &params).?;
            try writeCallNodeHint(builder, arena, store, call);

            for (call.ast.params) |param| {
                if (call.ast.params.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, param, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, param, range });
            }
        },

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            if (builder.config.inlay_hints_show_builtin and params.len > 1) {
                const name = tree.tokenSlice(main_tokens[node]);

                outer: for (data.builtins) |builtin| {
                    if (!std.mem.eql(u8, builtin.name, name)) continue;

                    for (inlay_hints_exclude_builtins) |builtin_name| {
                        if (std.mem.eql(u8, builtin_name, name)) break :outer;
                    }

                    try writeBuiltinHint(builder, params, builtin.arguments);
                }
            }

            for (params) |param| {
                if (params.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, param, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, param, range });
            }
        },

        .optional_type,
        .array_type,
        .@"continue",
        .anyframe_type,
        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .identifier,
        .enum_literal,
        .string_literal,
        .multiline_string_literal,
        .error_set_decl,
        => {},

        .array_type_sentinel => {
            const array_type = tree.arrayTypeSentinel(node);

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, array_type.ast.sentinel, range });
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const ptr_type: Ast.full.PtrType = ast.ptrType(tree, node).?;

            if (ptr_type.ast.sentinel != 0) {
                return try callWriteNodeInlayHint(allocator, .{ builder, arena, store, ptr_type.ast.sentinel, range });
            }

            if (ptr_type.ast.align_node != 0) {
                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, ptr_type.ast.align_node, range });

                if (ptr_type.ast.bit_range_start != 0) {
                    try callWriteNodeInlayHint(allocator, .{ builder, arena, store, ptr_type.ast.bit_range_start, range });
                    try callWriteNodeInlayHint(allocator, .{ builder, arena, store, ptr_type.ast.bit_range_end, range });
                }
            }

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, ptr_type.ast.child_type, range });
        },

        .@"usingnamespace",
        .field_access,
        .unwrap_optional,
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .deref,
        .@"suspend",
        .@"resume",
        .@"return",
        .grouped_expression,
        .@"comptime",
        .@"nosuspend",
        => try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].lhs, range }),

        .test_decl,
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        .@"errdefer",
        .@"defer",
        .@"break",
        => try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].rhs, range }),

        .@"catch",
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
        .array_access,
        .switch_range,
        .error_value,
        .error_union,
        => {
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].lhs, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].rhs, range });
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = switch (tag) {
                .slice => tree.slice(node),
                .slice_open => tree.sliceOpen(node),
                .slice_sentinel => tree.sliceSentinel(node),
                else => unreachable,
            };

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, slice.ast.sliced, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, slice.ast.start, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, slice.ast.end, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, slice.ast.sentinel, range });
        },

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const array_init: Ast.full.ArrayInit = switch (tag) {
                .array_init, .array_init_comma => tree.arrayInit(node),
                .array_init_one, .array_init_one_comma => tree.arrayInitOne(buffer[0..1], node),
                .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
                .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(&buffer, node),
                else => unreachable,
            };

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, array_init.ast.type_expr, range });
            for (array_init.ast.elements) |elem| {
                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, elem, range });
            }
        },

        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = switch (tag) {
                .struct_init, .struct_init_comma => tree.structInit(node),
                .struct_init_dot, .struct_init_dot_comma => tree.structInitDot(node),
                .struct_init_one, .struct_init_one_comma => tree.structInitOne(buffer[0..1], node),
                .struct_init_dot_two, .struct_init_dot_two_comma => tree.structInitDotTwo(&buffer, node),
                else => unreachable,
            };

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, struct_init.ast.type_expr, range });

            for (struct_init.ast.fields) |field_init| {
                if (struct_init.ast.fields.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, field_init, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, field_init, range });
            }
        },

        .@"switch",
        .switch_comma,
        => {
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].lhs, range });

            const extra = tree.extraData(node_data[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases) |case_node| {
                if (cases.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, case_node, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, case_node, range });
            }
        },

        .switch_case_one,
        .switch_case,
        .switch_case_inline_one,
        .switch_case_inline,
        => {
            const switch_case = if (tag == .switch_case or tag == .switch_case_inline) tree.switchCase(node) else tree.switchCaseOne(node);

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, switch_case.ast.target_expr, range });
        },

        .while_simple,
        .while_cont,
        .@"while",
        .for_simple,
        .@"for",
        => {
            const while_node = ast.whileAst(tree, node).?;

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, while_node.ast.cond_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, while_node.ast.cont_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, while_node.ast.then_expr, range });

            if (while_node.ast.else_expr != 0) {
                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, while_node.ast.else_expr, range });
            }
        },

        .if_simple,
        .@"if",
        => {
            const if_node = ast.ifFull(tree, node);
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, if_node.ast.cond_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, if_node.ast.then_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, if_node.ast.else_expr, range });
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        .fn_decl,
        => {
            var buffer: [1]Ast.Node.Index = undefined;
            const fn_proto: Ast.full.FnProto = ast.fnProto(tree, node, &buffer).?;

            var it = fn_proto.iterate(&tree);
            while (ast.nextFnParam(&it)) |param_decl| {
                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, param_decl.type_expr, range });
            }

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, fn_proto.ast.align_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, fn_proto.ast.addrspace_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, fn_proto.ast.section_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, fn_proto.ast.callconv_expr, range });

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, fn_proto.ast.return_type, range });

            if (tag == .fn_decl) {
                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].rhs, range });
            }
        },

        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const decl: Ast.full.ContainerDecl = ast.containerDecl(tree, node, &buffer).?;

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, decl.ast.arg, range });

            for (decl.ast.members) |child| {
                if (decl.ast.members.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, child, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, child, range });
            }
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => {
            const container_field = ast.containerField(tree, node).?;

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, container_field.ast.value_expr, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, container_field.ast.align_expr, range });
        },

        .block_two,
        .block_two_semicolon,
        => {
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].lhs, range });
            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, node_data[node].rhs, range });
        },

        .block,
        .block_semicolon,
        => {
            const subrange = tree.extra_data[node_data[node].lhs..node_data[node].rhs];

            for (subrange) |child| {
                if (subrange.len > inlay_hints_max_inline_children) {
                    if (!isNodeInRange(tree, child, range)) continue;
                }

                try callWriteNodeInlayHint(allocator, .{ builder, arena, store, child, range });
            }
        },

        .asm_simple,
        .@"asm",
        .asm_output,
        .asm_input,
        => {
            const asm_node: Ast.full.Asm = switch (tag) {
                .@"asm" => tree.asmFull(node),
                .asm_simple => tree.asmSimple(node),
                else => return,
            };

            try callWriteNodeInlayHint(allocator, .{ builder, arena, store, asm_node.ast.template, range });
        },
    }
}

/// creates a list of `InlayHint`'s from the given document
/// only parameter hints are created
/// only hints in the given range are created
/// Caller owns returned memory.
/// `InlayHint.tooltip.value` has to deallocated separately
pub fn writeRangeInlayHint(
    arena: *std.heap.ArenaAllocator,
    config: Config,
    store: *DocumentStore,
    handle: *const DocumentStore.Handle,
    range: types.Range,
    hover_kind: types.MarkupContent.Kind,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.InlayHint {
    var builder: Builder = .{
        .allocator = arena.child_allocator,
        .config = &config,
        .handle = handle,
        .hints = .{},
        .hover_kind = hover_kind,
        .encoding = encoding,
    };
    errdefer builder.deinit();

    var buf: [2]Ast.Node.Index = undefined;
    for (ast.declMembers(handle.tree, 0, &buf)) |child| {
        if (!isNodeInRange(handle.tree, child, range)) continue;
        try writeNodeInlayHint(&builder, arena, store, child, range);
    }

    return builder.toOwnedSlice();
}
