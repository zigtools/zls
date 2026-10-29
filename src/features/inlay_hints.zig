//! Implementation of [`textDocument/inlayHint`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_inlayHint)

const std = @import("std");
const Ast = @import("zirp").Ast;

const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");
const ast = @import("../ast.zig");
const Config = @import("../Config.zig");
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");

const data = @import("version_data");

pub const Error = Analyser.Error || error{InvalidParams};

/// don't show inlay hints for builtin functions whose parameter names carry no
/// meaningful information or are trivial deductible based on the builtin name.
const excluded_builtins_set: std.EnumArray(std.zig.BuiltinFn.Tag, bool) = .init(.{
    .add_with_overflow = true,
    .addrspace_cast = true,
    .align_cast = true,
    .align_of = true,
    .as = true,
    .atomic_load = false,
    .atomic_rmw = false,
    .atomic_store = false,
    .bit_cast = true,
    .bit_offset_of = true,
    .int_from_bool = true,
    .bit_size_of = true,
    .branch_hint = true,
    .breakpoint = true, // no parameters
    .disable_instrumentation = true, // no parameters
    .disable_intrinsics = true, // no parameters
    .mul_add = false,
    .byte_swap = true,
    .bit_reverse = true,
    .offset_of = false,
    .call = false,
    .clz = true,
    .cmpxchg_strong = false,
    .cmpxchg_weak = false,
    .compile_error = false,
    .compile_log = true, // variadic
    .const_cast = true,
    .ctz = true,
    .c_va_arg = false,
    .c_va_copy = false,
    .c_va_end = false,
    .c_va_start = false,
    .div_ceil = true,
    .div_exact = true,
    .div_floor = true,
    .div_trunc = true,
    .embed_file = true,
    .int_from_enum = true,
    .error_name = true,
    .error_return_trace = true, // no parameters
    .int_from_error = true,
    .error_cast = true,
    .@"export" = false,
    .@"extern" = false,
    .field = false,
    .field_parent_ptr = false,
    .FieldType = false,
    .float_cast = true,
    .int_from_float = true,
    .frame = true,
    .Frame = true,
    .frame_address = true, // no parameters
    .has_decl = false,
    .has_field = false,
    .import = true,
    .in_comptime = true, // no parameters
    .int_cast = true,
    .backing_int = true,
    .from_backing_int = true,
    .enum_from_int = true,
    .error_from_int = true,
    .float_from_int = true,
    .ptr_from_int = true,
    .max = true, // variadic
    .memcpy = false,
    .memset = false,
    .memmove = false,
    .min = true, // variadic
    .wasm_memory_size = false,
    .wasm_memory_grow = false,
    .mod = true,
    .mul_with_overflow = true,
    .panic = false,
    .pop_count = true,
    .prefetch = false,
    .ptr_cast = true,
    .int_from_ptr = true,
    .rem = true,
    .return_address = true, // no parameters
    .select = false,
    .set_eval_branch_quota = true,
    .set_float_mode = true,
    .set_runtime_safety = true,
    .shl_exact = false,
    .shl_with_overflow = false,
    .shr_exact = false,
    .shuffle = false,
    .size_of = true,
    .splat = true,
    .reduce = false,
    .src = true, // no parameters
    .sqrt = true,
    .sin = true,
    .cos = true,
    .tan = true,
    .exp = true,
    .exp2 = true,
    .log = true,
    .log2 = true,
    .log10 = true,
    .abs = true,
    .floor = true,
    .ceil = true,
    .trunc = true,
    .round = true,
    .sub_with_overflow = true,
    .tag_name = true,
    .This = true, // no parameters
    .trap = true, // no parameters
    .truncate = true,
    .EnumLiteral = true, // no parameters
    .Int = true,
    .Tuple = true,
    .Pointer = false,
    .Fn = false,
    .Struct = false,
    .Union = false,
    .Enum = false,
    .SpirvType = true,
    .type_info = true,
    .type_name = true,
    .TypeOf = true, // variadic
    .union_init = false,
    .Vector = false,
    .volatile_cast = true,
    .work_item_id = false,
    .work_group_size = false,
    .work_group_id = false,
});

pub fn @"textDocument/inlayHint"(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.InlayHint.Params,
) Error!?[]types.InlayHint {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();
    analyser.resolve_number_literal_values = true;

    var builder: Builder = .{
        .arena = arena,
        .analyser = &analyser,
        .config = &server.config_manager.config,
        .handle = handle,
        // The Language Server Specification does not provide a client capabilities that allows the client to specify the MarkupKind of inlay hints.
        .hover_kind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext,
    };

    const loc = offsets.rangeToLoc(handle.tree.source, request.range, server.offset_encoding);

    var walker: ast.Walker = try .init(arena, &handle.tree, .root);
    defer walker.deinit(arena);
    while (try walker.nextIgnoreClose(arena, &handle.tree)) |node| {
        if (offsets.locIntersect(loc, offsets.nodeToLoc(&handle.tree, node))) {
            try writeNodeInlayHint(&builder, &handle.tree, node);
        } else {
            walker.skip();
        }
    }

    return try builder.getInlayHints(server.offset_encoding);
}

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    config: *const Config,
    handle: *DocumentStore.Handle,
    hints: std.ArrayList(InlayHint) = .empty,
    hover_kind: types.MarkupKind,

    const InlayHint = struct {
        index: usize,
        label: []const u8,
        kind: types.InlayHint.Kind,
        tooltip: ?types.MarkupContent,

        fn lessThan(_: void, lhs: InlayHint, rhs: InlayHint) bool {
            return lhs.index < rhs.index;
        }
    };

    fn appendParameterHint(
        self: *Builder,
        node_tag: Ast.SyntaxTag,
        token_index: Ast.Token.Index,
        label: []const u8,
        tooltip_text: []const u8,
        tooltip_noalias: bool,
        tooltip_comptime: bool,
    ) error{OutOfMemory}!void {
        // adding tooltip_noalias & tooltip_comptime to InlayHint should be enough
        const tooltip: ?types.MarkupContent = tooltip: {
            if (tooltip_text.len == 0) break :tooltip null;
            const prefix = if (tooltip_noalias) "noalias " else if (tooltip_comptime) "comptime " else "";

            const text = switch (self.hover_kind) {
                .markdown => try self.arena.print("```zig\n{s}{s}\n```", .{ prefix, tooltip_text }),
                .plaintext, .unknown_value => try self.arena.print("{s}{s}", .{ prefix, tooltip_text }),
            };

            break :tooltip .{
                .kind = self.hover_kind,
                .value = text,
            };
        };

        try self.hints.append(self.arena, .{
            .index = if (node_tag == .multiline_string_line)
                offsets.tokenToLoc(&self.handle.tree, token_index.add(-1)).end
            else
                token_index.byteOffset(&self.handle.tree),
            .label = try self.arena.print("{s}:", .{label}),
            .kind = .Parameter,
            .tooltip = tooltip,
        });
    }

    fn getInlayHints(self: *Builder, offset_encoding: offsets.Encoding) error{OutOfMemory}![]types.InlayHint {
        const source_indices = try self.arena.alloc(usize, self.hints.items.len);
        for (source_indices, self.hints.items) |*index, hint| {
            index.* = hint.index;
        }

        const positions = try self.arena.alloc(types.Position, self.hints.items.len);

        try offsets.multiple.indexToPosition(
            self.arena,
            self.handle.tree.source,
            source_indices,
            positions,
            offset_encoding,
        );

        const converted_hints = try self.arena.alloc(types.InlayHint, self.hints.items.len);
        for (converted_hints, self.hints.items, positions) |*converted_hint, hint, position| {
            converted_hint.* = .{
                .position = position,
                .label = .{ .string = hint.label },
                .kind = hint.kind,
                .tooltip = if (hint.tooltip) |tooltip| .{ .markup_content = tooltip } else null,
                .paddingLeft = false,
                .paddingRight = hint.kind == .Parameter,
            };
        }

        return converted_hints;
    }
};

/// writes parameter hints into `builder.hints`
fn writeCallHint(builder: *Builder, call: Ast.Expr.Call) Analyser.Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const call_handle = builder.handle;

    // BRANCH_TODO remove call to `count`
    const arg_count = call.args.iter(&call_handle.tree).count(&call_handle.tree);

    if (arg_count == 0) return;
    if (builder.config.inlay_hints_exclude_single_argument and arg_count == 1) return;

    const ty = try builder.analyser.resolveTypeOfNode(.of(call.callee.idx, call_handle)) orelse return;
    const fn_ty = try builder.analyser.resolveFuncProtoOfCallable(ty) orelse return;
    const fn_info = fn_ty.data.function;

    const has_self_param = arg_count + 1 == fn_info.parameters.len and
        try builder.analyser.isInstanceCall(call_handle, call, fn_ty);

    const parameters = fn_info.parameters[@intFromBool(has_self_param)..];
    var arguments = call.args.iter(&call_handle.tree);
    for (parameters) |param| {
        const arg = arguments.next(&call_handle.tree) orelse break;
        const parameter_name = param.name orelse continue;

        if (builder.config.inlay_hints_hide_redundant_param_names or builder.config.inlay_hints_hide_redundant_param_names_last_token) dont_skip: {
            const arg_token = if (builder.config.inlay_hints_hide_redundant_param_names_last_token)
                ast.lastToken(&call_handle.tree, arg.idx)
            else if (builder.config.inlay_hints_hide_redundant_param_names)
                arg.idx.mainToken(&call_handle.tree)
            else
                unreachable;

            if (arg_token.tag(&call_handle.tree) != .name) break :dont_skip;
            const arg_token_name = offsets.identifierTokenToNameSlice(&call_handle.tree, arg_token);
            if (!std.mem.eql(u8, parameter_name, arg_token_name)) break :dont_skip;

            continue;
        }

        const no_alias = if (param.modifier) |m| m == .noalias_param else false;
        const comp_time = if (param.modifier) |m| m == .comptime_param else false;

        const tooltip = try param.type.stringifyTypeVal(
            builder.analyser,
            .{ .truncate_container_decls = true },
        );

        try builder.appendParameterHint(
            arg.idx.syntaxTag(&call_handle.tree),
            arg.idx.firstToken(&call_handle.tree),
            parameter_name,
            tooltip,
            no_alias,
            comp_time,
        );
    }
}

/// takes parameter nodes from the ast and function parameter names from `Builtin.parameters` and writes parameter hints into `builder.hints`
fn writeBuiltinHint(
    builder: *Builder,
    builtin: Ast.Expr.Builtin,
    params: []const data.Builtin.Parameter,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = builder.handle;
    const tree = &handle.tree;

    var it = builtin.args.iter(tree);
    for (params) |param| {
        const parameter = it.next(tree) orelse break;

        var signature = param.signature;
        if (std.mem.eql(u8, signature, "...")) return;

        var is_comptime = false;
        var is_noalias = false;
        if (std.mem.cutPrefix(u8, signature, "comptime")) |rest| {
            signature = rest;
            is_comptime = true;
        } else if (std.mem.cutPrefix(u8, signature, "noalias")) |rest| {
            signature = rest;
            is_noalias = true;
        }
        signature = std.mem.trimStart(u8, signature, &std.ascii.whitespace);

        const colon_index = std.mem.findScalar(u8, signature, ':');
        const label = signature[0 .. colon_index orelse signature.len];
        const tooltip = if (colon_index) |i| signature[i + 1 ..] else "";

        try builder.appendParameterHint(
            parameter.idx.syntaxTag(tree),
            parameter.idx.firstToken(tree),
            label,
            tooltip,
            is_noalias,
            is_comptime,
        );
    }
}

fn typeStrOfNode(builder: *Builder, node: Ast.Node.Index) Analyser.Error!?[]const u8 {
    const resolved_type = try builder.analyser.resolveTypeOfNode(.of(node, builder.handle)) orelse return null;
    return try resolved_type.stringifyTypeOf(
        builder.analyser,
        .{ .truncate_container_decls = true },
    );
}

fn typeStrOfToken(builder: *Builder, token: Ast.Token.Index) Analyser.Error!?[]const u8 {
    const things = try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        offsets.tokenToSlice(&builder.handle.tree, token),
        token.byteOffset(&builder.handle.tree),
    ) orelse return null;
    const resolved_type = try things.resolveType(builder.analyser) orelse return null;
    return try resolved_type.stringifyTypeOf(
        builder.analyser,
        .{ .truncate_container_decls = true },
    );
}

/// Append a hint in the form `: hint`
fn appendTypeHintString(builder: *Builder, type_token_index: Ast.Token.Index, hint: []const u8) error{OutOfMemory}!void {
    const name = offsets.tokenToSlice(&builder.handle.tree, type_token_index);
    if (std.mem.eql(u8, name, "_")) {
        return;
    }

    try builder.hints.append(builder.arena, .{
        .index = offsets.tokenToLoc(&builder.handle.tree, type_token_index).end,
        .label = try builder.arena.print(": {s}", .{hint}),
        .tooltip = null,
        .kind = .Type,
    });
}

fn inferAppendTypeStr(builder: *Builder, token: Ast.Token.Index) Analyser.Error!void {
    const type_str = try typeStrOfToken(builder, token) orelse return;
    try appendTypeHintString(builder, token, type_str);
}

fn writePayloadHint(builder: *Builder, payload: Ast.Payload) Analyser.Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = &builder.handle.tree;

    var it = payload.bindings.iter(tree);
    while (it.next(tree)) |binding| {
        const name_token = binding.get(tree).name(tree) orelse continue;
        const type_str = try typeStrOfToken(builder, name_token) orelse continue;
        try appendTypeHintString(builder, name_token, type_str);
    }
}

fn writeNodeInlayHint(
    builder: *Builder,
    tree: *const Ast,
    node: Ast.Node.Index,
) Analyser.Error!void {
    switch (node.tag(tree)) {
        .expr_call => {
            if (!builder.config.inlay_hints_show_parameter_name) return;
            const expr: Ast.Expr.Call = node.cast(.expr_call, tree).?;
            try writeCallHint(builder, expr);
        },
        inline .var_local, .var_global => |t| {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const var_decl = node.cast(t, tree).?;
            if (var_decl.type != null) return;

            try appendTypeHintString(
                builder,
                var_decl.name(tree) orelse return,
                try typeStrOfNode(builder, node) orelse return,
            );
        },
        .expr_destructure => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const expr: Ast.Expr.Destructure = node.cast(.expr_destructure, tree).?;
            var it = expr.lvalues.iter(tree);
            while (it.next(tree)) |lvalue| {
                const var_proto = switch (lvalue.get(tree)) {
                    .expr => continue,
                    .var_proto => |var_proto| var_proto.get(tree),
                };
                if (var_proto.type != null) continue;
                const name_token = var_proto.name(tree) orelse continue;
                try inferAppendTypeStr(builder, name_token);
            }
        },
        .expr_if,
        .expr_if_else,
        .expr_if_payload,
        .expr_if_full,
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const node_index: Ast.Expr.If.Index = .{ .idx = node };
            const expr = node_index.get(tree);
            if (expr.then_payload) |payload| try writePayloadHint(builder, payload.get(tree));
            if (expr.else_payload) |payload| try writePayloadHint(builder, payload.get(tree));
        },
        .expr_for => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const expr: Ast.Expr.For = node.cast(.expr_for, tree).?;
            try writePayloadHint(builder, expr.payload.get(tree));
        },
        .expr_while => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const expr: Ast.Expr.While = node.cast(.expr_while, tree).?;
            if (expr.payload) |payload| try writePayloadHint(builder, payload.get(tree));
            if (expr.else_payload) |payload| try writePayloadHint(builder, payload.get(tree));
        },
        .switch_prong => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const expr: Ast.Expr.Switch.Prong = node.cast(.switch_prong, tree).?;
            if (expr.payload) |payload| try writePayloadHint(builder, payload.get(tree));
        },
        .expr_catch => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const expr: Ast.Expr.Catch = node.cast(.expr_catch, tree).?;
            if (expr.payload) |payload| try writePayloadHint(builder, payload.get(tree));
        },
        .expr_builtin_call => {
            if (!builder.config.inlay_hints_show_parameter_name or !builder.config.inlay_hints_show_builtin) return;
            const expr: Ast.Expr.Builtin = node.cast(.expr_builtin_call, tree).?;

            const name = offsets.tokenToSlice(tree, expr.callee.token(tree));
            const item = std.zig.BuiltinFn.list.get(name) orelse return;
            if (excluded_builtins_set.get(item.tag)) return;

            const builtin_data = data.builtins.get(name) orelse return;
            try writeBuiltinHint(builder, expr, builtin_data.parameters);
        },
        .expr_init => {
            if (!builder.config.inlay_hints_show_struct_literal_field_type) return;
            const expr: Ast.Expr.Init = node.cast(.expr_init, tree).?;
            var it = expr.fields.iter(tree);
            while (it.next(tree)) |field| {
                const struct_field = switch (field.get(tree)) {
                    .struct_field => |struct_field| struct_field.get(tree),
                    .tuple_field => continue,
                };
                const name_token = struct_field.name.token(tree);
                const name_loc = offsets.tokenToLoc(tree, name_token);
                const name = offsets.locToSlice(tree.source, name_loc);
                const decl, const type_maybe = (try builder.analyser.getSymbolEnumLiteral(builder.handle, name_loc.start, name)) orelse continue;
                const ty = type_maybe orelse try decl.resolveType(builder.analyser) orelse continue;
                const type_str = try ty.stringifyTypeOf(builder.analyser, .{ .truncate_container_decls = true });
                if (type_str.len == 0) continue;
                try appendTypeHintString(
                    builder,
                    name_token,
                    type_str,
                );
            }
        },
        else => {},
    }
}
