//! Implementation of [`textDocument/inlayHint`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_inlayHint)

const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.inlay_hint);

const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");
const ast = @import("../ast.zig");
const Config = @import("../Config.zig");

const data = @import("version_data");

/// don't show inlay hints for builtin functions whose parameter names carry no
/// meaningful information or are trivial deductible based on the builtin name.
const excluded_builtins_set: std.StaticStringMap(void) = blk: {
    @setEvalBranchQuota(2000);
    break :blk .initComptime(.{
        .{"addrSpaceCast"},
        .{"addWithOverflow"},
        .{"alignCast"},
        .{"alignOf"},
        .{"as"},
        // .{"atomicLoad"},
        // .{"atomicRmw"},
        // .{"atomicStore"},
        .{"bitCast"},
        .{"bitOffsetOf"},
        .{"bitSizeOf"},
        .{"branchHint"},
        .{"breakpoint"}, // no parameters
        // .{"mulAdd"},
        .{"byteSwap"},
        .{"bitReverse"},
        .{"offsetOf"},
        // .{"call"},
        .{"cDefine"},
        .{"cImport"},
        .{"cInclude"},
        .{"clz"},
        // .{"cmpxchgStrong"},
        // .{"cmpxchgWeak"},
        // .{"compileError"},
        .{"compileLog"}, // variadic
        .{"constCast"},
        .{"ctz"},
        .{"cUndef"},
        // .{"cVaArg"},
        // .{"cVaCopy"},
        // .{"cVaEnd"},
        // .{"cVaStart"},
        .{"divExact"},
        .{"divFloor"},
        .{"divTrunc"},
        .{"embedFile"},
        .{"enumFromInt"},
        .{"errorFromInt"},
        .{"errorName"},
        .{"errorReturnTrace"}, // no parameters
        .{"errorCast"},
        // .{"export"},
        // .{"extern"},
        // .{"field"},
        // .{"fieldParentPtr"},
        // .{"FieldType"},
        .{"floatCast"},
        .{"floatFromInt"},
        .{"frameAddress"}, // no parameters
        // .{"hasDecl"},
        // .{"hasField"},
        .{"import"},
        .{"inComptime"}, // no parameters
        .{"intCast"},
        .{"intFromBool"},
        .{"intFromEnum"},
        .{"intFromError"},
        .{"intFromFloat"},
        .{"intFromPtr"},
        .{"max"},
        // .{"memcpy"},
        // .{"memset"},
        .{"min"},
        // .{"wasmMemorySize"},
        // .{"wasmMemoryGrow"},
        .{"mod"},
        .{"mulWithOverflow"},
        // .{"panic"},
        .{"popCount"},
        // .{"prefetch"},
        .{"ptrCast"},
        .{"ptrFromInt"},
        .{"rem"},
        .{"returnAddress"}, // no parameters
        // .{"select"},
        .{"setEvalBranchQuota"},
        .{"setFloatMode"},
        .{"setRuntimeSafety"},
        // .{"shlExact"},
        // .{"shlWithOverflow"},
        // .{"shrExact"},
        // .{"shuffle"},
        .{"sizeOf"},
        // .{"splat"},
        // .{"reduce"},
        .{"src"}, // no parameters
        .{"sqrt"},
        .{"sin"},
        .{"cos"},
        .{"tan"},
        .{"exp"},
        .{"exp2"},
        .{"log"},
        .{"log2"},
        .{"log10"},
        .{"abs"},
        .{"floor"},
        .{"ceil"},
        .{"trunc"},
        .{"round"},
        .{"subWithOverflow"},
        .{"tagName"},
        .{"This"}, // no parameters
        .{"trap"}, // no parameters
        .{"truncate"},
        .{"Type"},
        .{"typeInfo"},
        .{"typeName"},
        .{"TypeOf"}, // variadic
        // .{"unionInit"},
        // .{"Vector"},
        .{"volatileCast"},
        // .{"workGroupId"},
        // .{"workGroupSize"},
        // .{"workItemId"},
    });
};

pub const InlayHint = struct {
    index: usize,
    label: []const u8,
    kind: types.InlayHintKind,
    tooltip: ?types.MarkupContent,

    fn lessThan(_: void, lhs: InlayHint, rhs: InlayHint) bool {
        return lhs.index < rhs.index;
    }
};

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    config: *const Config,
    handle: *DocumentStore.Handle,
    hints: std.ArrayList(InlayHint) = .empty,
    hover_kind: types.MarkupKind,

    fn appendParameterHint(
        self: *Builder,
        node_tag: Ast.Node.Tag,
        token_index: Ast.TokenIndex,
        label: []const u8,
        tooltip: []const u8,
        tooltip_noalias: bool,
        tooltip_comptime: bool,
    ) !void {
        // adding tooltip_noalias & tooltip_comptime to InlayHint should be enough
        const tooltip_text = blk: {
            if (tooltip.len == 0) break :blk "";
            const prefix = if (tooltip_noalias) if (tooltip_comptime) "noalias comptime " else "noalias " else if (tooltip_comptime) "comptime " else "";

            if (self.hover_kind == .markdown) {
                break :blk try std.fmt.allocPrint(self.arena, "```zig\n{s}{s}\n```", .{ prefix, tooltip });
            }

            break :blk try std.fmt.allocPrint(self.arena, "{s}{s}", .{ prefix, tooltip });
        };

        try self.hints.append(self.arena, .{
            .index = if (node_tag == .multiline_string_literal)
                offsets.tokenToLoc(self.handle.tree, token_index - 1).end
            else
                self.handle.tree.tokenStart(token_index),
            .label = try std.fmt.allocPrint(self.arena, "{s}:", .{label}),
            .kind = .Parameter,
            .tooltip = .{
                .kind = self.hover_kind,
                .value = tooltip_text,
            },
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
                .tooltip = if (hint.tooltip) |tooltip| .{ .MarkupContent = tooltip } else null,
                .paddingLeft = false,
                .paddingRight = hint.kind == .Parameter,
            };
        }

        return converted_hints;
    }
};

/// writes parameter hints into `builder.hints`
fn writeCallHint(
    builder: *Builder,
    /// The function call.
    call: Ast.full.Call,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = builder.handle;

    const ty = try builder.analyser.resolveTypeOfNode(.of(call.ast.fn_expr, handle)) orelse return;
    const fn_ty = try builder.analyser.resolveFuncProtoOfCallable(ty) orelse return;
    const fn_info = fn_ty.data.function;

    const has_self_param = call.ast.params.len + 1 == fn_info.parameters.len and
        try builder.analyser.isInstanceCall(handle, call, fn_ty);

    const parameters = fn_info.parameters[@intFromBool(has_self_param)..];
    const arguments = call.ast.params;
    const min_len = @min(parameters.len, arguments.len);
    for (parameters[0..min_len], arguments[0..min_len]) |param, arg| {
        const parameter_name = param.name orelse continue;

        if (builder.config.inlay_hints_hide_redundant_param_names or builder.config.inlay_hints_hide_redundant_param_names_last_token) dont_skip: {
            const arg_token = if (builder.config.inlay_hints_hide_redundant_param_names_last_token)
                ast.lastToken(handle.tree, arg)
            else if (builder.config.inlay_hints_hide_redundant_param_names)
                handle.tree.nodeMainToken(arg)
            else
                unreachable;

            if (handle.tree.tokenTag(arg_token) != .identifier) break :dont_skip;
            const arg_token_name = offsets.identifierTokenToNameSlice(handle.tree, arg_token);
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
            handle.tree.nodeTag(arg),
            handle.tree.firstToken(arg),
            parameter_name,
            tooltip,
            no_alias,
            comp_time,
        );
    }
}

/// takes parameter nodes from the ast and function parameter names from `Builtin.parameters` and writes parameter hints into `builder.hints`
fn writeBuiltinHint(builder: *Builder, parameters: []const Ast.Node.Index, params: []const data.Builtin.Parameter) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = builder.handle;
    const tree = handle.tree;

    const len = @min(params.len, parameters.len);
    for (params[0..len], parameters[0..len]) |param, parameter| {
        const signature = param.signature;
        if (signature.len == 0) continue;

        const colonIndex = std.mem.indexOfScalar(u8, signature, ':');
        const type_expr = param.type orelse "";

        // TODO: parse noalias/comptime/label in config_gen.zig
        var maybe_label: ?[]const u8 = null;
        var no_alias = false;
        var comp_time = false;

        var it = std.mem.splitScalar(u8, signature[0 .. colonIndex orelse signature.len], ' ');
        while (it.next()) |item| {
            if (item.len == 0) continue;
            maybe_label = item;

            no_alias = no_alias or std.mem.eql(u8, item, "noalias");
            comp_time = comp_time or std.mem.eql(u8, item, "comptime");
        }

        const label = maybe_label orelse return;
        if (label.len == 0 or std.mem.eql(u8, label, "...")) return;

        try builder.appendParameterHint(
            tree.nodeTag(parameter),
            tree.firstToken(parameter),
            label,
            std.mem.trim(u8, type_expr, " \t\n"),
            no_alias,
            comp_time,
        );
    }
}

fn typeStrOfNode(builder: *Builder, node: Ast.Node.Index) !?[]const u8 {
    const resolved_type = try builder.analyser.resolveTypeOfNode(.of(node, builder.handle)) orelse return null;
    return try resolved_type.stringifyTypeOf(
        builder.analyser,
        .{ .truncate_container_decls = true },
    );
}

fn typeStrOfToken(builder: *Builder, token: Ast.TokenIndex) !?[]const u8 {
    const things = try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        offsets.tokenToSlice(builder.handle.tree, token),
        builder.handle.tree.tokenStart(token),
    ) orelse return null;
    const resolved_type = try things.resolveType(builder.analyser) orelse return null;
    return try resolved_type.stringifyTypeOf(
        builder.analyser,
        .{ .truncate_container_decls = true },
    );
}

/// Append a hint in the form `: hint`
fn appendTypeHintString(builder: *Builder, type_token_index: Ast.TokenIndex, hint: []const u8) !void {
    const name = offsets.tokenToSlice(builder.handle.tree, type_token_index);
    if (std.mem.eql(u8, name, "_")) {
        return;
    }

    try builder.hints.append(builder.arena, .{
        .index = offsets.tokenToLoc(builder.handle.tree, type_token_index).end,
        .label = try std.fmt.allocPrint(builder.arena, ": {s}", .{hint}),
        // TODO: Implement on-hover stuff.
        .tooltip = null,
        .kind = .Type,
    });
}

fn inferAppendTypeStr(builder: *Builder, token: Ast.TokenIndex) !void {
    const type_str = try typeStrOfToken(builder, token) orelse return;
    try appendTypeHintString(builder, token, type_str);
}

fn writeForCaptureHint(builder: *Builder, for_node: Ast.Node.Index) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = builder.handle.tree;
    const full_for = ast.fullFor(tree, for_node).?;
    var capture_token = full_for.payload_token;
    for (full_for.ast.inputs) |_| {
        if (capture_token + 1 >= tree.tokens.len) break;
        const capture_is_ref = tree.tokenTag(capture_token) == .asterisk;
        const name_token = capture_token + @intFromBool(capture_is_ref);
        capture_token = name_token + 2;

        if (try typeStrOfToken(builder, name_token)) |type_str| {
            try appendTypeHintString(builder, name_token, type_str);
        }
    }
}

/// takes a Ast.full.Call (a function call), analysis its function expression, finds its declaration and writes parameter hints into `builder.hints`
fn writeCallNodeHint(builder: *Builder, call: Ast.full.Call) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (call.ast.params.len == 0) return;
    if (builder.config.inlay_hints_exclude_single_argument and call.ast.params.len == 1) return;

    const handle = builder.handle;
    const tree = handle.tree;

    switch (tree.nodeTag(call.ast.fn_expr)) {
        .identifier, .field_access => try writeCallHint(builder, call),
        else => {
            log.debug("cannot deduce fn expression with tag '{}'", .{tree.nodeTag(call.ast.fn_expr)});
        },
    }
}

fn writeNodeInlayHint(
    builder: *Builder,
    tree: Ast,
    node: Ast.Node.Index,
) error{OutOfMemory}!void {
    switch (tree.nodeTag(node)) {
        .call_one,
        .call_one_comma,
        .call,
        .call_comma,
        => {
            if (!builder.config.inlay_hints_show_parameter_name) return;

            var params: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&params, node).?;
            try writeCallNodeHint(builder, call);
        },
        .local_var_decl,
        .simple_var_decl,
        .global_var_decl,
        .aligned_var_decl,
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const var_decl = builder.handle.tree.fullVarDecl(node).?;
            if (var_decl.ast.type_node != .none) return;

            try appendTypeHintString(
                builder,
                var_decl.ast.mut_token + 1,
                try typeStrOfNode(builder, node) orelse return,
            );
        },
        .assign_destructure => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const assign_destructure = tree.assignDestructure(node);
            for (assign_destructure.ast.variables) |lhs_node| {
                const var_decl = tree.fullVarDecl(lhs_node) orelse continue;
                if (var_decl.ast.type_node != .none) continue;
                try inferAppendTypeStr(builder, var_decl.ast.mut_token + 1);
            }
        },
        .if_simple,
        .@"if",
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const full_if = builder.handle.tree.fullIf(node).?;
            if (full_if.payload_token) |token| try inferAppendTypeStr(builder, token);
            if (full_if.error_token) |token| try inferAppendTypeStr(builder, token);
        },
        .for_simple,
        .@"for",
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            try writeForCaptureHint(builder, node);
        },
        .while_simple,
        .while_cont,
        .@"while",
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const full_while = builder.handle.tree.fullWhile(node).?;
            if (full_while.payload_token) |token| try inferAppendTypeStr(builder, token);
            if (full_while.error_token) |token| try inferAppendTypeStr(builder, token);
        },
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;
            const full_case = builder.handle.tree.fullSwitchCase(node).?;
            if (full_case.payload_token) |token| try inferAppendTypeStr(builder, token);
        },
        .@"catch" => {
            if (!builder.config.inlay_hints_show_variable_type_hints) return;

            const catch_token = tree.nodeMainToken(node) + 2;
            if (catch_token < tree.tokens.len and
                tree.tokenTag(catch_token - 1) == .pipe and
                tree.tokenTag(catch_token) == .identifier)
            {
                try inferAppendTypeStr(builder, catch_token);
            }
        },
        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => {
            if (!builder.config.inlay_hints_show_parameter_name or !builder.config.inlay_hints_show_builtin) return;

            const name = tree.tokenSlice(tree.nodeMainToken(node));
            if (name.len < 2 or excluded_builtins_set.has(name[1..])) return;

            var buffer: [2]Ast.Node.Index = undefined;
            const params = tree.builtinCallParams(&buffer, node).?;

            if (params.len == 0) return;

            if (data.builtins.get(name)) |builtin| {
                try writeBuiltinHint(builder, params, builtin.parameters);
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
            if (!builder.config.inlay_hints_show_struct_literal_field_type) return;
            var buffer: [2]Ast.Node.Index = undefined;
            const struct_init = tree.fullStructInit(&buffer, node).?;
            for (struct_init.ast.fields) |value_node| { // the node of `value` in `.name = value`
                const name_token = tree.firstToken(value_node) - 2; // math our way two token indexes back to get the `name`
                const name_loc = offsets.tokenToLoc(tree, name_token);
                const name = offsets.locToSlice(tree.source, name_loc);
                const decl = (try builder.analyser.getSymbolEnumLiteral(builder.handle, name_loc.start, name)) orelse continue;
                const ty = try decl.resolveType(builder.analyser) orelse continue;
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

/// creates a list of `InlayHint`'s from the given document
/// only parameter hints are created
/// only hints in the given loc are created
pub fn writeRangeInlayHint(
    arena: std.mem.Allocator,
    config: *const Config,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    hover_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}![]types.InlayHint {
    var builder: Builder = .{
        .arena = arena,
        .analyser = analyser,
        .config = config,
        .handle = handle,
        .hover_kind = hover_kind,
    };

    const nodes = try ast.nodesAtLoc(arena, handle.tree, loc);

    for (nodes) |child| {
        try writeNodeInlayHint(&builder, handle.tree, child);
        try ast.iterateChildrenRecursive(handle.tree, child, &builder, error{OutOfMemory}, writeNodeInlayHint);
    }

    return try builder.getInlayHints(offset_encoding);
}
