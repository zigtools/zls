const std = @import("std");
const zig_builtin = @import("builtin");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_inlay_hint);

const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const tracy = @import("../tracy.zig");
const ast = @import("../ast.zig");
const Config = @import("../Config.zig");

const data = @import("../data/data.zig");

/// don't show inlay hints for the given builtin functions
/// builtins with one parameter are skipped automatically
/// this option is rare and is therefore build-only and
/// non-configurable at runtime
pub const inlay_hints_exclude_builtins: []const u8 = &.{};

pub const InlayHint = struct {
    token_index: Ast.TokenIndex,
    label: []const u8,
    kind: types.InlayHintKind,
    tooltip: types.MarkupContent,
};

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    config: *const Config,
    handle: *const DocumentStore.Handle,
    hints: std.ArrayListUnmanaged(InlayHint),
    hover_kind: types.MarkupKind,

    fn appendParameterHint(self: *Builder, token_index: Ast.TokenIndex, label: []const u8, tooltip: []const u8, tooltip_noalias: bool, tooltip_comptime: bool) !void {
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
            .token_index = token_index,
            .label = try std.fmt.allocPrint(self.arena, "{s}:", .{label}),
            .kind = .Parameter,
            .tooltip = .{
                .kind = self.hover_kind,
                .value = tooltip_text,
            },
        });
    }

    fn toOwnedSlice(self: *Builder) error{OutOfMemory}![]InlayHint {
        return self.hints.toOwnedSlice(self.arena);
    }
};

/// `call` is the function call
/// `decl_handle` should be a function protototype
/// writes parameter hints into `builder.hints`
fn writeCallHint(builder: *Builder, call: Ast.full.Call, decl_handle: Analyser.DeclWithHandle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = builder.handle;
    const tree = handle.tree;

    const node = switch (decl_handle.decl.*) {
        .ast_node => |node| node,
        else => return,
    };

    const maybe_resolved_alias = try builder.analyser.resolveVarDeclAlias(.{ .node = node, .handle = decl_handle.handle });
    const resolved_decl_handle = if (maybe_resolved_alias) |resolved_decl| resolved_decl else decl_handle;

    const fn_node = switch (resolved_decl_handle.decl.*) {
        .ast_node => |fn_node| fn_node,
        else => return,
    };

    const decl_tree = resolved_decl_handle.handle.tree;

    var buffer: [1]Ast.Node.Index = undefined;
    const fn_proto = decl_tree.fullFnProto(&buffer, fn_node) orelse return;

    var params = try std.ArrayListUnmanaged(Ast.full.FnProto.Param).initCapacity(builder.arena, fn_proto.ast.params.len);
    defer params.deinit(builder.arena);

    var it = fn_proto.iterate(&decl_tree);
    while (ast.nextFnParam(&it)) |param| {
        try params.append(builder.arena, param);
    }

    const has_self_param = call.ast.params.len + 1 == params.items.len and
        try builder.analyser.isInstanceCall(handle, call, decl_handle.handle, fn_proto);

    const parameters = params.items[@intFromBool(has_self_param)..];
    const arguments = call.ast.params;
    const min_len = @min(parameters.len, arguments.len);
    for (parameters[0..min_len], arguments[0..min_len]) |param, arg| {
        const name_token = param.name_token orelse continue;
        const name = decl_tree.tokenSlice(name_token);

        if (builder.config.inlay_hints_hide_redundant_param_names or builder.config.inlay_hints_hide_redundant_param_names_last_token) {
            const last_arg_token = tree.lastToken(arg);
            const arg_name = tree.tokenSlice(last_arg_token);

            if (std.mem.eql(u8, arg_name, name)) {
                if (tree.firstToken(arg) == last_arg_token) {
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
            tree.firstToken(arg),
            name,
            tooltip,
            no_alias,
            comp_time,
        );
    }
}

/// takes parameter nodes from the ast and function parameter names from `Builtin.arguments` and writes parameter hints into `builder.hints`
fn writeBuiltinHint(builder: *Builder, parameters: []const Ast.Node.Index, arguments: []const []const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = builder.handle;
    const tree = handle.tree;

    const len = @min(arguments.len, parameters.len);
    for (arguments[0..len], parameters[0..len]) |arg, parameter| {
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
            tree.firstToken(parameter),
            label orelse "",
            std.mem.trim(u8, type_expr, " \t\n"),
            no_alias,
            comp_time,
        );
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
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    switch (node_tags[call.ast.fn_expr]) {
        .identifier => {
            const source_index = offsets.tokenToIndex(tree, main_tokens[call.ast.fn_expr]);
            const name = offsets.tokenToSlice(tree, main_tokens[call.ast.fn_expr]);

            if (try builder.analyser.lookupSymbolGlobal(handle, name, source_index)) |decl_handle| {
                try writeCallHint(builder, call, decl_handle);
            }
        },
        .field_access => {
            const lhsToken = tree.firstToken(call.ast.fn_expr);
            const rhsToken = node_data[call.ast.fn_expr].rhs;
            std.debug.assert(token_tags[rhsToken] == .identifier);

            const start = offsets.tokenToIndex(tree, lhsToken);
            const rhs_loc = offsets.tokenToLoc(tree, rhsToken);

            var held_range = try builder.arena.dupeZ(u8, handle.text[start..rhs_loc.end]);
            var tokenizer = std.zig.Tokenizer.init(held_range);

            // note: we have the ast node, traversing it would probably yield better results
            // than trying to re-tokenize and re-parse it
            if (try builder.analyser.getFieldAccessType(handle, rhs_loc.end, &tokenizer)) |result| {
                const container_handle = result.unwrapped orelse result.original;
                switch (container_handle.type.data) {
                    .other => |container_handle_node| {
                        if (try builder.analyser.lookupSymbolContainer(
                            .{ .node = container_handle_node, .handle = container_handle.handle },
                            tree.tokenSlice(rhsToken),
                            true,
                        )) |decl_handle| {
                            try writeCallHint(builder, call, decl_handle);
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

fn writeNodeInlayHint(
    builder: *Builder,
    tree: Ast,
    node: Ast.Node.Index,
) error{OutOfMemory}!void {
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    const tag = node_tags[node];

    switch (tag) {
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
            const call = tree.fullCall(&params, node).?;
            try writeCallNodeHint(builder, call);
        },

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => blk: {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            if (!builder.config.inlay_hints_show_builtin or params.len <= 1) break :blk;

            const name = tree.tokenSlice(main_tokens[node]);

            outer: for (data.builtins) |builtin| {
                if (!std.mem.eql(u8, builtin.name, name)) continue;

                for (inlay_hints_exclude_builtins) |builtin_name| {
                    if (std.mem.eql(u8, builtin_name, name)) break :outer;
                }

                try writeBuiltinHint(builder, params, builtin.arguments);
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
    config: Config,
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    loc: offsets.Loc,
    hover_kind: types.MarkupKind,
) error{OutOfMemory}![]InlayHint {
    var builder: Builder = .{
        .arena = arena,
        .analyser = analyser,
        .config = &config,
        .handle = handle,
        .hints = .{},
        .hover_kind = hover_kind,
    };

    const nodes = try ast.nodesAtLoc(arena, handle.tree, loc);

    for (nodes) |child| {
        try writeNodeInlayHint(&builder, handle.tree, child);
        try ast.iterateChildrenRecursive(handle.tree, child, &builder, error{OutOfMemory}, writeNodeInlayHint);
    }

    return try builder.toOwnedSlice();
}
