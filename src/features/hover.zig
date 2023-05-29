const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_hover);

const ast = @import("../ast.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const tracy = @import("../tracy.zig");

const Server = @import("../Server.zig");
const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");

const data = @import("../data/data.zig");

pub fn hoverSymbol(server: *Server, decl_handle: Analyser.DeclWithHandle, markup_kind: types.MarkupKind) error{OutOfMemory}!?[]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = decl_handle.handle;
    const tree = handle.tree;

    var doc_str: ?[]const u8 = null;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try server.analyser.resolveVarDeclAlias(.{ .node = node, .handle = handle })) |result| {
                return try hoverSymbol(server, result, markup_kind);
            }
            doc_str = try Analyser.getDocComments(server.arena.allocator(), tree, node, markup_kind);

            var buf: [1]Ast.Node.Index = undefined;

            if (tree.fullVarDecl(node)) |var_decl| {
                break :def Analyser.getVariableSignature(tree, var_decl);
            } else if (tree.fullFnProto(&buf, node)) |fn_proto| {
                break :def Analyser.getFunctionSignature(tree, fn_proto);
            } else if (tree.fullContainerField(node)) |field| {
                break :def Analyser.getContainerFieldSignature(tree, field);
            } else {
                break :def Analyser.nodeToString(tree, node) orelse return null;
            }
        },
        .param_payload => |pay| def: {
            const param = pay.param;
            if (param.first_doc_comment) |doc_comments| {
                doc_str = try Analyser.collectDocComments(server.arena.allocator(), handle.tree, doc_comments, markup_kind, false);
            }

            break :def ast.paramSlice(tree, param);
        },
        .pointer_payload,
        .array_payload,
        .array_index,
        .switch_payload,
        .label_decl,
        .error_token,
        => tree.tokenSlice(decl_handle.nameToken()),
    };

    const resolved_type = try decl_handle.resolveType(&server.analyser);

    const resolved_type_str = if (resolved_type) |rt|
        if (rt.type.is_type_val) switch (rt.type.data) {
            .@"comptime" => |co| try std.fmt.allocPrint(server.arena.allocator(), "{}", .{co.value.index.fmt(co.interpreter.ip.*)}),
            else => "type",
        } else switch (rt.type.data) {
            .pointer,
            .slice,
            .error_union,
            .primitive,
            => |p| offsets.nodeToSlice(rt.handle.tree, p),
            .other => |p| switch (rt.handle.tree.nodes.items(.tag)[p]) {
                .container_decl,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                => rt.handle.tree.tokenSlice(rt.handle.tree.nodes.items(.main_token)[p] - 2), // NOTE: This is a hacky nightmare but it works :P
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => "fn", // TODO:(?) Add more info?
                .array_type,
                .array_type_sentinel,
                .ptr_type,
                .ptr_type_aligned,
                .ptr_type_bit_range,
                .ptr_type_sentinel,
                => offsets.nodeToSlice(rt.handle.tree, p),
                else => "unknown", // TODO: Implement more "other" type expressions; better safe than sorry
            },
            else => "unknown",
        }
    else
        "unknown";

    var hover_text: []const u8 = undefined;
    if (markup_kind == .markdown) {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(server.arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(server.arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```", .{ def_str, resolved_type_str });
    } else {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(server.arena.allocator(), "{s} ({s})\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(server.arena.allocator(), "{s} ({s})", .{ def_str, resolved_type_str });
    }

    return hover_text;
}

pub fn hoverDefinitionLabel(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decl = (try Server.getLabelGlobal(pos_index, handle)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(server, decl, markup_kind)) orelse return null,
            },
        },
    };
}

pub fn hoverDefinitionBuiltin(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = Server.identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    const builtin = for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            break builtin;
        }
    } else return null;

    var contents: std.ArrayListUnmanaged(u8) = .{};
    var writer = contents.writer(server.arena.allocator());

    if (std.mem.eql(u8, name, "cImport")) blk: {
        const index = for (handle.cimports.items(.node), 0..) |cimport_node, index| {
            const main_token = handle.tree.nodes.items(.main_token)[cimport_node];
            const cimport_loc = offsets.tokenToLoc(handle.tree, main_token);
            if (cimport_loc.start <= pos_index and pos_index <= cimport_loc.end) break index;
        } else break :blk;

        const source = handle.cimports.items(.source)[index];

        try writer.print(
            \\```c
            \\{s}
            \\```
            \\
        , .{source});
    }

    try writer.print(
        \\```zig
        \\{s}
        \\```
        \\{s}
    , .{ builtin.signature, builtin.documentation });

    return types.Hover{
        .contents = .{
            .MarkupContent = .{
                .kind = .markdown,
                .value = contents.items,
            },
        },
    };
}

pub fn hoverDefinitionGlobal(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(server, decl, markup_kind)) orelse return null,
            },
        },
    };
}

pub fn hoverDefinitionFieldAccess(
    server: *Server,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decls = (try server.getSymbolFieldAccesses(handle, source_index, loc)) orelse return null;

    var content = std.ArrayListUnmanaged(types.MarkedString){};

    for (decls) |decl| {
        try content.append(server.arena.allocator(), .{
            .string = (try hoverSymbol(server, decl, markup_kind)) orelse continue,
        });
    }

    // Yes, this is deprecated; the issue is that there's no better
    // solution for multiple hover entries :(
    return .{
        .contents = .{
            .array_of_MarkedString = try content.toOwnedSlice(server.arena.allocator()),
        },
    };
}

pub fn hover(server: *Server, source_index: usize, handle: *const DocumentStore.Handle) !?types.Hover {
    const pos_context = try Analyser.getPositionContext(server.arena.allocator(), handle.text, source_index, true);

    const response = switch (pos_context) {
        .builtin => try hoverDefinitionBuiltin(server, source_index, handle),
        .var_access => try hoverDefinitionGlobal(server, source_index, handle),
        .field_access => |loc| try hoverDefinitionFieldAccess(server, handle, source_index, loc),
        .label => try hoverDefinitionLabel(server, source_index, handle),
        else => null,
    };

    return response;
}
