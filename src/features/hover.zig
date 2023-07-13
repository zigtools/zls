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

pub fn hoverSymbol(
    server: *Server,
    arena: std.mem.Allocator,
    decl_handle: Analyser.DeclWithHandle,
    markup_kind: types.MarkupKind,
    original_doc_str: ?[]const u8,
) error{OutOfMemory}!?[]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = decl_handle.handle;
    const tree = handle.tree;

    var type_references = Analyser.ReferencedType.Set.init(arena);
    var reference_collector = Analyser.ReferencedType.Collector.init(&type_references);
    var doc_str = original_doc_str orelse try decl_handle.docComments(arena);

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try server.analyser.resolveVarDeclAlias(.{ .node = node, .handle = handle })) |result| {
                return try hoverSymbol(server, arena, result, markup_kind, doc_str);
            }

            var buf: [1]Ast.Node.Index = undefined;

            if (tree.fullVarDecl(node)) |var_decl| {
                var struct_init_buf: [2]Ast.Node.Index = undefined;
                var type_node: Ast.Node.Index = 0;

                if (var_decl.ast.type_node != 0) {
                    type_node = var_decl.ast.type_node;
                } else if (tree.fullStructInit(&struct_init_buf, var_decl.ast.init_node)) |struct_init| {
                    if (struct_init.ast.type_expr != 0)
                        type_node = struct_init.ast.type_expr;
                }

                if (type_node != 0)
                    try server.analyser.referencedTypesFromNode(
                        .{ .node = type_node, .handle = handle },
                        &reference_collector,
                    );

                break :def try Analyser.getVariableSignature(arena, tree, var_decl);
            } else if (tree.fullFnProto(&buf, node)) |fn_proto| {
                break :def Analyser.getFunctionSignature(tree, fn_proto);
            } else if (tree.fullContainerField(node)) |field| {
                var converted = field;
                converted.convertToNonTupleLike(tree.nodes);
                if (converted.ast.type_expr != 0)
                    try server.analyser.referencedTypesFromNode(
                        .{ .node = converted.ast.type_expr, .handle = handle },
                        &reference_collector,
                    );

                break :def Analyser.getContainerFieldSignature(tree, field);
            } else {
                break :def Analyser.nodeToString(tree, node) orelse return null;
            }
        },
        .param_payload => |pay| def: {
            const param = pay.param;

            if (param.type_expr != 0) // zero for `anytype` and extern C varargs `...`
                try server.analyser.referencedTypesFromNode(
                    .{ .node = param.type_expr, .handle = handle },
                    &reference_collector,
                );

            break :def ast.paramSlice(tree, param);
        },
        .pointer_payload,
        .error_union_payload,
        .array_payload,
        .array_index,
        .switch_payload,
        .label_decl,
        .error_token,
        => tree.tokenSlice(decl_handle.nameToken()),
    };

    var resolved_type_str: []const u8 = "unknown";
    if (try decl_handle.resolveType(&server.analyser)) |resolved_type| {
        try server.analyser.referencedTypes(
            resolved_type,
            &resolved_type_str,
            &reference_collector,
        );
    }
    const referenced_types: []const Analyser.ReferencedType = type_references.keys();

    var hover_text = std.ArrayList(u8).init(arena);
    const writer = hover_text.writer();
    if (markup_kind == .markdown) {
        try writer.print("```zig\n{s}\n```\n```zig\n({s})\n```", .{ def_str, resolved_type_str });
        if (doc_str) |doc|
            try writer.print("\n{s}", .{doc});
        if (referenced_types.len > 0)
            try writer.print("\n\n" ++ "Go to ", .{});
        for (referenced_types, 0..) |ref, index| {
            if (index > 0)
                try writer.print(" | ", .{});
            const loc = offsets.tokenToPosition(ref.handle.tree, ref.token, server.offset_encoding);
            try writer.print("[{s}]({s}#L{d})", .{ ref.str, ref.handle.uri, loc.line + 1 });
        }
    } else {
        try writer.print("{s} ({s})", .{ def_str, resolved_type_str });
        if (doc_str) |doc|
            try writer.print("\n{s}", .{doc});
    }

    return hover_text.items;
}

pub fn hoverDefinitionLabel(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, pos_index: usize) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decl = (try Server.getLabelGlobal(pos_index, handle)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(server, arena, decl, markup_kind, null)) orelse return null,
            },
        },
    };
}

pub fn hoverDefinitionBuiltin(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, pos_index: usize) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    _ = server;

    const name = Server.identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    const builtin = for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            break builtin;
        }
    } else return null;

    var contents: std.ArrayListUnmanaged(u8) = .{};
    var writer = contents.writer(arena);

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

pub fn hoverDefinitionGlobal(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, pos_index: usize) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(server, arena, decl, markup_kind, null)) orelse return null,
            },
        },
    };
}

pub fn hoverDefinitionEnumLiteral(
    server: *Server,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decl = (try server.getSymbolEnumLiteral(arena, handle, source_index)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(server, arena, decl, markup_kind, null)) orelse return null,
            },
        },
    };
}

pub fn hoverDefinitionFieldAccess(
    server: *Server,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const decls = (try server.getSymbolFieldAccesses(arena, handle, source_index, loc)) orelse return null;

    var content = std.ArrayListUnmanaged(types.MarkedString){};

    for (decls) |decl| {
        try content.append(arena, .{
            .string = (try hoverSymbol(server, arena, decl, markup_kind, null)) orelse continue,
        });
    }

    // Yes, this is deprecated; the issue is that there's no better
    // solution for multiple hover entries :(
    return .{
        .contents = .{
            .array_of_MarkedString = try content.toOwnedSlice(arena),
        },
    };
}

pub fn hover(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, source_index: usize) !?types.Hover {
    const pos_context = try Analyser.getPositionContext(arena, handle.text, source_index, true);

    const response = switch (pos_context) {
        .builtin => try hoverDefinitionBuiltin(server, arena, handle, source_index),
        .var_access => try hoverDefinitionGlobal(server, arena, handle, source_index),
        .field_access => |loc| try hoverDefinitionFieldAccess(server, arena, handle, source_index, loc),
        .label => try hoverDefinitionLabel(server, arena, handle, source_index),
        .enum_literal => try hoverDefinitionEnumLiteral(server, arena, handle, source_index),
        else => null,
    };

    return response;
}
