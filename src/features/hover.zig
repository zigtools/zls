const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_hover);

const ast = @import("../ast.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const tracy = @import("../tracy.zig");

const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");

const data = @import("../data/data.zig");

pub fn hoverSymbol(
    analyser: *Analyser,
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

    var is_fn = false;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try analyser.resolveVarDeclAlias(.{ .node = node, .handle = handle })) |result| {
                return try hoverSymbol(analyser, arena, result, markup_kind, doc_str);
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
                    try analyser.referencedTypesFromNode(
                        .{ .node = type_node, .handle = handle },
                        &reference_collector,
                    );

                break :def try Analyser.getVariableSignature(arena, tree, var_decl);
            } else if (tree.fullFnProto(&buf, node)) |fn_proto| {
                is_fn = true;
                break :def Analyser.getFunctionSignature(tree, fn_proto);
            } else if (tree.fullContainerField(node)) |field| {
                var converted = field;
                converted.convertToNonTupleLike(tree.nodes);
                if (converted.ast.type_expr != 0)
                    try analyser.referencedTypesFromNode(
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
                try analyser.referencedTypesFromNode(
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
    if (try decl_handle.resolveType(analyser)) |resolved_type| {
        if (doc_str == null) {
            doc_str = try resolved_type.docComments(arena);
        }
        try analyser.referencedTypes(
            resolved_type,
            &resolved_type_str,
            &reference_collector,
        );
    }
    const referenced_types: []const Analyser.ReferencedType = type_references.keys();

    var hover_text = std.ArrayList(u8).init(arena);
    const writer = hover_text.writer();
    if (markup_kind == .markdown) {
        if (is_fn) {
            try writer.print("```zig\n{s}\n```", .{def_str});
        } else {
            try writer.print("```zig\n{s}\n```\n```zig\n({s})\n```", .{ def_str, resolved_type_str });
        }
        if (doc_str) |doc|
            try writer.print("\n{s}", .{doc});
        if (referenced_types.len > 0)
            try writer.print("\n\n" ++ "Go to ", .{});
        for (referenced_types, 0..) |ref, index| {
            if (index > 0)
                try writer.print(" | ", .{});
            const source_index = offsets.tokenToIndex(ref.handle.tree, ref.token);
            const line = 1 + std.mem.count(u8, ref.handle.tree.source[0..source_index], "\n");
            try writer.print("[{s}]({s}#L{d})", .{ ref.str, ref.handle.uri, line });
        }
    } else {
        if (is_fn) {
            try writer.print("{s}", .{def_str});
        } else {
            try writer.print("{s}\n({s})", .{ def_str, resolved_type_str });
        }
        if (doc_str) |doc|
            try writer.print("\n{s}", .{doc});
    }

    return hover_text.items;
}

pub fn hoverDefinitionLabel(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(pos_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try Analyser.getLabelGlobal(pos_index, handle, name)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(analyser, arena, decl, markup_kind, null)) orelse return null,
            },
        },
        .range = offsets.locToRange(handle.text, name_loc, offset_encoding),
    };
}

pub fn hoverDefinitionBuiltin(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    _ = analyser;
    _ = markup_kind;
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(pos_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);

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
        .range = offsets.locToRange(handle.text, name_loc, offset_encoding),
    };
}

pub fn hoverDefinitionGlobal(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(pos_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try analyser.getSymbolGlobal(pos_index, handle, name)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(analyser, arena, decl, markup_kind, null)) orelse return null,
            },
        },
        .range = offsets.locToRange(handle.text, name_loc, offset_encoding),
    };
}

pub fn hoverDefinitionEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(source_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try analyser.getSymbolEnumLiteral(arena, handle, source_index, name)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(analyser, arena, decl, markup_kind, null)) orelse return null,
            },
        },
        .range = offsets.locToRange(handle.text, name_loc, offset_encoding),
    };
}

pub fn hoverDefinitionFieldAccess(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(source_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const held_loc = offsets.locMerge(loc, name_loc);
    const decls = (try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name)) orelse return null;

    var content = std.ArrayListUnmanaged(types.MarkedString){};

    for (decls) |decl| {
        try content.append(arena, .{
            .string = (try hoverSymbol(analyser, arena, decl, markup_kind, null)) orelse continue,
        });
    }

    // Yes, this is deprecated; the issue is that there's no better
    // solution for multiple hover entries :(
    return .{
        .contents = .{
            .array_of_MarkedString = try content.toOwnedSlice(arena),
        },
        .range = offsets.locToRange(handle.text, name_loc, offset_encoding),
    };
}

pub fn hover(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) !?types.Hover {
    const pos_context = try Analyser.getPositionContext(arena, handle.text, source_index, true);

    const response = switch (pos_context) {
        .builtin => try hoverDefinitionBuiltin(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        .var_access => try hoverDefinitionGlobal(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        .field_access => |loc| try hoverDefinitionFieldAccess(analyser, arena, handle, source_index, loc, markup_kind, offset_encoding),
        .label => try hoverDefinitionLabel(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        .enum_literal => try hoverDefinitionEnumLiteral(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        else => null,
    };

    return response;
}
