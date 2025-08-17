//! Implementation of [`textDocument/hover`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_hover)

const std = @import("std");
const Ast = std.zig.Ast;

const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");

const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");

const data = @import("version_data");

fn hoverSymbol(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    param_decl_handle: Analyser.DeclWithHandle,
    markup_kind: types.MarkupKind,
) error{OutOfMemory}!?[]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var doc_strings: std.ArrayList([]const u8) = .empty;

    var decl_handle: Analyser.DeclWithHandle = param_decl_handle;
    var maybe_resolved_type = try param_decl_handle.resolveType(analyser);

    while (true) {
        if (try decl_handle.docComments(arena)) |doc_string| {
            try doc_strings.append(arena, doc_string);
        }
        if (decl_handle.decl != .ast_node) break;
        decl_handle = try analyser.resolveVarDeclAlias(.{
            .node_handle = .of(decl_handle.decl.ast_node, decl_handle.handle),
            .container_type = decl_handle.container_type,
        }) orelse break;
        maybe_resolved_type = maybe_resolved_type orelse try decl_handle.resolveType(analyser);
    }

    const tree = decl_handle.handle.tree;
    const def_str = switch (decl_handle.decl) {
        .ast_node => |node| switch (tree.nodeTag(node)) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => try Analyser.getVariableSignature(
                arena,
                tree,
                tree.fullVarDecl(node).?,
                true,
            ),
            .container_field,
            .container_field_init,
            .container_field_align,
            => Analyser.getContainerFieldSignature(tree, tree.fullContainerField(node).?) orelse return null,
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => def: {
                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buf, node).?;
                break :def Analyser.getFunctionSignature(tree, fn_proto);
            },
            else => unreachable,
        },
        .function_parameter => |payload| ast.paramSlice(tree, payload.get(tree).?, false),
        .optional_payload,
        .error_union_payload,
        .error_union_error,
        .for_loop_payload,
        .assign_destructure,
        .switch_payload,
        .switch_inline_tag_payload,
        .label,
        .error_token,
        => tree.tokenSlice(decl_handle.nameToken()),
    };

    return try hoverSymbolResolvedType(
        analyser,
        arena,
        def_str,
        markup_kind,
        &doc_strings,
        maybe_resolved_type,
    );
}

fn hoverSymbolResolvedType(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    def_str: []const u8,
    markup_kind: types.MarkupKind,
    doc_strings: *std.ArrayList([]const u8),
    resolved_type_maybe: ?Analyser.Type,
) error{OutOfMemory}!?[]const u8 {
    var referenced: Analyser.ReferencedType.Set = .empty;
    var resolved_type_strings: std.ArrayList([]const u8) = .empty;
    var has_more = false;
    if (resolved_type_maybe) |resolved_type| {
        if (try resolved_type.docComments(arena)) |doc|
            try doc_strings.append(arena, doc);
        const typeof = try resolved_type.typeOf(analyser);
        var possible_types: Analyser.Type.ArraySet = .empty;
        has_more = try typeof.getAllTypesWithHandlesArraySet(analyser, &possible_types);
        for (possible_types.keys()) |ty| {
            try resolved_type_strings.append(
                arena,
                try ty.stringifyTypeVal(analyser, .{
                    .referenced = &referenced,
                    .truncate_container_decls = possible_types.count() > 1,
                }),
            );
        }
    }
    const referenced_types: []const Analyser.ReferencedType = referenced.keys();
    return try hoverSymbolResolved(
        arena,
        markup_kind,
        doc_strings.items,
        def_str,
        resolved_type_strings.items,
        has_more,
        referenced_types,
    );
}

fn hoverSymbolResolved(
    arena: std.mem.Allocator,
    markup_kind: types.MarkupKind,
    doc_strings: []const []const u8,
    def_str: []const u8,
    resolved_type_strings: []const []const u8,
    has_more: bool,
    referenced_types: []const Analyser.ReferencedType,
) error{OutOfMemory}![]const u8 {
    var output: std.ArrayList(u8) = .empty;

    if (markup_kind == .markdown) {
        try output.print(arena, "```zig\n{s}\n```", .{def_str});
        for (resolved_type_strings) |resolved_type_str|
            try output.print(arena, "\n```zig\n({s})\n```", .{resolved_type_str});
        if (resolved_type_strings.len == 0)
            try output.appendSlice(arena, "\n```zig\n(unknown)\n```");
        if (has_more)
            try output.print(arena, "\n```txt\n(...)\n```", .{});
        if (referenced_types.len > 0)
            try output.print(arena, "\n\n" ++ "Go to ", .{});
        for (referenced_types, 0..) |ref, index| {
            if (index > 0)
                try output.print(arena, " | ", .{});
            const source_index = ref.handle.tree.tokenStart(ref.token);
            const line = 1 + std.mem.count(u8, ref.handle.tree.source[0..source_index], "\n");
            try output.print(arena, "[{s}]({s}#L{d})", .{ ref.str, ref.handle.uri, line });
        }
    } else {
        try output.print(arena, "{s}", .{def_str});
        for (resolved_type_strings) |resolved_type_str|
            try output.print(arena, "\n({s})", .{resolved_type_str});
        if (resolved_type_strings.len == 0)
            try output.appendSlice(arena, "\n(unknown)");
        if (has_more)
            try output.print(arena, "\n(...)", .{});
    }

    if (doc_strings.len > 0) {
        try output.appendSlice(arena, "\n\n");
        for (doc_strings, 0..) |doc, i| {
            try output.appendSlice(arena, doc);
            if (i != doc_strings.len - 1) try output.appendSlice(arena, "\n\n");
        }
    }

    return output.items;
}

fn hoverDefinitionLabel(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    loc: offsets.Loc,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = offsets.locToSlice(handle.tree.source, loc);
    const decl = (try Analyser.lookupLabel(handle, name, pos_index)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(analyser, arena, decl, markup_kind)) orelse return null,
            },
        },
        .range = offsets.locToRange(handle.tree.source, loc, offset_encoding),
    };
}

fn hoverDefinitionBuiltin(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    name_loc: offsets.Loc,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    _ = analyser;
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = offsets.locToSlice(handle.tree.source, name_loc);

    var contents: std.ArrayList(u8) = .empty;

    if (std.mem.eql(u8, name, "@cImport")) blk: {
        const index = for (handle.cimports.items(.node), 0..) |cimport_node, index| {
            const main_token = handle.tree.nodeMainToken(cimport_node);
            const cimport_loc = offsets.tokenToLoc(handle.tree, main_token);
            if (cimport_loc.start <= pos_index and pos_index <= cimport_loc.end) break index;
        } else break :blk;

        const source = handle.cimports.items(.source)[index];

        switch (markup_kind) {
            .plaintext, .unknown_value => {
                try contents.print(arena,
                    \\{s}
                    \\
                , .{source});
            },
            .markdown => {
                try contents.print(arena,
                    \\```c
                    \\{s}
                    \\```
                    \\
                , .{source});
            },
        }
    }

    const builtin = data.builtins.get(name) orelse return null;

    switch (markup_kind) {
        .plaintext, .unknown_value => {
            try contents.print(arena,
                \\{s}
                \\{s}
            , .{ builtin.signature, builtin.documentation });
        },
        .markdown => {
            try contents.print(arena,
                \\```zig
                \\{s}
                \\```
                \\{s}
            , .{ builtin.signature, builtin.documentation });
        },
    }

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = contents.items,
            },
        },
        .range = offsets.locToRange(handle.tree.source, name_loc, offset_encoding),
    };
}

fn hoverDefinitionGlobal(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_token, const name_loc = Analyser.identifierTokenAndLocFromIndex(handle.tree, pos_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const hover_text = blk: {
        const is_escaped_identifier = handle.tree.source[handle.tree.tokenStart(name_token)] == '@';
        if (!is_escaped_identifier) {
            if (std.mem.eql(u8, name, "_")) return null;
            if (try analyser.resolvePrimitive(name)) |ip_index| {
                const resolved_type_str = try std.fmt.allocPrint(arena, "{f}", .{analyser.ip.typeOf(ip_index).fmt(analyser.ip)});
                break :blk try hoverSymbolResolved(arena, markup_kind, &.{}, name, &.{resolved_type_str}, false, &.{});
            }
        }
        const decl = (try analyser.lookupSymbolGlobal(handle, name, pos_index)) orelse return null;
        break :blk (try hoverSymbol(analyser, arena, decl, markup_kind)) orelse return null;
    };

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = hover_text,
            },
        },
        .range = offsets.tokenToRange(handle.tree, name_token, offset_encoding),
    };
}

fn hoverDefinitionStructInit(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const token = offsets.sourceIndexToTokenIndex(handle.tree, source_index).pickPreferred(&.{.period}, &handle.tree) orelse return null;
    if (token + 1 >= handle.tree.tokens.len) return null;
    if (handle.tree.tokenTag(token + 1) != .l_brace) return null;

    const resolved_type = try analyser.resolveStructInitType(handle, source_index) orelse return null;

    var doc_strings: std.ArrayList([]const u8) = .empty;
    if (try resolved_type.docComments(arena)) |doc|
        try doc_strings.append(arena, doc);

    var referenced: Analyser.ReferencedType.Set = .empty;
    const def_str = try resolved_type.stringifyTypeOf(analyser, .{
        .referenced = &referenced,
        .truncate_container_decls = false,
    });
    const referenced_types: []const Analyser.ReferencedType = referenced.keys();

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = try hoverSymbolResolved(arena, markup_kind, doc_strings.items, def_str, &.{"type"}, false, referenced_types),
            },
        },
        .range = offsets.tokenToRange(handle.tree, token, offset_encoding),
    };
}

fn hoverDefinitionEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_token, const name_loc = Analyser.identifierTokenAndLocFromIndex(handle.tree, source_index) orelse {
        return try hoverDefinitionStructInit(analyser, arena, handle, source_index, markup_kind, offset_encoding);
    };
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const decl = (try analyser.getSymbolEnumLiteral(handle, source_index, name)) orelse return null;

    return .{
        .contents = .{
            .MarkupContent = .{
                .kind = markup_kind,
                .value = (try hoverSymbol(analyser, arena, decl, markup_kind)) orelse return null,
            },
        },
        .range = offsets.tokenToRange(handle.tree, name_token, offset_encoding),
    };
}

fn hoverDefinitionFieldAccess(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var decls: std.ArrayList(Analyser.DeclWithHandle) = .empty;
    var tys: std.ArrayList(Analyser.Type) = .empty;
    const highlight_loc = try analyser.getSymbolFieldAccessesHighlight(arena, handle, source_index, loc, &decls, &tys) orelse return null;

    var content: std.ArrayList([]const u8) = try .initCapacity(arena, decls.items.len + tys.items.len);

    for (decls.items) |decl| {
        content.appendAssumeCapacity(try hoverSymbol(analyser, arena, decl, markup_kind) orelse continue);
    }
    for (tys.items) |ty| {
        const def_str = offsets.locToSlice(handle.tree.source, highlight_loc);
        var doc_strings: std.ArrayList([]const u8) = .empty;
        content.appendAssumeCapacity(try hoverSymbolResolvedType(analyser, arena, def_str, markup_kind, &doc_strings, ty) orelse continue);
    }

    return .{
        .contents = .{ .MarkupContent = .{
            .kind = markup_kind,
            .value = switch (content.items.len) {
                0 => return null,
                1 => content.items[0],
                else => try std.mem.join(arena, "\n\n", content.items),
            },
        } },
        .range = offsets.locToRange(handle.tree.source, highlight_loc, offset_encoding),
    };
}

fn hoverNumberLiteral(
    handle: *DocumentStore.Handle,
    token_index: Ast.TokenIndex,
    arena: std.mem.Allocator,
    markup_kind: types.MarkupKind,
) error{OutOfMemory}!?[]const u8 {
    const tree = handle.tree;
    // number literals get tokenized separately from their minus sign
    const is_negative = tree.tokenTag(token_index -| 1) == .minus;
    const num_slice = tree.tokenSlice(token_index);
    const number = blk: {
        if (tree.tokenTag(token_index) == .char_literal) {
            switch (std.zig.parseCharLiteral(num_slice)) {
                .success => |value| break :blk value,
                else => return null,
            }
        }
        switch (std.zig.parseNumberLiteral(num_slice)) {
            .int => |value| break :blk value,
            else => return null,
        }
    };

    switch (markup_kind) {
        .markdown => return try std.fmt.allocPrint(arena,
            \\| Base | {[value]s:<[count]} |
            \\| ---- | {[dash]s:-<[count]} |
            \\| BIN  | {[sign]s}0b{[number]b:<[len]} |
            \\| OCT  | {[sign]s}0o{[number]o:<[len]} |
            \\| DEC  | {[sign]s}{[number]d:<[len]}   |
            \\| HEX  | {[sign]s}0x{[number]X:<[len]} |
        , .{
            .sign = if (is_negative) "-" else "",
            .dash = "-",
            .value = "Value",
            .number = number,
            .count = @max(@bitSizeOf(@TypeOf(number)) - @clz(number) + "0x".len + @intFromBool(is_negative), "Value".len),
            .len = @max(@bitSizeOf(@TypeOf(number)) - @clz(number), "Value".len - "0x".len),
        }),
        .plaintext, .unknown_value => return try std.fmt.allocPrint(
            arena,
            \\BIN: {[sign]s}0b{[number]b}
            \\OCT: {[sign]s}0o{[number]o}
            \\DEC: {[sign]s}{[number]d}
            \\HEX: {[sign]s}0x{[number]X}
        ,
            .{ .sign = if (is_negative) "-" else "", .number = number },
        ),
    }
}

fn hoverDefinitionNumberLiteral(
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) !?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;
    const token_index = offsets.sourceIndexToTokenIndex(tree, source_index).pickPreferred(&.{ .number_literal, .char_literal }, &tree) orelse return null;
    const num_loc = offsets.tokenToLoc(tree, token_index);
    const hover_text = (try hoverNumberLiteral(handle, token_index, arena, markup_kind)) orelse return null;

    return .{
        .contents = .{ .MarkupContent = .{
            .kind = markup_kind,
            .value = hover_text,
        } },
        .range = offsets.locToRange(handle.tree.source, num_loc, offset_encoding),
    };
}

pub fn hover(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    markup_kind: types.MarkupKind,
    offset_encoding: offsets.Encoding,
) !?types.Hover {
    const pos_context = try Analyser.getPositionContext(arena, handle.tree, source_index, true);

    const response = switch (pos_context) {
        .builtin => |loc| try hoverDefinitionBuiltin(analyser, arena, handle, source_index, loc, markup_kind, offset_encoding),
        .var_access => try hoverDefinitionGlobal(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        .field_access => |loc| try hoverDefinitionFieldAccess(analyser, arena, handle, source_index, loc, markup_kind, offset_encoding),
        .label_access, .label_decl => |loc| try hoverDefinitionLabel(analyser, arena, handle, source_index, loc, markup_kind, offset_encoding),
        .enum_literal => try hoverDefinitionEnumLiteral(analyser, arena, handle, source_index, markup_kind, offset_encoding),
        .number_literal, .char_literal => try hoverDefinitionNumberLiteral(arena, handle, source_index, markup_kind, offset_encoding),
        else => null,
    };

    return response;
}
