const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_goto);

const ast = @import("../ast.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const tracy = @import("../tracy.zig");

const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");

pub const GotoKind = enum {
    declaration,
    definition,
    type_definition,
};

fn gotoDefinitionSymbol(
    analyser: *Analyser,
    name_range: types.Range,
    decl_handle: Analyser.DeclWithHandle,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const token_handle = switch (kind) {
        .declaration => try decl_handle.definitionToken(analyser, false),
        .definition => try decl_handle.definitionToken(analyser, true),
        .type_definition => blk: {
            const resolved_type = try decl_handle.resolveType(analyser) orelse
                return null;

            break :blk resolved_type.typeDefinitionToken() orelse
                return null;
        },
    };
    const target_range = offsets.tokenToRange(token_handle.handle.tree, token_handle.token, offset_encoding);

    return types.DefinitionLink{
        .originSelectionRange = name_range,
        .targetUri = token_handle.handle.uri,
        .targetRange = target_range,
        .targetSelectionRange = target_range,
    };
}

fn gotoDefinitionLabel(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    _ = arena;

    const name_loc = Analyser.identifierLocFromPosition(pos_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try Analyser.getLabelGlobal(pos_index, handle, name)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.text, name_loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionGlobal(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    _ = arena;

    const name_loc = Analyser.identifierLocFromPosition(pos_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try analyser.getSymbolGlobal(pos_index, handle, name)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.text, name_loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(source_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const decl = (try analyser.getSymbolEnumLiteral(arena, handle, source_index, name)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.text, name_loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionBuiltin(
    document_store: *DocumentStore,
    handle: *const DocumentStore.Handle,
    loc: offsets.Loc,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = offsets.tokenIndexToLoc(handle.text, loc.start);
    const name = offsets.locToSlice(handle.text, name_loc);
    if (std.mem.eql(u8, name, "@cImport")) {
        const index = for (handle.cimports.items(.node), 0..) |cimport_node, index| {
            const main_token = handle.tree.nodes.items(.main_token)[cimport_node];
            if (loc.start == offsets.tokenToIndex(handle.tree, main_token)) break index;
        } else return null;
        const hash = handle.cimports.items(.hash)[index];

        const result = document_store.cimports.get(hash) orelse return null;
        const target_range = types.Range{
            .start = .{ .line = 0, .character = 0 },
            .end = .{ .line = 0, .character = 0 },
        };
        switch (result) {
            .failure => return null,
            .success => |uri| return types.DefinitionLink{
                .originSelectionRange = offsets.locToRange(handle.text, name_loc, offset_encoding),
                .targetUri = uri,
                .targetRange = target_range,
                .targetSelectionRange = target_range,
            },
        }
    }

    return null;
}

fn gotoDefinitionFieldAccess(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?[]const types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromPosition(source_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const held_loc = offsets.locMerge(loc, name_loc);
    const accesses = (try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name)) orelse return null;
    var locs = std.ArrayListUnmanaged(types.DefinitionLink){};

    for (accesses) |access| {
        if (try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.text, name_loc, offset_encoding), access, kind, offset_encoding)) |l|
            try locs.append(arena, l);
    }

    if (locs.items.len == 0)
        return null;

    return try locs.toOwnedSlice(arena);
}

fn gotoDefinitionString(
    document_store: *DocumentStore,
    arena: std.mem.Allocator,
    pos_context: Analyser.PositionContext,
    handle: *const DocumentStore.Handle,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const loc = pos_context.loc().?;
    var import_str_loc = offsets.tokenIndexToLoc(handle.tree.source, loc.start);
    if (import_str_loc.end - import_str_loc.start < 2) return null;
    import_str_loc.start += 1;
    if (std.mem.endsWith(u8, offsets.locToSlice(handle.tree.source, import_str_loc), "\"")) {
        import_str_loc.end -= 1;
    }
    const import_str = offsets.locToSlice(handle.tree.source, import_str_loc);

    const uri = switch (pos_context) {
        .import_string_literal,
        .embedfile_string_literal,
        => try document_store.uriFromImportStr(arena, handle.*, import_str),
        .cinclude_string_literal => try URI.fromPath(
            arena,
            blk: {
                if (std.fs.path.isAbsolute(import_str)) break :blk import_str;
                var include_dirs: std.ArrayListUnmanaged([]const u8) = .{};
                _ = document_store.collectIncludeDirs(arena, handle.*, &include_dirs) catch |err| {
                    log.err("failed to resolve include paths: {}", .{err});
                    return null;
                };
                for (include_dirs.items) |dir| {
                    const path = try std.fs.path.join(arena, &.{ dir, import_str });
                    std.fs.accessAbsolute(path, .{}) catch continue;
                    break :blk path;
                }
                return null;
            },
        ),
        else => unreachable,
    };

    const target_range = types.Range{
        .start = .{ .line = 0, .character = 0 },
        .end = .{ .line = 0, .character = 0 },
    };
    return types.DefinitionLink{
        .originSelectionRange = offsets.locToRange(handle.text, import_str_loc, offset_encoding),
        .targetUri = uri orelse return null,
        .targetRange = target_range,
        .targetSelectionRange = target_range,
    };
}

pub fn goto(
    analyser: *Analyser,
    document_store: *DocumentStore,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) !?[]const types.DefinitionLink {
    const pos_context = try Analyser.getPositionContext(arena, handle.text, source_index, true);
    var links = std.ArrayListUnmanaged(types.DefinitionLink){};

    try links.append(arena, switch (pos_context) {
        .builtin => |loc| try gotoDefinitionBuiltin(document_store, handle, loc, offset_encoding),
        .var_access => try gotoDefinitionGlobal(analyser, arena, handle, source_index, kind, offset_encoding),
        .field_access => |loc| return try gotoDefinitionFieldAccess(analyser, arena, handle, source_index, loc, kind, offset_encoding),
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        => try gotoDefinitionString(document_store, arena, pos_context, handle, offset_encoding),
        .label => try gotoDefinitionLabel(analyser, arena, handle, source_index, kind, offset_encoding),
        .enum_literal => try gotoDefinitionEnumLiteral(analyser, arena, handle, source_index, kind, offset_encoding),
        else => null,
    } orelse return null);

    return try links.toOwnedSlice(arena);
}
