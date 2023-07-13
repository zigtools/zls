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

pub fn gotoDefinitionSymbol(
    analyser: *Analyser,
    decl_handle: Analyser.DeclWithHandle,
    resolve_alias: bool,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle = decl_handle.handle;

    const name_token = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analyser.resolveVarDeclAlias(.{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;

                    break :block result.nameToken();
                }
            }

            break :block Analyser.getDeclNameToken(handle.tree, node) orelse return null;
        },
        else => decl_handle.nameToken(),
    };

    return types.Location{
        .uri = handle.uri,
        .range = offsets.tokenToRange(handle.tree, name_token, offset_encoding),
    };
}

pub fn gotoDefinitionLabel(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    _ = arena;

    const decl = (try Analyser.getLabelGlobal(pos_index, handle)) orelse return null;
    return try gotoDefinitionSymbol(analyser, decl, false, offset_encoding);
}

pub fn gotoDefinitionGlobal(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
    resolve_alias: bool,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    _ = arena;

    const decl = (try analyser.getSymbolGlobal(pos_index, handle)) orelse return null;
    return try gotoDefinitionSymbol(analyser, decl, resolve_alias, offset_encoding);
}

pub fn gotoDefinitionEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try analyser.getSymbolEnumLiteral(arena, handle, source_index)) orelse return null;
    return try gotoDefinitionSymbol(analyser, decl, false, offset_encoding);
}

pub fn gotoDefinitionBuiltin(
    document_store: *DocumentStore,
    handle: *const DocumentStore.Handle,
    loc: offsets.Loc,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = offsets.tokenIndexToSlice(handle.tree.source, loc.start);
    if (std.mem.eql(u8, name, "@cImport")) {
        const index = for (handle.cimports.items(.node), 0..) |cimport_node, index| {
            const main_token = handle.tree.nodes.items(.main_token)[cimport_node];
            if (loc.start == offsets.tokenToIndex(handle.tree, main_token)) break index;
        } else return null;
        const hash = handle.cimports.items(.hash)[index];

        const result = document_store.cimports.get(hash) orelse return null;
        switch (result) {
            .failure => return null,
            .success => |uri| return types.Location{
                .uri = uri,
                .range = .{
                    .start = .{ .line = 0, .character = 0 },
                    .end = .{ .line = 0, .character = 0 },
                },
            },
        }
    }

    return null;
}

pub fn gotoDefinitionFieldAccess(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    resolve_alias: bool,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?[]const types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const accesses = (try analyser.getSymbolFieldAccesses(arena, handle, source_index, loc)) orelse return null;
    var locs = std.ArrayListUnmanaged(types.Location){};

    for (accesses) |access| {
        if (try gotoDefinitionSymbol(analyser, access, resolve_alias, offset_encoding)) |l|
            try locs.append(arena, l);
    }

    if (locs.items.len == 0)
        return null;

    return try locs.toOwnedSlice(arena);
}

pub fn gotoDefinitionString(
    document_store: *DocumentStore,
    arena: std.mem.Allocator,
    pos_context: Analyser.PositionContext,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const loc = pos_context.loc().?;
    const import_str_loc = offsets.tokenIndexToLoc(handle.tree.source, loc.start);
    if (import_str_loc.end - import_str_loc.start < 2) return null;
    var import_str = offsets.locToSlice(handle.tree.source, .{
        .start = import_str_loc.start + 1,
        .end = import_str_loc.end - 1,
    });

    const uri = switch (pos_context) {
        .import_string_literal,
        .embedfile_string_literal,
        => try document_store.uriFromImportStr(arena, handle.*, import_str),
        .cinclude_string_literal => try URI.fromPath(
            arena,
            blk: {
                if (std.fs.path.isAbsolute(import_str)) break :blk import_str;
                var include_dirs: std.ArrayListUnmanaged([]const u8) = .{};
                document_store.collectIncludeDirs(arena, handle.*, &include_dirs) catch |err| {
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

    return types.Location{
        .uri = uri orelse return null,
        .range = .{
            .start = .{ .line = 0, .character = 0 },
            .end = .{ .line = 0, .character = 0 },
        },
    };
}

pub fn goto(
    analyser: *Analyser,
    document_store: *DocumentStore,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    resolve_alias: bool,
    offset_encoding: offsets.Encoding,
) !?types.Definition {
    const pos_context = try Analyser.getPositionContext(arena, handle.text, source_index, true);

    return switch (pos_context) {
        .builtin => |loc| .{ .Location = (try gotoDefinitionBuiltin(document_store, handle, loc)) orelse return null },
        .var_access => .{ .Location = (try gotoDefinitionGlobal(analyser, arena, handle, source_index, resolve_alias, offset_encoding)) orelse return null },
        .field_access => |loc| .{ .array_of_Location = (try gotoDefinitionFieldAccess(analyser, arena, handle, source_index, loc, resolve_alias, offset_encoding)) orelse return null },
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        => .{ .Location = (try gotoDefinitionString(document_store, arena, pos_context, handle)) orelse return null },
        .label => .{ .Location = (try gotoDefinitionLabel(analyser, arena, handle, source_index, offset_encoding)) orelse return null },
        .enum_literal => .{ .Location = (try gotoDefinitionEnumLiteral(analyser, arena, handle, source_index, offset_encoding)) orelse return null },
        else => null,
    };
}
