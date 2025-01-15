//! Implementation of:
//! - [`textDocument/declaration`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_declaration)
//! - [`textDocument/definition`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_definition)
//! - [`textDocument/typeDefinition`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_typeDefinition)
//! - [`textDocument/implementation`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_implementation) (same behaviour as `textDocument/definition`)

const std = @import("std");
const log = std.log.scoped(.goto);

const Server = @import("../Server.zig");
const lsp = @import("lsp");
const types = lsp.types;
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const tracy = @import("tracy");

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
            if (try decl_handle.resolveType(analyser)) |ty| {
                if (try ty.typeDefinitionToken()) |token_handle| break :blk token_handle;
            }
            const type_declaration = try decl_handle.typeDeclarationNode() orelse return null;

            const target_range = offsets.nodeToRange(type_declaration.handle.tree, type_declaration.node, offset_encoding);
            return .{
                .originSelectionRange = name_range,
                .targetUri = type_declaration.handle.uri,
                .targetRange = target_range,
                .targetSelectionRange = target_range,
            };
        },
    };
    const target_range = offsets.tokenToRange(token_handle.handle.tree, token_handle.token, offset_encoding);

    return .{
        .originSelectionRange = name_range,
        .targetUri = token_handle.handle.uri,
        .targetRange = target_range,
        .targetSelectionRange = target_range,
    };
}

fn gotoDefinitionLabel(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    loc: offsets.Loc,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromIndex(handle.tree, pos_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const decl = (try Analyser.lookupLabel(handle, name, pos_index)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.tree.source, loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionGlobal(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromIndex(handle.tree, pos_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const decl = (try analyser.lookupSymbolGlobal(handle, name, pos_index)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.tree.source, name_loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromIndex(handle.tree, source_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const decl = (try analyser.getSymbolEnumLiteral(arena, handle, source_index, name)) orelse return null;
    return try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.tree.source, name_loc, offset_encoding), decl, kind, offset_encoding);
}

fn gotoDefinitionBuiltin(
    document_store: *DocumentStore,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = offsets.tokenIndexToLoc(handle.tree.source, loc.start);
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    if (std.mem.eql(u8, name, "@cImport")) {
        const tree = handle.tree;
        const index = for (handle.cimports.items(.node), 0..) |cimport_node, index| {
            const main_token = tree.nodes.items(.main_token)[cimport_node];
            if (loc.start == offsets.tokenToIndex(tree, main_token)) break index;
        } else return null;
        const hash = handle.cimports.items(.hash)[index];

        const result = document_store.cimports.get(hash) orelse return null;
        const target_range: types.Range = .{
            .start = .{ .line = 0, .character = 0 },
            .end = .{ .line = 0, .character = 0 },
        };
        switch (result) {
            .failure => return null,
            .success => |uri| return .{
                .originSelectionRange = offsets.locToRange(handle.tree.source, name_loc, offset_encoding),
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
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    kind: GotoKind,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?[]const types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name_loc = Analyser.identifierLocFromIndex(handle.tree, source_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const held_loc = offsets.locMerge(loc, name_loc);
    const accesses = (try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name)) orelse return null;
    var locs: std.ArrayListUnmanaged(types.DefinitionLink) = .empty;

    for (accesses) |access| {
        if (try gotoDefinitionSymbol(analyser, offsets.locToRange(handle.tree.source, name_loc, offset_encoding), access, kind, offset_encoding)) |l|
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
    handle: *DocumentStore.Handle,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?types.DefinitionLink {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const loc = pos_context.stringLiteralContentLoc(handle.tree.source);
    if (loc.start == loc.end) return null;
    const import_str = offsets.locToSlice(handle.tree.source, loc);

    const uri = switch (pos_context) {
        .import_string_literal,
        .embedfile_string_literal,
        => try document_store.uriFromImportStr(arena, handle, import_str),
        .cinclude_string_literal => try URI.fromPath(
            arena,
            blk: {
                if (std.fs.path.isAbsolute(import_str)) break :blk import_str;
                var include_dirs: std.ArrayListUnmanaged([]const u8) = .empty;
                _ = document_store.collectIncludeDirs(arena, handle, &include_dirs) catch |err| {
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

    const target_range: types.Range = .{
        .start = .{ .line = 0, .character = 0 },
        .end = .{ .line = 0, .character = 0 },
    };
    return .{
        .originSelectionRange = offsets.locToRange(handle.tree.source, loc, offset_encoding),
        .targetUri = uri orelse return null,
        .targetRange = target_range,
        .targetSelectionRange = target_range,
    };
}

pub fn gotoHandler(
    server: *Server,
    arena: std.mem.Allocator,
    kind: GotoKind,
    request: types.DefinitionParams,
) Server.Error!lsp.ResultType("textDocument/definition") {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    var analyser = server.initAnalyser(handle);
    defer analyser.deinit();

    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);
    const pos_context = try Analyser.getPositionContext(arena, handle.tree, source_index, true);

    const response = switch (pos_context) {
        .builtin => |loc| try gotoDefinitionBuiltin(&server.document_store, handle, loc, server.offset_encoding),
        .var_access => try gotoDefinitionGlobal(&analyser, handle, source_index, kind, server.offset_encoding),
        .field_access => |loc| blk: {
            const links = try gotoDefinitionFieldAccess(&analyser, arena, handle, source_index, loc, kind, server.offset_encoding) orelse return null;
            if (server.client_capabilities.supports_textDocument_definition_linkSupport) {
                return .{ .array_of_DefinitionLink = links };
            }
            switch (links.len) {
                0 => unreachable,
                1 => break :blk links[0],
                else => return null,
            }
        },
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        => try gotoDefinitionString(&server.document_store, arena, pos_context, handle, server.offset_encoding),
        .label_access, .label_decl => |loc| try gotoDefinitionLabel(&analyser, handle, source_index, loc, kind, server.offset_encoding),
        .enum_literal => try gotoDefinitionEnumLiteral(&analyser, arena, handle, source_index, kind, server.offset_encoding),
        else => null,
    } orelse return null;

    if (server.client_capabilities.supports_textDocument_definition_linkSupport) {
        return .{
            .array_of_DefinitionLink = try arena.dupe(types.DefinitionLink, &.{response}),
        };
    }

    return .{
        .Definition = .{ .Location = .{
            .uri = response.targetUri,
            .range = response.targetSelectionRange,
        } },
    };
}
