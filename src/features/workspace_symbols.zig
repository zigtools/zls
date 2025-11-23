//! Implementation of [`workspace/symbol`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#workspace_symbol)

const std = @import("std");

const lsp = @import("lsp");
const types = lsp.types;

const DocumentStore = @import("../DocumentStore.zig");
const offsets = @import("../offsets.zig");
const Server = @import("../Server.zig");
const TrigramStore = @import("../TrigramStore.zig");

pub fn handler(server: *Server, arena: std.mem.Allocator, request: types.workspace.Symbol.Params) error{OutOfMemory}!lsp.ResultType("workspace/symbol") {
    if (request.query.len == 0) return null;

    var workspace_paths: std.ArrayList([]const u8) = try .initCapacity(arena, server.workspaces.items.len);
    for (server.workspaces.items) |workspace| {
        const path = workspace.uri.toFsPath(arena) catch |err| switch (err) {
            error.UnsupportedScheme => return null, // https://github.com/microsoft/language-server-protocol/issues/1264
            error.OutOfMemory => return error.OutOfMemory,
        };
        workspace_paths.appendAssumeCapacity(path);
    }

    const handles = try server.document_store.loadTrigramStores(workspace_paths.items);
    defer server.document_store.allocator.free(handles);

    var symbols: std.ArrayListUnmanaged(types.workspace.Symbol) = .empty;
    var declaration_buffer: std.ArrayListUnmanaged(TrigramStore.Declaration.Index) = .empty;

    for (handles) |handle| {
        const trigram_store = handle.getTrigramStoreCached();

        declaration_buffer.clearRetainingCapacity();
        try trigram_store.declarationsForQuery(arena, request.query, &declaration_buffer);

        const SortContext = struct {
            names: []const std.zig.Ast.TokenIndex,
            fn lessThan(ctx: @This(), lhs: TrigramStore.Declaration.Index, rhs: TrigramStore.Declaration.Index) bool {
                return ctx.names[@intFromEnum(lhs)] < ctx.names[@intFromEnum(rhs)];
            }
        };

        std.mem.sortUnstable(
            TrigramStore.Declaration.Index,
            declaration_buffer.items,
            SortContext{ .names = trigram_store.declarations.items(.name) },
            SortContext.lessThan,
        );

        const slice = trigram_store.declarations.slice();
        const names = slice.items(.name);
        const kinds = slice.items(.kind);

        var last_index: usize = 0;
        var last_position: offsets.Position = .{ .line = 0, .character = 0 };

        try symbols.ensureUnusedCapacity(arena, declaration_buffer.items.len);
        for (declaration_buffer.items) |declaration| {
            const name_token = names[@intFromEnum(declaration)];
            const kind = kinds[@intFromEnum(declaration)];

            const loc = switch (handle.tree.tokenTag(name_token)) {
                .identifier => offsets.identifierTokenToNameLoc(&handle.tree, name_token),
                .string_literal => offsets.tokenToLoc(&handle.tree, name_token),
                else => unreachable,
            };
            const name = offsets.locToSlice(handle.tree.source, loc);

            const start_position = offsets.advancePosition(handle.tree.source, last_position, last_index, loc.start, server.offset_encoding);
            const end_position = offsets.advancePosition(handle.tree.source, start_position, loc.start, loc.end, server.offset_encoding);
            last_index = loc.end;
            last_position = end_position;

            symbols.appendAssumeCapacity(.{
                .name = name,
                .kind = switch (kind) {
                    .variable => .Variable,
                    .constant => .Constant,
                    .function => .Function,
                    .test_function => .Method, // there is no SymbolKind that represents a tests,
                },
                .location = .{
                    .location = .{
                        .uri = handle.uri.raw,
                        .range = .{
                            .start = start_position,
                            .end = end_position,
                        },
                    },
                },
            });
        }
    }

    return .{ .workspace_symbols = symbols.items };
}
