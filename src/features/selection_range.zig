//! Implementation of [`textDocument/selectionRange`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_selectionRange)

const std = @import("std");
const Ast = @import("zirp").Ast;

const DocumentStore = @import("../DocumentStore.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");

pub const Error = error{ OutOfMemory, Canceled, InvalidParams };

pub fn @"textDocument/selectionRange"(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.SelectionRange.Params,
) Error!?[]types.SelectionRange {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;

    const tree = &handle.tree;
    var mappings: std.ArrayList(offsets.multiple.IndexToPositionMapping) = .empty;
    const result = try arena.alloc(types.SelectionRange, request.positions.len);
    for (request.positions, result) |position, *root_selection_range| {
        const source_index = offsets.positionToIndex(handle.tree.source, position, server.offset_encoding);

        var stack: std.ArrayList(offsets.Loc) = .empty;
        var walker: ast.Walker = try .init(arena, tree, .root);
        defer walker.deinit(arena);
        while (try walker.next(arena, tree)) |event| {
            switch (event) {
                .open => |node| {
                    const loc = offsets.nodeToLoc(tree, node);
                    if (loc.start <= source_index and source_index <= loc.end) {
                        try stack.append(arena, loc);
                    } else {
                        walker.skip();
                    }
                },
                .close => break,
            }
        }

        var builder: Builder = .init(root_selection_range, &mappings);
        if (stack.items.len == 0) {
            try builder.add(arena, offsets.nodeToLoc(tree, .root));
            continue;
        }
        while (stack.pop()) |loc| {
            try builder.add(arena, loc);
        }
    }
    offsets.multiple.indexToPositionWithMappings(tree.source, mappings.items, server.offset_encoding);
    return result;
}

const Builder = struct {
    node: *types.SelectionRange,
    is_node_uninitalized: bool,
    mappings: *std.ArrayList(offsets.multiple.IndexToPositionMapping),

    // `add` must be called at least once afterwards to initalize `root_selection_range`.
    fn init(
        root_selection_range: *types.SelectionRange,
        mappings: *std.ArrayList(offsets.multiple.IndexToPositionMapping),
    ) Builder {
        root_selection_range.* = undefined;
        return .{
            .node = root_selection_range,
            .is_node_uninitalized = true,
            .mappings = mappings,
        };
    }

    fn add(b: *Builder, arena: std.mem.Allocator, loc: offsets.Loc) error{OutOfMemory}!void {
        const new = if (b.is_node_uninitalized) b.node else try arena.create(types.SelectionRange);
        const current = if (b.is_node_uninitalized) null else b.node;
        new.* = .{
            .range = undefined, // set below
            .parent = null,
        };
        if (current) |c| c.parent = new;
        b.node = new;
        b.is_node_uninitalized = false;
        try b.mappings.appendSlice(arena, &.{
            .{ .output = &new.range.start, .source_index = loc.start },
            .{ .output = &new.range.end, .source_index = loc.end },
        });
    }
};
