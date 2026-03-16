//! Implementation of [`textDocument/selectionRange`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_selectionRange)

const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("../DocumentStore.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");

pub fn generateSelectionRanges(
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    positions: []const types.Position,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?[]types.SelectionRange {
    const tree = &handle.tree;
    var mappings: std.ArrayList(offsets.multiple.IndexToPositionMapping) = .empty;
    const result = try arena.alloc(types.SelectionRange, positions.len);
    for (positions, result) |position, *root_selection_range| {
        const source_index = offsets.positionToIndex(handle.tree.source, position, offset_encoding);

        var stack: std.ArrayList(struct { Ast.Node.Index, offsets.Loc }) = .empty;
        var walker: ast.Walker = try .init(arena, tree, .root);
        defer walker.deinit(arena);
        while (try walker.next(arena, tree)) |event| {
            switch (event) {
                .open => |node| {
                    const loc = offsets.nodeToLoc(tree, node);
                    if (loc.start <= source_index and source_index <= loc.end) {
                        try stack.append(arena, .{ node, loc });
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
        while (stack.pop()) |item| {
            const node = item[0];
            const loc = item[1];

            switch (tree.nodeTag(node)) {
                // Function parameters are not stored in the AST explicitly, iterate over them
                // manually.
                .fn_proto, .fn_proto_multi, .fn_proto_one, .fn_proto_simple => {
                    var buffer: [1]Ast.Node.Index = undefined;
                    const fn_proto = handle.tree.fullFnProto(&buffer, node).?;
                    var param_it: ast.FnParamIterator = .init(&fn_proto, &handle.tree);
                    while (param_it.next()) |param| {
                        const param_loc = ast.paramLoc(tree, param, true);
                        if (!(param_loc.start <= source_index and source_index <= param_loc.end)) continue;
                        try builder.add(arena, param_loc);
                        break;
                    }
                },
                else => {},
            }

            try builder.add(arena, loc);
        }
    }
    offsets.multiple.indexToPositionWithMappings(tree.source, mappings.items, offset_encoding);
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
