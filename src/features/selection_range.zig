const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("../DocumentStore.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");

pub fn generateSelectionRanges(
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    positions: []const types.Position,
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!?[]types.SelectionRange {
    // For each of the input positions, we need to compute the stack of AST
    // nodes/ranges which contain the position. At the moment, we do this in a
    // super inefficient way, by iterating _all_ nodes, selecting the ones that
    // contain position, and then sorting.
    //
    // A faster algorithm would be to walk the tree starting from the root,
    // descending into the child containing the position at every step.
    var result = try arena.alloc(types.SelectionRange, positions.len);
    var locs = try std.ArrayListUnmanaged(offsets.Loc).initCapacity(arena, 32);
    for (positions, result) |position, *out| {
        const index = offsets.positionToIndex(handle.tree.source, position, offset_encoding);

        locs.clearRetainingCapacity();
        for (0..handle.tree.nodes.len) |i| {
            const node = @as(Ast.Node.Index, @intCast(i));
            const loc = offsets.nodeToLoc(handle.tree, node);
            if (loc.start <= index and index <= loc.end) {
                try locs.append(arena, loc);
            }
        }

        std.mem.sort(offsets.Loc, locs.items, {}, shorterLocsFirst);
        {
            var i: usize = 0;
            while (i + 1 < locs.items.len) {
                if (std.meta.eql(locs.items[i], locs.items[i + 1])) {
                    _ = locs.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        var selection_ranges = try arena.alloc(types.SelectionRange, locs.items.len);
        for (selection_ranges, 0..) |*range, i| {
            range.range = offsets.locToRange(handle.tree.source, locs.items[i], offset_encoding);
            range.parent = if (i + 1 < selection_ranges.len) &selection_ranges[i + 1] else null;
        }
        out.* = selection_ranges[0];
    }

    return result;
}

fn shorterLocsFirst(_: void, lhs: offsets.Loc, rhs: offsets.Loc) bool {
    return (lhs.end - lhs.start) < (rhs.end - rhs.start);
}
