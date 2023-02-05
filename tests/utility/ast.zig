const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;
const ast = zls.ast;

const allocator = std.testing.allocator;

test "nodesAtLoc" {
    try testNodesAtLoc(
        \\<outer>const<inner> foo<inner> = 5<outer>;
    );
    try testNodesAtLoc(
        \\<outer>const f<inner>oo = 5;
        \\var bar = <inner>2<outer>;
    );
    try testNodesAtLoc(
        \\const foo = <outer>5<inner> +<inner> 2<outer>;
    );
    try testNodesAtLoc(
        \\<outer><inner>fn foo(alpha: u32) void {}
        \\const _ = foo(5);<inner><outer>
    );
}

fn testNodesAtLoc(source: []const u8) !void {
    var ccp = try helper.collectClearPlaceholders(allocator, source);
    defer ccp.deinit(allocator);

    const old_locs = ccp.locations.items(.old);
    const locs = ccp.locations.items(.new);

    std.debug.assert(ccp.locations.len == 4);
    std.debug.assert(std.mem.eql(u8, offsets.locToSlice(source, old_locs[0]), "<outer>"));
    std.debug.assert(std.mem.eql(u8, offsets.locToSlice(source, old_locs[1]), "<inner>"));
    std.debug.assert(std.mem.eql(u8, offsets.locToSlice(source, old_locs[2]), "<inner>"));
    std.debug.assert(std.mem.eql(u8, offsets.locToSlice(source, old_locs[3]), "<outer>"));

    const inner_loc = offsets.Loc{ .start = locs[1].start, .end = locs[2].start };
    const outer_loc = offsets.Loc{ .start = locs[0].start, .end = locs[3].end };

    const new_source = try allocator.dupeZ(u8, ccp.new_source);
    defer allocator.free(new_source);

    var tree = try std.zig.Ast.parse(allocator, new_source, .zig);
    defer tree.deinit(allocator);

    const nodes = try ast.nodesAtLoc(allocator, tree, inner_loc);
    defer allocator.free(nodes);

    const actual_loc = offsets.Loc{
        .start = offsets.nodeToLoc(tree, nodes[0]).start,
        .end = offsets.nodeToLoc(tree, nodes[nodes.len - 1]).end,
    };

    var error_builder = ErrorBuilder.init(allocator, new_source);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    if (outer_loc.start != actual_loc.start) {
        try error_builder.msgAtIndex("actual start here", actual_loc.start, .err, .{});
        try error_builder.msgAtIndex("expected start here", outer_loc.start, .err, .{});
        return error.LocStartMismatch;
    }

    if (outer_loc.end != actual_loc.end) {
        try error_builder.msgAtIndex("actual end here", actual_loc.end, .err, .{});
        try error_builder.msgAtIndex("expected end here", outer_loc.end, .err, .{});
        return error.LocEndMismatch;
    }
}
