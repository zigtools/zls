const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const ErrorBuilder = @import("../ErrorBuilder.zig");

const offsets = zls.offsets;
const ast = zls.ast;

const allocator = std.testing.allocator;

test "nodesAtLoc" {
    try testNodesAtLoc(
        \\<outer><inner><inner><outer>
    );
    try testNodesAtLoc(
        \\<outer><inner>var alpha = 1<inner><outer>;
    );
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
    try testNodesAtLoc(
        \\var alpha = 1;
        \\var beta = alpha + alpha;
        \\<outer>var gamma<inner> = beta * alpha;
        \\var delta = gamma - 2;
        \\var epsilon = delta - <inner>beta<outer>;
        \\var zeta = epsilon * epsilon;
    );
    try testNodesAtLoc(
        \\<outer><inner>var alpha = 1;
        \\var beta = alpha + alpha;<inner>
        \\var gamma = beta * alpha<outer>;
        \\var epsilon = delta - beta;
    );
    try testNodesAtLoc(
        \\fn foo() void {
        \\
        \\}
        \\<outer>fn <inner>bar() void {
        \\    <inner>
        \\}<outer>
        \\fn baz() void {
        \\
        \\}
    );
    try testNodesAtLoc(
        \\var alpha = 1;
        \\<outer>var beta = alpha + alpha;
        \\// some comment
        \\// <inner>because it is<inner>
        \\// not a node
        \\var gamma = beta * alpha<outer>;
        \\var epsilon = delta - beta;
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

    const inner_loc: offsets.Loc = .{ .start = locs[1].start, .end = locs[2].start };
    const outer_loc: offsets.Loc = .{ .start = locs[0].start, .end = locs[3].end };

    const new_source = try allocator.dupeZ(u8, ccp.new_source);
    defer allocator.free(new_source);

    var tree: std.zig.Ast = try .parse(allocator, new_source, .zig);
    defer tree.deinit(allocator);

    const nodes = try ast.nodesAtLoc(allocator, tree, inner_loc);
    defer allocator.free(nodes);

    const actual_loc: offsets.Loc = .{
        .start = offsets.nodeToLoc(tree, nodes[0]).start,
        .end = offsets.nodeToLoc(tree, nodes[nodes.len - 1]).end,
    };

    const uri = "file.zig";
    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(uri, new_source);

    if (outer_loc.start != actual_loc.start) {
        try error_builder.msgAtIndex("actual start here", uri, actual_loc.start, .err, .{});
        try error_builder.msgAtIndex("expected start here", uri, outer_loc.start, .err, .{});
        return error.LocStartMismatch;
    }

    if (outer_loc.end != actual_loc.end) {
        try error_builder.msgAtIndex("actual end here", uri, actual_loc.end, .err, .{});
        try error_builder.msgAtIndex("expected end here", uri, outer_loc.end, .err, .{});
        return error.LocEndMismatch;
    }
}
