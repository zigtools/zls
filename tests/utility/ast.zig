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

test "smallestEnclosingSubrange" {
    const children = &[_]offsets.Loc{
        .{ .start = 0, .end = 5 },
        .{ .start = 5, .end = 10 },
        .{ .start = 12, .end = 18 },
        .{ .start = 18, .end = 22 },
        .{ .start = 25, .end = 28 },
    };

    try std.testing.expect(ast.smallestEnclosingSubrange(&.{}, undefined) == null);

    // children  <-->
    // loc       <--->
    // result    null
    try std.testing.expect(
        ast.smallestEnclosingSubrange(&.{.{ .start = 0, .end = 4 }}, .{ .start = 0, .end = 5 }) == null,
    );

    // children  <---><--->  <----><-->   <->
    // loc       <---------------------------->
    // result    null
    try std.testing.expect(ast.smallestEnclosingSubrange(children, .{ .start = 0, .end = 30 }) == null);

    // children  <---><--->  <----><-->   <->
    // loc             <--------->
    // result         <--->  <---->
    const result1 = ast.smallestEnclosingSubrange(children, .{ .start = 6, .end = 17 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..3],
        children[result1.start .. result1.start + result1.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc            <------------->
    // result         <--->  <----><-->
    const result2 = ast.smallestEnclosingSubrange(children, .{ .start = 6, .end = 20 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..4],
        children[result2.start .. result2.start + result2.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc                 <----------->
    // result         <--->  <----><-->   <->
    const result3 = ast.smallestEnclosingSubrange(children, .{ .start = 10, .end = 23 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..5],
        children[result3.start .. result3.start + result3.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc                 <>
    // result         <--->  <---->
    const result4 = ast.smallestEnclosingSubrange(children, .{ .start = 10, .end = 12 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..3],
        children[result4.start .. result4.start + result4.len],
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
