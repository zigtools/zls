const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;

const types = zls.lsp.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "empty" {
    try testSelectionRange("<>", &.{});
}

test "smoke" {
    try testSelectionRange(
        \\fn main() void {
        \\    const x = 1 <>+ 1;
        \\}
    , &.{ "1 + 1", "const x = 1 + 1", "{\n    const x = 1 + 1;\n}" });
}

test "function parameter" {
    try testSelectionRange(
        \\fn f(x: i32, y: <>struct {}, z: f32) void {
        \\
        \\}
    , &.{ "struct {}", "y: struct {}", "fn f(x: i32, y: struct {}, z: f32) void" });
}

fn testSelectionRange(source: []const u8, want: []const []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = phr.new_source });

    const position = offsets.locToRange(phr.new_source, phr.locations.items(.new)[0], .@"utf-16").start;

    const params: types.SelectionRangeParams = .{
        .textDocument = .{ .uri = test_uri },
        .positions = &.{position},
    };
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/selectionRange", params);

    const selectionRanges: []const types.SelectionRange = response orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var got: std.ArrayList([]const u8) = .empty;
    defer got.deinit(allocator);

    var it: ?*const types.SelectionRange = &selectionRanges[0];
    while (it) |r| {
        const slice = offsets.rangeToSlice(phr.new_source, r.range, .@"utf-16");
        try got.append(allocator, slice);
        it = r.parent;
    }
    const last = got.pop().?;
    try std.testing.expectEqualStrings(phr.new_source, last);
    try std.testing.expectEqual(want.len, got.items.len);
    for (want, got.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}
