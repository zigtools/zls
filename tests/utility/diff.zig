const std = @import("std");
const zls = @import("zls");

fn gen(alloc: std.mem.Allocator, rand: std.Random) ![]const u8 {
    const buffer = try alloc.alloc(u8, rand.intRangeAtMost(usize, 0, 256));
    for (buffer) |*b| b.* = rand.intRangeAtMost(u8, ' ', '~');
    return buffer;
}

test "diff - random" {
    const allocator = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(allocator, testDiff, .{ 0, .@"utf-8" });
    for (0..30) |i| {
        try testDiff(allocator, i, .@"utf-8");
        try testDiff(allocator, i, .@"utf-16");
        try testDiff(allocator, i, .@"utf-32");
    }
}

fn testDiff(allocator: std.mem.Allocator, seed: u64, encoding: zls.offsets.Encoding) !void {
    var rand = std.Random.DefaultPrng.init(seed);
    const before = try gen(allocator, rand.random());
    defer allocator.free(before);
    const after = try gen(allocator, rand.random());
    defer allocator.free(after);

    var edits = try zls.diff.edits(allocator, before, after, encoding);
    defer {
        for (edits.items) |edit| allocator.free(edit.newText);
        edits.deinit(allocator);
    }

    const applied = try zls.diff.applyTextEdits(allocator, before, edits.items, encoding);
    defer allocator.free(applied);

    try std.testing.expectEqualStrings(after, applied);
}
