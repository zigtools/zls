const std = @import("std");
const zls = @import("zls");

fn gen(alloc: std.mem.Allocator, rand: std.Random) ![]const u8 {
    const buffer = try alloc.alloc(u8, rand.intRangeAtMost(usize, 0, 256));
    for (buffer) |*b| b.* = rand.intRangeAtMost(u8, ' ', '~');
    return buffer;
}

test "diff - random" {
    const allocator = std.testing.allocator;
    var rand: std.Random.DefaultPrng = .init(std.testing.random_seed);
    try testDiff(allocator, rand.random(), .@"utf-8");
    try testDiff(allocator, rand.random(), .@"utf-16");
    try testDiff(allocator, rand.random(), .@"utf-32");
}

fn testDiff(allocator: std.mem.Allocator, rand: std.Random, encoding: zls.offsets.Encoding) !void {
    var buffer: [256]u8 = undefined;
    rand.bytes(&buffer);
    for (&buffer) |*c| c.* = '0' + c.* % 32;

    const split_index = rand.intRangeLessThan(usize, 0, buffer.len);
    const before = buffer[0..split_index];
    const after = buffer[split_index..];

    var edits = try zls.diff.edits(allocator, before, after, encoding);
    defer {
        for (edits.items) |edit| allocator.free(edit.newText);
        edits.deinit(allocator);
    }

    const applied = try zls.diff.applyTextEdits(allocator, before, edits.items, encoding);
    defer allocator.free(applied);

    try std.testing.expectEqualStrings(after, applied);
}
