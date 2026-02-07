const std = @import("std");
const zls = @import("zls");

fn gen(alloc: std.mem.Allocator, rand: std.Random) ![]const u8 {
    const buffer = try alloc.alloc(u8, rand.intRangeAtMost(usize, 0, 256));
    for (buffer) |*b| b.* = rand.intRangeAtMost(u8, ' ', '~');
    return buffer;
}

test "diff - random" {
    var rand: std.Random.DefaultPrng = .init(std.testing.random_seed);
    try testDiff(rand.random(), .@"utf-8");
    try testDiff(rand.random(), .@"utf-16");
    try testDiff(rand.random(), .@"utf-32");
}

fn testDiff(rand: std.Random, encoding: zls.offsets.Encoding) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var buffer: [256]u8 = undefined;
    rand.bytes(&buffer);
    for (&buffer) |*c| c.* = '0' + c.* % 32;

    const split_index = rand.intRangeLessThan(usize, 0, buffer.len);
    const before = buffer[0..split_index];
    const after = buffer[split_index..];

    var edits = try zls.diff.edits(io, allocator, before, after, encoding);
    defer {
        for (edits.items) |edit| allocator.free(edit.newText);
        edits.deinit(allocator);
    }

    const applied = try zls.diff.applyTextEdits(allocator, before, edits.items, encoding);
    defer allocator.free(applied);

    try std.testing.expectEqualStrings(after, applied);
}
