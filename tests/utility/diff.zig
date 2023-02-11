const std = @import("std");
const zls = @import("zls");

const allocator = std.testing.allocator;

test "diff - jarred" {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const pre = @embedFile("samples/jarred-pre.zig");
    const post = @embedFile("samples/jarred-post.zig");

    var edits = try zls.diff.edits(arena.allocator(), pre, post);
    const applied = try zls.diff.applyTextEdits(arena.allocator(), pre, edits.items, .@"utf-8");
    try std.testing.expectEqualStrings(post, applied);
}

fn gen(alloc: std.mem.Allocator, rand: std.rand.Random) ![]const u8 {
    var buffer = try alloc.alloc(u8, rand.intRangeAtMost(usize, 16, 1024));
    for (buffer) |*b| b.* = rand.intRangeAtMost(u8, 32, 126);
    return buffer;
}

test "diff - random" {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var rand = std.rand.DefaultPrng.init(0);

    var index: usize = 0;

    while (index < 100) : (index += 1) {
        defer _ = arena.reset(.retain_capacity);

        const pre = try gen(arena.allocator(), rand.random());
        const post = try gen(arena.allocator(), rand.random());

        var edits = try zls.diff.edits(arena.allocator(), pre, post);
        const applied = try zls.diff.applyTextEdits(arena.allocator(), pre, edits.items, .@"utf-8");
        try std.testing.expectEqualStrings(post, applied);
    }
}
