const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const DiffMatchPatch = @import("diffz");

var dmp = DiffMatchPatch{
    .diff_timeout = 250,
    .diff_edit_cost = 10,
};

test {
    std.log.err("abc", .{});

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    const a = @embedFile("cases/memset_before.zig");
    const b = @embedFile("cases/memset_after.zig");

    const diffs = try dmp.diff(allocator, a, b, true);

    std.log.err("DIFF: {any}", .{diffs.items});

    const a_tokens = try tokenizer.tokenize(allocator, a, 0);

    const b_tokens = try tokenizer.retokenize(allocator, b, a_tokens, diffs.items, 1);

    std.debug.print("\n\n", .{});

    for (0..b_tokens.entries.len) |i| {
        const bruh = b_tokens.entries.get(i);

        if (bruh.key.version == 0)
            std.debug.print("\x1b[0;37m{s} ", .{b[bruh.value.loc.start..bruh.value.loc.end]})
        else
            std.debug.print("\x1b[0;31m{s} ", .{b[bruh.value.loc.start..bruh.value.loc.end]});
    }

    std.debug.print("\x1b[0;37m", .{});
}
