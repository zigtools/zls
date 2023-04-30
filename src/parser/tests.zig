const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const DiffMatchPatch = @import("diffz");

var dmp = DiffMatchPatch{};

test {
    std.log.err("abc", .{});

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    const a =
        \\const std = @import("std");
        \\pub fn main() void {}
    ;
    const b =
        \\const stad = 123;
        \\pub fn main() void {}
    ;

    const diffs = try dmp.diff(allocator, a, b, true);

    // std.log.err("DIFF: {any}", .{diffs.items});

    const a_tokens = try tokenizer.tokenize(allocator, a, 0);

    const b_tokens = try tokenizer.retokenize(allocator, b, a_tokens, diffs.items, 1);

    std.debug.print("\n\n", .{});

    for (0..b_tokens.len) |i| {
        const bruh: tokenizer.Token = b_tokens.get(i);

        if (bruh.orig_version == 0)
            std.debug.print("({s})", .{b[bruh.loc.start..bruh.loc.end]})
        else
            std.debug.print("[{s}]", .{b[bruh.loc.start..bruh.loc.end]});
    }
}
