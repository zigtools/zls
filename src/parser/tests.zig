const std = @import("std");
const Ast = @import("Ast.zig");
const Tokenizer = @import("Tokenizer.zig");
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

    var tokenizer = Tokenizer.init(allocator, a);

    try tokenizer.tokenize();
    _ = try tokenizer.retokenize(b, diffs.items);

    var tree = try Ast.parse(allocator, tokenizer, .zig);

    var l = std.ArrayList(u8).init(allocator);
    try tree.renderToArrayList(&l);
    std.debug.print("\n\n{s}", .{l.items});

    // std.log.err("{any}", .{tree.tokens});

    std.debug.print("\n\n", .{});

    for (tokenizer.origins.entries.items(.key), tokenizer.tokens.items(.loc)) |origin, loc| {
        if (origin.version == 0)
            std.debug.print("\x1b[0;37m{s} ", .{b[loc.start..loc.end]})
        else
            std.debug.print("\x1b[0;31m{s} ", .{b[loc.start..loc.end]});
    }

    std.debug.print("\x1b[0;37m", .{});
}
