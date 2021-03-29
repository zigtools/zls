const analysis = @import("analysis.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");
const URI = @import("uri.zig");

const std = @import("std");

const allocator = std.testing.allocator;

fn makeDocument(uri: []const u8, text: []const u8) !types.TextDocument {
    const mem = try allocator.alloc(u8, text.len);
    std.mem.copy(u8, mem, text);

    return types.TextDocument{
        .uri = uri,
        .mem = mem,
        .text = mem[0..],
    };
}

fn freeDocument(doc: types.TextDocument) void {
    allocator.free(doc.text);
}

fn makeUnnamedDocument(text: []const u8) !types.TextDocument {
    return try makeDocument("test", text);
}

fn testContext(comptime line: []const u8, comptime tag: anytype, comptime range: ?[]const u8) !void {
    const cursor_idx = comptime std.mem.indexOf(u8, line, "<cursor>").?;
    const final_line = line[0..cursor_idx] ++ line[cursor_idx + "<cursor>".len ..];

    const doc = try makeUnnamedDocument(final_line);
    defer freeDocument(doc);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const p = try offsets.documentPosition(doc, .{ .line = 0, .character = @intCast(i64, cursor_idx) }, .utf8);
    const ctx = try analysis.documentPositionContext(&arena, doc, p);

    if (std.meta.activeTag(ctx) != tag) {
        std.debug.warn("Expected tag {}, got {}\n", .{ tag, std.meta.activeTag(ctx) });
        return error.DifferentTag;
    }

    if (ctx.range()) |ctx_range| {
        if (range == null) {
            std.debug.warn("Expected null range, got `{s}`\n", .{
                doc.text[ctx_range.start..ctx_range.end],
            });
        } else {
            const range_start = comptime std.mem.indexOf(u8, final_line, range.?).?;
            const range_end = range_start + range.?.len;

            if (range_start != ctx_range.start or range_end != ctx_range.end) {
                std.debug.warn("Expected range `{s}` ({}..{}), got `{s}` ({}..{})\n", .{
                    doc.text[range_start..range_end],         range_start,     range_end,
                    doc.text[ctx_range.start..ctx_range.end], ctx_range.start, ctx_range.end,
                });
                return error.DifferentRange;
            }
        }
    } else if (range != null) {
        std.debug.warn("Unexpected null range\n", .{});
        return error.DifferentRange;
    }
}

test "documentPositionContext" {
    try testContext(
        \\const this_var = id<cursor>entifier;
    ,
        .var_access,
        "id",
    );

    try testContext(
        \\if (displ.*.?.c.*[0].<cursor>@"a" == foo) {
    ,
        .field_access,
        "displ.*.?.c.*[0].",
    );

    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).in<cursor>it(allocator);
    ,
        .field_access,
        "std.ArrayList(SomeStruct(a, b, c, d)).in",
    );

    try testContext(
        \\try erroringFn(the_first[arg], second[a..<cursor>]);
    ,
        .empty,
        null,
    );

    try testContext(
        \\    fn add(lhf: lself, rhs: rself) !Se<cursor> {
    ,
        .var_access,
        "Se",
    );
}


test "pathRelative and escapes" {
    const join1 = try URI.pathRelative(allocator, "file://project/zig", "/src/main+.zig");
    defer allocator.free(join1);
    std.testing.expectEqualStrings("file://project/zig/src/main%2B.zig", join1);

    const join2 = try URI.pathRelative(allocator, "file://project/zig/wow", "../]src]/]main.zig");
    defer allocator.free(join2);
    std.testing.expectEqualStrings("file://project/zig/%5Dsrc%5D/%5Dmain.zig", join2);
}

