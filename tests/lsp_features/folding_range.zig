const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;

const types = zls.types;

const allocator: std.mem.Allocator = std.testing.allocator;

test "foldingRange - empty" {
    try testFoldingRange("", "[]");
}

test "foldingRange - smoke" {
    try testFoldingRange(
        \\fn main() u32 {
        \\    return 1 + 1;
        \\}
    ,
        \\[{"startLine":0,"endLine":1}]
    );
}

test "foldingRange - #801" {
    try testFoldingRange(
        \\fn score(c: u8) !u32 {
        \\    return switch(c) {
        \\        'a'...'z' => c - 'a',
        \\        'A'...'Z' => c - 'A',
        \\        _ => error
        \\    };
        \\}
    ,
        \\[]
    );
}

fn testFoldingRange(source: []const u8, expect: []const u8) !void {
    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    try ctx.requestDidOpen(test_uri, source);

    const params = types.FoldingRangeParams{ .textDocument = .{ .uri = test_uri } };

    const response = try ctx.requestGetResponse(?[]types.FoldingRange, "textDocument/foldingRange", params);
    defer response.deinit();

    var actual = std.ArrayList(u8).init(allocator);
    defer actual.deinit();

    try std.json.stringify(response.result, .{}, actual.writer());
    try expectEqualJson(expect, actual.items);
}

fn expectEqualJson(expect: []const u8, actual: []const u8) !void {
    // TODO: Actually compare strings as JSON values.
    return std.testing.expectEqualStrings(expect, actual);
}
