const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;

const types = zls.types;

const allocator: std.mem.Allocator = std.testing.allocator;

test "semantic tokens - empty" {
    try testSemanticTokens("", &.{});
}

test "semantic tokens" {
    try testSemanticTokens(
        \\const std = @import("std");
    ,
        &.{ 0, 0, 5, 7, 0, 0, 6, 3, 0, 33, 0, 4, 1, 11, 0, 0, 2, 7, 12, 0, 0, 8, 5, 9, 0 },
    );

    // TODO more tests
}

test "semantic tokens - comments" {
    try testSemanticTokens(
        \\//!─
    ,
        &.{ 0, 0, 4, 8, 128 },
    );

    // TODO more tests
}

test "semantic tokens - string literals" {
    // https://github.com/zigtools/zls/issues/921
    try testSemanticTokens(
        \\"
        \\"",// 
        \\"": 
    ,
        // no idea if this output is correct but at least it doesn't crash
        &.{ 1, 3, 3, 8, 0, 1, 0, 2, 4, 0, 0, 0, 2, 9, 0 },
    );
}

const file_uri = switch (builtin.os.tag) {
    .windows => "file:///C:/test.zig",
    else => "file:///test.zig",
};

fn testSemanticTokens(source: []const u8, expected: []const u32) !void {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.requestDidOpen(file_uri, source);

    const Response = struct {
        data: []const u32,
    };

    const expected_bytes = try std.json.stringifyAlloc(allocator, Response{ .data = expected }, .{});
    defer allocator.free(expected_bytes);

    try ctx.request(
        "textDocument/semanticTokens/full",
        "{\"textDocument\":{\"uri\":\"" ++ file_uri ++ "\"}}",
        expected_bytes,
    );
}
