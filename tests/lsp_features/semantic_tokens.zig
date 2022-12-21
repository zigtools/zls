const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;

const requests = zls.requests;

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

const file_uri = switch (builtin.os.tag) {
    .windows => "file:///C:/test.zig",
    else => "file:///test.zig",
};

fn testSemanticTokens(source: []const u8, expected: []const u32) !void {
    var ctx = try Context.init();
    defer ctx.deinit();

    const open_document = requests.OpenDocument{
        .params = .{
            .textDocument = .{
                .uri = file_uri,
                // .languageId = "zig",
                // .version = 420,
                .text = source,
            },
        },
    };

    const did_open_method = try std.json.stringifyAlloc(allocator, open_document.params, .{});
    defer allocator.free(did_open_method);

    try ctx.request("textDocument/didOpen", did_open_method, null);

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
