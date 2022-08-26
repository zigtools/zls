const std = @import("std");
const zls = @import("zls");

const helper = @import("helper");
const Context = @import("context").Context;

const types = zls.types;
const requests = zls.requests;

const allocator: std.mem.Allocator = std.testing.allocator;

test "inlayhints - empty" {
    try testInlayHints("");
}

test "inlayhints - function call" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const _ = foo(<alpha>5);
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(<alpha>5,<beta>4);
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(  <alpha>3 + 2 ,  <beta>(3 - 2));
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(
        \\    <alpha>3 + 2,
        \\    <beta>(3 - 2),
        \\);
    );
}

test "inlayhints - function self parameter" {
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: *Foo, alpha: u32) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5);
    );
    try testInlayHints(
        \\const Foo = struct { pub fn bar(_: Foo, alpha: u32, beta: []const u8) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>"");
    );
}

test "inlayhints - builtin call" {
    try testInlayHints(
        \\const _ = @intCast(<DestType>u32,<int>5);
    );
    try testInlayHints(
        \\const _ = @memcpy(<dest>null,<source>null,<byte_count>0);
    );

    try testInlayHints(
        \\const _ = @sizeOf(u32);
    );
    try testInlayHints(
        \\const _ = @TypeOf(5);
    );
}

fn testInlayHints(source: []const u8) !void {
    const phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.config.enable_inlay_hints = true;
    ctx.server.config.inlay_hints_exclude_single_argument = false;
    ctx.server.config.inlay_hints_show_builtin = true;

    const open_document = requests.OpenDocument{
        .params = .{
            .textDocument = .{
                .uri = "file:///test.zig",
                // .languageId = "zig",
                // .version = 420,
                .text = phr.source,
            },
        },
    };

    const did_open_method = try std.json.stringifyAlloc(allocator, open_document.params, .{});
    defer allocator.free(did_open_method);

    try ctx.request("textDocument/didOpen", did_open_method, null);

    const range = types.Range{
        .start = types.Position{ .line = 0, .character = 0 },
        .end = sourceIndexPosition(phr.source, phr.source.len),
    };

    const method = try std.json.stringifyAlloc(allocator, .{
        .textDocument = .{
            .uri = "file:///test.zig",
        },
        .range = range,
    }, .{});
    defer allocator.free(method);

    const response_bytes = try ctx.requestAlloc("textDocument/inlayHint", method);
    defer allocator.free(response_bytes);

    const InlayHint = struct {
        position: types.Position,
        label: []const u8,
        kind: types.InlayHintKind,
    };

    const Response = struct {
        jsonrpc: []const u8,
        id: types.RequestId,
        result: []InlayHint,
    };

    const parse_options = std.json.ParseOptions{
        .allocator = allocator,
        .ignore_unknown_fields = true,
    };
    var token_stream = std.json.TokenStream.init(response_bytes);
    var response = try std.json.parse(Response, &token_stream, parse_options);
    defer std.json.parseFree(Response, response, parse_options);

    const hints = response.result;

    try std.testing.expectEqual(phr.placeholder_locations.len, hints.len);

    outer: for (phr.placeholder_locations) |loc, i| {
        const name = phr.placeholders[i].placeholderSlice(source);

        const position = sourceIndexPosition(phr.source, loc);

        for (hints) |hint| {
            if (position.line != hint.position.line or position.character != hint.position.character) continue;

            try std.testing.expect(hint.label.len != 0);
            const trimmedLabel = hint.label[0 .. hint.label.len - 1]; // exclude :
            try std.testing.expectEqualStrings(name, trimmedLabel);
            try std.testing.expectEqual(types.InlayHintKind.Parameter, hint.kind);

            continue :outer;
        }
        std.debug.print("Placeholder '{s}' at {}:{} (line:colon) not found!", .{ name, position.line, position.character });
        return error.PlaceholderNotFound;
    }
}

fn sourceIndexPosition(source: []const u8, index: usize) types.Position {
    const line = std.mem.count(u8, source[0..index], &.{'\n'});
    const last_line_index = if (std.mem.lastIndexOfScalar(u8, source[0..index], '\n')) |idx| idx + 1 else 0;
    const last_line_character = index - last_line_index;

    return types.Position{
        .line = @intCast(i64, line),
        .character = @intCast(i64, last_line_character),
    };
}
