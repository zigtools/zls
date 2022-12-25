const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

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
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    try ctx.requestDidOpen(test_uri, phr.new_source);

    const range = types.Range{
        .start = types.Position{ .line = 0, .character = 0 },
        .end = offsets.indexToPosition(phr.new_source, phr.new_source.len, .@"utf-16"),
    };

    const InlayHint = struct {
        position: types.Position,
        label: []const u8,
        kind: types.InlayHintKind,
    };

    const params = types.InlayHintParams{
        .textDocument = .{ .uri = test_uri },
        .range = range,
    };

    const response = try ctx.requestGetResponse(?[]InlayHint, "textDocument/inlayHint", params);
    defer response.deinit();

    const hints: []InlayHint = response.result orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var error_builder = ErrorBuilder.init(allocator, phr.new_source);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    var i: usize = 0;
    outer: while (i < phr.locations.len) : (i += 1) {
        const old_loc = phr.locations.items(.old)[i];
        const new_loc = phr.locations.items(.new)[i];

        const expected_name = offsets.locToSlice(source, old_loc);
        const expected_label = expected_name[1 .. expected_name.len - 1]; // convert <name> to name

        const position = offsets.indexToPosition(phr.new_source, new_loc.start, ctx.server.offset_encoding);

        for (hints) |hint| {
            if (position.line != hint.position.line or position.character != hint.position.character) continue;

            const actual_label = hint.label[0 .. hint.label.len];

            if (!std.mem.eql(u8, expected_label, actual_label)) {
                try error_builder.msgAtLoc("expected label `{s}` here but got `{s}`!", new_loc, .err, .{ expected_label, actual_label });
            }
            if (hint.kind != types.InlayHintKind.Parameter) {
                try error_builder.msgAtLoc("hint kind should be `{s}` but got `{s}`!", new_loc, .err, .{ @tagName(types.InlayHintKind.Parameter), @tagName(hint.kind) });
            }

            continue :outer;
        }
        try error_builder.msgAtLoc("expected hint `{s}` here", new_loc, .err, .{expected_label});
    }

    if (error_builder.hasMessages()) return error.InvalidResponse;
}
