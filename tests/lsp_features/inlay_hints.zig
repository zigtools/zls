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
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: anytype) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>4);
    );
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {} };
        \\const _ = Foo.bar(<self>undefined,<alpha>5,<beta>"");
    );
    try testInlayHints(
        \\const Foo = struct {
        \\  pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {}
        \\  pub fn foo() void {
        \\      bar(<self>undefined,<alpha>5,<beta>"");
        \\  }
        \\};
    );
}

test "inlayhints - builtin call" {
    try testInlayHints(
        \\const _ = @memcpy(<dest>"",<source>"");
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

    const test_uri = try ctx.addDocument(phr.new_source);

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

    const hints: []InlayHint = response.result orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var error_builder = ErrorBuilder.init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(test_uri, phr.new_source);

    var i: usize = 0;
    outer: while (i < phr.locations.len) : (i += 1) {
        const old_loc = phr.locations.items(.old)[i];
        const new_loc = phr.locations.items(.new)[i];

        const expected_name = offsets.locToSlice(source, old_loc);
        const expected_label = expected_name[1 .. expected_name.len - 1]; // convert <name> to name

        const position = offsets.indexToPosition(phr.new_source, new_loc.start, ctx.server.offset_encoding);

        for (hints) |hint| {
            if (position.line != hint.position.line or position.character != hint.position.character) continue;

            if (!std.mem.endsWith(u8, hint.label, ":")) {
                try error_builder.msgAtLoc("label `{s}` must end with a colon!", test_uri, new_loc, .err, .{hint.label});
            }
            const actual_label = hint.label[0 .. hint.label.len - 1];

            if (!std.mem.eql(u8, expected_label, actual_label)) {
                try error_builder.msgAtLoc("expected label `{s}` here but got `{s}`!", test_uri, new_loc, .err, .{ expected_label, actual_label });
            }
            if (hint.kind != types.InlayHintKind.Parameter) {
                try error_builder.msgAtLoc("hint kind should be `{s}` but got `{s}`!", test_uri, new_loc, .err, .{ @tagName(types.InlayHintKind.Parameter), @tagName(hint.kind) });
            }

            continue :outer;
        }
        try error_builder.msgAtLoc("expected hint `{s}` here", test_uri, new_loc, .err, .{expected_label});
    }

    if (error_builder.hasMessages()) return error.InvalidResponse;
}
