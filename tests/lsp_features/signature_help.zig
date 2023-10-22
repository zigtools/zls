const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "signature help - no parameters" {
    try testSignatureHelp(
        \\fn foo() void {
        \\    foo(<cursor>)
        \\}
    , "fn foo() void", null);
}

test "signature help - simple" {
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    foo(<cursor>)
        \\}
    , "fn foo(a: u32, b: u32) void", 0);
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    foo(0,<cursor>)
        \\}
    , "fn foo(a: u32, b: u32) void", 1);
}

test "signature help - syntax error resistance" {
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    foo(<cursor>
        \\}
    , "fn foo(a: u32, b: u32) void", 0);
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    foo(<cursor>;
        \\}
    , "fn foo(a: u32, b: u32) void", 0);
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    foo(<cursor>);
        \\}
    , "fn foo(a: u32, b: u32) void", 0);
}

test "signature help - alias" {
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    bar(<cursor>)
        \\}
        \\const bar = foo;
    , "fn foo(a: u32, b: u32) void", 0);
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) void {
        \\    bar(<cursor>)
        \\}
        \\const bar = &foo;
    , "fn foo(a: u32, b: u32) void", 0);
}

test "signature help - function pointer" {
    try testSignatureHelp(
        \\const foo: fn (bool, u32) void = undefined;
        \\comptime {
        \\  foo(<cursor>)
        \\}
    , "fn (bool, u32) void", 0);
    try testSignatureHelp(
        \\const foo: *fn (bool, u32) void = undefined;
        \\comptime {
        \\  foo(<cursor>)
        \\}
    , "fn (bool, u32) void", 0);
    try testSignatureHelp(
        \\const foo: *fn (bool, u32) void = undefined;
        \\comptime {
        \\  foo.*(<cursor>)
        \\}
    , "fn (bool, u32) void", 0);
}

test "signature help - function pointer container field" {
    try testSignatureHelp(
        \\const S = struct {
        \\    foo: fn(a: u32, b: void) bool {}
        \\};
        \\const s: S = undefined;
        \\const foo = s.foo(<cursor>);
    , "fn(a: u32, b: void) bool", 0);
    try testSignatureHelp(
        \\const S = struct {
        \\    foo: *const fn(a: u32, b: void) bool {}
        \\};
        \\const s: S = undefined;
        \\const foo = s.foo(<cursor>);
    , "fn(a: u32, b: void) bool", 0);
    try testSignatureHelp(
        \\const S = struct {
        \\    foo: *const fn(a: u32, b: void) bool {}
        \\};
        \\const s: S = undefined;
        \\const foo = s.foo.*(<cursor>);
    , "fn(a: u32, b: void) bool", 0);
}

test "signature help - self parameter" {
    try testSignatureHelp(
        \\const S = struct {
        \\    fn foo(self: @This(), a: u32, b: void) bool {}
        \\};
        \\const s: S = undefined;
        \\const foo = s.foo(3,<cursor>);
    , "fn foo(self: @This(), a: u32, b: void) bool", 2);
    try testSignatureHelp(
        \\const S = struct {
        \\    fn foo(self: @This(), a: u32, b: void) bool {}
        \\};
        \\const foo = S.foo(undefined,<cursor>);
    , "fn foo(self: @This(), a: u32, b: void) bool", 1);
}

test "signature help - anytype" {
    try testSignatureHelp(
        \\fn foo(a: u32, b: anytype, c: u32) void {
        \\    foo(1,<cursor>,2)
        \\}
    , "fn foo(a: u32, b: anytype, c: u32) void", 1);
}

test "signature help - nested function call" {
    try testSignatureHelp(
        \\fn foo(a: u32, b: u32) i32 {
        \\    foo(1, bar(<cursor>));
        \\}
        \\fn bar(c: bool) bool {}
    , "fn bar(c: bool) bool", 0);
}

fn testSignatureHelp(source: []const u8, expected_label: []const u8, expected_active_parameter: ?u32) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(source);

    const params = types.SignatureHelpParams{
        .textDocument = .{ .uri = test_uri },
        .position = offsets.indexToPosition(text, cursor_idx, ctx.server.offset_encoding),
    };

    const response: types.SignatureHelp = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/signatureHelp", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    try std.testing.expectEqual(@as(?u32, 0), response.activeSignature);
    try std.testing.expectEqual(@as(usize, 1), response.signatures.len);

    const signature = response.signatures[0];
    try std.testing.expectEqual(expected_active_parameter, response.activeParameter);
    try std.testing.expectEqual(response.activeParameter, signature.activeParameter);

    try std.testing.expectEqualStrings(expected_label, signature.label);
}
