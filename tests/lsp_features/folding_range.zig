const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.lsp.types;

test "empty" {
    try testFoldingRange("", &.{});
}

test "container type without members" {
    try testFoldingRange(
        \\const S = struct {
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 18, .endLine = 1, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const S = struct {
        \\    // hello there
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 18, .endLine = 2, .endCharacter = 0 },
    });
}

test "doc comment" {
    try testFoldingRange(
        \\/// hello
        \\/// world
        \\var foo = 5;
    , &.{
        .{ .startLine = 0, .startCharacter = 0, .endLine = 1, .endCharacter = 9, .kind = .comment },
    });
}

test "region" {
    try testFoldingRange(
        \\const foo = 0;
        \\//#region
        \\const bar = 1;
        \\//#endregion
        \\const baz = 2;
    , &.{
        .{ .startLine = 1, .startCharacter = 0, .endLine = 3, .endCharacter = 12, .kind = .region },
    });
    try testFoldingRange(
        \\//#region
        \\const foo = 0;
        \\//#region
        \\const bar = 1;
        \\//#endregion
        \\const baz = 2;
        \\//#endregion
    , &.{
        .{ .startLine = 2, .startCharacter = 0, .endLine = 4, .endCharacter = 12, .kind = .region },
        .{ .startLine = 0, .startCharacter = 0, .endLine = 6, .endCharacter = 12, .kind = .region },
    });
}

test "if" {
    try testFoldingRange(
        \\const foo = if (false) {
        \\
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 1, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const foo = if (false) {
        \\
        \\} else {
        \\
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 1, .endCharacter = 0 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 0 },
    });
}

test "for/while" {
    try testFoldingRange(
        \\const foo = for ("") |_| {
        \\
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const foo = for ("") |_| {
        \\    return;
        \\} else {
        \\
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 11 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 0 },
    });

    try testFoldingRange(
        \\const foo = while (true) {
        \\    //
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 6 },
    });
    try testFoldingRange(
        \\const foo = while (true) {
        \\
        \\} else {
        \\    //
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 0 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 6 },
    });
}

test "switch" {
    try testFoldingRange(
        \\const foo = switch (5) {
        \\    0 => {},
        \\    1 => {}
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const foo = switch (5) {
        \\    0 => {},
        \\    1 => {},
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const foo = switch (5) {
        \\    0,
        \\    1,
        \\    2,
        \\    3,
        \\    4,
        \\    => {},
        \\    else => {},
        \\};
    , &.{
        .{ .startLine = 1, .startCharacter = 4, .endLine = 5, .endCharacter = 6 },
        .{ .startLine = 0, .startCharacter = 24, .endLine = 8, .endCharacter = 0 },
    });
}

test "function" {
    try testFoldingRange(
        \\fn main() u32 {
        \\    return 1 + 1;
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 15, .endLine = 1, .endCharacter = 17 },
    });
    try testFoldingRange(
        \\fn main(
        \\    a: ?u32,
        \\    b: anytype,
        \\) !u32 {}
    , &.{
        .{ .startLine = 0, .startCharacter = 8, .endLine = 2, .endCharacter = 15 },
    });
    try testFoldingRange(
        \\fn main(
        \\    a: ?u32,
        \\) !u32 {
        \\    return 1 + 1;
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 8, .endLine = 1, .endCharacter = 12 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 17 },
    });
}

test "function with doc comment" {
    try testFoldingRange(
        \\/// this is
        \\/// a function
        \\fn foo(
        \\    /// this is a parameter
        \\    a: u32,
        \\    ///
        \\    /// this is another parameter
        \\    b: u32,
        \\) void {}
    , &.{
        .{ .startLine = 0, .startCharacter = 0, .endLine = 1, .endCharacter = 14, .kind = .comment },
        .{ .startLine = 5, .startCharacter = 4, .endLine = 6, .endCharacter = 33, .kind = .comment },
        .{ .startLine = 2, .startCharacter = 7, .endLine = 7, .endCharacter = 11 },
    });
}

test "container decl" {
    try testFoldingRange(
        \\const Foo = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    /// doc comment
        \\    alpha: u32,
        \\    // beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 4, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = packed struct(u32) {
        \\    alpha: u16,
        \\    beta: u16,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 32, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = union {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 19, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = union(enum) {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 25, .endLine = 3, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 2, .endCharacter = 0 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    fn bar() void {}
        \\    // some comment
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 4, .endCharacter = 0 },
    });
}

test "call" {
    try testFoldingRange(
        \\extern fn foo(a: bool, b: ?usize) void;
        \\const result = foo(
        \\    false,
        \\    null,
        \\);
    , &.{
        .{ .startLine = 1, .startCharacter = 19, .endLine = 4, .endCharacter = 0 },
    });
}

test "multi-line string literal" {
    try testFoldingRange(
        \\const foo =
        \\    \\hello
        \\    \\world
        \\;
    , &.{
        .{ .startLine = 1, .startCharacter = 4, .endLine = 2, .endCharacter = 11 },
    });
}

test "invalid condition within a `switch`" {
    try testFoldingRange(
        \\switch (a.) {
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 11, .endLine = 1, .endCharacter = 0 },
    });
}

test "weird code" {
    // the expected output is irrelevant, just ensure no crash
    try testFoldingRange(
        \\if ( {fn foo()}
        \\
    ,
        &.{},
    );
}

fn testFoldingRange(source: []const u8, expect: []const types.FoldingRange) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = source });

    const params: types.FoldingRangeParams = .{ .textDocument = .{ .uri = test_uri } };

    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/foldingRange", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    try zls.testing.expectEqual(expect, response);
}
