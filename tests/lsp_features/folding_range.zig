const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.lsp.types;

test "empty" {
    try testFoldingRange("", &.{});
}

test "container type without members" {
    try testFoldingRange(
        \\const S = struct {};
    , &.{});
    try testFoldingRange(
        \\const S = struct {
        \\};
    , &.{});
    try testFoldingRange(
        \\const S = struct {
        \\    // hello there
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 18, .endLine = 1, .endCharacter = 18 },
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
        \\    // then
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 1, .endCharacter = 11 },
    });
    try testFoldingRange(
        \\const foo = if (false) {
        \\    // then
        \\} else {
        \\    // else
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 1, .endCharacter = 11 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 11 },
    });
}

test "for/while" {
    try testFoldingRange(
        \\const foo = for ("") |_| {
        \\    // then
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 11 },
    });
    try testFoldingRange(
        \\const foo = for ("") |_| {
        \\    return;
        \\} else {
        \\    // else
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 11 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 11 },
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
        \\    // then
        \\} else {
        \\    //
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 26, .endLine = 1, .endCharacter = 11 },
        .{ .startLine = 2, .startCharacter = 8, .endLine = 3, .endCharacter = 6 },
    });
}

test "switch" {
    try testFoldingRange(
        \\const foo = switch (5) {};
    , &.{});
    try testFoldingRange(
        \\const foo = switch (5) {
        \\    0 => {},
        \\    1 => {}
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 2, .endCharacter = 11 },
    });
    try testFoldingRange(
        \\const foo = switch (5) {
        \\    0 => {},
        \\    1 => {},
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 24, .endLine = 2, .endCharacter = 12 },
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
        .{ .startLine = 0, .startCharacter = 24, .endLine = 7, .endCharacter = 15 },
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

test "function with multi-line return type" {
    try testFoldingRange(
        \\fn foo(a: u32, b: u32, c: u32) enum {
        \\    d,
        \\    e,
        \\    f,
        \\} {
        \\    _ = a;
        \\    _ = b;
        \\    _ = c;
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 37, .endLine = 3, .endCharacter = 6 },
        .{ .startLine = 4, .startCharacter = 3, .endLine = 7, .endCharacter = 10 },
    });
}

test "function with multi-line parameters and return type" {
    try testFoldingRange(
        \\fn foo(
        \\    a: u32,
        \\    b: u32,
        \\    c: u32,
        \\) enum {
        \\    d,
        \\    e,
        \\    f,
        \\} {
        \\    _ = a;
        \\    _ = b;
        \\    _ = c;
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 7, .endLine = 3, .endCharacter = 11 },
        .{ .startLine = 4, .startCharacter = 8, .endLine = 7, .endCharacter = 6 },
        .{ .startLine = 8, .startCharacter = 3, .endLine = 11, .endCharacter = 10 },
    });
}

test "nested folding ranges inside function parameter" {
    if (true) return error.SkipZigTest; // TODO
    try testFoldingRange(
        \\fn foo(a: u32, b: u32, c: enum {
        \\    d,
        \\    e,
        \\    f,
        \\}, g: u32) void {
        \\    _ = a;
        \\    _ = b;
        \\    _ = c;
        \\    _ = g;
        \\}
    , &.{
        .{ .startLine = 0, .startCharacter = 32, .endLine = 3, .endCharacter = 6 },
        .{ .startLine = 4, .startCharacter = 17, .endLine = 8, .endCharacter = 10 },
    });
}

test "nested folding ranges inside container types" {
    if (true) return error.SkipZigTest; // TODO
    try testFoldingRange(
        \\const Foo = struct { foo: struct {
        \\    bar: void,
        \\} };
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 1, .endCharacter = 14 },
    });
}

test "container decl" {
    try testFoldingRange(
        \\const Foo = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 2, .endCharacter = 21 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    /// doc comment
        \\    alpha: u32,
        \\    // beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 3, .endCharacter = 24 },
    });
    try testFoldingRange(
        \\const Foo = packed struct(u32) {
        \\    alpha: u16,
        \\    beta: u16,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 32, .endLine = 2, .endCharacter = 14 },
    });
    try testFoldingRange(
        \\const Foo = union {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 19, .endLine = 2, .endCharacter = 21 },
    });
    try testFoldingRange(
        \\const Foo = union(enum) {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 25, .endLine = 2, .endCharacter = 21 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 1, .endCharacter = 20 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    fn bar() void {}
        \\    // some comment
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 3, .endCharacter = 19 },
    });
    try testFoldingRange(
        \\const Foo = struct {
        \\    // some comment
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 20, .endLine = 1, .endCharacter = 19 },
    });
}

test "error set" {
    try testFoldingRange(
        \\const E = error{
        \\    Foo,
        \\    Bar,
        \\};
    , &.{
        .{ .startLine = 0, .startCharacter = 16, .endLine = 2, .endCharacter = 8 },
    });
}

test "array init" {
    try testFoldingRange(
        \\const foo = .{
        \\    1,
        \\    2,
        \\},
    , &.{
        .{ .startLine = 0, .startCharacter = 14, .endLine = 2, .endCharacter = 6 },
    });
}

test "struct init" {
    try testFoldingRange(
        \\const foo = .{
        \\    .alpha = 1,
        \\    .beta = 2,
        \\},
    , &.{
        .{ .startLine = 0, .startCharacter = 14, .endLine = 2, .endCharacter = 14 },
    });
}

test "builtin" {
    try testFoldingRange(
        \\const foo = @as(
        \\    u32,
        \\    undefined,
        \\);
    , &.{
        .{ .startLine = 0, .startCharacter = 16, .endLine = 2, .endCharacter = 14 },
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
        .{ .startLine = 1, .startCharacter = 19, .endLine = 3, .endCharacter = 9 },
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
    , &.{});
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

test "imports" {
    try testFoldingRange(
        \\const std = @import("std");
        \\const builtin = @import("builtin");
    , &.{
        .{ .startLine = 0, .startCharacter = 0, .endLine = 1, .endCharacter = 34 },
    });
    try testFoldingRange(
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\const lsp = @import("lsp");
        \\const types = lsp.types;
        \\
        \\pub fn main() void {}
    , &.{
        .{ .startLine = 0, .startCharacter = 0, .endLine = 3, .endCharacter = 23 },
    });
    // Single import should not create folding range
    try testFoldingRange(
        \\const std = @import("std");
        \\
        \\pub fn main() void {}
    , &.{});
    // Imports with gap in between should create separate folding ranges
    try testFoldingRange(
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\
        \\pub const foo = 5;
        \\
        \\const lsp = @import("lsp");
        \\const types = @import("types");
    , &.{
        .{ .startLine = 0, .startCharacter = 0, .endLine = 1, .endCharacter = 34 },
        .{ .startLine = 5, .startCharacter = 0, .endLine = 6, .endCharacter = 30 },
    });
}

fn testFoldingRange(source: []const u8, expect: []const types.FoldingRange) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = source });

    const params: types.FoldingRange.Params = .{ .textDocument = .{ .uri = test_uri.raw } };

    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/foldingRange", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    try zls.testing.expectEqual(expect, response);
}
