const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "hover - literal" {
    try testHover(
        \\const f<cursor>oo = 42;
    ,
        \\```zig
        \\const foo = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const f<cursor>oo = 'e';
    ,
        \\```zig
        \\const foo = 'e'
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const f<cursor>oo = "ipsum lorem";
    ,
        \\```zig
        \\const foo = "ipsum lorem"
        \\```
        \\```zig
        \\(*const [11:0]u8)
        \\```
    );
    try testHover(
        \\const f<cursor>oo =
        \\    \\ipsum lorem
        \\    \\dolor sit amet
        \\;
    ,
        \\```zig
        \\const foo =
        \\    \\ipsum lorem
        \\    \\dolor sit amet
        \\
        \\```
        \\```zig
        \\(*const [26:0]u8)
        \\```
    );
}

test "hover - builtin" {
    try testHover(
        \\@intFr<cursor>omBool(5);
    ,
        \\```zig
        \\@intFromBool(value: bool) u1
        \\```
        \\Converts `true` to `@as(u1, 1)` and `false` to `@as(u1, 0)`.
    );
}

test "hover - struct" {
    try testHover(
        \\const Str<cursor>uct = packed struct(u32) {};
    ,
        \\```zig
        \\const Struct = packed struct(u32)
        \\```
        \\```zig
        \\(type)
        \\```
    );
}

test "hover - enum member" {
    try testHover(
        \\const Enum = enum { foo, bar };
        \\const enum_member = Enum.f<cursor>oo;
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(Enum)
        \\```
        \\
        \\Go to [Enum](file:///test.zig#L1)
    );
}

test "hover - block label" {
    try testHover(
        \\const foo: i32 = undefined;
        \\const bar = b<cursor>az: {
        \\    break :baz foo;
        \\};
    ,
        \\```zig
        \\baz
        \\```
        \\```zig
        \\(i32)
        \\```
    );
}

test "hover - if capture" {
    try testHover(
        \\fn func() void {
        \\    const foo: ?i32 = undefined;
        \\    if (foo) |b<cursor>ar| {}
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: ?i32 = undefined;
        \\    if (foo) |b<cursor>ar| {} else {}
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: error{A}!i32 = undefined;
        \\    if (foo) |fi<cursor>zz| {} else |buzz| {}
        \\}
    ,
        \\```zig
        \\fizz
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: error{A}!i32 = undefined;
        \\    if (foo) |fizz| {} else |bu<cursor>zz| {}
        \\}
    ,
        \\```zig
        \\buzz
        \\```
        \\```zig
        \\(error{A})
        \\```
    );
}

test "hover - while capture" {
    try testHover(
        \\fn func() void {
        \\    const foo: ?i32 = undefined;
        \\    while (foo) |b<cursor>ar| {}
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: ?i32 = undefined;
        \\    while (foo) |b<cursor>ar| {} else {}
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: error{A}!i32 = undefined;
        \\    while (foo) |fi<cursor>zz| {} else |buzz| {}
        \\}
    ,
        \\```zig
        \\fizz
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: error{A}!i32 = undefined;
        \\    while (foo) |fizz| {} else |bu<cursor>zz| {}
        \\}
    ,
        \\```zig
        \\buzz
        \\```
        \\```zig
        \\(error{A})
        \\```
    );
}

test "hover - catch capture" {
    try testHover(
        \\const foo: error{A}!i32 = undefined;
        \\const bar = foo catch |b<cursor>ar| undefined;
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(error{A})
        \\```
    );
}

test "hover - for capture" {
    try testHover(
        \\fn func() void {
        \\    const foo: []i32 = undefined;
        \\    for (foo) |b<cursor>ar| {}
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo: []i32 = undefined;
        \\    for (foo, 0..) |bar, in<cursor>dex| {}
        \\}
    ,
        \\```zig
        \\index
        \\```
        \\```zig
        \\(usize)
        \\```
    );
}

test "hover - switch capture" {
    try testHover(
        \\const U = union(enum) { a: i32 };
        \\fn func() void {
        \\    const foo: U = undefined;
        \\    switch (foo) {
        \\        .a => |b<cursor>ar| {},
        \\    }
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(i32)
        \\```
    );
    try testHover(
        \\const E = enum { foo };
        \\fn func(e: E) void {
        \\    switch (e) {
        \\        .foo => |b<cursor>ar| {},
        \\    }
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(E)
        \\```
        \\
        \\Go to [E](file:///test.zig#L1)
    );
}

test "hover - errdefer capture" {
    try testHover(
        \\fn func() error{A}!void {
        \\    errdefer |f<cursor>oo| {}
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(unknown)
        \\```
    );
}

test "hover - function" {
    try testHover(
        \\const A = struct { a: i32 };
        \\const B = struct { b: bool };
        \\const C = struct { c: u8 };
        \\const E = error { A, B };
        \\fn f<cursor>oo(a: A, b: B) E!C {}
    ,
        \\```zig
        \\fn foo(a: A, b: B) E!C
        \\```
        \\
        \\Go to [A](file:///test.zig#L1) | [B](file:///test.zig#L2) | [E](file:///test.zig#L4) | [C](file:///test.zig#L3)
    );
    try testHover(
        \\const S = struct { a: i32 };
        \\const E = error { A, B };
        \\fn f<cursor>oo(a: S, b: S) E!S {}
    ,
        \\```zig
        \\fn foo(a: S, b: S) E!S
        \\```
        \\
        \\Go to [S](file:///test.zig#L1) | [E](file:///test.zig#L2)
    );
    try testHover(
        \\fn foo(b<cursor>ar: enum { fizz, buzz }) void {}
    ,
        \\```zig
        \\bar: enum { fizz, buzz }
        \\```
        \\```zig
        \\(enum { fizz, buzz })
        \\```
    );
    try testHover(
        \\fn f<cursor>oo() !i32 {}
    ,
        \\```zig
        \\fn foo() !i32
        \\```
    );
}

test "hover - optional" {
    try testHover(
        \\const S = struct { a: i32 };
        \\const f<cursor>oo: ?S = undefined;
    ,
        \\```zig
        \\const foo: ?S = undefined
        \\```
        \\```zig
        \\(?S)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );
}

test "hover - error union" {
    try testHover(
        \\const S = struct { a: i32 };
        \\const E = error { A, B };
        \\const f<cursor>oo: E!S = undefined;
    ,
        \\```zig
        \\const foo: E!S = undefined
        \\```
        \\```zig
        \\(E!S)
        \\```
        \\
        \\Go to [E](file:///test.zig#L2) | [S](file:///test.zig#L1)
    );
}

test "hover - var decl comments" {
    try testHover(
        \\///this is a comment
        \\const f<cursor>oo = 0 + 0;
    ,
        \\```zig
        \\const foo = 0 + 0
        \\```
        \\```zig
        \\(unknown)
        \\```
        \\this is a comment
    );
}

test "hover - var decl alias" {
    try testHover(
        \\extern fn foo() void;
        \\const b<cursor>ar = foo;
    ,
        \\```zig
        \\fn foo() void
        \\```
    );
    try testHover(
        \\const foo = 5;
        \\const b<cursor>ar = foo;
    ,
        \\```zig
        \\const foo = 5
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
}

// https://github.com/zigtools/zls/issues/1378
test "hover - type reference cycle" {
    try testHover(
        \\fn fo<cursor>o(
        \\    alpha: anytype,
        \\    beta: @TypeOf(alpha),
        \\) void {
        \\    _ = beta;
        \\}
    ,
        \\```zig
        \\fn foo(
        \\    alpha: anytype,
        \\    beta: @TypeOf(alpha),
        \\) void
        \\```
    );
}

test "hover - integer overflow on top level container" {
    try testHover(
        \\enum {  foo.bar: b<cursor>az,}
    ,
        \\```zig
        \\baz
        \\```
        \\```zig
        \\(enum {  foo.bar: baz,})
        \\```
    );
}

fn testHover(source: []const u8, expected: []const u8) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.client_capabilities.hover_supports_md = true;

    const test_uri = "file:///test.zig";
    try ctx.server.sendNotificationSync(ctx.arena.allocator(), "textDocument/didOpen", .{
        .textDocument = .{ .uri = test_uri, .languageId = "zig", .version = 420, .text = text },
    });

    const params = types.HoverParams{
        .textDocument = .{ .uri = test_uri },
        .position = offsets.indexToPosition(text, cursor_idx, ctx.server.offset_encoding),
    };

    const response: types.Hover = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/hover", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    const markup_context = response.contents.MarkupContent;

    try std.testing.expectEqual(types.MarkupKind.markdown, markup_context.kind);
    try std.testing.expectEqualStrings(expected, markup_context.value);
}
