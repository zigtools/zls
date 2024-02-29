const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "literal" {
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
        \\const f<cursor>oo = true;
    ,
        \\```zig
        \\const foo = true
        \\```
        \\```zig
        \\(bool)
        \\```
    );
    try testHover(
        \\const f<cursor>oo = false;
    ,
        \\```zig
        \\const foo = false
        \\```
        \\```zig
        \\(bool)
        \\```
    );
    try testHover(
        \\const f<cursor>oo = null;
    ,
        \\```zig
        \\const foo = null
        \\```
        \\```zig
        \\(@TypeOf(null))
        \\```
    );
    try testHover(
        \\const f<cursor>oo = unreachable;
    ,
        \\```zig
        \\const foo = unreachable
        \\```
        \\```zig
        \\(noreturn)
        \\```
    );
    try testHover(
        \\const f<cursor>oo = undefined;
    ,
        \\```zig
        \\const foo = undefined
        \\```
        \\```zig
        \\(@TypeOf(undefined))
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
        \\const f<cursor>oo = {};
    ,
        \\```zig
        \\const foo = {}
        \\```
        \\```zig
        \\(void)
        \\```
    );
}

test "string literal" {
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
        \\;
    ,
        \\```zig
        \\const foo =
        \\    \\ipsum lorem
        \\
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
    try testHover(
        \\const f<cursor>oo = "hello".*;
    ,
        \\```zig
        \\const foo = "hello".*
        \\```
        \\```zig
        \\([5:0]u8)
        \\```
    );
}

test "builtin" {
    try testHover(
        \\@intFr<cursor>omBool(5);
    ,
        \\```zig
        \\@intFromBool(value: bool) u1
        \\```
        \\Converts `true` to `@as(u1, 1)` and `false` to `@as(u1, 0)`.
    );
    try testHoverWithOptions(
        \\@intFr<cursor>omBool(5);
    ,
        \\@intFromBool(value: bool) u1
        \\Converts `true` to `@as(u1, 1)` and `false` to `@as(u1, 0)`.
    , .{ .markup_kind = .plaintext });
}

test "vector type" {
    try testHover(
        \\const u32<cursor>x4: @Vector(4, u32) = undefined;
    ,
        \\```zig
        \\const u32x4: @Vector(4, u32) = undefined
        \\```
        \\```zig
        \\(@Vector(4,u32))
        \\```
    );
}

test "negation" {
    try testHover(
        \\const f<cursor>oo = 1;
        \\const f = -a;
        \\const b = -%a;
        \\const _ = <cursor>
    ,
        \\```zig
        \\const foo = 1
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const foo = 1;
        \\const b<cursor>ar = -foo;
    ,
        \\```zig
        \\const bar = -foo
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const foo = 1;
        \\const b<cursor>ar = -%foo;
    ,
        \\```zig
        \\const bar = -%foo
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
}

test "struct" {
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

test "enum member" {
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

test "block label" {
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
    try testHover(
        \\const foo: i32 = undefined;
        \\const bar = baz: {
        \\    break :b<cursor>az foo;
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

test "if capture" {
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

test "while capture" {
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

test "catch capture" {
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

test "for capture" {
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

test "enum literal" {
    try testHover(
        \\const E = enum { foo };
        \\const e: E = .f<cursor>oo;
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(E)
        \\```
        \\
        \\Go to [E](file:///test.zig#L1)
    );
}

test "switch capture" {
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

test "errdefer capture" {
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

test "function" {
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
    try testHoverWithOptions(
        \\fn f<cursor>oo() i32 {}
    ,
        \\fn foo() i32
    , .{ .markup_kind = .plaintext });
}

test "optional" {
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

test "error union" {
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

test "either types" {
    try testHover(
        \\const A = struct {
        \\    ///small type
        \\    pub const T = u32;
        \\};
        \\const B = struct {
        \\    ///large type
        \\    pub const T = u64;
        \\};
        \\const either = if (undefined) A else B;
        \\const bar = either.<cursor>T;
    ,
        \\```zig
        \\const T = u32
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\small type
        \\
        \\```zig
        \\const T = u64
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\large type
    );
    try testHoverWithOptions(
        \\const A = struct {
        \\    ///small type
        \\    pub const T = u32;
        \\};
        \\const B = struct {
        \\    ///large type
        \\    pub const T = u64;
        \\};
        \\const either = if (undefined) A else B;
        \\const bar = either.<cursor>T;
    ,
        \\const T = u32
        \\(type)
        \\
        \\small type
        \\
        \\const T = u64
        \\(type)
        \\
        \\large type
    , .{ .markup_kind = .plaintext });
}

test "var decl comments" {
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
        \\
        \\this is a comment
    );
}

test "var decl alias" {
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

test "hover - destructuring" {
    try testHover(
        \\fn func() void {
        \\    const foo, const bar = .{ 1, 2 };
        \\    _ = f<cursor>oo;
        \\    _ = bar;
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
}

test "hover - destructuring multiple" {
    try testHover(
        \\fn func() void {
        \\    const foo, const bar, const baz = .{ 1, 2, 3 };
        \\    _ = f<cursor>oo;
        \\    _ = bar;
        \\    _ = baz;
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
}

test "hover - destructuring try" {
    try testHover(
        \\fn thing() !struct {usize, isize} {
        \\    return .{1, 2};
        \\}
        \\fn ex() void {
        \\    const foo, const bar = try thing();
        \\    _ = f<cursor>oo;
        \\    _ = bar;
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(usize)
        \\```
    );
}

// https://github.com/zigtools/zls/issues/1378
test "type reference cycle" {
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

test "integer overflow on top level container" {
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

test "combine doc comments of declaration and definition" {
    try testHover(
        \\/// Foo
        \\const f<cursor>oo = bar.baz;
        \\const bar = struct {
        \\    /// Bar
        \\    const baz = struct {};
        \\};
    ,
        \\```zig
        \\const baz = struct
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\ Foo
        \\
        \\ Bar
    );
    try testHoverWithOptions(
        \\/// Foo
        \\const f<cursor>oo = bar.baz;
        \\const bar = struct {
        \\    /// Bar
        \\    const baz = struct {};
        \\};
    ,
        \\const baz = struct
        \\(type)
        \\
        \\ Foo
        \\
        \\ Bar
    , .{ .markup_kind = .plaintext });
}

test "top-level doc comment" {
    try testHover(
        \\//! B
        \\
        \\/// A
        \\const S<cursor>elf = @This();
    ,
        \\```zig
        \\const Self = @This()
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\ A
        \\
        \\ B
    );
}

test "deprecated" {
    try testHover(
        \\const f<cursor>oo = @compileError("some message");
    ,
        \\```zig
        \\const foo = @compileError("some message")
        \\```
        \\```zig
        \\(@compileError("some message"))
        \\```
    );
}

fn testHover(source: []const u8, expected: []const u8) !void {
    try testHoverWithOptions(source, expected, .{ .markup_kind = .markdown });
}

fn testHoverWithOptions(
    source: []const u8,
    expected: []const u8,
    options: struct { markup_kind: types.MarkupKind },
) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.client_capabilities.hover_supports_md = options.markup_kind == .markdown;

    const test_uri = "file:///test.zig";
    try ctx.server.sendNotificationSync(ctx.arena.allocator(), "textDocument/didOpen", .{
        .textDocument = .{ .uri = test_uri, .languageId = .{ .custom_value = "zig" }, .version = 420, .text = text },
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

    try std.testing.expectEqual(options.markup_kind, markup_context.kind);
    try std.testing.expectEqualStrings(expected, markup_context.value);
}
