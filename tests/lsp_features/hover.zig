const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "primitive" {
    try testHover(
        \\const foo = bool<cursor>;
    ,
        \\```zig
        \\bool
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const foo = true<cursor>;
    ,
        \\```zig
        \\true
        \\```
        \\```zig
        \\(bool)
        \\```
    );
    try testHover(
        \\const foo = c_int<cursor>;
    ,
        \\```zig
        \\c_int
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const foo = f32<cursor>;
    ,
        \\```zig
        \\f32
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const foo = i64<cursor>;
    ,
        \\```zig
        \\i64
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const foo = null<cursor>;
    ,
        \\```zig
        \\null
        \\```
        \\```zig
        \\(@TypeOf(null))
        \\```
    );
    try testHover(
        \\const foo = undefined<cursor>;
    ,
        \\```zig
        \\undefined
        \\```
        \\```zig
        \\(@TypeOf(undefined))
        \\```
    );
}

test "char literal" {
    try testHover(
        \\const foo = '<cursor>a';
    ,
        \\| Base | Value     |
        \\| ---- | --------- |
        \\| BIN  | 0b1100001 |
        \\| OCT  | 0o141     |
        \\| DEC  | 97        |
        \\| HEX  | 0x61      |
    );

    try testHover(
        \\const foo = '<cursor>\'';
    ,
        \\| Base | Value    |
        \\| ---- | -------- |
        \\| BIN  | 0b100111 |
        \\| OCT  | 0o47     |
        \\| DEC  | 39       |
        \\| HEX  | 0x27     |
    );

    try testHover(
        \\const foo = '\'<cursor>';
    ,
        \\| Base | Value    |
        \\| ---- | -------- |
        \\| BIN  | 0b100111 |
        \\| OCT  | 0o47     |
        \\| DEC  | 39       |
        \\| HEX  | 0x27     |
    );
}
test "integer literal" {
    try testHover(
        \\const foo = 4<cursor>2;
    ,
        \\| Base | Value    |
        \\| ---- | -------- |
        \\| BIN  | 0b101010 |
        \\| OCT  | 0o52     |
        \\| DEC  | 42       |
        \\| HEX  | 0x2A     |
    );
    try testHover(
        \\const foo = -4<cursor>2;
    ,
        \\| Base | Value     |
        \\| ---- | --------- |
        \\| BIN  | -0b101010 |
        \\| OCT  | -0o52     |
        \\| DEC  | -42       |
        \\| HEX  | -0x2A     |
    );
    try testHover(
        \\const foo = 0b101<cursor>010;
    ,
        \\| Base | Value    |
        \\| ---- | -------- |
        \\| BIN  | 0b101010 |
        \\| OCT  | 0o52     |
        \\| DEC  | 42       |
        \\| HEX  | 0x2A     |
    );
    try testHover(
        \\const foo = -0b101<cursor>010;
    ,
        \\| Base | Value     |
        \\| ---- | --------- |
        \\| BIN  | -0b101010 |
        \\| OCT  | -0o52     |
        \\| DEC  | -42       |
        \\| HEX  | -0x2A     |
    );
    try testHover(
        \\const foo = 0x2<cursor>A;
    ,
        \\| Base | Value    |
        \\| ---- | -------- |
        \\| BIN  | 0b101010 |
        \\| OCT  | 0o52     |
        \\| DEC  | 42       |
        \\| HEX  | 0x2A     |
    );
    try testHover(
        \\const foo = -0x2<cursor>A;
    ,
        \\| Base | Value     |
        \\| ---- | --------- |
        \\| BIN  | -0b101010 |
        \\| OCT  | -0o52     |
        \\| DEC  | -42       |
        \\| HEX  | -0x2A     |
    );
    try testHover(
        \\const foo = 0x<cursor>0;
    ,
        \\| Base | Value |
        \\| ---- | ----- |
        \\| BIN  | 0b0   |
        \\| OCT  | 0o0   |
        \\| DEC  | 0     |
        \\| HEX  | 0x0   |
    );
    try testHoverWithOptions(
        \\const foo = 4<cursor>2;
    ,
        \\BIN: 0b101010
        \\OCT: 0o52
        \\DEC: 42
        \\HEX: 0x2A
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const foo = -4<cursor>2;
    ,
        \\BIN: -0b101010
        \\OCT: -0o52
        \\DEC: -42
        \\HEX: -0x2A
    , .{ .markup_kind = .plaintext });
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
    try testHover(
        \\const Str<cursor>uct = struct {
        \\    fn foo() void {}
        \\};
    ,
        \\```zig
        \\const Struct = struct
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const <cursor>S = struct {
        \\  fn foo() void {
        \\      // many lines here
        \\    }
        \\
        \\         fld: u8,
        \\};
    ,
        \\```zig
        \\const S = struct {
        \\    fld: u8,
        \\}
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\/// Foo doc comment
        \\const Foo<cursor>Struct = struct {
        \\    bar: u32,
        \\    baz: bool,
        \\    boo: MyInner,
        \\
        \\    pub const MyInner = struct {
        \\        another_field: bool,
        \\    };
        \\};
    ,
        \\ Foo doc comment
        \\
        \\```zig
        \\const FooStruct = struct {
        \\    bar: u32,
        \\    baz: bool,
        \\    boo: MyInner,
        \\}
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\const Edge<cursor>Cases = struct {
        \\    const str = "something";
        \\    const s = S{
        \\        .fld = 0,
        \\    };
        \\    pub fn myEdgeCase() void {}
        \\};
    ,
        \\```zig
        \\const EdgeCases = struct
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\<cursor>foo: u32,
    ,
        \\```zig
        \\u32
        \\```
        \\```zig
        \\(u32)
        \\```
    );
    try testHover(
        \\const S = struct { foo: u32 };
        \\const foo = (S{ .foo = 0 }).<cursor>foo;
    ,
        \\```zig
        \\u32
        \\```
        \\```zig
        \\(u32)
        \\```
    );
}

test "decl literal" {
    try testHover(
        \\const S = struct {
        \\    const foo: S = .{};
        \\};
        \\const s: S = .foo<cursor>;
    ,
        \\```zig
        \\const foo: S = .{}
        \\```
        \\```zig
        \\(S)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );
    try testHover(
        \\const S = struct {
        \\    bar: u32,
        \\    const foo: S = .{};
        \\};
        \\const s: S = .bar<cursor>;
    , "");
}

test "decl literal function" {
    try testHover(
        \\const S = struct {
        \\    fn foo() S {}
        \\};
        \\const s: S = .foo<cursor>;
    ,
        \\```zig
        \\fn foo() S
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );

    try testHover(
        \\const S = struct {
        \\    fn foo() !S {}
        \\};
        \\test {
        \\    const s: S = try .foo<cursor>();
        \\}
    ,
        \\```zig
        \\fn foo() !S
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );
    try testHover(
        \\const Inner = struct {
        \\    fn init() Inner {}
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
        \\const foo: Outer = .{
        \\    .inner = .in<cursor>it(),
        \\};
    ,
        \\```zig
        \\fn init() Inner
        \\```
        \\
        \\Go to [Inner](file:///test.zig#L1)
    );
}

test "decl literal on generic type" {
    try testHover(
        \\fn Box(comptime T: type) type {
        \\    return struct {
        \\        item: T,
        \\        const init: @This() = undefined;
        \\    };
        \\};
        \\test {
        \\    const box: Box(u8) = .in<cursor>it;
        \\}
    ,
        \\```zig
        \\const init: @This() = undefined
        \\```
        \\```zig
        \\(Box)
        \\```
        \\
        \\Go to [@This()](file:///test.zig#L1)
    );
}

test "enum" {
    try testHover(
        \\const My<cursor>Enum = enum {
        \\    foo,
        \\    bar,
        \\    baz,
        \\
        \\    fn enum_method() !void {
        \\        return .{};
        \\    }
        \\};
    ,
        \\```zig
        \\const MyEnum = enum {
        \\    foo,
        \\    bar,
        \\    baz,
        \\}
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHover(
        \\pub const M<cursor>ode = enum { zig, zon };
    ,
        \\```zig
        \\const Mode = enum { zig, zon }
        \\```
        \\```zig
        \\(type)
        \\```
    );
}

test "union" {
    try testHover(
        \\const Comptime<cursor>Reason = union(enum) {
        \\  c_import: struct {
        \\      block: *Block,
        \\      src: LazySrcLoc,
        \\  },
        \\  comptime_ret_ty: struct {
        \\      block: *Block,
        \\      func: Air.Inst.Ref,
        \\      func_src: LazySrcLoc,
        \\      return_ty: Type,
        \\  },
        \\
        \\  fn explain(cr: ComptimeReason, sema: *Sema, msg: ?*Module.ErrorMsg) !void {
        \\      // many lines here
        \\  }
        \\};
    ,
        \\```zig
        \\const ComptimeReason = union(enum) {
        \\  c_import: struct {
        \\      block: *Block,
        \\      src: LazySrcLoc,
        \\  },
        \\  comptime_ret_ty: struct {
        \\      block: *Block,
        \\      func: Air.Inst.Ref,
        \\      func_src: LazySrcLoc,
        \\      return_ty: Type,
        \\  },
        \\}
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
        \\Go to [A](file:///test.zig#L1) | [B](file:///test.zig#L2) | [C](file:///test.zig#L3)
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
        \\Go to [S](file:///test.zig#L1)
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
    try testHover(
        \\extern fn f<cursor>oo(u32) void;
    ,
        \\```zig
        \\fn foo(u32) void
        \\```
    );
    try testHoverWithOptions(
        \\fn f<cursor>oo() i32 {}
    ,
        \\fn foo() i32
    , .{ .markup_kind = .plaintext });
}

test "function parameter" {
    try testHover(
        \\fn foo(
        \\    /// hello world
        \\    <cursor>a: u32,
        \\) u32 {
        \\    return a;
        \\}
    ,
        \\ hello world
        \\
        \\```zig
        \\a: u32
        \\```
        \\```zig
        \\(u32)
        \\```
    );
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
        \\(error{A,B}!S)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
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
        \\small type
        \\
        \\```zig
        \\const T = u32
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\large type
        \\
        \\```zig
        \\const T = u64
        \\```
        \\```zig
        \\(type)
        \\```
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
        \\small type
        \\
        \\const T = u32
        \\(type)
        \\
        \\large type
        \\
        \\const T = u64
        \\(type)
    , .{ .markup_kind = .plaintext });
}

test "var decl comments" {
    try testHover(
        \\///this is a comment
        \\const f<cursor>oo = 0 + 0;
    ,
        \\this is a comment
        \\
        \\```zig
        \\const foo = 0 + 0
        \\```
        \\```zig
        \\(unknown)
        \\```
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

test "escaped identifier" {
    try testHover(
        \\const @"f<cursor>oo" = 42;
    ,
        \\```zig
        \\const @"foo" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const @"hello <cursor> world" = 42;
    ,
        \\```zig
        \\const @"hello  world" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const @<cursor>"hello  world" = 42;
    ,
        \\```zig
        \\const @"hello  world" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
}

test "escaped identifier with same name as primitive" {
    try testHover(
        \\const @"true"<cursor> = 42;
    ,
        \\```zig
        \\const @"true" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\const @"f32"<cursor> = 42;
    ,
        \\```zig
        \\const @"f32" = 42
        \\```
        \\```zig
        \\(comptime_int)
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
        \\ Foo
        \\
        \\ Bar
        \\
        \\```zig
        \\const baz = struct
        \\```
        \\```zig
        \\(type)
        \\```
    );
    try testHoverWithOptions(
        \\/// Foo
        \\const f<cursor>oo = bar.baz;
        \\const bar = struct {
        \\    /// Bar
        \\    const baz = struct {};
        \\};
    ,
        \\ Foo
        \\
        \\ Bar
        \\
        \\const baz = struct
        \\(type)
    , .{ .markup_kind = .plaintext });
}

test "top-level doc comment" {
    try testHover(
        \\//! B
        \\
        \\/// A
        \\const S<cursor>elf = @This();
    ,
        \\ A
        \\
        \\ B
        \\
        \\```zig
        \\const Self = @This()
        \\```
        \\```zig
        \\(type)
        \\```
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

    var ctx: Context = try .init();
    defer ctx.deinit();

    ctx.server.client_capabilities.hover_supports_md = options.markup_kind == .markdown;

    const uri = try ctx.addDocument(.{
        .uri = "file:///test.zig",
        .source = text,
    });

    const params: types.HoverParams = .{
        .textDocument = .{ .uri = uri },
        .position = offsets.indexToPosition(text, cursor_idx, ctx.server.offset_encoding),
    };

    const response: types.Hover = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/hover", params) orelse {
        if (expected.len == 0) return;
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    const markup_context = response.contents.MarkupContent;

    try std.testing.expectEqual(options.markup_kind, markup_context.kind);
    try std.testing.expectEqualStrings(expected, markup_context.value);
}
