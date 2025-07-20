const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.lsp.types;
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
        \\
        \\Foo doc comment
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

test "root struct" {
    try testHover(
        \\const f<cursor>oo: @This() = .{};
    ,
        \\```zig
        \\const foo: @This() = .{}
        \\```
        \\```zig
        \\(test)
        \\```
        \\
        \\Go to [test](file:///test.zig#L1)
    );
}

test "inferred struct init" {
    try testHover(
        \\const S = struct { foo: u32 };
        \\const foo: S = .<cursor>{ .foo = 0 };
    ,
        \\```zig
        \\S
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );
    try testHover(
        \\const S = struct { foo: u32 };
        \\fn f(_: S) void {}
        \\const foo = f(<cursor>.{ .foo = 0 });
    ,
        \\```zig
        \\S
        \\```
        \\```zig
        \\(type)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
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
        \\```zig
        \\(fn () S)
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
        \\```zig
        \\(fn () !S)
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
        \\```zig
        \\(fn () Inner)
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
        \\(Box(u8))
        \\```
        \\
        \\Go to [Box](file:///test.zig#L1)
    );
}

test "decl literal on generic type - alias" {
    try testHover(
        \\fn Box(comptime T: type) type {
        \\    return struct {
        \\        item: T,
        \\        const init: @This() = undefined;
        \\        const alias = init;
        \\    };
        \\}
        \\test {
        \\    const box: Box(u8) = .al<cursor>ias;
        \\}
    ,
        \\```zig
        \\const init: @This() = undefined
        \\```
        \\```zig
        \\(Box(u8))
        \\```
        \\
        \\Go to [Box](file:///test.zig#L1)
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

test "generic type" {
    try testHover(
        \\const StructType = struct {};
        \\const EnumType = enum {};
        \\fn GenericType(A: type, B: type) type {
        \\    _ = .{ A, B };
        \\    return struct {};
        \\}
        \\const T = GenericType(StructType, EnumType);
        \\const t<cursor>: T = .{};
    ,
        \\```zig
        \\const t: T = .{}
        \\```
        \\```zig
        \\(GenericType(StructType,EnumType))
        \\```
        \\
        \\Go to [GenericType](file:///test.zig#L3) | [StructType](file:///test.zig#L1) | [EnumType](file:///test.zig#L2)
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
        \\```zig
        \\(fn (A, B) error{A,B}!C)
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
        \\```zig
        \\(fn (S, S) error{A,B}!S)
        \\```
        \\
        \\Go to [S](file:///test.zig#L1)
    );
    try testHover(
        \\const E = error { A, B, C };
        \\fn f<cursor>oo() E!void {}
    ,
        \\```zig
        \\fn foo() E!void
        \\```
        \\```zig
        \\(fn () error{...}!void)
        \\```
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
        \\```zig
        \\(fn () !i32)
        \\```
    );
    try testHover(
        \\extern fn f<cursor>oo(u32) void;
    ,
        \\```zig
        \\fn foo(u32) void
        \\```
        \\```zig
        \\(fn (u32) void)
        \\```
    );
    try testHoverWithOptions(
        \\fn f<cursor>oo() i32 {}
    ,
        \\fn foo() i32
        \\(fn () i32)
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
        \\```zig
        \\a: u32
        \\```
        \\```zig
        \\(u32)
        \\```
        \\
        \\hello world
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

test "either type instances" {
    try testHoverWithOptions(
        \\const EitherType<cursor> = if (undefined) u32 else f64;
    ,
        \\const EitherType = if (undefined) u32 else f64
        \\(type)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: EitherType = undefined;
    ,
        \\const either: EitherType = undefined
        \\(u32)
        \\(f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: *EitherType = undefined;
    ,
        \\const either: *EitherType = undefined
        \\(*u32)
        \\(*f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: [3]EitherType = undefined;
    ,
        \\const either: [3]EitherType = undefined
        \\([3]u32)
        \\([3]f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: struct { EitherType } = undefined;
    ,
        \\const either: struct { EitherType } = undefined
        \\(struct { u32 })
        \\(struct { f64 })
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: ?EitherType = undefined;
    ,
        \\const either: ?EitherType = undefined
        \\(?u32)
        \\(?f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherError = if (undefined) error{Foo} else error{Bar};
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: EitherError!EitherType = undefined;
    ,
        \\const either: EitherError!EitherType = undefined
        \\(error{Foo}!u32)
        \\(error{Foo}!f64)
        \\(error{Bar}!u32)
        \\(error{Bar}!f64)
    , .{
        .markup_kind = .plaintext,
        .max_conditional_combos = 4,
    });
    try testHoverWithOptions(
        \\fn GenericStruct(T: type) type {
        \\    return struct { field: T };
        \\}
        \\const EitherType = if (undefined) u32 else f64;
        \\const either<cursor>: GenericStruct(EitherType) = undefined;
    ,
        \\const either: GenericStruct(EitherType) = undefined
        \\(GenericStruct(u32))
        \\(GenericStruct(f64))
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\fn function<cursor>() EitherType {}
    ,
        \\fn function() EitherType
        \\(fn () u32)
        \\(fn () f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\fn function<cursor>(_: EitherType) void {}
    ,
        \\fn function(_: EitherType) void
        \\(fn (u32) void)
        \\(fn (f64) void)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const EitherType = if (undefined) u32 else f64;
        \\fn function<cursor>(_: EitherType) EitherType {}
    ,
        \\fn function(_: EitherType) EitherType
        \\(fn (u32) u32)
        \\(fn (f64) f64)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const foo<cursor> = switch (undefined) {
        \\    .a => 42,
        \\    .b => true,
        \\    .c => 3.14,
        \\    .d => {},
        \\    .e => error.Foo,
        \\};
    ,
        \\const foo = switch (undefined) {
        \\    .a => 42,
        \\    .b => true,
        \\    .c => 3.14,
        \\    .d => {},
        \\    .e => error.Foo,
        \\}
        \\(comptime_int)
        \\(bool)
        \\(comptime_float)
        \\(...)
    , .{ .markup_kind = .plaintext });
}

test "either type instances - big" {
    try testHoverWithOptions(
        \\const foo = if (true) 1 else true;
        \\const bar<cursor> = if (true)
        \\    .{ foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo }
        \\else
        \\    .{ foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo };
    ,
        \\const bar = if (true)
        \\    .{ foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo }
        \\else
        \\    .{ foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo, foo }
        \\(struct { comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int, comptime_int })
        \\(struct { bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool })
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const a = if (true) 1 else true;
        \\const b = if (true) false else 0;
        \\const c = if (true) .{ a, b } else .{ b, a };
        \\const d = if (true) .{ a, c } else .{ b, c };
        \\const e = if (true) .{ c, d } else .{ d, c };
        \\const f = if (true) .{ d, e } else .{ e, d };
        \\const g = if (true) .{ e, f } else .{ f, e };
        \\const h<cursor> = if (true) .{ f, g } else .{ g, f };
    ,
        \\const h = if (true) .{ f, g } else .{ g, f }
        \\(struct { struct { struct { comptime_int, struct { comptime_int, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } }, struct { struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } }, struct { struct { comptime_int, struct { comptime_int, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } } } })
        \\(struct { struct { struct { bool, struct { comptime_int, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } }, struct { struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } }, struct { struct { comptime_int, struct { comptime_int, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } } } })
        \\(struct { struct { struct { comptime_int, struct { bool, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } }, struct { struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } }, struct { struct { comptime_int, struct { comptime_int, bool } }, struct { struct { comptime_int, bool }, struct { comptime_int, struct { comptime_int, bool } } } } } })
        \\(...)
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
        \\(comptime_int)
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
        \\```zig
        \\(fn () void)
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

test "alias with different type" {
    try testHoverWithOptions(
        \\const foo: i32 = 1;
        \\const bar<cursor>: ?i32 = foo;
    ,
        \\const foo: i32 = 1
        \\(?i32)
    , .{ .markup_kind = .plaintext });
}

test "escaped identifier" {
    try testHoverWithOptions(
        \\const @"f<cursor>oo" = 42;
    ,
        \\```zig
        \\const @"foo" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    , .{
        .highlight = "@\"foo\"",
        .markup_kind = .markdown,
    });
    try testHoverWithOptions(
        \\const @"hello <cursor> world" = 42;
    ,
        \\```zig
        \\const @"hello  world" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    , .{
        .highlight = "@\"hello  world\"",
        .markup_kind = .markdown,
    });
    try testHoverWithOptions(
        \\const @<cursor>"hello  world" = 42;
    ,
        \\```zig
        \\const @"hello  world" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    , .{
        .highlight = "@\"hello  world\"",
        .markup_kind = .markdown,
    });
}

test "escaped identifier with same name as primitive" {
    try testHoverWithOptions(
        \\const @"true"<cursor> = 42;
    ,
        \\```zig
        \\const @"true" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    , .{
        .highlight = "@\"true\"",
        .markup_kind = .markdown,
    });
    try testHoverWithOptions(
        \\const @"f32"<cursor> = 42;
    ,
        \\```zig
        \\const @"f32" = 42
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    , .{
        .highlight = "@\"f32\"",
        .markup_kind = .markdown,
    });
}

test "escaped identifier in enum literal" {
    try testHoverWithOptions(
        \\const E = enum { @"hello world" };
        \\const e: E = .@"hello world"<cursor>;
    ,
        \\```zig
        \\@"hello world"
        \\```
        \\```zig
        \\(E)
        \\```
        \\
        \\Go to [E](file:///test.zig#L1)
    , .{
        .highlight = "@\"hello world\"",
        .markup_kind = .markdown,
    });
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
        \\```zig
        \\(fn (anytype, anytype) void)
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
        \\Foo
        \\
        \\Bar
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
        \\Foo
        \\
        \\Bar
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
        \\A
        \\
        \\B
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

test "slice properties" {
    try testHoverWithOptions(
        \\const foo: []const u8 = undefined;
        \\const bar = foo.len<cursor>;
    ,
        \\len
        \\(usize)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const foo: []const u8 = undefined;
        \\const bar = foo.ptr<cursor>;
    ,
        \\ptr
        \\([*]const u8)
    , .{ .markup_kind = .plaintext });
}

test "array properties" {
    try testHoverWithOptions(
        \\const foo: [3]u8 = undefined;
        \\const bar = foo.len<cursor>;
    ,
        \\len
        \\(usize)
    , .{ .markup_kind = .plaintext });
}

test "tuple properties" {
    try testHoverWithOptions(
        \\const foo: struct { i32, bool } = undefined;
        \\const bar = foo.len<cursor>;
    ,
        \\len
        \\(usize)
    , .{ .markup_kind = .plaintext });
    try testHoverWithOptions(
        \\const foo: struct { i32, bool } = undefined;
        \\const bar = foo.@"0"<cursor>;
    ,
        \\@"0"
        \\(i32)
    , .{
        .highlight = "@\"0\"",
        .markup_kind = .plaintext,
    });
    try testHoverWithOptions(
        \\const foo: struct { i32, bool } = undefined;
        \\const bar = foo.@"1"<cursor>;
    ,
        \\@"1"
        \\(bool)
    , .{
        .highlight = "@\"1\"",
        .markup_kind = .plaintext,
    });
}

test "optional unwrap" {
    try testHoverWithOptions(
        \\const foo: ?f64 = undefined;
        \\const bar = foo.?<cursor>;
    ,
        \\?
        \\(f64)
    , .{
        .highlight = "?",
        .markup_kind = .plaintext,
    });
    try testHoverWithOptions(
        \\const foo: ?f64 = undefined;
        \\const bar = foo.<cursor>?;
    ,
        \\?
        \\(f64)
    , .{
        .highlight = "?",
        .markup_kind = .plaintext,
    });
}

test "pointer dereference" {
    try testHoverWithOptions(
        \\const foo: *f64 = undefined;
        \\const bar = foo.*<cursor>;
    ,
        \\*
        \\(f64)
    , .{
        .highlight = "*",
        .markup_kind = .plaintext,
    });
    try testHoverWithOptions(
        \\const foo: *f64 = undefined;
        \\const bar = foo.<cursor>*;
    ,
        \\*
        \\(f64)
    , .{
        .highlight = "*",
        .markup_kind = .plaintext,
    });
}

fn testHover(source: []const u8, expected: []const u8) !void {
    try testHoverWithOptions(source, expected, .{ .markup_kind = .markdown });
}

fn testHoverWithOptions(
    source: []const u8,
    expected: []const u8,
    options: struct {
        markup_kind: types.MarkupKind,
        max_conditional_combos: usize = 3,
        highlight: ?[]const u8 = null,
    },
) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx: Context = try .init();
    defer ctx.deinit();

    const server = ctx.server;
    const arena = ctx.arena.allocator();

    const uri = try ctx.addDocument(.{
        .uri = "file:///test.zig",
        .source = text,
    });
    const handle = server.document_store.getHandle(uri).?;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    analyser.max_conditional_combos = options.max_conditional_combos;

    const response = try zls.hover.hover(
        &analyser,
        arena,
        handle,
        cursor_idx,
        options.markup_kind,
        server.offset_encoding,
    ) orelse {
        if (expected.len == 0) return;
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    const markup_context = response.contents.MarkupContent;

    try std.testing.expectEqual(options.markup_kind, markup_context.kind);
    try zls.testing.expectEqualStrings(expected, markup_context.value);
    if (options.highlight) |expected_higlight| {
        const actual_highlight = offsets.rangeToSlice(text, response.range.?, ctx.server.offset_encoding);
        try std.testing.expectEqualStrings(expected_higlight, actual_highlight);
    }
}
