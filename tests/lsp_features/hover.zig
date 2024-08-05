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

test "sentinel values" {
    try testHover(
        \\const <cursor>a: [:0] i1 = undefined;
    ,
        \\```zig
        \\const a: [:0] i1 = undefined
        \\```
        \\```zig
        \\([:0]i1)
        \\```
    );
    try testHover(
        \\const <cursor>a: [:42] u8 = null;
    ,
        \\```zig
        \\const a: [:42] u8 = null
        \\```
        \\```zig
        \\([:42]u8)
        \\```
    );
    try testHover(
        \\const test<cursor>_str = "Hello, World!";
    ,
        \\```zig
        \\const test_str = "Hello, World!"
        \\```
        \\```zig
        \\(*const [13:0]u8)
        \\```
    );
    try testHover(
        \\const <cursor>array = [_:0]u8{ 1, 2, 3, 4 };
    ,
        \\```zig
        \\const array = [_:0]u8{ 1, 2, 3, 4 }
        \\```
        \\```zig
        \\([?:0]u8)
        \\```
    );
    try testHover(
        \\const a: [4:0]u8 = undefined;
        \\const <cursor>b = a;
    ,
        \\```zig
        \\const a: [4:0]u8 = undefined
        \\```
        \\```zig
        \\([4:0]u8)
        \\```
    );
    try testHover(
        \\const array = [_:0]u8{ 1, 2, 3, 4 };
        \\const <cursor>range = array[0..2];
    ,
        \\```zig
        \\const range = array[0..2]
        \\```
        \\```zig
        \\([]u8)
        \\```
    );
    try testHover(
        \\const array = [_:0]u8{ 1, 2, 3, 4 };
        \\const <cursor>open = array[1..];
    ,
        \\```zig
        \\const open = array[1..]
        \\```
        \\```zig
        \\([:0]u8)
        \\```
    );
    // try testHover(
    //     \\const hw = "Hello, World!";
    //     \\const <cursor>h = hw[0..5];
    // ,
    //     \\```zig
    //     \\const h = hw[0..5]
    //     \\```
    //     \\```zig
    //     \\([5]u8)
    //     \\```
    // );
    // try testHover(
    //     \\const hw = "Hello, World!";
    //     \\const <cursor>w = hw[7..];
    // ,
    //     \\```zig
    //     \\const h = hw[7..]
    //     \\```
    //     \\```zig
    //     \\([6:0]u8)
    //     \\```
    // );
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

    try testHover(
        \\const foo: ?i32 = 5;
        \\const b<cursor>ar = foo orelse 0;
    ,
        \\```zig
        \\const bar = foo orelse 0
        \\```
        \\```zig
        \\(i32)
        \\```
    );

    try testHover(
        \\const foo: ?i32 = 5;
        \\const b<cursor>ar = foo orelse foo;
    ,
        \\```zig
        \\const bar = foo orelse foo
        \\```
        \\```zig
        \\(?i32)
        \\```
    );

    try testHover(
        \\const foo: ?i32 = 5;
        \\const b<cursor>ar = foo orelse unreachable;
    ,
        \\```zig
        \\const bar = foo orelse unreachable
        \\```
        \\```zig
        \\(i32)
        \\```
    );

    try testHover(
        \\fn foo(a: ?i32) void {
        \\    const b<cursor>ar = a orelse return;
        \\}
    ,
        \\```zig
        \\const bar = a orelse return
        \\```
        \\```zig
        \\(i32)
        \\```
    );

    try testHover(
        \\fn foo() void {
        \\    const array: [1]?i32 = [1]?i32{ 4 };
        \\    for (array) |elem| {
        \\        const b<cursor>ar = elem orelse continue;
        \\    }
        \\}
    ,
        \\```zig
        \\const bar = elem orelse continue
        \\```
        \\```zig
        \\(i32)
        \\```
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

test "hover - destructuring" {
    try testHover(
        \\fn func() void {
        \\    const f<cursor>oo, const bar = .{ 1, 2 };
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo, const b<cursor>ar, const baz = .{ 1, 2, 3 };
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(comptime_int)
        \\```
    );
    try testHover(
        \\fn thing() !struct {usize, isize} {
        \\    return .{1, 2};
        \\}
        \\fn ex() void {
        \\    const f<cursor>oo, const bar = try thing();
        \\}
    ,
        \\```zig
        \\foo
        \\```
        \\```zig
        \\(usize)
        \\```
    );
    try testHover(
        \\fn func() void {
        \\    const foo, const b<cursor>ar: u32, const baz = undefined;
        \\}
    ,
        \\```zig
        \\bar
        \\```
        \\```zig
        \\(u32)
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

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.client_capabilities.hover_supports_md = options.markup_kind == .markdown;

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

    try std.testing.expectEqual(options.markup_kind, markup_context.kind);
    try std.testing.expectEqualStrings(expected, markup_context.value);
}
