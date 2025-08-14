const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.lsp.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

const Completion = struct {
    label: []const u8,
    labelDetails: ?types.CompletionItemLabelDetails = null,
    kind: types.CompletionItemKind,
    detail: ?[]const u8 = null,
    documentation: ?[]const u8 = null,
    deprecated: bool = false,
};

test "root scope" {
    try testCompletion(
        \\const foo = 5;
        \\const bar = <cursor>;
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });

    try testCompletion(
        \\var foo = 5;
        \\const bar = <cursor>
    , &.{
        .{ .label = "foo", .kind = .Variable },
    });

    try testCompletion(
        \\const foo = 5;
        \\const bar = <cursor>;
        \\const baz = 5;
    , &.{
        .{ .label = "foo", .kind = .Constant },
        .{ .label = "baz", .kind = .Constant },
    });
}

test "access root scope through '@This()' builtin" {
    try testCompletion(
        \\const foo = 5;
        \\const Self = @This();
        \\const bar = Self.<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
        .{ .label = "Self", .kind = .Struct },
    });
}

test "root scope with self referential decl" {
    try testCompletion(
        \\const foo = foo;
        \\const bar = <cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });
}

test "local scope" {
    if (true) return error.SkipZigTest;
    try testCompletion(
        \\const foo = {
        \\    var bar = 5;
        \\    const alpha = <cursor>;
        \\    const baz = 3;
        \\};
    , &.{
        .{ .label = "bar", .kind = .Variable },
    });
}

test "symbol lookup on escaped identifiers" {
    // decl name:   unescaped
    // symbol name: unescaped
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const Inner = Bar; };
        \\const foo = Outer.Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const Inner = Bar; };
        \\const Inner = Outer.Inner;
        \\const foo = Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    // decl name:   escaped
    // symbol name: unescaped
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const @"Inner" = Bar; };
        \\const foo = Outer.Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const @"Inner" = Bar; };
        \\const Inner = Outer.Inner;
        \\const foo = Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    // decl name:   unescaped
    // symbol name: escaped
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const Inner = Bar; };
        \\const foo = Outer.@"Inner".<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const Inner = Bar; };
        \\const Inner = Outer.@"Inner";
        \\const foo = Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    // decl name:   escaped
    // symbol name: escaped
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const @"Inner" = Bar; };
        \\const foo = Outer.@"Inner".<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const Bar = struct { const Some = u32; };
        \\const Outer = struct { const Inner = Bar; };
        \\const Inner = Outer.@"Inner";
        \\const foo = Inner.<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
}

test "escaped identifier normalization" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\var s: @"\x53" = undefined;
        \\const foo = @"\x73".<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });
}

test "symbol lookup on identifier named after primitive" {
    try testCompletion(
        \\const Outer = struct { const @"u32" = Bar; };
        \\const Bar = struct { const Some = u32; };
        \\const foo = Outer.@"u32".<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const Outer = struct { const @"undefined" = Bar; };
        \\const Bar = struct { const Some = u32; };
        \\const foo = Outer.@"undefined".<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const @"unreachable" = struct { const Some = u32; };
        \\const foo = @"unreachable".<cursor>
    , &.{
        .{ .label = "Some", .kind = .Constant, .detail = "u32" },
    });
}

test "assign destructure" {
    try testCompletion(
        \\test {
        \\    const foo, var bar: u32 = .{42, 7};
        \\    <cursor>
        \\}
    , &.{
        .{ .label = "foo", .kind = .Constant, .detail = "comptime_int" },
        .{ .label = "bar", .kind = .Variable, .detail = "u32" },
    });
    try testCompletion(
        \\test {
        \\    var foo, const bar = .{@as(u32, 42), @as(u64, 7)};
        \\    <cursor>
        \\}
    , &.{
        .{ .label = "foo", .kind = .Variable, .detail = "u32" },
        .{ .label = "bar", .kind = .Constant, .detail = "u64" },
    });
    try testCompletion(
        \\test {
        \\    var foo: u32 = undefined;
        \\    foo, const bar: u64, var baz = [_]u32{1, 2, 3};
        \\    <cursor>
        \\}
    , &.{
        .{ .label = "foo", .kind = .Variable, .detail = "u32" },
        .{ .label = "bar", .kind = .Constant, .detail = "u64" },
        .{ .label = "baz", .kind = .Variable, .detail = "u32" },
    });
}

test "function" {
    try testCompletion(
        \\fn foo(alpha: u32, beta: []const u8) void {
        \\    <cursor>
        \\}
    , &.{
        .{
            .label = "foo",
            .labelDetails = .{
                .detail = "(alpha: u32, beta: []const u8)",
                .description = "void",
            },
            .kind = .Function,
            .detail = "fn (alpha: u32, beta: []const u8) void",
        },
        .{ .label = "alpha", .kind = .Constant, .detail = "u32" },
        .{ .label = "beta", .kind = .Constant, .detail = "[]const u8" },
    });
    try testCompletion(
        \\fn foo(
        \\    comptime T: type,
        \\    value: anytype,
        \\) void {
        \\  <cursor>
        \\}
    , &.{
        .{
            .label = "foo",
            .labelDetails = .{
                .detail = "(comptime T: type, value: anytype)",
                .description = "void",
            },
            .kind = .Function,
            .detail = "fn (comptime T: type, value: anytype) void",
        },
        .{ .label = "T", .kind = .Constant, .detail = "type" },
        .{ .label = "value", .kind = .Constant },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() S { return undefined; }
        \\const bar = foo().<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "function alias" {
    try testCompletion(
        \\fn foo() void {
        \\    <cursor>
        \\}
        \\const bar = foo;
        \\const baz = &foo;
    , &.{
        .{
            .label = "foo",
            .kind = .Function,
            .detail = "fn () void",
        },
        .{
            .label = "bar",
            .kind = .Function,
            .detail = "fn () void",
        },
        .{
            .label = "baz",
            .kind = .Function,
            // TODO detail should be '*fn () void' or '*const fn () void'
            .detail = "fn () void",
        },
    });
    try testCompletion(
        \\const S = struct {
        \\    fn foo() void {}
        \\    const bar = foo;
        \\    const baz = &foo;
        \\};
        \\const _ = S.<cursor>
    , &.{
        .{
            .label = "foo",
            .kind = .Function,
            .detail = "fn () void",
        },
        .{
            .label = "bar",
            .kind = .Function,
            .detail = "fn () void",
        },
        .{
            .label = "baz",
            .kind = .Function,
            // TODO detail should be '*fn () void' or '*const fn () void'
            .detail = "fn () void",
        },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn foo(_: S) void {}
        \\    const bar = foo;
        \\};
        \\const baz = S.bar(.<cursor>);
    , &.{
        .{
            .label = "alpha",
            .kind = .Field,
            .detail = "u32",
        },
    });
}

test "generic function" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn ArrayList(comptime T: type) type {
        \\    return struct { items: []const T };
        \\}
        \\const array_list: ArrayList(S) = undefined;
        \\const foo = array_list.items[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(comptime T: type) T {}
        \\const s = foo(S);
        \\const foo = s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(any: anytype, comptime T: type) T {}
        \\const s = foo(null, S);
        \\const foo = s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn foo(self: S, comptime T: type) T {}
        \\};
        \\const s1: S = undefined;
        \\const s2 = s1.foo(S);
        \\const foo = s2.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "foo", .kind = .Method, .detail = "fn (self: S, comptime T: type) T" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn foo(self: S, any: anytype, comptime T: type) T {}
        \\};
        \\const s1: S = undefined;
        \\const s2 = s1.foo(null, S);
        \\const foo = s2.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "foo", .kind = .Method, .detail = "fn (self: S, any: anytype, comptime T: type) T" },
    });
}

test "nested generic function" {
    try testCompletion(
        \\fn ArrayList(comptime T: type) type {
        \\    return ArrayListAligned(T, null);
        \\}
        \\
        \\fn ArrayListAligned(comptime T: type) type {
        \\    return struct {
        \\        items: []T,
        \\
        \\        const empty: @This() = .{
        \\            .items = &.{},
        \\        };
        \\    };
        \\}
        \\
        \\var list: ArrayList(u8) = .<cursor>;
    , &.{
        .{ .label = "items", .kind = .Field, .detail = "[]u8" },
        .{ .label = "empty", .kind = .Constant, .detail = "ArrayListAligned(u8)" },
    });
}

test "recursive generic function" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn ArrayList(comptime T: type) type {
        \\    return ArrayList(T);
        \\}
        \\const array_list: ArrayList(S) = undefined;
        \\const foo = array_list.<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn ArrayList(comptime T: type) type {
        \\    return ArrayList(T);
        \\}
        \\const foo = ArrayList(S).<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn Foo(comptime T: type) type {
        \\    return Bar(T);
        \\}
        \\fn Bar(comptime T: type) type {
        \\    return Foo(T);
        \\}
        \\const foo: Foo(S) = undefined;
        \\const value = array_list.<cursor>
    , &.{});
}

test "generic function without body" {
    try testCompletion(
        \\const Foo: fn (type) type = undefined;
        \\const Bar = Foo(u32);
        \\const value = Bar.<cursor>;
    , &.{});
}

test "std.ArrayList" {
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const array_list: std.ArrayList(S) = undefined;
        \\const foo = array_list.items[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "std.ArrayHashMap" {
    try testCompletion(
        \\const std = @import("std");
        \\const map: std.StringArrayHashMapUnmanaged(void) = undefined;
        \\const key = map.getKey("");
        \\const foo = key.?.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]const u8" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoArrayHashMapUnmanaged(u32, S) = undefined;
        \\const s = map.get(0);
        \\const foo = s.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoArrayHashMapUnmanaged(u32, S) = undefined;
        \\const gop = try map.getOrPut(undefined, 0);
        \\const foo = gop.value_ptr.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "std.HashMap" {
    try testCompletion(
        \\const std = @import("std");
        \\const map: std.StringHashMapUnmanaged(void) = undefined;
        \\const key = map.getKey("");
        \\const foo = key.?.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]const u8" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoHashMapUnmanaged(u32, S) = undefined;
        \\const s = map.get(0);
        \\const foo = s.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoHashMapUnmanaged(u32, S) = undefined;
        \\const gop = try map.getOrPut(undefined, 0);
        \\const foo = gop.value_ptr.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "function call" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn func() S {}
        \\const foo = func().<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn func() S {}
        \\const foo = func();
        \\const bar = foo.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const func: fn() S = undefined;
        \\const foo = func().<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const func: fn() S = undefined;
        \\const foo = func();
        \\const bar = foo.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const func: *const fn() S = undefined;
        \\const foo = func().<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const func: *const fn() S = undefined;
        \\const foo = func();
        \\const bar = foo.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "chained function call" {
    try testCompletion(
        \\const S1 = struct {
        \\    alpha: u32,
        \\    fn init() S1 {}
        \\    fn foo(_: S1, _: S2) void {}
        \\};
        \\const S2 = struct {
        \\    beta: []const u8,
        \\};
        \\const bar = S1.init().foo(.{.<cursor>});
    , &.{
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
}

test "resolve return type of function with invalid parameter" {
    try testCompletion(
        \\fn Foo(foo: unknown) type {
        \\    _ = foo;
        \\    return struct { alpha: u32 };
        \\}
        \\var foo: Foo() = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "resolve parameters of function with invalid return type" {
    try testCompletion(
        \\fn foo(_: struct { alpha: u32 }) unknown {}
        \\const bar = foo(.<cursor>)
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "optional" {
    try testCompletion(
        \\const foo: ?u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "?", .kind = .Operator, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: ?S = undefined;
        \\const bar = foo.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "optional type" {
    try testCompletion(
        \\const foo = ?u32;
        \\const bar = foo.<cursor>
    , &.{});
}

test "pointer deref" {
    try testCompletion(
        \\const foo: *u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "u32" },
    });
    try testCompletion(
        \\const foo: [*c]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "u32" },
        .{ .label = "?", .kind = .Operator, .detail = "[*c]u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: *S = undefined;
        \\const bar = foo.*.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: *S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: [*c]S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "?", .kind = .Operator, .detail = "[*c]S" },
    });
}

test "pointer array access" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [*]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: []S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [*c]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: []S = undefined;
        \\const bar = foo.ptr[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "pointer subslicing" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: []S = undefined;
        \\const bar = foo[0..].<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]S" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: []S = undefined;
        \\const bar = foo.ptr[0..].<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: [*c]S = undefined;
        \\const bar = foo.ptr[0..].<cursor>
    , &.{});
}

test "pointer subslicing parser correctness" {
    try testCompletion(
        \\const foo: [*]u32 = undefined;
        \\const bar = foo[foo[0]..].<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: []S = undefined;
        \\const bar = foo.ptr[foo[0]..][0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const foo: [*]u32 = undefined;
        \\const bar = foo[foo[0..2]..].<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: [*c]S = undefined;
        \\const bar = foo[foo[0..2]..foo[0..]].<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]S" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: [*c]S = undefined;
        \\const bar = foo[foo[0..2]..foo[0..]][0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "slice pointer" {
    try testCompletion(
        \\const foo: []const u8 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]const u8" },
    });
}

test "many item pointer" {
    try testCompletion(
        \\const foo: [*]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{});
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: []S = undefined;
        \\const bar = foo.ptr.<cursor>
    , &.{});
}

test "address of" {
    try testCompletion(
        \\const value: u32 = undefined;
        \\const value_ptr = &value;
        \\const foo = value_ptr.<cursor>;
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const value: S = undefined;
        \\const value_ptr = &value;
        \\const foo = value_ptr.<cursor>;
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "pointer type" {
    try testCompletion(
        \\const foo = *u32;
        \\const bar = foo.<cursor>
    , &.{});
    try testCompletion(
        \\const foo = [*]u32;
        \\const bar = foo.<cursor>
    , &.{});
    try testCompletion(
        \\const foo = []u32;
        \\const bar = foo.<cursor>
    , &.{});
    try testCompletion(
        \\const foo = [*c]u32;
        \\const bar = foo.<cursor>
    , &.{});
}

test "array" {
    try testCompletion(
        \\const foo: [3]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize = 3" },
    });
    try testCompletion(
        \\const length = 3;
        \\const foo: [length]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize = 3" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [1]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const foo: [3]u32 = undefined;
        \\var index: usize = undefined;
        \\const bar = foo[0..index].<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]u32" },
    });
}

test "single pointer to slice" {
    try testCompletion(
        \\const foo: *[]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "[]u32" },
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]u32" },
    });
}

test "single pointer to array" {
    try testCompletion(
        \\const foo: *[3]u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "[3]u32" },
        .{ .label = "len", .kind = .Field, .detail = "usize = 3" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: *[2]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const foo: *[3]u32 = undefined;
        \\const bar = foo[0..3].<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]u32" },
    });
}

test "array type" {
    try testCompletion(
        \\const foo = [3]u32;
        \\const bar = foo.<cursor>
    , &.{});
}

test "tuple fields" {
    try testCompletion(
        \\fn foo() void {
        \\    var a: f32 = 0;
        \\    var b: i64 = 1;
        \\    const foo = .{ b, a };
        \\    const bar = foo.<cursor>
        \\}
    , &.{
        .{ .label = "@\"0\"", .kind = .Field, .detail = "i64" },
        .{ .label = "@\"1\"", .kind = .Field, .detail = "f32" },
    });
    try testCompletion(
        \\fn foo() void {
        \\    const foo: struct { i64, f32 } = .{ 1, 0 };
        \\    const bar = foo.<cursor>
        \\}
    , &.{
        .{ .label = "@\"0\"", .kind = .Field, .detail = "i64" },
        .{ .label = "@\"1\"", .kind = .Field, .detail = "f32" },
    });
}

test "if/for/while/catch scopes" {
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    if (true) {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    if (true) S.<cursor>
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    if (true) {
        \\    } else {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    for (undefined) |_| {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    for (undefined) |_| {
        \\
        \\    } else {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    while (true) {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    for (undefined) {
        \\
        \\    } else {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { pub const T = u32; };
        \\test {
        \\    error.Foo catch {
        \\        S.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "T", .kind = .Constant, .detail = "u32" },
    });
}

test "if captures" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    if(bar) |baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(maybe_maybe_s: ??S) void {
        \\    if (maybe_maybe_s) |maybe_s| if (maybe_s) |s| {
        \\        s.<cursor>
        \\    };
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    if (bar) |baz| {
        \\        baz.<cursor>
        \\    } else {
        \\        return;
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    // TODO fix value capture without block scope
    // try testCompletion(
    //     \\const S = struct { alpha: u32 };
    //     \\const foo: ?S = undefined;
    //     \\const bar = if(foo) |baz| baz.<cursor>
    // , &.{
    //     .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    // });

    try testCompletion(
        \\const E = error{ X, Y };
        \\const S = struct { alpha: u32 };
        \\fn foo() E!S { return undefined; }
        \\fn bar() void {
        \\    if (foo()) |baz| {
        \\        baz.<cursor>
        \\    } else |err| {
        \\        _ = err;
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "if capture by ref" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    if (bar) |*baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "for captures" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: []S) void {
        \\    for (items, 0..) |bar, i| {
        \\        bar.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: [2]S) void {
        \\    for (items) |bar| {
        \\        bar.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: []S) void {
        \\    for (items, items) |_, baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() void {
        \\    const manyptr: [*]S = undefined;
        \\    for (manyptr[0..10]) |s| {
        \\        s.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() void {
        \\    const optmanyptr: ?[*]S = undefined;
        \\    for (optmanyptr.?[0..10]) |s| {
        \\        s.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "for capture by ref" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: []S) void {
        \\    for (items, 0..) |*bar, i| {
        \\        bar.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "while captures" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    while (bar) |baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const E = error{ X, Y };
        \\const S = struct { alpha: u32 };
        \\fn foo() E!S { return undefined; }
        \\fn bar() void {
        \\    while (foo()) |baz| {
        \\        baz.<cursor>
        \\    } else |err| {
        \\        _ = err;
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "while capture by ref" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    while (bar) |*baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "catch captures" {
    try testCompletion(
        \\const E = error{ X, Y };
        \\const S = struct { alpha: u32 };
        \\fn foo() E!S { return undefined; }
        \\fn bar() void {
        \\    const baz = foo() catch |err| {
        \\        _ = err;
        \\        return;
        \\    };
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "switch capture by ref" {
    try testCompletion(
        \\const U = union { alpha: ?u32 };
        \\fn foo(bar: U) void {
        \\    switch (bar) {
        \\        .alpha => |*a| {
        \\            a.<cursor>
        \\        }
        \\    }
        \\}
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "?u32" },
        .{ .label = "?", .kind = .Operator, .detail = "u32" },
    });
}

test "namespace" {
    try testCompletion(
        \\const namespace = struct {};
        \\const bar = namespace.<cursor>
    , &.{});
    try testCompletion(
        \\const namespace = struct {
        \\    fn alpha() void {}
        \\    fn beta(_: anytype) void {}
        \\    fn gamma(_: @This()) void {}
        \\};
        \\const bar = namespace.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn () void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn (_: anytype) void" },
        .{ .label = "gamma", .kind = .Function, .detail = "fn (_: namespace) void" },
    });
    try testCompletion(
        \\const namespace = struct {
        \\    fn alpha() void {}
        \\    fn beta(_: anytype) void {}
        \\    fn gamma(_: @This()) void {}
        \\};
        \\const instance: namespace = undefined;
        \\const bar = instance.<cursor>
    , &.{
        .{ .label = "beta", .kind = .Function, .detail = "fn (_: anytype) void" },
        .{ .label = "gamma", .kind = .Function, .detail = "fn (_: namespace) void" },
    });
    try testCompletion(
        \\fn alpha() void {}
        \\fn beta(_: anytype) void {}
        \\fn gamma(_: @This()) void {}
        \\
        \\const foo: @This() = undefined;
        \\const bar = foo.<cursor>;
    , &.{
        .{ .label = "beta", .kind = .Function, .detail = "fn (_: anytype) void" },
        .{ .label = "gamma", .kind = .Function, .detail = "fn (_: test-0) void" },
    });
}

test "struct" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .alpha = 0, .beta = "" };
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });

    try testCompletion(
        \\const Foo = struct {
        \\    alpha: u32,
        \\    fn add(foo: Foo) Foo {}
        \\};
        \\test {
        \\    var builder = Foo{};
        \\    builder
        \\        // Comments should
        \\        // get ignored
        \\        .<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "add", .kind = .Method, .detail = "fn (foo: Foo) Foo" },
    });

    try testCompletion(
        \\fn doNothingWithInteger(a: u32) void { _ = a; }
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\    fn foo(self: S) void {
        \\        doNothingWithInteger(self.<cursor>
        \\    }
        \\};
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
        .{ .label = "foo", .kind = .Method, .detail = "fn (self: S) void" },
    });

    try testCompletion(
        \\const S = struct {
        \\    const Mode = enum { alpha, beta, };
        \\    fn foo(mode: <cursor>
        \\};
    , &.{
        .{ .label = "S", .kind = .Struct, .detail = "type" },
        .{ .label = "Mode", .kind = .Enum, .detail = "type" },
    });

    try testCompletion(
        \\fn fooImpl(_: Foo) void {}
        \\fn barImpl(_: *const Foo) void {}
        \\fn bazImpl(_: u32) void {}
        \\const Foo = struct {
        \\    alpha: u32,
        \\    pub const foo = fooImpl;
        \\    pub const bar = barImpl;
        \\    pub const baz = bazImpl;
        \\};
        \\const foo = Foo{};
        \\const baz = foo.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "foo", .kind = .Method, .detail = "fn (_: Foo) void" },
        .{ .label = "bar", .kind = .Method, .detail = "fn (_: *const Foo) void" },
    });
    try testCompletion(
        \\alpha: u32,
        \\
        \\fn alpha() void {}
        \\fn beta(_: anytype) void {}
        \\fn gamma(_: @This()) void {}
        \\
        \\const Self = @This();
        \\const bar = Self.<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn () void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn (_: anytype) void" },
        .{ .label = "gamma", .kind = .Function, .detail = "fn (_: test-0) void" },
        .{ .label = "Self", .kind = .Struct },
        .{ .label = "bar", .kind = .Struct },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo = (S{}).<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
}

test "union" {
    try testCompletion(
        \\const U = union {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: U = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });

    try testCompletion(
        \\const U = union { alpha: ?u32 };
        \\fn foo(bar: U) void {
        \\    switch (bar) {
        \\        .alpha => |a| {
        \\            a.<cursor>
        \\        }
        \\    }
        \\}
    , &.{
        .{ .label = "?", .kind = .Operator, .detail = "u32" },
    });
}

test "enum" {
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\};
        \\const foo = E.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
    });
    try testCompletion(
        \\const E = enum(u8) {
        \\    alpha,
        \\    beta = 42,
        \\    const bar = 5;
        \\};
        \\const foo: E = .<cursor>
    , &.{
        .{ .label = "alpha", .kind = .EnumMember, .detail = "E" },
        .{ .label = "beta", .kind = .EnumMember, .detail = "E = 42" },
    });
    try testCompletion(
        \\const E = enum {
        \\    _,
        \\    const bar = 5;
        \\    fn inner(_: E) void {}
        \\};
        \\const foo = E.<cursor>
    , &.{
        .{ .label = "bar", .kind = .Constant, .detail = "comptime_int" },
        .{ .label = "inner", .kind = .Function, .detail = "fn (_: E) void" },
    });
    try testCompletion(
        \\const E = enum {
        \\    _,
        \\    const bar = 5;
        \\    fn inner(_: E) void {}
        \\};
        \\const e: E = undefined;
        \\const foo = e.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Method, .detail = "fn (_: E) void" },
    });
    // Because current logic is to list all enums if all else fails,
    // the following tests include an extra enum to ensure that we're not just 'getting lucky'
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum(se: SomeEnum) void {
        \\    if (se == .<cursor>) {}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum() SomeEnum {}
        \\test {
        \\    retEnum() == .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    pub fn retEnum() SomeEnum {}
        \\};
        \\test {
        \\    S.retEnum() == .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    pub fn retEnum(self: S) SomeEnum {}
        \\};
        \\test {
        \\    const s = S{};
        \\    s.retEnum() == .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    se: SomeEnum = .sef1,
        \\};
        \\test {
        \\    const s = S{};
        \\    s.se == .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const S = struct {
        \\    mye: enum {
        \\        myef1,
        \\        myef2,
        \\    };
        \\};
        \\test {
        \\    const s = S{};
        \\    s.mye == .<cursor>
        \\}
    , &.{
        .{ .label = "myef1", .kind = .EnumMember },
        .{ .label = "myef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    const Self = @This();
        \\    pub fn f(_: *Self, _: SomeEnum) void {}
        \\};
        \\test {
        \\    S.f(null, .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    alpha: u32,
        \\    const Self = @This();
        \\    pub fn f(_: *Self, _: SomeEnum) void {}
        \\};
        \\test {
        \\    const s = S{};
        \\    s.f(.<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const SCE = struct{
        \\    se: SomeEnum,
        \\};
        \\const S = struct {
        \\    alpha: u32,
        \\    const Self = @This();
        \\    pub fn f(_: *Self, _: SCE) void {}
        \\};
        \\test {
        \\    const s = S{};
        // XXX This doesn't work without the closing brace at the end
        \\    s.f(.{.se = .<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    se: ?SomeEnum = null,
        \\};
        \\test {
        \\    const s = S{};
        \\    s.se = .<cursor>
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
}

test "decl literal" {
    try testCompletion(
        \\const S = struct {
        \\    field: u32,
        \\
        \\    pub const foo: error{OutOfMemory}!S = .{};
        \\    const bar: *const S = &.{};
        \\    var baz: @This() = .{};
        \\    var qux: u32 = .{};
        \\
        \\    fn init() ?S {}
        \\    fn create() !*S {}
        \\    fn func() void {}
        \\};
        \\const s: S = .<cursor>;
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u32" },
        .{ .label = "foo", .kind = .Constant },
        .{ .label = "bar", .kind = .Constant },
        .{ .label = "baz", .kind = .Variable },
        .{ .label = "init", .kind = .Function, .detail = "fn () ?S" },
        .{ .label = "create", .kind = .Function, .detail = "fn () !*S" },
    });
}

test "decl literal function" {
    try testCompletion(
        \\const Inner = struct {
        \\    fn init() Inner {}
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
        \\const foo: Outer = .{
        \\    .inner = .in<cursor>it(),
        \\};
    , &.{
        .{ .label = "init", .kind = .Function, .detail = "fn () Inner" },
    });
    try testCompletion(
        \\fn Empty() type {
        \\    return struct {
        \\        fn init() @This() {}
        \\    };
        \\}
        \\const foo: Empty() = .in<cursor>it();
    , &.{
        .{ .label = "init", .kind = .Function, .detail = "fn () Empty()" },
    });
}

test "decl literal function call" {
    try testCompletion(
        \\const S = struct {
        \\    field: u32,
        \\
        \\    const default: S = .{};
        \\    fn init() S {}
        \\};
        \\fn foo(s: S) void {}
        \\fn bar() void {
        \\    foo(.<cursor>);
        \\}
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u32" },
        .{ .label = "default", .kind = .Constant },
        .{ .label = "init", .kind = .Function, .detail = "fn () S" },
    });
}

test "enum literal" {
    try testCompletion(
        \\const literal = .foo;
        \\const foo = <cursor>
    , &.{
        .{ .label = "literal", .kind = .EnumMember, .detail = "@Type(.enum_literal)" },
    });
}

test "tagged union" {
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const Ue = union(enum) {
        \\    alpha,
        \\    beta: []const u8,
        \\};
        \\const S = struct{ foo: Ue };
        \\test {
        \\    const s = S{};
        \\    s.foo = .<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .Field },
    });
}

test "global enum set" {
    try testCompletion(
        \\const SomeError = error{ e };
        \\const E1 = enum {
        \\    foo,
        \\    bar,
        \\};
        \\const E2 = enum {
        \\    baz,
        \\    ///hello
        \\    qux,
        \\};
        \\const baz = .<cursor>
    , &.{
        .{ .label = "foo", .kind = .EnumMember },
        .{ .label = "bar", .kind = .EnumMember },
        .{ .label = "baz", .kind = .EnumMember },
        .{ .label = "qux", .kind = .EnumMember, .documentation = "hello" },
    });
    try testCompletion(
        \\const SomeError = error{ e };
        \\const Enum1 = enum {
        \\    ///hello world
        \\    foo,
        \\    bar,
        \\};
        \\const Enum2 = enum {
        \\    foo,
        \\    ///hallo welt
        \\    bar,
        \\};
        \\const baz = .<cursor>
    , &.{
        .{ .label = "foo", .kind = .EnumMember, .documentation = "hello world" },
        .{ .label = "bar", .kind = .EnumMember, .documentation = "hallo welt" },
    });
}

test "switch cases" {
    // Because current logic is to list all enums if all else fails,
    // the following tests include an extra enum to ensure that we're not just 'getting lucky'
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum() SomeEnum {}
        \\test {
        \\    switch(retEnum()) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum(se: SomeEnum) void {
        \\    switch(se) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });

    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\    sef3,
        \\    sef4,
        \\};
        \\fn retEnum(se: SomeEnum) void {
        \\    switch(se) {
        \\       .sef1 => {},
        \\       .sef4 => {},
        \\       .<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "sef2", .kind = .EnumMember },
        .{ .label = "sef3", .kind = .EnumMember },
    });

    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\    sef3,
        \\    sef4,
        \\};
        \\fn retEnum(se: SomeEnum) void {
        \\    switch(se) {
        \\       .sef1, .sef4 => {},
        \\       .<cursor>
        \\       .sef3 => {},
        \\    }
        \\}
    , &.{
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum() SomeEnum {}
        \\test {
        \\    var se = retEnum();
        \\    switch(se) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    pub fn retEnum() SomeEnum {}
        \\};
        \\test {
        \\    switch(S.retEnum()) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\const S = struct {
        \\    pub fn retEnum(self: S) SomeEnum {}
        \\};
        \\test {
        \\    const s = S{};
        \\    switch(s.retEnum()) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum() anyerror!SomeEnum {}
        \\test {
        \\    switch (try retEnum()) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\    pub fn retEnum() anyerror!SomeEnum {}
        \\};
        \\test {
        \\    switch (try SomeEnum.retEnum()) {.<cursor>}
        \\}
    , &.{
        .{ .label = "sef1", .kind = .EnumMember },
        .{ .label = "sef2", .kind = .EnumMember },
    });
    try testCompletion(
        \\const Birdie = enum {
        \\    canary,
        \\};
        \\const SomeEnum = enum {
        \\    sef1,
        \\    sef2,
        \\};
        \\fn retEnum() SomeEnum {}
        \\test {
        \\    switch(retEnum()) {
        \\        .sef1 => {const a = 1;},
        \\        .<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "sef2", .kind = .EnumMember },
    });
}

test "error set" {
    try testCompletion(
        \\const E = error {
        \\    foo,
        \\    bar,
        \\};
        \\const baz = E.<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant, .detail = "error.foo" },
        .{ .label = "bar", .kind = .Constant, .detail = "error.bar" },
    });
    try testCompletion(
        \\const E1 = error {
        \\    foo,
        \\    bar,
        \\};
        \\const E2 = error {
        \\    baz,
        \\    ///hello
        \\    qux,
        \\};
        \\const baz = E2.<cursor>
    , &.{
        .{ .label = "baz", .kind = .Constant, .detail = "error.baz" },
        .{ .label = "qux", .kind = .Constant, .detail = "error.qux" },
    });
}

test "global error set" {
    try testCompletion(
        \\const SomeEnum = enum { e };
        \\const Error1 = error {
        \\    foo,
        \\    bar,
        \\};
        \\const Error2 = error {
        \\    baz,
        \\    ///hello
        \\    qux,
        \\};
        \\const baz = error.<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant, .detail = "error.foo" },
        .{ .label = "bar", .kind = .Constant, .detail = "error.bar" },
        .{ .label = "baz", .kind = .Constant, .detail = "error.baz" },
        .{ .label = "qux", .kind = .Constant, .detail = "error.qux", .documentation = "hello" },
    });
    try testCompletion(
        \\const SomeEnum = enum { e };
        \\const Error1 = error {
        \\    ///hello world
        \\    foo,
        \\    bar,
        \\};
        \\const Error2 = error {
        \\    foo,
        \\    ///hallo welt
        \\    bar,
        \\};
        \\const baz = error.<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant, .detail = "error.foo", .documentation = "hello world" },
        .{ .label = "bar", .kind = .Constant, .detail = "error.bar", .documentation = "hallo welt" },
    });
    try testCompletion(
        \\const Error = error {
        \\    ///hello world
        \\    @"some name",
        \\};
        \\const baz = error.<cursor>
    , &.{
        .{ .label = "some name", .kind = .Constant, .detail = "error.@\"some name\"", .documentation = "hello world" },
    });
}

test "merged error sets" {
    try testCompletion(
        \\const FirstSet = error{
        \\    X,
        \\    Y,
        \\};
        \\const SecondSet = error{
        \\    Foo,
        \\    Bar,
        \\} || FirstSet;
        \\const e = error.<cursor>
    , &.{
        .{ .label = "X", .kind = .Constant, .detail = "error.X" },
        .{ .label = "Y", .kind = .Constant, .detail = "error.Y" },
        .{ .label = "Foo", .kind = .Constant, .detail = "error.Foo" },
        .{ .label = "Bar", .kind = .Constant, .detail = "error.Bar" },
    });

    try testCompletion(
        \\const FirstSet = error{
        \\    x,
        \\    y,
        \\};
        \\const SecondSet = error{
        \\    foo,
        \\    bar,
        \\} || FirstSet;
        \\const e = SecondSet.<cursor>
    , &.{
        .{ .label = "x", .kind = .Constant, .detail = "error.x" },
        .{ .label = "y", .kind = .Constant, .detail = "error.y" },
        .{ .label = "foo", .kind = .Constant, .detail = "error.foo" },
        .{ .label = "bar", .kind = .Constant, .detail = "error.bar" },
    });

    try testCompletion(
        \\const Error = error{Foo} || error{Bar};
        \\const E = <cursor>
    , &.{
        .{ .label = "Error", .kind = .Constant, .detail = "error{Foo,Bar}" },
    });
}

test "error union" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() error{Foo}!S {}
        \\fn bar() error{Foo}!void {
        \\    const baz = try foo();
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() !S {}
        \\fn bar() !void {
        \\    const baz = try foo();
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() error{Foo}!S {}
        \\fn bar() error{Foo}!void {
        \\    (try foo()).<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S1 = struct { alpha: u32 };
        \\const S2 = struct {
        \\    pub fn baz(_: S2) !S1 {}
        \\};
        \\fn foo() error{Foo}!S2 {}
        \\fn bar() error{Foo}!void {
        \\    (try (try foo()).baz()).<cursor>;
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() error{Foo}!S {}
        \\fn bar() error{Foo}!void {
        \\    const baz = foo() catch return;
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "structinit" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .<cursor> };
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\    gamma: ?*S,
        \\};
        \\const foo = S{ .alpha = 3, .<cursor>, .gamma = null };
    , &.{
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .alpha = S{ .beta = "{}" }, .<cursor> };
    , &.{
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\};
        \\const foo = S{ .alpha = S{ .<cursor> } };
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
    });
    // Incomplete struct field
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\};
        \\const foo = S{ .alpha = S{ .alp<cursor> } };
    , &.{
        // clients do the filtering
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?*S,
        \\};
        \\const foo = S{ .gamma = undefined, .<cursor> , .alpha = undefined };
    , &.{
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S,
        \\};
        \\const foo = S{ .gamma = .{.<cursor>};
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S = null,
        \\};
        \\test {
        \\    const foo: S = undefined;
        \\    foo.gamma = .{.<cursor>}
        \\}
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S = null" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S = null,
        \\};
        \\test {
        \\    const foo: S = undefined;
        \\    foo.gamma = .<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "gamma", .kind = .Field, .detail = "?S = null" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(s: S) void {}
        \\test {
        \\    foo(.<cursor>)
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(s: *S) void { s = .{.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(s: *S) void { s.* = .{.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() S {}
        \\test { foo(){.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() anyerror!S {}
        \\test { try foo(){.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const nmspc = struct {
        \\    fn foo() anyerror!S {}
        \\};
        \\test { try nmspc.foo(){.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const nmspc = struct {
        \\    fn foo() type {
        \\        return struct {
        \\            alpha: u32,
        \\        };
        \\    }
        \\};
        \\test { nmspc.foo(){.<cursor>} }
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    // Aliases
    try testCompletion(
        \\pub const Outer = struct {
        \\    pub const Inner = struct {
        \\        isf1: bool = true,
        \\        isf2: bool = false,
        \\    };
        \\};
        \\const Alias0 = Outer.Inner;
        \\const Alias = Alias0;
        \\
        \\fn alias() void {
        \\    var s = Alias{.<cursor>};
        \\}
    , &.{
        .{ .label = "isf1", .kind = .Field, .detail = "bool = true" },
        .{ .label = "isf2", .kind = .Field, .detail = "bool = false" },
    });
    // Parser workaround for when used before defined
    try testCompletion(
        \\fn alias() void {
        \\    var s = Alias{1.<cursor>};
        \\}
        \\pub const Outer = struct {
        \\    pub const Inner = struct {
        \\        isf1: bool = true,
        \\        isf2: bool = false,
        \\    };
        \\};
        \\const Alias0 = Outer.Inner;
        \\const Alias = Alias0;
    , &.{
        .{ .label = "isf1", .kind = .Field, .detail = "bool = true" },
        .{ .label = "isf2", .kind = .Field, .detail = "bool = false" },
    });
    // Parser workaround for completing within Self
    try testCompletion(
        \\const MyStruct = struct {
        \\    a: bool,
        \\    b: bool,
        \\    fn inside() void {
        \\        var s = MyStruct{1.<cursor>};
        \\    }
        \\};
    , &.{
        .{ .label = "a", .kind = .Field, .detail = "bool" },
        .{ .label = "b", .kind = .Field, .detail = "bool" },
    });
    try testCompletion(
        \\fn ref(p0: A, p1: B) void {}
        \\const A = struct {
        \\    this_is_a: u32 = 9,
        \\    arefb: B = 8,
        \\};
        \\const B = struct {
        \\    brefa: A,
        \\    this_is_b: []const u8,
        \\};
        \\ref(.{ .arefb = .{ .brefa = .{.<cursor>} } });
    , &.{
        .{ .label = "arefb", .kind = .Field, .detail = "B = 8" },
        .{ .label = "this_is_a", .kind = .Field, .detail = "u32 = 9" },
    });
    try testCompletion(
        \\const MyEnum = enum {
        \\  ef1,
        \\  ef2,
        \\};
        \\const S1 = struct { s1f1: u8, s1f2: u32 = 1, ref3: S3 = undefined };
        \\const S2 = struct { s2f1: u8, s2f2: u32 = 1, ref1: S1, mye: MyEnum = .ef1};
        \\const S3 = struct {
        \\  s3f1: u8,
        \\  s3f2: u32 = 1,
        \\  ref2: S2,
        \\  pub fn s3(p0: S1, p1: S2) void {}
        \\};
        \\const refs = S3{ .ref2 = .{ .ref1 = .{ .ref3 = .{ .ref2 = .{ .ref1 = .{.<cursor>} } } } } };
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "S3 = undefined" },
    });
    // Method of T requiring explicit self param
    try testCompletion(
        \\const MyEnum = enum {
        \\  ef1,
        \\  ef2,
        \\};
        \\const S1 = struct { s1f1: u8, s1f2: u32 = 1, ref3: S3 = undefined };
        \\const S2 = struct { s2f1: u8, s2f2: u32 = 1, ref1: S1, mye: MyEnum = .ef1};
        \\const S3 = struct {
        \\  s3f1: u8,
        \\  s3f2: u32 = 1,
        \\  ref2: S2,
        \\  const Self = @This();
        \\  pub fn s3(self: *Self, p0: S1, p1: S2) void {}
        \\};
        \\S3.s3(null, .{ .mye = .{} }, .{ .ref1 = .{ .ref3 = .{ .ref2 = .{ .ref1 = .{.<cursor>} } } } });
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "S3 = undefined" },
    });
    // Instance of T w/ self param + multitype (`switch`)
    try testCompletion(
        \\const MyEnum = enum {
        \\  ef1,
        \\  ef2,
        \\};
        \\const es = switch (1) {
        \\    1 => S1,
        \\    2 => S2,
        \\    3 => S3,
        \\};
        \\const S1 = struct { s1f1: u8, s1f2: u32 = 1, ref3: S3 = undefined };
        \\const S2 = struct { s2f1: u8, s2f2: u32 = 1, ref1: S1, mye: MyEnum = .ef1};
        \\const S3 = struct {
        \\  s3f1: u8,
        \\  s3f2: u32 = 1,
        \\  ref2: S2,
        \\  const Self = @This();
        \\  pub fn s3(self: Self, p0: es, p1: S1) void {}
        \\};
        \\const iofs3 = S3{};
        \\iofs3.s3(.{.<cursor>});
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "S3 = undefined" },
        .{ .label = "s2f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s2f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref1", .kind = .Field, .detail = "S1" },
        .{ .label = "s3f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s3f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref2", .kind = .Field, .detail = "S2" },
        .{ .label = "mye", .kind = .Field, .detail = "MyEnum = .ef1" },
    });
    try testCompletion(
        \\const MyEnum = enum {
        \\  ef1,
        \\  ef2,
        \\};
        \\const oes = struct {
        \\  const es = if (true) S1 else S2;
        \\};
        \\const S1 = struct { s1f1: u8, s1f2: u32 = 1, ref3: S3 = undefined };
        \\const S2 = struct { s2f1: u8, s2f2: u32 = 1, ref1: S1, mye: MyEnum = .ef1};
        \\const oesi: oes.es = .{ .<cursor>};
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "S3 = undefined" },
        .{ .label = "s2f1", .kind = .Field, .detail = "u8" },
        .{ .label = "s2f2", .kind = .Field, .detail = "u32 = 1" },
        .{ .label = "ref1", .kind = .Field, .detail = "S1" },
        .{ .label = "mye", .kind = .Field, .detail = "MyEnum = .ef1" },
    });
}

test "return - enum" {
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\};
        \\fn foo() E {
        \\    return .<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
    });
}

test "return - decl literal" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\
        \\    const default: S = .{};
        \\    fn init() S {}
        \\};
        \\fn foo() S {
        \\    return .<cursor>;
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
        .{ .label = "init", .kind = .Function, .detail = "fn () S" },
        .{ .label = "default", .kind = .Constant },
    });
}

test "return - generic decl literal" {
    try testCompletion(
        \\fn S(T: type) type {
        \\    return struct {
        \\        alpha: T,
        \\        beta: []const u8,
        \\
        \\        const default: @This() = .{};
        \\        fn init() @This() {}
        \\    };
        \\}
        \\fn foo() S(u8) {
        \\    return .<cursor>;
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u8" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
        .{ .label = "init", .kind = .Function, .detail = "fn () S(u8)" },
        .{ .label = "default", .kind = .Constant, .detail = "S(u8)" },
    });
}

test "return - structinit" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\fn foo() S {
        \\    return .{ .<cursor> }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S,
        \\};
        \\fn foo() S {
        \\    return .{ .gamma = .{ .<cursor> }
        \\}
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
    });
}

test "return - structinit decl literal" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S,
        \\
        \\    const default: S = .{};
        \\    fn init() S {}
        \\};
        \\fn foo() S {
        \\    return .{ .gamma = .<cursor> }
        \\}
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
        .{ .label = "init", .kind = .Function, .detail = "fn () S" },
        .{ .label = "default", .kind = .Constant },
    });
}

test "break - enum/decl literal" {
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\
        \\    const default: E = .alpha;
        \\    fn init() E {}
        \\};
        \\const foo: E = while (true) {
        \\    break .<cursor>
        \\};
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
        .{ .label = "init", .kind = .Function, .detail = "fn () E" },
        .{ .label = "default", .kind = .EnumMember },
    });
}

test "break - structinit" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: S = while (true) {
        \\    break .{ .<cursor> }
        \\};
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S,
        \\};
        \\const foo: S = while (true) {
        \\    break .{ .gamma = .{ .<cursor> }
        \\};
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
    });
}

test "break with label - enum/decl literal" {
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\
        \\    const default: E = .alpha;
        \\    fn init() E {}
        \\};
        \\const foo: E = blk: {
        \\    break :blk .<cursor>
        \\};
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
        .{ .label = "init", .kind = .Function, .detail = "fn () E" },
        .{ .label = "default", .kind = .EnumMember },
    });
}

test "break with label - structinit" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: S = blk: {
        \\    break :blk .{ .<cursor> }
        \\};
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?S,
        \\};
        \\const foo: S = blk: {
        \\    break :blk .{ .gamma = .{ .<cursor> }
        \\};
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
    });
}

test "continue with label - enum/decl literal" {
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\
        \\    const default: E = .alpha;
        \\    fn init() E {}
        \\};
        \\const foo: E = .alpha;
        \\const bar = blk: switch (foo) {
        \\    .alpha => continue :blk .<cursor>,
        \\};
    , &.{
        // TODO this should have the following completion items
        // .{ .label = "alpha", .kind = .EnumMember },
        // .{ .label = "beta", .kind = .EnumMember },
        // .{ .label = "init", .kind = .Function, .detail = "fn () E" },
        // .{ .label = "default", .kind = .EnumMember },
    });
    try testCompletion(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\
        \\    const default: E = .alpha;
        \\    fn init() E {}
        \\};
        \\const foo: E = .alpha;
        \\const bar = blk: switch (foo) {
        \\    .alpha => {
        \\        continue :blk .<cursor>
        \\    },
        \\};
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
        .{ .label = "init", .kind = .Function, .detail = "fn () E" },
        .{ .label = "default", .kind = .EnumMember },
    });
}

test "continue with label - structinit" {
    try testCompletion(
        \\const U = union(enum) {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: U = .{};
        \\const bar = blk: switch (foo) {
        \\    .alpha => continue :blk .{ .<cursor> }
        \\};
    , &.{
        // TODO this should have the following completion items
        // .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        // .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const U = union(enum) {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: U = .{};
        \\const bar = blk: switch (foo) {
        \\    .alpha => {
        \\        continue :blk .{ .<cursor> }
        \\    },
        \\};
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
    });
    try testCompletion(
        \\const U = union(enum) {
        \\    alpha: *const U,
        \\    beta: u32,
        \\    gamma: ?U,
        \\};
        \\const foo: U = .{};
        \\const bar = blk: switch (foo) {
        \\    .alpha => continue :blk .{ .gamma = .{ .<cursor> }
        \\};
    , &.{
        // TODO this should have the following completion items
        // .{ .label = "gamma", .kind = .Field, .detail = "?U" },
        // .{ .label = "beta", .kind = .Field, .detail = "u32" },
        // .{ .label = "alpha", .kind = .Field, .detail = "*const U" },
    });
    try testCompletion(
        \\const U = union(enum) {
        \\    alpha: *const U,
        \\    beta: u32,
        \\    gamma: ?U,
        \\};
        \\const foo: U = .{};
        \\const bar = blk: switch (foo) {
        \\    .alpha => {
        \\        continue :blk .{ .gamma = .{ .<cursor> }
        \\    },
        \\};
    , &.{
        .{ .label = "gamma", .kind = .Field, .detail = "?U" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Field, .detail = "*const U" },
    });
}

test "deprecated " {
    // removed symbols from the standard library are ofted marked with a compile error
    try testCompletion(
        \\const foo = @compileError("Deprecated; some message");
        \\const bar = <cursor>
    , &.{
        .{
            .label = "foo",
            .kind = .Constant,
            .documentation = "Deprecated; some message",
            .deprecated = true,
        },
    });
}

test "declarations" {
    try testCompletion(
        \\const S = struct {
        \\    pub const Public = u32;
        \\    const Private = u32;
        \\};
        \\const foo = S.<cursor>
    , &.{
        .{ .label = "Public", .kind = .Constant, .detail = "u32" },
        .{ .label = "Private", .kind = .Constant, .detail = "u32" },
    });
    try testCompletion(
        \\const S: type = struct {
        \\    pub const Public = u32;
        \\    const Private: type = u32;
        \\};
        \\const foo = S.<cursor>
    , &.{
        .{ .label = "Public", .kind = .Constant, .detail = "u32" },
        .{ .label = "Private", .kind = .Constant, .detail = "u32" },
    });

    try testCompletion(
        \\const S = struct {
        \\    pub fn public(self: S) S {}
        \\    fn private(self: S) !void {}
        \\};
        \\const foo: S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn (self: S) S" },
        .{ .label = "private", .kind = .Function, .detail = "fn (self: S) !void" },
    });
}

test "declarations - meta type" {
    try testCompletion(
        \\const S: type = struct {
        \\    pub fn public() S {}
        \\    fn private() !void {}
        \\};
        \\const foo = S.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn () S" },
        .{ .label = "private", .kind = .Function, .detail = "fn () !void" },
    });
}

test "generic method - @This() parameter" {
    try testCompletion(
        \\fn Foo(T: type) type {
        \\    return struct {
        \\        field: T,
        \\        fn bar(self: @This()) void {
        \\            _ = self;
        \\        }
        \\    };
        \\}
        \\const foo: Foo(u8) = .{};
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u8" },
        .{ .label = "bar", .kind = .Method, .detail = "fn (self: Foo(u8)) void" },
    });
}

test "generic method - Self parameter" {
    try testCompletion(
        \\fn Foo(T: type) type {
        \\    return struct {
        \\        field: T,
        \\        const Self = @This();
        \\        fn bar(self: Self) void {
        \\            _ = self;
        \\        }
        \\    };
        \\}
        \\const foo: Foo(u8) = .{};
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u8" },
        .{ .label = "bar", .kind = .Method, .detail = "fn (self: Foo(u8)) void" },
    });
}

test "generic method - recursive self parameter" {
    try testCompletion(
        \\fn Foo(T: type) type {
        \\    return struct {
        \\        field: T,
        \\        fn bar(self: Foo(T)) void {
        \\            _ = self;
        \\        }
        \\    };
        \\}
        \\const foo: Foo(u8) = .{};
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u8" },
        .{ .label = "bar", .kind = .Method, .detail = "fn (self: Foo(u8)) void" },
    });
}

test "function taking a generic struct arg" {
    try testCompletion(
        \\fn Foo(T: type) type {
        \\    return struct {
        \\        field: T,
        \\    };
        \\}
        \\fn foo(_: Foo(u8)) void {}
        \\const bar = foo(.{.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u8" },
    });
}

test "anytype resolution based on callsite-references" {
    try testCompletion(
        \\const Writer1 = struct {
        \\    fn write1(self: Writer1) void {}
        \\    fn writeAll1(self: Writer1) void {}
        \\};
        \\const Writer2 = struct {
        \\    fn write2(self: Writer2) void {}
        \\    fn writeAll2(self: Writer2) void {}
        \\};
        \\fn caller(a: Writer1, b: Writer2) void {
        \\    callee(a);
        \\    callee(b);
        \\}
        \\fn callee(writer: anytype) void {
        \\    writer.<cursor>
        \\}
    , &.{
        .{ .label = "write1", .kind = .Function, .detail = "fn (self: Writer1) void" },
        .{ .label = "write2", .kind = .Function, .detail = "fn (self: Writer2) void" },
        .{ .label = "writeAll1", .kind = .Function, .detail = "fn (self: Writer1) void" },
        .{ .label = "writeAll2", .kind = .Function, .detail = "fn (self: Writer2) void" },
    });
    try testCompletion(
        \\const Writer1 = struct {
        \\    fn write1(self: Writer1) void {}
        \\    fn writeAll1(self: Writer1) void {}
        \\};
        \\const Writer2 = struct {
        \\    fn write2(self: Writer2) void {}
        \\    fn writeAll2(self: Writer2) void {}
        \\};
        \\fn caller(a: Writer1, b: Writer2) void {
        \\    callee(a);
        \\    // callee(b);
        \\}
        \\fn callee(writer: anytype) void {
        \\    writer.<cursor>
        \\}
    , &.{
        .{ .label = "write1", .kind = .Function, .detail = "fn (self: Writer1) void" },
        .{ .label = "writeAll1", .kind = .Function, .detail = "fn (self: Writer1) void" },
    });
}

test "@field" {
    try testCompletion(
        \\pub const chip_mod = struct {
        \\    pub const devices = struct {
        \\        pub const chip1 = struct {
        \\            pub const peripherals = struct {};
        \\        };
        \\    };
        \\};
        \\test {
        \\    const chip = @field(chip_mod.devices, "chip1");
        \\    chip.<cursor>
        \\}
    , &.{
        .{ .label = "peripherals", .kind = .Struct, .detail = "type" },
    });
}

test "@FieldType" {
    try testCompletion(
        \\test {
        \\    const Foo = struct {
        \\        alpha: u32,
        \\    };
        \\    const Bar = struct {
        \\        beta: Foo,
        \\    };
        \\    const foo: @FieldType(Bar, "beta") = undefined;
        \\    foo.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "@extern" {
    try testCompletion(
        \\test {
        \\    const S = struct {
        \\        alpha: u32,
        \\    };
        \\    const foo = @extern(*S, .{});
        \\    foo.<cursor>
        \\}
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "builtin fns return type" {
    try testCompletion(
        \\pub const chip_mod = struct {
        \\    pub const devices = struct {
        \\        pub const chip1 = struct {
        \\            pub const peripherals = struct {};
        \\        };
        \\    };
        \\};
        \\test {
        \\    const chip_name = "chip1";
        \\    const chip = @field(chip_mod.devices, chip_name);
        \\    chip.<cursor>
        \\}
    , &.{
        .{ .label = "peripherals", .kind = .Struct, .detail = "type" },
    });
    try testCompletion(
        \\pub const chip_mod = struct {
        \\    pub const devices = struct {
        \\        pub const @"chip-1" = struct {
        \\            pub const peripherals = struct {};
        \\        };
        \\    };
        \\};
        \\test {
        \\    const chips = struct {
        \\          pub const chip_name: []const u8 = "chip-1";
        \\      };
        \\    const chip = @field(chip_mod.devices, chips.chip_name);
        \\    chip.<cursor>
        \\}
    , &.{
        .{ .label = "peripherals", .kind = .Struct, .detail = "type" },
    });
    try testCompletion(
        \\test {
        \\    const src = @src();
        \\    src.<cursor>
        \\}
    , &.{
        .{ .label = "module", .kind = .Field, .detail = "[:0]const u8" },
        .{ .label = "file", .kind = .Field, .detail = "[:0]const u8" },
        .{ .label = "fn_name", .kind = .Field, .detail = "[:0]const u8" },
        .{ .label = "line", .kind = .Field, .detail = "u32" },
        .{ .label = "column", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\test {
        \\    const ti = @typeInfo().<cursor>;
        \\}
    , &.{
        .{ .label = "type", .kind = .Field, .detail = "void" },
        .{ .label = "void", .kind = .Field, .detail = "void" },
        .{ .label = "bool", .kind = .Field, .detail = "void" },
        .{ .label = "noreturn", .kind = .Field, .detail = "void" },
        .{ .label = "int", .kind = .Field, .detail = "Int" },
        .{ .label = "float", .kind = .Field, .detail = "Float" },
        .{ .label = "pointer", .kind = .Field, .detail = "Pointer" },
        .{ .label = "array", .kind = .Field, .detail = "Array" },
        .{ .label = "@\"struct\"", .kind = .Field, .detail = "Struct" },
        .{ .label = "comptime_float", .kind = .Field, .detail = "void" },
        .{ .label = "comptime_int", .kind = .Field, .detail = "void" },
        .{ .label = "undefined", .kind = .Field, .detail = "void" },
        .{ .label = "null", .kind = .Field, .detail = "void" },
        .{ .label = "optional", .kind = .Field, .detail = "Optional" },
        .{ .label = "error_union", .kind = .Field, .detail = "ErrorUnion" },
        .{ .label = "error_set", .kind = .Field, .detail = "?[]const Error" },
        .{ .label = "@\"enum\"", .kind = .Field, .detail = "Enum" },
        .{ .label = "@\"union\"", .kind = .Field, .detail = "Union" },
        .{ .label = "@\"fn\"", .kind = .Field, .detail = "Fn" },
        .{ .label = "@\"opaque\"", .kind = .Field, .detail = "Opaque" },
        .{ .label = "frame", .kind = .Field, .detail = "Frame" },
        .{ .label = "@\"anyframe\"", .kind = .Field, .detail = "AnyFrame" },
        .{ .label = "vector", .kind = .Field, .detail = "Vector" },
        .{ .label = "enum_literal", .kind = .Field, .detail = "void" },
    });
}

test "builtin fns taking an enum arg" {
    try testCompletion(
        \\test {
        \\    @Type(.{.<cursor>
        \\}
    , &.{
        .{ .label = "type", .kind = .Field, .detail = "void" },
        .{ .label = "void", .kind = .Field, .detail = "void" },
        .{ .label = "bool", .kind = .Field, .detail = "void" },
        .{ .label = "noreturn", .kind = .Field, .detail = "void" },
        .{ .label = "int", .kind = .Field, .detail = "Int" },
        .{ .label = "float", .kind = .Field, .detail = "Float" },
        .{ .label = "pointer", .kind = .Field, .detail = "Pointer" },
        .{ .label = "array", .kind = .Field, .detail = "Array" },
        .{ .label = "@\"struct\"", .kind = .Field, .detail = "Struct" },
        .{ .label = "comptime_float", .kind = .Field, .detail = "void" },
        .{ .label = "comptime_int", .kind = .Field, .detail = "void" },
        .{ .label = "undefined", .kind = .Field, .detail = "void" },
        .{ .label = "null", .kind = .Field, .detail = "void" },
        .{ .label = "optional", .kind = .Field, .detail = "Optional" },
        .{ .label = "error_union", .kind = .Field, .detail = "ErrorUnion" },
        .{ .label = "error_set", .kind = .Field, .detail = "?[]const Error" },
        .{ .label = "@\"enum\"", .kind = .Field, .detail = "Enum" },
        .{ .label = "@\"union\"", .kind = .Field, .detail = "Union" },
        .{ .label = "@\"fn\"", .kind = .Field, .detail = "Fn" },
        .{ .label = "@\"opaque\"", .kind = .Field, .detail = "Opaque" },
        .{ .label = "frame", .kind = .Field, .detail = "Frame" },
        .{ .label = "@\"anyframe\"", .kind = .Field, .detail = "AnyFrame" },
        .{ .label = "vector", .kind = .Field, .detail = "Vector" },
        .{ .label = "enum_literal", .kind = .Field, .detail = "void" },
    });
    try testCompletion(
        \\test {
        \\    @Type(.{.@"struct" = .{.<cursor>
        \\}
    , &.{
        .{ .label = "layout", .kind = .Field, .detail = "ContainerLayout" },
        .{ .label = "backing_integer", .kind = .Field, .detail = "?type = null" },
        .{ .label = "fields", .kind = .Field, .detail = "[]const StructField" },
        .{ .label = "decls", .kind = .Field, .detail = "[]const Declaration" },
        .{ .label = "is_tuple", .kind = .Field, .detail = "bool" },
    });
    try testCompletion(
        \\test {
        \\    @setFloatMode(.<cursor>)
        \\}
    , &.{
        .{ .label = "strict", .kind = .EnumMember },
        .{ .label = "optimized", .kind = .EnumMember },
    });
    try testCompletion(
        \\test {
        \\    @prefetch(, .{.<cursor>})
        \\}
    , &.{
        .{ .label = "rw", .kind = .Field, .detail = "Rw = .read" },
        .{ .label = "locality", .kind = .Field, .detail = "u2 = 3" },
        .{ .label = "cache", .kind = .Field, .detail = "Cache = .data" },
    });
    try testCompletion(
        \\test {
        \\    @reduce(.<cursor>
        \\}
    , &.{
        .{ .label = "And", .kind = .EnumMember },
        .{ .label = "Or", .kind = .EnumMember },
        .{ .label = "Xor", .kind = .EnumMember },
        .{ .label = "Min", .kind = .EnumMember },
        .{ .label = "Max", .kind = .EnumMember },
        .{ .label = "Add", .kind = .EnumMember },
        .{ .label = "Mul", .kind = .EnumMember },
    });
    try testCompletionTextEdit(.{
        .source = "comptime { @export(foo ,.<cursor>",
        .label = "name",
        .expected_insert_line = "comptime { @export(foo ,.{ .name = ",
        .expected_replace_line = "comptime { @export(foo ,.{ .name = ",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @extern(T , .<cursor>",
        .label = "is_thread_local",
        .expected_insert_line = "test { @extern(T , .{ .is_thread_local = ",
        .expected_replace_line = "test { @extern(T , .{ .is_thread_local = ",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @cmpxchgWeak(1,2,3,4, .<cursor>",
        .label = "acq_rel",
        .expected_insert_line = "test { @cmpxchgWeak(1,2,3,4, .acq_rel",
        .expected_replace_line = "test { @cmpxchgWeak(1,2,3,4, .acq_rel",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @cmpxchgStrong(1,2,3,4,5,.<cursor>",
        .label = "acq_rel",
        .expected_insert_line = "test { @cmpxchgStrong(1,2,3,4,5,.acq_rel",
        .expected_replace_line = "test { @cmpxchgStrong(1,2,3,4,5,.acq_rel",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @atomicLoad(1,2,.<cursor>",
        .label = "acq_rel",
        .expected_insert_line = "test { @atomicLoad(1,2,.acq_rel",
        .expected_replace_line = "test { @atomicLoad(1,2,.acq_rel",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @atomicStore(1,2,3,.<cursor>",
        .label = "acq_rel",
        .expected_insert_line = "test { @atomicStore(1,2,3,.acq_rel",
        .expected_replace_line = "test { @atomicStore(1,2,3,.acq_rel",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @atomicRmw(1,2,.<cursor>",
        .label = "Add",
        .expected_insert_line = "test { @atomicRmw(1,2,.Add",
        .expected_replace_line = "test { @atomicRmw(1,2,.Add",
        .enable_snippets = false,
    });
    try testCompletionTextEdit(.{
        .source = "test { @atomicRmw(1,2,3,4,.<cursor>",
        .label = "acq_rel",
        .expected_insert_line = "test { @atomicRmw(1,2,3,4,.acq_rel",
        .expected_replace_line = "test { @atomicRmw(1,2,3,4,.acq_rel",
        .enable_snippets = false,
    });
    try testCompletion(
        \\test {
        \\    @call(.<cursor>
        \\}
    , &.{
        .{ .label = "auto", .kind = .EnumMember },
        .{ .label = "never_tail", .kind = .EnumMember },
        .{ .label = "never_inline", .kind = .EnumMember },
        .{ .label = "always_tail", .kind = .EnumMember },
        .{ .label = "always_inline", .kind = .EnumMember },
        .{ .label = "compile_time", .kind = .EnumMember },
        .{ .label = "no_suspend", .kind = .EnumMember },
    });
    try testCompletionTextEdit(.{
        .source = "var a: u16 addrspace(.<cursor>",
        .label = "constant",
        .expected_insert_line = "var a: u16 addrspace(.constant",
        .expected_replace_line = "var a: u16 addrspace(.constant",
    });
    try testCompletionTextEdit(.{
        .source = "fn foo() callconv(.<cursor>",
        .label = "arm_aapcs",
        .expected_insert_line = "fn foo() callconv(.{ .arm_aapcs = ",
        .expected_replace_line = "fn foo() callconv(.{ .arm_aapcs = ",
    });
}

test "label" {
    try testCompletion(
        \\const foo = blk: {
        \\    break :<cursor>
        \\};
    , &.{
        .{ .label = "blk", .kind = .Text }, // idk what kind this should be
    });
    // TODO: the AST for this only contains the comptime block so the label isn't completed
    // try testCompletion(
    //     \\comptime {
    //     \\    sw: switch (0) {
    //     \\        else => break :<cursor>,
    //     \\    }
    //     \\}
    // , &.{
    //     .{ .label = "sw", .kind = .Text },
    // });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: S = undefined;
        \\const bar = blk: {
        \\    break :blk foo;
        \\};
        \\const baz = bar.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "either" {
    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha(_: @This()) void {}
        \\};
        \\const Beta = struct {
        \\    field: u32,
        \\    fn beta(_: @This()) void {}
        \\};
        \\const foo: if (undefined) Alpha else Beta = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Function, .detail = "fn (_: Alpha) void" },
        .{ .label = "beta", .kind = .Method, .detail = "fn (_: Beta) void" },
    });
    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha(_: @This()) void {}
        \\};
        \\const Beta = struct {
        \\    field: u32,
        \\    fn beta(_: @This()) void {}
        \\};
        \\const alpha: Alpha = undefined;
        \\const beta: Beta = undefined;
        \\const gamma = if (undefined) alpha else beta;
        \\const foo = gamma.<cursor>
    , &.{
        .{ .label = "field", .kind = .Field, .detail = "u32" },
        .{ .label = "alpha", .kind = .Function, .detail = "fn (_: Alpha) void" },
        .{ .label = "beta", .kind = .Method, .detail = "fn (_: Beta) void" },
    });

    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha(_: @This()) void {}
        \\};
        \\const Beta = struct {
        \\    fn beta(_: @This()) void {}
        \\};
        \\const T = if (undefined) Alpha else Beta;
        \\const bar = T.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn (_: Alpha) void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn (_: Beta) void" },
    });
}

test "container type inside switch case value" {
    try testCompletion(
        \\test {
        \\    switch (undefined) {
        \\        struct {
        \\            const This = @This();
        \\            fn func() void {
        \\                This.<cursor>
        \\            }
        \\        } => {},
        \\    }
        \\}
    , &.{
        .{ .label = "This", .kind = .Struct, .detail = "type" },
        .{ .label = "func", .kind = .Function, .detail = "fn () void" },
    });
}

// https://github.com/zigtools/zls/issues/1370
test "cyclic struct init field" {
    try testCompletion(
        \\_ = .{} .foo = .{ .<cursor>foo
    , &.{});
}

test "integer overflow in struct init field without lhs" {
    try testCompletion(
        \\= .{ .<cursor>foo
    , &.{});
}

test "integer overflow in dot completions at beginning of file" {
    try testCompletion(
        \\.<cursor>
    , &.{});
}

test "enum completion on out of bound parameter index" {
    try testCompletion(
        \\fn foo() void {}
        \\const foo = foo(,.<cursor>);
    , &.{});
}

test "enum completion on out of bound token index" {
    try testCompletion(
        \\ = 1.<cursor>
    , &.{});
}

test "combine doc comments of declaration and definition" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletion(
        \\const foo = struct {
        \\    /// A
        \\    const bar = fizz.buzz;
        \\};
        \\const fizz = struct {
        \\    /// B
        \\    const buzz = struct {};
        \\};
        \\test {
        \\    foo.<cursor>
        \\}
    , &.{
        .{
            .label = "bar",
            .kind = .Struct,
            .detail = "struct",
            .documentation =
            \\ A
            \\
            \\ B
            ,
        },
    });
}

test "top-level doc comment" {
    try testCompletion(
        \\//! B
        \\
        \\/// A
        \\const Foo = @This();
        \\
        \\const Bar = <cursor>
    , &.{
        .{
            .label = "Foo",
            .kind = .Struct,
            .detail = "type",
            .documentation =
            \\A
            \\
            \\B
            ,
        },
    });
}

test "filesystem" {
    if (@import("builtin").target.cpu.arch.isWasm()) return error.SkipZigTest;

    try testCompletion(
        \\const foo = @import("<cursor>");
    , &.{
        .{
            .label = "std",
            .kind = .Module,
        },
        .{
            .label = "builtin",
            .kind = .Module,
        },
    });
}

test "filesystem string literal ends with non ASCII symbol" {
    if (@import("builtin").target.cpu.arch.isWasm()) return error.SkipZigTest;

    try testCompletion(
        \\const foo = @import("<cursor> 🠁
    , &.{
        .{
            .label = "std",
            .kind = .Module,
        },
        .{
            .label = "builtin",
            .kind = .Module,
        },
    });
}

test "label details disabled" {
    try testCompletionWithOptions(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{
            .label = "f",
            .labelDetails = .{
                .detail = "()",
                .description = "void",
            },
            .kind = .Method,
            .detail = "fn (self: S) void",
        },
    }, .{
        .completion_label_details = false,
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S, value: u32) !void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{
            .label = "f",
            .labelDetails = .{
                .detail = "(...)",
                .description = "!void",
            },
            .kind = .Method,
            .detail = "fn (self: S, value: u32) !void",
        },
    }, .{
        .completion_label_details = false,
    });
}

test "insert replace behaviour - keyword" {
    try testCompletionTextEdit(.{
        .source = "const foo = <cursor>@abs(5);",
        .label = "comptime",
        .expected_insert_line = "const foo = comptime@abs(5);",
        .expected_replace_line = "const foo = comptime@abs(5);",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = <cursor>comptime;",
        .label = "comptime_float",
        .expected_insert_line = "const foo = comptime_floatcomptime;",
        .expected_replace_line = "const foo = comptime_float;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = <cursor>comptime;",
        .label = "comptime_float",
        .expected_insert_line = "const foo = comptime_floatcomptime;",
        .expected_replace_line = "const foo = comptime_float;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = comp<cursor>;",
        .label = "comptime",
        .expected_insert_line = "const foo = comptime;",
        .expected_replace_line = "const foo = comptime;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = comp<cursor>time;",
        .label = "comptime",
        .expected_insert_line = "const foo = comptimetime;",
        .expected_replace_line = "const foo = comptime;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = comptime<cursor>;",
        .label = "comptime",
        .expected_insert_line = "const foo = comptime;",
        .expected_replace_line = "const foo = comptime;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = comptime<cursor>;",
        .label = "comptime_float",
        .expected_insert_line = "const foo = comptime_float;",
        .expected_replace_line = "const foo = comptime_float;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = comptime <cursor>;",
        .label = "comptime_float",
        .expected_insert_line = "const foo = comptime comptime_float;",
        .expected_replace_line = "const foo = comptime comptime_float;",
    });
}

test "insert replace behaviour - builtin" {
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@abs",
        .expected_insert_line = "const foo = @abs;",
        .expected_replace_line = "const foo = @abs;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @a<cursor>;",
        .label = "@abs",
        .expected_insert_line = "const foo = @abs;",
        .expected_replace_line = "const foo = @abs;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>abs;",
        .label = "@abs",
        .expected_insert_line = "const foo = @absabs;",
        .expected_replace_line = "const foo = @abs;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @a<cursor>bs;",
        .label = "@abs",
        .expected_insert_line = "const foo = @absbs;",
        .expected_replace_line = "const foo = @abs;",
    });

    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(5);",
        .label = "@abs",
        .expected_insert_line = "const foo = @abs(5);",
        .expected_replace_line = "const foo = @abs(5);",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @a<cursor>(5);",
        .label = "@abs",
        .expected_insert_line = "const foo = @abs(5);",
        .expected_replace_line = "const foo = @abs(5);",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>abs(5);",
        .label = "@abs",
        .expected_insert_line = "const foo = @absabs(5);",
        .expected_replace_line = "const foo = @abs(5);",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @a<cursor>bs(5);",
        .label = "@abs",
        .expected_insert_line = "const foo = @absbs(5);",
        .expected_replace_line = "const foo = @abs(5);",
    });
}

test "insert replace behaviour - builtin with no parameters" {
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@src",
        .expected_insert_line = "const foo = @src;",
        .expected_replace_line = "const foo = @src;",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>();",
        .label = "@src",
        .expected_insert_line = "const foo = @src();",
        .expected_replace_line = "const foo = @src();",
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(5);",
        .label = "@src",
        .expected_insert_line = "const foo = @src(5);",
        .expected_replace_line = "const foo = @src(5);",
    });
}

test "insert replace behaviour - builtin with snippets" {
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@as",
        .expected_insert_line = "const foo = @as(${1:comptime T: type}, ${2:expression});",
        .expected_replace_line = "const foo = @as(${1:comptime T: type}, ${2:expression});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(;",
        .label = "@as",
        .expected_insert_line = "const foo = @as(;",
        .expected_replace_line = "const foo = @as(;",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>();",
        .label = "@as",
        .expected_insert_line = "const foo = @as(${1:comptime T: type}, ${2:expression});",
        .expected_replace_line = "const foo = @as(${1:comptime T: type}, ${2:expression});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@src",
        .expected_insert_line = "const foo = @src();",
        .expected_replace_line = "const foo = @src();",
        .enable_snippets = true,
        .enable_argument_placeholders = false,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@as",
        .expected_insert_line = "const foo = @as(${1:});",
        .expected_replace_line = "const foo = @as(${1:});",
        .enable_snippets = true,
        .enable_argument_placeholders = false,
    });

    // remove the following test when partial argument placeholders are supported (see test below)
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(u32);",
        .label = "@as",
        .expected_insert_line = "const foo = @as(u32);",
        .expected_replace_line = "const foo = @as(u32);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - builtin with snippets - @errorFromInt" {
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>;",
        .label = "@errorFromInt",
        .expected_insert_line = "const foo = @errorFromInt(${1:value: std.meta.Int(.unsigned, @bitSizeOf(anyerror))});",
        .expected_replace_line = "const foo = @errorFromInt(${1:value: std.meta.Int(.unsigned, @bitSizeOf(anyerror))});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - builtin with partial argument placeholders" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(u32,);",
        .label = "@as",
        .expected_insert_line = "const foo = @as(u32, ${1:expression});",
        .expected_replace_line = "const foo = @as(u32, ${1:expression});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>( , 5);",
        .label = "@as",
        .expected_insert_line = "const foo = @as(${1:comptime T: type}, 5);",
        .expected_replace_line = "const foo = @as(${1:comptime T: type}, 5);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source = "const foo = @<cursor>(u32, 5);",
        .label = "@as",
        .expected_insert_line = "const foo = @as(u32, 5);",
        .expected_replace_line = "const foo = @as(u32, 5);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - function" {
    try testCompletionTextEdit(.{
        .source =
        \\fn foo() void {}
        \\const _ = <cursor>bar()
        ,
        .label = "foo",
        .expected_insert_line = "const _ = foobar()",
        .expected_replace_line = "const _ = foo()",
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn foo(number: u32) void {}
        \\const _ = <cursor>bar()
        ,
        .label = "foo",
        .expected_insert_line = "const _ = foobar()",
        .expected_replace_line = "const _ = foo()",
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn foo(a: u32, b: u32) void {}
        \\const _ = <cursor>
        ,
        .label = "foo",
        .expected_insert_line = "const _ = foo",
        .expected_replace_line = "const _ = foo",
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn foo(number: u32) void {}
        \\const _ = <cursor>()
        ,
        .label = "foo",
        .expected_insert_line = "const _ = foo(${1:})",
        .expected_replace_line = "const _ = foo(${1:})",
        .enable_snippets = true,
        .enable_argument_placeholders = false,
    });
}

test "insert replace behaviour - function 'self parameter' detection" {
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f()",
        .expected_replace_line = "s.f()",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "S.f(${1:})",
        .expected_replace_line = "S.f(${1:})",
        .enable_snippets = true,
    });

    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: @This()) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f()",
        .expected_replace_line = "s.f()",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: anytype) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f()",
        .expected_replace_line = "s.f()",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S, number: u32) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f(${1:})",
        .expected_replace_line = "s.f(${1:})",
        .enable_snippets = true,
    });
}

test "insert replace behaviour - function with snippets" {
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>;
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(${1:comptime T: type}, ${2:number: u32});",
        .expected_replace_line = "const foo = func(${1:comptime T: type}, ${2:number: u32});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>(;
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(;",
        .expected_replace_line = "const foo = func(;",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>();
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(${1:comptime T: type}, ${2:number: u32});",
        .expected_replace_line = "const foo = func(${1:comptime T: type}, ${2:number: u32});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - function with snippets - 'self parameter' with placeholder" {
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "S.f(${1:self: S})",
        .expected_replace_line = "S.f(${1:self: S})",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S, number: u32) void {}
        \\};
        \\var s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f(${1:number: u32})",
        .expected_replace_line = "s.f(${1:number: u32})",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "s.f()",
        .expected_replace_line = "s.f()",
        .enable_snippets = true,
        .enable_argument_placeholders = false,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
        ,
        .label = "f",
        .expected_insert_line = "S.f(${1:})",
        .expected_replace_line = "S.f(${1:})",
        .enable_snippets = true,
        .enable_argument_placeholders = false,
    });
}

test "insert replace behaviour - function with snippets - partial argument placeholders" {
    // remove the following tests when partial argument placeholders are supported (see test below)
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>(u32);
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(u32);",
        .expected_replace_line = "const foo = func(u32);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>c(u32);
        ,
        .label = "func",
        .expected_insert_line = "const foo = funcc(u32);",
        .expected_replace_line = "const foo = func(u32);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - function with partial argument placeholders" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>(u32,);
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(u32, ${1:number: u32});",
        .expected_replace_line = "const foo = func(u32, ${1:number: u32});",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>( , 5);
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(${1:comptime T: type}, 5);",
        .expected_replace_line = "const foo = func(${1:comptime T: type}, 5);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func(comptime T: type, number: u32) void {}
        \\const foo = <cursor>(u32, 5);
        ,
        .label = "func",
        .expected_insert_line = "const foo = func(u32, 5);",
        .expected_replace_line = "const foo = func(u32, 5);",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - function alias" {
    try testCompletionTextEdit(.{
        .source =
        \\fn func() void {}
        \\const alias = func;
        \\const foo = <cursor>();
        ,
        .label = "alias",
        .expected_insert_line = "const foo = alias();",
        .expected_replace_line = "const foo = alias();",
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn func() void {}
        \\const alias = func;
        \\const foo = <cursor>();
        ,
        .label = "alias",
        .expected_insert_line = "const foo = alias();",
        .expected_replace_line = "const foo = alias();",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - decl literal function" {
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct {
        \\    fn init() S {}
        \\};
        \\const foo: S = .<cursor>;
        ,
        .label = "init",
        .expected_insert_line = "const foo: S = .init;",
        .expected_replace_line = "const foo: S = .init;",
    });
}

test "insert replace behaviour - struct literal" {
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .{ .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ .alpha = ",
        .expected_replace_line = "const foo: S = .{ .alpha = ",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ .alpha = ",
        .expected_replace_line = "const foo: S = .{ .alpha = ",
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ .alpha = $1 }$0",
        .expected_replace_line = "const foo: S = .{ .alpha = $1 }$0",
        .enable_snippets = true,
    });
}

test "insert replace behaviour - struct literal - check for equal sign" {
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .{ .<cursor> = 5 };
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ .alpha = 5 };",
        .expected_replace_line = "const foo: S = .{ .alpha = 5 };",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .{ . <cursor> = 5 };
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ . alpha = 5 };",
        .expected_replace_line = "const foo: S = .{ . alpha = 5 };",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const S = struct { alpha: u32 };
        \\const foo: S = .{ .<cursor>= 5 };
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: S = .{ .alpha= 5 };",
        .expected_replace_line = "const foo: S = .{ .alpha= 5 };",
        .enable_snippets = true,
    });
}

test "insert replace behaviour - tagged union" {
    try testCompletionTextEdit(.{
        .source =
        \\const Birdie = enum { canary };
        \\const U = union(enum) { alpha: []const u8 };
        \\const foo: U = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: U = .{ .alpha = $1 }$0",
        .expected_replace_line = "const foo: U = .{ .alpha = $1 }$0",
        .enable_snippets = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\const Birdie = enum { canary };
        \\const U = union(enum) { alpha: []const u8 };
        \\const foo: U = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: U = .{ .alpha = ",
        .expected_replace_line = "const foo: U = .{ .alpha = ",
    });
    try testCompletionTextEdit(.{
        .source =
        \\const U = union(enum) { alpha: []const u8 };
        \\const u: U = undefined;
        \\const boolean = u == .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const boolean = u == .alpha",
        .expected_replace_line = "const boolean = u == .alpha",
    });
    try testCompletionTextEdit(.{
        .source =
        \\const E = union(enum) {
        \\    foo: []const u8,
        \\    bar,
        \\};
        \\
        \\test {
        \\    var e: E = undefined;
        \\    switch (e) {.<cursor>}
        \\}
        ,
        .label = "foo",
        .expected_insert_line = "    switch (e) {.foo}",
        .expected_replace_line = "    switch (e) {.foo}",
        .enable_snippets = true,
    });
}

test "insert replace behaviour - tagged union - zero-bit field" {
    try testCompletionTextEdit(.{
        .source =
        \\const U = union(enum) { alpha: void };
        \\const foo: U = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: U = .alpha",
        .expected_replace_line = "const foo: U = .alpha",
    });
    try testCompletionTextEdit(.{
        .source =
        \\const U = union(enum) { alpha: u0 };
        \\const foo: U = .<cursor>
        ,
        .label = "alpha",
        .expected_insert_line = "const foo: U = .alpha",
        .expected_replace_line = "const foo: U = .alpha",
    });
}

test "insert replace behaviour - doc test name" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletionTextEdit(.{
        .source =
        \\fn foo() void {};
        \\test <cursor>
        ,
        .label = "foo",
        .expected_insert_line = "test foo",
        .expected_replace_line = "test foo",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn foo() void {};
        \\test f<cursor> {}
        ,
        .label = "foo",
        .expected_insert_line = "test foo {}",
        .expected_replace_line = "test foo {}",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
    try testCompletionTextEdit(.{
        .source =
        \\fn foo() void {};
        \\test <cursor>oo {}
        ,
        .label = "foo",
        .expected_insert_line = "test foooo {}",
        .expected_replace_line = "test foo {}",
        .enable_snippets = true,
        .enable_argument_placeholders = true,
    });
}

test "insert replace behaviour - file system completions" {
    // zig fmt: off
    try testCompletionTextEdit(.{
        .source = \\const std = @import("<cursor>");
        , .label = "std"
        , .expected_insert_line = \\const std = @import("std");
        , .expected_replace_line = \\const std = @import("std");
        ,
    });
    try testCompletionTextEdit(.{
        .source = \\const std = @import("s<cursor>td");
        , .label = "std"
        , .expected_insert_line = \\const std = @import("stdtd");
        , .expected_replace_line = \\const std = @import("std");
        ,
    });
    try testCompletionTextEdit(.{
        .source = \\const std = @import("<cursor>std");
        , .label = "std"
        , .expected_insert_line = \\const std = @import("stdstd");
        , .expected_replace_line = \\const std = @import("std");
        ,
    });
    try testCompletionTextEdit(.{
        .source = \\const std = @import("<cursor>.zig");
        , .label = "std"
        , .expected_insert_line = \\const std = @import("std.zig");
        , .expected_replace_line = \\const std = @import("std");
        ,
    });
    try testCompletionTextEdit(.{
        .source = \\const std = @import("st<cursor>.zig");
        , .label = "std"
        , .expected_insert_line = \\const std = @import("std.zig");
        , .expected_replace_line = \\const std = @import("std");
        ,
    });
    if (true) return error.SkipZigTest; // TODO
    try testCompletionTextEdit(.{
        .source = \\const std = @import("file<cursor>.zig");
        , .label = "file.zig"
        , .expected_insert_line = \\const std = @import("file.zig");
        , .expected_replace_line = \\const std = @import("file.zig");
        ,
    });
    try testCompletionTextEdit(.{
        .source = \\const std = @import("fi<cursor>le.zig");
        , .label = "file.zig"
        , .expected_insert_line = \\const std = @import("filele.zig");
        , .expected_replace_line = \\const std = @import("file.zig");
        ,
    });
    // zig fmt: on
}

fn testCompletion(source: []const u8, expected_completions: []const Completion) !void {
    try testCompletionWithOptions(source, expected_completions, .{});
}

fn testCompletionWithOptions(
    source: []const u8,
    expected_completions: []const Completion,
    options: struct {
        enable_argument_placeholders: bool = true,
        enable_snippets: bool = true,
        completion_label_details: bool = true,
    },
) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx: Context = try .init();
    defer ctx.deinit();

    ctx.server.client_capabilities.completion_doc_supports_md = true;
    ctx.server.client_capabilities.supports_snippets = true;
    ctx.server.client_capabilities.label_details_support = true;
    ctx.server.client_capabilities.supports_completion_deprecated_old = true;
    ctx.server.client_capabilities.supports_completion_deprecated_tag = true;

    ctx.server.config_manager.config.enable_argument_placeholders = options.enable_argument_placeholders;
    ctx.server.config_manager.config.enable_snippets = options.enable_snippets;
    ctx.server.config_manager.config.completion_label_details = options.completion_label_details;

    const test_uri = try ctx.addDocument(.{ .source = text });

    const params: types.CompletionParams = .{
        .textDocument = .{ .uri = test_uri },
        .position = offsets.indexToPosition(source, cursor_idx, ctx.server.offset_encoding),
    };

    @setEvalBranchQuota(5000);
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/completion", params);

    const completion_list: types.CompletionList = (response orelse {
        if (expected_completions.len == 0) return;
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    }).CompletionList;

    var actual = try extractCompletionLabels(completion_list.items);
    defer actual.deinit(allocator);

    var expected = try extractCompletionLabels(expected_completions);
    defer expected.deinit(allocator);

    var found = try set_intersection(actual, expected);
    defer found.deinit(allocator);

    var missing = try set_difference(expected, actual);
    defer missing.deinit(allocator);

    var unexpected = try set_difference(actual, expected);
    defer unexpected.deinit(allocator);

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(test_uri, text);

    for (found.keys()) |label| {
        const actual_completion: types.CompletionItem = blk: {
            for (completion_list.items) |item| {
                if (std.mem.eql(u8, label, item.label)) break :blk item;
            }
            unreachable;
        };

        const expected_completion: Completion = blk: {
            for (expected_completions) |item| {
                if (std.mem.eql(u8, label, item.label)) break :blk item;
            }
            unreachable;
        };

        if (actual_completion.kind == null or expected_completion.kind != actual_completion.kind.?) {
            try error_builder.msgAtIndex("completion item '{s}' should be of kind '{t}' but was '{?t}'!", test_uri, cursor_idx, .err, .{
                label,
                expected_completion.kind,
                if (actual_completion.kind) |kind| kind else null,
            });
            return error.InvalidCompletionKind;
        }

        if (expected_completion.documentation) |expected_doc| doc_blk: {
            const actual_doc = if (actual_completion.documentation) |doc| blk: {
                const markup_context = doc.MarkupContent;
                try std.testing.expectEqual(types.MarkupKind.markdown, markup_context.kind);
                break :blk markup_context.value;
            } else null;

            if (actual_doc != null and std.mem.eql(u8, expected_doc, actual_doc.?)) break :doc_blk;

            try error_builder.msgAtIndex("completion item '{s}' should have doc '{f}' but was '{?f}'!", test_uri, cursor_idx, .err, .{
                label,
                std.zig.fmtString(expected_doc),
                if (actual_doc) |str| std.zig.fmtString(str) else null,
            });
            return error.InvalidCompletionDoc;
        }

        try std.testing.expect(actual_completion.insertText == null); // 'insertText' is subject to interpretation on the client so 'textEdit' should be preferred

        if (!ctx.server.client_capabilities.supports_snippets) {
            try std.testing.expectEqual(types.InsertTextFormat.PlainText, actual_completion.insertTextFormat orelse .PlainText);
        }

        if (expected_completion.detail) |expected_detail| blk: {
            if (actual_completion.detail != null and std.mem.eql(u8, expected_detail, actual_completion.detail.?)) break :blk;

            try error_builder.msgAtIndex("completion item '{s}' should have detail '{s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                label,
                expected_detail,
                actual_completion.detail,
            });
            return error.InvalidCompletionDetail;
        }

        if (expected_completion.labelDetails) |expected_label_details| {
            const actual_label_details = actual_completion.labelDetails orelse {
                try error_builder.msgAtIndex("expected label details on completion item '{s}'!", test_uri, cursor_idx, .err, .{label});
                return error.InvalidCompletionLabelDetails;
            };
            const detail_ok = (expected_label_details.detail == null and actual_label_details.detail == null) or
                (expected_label_details.detail != null and actual_label_details.detail != null and std.mem.eql(u8, expected_label_details.detail.?, actual_label_details.detail.?));

            if (!detail_ok) {
                try error_builder.msgAtIndex("completion item '{s}' should have label detail '{?s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                    label,
                    expected_label_details.detail,
                    actual_label_details.detail,
                });
                return error.InvalidCompletionLabelDetails;
            }

            const description_ok = (expected_label_details.description == null and actual_label_details.description == null) or
                (expected_label_details.description != null and actual_label_details.description != null and std.mem.eql(u8, expected_label_details.description.?, actual_label_details.description.?));

            if (!description_ok) {
                try error_builder.msgAtIndex("completion item '{s}' should have label detail description '{?s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                    label,
                    expected_label_details.description,
                    actual_label_details.description,
                });
                return error.InvalidCompletionLabelDetails;
            }
        }

        blk: {
            const actual_deprecated = if (actual_completion.tags) |tags|
                std.mem.indexOfScalar(types.CompletionItemTag, tags, .Deprecated) != null
            else
                false;
            std.debug.assert(actual_deprecated == (actual_completion.deprecated orelse false));
            if (expected_completion.deprecated == actual_deprecated) break :blk;

            try error_builder.msgAtIndex("completion item '{s}' should {s} be marked as deprecated but {s}!", test_uri, cursor_idx, .err, .{
                label,
                if (expected_completion.deprecated) "" else "not",
                if (actual_deprecated) "was" else "wasn't",
            });
            return error.InvalidCompletionDeprecation;
        }
    }

    if (missing.count() != 0 or unexpected.count() != 0) {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(allocator);

        try printLabels(&buffer, found, "found");
        try printLabels(&buffer, missing, "missing");
        try printLabels(&buffer, unexpected, "unexpected");
        try error_builder.msgAtIndex("invalid completions\n{s}", test_uri, cursor_idx, .err, .{buffer.items});
        return error.MissingOrUnexpectedCompletions;
    }
}

fn extractCompletionLabels(items: anytype) error{ DuplicateCompletionLabel, OutOfMemory }!std.StringArrayHashMapUnmanaged(void) {
    var set: std.StringArrayHashMapUnmanaged(void) = .empty;
    errdefer set.deinit(allocator);
    try set.ensureTotalCapacity(allocator, items.len);
    for (items) |item| {
        const maybe_kind = switch (@typeInfo(@TypeOf(item.kind))) {
            .optional => item.kind,
            else => @as(?@TypeOf(item.kind), item.kind),
        };
        if (maybe_kind) |kind| {
            switch (kind) {
                .Keyword, .Snippet => continue,
                else => {},
            }
        }
        if (set.fetchPutAssumeCapacity(item.label, {}) != null) return error.DuplicateCompletionLabel;
    }
    return set;
}

fn set_intersection(a: std.StringArrayHashMapUnmanaged(void), b: std.StringArrayHashMapUnmanaged(void)) error{OutOfMemory}!std.StringArrayHashMapUnmanaged(void) {
    var result: std.StringArrayHashMapUnmanaged(void) = .empty;
    errdefer result.deinit(allocator);
    for (a.keys()) |key| {
        if (b.contains(key)) try result.putNoClobber(allocator, key, {});
    }
    return result;
}

fn set_difference(a: std.StringArrayHashMapUnmanaged(void), b: std.StringArrayHashMapUnmanaged(void)) error{OutOfMemory}!std.StringArrayHashMapUnmanaged(void) {
    var result: std.StringArrayHashMapUnmanaged(void) = .empty;
    errdefer result.deinit(allocator);
    for (a.keys()) |key| {
        if (!b.contains(key)) try result.putNoClobber(allocator, key, {});
    }
    return result;
}

fn printLabels(output: *std.ArrayList(u8), labels: std.StringArrayHashMapUnmanaged(void), name: []const u8) error{OutOfMemory}!void {
    if (labels.count() != 0) {
        try output.print(allocator, "{s}:\n", .{name});
        for (labels.keys()) |label| {
            try output.print(allocator, "  - {s}\n", .{label});
        }
    }
}

/// TODO this function should allow asserting where the cursor is placed after the text edit
fn testCompletionTextEdit(
    options: struct {
        source: []const u8,
        /// label of the completion item that should be applied
        label: []const u8,
        /// expected line when `textDocument.completion.insertReplaceSupport` is unset or the 'insert' text edit is applied.
        expected_insert_line: []const u8,
        /// expected line when `textDocument.completion.insertReplaceSupport` is set and the 'replace' text edit is applied.
        expected_replace_line: []const u8,

        enable_argument_placeholders: bool = false,
        enable_snippets: bool = false,
    },
) !void {
    const cursor_idx = std.mem.indexOf(u8, options.source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ options.source[0..cursor_idx], options.source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    const cursor_line_loc = offsets.lineLocAtIndex(text, cursor_idx);

    const expected_insert_text = try std.mem.concat(allocator, u8, &.{ text[0..cursor_line_loc.start], options.expected_insert_line, text[cursor_line_loc.end..] });
    defer allocator.free(expected_insert_text);

    const expected_replace_text = try std.mem.concat(allocator, u8, &.{ text[0..cursor_line_loc.start], options.expected_replace_line, text[cursor_line_loc.end..] });
    defer allocator.free(expected_replace_text);

    var ctx: Context = try .init();
    defer ctx.deinit();

    ctx.server.client_capabilities.supports_snippets = true;

    ctx.server.config_manager.config.enable_argument_placeholders = options.enable_argument_placeholders;
    ctx.server.config_manager.config.enable_snippets = options.enable_snippets;

    const test_uri = try ctx.addDocument(.{ .source = text });
    const handle = ctx.server.document_store.getHandle(test_uri).?;

    const cursor_position = offsets.indexToPosition(options.source, cursor_idx, ctx.server.offset_encoding);
    const params: types.CompletionParams = .{
        .textDocument = .{ .uri = test_uri },
        .position = cursor_position,
    };

    for ([_]bool{ false, true }) |supports_insert_replace| {
        ctx.server.client_capabilities.supports_completion_insert_replace_support = supports_insert_replace;

        @setEvalBranchQuota(5000);
        const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/completion", params) orelse {
            std.debug.print("Server returned `null` as the result\n", .{});
            return error.InvalidResponse;
        };
        const completion_item = try searchCompletionItemWithLabel(response.CompletionList, options.label);

        std.debug.assert(completion_item.additionalTextEdits == null); // unsupported

        const TextEditOrInsertReplace = std.meta.Child(@TypeOf(completion_item.textEdit));

        const text_edit_or_insert_replace: TextEditOrInsertReplace = completion_item.textEdit orelse blk: {
            var start_index: usize = cursor_idx;
            while (start_index > 0 and zls.Analyser.isSymbolChar(handle.tree.source[start_index - 1])) {
                start_index -= 1;
            }

            const start_position = offsets.indexToPosition(text, start_index, ctx.server.offset_encoding);

            break :blk .{
                .TextEdit = .{
                    .newText = completion_item.insertText orelse completion_item.label,
                    .range = .{ .start = start_position, .end = cursor_position },
                },
            };
        };

        switch (text_edit_or_insert_replace) {
            .TextEdit => |text_edit| {
                try std.testing.expect(text_edit.range.start.line == text_edit.range.end.line); // text edit range must be a single line
                try std.testing.expect(offsets.positionInsideRange(cursor_position, text_edit.range)); // text edit range must contain the cursor position

                const actual_text = try zls.diff.applyTextEdits(allocator, text, &.{text_edit}, ctx.server.offset_encoding);
                defer allocator.free(actual_text);

                try std.testing.expectEqualStrings(expected_insert_text, actual_text);

                if (supports_insert_replace) {
                    try std.testing.expectEqualStrings(expected_replace_text, actual_text);
                }
            },
            .InsertReplaceEdit => |insert_replace_edit| {
                std.debug.assert(supports_insert_replace);

                try std.testing.expect(insert_replace_edit.insert.start.line == insert_replace_edit.insert.end.line); // text edit range must be a single line
                try std.testing.expect(insert_replace_edit.replace.start.line == insert_replace_edit.replace.end.line); // text edit range must be a single line
                try std.testing.expect(offsets.positionInsideRange(cursor_position, insert_replace_edit.insert)); // text edit range must contain the cursor position
                try std.testing.expect(offsets.positionInsideRange(cursor_position, insert_replace_edit.replace)); // text edit range must contain the cursor position

                const insert_text_edit: types.TextEdit = .{ .newText = insert_replace_edit.newText, .range = insert_replace_edit.insert };
                const replace_text_edit: types.TextEdit = .{ .newText = insert_replace_edit.newText, .range = insert_replace_edit.replace };

                const actual_insert_text = try zls.diff.applyTextEdits(allocator, text, &.{insert_text_edit}, ctx.server.offset_encoding);
                defer allocator.free(actual_insert_text);

                const actual_replace_text = try zls.diff.applyTextEdits(allocator, text, &.{replace_text_edit}, ctx.server.offset_encoding);
                defer allocator.free(actual_replace_text);

                try std.testing.expectEqualStrings(expected_insert_text, actual_insert_text);
                try std.testing.expectEqualStrings(expected_replace_text, actual_replace_text);
            },
        }
    }
}

fn searchCompletionItemWithLabel(completion_list: types.CompletionList, label: []const u8) !types.CompletionItem {
    for (completion_list.items) |item| {
        if (std.mem.eql(u8, item.label, label)) return item;
    }

    const stderr = std.debug.lockStderrWriter(&.{});
    defer std.debug.unlockStderrWriter();

    try stderr.print(
        \\server returned no completion item with label '{s}'
        \\
        \\labels:
        \\
    , .{label});
    for (completion_list.items) |item| {
        try stderr.print("  - {s}\n", .{item.label});
    }

    return error.MissingCompletionItem;
}
