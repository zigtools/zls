const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

const Completion = struct {
    label: []const u8,
    kind: types.CompletionItemKind,
    detail: ?[]const u8 = null,
};

const CompletionSet = std.StringArrayHashMapUnmanaged(Completion);

test "completion - root scope" {
    try testCompletion(
        \\const foo = 5;
        \\const bar = <cursor>;
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });

    try testCompletion(
        \\const foo = 5;
        \\const bar = <cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
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

test "completion - root scope with self referential decl" {
    try testCompletion(
        \\const foo = foo;
        \\const bar = <cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });
}

test "completion - local scope" {
    if (true) return error.SkipZigTest;
    try testCompletion(
        \\const foo = {
        \\    var bar = 5;
        \\    const alpha = <cursor>;
        \\    const baz = 3;
        \\};
    , &.{
        .{ .label = "foo", .kind = .Constant }, // should foo be referencable?
        .{ .label = "bar", .kind = .Variable },
    });
}

test "completion - function" {
    try testCompletion(
        \\fn foo(alpha: u32, beta: []const u8) void {
        \\    <cursor>
        \\}
    , &.{
        // TODO detail should be 'fn(alpha: u32, beta: []const u8) void' or 'foo: fn(alpha: u32, beta: []const u8) void'
        .{ .label = "foo", .kind = .Function, .detail = "fn foo(alpha: u32, beta: []const u8) void" },
        .{ .label = "alpha", .kind = .Constant, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Constant, .detail = "beta: []const u8" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() S { return undefined; }
        \\const bar = foo().<cursor>;
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - generic function" {
    // TODO doesn't work for std.ArrayList

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn ArrayList(comptime T: type) type {
        \\    return struct { items: []const T };
        \\}
        \\const array_list: ArrayList(S) = undefined;
        \\const foo = array_list.items[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(comptime T: type) T {}
        \\const s = foo(S);
        \\const foo = s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(any: anytype, comptime T: type) T {}
        \\const s = foo(null, S);
        \\const foo = s.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "foo", .kind = .Function, .detail = "fn foo(self: S, comptime T: type) T" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "foo", .kind = .Function, .detail = "fn foo(self: S, any: anytype, comptime T: type) T" },
    });
}

test "completion - std.ArrayList" {
    if (!std.process.can_spawn) return error.SkipZigTest;
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const array_list: std.ArrayList(S) = undefined;
        \\const foo = array_list.items[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - optional" {
    try testCompletion(
        \\const foo: ?u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        // TODO detail should be 'u32'
        .{ .label = "?", .kind = .Operator },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: ?S = undefined;
        \\const bar = foo.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - pointer" {
    try testCompletion(
        \\const foo: *u32 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        // TODO detail should be 'u32'
        .{ .label = "*", .kind = .Operator },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: *S = undefined;
        \\const bar = foo.*.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const foo: []const u8 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "const len: usize" },
        // TODO detail should be 'const ptr: [*]const u8'
        .{ .label = "ptr", .kind = .Field },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: []S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: *S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        // TODO detail should be 'S'
        .{ .label = "*", .kind = .Operator },
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    // try testCompletion(
    //     \\const S = struct {
    //     \\    alpha: u32,
    //     \\};
    //     \\const foo: []S = undefined;
    //     \\const bar = foo.ptr[0].<cursor>
    // , &.{
    //     .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    // });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [*]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [*c]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\};
        \\const foo: [1]S = undefined;
        \\const bar = foo[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - captures" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    if(bar) |baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: []S) void {
        \\    for (items, 0..) |bar, i| {
        \\        bar.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: [2]S) void {
        \\    for (items) |bar| {
        \\        bar.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(items: []S) void {
        \\    for (items, items) |_, baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo(bar: ?S) void {
        \\    while (bar) |baz| {
        \\        baz.<cursor>
        \\    }
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    // TODO fix value capture without block scope
    // try testCompletion(
    //     \\const S = struct { alpha: u32 };
    //     \\const foo: ?S = undefined;
    //     \\const bar = if(foo) |baz| baz.<cursor>
    // , &.{
    //     .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    // });

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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - struct" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
    });

    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .alpha = 0, .beta = "" };
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
        .{ .label = "foo", .kind = .Function, .detail = "fn foo(self: S) void" },
    });

    try testCompletion(
        \\const S = struct {
        \\    const Mode = enum { alpha, beta, };
        \\    fn foo(mode: <cursor>
        \\};
    , &.{
        .{ .label = "S", .kind = .Constant, .detail = "const S = struct" },
        .{ .label = "Mode", .kind = .Constant, .detail = "const Mode = enum" },
    });
}

test "completion - union" {
    try testCompletion(
        \\const U = union {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo: U = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
    });

    try testCompletion(
        \\const U = union {
        \\    alpha: ?u32,
        \\};
        \\fn foo(bar: U) void {
        \\    switch (bar) {
        \\        .alpha => |a| {
        \\            a.<cursor>
        \\        }
        \\    }
        \\}
    , &.{
        .{ .label = "?", .kind = .Operator },
    });
}

test "completion - enum" {
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
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\};
        \\const foo: E = .<cursor>
    , &.{
        .{ .label = "alpha", .kind = .EnumMember },
        .{ .label = "beta", .kind = .EnumMember },
    });
    try testCompletion(
        \\const E = enum {
        \\    _,
        \\    fn inner(_: E) void {} 
        \\};
        \\const foo = E.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Function, .detail = "fn inner(_: E) void" },
    });
    try testCompletion(
        \\const E = enum {
        \\    _,
        \\    fn inner(_: E) void {} 
        \\};
        \\const e: E = undefined;
        \\const foo = e.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Function, .detail = "fn inner(_: E) void" },
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
        \\    pub fn retEnum() SomeEnum {}
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
}

test "completion - error set" {
    try testCompletion(
        \\const E = error {
        \\    Foo,
        \\    Bar,
        \\};
        \\const baz = error.<cursor>
    , &.{
        .{ .label = "Foo", .kind = .Constant, .detail = "error.Foo" },
        .{ .label = "Bar", .kind = .Constant, .detail = "error.Bar" },
    });

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
}

test "completion - merged error sets" {
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
}

test "completion - error union" {
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() error{Foo}!S {}
        \\fn bar() error{Foo}!void {
        \\    const baz = try foo();
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });

    // try testCompletion(
    //     \\const S = struct { alpha: u32 };
    //     \\fn foo() error{Foo}!S {}
    //     \\fn bar() error{Foo}!void {
    //     \\    (try foo()).<cursor>
    //     \\}
    // , &.{
    //     .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    // });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\fn foo() error{Foo}!S {}
        \\fn bar() error{Foo}!void {
        \\    const baz = foo() catch return;
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - struct init" {
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .<cursor> };
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: u32,
        \\    beta: []const u8,
        \\    gamma: ?*S,
        \\};
        \\const foo = S{ .alpha = 3, .<cursor>, .gamma = null };
    , &.{
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
        // TODO `gamma` should be excluded
        .{ .label = "gamma", .kind = .Field, .detail = "gamma: ?*S" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .alpha = S{ .beta = "{}" }, .<cursor> };
    , &.{
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: *const S" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: []const u8" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\};
        \\const foo = S{ .alpha = S{ .<cursor> } };
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: *const S" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: u32" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?*S,
        \\};
        \\const foo = S{ .gamma = undefined, .<cursor> , .alpha = undefined };
    , &.{
        // TODO `gamma` should be excluded
        .{ .label = "gamma", .kind = .Field, .detail = "gamma: ?*S" },
        .{ .label = "beta", .kind = .Field, .detail = "beta: u32" },
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: *const S" },
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
        .{ .label = "isf1", .kind = .Field, .detail = "isf1: bool = true" },
        .{ .label = "isf2", .kind = .Field, .detail = "isf2: bool = false" },
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
        .{ .label = "isf1", .kind = .Field, .detail = "isf1: bool = true" },
        .{ .label = "isf2", .kind = .Field, .detail = "isf2: bool = false" },
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
        .{ .label = "a", .kind = .Field, .detail = "a: bool" },
        .{ .label = "b", .kind = .Field, .detail = "b: bool" },
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
        .{ .label = "arefb", .kind = .Field, .detail = "arefb: B = 8" },
        .{ .label = "this_is_a", .kind = .Field, .detail = "this_is_a: u32 = 9" },
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
        \\  pub fn s3(p0: es, p1: S2) void {}
        \\};
        \\const refs = S3{ .ref2 = .{ .ref1 = .{ .ref3 = .{ .ref2 = .{ .ref1 = .{.<cursor>} } } } } };
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "s1f1: u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "s1f2: u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "ref3: S3 = undefined" },
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
        \\  pub fn s3(self: *Self, p0: es, p1: S2) void {}
        \\};
        \\S3.s3(null, .{ .mye = .{} }, .{ .ref1 = .{ .ref3 = .{ .ref2 = .{ .ref1 = .{.<cursor>} } } } });
    , &.{
        .{ .label = "s1f1", .kind = .Field, .detail = "s1f1: u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "s1f2: u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "ref3: S3 = undefined" },
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
        .{ .label = "s1f1", .kind = .Field, .detail = "s1f1: u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "s1f2: u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "ref3: S3 = undefined" },
        .{ .label = "s2f1", .kind = .Field, .detail = "s2f1: u8" },
        .{ .label = "s2f2", .kind = .Field, .detail = "s2f2: u32 = 1" },
        .{ .label = "ref1", .kind = .Field, .detail = "ref1: S1" },
        .{ .label = "s3f1", .kind = .Field, .detail = "s3f1: u8" },
        .{ .label = "s3f2", .kind = .Field, .detail = "s3f2: u32 = 1" },
        .{ .label = "ref2", .kind = .Field, .detail = "ref2: S2" },
        .{ .label = "mye", .kind = .Field, .detail = "mye: MyEnum = .ef1" },
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
        .{ .label = "s1f1", .kind = .Field, .detail = "s1f1: u8" },
        .{ .label = "s1f2", .kind = .Field, .detail = "s1f2: u32 = 1" },
        .{ .label = "ref3", .kind = .Field, .detail = "ref3: S3 = undefined" },
        .{ .label = "s2f1", .kind = .Field, .detail = "s2f1: u8" },
        .{ .label = "s2f2", .kind = .Field, .detail = "s2f2: u32 = 1" },
        .{ .label = "ref1", .kind = .Field, .detail = "ref1: S1" },
        .{ .label = "mye", .kind = .Field, .detail = "mye: MyEnum = .ef1" },
    });
}

test "completion - declarations" {
    try testCompletion(
        \\const S = struct {
        \\    pub fn public() S {}
        \\    fn private() !void {}
        \\};
        \\const foo: S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn public() S" },
        .{ .label = "private", .kind = .Function, .detail = "fn private() !void" },
    });

    try testCompletion(
        \\const S = struct {
        \\    pub fn public() S {}
        \\    fn private() !void {}
        \\};
        \\const foo = S.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn public() S" },
        .{ .label = "private", .kind = .Function, .detail = "fn private() !void" },
    });
}

test "completion - usingnamespace" {
    try testCompletion(
        \\const S1 = struct {
        \\    member: u32,
        \\    pub fn public() S1 {}
        \\    fn private() !void {}
        \\};
        \\const S2 = struct {
        \\    usingnamespace S1;
        \\};
        \\const foo = S2.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn public() S1" },
        .{ .label = "private", .kind = .Function, .detail = "fn private() !void" },
    });
    try testCompletion(
        \\const S1 = struct {
        \\    usingnamespace struct {
        \\        pub fn inner() void {}
        \\    };
        \\};
        \\const foo = S1.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Function, .detail = "fn inner() void" },
    });
    try testCompletion(
        \\fn Bar(comptime Self: type) type {
        \\    return struct {
        \\        fn inner(self: Self) void { _ = self; }
        \\    };
        \\}
        \\const Foo = struct {
        \\    pub usingnamespace Bar(Foo);
        \\    fn deinit(self: Foo) void { _ = self; }
        \\};
        \\const foo: Foo = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Function, .detail = "fn inner(self: Self) void" },
        .{ .label = "deinit", .kind = .Function, .detail = "fn deinit(self: Foo) void" },
    });
    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha() void {}
        \\};
        \\const Beta = struct {
        \\    fn beta() void {}
        \\};
        \\const Gamma = struct {
        \\    usingnamespace if (undefined) Alpha else Beta;
        \\};
        \\const gamma: Gamma = undefined;
        \\const g = gamma.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn alpha() void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn beta() void" },
    });
}

test "completion - block" {
    try testCompletion(
        \\const foo = blk: {
        \\    break :<cursor>
        \\};
    , &.{
        .{ .label = "blk", .kind = .Text }, // idk what kind this should be
    });

    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\const foo: S = undefined;
        \\const bar = blk: {
        \\    break :blk foo;
        \\};
        \\const baz = bar.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "alpha: u32" },
    });
}

test "completion - either" {
    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha() void {}
        \\};
        \\const Beta = struct {
        \\    fn beta() void {}
        \\};
        \\const foo: if (undefined) Alpha else Beta = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn alpha() void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn beta() void" },
    });
    try testCompletion(
        \\const Alpha = struct {
        \\    fn alpha() void {}
        \\};
        \\const Beta = struct {
        \\    fn beta() void {}
        \\};
        \\const alpha: Alpha = undefined;
        \\const beta: Beta = undefined;
        \\const gamma = if (undefined) alpha else beta;
        \\const foo = gamma.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Function, .detail = "fn alpha() void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn beta() void" },
    });
}

// https://github.com/zigtools/zls/issues/1370
test "completion - cyclic struct init field" {
    try testCompletion(
        \\_ = .{} .foo = .{ .<cursor>foo
    , &.{});
}

test "completion - integer overflow in struct init field without lhs" {
    try testCompletion(
        \\= .{ .<cursor>foo
    , &.{});
}

test "completion - integer overflow in dot completions at beginning of file" {
    try testCompletion(
        \\.<cursor>
    , &.{});
}

fn testCompletion(source: []const u8, expected_completions: []const Completion) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(text);

    const params = types.CompletionParams{
        .textDocument = .{ .uri = test_uri },
        .position = offsets.indexToPosition(source, cursor_idx, ctx.server.offset_encoding),
    };

    @setEvalBranchQuota(5000);
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/completion", params);

    const completion_list: types.CompletionList = (response orelse {
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

    var error_builder = ErrorBuilder.init(allocator);
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
            try error_builder.msgAtIndex("label '{s}' should be of kind '{s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                label,
                @tagName(expected_completion.kind),
                if (actual_completion.kind) |kind| @tagName(kind) else null,
            });
            return error.InvalidCompletionKind;
        }

        if (expected_completion.detail == null) continue;
        if (actual_completion.detail != null and std.mem.eql(u8, expected_completion.detail.?, actual_completion.detail.?)) continue;

        try error_builder.msgAtIndex("label '{s}' should have detail '{?s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
            label,
            expected_completion.detail,
            actual_completion.detail,
        });
        return error.InvalidCompletionDetail;
    }

    if (missing.count() != 0 or unexpected.count() != 0) {
        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);
        var out = buffer.writer(allocator);

        try printLabels(out, found, "found");
        try printLabels(out, missing, "missing");
        try printLabels(out, unexpected, "unexpected");
        try error_builder.msgAtIndex("invalid completions\n{s}", test_uri, cursor_idx, .err, .{buffer.items});
        return error.InvalidCompletions;
    }
}

fn extractCompletionLabels(items: anytype) error{ DuplicateCompletionLabel, OutOfMemory }!std.StringArrayHashMapUnmanaged(void) {
    var set = std.StringArrayHashMapUnmanaged(void){};
    errdefer set.deinit(allocator);
    try set.ensureTotalCapacity(allocator, items.len);
    for (items) |item| {
        const maybe_kind = switch (@typeInfo(@TypeOf(item.kind))) {
            .Optional => item.kind,
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
    var result = std.StringArrayHashMapUnmanaged(void){};
    errdefer result.deinit(allocator);
    for (a.keys()) |key| {
        if (b.contains(key)) try result.putNoClobber(allocator, key, {});
    }
    return result;
}

fn set_difference(a: std.StringArrayHashMapUnmanaged(void), b: std.StringArrayHashMapUnmanaged(void)) error{OutOfMemory}!std.StringArrayHashMapUnmanaged(void) {
    var result = std.StringArrayHashMapUnmanaged(void){};
    errdefer result.deinit(allocator);
    for (a.keys()) |key| {
        if (!b.contains(key)) try result.putNoClobber(allocator, key, {});
    }
    return result;
}

fn printLabels(writer: anytype, labels: std.StringArrayHashMapUnmanaged(void), name: []const u8) @TypeOf(writer).Error!void {
    if (labels.count() != 0) {
        try writer.print("{s}:\n", .{name});
        for (labels.keys()) |label| {
            try writer.print("  - {s}\n", .{label});
        }
    }
}
