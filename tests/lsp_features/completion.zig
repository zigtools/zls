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
    labelDetails: ?types.CompletionItemLabelDetails = null,
    kind: types.CompletionItemKind,
    detail: ?[]const u8 = null,
    documentation: ?[]const u8 = null,
    insert_text: ?[]const u8 = null,
    deprecated: bool = false,
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

test "completion - symbol lookup on escaped identifiers" {
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

test "completion - escaped identifier normalization" {
    if (true) return error.SkipZigTest; // TODO
    try testCompletion(
        \\const S = struct { alpha: u32 };
        \\var s: @"\x53" = undefined;
        \\const foo = @"\x73".<cursor>
    , &.{
        .{ .label = "foo", .kind = .Constant },
    });
}

test "completion - symbol lookup on identifier named after primitive" {
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

test "completion - function" {
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

test "completion - std.ArrayList" {
    if (!std.process.can_spawn) return error.SkipZigTest;
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const array_list: std.ArrayList(S) = undefined;
        \\const foo = array_list.items[0].<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "completion - std.ArrayHashMap" {
    if (!std.process.can_spawn) return error.SkipZigTest;
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
        \\const map: std.AutoArrayHashMap(u32, S) = undefined;
        \\const s = map.get(0);
        \\const foo = s.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoArrayHashMap(u32, S) = undefined;
        \\const gop = try map.getOrPut(0);
        \\const foo = gop.value_ptr.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "completion - std.HashMap" {
    if (!std.process.can_spawn) return error.SkipZigTest;
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
        \\const map: std.AutoHashMap(u32, S) = undefined;
        \\const s = map.get(0);
        \\const foo = s.?.<cursor>
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
    try testCompletion(
        \\const std = @import("std");
        \\const S = struct { alpha: u32 };
        \\const map: std.AutoHashMap(u32, S) = undefined;
        \\const gop = try map.getOrPut(0);
        \\const foo = gop.value_ptr.<cursor>
    , &.{
        .{ .label = "*", .kind = .Operator, .detail = "S" },
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });
}

test "completion - function call" {
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

test "completion - optional" {
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

test "completion - optional type" {
    try testCompletion(
        \\const foo = ?u32;
        \\const bar = foo.<cursor>
    , &.{});
}

test "completion - pointer deref" {
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
    });
}

test "completion - pointer array access" {
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

test "completion - pointer subslicing" {
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

test "completion - pointer subslicing parser correctness" {
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

test "completion - slice pointer" {
    try testCompletion(
        \\const foo: []const u8 = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "len", .kind = .Field, .detail = "usize" },
        .{ .label = "ptr", .kind = .Field, .detail = "[*]const u8" },
    });
}

test "completion - many item pointer" {
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

test "completion - address of" {
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

test "completion - pointer type" {
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

test "completion - array" {
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

test "completion - single pointer to array" {
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

test "completion - array type" {
    try testCompletion(
        \\const foo = [3]u32;
        \\const bar = foo.<cursor>
    , &.{});
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
        \\    const baz = foo() catch |err| {
        \\        _ = err;
        \\        return;
        \\    };
        \\    baz.<cursor>
        \\}
    , &.{
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
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

test "completion - struct" {
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
        .{ .label = "S", .kind = .Constant, .detail = "struct" },
        .{ .label = "Mode", .kind = .Constant, .detail = "enum" },
    });

    try testCompletion(
        \\fn fooImpl(_: Foo) void {}
        \\fn barImpl(_: *const Foo) void {}
        \\fn bazImpl(_: u32) void {}
        \\const Foo = struct {
        \\    pub const foo = fooImpl;
        \\    pub const bar = barImpl;
        \\    pub const baz = bazImpl;
        \\};
        \\const foo = Foo{};
        \\const baz = foo.<cursor>;
    , &.{
        // TODO kind should be .Method
        .{ .label = "foo", .kind = .Function, .detail = "fn (_: Foo) void" },
        // TODO kind should be .Method
        .{ .label = "bar", .kind = .Function, .detail = "fn (_: *const Foo) void" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
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
        .{ .label = "inner", .kind = .Function, .detail = "fn (_: E) void" },
    });
    try testCompletion(
        \\const E = enum {
        \\    _,
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

test "completion - global enum set" {
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

test "completion - switch cases" {
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
        \\    pub fn retEnum() SomeEnum {}
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
}

test "completion - error set" {
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
        .{ .label = "qux", .kind = .Constant, .detail = "error.qux", .documentation = "hello" },
    });
}

test "completion - global error set" {
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

    try testCompletion(
        \\const Error = error{Foo} || error{Bar};
        \\const E = <cursor>
    , &.{
        .{ .label = "Error", .kind = .Constant, .detail = "error" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    });

    // try testCompletion(
    //     \\const S = struct { alpha: u32 };
    //     \\fn foo() error{Foo}!S {}
    //     \\fn bar() error{Foo}!void {
    //     \\    (try foo()).<cursor>
    //     \\}
    // , &.{
    //     .{ .label = "alpha", .kind = .Field, .detail = "u32" },
    // });

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

test "completion - struct init" {
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
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
        .{ .label = "beta", .kind = .Field, .detail = "[]const u8" },
        // TODO `gamma` should be excluded
        .{ .label = "gamma", .kind = .Field, .detail = "?*S" },
    });
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: []const u8,
        \\};
        \\const foo = S{ .alpha = S{ .beta = "{}" }, .<cursor> };
    , &.{
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
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
    try testCompletion(
        \\const S = struct {
        \\    alpha: *const S,
        \\    beta: u32,
        \\    gamma: ?*S,
        \\};
        \\const foo = S{ .gamma = undefined, .<cursor> , .alpha = undefined };
    , &.{
        // TODO `gamma` should be excluded
        .{ .label = "gamma", .kind = .Field, .detail = "?*S" },
        .{ .label = "beta", .kind = .Field, .detail = "u32" },
        // TODO `alpha` should be excluded
        .{ .label = "alpha", .kind = .Field, .detail = "*const S" },
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
        \\  pub fn s3(p0: es, p1: S2) void {}
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
        \\  pub fn s3(self: *Self, p0: es, p1: S2) void {}
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

test "completion - deprecated " {
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

test "completion - declarations" {
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
        .{ .label = "Private", .kind = .Constant, .detail = "type = u32" },
    });

    try testCompletion(
        \\const S = struct {
        \\    pub fn public() S {}
        \\    fn private() !void {}
        \\};
        \\const foo: S = undefined;
        \\const bar = foo.<cursor>
    , &.{
        .{ .label = "public", .kind = .Function, .detail = "fn () S" },
        .{ .label = "private", .kind = .Function, .detail = "fn () !void" },
    });

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
        .{ .label = "public", .kind = .Function, .detail = "fn () S1" },
        .{ .label = "private", .kind = .Function, .detail = "fn () !void" },
    });
    try testCompletion(
        \\const S1 = struct {
        \\    usingnamespace struct {
        \\        pub fn inner() void {}
        \\    };
        \\};
        \\const foo = S1.<cursor>
    , &.{
        .{ .label = "inner", .kind = .Function, .detail = "fn () void" },
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
        // TODO kind should be .Method
        .{ .label = "inner", .kind = .Function, .detail = "fn (self: Self) void" },
        .{ .label = "deinit", .kind = .Method, .detail = "fn (self: Foo) void" },
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
        .{ .label = "alpha", .kind = .Function, .detail = "fn () void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn () void" },
    });
    try testCompletion(
        \\pub const chip_mod = struct {
        \\    pub const devices = struct {
        \\        pub const chip1 = struct {
        \\            canary: bool,
        \\            pub const peripherals = struct {};
        \\            pub fn chip1fn1() void {}
        \\            pub fn chip1fn2(_: u32) void {}
        \\        };
        \\        pub const chip2 = struct {
        \\            pub fn chip2fn1() void {}
        \\        };
        \\    };
        \\};
        \\const chip = struct {
        \\    const inner = chip_mod; //@import("chip");
        \\    pub usingnamespace @field(inner.devices, "chip1");
        \\};
        \\test {
        \\    _ = chip.<cursor>;
        \\}
    , &.{
        .{ .label = "inner", .kind = .Constant, .detail = "struct" },
        .{ .label = "peripherals", .kind = .Constant, .detail = "struct" },
        .{ .label = "chip1fn1", .kind = .Function, .detail = "fn () void" },
        .{ .label = "chip1fn2", .kind = .Function, .detail = "fn (_: u32) void" },
    });
}

test "completion - anytype resolution based on callsite-references" {
    try testCompletion(
        \\const Writer1 = struct {
        \\    fn write1() void {}
        \\    fn writeAll1() void {}
        \\};
        \\const Writer2 = struct {
        \\    fn write2() void {}
        \\    fn writeAll2() void {}
        \\};
        \\fn caller(a: Writer1, b: Writer2) void {
        \\    callee(a);
        \\    callee(b);
        \\}
        \\fn callee(writer: anytype) void {
        \\    writer.<cursor>
        \\}
    , &.{
        .{ .label = "write1", .kind = .Function, .detail = "fn () void" },
        .{ .label = "write2", .kind = .Function, .detail = "fn () void" },
        .{ .label = "writeAll1", .kind = .Function, .detail = "fn () void" },
        .{ .label = "writeAll2", .kind = .Function, .detail = "fn () void" },
    });
    try testCompletion(
        \\const Writer1 = struct {
        \\    fn write1() void {}
        \\    fn writeAll1() void {}
        \\};
        \\const Writer2 = struct {
        \\    fn write2() void {}
        \\    fn writeAll2() void {}
        \\};
        \\fn caller(a: Writer1, b: Writer2) void {
        \\    callee(a);
        \\    // callee(b);
        \\}
        \\fn callee(writer: anytype) void {
        \\    writer.<cursor>
        \\}
    , &.{
        .{ .label = "write1", .kind = .Function, .detail = "fn () void" },
        .{ .label = "writeAll1", .kind = .Function, .detail = "fn () void" },
    });
}

test "builtin fn `field`" {
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
        .{ .label = "peripherals", .kind = .Constant, .detail = "struct" },
    });
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
        .{ .label = "peripherals", .kind = .Constant, .detail = "struct" },
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
        .{ .label = "peripherals", .kind = .Constant, .detail = "struct" },
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
        .{ .label = "alpha", .kind = .Field, .detail = "u32" },
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
        .{ .label = "alpha", .kind = .Function, .detail = "fn () void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn () void" },
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
        .{ .label = "alpha", .kind = .Function, .detail = "fn () void" },
        .{ .label = "beta", .kind = .Function, .detail = "fn () void" },
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

test "completion - enum completion on out of bound parameter index" {
    try testCompletion(
        \\fn foo() void {}
        \\const foo = foo(,.<cursor>);
    , &.{});
}

test "completion - combine doc comments of declaration and definition" {
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
            .kind = .Constant,
            .detail = "struct",
            .documentation =
            \\ A
            \\
            \\ B
            ,
        },
    });
}

test "hover - top-level doc comment" {
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
            .kind = .Constant,
            .detail = "@This()",
            .documentation =
            \\ A
            \\
            \\ B
            ,
        },
    });
}

test "completion - snippet - function with `self` parameter" {
    try testCompletion(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{ .label = "f", .kind = .Method, .detail = "fn (self: S) void", .insert_text = "f()" },
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{ .label = "f", .kind = .Method, .detail = "fn (self: S) void", .insert_text = "f()" },
    }, .{
        .enable_argument_placeholders = false,
    });
    try testCompletion(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
    , &.{
        .{ .label = "f", .kind = .Function, .detail = "fn (self: S) void", .insert_text = "f(${1:self: S})" },
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
    , &.{
        .{ .label = "f", .kind = .Function, .detail = "fn (self: S) void", .insert_text = "f(${1:})" },
    }, .{
        .enable_argument_placeholders = false,
    });
}

test "completion - snippets disabled" {
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{ .label = "f", .kind = .Method, .detail = "fn (self: S) void", .insert_text = "f()" },
    }, .{
        .enable_snippets = false,
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\S.<cursor>
    , &.{
        .{ .label = "f", .kind = .Function, .detail = "fn (self: S) void", .insert_text = "f" },
    }, .{
        .enable_snippets = false,
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f() void {}
        \\};
        \\S.<cursor>
    , &.{
        .{ .label = "f", .kind = .Function, .detail = "fn () void", .insert_text = "f()" },
    }, .{
        .enable_snippets = false,
    });
}

test "completion - label details disabled" {
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S) void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{
            .label = "f",
            .labelDetails = .{
                .detail = "()",
                .description = "void",
            },
            .kind = .Method,
            .detail = "fn (self: S) void",
            .insert_text = "f()",
        },
    }, .{
        .completion_label_details = false,
    });
    try testCompletionWithOptions(
        \\const S = struct {
        \\    fn f(self: S, value: u32) !void {}
        \\};
        \\const s = S{};
        \\s.<cursor>
    , &.{
        .{
            .label = "f",
            .labelDetails = .{
                .detail = "(...)",
                .description = "!void",
            },
            .kind = .Method,
            .detail = "fn (self: S, value: u32) !void",
            .insert_text = "f(${1:value: u32})",
        },
    }, .{
        .completion_label_details = false,
    });
}

fn testCompletion(source: []const u8, expected_completions: []const Completion) !void {
    try testCompletionWithOptions(source, expected_completions, .{});
}

fn testCompletionWithOptions(source: []const u8, expected_completions: []const Completion, options: struct {
    enable_argument_placeholders: bool = true,
    enable_snippets: bool = true,
    completion_label_details: bool = true,
}) !void {
    const cursor_idx = std.mem.indexOf(u8, source, "<cursor>").?;
    const text = try std.mem.concat(allocator, u8, &.{ source[0..cursor_idx], source[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(text);

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.client_capabilities.completion_doc_supports_md = true;
    ctx.server.client_capabilities.supports_snippets = options.enable_snippets;
    ctx.server.client_capabilities.label_details_support = true;
    ctx.server.client_capabilities.supports_completion_deprecated_old = true;
    ctx.server.client_capabilities.supports_completion_deprecated_tag = true;

    ctx.server.config.enable_argument_placeholders = options.enable_argument_placeholders;
    ctx.server.config.enable_snippets = options.enable_snippets;
    ctx.server.config.completion_label_details = options.completion_label_details;

    const test_uri = try ctx.addDocument(text);

    const params = types.CompletionParams{
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
            try error_builder.msgAtIndex("completion item '{s}' should be of kind '{s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                label,
                @tagName(expected_completion.kind),
                if (actual_completion.kind) |kind| @tagName(kind) else null,
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

            try error_builder.msgAtIndex("completion item '{s}' should have doc '{s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                label,
                expected_doc,
                actual_doc,
            });
            return error.InvalidCompletionDoc;
        }

        if (expected_completion.insert_text) |expected_insert| blk: {
            try std.testing.expectEqual(
                @as(?types.InsertTextFormat, if (options.enable_snippets) .Snippet else .PlainText),
                actual_completion.insertTextFormat,
            );
            const actual_insert = actual_completion.insertText;
            if (actual_insert != null and std.mem.eql(u8, expected_insert, actual_insert.?)) break :blk;
            try error_builder.msgAtIndex("completion item '{s}' should have insert text '{s}' but was '{?s}'!", test_uri, cursor_idx, .err, .{
                label,
                expected_insert,
                actual_insert,
            });
            return error.InvalidCompletionInsertText;
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
            const actual_deprecated =
                if (actual_completion.tags) |tags|
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
        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);
        const out = buffer.writer(allocator);

        try printLabels(out, found, "found");
        try printLabels(out, missing, "missing");
        try printLabels(out, unexpected, "unexpected");
        try error_builder.msgAtIndex("invalid completions\n{s}", test_uri, cursor_idx, .err, .{buffer.items});
        return error.MissingOrUnexpectedCompletions;
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
