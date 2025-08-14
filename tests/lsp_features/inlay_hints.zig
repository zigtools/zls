const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.lsp.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "empty" {
    try testInlayHints("", .{ .kind = .Parameter });
    try testInlayHints("", .{ .kind = .Type });
}

test "function call" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const _ = foo(<alpha>5);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(<alpha>5,<beta>4);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(  <alpha>3 + 2 ,  <beta>(3 - 2));
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(
        \\    <alpha>3 + 2,
        \\    <beta>(3 - 2),
        \\);
    , .{ .kind = .Parameter });
}

test "function call with multiline string literal" {
    try testInlayHints(
        \\fn foo(bar: []const u8) void {}
        \\const _ = foo(<bar>
        \\    \\alpha
        \\    \\beta
        \\);
    , .{ .kind = .Parameter });
}

test "extern function call" {
    try testInlayHints(
        \\extern fn foo(u32, beta: bool, []const u8) void;
        \\const _ = foo(5, <beta>true, "");
    , .{ .kind = .Parameter });
}

test "function self parameter" {
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: *Foo, alpha: u32) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: *Foo, alpha: u32) void {} };
        \\const foo: *Foo = undefined;
        \\const _ = foo.bar(<alpha>5);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct { pub fn bar(_: Foo, alpha: u32, beta: []const u8) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>"");
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: anytype) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>4);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: anytype) void {} };
        \\const foo: *Foo = undefined;
        \\const _ = foo.bar(<alpha>5,<beta>4);
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {} };
        \\const _ = Foo.bar(<self>undefined,<alpha>5,<beta>"");
    , .{ .kind = .Parameter });
    try testInlayHints(
        \\const Foo = struct {
        \\  pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {}
        \\  pub fn foo() void {
        \\      bar(<self>undefined,<alpha>5,<beta>"");
        \\  }
        \\};
    , .{ .kind = .Parameter });
}

test "function self parameter with pointer type in type declaration" {
    try testInlayHints(
        \\const Foo = *opaque { pub fn bar(self: Foo, alpha: u32) void {} };
        \\const foo: Foo = undefined;
        \\const _ = foo.bar(<alpha>5);
    , .{ .kind = .Parameter });
}

test "resolve alias" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const bar = foo;
        \\const _ = bar(<alpha>5);
    , .{ .kind = .Parameter });
}

test "builtin call" {
    try testInlayHints(
        \\const _ = @memcpy(<dest>"",<source>"");
        \\const _ = @Vector(<len>4,<Element>u32);
        \\const _ = @compileError(<msg>"");
    , .{ .kind = .Parameter });

    // exclude variadics
    try testInlayHints(
        \\const _ = @compileLog(2, 3);
        \\const _ = @TypeOf(null, 5);
    , .{ .kind = .Parameter });

    // exclude other builtins
    try testInlayHints(
        \\const _ = @sizeOf(u32);
        \\const _ = @max(2, 4);
    , .{ .kind = .Parameter });

    try testInlayHints(
        \\const _ = @memcpy("","");
        \\const _ = @TypeOf(null, 5);
        \\const _ = @sizeOf(u32);
        \\const _ = @TypeOf(5);
    , .{
        .kind = .Parameter,
        .show_builtin = false,
    });
}

test "builtin call with multiline string literal" {
    try testInlayHints(
        \\const _ = @compileError(<msg>
        \\    \\foo
        \\    \\bar
        \\);
    , .{ .kind = .Parameter });
}

test "exclude single argument" {
    try testInlayHints(
        \\fn func1(alpha: u32) void {}
        \\fn func2(alpha: u32, beta: u32) void {}
        \\test {
        \\    func1(1);
        \\    func2(<alpha>1, <beta>2);
        \\}
    , .{
        .kind = .Parameter,
        .exclude_single_argument = true,
    });
    try testInlayHints(
        \\const S = struct {
        \\    fn method1(self: S) void {}
        \\    fn method2(self: S, alpha: u32) void {}
        \\    fn method3(self: S, alpha: u32, beta: u32) void {}
        \\    fn method4(alpha: u32, beta: u32) void {}
        \\};
        \\test {
        \\    S.method1(undefined);
        \\    S.method2(<self>undefined, <alpha>1);
        \\    S.method3(<self>undefined, <alpha>1, <beta>2);
        \\    S.method4(<alpha>1, <beta>2);
        \\
        \\    const s: S = undefined;
        \\    s.method1();
        \\    s.method2(1);
        \\    s.method3(<alpha>1, <beta>2);
        \\}
    , .{
        .kind = .Parameter,
        .exclude_single_argument = true,
    });
}

test "hide redundant parameter names" {
    try testInlayHints(
        \\fn func(alpha: u32) void {}
        \\test {
        \\    const alpha: u32 = 5;
        \\    const beta: u32 = 5;
        \\    const s = .{ .alpha = 5, .beta = 5 };
        \\
        \\    func(alpha);
        \\
        \\    func(<alpha>&alpha);
        \\    func(<alpha>s.alpha);
        \\    func(<alpha>beta);
        \\    func(<alpha>&beta);
        \\    func(<alpha>s.beta);
        \\}
    , .{
        .kind = .Parameter,
        .hide_redundant_param_names = true,
        .hide_redundant_param_names_last_token = false,
    });
    try testInlayHints(
        \\fn func(alpha: u32) void {}
        \\test {
        \\    const alpha: u32 = 5;
        \\    const beta: u32 = 5;
        \\    const s = .{ .alpha = 5, .beta = 5 };
        \\
        \\    func(alpha);
        \\    func(&alpha);
        \\    func(s.alpha);
        \\
        \\    func(<alpha>beta);
        \\    func(<alpha>&beta);
        \\    func(<alpha>s.beta);
        \\}
    , .{
        .kind = .Parameter,
        .hide_redundant_param_names = true,
        .hide_redundant_param_names_last_token = true,
    });
}

test "var decl" {
    try testInlayHints(
        \\const a<@Vector(2,u8)> = @Vector(2, u8){1,2};
        \\const foo<@Vector(2,bool)> = a == a;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo<comptime_int> = 5;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo<bool> = true;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo<@TypeOf(undefined)> = undefined;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo<*const *const [3:0]u8> = &"Bar";
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo: *[]const u8 = &"Bar";
        \\const baz<*const *[]const u8> = &foo;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const Foo<type> = struct { bar: u32 };
        \\const Error<type> = error{e};
        \\fn test_context() !void {
        \\    const baz: ?Foo = Foo{ .bar<u32> = 42 };
        \\    if (baz) |b<Foo>| {
        \\        const d: Error!?Foo = b;
        \\        const e<*const error{e}!?Foo> = &d;
        \\        const f<Foo> = (try e.*).?;
        \\        _ = f;
        \\    }
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\ fn thing(a: u32, b: i32) struct {
        \\     a: u32,
        \\     b: i32,
        \\     c: struct {
        \\         d: usize,
        \\         e: []const u8,
        \\     },
        \\ } {
        \\     return .{
        \\         .a<u32> = a,
        \\         .b<i32> = b,
        \\         .c<struct {...}> = .{
        \\             .d<usize> = 0,
        \\             .e<[]const u8> = "Testing",
        \\         }
        \\     };
        \\ }
        \\
        \\ var a<struct {...}> = thing(10, -4);
        \\ _ = a;
    , .{ .kind = .Type });
}

test "comptime return types" {
    try testInlayHints(
        \\fn Box(comptime T: type) type {
        \\    return struct {
        \\        value: T,
        \\    };
        \\}
        \\const list: Box(Box(i32)) = undefined;
        \\const innerList: Box(i32) = list.value;
        \\const nested: i32 = list.value.value;
    , .{ .kind = .Type });

    try testInlayHints(
        \\fn concat(comptime T: type, slices: []const []const T) error{OutOfMemory}![]T {}
        \\const str<[]u8> = try concat(u8, .{ "foo", "bar" });
        \\const int<[]i32> = try concat(i32, .{ .{ 1, 2, 3 }, .{ 4, 5, 6 } });
    , .{ .kind = .Type });
}

test "comptime return types - HashMap" {
    try testInlayHints(
        \\const std<type> = @import("std");
        \\const boolMap<HashMap(i32,bool,AutoContext(i32))> = std.AutoHashMap(i32, bool).init(allocator);
        \\const u32Map<HashMap(i32,u32,AutoContext(i32))> = std.AutoHashMap(i32, u32).init(allocator);
        \\const boolPtr<?*bool> = boolMap.getPtr(123);
        \\const u32Ptr<?*u32> = u32Map.getPtr(123);
    , .{ .kind = .Type });

    try testInlayHints(
        \\const std<type> = @import("std");
        \\const map<HashMap(i32,HashMap(i32,void,AutoContext(i32)),AutoContext(i32))> = std.AutoHashMap(i32, std.AutoHashMap(i32, void)).init(allocator);
        \\const value<?*HashMap(i32,void,AutoContext(i32))> = map.getPtr(123);
        \\const double<?*void> = map.getPtr(123).?.*.getPtr(456);
    , .{ .kind = .Type });
}

test "assign destructure" {
    try testInlayHints(
        \\test {
        \\    const foo<u32>, const bar<comptime_int> = .{@as(u32, 1), 2};
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\    const foo: comptime_int, const bar<u64> = .{1, @as(u64, 7)};
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\    const foo<u32>, const bar: u64, var baz<u32> = [_]u32{1, 2, 3};
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\    var foo: u32 = undefined;
        \\    var bar: u64 = undefined;
        \\    foo, bar = .{ 3, 4 };
        \\}
    , .{ .kind = .Type });
}

test "function alias" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {
        \\    return alpha;
        \\}
        \\const bar<fn (u32) void> = foo;
    , .{ .kind = .Type });
    try testInlayHints(
        \\pub fn foo(
        \\  // some documentation
        \\  comptime alpha: u32,
        \\) u32 {
        \\    return alpha;
        \\}
        \\const bar<*const fn (comptime u32) u32> = &foo;
    , .{ .kind = .Type });
}

test "function with error union" {
    try testInlayHints(
        \\fn foo() !u32 {}
        \\test {
        \\    const val<!u32> = foo();
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\const Error<type> = error{OutOfMemory};
        \\fn foo() Error!u32 {}
        \\test {
        \\    const val<error{OutOfMemory}!u32> = foo();
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\fn foo() error{OutOfMemory}!u32 {}
        \\test {
        \\    const val<error{OutOfMemory}!u32> = foo();
        \\}
    , .{ .kind = .Type });

    // same but with `try`
    try testInlayHints(
        \\fn foo() !u32 {}
        \\test {
        \\    const val<u32> = try foo();
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\const Error<type> = error{OutOfMemory};
        \\fn foo() Error!u32 {}
        \\test {
        \\    const val<u32> = try foo();
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\fn foo() error{OutOfMemory}!u32 {}
        \\test {
        \\    const val<u32> = try foo();
        \\}
    , .{ .kind = .Type });
}

test "generic function parameter" {
    try testInlayHints(
        \\fn foo(comptime T: type, param: T) void {
        \\    const val: T = param;
        \\}
    , .{ .kind = .Type });
}

test "capture values with if" {
    try testInlayHints(
        \\const FooError<type> = error{
        \\  Err1,
        \\};
        \\fn testFn() void {
        \\const foo: FooError!?[]const u8 = null;
        \\    if (foo) |f<?[]const u8>| {
        \\        if (f) |g<[]const u8>| {
        \\            for (g) |c<u8>| {
        \\               _ = c;
        \\            }
        \\        }
        \\    } else |e<error{Err1}>| {
        \\        _ = e;
        \\    }
        \\}
    , .{ .kind = .Type });
}

test "capture values with for loop" {
    try testInlayHints(
        \\test {
        \\  const foo: []const u8 = "abc";
        \\  for (foo) |bar<u8>| {
        \\      _ = bar;
        \\  }
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\  var foo: []const u8 = "abc";
        \\  for (foo) |*bar<*u8>| {
        \\      _ = bar;
        \\  }
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\  const foo: []const u8 = "abc";
        \\  for (foo) |bar<u8>| {
        \\      _ = bar;
        \\  }
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\test {
        \\  const bar: []const u8 = "test";
        \\  for (bar, 0..3) |ch<u8>, _| {
        \\      _ = ch;
        \\  }
        \\  for (bar, 0..3) |_, index<usize>| {
        \\      _ = index;
        \\  }
        \\  for (bar, 0..) |_, index<usize>| {
        \\      _ = index;
        \\  }
        \\}
    , .{ .kind = .Type });
}

test "capture values with while loop" {
    try testInlayHints(
        \\const Error<type> = error{
        \\  Err1,
        \\};
        \\const Iterator<type> = struct {
        \\    pub fn next(self: *Iterator) Error!?usize {}
        \\};
        \\test {
        \\    var it: Iterator = .{};
        \\    while (it.next()) |val<?usize>| {
        \\        if (val) |v<usize>| { _ = v; }
        \\    } else |e<error{Err1}>| { _ = e; }
        \\}
    , .{ .kind = .Type });
}

test "capture value with switch" {
    try testInlayHints(
        \\const U<type> = union(enum) {
        \\    foo: u32,
        \\    bar: []const u8,
        \\};
        \\fn foo(u: U) void {
        \\    switch (u) {
        \\        .foo => |number<u32>| {},
        \\        .bar => |slice<[]const u8>| {},
        \\    }
        \\}
    , .{ .kind = .Type });
}

test "capture value with catch" {
    try testInlayHints(
        \\fn foo() !u32 {}
        \\test {
        \\    foo() catch |err| {}
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\const Error<type> = error{OutOfMemory};
        \\fn foo() Error!u32 {}
        \\test {
        \\    foo() catch |err<error{OutOfMemory}>| {}
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\fn foo() error{OutOfMemory}!u32 {}
        \\test {
        \\    foo() catch |err<error{OutOfMemory}>| {}
        \\}
    , .{ .kind = .Type });
}

test "truncate anonymous container declarations" {
    try testInlayHints(
        \\const A<struct {...}> = @as(struct { a: u32 }, undefined);
        \\const B<packed union {...}> = @as(packed union { a: u32 }, undefined);
        \\const C<union(enum) {...}> = @as(union(enum) { a: u32 }, undefined);
        \\const D<union(u32) {...}> = @as(union(u32) { a: u32 }, undefined);
    , .{ .kind = .Type });
}

test "truncate anonymous error sets" {
    try testInlayHints(
        \\const A<error{Foo}> = @as(error{Foo}, undefined);
        \\const B<error{Foo,Bar}> = @as(error{Foo,Bar}, undefined);
        \\const C<error{...}> = @as(error{Foo,Bar,Baz}, undefined);
        \\const D<error{...}> = @as(error{A,B,C,D}, undefined);
    , .{ .kind = .Type });
}

test "truncate merged error sets" {
    try testInlayHints(
        \\const A<error{Foo,Bar}> =  @as(error{ Foo } || error{ Bar }, undefined);
    , .{ .kind = .Type });
}

test "tuples" {
    try testInlayHints(
        \\fn foo() void {
        \\    var a: f32 = 0;
        \\    var b: i64 = 1;
        \\    const tmp<struct { i64, f32 }> = .{ b, a };
        \\}
    , .{ .kind = .Type });
}

test "tuple fields" {
    try testInlayHints(
        \\fn foo() void {
        \\    var a: f32 = 0;
        \\    var b: i64 = 1;
        \\    const tmp<struct { i64, f32 }> = .{ b, a };
        \\    const x<i64> = tmp.@"0";
        \\    const y<f32> = tmp.@"1";
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\fn foo() void {
        \\    const tmp: struct { i64, f32 } = .{ 1, 0 };
        \\    const x<i64> = tmp.@"0";
        \\    const y<f32> = tmp.@"1";
        \\}
    , .{ .kind = .Type });
}

const Options = struct {
    kind: types.InlayHintKind,
    show_builtin: bool = true,
    exclude_single_argument: bool = false,
    hide_redundant_param_names: bool = false,
    hide_redundant_param_names_last_token: bool = false,
};

fn testInlayHints(source: []const u8, options: Options) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx: Context = try .init();
    defer ctx.deinit();

    ctx.server.config_manager.config.inlay_hints_show_parameter_name = options.kind == .Parameter;
    ctx.server.config_manager.config.inlay_hints_show_variable_type_hints = options.kind == .Type;
    ctx.server.config_manager.config.inlay_hints_show_builtin = options.show_builtin;
    ctx.server.config_manager.config.inlay_hints_exclude_single_argument = options.exclude_single_argument;
    ctx.server.config_manager.config.inlay_hints_hide_redundant_param_names = options.hide_redundant_param_names;
    ctx.server.config_manager.config.inlay_hints_hide_redundant_param_names_last_token = options.hide_redundant_param_names_last_token;

    const test_uri = try ctx.addDocument(.{ .source = phr.new_source });

    const range: types.Range = .{
        .start = .{ .line = 0, .character = 0 },
        .end = offsets.indexToPosition(phr.new_source, phr.new_source.len, .@"utf-16"),
    };

    const params: types.InlayHintParams = .{
        .textDocument = .{ .uri = test_uri },
        .range = range,
    };
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/inlayHint", params);

    const hints: []const types.InlayHint = response orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var visited: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, hints.len);
    defer visited.deinit(allocator);

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(test_uri, phr.new_source);

    outer: for (phr.locations.items(.old), phr.locations.items(.new)) |old_loc, new_loc| {
        const expected_name = offsets.locToSlice(source, old_loc);
        const expected_label = expected_name[1 .. expected_name.len - 1]; // convert <name> to name

        const position = offsets.indexToPosition(phr.new_source, new_loc.start, ctx.server.offset_encoding);

        for (hints, 0..) |hint, i| {
            if (position.line != hint.position.line or position.character != hint.position.character) continue;
            try std.testing.expectEqual(options.kind, hint.kind.?);

            if (visited.isSet(i)) {
                try error_builder.msgAtIndex("duplicate inlay hint here!", test_uri, new_loc.start, .err, .{});
                continue :outer;
            } else {
                visited.set(i);
            }

            const actual_label = switch (options.kind) {
                .Parameter => blk: {
                    if (!std.mem.endsWith(u8, hint.label.string, ":")) {
                        try error_builder.msgAtLoc("label `{s}` must end with a colon!", test_uri, new_loc, .err, .{hint.label.string});
                        continue :outer;
                    }
                    break :blk hint.label.string[0 .. hint.label.string.len - 1];
                },
                .Type => blk: {
                    if (!std.mem.startsWith(u8, hint.label.string, ": ")) {
                        try error_builder.msgAtLoc("label `{s}` must start with \": \"!", test_uri, new_loc, .err, .{hint.label.string});
                        continue :outer;
                    }
                    break :blk hint.label.string[2..hint.label.string.len];
                },
                _ => unreachable,
            };

            if (!std.mem.eql(u8, expected_label, actual_label)) {
                try error_builder.msgAtLoc("expected label `{s}` here but got `{s}`!", test_uri, new_loc, .err, .{ expected_label, actual_label });
            }

            continue :outer;
        }
        try error_builder.msgAtLoc("expected hint `{s}` here", test_uri, new_loc, .err, .{expected_label});
    }

    var it = visited.iterator(.{ .kind = .unset });
    while (it.next()) |index| {
        const hint = hints[index];
        try std.testing.expectEqual(options.kind, hint.kind.?);
        const source_index = offsets.positionToIndex(phr.new_source, hint.position, ctx.server.offset_encoding);
        try error_builder.msgAtIndex("unexpected inlay hint `{s}` here!", test_uri, source_index, .err, .{hint.label.string});
    }

    if (error_builder.hasMessages()) return error.InvalidResponse;
}
