const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "inlayhints - empty" {
    try testInlayHints("", .{ .kind = .Parameter });
    try testInlayHints("", .{ .kind = .Type });
}

test "inlayhints - function call" {
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

test "inlayhints - function self parameter" {
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

test "inlayhints - function self parameter with pointer type in type declaration" {
    try testInlayHints(
        \\const Foo = *opaque { pub fn bar(self: Foo, alpha: u32) void {} };
        \\const foo: Foo = undefined;
        \\const _ = foo.bar(<alpha>5);
    , .{ .kind = .Parameter });
}

test "inlayhints - resolve alias" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const bar = foo;
        \\const _ = bar(<alpha>5);
    , .{ .kind = .Parameter });
}

test "inlayhints - builtin call" {
    try testInlayHints(
        \\const _ = @memcpy(<dest>"",<source>"");
        \\const _ = @sizeOf(<T>u32);
        \\const _ = @TypeOf(5);
    , .{
        .kind = .Parameter,
    });
    try testInlayHints(
        \\const _ = @memcpy("","");
        \\const _ = @sizeOf(u32);
        \\const _ = @TypeOf(5);
    , .{
        .kind = .Parameter,
        .show_builtin = false,
    });
}

test "inlayhints - exclude single argument" {
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

test "inlayhints - hide redundant parameter names" {
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

test "inlayhints - var decl" {
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
        \\const foo<**const [3:0]u8> = &"Bar";
    , .{ .kind = .Type });
    try testInlayHints(
        \\const foo: *[]const u8 = &"Bar";
        \\const baz<**[]const u8> = &foo;
    , .{ .kind = .Type });
    try testInlayHints(
        \\const Foo<type> = struct { bar: u32 };
        \\const Error<type> = error{e};
        \\fn test_context() !void {
        \\    const baz: ?Foo = Foo{ .bar<u32> = 42 };
        \\    if (baz) |b<Foo>| {
        \\        const d: Error!?Foo = b;
        \\        const e<*Error!?Foo> = &d;
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
        \\         .c<struct { d: usize, e: []const u8, }> = .{
        \\             .d<usize> = 0,
        \\             .e<[]const u8> = "Testing",
        \\         }
        \\     }; 
        \\ }
        \\
        \\ var a<struct { a: u32, b: i32, c: struct { d: usize, e: []const u8, }, }> = thing(10, -4);
        \\ _ = a;
    , .{ .kind = .Type });
}

test "inlayhints - function alias" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {
        \\    return alpha;
        \\}
        \\const bar<fn (alpha: u32) void> = foo;
    , .{ .kind = .Type });
    try testInlayHints(
        \\pub fn foo(
        \\  // some documentation
        \\  comptime alpha: u32,
        \\) u32 {
        \\    return alpha; 
        \\}
        \\const bar<*fn (comptime alpha: u32) u32> = &foo;
    , .{ .kind = .Type });
}

test "inlayhints - function with error union" {
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
        \\    const val<Error!u32> = foo();
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

test "inlayhints - generic function parameter" {
    // TODO there should be an inlay hint that shows `T`
    try testInlayHints(
        \\fn foo(comptime T: type, param: T) void {
        \\    const val = param;
        \\}
    , .{ .kind = .Type });
}

test "inlayhints - capture values" {
    try testInlayHints(
        \\fn a() void {
        \\  const foo: []const u8 = "abc";
        \\      for (foo) |bar<u8>| {
        \\      _ = bar;
        \\  }
        \\}
    , .{ .kind = .Type });
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
        \\    } else |e<FooError>| {
        \\        _ = e;
        \\    }
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\const FooError<type> = error{
        \\  Err1,
        \\};
        \\const Foo<type> = struct {
        \\    counter: usize,
        \\    pub fn next(self: *Foo) FooError!?usize {
        \\        if (self.counter == 0) {
        \\            return null;
        \\        }
        \\        self.counter -= 1;
        \\        return self.counter;
        \\    }
        \\};
        \\fn a() void {
        \\    var foo<Foo> = Foo {
        \\        .counter<usize> = 10,
        \\    };
        \\    while (foo.next()) |val<?usize>| {
        \\        if (val) |v<usize>| { _ = v; }
        \\    } else |e<FooError>| { _ = e; }
        \\}
    , .{ .kind = .Type });

    try testInlayHints(
        \\fn foo() void {
        \\  const bar: []const u8 = "test";
        \\  for (bar, 0..3) |_, u<usize>| {
        \\      _ = u;
        \\  }
        \\  for (bar, 0..3) |ch<u8>, _| {
        \\      _ = ch;
        \\  }
        \\}
    , .{ .kind = .Type });
}

test "inlayhints - capture value with switch" {
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

test "inlayhints - capture value with catch" {
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
        \\    foo() catch |err<Error>| {}
        \\}
    , .{ .kind = .Type });
    try testInlayHints(
        \\fn foo() error{OutOfMemory}!u32 {}
        \\test {
        \\    foo() catch |err<error{OutOfMemory}>| {}
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

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.config.inlay_hints_show_parameter_name = options.kind == .Parameter;
    ctx.server.config.inlay_hints_show_variable_type_hints = options.kind == .Type;
    ctx.server.config.inlay_hints_show_builtin = options.show_builtin;
    ctx.server.config.inlay_hints_exclude_single_argument = options.exclude_single_argument;
    ctx.server.config.inlay_hints_hide_redundant_param_names = options.hide_redundant_param_names;
    ctx.server.config.inlay_hints_hide_redundant_param_names_last_token = options.hide_redundant_param_names_last_token;

    const test_uri = try ctx.addDocument(phr.new_source);

    const range = types.Range{
        .start = types.Position{ .line = 0, .character = 0 },
        .end = offsets.indexToPosition(phr.new_source, phr.new_source.len, .@"utf-16"),
    };

    const params = types.InlayHintParams{
        .textDocument = .{ .uri = test_uri },
        .range = range,
    };
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/inlayHint", params);

    const hints: []const types.InlayHint = response orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var visited = try std.DynamicBitSetUnmanaged.initEmpty(allocator, hints.len);
    defer visited.deinit(allocator);

    var error_builder = ErrorBuilder.init(allocator);
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
