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
    try testInlayHints("", .Parameter);
    try testInlayHints("", .Type);
}

test "inlayhints - function call" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const _ = foo(<alpha>5);
    , .Parameter);
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(<alpha>5,<beta>4);
    , .Parameter);
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(  <alpha>3 + 2 ,  <beta>(3 - 2));
    , .Parameter);
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(
        \\    <alpha>3 + 2,
        \\    <beta>(3 - 2),
        \\);
    , .Parameter);
}

test "inlayhints - function self parameter" {
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: *Foo, alpha: u32) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5);
    , .Parameter);
    try testInlayHints(
        \\const Foo = struct { pub fn bar(_: Foo, alpha: u32, beta: []const u8) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>"");
    , .Parameter);
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: anytype) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>4);
    , .Parameter);
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {} };
        \\const _ = Foo.bar(<self>undefined,<alpha>5,<beta>"");
    , .Parameter);
    try testInlayHints(
        \\const Foo = struct {
        \\  pub fn bar(self: Foo, alpha: u32, beta: []const u8) void {}
        \\  pub fn foo() void {
        \\      bar(<self>undefined,<alpha>5,<beta>"");
        \\  }
        \\};
    , .Parameter);
}

test "inlayhints - resolve alias" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const bar = foo;
        \\const _ = bar(<alpha>5);
    , .Parameter);
}

test "inlayhints - builtin call" {
    try testInlayHints(
        \\const _ = @memcpy(<dest>"",<source>"");
    , .Parameter);
    try testInlayHints(
        \\const _ = @sizeOf(<T>u32);
    , .Parameter);
    try testInlayHints(
        \\const _ = @TypeOf(5);
    , .Parameter);
}

test "inlayhints - var decl" {
    try testInlayHints(
        \\const foo<comptime_int> = 5;
    , .Type);
    try testInlayHints(
        \\const foo<bool> = true;
    , .Type);
    try testInlayHints(
        \\const foo<@TypeOf(undefined)> = undefined;
    , .Type);
    try testInlayHints(
        \\const foo<**const [3:0]u8> = &"Bar";
    , .Type);
    try testInlayHints(
        \\const foo: *[]const u8 = &"Bar";
        \\const baz<**[]const u8> = &foo;
    , .Type);
    try testInlayHints(
        \\const Foo<type> = struct { bar: u32 };
        \\const Error<type> = error{e};
        \\fn test_context() !void {
        \\    const baz: ?Foo = Foo{ .bar = 42 };
        \\    if (baz) |b<Foo>| {
        \\        const d: Error!?Foo = b;
        \\        const e<*Error!?Foo> = &d;
        \\        const f<Foo> = (try e.*).?;
        \\        _ = f;
        \\    }
        \\}
    , .Type);
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
        \\         .a = a,
        \\         .b = b,
        \\         .c = .{
        \\             .d = 0,
        \\             .e = "Testing",
        \\         }
        \\     }; 
        \\ }
        \\
        \\ var a<struct { a: u32, b: i32, c: struct { d: usize, e: []const u8, }, }> = thing(10, -4);
        \\ _ = a;
    , .Type);
}

test "inlayhints - capture values" {
    try testInlayHints(
        \\fn a() void {
        \\  const foo: []const u8 = "abc";
        \\      for (foo) |bar<u8>| {
        \\      _ = bar;
        \\  }
        \\}
    , .Type);
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
    , .Type);
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
        \\        .counter = 10,
        \\    };
        \\    while (foo.next()) |val<?usize>| {
        \\        if (val) |v<usize>| { _ = v; }
        \\    } else |e<FooError>| { _ = e; }
        \\}
    , .Type);

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
    , .Type);
}

fn testInlayHints(source: []const u8, kind: types.InlayHintKind) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

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
            if (hint.kind.? != kind) continue;

            if (visited.isSet(i)) {
                try error_builder.msgAtIndex("duplicate inlay hint here!", test_uri, new_loc.start, .err, .{});
                continue :outer;
            } else {
                visited.set(i);
            }

            const actual_label = switch (kind) {
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
        if (hint.kind.? != kind) continue;
        const source_index = offsets.positionToIndex(phr.new_source, hint.position, ctx.server.offset_encoding);
        try error_builder.msgAtIndex("unexpected inlay hint `{s}` here!", test_uri, source_index, .err, .{hint.label.string});
    }

    if (error_builder.hasMessages()) return error.InvalidResponse;
}
