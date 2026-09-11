const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.lsp.types;

const allocator: std.mem.Allocator = std.testing.allocator;

test "container decl" {
    try testDocumentSymbol(
        \\const S = struct {
        \\    fn f() void {}
        \\};
    ,
        \\Struct S
        \\  Function f (fn f() void)
    );
    try testDocumentSymbol(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f() void {}
        \\};
    ,
        \\Struct S
        \\  Field alpha (S)
        \\  Function f (fn f() void)
    );
}

test "tuple" {
    try testDocumentSymbol(
        \\const S = struct {
        \\    []const u8,
        \\    u32,
        \\};
    ,
        \\Struct S
    );
}

test "union" {
    try testDocumentSymbol(
        \\const U = union {
        \\    alpha: u32,
        \\    beta,
        \\};
    ,
        \\Struct U
        \\  Field alpha (U)
        \\  Field beta (U)
    );
}

test "enum" {
    try testDocumentSymbol(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\};
    ,
        \\Enum E
        \\  EnumMember alpha (E)
        \\  EnumMember beta (E)
    );
}

test "non-exhaustive enum" {
    try testDocumentSymbol(
        \\const E = enum(u8) {
        \\    alpha,
        \\    _,
        \\};
        \\const F = enum {
        \\    @"_",
        \\};
    ,
        \\Enum E
        \\  EnumMember alpha (E)
        \\Enum F
        \\  EnumMember @"_" (F)
    );
}

test "kind inference from initializer" {
    try testDocumentSymbol(
        \\const std = @import("std");
        \\const c = @cImport(@cInclude("foo.h"));
        \\const Error = error{ A, B };
        \\const Combined = Error || error{C};
        \\const Opaque = opaque {};
        \\const Sized = enum(u8) {
        \\    alpha,
        \\};
        \\const Tagged = union(enum) {
        \\    alpha: u32,
        \\};
        \\var Mutable = struct {};
        \\const alias = std.ArrayList;
        \\const value = 42;
        \\var counter: u32 = 0;
    ,
        \\Module std
        \\Module c
        \\Enum Error
        \\Enum Combined
        \\Class Opaque
        \\Enum Sized
        \\  EnumMember alpha (Sized)
        \\Struct Tagged
        \\  Field alpha (Tagged)
        \\Struct Mutable
        \\Constant alias
        \\Constant value
        \\Variable counter
    );
}

test "method detection" {
    try testDocumentSymbol(
        \\const Foo = struct {
        \\    const Self = @This();
        \\    fn init() Foo {}
        \\    fn deinit(self: Foo) void {}
        \\    fn reset(self: *Foo) void {}
        \\    fn get(self: Self) u32 {}
        \\    fn set(self: *const @This(), v: u32) void {}
        \\    fn helper(x: u32) u32 {}
        \\    fn deinitAll(items: []Foo) void {}
        \\    fn firstOf(p: [*]Foo) u32 {}
        \\    fn fromC(p: [*c]Foo) void {}
        \\    fn make() void {
        \\        const Bar = struct {
        \\            fn m(self: Foo) void {}
        \\            fn n(self: Bar) void {}
        \\        };
        \\        _ = Bar;
        \\    }
        \\    const Inner = struct {
        \\        fn innerMethod(i: Inner) void {}
        \\        fn outerParam(f: Foo) void {}
        \\    };
        \\};
        \\fn free(foo: Foo) void {}
    ,
        \\Struct Foo
        \\  Constant Self
        \\  Function init (fn init() Foo)
        \\  Method deinit (fn deinit(self: Foo) void)
        \\  Method reset (fn reset(self: *Foo) void)
        \\  Method get (fn get(self: Self) u32)
        \\  Method set (fn set(self: *const @This(), v: u32) void)
        \\  Function helper (fn helper(x: u32) u32)
        \\  Function deinitAll (fn deinitAll(items: []Foo) void)
        \\  Function firstOf (fn firstOf(p: [*]Foo) u32)
        \\  Method fromC (fn fromC(p: [*c]Foo) void)
        \\  Function make (fn make() void)
        \\    Function m (fn m(self: Foo) void)
        \\    Method n (fn n(self: Bar) void)
        \\  Struct Inner
        \\    Method innerMethod (fn innerMethod(i: Inner) void)
        \\    Function outerParam (fn outerParam(f: Foo) void)
        \\Function free (fn free(foo: Foo) void)
    );
}

test "invalid tuple-like container" {
    try testDocumentSymbol(
        \\const E = enum {
        \\    '=',
        \\};
    ,
        \\Enum E
    );
    try testDocumentSymbol(
        \\const E = enum {
        \\    @src
        \\};
    ,
        \\Enum E
    );
    try testDocumentSymbol(
        \\const U = union {
        \\    '=',
        \\};
    ,
        \\Struct U
    );
    try testDocumentSymbol(
        \\const U = union(enum) {
        \\    '=',
        \\};
    ,
        \\Struct U
    );
}

test "extern function" {
    try testDocumentSymbol(
        \\fn foo() void;
    ,
        \\Function foo (fn foo() void)
    );
}

test "test decl" {
    try testDocumentSymbol(
        \\test foo {}
        \\test "bar" {}
        \\test {}
    ,
        \\Function foo
        \\Function bar
    );
}

test "root container field" {
    try testDocumentSymbol(
        \\foo: u32,
    ,
        \\Field foo
    );
}

// https://github.com/zigtools/zls/issues/1583
test "builtin" {
    try testDocumentSymbol(
        \\comptime {
        \\    @abs();
        \\    @foo();
        \\    @foo
        \\}
        \\
    ,
        \\
    );
}

// https://github.com/zigtools/zls/issues/986
test "nested struct with self" {
    try testDocumentSymbol(
        \\const Foo = struct {
        \\    const Self = @This();
        \\    pub fn foo() !Self {}
        \\    const Bar = union {};
        \\};
    ,
        \\Struct Foo
        \\  Constant Self
        \\  Function foo (fn foo() !Self)
        \\  Struct Bar
    );
}

test "invalid top level enum literal" {
    try testDocumentSymbol(
        \\.foo: u32,
    ,
        \\
    );
}

test "decl names that are empty or contain whitespace return non-empty document symbol" {
    try testDocumentSymbol(
        \\test "" {}
        \\test "          " {}
        \\test " a " {}
        \\const @"" = 0;
        \\const @"   " = 0;
        \\const @" a " = 0;
    ,
        \\Function ""
        \\Function "          "
        \\Function " a "
        \\Constant @""
        \\Constant @"   "
        \\Constant @" a "
    );
}

test "nested function declarations" {
    try testDocumentSymbol(
        \\fn outer(_: struct {
        \\    fn foo() void {}
        \\}) void {
        \\    _ = struct {
        \\        fn inner() void {
        \\            //
        \\        }
        \\    };
        \\}
    ,
        \\Function outer (fn outer(_: struct {
        \\    fn foo() void {}
        \\}) void)
        \\  Function foo (fn foo() void)
        \\  Function inner (fn inner() void)
    );
}

test "zon" {
    try testZonDocumentSymbol(
        \\.{
        \\    .name = .zls,
        \\    .version = "0.15.0",
        \\    .fingerprint = 0xd80840b2c3f0c8f3,
        \\    .dependencies = .{
        \\        .known_folders = .{
        \\            .url = "https://example.com/archive.tar.gz",
        \\            .hash = "N-V-__AAAJC9AgCq",
        \\            .lazy = true,
        \\        },
        \\    },
        \\    .paths = .{
        \\        "build.zig",
        \\        "src",
        \\    },
        \\}
    ,
        \\EnumMember name
        \\String version
        \\Number fingerprint
        \\Module dependencies
        \\  Module known_folders
        \\    String url
        \\    String hash
        \\    Boolean lazy
        \\Array paths
        \\  String 0
        \\  String 1
    );
}

test "zon scalar values" {
    try testZonDocumentSymbol(
        \\.{
        \\    .enabled = true,
        \\    .disabled = false,
        \\    .nothing = null,
        \\    .offset = -42,
        \\    .not_a_number = nan,
        \\    .tag = .zls,
        \\    .empty = .{},
        \\}
    ,
        \\Boolean enabled
        \\Boolean disabled
        \\Null nothing
        \\Number offset
        \\Number not_a_number
        \\EnumMember tag
        \\Module empty
    );
}

test "zon root array" {
    try testZonDocumentSymbol(
        \\.{ 1, "two", .{ .three = 3 } }
    ,
        \\Number 0
        \\String 1
        \\Module 2
        \\  Number three
    );
}

test "zon with parse errors" {
    try testZonDocumentSymbol(
        \\.{ .a = }
    ,
        \\
    );
}

fn testDocumentSymbol(source: []const u8, expected: []const u8) !void {
    try testDocumentSymbolWithMode(source, expected, .zig);
}

fn testZonDocumentSymbol(source: []const u8, expected: []const u8) !void {
    try testDocumentSymbolWithMode(source, expected, .zon);
}

fn testDocumentSymbolWithMode(source: []const u8, expected: []const u8, mode: std.zig.Ast.Mode) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = source, .mode = mode });

    const params: types.DocumentSymbol.Params = .{
        .textDocument = .{ .uri = test_uri.raw },
    };

    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/documentSymbol", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var actual: std.ArrayList(u8) = .empty;
    defer actual.deinit(allocator);

    var stack_buffer: [16][]const types.DocumentSymbol = undefined;
    var stack: std.ArrayList([]const types.DocumentSymbol) = .initBuffer(&stack_buffer);
    stack.appendAssumeCapacity(response.document_symbols);

    while (stack.items.len > 0) {
        const depth = stack.items.len - 1;
        const top = stack.items[depth];
        if (top.len > 0) {
            try actual.appendNTimes(allocator, ' ', depth * 2);
            try actual.print(allocator, "{t} {s}", .{ top[0].kind, top[0].name });
            if (top[0].detail) |detail| try actual.print(allocator, " ({s})", .{detail});
            try actual.append(allocator, '\n');
            if (top[0].children) |children| {
                try stack.appendBounded(children);
            }
            stack.items[depth] = top[1..];
        } else {
            _ = stack.pop();
        }
    }
    _ = actual.pop(); // Final \n

    try std.testing.expectEqualStrings(expected, actual.items);
}
