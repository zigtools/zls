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
        \\Constant S
        \\  Function f (fn f() void)
    );
    try testDocumentSymbol(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f() void {}
        \\};
    ,
        \\Constant S
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
        \\Constant S
    );
}

test "union" {
    try testDocumentSymbol(
        \\const U = union {
        \\    alpha: u32,
        \\    beta,
        \\};
    ,
        \\Constant U
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
        \\Constant E
        \\  EnumMember alpha (E)
        \\  EnumMember beta (E)
    );
}

test "invalid tuple-like container" {
    try testDocumentSymbol(
        \\const E = enum {
        \\    '=',
        \\};
    ,
        \\Constant E
    );
    try testDocumentSymbol(
        \\const E = enum {
        \\    @src
        \\};
    ,
        \\Constant E
    );
    try testDocumentSymbol(
        \\const U = union {
        \\    '=',
        \\};
    ,
        \\Constant U
    );
    try testDocumentSymbol(
        \\const U = union(enum) {
        \\    '=',
        \\};
    ,
        \\Constant U
    );
}

test "test decl" {
    try testDocumentSymbol(
        \\test foo {}
        \\test "bar" {}
        \\test {}
    ,
        \\Method foo
        \\Method bar
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
        \\Constant Foo
        \\  Constant Self
        \\  Function foo (fn foo() !Self)
        \\  Constant Bar
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
        \\Method ""
        \\Method "          "
        \\Method " a "
        \\Constant @""
        \\Constant @"   "
        \\Constant @" a "
    );
}

fn testDocumentSymbol(source: []const u8, expected: []const u8) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = source });

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
