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
        \\  Function f
    );
    try testDocumentSymbol(
        \\const S = struct {
        \\    alpha: u32,
        \\    fn f() void {}
        \\};
    ,
        \\Constant S
        \\  Field alpha
        \\  Function f
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

test "enum" {
    try testDocumentSymbol(
        \\const E = enum {
        \\    alpha,
        \\    beta,
        \\};
    ,
        \\Constant E
        \\  EnumMember alpha
        \\  EnumMember beta
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
        \\  Function foo
        \\  Constant Bar
    );
}

fn testDocumentSymbol(source: []const u8, expected: []const u8) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(.{ .source = source });

    const params: types.DocumentSymbolParams = .{
        .textDocument = .{ .uri = test_uri },
    };

    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/documentSymbol", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var actual: std.ArrayList(u8) = .empty;
    defer actual.deinit(allocator);

    var stack_buffer: [16][]const types.DocumentSymbol = undefined;
    var stack: std.ArrayList([]const types.DocumentSymbol) = .initBuffer(&stack_buffer);
    stack.appendAssumeCapacity(response.array_of_DocumentSymbol);

    while (stack.items.len > 0) {
        const depth = stack.items.len - 1;
        const top = stack.items[depth];
        if (top.len > 0) {
            try actual.appendNTimes(allocator, ' ', depth * 2);
            try actual.print(allocator, "{t} {s}\n", .{ top[0].kind, top[0].name });
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
