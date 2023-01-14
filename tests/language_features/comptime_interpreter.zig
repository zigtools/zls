const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Ast = std.zig.Ast;

const ComptimeInterpreter = zls.ComptimeInterpreter;
const InternPool = zls.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - call return primitive type" {
    try testCallCheck(
        \\pub fn Foo() type {
        \\    return bool;
        \\}
    , &.{}, .{ .simple = .bool });

    try testCallCheck(
        \\pub fn Foo() type {
        \\    return u32;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    try testCallCheck(
        \\pub fn Foo() type {
        \\    return i128;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .signed, .bits = 128 } });

    try testCallCheck(
        \\pub fn Foo() type {
        \\    const alpha = i128;
        \\    return alpha;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .signed, .bits = 128 } });
}

test "ComptimeInterpreter - call return struct" {
    var result = try testCall(
        \\pub fn Foo() type {
        \\    return struct {
        \\        slay: bool,
        \\        var abc = 123;
        \\    };
        \\}
    , &.{});
    defer result.deinit();
    const struct_info = result.key.struct_type;
    try std.testing.expectEqual(Index.none, struct_info.backing_int_ty);
    try std.testing.expectEqual(std.builtin.Type.ContainerLayout.Auto, struct_info.layout);
    try std.testing.expectEqual(@as(usize, 1), struct_info.fields.len);
    // try std.testing.expectEqualStrings("slay", struct_info.fields[0].name);
    // try std.testing.expect(struct_info.fields[0].ty != .none); // TODO check for bool
}

test "ComptimeInterpreter - call comptime argument" {
    const source =
        \\pub fn Foo(comptime my_arg: bool) type {
        \\    var abc = z: {break :z if (!my_arg) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    ;

    var result1 = try testCall(source, &.{
        Value{
            .ty = .{ .simple = .bool },
            .val = .{ .simple = .bool_true },
        },
    });
    defer result1.deinit();
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 8 } }, result1.key);

    var result2 = try testCall(source, &.{
        Value{
            .ty = .{ .simple = .bool },
            .val = .{ .simple = .bool_false },
        },
    });
    defer result2.deinit();
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 69 } }, result2.key);
}

//
// Helper functions
//

const CallResult = struct {
    interpreter: ComptimeInterpreter,
    key: Key,

    pub fn deinit(self: *CallResult) void {
        self.interpreter.deinit();
    }
};

const Value = struct {
    ty: Key,
    val: Key,
};

fn testCall(source: []const u8, arguments: []const Value) !CallResult {
    var config = zls.Config{};
    var doc_store = zls.DocumentStore{
        .allocator = allocator,
        .config = &config,
    };
    defer doc_store.deinit();

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    const handle = try doc_store.openDocument(test_uri, source);

    var interpreter = ComptimeInterpreter{
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .document_store = &doc_store,
        .uri = handle.uri,
    };
    errdefer interpreter.deinit();

    _ = try interpreter.interpret(0, .none, .{});

    var args = try allocator.alloc(ComptimeInterpreter.Value, arguments.len);
    defer allocator.free(args);

    for (arguments) |argument, i| {
        args[i] = .{
            .interpreter = &interpreter,
            .node_idx = 0,
            .ty = try interpreter.ip.get(interpreter.allocator, argument.ty),
            .val = try interpreter.ip.get(interpreter.allocator, argument.val),
        };
    }

    const func_node = for (handle.tree.nodes.items(.tag)) |tag, i| {
        if (tag == .fn_decl) break @intCast(Ast.Node.Index, i);
    } else unreachable;

    const call_result = try interpreter.call(.none, func_node, args, .{});

    try std.testing.expectEqual(Key{ .simple = .type }, interpreter.ip.indexToKey(call_result.result.value.ty));

    return CallResult{
        .interpreter = interpreter,
        .key = interpreter.ip.indexToKey(call_result.result.value.val),
    };
}

fn testCallCheck(
    source: []const u8,
    arguments: []const Value,
    expected: Key,
) !void {
    var result = try testCall(source, arguments);
    defer result.deinit();
    try std.testing.expectEqual(expected, result.key);
}
