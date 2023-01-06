const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

const ComptimeInterpreter = zls.ComptimeInterpreter;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - basic test" {
    var config = zls.Config{};
    var doc_store = zls.DocumentStore{
        .allocator = allocator,
        .config = &config,
    };
    defer doc_store.deinit();

    _ = try doc_store.openDocument("file:///file.zig",
        \\pub fn ReturnMyType(comptime my_arg: bool) type {
        \\    var abc = z: {break :z if (!my_arg) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    );

    var interpreter = ComptimeInterpreter{
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .document_store = &doc_store,
        .uri = "file:///file.zig",
    };
    defer interpreter.deinit();

    _ = try interpreter.interpret(0, 0, .{});

    var bool_type = try interpreter.ip.get(allocator, .{ .simple = .bool });
    var bool_true = try interpreter.ip.get(allocator, .{ .simple = .bool_true });
    var bool_false = try interpreter.ip.get(allocator, .{ .simple = .bool_false });

    var arg_false = ComptimeInterpreter.Value{
        .interpreter = &interpreter,
        .node_idx = std.math.maxInt(Ast.Node.Index),
        .ty = bool_type,
        .val = bool_false,
    };
    var arg_true = ComptimeInterpreter.Value{
        .interpreter = &interpreter,
        .node_idx = std.math.maxInt(Ast.Node.Index),
        .ty = bool_type,
        .val = bool_true,
    };

    const function_node: Ast.Node.Index = 4;

    const call_with_false = try interpreter.call(0, function_node, &.{arg_false}, .{});
    const call_with_true = try interpreter.call(0, function_node, &.{arg_true}, .{});

    try std.testing.expectFmt("u69", "{any}", .{call_with_false.result.value.val.fmtValue(call_with_false.result.value.ty, &interpreter.ip)});
    try std.testing.expectFmt("u8", "{any}", .{call_with_true.result.value.val.fmtValue(call_with_true.result.value.ty, &interpreter.ip)});
}

test "ComptimeInterpreter - struct" {
    var config = zls.Config{};
    var doc_store = zls.DocumentStore{
        .allocator = allocator,
        .config = &config,
    };
    defer doc_store.deinit();

    _ = try doc_store.openDocument("file:///file.zig",
        \\pub fn ReturnMyType() type {
        \\    return struct {
        \\        slay: bool,
        \\        var abc = 123;
        \\    };
        \\}
    );

    var interpreter = ComptimeInterpreter{
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .document_store = &doc_store,
        .uri = "file:///file.zig",
    };
    defer interpreter.deinit();

    _ = try interpreter.interpret(0, 0, .{});

    const function_node: Ast.Node.Index = 3;

    const call_result = try interpreter.call(0, function_node, &.{}, .{});

    const result_struct = interpreter.ip.indexToKey(call_result.result.value.val).struct_type;
    
    try std.testing.expectEqual(@intCast(usize, 1), result_struct.fields.len);
    try std.testing.expectEqualStrings("slay", result_struct.fields[0].name);
    try std.testing.expectFmt("bool", "{}", .{result_struct.fields[0].ty.fmtType(&interpreter.ip)});
}
