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
        .document_store = &doc_store,
        .uri = "file:///file.zig",
    };
    defer interpreter.deinit();

    _ = try interpreter.interpret(0, null, .{});

    var bool_type = try interpreter.createType(std.math.maxInt(std.zig.Ast.Node.Index), .{ .@"bool" = {} });
    var arg_false = ComptimeInterpreter.Value{
        .interpreter = &interpreter,
        .node_idx = std.math.maxInt(std.zig.Ast.Node.Index),
        .@"type" = bool_type,
        .value_data = try interpreter.createValueData(.{ .@"bool" = false }),
    };
    var arg_true = ComptimeInterpreter.Value{
        .interpreter = &interpreter,
        .node_idx = std.math.maxInt(std.zig.Ast.Node.Index),
        .@"type" = bool_type,
        .value_data = try interpreter.createValueData(.{ .@"bool" = true }),
    };

    const rmt = interpreter.root_type.?.getTypeInfo().@"struct".scope.declarations.get("ReturnMyType").?;

    const call_with_false = try interpreter.call(null, rmt.node_idx, &.{
        arg_false,
    }, .{});
    defer call_with_false.scope.deinit();
    const call_with_true = try interpreter.call(null, rmt.node_idx, &.{
        arg_true,
    }, .{});
    defer call_with_true.scope.deinit();

    try std.testing.expectFmt("u69", "{any}", .{interpreter.formatTypeInfo(call_with_false.result.value.value_data.@"type".getTypeInfo())});
    try std.testing.expectFmt("u8", "{any}", .{interpreter.formatTypeInfo(call_with_true.result.value.value_data.@"type".getTypeInfo())});
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
        .document_store = &doc_store,
        .uri = "file:///file.zig",
    };
    defer interpreter.deinit();

    _ = try interpreter.interpret(0, null, .{});

    const rmt = interpreter.root_type.?.getTypeInfo().@"struct".scope.declarations.get("ReturnMyType").?;

    const z = try interpreter.call(null, rmt.node_idx, &.{}, .{});
    defer z.scope.deinit();

    try std.testing.expectFmt("struct {slay: bool, var abc: comptime_int = 123, }", "{any}", .{interpreter.formatTypeInfo(z.result.value.value_data.@"type".getTypeInfo())});
}
