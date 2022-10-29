const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

const ComptimeInterpreter = zls.ComptimeInterpreter;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - basic test" {
    var tree = try std.zig.parse(allocator,
        \\pub fn ReturnMyType(comptime my_arg: bool) type {
        \\    var abc = z: {break :z if (!my_arg) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    );
    defer tree.deinit(allocator);

    var interpreter = ComptimeInterpreter{ .tree = tree, .allocator = allocator };
    defer interpreter.deinit();

    var bool_type = try interpreter.createType(std.math.maxInt(std.zig.Ast.Node.Index), .{ .@"bool" = .{} });
    var arg_false = ComptimeInterpreter.Value{
        .node_idx = std.math.maxInt(std.zig.Ast.Node.Index),
        .@"type" = bool_type,
        .value_data = .{ .@"bool" = false },
    };
    var arg_true = ComptimeInterpreter.Value{
        .node_idx = std.math.maxInt(std.zig.Ast.Node.Index),
        .@"type" = bool_type,
        .value_data = .{ .@"bool" = true },
    };

    const call_with_false = try interpreter.call(tree.rootDecls()[0], &.{
        arg_false,
    }, .{});
    defer call_with_false.scope.deinit();
    const call_with_true = try interpreter.call(tree.rootDecls()[0], &.{
        arg_true,
    }, .{});
    defer call_with_true.scope.deinit();

    try std.testing.expectFmt("u69", "{any}", .{interpreter.formatTypeInfo(call_with_false.result.value.value_data.@"type".getTypeInfo())});
    try std.testing.expectFmt("u8", "{any}", .{interpreter.formatTypeInfo(call_with_true.result.value.value_data.@"type".getTypeInfo())});
}

test "ComptimeInterpreter - struct" {
    var tree = try std.zig.parse(allocator,
        \\pub fn ReturnMyType() type {
        \\    return struct {
        \\        slay: bool,
        \\        var abc = 123;
        \\    };
        \\}
    );
    defer tree.deinit(allocator);

    var interpreter = ComptimeInterpreter{ .tree = tree, .allocator = allocator };
    defer interpreter.deinit();

    const z = try interpreter.call(tree.rootDecls()[0], &.{}, .{});
    defer z.scope.deinit();

    try std.testing.expectFmt("struct {slay: bool, const abc: comptime_int = TODO_PRINT_VALUES, }", "{any}", .{interpreter.formatTypeInfo(interpreter.typeToTypeInfo(z.result.value.value_data.@"type"))});
}
