const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

const ComptimeInterpreter = zls.ComptimeInterpreter;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - basic test" {
    var tree = try std.zig.parse(allocator,
        \\pub fn ReturnMyType() type {
        \\    var abc = z: {break :z if (!false) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    );
    defer tree.deinit(allocator);

    var interpreter = ComptimeInterpreter{ .tree = tree, .allocator = allocator };
    defer interpreter.deinit();

    const z = try interpreter.call(tree.rootDecls()[0], &.{}, .{});
    defer z.scope.deinit();

    try std.testing.expectFmt("u69", "{any}", .{interpreter.formatTypeInfo(interpreter.typeToTypeInfo(z.result.value.value_data.@"type"))});
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
