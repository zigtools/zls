const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Ast = std.zig.Ast;

const ComptimeInterpreter = zls.ComptimeInterpreter;
const InternPool = zls.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const ast = zls.ast;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - primitive types" {
    try testExprCheck("true", .{ .simple = .bool }, .{ .simple = .bool_true });
    try testExprCheck("false", .{ .simple = .bool }, .{ .simple = .bool_false });
    try testExprCheck("5", .{ .simple = .comptime_int }, .{ .int_u64_value = 5 });
    // TODO try testExprCheck("-2", .{ .simple = .comptime_int }, .{ .int_i64_value = -2 });
    try testExprCheck("3.0", .{ .simple = .comptime_float }, null);

    try testExprCheck("null", .{ .simple = .null_type }, .{ .simple = .null_value });
    try testExprCheck("void", .{ .simple = .type }, .{ .simple = .void });
    try testExprCheck("undefined", .{ .simple = .undefined_type }, .{ .simple = .undefined_value });
    try testExprCheck("noreturn", .{ .simple = .type }, .{ .simple = .noreturn });
}

test "ComptimeInterpreter - expressions" {
    if (true) return error.SkipZigTest; // TODO
    try testExprCheck("5 + 3", .{ .simple = .comptime_int }, .{ .int_u64_value = 8 });
    try testExprCheck("5.2 + 4.2", .{ .simple = .comptime_float }, null);

    try testExprCheck("3 == 3", .{ .simple = .bool }, .{ .simple = .bool_true });
    try testExprCheck("5.2 == 2.1", .{ .simple = .bool }, .{ .simple = .bool_false });

    try testExprCheck("@as(?bool, null) orelse true", .{ .simple = .bool }, .{ .simple = .bool_true });
}

test "ComptimeInterpreter - builtins" {
    if (true) return error.SkipZigTest; // TODO
    try testExprCheck("@as(bool, true)", .{ .simple = .bool }, .{ .simple = .bool_true });
    try testExprCheck("@as(u32, 3)", .{ .int_type = .{
        .signedness = .unsigned,
        .bits = 32,
    } }, .{ .int_u64_value = 3 });
}

test "ComptimeInterpreter - string literal" {
    const source =
        \\const foobarbaz = "hello world!";
        \\
    ;

    var result = try testInterpret(source, 1);
    defer result.deinit();

    try std.testing.expect(result.ty == .pointer_type);
    try std.testing.expect(result.val == .bytes);

    try std.testing.expectEqualStrings("hello world!", result.val.bytes);
}

test "ComptimeInterpreter - labeled block" {
    try testExprCheck(
        \\blk: {
        \\    break :blk true;
        \\}
    , .{ .simple = .bool }, .{ .simple = .bool_true });
}

test "ComptimeInterpreter - if" {
    try testExprCheck(
        \\blk: {
        \\    break :blk if (true) true else false;
        \\}
    , .{ .simple = .bool }, .{ .simple = .bool_true });
    try testExprCheck(
        \\blk: {
        \\    break :blk if (false) true else false;
        \\}
    , .{ .simple = .bool }, .{ .simple = .bool_false });
}

test "ComptimeInterpreter - field access" {
    if (true) return error.SkipZigTest; // TODO
    try testExprCheck(
        \\blk: {
        \\    const foo = struct {alpha: u32, beta: bool} = undefined;
        \\    break :blk foo.beta;
        \\}
    , .{ .simple = .bool }, null);
}

test "ComptimeInterpreter - pointer operations" {
    if (true) return error.SkipZigTest; // TODO
    try testExprCheck(
        \\blk: {
        \\    const foo: []const u8 = "";
        \\    break :blk foo.len;
        \\}
    , .{ .simple = .usize }, .{ .bytes = "" });
    try testExprCheck(
        \\blk: {
        \\    const foo = true;
        \\    break :blk &foo;
        \\}
    , @panic("TODO"), .{ .simple = .bool_true });
    try testExprCheck(
        \\blk: {
        \\    const foo = true;
        \\    const bar = &foo;
        \\    break :blk bar.*;
        \\}
    , @panic("TODO"), .{ .simple = .bool_true });
}

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
    try std.testing.expect(result.ty == .simple);
    try std.testing.expect(result.ty.simple == .type);
    const struct_info = result.val.struct_type;
    try std.testing.expectEqual(Index.none, struct_info.backing_int_ty);
    try std.testing.expectEqual(std.builtin.Type.ContainerLayout.Auto, struct_info.layout);

    const field_name = result.interpreter.ip.indexToKey(struct_info.fields[0].name).bytes;
    const bool_type = try result.interpreter.ip.get(allocator, .{ .simple = .bool });

    try std.testing.expectEqual(@as(usize, 1), struct_info.fields.len);
    try std.testing.expectEqualStrings("slay", field_name);
    try std.testing.expect(struct_info.fields[0].ty == bool_type);
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
    try std.testing.expect(result1.ty == .simple);
    try std.testing.expect(result1.ty.simple == .type);
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 8 } }, result1.val);

    var result2 = try testCall(source, &.{
        Value{
            .ty = .{ .simple = .bool },
            .val = .{ .simple = .bool_false },
        },
    });
    defer result2.deinit();
    try std.testing.expect(result2.ty == .simple);
    try std.testing.expect(result2.ty.simple == .type);
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 69 } }, result2.val);
}

//
// Helper functions
//

const Result = struct {
    interpreter: ComptimeInterpreter,
    ty: Key,
    val: Key,

    pub fn deinit(self: *Result) void {
        self.interpreter.deinit();
    }
};

const Value = struct {
    ty: Key,
    val: Key,
};

fn testCall(source: []const u8, arguments: []const Value) !Result {
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
        .document_store = &doc_store,
        .uri = handle.uri,
    };
    errdefer interpreter.deinit();

    _ = try interpretReportErrors(&interpreter, 0, .none);

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

    return Result{
        .interpreter = interpreter,
        .ty = interpreter.ip.indexToKey(call_result.result.value.ty),
        .val = interpreter.ip.indexToKey(call_result.result.value.val),
    };
}

fn testCallCheck(
    source: []const u8,
    arguments: []const Value,
    expected_ty: Key,
) !void {
    var result = try testCall(source, arguments);
    defer result.deinit();
    try std.testing.expect(result.ty == .simple);
    try std.testing.expect(result.ty.simple == .type);
    if (!expected_ty.eql(result.val)) {
        std.debug.print("expected type `{}`, found `{}`\n", .{ expected_ty.fmtType(result.interpreter.ip), result.val.fmtType(result.interpreter.ip) });
        return error.TestExpectedEqual;
    }
}

fn testInterpret(source: []const u8, node_idx: Ast.Node.Index) !Result {
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
        .document_store = &doc_store,
        .uri = handle.uri,
    };
    errdefer interpreter.deinit();

    _ = try interpretReportErrors(&interpreter, 0, .none);

    const result = try interpreter.interpret(node_idx, .none, .{});

    try std.testing.expect(result.value.ty != .none);
    try std.testing.expect(result.value.val != .none);

    return Result{
        .interpreter = interpreter,
        .ty = interpreter.ip.indexToKey(result.value.ty),
        .val = interpreter.ip.indexToKey(result.value.val),
    };
}

fn testExprCheck(
    expr: []const u8,
    expected_ty: Key,
    expected_val: ?Key,
) !void {
    const source = try std.fmt.allocPrint(allocator,
        \\const foobarbaz = {s};
    , .{expr});
    defer allocator.free(source);

    var result = try testInterpret(source, 1);
    defer result.deinit();
    var ip: *InternPool = &result.interpreter.ip;

    if (!expected_ty.eql(result.ty)) {
        std.debug.print("expected type `{}`, found `{}`\n", .{ expected_ty.fmtType(ip.*), result.ty.fmtType(ip.*) });
        return error.TestExpectedEqual;
    }

    if (expected_val) |expected_value| {
        if (!expected_value.eql(result.val)) {
            const expected_ty_index = try ip.get(allocator, expected_ty);
            const actual_ty_index = try ip.get(allocator, result.ty);
            std.debug.print("expected value `{}`, found `{}`\n", .{
                expected_value.fmtValue(expected_ty_index, ip.*),
                result.val.fmtValue(actual_ty_index, ip.*),
            });
            return error.TestExpectedEqual;
        }
    }
}

fn interpretReportErrors(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    namespace: InternPool.NamespaceIndex,
) !ComptimeInterpreter.InterpretResult {
    const result = interpreter.interpret(node_idx, namespace, .{});

    // TODO use ErrorBuilder
    var err_it = interpreter.errors.iterator();
    if (interpreter.errors.count() != 0) {
        const handle = interpreter.getHandle();
        std.debug.print("\n{s}\n", .{handle.text});
        while (err_it.next()) |entry| {
            const token = handle.tree.firstToken(entry.key_ptr.*);
            const position = offsets.tokenToPosition(handle.tree, token, .@"utf-8");
            std.debug.print("{d}:{d}: {s}\n", .{ position.line, position.character, entry.value_ptr.message });
        }
    }
    return result;
}
