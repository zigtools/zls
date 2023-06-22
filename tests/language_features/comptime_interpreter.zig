const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Ast = std.zig.Ast;
const ZigVersionWrapper = zls.ZigVersionWrapper;
const ComptimeInterpreter = zls.ComptimeInterpreter;
const InternPool = zls.analyser.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const ast = zls.ast;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "ComptimeInterpreter - primitive types" {
    try testExpr("true", .{ .simple_value = .bool_true });
    try testExpr("false", .{ .simple_value = .bool_false });
    try testExpr("5", .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 5 } });
    // TODO try testExpr("-2", .{ .int_i64_value = .{ .ty = .comptime_int, .int = -2 } });
    try testExpr("3.0", .{ .float_comptime_value = 3.0 });

    try testExpr("null", .{ .simple_value = .null_value });
    try testExpr("void", .{ .simple_type = .void });
    try testExpr("undefined", .{ .simple_value = .undefined_value });
    try testExpr("noreturn", .{ .simple_type = .noreturn });
}

test "ComptimeInterpreter - expressions" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr("5 + 3", .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 8 } });
    // try testExpr("5.2 + 4.2", .{ .simple_type = .comptime_float }, null);

    try testExpr("3 == 3", .{ .simple_valueclear = .bool_true });
    try testExpr("5.2 == 2.1", .{ .simple_value = .bool_false });

    try testExpr("@as(?bool, null) orelse true", .{ .simple_value = .bool_true });
}

test "ComptimeInterpreter - builtins" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr("@as(bool, true)", .{ .simple_value = .bool_true });
    try testExpr("@as(u32, 3)", .{ .int_u64_value = .{ .ty = .u32_type, .int = 3 } });
}

test "ComptimeInterpreter - @TypeOf" {
    try testExpr("@TypeOf(bool)", .{ .simple_type = .type });
    try testExpr("@TypeOf(5)", .{ .simple_type = .comptime_int });
    try testExpr("@TypeOf(3.14)", .{ .simple_type = .comptime_float });

    try testExpr("@TypeOf(bool, u32)", .{ .simple_type = .type });
    try testExpr("@TypeOf(true, false)", .{ .simple_type = .bool });
    try testExpr("@TypeOf(3, 2)", .{ .simple_type = .comptime_int });
    try testExpr("@TypeOf(3.14, 2)", .{ .simple_type = .comptime_float });

    try testExpr("@TypeOf(null, 2)", .{ .optional_type = .{ .payload_type = .comptime_int_type } });
}

test "ComptimeInterpreter - string literal" {
    if (true) return error.SkipZigTest; // TODO
    var context = try Context.init(
        \\const foobarbaz = "hello world!";
        \\
    );
    defer context.deinit();
    const result = try context.interpret(context.findVar("foobarbaz"));

    try std.testing.expect(result.ty == .pointer_type);

    try std.testing.expectEqualStrings("hello world!", result.val.?.bytes);
}

test "ComptimeInterpreter - labeled block" {
    try testExpr(
        \\blk: {
        \\    break :blk true;
        \\}
    , .{ .simple_value = .bool_true });
    try testExpr(
        \\blk: {
        \\    break :blk 3;
        \\}
    , .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 3 } });
}

test "ComptimeInterpreter - if" {
    try testExpr(
        \\blk: {
        \\    break :blk if (true) true else false;
        \\}
    , .{ .simple_value = .bool_true });
    try testExpr(
        \\blk: {
        \\    break :blk if (false) true else false;
        \\}
    , .{ .simple_value = .bool_false });
    try testExpr(
        \\blk: {
        \\    if (false) break :blk true;
        \\    break :blk false;
        \\}
    , .{ .simple_value = .bool_false });
    // TODO
    // try testExpr(
    //     \\outer: {
    //     \\    if (:inner {
    //     \\        break :inner true;
    //     \\    }) break :outer true;
    //     \\    break :outer false;
    //     \\}
    // , .{ .simple_value = .bool_true });
}

test "ComptimeInterpreter - variable lookup" {
    try testExpr(
        \\blk: {
        \\    var foo = 42;
        \\    break :blk foo;
        \\}
    , .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 42 } });
    try testExpr(
        \\blk: {
        \\    var foo = 1;
        \\    var bar = 2;
        \\    var baz = 3;
        \\    break :blk bar;
        \\}
    , .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 2 } });

    var context = try Context.init(
        \\const bar = foo;
        \\const foo = 3;
    );
    defer context.deinit();

    const result = try context.interpret(context.findVar("bar"));
    try expectEqualKey(context.interpreter.ip.*, .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 3 } }, result.val);
}

test "ComptimeInterpreter - field access" {
    try testExpr(
        \\blk: {
        \\    const foo: struct {alpha: u64, beta: bool} = undefined;
        \\    break :blk @TypeOf(foo.beta);
        \\}
    , .{ .simple_type = .bool });
    try testExpr(
        \\blk: {
        \\    const foo: struct {alpha: u64, beta: bool} = undefined;
        \\    break :blk @TypeOf(foo.alpha);
        \\}
    , .{ .int_type = .{
        .signedness = .unsigned,
        .bits = 64,
    } });
}

test "ComptimeInterpreter - optional operations" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr(
        \\blk: {
        \\    const foo: ?bool = true;
        \\    break :blk foo.?;
        \\}
    , .{ .simple_value = .bool_true });
    try testExpr(
        \\blk: {
        \\    const foo: ?bool = true;
        \\    break :blk foo == null;
        \\}
    , .{ .simple_value = .bool_false });
}

test "ComptimeInterpreter - pointer operations" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr(
        \\blk: {
        \\    const foo: []const u8 = "";
        \\    break :blk foo.len;
        \\}
    , .{ .int_u64_value = .{ .ty = .usize_type, .int = 0 } });
    try testExpr(
        \\blk: {
        \\    const foo = true;
        \\    break :blk &foo;
        \\}
    , .{ .simple_value = .bool_true });
    try testExpr(
        \\blk: {
        \\    const foo = true;
        \\    const bar = &foo;
        \\    break :blk bar.*;
        \\}
    , .{ .simple_value = .bool_true });
}

test "ComptimeInterpreter - call return primitive type" {
    try testCall(
        \\pub fn Foo() type {
        \\    return bool;
        \\}
    , &.{}, .{ .simple_type = .bool });

    try testCall(
        \\pub fn Foo() type {
        \\    return u32;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    try testCall(
        \\pub fn Foo() type {
        \\    return i128;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .signed, .bits = 128 } });

    try testCall(
        \\pub fn Foo() type {
        \\    const alpha = i128;
        \\    return alpha;
        \\}
    , &.{}, .{ .int_type = .{ .signedness = .signed, .bits = 128 } });
}

test "ComptimeInterpreter - call return struct" {
    var context = try Context.init(
        \\pub fn Foo() type {
        \\    return struct {
        \\        slay: bool,
        \\        var abc = 123;
        \\    };
        \\}
    );
    defer context.deinit();
    const result = try context.call(context.findFn("Foo"), &.{});

    try std.testing.expect(result.ty == .simple_type);
    try std.testing.expect(result.ty.simple_type == .type);
    const struct_info = context.interpreter.ip.getStruct(result.val.?.struct_type);
    try std.testing.expectEqual(Index.none, struct_info.backing_int_ty);
    try std.testing.expectEqual(std.builtin.Type.ContainerLayout.Auto, struct_info.layout);

    try std.testing.expectEqual(@as(usize, 1), struct_info.fields.count());
    try std.testing.expectEqualStrings("slay", struct_info.fields.keys()[0]);
    try std.testing.expect(struct_info.fields.values()[0].ty == Index.bool_type);
}

test "ComptimeInterpreter - call comptime argument" {
    var context = try Context.init(
        \\pub fn Foo(comptime my_arg: bool) type {
        \\    var abc = z: {break :z if (!my_arg) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    );
    defer context.deinit();

    const result1 = try context.call(context.findFn("Foo"), &.{KV{
        .ty = .{ .simple_type = .bool },
        .val = .{ .simple_value = .bool_true },
    }});
    try std.testing.expect(result1.ty == .simple_type);
    try std.testing.expect(result1.ty.simple_type == .type);
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 8 } }, result1.val.?);

    var result2 = try context.call(context.findFn("Foo"), &.{KV{
        .ty = .{ .simple_type = .bool },
        .val = .{ .simple_value = .bool_false },
    }});
    try std.testing.expect(result2.ty == .simple_type);
    try std.testing.expect(result2.ty.simple_type == .type);
    try std.testing.expectEqual(Key{ .int_type = .{ .signedness = .unsigned, .bits = 69 } }, result2.val.?);
}

test "ComptimeInterpreter - call inner function" {
    try testCall(
        \\pub fn Inner() type {
        \\    return bool;
        \\}
        \\pub fn Foo() type {
        \\    return Inner();
        \\}
    , &.{}, .{ .simple_type = .bool });
}

//
// Helper functions
//

const KV = struct {
    ty: Key,
    val: ?Key,
};

const Context = struct {
    config: *zls.Config,
    document_store: *zls.DocumentStore,
    ip: *InternPool,
    interpreter: *ComptimeInterpreter,

    pub fn init(source: []const u8) !Context {
        var config = try allocator.create(zls.Config);
        errdefer allocator.destroy(config);

        var document_store = try allocator.create(zls.DocumentStore);
        errdefer allocator.destroy(document_store);

        var interpreter = try allocator.create(ComptimeInterpreter);
        errdefer allocator.destroy(interpreter);

        var ip = try allocator.create(InternPool);
        errdefer allocator.destroy(ip);

        ip.* = try InternPool.init(allocator);
        errdefer ip.deinit(allocator);

        config.* = .{};
        document_store.* = .{
            .allocator = allocator,
            .config = config,
            .runtime_zig_version = &@as(?ZigVersionWrapper, null),
        };
        errdefer document_store.deinit();

        const test_uri: []const u8 = switch (builtin.os.tag) {
            .windows => "file:///C:\\test.zig",
            else => "file:///test.zig",
        };

        const handle = try document_store.openDocument(test_uri, try document_store.allocator.dupeZ(u8, source));

        // TODO handle handle.tree.errors

        interpreter.* = .{
            .allocator = allocator,
            .ip = ip,
            .document_store = document_store,
            .uri = handle.uri,
        };
        errdefer interpreter.deinit();

        _ = try interpreter.interpret(0, .none, .{});
        // _ = reportErrors(interpreter);

        return .{
            .config = config,
            .document_store = document_store,
            .ip = ip,
            .interpreter = interpreter,
        };
    }

    pub fn deinit(self: *Context) void {
        self.interpreter.deinit();
        self.document_store.deinit();
        self.ip.deinit(allocator);

        allocator.destroy(self.config);
        allocator.destroy(self.document_store);
        allocator.destroy(self.interpreter);
        allocator.destroy(self.ip);
    }

    pub fn call(self: *Context, func_node: Ast.Node.Index, arguments: []const KV) !KV {
        var args = try allocator.alloc(ComptimeInterpreter.Value, arguments.len);
        defer allocator.free(args);

        for (arguments, 0..) |argument, i| {
            args[i] = .{
                .interpreter = self.interpreter,
                .node_idx = 0,
                .index = if (argument.val) |val|
                    try self.interpreter.ip.get(self.interpreter.allocator, val)
                else
                    try self.interpreter.ip.get(self.interpreter.allocator, .{
                        .unknown_value = .{ .ty = try self.interpreter.ip.get(self.interpreter.allocator, argument.ty) },
                    }),
            };
        }

        const namespace = @enumFromInt(ComptimeInterpreter.Namespace.Index, 0); // root namespace
        const result = (try self.interpreter.call(namespace, func_node, args, .{})).result;

        const val = self.interpreter.ip.indexToKey(result.value.index);
        const ty = self.interpreter.ip.indexToKey(val.typeOf());

        return KV{
            .ty = ty,
            .val = val,
        };
    }

    pub fn interpret(self: *Context, node: Ast.Node.Index) !KV {
        const namespace = @enumFromInt(ComptimeInterpreter.Namespace.Index, 0); // root namespace
        const result = try (try self.interpreter.interpret(node, namespace, .{})).getValue();

        const val = self.interpreter.ip.indexToKey(result.index);
        const ty = self.interpreter.ip.indexToKey(val.typeOf());

        return KV{
            .ty = ty,
            .val = val,
        };
    }

    pub fn findFn(self: Context, name: []const u8) Ast.Node.Index {
        const handle = self.interpreter.getHandle();
        for (handle.tree.nodes.items(.tag), 0..) |tag, i| {
            if (tag != .fn_decl) continue;
            const node = @intCast(Ast.Node.Index, i);
            var buffer: [1]Ast.Node.Index = undefined;
            const fn_decl = handle.tree.fullFnProto(&buffer, node).?;
            const fn_name = offsets.tokenToSlice(handle.tree, fn_decl.name_token.?);
            if (std.mem.eql(u8, fn_name, name)) return node;
        }
        std.debug.panic("failed to find function with name '{s}'", .{name});
    }

    pub fn findVar(self: Context, name: []const u8) Ast.Node.Index {
        const handle = self.interpreter.getHandle();
        var node: Ast.Node.Index = 0;
        while (node < handle.tree.nodes.len) : (node += 1) {
            const var_decl = handle.tree.fullVarDecl(node) orelse continue;
            const name_token = var_decl.ast.mut_token + 1;
            const var_name = offsets.tokenToSlice(handle.tree, name_token);
            if (std.mem.eql(u8, var_name, name)) return var_decl.ast.init_node;
        }
        std.debug.panic("failed to find var declaration with name '{s}'", .{name});
    }
};

fn testCall(
    source: []const u8,
    arguments: []const KV,
    expected_ty: Key,
) !void {
    var context = try Context.init(source);
    defer context.deinit();

    const result = try context.call(context.findFn("Foo"), arguments);

    try expectEqualKey(context.interpreter.ip.*, Key{ .simple_type = .type }, result.ty);
    try expectEqualKey(context.interpreter.ip.*, expected_ty, result.val);
}

fn testExpr(
    expr: []const u8,
    expected: Key,
) !void {
    const source = try std.fmt.allocPrint(allocator,
        \\const foobarbaz = {s};
    , .{expr});
    defer allocator.free(source);

    var context = try Context.init(source);
    defer context.deinit();

    const result = try context.interpret(context.findVar("foobarbaz"));

    try expectEqualKey(context.interpreter.ip.*, expected, result.val);
}

fn expectEqualKey(ip: InternPool, expected: Key, actual: ?Key) !void {
    if (actual) |actual_key| {
        if (!expected.eql(actual_key)) {
            std.debug.print("expected `{}`, found `{}`\n", .{ expected.fmt(ip), actual_key.fmt(ip) });
            return error.TestExpectedEqual;
        }
    } else {
        std.debug.print("expected `{}`, found null\n", .{expected.fmt(ip)});
        return error.TestExpectedEqual;
    }
}

fn reportErrors(interpreter: *ComptimeInterpreter) void {
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
}
