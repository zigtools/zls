const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Ast = std.zig.Ast;
const ComptimeInterpreter = zls.ComptimeInterpreter;
const InternPool = zls.analyser.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const ast = zls.ast;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "primitive types" {
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

test "expressions" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr("5 + 3", .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 8 } });
    // try testExpr("5.2 + 4.2", .{ .simple_type = .comptime_float }, null);

    try testExpr("3 == 3", .{ .simple_valueclear = .bool_true });
    try testExpr("5.2 == 2.1", .{ .simple_value = .bool_false });

    try testExpr("@as(?bool, null) orelse true", .{ .simple_value = .bool_true });
}

test "builtins" {
    if (true) return error.SkipZigTest; // TODO
    try testExpr("@as(bool, true)", .{ .simple_value = .bool_true });
    try testExpr("@as(u32, 3)", .{ .int_u64_value = .{ .ty = .u32_type, .int = 3 } });
}

test "@TypeOf" {
    try testExpr("@TypeOf(bool)", .{ .simple_type = .type });
    try testExpr("@TypeOf(5)", .{ .simple_type = .comptime_int });
    try testExpr("@TypeOf(3.14)", .{ .simple_type = .comptime_float });

    try testExpr("@TypeOf(bool, u32)", .{ .simple_type = .type });
    try testExpr("@TypeOf(true, false)", .{ .simple_type = .bool });
    try testExpr("@TypeOf(3, 2)", .{ .simple_type = .comptime_int });
    try testExpr("@TypeOf(3.14, 2)", .{ .simple_type = .comptime_float });

    try testExpr("@TypeOf(null, 2)", .{ .optional_type = .{ .payload_type = .comptime_int_type } });
}

test "string literal" {
    if (true) return error.SkipZigTest; // TODO
    var tester = try Tester.init(
        \\const foobarbaz = "hello world!";
        \\
    );
    defer tester.deinit();
    const result = try tester.interpret(tester.findVar("foobarbaz"));

    try std.testing.expect(result.ty == .pointer_type);

    try std.testing.expectEqualStrings("hello world!", result.val.?.bytes);
}

test "labeled block" {
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

test "if" {
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

test "variable lookup" {
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

    var tester = try Tester.init(
        \\const bar = foo;
        \\const foo = 3;
    );
    defer tester.deinit();

    const result = try tester.interpret(tester.findVar("bar"));
    try std.testing.expect(result.val.?.eql(Key{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 3 } }, tester.ip));
}

test "field access" {
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

test "optional operations" {
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

test "pointer operations" {
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

test "call return primitive type" {
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

test "call return struct" {
    var tester = try Tester.init(
        \\pub fn Foo() type {
        \\    return struct {
        \\        slay: bool,
        \\        var abc = 123;
        \\    };
        \\}
    );
    defer tester.deinit();
    const result = try tester.call(tester.findFn("Foo"), &.{});

    try std.testing.expect(result.ty == .simple_type);
    try std.testing.expect(result.ty.simple_type == .type);
    const struct_info = tester.ip.getStruct(result.val.?.struct_type);
    try std.testing.expectEqual(Index.none, struct_info.backing_int_ty);
    try std.testing.expectEqual(std.builtin.Type.ContainerLayout.Auto, struct_info.layout);

    try std.testing.expectEqual(@as(usize, 1), struct_info.fields.count());
    try std.testing.expectFmt("slay", "{}", .{tester.ip.fmtId(struct_info.fields.keys()[0])});
    try std.testing.expect(struct_info.fields.values()[0].ty == Index.bool_type);
}

test "call comptime argument" {
    var tester = try Tester.init(
        \\pub fn Foo(comptime my_arg: bool) type {
        \\    var abc = z: {break :z if (!my_arg) 123 else 0;};
        \\    if (abc == 123) return u69;
        \\    return u8;
        \\}
    );
    defer tester.deinit();

    const result1 = try tester.call(tester.findFn("Foo"), &.{KV{
        .ty = .{ .simple_type = .bool },
        .val = .{ .simple_value = .bool_true },
    }});
    try std.testing.expect(result1.ty == .simple_type);
    try std.testing.expect(result1.ty.simple_type == .type);
    try std.testing.expect(result1.val.?.eql(Key{ .int_type = .{ .signedness = .unsigned, .bits = 8 } }, tester.ip));

    const result2 = try tester.call(tester.findFn("Foo"), &.{KV{
        .ty = .{ .simple_type = .bool },
        .val = .{ .simple_value = .bool_false },
    }});
    try std.testing.expect(result2.ty == .simple_type);
    try std.testing.expect(result2.ty.simple_type == .type);
    try std.testing.expect(result2.val.?.eql(Key{ .int_type = .{ .signedness = .unsigned, .bits = 69 } }, tester.ip));
}

test "call inner function" {
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

pub const Tester = struct {
    context: Context,
    handle: *zls.DocumentStore.Handle,
    ip: *zls.analyser.InternPool,
    interpreter: *zls.ComptimeInterpreter,

    const Context = @import("../context.zig").Context;

    pub fn init(source: []const u8) !Tester {
        var context = try Context.init();
        errdefer context.deinit();

        const uri = try context.addDocument(source);
        const handle = context.server.document_store.getHandle(uri).?;
        const interpreter = try handle.getComptimeInterpreter(&context.server.document_store, &context.server.ip);

        // TODO report handle.tree.errors
        _ = try interpreter.interpret(0, .none, .{});
        // TODO report handle.analysis_errors

        return .{
            .context = context,
            .handle = handle,
            .ip = &context.server.ip,
            .interpreter = interpreter,
        };
    }

    pub fn deinit(self: *Tester) void {
        self.context.deinit();
        self.* = undefined;
    }

    pub fn call(self: *Tester, func_node: Ast.Node.Index, arguments: []const KV) !KV {
        var args = try allocator.alloc(ComptimeInterpreter.Value, arguments.len);
        defer allocator.free(args);

        for (arguments, 0..) |argument, i| {
            args[i] = .{
                .interpreter = self.interpreter,
                .node_idx = 0,
                .index = if (argument.val) |val|
                    try self.ip.get(allocator, val)
                else
                    try self.ip.get(allocator, .{
                        .unknown_value = .{ .ty = try self.ip.get(allocator, argument.ty) },
                    }),
            };
        }

        const namespace: ComptimeInterpreter.Namespace.Index = @enumFromInt(0); // root namespace
        const result = (try self.interpreter.call(namespace, func_node, args, .{})).result;

        const val = result.value.index;
        const ty = self.ip.typeOf(val);

        return KV{
            .ty = self.ip.indexToKey(ty),
            .val = self.ip.indexToKey(val),
        };
    }

    pub fn interpret(self: *Tester, node: Ast.Node.Index) !KV {
        const namespace: ComptimeInterpreter.Namespace.Index = @enumFromInt(0); // root namespace
        const result = try (try self.interpreter.interpret(node, namespace, .{})).getValue();

        const val = result.index;
        const ty = self.ip.typeOf(val);

        return KV{
            .ty = self.ip.indexToKey(ty),
            .val = self.ip.indexToKey(val),
        };
    }

    pub fn findFn(self: Tester, name: []const u8) Ast.Node.Index {
        const handle = self.handle;
        for (handle.tree.nodes.items(.tag), 0..) |tag, i| {
            if (tag != .fn_decl) continue;
            const node: Ast.Node.Index = @intCast(i);
            var buffer: [1]Ast.Node.Index = undefined;
            const fn_decl = handle.tree.fullFnProto(&buffer, node).?;
            const fn_name = offsets.tokenToSlice(handle.tree, fn_decl.name_token.?);
            if (std.mem.eql(u8, fn_name, name)) return node;
        }
        std.debug.panic("failed to find function with name '{s}'", .{name});
    }

    pub fn findVar(self: Tester, name: []const u8) Ast.Node.Index {
        const handle = self.handle;
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
    var tester = try Tester.init(source);
    defer tester.deinit();

    const result = try tester.call(tester.findFn("Foo"), arguments);

    const ty = try tester.ip.get(allocator, result.ty);
    const val = if (result.val) |key| try tester.ip.get(allocator, key) else .none;
    const expected_ty_index = try tester.ip.get(allocator, expected_ty);

    try expectEqualIndex(tester.ip, .type_type, ty);
    try expectEqualIndex(tester.ip, expected_ty_index, val);
}

fn testExpr(
    expr: []const u8,
    expected: Key,
) !void {
    const source = try std.fmt.allocPrint(allocator,
        \\const foobarbaz = {s};
    , .{expr});
    defer allocator.free(source);

    var tester = try Tester.init(source);
    defer tester.deinit();

    const result = try tester.interpret(tester.findVar("foobarbaz"));

    const expected_index = try tester.ip.get(allocator, expected);
    const val = if (result.val) |key| try tester.ip.get(allocator, key) else .none;

    try expectEqualIndex(tester.ip, expected_index, val);
}

fn expectEqualIndex(ip: *InternPool, expected: Index, actual: Index) !void {
    if (expected == actual) return;
    std.debug.print("expected `{}`, found `{}`\n", .{ expected.fmtDebug(ip), actual.fmtDebug(ip) });
    return error.TestExpectedEqual;
}
