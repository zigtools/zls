const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "semantic tokens - empty" {
    try testSemanticTokens("", &.{});
}

test "semantic tokens - comment" {
    try testSemanticTokens(
        \\// hello world
    , &.{
        .{ "// hello world", .comment, .{} },
    });
    try testSemanticTokens(
        \\//! hello world
        \\
    , &.{
        .{ "//! hello world", .comment, .{ .documentation = true } },
    });
    try testSemanticTokens(
        \\//! first line
        \\//! second line
        \\
    , &.{
        .{ "//! first line", .comment, .{ .documentation = true } },
        .{ "//! second line", .comment, .{ .documentation = true } },
    });
    try testSemanticTokens(
        \\/// hello world
        \\const a;
    , &.{
        .{ "/// hello world", .comment, .{ .documentation = true } },
        .{ "const", .keyword, .{} },
        .{ "a", .variable, .{ .declaration = true } },
    });
}

test "semantic tokens - string literals" {
    try testSemanticTokens(
        \\const alpha = "";
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "\"\"", .string, .{} },
    });
    try testSemanticTokens(
        \\const beta = "hello";
    , &.{
        .{ "const", .keyword, .{} },
        .{ "beta", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "\"hello\"", .string, .{} },
    });
    try testSemanticTokens(
        \\const gamma =
        \\    \\hello
        \\    \\world
        \\    \\
        \\;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "gamma", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        // TODO remove the newline
        .{ "\\\\hello\n", .string, .{} },
        .{ "\\\\world\n", .string, .{} },
        .{ "\\\\\n", .string, .{} },
    });
}

test "semantic tokens - type literals" {
    try testSemanticTokens(
        \\bool,
        \\f16,
        \\u8,
        \\u15,
    , &.{
        .{ "bool", .type, .{} },
        .{ "f16", .type, .{} },
        .{ "u8", .type, .{} },
        .{ "u15", .type, .{} },
    });
}

test "semantic tokens - value literals" {
    try testSemanticTokens(
        \\true,
        \\false,
        \\undefined,
        \\null,
    , &.{
        .{ "true", .keywordLiteral, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "undefined", .keywordLiteral, .{} },
        .{ "null", .keywordLiteral, .{} },
    });
}

test "semantic tokens - char literals" {
    try testSemanticTokens(
        \\var alpha = ' ';
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "' '", .string, .{} },
    });
}

test "semantic tokens - var decl" {
    try testSemanticTokens(
        \\var alpha = 3;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\threadlocal var alpha = 3;
    , &.{
        .{ "threadlocal", .keyword, .{} },
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\extern var alpha: u32;
    , &.{
        .{ "extern", .keyword, .{} },
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\pub extern var alpha = 3;
    , &.{
        .{ "pub", .keyword, .{} },
        .{ "extern", .keyword, .{} },
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
    });
}

test "semantic tokens - var decl destructure" {
    try testSemanticTokens(
        \\const foo = {
        \\    var alpha: bool, var beta = .{ 1, 2 };
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "bool", .type, .{} },
        .{ "var", .keyword, .{} },
        .{ "beta", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
    });
}

test "semantic tokens - local var decl" {
    try testSemanticTokens(
        \\const alpha = {
        \\    comptime var beta: u32 = 3;
        \\};
        \\
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "comptime", .keyword, .{} },
        .{ "var", .keyword, .{} },
        .{ "beta", .variable, .{ .declaration = true } },
        .{ "u32", .type, .{} },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
    });
}

test "semantic tokens - escaped identifier" {
    try testSemanticTokens(
        \\var @"@" = 3;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "@\"@\"", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
    });
}

test "semantic tokens - operators" {
    try testSemanticTokens(
        \\var alpha = 3 + 3;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
        .{ "+", .operator, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha = 3 orelse 3;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
        .{ "orelse", .keyword, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha = true and false;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "true", .keywordLiteral, .{} },
        .{ "and", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
    });
}

test "semantic tokens - field access with @import" {
    if (!std.process.can_spawn) return error.SkipZigTest;
    // this will make sure that the std module can be resolved
    try testSemanticTokens(
        \\const std = @import("std");
    , &.{
        .{ "const", .keyword, .{} },
        .{ "std", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "@import", .builtin, .{} },
        .{ "\"std\"", .string, .{} },
    });
    try testSemanticTokens(
        \\const std = @import("std");
        \\const Ast = std.zig.Ast;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "std", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "@import", .builtin, .{} },
        .{ "\"std\"", .string, .{} },

        .{ "const", .keyword, .{} },
        .{ "Ast", .@"struct", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "std", .namespace, .{} },
        .{ "zig", .namespace, .{} },
        .{ "Ast", .@"struct", .{} },
    });
}

test "semantic tokens - field access" {
    try testSemanticTokens(
        \\const S = struct {
        \\    const @"u32" = 5;
        \\};
        \\const alpha = S.u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "S", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "const", .keyword, .{} },
        .{ "@\"u32\"", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "5", .number, .{} },

        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "S", .namespace, .{} },
        .{ "u32", .variable, .{} },
    });
}

test "semantic tokens - alias" {
    try testSemanticTokens(
        \\extern fn foo() u32;
        \\const bar = foo;
    , &.{
        .{ "extern", .keyword, .{} },
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "u32", .type, .{} },

        .{ "const", .keyword, .{} },
        .{ "bar", .function, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "foo", .function, .{} },
    });
}

test "semantic tokens - call" {
    try testSemanticTokens(
        \\fn foo() void {}
        \\const alpha = foo();
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },

        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "foo", .function, .{} },
    });
    try testSemanticTokens(
        \\const ns = struct {
        \\    fn foo() void {}
        \\};
        \\const alpha = ns.foo();
    , &.{
        .{ "const", .keyword, .{} },
        .{ "ns", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },

        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "ns", .namespace, .{} },
        .{ "foo", .function, .{} },
    });
    try testSemanticTokens(
        \\fn foo(a: anytype) void {
        \\  _ = a;
        \\}
        \\const alpha = foo(0);
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true, .generic = true } },
        .{ "a", .parameter, .{ .declaration = true } },
        .{ "anytype", .type, .{} },
        .{ "void", .type, .{} },

        .{ "=", .operator, .{} },
        .{ "a", .parameter, .{} },

        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "foo", .function, .{ .generic = true } },
        .{ "0", .number, .{} },
    });
}

test "semantic tokens - catch" {
    try testSemanticTokens(
        \\var alpha = a catch b;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "a", .variable, .{} },
        .{ "catch", .keyword, .{} },
        .{ "b", .variable, .{} },
    });
    try testSemanticTokens(
        \\var alpha = a catch |err| b;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "a", .variable, .{} },
        .{ "catch", .keyword, .{} },
        .{ "err", .variable, .{ .declaration = true } },
        .{ "b", .variable, .{} },
    });
}

test "semantic tokens - slicing" {
    try testSemanticTokens(
        \\var alpha = a[0..1];
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "a", .variable, .{} },
        .{ "0", .number, .{} },
        .{ "1", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha = a[0..1: 2];
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "a", .variable, .{} },
        .{ "0", .number, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
    });
}

test "semantic tokens - enum literal" {
    try testSemanticTokens(
        \\var alpha = .beta;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "beta", .enumMember, .{} },
    });
}

test "semantic tokens - error literal" {
    try testSemanticTokens(
        \\var alpha = error.OutOfMemory;
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "error", .keyword, .{} },
        .{ "OutOfMemory", .errorTag, .{} },
    });
}

test "semantic tokens - array literal" {
    try testSemanticTokens(
        \\var alpha = [_]u32{ 1, 2 };
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "u32", .type, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha = [_:3]u32{};
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - struct literal" {
    try testSemanticTokens(
        \\var alpha = .{};
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
    });
    try testSemanticTokens(
        \\var alpha = .{1,2};
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
    });
    try testSemanticTokens(
        \\var alpha = Unknown{1,2};
    , &.{
        .{ "var", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "Unknown", .variable, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
    });
}

test "semantic tokens - optional types" {
    try testSemanticTokens(
        \\const alpha = ?u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "?", .operator, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - array types" {
    try testSemanticTokens(
        \\const alpha = [1]u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "1", .number, .{} },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\const alpha = [1:0]u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "1", .number, .{} },
        .{ "0", .number, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - pointer types" {
    try testSemanticTokens(
        \\const alpha = *u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "*", .operator, .{} },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\const alpha = *allowzero u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "*", .operator, .{} },
        .{ "allowzero", .keyword, .{} },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\const alpha = [:0]const u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "0", .number, .{} },
        .{ "const", .keyword, .{} },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\const alpha = *align(1:2:3) u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "*", .operator, .{} },
        .{ "align", .keyword, .{} },
        .{ "1", .number, .{} },
        .{ "2", .number, .{} },
        .{ "3", .number, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - anyframe type" {
    try testSemanticTokens(
        \\const alpha = anyframe->u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "anyframe", .keyword, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - error union types" {
    try testSemanticTokens(
        \\const alpha = u32!u32;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "alpha", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "u32", .type, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - struct" {
    try testSemanticTokens(
        \\const Foo = struct {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
    });
    try testSemanticTokens(
        \\const Foo = packed struct(u32) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "packed", .keyword, .{} },
        .{ "struct", .keyword, .{} },
        .{ "u32", .type, .{} },
    });
    try testSemanticTokens(
        \\const Foo = struct {
        \\    alpha: u32,
        \\    beta: void,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"struct", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "alpha", .property, .{ .declaration = true } },
        .{ "u32", .type, .{} },
        .{ "beta", .property, .{ .declaration = true } },
        .{ "void", .type, .{} },
    });
    try testSemanticTokens(
        \\const Foo = struct {
        \\    alpha: u32 = 3,
        \\    comptime beta: void = {},
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"struct", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "alpha", .property, .{ .declaration = true } },
        .{ "u32", .type, .{} },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
        .{ "comptime", .keyword, .{} },
        .{ "beta", .property, .{ .declaration = true } },
        .{ "void", .type, .{} },
        .{ "=", .operator, .{} },
    });
    try testSemanticTokens(
        \\const T = u32;
        \\const Foo = struct {
        \\    u32,
        \\    T align(4),
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "T", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "u32", .type, .{} },
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"struct", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "u32", .type, .{} },
        .{ "T", .type, .{} },
        .{ "align", .keyword, .{} },
        .{ "4", .number, .{} },
    });
}

test "semantic tokens - union" {
    try testSemanticTokens(
        \\const Foo = union {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "union", .keyword, .{} },
    });
    try testSemanticTokens(
        \\const Foo = packed union(enum) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "packed", .keyword, .{} },
        .{ "union", .keyword, .{} },
        .{ "enum", .keyword, .{} },
    });
    try testSemanticTokens(
        \\const Foo = union(E) {
        \\    alpha,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "union", .keyword, .{} },
        .{ "E", .variable, .{} },
        .{ "alpha", .property, .{ .declaration = true } },
    });
    try testSemanticTokens(
        \\const Foo = union(E) {
        \\    alpha,
        \\    beta: void,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "union", .keyword, .{} },
        .{ "E", .variable, .{} },
        .{ "alpha", .property, .{ .declaration = true } },
        .{ "beta", .property, .{ .declaration = true } },
        .{ "void", .type, .{} },
    });
    try testSemanticTokens(
        \\const Foo = union(E) {
        \\    alpha: void align(2),
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "union", .keyword, .{} },
        .{ "E", .variable, .{} },
        .{ "alpha", .property, .{ .declaration = true } },
        .{ "void", .type, .{} },
        .{ "align", .keyword, .{} },
        .{ "2", .number, .{} },
    });
}

test "semantic tokens - enum" {
    try testSemanticTokens(
        \\const Foo = enum {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"enum", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "enum", .keyword, .{} },
    });
    try testSemanticTokens(
        \\const Foo = enum {
        \\    alpha = 3,
        \\    beta,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"enum", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "enum", .keyword, .{} },
        .{ "alpha", .enumMember, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "3", .number, .{} },
        .{ "beta", .enumMember, .{ .declaration = true } },
    });
    try testSemanticTokens(
        \\const Foo = enum(u4) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"enum", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "enum", .keyword, .{} },
        .{ "u4", .type, .{} },
    });
}

test "semantic tokens - enum member" {
    try testSemanticTokens(
        \\const Foo = enum { bar, baz };
        \\const alpha = Foo.bar;
        \\const beta = .baz;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .@"enum", .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "enum", .keyword, .{} },
        .{ "bar", .enumMember, .{ .declaration = true } },
        .{ "baz", .enumMember, .{ .declaration = true } },

        .{ "const", .keyword, .{} },
        .{ "alpha", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "Foo", .@"enum", .{} },
        .{ "bar", .enumMember, .{} },

        .{ "const", .keyword, .{} },
        .{ "beta", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "baz", .enumMember, .{} },
    });
}

test "semantic tokens - error set" {
    try testSemanticTokens(
        \\const Foo = error {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "error", .keyword, .{} },
    });
    try testSemanticTokens(
        \\const Foo = error {
        \\    OutOfMemory,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "error", .keyword, .{} },
        .{ "OutOfMemory", .errorTag, .{ .declaration = true } },
    });
}

test "semantic tokens - error set member" {
    try testSemanticTokens(
        \\const Foo = error {
        \\    OutOfMemory,
        \\};
        \\const bar = Foo.OutOfMemory;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "error", .keyword, .{} },
        .{ "OutOfMemory", .errorTag, .{ .declaration = true } },

        .{ "const", .keyword, .{} },
        .{ "bar", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "Foo", .type, .{} },
        .{ "OutOfMemory", .errorTag, .{} },
    });
}

test "semantic tokens - opaque" {
    try testSemanticTokens(
        \\const Foo = opaque {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .type, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "opaque", .keyword, .{} },
    });
}

test "semantic tokens - function" {
    try testSemanticTokens(
        \\fn foo() void {}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },
    });
    try testSemanticTokens(
        \\pub fn foo(alpha: u32) void {}
    , &.{
        .{ "pub", .keyword, .{} },
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "alpha", .parameter, .{ .declaration = true } },
        .{ "u32", .type, .{} },
        .{ "void", .type, .{} },
    });
    try testSemanticTokens(
        \\extern fn foo() align(4) callconv(.C) void;
    , &.{
        .{ "extern", .keyword, .{} },
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "align", .keyword, .{} },
        .{ "4", .number, .{} },
        .{ "callconv", .keyword, .{} },
        .{ "C", .enumMember, .{} },
        .{ "void", .type, .{} },
    });
    try testSemanticTokens(
        \\fn foo(comptime T: type) void {
        \\    _ = T;
        \\}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true, .generic = true } },
        .{ "comptime", .keyword, .{} },
        .{ "T", .typeParameter, .{ .declaration = true } },
        .{ "type", .type, .{} },
        .{ "void", .type, .{} },
        .{ "=", .operator, .{} },
        .{ "T", .typeParameter, .{} },
    });
}

test "semantic tokens - method" {
    try testSemanticTokens(
        \\const S = struct {
        \\    fn create() S {}
        \\    fn doTheThing(self: S) void {}
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "S", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },

        .{ "fn", .keyword, .{} },
        .{ "create", .function, .{ .declaration = true } },
        .{ "S", .namespace, .{} },

        .{ "fn", .keyword, .{} },
        .{ "doTheThing", .method, .{ .declaration = true } },
        .{ "self", .parameter, .{ .declaration = true } },
        .{ "S", .namespace, .{} },
        .{ "void", .type, .{} },
    });
}

test "semantic tokens - builtin fuctions" {
    try testSemanticTokens(
        \\const foo = @as(type, u32);
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "@as", .builtin, .{} },
        .{ "type", .type, .{} },
        .{ "u32", .type, .{} },
    });
}

test "semantic tokens - block" {
    try testSemanticTokens(
        \\const foo = blk: {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "blk", .label, .{ .declaration = true } },
    });
    try testSemanticTokens(
        \\const foo = blk: {
        \\    break :blk 5;
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "blk", .label, .{ .declaration = true } },
        .{ "break", .keyword, .{} },
        .{ "blk", .label, .{} },
        .{ "5", .number, .{} },
    });
}

test "semantic tokens - if" {
    try testSemanticTokens(
        \\const foo = if (false) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "if", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
    });
    try testSemanticTokens(
        \\const foo = if (false) 1 else 2;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "if", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "1", .number, .{} },
        .{ "else", .keyword, .{} },
        .{ "2", .number, .{} },
    });
    try testSemanticTokens(
        \\const foo = if (false) |val| val else |err| err;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "if", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "val", .variable, .{ .declaration = true } },
        .{ "val", .variable, .{} },
        .{ "else", .keyword, .{} },
        .{ "err", .variable, .{ .declaration = true } },
        .{ "err", .variable, .{} },
    });
    try testSemanticTokens(
        \\const foo = if (null) |*value| {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "if", .keyword, .{} },
        .{ "null", .keywordLiteral, .{} },
        .{ "value", .variable, .{ .declaration = true } },
    });
}

test "semantic tokens - while" {
    try testSemanticTokens(
        \\const foo = while (false) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "while", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
    });
    try testSemanticTokens(
        \\const foo = while (false) |*val| {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "while", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "val", .variable, .{ .declaration = true } },
    });
    try testSemanticTokens(
        \\const foo = while (false) false else true;
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "while", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "false", .keywordLiteral, .{} },
        .{ "else", .keyword, .{} },
        .{ "true", .keywordLiteral, .{} },
    });
}

test "semantic tokens - for" {
    try testSemanticTokens(
        \\const foo = for ("") {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "for", .keyword, .{} },
        .{ "\"\"", .string, .{} },
    });
    try testSemanticTokens(
        \\const foo = for ("") |val| {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "for", .keyword, .{} },
        .{ "\"\"", .string, .{} },
        .{ "val", .variable, .{ .declaration = true } },
    });
}

test "semantic tokens - for with invalid capture" {
    try testSemanticTokens(
        \\for (foo bar) baz
    , &.{
        .{ "for", .keyword, .{} },
        .{ "foo", .variable, .{} },
        .{ "bar", .variable, .{} },
        .{ "baz", .variable, .{} },
    });
}

test "semantic tokens - switch" {
    try testSemanticTokens(
        \\const foo = switch (3) {};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "switch", .keyword, .{} },
        .{ "3", .number, .{} },
    });
    try testSemanticTokens(
        \\const foo = switch (3) {
        \\    0 => true,
        \\    else => false,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "switch", .keyword, .{} },
        .{ "3", .number, .{} },
        .{ "0", .number, .{} },
        .{ "true", .keywordLiteral, .{} },
        .{ "else", .keyword, .{} },
        .{ "false", .keywordLiteral, .{} },
    });
    try testSemanticTokens(
        \\const foo = switch (3) {
        \\    inline else => |*val| val,
        \\};
    , &.{
        .{ "const", .keyword, .{} },
        .{ "foo", .variable, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "switch", .keyword, .{} },
        .{ "3", .number, .{} },
        .{ "inline", .keyword, .{} },
        .{ "else", .keyword, .{} },
        .{ "val", .variable, .{ .declaration = true } },
        .{ "val", .variable, .{} },
    });
}

test "semantic tokens - defer" {
    try testSemanticTokens(
        \\fn foo() void {
        \\    defer {};
        \\}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },
        .{ "defer", .keyword, .{} },
    });
}

test "semantic tokens - errdefer" {
    try testSemanticTokens(
        \\fn foo() void {
        \\    errdefer {};
        \\}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },
        .{ "errdefer", .keyword, .{} },
    });
    try testSemanticTokens(
        \\fn foo() void {
        \\    errdefer |err| {};
        \\}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "foo", .function, .{ .declaration = true } },
        .{ "void", .type, .{} },
        .{ "errdefer", .keyword, .{} },
        .{ "err", .variable, .{ .declaration = true } },
    });
}

test "semantic tokens - test decl" {
    try testSemanticTokens(
        \\test "test inside a test" {}
    , &.{
        .{ "test", .keyword, .{} },
        .{ "\"test inside a test\"", .string, .{} },
    });
    try testSemanticTokens(
        \\test foo {}
    , &.{
        .{ "test", .keyword, .{} },
        .{ "foo", .variable, .{} },
    });
    try testSemanticTokens(
        \\const Foo = struct {};
        \\test Foo {}
    , &.{
        .{ "const", .keyword, .{} },
        .{ "Foo", .namespace, .{ .declaration = true } },
        .{ "=", .operator, .{} },
        .{ "struct", .keyword, .{} },
        .{ "test", .keyword, .{} },
        .{ "Foo", .namespace, .{} },
    });
}

test "semantic tokens - assembly" {
    try testSemanticTokens(
        \\fn syscall1(number: usize, arg1: usize) usize {
        \\    return asm volatile ("syscall"
        \\        : [ret] "={rax}" (-> usize),
        \\        : [number] "{rax}" (number),
        \\          [arg1] "{rdi}" (arg1),
        \\        : "rcx", "r11"
        \\    );
        \\}
    , &.{
        .{ "fn", .keyword, .{} },
        .{ "syscall1", .function, .{ .declaration = true } },
        .{ "number", .parameter, .{ .declaration = true } },
        .{ "usize", .type, .{} },
        .{ "arg1", .parameter, .{ .declaration = true } },
        .{ "usize", .type, .{} },
        .{ "usize", .type, .{} },
        .{ "return", .keyword, .{} },
        .{ "asm", .keyword, .{} },
        .{ "volatile", .keyword, .{} },
        .{ "\"syscall\"", .string, .{} },
        .{ "ret", .variable, .{} },
        .{ "\"={rax}\"", .string, .{} },
        .{ "usize", .type, .{} },
        .{ "number", .variable, .{} },
        .{ "\"{rax}\"", .string, .{} },
        .{ "number", .parameter, .{} },
        .{ "arg1", .variable, .{} },
        .{ "\"{rdi}\"", .string, .{} },
        .{ "arg1", .parameter, .{} },
        .{ "\"rcx\"", .string, .{} },
        .{ "\"r11\"", .string, .{} },
    });
}

const TokenData = struct {
    []const u8,
    zls.semantic_tokens.TokenType,
    zls.semantic_tokens.TokenModifiers,
};

const TokenIterator = struct {
    it: std.mem.WindowIterator(u32),
    source: []const u8,
    position: types.Position,

    pub const Token = struct {
        loc: offsets.Loc,
        type: zls.semantic_tokens.TokenType,
        modifiers: zls.semantic_tokens.TokenModifiers,
    };

    pub fn init(source: []const u8, data: []const u32) TokenIterator {
        std.debug.assert(data.len % 5 == 0);
        return .{
            .it = std.mem.window(u32, data, 5, 5),
            .source = source,
            .position = .{ .line = 0, .character = 0 },
        };
    }

    pub fn next(self: *TokenIterator) ?Token {
        const token_data = self.it.next() orelse return null;
        if (token_data.len != 5) return null;
        const delta_line = token_data[0];
        const delta_start = token_data[1];
        const length = token_data[2];
        const token_type: zls.semantic_tokens.TokenType = @enumFromInt(token_data[3]);
        const token_modifiers: zls.semantic_tokens.TokenModifiers = @bitCast(@as(u16, @intCast(token_data[4])));

        self.position.line += delta_line;
        self.position.character = delta_start + if (delta_line == 0) self.position.character else 0;

        const source_index = offsets.positionToIndex(self.source, self.position, .@"utf-8");
        const loc: offsets.Loc = .{ .start = source_index, .end = source_index + length };

        return .{
            .loc = loc,
            .type = token_type,
            .modifiers = token_modifiers,
        };
    }
};

fn testSemanticTokens(source: [:0]const u8, expected_tokens: []const TokenData) !void {
    var ctx = try Context.init();
    defer ctx.deinit();

    const uri = try ctx.addDocument(source);

    const params = types.SemanticTokensParams{
        .textDocument = .{ .uri = uri },
    };
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/semanticTokens/full", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    const actual = response.data;
    try std.testing.expect(actual.len % 5 == 0); // every token is represented by 5 integers

    var error_builder = ErrorBuilder.init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(uri, source);

    var token_it = TokenIterator.init(source, actual);
    var last_token_end: usize = 0;

    for (expected_tokens) |expected_token| {
        const token = token_it.next() orelse {
            try error_builder.msgAtIndex("expected a `{s}` token here", uri, last_token_end, .err, .{expected_token.@"0"});
            return error.ExpectedToken;
        };
        last_token_end = token.loc.end;

        const token_source = offsets.locToSlice(source, token.loc);

        const expected_token_source = expected_token.@"0";
        const expected_token_type = expected_token.@"1";
        const expected_token_modifiers = expected_token.@"2";

        if (!std.mem.eql(u8, expected_token_source, token_source)) {
            try error_builder.msgAtLoc("expected `{s}` as the next token but got `{s}` here", uri, token.loc, .err, .{ expected_token_source, token_source });
            return error.UnexpectedTokenContent;
        } else if (expected_token_type != token.type) {
            try error_builder.msgAtLoc("expected token type `{s}` but got `{s}`", uri, token.loc, .err, .{ @tagName(expected_token_type), @tagName(token.type) });
            return error.UnexpectedTokenType;
        } else if (!std.meta.eql(expected_token_modifiers, token.modifiers)) {
            try error_builder.msgAtLoc("expected token modifiers `{}` but got `{}`", uri, token.loc, .err, .{ expected_token_modifiers, token.modifiers });
            return error.UnexpectedTokenModifiers;
        }
    }

    if (token_it.next()) |unexpected_token| {
        try error_builder.msgAtLoc("unexpected `{}` token here", uri, unexpected_token.loc, .err, .{unexpected_token.type});
        return error.UnexpectedToken;
    }
}
