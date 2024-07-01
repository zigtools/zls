const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

const Context = @import("../context.zig").Context;

const offsets = zls.offsets;
const translate_c = zls.translate_c;

const allocator: std.mem.Allocator = std.testing.allocator;

test "zig compile server - translate c" {
    var result1 = try testTranslate(
        \\void foo(int);
        \\void bar(float*);
    );
    defer result1.deinit(allocator);
    try std.testing.expect(result1 == .success);

    var result2 = try testTranslate(
        \\#include <this_file_doesnt_exist>
    );
    defer result2.deinit(allocator);
    try std.testing.expect(result2 == .failure);
}

test "empty" {
    try testConvertCInclude("@cImport()", "");
    try testConvertCInclude("@cImport({})", "");
    try testConvertCInclude("@cImport({{}, {}})", "");
}

test "cInclude" {
    try testConvertCInclude(
        \\@cImport(@cInclude("foo.zig"))
    ,
        \\#include <foo.zig>
    );

    try testConvertCInclude(
        \\@cImport(@cInclude("foo.zig"), @cInclude("bar.zig"))
    ,
        \\#include <foo.zig>
        \\#include <bar.zig>
    );
}

test "cDefine" {
    try testConvertCInclude(
        \\@cImport(@cDefine("FOO", "BAR"))
    ,
        \\#define FOO BAR
    );
    try testConvertCInclude(
        \\@cImport(@cDefine("FOO", {}))
    ,
        \\#define FOO
    );
}

test "cUndef" {
    try testConvertCInclude(
        \\@cImport(@cUndef("FOO"))
    ,
        \\#undef FOO
    );
}

fn testConvertCInclude(cimport_source: []const u8, expected: []const u8) !void {
    const source: [:0]u8 = try std.fmt.allocPrintZ(allocator, "const c = {s};", .{cimport_source});
    defer allocator.free(source);

    var tree = try Ast.parse(allocator, source, .zig);
    defer tree.deinit(allocator);

    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    const node: Ast.Node.Index = blk: {
        for (node_tags, main_tokens, 0..) |tag, token, i| {
            switch (tag) {
                .builtin_call_two,
                .builtin_call_two_comma,
                .builtin_call,
                .builtin_call_comma,
                => {},
                else => continue,
            }

            if (!std.mem.eql(u8, offsets.tokenToSlice(tree, token), "@cImport")) continue;

            break :blk @intCast(i);
        }
        return error.TestUnexpectedResult; // source doesn't contain a cImport
    };

    const output = try translate_c.convertCInclude(allocator, tree, node);
    defer allocator.free(output);

    const trimmed_output = std.mem.trimRight(u8, output, &.{'\n'});

    try std.testing.expectEqualStrings(expected, trimmed_output);
}

fn testTranslate(c_source: []const u8) !translate_c.Result {
    if (!std.process.can_spawn) return error.SkipZigTest;

    var ctx = try Context.init();
    defer ctx.deinit();

    var result = (try translate_c.translate(allocator, zls.DocumentStore.Config.fromMainConfig(ctx.server.config), &.{}, c_source)).?;
    errdefer result.deinit(allocator);

    switch (result) {
        .success => |uri| {
            const path = try zls.URI.parse(allocator, uri);
            defer allocator.free(path);
            try std.testing.expect(std.fs.path.isAbsolute(path));
        },
        .failure => |message| {
            try std.testing.expect(message.errorMessageCount() != 0);
        },
    }
    return result;
}
