const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

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

    // TODO the zig compiler doesn't seem to report error bundles for translate-c
    // Hopefully I can fix that once llvm-16 finished compiling :)

    var result2 = testTranslate(
        \\#include <this_file_doesnt_exist>
    );
    defer if (result2) |*r| r.deinit(allocator) else |_| {};
    try std.testing.expectError(error.Timeout, result2);
}

test "convertCInclude - empty" {
    try testConvertCInclude("@cImport()", "");
    try testConvertCInclude("@cImport({})", "");
    try testConvertCInclude("@cImport({{}, {}})", "");
}

test "convertCInclude - cInclude" {
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

test "convertCInclude - cDefine" {
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

test "convertCInclude - cUndef" {
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

    var config: zls.Config = .{};
    defer zls.legacy_json.parseFree(zls.Config, allocator, config);

    var runtime_zig_version: ?zls.ZigVersionWrapper = null;
    defer if (runtime_zig_version) |*v| v.free();

    try zls.configuration.configChanged(&config, &runtime_zig_version, allocator, null);

    if (config.global_cache_path == null or
        config.zig_exe_path == null or
        config.zig_lib_path == null) return error.SkipZigTest;

    const result = (try translate_c.translate(allocator, config, &.{}, c_source)).?;

    switch (result) {
        .success => |uri| {
            const path = try zls.URI.parse(allocator, uri);
            defer allocator.free(path);
            try std.testing.expect(std.fs.path.isAbsolute(path));
        },
        .failure => |message| {
            try std.testing.expect(message.len != 0);
        },
    }
    return result;
}
