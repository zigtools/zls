//! Collection of custom snippets used for code completion.

const std = @import("std");

pub const Item = struct {
    label: []const u8,
    /// https://microsoft.github.io/language-server-protocol/specifications/specification-current/#snippet_syntax
    snippet: []const u8,
};

pub const top_level: []const Item = &.{
    .{ .label = "std", .snippet = "const std = @import(\"std\");" },
    .{ .label = "builtin", .snippet = "const builtin = @import(\"builtin\");" },
    .{ .label = "root", .snippet = "const root = @import(\"root\");" },
    .{ .label = "import", .snippet = "const $1 = @import(\"$2\")" },
    .{ .label = "fn", .snippet = "fn ${1:name}($2) ${3:!void} {$0}" },
    .{ .label = "pub fn", .snippet = "pub fn ${1:name}($2) ${3:!void} {$0}" },
    .{ .label = "struct", .snippet = "const $1 = struct {$0};" },
    .{ .label = "error set", .snippet = "const ${1:Error} = error {$0};" },
    .{ .label = "enum", .snippet = "const $1 = enum {$0};" },
    .{ .label = "union", .snippet = "const $1 = union {$0};" },
    .{ .label = "union tagged", .snippet = "const $1 = union(${2:enum}) {$0};" },
    .{ .label = "test", .snippet = "test \"$1\" {$0}" },
    .{ .label = "main", .snippet = "pub fn main() !void {$0}" },
    .{ .label = "std_options", .snippet = "pub const std_options: std.Options = .{$0};" },
    .{ .label = "panic", .snippet =
    \\pub fn panic(
    \\    msg: []const u8,
    \\    trace: ?*std.builtin.StackTrace,
    \\    ret_addr: ?usize,
    \\) noreturn {$0}
    },
};

pub const keywords: std.EnumMap(std.zig.Token.Tag, []const u8) = .init(.{
    .keyword_callconv = "callconv($0)",
    .keyword_else = "else {$0}",
    .keyword_enum = "enum {$0}",
    .keyword_fn = "fn ${1:name}($2) ${3:!void} {$0}",
    .keyword_for = "for ($1) |${2:value}| {$0}",
    .keyword_if = "if ($1) {$0}",
    .keyword_struct = "struct {$0};",
    .keyword_switch = "switch ($1) {$0}",
    .keyword_test = "test \"$1\" {$0}",
    .keyword_while = "while ($1) {$0}",
});

pub const generic: []const Item = &.{
    .{ .label = "asmv", .snippet = "asm volatile (${1:input}, ${0:input})" },
    .{ .label = "fori", .snippet = "for ($1, 0..) |${2:value}, ${3:i}| {$0}" },
    .{ .label = "if else", .snippet = "if ($1) {$2} else {$0}" },
    .{ .label = "catch switch", .snippet = "catch |${1:err}| switch (${1:err}) {$0};" },

    .{ .label = "print", .snippet = "std.debug.print(\"$1\", .{$0});" },
    .{ .label = "log err", .snippet = "std.log.err(\"$1\", .{$0});" },
    .{ .label = "log warn", .snippet = "std.log.warn(\"$1\", .{$0});" },
    .{ .label = "log info", .snippet = "std.log.info(\"$1\", .{$0});" },
    .{ .label = "log debug", .snippet = "std.log.debug(\"$1\", .{$0});" },
    .{ .label = "format", .snippet =
    \\pub fn format(
    \\    self: @This(),
    \\    writer: *std.Io.Writer,
    \\) std.Io.Writer.Error!void {}
    },
};
