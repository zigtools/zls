//! Collection of all snippets and keywords.

const types = @import("lsp").types;

pub const Snipped = struct {
    label: []const u8,
    kind: types.CompletionItemKind,
    text: ?[]const u8 = null,
};

pub const top_level_decl_data = [_]Snipped{
    .{ .label = "std", .kind = .Snippet, .text = "const std = @import(\"std\");" },
    .{ .label = "root", .kind = .Snippet, .text = "const root = @import(\"root\");" },
    .{ .label = "import", .kind = .Snippet, .text = "const $1 = @import(\"$2\")" },
    .{ .label = "fn", .kind = .Snippet, .text = "fn ${1:name}($2) ${3:!void} {$0}" },
    .{ .label = "pub fn", .kind = .Snippet, .text = "pub fn ${1:name}($2) ${3:!void} {$0}" },
    .{ .label = "struct", .kind = .Snippet, .text = "const $1 = struct {$0};" },
    .{ .label = "error set", .kind = .Snippet, .text = "const ${1:Error} = error {$0};" },
    .{ .label = "enum", .kind = .Snippet, .text = "const $1 = enum {$0};" },
    .{ .label = "union", .kind = .Snippet, .text = "const $1 = union {$0};" },
    .{ .label = "union tagged", .kind = .Snippet, .text = "const $1 = union(${2:enum}) {$0};" },
    .{ .label = "test", .kind = .Snippet, .text = "test \"$1\" {$0}" },
    .{ .label = "main", .kind = .Snippet, .text = "pub fn main() !void {$0}" },
    .{ .label = "std_options", .kind = .Snippet, .text = "pub const std_options: std.Options = .{$0};" },
    .{ .label = "panic", .kind = .Snippet, .text = 
    \\pub fn panic(
    \\    msg: []const u8,
    \\    trace: ?*std.builtin.StackTrace,
    \\    ret_addr: ?usize,
    \\) noreturn {$0}
    },
};

pub const generic = [_]Snipped{
    // keywords
    .{ .label = "align", .kind = .Keyword },
    .{ .label = "allowzero", .kind = .Keyword },
    .{ .label = "and", .kind = .Keyword },
    .{ .label = "asm", .kind = .Keyword },
    .{ .label = "break", .kind = .Keyword },
    .{ .label = "callconv", .kind = .Keyword, .text = "callconv($0)" },
    .{ .label = "catch", .kind = .Keyword },
    .{ .label = "comptime", .kind = .Keyword },
    .{ .label = "const", .kind = .Keyword },
    .{ .label = "continue", .kind = .Keyword },
    .{ .label = "defer", .kind = .Keyword },
    .{ .label = "else", .kind = .Keyword, .text = "else {$0}" },
    .{ .label = "enum", .kind = .Keyword, .text = "enum {$0}" },
    .{ .label = "errdefer", .kind = .Keyword },
    .{ .label = "error", .kind = .Keyword },
    .{ .label = "export", .kind = .Keyword },
    .{ .label = "extern", .kind = .Keyword },
    .{ .label = "fn", .kind = .Keyword, .text = "fn ${1:name}($2) ${3:!void} {$0}" },
    .{ .label = "for", .kind = .Keyword, .text = "for ($1) |${2:value}| {$0}" },
    .{ .label = "if", .kind = .Keyword, .text = "if ($1) {$0}" },
    .{ .label = "inline", .kind = .Keyword },
    .{ .label = "noalias", .kind = .Keyword },
    .{ .label = "nosuspend", .kind = .Keyword },
    .{ .label = "noinline", .kind = .Keyword },
    .{ .label = "opaque", .kind = .Keyword },
    .{ .label = "or", .kind = .Keyword },
    .{ .label = "orelse", .kind = .Keyword },
    .{ .label = "packed", .kind = .Keyword },
    .{ .label = "pub", .kind = .Keyword },
    .{ .label = "resume", .kind = .Keyword },
    .{ .label = "return", .kind = .Keyword },
    .{ .label = "linksection", .kind = .Keyword },
    .{ .label = "struct", .kind = .Keyword, .text = "struct {$0};" },
    .{ .label = "suspend", .kind = .Keyword },
    .{ .label = "switch", .kind = .Keyword, .text = "switch ($1) {$0}" },
    .{ .label = "test", .kind = .Keyword, .text = "test \"$1\" {$0}" },
    .{ .label = "threadlocal", .kind = .Keyword },
    .{ .label = "try", .kind = .Keyword },
    .{ .label = "union", .kind = .Keyword },
    .{ .label = "unreachable", .kind = .Keyword },
    .{ .label = "var", .kind = .Keyword },
    .{ .label = "volatile", .kind = .Keyword },
    .{ .label = "while", .kind = .Keyword, .text = "while ($1) {$0}" },

    // keyword snippets
    .{ .label = "asmv", .kind = .Snippet, .text = "asm volatile (${1:input}, ${0:input})" },
    .{ .label = "fori", .kind = .Snippet, .text = "for ($1, 0..) |${2:value}, ${3:i}| {$0}" },
    .{ .label = "if else", .kind = .Snippet, .text = "if ($1) {$2} else {$0}" },
    .{ .label = "catch switch", .kind = .Snippet, .text = "catch |${1:err}| switch (${1:err}) {$0};" },

    // snippets
    .{ .label = "print", .kind = .Snippet, .text = "std.debug.print(\"$1\", .{$0});" },
    .{ .label = "log err", .kind = .Snippet, .text = "std.log.err(\"$1\", .{$0});" },
    .{ .label = "log warn", .kind = .Snippet, .text = "std.log.warn(\"$1\", .{$0});" },
    .{ .label = "log info", .kind = .Snippet, .text = "std.log.info(\"$1\", .{$0});" },
    .{ .label = "log debug", .kind = .Snippet, .text = "std.log.debug(\"$1\", .{$0});" },
    .{ .label = "format", .kind = .Snippet, .text = 
    \\pub fn format(
    \\    self: @This(),
    \\    writer: *std.Io.Writer,
    \\) std.Io.Writer.Error!void {}
    },

    // types
    .{ .label = "anyerror", .kind = .Keyword },
    .{ .label = "anyframe", .kind = .Keyword },
    .{ .label = "anytype", .kind = .Keyword },
    .{ .label = "anyopaque", .kind = .Keyword },
    .{ .label = "bool", .kind = .Keyword },
    .{ .label = "c_char", .kind = .Keyword },
    .{ .label = "c_int", .kind = .Keyword },
    .{ .label = "c_long", .kind = .Keyword },
    .{ .label = "c_longdouble", .kind = .Keyword },
    .{ .label = "c_longlong", .kind = .Keyword },
    .{ .label = "c_short", .kind = .Keyword },
    .{ .label = "c_uint", .kind = .Keyword },
    .{ .label = "c_ulong", .kind = .Keyword },
    .{ .label = "c_ulonglong", .kind = .Keyword },
    .{ .label = "c_ushort", .kind = .Keyword },
    .{ .label = "comptime_float", .kind = .Keyword },
    .{ .label = "comptime_int", .kind = .Keyword },
    .{ .label = "false", .kind = .Keyword },
    .{ .label = "isize", .kind = .Keyword },
    .{ .label = "noreturn", .kind = .Keyword },
    .{ .label = "null", .kind = .Keyword },
    .{ .label = "true", .kind = .Keyword },
    .{ .label = "type", .kind = .Keyword },
    .{ .label = "undefined", .kind = .Keyword },
    .{ .label = "usize", .kind = .Keyword },
    .{ .label = "void", .kind = .Keyword },
};
