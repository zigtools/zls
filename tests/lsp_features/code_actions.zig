const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;
const helper = @import("../helper.zig");

const types = zls.lsp.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "discard value" {
    try testAutofix(
        \\test {
        \\    var foo = {};
        \\    const bar, var baz = .{ 1, 2 };
        \\}
        \\
    ,
        \\test {
        \\    var foo = {};
        \\    _ = foo; // autofix
        \\    const bar, var baz = .{ 1, 2 };
        \\    _ = baz; // autofix
        \\    _ = bar; // autofix
        \\}
        \\
    );
}

test "discard value with comments" {
    try testAutofix(
        \\test {
        \\    const a = {}; // a comment
        \\    const b = {} // a comment
        \\    ;
        \\    const c = // a comment
        \\    {};
        \\    const d // a comment
        \\    = {};
        \\}
        \\
    ,
        \\test {
        \\    const a = {}; // a comment
        \\    _ = a; // autofix
        \\    const b = {} // a comment
        \\    ;
        \\    _ = b; // autofix
        \\    const c = // a comment
        \\    {};
        \\    _ = c; // autofix
        \\    const d // a comment
        \\    = {};
        \\    _ = d; // autofix
        \\}
        \\
    );
}

test "discard function parameter" {
    try testAutofix(
        \\fn foo(a: void, b: void, c: void) void {}
        \\
    ,
        \\fn foo(a: void, b: void, c: void) void {
        \\    _ = a; // autofix
        \\    _ = b; // autofix
        \\    _ = c; // autofix
        \\}
        \\
    );
    try testAutofix(
        \\fn foo(a: void, b: void, c: void,) void {}
        \\
    ,
        \\fn foo(a: void, b: void, c: void,) void {
        \\    _ = a; // autofix
        \\    _ = b; // autofix
        \\    _ = c; // autofix
        \\}
        \\
    );
}

test "discard function parameter with comments" {
    try testAutofix(
        \\fn foo(a: void) void { // a comment
        \\}
        \\
    ,
        \\fn foo(a: void) void { // a comment
        \\    _ = a; // autofix
        \\}
        \\
    );
    try testAutofix(
        \\fn foo(a: void) void {
        \\    // a comment
        \\}
        \\
    ,
        \\fn foo(a: void) void {
        \\    _ = a; // autofix
        \\    // a comment
        \\}
        \\
    );
}

test "discard captures" {
    try testAutofix(
        \\test {
        \\    for (0..10, 0..10, 0..10) |i, j, k| {}
        \\    switch (union(enum) {}{}) {
        \\        inline .a => |cap, tag| {},
        \\    }
        \\    if (null) |x| {}
        \\    if (null) |v| {} else |e| {}
        \\    _ = null catch |e| {};
        \\    _ = null catch |_| {};
        \\}
        \\
    ,
        \\test {
        \\    for (0..10, 0..10, 0..10) |i, j, k| {
        \\        _ = i; // autofix
        \\        _ = j; // autofix
        \\        _ = k; // autofix
        \\    }
        \\    switch (union(enum) {}{}) {
        \\        inline .a => |cap, tag| {
        \\            _ = cap; // autofix
        \\            _ = tag; // autofix
        \\        },
        \\    }
        \\    if (null) |x| {
        \\        _ = x; // autofix
        \\    }
        \\    if (null) |v| {
        \\        _ = v; // autofix
        \\    } else |e| {
        \\        _ = e; // autofix
        \\    }
        \\    _ = null catch |e| {
        \\        _ = e; // autofix
        \\    };
        \\    _ = null catch |_| {};
        \\}
        \\
    );
}

test "discard capture with comment" {
    try testAutofix(
        \\test {
        \\    if (1 == 1) |a| // a comment
        \\    {}
        \\    for (0..10, 0..10, 0..10) |i, j, k| // a comment
        \\    {}
        \\}
        \\
    ,
        \\test {
        \\    if (1 == 1) |a| // a comment
        \\    {
        \\        _ = a; // autofix
        \\    }
        \\    for (0..10, 0..10, 0..10) |i, j, k| // a comment
        \\    {
        \\        _ = i; // autofix
        \\        _ = j; // autofix
        \\        _ = k; // autofix
        \\    }
        \\}
        \\
    );
    try testAutofix(
        \\test {
        \\    if (1 == 1) |a|
        \\    // a comment
        \\    {}
        \\    for (0..10, 0..10, 0..10) |i, j, k|
        \\    // a comment
        \\    {}
        \\}
        \\
    ,
        \\test {
        \\    if (1 == 1) |a|
        \\    // a comment
        \\    {
        \\        _ = a; // autofix
        \\    }
        \\    for (0..10, 0..10, 0..10) |i, j, k|
        \\    // a comment
        \\    {
        \\        _ = i; // autofix
        \\        _ = j; // autofix
        \\        _ = k; // autofix
        \\    }
        \\}
        \\
    );
    try testAutofix(
        \\test {
        \\    if (1 == 1) |a| { // a comment
        \\    }
        \\    for (0..10, 0..10, 0..10) |i, j, k| { // a comment
        \\    }
        \\}
        \\
    ,
        \\test {
        \\    if (1 == 1) |a| { // a comment
        \\        _ = a; // autofix
        \\    }
        \\    for (0..10, 0..10, 0..10) |i, j, k| { // a comment
        \\        _ = i; // autofix
        \\        _ = j; // autofix
        \\        _ = k; // autofix
        \\    }
        \\}
        \\
    );
}

test "discard capture - while loop with continue" {
    try testAutofix(
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += 1) {}
        \\}
        \\
    ,
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += 1) {
        \\        _ = line; // autofix
        \\    }
        \\}
        \\
    );

    try testAutofix(
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += (1 * (2 + 1))) {}
        \\}
        \\
    ,
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += (1 * (2 + 1))) {
        \\        _ = line; // autofix
        \\    }
        \\}
        \\
    );
    try testAutofix(
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += ")))".len) {}
        \\}
        \\
    ,
        \\test {
        \\    var lines: ?[]const u8 = "";
        \\    var linei: usize = 0;
        \\    while (lines.next()) |line| : (linei += ")))".len) {
        \\        _ = line; // autofix
        \\    }
        \\}
        \\
    );
}

test "remove pointless discard" {
    try testAutofix(
        \\fn foo(a: u32) u32 {
        \\    _ = a; // autofix
        \\    const b: ?u32 = a;
        \\    _ = b; // autofix
        \\    const c = b;
        \\    _ = c; // autofix
        \\    if (c) |d| {
        \\        _ = d; // autofix
        \\        return d;
        \\    }
        \\    return 0;
        \\}
        \\
    ,
        \\fn foo(a: u32) u32 {
        \\    const b: ?u32 = a;
        \\    const c = b;
        \\    if (c) |d| {
        \\        return d;
        \\    }
        \\    return 0;
        \\}
        \\
    );
}

test "remove discard of unknown identifier" {
    try testAutofix(
        \\fn foo() void {
        \\    _ = a; // autofix
        \\}
        \\
    ,
        \\fn foo() void {
        \\}
        \\
    );
}

test "ignore autofix comment whitespace" {
    try testAutofix(
        \\fn foo() void {
        \\    _ = a; // autofix
        \\}
        \\
    ,
        \\fn foo() void {
        \\}
        \\
    );
    try testAutofix(
        \\fn foo() void {
        \\    _ = a;// autofix
        \\}
        \\
    ,
        \\fn foo() void {
        \\}
        \\
    );
    try testAutofix(
        \\fn foo() void {
        \\    _ = a;//autofix
        \\}
        \\
    ,
        \\fn foo() void {
        \\}
        \\
    );
    try testAutofix(
        \\fn foo() void {
        \\    _ = a;   //   autofix
        \\}
        \\
    ,
        \\fn foo() void {
        \\}
        \\
    );
}

test "remove function parameter" {
    try testDiagnostic(
        \\fn foo(alpha: u32) void {}
    ,
        \\fn foo() void {}
    , .{ .filter_title = "remove function parameter" });
    try testDiagnostic(
        \\fn foo(
        \\    alpha: u32,
        \\) void {}
    ,
        \\fn foo() void {}
    , .{ .filter_title = "remove function parameter" });
}

test "variable never mutated" {
    try testDiagnostic(
        \\test {
        \\    var foo = 5;
        \\    _ = foo;
        \\}
    ,
        \\test {
        \\    const foo = 5;
        \\    _ = foo;
        \\}
    , .{ .filter_title = "use 'const'" });
}

test "discard capture name" {
    try testDiagnostic(
        \\test {
        \\    const maybe: ?u32 = 5;
        \\    if (maybe) |value| {}
        \\}
    ,
        \\test {
        \\    const maybe: ?u32 = 5;
        \\    if (maybe) |_| {}
        \\}
    , .{ .filter_title = "discard capture name" });
}

test "remove capture" {
    // TODO fix whitespace
    try testDiagnostic(
        \\test {
        \\    const maybe: ?u32 = 5;
        \\    if (maybe) |value| {}
        \\}
    ,
        \\test {
        \\    const maybe: ?u32 = 5;
        \\    if (maybe)  {}
        \\}
    , .{ .filter_title = "remove capture" });
}

test "organize imports" {
    try testOrganizeImports(
        \\const xyz = @import("xyz.zig");
        \\const abc = @import("abc.zig");
    ,
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig");
        \\
        \\
    );
    // Three different import groups: std, build_options and builtin, but these groups do not have separator
    // Builtin comes before build_options despite alphabetical order (they are different import kinds)
    // Case insensitive, pub is preserved
    try testOrganizeImports(
        \\const std = @import("std");
        \\const abc = @import("abc.zig");
        \\const build_options = @import("build_options");
        \\const builtin = @import("builtin");
        \\const tres = @import("tres");
        \\
        \\pub const offsets = @import("offsets.zig");
        \\const Config = @import("Config.zig");
        \\const debug = @import("debug.zig");
        \\const Server = @import("Server.zig");
        \\const root = @import("root");
    ,
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\const root = @import("root");
        \\const build_options = @import("build_options");
        \\
        \\const tres = @import("tres");
        \\
        \\const abc = @import("abc.zig");
        \\const Config = @import("Config.zig");
        \\const debug = @import("debug.zig");
        \\pub const offsets = @import("offsets.zig");
        \\const Server = @import("Server.zig");
        \\
        \\
    );
    // Relative paths are sorted by import path
    try testOrganizeImports(
        \\const y = @import("a/file2.zig");
        \\const x = @import("a/file3.zig");
        \\const z = @import("a/file1.zig");
    ,
        \\const z = @import("a/file1.zig");
        \\const y = @import("a/file2.zig");
        \\const x = @import("a/file3.zig");
        \\
        \\
    );
}

test "organize imports - bubbles up" {
    try testOrganizeImports(
        \\const std = @import("std");
        \\fn main() void {}
        \\const abc = @import("abc.zig");
        \\fn foo() void {}
    ,
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\
        \\fn main() void {}
        \\fn foo() void {}
    );
}

test "organize imports - bottom placement" {
    // When imports are at the bottom, they should stay at the bottom
    try testOrganizeImports(
        \\fn main() void {
        \\    std.debug.print("Hello\n", .{});
        \\}
        \\
        \\const xyz = @import("xyz.zig");
        \\const abc = @import("abc.zig");
        \\const std = @import("std");
    ,
        \\fn main() void {
        \\    std.debug.print("Hello\n", .{});
        \\}
        \\
        \\
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig");
        \\
        \\
    );
}

test "organize imports - bottom placement with multiple functions" {
    // Bottom imports with multiple declarations
    try testOrganizeImports(
        \\fn foo() void {}
        \\
        \\fn bar() void {}
        \\
        \\const test_input = "test";
        \\
        \\const xyz = @import("xyz.zig");
        \\const abc = @import("abc.zig");
        \\const std = @import("std");
    ,
        \\fn foo() void {}
        \\
        \\fn bar() void {}
        \\
        \\const test_input = "test";
        \\
        \\
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig");
        \\
        \\
    );
}

test "organize imports - mixed placement defaults to bottom" {
    // When imports are mixed (both top and bottom), consolidate at bottom
    try testOrganizeImports(
        \\const std = @import("std");
        \\
        \\fn main() void {}
        \\
        \\const xyz = @import("xyz.zig");
        \\const abc = @import("abc.zig");
    ,
        \\fn main() void {}
        \\
        \\
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig");
        \\
        \\
    );
}

test "organize imports - scope" {
    // Ignore imports not in root scope
    try testOrganizeImports(
        \\const b = @import("a.zig");
        \\const a = @import("b.zig");
        \\fn main() void {
        \\  const y = @import("y");
        \\  const x = @import("x");
        \\  _ = y; // autofix
        \\  _ = x; // autofix
        \\}
    ,
        \\const a = @import("b.zig");
        \\const b = @import("a.zig");
        \\
        \\fn main() void {
        \\  const y = @import("y");
        \\  const x = @import("x");
        \\  _ = y; // autofix
        \\  _ = x; // autofix
        \\}
    );
}

test "organize imports - comments" {
    // Doc comments are preserved
    try testOrganizeImports(
        \\const xyz = @import("xyz.zig");
        \\/// Do not look inside
        \\const abc = @import("abc.zig");
    ,
        \\/// Do not look inside
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig");
        \\
        \\
    );
    // Respects top-level doc-comment
    try testOrganizeImports(
        \\//! A module doc
        \\//! Another line
        \\
        \\const abc = @import("abc.zig");
        \\const std = @import("std");
    ,
        \\//! A module doc
        \\//! Another line
        \\
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\
        \\
    );
}

test "organize imports - field access" {
    // field access on import
    try testOrganizeImports(
        \\const xyz = @import("xyz.zig").a.long.chain;
        \\const abc = @import("abc.zig");
    ,
        \\const abc = @import("abc.zig");
        \\const xyz = @import("xyz.zig").a.long.chain;
        \\
        \\
    );
    // declarations without @import move under the parent import
    try testOrganizeImports(
        \\const xyz = @import("xyz.zig").a.long.chain;
        \\const abc = @import("abc.zig");
        \\const abc_related = abc.related;
    ,
        \\const abc = @import("abc.zig");
        \\const abc_related = abc.related;
        \\const xyz = @import("xyz.zig").a.long.chain;
        \\
        \\
    );
    try testOrganizeImports(
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\
        \\const mem = std.mem;
    ,
        \\const std = @import("std");
        \\const mem = std.mem;
        \\const builtin = @import("builtin");
        \\
        \\
    );
    // Inverse chain of parents
    try testOrganizeImports(
        \\const abc = @import("abc.zig");
        \\const isLower = ascii.isLower;
        \\const ascii = std.ascii;
        \\const std = @import("std");
    ,
        \\const std = @import("std");
        \\const ascii = std.ascii;
        \\const isLower = ascii.isLower;
        \\
        \\const abc = @import("abc.zig");
        \\
        \\
    );
    // Parent chains are not mixed
    try testOrganizeImports(
        \\const xyz = @import("xyz.zig");
        \\const abc = @import("abc.zig");
        \\const xyz_related = xyz.related;
        \\/// comment
        \\const abc_related = abc.related;
    ,
        \\const abc = @import("abc.zig");
        \\/// comment
        \\const abc_related = abc.related;
        \\const xyz = @import("xyz.zig");
        \\const xyz_related = xyz.related;
        \\
        \\
    );
}

test "organize imports - @embedFile" {
    try testOrganizeImports(
        \\const foo = @embedFile("foo.zig");
        \\const abc = @import("abc.zig");
        \\const bar = @embedFile("bar.zig");
    ,
        \\const abc = @import("abc.zig");
        \\
        \\const foo = @embedFile("foo.zig");
        \\const bar = @embedFile("bar.zig");
    );
}

test "organize imports - edge cases" {
    // Withstands non-standard behavior
    try testOrganizeImports(
        \\const std = @import("std");
        \\const abc = @import("abc.zig");
        \\const std = @import("std");
    ,
        \\const std = @import("std");
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\
        \\
    );
}

test "convert multiline string literal" {
    try testConvertString(
        \\const foo = \\Hell<cursor>o
        \\            \\World
        \\;
    ,
        \\const foo = "Hello\nWorld";
    );
    // Empty
    try testConvertString(
        \\const foo = \\<cursor>
        \\;
    ,
        \\const foo = "";
    );
    // Multi-byte characters
    try testConvertString(
        \\const foo = \\He😂ll<cursor>o
        \\            \\Wo🤓rld
        \\;
    ,
        \\const foo = "He😂llo\nWo🤓rld";
    );
    // Quotes
    try testConvertString(
        \\const foo = \\The<cursor> "cure"
        \\;
    ,
        \\const foo = "The \"cure\"";
    );
    try testConvertString(
        \\const foo = \\<cursor>\x49 \u{0033}
        \\            \\\n'
        \\            \\
        \\;
    ,
        \\const foo = "\\x49 \\u{0033}\n\\n'\n";
    );
    // The control characters TAB and CR are rejected by the grammar inside multi-line string literals,
    // except if CR is directly before NL.
    try testConvertString( // (force format)
        "const foo = \\\\<cursor>Hello\r\n;",
        \\const foo = "Hello";
    );
}

test "convert string literal to multiline" {
    try testConvertString(
        \\const foo = "He<cursor>llo\nWorld";
    ,
        \\const foo = \\Hello
        \\    \\World
        \\;
    );
    // Empty
    try testConvertString(
        \\const foo = "<cursor>";
    ,
        \\const foo = \\
        \\;
    );
    // In function
    try testConvertString(
        \\const x = foo("<cursor>bar\nbaz");
    ,
        \\const x = foo(\\bar
        \\    \\baz
        \\);
    );
}

test "convert string literal to multiline - cursor outside of string literal" {
    try testConvertString(
        \\const foo = <cursor> "hello";
    ,
        \\const foo =  "hello";
    );
    try testConvertString(
        \\const foo = <cursor>"hello";
    ,
        \\const foo = \\hello
        \\;
    );
    try testConvertString(
        \\const foo = "hello"<cursor>;
    ,
        \\const foo = \\hello
        \\;
    );
    // TODO
    // try testConvertString(
    //     \\const foo = "hello" <cursor>;
    // ,
    //     \\const foo = "hello" <cursor>;
    // );
}

test "convert string literal to multiline - escapes" {
    // Hex escapes
    try testConvertString(
        \\const foo = "<cursor>\x41\x42\x43";
    ,
        \\const foo = \\ABC
        \\;
    );
    // Hex escapes that form a unicode character in utf-8
    try testConvertString(
        \\const foo = "<cursor>\xE2\x9C\x85";
    ,
        \\const foo = \\✅
        \\;
    );
    // Newlines
    try testConvertString(
        \\const foo = "<cursor>\nhello\n\n";
    ,
        \\const foo = \\
        \\    \\hello
        \\    \\
        \\    \\
        \\;
    );
    // Quotes and slashes
    try testConvertString(
        \\const foo = "<cursor>A slash: \'\\\'";
    ,
        \\const foo = \\A slash: '\'
        \\;
    );
    // Unicode
    try testConvertString(
        \\const foo = "<cursor>Smile: \u{1F913}";
    ,
        \\const foo = \\Smile: 🤓
        \\;
    );
}

test "convert string literal to multiline - invalid" {
    // Invalid unicode
    try testConvertString(
        \\const foo = "<cursor>Smile: \u{1F9131}";
    ,
        \\const foo = "Smile: \u{1F9131}";
    );
    // Invalid utf-8
    try testConvertString(
        \\const foo = "<cursor>\xaa";
    ,
        \\const foo = "\xaa";
    );
    // Hex escaped unprintable character
    try testConvertString(
        \\const foo = "<cursor>\x7f";
    ,
        \\const foo = "\x7f";
    );
    // Tabs are invalid too
    try testConvertString(
        \\const foo = "<cursor>\tWe use tabs";
    ,
        \\const foo = "\tWe use tabs";
    );
    // A Multi-Line String Literals can't contain carriage returns
    try testConvertString(
        \\const foo = "<cursor>\r";
    ,
        \\const foo = "\r";
    );
    // Not in @import
    try testConvertString(
        \\const std = @import("<cursor>std");
    ,
        \\const std = @import("std");
    );
    // Not in test
    try testConvertString(
        \\test "<cursor>addition" { }
    ,
        \\test "addition" { }
    );
    // Not in extern
    try testConvertString(
        \\pub extern "<cursor>c" fn printf(format: [*:0]const u8) c_int;
    ,
        \\pub extern "c" fn printf(format: [*:0]const u8) c_int;
    );
}

fn testAutofix(before: []const u8, after: []const u8) !void {
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.fixAll", .want_zir = true }); // diagnostics come from std.zig.AstGen
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.fixAll", .want_zir = false }); // diagnostics come from calling zig ast-check
}

fn testOrganizeImports(before: []const u8, after: []const u8) !void {
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.organizeImports" });
}

fn testConvertString(before: []const u8, after: []const u8) !void {
    try testDiagnostic(before, after, .{ .filter_kind = types.CodeActionKind.refactor });
}

fn testDiagnostic(
    before: []const u8,
    after: []const u8,
    options: struct {
        filter_kind: ?types.CodeActionKind = null,
        filter_title: ?[]const u8 = null,
        want_zir: bool = true,
    },
) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();
    ctx.server.config_manager.config.prefer_ast_check_as_child_process = !options.want_zir;

    var phr = try helper.collectClearPlaceholders(allocator, before);
    defer phr.deinit(allocator);
    const placeholders = phr.locations.items(.new);
    const source = phr.new_source;

    const range: types.Range = switch (placeholders.len) {
        0 => .{
            .start = .{ .line = 0, .character = 0 },
            .end = offsets.indexToPosition(before, before.len, ctx.server.offset_encoding),
        },
        1 => blk: {
            const point = offsets.indexToPosition(before, placeholders[0].start, ctx.server.offset_encoding);
            break :blk .{ .start = point, .end = point };
        },
        else => unreachable,
    };

    const uri = try ctx.addDocument(.{ .source = source });
    const handle = ctx.server.document_store.getHandle(uri).?;

    const params: types.CodeActionParams = .{
        .textDocument = .{ .uri = uri },
        .range = range,
        .context = .{
            .diagnostics = &.{},
            .only = if (options.filter_kind) |kind| &.{kind} else null,
        },
    };

    @setEvalBranchQuota(5000);
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/codeAction", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var text_edits: std.ArrayList(types.TextEdit) = .empty;
    defer text_edits.deinit(allocator);

    for (response) |action| {
        const code_action: types.CodeAction = action.CodeAction;

        if (options.filter_kind) |kind| {
            // check that `types.CodeActionContext.only` is being respected
            try std.testing.expectEqual(code_action.kind.?, kind);
        }
        if (options.filter_title) |title| {
            if (!std.mem.eql(u8, title, code_action.title)) continue;
        }

        const workspace_edit = code_action.edit.?;
        const changes = workspace_edit.changes.?.map;
        try std.testing.expectEqual(@as(usize, 1), changes.count());
        try std.testing.expect(changes.contains(uri));

        try text_edits.appendSlice(allocator, changes.get(uri).?);
    }

    const actual = try zls.diff.applyTextEdits(allocator, source, text_edits.items, ctx.server.offset_encoding);
    defer allocator.free(actual);
    try ctx.server.document_store.refreshLspSyncedDocument(uri, try allocator.dupeZ(u8, actual));

    try std.testing.expectEqualStrings(after, handle.tree.source);
}
