const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.types;
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
    ,
        \\const std = @import("std");
        \\
        \\const abc = @import("abc.zig");
        \\
        \\fn main() void {}
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
    ,
        \\const abc = @import("abc.zig");
        \\
        \\const foo = @embedFile("foo.zig");
        \\
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

fn testAutofix(before: []const u8, after: []const u8) !void {
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.fixAll", .want_zir = true }); // diagnostics come from our AstGen fork
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.fixAll", .want_zir = false }); // diagnostics come from calling zig ast-check
}

fn testOrganizeImports(before: []const u8, after: []const u8) !void {
    try testDiagnostic(before, after, .{ .filter_kind = .@"source.organizeImports" });
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
    var ctx = try Context.init();
    defer ctx.deinit();
    ctx.server.config.prefer_ast_check_as_child_process = !options.want_zir;

    const uri = try ctx.addDocument(.{ .source = before });
    const handle = ctx.server.document_store.getHandle(uri).?;

    var error_bundle = try zls.diagnostics.getAstCheckDiagnostics(ctx.server, handle);
    defer error_bundle.deinit(ctx.server.allocator);
    var diagnostics_set: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.Diagnostic)) = .{};
    try zls.diagnostics.errorBundleToDiagnostics(error_bundle, ctx.arena.allocator(), &diagnostics_set, "ast-check", ctx.server.offset_encoding);

    const diagnostics: []const types.Diagnostic = switch (diagnostics_set.count()) {
        0 => &.{},
        1 => diagnostics_set.values()[0].items,
        else => unreachable, // ast-check diagnostics only affect a single file
    };

    const params: types.CodeActionParams = .{
        .textDocument = .{ .uri = uri },
        .range = .{
            .start = .{ .line = 0, .character = 0 },
            .end = offsets.indexToPosition(before, before.len, ctx.server.offset_encoding),
        },
        .context = .{ .diagnostics = diagnostics },
    };

    @setEvalBranchQuota(5000);
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/codeAction", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var text_edits: std.ArrayListUnmanaged(types.TextEdit) = .{};
    defer text_edits.deinit(allocator);

    for (response) |action| {
        const code_action: types.CodeAction = action.CodeAction;

        if (options.filter_kind) |kind| if (!code_action.kind.?.eql(kind)) continue;
        if (options.filter_title) |title| if (!std.mem.eql(u8, title, code_action.title)) continue;

        const workspace_edit = code_action.edit.?;
        const changes = workspace_edit.changes.?.map;
        try std.testing.expectEqual(@as(usize, 1), changes.count());
        try std.testing.expect(changes.contains(uri));

        try text_edits.appendSlice(allocator, changes.get(uri).?);
    }

    const actual = try zls.diff.applyTextEdits(allocator, before, text_edits.items, ctx.server.offset_encoding);
    defer allocator.free(actual);
    try ctx.server.document_store.refreshDocument(uri, try allocator.dupeZ(u8, actual));

    try std.testing.expectEqualStrings(after, handle.tree.source);
}
