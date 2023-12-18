const std = @import("std");
const zls = @import("zls");

const Context = @import("../context.zig").Context;

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "code actions - discard value" {
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

test "code actions - discard function parameter" {
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

test "code actions - discard captures" {
    try testAutofix(
        \\test {
        \\    for (0..10, 0..10, 0..10) |i, j, k| {}
        \\    switch (union(enum) {}{}) {
        \\        inline .a => |cap, tag| {},
        \\    }
        \\    if (null) |x| {}
        \\    if (null) |v| {} else |e| {}
        \\    _ = null catch |e| {};
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
        \\}
        \\
    );
}

test "code actions - discard capture with comment" {
    try testAutofix(
        \\test {
        \\    if (1 == 1) |a|
        \\    //a
        \\    {}
        \\}
        \\
    ,
        \\test {
        \\    if (1 == 1) |a|
        \\    //a
        \\    {
        \\        _ = a; // autofix
        \\    }
        \\}
        \\
    );
}

test "code actions - discard capture - while loop with continue" {
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

test "code actions - remove pointless discard" {
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

test "code actions - remove discard of unknown identifier" {
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

test "code actions - ignore autofix comment whitespace" {
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

fn testAutofix(before: []const u8, after: []const u8) !void {
    try testAutofixOptions(before, after, true); // diagnostics come from our AstGen fork
    try testAutofixOptions(before, after, false); // diagnostics come from calling zig ast-check
}

fn testAutofixOptions(before: []const u8, after: []const u8, want_zir: bool) !void {
    var ctx = try Context.init();
    defer ctx.deinit();
    ctx.server.config.enable_autofix = true;
    ctx.server.config.enable_ast_check_diagnostics = true;
    ctx.server.config.prefer_ast_check_as_child_process = !want_zir;

    const uri = try ctx.addDocument(before);
    const handle = ctx.server.document_store.getHandle(uri).?;

    var diagnostics: std.ArrayListUnmanaged(types.Diagnostic) = .{};
    try zls.diagnostics.getAstCheckDiagnostics(ctx.server, ctx.arena.allocator(), handle, &diagnostics);

    const params = types.CodeActionParams{
        .textDocument = .{ .uri = uri },
        .range = .{
            .start = .{ .line = 0, .character = 0 },
            .end = offsets.indexToPosition(before, before.len, ctx.server.offset_encoding),
        },
        .context = .{ .diagnostics = diagnostics.items },
    };

    @setEvalBranchQuota(5000);
    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/codeAction", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var text_edits: std.ArrayListUnmanaged(types.TextEdit) = .{};
    defer text_edits.deinit(allocator);

    for (response) |action| {
        const code_action = action.CodeAction;
        if (code_action.kind.? != .@"source.fixAll") continue;
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
