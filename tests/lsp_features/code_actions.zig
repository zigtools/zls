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
        \\    _ = foo;
        \\    const bar, var baz = .{ 1, 2 };
        \\    _ = baz;
        \\    _ = bar;
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
        \\    _ = c;
        \\    _ = b;
        \\    _ = a;
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
        \\        _ = k;
        \\        _ = j;
        \\        _ = i;
        \\    }
        \\    switch (union(enum) {}{}) {
        \\        inline .a => |cap, tag| {
        \\            _ = tag;
        \\            _ = cap;
        \\        },
        \\    }
        \\    if (null) |x| {
        \\        _ = x;
        \\    }
        \\    if (null) |v| {
        \\        _ = v;
        \\    } else |e| {
        \\        _ = e;
        \\    }
        \\    _ = null catch |e| {
        \\        _ = e;
        \\    };
        \\}
        \\
    );
}

test "code actions - discard capture with comment" {
    try testAutofix(
        \\test {
        \\  if (1 == 1) |a|
        \\      //a
        \\      {}
        \\}
    ,
        \\test {
        \\    if (1 == 1) |a|
        \\    //a
        \\    {
        \\        _ = a;
        \\    }
        \\}
        \\
    );
}

test "code actions - remove pointless discard" {
    try testAutofix(
        \\fn foo(a: u32) u32 {
        \\    _ = a;
        \\    var b: ?u32 = a;
        \\    _ = b;
        \\    const c = b;
        \\    _ = c;
        \\    if (c) |d| {
        \\        _ = d;
        \\        return d;
        \\    }
        \\    return 0;
        \\}
        \\
    ,
        \\fn foo(a: u32) u32 {
        \\    var b: ?u32 = a;
        \\    const c = b;
        \\    if (c) |d| {
        \\        return d;
        \\    }
        \\    return 0;
        \\}
        \\
    );
}

/// does not check for correct formatting
fn testAutofix(before: []const u8, after: []const u8) !void {
    var ctx = try Context.init();
    defer ctx.deinit();
    ctx.server.config.enable_ast_check_diagnostics = true;

    const uri = try ctx.addDocument(before);
    const handle = ctx.server.document_store.getHandle(uri).?;

    var diagnostics: std.ArrayListUnmanaged(types.Diagnostic) = .{};
    try zls.diagnostics.getAstCheckDiagnostics(ctx.server, ctx.arena.allocator(), handle.*, &diagnostics);

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

    try std.testing.expect(handle.tree.errors.len == 0);
    const formatted_actual = try handle.tree.render(allocator);
    defer allocator.free(formatted_actual);

    try std.testing.expectEqualStrings(after, formatted_actual);
}
