const std = @import("std");
const zls = @import("zls");

const helper = @import("helper");
const Context = @import("context").Context;

const types = zls.types;
const offsets = zls.offsets;
const requests = zls.requests;

const allocator: std.mem.Allocator = std.testing.allocator;

test "inlayhints - empty" {
    try testInlayHints("");
}

test "inlayhints - function call" {
    try testInlayHints(
        \\fn foo(alpha: u32) void {}
        \\const _ = foo(<alpha>5);
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(<alpha>5,<beta>4);
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(  <alpha>3 + 2 ,  <beta>(3 - 2));
    );
    try testInlayHints(
        \\fn foo(alpha: u32, beta: u64) void {}
        \\const _ = foo(
        \\    <alpha>3 + 2,
        \\    <beta>(3 - 2),
        \\);
    );
}

test "inlayhints - function self parameter" {
    try testInlayHints(
        \\const Foo = struct { pub fn bar(self: *Foo, alpha: u32) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5);
    );
    try testInlayHints(
        \\const Foo = struct { pub fn bar(_: Foo, alpha: u32, beta: []const u8) void {} };
        \\const foo: Foo = .{};
        \\const _ = foo.bar(<alpha>5,<beta>"");
    );
}

test "inlayhints - builtin call" {
    try testInlayHints(
        \\const _ = @intCast(<DestType>u32,<int>5);
    );
    try testInlayHints(
        \\const _ = @memcpy(<dest>null,<source>null,<byte_count>0);
    );

    try testInlayHints(
        \\const _ = @sizeOf(u32);
    );
    try testInlayHints(
        \\const _ = @TypeOf(5);
    );
}

fn testInlayHints(source: []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.requestDidOpen("file:///test.zig", phr.new_source);

    const range = types.Range{
        .start = types.Position{ .line = 0, .character = 0 },
        .end = offsets.indexToPosition(phr.new_source, phr.new_source.len, .utf16),
    };

    const InlayHint = struct {
        position: types.Position,
        label: []const u8,
        kind: types.InlayHintKind,
    };

    const request = requests.InlayHint{
        .params = .{
            .textDocument = .{ .uri = "file:///test.zig" },
            .range = range,
        },
    };

    const response = try ctx.requestGetResponse([]InlayHint, "textDocument/inlayHint", request);
    defer response.deinit();

    const hints = response.result;

    var i: usize = 0;
    outer: while (i < phr.locations.len) : (i += 1) {
        const old_loc = phr.locations.items(.old)[i];
        const new_loc = phr.locations.items(.new)[i];

        const expected_name = offsets.locToSlice(source, old_loc);
        const expected_label = expected_name[1 .. expected_name.len - 1]; // convert <name> to name

        const position = offsets.indexToPosition(phr.new_source, new_loc.start, ctx.server.offset_encoding);

        for (hints) |hint| {
            if (position.line != hint.position.line or position.character != hint.position.character) continue;

            try std.testing.expect(hint.label.len != 0);
            const trimmedLabel = hint.label[0 .. hint.label.len - 1]; // exclude :
            try std.testing.expectEqualStrings(expected_label, trimmedLabel);
            try std.testing.expectEqual(types.InlayHintKind.Parameter, hint.kind);

            continue :outer;
        }
        std.debug.print("Placeholder '{s}' at {}:{} (line:colon) not found!", .{ expected_name, position.line, position.character });
        return error.PlaceholderNotFound;
    }
}
