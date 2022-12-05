const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;
const requests = zls.requests;

const allocator: std.mem.Allocator = std.testing.allocator;

test "selectionRange - empty" {
    try testSelectionRange("<>", &.{});
}

test "seletionRange - smoke" {
    try testSelectionRange(
        \\fn main() void {
        \\    const x = 1 <>+ 1;
        \\}
    , &.{ "1 + 1", "const x = 1 + 1", "{\n    const x = 1 + 1;\n}" });
}

fn testSelectionRange(source: []const u8, want: []const []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    try ctx.requestDidOpen(test_uri, phr.new_source);

    const position = offsets.locToRange(phr.new_source, phr.locations.items(.new)[0], .utf16).start;

    const SelectionRange = struct {
        range: types.Range,
        parent: ?*@This(),
    };

    const request = requests.SelectionRange{ .params = .{
        .textDocument = .{ .uri = test_uri },
        .positions = &.{position},
    } };

    const response = try ctx.requestGetResponse(?[]SelectionRange, "textDocument/selectionRange", request);
    defer response.deinit();

    const selectionRanges: []SelectionRange = response.result orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    var got = std.ArrayList([]const u8).init(allocator);
    defer got.deinit();

    var it: ?*SelectionRange = &selectionRanges[0];
    while (it) |r| {
        const slice = offsets.rangeToSlice(phr.new_source, r.range, .utf16);
        (try got.addOne()).* = slice;
        it = r.parent;
    }
    const last = got.pop();
    try std.testing.expectEqualStrings(phr.new_source, last);
    try std.testing.expectEqual(want.len, got.items.len);
    for (want) |w, i| {
        try std.testing.expectEqualStrings(w, got.items[i]);
    }
}
