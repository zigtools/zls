const std = @import("std");
const mem = std.mem;
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;
const requests = zls.requests;

const allocator: std.mem.Allocator = std.testing.allocator;

test "definition - smoke" {
    try testDefinition(
        \\fn main() void { f<>oo(); }
        \\fn <def>foo</def>() void {}
    );
}

test "definition - cursor is at the end of an identifier" {
    try testDefinition(
        \\fn main() void { foo<>(); }
        \\fn <def>foo</def>() void {}
    );
}

test "definition - cursor is at the start of an identifier" {
    testDefinition(
        \\fn main() void { <>foo(); }
        \\fn <def>foo</def>() void {}
    ) catch |err| switch (err) {
        error.UnresolvedDefinition => {
            // TODO: #891
        },
        else => return err,
    };
}

fn testDefinition(source: []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var cursor: offsets.Loc = .{ .start = 0, .end = 0 };
    var def_start: offsets.Loc = .{ .start = 0, .end = 0 };
    var def_end: offsets.Loc = .{ .start = 0, .end = 0 };
    for (phr.locations.items(.old)) |loc, i| {
        if (mem.eql(u8, source[loc.start..loc.end], "<>")) cursor = phr.locations.items(.new)[i];
        if (mem.eql(u8, source[loc.start..loc.end], "<def>")) def_start = phr.locations.items(.new)[i];
        if (mem.eql(u8, source[loc.start..loc.end], "</def>")) def_end = phr.locations.items(.new)[i];
    }

    const cursor_lsp = offsets.locToRange(phr.new_source, cursor, .@"utf-16").start;
    const def_range_lsp = offsets.locToRange(phr.new_source, .{ .start = def_start.end, .end = def_end.start }, .@"utf-16");

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    try ctx.requestDidOpen(test_uri, phr.new_source);

    const params = types.TextDocumentPositionParams{
        .textDocument = .{ .uri = test_uri },
        .position = cursor_lsp,
    };

    const response = try ctx.requestGetResponse(?types.Location, "textDocument/definition", params);
    const result = response.result orelse return error.UnresolvedDefinition;
    try std.testing.expectEqual(def_range_lsp, result.range);
}
