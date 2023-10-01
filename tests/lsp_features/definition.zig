const std = @import("std");
const mem = std.mem;
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

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
    try testDefinition(
        \\fn main() void { <>foo(); }
        \\fn <def>foo</def>() void {}
    );
}

fn testDefinition(source: []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var cursor: ?offsets.Loc = null;
    var def_start: ?offsets.Loc = null;
    var def_end: ?offsets.Loc = null;
    for (phr.locations.items(.old), phr.locations.items(.new)) |old_loc, new_loc| {
        const str = offsets.locToSlice(source, old_loc);
        if (mem.eql(u8, str, "<>")) cursor = new_loc;
        if (mem.eql(u8, str, "<def>")) def_start = new_loc;
        if (mem.eql(u8, str, "</def>")) def_end = new_loc;
    }
    try std.testing.expect(cursor != null);
    try std.testing.expect(def_start != null);
    try std.testing.expect(def_end != null);

    var ctx = try Context.init();
    defer ctx.deinit();

    ctx.server.client_capabilities.supports_textDocument_definition_linkSupport = true;

    const cursor_lsp = offsets.locToRange(phr.new_source, cursor.?, ctx.server.offset_encoding).start;
    const def_range_lsp = offsets.locToRange(phr.new_source, .{ .start = def_start.?.end, .end = def_end.?.start }, ctx.server.offset_encoding);

    const test_uri = try ctx.addDocument(phr.new_source);

    const params = types.DefinitionParams{
        .textDocument = .{ .uri = test_uri },
        .position = cursor_lsp,
    };

    const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/definition", params) orelse return error.UnresolvedDefinition;
    try std.testing.expectEqual(@as(usize, 1), response.array_of_DefinitionLink.len);
    try std.testing.expectEqual(def_range_lsp, response.array_of_DefinitionLink[0].targetSelectionRange);
}
