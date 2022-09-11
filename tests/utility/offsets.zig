const std = @import("std");
const zls = @import("zls");

const types = zls.types;
const offsets = zls.offsets;

test "offsets - index <-> Position" {
    try testIndexPosition("", 0, 0, .{ 0, 0, 0 });

    try testIndexPosition("hello from zig", 10, 0, .{ 10, 10, 10 });

    try testIndexPosition("\n", 0, 0, .{ 0, 0, 0 });
    try testIndexPosition("\n", 1, 1, .{ 0, 0, 0 });

    try testIndexPosition("hello\nfrom\nzig\n", 5, 0, .{ 5, 5, 5 });
    try testIndexPosition("hello\nfrom\nzig\n", 6, 1, .{ 0, 0, 0 });
    try testIndexPosition("hello\nfrom\nzig\n", 8, 1, .{ 2, 2, 2 });
    try testIndexPosition("\nhello\nfrom\nzig", 15, 3, .{ 3, 3, 3 });

    try testIndexPosition("a¶↉🠁", 10, 0, .{ 10, 5, 4 });
    try testIndexPosition("🇺🇸 🇩🇪", 17, 0, .{ 17, 9, 5 });

    try testIndexPosition("a¶↉🠁\na¶↉🠁", 10, 0, .{ 10, 5, 4 });
    try testIndexPosition("a¶↉🠁\na¶↉🠁", 11, 1, .{ 0, 0, 0 });
    try testIndexPosition("a¶↉🠁\na¶↉🠁", 21, 1, .{ 10, 5, 4 });

    try testIndexPosition("\na¶↉🠁", 4, 1, .{ 3, 2, 2 });
    try testIndexPosition("a¶↉🠁\n", 6, 0, .{ 6, 3, 3 });
    try testIndexPosition("a¶↉🠁\n", 11, 1, .{ 0, 0, 0 });
}

test "offsets - tokenToLoc" {
    try testTokenToLoc("foo", 0, 0, 3);
    try testTokenToLoc("foo\n", 0, 0, 3);
    try testTokenToLoc("\nfoo", 0, 1, 4);
    try testTokenToLoc("foo:", 0, 0, 3);
    try testTokenToLoc(";;", 1, 1, 2);
}

test "offsets - tokenIndexToLoc" {
    try testTokenIndexToLoc("", 0, 0, 0);
    try testTokenIndexToLoc("foo", 0, 0, 3);
    try testTokenIndexToLoc("0, 0", 3, 3, 4);
    try testTokenIndexToLoc(" bar ", 0, 1, 4);
}

test "offsets - lineLocAtIndex" {
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("\n", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("\n", 1));

    try std.testing.expectEqualStrings("foo", offsets.lineSliceAtIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("bar", offsets.lineSliceAtIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("bar", offsets.lineSliceAtIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", offsets.lineSliceAtIndex("foo\n", 3));
}

test "offsets - lineLocUntilIndex" {
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("\n", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("\n", 1));

    try std.testing.expectEqualStrings("fo", offsets.lineSliceUntilIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("ba", offsets.lineSliceUntilIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", offsets.lineSliceUntilIndex("foo\n", 3));
}

test "offsets - convertPositionEncoding" {
    // TODO implements tests
}

test "offsets - advancePosition" {
    try testAdvancePosition("", 0, 0, 0, 0, 0, 0);
    try testAdvancePosition("foo", 0, 3, 0, 0, 0, 3);
    try testAdvancePosition("\n", 1, 0, 0, 0, 0, 1);
    // try testAdvancePosition("foo\nbar", 1, 2, 0, 1, 1, 6); // TODO fix failing test
}

test "offsets - countCodeUnits" {
    try testCountCodeUnits("", .{ 0, 0, 0 });
    try testCountCodeUnits("a\na", .{ 3, 3, 3 });
    try testCountCodeUnits("a¶↉🠁", .{ 10, 5, 4 });
    try testCountCodeUnits("🠁↉¶a", .{ 10, 5, 4 });
    try testCountCodeUnits("🇺🇸 🇩🇪", .{ 17, 9, 5 });
}

test "offsets - getNCodeUnitByteCount" {
    try testGetNCodeUnitByteCount("", .{ 0, 0, 0 });
    try testGetNCodeUnitByteCount("foo", .{ 2, 2, 2 });
    try testGetNCodeUnitByteCount("a¶🠁🠁", .{ 7, 4, 3 });
    try testGetNCodeUnitByteCount("🇺🇸 🇩🇪", .{ 9, 5, 3 });
}

fn testIndexPosition(text: []const u8, index: usize, line: u32, characters: [3]u32) !void {
    const position8: types.Position = .{ .line = line, .character = characters[0] };
    const position16: types.Position = .{ .line = line, .character = characters[1] };
    const position32: types.Position = .{ .line = line, .character = characters[2] };

    try std.testing.expectEqual(position8, offsets.indexToPosition(text, index, .utf8));
    try std.testing.expectEqual(position16, offsets.indexToPosition(text, index, .utf16));
    try std.testing.expectEqual(position32, offsets.indexToPosition(text, index, .utf32));

    try std.testing.expectEqual(index, offsets.positionToIndex(text, position8, .utf8));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position16, .utf16));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position32, .utf32));
}

fn testTokenToLoc(text: [:0]const u8, token_index: std.zig.Ast.TokenIndex, start: usize, end: usize) !void {
    var tree = try std.zig.parse(std.testing.allocator, text);
    defer tree.deinit(std.testing.allocator);

    const actual = offsets.tokenToLoc(tree, token_index);

    try std.testing.expectEqual(start, actual.start);
    try std.testing.expectEqual(end, actual.end);
}

fn testTokenIndexToLoc(text: [:0]const u8, index: usize, start: usize, end: usize) !void {
    const loc = offsets.tokenIndexToLoc(text, index);

    try std.testing.expectEqual(start, loc.start);
    try std.testing.expectEqual(end, loc.end);
}

fn testAdvancePosition(text: [:0]const u8, expected_line: u32, expected_character: u32, line: u32, character: u32, from: usize, to: usize) !void {
    const expected: types.Position = .{.line = expected_line, .character = expected_character};
    const actual = offsets.advancePosition(text, .{.line = line, .character = character}, from, to, .utf16);

    try std.testing.expectEqual(expected, actual);
}

fn testCountCodeUnits(text: []const u8, counts: [3]usize) !void {
    try std.testing.expectEqual(counts[0], offsets.countCodeUnits(text, .utf8));
    try std.testing.expectEqual(counts[1], offsets.countCodeUnits(text, .utf16));
    try std.testing.expectEqual(counts[2], offsets.countCodeUnits(text, .utf32));
}

fn testGetNCodeUnitByteCount(text: []const u8, n: [3]usize) !void {
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[0], .utf8));
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[1], .utf16));
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[2], .utf32));
}

