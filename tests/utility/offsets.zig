const std = @import("std");
const zls = @import("zls");

const types = zls.types;
const offsets = zls.offsets;
const Loc = offsets.Loc;

const Ast = std.zig.Ast;

test "index <-> Position" {
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

test "positionToIndex where character value is greater than the line length" {
    try testPositionToIndex("", 0, 0, .{ 1, 1, 1 });

    try testPositionToIndex("\n", 0, 0, .{ 1, 1, 1 });
    try testPositionToIndex("\n", 0, 0, .{ 2, 2, 2 });
    try testPositionToIndex("\n", 0, 0, .{ 3, 3, 3 });

    try testPositionToIndex("\n", 1, 1, .{ 1, 1, 1 });
    try testPositionToIndex("\n", 1, 1, .{ 2, 2, 2 });
    try testPositionToIndex("\n", 1, 1, .{ 3, 3, 3 });

    try testPositionToIndex("hello\nfrom\nzig\n", 5, 0, .{ 6, 6, 6 });
    try testPositionToIndex("hello\nfrom\nzig\n", 10, 1, .{ 5, 5, 5 });

    try testPositionToIndex("a¶↉🠁\na¶↉🠁", 21, 1, .{ 11, 6, 5 });
    try testPositionToIndex("a¶↉🠁\na¶↉🠁\n", 21, 1, .{ 11, 6, 5 });
}

test "tokenToLoc" {
    try testTokenToLoc("foo", 0, 0, 3);
    try testTokenToLoc("foo\n", 0, 0, 3);
    try testTokenToLoc("\nfoo", 0, 1, 4);
    try testTokenToLoc("foo:", 0, 0, 3);
    try testTokenToLoc(";;", 1, 1, 2);
}

test "tokenIndexToLoc" {
    try testTokenIndexToLoc("", 0, 0, 0);
    try testTokenIndexToLoc("foo", 0, 0, 3);
    try testTokenIndexToLoc("0, 0", 3, 3, 4);
    try testTokenIndexToLoc(" bar ", 0, 1, 4);
}

test "identifierIndexToNameLoc" {
    try std.testing.expectEqualStrings("", offsets.identifierIndexToNameSlice("", 0));
    try std.testing.expectEqualStrings("", offsets.identifierIndexToNameSlice(" ", 0));
    try std.testing.expectEqualStrings("", offsets.identifierIndexToNameSlice(" world", 0));

    try std.testing.expectEqualStrings("hello", offsets.identifierIndexToNameSlice("hello", 0));
    try std.testing.expectEqualStrings("hello", offsets.identifierIndexToNameSlice("hello world", 0));
    try std.testing.expectEqualStrings("world", offsets.identifierIndexToNameSlice("hello world", 6));

    try std.testing.expectEqualStrings("hello", offsets.identifierIndexToNameSlice("@\"hello\"", 0));
    try std.testing.expectEqualStrings("hello", offsets.identifierIndexToNameSlice("@\"hello\" world", 0));
    try std.testing.expectEqualStrings("world", offsets.identifierIndexToNameSlice("@\"hello\" @\"world\"", 9));
}

test "lineLocAtIndex" {
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("\n", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("\n", 1));

    try std.testing.expectEqualStrings("foo", offsets.lineSliceAtIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("bar", offsets.lineSliceAtIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("bar", offsets.lineSliceAtIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", offsets.lineSliceAtIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", offsets.lineSliceAtIndex("foo\n", 3));
}

test "multilineLocAtIndex" {
    const text =
        \\line0
        \\line1
        \\line2
        \\line3
        \\line4
    ;
    try std.testing.expectEqualStrings(offsets.lineSliceAtIndex(text, 0), offsets.multilineSliceAtIndex(text, 0, 0));
    try std.testing.expectEqualStrings(offsets.lineSliceAtIndex(text, 5), offsets.multilineSliceAtIndex(text, 5, 0));
    try std.testing.expectEqualStrings(offsets.lineSliceAtIndex(text, 6), offsets.multilineSliceAtIndex(text, 6, 0));

    try std.testing.expectEqualStrings("line1\nline2\nline3", offsets.multilineSliceAtIndex(text, 15, 1));
    try std.testing.expectEqualStrings("line0\nline1", offsets.multilineSliceAtIndex(text, 3, 1));
    try std.testing.expectEqualStrings("line3\nline4", offsets.multilineSliceAtIndex(text, 27, 1));
}

test "lineLocUntilIndex" {
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("\n", 0));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("\n", 1));

    try std.testing.expectEqualStrings("fo", offsets.lineSliceUntilIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("ba", offsets.lineSliceUntilIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", offsets.lineSliceUntilIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", offsets.lineSliceUntilIndex("foo\n", 3));
}

test "convertPositionEncoding" {
    try testConvertPositionEncoding("", 0, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("\n", 0, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("\n", 1, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("foo", 0, 3, .{ 3, 3, 3 });
    try testConvertPositionEncoding("a¶↉🠁", 0, 10, .{ 10, 5, 4 });
    try testConvertPositionEncoding("a¶↉🠁\na¶↉🠁", 1, 6, .{ 6, 3, 3 });
}
test "locIntersect" {
    const a = Loc{ .start = 2, .end = 5 };
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 0, .end = 2 }) == false);
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 1, .end = 3 }) == true);
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 2, .end = 4 }) == true);
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 3, .end = 5 }) == true);
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 4, .end = 6 }) == true);
    try std.testing.expect(offsets.locIntersect(a, .{ .start = 5, .end = 7 }) == false);
}

test "locInside" {
    const outer = Loc{ .start = 2, .end = 5 };
    try std.testing.expect(offsets.locInside(.{ .start = 0, .end = 2 }, outer) == false);
    try std.testing.expect(offsets.locInside(.{ .start = 1, .end = 3 }, outer) == false);
    try std.testing.expect(offsets.locInside(.{ .start = 2, .end = 4 }, outer) == true);
    try std.testing.expect(offsets.locInside(.{ .start = 3, .end = 5 }, outer) == true);
    try std.testing.expect(offsets.locInside(.{ .start = 4, .end = 6 }, outer) == false);
    try std.testing.expect(offsets.locInside(.{ .start = 5, .end = 7 }, outer) == false);
}

test "locMerge" {
    const a = Loc{ .start = 2, .end = 5 };
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 0, .end = 2 }), Loc{ .start = 0, .end = 5 });
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 1, .end = 3 }), Loc{ .start = 1, .end = 5 });
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 2, .end = 4 }), Loc{ .start = 2, .end = 5 });
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 3, .end = 5 }), Loc{ .start = 2, .end = 5 });
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 4, .end = 6 }), Loc{ .start = 2, .end = 6 });
    try std.testing.expectEqualDeep(offsets.locMerge(a, .{ .start = 5, .end = 7 }), Loc{ .start = 2, .end = 7 });
}

test "advancePosition" {
    try testAdvancePosition("", 0, 0, 0, 0, 0, 0);
    try testAdvancePosition("foo", 0, 3, 0, 0, 0, 3);
    try testAdvancePosition("\n", 1, 0, 0, 0, 0, 1);
    try testAdvancePosition("foo\nbar", 1, 2, 0, 1, 1, 6);
    try testAdvancePosition("foo\nbar", 1, 3, 1, 0, 4, 7);
}

test "countCodeUnits" {
    try testCountCodeUnits("", .{ 0, 0, 0 });
    try testCountCodeUnits("a\na", .{ 3, 3, 3 });
    try testCountCodeUnits("a¶↉🠁", .{ 10, 5, 4 });
    try testCountCodeUnits("🠁↉¶a", .{ 10, 5, 4 });
    try testCountCodeUnits("🇺🇸 🇩🇪", .{ 17, 9, 5 });
}

test "getNCodeUnitByteCount" {
    try testGetNCodeUnitByteCount("", .{ 0, 0, 0 });
    try testGetNCodeUnitByteCount("foo", .{ 2, 2, 2 });
    try testGetNCodeUnitByteCount("a¶🠁🠁", .{ 7, 4, 3 });
    try testGetNCodeUnitByteCount("🇺🇸 🇩🇪", .{ 9, 5, 3 });
}

fn testIndexPosition(text: []const u8, index: usize, line: u32, characters: [3]u32) !void {
    const position8: types.Position = .{ .line = line, .character = characters[0] };
    const position16: types.Position = .{ .line = line, .character = characters[1] };
    const position32: types.Position = .{ .line = line, .character = characters[2] };

    try std.testing.expectEqual(position8, offsets.indexToPosition(text, index, .@"utf-8"));
    try std.testing.expectEqual(position16, offsets.indexToPosition(text, index, .@"utf-16"));
    try std.testing.expectEqual(position32, offsets.indexToPosition(text, index, .@"utf-32"));

    try std.testing.expectEqual(index, offsets.positionToIndex(text, position8, .@"utf-8"));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position16, .@"utf-16"));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position32, .@"utf-32"));
}

fn testPositionToIndex(text: []const u8, index: usize, line: u32, characters: [3]u32) !void {
    const position8: types.Position = .{ .line = line, .character = characters[0] };
    const position16: types.Position = .{ .line = line, .character = characters[1] };
    const position32: types.Position = .{ .line = line, .character = characters[2] };

    try std.testing.expectEqual(index, offsets.positionToIndex(text, position8, .@"utf-8"));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position16, .@"utf-16"));
    try std.testing.expectEqual(index, offsets.positionToIndex(text, position32, .@"utf-32"));
}

fn testTokenToLoc(text: [:0]const u8, token_index: Ast.TokenIndex, start: usize, end: usize) !void {
    var tree = try Ast.parse(std.testing.allocator, text, .zig);
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
    const expected: types.Position = .{ .line = expected_line, .character = expected_character };
    const actual = offsets.advancePosition(text, .{ .line = line, .character = character }, from, to, .@"utf-16");

    try std.testing.expectEqual(expected, actual);
}

fn testConvertPositionEncoding(text: [:0]const u8, line: u32, character: u32, new_characters: [3]u32) !void {
    const position: types.Position = .{ .line = line, .character = character };

    const position8 = offsets.convertPositionEncoding(text, position, .@"utf-8", .@"utf-8");
    const position16 = offsets.convertPositionEncoding(text, position, .@"utf-8", .@"utf-16");
    const position32 = offsets.convertPositionEncoding(text, position, .@"utf-8", .@"utf-32");

    try std.testing.expectEqual(line, position8.line);
    try std.testing.expectEqual(line, position16.line);
    try std.testing.expectEqual(line, position32.line);

    try std.testing.expectEqual(new_characters[0], position8.character);
    try std.testing.expectEqual(new_characters[1], position16.character);
    try std.testing.expectEqual(new_characters[2], position32.character);
}

fn testCountCodeUnits(text: []const u8, counts: [3]usize) !void {
    try std.testing.expectEqual(counts[0], offsets.countCodeUnits(text, .@"utf-8"));
    try std.testing.expectEqual(counts[1], offsets.countCodeUnits(text, .@"utf-16"));
    try std.testing.expectEqual(counts[2], offsets.countCodeUnits(text, .@"utf-32"));
}

fn testGetNCodeUnitByteCount(text: []const u8, n: [3]usize) !void {
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[0], .@"utf-8"));
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[1], .@"utf-16"));
    try std.testing.expectEqual(n[0], offsets.getNCodeUnitByteCount(text, n[2], .@"utf-32"));
}
