//! Conversion functions between the following Units:
//! - A "index" or "source index" is a offset into a utf-8 encoding source file.
//! - `Loc`
//! - `Position`
//! - `Range`
//! - `std.zig.Ast.TokenIndex`
//! - `std.zig.Ast.Node.Index`

const std = @import("std");
const offsets = @import("lsp").offsets;
const ast = @import("ast.zig");
const Ast = std.zig.Ast;

pub const Encoding = offsets.Encoding;
pub const Loc = offsets.Loc;
pub const Position = offsets.Position;
pub const Range = offsets.Range;

pub const indexToPosition = offsets.indexToPosition;
pub const positionToIndex = offsets.positionToIndex;

pub const orderPosition = offsets.orderPosition;

pub const locLength = offsets.locLength;
pub const rangeLength = offsets.rangeLength;

pub const locToSlice = offsets.locToSlice;
pub const locToRange = offsets.locToRange;
pub const rangeToSlice = offsets.rangeToSlice;
pub const rangeToLoc = offsets.rangeToLoc;

pub const lineLocAtIndex = offsets.lineLocAtIndex;
pub const lineSliceAtIndex = offsets.lineSliceAtIndex;
pub const lineLocAtPosition = offsets.lineLocAtPosition;
pub const lineSliceAtPosition = offsets.lineSliceAtPosition;

pub const lineLocUntilIndex = offsets.lineLocUntilIndex;
pub const lineLocUntilPosition = offsets.lineLocUntilPosition;
pub const lineSliceUntilIndex = offsets.lineSliceUntilIndex;
pub const lineSliceUntilPosition = offsets.lineSliceUntilPosition;

pub const convertPositionEncoding = offsets.convertPositionEncoding;
pub const convertRangeEncoding = offsets.convertRangeEncoding;

pub const advancePosition = offsets.advancePosition;
pub const countCodeUnits = offsets.countCodeUnits;
pub const getNCodeUnitByteCount = offsets.getNCodeUnitByteCount;

pub const SourceIndexToTokenIndexResult = union(enum) {
    /// The source index is inside of whitespace.
    none: struct {
        /// The the first token to the left of the source index, if any.
        left: ?Ast.TokenIndex,
        /// The the first token to the right of the source index, if any.
        /// Will ignore the `.eof` token.
        right: ?Ast.TokenIndex,
    },
    /// The source index is on the edge or inside of a token.
    one: Ast.TokenIndex,
    /// The source index is between two tokens.
    between: struct {
        /// The the first token to the left of the source index.
        left: Ast.TokenIndex,
        /// The the first token to the right of the source index.
        right: Ast.TokenIndex,
    },

    pub fn pickPreferred(
        result: SourceIndexToTokenIndexResult,
        preferred_tags: []const std.zig.Token.Tag,
        tree: *const Ast,
    ) ?Ast.TokenIndex {
        switch (result) {
            .none => return null,
            .one => |token| return token,
            .between => |data| {
                if (std.mem.indexOfScalar(std.zig.Token.Tag, preferred_tags, tree.tokenTag(data.left)) != null) {
                    return data.left;
                }
                if (std.mem.indexOfScalar(std.zig.Token.Tag, preferred_tags, tree.tokenTag(data.right)) != null) {
                    return data.right;
                }
                return null;
            },
        }
    }

    pub fn preferLeft(result: SourceIndexToTokenIndexResult) Ast.TokenIndex {
        switch (result) {
            .none => |data| return data.left orelse 0,
            .one => |token| return token,
            .between => |data| return data.left,
        }
    }

    pub fn preferRight(result: SourceIndexToTokenIndexResult, tree: *const Ast) Ast.TokenIndex {
        switch (result) {
            .none => |data| return data.right orelse @intCast(tree.tokens.len - 1),
            .one => |token| return token,
            .between => |data| return data.right,
        }
    }
};

pub fn sourceIndexToTokenIndex(tree: Ast, source_index: usize) SourceIndexToTokenIndexResult {
    std.debug.assert(source_index <= tree.source.len);

    var upper_index: Ast.TokenIndex = @intCast(tree.tokens.len - 1);
    var lower_index: Ast.TokenIndex = 0;
    while (upper_index - lower_index > 64) {
        const mid = lower_index + (upper_index - lower_index) / 2;
        if (tree.tokenStart(mid) < source_index) {
            lower_index = mid;
        } else {
            upper_index = mid;
        }
    }

    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = tree.tokenStart(lower_index),
    };

    var previous_token_index: ?Ast.TokenIndex = null;
    var previous_token_loc: ?Loc = null;
    var current_token_index: Ast.TokenIndex = lower_index;
    while (current_token_index <= upper_index) {
        const current_token = tokenizer.next();

        if (previous_token_loc) |previous_loc| {
            if (previous_loc.end == source_index) {
                if (source_index == current_token.loc.start and current_token.tag != .eof) {
                    return .{ .between = .{ .left = previous_token_index.?, .right = current_token_index } };
                } else {
                    return .{ .one = previous_token_index.? };
                }
            }
            if (previous_loc.end < source_index and source_index < current_token.loc.start) {
                return .{ .none = .{ .left = previous_token_index.?, .right = current_token_index } };
            }
        }

        if (current_token.tag == .eof) {
            return .{ .none = .{ .left = previous_token_index, .right = null } };
        }

        if (source_index < current_token.loc.start) {
            return .{ .none = .{ .left = previous_token_index, .right = current_token_index } };
        } else if (source_index < current_token.loc.end) {
            return .{ .one = current_token_index };
        } else {
            // continue to the next iteration
        }

        previous_token_index = current_token_index;
        previous_token_loc = current_token.loc;
        current_token_index += 1;
    }

    unreachable;
}

test sourceIndexToTokenIndex {
    var tree: Ast = try .parse(std.testing.allocator, " a  bb; ", .zig);
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(
        std.zig.Token.Tag,
        &.{ .identifier, .identifier, .semicolon, .eof },
        tree.tokens.items(.tag),
    );

    const Result = SourceIndexToTokenIndexResult;
    const expectEqual = std.testing.expectEqual;

    // zig fmt: off
    try expectEqual(Result{ .none    = .{ .left = null, .right = 0    } }, sourceIndexToTokenIndex(tree, 0));
    try expectEqual(Result{ .one     = 0                                }, sourceIndexToTokenIndex(tree, 1));
    try expectEqual(Result{ .one     = 0                                }, sourceIndexToTokenIndex(tree, 2));
    try expectEqual(Result{ .none    = .{ .left = 0,    .right = 1    } }, sourceIndexToTokenIndex(tree, 3));
    try expectEqual(Result{ .one     = 1                                }, sourceIndexToTokenIndex(tree, 4));
    try expectEqual(Result{ .one     = 1                                }, sourceIndexToTokenIndex(tree, 5));
    try expectEqual(Result{ .between = .{ .left = 1,    .right = 2    } }, sourceIndexToTokenIndex(tree, 6));
    try expectEqual(Result{ .one     = 2                                }, sourceIndexToTokenIndex(tree, 7));
    try expectEqual(Result{ .none    = .{ .left = 2,    .right = null } }, sourceIndexToTokenIndex(tree, 8));
    // zig fmt: on
}

test "sourceIndexToTokenIndex - token at end" {
    var tree: Ast = try .parse(std.testing.allocator, " a", .zig);
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(
        std.zig.Token.Tag,
        &.{ .identifier, .eof },
        tree.tokens.items(.tag),
    );

    const Result = SourceIndexToTokenIndexResult;
    const expectEqual = std.testing.expectEqual;

    try expectEqual(Result{ .none = .{ .left = null, .right = 0 } }, sourceIndexToTokenIndex(tree, 0));
    try expectEqual(Result{ .one = 0 }, sourceIndexToTokenIndex(tree, 1));
    try expectEqual(Result{ .one = 0 }, sourceIndexToTokenIndex(tree, 2));
}

pub const IdentifierIndexRange = enum {
    /// delimiting `@` and `"`s are excluded
    name,
    /// delimiting `@` and `"`s are included
    full,
};

/// Support formats:
/// - `foo`
/// - `@"foo"`
/// - `@foo`
pub fn identifierIndexToLoc(text: [:0]const u8, source_index: usize, range: IdentifierIndexRange) Loc {
    if (text[source_index] == '@' and text[source_index + 1] == '"') {
        const start_index = source_index + 2;
        var index: usize = start_index;
        while (true) : (index += 1) {
            switch (text[index]) {
                '\n' => break,
                '\\' => index += 1,
                '"' => {
                    // include the closing quote
                    if (range == .full) index += 1;
                    break;
                },
                else => {},
            }
        }
        return .{ .start = if (range == .full) source_index else start_index, .end = index };
    } else {
        const start: usize = source_index + @intFromBool(text[source_index] == '@');
        var index = start;
        while (true) : (index += 1) {
            switch (text[index]) {
                'a'...'z', 'A'...'Z', '_', '0'...'9' => {},
                else => break,
            }
        }
        return .{ .start = if (range == .full) source_index else start, .end = index };
    }
}

test identifierIndexToLoc {
    try std.testing.expectEqualStrings("", identifierIndexToSlice("", 0, .name));
    try std.testing.expectEqualStrings("", identifierIndexToSlice(" ", 0, .name));
    try std.testing.expectEqualStrings("", identifierIndexToSlice(" world", 0, .name));

    try std.testing.expectEqualStrings("hello", identifierIndexToSlice("hello", 0, .name));
    try std.testing.expectEqualStrings("hello", identifierIndexToSlice("hello world", 0, .name));
    try std.testing.expectEqualStrings("world", identifierIndexToSlice("hello world", 6, .name));

    try std.testing.expectEqualStrings("hello", identifierIndexToSlice("@\"hello\"", 0, .name));
    try std.testing.expectEqualStrings("hello", identifierIndexToSlice("@\"hello\" world", 0, .name));
    try std.testing.expectEqualStrings("world", identifierIndexToSlice("@\"hello\" @\"world\"", 9, .name));

    try std.testing.expectEqualStrings("hello", identifierIndexToSlice("@hello", 0, .name));

    try std.testing.expectEqualStrings("\\\"", identifierIndexToSlice("@\"\\\"\"", 0, .name));

    try std.testing.expectEqualStrings("@hello", identifierIndexToSlice("@hello", 0, .full));
    try std.testing.expectEqualStrings("@\"hello\"", identifierIndexToSlice("@\"hello\"", 0, .full));
    try std.testing.expectEqualStrings(
        \\@"\"\\\""
    , identifierIndexToSlice(
        \\@"\"\\\""
    , 0, .full));
}

pub fn identifierIndexToSlice(text: [:0]const u8, source_index: usize, range: IdentifierIndexRange) []const u8 {
    return locToSlice(text, identifierIndexToLoc(text, source_index, range));
}

pub fn identifierTokenToNameLoc(tree: Ast, identifier_token: Ast.TokenIndex) Loc {
    std.debug.assert(switch (tree.tokenTag(identifier_token)) {
        .builtin => true, // The Zig parser likes to emit .builtin where a identifier would be expected
        .identifier => true,
        else => false,
    });
    return identifierIndexToLoc(tree.source, tree.tokenStart(identifier_token), .name);
}

pub fn identifierTokenToNameSlice(tree: Ast, identifier_token: Ast.TokenIndex) []const u8 {
    return locToSlice(tree.source, identifierTokenToNameLoc(tree, identifier_token));
}

pub fn tokensToLoc(tree: Ast, first_token: Ast.TokenIndex, last_token: Ast.TokenIndex) Loc {
    return .{ .start = tree.tokenStart(first_token), .end = tokenToLoc(tree, last_token).end };
}

pub fn tokenToLoc(tree: Ast, token_index: Ast.TokenIndex) Loc {
    const start = tree.tokenStart(token_index);
    const tag = tree.tokenTag(token_index);

    // Many tokens can be determined entirely by their tag.
    if (tag == .identifier) {
        // fast path for identifiers
        return identifierIndexToLoc(tree.source, start, .full);
    } else if (tag.lexeme()) |lexeme| {
        return .{
            .start = start,
            .end = start + lexeme.len,
        };
    } else if (tag == .invalid) {
        // invalid tokens are one byte sized so we scan left and right to find the
        // source location that contains complete code units
        // this assumes that `tree.source` is valid utf8
        var begin = token_index;
        while (begin > 0 and tree.tokenTag(begin - 1) == .invalid) : (begin -= 1) {}

        var end = token_index;
        while (end < tree.tokens.len and tree.tokenTag(end) == .invalid) : (end += 1) {}
        return .{
            .start = tree.tokenStart(begin),
            .end = tree.tokenStart(end),
        };
    }

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = start,
    };

    const token = tokenizer.next();
    // A failure would indicate a corrupted tree.source
    std.debug.assert(token.tag == tag);
    return token.loc;
}

test tokenToLoc {
    try testTokenToLoc("foo", 0, 0, 3);
    try testTokenToLoc("foo\n", 0, 0, 3);
    try testTokenToLoc("\nfoo", 0, 1, 4);
    try testTokenToLoc("foo:", 0, 0, 3);
    try testTokenToLoc(";;", 1, 1, 2);
}

fn testTokenToLoc(text: [:0]const u8, token_index: Ast.TokenIndex, start: usize, end: usize) !void {
    var tree = try Ast.parse(std.testing.allocator, text, .zig);
    defer tree.deinit(std.testing.allocator);

    const actual = tokenToLoc(tree, token_index);

    try std.testing.expectEqual(start, actual.start);
    try std.testing.expectEqual(end, actual.end);
}

pub fn tokenToSlice(tree: Ast, token_index: Ast.TokenIndex) []const u8 {
    return locToSlice(tree.source, tokenToLoc(tree, token_index));
}

pub fn tokensToSlice(tree: Ast, first_token: Ast.TokenIndex, last_token: Ast.TokenIndex) []const u8 {
    std.debug.assert(first_token <= last_token);
    return locToSlice(tree.source, tokensToLoc(tree, first_token, last_token));
}

pub fn tokenToPosition(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) Position {
    const start = tree.tokenStart(token_index);
    return indexToPosition(tree.source, start, encoding);
}

pub fn tokenToRange(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) Range {
    const start = tokenToPosition(tree, token_index, encoding);
    const loc = tokenToLoc(tree, token_index);

    return .{
        .start = start,
        .end = advancePosition(tree.source, start, loc.start, loc.end, encoding),
    };
}

pub fn tokenLength(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) usize {
    const loc = tokenToLoc(tree, token_index);
    return locLength(tree.source, loc, encoding);
}

pub fn tokenIndexLength(text: [:0]const u8, index: usize, encoding: Encoding) usize {
    const loc = tokenIndexToLoc(text, index);
    return locLength(text, loc, encoding);
}

pub fn tokenIndexToLoc(text: [:0]const u8, index: usize) Loc {
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = text,
        .index = index,
    };

    const token = tokenizer.next();
    return .{ .start = token.loc.start, .end = token.loc.end };
}

test tokenIndexToLoc {
    try std.testing.expectEqual(Loc{ .start = 0, .end = 0 }, tokenIndexToLoc("", 0));
    try std.testing.expectEqual(Loc{ .start = 0, .end = 3 }, tokenIndexToLoc("foo", 0));
    try std.testing.expectEqual(Loc{ .start = 3, .end = 4 }, tokenIndexToLoc("0, 0", 3));
    try std.testing.expectEqual(Loc{ .start = 1, .end = 4 }, tokenIndexToLoc(" bar ", 0));
}

pub fn tokenPositionToLoc(text: [:0]const u8, position: Position, encoding: Encoding) Loc {
    const index = positionToIndex(text, position, encoding);
    return tokenIndexToLoc(text, index);
}

pub fn tokenIndexToSlice(text: [:0]const u8, index: usize) []const u8 {
    return locToSlice(text, tokenIndexToLoc(text, index));
}

pub fn tokenPositionToSlice(text: [:0]const u8, position: Position) []const u8 {
    return locToSlice(text, tokenPositionToLoc(text, position));
}

pub fn tokenIndexToRange(text: [:0]const u8, index: usize, encoding: Encoding) Range {
    const start = indexToPosition(text, index, encoding);
    const loc = tokenIndexToLoc(text, index);

    return .{
        .start = start,
        .end = advancePosition(text, start, loc.start, loc.end, encoding),
    };
}

pub fn tokenPositionToRange(text: [:0]const u8, position: Position, encoding: Encoding) Range {
    const index = positionToIndex(text, position, encoding);
    const loc = tokenIndexToLoc(text, index);

    return .{
        .start = position,
        .end = advancePosition(text, position, loc.start, loc.end, encoding),
    };
}

pub fn nodeToLoc(tree: Ast, node: Ast.Node.Index) Loc {
    return tokensToLoc(tree, tree.firstToken(node), ast.lastToken(tree, node));
}

pub fn nodeToSlice(tree: Ast, node: Ast.Node.Index) []const u8 {
    return locToSlice(tree.source, nodeToLoc(tree, node));
}

pub fn nodeToRange(tree: Ast, node: Ast.Node.Index, encoding: Encoding) Range {
    return locToRange(tree.source, nodeToLoc(tree, node), encoding);
}

/// return the source location
/// that starts `n` lines before the line at which `index` is located
/// and    ends `n` lines after  the line at which `index` is located.
/// `n == 0` is equivalent to calling `lineLocAtIndex`.
pub fn multilineLocAtIndex(text: []const u8, index: usize, n: usize) Loc {
    const start = blk: {
        var i: usize = index;
        var num_lines: usize = 0;
        while (i != 0) : (i -= 1) {
            if (text[i - 1] != '\n') continue;
            if (num_lines >= n) break :blk i;
            num_lines += 1;
        }
        break :blk 0;
    };
    const end = blk: {
        var i: usize = index;
        var num_lines: usize = 0;
        while (i < text.len) : (i += 1) {
            if (text[i] != '\n') continue;
            if (num_lines >= n) break :blk i;
            num_lines += 1;
        }
        break :blk text.len;
    };

    return .{
        .start = start,
        .end = end,
    };
}

test multilineLocAtIndex {
    const text =
        \\line0
        \\line1
        \\line2
        \\line3
        \\line4
    ;
    try std.testing.expectEqualStrings(lineSliceAtIndex(text, 0), multilineSliceAtIndex(text, 0, 0));
    try std.testing.expectEqualStrings(lineSliceAtIndex(text, 5), multilineSliceAtIndex(text, 5, 0));
    try std.testing.expectEqualStrings(lineSliceAtIndex(text, 6), multilineSliceAtIndex(text, 6, 0));

    try std.testing.expectEqualStrings("line1\nline2\nline3", multilineSliceAtIndex(text, 15, 1));
    try std.testing.expectEqualStrings("line0\nline1", multilineSliceAtIndex(text, 3, 1));
    try std.testing.expectEqualStrings("line3\nline4", multilineSliceAtIndex(text, 27, 1));
}

/// see `multilineLocAtIndex`
pub fn multilineSliceAtIndex(text: []const u8, index: usize, n: usize) []const u8 {
    return locToSlice(text, multilineLocAtIndex(text, index, n));
}

/// see `multilineLocAtIndex`
pub fn multilineLocAtPosition(text: []const u8, position: Position, n: usize, encoding: Encoding) Loc {
    return lineLocAtIndex(text, positionToIndex(text, position, n, encoding));
}

/// see `multilineLocAtIndex`
pub fn multilineSliceAtPosition(text: []const u8, position: Position, n: usize, encoding: Encoding) []const u8 {
    return locToSlice(text, multilineLocAtPosition(text, position, n, encoding));
}

/// returns true if a and b intersect
pub fn locIntersect(a: Loc, b: Loc) bool {
    std.debug.assert(a.start <= a.end and b.start <= b.end);
    return a.start < b.end and a.end > b.start;
}

test locIntersect {
    const a: Loc = .{ .start = 2, .end = 5 };
    try std.testing.expect(locIntersect(a, .{ .start = 0, .end = 2 }) == false);
    try std.testing.expect(locIntersect(a, .{ .start = 1, .end = 3 }) == true);
    try std.testing.expect(locIntersect(a, .{ .start = 2, .end = 4 }) == true);
    try std.testing.expect(locIntersect(a, .{ .start = 3, .end = 5 }) == true);
    try std.testing.expect(locIntersect(a, .{ .start = 4, .end = 6 }) == true);
    try std.testing.expect(locIntersect(a, .{ .start = 5, .end = 7 }) == false);
}

/// returns true if a is inside b
pub fn locInside(inner: Loc, outer: Loc) bool {
    std.debug.assert(inner.start <= inner.end and outer.start <= outer.end);
    return outer.start <= inner.start and inner.end <= outer.end;
}

test locInside {
    const outer: Loc = .{ .start = 2, .end = 5 };
    try std.testing.expect(locInside(.{ .start = 0, .end = 2 }, outer) == false);
    try std.testing.expect(locInside(.{ .start = 1, .end = 3 }, outer) == false);
    try std.testing.expect(locInside(.{ .start = 2, .end = 4 }, outer) == true);
    try std.testing.expect(locInside(.{ .start = 3, .end = 5 }, outer) == true);
    try std.testing.expect(locInside(.{ .start = 4, .end = 6 }, outer) == false);
    try std.testing.expect(locInside(.{ .start = 5, .end = 7 }, outer) == false);
}

/// returns the union of a and b
pub fn locMerge(a: Loc, b: Loc) Loc {
    std.debug.assert(a.start <= a.end and b.start <= b.end);
    return .{
        .start = @min(a.start, b.start),
        .end = @max(a.end, b.end),
    };
}

test locMerge {
    const a: Loc = .{ .start = 2, .end = 5 };
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 0, .end = 2 }), Loc{ .start = 0, .end = 5 });
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 1, .end = 3 }), Loc{ .start = 1, .end = 5 });
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 2, .end = 4 }), Loc{ .start = 2, .end = 5 });
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 3, .end = 5 }), Loc{ .start = 2, .end = 5 });
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 4, .end = 6 }), Loc{ .start = 2, .end = 6 });
    try std.testing.expectEqualDeep(locMerge(a, .{ .start = 5, .end = 7 }), Loc{ .start = 2, .end = 7 });
}

pub fn positionInsideRange(inner: Position, outer: Range) bool {
    std.debug.assert(orderPosition(outer.start, outer.end) != .gt);
    return orderPosition(outer.start, inner) != .gt and orderPosition(inner, outer.end) != .gt;
}

test positionInsideRange {
    const range: Range = .{
        .start = .{ .line = 1, .character = 2 },
        .end = .{ .line = 2, .character = 4 },
    };
    try std.testing.expect(!positionInsideRange(.{ .line = 0, .character = 0 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 0, .character = 2 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 0, .character = 4 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 1, .character = 0 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 1, .character = 1 }, range));

    try std.testing.expect(positionInsideRange(.{ .line = 1, .character = 2 }, range));
    try std.testing.expect(positionInsideRange(.{ .line = 1, .character = 4 }, range));
    try std.testing.expect(positionInsideRange(.{ .line = 2, .character = 0 }, range));
    try std.testing.expect(positionInsideRange(.{ .line = 2, .character = 2 }, range));
    try std.testing.expect(positionInsideRange(.{ .line = 2, .character = 4 }, range));

    try std.testing.expect(!positionInsideRange(.{ .line = 2, .character = 6 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 3, .character = 0 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 3, .character = 2 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 3, .character = 4 }, range));
    try std.testing.expect(!positionInsideRange(.{ .line = 3, .character = 6 }, range));
}

/// More efficient conversion functions that operate on multiple elements.
pub const multiple = struct {
    /// a mapping from a source index to a line character pair
    pub const IndexToPositionMapping = struct {
        output: *Position,
        source_index: usize,

        fn lessThan(_: void, lhs: IndexToPositionMapping, rhs: IndexToPositionMapping) bool {
            return lhs.source_index < rhs.source_index;
        }
    };

    pub fn indexToPositionWithMappings(
        text: []const u8,
        mappings: []IndexToPositionMapping,
        encoding: Encoding,
    ) void {
        std.mem.sort(IndexToPositionMapping, mappings, {}, IndexToPositionMapping.lessThan);

        var last_index: usize = 0;
        var last_position: Position = .{ .line = 0, .character = 0 };
        for (mappings) |mapping| {
            const index = mapping.source_index;
            const position = advancePosition(text, last_position, last_index, index, encoding);
            defer last_index = index;
            defer last_position = position;

            mapping.output.* = position;
        }
    }

    pub fn indexToPosition(
        allocator: std.mem.Allocator,
        text: []const u8,
        source_indices: []const usize,
        result_positions: []Position,
        encoding: Encoding,
    ) error{OutOfMemory}!void {
        std.debug.assert(source_indices.len == result_positions.len);

        // one mapping for every start and end position
        const mappings = try allocator.alloc(IndexToPositionMapping, source_indices.len);
        defer allocator.free(mappings);

        for (mappings, source_indices, result_positions) |*mapping, index, *position| {
            mapping.* = .{ .output = position, .source_index = index };
        }

        indexToPositionWithMappings(text, mappings, encoding);
    }

    test "indexToPosition" {
        const text =
            \\hello
            \\world
        ;

        const source_indices: []const usize = &.{ 3, 9, 6, 0 };
        var result_positions: [4]Position = undefined;
        try multiple.indexToPosition(std.testing.allocator, text, source_indices, &result_positions, .@"utf-16");

        try std.testing.expectEqualSlices(Position, &.{
            .{ .line = 0, .character = 3 },
            .{ .line = 1, .character = 3 },
            .{ .line = 1, .character = 0 },
            .{ .line = 0, .character = 0 },
        }, &result_positions);
    }

    pub fn locToRange(
        allocator: std.mem.Allocator,
        text: []const u8,
        locs: []const Loc,
        ranges: []Range,
        encoding: Encoding,
    ) error{OutOfMemory}!void {
        std.debug.assert(locs.len == ranges.len);

        // one mapping for every start and end position
        var mappings = try allocator.alloc(IndexToPositionMapping, locs.len * 2);
        defer allocator.free(mappings);

        for (locs, ranges, 0..) |loc, *range, i| {
            mappings[2 * i + 0] = .{ .output = &range.start, .source_index = loc.start };
            mappings[2 * i + 1] = .{ .output = &range.end, .source_index = loc.end };
        }

        indexToPositionWithMappings(text, mappings, encoding);
    }

    test "locToRange" {
        const text =
            \\hello
            \\world
        ;

        const locs: []const Loc = &.{
            .{ .start = 3, .end = 9 },
            .{ .start = 6, .end = 0 },
        };
        var result_ranges: [2]Range = undefined;
        try multiple.locToRange(std.testing.allocator, text, locs, &result_ranges, .@"utf-16");

        try std.testing.expectEqualSlices(Range, &.{
            .{ .start = .{ .line = 0, .character = 3 }, .end = .{ .line = 1, .character = 3 } },
            .{ .start = .{ .line = 1, .character = 0 }, .end = .{ .line = 0, .character = 0 } },
        }, &result_ranges);
    }
};

comptime {
    std.testing.refAllDecls(multiple);
}
