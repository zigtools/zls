//! Conversion functions between the following Units:
//! - A "index" or "source index" is a offset into a utf-8 encoding source file.
//! - `Loc`
//! - `types.Position`
//! - `types.Range`
//! - `std.zig.Ast.TokenIndex`
//! - `std.zig.Ast.Node.Index`

const std = @import("std");
const types = @import("lsp").types;
const ast = @import("ast.zig");
const Ast = std.zig.Ast;

/// Specifies how the `character` field in `types.Position` is defined.
/// The Character encoding is negotiated during initialization with the Client/Editor.
pub const Encoding = enum {
    /// Character offsets count UTF-8 code units (e.g. bytes).
    @"utf-8",
    /// Character offsets count UTF-16 code units.
    ///
    /// This is the default and must always be supported
    /// by servers
    @"utf-16",
    /// Character offsets count UTF-32 code units.
    ///
    /// Implementation note: these are the same as Unicode codepoints,
    /// so this `PositionEncodingKind` may also be used for an
    /// encoding-agnostic representation of character offsets.
    @"utf-32",
};

/// A pair of two source indexes into a document.
/// Asserts that `start <= end`.
pub const Loc = std.zig.Token.Loc;

pub fn indexToPosition(text: []const u8, index: usize, encoding: Encoding) types.Position {
    const last_line_start = if (std.mem.lastIndexOfScalar(u8, text[0..index], '\n')) |line| line + 1 else 0;
    const line_count = std.mem.count(u8, text[0..last_line_start], "\n");

    return .{
        .line = @intCast(line_count),
        .character = @intCast(countCodeUnits(text[last_line_start..index], encoding)),
    };
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

test "positionToIndex where line value is greater than the number of lines" {
    try testPositionToIndex("", 0, 1, .{ 0, 0, 0 });
    try testPositionToIndex("", 0, 1, .{ 3, 2, 1 });

    try testPositionToIndex("hello", 5, 1, .{ 0, 0, 0 });
    try testPositionToIndex("hello", 5, 1, .{ 3, 2, 1 });

    try testPositionToIndex("hello\nfrom\nzig", 14, 3, .{ 0, 0, 0 });
    try testPositionToIndex("hello\nfrom\nzig", 14, 3, .{ 3, 2, 1 });
}

fn testPositionToIndex(text: []const u8, index: usize, line: u32, characters: [3]u32) !void {
    const position8: types.Position = .{ .line = line, .character = characters[0] };
    const position16: types.Position = .{ .line = line, .character = characters[1] };
    const position32: types.Position = .{ .line = line, .character = characters[2] };

    try std.testing.expectEqual(index, positionToIndex(text, position8, .@"utf-8"));
    try std.testing.expectEqual(index, positionToIndex(text, position16, .@"utf-16"));
    try std.testing.expectEqual(index, positionToIndex(text, position32, .@"utf-32"));
}

pub fn positionToIndex(text: []const u8, position: types.Position, encoding: Encoding) usize {
    var line: u32 = 0;
    var line_start_index: usize = 0;
    for (text, 0..) |c, i| {
        if (line == position.line) break;
        if (c == '\n') {
            line += 1;
            line_start_index = i + 1;
        }
    } else return text.len;

    const line_text = std.mem.sliceTo(text[line_start_index..], '\n');
    const line_byte_length = getNCodeUnitByteCount(line_text, position.character, encoding);

    return line_start_index + line_byte_length;
}

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

fn testIndexPosition(text: []const u8, index: usize, line: u32, characters: [3]u32) !void {
    const position8: types.Position = .{ .line = line, .character = characters[0] };
    const position16: types.Position = .{ .line = line, .character = characters[1] };
    const position32: types.Position = .{ .line = line, .character = characters[2] };

    try std.testing.expectEqual(position8, indexToPosition(text, index, .@"utf-8"));
    try std.testing.expectEqual(position16, indexToPosition(text, index, .@"utf-16"));
    try std.testing.expectEqual(position32, indexToPosition(text, index, .@"utf-32"));

    try std.testing.expectEqual(index, positionToIndex(text, position8, .@"utf-8"));
    try std.testing.expectEqual(index, positionToIndex(text, position16, .@"utf-16"));
    try std.testing.expectEqual(index, positionToIndex(text, position32, .@"utf-32"));
}

pub fn sourceIndexToTokenIndex(tree: Ast, source_index: usize) Ast.TokenIndex {
    std.debug.assert(source_index <= tree.source.len);

    const tokens_start = tree.tokens.items(.start);

    // at which point to stop dividing and just iterate
    // good results w/ 256 as well, anything lower/higher and the cost of
    // dividing overruns the cost of iterating and vice versa
    const threshold = 336;

    var upper_index: Ast.TokenIndex = @intCast(tokens_start.len - 1); // The Ast always has a .eof token
    var lower_index: Ast.TokenIndex = 0;
    while (upper_index - lower_index > threshold) {
        const mid = lower_index + (upper_index - lower_index) / 2;
        if (tokens_start[mid] < source_index) {
            lower_index = mid;
        } else {
            upper_index = mid;
        }
    }

    while (upper_index > 0) : (upper_index -= 1) {
        const token_start = tokens_start[upper_index];
        if (token_start > source_index) continue; // checking for equality here is suboptimal
        // Handle source_index being > than the last possible token_start (max_token_start < source_index < tree.source.len)
        if (upper_index == tokens_start.len - 1) break;
        // Check if source_index is within current token
        // (`token_start - 1` to include it's loc.start source_index and avoid the equality part of the check)
        const is_within_current_token = (source_index > (token_start - 1)) and (source_index < tokens_start[upper_index + 1]);
        if (!is_within_current_token) upper_index += 1; // gone 1 past
        break;
    }

    std.debug.assert(upper_index < tree.tokens.len);
    return upper_index;
}

test sourceIndexToTokenIndex {
    var tree = try std.zig.Ast.parse(std.testing.allocator, "🠁↉¶\na", .zig);
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(std.zig.Token.Tag, &.{
        .invalid, // 🠁↉¶
        .identifier, // a
        .eof,
    }, tree.tokens.items(.tag));

    // 🠁
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 0));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 1));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 2));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 3));

    // ↉
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 4));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 5));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 6));

    // ¶
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 7));
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 8));

    // \n
    try std.testing.expectEqual(0, sourceIndexToTokenIndex(tree, 9));

    // a
    try std.testing.expectEqual(1, sourceIndexToTokenIndex(tree, 10));

    // EOF
    try std.testing.expectEqual(2, sourceIndexToTokenIndex(tree, 11));
}

fn identifierIndexToLoc(tree: Ast, source_index: usize) Loc {
    var index: usize = source_index;
    if (tree.source[index] == '@') {
        index += 1;
        std.debug.assert(tree.source[index] == '\"');
        index += 1;
        while (true) : (index += 1) {
            if (tree.source[index] == '\"') {
                index += 1;
                break;
            }
        }
    } else {
        while (true) : (index += 1) {
            switch (tree.source[index]) {
                'a'...'z', 'A'...'Z', '_', '0'...'9' => {},
                else => break,
            }
        }
    }
    return .{ .start = source_index, .end = index };
}

/// Support formats:
/// - `foo`
/// - `@"foo"`
/// - `@foo`
pub fn identifierIndexToNameLoc(text: [:0]const u8, source_index: usize) Loc {
    if (text[source_index] == '@' and text[source_index + 1] == '\"') {
        const start_index = source_index + 2;
        var index: usize = start_index;
        while (true) : (index += 1) {
            switch (text[index]) {
                '\n', '\"' => break,
                else => {},
            }
        }
        return .{ .start = start_index, .end = index };
    } else {
        const start: usize = source_index + @intFromBool(text[source_index] == '@');
        var index = start;
        while (true) : (index += 1) {
            switch (text[index]) {
                'a'...'z', 'A'...'Z', '_', '0'...'9' => {},
                else => break,
            }
        }
        return .{ .start = start, .end = index };
    }
}

test identifierIndexToNameLoc {
    try std.testing.expectEqualStrings("", identifierIndexToNameSlice("", 0));
    try std.testing.expectEqualStrings("", identifierIndexToNameSlice(" ", 0));
    try std.testing.expectEqualStrings("", identifierIndexToNameSlice(" world", 0));

    try std.testing.expectEqualStrings("hello", identifierIndexToNameSlice("hello", 0));
    try std.testing.expectEqualStrings("hello", identifierIndexToNameSlice("hello world", 0));
    try std.testing.expectEqualStrings("world", identifierIndexToNameSlice("hello world", 6));

    try std.testing.expectEqualStrings("hello", identifierIndexToNameSlice("@\"hello\"", 0));
    try std.testing.expectEqualStrings("hello", identifierIndexToNameSlice("@\"hello\" world", 0));
    try std.testing.expectEqualStrings("world", identifierIndexToNameSlice("@\"hello\" @\"world\"", 9));

    try std.testing.expectEqualStrings("hello", identifierIndexToNameSlice("@hello", 0));
}

pub fn identifierIndexToNameSlice(text: [:0]const u8, source_index: usize) []const u8 {
    return locToSlice(text, identifierIndexToNameLoc(text, source_index));
}

pub fn identifierTokenToNameLoc(tree: Ast, identifier_token: Ast.TokenIndex) Loc {
    std.debug.assert(switch (tree.tokens.items(.tag)[identifier_token]) {
        .builtin => true, // The Zig parser likes to emit .builtin where a identifier would be expected
        .identifier => true,
        else => false,
    });
    return identifierIndexToNameLoc(tree.source, tree.tokens.items(.start)[identifier_token]);
}

pub fn identifierTokenToNameSlice(tree: Ast, identifier_token: Ast.TokenIndex) []const u8 {
    return locToSlice(tree.source, identifierTokenToNameLoc(tree, identifier_token));
}

pub fn tokenToIndex(tree: Ast, token_index: Ast.TokenIndex) usize {
    return tree.tokens.items(.start)[token_index];
}

test tokenToIndex {
    var tree = try std.zig.Ast.parse(std.testing.allocator, "🠁↉¶\na", .zig);
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(std.zig.Token.Tag, &.{
        .invalid, // 🠁↉¶
        .identifier, // a
        .eof,
    }, tree.tokens.items(.tag));

    try std.testing.expectEqual(0, tokenToIndex(tree, 0)); // 🠁↉¶
    try std.testing.expectEqual(10, tokenToIndex(tree, 1)); // a
    try std.testing.expectEqual(11, tokenToIndex(tree, 2)); // EOF
}

pub fn tokensToLoc(tree: Ast, first_token: Ast.TokenIndex, last_token: Ast.TokenIndex) Loc {
    return .{ .start = tokenToIndex(tree, first_token), .end = tokenToLoc(tree, last_token).end };
}

pub fn tokenToLoc(tree: Ast, token_index: Ast.TokenIndex) Loc {
    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);
    const start = token_starts[token_index];
    const tag = token_tags[token_index];

    // Many tokens can be determined entirely by their tag.
    if (tag == .identifier) {
        // fast path for identifiers
        return identifierIndexToLoc(tree, start);
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
        while (begin > 0 and token_tags[begin - 1] == .invalid) : (begin -= 1) {}

        var end = token_index;
        while (end < tree.tokens.len and token_tags[end] == .invalid) : (end += 1) {}
        return .{
            .start = token_starts[begin],
            .end = token_starts[end],
        };
    }

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = start,
    };

    // Maybe combine multi-line tokens?
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

pub fn tokenToPosition(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) types.Position {
    const start = tokenToIndex(tree, token_index);
    return indexToPosition(tree.source, start, encoding);
}

pub fn tokenToRange(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) types.Range {
    const start = tokenToPosition(tree, token_index, encoding);
    const loc = tokenToLoc(tree, token_index);

    return .{
        .start = start,
        .end = advancePosition(tree.source, start, loc.start, loc.end, encoding),
    };
}

pub fn locLength(text: []const u8, loc: Loc, encoding: Encoding) usize {
    return countCodeUnits(text[loc.start..loc.end], encoding);
}

pub fn tokenLength(tree: Ast, token_index: Ast.TokenIndex, encoding: Encoding) usize {
    const loc = tokenToLoc(tree, token_index);
    return locLength(tree.source, loc, encoding);
}

pub fn rangeLength(text: []const u8, range: types.Range, encoding: Encoding) usize {
    const loc = rangeToLoc(text, range, encoding);
    return locLength(text, loc, encoding);
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

pub fn tokenPositionToLoc(text: [:0]const u8, position: types.Position, encoding: Encoding) Loc {
    const index = positionToIndex(text, position, encoding);
    return tokenIndexToLoc(text, index);
}

pub fn tokenIndexToSlice(text: [:0]const u8, index: usize) []const u8 {
    return locToSlice(text, tokenIndexToLoc(text, index));
}

pub fn tokenPositionToSlice(text: [:0]const u8, position: types.Position) []const u8 {
    return locToSlice(text, tokenPositionToLoc(text, position));
}

pub fn tokenIndexToRange(text: [:0]const u8, index: usize, encoding: Encoding) types.Range {
    const start = indexToPosition(text, index, encoding);
    const loc = tokenIndexToLoc(text, index);

    return .{
        .start = start,
        .end = advancePosition(text, start, loc.start, loc.end, encoding),
    };
}

pub fn tokenPositionToRange(text: [:0]const u8, position: types.Position, encoding: Encoding) types.Range {
    const index = positionToIndex(text, position, encoding);
    const loc = tokenIndexToLoc(text, index);

    return .{
        .start = position,
        .end = advancePosition(text, position, loc.start, loc.end, encoding),
    };
}

pub fn locToSlice(text: []const u8, loc: Loc) []const u8 {
    return text[loc.start..loc.end];
}

pub fn locToRange(text: []const u8, loc: Loc, encoding: Encoding) types.Range {
    std.debug.assert(loc.start <= loc.end and loc.end <= text.len);
    const start = indexToPosition(text, loc.start, encoding);
    return .{
        .start = start,
        .end = advancePosition(text, start, loc.start, loc.end, encoding),
    };
}

pub fn rangeToSlice(text: []const u8, range: types.Range, encoding: Encoding) []const u8 {
    return locToSlice(text, rangeToLoc(text, range, encoding));
}

pub fn rangeToLoc(text: []const u8, range: types.Range, encoding: Encoding) Loc {
    std.debug.assert(orderPosition(range.start, range.end) != .gt);
    const start = positionToIndex(text, range.start, encoding);

    const end_position_relative_to_start: types.Position = .{
        .line = range.end.line - range.start.line,
        .character = if (range.start.line == range.end.line)
            range.end.character - range.start.character
        else
            range.end.character,
    };

    const relative_end = positionToIndex(text[start..], end_position_relative_to_start, encoding);
    return .{ .start = start, .end = start + relative_end };
}

test rangeToSlice {
    try std.testing.expectEqualStrings("", rangeToSlice(
        "",
        .{
            .start = .{ .line = 0, .character = 0 },
            .end = .{ .line = 0, .character = 0 },
        },
        .@"utf-8",
    ));
    try std.testing.expectEqualStrings("-A-", rangeToSlice(
        "Peek-A-Boo",
        .{
            .start = .{ .line = 0, .character = 4 },
            .end = .{ .line = 0, .character = 7 },
        },
        .@"utf-8",
    ));
    try std.testing.expectEqualStrings("ek\nA\nB", rangeToSlice(
        "Peek\nA\nBoo",
        .{
            .start = .{ .line = 0, .character = 2 },
            .end = .{ .line = 2, .character = 1 },
        },
        .@"utf-8",
    ));
}

pub fn nodeToLoc(tree: Ast, node: Ast.Node.Index) Loc {
    return tokensToLoc(tree, tree.firstToken(node), tree.lastToken(node));
}

pub fn nodeToSlice(tree: Ast, node: Ast.Node.Index) []const u8 {
    return locToSlice(tree.source, nodeToLoc(tree, node));
}

pub fn nodeToRange(tree: Ast, node: Ast.Node.Index, encoding: Encoding) types.Range {
    return locToRange(tree.source, nodeToLoc(tree, node), encoding);
}

pub fn lineLocAtIndex(text: []const u8, index: usize) Loc {
    return .{
        .start = if (std.mem.lastIndexOfScalar(u8, text[0..index], '\n')) |idx| idx + 1 else 0,
        .end = std.mem.indexOfScalarPos(u8, text, index, '\n') orelse text.len,
    };
}

test lineLocAtIndex {
    try std.testing.expectEqualStrings("", lineSliceAtIndex("", 0));
    try std.testing.expectEqualStrings("", lineSliceAtIndex("\n", 0));
    try std.testing.expectEqualStrings("", lineSliceAtIndex("\n", 1));

    try std.testing.expectEqualStrings("foo", lineSliceAtIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("bar", lineSliceAtIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("bar", lineSliceAtIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", lineSliceAtIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", lineSliceAtIndex("foo\n", 3));
}

pub fn lineSliceAtIndex(text: []const u8, index: usize) []const u8 {
    return locToSlice(text, lineLocAtIndex(text, index));
}

pub fn lineLocAtPosition(text: []const u8, position: types.Position, encoding: Encoding) Loc {
    return lineLocAtIndex(text, positionToIndex(text, position, encoding));
}

pub fn lineSliceAtPosition(text: []const u8, position: types.Position, encoding: Encoding) []const u8 {
    return locToSlice(text, lineLocAtPosition(text, position, encoding));
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
pub fn multilineLocAtPosition(text: []const u8, position: types.Position, n: usize, encoding: Encoding) Loc {
    return lineLocAtIndex(text, positionToIndex(text, position, n, encoding));
}

/// see `multilineLocAtIndex`
pub fn multilineSliceAtPosition(text: []const u8, position: types.Position, n: usize, encoding: Encoding) []const u8 {
    return locToSlice(text, multilineLocAtPosition(text, position, n, encoding));
}

pub fn lineLocUntilIndex(text: []const u8, index: usize) Loc {
    return .{
        .start = if (std.mem.lastIndexOfScalar(u8, text[0..index], '\n')) |idx| idx + 1 else 0,
        .end = index,
    };
}

test lineLocUntilIndex {
    try std.testing.expectEqualStrings("", lineSliceUntilIndex("", 0));
    try std.testing.expectEqualStrings("", lineSliceUntilIndex("\n", 0));
    try std.testing.expectEqualStrings("", lineSliceUntilIndex("\n", 1));

    try std.testing.expectEqualStrings("fo", lineSliceUntilIndex("foo\nbar", 2));
    try std.testing.expectEqualStrings("", lineSliceUntilIndex("foo\nbar", 4));
    try std.testing.expectEqualStrings("ba", lineSliceUntilIndex("foo\nbar", 6));

    try std.testing.expectEqualStrings("", lineSliceUntilIndex("foo\n", 4));
    try std.testing.expectEqualStrings("foo", lineSliceUntilIndex("foo\n", 3));
}

pub fn lineSliceUntilIndex(text: []const u8, index: usize) []const u8 {
    return locToSlice(text, lineLocUntilIndex(text, index));
}

pub fn lineLocUntilPosition(text: []const u8, position: types.Position, encoding: Encoding) Loc {
    return lineLocUntilIndex(text, positionToIndex(text, position, encoding));
}

pub fn lineSliceUntilPosition(text: []const u8, position: types.Position, encoding: Encoding) []const u8 {
    return locToSlice(text, lineLocUntilPosition(text, position, encoding));
}

pub fn convertPositionEncoding(text: []const u8, position: types.Position, from_encoding: Encoding, to_encoding: Encoding) types.Position {
    if (from_encoding == to_encoding) return position;

    const line_loc = lineLocUntilPosition(text, position, from_encoding);

    return .{
        .line = position.line,
        .character = @intCast(locLength(text, line_loc, to_encoding)),
    };
}

test convertPositionEncoding {
    try testConvertPositionEncoding("", 0, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("\n", 0, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("\n", 1, 0, .{ 0, 0, 0 });
    try testConvertPositionEncoding("foo", 0, 3, .{ 3, 3, 3 });
    try testConvertPositionEncoding("a¶↉🠁", 0, 10, .{ 10, 5, 4 });
    try testConvertPositionEncoding("a¶↉🠁\na¶↉🠁", 1, 6, .{ 6, 3, 3 });
}

fn testConvertPositionEncoding(text: [:0]const u8, line: u32, character: u32, new_characters: [3]u32) !void {
    const position: types.Position = .{ .line = line, .character = character };

    const position8 = convertPositionEncoding(text, position, .@"utf-8", .@"utf-8");
    const position16 = convertPositionEncoding(text, position, .@"utf-8", .@"utf-16");
    const position32 = convertPositionEncoding(text, position, .@"utf-8", .@"utf-32");

    try std.testing.expectEqual(line, position8.line);
    try std.testing.expectEqual(line, position16.line);
    try std.testing.expectEqual(line, position32.line);

    try std.testing.expectEqual(new_characters[0], position8.character);
    try std.testing.expectEqual(new_characters[1], position16.character);
    try std.testing.expectEqual(new_characters[2], position32.character);
}

pub fn convertRangeEncoding(text: []const u8, range: types.Range, from_encoding: Encoding, to_encoding: Encoding) types.Range {
    std.debug.assert(orderPosition(range.start, range.end) != .gt);
    if (from_encoding == to_encoding) return range;
    return .{
        .start = convertPositionEncoding(text, range.start, from_encoding, to_encoding),
        .end = convertPositionEncoding(text, range.end, from_encoding, to_encoding),
    };
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

pub fn orderPosition(a: types.Position, b: types.Position) std.math.Order {
    const line_order = std.math.order(a.line, b.line);
    if (line_order != .eq) return line_order;
    return std.math.order(a.character, b.character);
}

test orderPosition {
    try std.testing.expectEqual(.lt, orderPosition(.{ .line = 1, .character = 0 }, .{ .line = 3, .character = 5 }));
    try std.testing.expectEqual(.lt, orderPosition(.{ .line = 1, .character = 3 }, .{ .line = 3, .character = 5 }));
    try std.testing.expectEqual(.lt, orderPosition(.{ .line = 1, .character = 6 }, .{ .line = 3, .character = 5 }));
    try std.testing.expectEqual(.lt, orderPosition(.{ .line = 3, .character = 0 }, .{ .line = 3, .character = 5 }));

    try std.testing.expectEqual(.eq, orderPosition(.{ .line = 3, .character = 3 }, .{ .line = 3, .character = 3 }));

    try std.testing.expectEqual(.gt, orderPosition(.{ .line = 3, .character = 6 }, .{ .line = 3, .character = 3 }));
    try std.testing.expectEqual(.gt, orderPosition(.{ .line = 5, .character = 0 }, .{ .line = 3, .character = 5 }));
    try std.testing.expectEqual(.gt, orderPosition(.{ .line = 5, .character = 3 }, .{ .line = 3, .character = 5 }));
    try std.testing.expectEqual(.gt, orderPosition(.{ .line = 5, .character = 6 }, .{ .line = 3, .character = 5 }));
}

pub fn positionInsideRange(inner: types.Position, outer: types.Range) bool {
    std.debug.assert(orderPosition(outer.start, outer.end) != .gt);
    return orderPosition(outer.start, inner) != .gt and orderPosition(inner, outer.end) != .gt;
}

test positionInsideRange {
    const range: types.Range = .{
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
        output: *types.Position,
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
        var last_position: types.Position = .{ .line = 0, .character = 0 };
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
        result_positions: []types.Position,
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
        var result_positions: [4]types.Position = undefined;
        try multiple.indexToPosition(std.testing.allocator, text, source_indices, &result_positions, .@"utf-16");

        try std.testing.expectEqualSlices(types.Position, &.{
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
        ranges: []types.Range,
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
        var result_ranges: [2]types.Range = undefined;
        try multiple.locToRange(std.testing.allocator, text, locs, &result_ranges, .@"utf-16");

        try std.testing.expectEqualSlices(types.Range, &.{
            .{ .start = .{ .line = 0, .character = 3 }, .end = .{ .line = 1, .character = 3 } },
            .{ .start = .{ .line = 1, .character = 0 }, .end = .{ .line = 0, .character = 0 } },
        }, &result_ranges);
    }
};

comptime {
    std.testing.refAllDecls(multiple);
}

// Helper functions

/// advance `position` which starts at `from_index` to `to_index` accounting for line breaks
pub fn advancePosition(text: []const u8, position: types.Position, from_index: usize, to_index: usize, encoding: Encoding) types.Position {
    var line = position.line;

    for (text[from_index..to_index]) |c| {
        if (c == '\n') {
            line += 1;
        }
    }

    const line_loc = lineLocUntilIndex(text, to_index);

    return .{
        .line = line,
        .character = @intCast(locLength(text, line_loc, encoding)),
    };
}

test advancePosition {
    try testAdvancePosition("", 0, 0, 0, 0, 0, 0);
    try testAdvancePosition("foo", 0, 3, 0, 0, 0, 3);
    try testAdvancePosition("\n", 1, 0, 0, 0, 0, 1);
    try testAdvancePosition("foo\nbar", 1, 2, 0, 1, 1, 6);
    try testAdvancePosition("foo\nbar", 1, 3, 1, 0, 4, 7);
}

fn testAdvancePosition(text: [:0]const u8, expected_line: u32, expected_character: u32, line: u32, character: u32, from: usize, to: usize) !void {
    const expected: types.Position = .{ .line = expected_line, .character = expected_character };
    const actual = advancePosition(text, .{ .line = line, .character = character }, from, to, .@"utf-16");

    try std.testing.expectEqual(expected, actual);
}

/// returns the number of code units in `text`
pub fn countCodeUnits(text: []const u8, encoding: Encoding) usize {
    switch (encoding) {
        .@"utf-8" => return text.len,
        .@"utf-16" => {
            var iter: std.unicode.Utf8Iterator = .{ .bytes = text, .i = 0 };

            var utf16_len: usize = 0;
            while (iter.nextCodepoint()) |codepoint| {
                if (codepoint < 0x10000) {
                    utf16_len += 1;
                } else {
                    utf16_len += 2;
                }
            }
            return utf16_len;
        },
        .@"utf-32" => return std.unicode.utf8CountCodepoints(text) catch unreachable,
    }
}

test countCodeUnits {
    try testCountCodeUnits("", .{ 0, 0, 0 });
    try testCountCodeUnits("a\na", .{ 3, 3, 3 });
    try testCountCodeUnits("a¶↉🠁", .{ 10, 5, 4 });
    try testCountCodeUnits("🠁↉¶a", .{ 10, 5, 4 });
    try testCountCodeUnits("🇺🇸 🇩🇪", .{ 17, 9, 5 });
}

fn testCountCodeUnits(text: []const u8, counts: [3]usize) !void {
    try std.testing.expectEqual(counts[0], countCodeUnits(text, .@"utf-8"));
    try std.testing.expectEqual(counts[1], countCodeUnits(text, .@"utf-16"));
    try std.testing.expectEqual(counts[2], countCodeUnits(text, .@"utf-32"));
}

/// returns the number of (utf-8 code units / bytes) that represent `n` code units in `text`
/// if `text` has less than `n` code units then the number of code units in
/// `text` are returned, i.e. the result is being clamped.
pub fn getNCodeUnitByteCount(text: []const u8, n: usize, encoding: Encoding) usize {
    switch (encoding) {
        .@"utf-8" => return @min(text.len, n),
        .@"utf-16" => {
            if (n == 0) return 0;
            var iter: std.unicode.Utf8Iterator = .{ .bytes = text, .i = 0 };

            var utf16_len: usize = 0;
            while (iter.nextCodepoint()) |codepoint| {
                if (codepoint < 0x10000) {
                    utf16_len += 1;
                } else {
                    utf16_len += 2;
                }
                if (utf16_len >= n) break;
            }
            return iter.i;
        },
        .@"utf-32" => {
            var i: usize = 0;
            var count: usize = 0;
            while (count != n) : (count += 1) {
                if (i >= text.len) break;
                i += std.unicode.utf8ByteSequenceLength(text[i]) catch unreachable;
            }
            return i;
        },
    }
}

test getNCodeUnitByteCount {
    try testGetNCodeUnitByteCount("", .{ 0, 0, 0 });
    try testGetNCodeUnitByteCount("foo", .{ 2, 2, 2 });
    try testGetNCodeUnitByteCount("a¶🠁🠁", .{ 7, 4, 3 });
    try testGetNCodeUnitByteCount("🇺🇸 🇩🇪", .{ 9, 5, 3 });
}

fn testGetNCodeUnitByteCount(text: []const u8, n: [3]usize) !void {
    try std.testing.expectEqual(n[0], getNCodeUnitByteCount(text, n[0], .@"utf-8"));
    try std.testing.expectEqual(n[0], getNCodeUnitByteCount(text, n[1], .@"utf-16"));
    try std.testing.expectEqual(n[0], getNCodeUnitByteCount(text, n[2], .@"utf-32"));
}

pub fn positionLessThan(a: types.Position, b: types.Position) bool {
    if (a.line < b.line) {
        return true;
    }
    if (a.line > b.line) {
        return false;
    }

    if (a.character < b.character) {
        return true;
    }

    return false;
}
