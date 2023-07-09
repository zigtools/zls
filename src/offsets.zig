const std = @import("std");
const types = @import("lsp.zig");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;

pub const Encoding = types.PositionEncodingKind;

pub const Loc = std.zig.Token.Loc;

pub fn indexToPosition(text: []const u8, index: usize, encoding: Encoding) types.Position {
    const last_line_start = if (std.mem.lastIndexOf(u8, text[0..index], "\n")) |line| line + 1 else 0;
    const line_count = std.mem.count(u8, text[0..last_line_start], "\n");

    return .{
        .line = @intCast(line_count),
        .character = @intCast(countCodeUnits(text[last_line_start..index], encoding)),
    };
}

pub fn maybePositionToIndex(text: []const u8, position: types.Position, encoding: Encoding) ?usize {
    var line: u32 = 0;
    var line_start_index: usize = 0;
    for (text, 0..) |c, i| {
        if (line == position.line) break;
        if (c == '\n') {
            line += 1;
            line_start_index = i + 1;
        }
    }

    if (line != position.line) return null;

    const line_text = std.mem.sliceTo(text[line_start_index..], '\n');
    const line_byte_length = getNCodeUnitByteCount(line_text, position.character, encoding);

    return line_start_index + line_byte_length;
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
    }
    std.debug.assert(line == position.line);

    const line_text = std.mem.sliceTo(text[line_start_index..], '\n');
    const line_byte_length = getNCodeUnitByteCount(line_text, position.character, encoding);

    return line_start_index + line_byte_length;
}

pub fn sourceIndexToTokenIndex(tree: Ast, source_index: usize) usize {
    std.debug.assert(source_index < tree.source.len);

    const tokens_start = tree.tokens.items(.start);
    var upper_index = tokens_start.len - 1;
    var mid: usize = upper_index / 2;

    if (tokens_start.len < 600) {
        const mid_tok_start = tokens_start[mid];
        if (mid_tok_start < source_index) { // source_index is in upper half
            const quart_index = mid + (mid / 2);
            const quart_tok_start = tokens_start[quart_index];
            if (quart_tok_start < source_index) { // source_index is in upper fourth
            } else { // source_index is in upper third
                upper_index = quart_index;
            }
        } else { // source_index is in lower half
            const quart_index = mid / 2;
            const quart_tok_start = tokens_start[quart_index];
            if (quart_tok_start < source_index) { // source_index is in second/4
                upper_index = mid;
            } else { // source_index is in first/4
                upper_index = quart_index;
            }
        }
    } else {
        // at which point to stop dividing and just iterate
        // good results w/ 128 as well, anything lower/higher and the cost of
        // dividing overruns the cost of iterating and vice versa
        const threshold = 168;

        var lower_index: usize = 0;
        while (true) {
            const mid_tok_start = tokens_start[mid];
            if (mid_tok_start < source_index) { // source_index is in upper half
                if ((upper_index - mid) < threshold) break;
                lower_index = mid; // raise the lower_index to mid
            } else { // source_index is in lower half
                upper_index = mid; // lower the upper_index to mid
                if ((mid - lower_index) < threshold) break;
            }
            mid = lower_index + (upper_index - lower_index) / 2;
        }
    }
    while (upper_index > 0) : (upper_index -= 1) {
        var token_start = tokens_start[upper_index];
        if (token_start > source_index) continue; // checking for equality here is suboptimal
        // check if source_index is within current token
        //  `token_start - 1` to include it's loc.start source_index and avoid the equality part of the check
        //  because the above `if` doesn't check for equality upper_index ends up always `< last/max index`,
        //  and the check below doesn't overflow => ie if upper_index is the last index and even if
        //  token_start == source_index => another iteration, `(upper_index -= 1)`
        const is_within_current_token = (source_index > (token_start - 1)) and (source_index < tokens_start[upper_index + 1]);
        if (!is_within_current_token) upper_index += 1; // gone 1 past
        break;
    }

    return upper_index;
}

pub fn tokenToIndex(tree: Ast, token_index: Ast.TokenIndex) usize {
    return tree.tokens.items(.start)[token_index];
}

pub fn tokensToLoc(tree: Ast, first_token: Ast.TokenIndex, last_token: Ast.TokenIndex) Loc {
    return .{ .start = tokenToIndex(tree, first_token), .end = tokenToLoc(tree, last_token).end };
}

pub fn tokenToLoc(tree: Ast, token_index: Ast.TokenIndex) Loc {
    const start = tree.tokens.items(.start)[token_index];
    const tag = tree.tokens.items(.tag)[token_index];

    // Many tokens can be determined entirely by their tag.
    if (tag.lexeme()) |lexeme| {
        return .{
            .start = start,
            .end = start + lexeme.len,
        };
    }

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = start,
        .pending_invalid_token = null,
    };

    // Maybe combine multi-line tokens?
    const token = tokenizer.next();
    // A failure would indicate a corrupted tree.source
    std.debug.assert(token.tag == tag);
    return token.loc;
}

pub fn tokenToSlice(tree: Ast, token_index: Ast.TokenIndex) []const u8 {
    return locToSlice(tree.source, tokenToLoc(tree, token_index));
}

pub fn tokensToSlice(tree: Ast, first_token: Ast.TokenIndex, last_token: Ast.TokenIndex) []const u8 {
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
        .pending_invalid_token = null,
    };

    const token = tokenizer.next();
    return .{ .start = token.loc.start, .end = token.loc.end };
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
    return .{
        .start = positionToIndex(text, range.start, encoding),
        .end = positionToIndex(text, range.end, encoding),
    };
}

pub fn nodeToLoc(tree: Ast, node: Ast.Node.Index) Loc {
    return tokensToLoc(tree, tree.firstToken(node), ast.lastToken(tree, node));
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

pub fn lineSliceAtIndex(text: []const u8, index: usize) []const u8 {
    return locToSlice(text, lineLocAtIndex(text, index));
}

pub fn lineLocAtPosition(text: []const u8, position: types.Position, encoding: Encoding) Loc {
    return lineLocAtIndex(text, positionToIndex(text, position, encoding));
}

pub fn lineSliceAtPosition(text: []const u8, position: types.Position, encoding: Encoding) []const u8 {
    return locToSlice(text, lineLocAtPosition(text, position, encoding));
}

pub fn lineLocUntilIndex(text: []const u8, index: usize) Loc {
    return .{
        .start = if (std.mem.lastIndexOfScalar(u8, text[0..index], '\n')) |idx| idx + 1 else 0,
        .end = index,
    };
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

pub fn convertRangeEncoding(text: []const u8, range: types.Range, from_encoding: Encoding, to_encoding: Encoding) types.Range {
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

/// returns true if a is inside b
pub fn locInside(inner: Loc, outer: Loc) bool {
    std.debug.assert(inner.start <= inner.end and outer.start <= outer.end);
    return outer.start <= inner.start and inner.end <= outer.end;
}

/// returns the union of a and b
pub fn locMerge(a: Loc, b: Loc) Loc {
    std.debug.assert(a.start <= a.end and b.start <= b.end);
    return .{
        .start = @min(a.start, b.start),
        .end = @max(a.end, b.end),
    };
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

/// returns the number of (utf-8 code units / bytes) that represent `n` code units in `text`
pub fn getNCodeUnitByteCount(text: []const u8, n: usize, encoding: Encoding) usize {
    switch (encoding) {
        .@"utf-8" => return n,
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
                i += std.unicode.utf8ByteSequenceLength(text[i]) catch unreachable;
            }
            return i;
        },
    }
}

pub fn rangeLessThan(a: types.Range, b: types.Range) bool {
    return positionLessThan(a.start, b.start) or positionLessThan(a.end, b.end);
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
