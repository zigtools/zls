const std = @import("std");
const types = @import("types.zig");
const ast = std.zig.ast;

pub const Encoding = enum {
    utf8,
    utf16,
};

pub const DocumentPosition = struct {
    line: []const u8,
    line_index: usize,
    absolute_index: usize,
};

pub fn documentPosition(doc: types.TextDocument, position: types.Position, encoding: Encoding) !DocumentPosition {
    var split_iterator = std.mem.split(doc.text, "\n");

    var line_idx: i64 = 0;
    var line: []const u8 = "";
    while (line_idx < position.line) : (line_idx += 1) {
        line = split_iterator.next() orelse return error.InvalidParams;
    }

    const line_start_idx = split_iterator.index.?;
    line = split_iterator.next() orelse return error.InvalidParams;

    if (encoding == .utf8) {
        const index = @intCast(i64, line_start_idx) + position.character;
        if (index < 0 or index > @intCast(i64, doc.text.len)) {
            return error.InvalidParams;
        }
        return DocumentPosition{
            .line = line,
            .absolute_index = @intCast(usize, index),
            .line_index = @intCast(usize, position.character),
        };
    } else {
        const utf8 = doc.text[line_start_idx..];
        var utf8_idx: usize = 0;
        var utf16_idx: usize = 0;
        while (utf16_idx < position.character) {
            if (utf8_idx > utf8.len) {
                return error.InvalidParams;
            }

            const n = try std.unicode.utf8ByteSequenceLength(utf8[utf8_idx]);
            const next_utf8_idx = utf8_idx + n;
            const codepoint = try std.unicode.utf8Decode(utf8[utf8_idx..next_utf8_idx]);
            if (codepoint < 0x10000) {
                utf16_idx += 1;
            } else {
                utf16_idx += 2;
            }
            utf8_idx = next_utf8_idx;
        }
        return DocumentPosition{
            .line = line,
            .absolute_index = line_start_idx + utf8_idx,
            .line_index = utf8_idx,
        };
    }
}

pub fn lineSectionLength(tree: ast.Tree, start_index: usize, end_index: usize, encoding: Encoding) !usize {
    const source = tree.source[start_index..];
    std.debug.assert(end_index >= start_index and source.len >= end_index - start_index);
    if (encoding == .utf8) {
        return end_index - start_index;
    }

    var result: usize = 0;
    var i: usize = 0;
    while (i + start_index < end_index) {
        std.debug.assert(source[i] != '\n');

        const n = try std.unicode.utf8ByteSequenceLength(source[i]);
        if (i + n >= source.len)
            return error.CodepointTooLong;

        const codepoint = try std.unicode.utf8Decode(source[i .. i + n]);

        result += 1 + @as(usize, @boolToInt(codepoint >= 0x10000));
        i += n;
    }
    return result;
}

pub const TokenLocation = struct {
    line: usize,
    column: usize,
    offset: usize,

    pub fn add(lhs: TokenLocation, rhs: TokenLocation) TokenLocation {
        return .{
            .line = lhs.line + rhs.line,
            .column = if (rhs.line == 0)
                lhs.column + rhs.column
            else
                rhs.column,
            .offset = rhs.offset,
        };
    }
};

pub fn tokenRelativeLocation(tree: ast.Tree, start_index: usize, token_start: usize, encoding: Encoding) !TokenLocation {
    std.debug.assert(token_start >= start_index);
    var loc = TokenLocation{
        .line = 0,
        .column = 0,
        .offset = 0,
    };

    const source = tree.source[start_index..];
    var i: usize = 0;
    while (i + start_index < token_start) {
        const c = source[i];
        if (c == '\n') {
            loc.line += 1;
            loc.column = 0;
            i += 1;
        } else {
            if (encoding == .utf16) {
                const n = try std.unicode.utf8ByteSequenceLength(c);
                if (i + n >= source.len)
                    return error.CodepointTooLong;

                const codepoint = try std.unicode.utf8Decode(source[i .. i + n]);
                loc.column += 1 + @as(usize, @boolToInt(codepoint >= 0x10000));
                i += n;
            } else {
                loc.column += 1;
                i += 1;
            }
        }
    }
    loc.offset = i + start_index;
    return loc;
}

/// Asserts the token is comprised of valid utf8
pub fn tokenLength(tree: ast.Tree, token: ast.TokenIndex, encoding: Encoding) usize {
    const token_loc = tokenLocation(tree, token);
    if (encoding == .utf8)
        return token_loc.end - token_loc.start;

    var i: usize = token_loc.start;
    var utf16_len: usize = 0;
    while (i < token_loc.end) {
        const n = std.unicode.utf8ByteSequenceLength(tree.source[i]) catch unreachable;
        const codepoint = std.unicode.utf8Decode(tree.source[i .. i + n]) catch unreachable;
        if (codepoint < 0x10000) {
            utf16_len += 1;
        } else {
            utf16_len += 2;
        }
        i += n;
    }
    return utf16_len;
}

/// Token location inside source
pub const Loc = struct {
    start: usize,
    end: usize,
};

pub fn tokenLocation(tree: ast.Tree, token_index: ast.TokenIndex) Loc {
    const start = tree.tokens.items(.start)[token_index];
    const tag = tree.tokens.items(.tag)[token_index];

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = start,
        .pending_invalid_token = null,
    };

    const token = tokenizer.next();
    std.debug.assert(token.tag == tag);
    return .{ .start = token.loc.start, .end = token.loc.end };
}

pub fn documentRange(doc: types.TextDocument, encoding: Encoding) !types.Range {
    var line_idx: i64 = 0;
    var curr_line: []const u8 = doc.text;

    var split_iterator = std.mem.split(doc.text, "\n");
    while (split_iterator.next()) |line| : (line_idx += 1) {
        curr_line = line;
    }

    if (encoding == .utf8) {
        return types.Range{
            .start = .{
                .line = 0,
                .character = 0,
            },
            .end = .{
                .line = line_idx,
                .character = @intCast(i64, curr_line.len),
            },
        };
    } else {
        var utf16_len: usize = 0;
        var line_utf8_idx: usize = 0;
        while (line_utf8_idx < curr_line.len) {
            const n = try std.unicode.utf8ByteSequenceLength(curr_line[line_utf8_idx]);
            const codepoint = try std.unicode.utf8Decode(curr_line[line_utf8_idx .. line_utf8_idx + n]);
            if (codepoint < 0x10000) {
                utf16_len += 1;
            } else {
                utf16_len += 2;
            }
            line_utf8_idx += n;
        }
        return types.Range{
            .start = .{
                .line = 0,
                .character = 0,
            },
            .end = .{
                .line = line_idx,
                .character = @intCast(i64, utf16_len),
            },
        };
    }
}
