const std = @import("std");
const types = @import("types.zig");

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
        return DocumentPosition{ .line = line, .absolute_index = @intCast(usize, index), .line_index = @intCast(usize, position.character) };
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
        return DocumentPosition{ .line = line, .absolute_index = line_start_idx + utf8_idx, .line_index = utf8_idx };
    }
}

pub const TokenLocation = struct {
    line: usize,
    column: usize,
};

pub fn tokenRelativeLocation(tree: *std.zig.ast.Tree, start_index: usize, token: std.zig.ast.TokenIndex, encoding: Encoding) !TokenLocation {
    const token_loc = tree.token_locs[token];

    var loc = TokenLocation{
        .line = 0,
        .column = 0,
    };
    const token_start = token_loc.start;
    const source = tree.source[start_index..];
    var i: usize = 0;
    while (i < token_start - start_index) {
        const c = source[i];
        if (c == '\n') {
            loc.line += 1;
            loc.column = 0;
            i += 1;
        } else {
            if (encoding == .utf16) {
                const n = try std.unicode.utf8ByteSequenceLength(c);
                const codepoint = try std.unicode.utf8Decode(source[i .. i + n]);
                if (codepoint < 0x10000) {
                    loc.column += 1;
                } else {
                    loc.column += 2;
                }
                i += n;
            } else {
                loc.column += 1;
                i += 1;
            }
        }
    }
    return loc;
}

/// Asserts the token is comprised of valid utf8
pub fn tokenLength(tree: *std.zig.ast.Tree, token: std.zig.ast.TokenIndex, encoding: Encoding) usize {
    const token_loc = tree.token_locs[token];
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
