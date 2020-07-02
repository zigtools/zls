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
