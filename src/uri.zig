const std = @import("std");
const mem = std.mem;

const reserved_chars = &[_]u8{
    '!', '#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', ':',
    ';', '=', '?', '@', '[', ']',
};
const reserved_escapes = comptime blk: {
    var escapes: [reserved_chars.len][3]u8
        = [_][3]u8{[_]u8{undefined} ** 3} ** reserved_chars.len;

    for (reserved_chars) |c, i| {
        escapes[i][0] = '%';
        _ = std.fmt.bufPrint(escapes[i][1..], "{X}", .{c}) catch unreachable;
    }
    break :blk &escapes;
};

/// Returns a URI from a path, caller owns the memory allocated with `allocator`
pub fn fromPath(allocator: *mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len == 0) return "";
    const prefix = if (std.builtin.os.tag == .windows) "file:///" else "file://";

    var buf = std.ArrayList(u8).init(allocator);
    try buf.appendSlice(prefix);

    const out_stream = buf.writer();

    for (path) |char| {
        if (char == std.fs.path.sep) {
            try buf.append('/');
        } else if (mem.indexOfScalar(u8, reserved_chars, char)) |reserved| {
            try buf.appendSlice(&reserved_escapes[reserved]);
        } else {
            try buf.append(char);
        }
    }

    // On windows, we need to lowercase the drive name.
    if (std.builtin.os.tag == .windows) {
        if (buf.items.len > prefix.len + 1 and
            std.ascii.isAlpha(buf.items[prefix.len]) and
            mem.startsWith(u8, buf.items[prefix.len + 1 ..], "%3A"))
        {
            buf.items[prefix.len] = std.ascii.toLower(buf.items[prefix.len]);
        }
    }

    return buf.toOwnedSlice();
}

/// Move along `rel` from `base` with a single allocation.
/// `base` is a URI of a folder, `rel` is a raw relative path.
pub fn pathRelative(allocator: *mem.Allocator, base: []const u8, rel: []const u8) ![]const u8 {
    const max_size = base.len + rel.len * 3 + 1;

    var result = try allocator.alloc(u8, max_size);
    errdefer allocator.free(result);
    mem.copy(u8, result, base);
    var result_index: usize = base.len;

    var it = mem.tokenize(rel, "/");
    while (it.next()) |component| {
        if (mem.eql(u8, component, ".")) {
            continue;
        } else if (mem.eql(u8, component, "..")) {
            while (true) {
                if (result_index == 0)
                    return error.UriBadScheme;
                result_index -= 1;
                if (result[result_index] == '/')
                    break;
            }
        } else {
            result[result_index] = '/';
            result_index += 1;
            for (component) |char| {
                if (mem.indexOfScalar(u8, reserved_chars, char)) |reserved| {
                    const escape = &reserved_escapes[reserved];
                    mem.copy(u8, result[result_index..], escape);
                    result_index += escape.len;
                } else {
                    result[result_index] = char;
                    result_index += 1;
                }
            }
        }
    }

    return allocator.resize(result, result_index);
}

pub const UriParseError = error{
    UriBadScheme,
    UriBadHexChar,
    UriBadEscape,
    OutOfMemory,
};

// Original code: https://github.com/andersfr/zig-lsp/blob/master/uri.zig
fn parseHex(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => return error.UriBadHexChar,
    };
}

/// Caller should free memory
pub fn parse(allocator: *mem.Allocator, str: []const u8) ![]u8 {
    if (str.len < 7 or !mem.eql(u8, "file://", str[0..7])) return error.UriBadScheme;

    const uri = try allocator.alloc(u8, str.len - (if (std.fs.path.sep == '\\') 8 else 7));
    errdefer allocator.free(uri);

    const path = if (std.fs.path.sep == '\\') str[8..] else str[7..];

    var i: usize = 0;
    var j: usize = 0;
    while (j < path.len) : (i += 1) {
        if (path[j] == '%') {
            if (j + 2 >= path.len) return error.UriBadEscape;
            const upper = try parseHex(path[j + 1]);
            const lower = try parseHex(path[j + 2]);
            uri[i] = (upper << 4) + lower;
            j += 3;
        } else {
            uri[i] = if (path[j] == '/') std.fs.path.sep else path[j];
            j += 1;
        }
    }

    // Remove trailing separator
    if (i > 0 and uri[i - 1] == std.fs.path.sep) {
        i -= 1;
    }

    return allocator.shrink(uri, i);
}

