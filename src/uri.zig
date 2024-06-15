const std = @import("std");
const builtin = @import("builtin");

// http://tools.ietf.org/html/rfc3986#section-2.2
const reserved_chars = &[_]u8{
    '!', '#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', ':',
    ';', '=', '?', '@', '[', ']',
};

const reserved_escapes = blk: {
    var escapes: [reserved_chars.len][3]u8 = [_][3]u8{[_]u8{undefined} ** 3} ** reserved_chars.len;

    for (reserved_chars, 0..) |c, i| {
        escapes[i][0] = '%';
        _ = std.fmt.bufPrint(escapes[i][1..], "{X}", .{c}) catch unreachable;
    }
    break :blk escapes;
};

/// Returns a URI from a path, caller owns the memory allocated with `allocator`
pub fn fromPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len == 0) return "";
    const prefix = if (builtin.os.tag == .windows) "file:///" else "file://";

    var buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, prefix.len + path.len);
    errdefer buf.deinit(allocator);

    buf.appendSliceAssumeCapacity(prefix);

    for (path) |char| {
        if (char == std.fs.path.sep) {
            try buf.append(allocator, '/');
        } else if (std.mem.indexOfScalar(u8, reserved_chars, char)) |reserved| {
            try buf.appendSlice(allocator, &reserved_escapes[reserved]);
        } else {
            try buf.append(allocator, char);
        }
    }

    // On windows, we need to lowercase the drive name.
    if (builtin.os.tag == .windows) {
        if (buf.items.len > prefix.len + 1 and
            std.ascii.isAlphanumeric(buf.items[prefix.len]) and
            std.mem.startsWith(u8, buf.items[prefix.len + 1 ..], "%3A"))
        {
            buf.items[prefix.len] = std.ascii.toLower(buf.items[prefix.len]);
        }
    }

    return buf.toOwnedSlice(allocator);
}

test fromPath {
    if (builtin.os.tag == .windows) {
        const fromPathWin = try fromPath(std.testing.allocator, "c:\\main.zig");
        defer std.testing.allocator.free(fromPathWin);
        try std.testing.expectEqualStrings("file:///c%3A/main.zig", fromPathWin);
    }

    if (builtin.os.tag != .windows) {
        const fromPathUnix = try fromPath(std.testing.allocator, "/home/main.zig");
        defer std.testing.allocator.free(fromPathUnix);
        try std.testing.expectEqualStrings("file:///home/main.zig", fromPathUnix);
    }
}

/// Move along `rel` from `base` with a single allocation.
/// `base` is a URI of a folder, `rel` is a raw relative path.
pub fn pathRelative(allocator: std.mem.Allocator, base: []const u8, rel: []const u8) error{ OutOfMemory, UriBadScheme }![]const u8 {
    const max_size = base.len + rel.len * 3 + 1;

    var result = try std.ArrayListUnmanaged(u8).initCapacity(allocator, max_size);
    errdefer result.deinit(allocator);

    result.appendSliceAssumeCapacity(base);

    var it = std.mem.tokenizeScalar(u8, rel, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, ".")) {
            continue;
        } else if (std.mem.eql(u8, component, "..")) {
            while ((result.getLastOrNull() orelse return error.UriBadScheme) == '/') {
                _ = result.pop();
            }
            while (true) {
                const char = result.popOrNull() orelse return error.UriBadScheme;
                if (char == '/') break;
            }
        } else {
            result.appendAssumeCapacity('/');
            for (component) |char| {
                if (std.mem.indexOfScalar(u8, reserved_chars, char)) |reserved| {
                    const escape = &reserved_escapes[reserved];
                    result.appendSliceAssumeCapacity(escape);
                } else {
                    result.appendAssumeCapacity(char);
                }
            }
        }
    }

    return result.toOwnedSlice(allocator);
}

test pathRelative {
    const join1 = try pathRelative(std.testing.allocator, "file:///project/zig", "/src/main+.zig");
    defer std.testing.allocator.free(join1);
    try std.testing.expectEqualStrings("file:///project/zig/src/main%2B.zig", join1);

    const join2 = try pathRelative(std.testing.allocator, "file:///project/zig/wow", "../]src]/]main.zig");
    defer std.testing.allocator.free(join2);
    try std.testing.expectEqualStrings("file:///project/zig/%5Dsrc%5D/%5Dmain.zig", join2);

    const join3 = try pathRelative(std.testing.allocator, "file:///project/zig/wow//", "../src/main.zig");
    defer std.testing.allocator.free(join3);
    try std.testing.expectEqualStrings("file:///project/zig/src/main.zig", join3);
}

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
pub fn parse(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    if (str.len < 7 or !std.mem.eql(u8, "file://", str[0..7])) return error.UriBadScheme;

    var uri = try allocator.alloc(u8, str.len - (if (std.fs.path.sep == '\\') 8 else 7));
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

    return allocator.realloc(uri, i);
}

test parse {
    if (builtin.os.tag == .windows) {
        const parseWin = try parse(std.testing.allocator, "file:///c%3A/main.zig");
        defer std.testing.allocator.free(parseWin);
        try std.testing.expectEqualStrings("c:\\main.zig", parseWin);

        const parseWin2 = try parse(std.testing.allocator, "file:///c%3A/main%2B.zig");
        defer std.testing.allocator.free(parseWin2);
        try std.testing.expectEqualStrings("c:\\main+.zig", parseWin2);
    }

    if (builtin.os.tag != .windows) {
        const parseUnix = try parse(std.testing.allocator, "file:///home/main.zig");
        defer std.testing.allocator.free(parseUnix);
        try std.testing.expectEqualStrings("/home/main.zig", parseUnix);

        const parseUnix2 = try parse(std.testing.allocator, "file:///home/main%2B.zig");
        defer std.testing.allocator.free(parseUnix2);
        try std.testing.expectEqualStrings("/home/main+.zig", parseUnix2);
    }
}
