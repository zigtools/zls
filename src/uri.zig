const std = @import("std");
const builtin = @import("builtin");

/// Returns a file URI from a path.
/// Caller owns the returned memory
pub fn fromPath(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]u8 {
    if (path.len == 0) return try allocator.dupe(u8, "/");
    const prefix = if (builtin.os.tag == .windows) "file:///" else "file://";

    var buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, prefix.len + path.len);
    errdefer buf.deinit(allocator);

    buf.appendSliceAssumeCapacity(prefix);

    const writer = buf.writer(allocator);

    var start: usize = 0;
    for (path, 0..) |char, index| {
        switch (char) {
            // zig fmt: off
            'A'...'Z',
            'a'...'z',
            '0'...'9',
            '-', '.', '_', '~', '!',
            '$', '&', '\'','(', ')',
            '+', ',', ';', '=', '@',
            // zig fmt: on
            => continue,
            ':', '*' => if (builtin.os.tag != .windows) continue,
            else => {},
        }

        try writer.writeAll(path[start..index]);
        if (std.fs.path.isSep(char)) {
            try writer.writeByte('/');
        } else {
            try writer.print("%{X:0>2}", .{char});
        }
        start = index + 1;
    }
    try writer.writeAll(path[start..]);

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
        const fromPathWin = try fromPath(std.testing.allocator, "C:\\main.zig");
        defer std.testing.allocator.free(fromPathWin);
        try std.testing.expectEqualStrings("file:///c%3A/main.zig", fromPathWin);
    }

    if (builtin.os.tag != .windows) {
        const fromPathUnix = try fromPath(std.testing.allocator, "/home/main.zig");
        defer std.testing.allocator.free(fromPathUnix);
        try std.testing.expectEqualStrings("file:///home/main.zig", fromPathUnix);
    }
}

/// Parses a Uri and returns the unescaped path
/// Caller owns the returned memory
pub fn parse(allocator: std.mem.Allocator, str: []const u8) (std.Uri.ParseError || error{OutOfMemory})![]u8 {
    var uri = try std.Uri.parse(str);
    if (!std.mem.eql(u8, uri.scheme, "file")) return error.InvalidFormat;
    if (builtin.os.tag == .windows and uri.path.percent_encoded[0] == '/') {
        uri.path.percent_encoded = uri.path.percent_encoded[1..];
    }
    return try std.fmt.allocPrint(allocator, "{raw}", .{uri.path});
}
