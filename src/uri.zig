const std = @import("std");
const builtin = @import("builtin");

/// Converts a file system path to a Uri.
/// Caller owns the returned memory
pub fn fromPath(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]u8 {
    return try fromPathWithOs(allocator, path, builtin.os.tag == .windows);
}

fn fromPathWithOs(
    allocator: std.mem.Allocator,
    path: []const u8,
    comptime is_windows: bool,
) error{OutOfMemory}![]u8 {
    var buf: std.ArrayList(u8) = try .initCapacity(allocator, path.len + 8);
    errdefer buf.deinit(allocator);

    buf.appendSliceAssumeCapacity("file://");
    if (!std.mem.startsWith(u8, path, "/")) {
        buf.appendAssumeCapacity('/');
    }

    var value = path;

    if (is_windows and
        path.len >= 2 and
        std.ascii.isAlphabetic(path[0]) and
        path[1] == ':')
    {
        // convert windows drive letter to lower case
        try buf.append(allocator, std.ascii.toLower(path[0]));
        value = value[1..];
    }

    for (value) |c| {
        if (is_windows and c == '\\') {
            try buf.append(allocator, '/');
            continue;
        }
        switch (c) {
            // zig fmt: off
            'A'...'Z', 'a'...'z', '0'...'9',
            '-', '.', '_', '~',
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=',
            '/', ':', '@',
            // zig fmt: on
            => try buf.append(allocator, c),
            else => try buf.print(allocator, "%{X:0>2}", .{c}),
        }
    }

    return try buf.toOwnedSlice(allocator);
}

test "fromPath (posix)" {
    const uri = try fromPathWithOs(std.testing.allocator, "/home/main.zig", false);
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("file:///home/main.zig", uri);
}

test "fromPath (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "C:/main.zig", true);
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("file:///c:/main.zig", uri);
}

test "fromPath - preserve '\\' (posix)" {
    const uri = try fromPathWithOs(std.testing.allocator, "/home\\main.zig", false);
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("file:///home%5Cmain.zig", uri);
}

test "fromPath - convert '\\' to '/' (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "C:\\main.zig", true);
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("file:///c:/main.zig", uri);
}

test "fromPath - windows like path on posix" {
    const uri = try fromPathWithOs(std.testing.allocator, "/C:\\main.zig", false);
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("file:///C:%5Cmain.zig", uri);
}

/// Converts a Uri to a file system path.
/// Caller owns the returned memory
pub fn toFsPath(allocator: std.mem.Allocator, raw_uri: []const u8) (std.Uri.ParseError || error{ UnsupportedScheme, OutOfMemory })![]u8 {
    return try toFsPathWithOs(allocator, raw_uri, builtin.os.tag == .windows);
}

fn toFsPathWithOs(
    allocator: std.mem.Allocator,
    raw_uri: []const u8,
    comptime is_windows: bool,
) (std.Uri.ParseError || error{ UnsupportedScheme, OutOfMemory })![]u8 {
    const uri: std.Uri = try .parse(raw_uri);
    if (!std.mem.eql(u8, uri.scheme, "file")) return error.UnsupportedScheme;

    var aw: std.Io.Writer.Allocating = try .initCapacity(allocator, raw_uri.len);
    uri.path.formatRaw(&aw.writer) catch unreachable;
    var buf = aw.toArrayList();
    defer buf.deinit(allocator);

    if (is_windows and
        buf.items.len >= 3 and
        buf.items[0] == '/' and
        std.ascii.isAlphabetic(buf.items[1]) and
        buf.items[2] == ':')
    {
        // convert windows drive letter to lower case
        buf.items[1] = std.ascii.toLower(buf.items[1]);

        // remove the extra slash
        @memmove(buf.items[0 .. buf.items.len - 1], buf.items[1..]);
        buf.items.len -= 1;
    }

    if (is_windows) {
        for (buf.items) |*c| {
            if (c.* == '\\') c.* = '/';
        }
    }

    return try buf.toOwnedSlice(allocator);
}

test "toFsPath - convert percent encoded '\\' to '/' (windows)" {
    const path = try toFsPathWithOs(std.testing.allocator, "file:///C:%5Cmain.zig", true);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("c:/main.zig", path);
}

test "toFsPath - preserve percent encoded '\\'  (posix)" {
    const path = try toFsPathWithOs(std.testing.allocator, "file:///foo%5Cmain.zig", false);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/foo\\main.zig", path);
}

test "toFsPath - percent encoded drive letter (windows)" {
    const path = try toFsPathWithOs(std.testing.allocator, "file:///%43%3a%5Cfoo\\main.zig", true);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("c:/foo/main.zig", path);
}

test "toFsPath - windows like path on posix" {
    const path = try toFsPathWithOs(std.testing.allocator, "file:///C:%5Cmain.zig", false);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/C:\\main.zig", path);
}
