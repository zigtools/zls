const std = @import("std");
const builtin = @import("builtin");

/// Returns a URI from a path.
/// Caller should free memory
pub fn fromPath(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]const u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);
    const writer = buffer.writer(allocator);

    try writer.writeAll("file://" ++ if (builtin.target.os.tag == .windows) "/" else "");
    try std.Uri.writeEscapedPath(writer, path);

    return try buffer.toOwnedSlice(allocator);
}

test fromPath {
    if (builtin.os.tag == .windows) {
        const fromPathWin = try fromPath(std.testing.allocator, "c:\\main.zig");
        defer std.testing.allocator.free(fromPathWin);
        try std.testing.expectEqualStrings("file:///c:%5Cmain.zig", fromPathWin);
    }

    if (builtin.os.tag != .windows) {
        const fromPathUnix = try fromPath(std.testing.allocator, "/home/main.zig");
        defer std.testing.allocator.free(fromPathUnix);
        try std.testing.expectEqualStrings("file:///home/main.zig", fromPathUnix);
    }
}

/// parses a Uri and return the unescaped path
/// Caller should free memory
pub fn parse(allocator: std.mem.Allocator, str: []const u8) (std.Uri.ParseError || error{OutOfMemory})![]u8 {
    const uri = try std.Uri.parse(str);

    if (!std.mem.eql(u8, uri.scheme, "file")) return error.InvalidFormat;
    const path = uri.path[@intFromBool(builtin.os.tag == .windows)..];
    return try std.Uri.unescapeString(allocator, path);
}

test parse {
    if (builtin.os.tag == .windows) {
        const parseWin = try parse(std.testing.allocator, "file:///c%3A/main.zig");
        defer std.testing.allocator.free(parseWin);
        try std.testing.expectEqualStrings("c:/main.zig", parseWin);

        const parseWin2 = try parse(std.testing.allocator, "file:///c%3A/main%2B.zig");
        defer std.testing.allocator.free(parseWin2);
        try std.testing.expectEqualStrings("c:/main+.zig", parseWin2);
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
