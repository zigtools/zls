const std = @import("std");
const builtin = @import("builtin");
const zls = @import("zls");

const URI = zls.URI;

const allocator = std.testing.allocator;

test "uri - parse (Windows)" {
    if (builtin.os.tag == .windows) {
        const parseWin = try URI.parse(allocator, "file:///c%3A/main.zig");
        defer allocator.free(parseWin);
        try std.testing.expectEqualStrings("c:\\main.zig", parseWin);

        const parseWin2 = try URI.parse(allocator, "file:///c%3A/main%2B.zig");
        defer allocator.free(parseWin2);
        try std.testing.expectEqualStrings("c:\\main+.zig", parseWin2);
    }
}

test "uri - parse (Unix-style)" {
    if (builtin.os.tag != .windows) {
        const parseUnix = try URI.parse(allocator, "file:///home/main.zig");
        defer allocator.free(parseUnix);
        try std.testing.expectEqualStrings("/home/main.zig", parseUnix);

        const parseUnix2 = try URI.parse(allocator, "file:///home/main%2B.zig");
        defer allocator.free(parseUnix2);
        try std.testing.expectEqualStrings("/home/main+.zig", parseUnix2);
    }
}

test "uri - fromPath" {
    if (builtin.os.tag == .windows) {
        const fromPathWin = try URI.fromPath(allocator, "c:\\main.zig");
        defer allocator.free(fromPathWin);
        try std.testing.expectEqualStrings("file:///c%3A/main.zig", fromPathWin);
    }

    if (builtin.os.tag != .windows) {
        const fromPathUnix = try URI.fromPath(allocator, "/home/main.zig");
        defer allocator.free(fromPathUnix);
        try std.testing.expectEqualStrings("file:///home/main.zig", fromPathUnix);
    }
}

test "uri - pathRelative" {
    const join1 = try URI.pathRelative(allocator, "file:///project/zig", "/src/main+.zig");
    defer allocator.free(join1);
    try std.testing.expectEqualStrings("file:///project/zig/src/main%2B.zig", join1);

    const join2 = try URI.pathRelative(allocator, "file:///project/zig/wow", "../]src]/]main.zig");
    defer allocator.free(join2);
    try std.testing.expectEqualStrings("file:///project/zig/%5Dsrc%5D/%5Dmain.zig", join2);

    const join3 = try URI.pathRelative(allocator, "file:///project/zig/wow//", "../src/main.zig");
    defer allocator.free(join3);
    try std.testing.expectEqualStrings("file:///project/zig/src/main.zig", join3);
}
