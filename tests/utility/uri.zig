const std = @import("std");
const zls = @import("zls");

const URI = zls.URI;

const allocator = std.testing.allocator;

test "uri - parse" {
    const parseWin = try URI.parse(allocator, "file:///c%3A/main.zig");
    defer allocator.free(parseWin);
    try std.testing.expectEqualStrings("c:\\main.zig", parseWin);

    const parseWin2 = try URI.parse(allocator, "file:///c%3A/main%2B.zig");
    defer allocator.free(parseWin2);
    try std.testing.expectEqualStrings("c:\\main+.zig", parseWin2);
}

test "uri - fromPath" {
    const fromPathWin = try URI.fromPath(allocator, "c:\\main.zig");
    defer allocator.free(fromPathWin);
    try std.testing.expectEqualStrings("file:///c%3A/main.zig", fromPathWin);
}

test "uri - pathRelative" {
    const join1 = try URI.pathRelative(allocator, "file://project/zig", "/src/main+.zig");
    defer allocator.free(join1);
    try std.testing.expectEqualStrings("file://project/zig/src/main%2B.zig", join1);

    const join2 = try URI.pathRelative(allocator, "file://project/zig/wow", "../]src]/]main.zig");
    defer allocator.free(join2);
    try std.testing.expectEqualStrings("file://project/zig/%5Dsrc%5D/%5Dmain.zig", join2);
}
