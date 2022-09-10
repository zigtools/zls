const std = @import("std");
const zls = @import("zls");

const URI = zls.URI;

const allocator = std.testing.allocator;

test "uri - pathRelative" {
    const join1 = try URI.pathRelative(allocator, "file://project/zig", "/src/main+.zig");
    defer allocator.free(join1);
    try std.testing.expectEqualStrings("file://project/zig/src/main%2B.zig", join1);

    const join2 = try URI.pathRelative(allocator, "file://project/zig/wow", "../]src]/]main.zig");
    defer allocator.free(join2);
    try std.testing.expectEqualStrings("file://project/zig/%5Dsrc%5D/%5Dmain.zig", join2);
}