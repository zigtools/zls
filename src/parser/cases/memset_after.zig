const std = @import("std");

test "bytes value!" {
    const gpa = std.testing.allocator;
    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    var str1: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value1 = try ip.get(gpa, .{ .bytes = &str1 });
    @memset(&str1, 0);

    var str2: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value2 = try ip.get(gpa, .{ .bytes = &str2 });
    @memset(&str2, 0);

    var str3: [26]u8 = "https://www.duckduckgo.com".*;
    const bytes_value3 = try ip.get(gpa, .{ .bytes = &str3 });
    @memset(&str3, 0);

    try expect(bytes_value1 == bytes_value2);
    try expect(bytes_value2 != bytes_value3);
    try expect(@ptrToInt(&str1) != @ptrToInt(ip.indexToKey(bytes_value1).bytes.ptr));
    try expect(@ptrToInt(&str2) != @ptrToInt(ip.indexToKey(bytes_value2).bytes.ptr));
    try expect(@ptrToInt(&str3) != @ptrToInt(ip.indexToKey(bytes_value3).bytes.ptr));
    try std.testing.expectEqual(ip.indexToKey(bytes_value1).bytes.ptr, ip.indexToKey(bytes_value2).bytes.ptr);
    try std.testing.expectEqualStrings("https://www.youtube.com/watch?v=dQw4w9WgXcQ", ip.indexToKey(bytes_value1).bytes);
    try std.testing.expectEqualStrings("https://www.youtube.com/watch?v=dQw4w9WgXcQ", ip.indexToKey(bytes_value2).bytes);
    try std.testing.expectEqualStrings("https://www.duckduckgo.com", ip.indexToKey(bytes_value3).bytes);
}
