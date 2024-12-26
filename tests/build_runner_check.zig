const std = @import("std");

pub fn main() !u8 {
    var general_purpose_allocator: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = general_purpose_allocator.deinit();
    const gpa = general_purpose_allocator.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 4) @panic("invalid arguments");

    const expected = std.fs.cwd().readFileAlloc(gpa, args[1], std.math.maxInt(u32)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[1], err });
    defer gpa.free(expected);

    const actual_unsanitized = std.fs.cwd().readFileAlloc(gpa, args[2], std.math.maxInt(u32)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[2], err });
    defer gpa.free(actual_unsanitized);

    const actual = blk: {
        var base_dir_buffer: std.ArrayListUnmanaged(u8) = .{};
        defer base_dir_buffer.deinit(gpa);

        try std.json.encodeJsonStringChars(args[3], .{}, base_dir_buffer.writer(gpa));
        try std.json.encodeJsonStringChars(&.{std.fs.path.sep}, .{}, base_dir_buffer.writer(gpa));

        // The build runner will produce absolute paths in the output so we remove them here.
        const actual = try std.mem.replaceOwned(u8, gpa, actual_unsanitized, base_dir_buffer.items, "");

        // We also convert windows style '\\' path separators to posix style '/'.
        switch (std.fs.path.sep) {
            '/' => break :blk actual,
            '\\' => {
                defer gpa.free(actual);
                break :blk try std.mem.replaceOwned(u8, gpa, actual, "\\\\", "/");
            },
            else => unreachable,
        }
    };
    defer gpa.free(actual);

    if (std.mem.eql(u8, expected, actual)) return 0;

    std.testing.expectEqualStrings(expected, actual) catch {};

    return 1;
}
