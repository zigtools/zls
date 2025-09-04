//! This file implements a standalone executable that is used by
//! `add_build_runner_cases.zig` to run build runner tests.
//! See the `./build_runner_cases` subdirectory.

const std = @import("std");
const zls = @import("zls");

pub fn main() !u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 4) @panic("invalid arguments");

    const expected = std.fs.cwd().readFileAlloc(args[1], gpa, .limited(16 * 1024 * 1024)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[1], err });
    defer gpa.free(expected);

    const actual_unsanitized = std.fs.cwd().readFileAlloc(args[2], gpa, .limited(16 * 1024 * 1024)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[2], err });
    defer gpa.free(actual_unsanitized);

    const actual = blk: {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();

        try std.json.Stringify.encodeJsonStringChars(args[3], .{}, &aw.writer);
        try std.json.Stringify.encodeJsonStringChars(&.{std.fs.path.sep}, .{}, &aw.writer);

        // The build runner will produce absolute paths in the output so we remove them here.
        const actual = try std.mem.replaceOwned(u8, gpa, actual_unsanitized, aw.written(), "");

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

    zls.testing.renderLineDiff(gpa, expected, actual);

    return 1;
}
