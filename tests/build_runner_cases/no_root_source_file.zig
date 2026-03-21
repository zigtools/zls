const std = @import("std");

pub fn build(b: *std.Build) void {
    const with_root_source_file = b.createModule(.{ .root_source_file = b.path("baz.zig") });
    const without_root_source_file = b.createModule(.{});
    _ = b.addModule("foo", .{
        .imports = &.{
            .{ .name = "with-root-source-file", .module = with_root_source_file },
            .{ .name = "without-root-source-file", .module = without_root_source_file },
        },
    });
    _ = b.addModule("bar", .{
        .root_source_file = b.path("bar.zig"),
        .imports = &.{
            .{ .name = "with-root-source-file", .module = with_root_source_file },
            .{ .name = "without-root-source-file", .module = without_root_source_file },
        },
    });
}
