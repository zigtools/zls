//! There are three different module with `main.zig` as their root source file
//! and every one of them defines an import with the name `collision`.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const first = b.createModule(.{ .root_source_file = b.path("first.zig") });
    const second = b.createModule(.{ .root_source_file = b.path("second.zig") });
    const third = b.createModule(.{ .root_source_file = b.path("third.zig") });

    const exe = b.addExecutable(.{
        .name = "exe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "collision", .module = third },
            },
        }),
    });
    b.installArtifact(exe);

    _ = b.addModule("foo", .{
        .root_source_file = b.path("main.zig"),
        .imports = &.{
            .{ .name = "collision", .module = first },
            .{ .name = "first", .module = first },
        },
    });
    _ = b.addModule("bar", .{
        .root_source_file = b.path("main.zig"),
        .imports = &.{
            .{ .name = "collision", .module = second },
            .{ .name = "second", .module = second },
        },
    });
}
