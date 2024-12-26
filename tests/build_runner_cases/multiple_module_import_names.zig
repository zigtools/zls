const std = @import("std");

// https://github.com/zigtools/zls/issues/2118
pub fn build(b: *std.Build) void {
    const foo = b.addModule("foo", .{ .root_source_file = b.path("foo.zig") });
    const bar = b.addModule("bar", .{ .root_source_file = b.path("bar.zig") });

    foo.addImport("bar_in_foo", bar);
    bar.addImport("foo_in_bar", foo);

    _ = b.addModule("main", .{
        .root_source_file = b.path("main.zig"),
        .imports = &.{
            .{ .name = "foo_in_main", .module = foo },
            .{ .name = "bar_in_main", .module = bar },
        },
    });
}
