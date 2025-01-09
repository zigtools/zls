const std = @import("std");

pub fn build(b: *std.Build) void {
    const foo = b.addModule("foo", .{
        .root_source_file = b.path("root.zig"),
    });
    foo.addCMacro("key", "value");
}
