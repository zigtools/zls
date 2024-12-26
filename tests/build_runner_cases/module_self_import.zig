const std = @import("std");

// https://github.com/zigtools/zls/issues/2117
pub fn build(b: *std.Build) void {
    const module = b.addModule("foo", .{
        .root_source_file = b.path("root.zig"),
    });
    module.addImport("bar", module);
}
