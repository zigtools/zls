const std = @import("std");

pub fn build(b: *std.Build) void {
    const module = b.addModule("root", .{
        .root_source_file = b.path("root.zig"),
    });

    const options = b.addOptions();
    options.addOption(bool, "enabled", true);
    module.addOptions("options", options);
}
