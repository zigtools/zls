const std = @import("std");

pub fn build(b: *std.Build) void {
    const write_files = b.addWriteFiles();
    const generated = write_files.add("generated.zig", "");

    _ = b.addModule("root", .{
        .root_source_file = generated,
    });
}
