const std = @import("std");
const builtin = @import("builtin");
// const build_options = @import("build_options");

pub fn build(b: *std.build.Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zls", "src/main.zig");

    const data_version = try std.mem.concat(b.allocator, u8, &[3][]const u8{"\"", b.option([]const u8, "data_version", "The data version - either 0.6.0 or master.") orelse "0.6.0", "\""});
    defer b.allocator.free(data_version);
    exe.addBuildOption(
        []const u8,
        "data_version",
        data_version,
    );

    exe.addBuildOption(
        bool,
        "allocation_info",
        b.option(bool, "allocation_info", "Enable use of debugging allocator and info logging.") orelse false,
    );

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
