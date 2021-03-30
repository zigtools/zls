const std = @import("std");
const builtin = @import("builtin");
// const build_options = @import("build_options")

var builder: *std.build.Builder = undefined;

pub fn build(b: *std.build.Builder) !void {
    builder = b;
    const target = b.standardTargetOptions(.{});

    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zls", "src/main.zig");

    exe.addBuildOption(
        []const u8,
        "data_version",
        b.option([]const u8, "data_version", "The data version - either 0.7.0 or master.") orelse "master",
    );

    exe.addPackage(.{ .name = "known-folders", .path = "src/known-folders/known-folders.zig" });

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    b.installFile("src/special/build_runner.zig", "bin/build_runner.zig");

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(builder.getInstallStep());

    var unit_tests = b.addTest("src/unit_tests.zig");
    unit_tests.setBuildMode(.Debug);
    test_step.dependOn(&unit_tests.step);

    var session_tests = b.addTest("tests/sessions.zig");
    session_tests.addPackage(.{ .name = "header", .path = "src/header.zig" });
    session_tests.setBuildMode(.Debug);
    test_step.dependOn(&session_tests.step);
}
