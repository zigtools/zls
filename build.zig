const std = @import("std");
const builtin = @import("builtin");
// const build_options = @import("build_options")

const setup = @import("src/setup.zig");

var builder: *std.build.Builder = undefined;

pub fn config(step: *std.build.Step) anyerror!void {
    try setup.wizard(builder.allocator, builder.exe_dir);
}

pub fn build(b: *std.build.Builder) !void {
    builder = b;
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
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

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const configure_step = b.step("config", "Configure zls");
    configure_step.makeFn = config;

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
