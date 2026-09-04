//! This file is imported by `../build.zig` to add code analysis tests to the build system.
//! See the `./analysis` subdirectory.

const std = @import("std");

pub fn addCases(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.OptimizeMode,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
) void {
    const cases_path = "tests/analysis";

    const check_exe = b.addExecutable(.{
        .name = "analysis_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/analysis_check.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zls", .module = b.modules.get("zls").? },
            },
        }),
    });

    b.dependOnDirectory(b.path(cases_path));

    var dir = b.root.openDir(b.graph.io, cases_path, .{ .iterate = true }) catch |err|
        std.debug.panic("failed to open '{f}': {}", .{ b.path(cases_path), err });
    defer dir.close(b.graph.io);

    var it = dir.iterate();

    while (true) {
        const entry = it.next(b.graph.io) catch |err|
            std.debug.panic("failed to walk directory '{f}': {}", .{ b.path(cases_path), err }) orelse break;

        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, std.Io.Dir.path.extension(entry.name), ".zig")) continue;

        for (test_filters) |test_filter| {
            if (std.mem.find(u8, entry.name, test_filter) != null) break;
        } else if (test_filters.len > 0) continue;

        const run_check = std.Build.Step.Run.create(b, b.fmt("run analysis on {s}", .{entry.name}));
        run_check.producer = check_exe;

        run_check.addArtifactArg(check_exe);
        if (target.query.eql(b.graph.host.query)) {
            run_check.addArg("--zig-exe-path");
            run_check.addFileArg(.zig_exe);
        }
        run_check.setPreopen("/lib", .zig_lib);
        if (!target.result.cpu.arch.isWasm()) {
            run_check.addArg("--zig-lib-path");
            run_check.addDirectoryArg(.zig_lib);
        }

        const input_file = b.path(cases_path).path(b, entry.name);
        if (!target.result.cpu.arch.isWasm()) {
            run_check.addFileArg(input_file);
        } else {
            // pass a relative file path when running with wasmtime
            run_check.setCwd(b.path(cases_path));
            run_check.addArg(entry.name);
            run_check.addFileInput(input_file);
        }

        test_step.dependOn(&run_check.step);
    }
}
