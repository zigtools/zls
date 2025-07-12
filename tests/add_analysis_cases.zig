//! This file is imported by `../build.zig` to add code analysis tests to the build system.
//! See the `./analysis` subdirectory.

const std = @import("std");

pub fn addCases(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
) void {
    const cases_dir = b.path("tests/analysis");
    const cases_path_from_root = b.pathFromRoot("tests/analysis");

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

    // https://github.com/ziglang/zig/issues/20605
    var dir = std.fs.openDirAbsolute(b.pathFromRoot(cases_path_from_root), .{ .iterate = true }) catch |err|
        std.debug.panic("failed to open '{s}': {}", .{ cases_path_from_root, err });
    defer dir.close();

    var it = dir.iterate();

    while (true) {
        const entry = it.next() catch |err|
            std.debug.panic("failed to walk directory '{s}': {}", .{ cases_path_from_root, err }) orelse break;

        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, std.fs.path.extension(entry.name), ".zig")) continue;

        for (test_filters) |test_filter| {
            if (std.mem.indexOf(u8, entry.name, test_filter) != null) break;
        } else if (test_filters.len > 0) continue;

        const run_check = std.Build.Step.Run.create(b, b.fmt("run analysis on {s}", .{entry.name}));
        run_check.producer = check_exe;

        if (target.result.cpu.arch.isWasm() and b.enable_wasmtime) {
            run_check.skip_foreign_checks = true;
            run_check.addArgs(&.{
                "wasmtime",
                "--dir=.",
                b.fmt("--dir={f}::/lib", .{b.graph.zig_lib_directory}),
                "--",
            });
        }

        run_check.addArtifactArg(check_exe);
        if (target.query.eql(b.graph.host.query)) {
            run_check.addArg("--zig-exe-path");
            run_check.addFileArg(.{ .cwd_relative = b.graph.zig_exe });
        }
        if (!target.result.cpu.arch.isWasm()) {
            run_check.addArg("--zig-lib-path");
            run_check.addDirectoryArg(.{ .cwd_relative = b.fmt("{f}", .{b.graph.zig_lib_directory}) });
        }

        const input_file = cases_dir.path(b, entry.name);
        if (!target.result.cpu.arch.isWasm()) {
            run_check.addFileArg(input_file);
        } else {
            // pass a relative file path when running with wasmtime
            run_check.setCwd(cases_dir);
            run_check.addArg(entry.name);
            run_check.addFileInput(input_file);
        }

        test_step.dependOn(&run_check.step);
    }
}
