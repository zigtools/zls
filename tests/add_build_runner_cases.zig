//! This file is imported by `../build.zig` to add build runner tests to the build system.
//! See the `./build_runner_cases` subdirectory.

const std = @import("std");

pub fn addCases(
    b: *std.Build,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
) void {
    const cases_path = "tests/build_runner_cases";

    const global_cache: std.Build.LazyPath = .{ .relative = .{ .base = .global_cache } };

    const check_exe = b.addExecutable(.{
        .name = "build_runner_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_runner_check.zig"),
            .target = b.graph.host,
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

        const build_file = b.path(cases_path).path(b, entry.name);
        const expected_build_config_json = b.path(cases_path).path(b, std.Io.Dir.path.stem(entry.name));

        const build_cmd = std.Build.Step.Run.create(b, b.fmt("run build runner ({s})", .{entry.name}));
        build_cmd.addFileArg(.zig_exe);
        build_cmd.addArg("build");
        build_cmd.addArg("--build-file");
        build_cmd.addFileArg(build_file);
        build_cmd.addArg("--build-runner");
        build_cmd.addFileArg(b.path("src/build_runner/build_runner.zig"));
        build_cmd.addArg("--cache-dir");
        build_cmd.addDirectoryArg(.cache_root);
        build_cmd.addArg("--global-cache-dir");
        build_cmd.addDirectoryArg(global_cache);
        build_cmd.addArg("--zig-lib-dir");
        build_cmd.addDirectoryArg(.zig_lib);

        build_cmd.addFileInput(b.path("src/build_runner/shared.zig"));

        const actual_build_config_json = build_cmd.captureStdOut(.{});

        const run_diff = b.addRunArtifact(check_exe);
        run_diff.setName(b.fmt("run {s} ({s})", .{ check_exe.name, entry.name }));
        run_diff.setCwd(b.path(cases_path));
        run_diff.addFileArg(expected_build_config_json);
        run_diff.addFileArg(actual_build_config_json);
        run_diff.addArg("--cache-dir");
        run_diff.addDirectoryArg(.cache_root);
        run_diff.addArg("--global-cache-dir");
        run_diff.addDirectoryArg(global_cache);

        test_step.dependOn(&run_diff.step);
    }
}
