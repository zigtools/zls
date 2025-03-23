const std = @import("std");

pub fn addCases(
    b: *std.Build,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
    build_runner: std.Build.LazyPath,
) void {
    const cases_dir = b.path("tests/build_runner_cases");
    const cases_path_from_root = b.pathFromRoot("tests/build_runner_cases");

    const check_exe = b.addExecutable(.{
        .name = "build_runner_check",
        .root_source_file = b.path("tests/build_runner_check.zig"),
        .target = b.graph.host,
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

        const build_file = cases_dir.path(b, entry.name);
        const build_config_json_path = b.fmt("{s}/{s}.json", .{ cases_path_from_root, std.fs.path.stem(entry.name) });
        const expected_build_config_json = cases_dir.path(b, build_config_json_path);

        const build_cmd = std.Build.Step.Run.create(b, b.fmt("run build runner ({s})", .{entry.name}));
        build_cmd.addFileArg(.{ .cwd_relative = b.graph.zig_exe });
        build_cmd.addArg("build");
        build_cmd.addArg("--build-file");
        build_cmd.addFileArg(build_file);
        build_cmd.addArg("--build-runner");
        build_cmd.addFileArg(build_runner);
        build_cmd.addArg("--cache-dir");
        build_cmd.addDirectoryArg(.{ .cwd_relative = b.fmt("{}", .{b.cache_root}) });
        build_cmd.addArg("--global-cache-dir");
        build_cmd.addDirectoryArg(.{ .cwd_relative = b.fmt("{}", .{b.graph.global_cache_root}) });

        const actual_build_config_json = build_cmd.captureStdOut();

        const run_diff = b.addRunArtifact(check_exe);
        run_diff.setName(b.fmt("run {s} ({s})", .{ check_exe.name, entry.name }));
        run_diff.addFileArg(expected_build_config_json);
        run_diff.addFileArg(actual_build_config_json);
        run_diff.addDirectoryArg(cases_dir);

        test_step.dependOn(&run_diff.step);
    }
}
