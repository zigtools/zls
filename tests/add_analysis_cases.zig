const std = @import("std");

pub fn addCases(
    b: *std.Build,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
) void {
    const cases_dir = b.path("tests/analysis");
    const cases_path_from_root = b.pathFromRoot("tests/analysis");

    const check_exe = b.addExecutable(.{
        .name = "analysis_check",
        .root_source_file = b.path("tests/analysis_check.zig"),
        .target = b.graph.host,
    });
    check_exe.root_module.addImport("zls", b.modules.get("zls").?);

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
        run_check.addArtifactArg(check_exe);
        run_check.addArg("--zig-exe-path");
        run_check.addFileArg(.{ .cwd_relative = b.graph.zig_exe });
        run_check.addArg("--zig-lib-path");
        run_check.addDirectoryArg(.{ .cwd_relative = b.fmt("{}", .{b.graph.zig_lib_directory}) });
        run_check.addFileArg(cases_dir.path(b, entry.name));

        test_step.dependOn(&run_check.step);
    }
}
