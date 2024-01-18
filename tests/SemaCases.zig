const std = @import("std");

allocator: std.mem.Allocator,
file_sets: std.ArrayListUnmanaged(FileSet) = .{},

const Options = struct {
    ignore_annotation: bool,
};

const FileSet = struct {
    name: []const u8,
    files: []const []const u8,
    options: Options,
};

pub fn lowerToBuild(
    self: @This(),
    b: *std.Build,
    test_step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
) *std.Build.Step.Compile {
    const sema_test = b.addExecutable(.{
        .name = "zls_sema_test",
        .root_source_file = .{ .path = "tests/sema_tester.zig" },
        .target = target,
        .optimize = .Debug,
    });

    for (self.file_sets.items) |file_set| {
        const run_test = b.addRunArtifact(sema_test);
        test_step.dependOn(&run_test.step);
        run_test.setName(b.fmt("run sema test on {s}", .{file_set.name}));
        run_test.stdio = .zig_test;

        run_test.addArg("--zig-exe-path");
        run_test.addFileArg(.{ .path = b.zig_exe });
        if (b.zig_lib_dir) |zig_lib_dir| {
            run_test.addArg("--zig-lib-path");
            run_test.addDirectoryArg(zig_lib_dir);
        }

        if (file_set.options.ignore_annotation) {
            run_test.addArg("--fuzz");
        }
        run_test.addArg("--");

        for (file_set.files) |file_path| {
            run_test.addFileArg(.{ .path = file_path });
        }
    }

    return sema_test;
}

pub fn addCasesFromDir(
    self: *@This(),
    dir_path: []const u8,
    options: Options,
) !void {
    const dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });

    var it = try dir.walk(self.allocator);
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, std.fs.path.extension(entry.basename), ".zig")) continue;
        if (std.mem.eql(u8, entry.basename, "udivmodti4_test.zig")) continue; // exclude very large file
        if (std.mem.eql(u8, entry.basename, "udivmoddi4_test.zig")) continue; // exclude very large file
        if (std.mem.eql(u8, entry.basename, "darwin.zig")) continue; // TODO fix upstream issue with OS_SIGNPOST_ID_INVALID
        if (std.mem.eql(u8, entry.basename, "lock.zig")) continue; // TODO

        var files = std.ArrayListUnmanaged([]const u8){};

        files.append(self.allocator, try std.fs.path.join(self.allocator, &.{ dir_path, entry.path })) catch @panic("OOM");

        self.file_sets.append(self.allocator, .{
            .name = self.allocator.dupe(u8, entry.basename) catch @panic("OOM"),
            .files = files.items,
            .options = options,
        }) catch @panic("OOM");
    }
}
