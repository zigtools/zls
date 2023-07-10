const std = @import("std");
const builtin = @import("builtin");
const shared = @import("src/shared.zig");

const zls_version = std.SemanticVersion{ .major = 0, .minor = 11, .patch = 0 };

pub fn build(b: *std.build.Builder) !void {
    comptime {
        const current_zig = builtin.zig_version;
        const min_zig = std.SemanticVersion.parse("0.11.0-dev.3957+3bf0b8ead") catch unreachable; // explicitly specify error set of `std.json.stringify`
        if (current_zig.order(min_zig) == .lt) {
            @compileError(std.fmt.comptimePrint("Your Zig version v{} does not meet the minimum build requirement of v{}", .{ current_zig, min_zig }));
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zls",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const exe_options = b.addOptions();
    exe.addOptions("build_options", exe_options);

    const pie = b.option(bool, "pie", "Build a Position Independent Executable");
    const enable_tracy = b.option(bool, "enable_tracy", "Whether tracy should be enabled.") orelse false;
    const coverage = b.option(bool, "generate_coverage", "Generate coverage data with kcov") orelse false;
    const coverage_output_dir = b.option([]const u8, "coverage_output_dir", "Output directory for coverage data") orelse b.pathJoin(&.{ b.install_prefix, "kcov" });
    const test_filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");

    exe_options.addOption(shared.ZigVersion, "data_version", b.option(shared.ZigVersion, "data_version", "The Zig version your compiler is.") orelse .master);
    exe_options.addOption(std.log.Level, "log_level", b.option(std.log.Level, "log_level", "The Log Level to be used.") orelse .info);
    exe_options.addOption(bool, "enable_tracy", enable_tracy);
    exe_options.addOption(bool, "enable_tracy_allocation", b.option(bool, "enable_tracy_allocation", "Enable using TracyAllocator to monitor allocations.") orelse enable_tracy);
    exe_options.addOption(bool, "enable_tracy_callstack", b.option(bool, "enable_tracy_callstack", "Enable callstack graphs.") orelse enable_tracy);
    exe_options.addOption(bool, "enable_failing_allocator", b.option(bool, "enable_failing_allocator", "Whether to use a randomly failing allocator.") orelse false);
    exe_options.addOption(u32, "enable_failing_allocator_likelihood", b.option(u32, "enable_failing_allocator_likelihood", "The chance that an allocation will fail is `1/likelihood`") orelse 256);
    exe_options.addOption(bool, "use_gpa", b.option(bool, "use_gpa", "Good for debugging") orelse (optimize == .Debug));

    const version = v: {
        const version_string = b.fmt("{d}.{d}.{d}", .{ zls_version.major, zls_version.minor, zls_version.patch });
        const build_root_path = b.build_root.path orelse ".";

        var code: u8 = undefined;
        const git_describe_untrimmed = b.execAllowFail(&[_][]const u8{
            "git", "-C", build_root_path, "describe", "--match", "*.*.*", "--tags",
        }, &code, .Ignore) catch break :v version_string;

        const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

        switch (std.mem.count(u8, git_describe, "-")) {
            0 => {
                // Tagged release version (e.g. 0.10.0).
                std.debug.assert(std.mem.eql(u8, git_describe, version_string)); // tagged release must match version string
                break :v version_string;
            },
            2 => {
                // Untagged development build (e.g. 0.10.0-dev.216+34ce200).
                var it = std.mem.split(u8, git_describe, "-");
                const tagged_ancestor = it.first();
                const commit_height = it.next().?;
                const commit_id = it.next().?;

                const ancestor_ver = try std.SemanticVersion.parse(tagged_ancestor);
                std.debug.assert(zls_version.order(ancestor_ver) == .gt); // zls version must be greater than its previous version
                std.debug.assert(std.mem.startsWith(u8, commit_id, "g")); // commit hash is prefixed with a 'g'

                break :v b.fmt("{s}-dev.{s}+{s}", .{ version_string, commit_height, commit_id[1..] });
            },
            else => {
                std.debug.print("Unexpected 'git describe' output: '{s}'\n", .{git_describe});
                std.process.exit(1);
            },
        }
    };

    exe_options.addOption([]const u8, "version", version);

    const known_folders_module = b.dependency("known_folders", .{}).module("known-folders");
    exe.addModule("known-folders", known_folders_module);

    const diffz_module = b.dependency("diffz", .{}).module("diffz");
    exe.addModule("diffz", diffz_module);

    const binned_allocator_module = b.dependency("binned_allocator", .{}).module("binned_allocator");
    exe.addModule("binned_allocator", binned_allocator_module);

    if (enable_tracy) {
        const client_cpp = "src/tracy/public/TracyClient.cpp";

        // On mingw, we need to opt into windows 7+ to get some features required by tracy.
        const tracy_c_flags: []const []const u8 = if (target.isWindows() and target.getAbi() == .gnu)
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
        else
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

        exe.addIncludePath("src/tracy");
        exe.addCSourceFile(client_cpp, tracy_c_flags);
        exe.linkLibCpp();
        exe.linkLibC();

        if (target.isWindows()) {
            exe.linkSystemLibrary("dbghelp");
            exe.linkSystemLibrary("ws2_32");
        }
    }

    exe.pie = pie;
    b.installArtifact(exe);

    const build_options_module = exe_options.createModule();

    const zls_module = b.addModule("zls", .{
        .source_file = .{ .path = "src/zls.zig" },
        .dependencies = &.{
            .{ .name = "known-folders", .module = known_folders_module },
            .{ .name = "diffz", .module = diffz_module },
            .{ .name = "binned_allocator", .module = binned_allocator_module },
            .{ .name = "build_options", .module = build_options_module },
        },
    });

    const gen_exe = b.addExecutable(.{
        .name = "zls_gen",
        .root_source_file = .{ .path = "src/config_gen/config_gen.zig" },
    });

    const gen_cmd = b.addRunArtifact(gen_exe);
    gen_cmd.addArgs(&.{
        b.pathFromRoot("src/Config.zig"),
        b.pathFromRoot("schema.json"),
        b.pathFromRoot("README.md"),
        b.pathFromRoot("src/data"),
    });
    if (b.args) |args| gen_cmd.addArgs(args);

    const gen_step = b.step("gen", "Regenerate config files");
    gen_step.dependOn(&gen_cmd.step);

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(b.getInstallStep());

    var tests = b.addTest(.{
        .root_source_file = .{ .path = "tests/tests.zig" },
        .target = target,
        .optimize = .Debug,
        .filter = test_filter,
    });

    tests.addModule("zls", zls_module);
    tests.addModule("diffz", diffz_module);
    tests.addModule("binned_allocator", binned_allocator_module);
    test_step.dependOn(&b.addRunArtifact(tests).step);

    var src_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/zls.zig" },
        .target = target,
        .optimize = .Debug,
        .filter = test_filter,
    });
    test_step.dependOn(&b.addRunArtifact(src_tests).step);

    if (coverage) {
        const src_dir = b.pathFromRoot("src");
        const include_pattern = b.fmt("--include-pattern={s}", .{src_dir});
        const args = &[_]?[]const u8{ "kcov", include_pattern, coverage_output_dir, null };

        tests.setExecCmd(args);
        src_tests.setExecCmd(args);
        // TODO merge coverage reports
    }
}
