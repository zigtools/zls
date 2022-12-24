const std = @import("std");
const builtin = @import("builtin");
const shared = @import("src/shared.zig");

const zls_version = std.builtin.Version{ .major = 0, .minor = 11, .patch = 0 };

pub fn build(b: *std.build.Builder) !void {
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse("0.11.0-dev.874+40ed6ae84") catch return; // Changes to builtin.Type API
    if (current_zig.order(min_zig).compare(.lt)) @panic(b.fmt("Your Zig version v{} does not meet the minimum build requirement of v{}", .{ current_zig, min_zig }));

    const target = b.standardTargetOptions(.{});

    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zls", "src/main.zig");
    const exe_options = b.addOptions();
    exe.addOptions("build_options", exe_options);

    const enable_tracy = b.option(bool, "enable_tracy", "Whether tracy should be enabled.") orelse false;
    const coverage = b.option(bool, "generate_coverage", "Generate coverage data with kcov") orelse false;
    const coverage_output_dir = b.option([]const u8, "coverage_output_dir", "Output directory for coverage data") orelse b.pathJoin(&.{ b.install_prefix, "kcov" });

    exe_options.addOption(
        shared.ZigVersion,
        "data_version",
        b.option(shared.ZigVersion, "data_version", "The Zig version your compiler is.") orelse .master,
    );

    exe_options.addOption(
        std.log.Level,
        "log_level",
        b.option(std.log.Level, "log_level", "The Log Level to be used.") orelse .info,
    );

    exe_options.addOption(
        bool,
        "enable_tracy",
        enable_tracy,
    );

    exe_options.addOption(
        bool,
        "enable_tracy_allocation",
        b.option(bool, "enable_tracy_allocation", "Enable using TracyAllocator to monitor allocations.") orelse false,
    );

    exe_options.addOption(
        bool,
        "enable_tracy_callstack",
        b.option(bool, "enable_tracy_callstack", "Enable callstack graphs.") orelse false,
    );

    const version = v: {
        const version_string = b.fmt("{d}.{d}.{d}", .{ zls_version.major, zls_version.minor, zls_version.patch });

        var code: u8 = undefined;
        const git_describe_untrimmed = b.execAllowFail(&[_][]const u8{
            "git", "-C", b.build_root, "describe", "--match", "*.*.*", "--tags",
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

                const ancestor_ver = try std.builtin.Version.parse(tagged_ancestor);
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

    exe_options.addOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const KNOWN_FOLDERS_DEFAULT_PATH = "src/known-folders/known-folders.zig";
    const known_folders_path = b.option([]const u8, "known-folders", "Path to known-folders package (default: " ++ KNOWN_FOLDERS_DEFAULT_PATH ++ ")") orelse KNOWN_FOLDERS_DEFAULT_PATH;
    exe.addPackage(.{ .name = "known-folders", .source = .{ .path = known_folders_path } });

    exe.addPackage(.{ .name = "tres", .source = .{ .path = "src/tres/tres.zig" } });

    if (enable_tracy) {
        const client_cpp = "src/tracy/TracyClient.cpp";

        // On mingw, we need to opt into windows 7+ to get some features required by tracy.
        const tracy_c_flags: []const []const u8 = if (target.isWindows() and target.getAbi() == .gnu)
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
        else
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

        exe.addIncludePath("src/tracy");
        exe.addCSourceFile(client_cpp, tracy_c_flags);
        exe.linkSystemLibraryName("c++");
        exe.linkLibC();

        if (target.isWindows()) {
            exe.linkSystemLibrary("dbghelp");
            exe.linkSystemLibrary("ws2_32");
        }
    }

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const gen_exe = b.addExecutable("zls_gen", "src/config_gen/config_gen.zig");

    const gen_cmd = gen_exe.run();
    gen_cmd.addArgs(&.{
        b.fmt("{s}/src/Config.zig", .{b.build_root}),
        b.fmt("{s}/schema.json", .{b.build_root}),
        b.fmt("{s}/README.md", .{b.build_root}),
    });

    const gen_step = b.step("gen", "Regenerate config files");
    gen_step.dependOn(&gen_cmd.step);

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(b.getInstallStep());

    var tests = b.addTest("tests/tests.zig");

    if (coverage) {
        const src_dir = b.pathJoin(&.{ b.build_root, "src" });
        const include_pattern = b.fmt("--include-pattern={s}", .{src_dir});

        tests.setExecCmd(&[_]?[]const u8{
            "kcov",
            include_pattern,
            coverage_output_dir,
            null,
        });
    }

    tests.addPackage(.{ .name = "zls", .source = .{ .path = "src/zls.zig" }, .dependencies = exe.packages.items });
    tests.setBuildMode(.Debug);
    tests.setTarget(target);
    test_step.dependOn(&tests.step);
}
