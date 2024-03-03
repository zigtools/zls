const std = @import("std");
const builtin = @import("builtin");

const zls_version = std.SemanticVersion{ .major = 0, .minor = 12, .patch = 0 };
/// set this to true when tagging a new ZLS release and then unset it on the next development cycle.
const zls_version_is_tagged: bool = false;

/// document the latest breaking change that caused a change to the string below:
/// decouple Zir, AstGen -> std.zig.Zir/AstGen
const min_zig_string = "0.12.0-dev.3071+6f7354a04";

const Build = blk: {
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse(min_zig_string) catch unreachable;
    const is_current_zig_tagged_release = current_zig.pre == null and current_zig.build == null;
    if (current_zig.order(min_zig) == .lt) {
        const message = std.fmt.comptimePrint(
            \\Your Zig version does not meet the minimum build requirement:
            \\  required Zig version: {[minimum_version]} (or greater)
            \\  actual   Zig version: {[current_version]}
            \\
            \\
        ++ if (is_current_zig_tagged_release)
            \\Please download or compile a tagged release of ZLS.
            \\  -> https://github.com/zigtools/zls/releases
            \\  -> https://github.com/zigtools/zls/releases/tag/{[current_version]}
        else
            \\You can take one of the following actions to resolve this issue:
            \\  - Download the latest nightly of Zig (https://ziglang.org/download/)
            \\  - Compile an older version of ZLS that is compatible with your Zig version
        , .{ .current_version = current_zig, .minimum_version = min_zig });
        @compileError(message);
    }
    break :blk std.Build;
};

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const single_threaded = b.option(bool, "single-threaded", "Build a single threaded Executable");
    const pie = b.option(bool, "pie", "Build a Position Independent Executable");
    const enable_tracy = b.option(bool, "enable_tracy", "Whether tracy should be enabled.") orelse false;
    const enable_tracy_allocation = b.option(bool, "enable_tracy_allocation", "Enable using TracyAllocator to monitor allocations.") orelse enable_tracy;
    const enable_tracy_callstack = b.option(bool, "enable_tracy_callstack", "Enable callstack graphs.") orelse enable_tracy;
    const coverage = b.option(bool, "generate_coverage", "Generate coverage data with kcov") orelse false;
    const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match filter") orelse &[0][]const u8{};
    const data_version = b.option([]const u8, "data_version", "The Zig version your compiler is.") orelse "master";
    const data_version_path = b.option([]const u8, "version_data_path", "Manually specify zig language reference file");
    const override_version_data_file_path = b.option([]const u8, "version_data_file_path", "Relative path to version data file (if none, will be named with timestamp)");
    const use_llvm = b.option(bool, "use_llvm", "Use Zig's llvm code backend");

    const maybe_version_string = getVersion(b);
    const fallback_version_string = b.fmt("{d}.{d}.{d}", .{ zls_version.major, zls_version.minor, zls_version.patch });
    const version_string = maybe_version_string orelse fallback_version_string;
    const precise_version_string = if (zls_version_is_tagged) version_string else maybe_version_string;

    const build_options = b.addOptions();
    const build_options_module = build_options.createModule();
    build_options.addOption([]const u8, "version_string", version_string);
    build_options.addOption(std.SemanticVersion, "version", try std.SemanticVersion.parse(version_string));
    build_options.addOption(?[]const u8, "precise_version_string", precise_version_string);
    build_options.addOption([]const u8, "min_zig_string", min_zig_string);

    const exe_options = b.addOptions();
    const exe_options_module = exe_options.createModule();
    exe_options.addOption(std.log.Level, "log_level", b.option(std.log.Level, "log_level", "The Log Level to be used.") orelse .info);
    exe_options.addOption(bool, "enable_failing_allocator", b.option(bool, "enable_failing_allocator", "Whether to use a randomly failing allocator.") orelse false);
    exe_options.addOption(u32, "enable_failing_allocator_likelihood", b.option(u32, "enable_failing_allocator_likelihood", "The chance that an allocation will fail is `1/likelihood`") orelse 256);
    exe_options.addOption(bool, "use_gpa", b.option(bool, "use_gpa", "Good for debugging") orelse (optimize == .Debug));

    const global_cache_path = try b.cache_root.join(b.allocator, &.{"zls"});
    b.cache_root.handle.makePath(global_cache_path) catch |err| {
        std.debug.panic("unable to make tmp path '{s}': {}", .{ global_cache_path, err });
    };

    const test_options = b.addOptions();
    const test_options_module = test_options.createModule();
    test_options.addOption([]const u8, "zig_exe_path", b.graph.zig_exe);
    test_options.addOption([]const u8, "global_cache_path", global_cache_path);

    const known_folders_module = b.dependency("known_folders", .{}).module("known-folders");
    const diffz_module = b.dependency("diffz", .{}).module("diffz");
    const tracy_module = getTracyModule(b, .{
        .target = target,
        .optimize = optimize,
        .enable = enable_tracy,
        .enable_allocation = enable_tracy_allocation,
        .enable_callstack = enable_tracy_callstack,
    });

    const gen_exe = b.addExecutable(.{
        .name = "zls_gen",
        .root_source_file = .{ .path = "src/config_gen/config_gen.zig" },
        .target = b.host,
        .single_threaded = true,
    });

    const gen_cmd = b.addRunArtifact(gen_exe);
    gen_cmd.addArgs(&.{
        "--readme-path",
        b.pathFromRoot("README.md"),
        "--generate-config-path",
        b.pathFromRoot("src/Config.zig"),
        "--generate-schema-path",
        b.pathFromRoot("schema.json"),
    });
    if (b.args) |args| gen_cmd.addArgs(args);

    const gen_step = b.step("gen", "Regenerate config files");
    gen_step.dependOn(&gen_cmd.step);

    const gen_version_data_cmd = b.addRunArtifact(gen_exe);
    gen_version_data_cmd.addArgs(&.{ "--generate-version-data", data_version });
    if (data_version_path) |path| {
        gen_version_data_cmd.addArg("--langref_path");
        gen_version_data_cmd.addFileArg(.{ .cwd_relative = path });
    }
    const version_data_file_name = if (data_version_path != null)
        b.fmt("version_data_{s}.zig", .{data_version})
    else blk: {
        // invalidate version data periodically from cache because the website content may change
        // setting `has_side_effects` would also be possible but that would always force a re-run
        const timestamp = @divFloor(std.time.timestamp(), std.time.s_per_day);
        break :blk b.fmt("version_data_{s}_{d}.zig", .{ data_version, timestamp });
    };
    gen_version_data_cmd.addArg("--generate-version-data-path");
    const version_data_path: std.Build.LazyPath = if (override_version_data_file_path) |path|
        .{ .cwd_relative = path }
    else
        gen_version_data_cmd.addOutputFileArg(version_data_file_name);
    const version_data_module = b.addModule("version_data", .{ .root_source_file = version_data_path });

    const zls_module = b.addModule("zls", .{
        .root_source_file = .{ .path = "src/zls.zig" },
        .imports = &.{
            .{ .name = "known-folders", .module = known_folders_module },
            .{ .name = "diffz", .module = diffz_module },
            .{ .name = "tracy", .module = tracy_module },
            .{ .name = "build_options", .module = build_options_module },
            .{ .name = "version_data", .module = version_data_module },
        },
    });

    const targets: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .x86_64, .os_tag = .linux },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .x86, .os_tag = .windows },
        .{ .cpu_arch = .x86, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .wasm32, .os_tag = .wasi },
    };

    const release_step = b.step("release", "Build all release binaries");

    for (targets) |target_query| {
        const exe = b.addExecutable(.{
            .name = "zls",
            .root_source_file = .{ .path = "src/main.zig" },
            .target = b.resolveTargetQuery(target_query),
            .optimize = optimize,
            .single_threaded = single_threaded,
            .use_llvm = use_llvm,
            .use_lld = use_llvm,
        });
        exe.pie = pie;
        exe.root_module.addImport("exe_options", exe_options_module);
        exe.root_module.addImport("tracy", tracy_module);
        exe.root_module.addImport("known-folders", known_folders_module);
        exe.root_module.addImport("zls", zls_module);

        const target_output = b.addInstallArtifact(exe, .{
            .dest_dir = .{
                .override = .{
                    .custom = try target_query.zigTriple(b.allocator),
                },
            },
        });
        release_step.dependOn(&target_output.step);
    }

    const exe = b.addExecutable(.{
        .name = "zls",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });
    exe.pie = pie;
    exe.root_module.addImport("exe_options", exe_options_module);
    exe.root_module.addImport("tracy", tracy_module);
    exe.root_module.addImport("known-folders", known_folders_module);
    exe.root_module.addImport("zls", zls_module);
    b.installArtifact(exe);

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(b.getInstallStep());

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "tests/tests.zig" },
        .target = target,
        .optimize = optimize,
        .filters = test_filters,
        .single_threaded = single_threaded,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    tests.root_module.addImport("zls", zls_module);
    tests.root_module.addImport("test_options", test_options_module);
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const src_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/zls.zig" },
        .target = target,
        .optimize = optimize,
        .filters = test_filters,
        .single_threaded = single_threaded,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });
    src_tests.root_module.addImport("build_options", build_options_module);
    src_tests.root_module.addImport("test_options", test_options_module);
    test_step.dependOn(&b.addRunArtifact(src_tests).step);

    if (coverage) {
        const coverage_output_dir = b.makeTempPath();
        const include_pattern = b.fmt("--include-pattern=/src", .{});
        const exclude_pattern = b.fmt("--exclude-pattern=/src/stage2", .{});
        const args = &[_]std.Build.Step.Run.Arg{
            .{ .bytes = b.dupe("kcov") },
            .{ .bytes = b.dupe("--collect-only") },
            .{ .bytes = b.dupe(include_pattern) },
            .{ .bytes = b.dupe(exclude_pattern) },
            .{ .bytes = b.dupe(coverage_output_dir) },
        };

        const tests_run = b.addRunArtifact(tests);
        const src_tests_run = b.addRunArtifact(src_tests);
        tests_run.has_side_effects = true;
        src_tests_run.has_side_effects = true;

        tests_run.argv.insertSlice(0, args) catch @panic("OOM");
        src_tests_run.argv.insertSlice(0, args) catch @panic("OOM");

        const merge_step = std.Build.Step.Run.create(b, "merge kcov");
        merge_step.has_side_effects = true;
        merge_step.addArgs(&.{
            "kcov",
            "--merge",
            b.pathJoin(&.{ coverage_output_dir, "output" }),
            b.pathJoin(&.{ coverage_output_dir, "test" }),
        });
        merge_step.step.dependOn(&tests_run.step);
        merge_step.step.dependOn(&src_tests_run.step);

        const install_coverage = b.addInstallDirectory(.{
            .source_dir = .{ .path = b.pathJoin(&.{ coverage_output_dir, "output" }) },
            .install_dir = .{ .custom = "coverage" },
            .install_subdir = "",
        });
        install_coverage.step.dependOn(&merge_step.step);
        test_step.dependOn(&install_coverage.step);
    }
}

fn getVersion(b: *Build) ?[]const u8 {
    const version_string = b.fmt("{d}.{d}.{d}", .{ zls_version.major, zls_version.minor, zls_version.patch });
    const build_root_path = b.build_root.path orelse ".";

    var code: u8 = undefined;
    const git_describe_untrimmed = b.runAllowFail(&[_][]const u8{
        "git", "-C", build_root_path, "describe", "--match", "*.*.*", "--tags",
    }, &code, .Ignore) catch return null;

    const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

    switch (std.mem.count(u8, git_describe, "-")) {
        0 => {
            // Tagged release version (e.g. 0.10.0).
            std.debug.assert(std.mem.eql(u8, git_describe, version_string)); // tagged release must match version string
            return version_string;
        },
        2 => {
            // Untagged development build (e.g. 0.10.0-dev.216+34ce200).
            var it = std.mem.splitScalar(u8, git_describe, '-');
            const tagged_ancestor = it.first();
            const commit_height = it.next().?;
            const commit_id = it.next().?;

            const ancestor_ver = std.SemanticVersion.parse(tagged_ancestor) catch unreachable;
            std.debug.assert(zls_version.order(ancestor_ver) == .gt); // zls version must be greater than its previous version
            std.debug.assert(std.mem.startsWith(u8, commit_id, "g")); // commit hash is prefixed with a 'g'

            return b.fmt("{s}-dev.{s}+{s}", .{ version_string, commit_height, commit_id[1..] });
        },
        else => {
            std.debug.print("Unexpected 'git describe' output: '{s}'\n", .{git_describe});
            std.process.exit(1);
        },
    }
}

fn getTracyModule(
    b: *Build,
    options: struct {
        target: Build.ResolvedTarget,
        optimize: std.builtin.OptimizeMode,
        enable: bool,
        enable_allocation: bool,
        enable_callstack: bool,
    },
) *Build.Module {
    const tracy_options = b.addOptions();
    tracy_options.addOption(bool, "enable", options.enable);
    tracy_options.addOption(bool, "enable_allocation", options.enable and options.enable_allocation);
    tracy_options.addOption(bool, "enable_callstack", options.enable and options.enable_callstack);

    const tracy_module = b.addModule("tracy", .{
        .root_source_file = .{ .path = "src/tracy.zig" },
        .target = options.target,
        .optimize = options.optimize,
    });
    tracy_module.addImport("options", tracy_options.createModule());
    if (!options.enable) return tracy_module;
    tracy_module.link_libc = true;
    tracy_module.link_libcpp = true;

    const client_cpp = "src/tracy/public/TracyClient.cpp";

    // On mingw, we need to opt into windows 7+ to get some features required by tracy.
    const tracy_c_flags: []const []const u8 = if (options.target.result.isMinGW())
        &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
    else
        &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

    tracy_module.addIncludePath(.{ .path = "src/tracy" });
    tracy_module.addCSourceFile(.{
        .file = .{ .path = client_cpp },
        .flags = tracy_c_flags,
    });

    if (options.target.result.os.tag == .windows) {
        tracy_module.linkSystemLibrary("dbghelp", .{});
        tracy_module.linkSystemLibrary("ws2_32", .{});
    }

    return tracy_module;
}

comptime {
    const min_zig = std.SemanticVersion.parse(min_zig_string) catch unreachable;
    const min_zig_simple = std.SemanticVersion{ .major = min_zig.major, .minor = min_zig.minor, .patch = 0 };
    const zls_version_simple = std.SemanticVersion{ .major = zls_version.major, .minor = zls_version.minor, .patch = 0 };
    std.debug.assert(zls_version_simple.order(min_zig_simple) == .eq);
}
