const std = @import("std");
const builtin = @import("builtin");

/// Must match the `version` in `build.zig.zon`. Add a `-dev` suffix when `zls_version_is_tagged == false`.
const zls_version = std.SemanticVersion{ .major = 0, .minor = 13, .patch = 0 };
/// set this to true when tagging a new ZLS release and then unset it on the next development cycle.
const zls_version_is_tagged: bool = false;

/// Specify the minimum Zig version that is required to compile and test ZLS:
/// ComptimeStringMap: return a regular struct and optimize
///
/// Must match the `minimum_zig_version` in `build.zig.zon`.
const minimum_zig_version = "0.13.0-dev.33+8af59d1f9";

/// Specify the minimum Zig version that is required to run ZLS:
/// Release 0.12.0
///
/// Examples of reasons that would cause the minimum runtime version to be bumped are:
///   - breaking change to the Zig Syntax
///   - breaking change to AstGen (i.e `zig ast-check`)
///   - breaking change to the build system (see `src/build_runner`)
const minimum_runtime_zig_version = "0.12.0";

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
    const data_version = b.option([]const u8, "data_version", "The Zig version your compiler is.");
    const data_version_path = b.option([]const u8, "version_data_path", "Manually specify zig language reference file");
    const override_version_data_file_path = b.option([]const u8, "version_data_file_path", "Relative path to version data file (if none, will be named with timestamp)");
    const use_llvm = b.option(bool, "use_llvm", "Use Zig's llvm code backend");

    const version_result = getVersion(b);

    const build_options = b.addOptions();
    build_options.step.name = "ZLS build options";
    const build_options_module = build_options.createModule();
    build_options.addOption([]const u8, "version_string", version_result.version_string);
    build_options.addOption(std.SemanticVersion, "version", try std.SemanticVersion.parse(version_result.version_string));
    build_options.addOption(?[]const u8, "precise_version_string", version_result.precise_version_string);
    build_options.addOption([]const u8, "minimum_runtime_zig_version_string", minimum_runtime_zig_version);

    const exe_options = b.addOptions();
    exe_options.step.name = "ZLS exe options";
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
    test_options.step.name = "ZLS test options";
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
        .root_source_file = b.path("src/config_gen/config_gen.zig"),
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
    const resolved_data_version = data_version orelse if (zls_version_is_tagged) b.fmt("{}", .{zls_version}) else "master";
    gen_version_data_cmd.addArgs(&.{ "--generate-version-data", resolved_data_version });
    if (data_version_path) |path| {
        gen_version_data_cmd.addArg("--langref_path");
        gen_version_data_cmd.addFileArg(.{ .cwd_relative = path });
    }
    const version_data_file_name = if (data_version_path != null)
        b.fmt("version_data_{s}.zig", .{resolved_data_version})
    else blk: {
        // invalidate version data periodically from cache because the website content may change
        // setting `has_side_effects` would also be possible but that would always force a re-run
        const timestamp = @divFloor(std.time.timestamp(), std.time.s_per_day);
        break :blk b.fmt("version_data_{s}_{d}.zig", .{ resolved_data_version, timestamp });
    };
    gen_version_data_cmd.addArg("--generate-version-data-path");
    const version_data_path: std.Build.LazyPath = if (override_version_data_file_path) |path|
        .{ .cwd_relative = path }
    else
        gen_version_data_cmd.addOutputFileArg(version_data_file_name);
    const version_data_module = b.addModule("version_data", .{ .root_source_file = version_data_path });

    const zls_module = b.addModule("zls", .{
        .root_source_file = b.path("src/zls.zig"),
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
    const release_compress = b.option(bool, "release-compress", "Install release binaries as compress files. Requires tar and 7z") orelse false;
    const release_minisig = b.option(bool, "release-minisig", "Sign release binaries with Minisign.") orelse false;

    if (release_minisig and !release_compress) {
        std.log.err("-Drelease-minisig can only be used along with -Drelease-compress", .{});
        return;
    }

    for (targets) |target_query| {
        const exe = b.addExecutable(.{
            .name = "zls",
            .root_source_file = b.path("src/main.zig"),
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

        if (!release_compress) {
            const target_output = b.addInstallArtifact(exe, .{
                .dest_dir = .{
                    .override = .{
                        .custom = try target_query.zigTriple(b.allocator),
                    },
                },
            });
            release_step.dependOn(&target_output.step);
            continue;
        }

        const resolved_target = exe.root_module.resolved_target.?.result;
        const is_windows = resolved_target.os.tag == .windows;
        const zig_triple = try target_query.zigTriple(b.allocator);

        const install_dir: std.Build.InstallDir = .{ .custom = "artifacts" };
        const file_name = b.fmt("{s}.{s}", .{ zig_triple, if (is_windows) "zip" else "tar.xz" });
        const exe_name = b.fmt("{s}{s}", .{ exe.name, resolved_target.exeFileExt() });

        const compress_cmd = std.Build.Step.Run.create(b, b.fmt("create {s}", .{file_name}));
        const output_path = if (is_windows) blk: {
            compress_cmd.addArgs(&.{ "7z", "a", "-mx=9" });
            const output_path = compress_cmd.addOutputFileArg(file_name);
            compress_cmd.addArtifactArg(exe);
            compress_cmd.addFileArg(exe.getEmittedPdb());
            compress_cmd.addFileArg(b.path("LICENSE"));
            compress_cmd.addFileArg(b.path("README.md"));
            break :blk output_path;
        } else blk: {
            compress_cmd.setEnvironmentVariable("XZ_OPT", "9");
            compress_cmd.addArgs(&.{ "tar", "cJf" });
            const output_path = compress_cmd.addOutputFileArg(file_name);
            compress_cmd.addArgs(&.{ "--owner=0", "--group=0" });
            compress_cmd.addArg("-C");
            compress_cmd.addDirectoryArg(exe.getEmittedBinDirectory());
            compress_cmd.addArg(exe_name);

            compress_cmd.addArg("-C");
            compress_cmd.addArg(b.pathFromRoot("."));
            compress_cmd.addArg("LICENSE");
            compress_cmd.addArg("README.md");
            break :blk output_path;
        };

        const install_tarball = b.addInstallFileWithDir(output_path, install_dir, file_name);
        release_step.dependOn(&install_tarball.step);

        if (release_minisig) {
            const minisign_basename = b.fmt("{s}.minisign", .{file_name});

            const minising_cmd = b.addSystemCommand(&.{ "minisign", "-Sm" });
            // uncomment the followng line when https://github.com/ziglang/zig/issues/18281 is fixed:
            // minising_cmd.has_side_effects = true; // the secret key file may change
            minising_cmd.addFileArg(output_path);
            minising_cmd.addArg("-x");
            const minising_file_path = minising_cmd.addOutputFileArg(minisign_basename);
            const install_minising = b.addInstallFileWithDir(minising_file_path, install_dir, minisign_basename);
            release_step.dependOn(&install_minising.step);
        }
    }

    const exe = b.addExecutable(.{
        .name = "zls",
        .root_source_file = b.path("src/main.zig"),
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
        .root_source_file = b.path("tests/tests.zig"),
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
        .root_source_file = b.path("src/zls.zig"),
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
            .source_dir = .{ .cwd_relative = b.pathJoin(&.{ coverage_output_dir, "output" }) },
            .install_dir = .{ .custom = "coverage" },
            .install_subdir = "",
        });
        install_coverage.step.dependOn(&merge_step.step);
        test_step.dependOn(&install_coverage.step);
    }
}

fn getVersion(b: *Build) struct {
    version_string: []const u8,
    precise_version_string: ?[]const u8,
} {
    const version_string = b.fmt("{d}.{d}.{d}", .{ zls_version.major, zls_version.minor, zls_version.patch });
    const build_root_path = b.build_root.path orelse ".";

    var code: u8 = undefined;
    const git_describe_untrimmed = b.runAllowFail(&[_][]const u8{
        "git", "-C", build_root_path, "describe", "--match", "*.*.*", "--tags",
    }, &code, .Ignore) catch {
        return .{
            .version_string = version_string,
            .precise_version_string = if (zls_version_is_tagged) version_string else null,
        };
    };

    const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

    switch (std.mem.count(u8, git_describe, "-")) {
        0 => {
            // Tagged release version (e.g. 0.10.0).
            std.debug.assert(std.mem.eql(u8, git_describe, version_string)); // tagged release must match version string
            std.debug.assert(zls_version_is_tagged); // `zls_version_is_tagged` disagrees with git describe
            return .{ .version_string = version_string, .precise_version_string = version_string };
        },
        2 => {
            // Untagged development build (e.g. 0.10.0-dev.216+34ce200).
            std.debug.assert(!zls_version_is_tagged); // `zls_version_is_tagged` disagrees with git describe
            var it = std.mem.splitScalar(u8, git_describe, '-');
            const tagged_ancestor = it.first();
            const commit_height = it.next().?;
            const commit_id = it.next().?;

            const ancestor_ver = std.SemanticVersion.parse(tagged_ancestor) catch unreachable;
            std.debug.assert(zls_version.order(ancestor_ver) == .gt); // ZLS version must be greater than its previous version
            std.debug.assert(std.mem.startsWith(u8, commit_id, "g")); // commit hash is prefixed with a 'g'

            const precise_version_string = b.fmt("{s}-dev.{s}+{s}", .{ version_string, commit_height, commit_id[1..] });
            return .{ .version_string = precise_version_string, .precise_version_string = precise_version_string };
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
    tracy_options.step.name = "tracy options";
    tracy_options.addOption(bool, "enable", options.enable);
    tracy_options.addOption(bool, "enable_allocation", options.enable and options.enable_allocation);
    tracy_options.addOption(bool, "enable_callstack", options.enable and options.enable_callstack);

    const tracy_module = b.addModule("tracy", .{
        .root_source_file = b.path("src/tracy.zig"),
        .target = options.target,
        .optimize = options.optimize,
    });
    tracy_module.addImport("options", tracy_options.createModule());
    if (!options.enable) return tracy_module;
    tracy_module.link_libc = true;
    tracy_module.link_libcpp = true;

    // On mingw, we need to opt into windows 7+ to get some features required by tracy.
    const tracy_c_flags: []const []const u8 = if (options.target.result.isMinGW())
        &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
    else
        &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

    tracy_module.addIncludePath(b.path("src/tracy"));
    tracy_module.addCSourceFile(.{
        .file = b.path("src/tracy/public/TracyClient.cpp"),
        .flags = tracy_c_flags,
    });

    if (options.target.result.os.tag == .windows) {
        tracy_module.linkSystemLibrary("dbghelp", .{});
        tracy_module.linkSystemLibrary("ws2_32", .{});
    }

    return tracy_module;
}

const Build = blk: {
    const min_zig = std.SemanticVersion.parse(minimum_zig_version) catch unreachable;
    const min_runtime_zig = std.SemanticVersion.parse(minimum_runtime_zig_version) catch unreachable;

    if (min_runtime_zig.order(min_zig) == .gt) {
        const message = std.fmt.comptimePrint(
            \\A Zig version that is able to build ZLS must be compatible with ZLS at runtime.
            \\
            \\This means that the minimum runtime Zig version must be less or equal to the minimum build Zig version:
            \\  minimum build   Zig version: {[min_build_zig]}
            \\  minimum runtime Zig version: {[min_runtime_zig]}
            \\
            \\This is a developer error.
        , .{ .min_build_zig = min_zig, .min_runtime_zig = min_runtime_zig });
        @compileError(message);
    }

    // check that the ZLS version and minimum build version make sense
    if (zls_version_is_tagged) {
        if (zls_version.order(min_zig) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum build requirement:
                \\          ZLS version: {[current_version]}
                \\  minimum Zig version: {[minimum_version]}
                \\
                \\This is a developer error. Set `minimum_zig_version` in `build.zig` and `minimum_zig_version` in `build.zig.zon` to {[current_version]}.
            , .{ .current_version = zls_version, .minimum_version = min_zig });
            @compileError(message);
        }
    } else {
        const min_zig_simple = std.SemanticVersion{ .major = min_zig.major, .minor = min_zig.minor, .patch = 0 };
        const zls_version_simple = std.SemanticVersion{ .major = zls_version.major, .minor = zls_version.minor, .patch = 0 };
        const min_zig_is_tagged = min_zig.build == null and min_zig.pre == null;
        if (!min_zig_is_tagged and zls_version_simple.order(min_zig_simple) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A development build of ZLS should have a tagged release of Zig as the minimum build requirement or
                \\have a development build of Zig as the minimum build requirement with the same major and minor version.
                \\          ZLS version: {d}.{d}.*
                \\  minimum Zig version: {}
                \\
                \\
                \\This is a developer error.
            , .{ zls_version.major, zls_version.minor, min_zig });
            @compileError(message);
        }
    }

    // check minimum build version
    const is_current_zig_tagged_release = builtin.zig_version.pre == null and builtin.zig_version.build == null;
    const is_min_zig_tagged_release = min_zig.pre == null and min_zig.build == null;
    const min_zig_simple = std.SemanticVersion{ .major = min_zig.major, .minor = min_zig.minor, .patch = 0 };
    const current_zig_simple = std.SemanticVersion{ .major = builtin.zig_version.major, .minor = builtin.zig_version.minor, .patch = 0 };
    if (switch (builtin.zig_version.order(min_zig)) {
        .lt => true,
        .eq => false,
        // a tagged release of ZLS must be build with a tagged release of Zig that has the same major and minor version.
        .gt => zls_version_is_tagged and (min_zig_simple.order(current_zig_simple) != .eq),
    }) {
        const message = std.fmt.comptimePrint(
            \\Your Zig version does not meet the minimum build requirement:
            \\  required Zig version: {[minimum_version]} {[required_zig_version_note]s}
            \\  actual   Zig version: {[current_version]}
            \\
            \\
        ++ if (is_min_zig_tagged_release)
            \\Please download the {[minimum_version]} release of Zig. (https://ziglang.org/download/)
            \\
            \\Tagged releases of ZLS are also available.
            \\  -> https://github.com/zigtools/zls/releases
            \\  -> https://github.com/zigtools/zls/releases/tag/{[minimum_version_simple]} (may not exist yet)
        else if (is_current_zig_tagged_release)
            \\Please download or compile a tagged release of ZLS.
            \\  -> https://github.com/zigtools/zls/releases
            \\  -> https://github.com/zigtools/zls/releases/tag/{[current_version]} (may not exist yet)
        else
            \\You can take one of the following actions to resolve this issue:
            \\  - Download the latest nightly of Zig (https://ziglang.org/download/)
            \\  - Compile an older version of ZLS that is compatible with your Zig version
        , .{
            .current_version = builtin.zig_version,
            .minimum_version = min_zig,
            .minimum_version_simple = min_zig_simple,
            .required_zig_version_note = if (!zls_version_is_tagged) "(or greater)" else "",
        });
        @compileError(message);
    }
    break :blk std.Build;
};
