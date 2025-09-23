const std = @import("std");
const builtin = @import("builtin");

/// Must match the `version` in `build.zig.zon`.
/// Remove `.pre` when tagging a new ZLS release and add it back on the next development cycle.
const zls_version: std.SemanticVersion = .{ .major = 0, .minor = 16, .patch = 0, .pre = "dev" };

/// Specify the minimum Zig version that is required to compile and test ZLS:
/// std.Build.Step.Run: Enable passing (generated) file content as args
///
/// If you do not use Nix, a ZLS maintainer can take care of this.
/// Whenever this version is increased, run the following command:
/// ```bash
/// nix flake update --commit-lock-file
/// ```
///
/// Also update the `minimum_zig_version` in `build.zig.zon`.
const minimum_build_zig_version = "0.16.0-dev.313+be571f32c";

/// Specify the minimum Zig version that is usable with ZLS:
/// Release 0.15.1
///
/// A breaking change to the Zig Build System should be handled by updating ZLS's build runner (see src\build_runner)
const minimum_runtime_zig_version = "0.15.1";

const release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .aarch64, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .windows },
    .{ .cpu_arch = .arm, .os_tag = .linux },
    .{ .cpu_arch = .loongarch64, .os_tag = .linux },
    .{ .cpu_arch = .riscv64, .os_tag = .linux },
    .{ .cpu_arch = .x86, .os_tag = .linux },
    .{ .cpu_arch = .x86, .os_tag = .windows },
    .{ .cpu_arch = .x86_64, .os_tag = .linux },
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .x86_64, .os_tag = .windows },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

const additional_tagged_release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .powerpc64le, .os_tag = .linux },
    .{ .cpu_arch = .s390x, .os_tag = .linux },
};

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const single_threaded = b.option(bool, "single-threaded", "Build a single threaded Executable");
    const pie = b.option(bool, "pie", "Build a Position Independent Executable");
    const strip = b.option(bool, "strip", "Strip executable");
    const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match filter") orelse &.{};
    const use_llvm = b.option(bool, "use-llvm", "Use Zig's llvm code backend");
    const coverage = b.option(bool, "coverage", "Generate a coverage report with kcov") orelse false;

    const resolved_zls_version = getVersion(b);

    const build_options = blk: {
        const build_options = b.addOptions();
        build_options.step.name = "ZLS build options";

        build_options.addOption(std.SemanticVersion, "version", resolved_zls_version);
        build_options.addOption([]const u8, "version_string", b.fmt("{f}", .{resolved_zls_version}));
        build_options.addOption([]const u8, "minimum_runtime_zig_version_string", minimum_runtime_zig_version);

        break :blk build_options.createModule();
    };
    const exe_options = blk: {
        const exe_options = b.addOptions();
        exe_options.step.name = "ZLS exe options";

        exe_options.addOption(bool, "enable_failing_allocator", b.option(bool, "enable-failing-allocator", "Whether to use a randomly failing allocator.") orelse false);
        exe_options.addOption(u32, "enable_failing_allocator_likelihood", b.option(u32, "enable-failing-allocator-likelihood", "The chance that an allocation will fail is `1/likelihood`") orelse 256);
        exe_options.addOption(bool, "debug_gpa", b.option(bool, "debug-allocator", "Force the DebugAllocator to be used in all release modes") orelse false);

        break :blk exe_options.createModule();
    };
    const test_options = blk: {
        const test_options = b.addOptions();
        test_options.step.name = "ZLS test options";

        test_options.addOptionPath("zig_exe_path", .{ .cwd_relative = b.graph.zig_exe });
        test_options.addOptionPath("zig_lib_path", .{ .cwd_relative = b.fmt("{f}", .{b.graph.zig_lib_directory}) });
        test_options.addOptionPath("global_cache_path", .{ .cwd_relative = b.cache_root.join(b.allocator, &.{"zls"}) catch @panic("OOM") });

        break :blk test_options.createModule();
    };
    const tracy_options, const tracy_enable = blk: {
        const tracy_options = b.addOptions();
        tracy_options.step.name = "tracy options";

        const enable = b.option(bool, "enable-tracy", "Whether tracy should be enabled.") orelse false;
        const enable_allocation = b.option(bool, "enable-tracy-allocation", "Enable using TracyAllocator to monitor allocations.") orelse enable;
        const enable_callstack = b.option(bool, "enable-tracy-callstack", "Enable callstack graphs.") orelse enable;
        if (!enable) std.debug.assert(!enable_allocation and !enable_callstack);

        tracy_options.addOption(bool, "enable", enable);
        tracy_options.addOption(bool, "enable_allocation", enable and enable_allocation);
        tracy_options.addOption(bool, "enable_callstack", enable and enable_callstack);

        break :blk .{ tracy_options.createModule(), enable };
    };

    const gen_exe = b.addExecutable(.{
        .name = "zls_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/config_gen.zig"),
            .target = b.graph.host,
            .single_threaded = true,
        }),
    });

    const version_data_module = blk: {
        const gen_version_data_cmd = b.addRunArtifact(gen_exe);
        const version = if (zls_version.pre == null and zls_version.build == null) b.fmt("{f}", .{zls_version}) else "master";
        gen_version_data_cmd.addArgs(&.{ "--langref-version", version });

        gen_version_data_cmd.addArg("--langref-path");
        gen_version_data_cmd.addFileArg(b.path("src/tools/langref.html.in"));

        gen_version_data_cmd.addArg("--generate-version-data");
        const version_data_path = gen_version_data_cmd.addOutputFileArg("version_data.zig");

        break :blk b.createModule(.{ .root_source_file = version_data_path });
    };

    { // zig build gen
        const gen_step = b.step("gen", "Regenerate config files");

        const gen_cmd = b.addRunArtifact(gen_exe);
        if (b.args) |args| {
            gen_cmd.addArgs(args);
            gen_step.dependOn(&gen_cmd.step);
        } else {
            const update_source = b.addUpdateSourceFiles();
            gen_cmd.addArg("--generate-config");
            update_source.addCopyFileToSource(gen_cmd.addOutputFileArg("Config.zig"), "src/Config.zig");
            gen_cmd.addArg("--generate-schema");
            update_source.addCopyFileToSource(gen_cmd.addOutputFileArg("schema.json"), "schema.json");
            gen_step.dependOn(&update_source.step);
        }
    }

    { // zig build release
        const is_tagged_release = zls_version.pre == null and zls_version.build == null;
        const targets = comptime if (is_tagged_release) release_targets ++ additional_tagged_release_targets else release_targets;

        var release_artifacts: [targets.len]*Build.Step.Compile = undefined;
        for (targets, &release_artifacts) |target_query, *artifact| {
            const release_target = b.resolveTargetQuery(target_query);

            const zls_release_module = createZLSModule(b, .{
                .target = release_target,
                .optimize = optimize,
                .tracy_enable = tracy_enable,
                .tracy_options = tracy_options,
                .build_options = build_options,
                .version_data = version_data_module,
            });

            const known_folders_module = b.dependency("known_folders", .{
                .target = release_target,
                .optimize = optimize,
            }).module("known-folders");

            const exe_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = release_target,
                .optimize = optimize,
                .single_threaded = single_threaded,
                .pic = pie,
                .strip = strip,
                .imports = &.{
                    .{ .name = "exe_options", .module = exe_options },
                    .{ .name = "known-folders", .module = known_folders_module },
                    .{ .name = "tracy", .module = zls_release_module.import_table.get("tracy").? },
                    .{ .name = "zls", .module = zls_release_module },
                },
            });

            artifact.* = b.addExecutable(.{
                .name = "zls",
                .root_module = exe_module,
                .max_rss = if (optimize == .Debug and target_query.os_tag == .wasi) 2_200_000_000 else 1_800_000_000,
                .use_llvm = use_llvm,
                .use_lld = use_llvm,
            });
        }

        release(b, &release_artifacts, resolved_zls_version);
    }

    const zls_module = createZLSModule(b, .{
        .target = target,
        .optimize = optimize,
        .tracy_enable = tracy_enable,
        .tracy_options = tracy_options,
        .build_options = build_options,
        .version_data = version_data_module,
    });
    b.modules.put("zls", zls_module) catch @panic("OOM");

    const known_folders_module = b.dependency("known_folders", .{
        .target = target,
        .optimize = optimize,
    }).module("known-folders");

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
        .pic = pie,
        .strip = strip,
        .imports = &.{
            .{ .name = "exe_options", .module = exe_options },
            .{ .name = "known-folders", .module = known_folders_module },
            .{ .name = "tracy", .module = zls_module.import_table.get("tracy").? },
            .{ .name = "zls", .module = zls_module },
        },
    });

    { // zig build
        const exe = b.addExecutable(.{
            .name = "zls",
            .root_module = exe_module,
            .use_llvm = use_llvm,
            .use_lld = use_llvm,
        });
        b.installArtifact(exe);
    }

    { // zig build check
        const exe_check = b.addExecutable(.{
            .name = "zls",
            .root_module = exe_module,
        });

        const check = b.step("check", "Check if ZLS compiles");
        check.dependOn(&exe_check.step);
    }

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = single_threaded,
            .pic = pie,
            .imports = &.{
                .{ .name = "zls", .module = zls_module },
                .{ .name = "test_options", .module = test_options },
            },
        }),
        .filters = test_filters,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    const src_tests = b.addTest(.{
        .name = "src test",
        .root_module = zls_module,
        .filters = test_filters,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    if (target.result.cpu.arch.isWasm() and b.enable_wasmtime) {
        // Zig's build system integration with wasmtime does not support adding custom preopen directories so it is done manually.
        const args: []const ?[]const u8 = &.{
            "wasmtime",
            "--dir=.",
            b.fmt("--dir={f}::/lib", .{b.graph.zig_lib_directory}),
            b.fmt("--dir={s}::/cache", .{b.cache_root.join(b.allocator, &.{"zls"}) catch @panic("OOM")}),
            "--",
            null,
        };
        tests.setExecCmd(args);
        src_tests.setExecCmd(args);
    }

    blk: { // zig build test, zig build test-build-runner, zig build test-analysis
        const test_step = b.step("test", "Run all the tests");
        const test_build_runner_step = b.step("test-build-runner", "Run all the build runner tests");
        const test_analysis_step = b.step("test-analysis", "Run all the analysis tests");

        // Create run steps
        @import("tests/add_build_runner_cases.zig").addCases(b, test_build_runner_step, test_filters);
        @import("tests/add_analysis_cases.zig").addCases(b, target, optimize, test_analysis_step, test_filters);

        const run_tests = b.addRunArtifact(tests);
        const run_src_tests = b.addRunArtifact(src_tests);

        run_tests.skip_foreign_checks = target.result.cpu.arch.isWasm() and b.enable_wasmtime;
        run_src_tests.skip_foreign_checks = target.result.cpu.arch.isWasm() and b.enable_wasmtime;

        // Setup dependencies of `zig build test`
        test_step.dependOn(&run_tests.step);
        test_step.dependOn(&run_src_tests.step);
        test_step.dependOn(test_analysis_step);
        if (target.query.eql(b.graph.host.query)) test_step.dependOn(test_build_runner_step);

        if (!coverage) break :blk;

        // Collect all run steps into one ArrayList
        var run_test_steps: std.ArrayList(*std.Build.Step.Run) = .empty;
        run_test_steps.append(b.allocator, run_tests) catch @panic("OOM");
        run_test_steps.append(b.allocator, run_src_tests) catch @panic("OOM");
        for (test_build_runner_step.dependencies.items) |step| {
            run_test_steps.append(b.allocator, step.cast(std.Build.Step.Run).?) catch @panic("OOM");
        }
        for (test_analysis_step.dependencies.items) |step| {
            run_test_steps.append(b.allocator, step.cast(std.Build.Step.Run).?) catch @panic("OOM");
        }

        const kcov_bin = b.findProgram(&.{"kcov"}, &.{}) catch "kcov";

        const merge_step = std.Build.Step.Run.create(b, "merge coverage");
        merge_step.addArgs(&.{ kcov_bin, "--merge" });
        merge_step.rename_step_with_output_arg = false;
        const merged_coverage_output = merge_step.addOutputFileArg(".");

        for (run_test_steps.items) |run_step| {
            run_step.setName(b.fmt("{s} (collect coverage)", .{run_step.step.name}));

            // prepend the kcov exec args
            const argv = run_step.argv.toOwnedSlice(b.allocator) catch @panic("OOM");
            run_step.addArgs(&.{ kcov_bin, "--collect-only" });
            run_step.addPrefixedDirectoryArg("--include-pattern=", b.path("src"));
            merge_step.addDirectoryArg(run_step.addOutputFileArg(run_step.producer.?.name));
            run_step.argv.appendSlice(b.allocator, argv) catch @panic("OOM");
        }

        const install_coverage = b.addInstallDirectory(.{
            .source_dir = merged_coverage_output,
            .install_dir = .{ .custom = "coverage" },
            .install_subdir = "",
        });
        test_step.dependOn(&install_coverage.step);
    }
}

/// Returns `MAJOR.MINOR.PATCH-dev` when `git describe` failed.
fn getVersion(b: *Build) std.SemanticVersion {
    const version_string = b.option([]const u8, "version-string", "Override the version of this build. Must be a semantic version.");
    if (version_string) |semver_string| {
        return std.SemanticVersion.parse(semver_string) catch |err| {
            std.debug.panic("Expected -Dversion-string={s} to be a semantic version: {}", .{ semver_string, err });
        };
    }

    if (zls_version.pre == null and zls_version.build == null) return zls_version;

    const argv: []const []const u8 = &.{
        "git", "-C", b.pathFromRoot("."), "--git-dir", ".git", "describe", "--match", "*.*.*", "--tags",
    };
    var code: u8 = undefined;
    const git_describe_untrimmed = b.runAllowFail(argv, &code, .Ignore) catch |err| {
        const argv_joined = std.mem.join(b.allocator, " ", argv) catch @panic("OOM");
        std.log.warn(
            \\Failed to run git describe to resolve ZLS version: {}
            \\command: {s}
            \\
            \\Consider passing the -Dversion-string flag to specify the ZLS version.
        , .{ err, argv_joined });
        return zls_version;
    };

    const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

    switch (std.mem.count(u8, git_describe, "-")) {
        0 => {
            // Tagged release version (e.g. 0.10.0).
            std.debug.assert(std.mem.eql(u8, git_describe, b.fmt("{f}", .{zls_version}))); // tagged release must match version string
            return zls_version;
        },
        2 => {
            // Untagged development build (e.g. 0.10.0-dev.216+34ce200).
            var it = std.mem.splitScalar(u8, git_describe, '-');
            const tagged_ancestor = it.first();
            const commit_height = it.next().?;
            const commit_id = it.next().?;

            const ancestor_ver = std.SemanticVersion.parse(tagged_ancestor) catch unreachable;
            std.debug.assert(zls_version.order(ancestor_ver) == .gt); // ZLS version must be greater than its previous version
            std.debug.assert(std.mem.startsWith(u8, commit_id, "g")); // commit hash is prefixed with a 'g'

            return .{
                .major = zls_version.major,
                .minor = zls_version.minor,
                .patch = zls_version.patch,
                .pre = b.fmt("dev.{s}", .{commit_height}),
                .build = commit_id[1..],
            };
        },
        else => {
            std.debug.print("Unexpected 'git describe' output: '{s}'\n", .{git_describe});
            std.process.exit(1);
        },
    }
}

fn createZLSModule(
    b: *Build,
    options: struct {
        target: Build.ResolvedTarget,
        optimize: std.builtin.OptimizeMode,
        tracy_enable: bool,
        tracy_options: *std.Build.Module,
        build_options: *std.Build.Module,
        version_data: *std.Build.Module,
    },
) *std.Build.Module {
    const diffz_module = b.dependency("diffz", .{
        .target = options.target,
        .optimize = options.optimize,
    }).module("diffz");
    const lsp_module = b.dependency("lsp_kit", .{
        .target = options.target,
        .optimize = options.optimize,
    }).module("lsp");
    const tracy_module = createTracyModule(b, .{
        .target = options.target,
        .optimize = options.optimize,
        .enable = options.tracy_enable,
        .tracy_options = options.tracy_options,
    });

    const zls_module = b.createModule(.{
        .root_source_file = b.path("src/zls.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "diffz", .module = diffz_module },
            .{ .name = "lsp", .module = lsp_module },
            .{ .name = "tracy", .module = tracy_module },
            .{ .name = "build_options", .module = options.build_options },
            .{ .name = "version_data", .module = options.version_data },
        },
    });

    if (options.target.result.os.tag == .windows) {
        zls_module.linkSystemLibrary("advapi32", .{});
    }

    return zls_module;
}

fn createTracyModule(
    b: *Build,
    options: struct {
        target: Build.ResolvedTarget,
        optimize: std.builtin.OptimizeMode,
        enable: bool,
        tracy_options: *std.Build.Module,
    },
) *Build.Module {
    const tracy_module = b.createModule(.{
        .root_source_file = b.path("src/tracy.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "options", .module = options.tracy_options },
        },
        .link_libc = options.enable,
        .link_libcpp = options.enable,
        .sanitize_c = .off,
    });
    if (!options.enable) return tracy_module;

    const tracy_dependency = b.lazyDependency("tracy", .{
        .target = options.target,
        .optimize = options.optimize,
    }) orelse return tracy_module;

    tracy_module.addCMacro("TRACY_ENABLE", "1");
    tracy_module.addIncludePath(tracy_dependency.path(""));
    tracy_module.addCSourceFile(.{
        .file = tracy_dependency.path("public/TracyClient.cpp"),
    });

    if (options.target.result.os.tag == .windows) {
        tracy_module.linkSystemLibrary("dbghelp", .{});
        tracy_module.linkSystemLibrary("ws2_32", .{});
    }

    return tracy_module;
}

/// - compile amdZLS binaries with different targets
/// - compress them (.tar.xz or .zip)
/// - optionally sign them with minisign (https://github.com/jedisct1/minisign)
/// - install artifacts and a `release.json` metadata file to `./zig-out`
fn release(b: *Build, release_artifacts: []const *Build.Step.Compile, released_zls_version: std.SemanticVersion) void {
    std.debug.assert(release_artifacts.len > 0);

    const release_step = b.step("release", "Build all release artifacts. (requires tar and 7z)");
    const release_minisign = b.option(bool, "release-minisign", "Sign release artifacts with Minisign") orelse false;

    if (released_zls_version.pre != null and released_zls_version.build == null) {
        release_step.addError("Cannot build release because the ZLS version could not be resolved", .{}) catch @panic("OOM");
        return;
    }

    const FileExtension = enum {
        zip,
        @"tar.xz",
        @"tar.gz",
    };

    var compressed_artifacts: std.StringArrayHashMapUnmanaged(std.Build.LazyPath) = .empty;

    for (release_artifacts) |exe| {
        const resolved_target = exe.root_module.resolved_target.?.result;
        const is_windows = resolved_target.os.tag == .windows;
        const exe_name = b.fmt("{s}{s}", .{ exe.name, resolved_target.exeFileExt() });

        const extensions: []const FileExtension = if (is_windows) &.{.zip} else &.{ .@"tar.xz", .@"tar.gz" };

        for (extensions) |extension| {
            const file_name = b.fmt("zls-{t}-{t}-{f}.{t}", .{
                resolved_target.cpu.arch,
                resolved_target.os.tag,
                released_zls_version,
                extension,
            });

            const compress_cmd = std.Build.Step.Run.create(b, "compress artifact");
            compress_cmd.clearEnvironment();
            compress_cmd.step.max_rss = switch (extension) {
                .zip => 160 * 1024 * 1024, // 160 MiB
                .@"tar.xz" => 768 * 1024 * 1024, // 512 MiB
                .@"tar.gz" => 16 * 1024 * 1024, // 12 MiB
            };
            switch (extension) {
                .zip => {
                    compress_cmd.addArgs(&.{ "7z", "a", "-mx=9" });
                    compressed_artifacts.putNoClobber(b.allocator, file_name, compress_cmd.addOutputFileArg(file_name)) catch @panic("OOM");
                    compress_cmd.addArtifactArg(exe);
                    compress_cmd.addFileArg(exe.getEmittedPdb());
                    compress_cmd.addFileArg(b.path("LICENSE"));
                    compress_cmd.addFileArg(b.path("README.md"));
                },
                .@"tar.xz",
                .@"tar.gz",
                => {
                    compress_cmd.setEnvironmentVariable("XZ_OPT", "-9");
                    compress_cmd.addArgs(&.{ "tar", "caf" });
                    compressed_artifacts.putNoClobber(b.allocator, file_name, compress_cmd.addOutputFileArg(file_name)) catch @panic("OOM");
                    compress_cmd.addPrefixedDirectoryArg("-C", exe.getEmittedBinDirectory());
                    compress_cmd.addArg(exe_name);

                    compress_cmd.addPrefixedDirectoryArg("-C", b.path("."));
                    compress_cmd.addArg("LICENSE");
                    compress_cmd.addArg("README.md");

                    compress_cmd.addArgs(&.{
                        "--sort=name",
                        "--numeric-owner",
                        "--owner=0",
                        "--group=0",
                        "--mtime=1970-01-01",
                    });
                },
            }
        }
    }

    for (compressed_artifacts.keys(), compressed_artifacts.values()) |file_name, file_path| {
        const install_dir: std.Build.InstallDir = .{ .custom = "artifacts" };

        const install_tarball = b.addInstallFileWithDir(file_path, install_dir, file_name);
        release_step.dependOn(&install_tarball.step);

        if (release_minisign) {
            const minisign_basename = b.fmt("{s}.minisig", .{file_name});

            const minising_cmd = b.addSystemCommand(&.{ "minisign", "-Sm" });
            minising_cmd.clearEnvironment();
            minising_cmd.addFileArg(file_path);
            minising_cmd.addPrefixedFileArg("-s", .{ .cwd_relative = "minisign.key" });
            const minising_file_path = minising_cmd.addPrefixedOutputFileArg("-x", minisign_basename);

            const install_minising = b.addInstallFileWithDir(minising_file_path, install_dir, minisign_basename);
            release_step.dependOn(&install_minising.step);
        }
    }

    const source = b.fmt(
        \\{{
        \\  "zlsVersion": "{[zls_version]f}",
        \\  "zigVersion": "{[zig_version]f}",
        \\  "minimumBuildZigVersion": "{[minimum_build_zig_version]s}",
        \\  "minimumRuntimeZigVersion": "{[minimum_runtime_zig_version]s}",
        \\  "files": {[files]f}
        \\}}
        \\
    , .{
        .zls_version = released_zls_version,
        .zig_version = builtin.zig_version,
        .minimum_build_zig_version = minimum_build_zig_version,
        .minimum_runtime_zig_version = minimum_runtime_zig_version,
        .files = std.json.fmt(compressed_artifacts.keys(), .{}),
    });

    const write_files = b.addWriteFiles();
    const install_metadata = b.addInstallFile(write_files.add("release.json", source), "release.json");
    release_step.dependOn(&install_metadata.step);
}

const Build = blk: {
    @setEvalBranchQuota(10_000);

    const min_build_zig = std.SemanticVersion.parse(minimum_build_zig_version) catch unreachable;
    const min_runtime_zig = std.SemanticVersion.parse(minimum_runtime_zig_version) catch unreachable;

    const min_build_zig_is_tagged = min_build_zig.build == null and min_build_zig.pre == null;
    const min_runtime_is_tagged = min_build_zig.build == null and min_build_zig.pre == null;

    const min_build_zig_simple: std.SemanticVersion = .{ .major = min_build_zig.major, .minor = min_build_zig.minor, .patch = 0 };
    const min_runtime_zig_simple: std.SemanticVersion = .{ .major = min_runtime_zig.major, .minor = min_runtime_zig.minor, .patch = 0 };

    std.debug.assert(zls_version.pre == null or std.mem.eql(u8, zls_version.pre.?, "dev"));
    std.debug.assert(zls_version.build == null);
    const zls_version_is_tagged = zls_version.pre == null and zls_version.build == null;
    const zls_version_simple: std.SemanticVersion = .{ .major = zls_version.major, .minor = zls_version.minor, .patch = 0 };
    const zls_version_simple_str = std.fmt.comptimePrint("{d}.{d}.0", .{ zls_version.major, zls_version.minor });

    if (min_runtime_zig.order(min_build_zig) == .gt) {
        const message = std.fmt.comptimePrint(
            \\A Zig version that is able to build ZLS must be compatible with ZLS at runtime.
            \\
            \\This means that the minimum runtime Zig version must be less or equal to the minimum build Zig version:
            \\  minimum build   Zig version: {[min_build_zig]s}
            \\  minimum runtime Zig version: {[min_runtime_zig]s}
            \\
            \\This is a developer error.
        , .{ .min_build_zig = minimum_build_zig_version, .min_runtime_zig = minimum_runtime_zig_version });
        @compileError(message);
    }

    // check that the ZLS version and minimum build version make sense
    if (zls_version_is_tagged) {
        // A different patch version is allowed (e.g ZLS 0.15.0 can require Zig 0.15.1)

        if (!min_build_zig_is_tagged or zls_version_simple.order(min_build_zig_simple) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum build requirement:
                \\          ZLS version: {[current_version]s}
                \\  minimum Zig version: {[minimum_version]s}
                \\
                \\This is a developer error. Set `minimum_build_zig_version` in `build.zig` and `minimum_zig_version` in `build.zig.zon` to {[current_version]s}.
            , .{ .current_version = zls_version_simple_str, .minimum_version = minimum_build_zig_version });
            @compileError(message);
        }
        if (!min_runtime_is_tagged or zls_version_simple.order(min_runtime_zig_simple) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum runtime version:
                \\          ZLS version: {[current_version]s}
                \\  minimum Zig version: {[minimum_version]s}
                \\
                \\This is a developer error. Set `minimum_runtime_zig_version` in `build.zig` to `{[current_version]s}`.
            , .{ .current_version = zls_version_simple_str, .minimum_version = minimum_runtime_zig_version });
            @compileError(message);
        }
    } else {
        if (!min_build_zig_is_tagged and zls_version_simple.order(min_build_zig_simple) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A development build of ZLS should have a tagged release of Zig as the minimum build requirement or
                \\have a development build of Zig as the minimum build requirement with the same major and minor version.
                \\          ZLS version: {d}.{d}.*
                \\  minimum Zig version: {s}
                \\
                \\
                \\This is a developer error.
            , .{ zls_version.major, zls_version.minor, minimum_build_zig_version });
            @compileError(message);
        }
    }

    // check minimum build version
    const is_current_zig_tagged_release = builtin.zig_version.pre == null and builtin.zig_version.build == null;
    const is_min_build_zig_tagged_release = min_build_zig.pre == null and min_build_zig.build == null;
    const current_zig_simple: std.SemanticVersion = .{ .major = builtin.zig_version.major, .minor = builtin.zig_version.minor, .patch = 0 };
    if (switch (builtin.zig_version.order(min_build_zig)) {
        .lt => true,
        .eq => false,
        .gt => (is_current_zig_tagged_release and !is_min_build_zig_tagged_release) or
            // a tagged release of ZLS must be build with a tagged release of Zig that has the same major and minor version.
            (zls_version_is_tagged and (min_build_zig_simple.order(current_zig_simple) != .eq)),
    }) {
        const message = std.fmt.comptimePrint(
            \\Your Zig version does not meet the minimum build requirement:
            \\  required Zig version: {[minimum_version]s} {[required_zig_version_note]s}
            \\  actual   Zig version: {[current_version]s}
            \\
            \\
        ++ if (is_min_build_zig_tagged_release)
            std.fmt.comptimePrint(
                \\Please download the {[minimum_version]s} release of Zig. (https://ziglang.org/download/)
                \\
                \\Tagged releases of ZLS are also available.
                \\  -> https://github.com/zigtools/zls/releases
                \\  -> https://github.com/zigtools/zls/releases/tag/{[minimum_version_simple]} (may not exist yet)
            , .{
                .minimum_version = minimum_build_zig_version,
                .minimum_version_simple = min_build_zig_simple,
            })
        else if (is_current_zig_tagged_release)
            \\Please download or compile a tagged release of ZLS.
            \\  -> https://github.com/zigtools/zls/releases
            \\  -> https://github.com/zigtools/zls/releases/tag/{[current_version]s} (may not exist yet)
        else
            \\You can take one of the following actions to resolve this issue:
            \\  - Download the latest nightly of Zig (https://ziglang.org/download/)
            \\  - Compile an older version of ZLS that is compatible with your Zig version
        , .{
            .current_version = builtin.zig_version_string,
            .minimum_version = minimum_build_zig_version,
            .required_zig_version_note = if (!zls_version_is_tagged) "(or greater)" else "",
        });
        @compileError(message);
    }
    break :blk std.Build;
};
