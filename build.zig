const std = @import("std");
const builtin = @import("builtin");

/// Must match the `version` in `build.zig.zon`.
/// Remove `.pre` when tagging a new ZLS release and add it back on the next development cycle.
const zls_version: std.SemanticVersion = .{ .major = 0, .minor = 14, .patch = 0, .pre = "dev" };

/// Specify the minimum Zig version that is required to compile and test ZLS:
/// std.builtin.Type renames, and make it easier to modify std.builtin
///
/// If you do not use Nix, a ZLS maintainer can take care of this.
/// Whenever this version is increased, run the following command:
/// ```bash
/// nix flake update --commit-lock-file
/// ```
///
/// Also update the `minimum_zig_version` in `build.zig.zon`.
const minimum_build_zig_version = "0.14.0-dev.3046+08d661fcf";

/// Specify the minimum Zig version that is required to run ZLS:
/// std.Build: add new functions to create artifacts/Step.Compile from existing module
///
/// Examples of reasons that would cause the minimum runtime version to be bumped are:
///   - breaking change to the Zig Syntax
///   - breaking change to AstGen (i.e `zig ast-check`)
///
/// A breaking change to the Zig Build System should be handled by updating ZLS's build runner (see src\build_runner)
const minimum_runtime_zig_version = "0.14.0-dev.3046+08d661fcf";

const release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .windows },
    .{ .cpu_arch = .x86_64, .os_tag = .linux },
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .x86, .os_tag = .windows },
    .{ .cpu_arch = .x86, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .windows },
    .{ .cpu_arch = .aarch64, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .arm, .os_tag = .linux },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const single_threaded = b.option(bool, "single-threaded", "Build a single threaded Executable");
    const pie = b.option(bool, "pie", "Build a Position Independent Executable");
    const enable_tracy = b.option(bool, "enable-tracy", "Whether tracy should be enabled.") orelse false;
    const enable_tracy_allocation = b.option(bool, "enable-tracy-allocation", "Enable using TracyAllocator to monitor allocations.") orelse enable_tracy;
    const enable_tracy_callstack = b.option(bool, "enable-tracy-callstack", "Enable callstack graphs.") orelse enable_tracy;
    const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match filter") orelse &.{};
    const use_llvm = b.option(bool, "use-llvm", "Use Zig's llvm code backend");

    const resolved_zls_version = getVersion(b);
    const resolved_zls_version_string = b.fmt("{}", .{resolved_zls_version});

    const build_options = blk: {
        const build_options = b.addOptions();
        build_options.step.name = "ZLS build options";

        build_options.addOption(std.SemanticVersion, "version", resolved_zls_version);
        build_options.addOption([]const u8, "version_string", resolved_zls_version_string);
        build_options.addOption([]const u8, "minimum_runtime_zig_version_string", minimum_runtime_zig_version);

        break :blk build_options.createModule();
    };
    const exe_options = blk: {
        const exe_options = b.addOptions();
        exe_options.step.name = "ZLS exe options";

        exe_options.addOption(bool, "enable_failing_allocator", b.option(bool, "enable-failing-allocator", "Whether to use a randomly failing allocator.") orelse false);
        exe_options.addOption(u32, "enable_failing_allocator_likelihood", b.option(u32, "enable-failing-allocator-likelihood", "The chance that an allocation will fail is `1/likelihood`") orelse 256);
        exe_options.addOption(bool, "use_gpa", b.option(bool, "use-gpa", "Good for debugging") orelse (optimize == .Debug));

        break :blk exe_options.createModule();
    };
    const test_options = blk: {
        const test_options = b.addOptions();
        test_options.step.name = "ZLS test options";

        test_options.addOptionPath("zig_exe_path", .{ .cwd_relative = b.graph.zig_exe });
        // TODO these paths may be relative
        test_options.addOptionPath("zig_lib_path", .{ .cwd_relative = b.fmt("{}", .{b.graph.zig_lib_directory}) });
        test_options.addOptionPath("global_cache_path", .{ .cwd_relative = b.cache_root.join(b.allocator, &.{"zls"}) catch @panic("OOM") });

        break :blk test_options.createModule();
    };

    const known_folders_module = b.dependency("known_folders", .{}).module("known-folders");
    const diffz_module = b.dependency("diffz", .{}).module("diffz");
    const lsp_module = b.dependency("lsp-codegen", .{}).module("lsp");

    const tracy_module = getTracyModule(b, .{
        .target = target,
        .optimize = optimize,
        .enable = enable_tracy,
        .enable_allocation = enable_tracy_allocation,
        .enable_callstack = enable_tracy_callstack,
    });

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
        const version = if (zls_version.pre == null and zls_version.build == null) b.fmt("{}", .{zls_version}) else "master";
        gen_version_data_cmd.addArgs(&.{ "--langref-version", version });

        gen_version_data_cmd.addArg("--langref-path");
        gen_version_data_cmd.addFileArg(b.path(b.fmt("src/tools/langref_{s}.html.in", .{version})));

        gen_version_data_cmd.addArg("--generate-version-data");
        const version_data_path = gen_version_data_cmd.addOutputFileArg("version_data.zig");

        break :blk b.addModule("version_data", .{ .root_source_file = version_data_path });
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

    const zls_module = b.addModule("zls", .{
        .root_source_file = b.path("src/zls.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
        .pic = pie,
        .imports = &.{
            .{ .name = "known-folders", .module = known_folders_module },
            .{ .name = "diffz", .module = diffz_module },
            .{ .name = "lsp", .module = lsp_module },
            .{ .name = "tracy", .module = tracy_module },
            .{ .name = "build_options", .module = build_options },
            .{ .name = "version_data", .module = version_data_module },
        },
    });

    { // zig build release
        var release_artifacts: [release_targets.len]*Build.Step.Compile = undefined;

        for (release_targets, &release_artifacts) |target_query, *artifact| {
            artifact.* = b.addExecutable(.{
                .name = "zls",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/main.zig"),
                    .target = b.resolveTargetQuery(target_query),
                    .optimize = optimize,
                    .single_threaded = single_threaded,
                    .pic = pie,
                    .imports = &.{
                        .{ .name = "exe_options", .module = exe_options },
                        .{ .name = "known-folders", .module = known_folders_module },
                        .{ .name = "tracy", .module = tracy_module },
                        .{ .name = "zls", .module = zls_module },
                    },
                }),
                .version = resolved_zls_version,
                .max_rss = if (optimize == .Debug and target_query.os_tag == .wasi) 2_200_000_000 else 1_600_000_000,
                .use_llvm = use_llvm,
                .use_lld = use_llvm,
            });
        }

        release(b, &release_targets, &release_artifacts);
    }

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
        .pic = pie,
        .imports = &.{
            .{ .name = "exe_options", .module = exe_options },
            .{ .name = "known-folders", .module = known_folders_module },
            .{ .name = "tracy", .module = tracy_module },
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

    { // zig build test
        const test_step = b.step("test", "Run all the tests");

        const test_build_runner_step = b.step("test-build-runner", "Run all the build runner tests");
        @import("tests/add_build_runner_cases.zig").addCases(b, test_build_runner_step, test_filters);

        test_step.dependOn(test_build_runner_step);
        test_step.dependOn(&b.addRunArtifact(tests).step);
        test_step.dependOn(&b.addRunArtifact(src_tests).step);
    }

    { // zig build coverage
        const kcov_bin = b.findProgram(&.{"kcov"}, &.{}) catch "kcov";

        const merge_step = std.Build.Step.Run.create(b, "merge coverage");
        merge_step.addArgs(&.{ kcov_bin, "--merge" });
        merge_step.rename_step_with_output_arg = false;
        const merged_coverage_output = merge_step.addOutputFileArg(".");

        for ([_]*std.Build.Step.Compile{ tests, src_tests }) |test_exe| {
            const kcov_collect = std.Build.Step.Run.create(b, "collect coverage");
            kcov_collect.addArgs(&.{ kcov_bin, "--collect-only" });
            kcov_collect.addPrefixedDirectoryArg("--include-pattern=", b.path("src"));
            merge_step.addDirectoryArg(kcov_collect.addOutputFileArg(test_exe.name));
            kcov_collect.addArtifactArg(test_exe);
            kcov_collect.enableTestRunnerMode();
        }

        const install_coverage = b.addInstallDirectory(.{
            .source_dir = merged_coverage_output,
            .install_dir = .{ .custom = "coverage" },
            .install_subdir = "",
        });
        const coverage_step = b.step("coverage", "Generate a coverage report with kcov");
        coverage_step.dependOn(&install_coverage.step);
    }
}

/// Returns `MAJOR.MINOR.PATCH-dev` when `git describe` failed.
fn getVersion(b: *Build) std.SemanticVersion {
    if (zls_version.pre == null and zls_version.build == null) return zls_version;

    const argv: []const []const u8 = &.{
        "git", "-C", b.pathFromRoot("."), "describe", "--match", "*.*.*", "--tags",
    };
    var code: u8 = undefined;
    const git_describe_untrimmed = b.runAllowFail(argv, &code, .Ignore) catch |err| {
        const argv_joined = std.mem.join(b.allocator, " ", argv) catch @panic("OOM");
        std.log.warn("Failed to run git describe to resolve ZLS version: {}\ncommand: {s}", .{
            err, argv_joined,
        });
        return zls_version;
    };

    const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

    switch (std.mem.count(u8, git_describe, "-")) {
        0 => {
            // Tagged release version (e.g. 0.10.0).
            std.debug.assert(std.mem.eql(u8, git_describe, b.fmt("{}", .{zls_version}))); // tagged release must match version string
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
        .imports = &.{
            .{ .name = "options", .module = tracy_options.createModule() },
        },
        .link_libc = options.enable,
        .link_libcpp = options.enable,
    });
    if (!options.enable) return tracy_module;
    const tracy_dependency = b.lazyDependency("tracy", .{}) orelse return tracy_module;

    // On mingw, we need to opt into windows 7+ to get some features required by tracy.
    const tracy_c_flags: []const []const u8 = if (options.target.result.isMinGW())
        &.{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
    else
        &.{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

    tracy_module.addIncludePath(tracy_dependency.path(""));
    tracy_module.addCSourceFile(.{
        .file = tracy_dependency.path("public/TracyClient.cpp"),
        .flags = tracy_c_flags,
    });

    if (options.target.result.os.tag == .windows) {
        tracy_module.linkSystemLibrary("dbghelp", .{});
        tracy_module.linkSystemLibrary("ws2_32", .{});
    }

    return tracy_module;
}

/// - compile ZLS binaries with different targets
/// - compress them (.tar.xz or .zip)
/// - optionally sign them with minisign (https://github.com/jedisct1/minisign)
/// - send a http `multipart/form-data` request to a Cloudflare worker at https://github.com/zigtools/release-worker
fn release(b: *Build, target_queries: []const std.Target.Query, release_artifacts: []const *Build.Step.Compile) void {
    std.debug.assert(release_artifacts.len > 0);
    for (release_artifacts) |compile| std.debug.assert(compile.version != null);

    const publish_step = b.step("publish", "Publish release artifacts to releases.zigtools.org");
    const release_step = b.step("release", "Build all release artifacts. (requires tar and 7z)");
    const release_minisign = b.option(bool, "release-minisign", "Sign release artifacts with Minisign") orelse false;

    const FileExtension = enum {
        zip,
        @"tar.xz",
        @"tar.gz",
    };

    const uri: std.Uri = if (b.graph.env_map.get("ZLS_WORKER_ENDPOINT")) |endpoint| blk: {
        var uri = std.Uri.parse(endpoint) catch std.debug.panic("invalid URI: '{s}'", .{endpoint});
        if (!uri.path.isEmpty()) std.debug.panic("ZLS_WORKER_ENDPOINT URI must have no path component: '{s}'", .{endpoint});
        uri.path = .{ .raw = "/v1/zls/publish" };
        break :blk uri;
    } else .{
        .scheme = "https",
        .host = .{ .raw = "releases.zigtools.org" },
        .path = .{ .raw = "/v1/zls/publish" },
    };

    const password = b.graph.env_map.get("ZLS_WORKER_API_TOKEN") orelse "amogus";

    const publish_exe = b.addExecutable(.{
        .name = "publish",
        .target = b.graph.host,
        .root_source_file = b.path("src/tools/publish_http_form.zig"),
    });

    // var publish_artifacts = b.addSystemCommand("curl")
    var publish_artifacts = b.addRunArtifact(publish_exe);
    publish_step.dependOn(&publish_artifacts.step);

    publish_artifacts.addArgs(&.{
        b.fmt("{}", .{uri}),
        "--user",
        b.fmt("admin:{s}", .{password}),
    });
    // It is possible for the version to be something like `0.12.0-dev` when `git describe` failed.
    // Ideally we would want to report a failure about this when running one of the release/publish steps.
    // The problem is during the configure phase, it is not possible to know which top level steps gets run.
    // So instead we use rely on the release-worker to reject this version string during the make phase.
    // One possible alternative would be to use a configuration option (i.e. -Dpublish) to conditionally run an assertion.
    publish_artifacts.addArgs(&.{
        "--form", b.fmt("zls-version={}", .{release_artifacts[0].version.?}),
        "--form", "compatibility=full",
        "--form", b.fmt("zig-version={s}", .{builtin.zig_version_string}),
        "--form", b.fmt("minimum-build-zig-version={s}", .{minimum_build_zig_version}),
        "--form", b.fmt("minimum-runtime-zig-version={s}", .{minimum_runtime_zig_version}),
    });

    var compressed_artifacts: std.StringArrayHashMapUnmanaged(std.Build.LazyPath) = .empty;

    for (target_queries, release_artifacts) |target_query, exe| {
        const resolved_target = exe.root_module.resolved_target.?.result;
        const is_windows = resolved_target.os.tag == .windows;
        const exe_name = b.fmt("{s}{s}", .{ exe.name, resolved_target.exeFileExt() });

        const extensions: []const FileExtension = if (is_windows) &.{.zip} else &.{ .@"tar.xz", .@"tar.gz" };

        for (extensions) |extension| {
            const file_name = b.fmt("zls-{s}-{s}-{}.{s}", .{
                @tagName(target_query.os_tag.?),
                @tagName(target_query.cpu_arch.?),
                exe.version.?,
                @tagName(extension),
            });

            const compress_cmd = std.Build.Step.Run.create(b, "compress artifact");
            compress_cmd.step.max_rss = switch (extension) {
                .zip => 160 * 1024 * 1024, // 160 MiB
                .@"tar.xz" => 256 * 1024 * 1024, // 256 MiB
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
        publish_artifacts.addArg("--form");
        publish_artifacts.addPrefixedFileArg(b.fmt("{s}=@", .{file_name}), file_path);

        if (release_minisign) {
            const minisign_basename = b.fmt("{s}.minisig", .{file_name});

            const minising_cmd = b.addSystemCommand(&.{ "minisign", "-Sm" });
            minising_cmd.addFileArg(file_path);
            minising_cmd.addPrefixedFileArg("-s", .{ .cwd_relative = "minisign.key" });
            const minising_file_path = minising_cmd.addPrefixedOutputFileArg("-x", minisign_basename);

            const install_minising = b.addInstallFileWithDir(minising_file_path, install_dir, minisign_basename);
            release_step.dependOn(&install_minising.step);

            publish_artifacts.addArg("--form");
            publish_artifacts.addPrefixedFileArg(b.fmt("{s}=@", .{minisign_basename}), minising_file_path);
        }
    }
}

const Build = blk: {
    @setEvalBranchQuota(10_000);

    const min_build_zig = std.SemanticVersion.parse(minimum_build_zig_version) catch unreachable;
    const min_runtime_zig = std.SemanticVersion.parse(minimum_runtime_zig_version) catch unreachable;

    std.debug.assert(zls_version.pre == null or std.mem.eql(u8, zls_version.pre.?, "dev"));
    std.debug.assert(zls_version.build == null);
    const zls_version_is_tagged = zls_version.pre == null and zls_version.build == null;
    const zls_version_simple: std.SemanticVersion = .{ .major = zls_version.major, .minor = zls_version.minor, .patch = 0 };

    if (min_runtime_zig.order(min_build_zig) == .gt) {
        const message = std.fmt.comptimePrint(
            \\A Zig version that is able to build ZLS must be compatible with ZLS at runtime.
            \\
            \\This means that the minimum runtime Zig version must be less or equal to the minimum build Zig version:
            \\  minimum build   Zig version: {[min_build_zig]}
            \\  minimum runtime Zig version: {[min_runtime_zig]}
            \\
            \\This is a developer error.
        , .{ .min_build_zig = min_build_zig, .min_runtime_zig = min_runtime_zig });
        @compileError(message);
    }

    // check that the ZLS version and minimum build version make sense
    if (zls_version_is_tagged) {
        if (zls_version_simple.order(min_build_zig) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum build requirement:
                \\          ZLS version: {[current_version]}
                \\  minimum Zig version: {[minimum_version]}
                \\
                \\This is a developer error. Set `minimum_build_zig_version` in `build.zig` and `minimum_zig_version` in `build.zig.zon` to {[current_version]}.
            , .{ .current_version = zls_version_simple, .minimum_version = min_build_zig });
            @compileError(message);
        }
        if (zls_version_simple.order(min_runtime_zig) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum runtime version:
                \\          ZLS version: {[current_version]}
                \\  minimum Zig version: {[minimum_version]}
                \\
                \\This is a developer error. Set `minimum_runtime_zig_version` in `build.zig` to `{[current_version]}`.
            , .{ .current_version = zls_version_simple, .minimum_version = min_runtime_zig });
            @compileError(message);
        }
    } else {
        const min_build_zig_simple: std.SemanticVersion = .{ .major = min_build_zig.major, .minor = min_build_zig.minor, .patch = 0 };
        const min_zig_is_tagged = min_build_zig.build == null and min_build_zig.pre == null;
        if (!min_zig_is_tagged and zls_version_simple.order(min_build_zig_simple) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A development build of ZLS should have a tagged release of Zig as the minimum build requirement or
                \\have a development build of Zig as the minimum build requirement with the same major and minor version.
                \\          ZLS version: {d}.{d}.*
                \\  minimum Zig version: {}
                \\
                \\
                \\This is a developer error.
            , .{ zls_version.major, zls_version.minor, min_build_zig });
            @compileError(message);
        }
    }

    // check minimum build version
    const is_current_zig_tagged_release = builtin.zig_version.pre == null and builtin.zig_version.build == null;
    const is_min_build_zig_tagged_release = min_build_zig.pre == null and min_build_zig.build == null;
    const min_build_zig_simple: std.SemanticVersion = .{ .major = min_build_zig.major, .minor = min_build_zig.minor, .patch = 0 };
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
            \\  required Zig version: {[minimum_version]} {[required_zig_version_note]s}
            \\  actual   Zig version: {[current_version]}
            \\
            \\
        ++ if (is_min_build_zig_tagged_release)
            std.fmt.comptimePrint(
                \\Please download the {[minimum_version]} release of Zig. (https://ziglang.org/download/)
                \\
                \\Tagged releases of ZLS are also available.
                \\  -> https://github.com/zigtools/zls/releases
                \\  -> https://github.com/zigtools/zls/releases/tag/{[minimum_version_simple]} (may not exist yet)
            , .{
                .minimum_version = min_build_zig,
                .minimum_version_simple = min_build_zig_simple,
            })
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
            .minimum_version = min_build_zig,
            .required_zig_version_note = if (!zls_version_is_tagged) "(or greater)" else "",
        });
        @compileError(message);
    }
    break :blk std.Build;
};
