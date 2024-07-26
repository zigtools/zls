const std = @import("std");
const builtin = @import("builtin");

/// Must match the `version` in `build.zig.zon`.
/// Remove `.pre` when tagging a new ZLS release and add it back on the next development cycle.
const zls_version = std.SemanticVersion{ .major = 0, .minor = 14, .patch = 0, .pre = "dev" };

/// Specify the minimum Zig version that is required to compile and test ZLS:
/// fix(fmt): pointer type syntax to index (take 2) (#20336)
///
/// Must match the `minimum_zig_version` in `build.zig.zon`.
const minimum_build_zig_version = "0.14.0-dev.470+7e7681813";

/// Specify the minimum Zig version that is required to run ZLS:
/// Release 0.12.0
///
/// Examples of reasons that would cause the minimum runtime version to be bumped are:
///   - breaking change to the Zig Syntax
///   - breaking change to AstGen (i.e `zig ast-check`)
///
/// A breaking change to the Zig Build System should be handled by updating ZLS's build runner (see src\build_runner)
const minimum_runtime_zig_version = "0.12.0";

const release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .windows },
    .{ .cpu_arch = .x86_64, .os_tag = .linux },
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .x86, .os_tag = .windows },
    .{ .cpu_arch = .x86, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const single_threaded = b.option(bool, "single-threaded", "Build a single threaded Executable");
    const pie = b.option(bool, "pie", "Build a Position Independent Executable");
    const enable_tracy = b.option(bool, "enable_tracy", "Whether tracy should be enabled.") orelse false;
    const enable_tracy_allocation = b.option(bool, "enable_tracy_allocation", "Enable using TracyAllocator to monitor allocations.") orelse enable_tracy;
    const enable_tracy_callstack = b.option(bool, "enable_tracy_callstack", "Enable callstack graphs.") orelse enable_tracy;
    const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match filter") orelse &[0][]const u8{};
    const data_version = b.option([]const u8, "data_version", "The Zig version your compiler is.");
    const data_version_path = b.option([]const u8, "version_data_path", "Manually specify zig language reference file");
    const override_version_data_file_path = b.option([]const u8, "version_data_file_path", "Relative path to version data file (if none, will be named with timestamp)");
    const use_llvm = b.option(bool, "use_llvm", "Use Zig's llvm code backend");

    const resolved_zls_version = getVersion(b);
    const resolved_zls_version_string = b.fmt("{}", .{resolved_zls_version});

    const build_options = b.addOptions();
    build_options.step.name = "ZLS build options";
    const build_options_module = build_options.createModule();
    build_options.addOption(std.SemanticVersion, "version", resolved_zls_version);
    build_options.addOption([]const u8, "version_string", resolved_zls_version_string);
    build_options.addOption([]const u8, "minimum_runtime_zig_version_string", minimum_runtime_zig_version);

    const exe_options = b.addOptions();
    exe_options.step.name = "ZLS exe options";
    const exe_options_module = exe_options.createModule();
    exe_options.addOption(bool, "enable_failing_allocator", b.option(bool, "enable_failing_allocator", "Whether to use a randomly failing allocator.") orelse false);
    exe_options.addOption(u32, "enable_failing_allocator_likelihood", b.option(u32, "enable_failing_allocator_likelihood", "The chance that an allocation will fail is `1/likelihood`") orelse 256);
    exe_options.addOption(bool, "use_gpa", b.option(bool, "use_gpa", "Good for debugging") orelse (optimize == .Debug));

    const test_options = b.addOptions();
    test_options.step.name = "ZLS test options";
    const test_options_module = test_options.createModule();
    test_options.addOption([]const u8, "zig_exe_path", b.graph.zig_exe);
    test_options.addOption([]const u8, "zig_lib_path", b.graph.zig_lib_directory.path.?);
    test_options.addOption([]const u8, "global_cache_path", b.graph.global_cache_root.join(b.allocator, &.{"zls"}) catch @panic("OOM"));

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
        .root_source_file = b.path("src/config_gen/config_gen.zig"),
        .target = b.host,
        .single_threaded = true,
    });

    const gen_cmd = b.addRunArtifact(gen_exe);
    gen_cmd.addArgs(&.{
        "--generate-config-path",
        b.pathFromRoot("src/Config.zig"),
        "--generate-schema-path",
        b.pathFromRoot("schema.json"),
    });
    if (b.args) |args| gen_cmd.addArgs(args);

    const gen_step = b.step("gen", "Regenerate config files");
    gen_step.dependOn(&gen_cmd.step);

    const gen_version_data_cmd = b.addRunArtifact(gen_exe);
    const resolved_data_version = data_version orelse if (zls_version.pre == null and zls_version.build == null) b.fmt("{}", .{zls_version}) else "master";
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
            .{ .name = "lsp", .module = lsp_module },
            .{ .name = "tracy", .module = tracy_module },
            .{ .name = "build_options", .module = build_options_module },
            .{ .name = "version_data", .module = version_data_module },
        },
    });

    var release_artifacts: std.BoundedArray(*Build.Step.Compile, release_targets.len) = .{};

    for (release_targets) |target_query| {
        const exe = b.addExecutable(.{
            .name = "zls",
            .target = b.resolveTargetQuery(target_query),
            .root_source_file = b.path("src/main.zig"),
            .version = resolved_zls_version,
            .optimize = optimize,
            .max_rss = if (optimize == .Debug and target_query.os_tag == .wasi) 2_000_000_000 else 1_500_000_000,
            .single_threaded = single_threaded,
            .pic = pie,
            .use_llvm = use_llvm,
            .use_lld = use_llvm,
        });
        exe.root_module.addImport("exe_options", exe_options_module);
        exe.root_module.addImport("tracy", tracy_module);
        exe.root_module.addImport("diffz", diffz_module);
        exe.root_module.addImport("lsp", lsp_module);
        exe.root_module.addImport("known-folders", known_folders_module);
        exe.root_module.addImport("zls", zls_module);

        release_artifacts.appendAssumeCapacity(exe);
    }

    release(b, &release_targets, release_artifacts.constSlice());

    const exe = b.addExecutable(.{
        .name = "zls",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
        .pic = pie,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });
    exe.pie = pie;
    exe.root_module.addImport("exe_options", exe_options_module);
    exe.root_module.addImport("tracy", tracy_module);
    exe.root_module.addImport("diffz", diffz_module);
    exe.root_module.addImport("lsp", lsp_module);
    exe.root_module.addImport("known-folders", known_folders_module);
    exe.root_module.addImport("zls", zls_module);
    b.installArtifact(exe);

    const test_step = b.step("test", "Run all the tests");

    const tests = b.addTest(.{
        .root_source_file = b.path("tests/tests.zig"),
        .target = target,
        .optimize = optimize,
        .filters = test_filters,
        .single_threaded = single_threaded,
        .pic = pie,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    tests.root_module.addImport("zls", zls_module);
    tests.root_module.addImport("test_options", test_options_module);
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const src_tests = b.addTest(.{
        .name = "src test",
        .root_source_file = b.path("src/zls.zig"),
        .target = target,
        .optimize = optimize,
        .filters = test_filters,
        .single_threaded = single_threaded,
        .pic = pie,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });
    src_tests.root_module.addImport("build_options", build_options_module);
    src_tests.root_module.addImport("test_options", test_options_module);
    src_tests.root_module.addImport("lsp", lsp_module);
    test_step.dependOn(&b.addRunArtifact(src_tests).step);

    const coverage_step = b.step("coverage", "Generate a coverage report with kcov");

    const merge_step = std.Build.Step.Run.create(b, "merge coverage");
    merge_step.addArgs(&.{ "kcov", "--merge" });
    merge_step.rename_step_with_output_arg = false;
    const merged_coverage_output = merge_step.addOutputFileArg(".");

    {
        const kcov_collect = std.Build.Step.Run.create(b, "collect coverage");
        kcov_collect.addArgs(&.{ "kcov", "--collect-only" });
        kcov_collect.addPrefixedDirectoryArg("--include-pattern=", b.path("src"));
        merge_step.addDirectoryArg(kcov_collect.addOutputFileArg(tests.name));
        kcov_collect.addArtifactArg(tests);
        kcov_collect.enableTestRunnerMode();
    }

    {
        const kcov_collect = std.Build.Step.Run.create(b, "collect coverage");
        kcov_collect.addArgs(&.{ "kcov", "--collect-only" });
        kcov_collect.addPrefixedDirectoryArg("--include-pattern=", b.path("src"));
        merge_step.addDirectoryArg(kcov_collect.addOutputFileArg(src_tests.name));
        kcov_collect.addArtifactArg(src_tests);
        kcov_collect.enableTestRunnerMode();
    }

    const install_coverage = b.addInstallDirectory(.{
        .source_dir = merged_coverage_output,
        .install_dir = .{ .custom = "coverage" },
        .install_subdir = "",
    });
    coverage_step.dependOn(&install_coverage.step);
}

/// Returns `MAJOR.MINOR.PATCH-dev` when `git describe` failed.
fn getVersion(b: *Build) std.SemanticVersion {
    if (zls_version.pre == null and zls_version.build == null) return zls_version;

    var code: u8 = undefined;
    const git_describe_untrimmed = b.runAllowFail(
        &.{ "git", "-C", b.pathFromRoot("."), "describe", "--match", "*.*.*", "--tags" },
        &code,
        .Ignore,
    ) catch return zls_version;

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

            return std.SemanticVersion{
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

    const uri: std.Uri = if (b.graph.env_map.get("ZLS_WORKER_ENDPOINT")) |endpoint| blk: {
        var uri = std.Uri.parse(endpoint) catch std.debug.panic("invalid URI: '{s}'", .{endpoint});
        if (!uri.path.isEmpty()) std.debug.panic("ZLS_WORKER_ENDPOINT URI must have no path component: '{s}'", .{endpoint});
        uri.path = .{ .raw = "/publish" };
        break :blk uri;
    } else .{
        .scheme = "https",
        .host = .{ .raw = "releases.zigtools.org" },
        .path = .{ .raw = "/publish" },
    };

    const authorization: std.http.Client.Request.Headers.Value = blk: {
        const api_token = b.graph.env_map.get("ZLS_WORKER_API_TOKEN") orelse "amogus";
        const usename_password = b.fmt("admin:{s}", .{api_token});
        const buffer = b.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(usename_password.len)) catch @panic("OOM");
        const auth = std.base64.standard.Encoder.encode(buffer, usename_password);
        break :blk .{ .override = b.fmt("Basic {s}", .{auth}) };
    };

    var publish_artifacts = PostMultiPartForm.create(b, uri, .{ .authorization = authorization });
    publish_step.dependOn(&publish_artifacts.step);

    // It is possible for the version to be something like `0.12.0-dev` when `git describe` failed.
    // Ideally we would want to report a failure about this when running one of the release/publish steps.
    // The problem is during the configure phase, it is not possible to know which top level steps gets run.
    // So instead we use rely on the release-worker to reject this version string during the make phase.
    // One possible alternative would be to use a configuration option (i.e. -Dpublish) to conditionally run an assertion.
    publish_artifacts.addText("zls-version", b.fmt("{}", .{release_artifacts[0].version.?}));
    publish_artifacts.addText("compatibility", "full");
    publish_artifacts.addText("zig-version", builtin.zig_version_string);
    publish_artifacts.addText("minimum-build-zig-version", minimum_build_zig_version);
    publish_artifacts.addText("minimum-runtime-zig-version", minimum_runtime_zig_version);

    var compressed_artifacts = std.StringArrayHashMap(std.Build.LazyPath).init(b.allocator);

    for (target_queries, release_artifacts) |target_query, exe| {
        const resolved_target = exe.root_module.resolved_target.?.result;
        const is_windows = resolved_target.os.tag == .windows;
        const exe_name = b.fmt("{s}{s}", .{ exe.name, resolved_target.exeFileExt() });

        const extensions: []const []const u8 = if (is_windows) &.{"zip"} else &.{ "tar.xz", "tar.gz" };

        for (extensions) |extension| {
            const file_name = b.fmt("zls-{s}-{s}-{}.{s}", .{
                @tagName(target_query.os_tag.?),
                @tagName(target_query.cpu_arch.?),
                exe.version.?,
                extension,
            });

            const compress_cmd = std.Build.Step.Run.create(b, "compress artifact");
            if (is_windows) {
                compress_cmd.step.max_rss = 165_000_000;
                compress_cmd.addArgs(&.{ "7z", "a", "-mx=9" });
                compressed_artifacts.putNoClobber(file_name, compress_cmd.addOutputFileArg(file_name)) catch @panic("OOM");
                compress_cmd.addArtifactArg(exe);
                compress_cmd.addFileArg(exe.getEmittedPdb());
                compress_cmd.addFileArg(b.path("LICENSE"));
                compress_cmd.addFileArg(b.path("README.md"));
            } else {
                compress_cmd.step.max_rss = 240_000_000;
                compress_cmd.setEnvironmentVariable("XZ_OPT", "-9");
                compress_cmd.addArgs(&.{ "tar", "caf" });
                compressed_artifacts.putNoClobber(file_name, compress_cmd.addOutputFileArg(file_name)) catch @panic("OOM");
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
            }
        }
    }

    for (compressed_artifacts.keys(), compressed_artifacts.values()) |file_name, file_path| {
        const install_dir: std.Build.InstallDir = .{ .custom = "artifacts" };

        const install_tarball = b.addInstallFileWithDir(file_path, install_dir, file_name);
        release_step.dependOn(&install_tarball.step);
        publish_artifacts.addFile(file_name, file_path);

        if (release_minisign) {
            const minisign_basename = b.fmt("{s}.minisig", .{file_name});

            const minising_cmd = b.addSystemCommand(&.{ "minisign", "-Sm" });
            minising_cmd.addFileArg(file_path);
            minising_cmd.addPrefixedFileArg("-s", .{ .cwd_relative = "minisign.key" });
            const minising_file_path = minising_cmd.addPrefixedOutputFileArg("-x", minisign_basename);

            const install_minising = b.addInstallFileWithDir(minising_file_path, install_dir, minisign_basename);
            release_step.dependOn(&install_minising.step);
            publish_artifacts.addFile(minisign_basename, minising_file_path);
        }
    }
}

const PostMultiPartForm = struct {
    pub const base_id: Build.Step.Id = .custom;

    step: Build.Step,
    uri: std.Uri,
    headers: std.http.Client.Request.Headers,
    fields: std.ArrayListUnmanaged(Field) = .{},

    pub const Field = struct {
        name: []const u8,
        value: FieldValue,
        content_type: std.http.Client.Request.Headers.Value,
    };

    pub const FieldValue = union(enum) {
        lazy_path: Build.LazyPath,
        bytes: []u8,
    };

    pub fn create(owner: *Build, uri: std.Uri, headers: std.http.Client.Request.Headers) *PostMultiPartForm {
        const self = owner.allocator.create(PostMultiPartForm) catch @panic("OOM");
        self.* = .{
            .step = Build.Step.init(.{
                .id = base_id,
                .name = "PostMultiPartForm",
                .owner = owner,
                .makeFn = make,
            }),
            .uri = std.Uri.parse(owner.fmt("{}", .{uri})) catch unreachable, // super efficient dupe
            .headers = headers,
        };
        return self;
    }

    pub fn addText(self: *PostMultiPartForm, name: []const u8, text: []const u8) void {
        const b = self.step.owner;
        self.fields.append(b.allocator, .{
            .name = b.dupe(name),
            .value = .{ .bytes = b.dupe(text) },
            .content_type = .omit,
        }) catch @panic("OOM");
    }

    pub fn addFile(self: *PostMultiPartForm, name: []const u8, path: Build.LazyPath) void {
        const b = self.step.owner;
        path.addStepDependencies(&self.step);
        self.fields.append(b.allocator, .{
            .name = b.dupe(name),
            .value = .{ .lazy_path = path },
            .content_type = .{ .override = "application/octet-stream" },
        }) catch @panic("OOM");
    }

    fn make(step: *Build.Step, options: Build.Step.MakeOptions) !void {
        _ = options;
        const b = step.owner;
        const self: *const PostMultiPartForm = @fieldParentPtr("step", step);

        var client = std.http.Client{ .allocator = b.allocator };
        defer client.deinit();
        try client.initDefaultProxies(b.allocator);

        var server_header_buffer: [16 * 1024]u8 = undefined;
        var request_options: std.http.Client.RequestOptions = .{
            .keep_alive = false,
            .server_header_buffer = &server_header_buffer,
            .headers = self.headers,
        };

        var boundary: [64 + 3]u8 = undefined;
        std.debug.assert((std.fmt.bufPrint(
            &boundary,
            "{x:0>16}-{x:0>16}-{x:0>16}-{x:0>16}",
            .{ std.crypto.random.int(u64), std.crypto.random.int(u64), std.crypto.random.int(u64), std.crypto.random.int(u64) },
        ) catch unreachable).len == boundary.len);

        request_options.headers.content_type = .{ .override = b.fmt("multipart/form-data; boundary={s}", .{boundary}) };

        var request = try client.open(.POST, self.uri, request_options);
        defer request.deinit();
        request.transfer_encoding = .chunked;

        try request.send();

        var buffered_writer = std.io.bufferedWriter(request.writer());
        const writer = buffered_writer.writer();

        for (self.fields.items) |field| {
            try writer.print("--{s}\r\n", .{boundary});

            switch (field.value) {
                .lazy_path => |lazy_path| try writer.print(
                    "Content-Disposition: form-data; name=\"{s}\"; filename=\"{s}\"\r\n",
                    .{ field.name, std.fs.path.basename(lazy_path.getPath2(b, step)) },
                ),
                .bytes => try writer.print(
                    "Content-Disposition: form-data; name=\"{s}\"\r\n",
                    .{field.name},
                ),
            }

            switch (field.content_type) {
                .omit, .default => {},
                .override => |content_type| try writer.print("Content-Type: {s}\r\n", .{content_type}),
            }
            try writer.writeAll("\r\n");

            switch (field.value) {
                .lazy_path => |lazy_path| {
                    const path = lazy_path.getPath2(b, step);
                    const file = try std.fs.openFileAbsolute(path, .{});
                    defer file.close();

                    var buffer: [16 * 1024]u8 = undefined;
                    while (true) {
                        const amt = try file.read(&buffer);
                        if (amt == 0) break;
                        try writer.writeAll(buffer[0..amt]);
                    }
                },
                .bytes => |bytes| try writer.writeAll(bytes),
            }
            try writer.writeAll("\r\n");
        }
        try writer.print("--{s}--\r\n", .{boundary});

        try buffered_writer.flush();

        try request.finish();
        try request.wait();

        if (request.response.status.class() == .success) return;

        return step.fail("response {s} ({d}): {s}", .{
            request.response.status.phrase() orelse "",
            @intFromEnum(request.response.status),
            try request.reader().readAllAlloc(b.allocator, std.math.maxInt(u32)),
        });
    }
};

const Build = blk: {
    const min_build_zig = std.SemanticVersion.parse(minimum_build_zig_version) catch unreachable;
    const min_runtime_zig = std.SemanticVersion.parse(minimum_runtime_zig_version) catch unreachable;

    std.debug.assert(zls_version.pre == null or std.mem.eql(u8, zls_version.pre.?, "dev"));
    std.debug.assert(zls_version.build == null);
    const zls_version_is_tagged = zls_version.pre == null and zls_version.build == null;

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
        if (zls_version.order(min_build_zig) != .eq) {
            const message = std.fmt.comptimePrint(
                \\A tagged release of ZLS should have the same tagged release of Zig as the minimum build requirement:
                \\          ZLS version: {[current_version]}
                \\  minimum Zig version: {[minimum_version]}
                \\
                \\This is a developer error. Set `minimum_build_zig_version` in `build.zig` and `minimum_zig_version` in `build.zig.zon` to {[current_version]}.
            , .{ .current_version = zls_version, .minimum_version = min_build_zig });
            @compileError(message);
        }
    } else {
        const min_build_zig_simple = std.SemanticVersion{ .major = min_build_zig.major, .minor = min_build_zig.minor, .patch = 0 };
        const zls_version_simple = std.SemanticVersion{ .major = zls_version.major, .minor = zls_version.minor, .patch = 0 };
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
    const min_build_zig_simple = std.SemanticVersion{ .major = min_build_zig.major, .minor = min_build_zig.minor, .patch = 0 };
    const current_zig_simple = std.SemanticVersion{ .major = builtin.zig_version.major, .minor = builtin.zig_version.minor, .patch = 0 };
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
