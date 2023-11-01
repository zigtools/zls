const BuildConfig = @import("BuildConfig.zig");
const Build = std.Build;
const root = @import("@build");
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const io = std.io;
const fmt = std.fmt;
const mem = std.mem;
const process = std.process;
const ArrayList = std.ArrayList;
const File = std.fs.File;
const Step = std.Build.Step;

pub const dependencies = @import("@dependencies");

pub fn main() !void {
    // Here we use an ArenaAllocator backed by a DirectAllocator because a build is a short-lived,
    // one shot program. We don't need to waste time freeing memory and finding places to squish
    // bytes into. So we free everything all at once at the very end.
    var single_threaded_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer single_threaded_arena.deinit();

    var thread_safe_arena: std.heap.ThreadSafeAllocator = .{
        .child_allocator = single_threaded_arena.allocator(),
    };
    const arena = thread_safe_arena.allocator();

    var args = try process.argsAlloc(arena);

    // skip my own exe name
    var arg_idx: usize = 1;

    const zig_exe = nextArg(args, &arg_idx) orelse {
        std.debug.print("Expected path to zig compiler\n", .{});
        return error.InvalidArgs;
    };
    const build_root = nextArg(args, &arg_idx) orelse {
        std.debug.print("Expected build root directory path\n", .{});
        return error.InvalidArgs;
    };
    const cache_root = nextArg(args, &arg_idx) orelse {
        std.debug.print("Expected cache root directory path\n", .{});
        return error.InvalidArgs;
    };
    const global_cache_root = nextArg(args, &arg_idx) orelse {
        std.debug.print("Expected global cache root directory path\n", .{});
        return error.InvalidArgs;
    };

    const host = try std.zig.system.NativeTargetInfo.detect(.{});

    const build_root_directory: std.Build.Cache.Directory = .{
        .path = build_root,
        .handle = try std.fs.cwd().openDir(build_root, .{}),
    };

    const local_cache_directory: std.Build.Cache.Directory = .{
        .path = cache_root,
        .handle = try std.fs.cwd().makeOpenPath(cache_root, .{}),
    };

    const global_cache_directory: std.Build.Cache.Directory = .{
        .path = global_cache_root,
        .handle = try std.fs.cwd().makeOpenPath(global_cache_root, .{}),
    };

    var cache: std.Build.Cache = .{
        .gpa = arena,
        .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
    };
    cache.addPrefix(.{ .path = null, .handle = std.fs.cwd() });
    cache.addPrefix(build_root_directory);
    cache.addPrefix(local_cache_directory);
    cache.addPrefix(global_cache_directory);
    cache.hash.addBytes(builtin.zig_version_string);

    const builder = try std.Build.create(
        arena,
        zig_exe,
        build_root_directory,
        local_cache_directory,
        global_cache_directory,
        host,
        &cache,
    );
    defer builder.destroy();

    var targets = ArrayList([]const u8).init(arena);
    var debug_log_scopes = ArrayList([]const u8).init(arena);
    var thread_pool_options: std.Thread.Pool.Options = .{ .allocator = arena };

    var install_prefix: ?[]const u8 = null;
    var dir_list = std.Build.DirList{};
    var summary: ?Summary = null;
    var max_rss: usize = 0;
    var color: Color = .auto;

    const stderr_stream = io.getStdErr().writer();
    const stdout_stream = io.getStdOut().writer();

    while (nextArg(args, &arg_idx)) |arg| {
        if (mem.startsWith(u8, arg, "-D")) {
            const option_contents = arg[2..];
            if (option_contents.len == 0) {
                std.debug.print("Expected option name after '-D'\n\n", .{});
                usageAndErr(builder, false, stderr_stream);
            }
            if (mem.indexOfScalar(u8, option_contents, '=')) |name_end| {
                const option_name = option_contents[0..name_end];
                const option_value = option_contents[name_end + 1 ..];
                if (try builder.addUserInputOption(option_name, option_value))
                    usageAndErr(builder, false, stderr_stream);
            } else {
                if (try builder.addUserInputFlag(option_contents))
                    usageAndErr(builder, false, stderr_stream);
            }
        } else if (mem.startsWith(u8, arg, "-")) {
            if (mem.eql(u8, arg, "--verbose")) {
                builder.verbose = true;
            } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                return usage(builder, false, stdout_stream);
            } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--prefix")) {
                install_prefix = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "-l") or mem.eql(u8, arg, "--list-steps")) {
                return steps(builder, false, stdout_stream);
            } else if (mem.eql(u8, arg, "--prefix-lib-dir")) {
                dir_list.lib_dir = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--prefix-exe-dir")) {
                dir_list.exe_dir = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--prefix-include-dir")) {
                dir_list.include_dir = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--sysroot")) {
                const sysroot = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                builder.sysroot = sysroot;
            } else if (mem.eql(u8, arg, "--maxrss")) {
                const max_rss_text = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                max_rss = std.fmt.parseIntSizeSuffix(max_rss_text, 10) catch |err| {
                    std.debug.print("invalid byte size: '{s}': {s}\n", .{
                        max_rss_text, @errorName(err),
                    });
                    process.exit(1);
                };
            } else if (mem.eql(u8, arg, "--search-prefix")) {
                const search_prefix = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                builder.addSearchPrefix(search_prefix);
            } else if (mem.eql(u8, arg, "--libc")) {
                const libc_file = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                builder.libc_file = libc_file;
            } else if (mem.eql(u8, arg, "--color")) {
                const next_arg = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected [auto|on|off] after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                color = std.meta.stringToEnum(Color, next_arg) orelse {
                    std.debug.print("Expected [auto|on|off] after {s}, found '{s}'\n\n", .{ arg, next_arg });
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--summary")) {
                const next_arg = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected [all|failures|none] after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                summary = std.meta.stringToEnum(Summary, next_arg) orelse {
                    std.debug.print("Expected [all|failures|none] after {s}, found '{s}'\n\n", .{ arg, next_arg });
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--zig-lib-dir")) {
                builder.zig_lib_dir = .{ .cwd_relative = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                } };
            } else if (mem.eql(u8, arg, "--debug-log")) {
                const next_arg = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
                try debug_log_scopes.append(next_arg);
            } else if (mem.eql(u8, arg, "--debug-pkg-config")) {
                builder.debug_pkg_config = true;
            } else if (mem.eql(u8, arg, "--debug-compile-errors")) {
                builder.debug_compile_errors = true;
            } else if (mem.eql(u8, arg, "--glibc-runtimes")) {
                builder.glibc_runtimes_dir = nextArg(args, &arg_idx) orelse {
                    std.debug.print("Expected argument after {s}\n\n", .{arg});
                    usageAndErr(builder, false, stderr_stream);
                };
            } else if (mem.eql(u8, arg, "--verbose-link")) {
                builder.verbose_link = true;
            } else if (mem.eql(u8, arg, "--verbose-air")) {
                builder.verbose_air = true;
            } else if (mem.eql(u8, arg, "--verbose-llvm-ir")) {
                builder.verbose_llvm_ir = "-";
            } else if (mem.startsWith(u8, arg, "--verbose-llvm-ir=")) {
                builder.verbose_llvm_ir = arg["--verbose-llvm-ir=".len..];
            } else if (mem.eql(u8, arg, "--verbose-llvm-bc=")) {
                builder.verbose_llvm_bc = arg["--verbose-llvm-bc=".len..];
            } else if (mem.eql(u8, arg, "--verbose-cimport")) {
                builder.verbose_cimport = true;
            } else if (mem.eql(u8, arg, "--verbose-cc")) {
                builder.verbose_cc = true;
            } else if (mem.eql(u8, arg, "--verbose-llvm-cpu-features")) {
                builder.verbose_llvm_cpu_features = true;
            } else if (mem.eql(u8, arg, "-fwine")) {
                builder.enable_wine = true;
            } else if (mem.eql(u8, arg, "-fno-wine")) {
                builder.enable_wine = false;
            } else if (mem.eql(u8, arg, "-fqemu")) {
                builder.enable_qemu = true;
            } else if (mem.eql(u8, arg, "-fno-qemu")) {
                builder.enable_qemu = false;
            } else if (mem.eql(u8, arg, "-fwasmtime")) {
                builder.enable_wasmtime = true;
            } else if (mem.eql(u8, arg, "-fno-wasmtime")) {
                builder.enable_wasmtime = false;
            } else if (mem.eql(u8, arg, "-frosetta")) {
                builder.enable_rosetta = true;
            } else if (mem.eql(u8, arg, "-fno-rosetta")) {
                builder.enable_rosetta = false;
            } else if (mem.eql(u8, arg, "-fdarling")) {
                builder.enable_darling = true;
            } else if (mem.eql(u8, arg, "-fno-darling")) {
                builder.enable_darling = false;
            } else if (mem.eql(u8, arg, "-freference-trace")) {
                builder.reference_trace = 256;
            } else if (mem.startsWith(u8, arg, "-freference-trace=")) {
                const num = arg["-freference-trace=".len..];
                builder.reference_trace = std.fmt.parseUnsigned(u32, num, 10) catch |err| {
                    std.debug.print("unable to parse reference_trace count '{s}': {s}", .{ num, @errorName(err) });
                    process.exit(1);
                };
            } else if (mem.eql(u8, arg, "-fno-reference-trace")) {
                builder.reference_trace = null;
            } else if (mem.startsWith(u8, arg, "-j")) {
                const num = arg["-j".len..];
                const n_jobs = std.fmt.parseUnsigned(u32, num, 10) catch |err| {
                    std.debug.print("unable to parse jobs count '{s}': {s}", .{
                        num, @errorName(err),
                    });
                    process.exit(1);
                };
                if (n_jobs < 1) {
                    std.debug.print("number of jobs must be at least 1\n", .{});
                    process.exit(1);
                }
                thread_pool_options.n_jobs = n_jobs;
            } else if (mem.eql(u8, arg, "--")) {
                builder.args = argsRest(args, arg_idx);
                break;
            } else {
                std.debug.print("Unrecognized argument: {s}\n\n", .{arg});
                usageAndErr(builder, false, stderr_stream);
            }
        } else {
            try targets.append(arg);
        }
    }

    const stderr = std.io.getStdErr();
    const ttyconf = get_tty_conf(color, stderr);
    switch (ttyconf) {
        .no_color => try builder.env_map.put("NO_COLOR", "1"),
        .escape_codes => try builder.env_map.put("YES_COLOR", "1"),
        .windows_api => {},
    }

    var progress: std.Progress = .{ .dont_print_on_dumb = true };
    const main_progress_node = progress.start("", 0);

    builder.debug_log_scopes = debug_log_scopes.items;
    builder.resolveInstallPrefix(install_prefix, dir_list);
    {
        var prog_node = main_progress_node.start("user build.zig logic", 0);
        defer prog_node.end();
        try builder.runBuild(root);
    }

    if (builder.validateUserInputDidItFail())
        usageAndErr(builder, true, stderr_stream);

    var run: Run = .{
        .max_rss = max_rss,
        .max_rss_is_default = false,
        .max_rss_mutex = .{},
        .memory_blocked_steps = std.ArrayList(*Step).init(arena),

        .claimed_rss = 0,
        .summary = summary,
        .ttyconf = ttyconf,
        .stderr = stderr,
    };

    if (run.max_rss == 0) {
        run.max_rss = process.totalSystemMemory() catch std.math.maxInt(usize);
        run.max_rss_is_default = true;
    }

    runStepNames(
        arena,
        builder,
        targets.items,
        main_progress_node,
        thread_pool_options,
        &run,
    ) catch |err| switch (err) {
        error.UncleanExit => process.exit(1),
        else => return err,
    };

    // <--------    ZLS     -------->

    var deps_build_roots: std.ArrayListUnmanaged(BuildConfig.DepsBuildRoots) = .{};
    inline for (@typeInfo(dependencies.build_root).Struct.decls) |decl| {
        try deps_build_roots.append(arena, .{
            .name = decl.name,
            // XXX Check if it exists?
            .path = try std.fs.path.resolve(arena, &[_][]const u8{ @field(dependencies.build_root, decl.name), "./build.zig" }),
        });
    }

    var packages = Packages{ .allocator = arena };
    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.top_level_steps.values()) |tls| {
        for (tls.step.dependencies.items) |step| {
            try processStep(builder, &packages, &include_dirs, step);
        }
    }

    try std.json.stringify(
        BuildConfig{
            .deps_build_roots = try deps_build_roots.toOwnedSlice(arena),
            .packages = try packages.toPackageList(),
            .include_dirs = include_dirs.keys(),
        },
        .{},
        std.io.getStdOut().writer(),
    );

    cleanExit();
}

const Run = struct {
    max_rss: usize,
    max_rss_is_default: bool,
    max_rss_mutex: std.Thread.Mutex,
    memory_blocked_steps: std.ArrayList(*Step),

    claimed_rss: usize,
    summary: ?Summary,
    ttyconf: std.io.tty.Config,
    stderr: std.fs.File,
};

fn runStepNames(
    arena: std.mem.Allocator,
    b: *std.Build,
    step_names: []const []const u8,
    parent_prog_node: *std.Progress.Node,
    thread_pool_options: std.Thread.Pool.Options,
    run: *Run,
) !void {
    const gpa = b.allocator;
    var step_stack: std.AutoArrayHashMapUnmanaged(*Step, void) = .{};
    defer step_stack.deinit(gpa);

    if (step_names.len == 0) {
        try step_stack.put(gpa, b.default_step, {});
    } else {
        try step_stack.ensureUnusedCapacity(gpa, step_names.len);
        for (0..step_names.len) |i| {
            const step_name = step_names[step_names.len - i - 1];
            const s = b.top_level_steps.get(step_name) orelse {
                std.debug.print("no step named '{s}'. Access the help menu with 'zig build -h'\n", .{step_name});
                process.exit(1);
            };
            step_stack.putAssumeCapacity(&s.step, {});
        }
    }

    const starting_steps = try arena.dupe(*Step, step_stack.keys());
    for (starting_steps) |s| {
        checkForDependencyLoop(b, s, &step_stack) catch |err| switch (err) {
            error.DependencyLoopDetected => return error.UncleanExit,
            else => |e| return e,
        };
    }

    {
        // Check that we have enough memory to complete the build.
        var any_problems = false;
        for (step_stack.keys()) |s| {
            if (s.max_rss == 0) continue;
            if (s.max_rss > run.max_rss) {
                std.debug.print("{s}{s}: this step declares an upper bound of {d} bytes of memory, exceeding the available {d} bytes of memory\n", .{
                    s.owner.dep_prefix, s.name, s.max_rss, run.max_rss,
                });
                any_problems = true;
            }
        }
        if (any_problems) {
            if (run.max_rss_is_default) {
                std.debug.print("note: use --maxrss to override the default", .{});
            }
            return error.UncleanExit;
        }
    }

    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(thread_pool_options);
    defer thread_pool.deinit();

    {
        defer parent_prog_node.end();

        var step_prog = parent_prog_node.start("steps", step_stack.count());
        defer step_prog.end();

        var wait_group: std.Thread.WaitGroup = .{};
        defer wait_group.wait();

        // Here we spawn the initial set of tasks with a nice heuristic -
        // dependency order. Each worker when it finishes a step will then
        // check whether it should run any dependants.
        const steps_slice = step_stack.keys();
        for (0..steps_slice.len) |i| {
            const step = steps_slice[steps_slice.len - i - 1];

            wait_group.start();
            thread_pool.spawn(workerMakeOneStep, .{
                &wait_group, &thread_pool, b, step, &step_prog, run,
            }) catch @panic("OOM");
        }
    }
    // Even if there were errors, return and try to work with whatever worked
}

const PrintNode = struct {
    parent: ?*PrintNode,
    last: bool = false,
};

fn printPrefix(node: *PrintNode, stderr: std.fs.File, ttyconf: std.io.tty.Config) !void {
    const parent = node.parent orelse return;
    if (parent.parent == null) return;
    try printPrefix(parent, stderr, ttyconf);
    if (parent.last) {
        try stderr.writeAll("   ");
    } else {
        try stderr.writeAll(switch (ttyconf) {
            .no_color, .windows_api => "|  ",
            .escape_codes => "\x1B\x28\x30\x78\x1B\x28\x42  ", // │
        });
    }
}

fn printTreeStep(
    b: *std.Build,
    s: *Step,
    stderr: std.fs.File,
    ttyconf: std.io.tty.Config,
    parent_node: *PrintNode,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
    failures_only: bool,
) !void {
    const first = step_stack.swapRemove(s);
    if (failures_only and s.state == .success) return;
    try printPrefix(parent_node, stderr, ttyconf);

    if (!first) try ttyconf.setColor(stderr, .dim);
    if (parent_node.parent != null) {
        if (parent_node.last) {
            try stderr.writeAll(switch (ttyconf) {
                .no_color, .windows_api => "+- ",
                .escape_codes => "\x1B\x28\x30\x6d\x71\x1B\x28\x42 ", // └─
            });
        } else {
            try stderr.writeAll(switch (ttyconf) {
                .no_color, .windows_api => "+- ",
                .escape_codes => "\x1B\x28\x30\x74\x71\x1B\x28\x42 ", // ├─
            });
        }
    }

    // dep_prefix omitted here because it is redundant with the tree.
    try stderr.writeAll(s.name);

    if (first) {
        switch (s.state) {
            .precheck_unstarted => unreachable,
            .precheck_started => unreachable,
            .precheck_done => unreachable,
            .running => unreachable,

            .dependency_failure => {
                try ttyconf.setColor(stderr, .dim);
                try stderr.writeAll(" transitive failure\n");
                try ttyconf.setColor(stderr, .reset);
            },

            .success => {
                try ttyconf.setColor(stderr, .green);
                if (s.result_cached) {
                    try stderr.writeAll(" cached");
                } else if (s.test_results.test_count > 0) {
                    const pass_count = s.test_results.passCount();
                    try stderr.writer().print(" {d} passed", .{pass_count});
                    if (s.test_results.skip_count > 0) {
                        try ttyconf.setColor(stderr, .yellow);
                        try stderr.writer().print(" {d} skipped", .{s.test_results.skip_count});
                    }
                } else {
                    try stderr.writeAll(" success");
                }
                try ttyconf.setColor(stderr, .reset);
                if (s.result_duration_ns) |ns| {
                    try ttyconf.setColor(stderr, .dim);
                    if (ns >= std.time.ns_per_min) {
                        try stderr.writer().print(" {d}m", .{ns / std.time.ns_per_min});
                    } else if (ns >= std.time.ns_per_s) {
                        try stderr.writer().print(" {d}s", .{ns / std.time.ns_per_s});
                    } else if (ns >= std.time.ns_per_ms) {
                        try stderr.writer().print(" {d}ms", .{ns / std.time.ns_per_ms});
                    } else if (ns >= std.time.ns_per_us) {
                        try stderr.writer().print(" {d}us", .{ns / std.time.ns_per_us});
                    } else {
                        try stderr.writer().print(" {d}ns", .{ns});
                    }
                    try ttyconf.setColor(stderr, .reset);
                }
                if (s.result_peak_rss != 0) {
                    const rss = s.result_peak_rss;
                    try ttyconf.setColor(stderr, .dim);
                    if (rss >= 1000_000_000) {
                        try stderr.writer().print(" MaxRSS:{d}G", .{rss / 1000_000_000});
                    } else if (rss >= 1000_000) {
                        try stderr.writer().print(" MaxRSS:{d}M", .{rss / 1000_000});
                    } else if (rss >= 1000) {
                        try stderr.writer().print(" MaxRSS:{d}K", .{rss / 1000});
                    } else {
                        try stderr.writer().print(" MaxRSS:{d}B", .{rss});
                    }
                    try ttyconf.setColor(stderr, .reset);
                }
                try stderr.writeAll("\n");
            },

            .skipped => {
                try ttyconf.setColor(stderr, .yellow);
                try stderr.writeAll(" skipped\n");
                try ttyconf.setColor(stderr, .reset);
            },

            .failure => {
                if (s.result_error_bundle.errorMessageCount() > 0) {
                    try ttyconf.setColor(stderr, .red);
                    try stderr.writer().print(" {d} errors\n", .{
                        s.result_error_bundle.errorMessageCount(),
                    });
                    try ttyconf.setColor(stderr, .reset);
                } else if (!s.test_results.isSuccess()) {
                    try stderr.writer().print(" {d}/{d} passed", .{
                        s.test_results.passCount(), s.test_results.test_count,
                    });
                    if (s.test_results.fail_count > 0) {
                        try stderr.writeAll(", ");
                        try ttyconf.setColor(stderr, .red);
                        try stderr.writer().print("{d} failed", .{
                            s.test_results.fail_count,
                        });
                        try ttyconf.setColor(stderr, .reset);
                    }
                    if (s.test_results.skip_count > 0) {
                        try stderr.writeAll(", ");
                        try ttyconf.setColor(stderr, .yellow);
                        try stderr.writer().print("{d} skipped", .{
                            s.test_results.skip_count,
                        });
                        try ttyconf.setColor(stderr, .reset);
                    }
                    if (s.test_results.leak_count > 0) {
                        try stderr.writeAll(", ");
                        try ttyconf.setColor(stderr, .red);
                        try stderr.writer().print("{d} leaked", .{
                            s.test_results.leak_count,
                        });
                        try ttyconf.setColor(stderr, .reset);
                    }
                    try stderr.writeAll("\n");
                } else {
                    try ttyconf.setColor(stderr, .red);
                    try stderr.writeAll(" failure\n");
                    try ttyconf.setColor(stderr, .reset);
                }
            },
        }

        const last_index = if (!failures_only) s.dependencies.items.len -| 1 else blk: {
            var i: usize = s.dependencies.items.len;
            while (i > 0) {
                i -= 1;
                if (s.dependencies.items[i].state != .success) break :blk i;
            }
            break :blk s.dependencies.items.len -| 1;
        };
        for (s.dependencies.items, 0..) |dep, i| {
            var print_node: PrintNode = .{
                .parent = parent_node,
                .last = i == last_index,
            };
            try printTreeStep(b, dep, stderr, ttyconf, &print_node, step_stack, failures_only);
        }
    } else {
        if (s.dependencies.items.len == 0) {
            try stderr.writeAll(" (reused)\n");
        } else {
            try stderr.writer().print(" (+{d} more reused dependencies)\n", .{
                s.dependencies.items.len,
            });
        }
        try ttyconf.setColor(stderr, .reset);
    }
}

fn checkForDependencyLoop(
    b: *std.Build,
    s: *Step,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
) !void {
    switch (s.state) {
        .precheck_started => {
            std.debug.print("dependency loop detected:\n  {s}\n", .{s.name});
            return error.DependencyLoopDetected;
        },
        .precheck_unstarted => {
            s.state = .precheck_started;

            try step_stack.ensureUnusedCapacity(b.allocator, s.dependencies.items.len);
            for (s.dependencies.items) |dep| {
                try step_stack.put(b.allocator, dep, {});
                try dep.dependants.append(b.allocator, s);
                checkForDependencyLoop(b, dep, step_stack) catch |err| {
                    if (err == error.DependencyLoopDetected) {
                        std.debug.print("  {s}\n", .{s.name});
                    }
                    return err;
                };
            }

            s.state = .precheck_done;
        },
        .precheck_done => {},

        // These don't happen until we actually run the step graph.
        .dependency_failure => unreachable,
        .running => unreachable,
        .success => unreachable,
        .failure => unreachable,
        .skipped => unreachable,
    }
}

fn workerMakeOneStep(
    wg: *std.Thread.WaitGroup,
    thread_pool: *std.Thread.Pool,
    b: *std.Build,
    s: *Step,
    prog_node: *std.Progress.Node,
    run: *Run,
) void {
    defer wg.finish();

    // First, check the conditions for running this step. If they are not met,
    // then we return without doing the step, relying on another worker to
    // queue this step up again when dependencies are met.
    for (s.dependencies.items) |dep| {
        switch (@atomicLoad(Step.State, &dep.state, .SeqCst)) {
            .success, .skipped => continue,
            .failure, .dependency_failure => {
                @atomicStore(Step.State, &s.state, .dependency_failure, .SeqCst);
                return;
            },
            .precheck_done, .running => {
                // dependency is not finished yet.
                return;
            },
            .precheck_unstarted => unreachable,
            .precheck_started => unreachable,
        }
    }

    if (s.max_rss != 0) {
        run.max_rss_mutex.lock();
        defer run.max_rss_mutex.unlock();

        // Avoid running steps twice.
        if (s.state != .precheck_done) {
            // Another worker got the job.
            return;
        }

        const new_claimed_rss = run.claimed_rss + s.max_rss;
        if (new_claimed_rss > run.max_rss) {
            // Running this step right now could possibly exceed the allotted RSS.
            // Add this step to the queue of memory-blocked steps.
            run.memory_blocked_steps.append(s) catch @panic("OOM");
            return;
        }

        run.claimed_rss = new_claimed_rss;
        s.state = .running;
    } else {
        // Avoid running steps twice.
        if (@cmpxchgStrong(Step.State, &s.state, .precheck_done, .running, .SeqCst, .SeqCst) != null) {
            // Another worker got the job.
            return;
        }
    }

    var sub_prog_node = prog_node.start(s.name, 0);
    sub_prog_node.activate();
    defer sub_prog_node.end();

    const make_result = s.make(&sub_prog_node);

    // No matter the result, we want to display error/warning messages.
    if (s.result_error_msgs.items.len > 0) {
        sub_prog_node.context.lock_stderr();
        defer sub_prog_node.context.unlock_stderr();

        const stderr = run.stderr;
        const ttyconf = run.ttyconf;

        for (s.result_error_msgs.items) |msg| {
            // Sometimes it feels like you just can't catch a break. Finally,
            // with Zig, you can.
            ttyconf.setColor(stderr, .bold) catch break;
            stderr.writeAll(s.owner.dep_prefix) catch break;
            stderr.writeAll(s.name) catch break;
            stderr.writeAll(": ") catch break;
            ttyconf.setColor(stderr, .red) catch break;
            stderr.writeAll("error: ") catch break;
            ttyconf.setColor(stderr, .reset) catch break;
            stderr.writeAll(msg) catch break;
            stderr.writeAll("\n") catch break;
        }
    }

    handle_result: {
        if (make_result) |_| {
            @atomicStore(Step.State, &s.state, .success, .SeqCst);
        } else |err| switch (err) {
            error.MakeFailed => {
                @atomicStore(Step.State, &s.state, .failure, .SeqCst);
                break :handle_result;
            },
            error.MakeSkipped => @atomicStore(Step.State, &s.state, .skipped, .SeqCst),
        }

        // Successful completion of a step, so we queue up its dependants as well.
        for (s.dependants.items) |dep| {
            wg.start();
            thread_pool.spawn(workerMakeOneStep, .{
                wg, thread_pool, b, dep, prog_node, run,
            }) catch @panic("OOM");
        }
    }

    // If this is a step that claims resources, we must now queue up other
    // steps that are waiting for resources.
    if (s.max_rss != 0) {
        run.max_rss_mutex.lock();
        defer run.max_rss_mutex.unlock();

        // Give the memory back to the scheduler.
        run.claimed_rss -= s.max_rss;
        // Avoid kicking off too many tasks that we already know will not have
        // enough resources.
        var remaining = run.max_rss - run.claimed_rss;
        var i: usize = 0;
        var j: usize = 0;
        while (j < run.memory_blocked_steps.items.len) : (j += 1) {
            const dep = run.memory_blocked_steps.items[j];
            assert(dep.max_rss != 0);
            if (dep.max_rss <= remaining) {
                remaining -= dep.max_rss;

                wg.start();
                thread_pool.spawn(workerMakeOneStep, .{
                    wg, thread_pool, b, dep, prog_node, run,
                }) catch @panic("OOM");
            } else {
                run.memory_blocked_steps.items[i] = dep;
                i += 1;
            }
        }
        run.memory_blocked_steps.shrinkRetainingCapacity(i);
    }
}

fn steps(builder: *std.Build, already_ran_build: bool, out_stream: anytype) !void {
    // run the build script to collect the options
    if (!already_ran_build) {
        builder.resolveInstallPrefix(null, .{});
        try builder.runBuild(root);
    }

    const allocator = builder.allocator;
    for (builder.top_level_steps.values()) |top_level_step| {
        const name = if (&top_level_step.step == builder.default_step)
            try fmt.allocPrint(allocator, "{s} (default)", .{top_level_step.step.name})
        else
            top_level_step.step.name;
        try out_stream.print("  {s:<28} {s}\n", .{ name, top_level_step.description });
    }
}

fn usage(builder: *std.Build, already_ran_build: bool, out_stream: anytype) !void {
    // run the build script to collect the options
    if (!already_ran_build) {
        builder.resolveInstallPrefix(null, .{});
        try builder.runBuild(root);
    }

    try out_stream.print(
        \\
        \\Usage: {s} build [steps] [options]
        \\
        \\Steps:
        \\
    , .{builder.zig_exe});
    try steps(builder, true, out_stream);

    try out_stream.writeAll(
        \\
        \\General Options:
        \\  -p, --prefix [path]          Override default install prefix
        \\  --prefix-lib-dir [path]      Override default library directory path
        \\  --prefix-exe-dir [path]      Override default executable directory path
        \\  --prefix-include-dir [path]  Override default include directory path
        \\
        \\  --sysroot [path]             Set the system root directory (usually /)
        \\  --search-prefix [path]       Add a path to look for binaries, libraries, headers
        \\  --libc [file]                Provide a file which specifies libc paths
        \\
        \\  -fdarling,  -fno-darling     Integration with system-installed Darling to
        \\                               execute macOS programs on Linux hosts
        \\                               (default: no)
        \\  -fqemu,     -fno-qemu        Integration with system-installed QEMU to execute
        \\                               foreign-architecture programs on Linux hosts
        \\                               (default: no)
        \\  --glibc-runtimes [path]      Enhances QEMU integration by providing glibc built
        \\                               for multiple foreign architectures, allowing
        \\                               execution of non-native programs that link with glibc.
        \\  -frosetta,  -fno-rosetta     Rely on Rosetta to execute x86_64 programs on
        \\                               ARM64 macOS hosts. (default: no)
        \\  -fwasmtime, -fno-wasmtime    Integration with system-installed wasmtime to
        \\                               execute WASI binaries. (default: no)
        \\  -fwine,     -fno-wine        Integration with system-installed Wine to execute
        \\                               Windows programs on Linux hosts. (default: no)
        \\
        \\  -h, --help                   Print this help and exit
        \\  -l, --list-steps             Print available steps
        \\  --verbose                    Print commands before executing them
        \\  --color [auto|off|on]        Enable or disable colored error messages
        \\  --summary [mode]             Control the printing of the build summary
        \\    all                        Print the build summary in its entirety
        \\    failures                   (Default) Only print failed steps
        \\    none                       Do not print the build summary
        \\  -j<N>                        Limit concurrent jobs (default is to use all CPU cores)
        \\  --maxrss <bytes>             Limit memory usage (default is to use available memory)
        \\
        \\Project-Specific Options:
        \\
    );

    const allocator = builder.allocator;
    if (builder.available_options_list.items.len == 0) {
        try out_stream.print("  (none)\n", .{});
    } else {
        for (builder.available_options_list.items) |option| {
            const name = try fmt.allocPrint(allocator, "  -D{s}=[{s}]", .{
                option.name,
                @tagName(option.type_id),
            });
            defer allocator.free(name);
            try out_stream.print("{s:<30} {s}\n", .{ name, option.description });
            if (option.enum_options) |enum_options| {
                const padding = " " ** 33;
                try out_stream.writeAll(padding ++ "Supported Values:\n");
                for (enum_options) |enum_option| {
                    try out_stream.print(padding ++ "  {s}\n", .{enum_option});
                }
            }
        }
    }

    try out_stream.writeAll(
        \\
        \\Advanced Options:
        \\  -freference-trace[=num]      How many lines of reference trace should be shown per compile error
        \\  -fno-reference-trace         Disable reference trace
        \\  --build-file [file]          Override path to build.zig
        \\  --cache-dir [path]           Override path to local Zig cache directory
        \\  --global-cache-dir [path]    Override path to global Zig cache directory
        \\  --zig-lib-dir [arg]          Override path to Zig lib directory
        \\  --build-runner [file]        Override path to build runner
        \\  --debug-log [scope]          Enable debugging the compiler
        \\  --debug-pkg-config           Fail if unknown pkg-config flags encountered
        \\  --verbose-link               Enable compiler debug output for linking
        \\  --verbose-air                Enable compiler debug output for Zig AIR
        \\  --verbose-llvm-ir[=file]     Enable compiler debug output for LLVM IR
        \\  --verbose-llvm-bc=[file]     Enable compiler debug output for LLVM BC
        \\  --verbose-cimport            Enable compiler debug output for C imports
        \\  --verbose-cc                 Enable compiler debug output for C compilation
        \\  --verbose-llvm-cpu-features  Enable compiler debug output for LLVM CPU features
        \\
    );
}

fn usageAndErr(builder: *std.Build, already_ran_build: bool, out_stream: anytype) noreturn {
    usage(builder, already_ran_build, out_stream) catch {};
    process.exit(1);
}

fn nextArg(args: [][:0]const u8, idx: *usize) ?[:0]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

fn argsRest(args: [][:0]const u8, idx: usize) ?[][:0]const u8 {
    if (idx >= args.len) return null;
    return args[idx..];
}

fn cleanExit() void {
    // Perhaps in the future there could be an Advanced Options flag such as
    // --debug-build-runner-leaks which would make this function return instead
    // of calling exit.
    process.exit(0);
}

const Color = enum { auto, off, on };
const Summary = enum { all, failures, none };

fn get_tty_conf(color: Color, stderr: std.fs.File) std.io.tty.Config {
    return switch (color) {
        .auto => std.io.tty.detectConfig(stderr),
        .on => .escape_codes,
        .off => .no_color,
    };
}

fn renderOptions(ttyconf: std.io.tty.Config) std.zig.ErrorBundle.RenderOptions {
    return .{
        .ttyconf = ttyconf,
        .include_source_line = ttyconf != .no_color,
        .include_reference_trace = ttyconf != .no_color,
    };
}

fn reifyOptions(step: *Build.Step) anyerror!void {
    if (step.cast(Build.Step.Options)) |option| {
        // We don't know how costly the dependency tree might be, so err on the side of caution
        if (step.dependencies.items.len == 0) {
            var progress: std.Progress = .{};
            const main_progress_node = progress.start("", 0);
            defer main_progress_node.end();

            try option.step.make(main_progress_node);
        }
    }

    for (step.dependencies.items) |unknown_step| {
        try reifyOptions(unknown_step);
    }
}

const Packages = struct {
    allocator: std.mem.Allocator,

    /// Outer key is the package name, inner key is the file path.
    packages: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .{},

    /// Returns true if the package was already present.
    pub fn addPackage(self: *Packages, name: []const u8, path: []const u8) !bool {
        const name_gop_result = try self.packages.getOrPut(self.allocator, name);
        if (!name_gop_result.found_existing) {
            name_gop_result.value_ptr.* = .{};
        }

        const path_gop_result = try name_gop_result.value_ptr.getOrPut(self.allocator, path);
        return path_gop_result.found_existing;
    }

    pub fn toPackageList(self: *Packages) ![]BuildConfig.Pkg {
        var result: std.ArrayListUnmanaged(BuildConfig.Pkg) = .{};
        errdefer result.deinit(self.allocator);

        var name_iter = self.packages.iterator();
        while (name_iter.next()) |path_hashmap| {
            var path_iter = path_hashmap.value_ptr.iterator();
            while (path_iter.next()) |path| {
                try result.append(self.allocator, .{ .name = path_hashmap.key_ptr.*, .path = path.key_ptr.* });
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    pub fn deinit(self: *Packages) void {
        var outer_iter = self.packages.iterator();
        while (outer_iter.next()) |inner| {
            inner.value_ptr.deinit(self.allocator);
        }
        self.packages.deinit(self.allocator);
    }
};

fn processStep(
    builder: *std.Build,
    packages: *Packages,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    step: *Build.Step,
) anyerror!void {
    if (step.cast(Build.Step.InstallArtifact)) |install_exe| {
        if (install_exe.artifact.root_src) |src| {
            _ = try packages.addPackage("root", src.getPath(builder));
        }
        try processIncludeDirs(builder, include_dirs, install_exe.artifact.include_dirs.items);
        try processPkgConfig(builder.allocator, include_dirs, install_exe.artifact);
        try processModules(builder, packages, install_exe.artifact.modules);
    } else if (step.cast(Build.Step.Compile)) |exe| {
        if (exe.root_src) |src| {
            _ = try packages.addPackage("root", src.getPath(builder));
        }
        try processIncludeDirs(builder, include_dirs, exe.include_dirs.items);
        try processPkgConfig(builder.allocator, include_dirs, exe);
        try processModules(builder, packages, exe.modules);
    } else {
        for (step.dependencies.items) |unknown_step| {
            try processStep(builder, packages, include_dirs, unknown_step);
        }
    }
}

fn processModules(
    builder: *Build,
    packages: *Packages,
    modules: std.StringArrayHashMap(*Build.Module),
) !void {
    for (modules.keys(), modules.values()) |name, mod| {
        const path = mod.builder.pathFromRoot(mod.source_file.getPath(mod.builder));

        const already_added = try packages.addPackage(name, path);
        // if the package has already been added short circuit here or recursive modules will ruin us
        if (already_added) continue;

        try processModules(builder, packages, mod.dependencies);
    }
}

fn processIncludeDirs(
    builder: *Build,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    dirs: []Build.Step.Compile.IncludeDir,
) !void {
    try include_dirs.ensureUnusedCapacity(builder.allocator, dirs.len);

    for (dirs) |dir| {
        const candidate: []const u8 = switch (dir) {
            .path => |path| path.getPath(builder),
            .path_system => |path| path.getPath(builder),
            else => continue,
        };

        include_dirs.putAssumeCapacity(candidate, {});
    }
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *Build.Step.Compile,
) !void {
    for (exe.link_objects.items) |link_object| {
        if (link_object != .system_lib) continue;
        const system_lib = link_object.system_lib;

        if (system_lib.use_pkg_config == .no) continue;

        getPkgConfigIncludes(allocator, include_dirs, exe, system_lib.name) catch |err| switch (err) {
            error.PkgConfigInvalidOutput,
            error.PkgConfigCrashed,
            error.PkgConfigFailed,
            error.PkgConfigNotInstalled,
            error.PackageNotFound,
            => switch (system_lib.use_pkg_config) {
                .yes => {
                    // pkg-config failed, so zig will not add any include paths
                },
                .force => {
                    std.log.warn("pkg-config failed for library {s}", .{system_lib.name});
                },
                .no => unreachable,
            },
            else => |e| return e,
        };
    }
}

fn getPkgConfigIncludes(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *Build.Step.Compile,
    name: []const u8,
) !void {
    if (copied_from_zig.runPkgConfig(exe, name)) |args| {
        for (args) |arg| {
            if (std.mem.startsWith(u8, arg, "-I")) {
                const candidate = arg[2..];
                try include_dirs.put(allocator, candidate, {});
            }
        }
    } else |err| return err;
}

// TODO: Having a copy of this is not very nice
const copied_from_zig = struct {
    fn runPkgConfig(self: *Build.Step.Compile, lib_name: []const u8) ![]const []const u8 {
        const b = self.step.owner;
        const pkg_name = match: {
            // First we have to map the library name to pkg config name. Unfortunately,
            // there are several examples where this is not straightforward:
            // -lSDL2 -> pkg-config sdl2
            // -lgdk-3 -> pkg-config gdk-3.0
            // -latk-1.0 -> pkg-config atk
            const pkgs = try getPkgConfigList(b);

            // Exact match means instant winner.
            for (pkgs) |pkg| {
                if (std.mem.eql(u8, pkg.name, lib_name)) {
                    break :match pkg.name;
                }
            }

            // Next we'll try ignoring case.
            for (pkgs) |pkg| {
                if (std.ascii.eqlIgnoreCase(pkg.name, lib_name)) {
                    break :match pkg.name;
                }
            }

            // Now try appending ".0".
            for (pkgs) |pkg| {
                if (std.ascii.indexOfIgnoreCase(pkg.name, lib_name)) |pos| {
                    if (pos != 0) continue;
                    if (std.mem.eql(u8, pkg.name[lib_name.len..], ".0")) {
                        break :match pkg.name;
                    }
                }
            }

            // Trimming "-1.0".
            if (std.mem.endsWith(u8, lib_name, "-1.0")) {
                const trimmed_lib_name = lib_name[0 .. lib_name.len - "-1.0".len];
                for (pkgs) |pkg| {
                    if (std.ascii.eqlIgnoreCase(pkg.name, trimmed_lib_name)) {
                        break :match pkg.name;
                    }
                }
            }

            return error.PackageNotFound;
        };

        var code: u8 = undefined;
        const stdout = if (b.execAllowFail(&[_][]const u8{
            "pkg-config",
            pkg_name,
            "--cflags",
            "--libs",
        }, &code, .Ignore)) |stdout| stdout else |err| switch (err) {
            error.ProcessTerminated => return error.PkgConfigCrashed,
            error.ExecNotSupported => return error.PkgConfigFailed,
            error.ExitCodeFailure => return error.PkgConfigFailed,
            error.FileNotFound => return error.PkgConfigNotInstalled,
            else => return err,
        };

        var zig_args = std.ArrayList([]const u8).init(b.allocator);
        defer zig_args.deinit();

        var it = std.mem.tokenize(u8, stdout, " \r\n\t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "-I")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-I", dir });
            } else if (std.mem.startsWith(u8, tok, "-I")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-L")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-L", dir });
            } else if (std.mem.startsWith(u8, tok, "-L")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-l")) {
                const lib = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-l", lib });
            } else if (std.mem.startsWith(u8, tok, "-l")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-D")) {
                const macro = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-D", macro });
            } else if (std.mem.startsWith(u8, tok, "-D")) {
                try zig_args.append(tok);
            } else if (b.debug_pkg_config) {
                return self.step.fail("unknown pkg-config flag '{s}'", .{tok});
            }
        }

        return zig_args.toOwnedSlice();
    }

    fn execPkgConfigList(self: *std.Build, out_code: *u8) (PkgConfigError || ExecError)![]const PkgConfigPkg {
        const stdout = try self.execAllowFail(&[_][]const u8{ "pkg-config", "--list-all" }, out_code, .Ignore);
        var list = std.ArrayList(PkgConfigPkg).init(self.allocator);
        errdefer list.deinit();
        var line_it = std.mem.tokenize(u8, stdout, "\r\n");
        while (line_it.next()) |line| {
            if (std.mem.trim(u8, line, " \t").len == 0) continue;
            var tok_it = std.mem.tokenize(u8, line, " \t");
            try list.append(PkgConfigPkg{
                .name = tok_it.next() orelse return error.PkgConfigInvalidOutput,
                .desc = tok_it.rest(),
            });
        }
        return list.toOwnedSlice();
    }

    fn getPkgConfigList(self: *std.Build) ![]const PkgConfigPkg {
        if (self.pkg_config_pkg_list) |res| {
            return res;
        }
        var code: u8 = undefined;
        if (execPkgConfigList(self, &code)) |list| {
            self.pkg_config_pkg_list = list;
            return list;
        } else |err| {
            const result = switch (err) {
                error.ProcessTerminated => error.PkgConfigCrashed,
                error.ExecNotSupported => error.PkgConfigFailed,
                error.ExitCodeFailure => error.PkgConfigFailed,
                error.FileNotFound => error.PkgConfigNotInstalled,
                error.InvalidName => error.PkgConfigNotInstalled,
                error.PkgConfigInvalidOutput => error.PkgConfigInvalidOutput,
                else => return err,
            };
            self.pkg_config_pkg_list = result;
            return result;
        }
    }

    pub const ExecError = std.Build.ExecError;
    pub const PkgConfigError = std.Build.PkgConfigError;
    pub const PkgConfigPkg = std.Build.PkgConfigPkg;
};
