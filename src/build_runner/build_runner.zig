//! PLEASE READ THE FOLLOWING MESSAGE BEFORE EDITING THIS FILE:
//!
//! This build runner is targeting compatibility with the following Zig versions:
//!   - 0.15.1 or later
//!
//! Handling multiple Zig versions can be achieved with one of the following strategies:
//!   - use `@hasDecl` or `@hasField` (recommended)
//!   - use `builtin.zig_version`
//!
//! You can test out the build runner on ZLS's `build.zig` with the following command:
//! `zig build --build-runner src/build_runner/build_runner.zig`
//!
//! You can also test the build runner on any other `build.zig` with the following command:
//! `zig build --build-file /path/to/build.zig --build-runner /path/to/zls/src/build_runner/build_runner.zig`
//! `zig build --build-runner /path/to/zls/src/build_runner/build_runner.zig` (if the cwd contains build.zig)
//!

const root = @import("@build");
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const process = std.process;
const ArrayListManaged = if (@hasDecl(std, "array_list")) std.array_list.Managed else std.ArrayList;
const ArrayList = if (@hasDecl(std, "array_list")) std.ArrayList else std.ArrayList;
const Step = std.Build.Step;
const Allocator = std.mem.Allocator;

pub const dependencies = @import("@dependencies");

///! This is a modified build runner to extract information out of build.zig
///! Modified version of lib/build_runner.zig
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

    const args = try process.argsAlloc(arena);

    // skip my own exe name
    var arg_idx: usize = 1;

    const zig_exe = nextArg(args, &arg_idx) orelse fatal("missing zig compiler path", .{});
    const zig_lib_dir = nextArg(args, &arg_idx) orelse fatal("missing zig lib directory path", .{});
    const build_root = nextArg(args, &arg_idx) orelse fatal("missing build root directory path", .{});
    const cache_root = nextArg(args, &arg_idx) orelse fatal("missing cache root directory path", .{});
    const global_cache_root = nextArg(args, &arg_idx) orelse fatal("missing global cache root directory path", .{});

    const zig_lib_directory: std.Build.Cache.Directory = .{
        .path = zig_lib_dir,
        .handle = try std.fs.cwd().openDir(zig_lib_dir, .{}),
    };

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

    var graph = structInitIgnoreUnknown(std.Build.Graph, .{
        .arena = arena,
        .cache = .{
            .gpa = arena,
            .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
        },
        .zig_exe = zig_exe,
        .env_map = try process.getEnvMap(arena),
        .global_cache_root = global_cache_directory,
        .zig_lib_directory = zig_lib_directory,
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolveTargetQuery(.{}),
        },
        .time_report = false,
    });

    graph.cache.addPrefix(.{ .path = null, .handle = std.fs.cwd() });
    graph.cache.addPrefix(build_root_directory);
    graph.cache.addPrefix(local_cache_directory);
    graph.cache.addPrefix(global_cache_directory);
    graph.cache.hash.addBytes(builtin.zig_version_string);

    const builder = try std.Build.create(
        &graph,
        build_root_directory,
        local_cache_directory,
        dependencies.root_deps,
    );

    var targets = ArrayListManaged([]const u8).init(arena);
    var debug_log_scopes = ArrayListManaged([]const u8).init(arena);
    var thread_pool_options: std.Thread.Pool.Options = .{ .allocator = arena };

    var install_prefix: ?[]const u8 = null;
    var dir_list: std.Build.DirList = .{};
    var max_rss: u64 = 0;
    var skip_oom_steps = false;
    var seed: u32 = 0;
    var output_tmp_nonce: ?[16]u8 = null;
    var debounce_interval_ms: u16 = 50;
    var watch = false;
    var check_step_only = false;

    while (nextArg(args, &arg_idx)) |arg| {
        if (mem.startsWith(u8, arg, "-Z")) {
            if (arg.len != 18) fatal("bad argument: '{s}'", .{arg});
            output_tmp_nonce = arg[2..18].*;
        } else if (mem.startsWith(u8, arg, "-D")) {
            const option_contents = arg[2..];
            if (option_contents.len == 0)
                fatal("expected option name after '-D'", .{});
            if (mem.indexOfScalar(u8, option_contents, '=')) |name_end| {
                const option_name = option_contents[0..name_end];
                const option_value = option_contents[name_end + 1 ..];
                if (try builder.addUserInputOption(option_name, option_value))
                    fatal("  access the help menu with 'zig build -h'", .{});
            } else {
                if (try builder.addUserInputFlag(option_contents))
                    fatal("  access the help menu with 'zig build -h'", .{});
            }
        } else if (mem.startsWith(u8, arg, "-")) {
            if (mem.eql(u8, arg, "--verbose")) {
                builder.verbose = true;
            } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                fatal("argument '{s}' is not available", .{arg});
            } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--prefix")) {
                install_prefix = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "-l") or mem.eql(u8, arg, "--list-steps")) {
                fatal("argument '{s}' is not available", .{arg});
            } else if (mem.startsWith(u8, arg, "-fsys=")) {
                const name = arg["-fsys=".len..];
                graph.system_library_options.put(arena, name, .user_enabled) catch @panic("OOM");
            } else if (mem.startsWith(u8, arg, "-fno-sys=")) {
                const name = arg["-fno-sys=".len..];
                graph.system_library_options.put(arena, name, .user_disabled) catch @panic("OOM");
            } else if (mem.eql(u8, arg, "--release")) {
                builder.release_mode = .any;
            } else if (mem.startsWith(u8, arg, "--release=")) {
                const text = arg["--release=".len..];
                builder.release_mode = std.meta.stringToEnum(std.Build.ReleaseMode, text) orelse {
                    fatal("expected [off|any|fast|safe|small] in '{s}', found '{s}'", .{
                        arg, text,
                    });
                };
            } else if (mem.eql(u8, arg, "--prefix-lib-dir")) {
                dir_list.lib_dir = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--prefix-exe-dir")) {
                dir_list.exe_dir = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--prefix-include-dir")) {
                dir_list.include_dir = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--sysroot")) {
                builder.sysroot = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--maxrss")) {
                const max_rss_text = nextArgOrFatal(args, &arg_idx);
                max_rss = std.fmt.parseIntSizeSuffix(max_rss_text, 10) catch |err| {
                    std.debug.print("invalid byte size: '{s}': {s}\n", .{
                        max_rss_text, @errorName(err),
                    });
                    process.exit(1);
                };
            } else if (mem.eql(u8, arg, "--skip-oom-steps")) {
                skip_oom_steps = true;
            } else if (mem.eql(u8, arg, "--search-prefix")) {
                const search_prefix = nextArgOrFatal(args, &arg_idx);
                builder.addSearchPrefix(search_prefix);
            } else if (mem.eql(u8, arg, "--libc")) {
                builder.libc_file = nextArgOrFatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--color")) {
                const next_arg = nextArg(args, &arg_idx) orelse
                    fatal("expected [auto|on|off] after '{s}'", .{arg});
                _ = next_arg;
            } else if (mem.eql(u8, arg, "--summary")) {
                const next_arg = nextArg(args, &arg_idx) orelse
                    fatal("expected [all|new|failures|none] after '{s}'", .{arg});
                _ = next_arg;
            } else if (mem.eql(u8, arg, "--seed")) {
                const next_arg = nextArg(args, &arg_idx) orelse
                    fatal("expected u32 after '{s}'", .{arg});
                seed = std.fmt.parseUnsigned(u32, next_arg, 0) catch |err| {
                    fatal("unable to parse seed '{s}' as unsigned 32-bit integer: {s}\n", .{
                        next_arg, @errorName(err),
                    });
                };
            } else if (mem.eql(u8, arg, "--debounce")) {
                const next_arg = nextArg(args, &arg_idx) orelse
                    fatal("expected u16 after '{s}'", .{arg});
                debounce_interval_ms = std.fmt.parseUnsigned(u16, next_arg, 0) catch |err| {
                    fatal("unable to parse debounce interval '{s}' as unsigned 16-bit integer: {s}\n", .{
                        next_arg, @errorName(err),
                    });
                };
            } else if (mem.eql(u8, arg, "--debug-log")) {
                const next_arg = nextArgOrFatal(args, &arg_idx);
                try debug_log_scopes.append(next_arg);
            } else if (mem.eql(u8, arg, "--debug-pkg-config")) {
                builder.debug_pkg_config = true;
            } else if (mem.eql(u8, arg, "--debug-compile-errors")) {
                builder.debug_compile_errors = true;
            } else if (mem.eql(u8, arg, "--system")) {
                // The usage text shows another argument after this parameter
                // but it is handled by the parent process. The build runner
                // only sees this flag.
                graph.system_package_mode = true;
            } else if (mem.eql(u8, arg, "--libc-runtimes") or mem.eql(u8, arg, "--glibc-runtimes")) {
                if (@hasField(std.Build, "glibc_runtimes_dir")) {
                    builder.glibc_runtimes_dir = nextArgOrFatal(args, &arg_idx);
                } else {
                    builder.libc_runtimes_dir = nextArgOrFatal(args, &arg_idx);
                }
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
            } else if (mem.eql(u8, arg, "--prominent-compile-errors")) {
                // prominent_compile_errors = true;
            } else if (mem.eql(u8, arg, "--watch")) {
                watch = true;
            } else if (mem.eql(u8, arg, "--check-only")) { // ZLS only
                check_step_only = true;
            } else if (mem.eql(u8, arg, "-fincremental")) {
                graph.incremental = true;
            } else if (mem.eql(u8, arg, "-fno-incremental")) {
                graph.incremental = false;
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
                fatal("unrecognized argument: '{s}'", .{arg});
            }
        } else {
            try targets.append(arg);
        }
    }

    const main_progress_node = std.Progress.start(.{
        .disable_printing = true,
    });
    defer main_progress_node.end();

    builder.debug_log_scopes = debug_log_scopes.items;
    builder.resolveInstallPrefix(install_prefix, dir_list);
    {
        var prog_node = main_progress_node.start("Configure", 0);
        defer prog_node.end();
        try builder.runBuild(root);
        createModuleDependencies(builder) catch @panic("OOM");
    }

    if (graph.needed_lazy_dependencies.entries.len != 0) {
        var buffer: ArrayList(u8) = .{};
        for (graph.needed_lazy_dependencies.keys()) |k| {
            try buffer.appendSlice(arena, k);
            try buffer.append(arena, '\n');
        }
        const s = std.fs.path.sep_str;
        const tmp_sub_path = "tmp" ++ s ++ (output_tmp_nonce orelse fatal("missing -Z arg", .{}));

        std.fs.Dir.writeFile(local_cache_directory.handle, .{
            .sub_path = tmp_sub_path,
            .data = buffer.items,
            .flags = .{ .exclusive = true },
        }) catch |err| {
            fatal("unable to write configuration results to '{f}{s}': {}", .{
                local_cache_directory, tmp_sub_path, err,
            });
        };

        process.exit(3); // Indicate configure phase failed with meaningful stdout.
    }

    if (builder.validateUserInputDidItFail()) {
        fatal("  access the help menu with 'zig build -h'", .{});
    }

    validateSystemLibraryOptions(builder);

    var run: Run = .{
        .max_rss = max_rss,
        .max_rss_is_default = false,
        .max_rss_mutex = .{},
        .skip_oom_steps = skip_oom_steps,
        .memory_blocked_steps = .init(arena),
        .thread_pool = undefined, // set below

        .claimed_rss = 0,

        .watch = watch,
        .cycle = 0,
    };

    if (run.max_rss == 0) {
        run.max_rss = process.totalSystemMemory() catch std.math.maxInt(u64);
        run.max_rss_is_default = true;
    }

    try run.thread_pool.init(thread_pool_options);
    defer run.thread_pool.deinit();

    if (!watch) {
        try extractBuildInformation(
            arena,
            builder,
            arena,
            main_progress_node,
            &run,
            seed,
        );
        return;
    }

    var w = try Watch.init();

    const message_thread = try std.Thread.spawn(.{}, struct {
        fn do(ww: *Watch) void {
            while (true) {
                var buffer: [1]u8 = undefined;
                var file_reader = std.fs.File.stdin().reader(&buffer);
                const reader = &file_reader.interface;
                const byte = reader.takeByte() catch |err| switch (err) {
                    error.EndOfStream => process.exit(0),
                    else => process.exit(1),
                };
                switch (byte) {
                    '\x00' => ww.trigger(),
                    else => process.exit(1),
                }
            }
        }
    }.do, .{&w});
    message_thread.detach();

    const gpa = arena;

    var step_stack = try stepNamesToStepStack(gpa, builder, targets.items, check_step_only);
    if (step_stack.count() == 0) {
        // This means that `enable_build_on_save == null` and the project contains no "check" step.
        return;
    }

    prepare(gpa, builder, &step_stack, &run, seed) catch |err| switch (err) {
        error.UncleanExit => process.exit(1),
        else => return err,
    };

    rebuild: while (true) : (run.cycle += 1) {
        runSteps(
            gpa,
            builder,
            &step_stack,
            main_progress_node,
            &run,
        ) catch |err| switch (err) {
            error.UncleanExit => process.exit(1),
            else => return err,
        };

        try w.update(gpa, step_stack.keys());

        // Wait until a file system notification arrives. Read all such events
        // until the buffer is empty. Then wait for a debounce interval, resetting
        // if any more events come in. After the debounce interval has passed,
        // trigger a rebuild on all steps with modified inputs, as well as their
        // recursive dependants.
        var debounce_timeout: std.Build.Watch.Timeout = .none;
        while (true) switch (try w.wait(gpa, debounce_timeout)) {
            .timeout => {
                markFailedStepsDirty(gpa, step_stack.keys());
                continue :rebuild;
            },
            .dirty => if (debounce_timeout == .none) {
                debounce_timeout = .{ .ms = debounce_interval_ms };
            },
            .clean => {},
        };
    }
}

fn markFailedStepsDirty(gpa: Allocator, all_steps: []const *Step) void {
    for (all_steps) |step| switch (step.state) {
        .dependency_failure, .failure, .skipped => step.recursiveReset(gpa),
        else => continue,
    };
    // Now that all dirty steps have been found, the remaining steps that
    // succeeded from last run shall be marked "cached".
    for (all_steps) |step| switch (step.state) {
        .success => step.result_cached = true,
        else => continue,
    };
}

/// A wrapper around `std.Build.Watch` that supports manually triggering recompilations.
const Watch = struct {
    fs_watch: std.Build.Watch,
    supports_fs_watch: bool,
    manual_event: std.Thread.ResetEvent,
    steps: []const *Step,

    fn init() !Watch {
        return .{
            .fs_watch = if (@TypeOf(std.Build.Watch) != void) try std.Build.Watch.init() else {},
            .supports_fs_watch = @TypeOf(std.Build.Watch) != void and shared.BuildOnSaveSupport.isSupportedRuntime(builtin.zig_version) == .supported,
            .manual_event = .{},
            .steps = &.{},
        };
    }

    fn update(w: *Watch, gpa: Allocator, steps: []const *Step) !void {
        if (@TypeOf(std.Build.Watch) != void and w.supports_fs_watch) {
            return try w.fs_watch.update(gpa, steps);
        }
        w.steps = steps;
    }

    fn trigger(w: *Watch) void {
        if (w.supports_fs_watch) {
            @panic("received manualy filesystem event even though std.Build.Watch is supported");
        }
        w.manual_event.set();
    }

    fn wait(w: *Watch, gpa: Allocator, timeout: std.Build.Watch.Timeout) !std.Build.Watch.WaitResult {
        if (@TypeOf(std.Build.Watch) != void and w.supports_fs_watch) {
            return try w.fs_watch.wait(gpa, timeout);
        }
        switch (timeout) {
            .none => w.manual_event.wait(),
            .ms => |ms| w.manual_event.timedWait(@as(u64, ms) * std.time.ns_per_ms) catch return .timeout,
        }
        w.manual_event.reset();
        markStepsDirty(gpa, w.steps);
        return .dirty;
    }

    fn markStepsDirty(gpa: Allocator, all_steps: []const *Step) void {
        for (all_steps) |step| switch (step.state) {
            .precheck_done => continue,
            else => step.recursiveReset(gpa),
        };
    }
};

const Run = struct {
    max_rss: u64,
    max_rss_is_default: bool,
    max_rss_mutex: std.Thread.Mutex,
    skip_oom_steps: bool,
    memory_blocked_steps: ArrayListManaged(*Step),
    thread_pool: std.Thread.Pool,

    claimed_rss: usize,

    watch: bool,
    cycle: u32,
};

fn stepNamesToStepStack(
    gpa: Allocator,
    b: *std.Build,
    step_names: []const []const u8,
    check_step_only: bool,
) !std.AutoArrayHashMapUnmanaged(*Step, void) {
    var step_stack: std.AutoArrayHashMapUnmanaged(*Step, void) = .{};
    errdefer step_stack.deinit(gpa);

    if (step_names.len == 0) {
        if (b.top_level_steps.get("check")) |tls| {
            try step_stack.put(gpa, &tls.step, {});
        } else if (!check_step_only) {
            try step_stack.put(gpa, b.default_step, {});
        }
    } else {
        try step_stack.ensureUnusedCapacity(gpa, step_names.len);
        for (0..step_names.len) |i| {
            const step_name = step_names[step_names.len - i - 1];
            const s = b.top_level_steps.get(step_name) orelse {
                std.debug.print("no step named '{s}'\n  access the help menu with 'zig build -h'\n", .{step_name});
                process.exit(1);
            };
            step_stack.putAssumeCapacity(&s.step, {});
        }
    }

    return step_stack;
}

fn prepare(
    gpa: Allocator,
    b: *std.Build,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
    run: *Run,
    seed: u32,
) error{ OutOfMemory, UncleanExit }!void {
    const starting_steps = try gpa.dupe(*Step, step_stack.keys());
    defer gpa.free(starting_steps);

    var rng = std.Random.DefaultPrng.init(seed);
    const rand = rng.random();
    rand.shuffle(*Step, starting_steps);

    for (starting_steps) |s| {
        constructGraphAndCheckForDependencyLoop(b, s, step_stack, rand) catch |err| switch (err) {
            error.DependencyLoopDetected => return uncleanExit(),
            else => |e| return e,
        };
    }

    {
        // Check that we have enough memory to complete the build.
        var any_problems = false;
        for (step_stack.keys()) |s| {
            if (s.max_rss == 0) continue;
            if (s.max_rss > run.max_rss) {
                if (run.skip_oom_steps) {
                    s.state = .skipped_oom;
                } else {
                    std.debug.print("{s}{s}: this step declares an upper bound of {d} bytes of memory, exceeding the available {d} bytes of memory\n", .{
                        s.owner.dep_prefix, s.name, s.max_rss, run.max_rss,
                    });
                    any_problems = true;
                }
            }
        }
        if (any_problems) {
            if (run.max_rss_is_default) {
                std.debug.print("note: use --maxrss to override the default", .{});
            }
            return uncleanExit();
        }
    }
}

fn runSteps(
    gpa: std.mem.Allocator,
    b: *std.Build,
    steps_stack: *const std.AutoArrayHashMapUnmanaged(*Step, void),
    parent_prog_node: std.Progress.Node,
    run: *Run,
) error{ OutOfMemory, UncleanExit }!void {
    const thread_pool = &run.thread_pool;
    const steps = steps_stack.keys();

    var step_prog = parent_prog_node.start("steps", steps.len);
    defer step_prog.end();

    var wait_group: std.Thread.WaitGroup = .{};
    defer wait_group.wait();

    // Here we spawn the initial set of tasks with a nice heuristic -
    // dependency order. Each worker when it finishes a step will then
    // check whether it should run any dependants.
    for (steps) |step| {
        if (step.state == .skipped_oom) continue;

        wait_group.start();
        thread_pool.spawn(workerMakeOneStep, .{
            &wait_group, gpa, b, steps_stack, step, step_prog, run,
        }) catch @panic("OOM");
    }

    if (run.watch) {
        for (steps) |step| {
            const step_id: u32 = @intCast(steps_stack.getIndex(step).?);
            // missing fields:
            // - result_error_msgs
            // - result_stderr
            serveWatchErrorBundle(step_id, run.cycle, step.result_error_bundle) catch @panic("failed to send watch errors");
        }
    }
}

/// Traverse the dependency graph depth-first and make it undirected by having
/// steps know their dependants (they only know dependencies at start).
/// Along the way, check that there is no dependency loop, and record the steps
/// in traversal order in `step_stack`.
/// Each step has its dependencies traversed in random order, this accomplishes
/// two things:
/// - `step_stack` will be in randomized-depth-first order, so the build runner
///   spawns steps in a random (but optimized) order
/// - each step's `dependants` list is also filled in a random order, so that
///   when it finishes executing in `workerMakeOneStep`, it spawns next steps
///   to run in random order
fn constructGraphAndCheckForDependencyLoop(
    b: *std.Build,
    s: *Step,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
    rand: std.Random,
) error{ OutOfMemory, DependencyLoopDetected }!void {
    switch (s.state) {
        .precheck_started => return error.DependencyLoopDetected,
        .precheck_unstarted => {
            s.state = .precheck_started;

            try step_stack.ensureUnusedCapacity(b.allocator, s.dependencies.items.len);

            // We dupe to avoid shuffling the steps in the summary, it depends
            // on s.dependencies' order.
            const deps = b.allocator.dupe(*Step, s.dependencies.items) catch @panic("OOM");
            rand.shuffle(*Step, deps);

            for (deps) |dep| {
                try step_stack.put(b.allocator, dep, {});
                try dep.dependants.append(b.allocator, s);
                try constructGraphAndCheckForDependencyLoop(b, dep, step_stack, rand);
            }

            s.state = .precheck_done;
        },
        .precheck_done => {},

        // These don't happen until we actually run the step graph.
        .dependency_failure,
        .running,
        .success,
        .failure,
        .skipped,
        .skipped_oom,
        => {},
    }
}

fn workerMakeOneStep(
    wg: *std.Thread.WaitGroup,
    gpa: std.mem.Allocator,
    b: *std.Build,
    steps_stack: *const std.AutoArrayHashMapUnmanaged(*Step, void),
    s: *Step,
    prog_node: std.Progress.Node,
    run: *Run,
) void {
    defer wg.finish();
    const thread_pool = &run.thread_pool;

    // First, check the conditions for running this step. If they are not met,
    // then we return without doing the step, relying on another worker to
    // queue this step up again when dependencies are met.
    for (s.dependencies.items) |dep| {
        switch (@atomicLoad(Step.State, &dep.state, .seq_cst)) {
            .success, .skipped => continue,
            .failure, .dependency_failure, .skipped_oom => {
                @atomicStore(Step.State, &s.state, .dependency_failure, .seq_cst);
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
        if (@cmpxchgStrong(Step.State, &s.state, .precheck_done, .running, .seq_cst, .seq_cst) != null) {
            // Another worker got the job.
            return;
        }
    }

    var sub_prog_node = prog_node.start(s.name, 0);
    defer sub_prog_node.end();

    const make_result = s.make(structInitIgnoreUnknown(std.Build.Step.MakeOptions, .{
        .progress_node = sub_prog_node,
        .thread_pool = thread_pool,
        .watch = true,
        .gpa = gpa,
        .web_server = null,
    }));

    if (run.watch) {
        const step_id: u32 = @intCast(steps_stack.getIndex(s).?);
        // missing fields:
        // - result_error_msgs
        // - result_stderr
        serveWatchErrorBundle(step_id, run.cycle, s.result_error_bundle) catch @panic("failed to send watch errors");
    }

    handle_result: {
        if (make_result) |_| {
            @atomicStore(Step.State, &s.state, .success, .seq_cst);
        } else |err| switch (err) {
            error.MakeFailed => {
                @atomicStore(Step.State, &s.state, .failure, .seq_cst);
                break :handle_result;
            },
            error.MakeSkipped => @atomicStore(Step.State, &s.state, .skipped, .seq_cst),
        }

        // Successful completion of a step, so we queue up its dependants as well.
        for (s.dependants.items) |dep| {
            wg.start();
            thread_pool.spawn(workerMakeOneStep, .{
                wg, gpa, b, steps_stack, dep, prog_node, run,
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
                    wg, gpa, b, steps_stack, dep, prog_node, run,
                }) catch @panic("OOM");
            } else {
                run.memory_blocked_steps.items[i] = dep;
                i += 1;
            }
        }
        run.memory_blocked_steps.shrinkRetainingCapacity(i);
    }
}

fn nextArg(args: []const [:0]const u8, idx: *usize) ?[:0]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

fn nextArgOrFatal(args: []const [:0]const u8, idx: *usize) [:0]const u8 {
    return nextArg(args, idx) orelse {
        std.debug.print("expected argument after '{s}'\n  access the help menu with 'zig build -h'\n", .{args[idx.* - 1]});
        process.exit(1);
    };
}

fn argsRest(args: []const [:0]const u8, idx: usize) ?[]const [:0]const u8 {
    if (idx >= args.len) return null;
    return args[idx..];
}

/// Perhaps in the future there could be an Advanced Options flag such as
/// --debug-build-runner-leaks which would make this function return instead of
/// calling exit.
fn cleanExit() void {
    std.debug.lockStdErr();
    process.exit(0);
}

/// Perhaps in the future there could be an Advanced Options flag such as
/// --debug-build-runner-leaks which would make this function return instead of
/// calling exit.
fn uncleanExit() error{UncleanExit} {
    std.debug.lockStdErr();
    process.exit(1);
}

fn fatal(comptime f: []const u8, args: anytype) noreturn {
    std.debug.print(f ++ "\n", args);
    process.exit(1);
}

fn validateSystemLibraryOptions(b: *std.Build) void {
    var bad = false;
    for (b.graph.system_library_options.keys(), b.graph.system_library_options.values()) |k, v| {
        switch (v) {
            .user_disabled, .user_enabled => {
                // The user tried to enable or disable a system library integration, but
                // the build script did not recognize that option.
                std.debug.print("system library name not recognized by build script: '{s}'\n", .{k});
                bad = true;
            },
            .declared_disabled, .declared_enabled => {},
        }
    }
    if (bad) {
        std.debug.print("  access the help menu with 'zig build -h'\n", .{});
        process.exit(1);
    }
}

/// Starting from all top-level steps in `b`, traverses the entire step graph
/// and adds all step dependencies implied by module graphs.
fn createModuleDependencies(b: *std.Build) Allocator.Error!void {
    const arena = b.graph.arena;

    var all_steps: std.AutoArrayHashMapUnmanaged(*Step, void) = .empty;
    var next_step_idx: usize = 0;

    try all_steps.ensureUnusedCapacity(arena, b.top_level_steps.count());
    for (b.top_level_steps.values()) |tls| {
        all_steps.putAssumeCapacityNoClobber(&tls.step, {});
    }

    while (next_step_idx < all_steps.count()) {
        const step = all_steps.keys()[next_step_idx];
        next_step_idx += 1;

        // Set up any implied dependencies for this step. It's important that we do this first, so
        // that the loop below discovers steps implied by the module graph.
        try createModuleDependenciesForStep(step);

        try all_steps.ensureUnusedCapacity(arena, step.dependencies.items.len);
        for (step.dependencies.items) |other_step| {
            all_steps.putAssumeCapacity(other_step, {});
        }
    }
}

/// If the given `Step` is a `Step.Compile`, adds any dependencies for that step which
/// are implied by the module graph rooted at `step.cast(Step.Compile).?.root_module`.
fn createModuleDependenciesForStep(step: *Step) Allocator.Error!void {
    const root_module = if (step.cast(Step.Compile)) |cs| root: {
        break :root cs.root_module;
    } else return; // not a compile step so no module dependencies

    // Starting from `root_module`, discover all modules in this graph.
    const modules = root_module.getGraph().modules;

    // For each of those modules, set up the implied step dependencies.
    for (modules) |mod| {
        if (mod.root_source_file) |lp| lp.addStepDependencies(step);
        for (mod.include_dirs.items) |include_dir| switch (include_dir) {
            .path,
            .path_system,
            .path_after,
            .framework_path,
            .framework_path_system,
            .embed_path,
            => |lp| lp.addStepDependencies(step),

            .other_step => |other| {
                other.getEmittedIncludeTree().addStepDependencies(step);
                step.dependOn(&other.step);
            },

            .config_header_step => |config_header| step.dependOn(&config_header.step),
        };
        for (mod.lib_paths.items) |lp| lp.addStepDependencies(step);
        for (mod.rpaths.items) |rpath| switch (rpath) {
            .lazy_path => |lp| lp.addStepDependencies(step),
            .special => {},
        };
        for (mod.link_objects.items) |link_object| switch (link_object) {
            .static_path,
            .assembly_file,
            => |lp| lp.addStepDependencies(step),
            .other_step => |other| step.dependOn(&other.step),
            .system_lib => {},
            .c_source_file => |source| source.file.addStepDependencies(step),
            .c_source_files => |source_files| source_files.root.addStepDependencies(step),
            .win32_resource_file => |rc_source| {
                rc_source.file.addStepDependencies(step);
                for (rc_source.include_paths) |lp| lp.addStepDependencies(step);
            },
        };
    }
}

//
//
// ZLS code
//
//

const shared = @import("shared.zig");
const Transport = shared.Transport;
const BuildConfig = shared.BuildConfig;

const Packages = struct {
    allocator: std.mem.Allocator,

    /// Outer key is the package name, inner key is the file path.
    packages: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .{},

    /// Returns true if the package was already present.
    pub fn addPackage(self: *Packages, name: []const u8, path: []const u8) !bool {
        const name_gop_result = try self.packages.getOrPutValue(self.allocator, name, .{});
        const path_gop_result = try name_gop_result.value_ptr.getOrPut(self.allocator, path);
        return path_gop_result.found_existing;
    }

    pub fn toPackageList(self: *Packages) ![]BuildConfig.Package {
        var result: ArrayList(BuildConfig.Package) = .{};
        errdefer result.deinit(self.allocator);

        const Context = struct {
            keys: [][]const u8,

            pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
            }
        };

        self.packages.sort(Context{ .keys = self.packages.keys() });

        for (self.packages.keys(), self.packages.values()) |name, path_hashmap| {
            for (path_hashmap.keys()) |path| {
                try result.append(self.allocator, .{ .name = name, .path = path });
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    pub fn deinit(self: *Packages) void {
        for (self.packages.values()) |*path_hashmap| {
            path_hashmap.deinit(self.allocator);
        }
        self.packages.deinit(self.allocator);
    }
};

fn extractBuildInformation(
    gpa: Allocator,
    b: *std.Build,
    arena: Allocator,
    main_progress_node: std.Progress.Node,
    run: *Run,
    seed: u32,
) !void {
    var steps = std.AutoArrayHashMapUnmanaged(*Step, void){};
    defer steps.deinit(gpa);

    // collect the set of all steps
    {
        var stack: ArrayList(*Step) = .{};
        defer stack.deinit(gpa);

        try stack.ensureUnusedCapacity(gpa, b.top_level_steps.count());
        for (b.top_level_steps.values()) |tls| {
            stack.appendAssumeCapacity(&tls.step);
        }

        while (stack.pop()) |step| {
            const gop = try steps.getOrPut(gpa, step);
            if (gop.found_existing) continue;

            try stack.appendSlice(gpa, step.dependencies.items);
        }
    }

    const helper = struct {
        fn addLazyPathStepDependencies(allocator: Allocator, set: *std.AutoArrayHashMapUnmanaged(*Step, void), lazy_path: std.Build.LazyPath) !void {
            switch (lazy_path) {
                .src_path, .cwd_relative, .dependency => {},
                .generated => |gen| try set.put(allocator, gen.file.step, {}),
            }
        }
        fn addIncludeDirStepDependencies(allocator: Allocator, set: *std.AutoArrayHashMapUnmanaged(*Step, void), include_dir: std.Build.Module.IncludeDir) !void {
            switch (include_dir) {
                .path,
                .path_system,
                .path_after,
                .framework_path,
                .framework_path_system,
                => |lazy_path| try addLazyPathStepDependencies(allocator, set, lazy_path),
                .other_step => |other| {
                    if (other.generated_h) |header| {
                        try set.put(allocator, header.step, {});
                    }
                    if (other.installed_headers_include_tree) |include_tree| {
                        try set.put(allocator, include_tree.generated_directory.step, {});
                    }
                },
                .embed_path => {
                    // This only affects C source files
                },
                .config_header_step => |config_header| try set.put(allocator, &config_header.step, {}),
            }
        }

        fn addModuleDependencies(allocator: Allocator, set: *std.AutoArrayHashMapUnmanaged(*Step, void), module: *std.Build.Module) !void {
            if (module.root_source_file) |root_source_file| {
                try addLazyPathStepDependencies(allocator, set, root_source_file);
            }

            for (module.import_table.values()) |import| {
                if (import.root_source_file) |root_source_file| {
                    try addLazyPathStepDependencies(allocator, set, root_source_file);
                }
            }

            for (module.include_dirs.items) |include_dir| {
                try addIncludeDirStepDependencies(allocator, set, include_dir);
            }
        }

        fn processItem(
            allocator: Allocator,
            module: *std.Build.Module,
            compile: ?*std.Build.Step.Compile,
            name: []const u8,
            packages: *Packages,
            include_dirs: *std.StringArrayHashMapUnmanaged(void),
            c_macros: *std.StringArrayHashMapUnmanaged(void),
        ) !void {
            if (module.root_source_file) |root_source_file| {
                _ = try packages.addPackage(name, root_source_file.getPath(module.owner));
            }

            if (compile) |exe| {
                try processPkgConfig(allocator, include_dirs, c_macros, exe);
            }

            try c_macros.ensureUnusedCapacity(allocator, module.c_macros.items.len);
            for (module.c_macros.items) |c_macro| {
                c_macros.putAssumeCapacity(c_macro, {});
            }

            for (module.include_dirs.items) |include_dir| {
                switch (include_dir) {
                    .path,
                    .path_system,
                    .path_after,
                    .framework_path,
                    .framework_path_system,
                    => |include_path| try include_dirs.put(allocator, include_path.getPath(module.owner), {}),

                    .other_step => |other| {
                        if (other.generated_h) |header| {
                            try include_dirs.put(
                                allocator,
                                std.fs.path.dirname(header.getPath()).?,
                                {},
                            );
                        }
                        if (other.installed_headers_include_tree) |include_tree| {
                            try include_dirs.put(
                                allocator,
                                include_tree.generated_directory.getPath(),
                                {},
                            );
                        }
                    },
                    .embed_path => {
                        // This only affects C source files
                    },
                    .config_header_step => |config_header| {
                        try include_dirs.put(
                            allocator,
                            config_header.generated_dir.getPath(),
                            {},
                        );
                    },
                }
            }
        }
    };

    var step_dependencies: std.AutoArrayHashMapUnmanaged(*Step, void) = .{};
    defer step_dependencies.deinit(gpa);

    // collect step dependencies
    {
        var modules: std.AutoArrayHashMapUnmanaged(*std.Build.Module, void) = .{};
        defer modules.deinit(gpa);

        // collect root modules of `Step.Compile`
        for (steps.keys()) |step| {
            const compile = step.cast(Step.Compile) orelse continue;
            const graph = compile.root_module.getGraph();
            try modules.ensureUnusedCapacity(gpa, graph.modules.len);
            for (graph.modules) |module| modules.putAssumeCapacity(module, {});
        }

        // collect public modules
        for (b.modules.values()) |root_module| {
            const graph = root_module.getGraph();
            try modules.ensureUnusedCapacity(gpa, graph.modules.len);
            for (graph.modules) |module| modules.putAssumeCapacity(module, {});
        }

        // collect all dependencies of all found modules
        for (modules.keys()) |module| {
            try helper.addModuleDependencies(gpa, &step_dependencies, module);
        }
    }

    prepare(gpa, b, &step_dependencies, run, seed) catch |err| switch (err) {
        error.UncleanExit => process.exit(1),
        else => return err,
    };

    // run all steps that are dependencies
    try runSteps(
        gpa,
        b,
        &step_dependencies,
        main_progress_node,
        run,
    );

    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};
    defer include_dirs.deinit(gpa);

    var c_macros: std.StringArrayHashMapUnmanaged(void) = .{};
    defer c_macros.deinit(gpa);

    var packages: Packages = .{ .allocator = gpa };
    defer packages.deinit();

    // extract packages and include paths
    {
        for (steps.keys()) |step| {
            const compile = step.cast(Step.Compile) orelse continue;
            const graph = compile.root_module.getGraph();
            try helper.processItem(gpa, compile.root_module, compile, "root", &packages, &include_dirs, &c_macros);
            for (graph.modules) |module| {
                for (module.import_table.keys(), module.import_table.values()) |name, import| {
                    try helper.processItem(gpa, import, null, name, &packages, &include_dirs, &c_macros);
                }
            }
        }

        for (b.modules.values()) |root_module| {
            const graph = root_module.getGraph();
            try helper.processItem(gpa, root_module, null, "root", &packages, &include_dirs, &c_macros);
            for (graph.modules) |module| {
                for (module.import_table.keys(), module.import_table.values()) |name, import| {
                    try helper.processItem(gpa, import, null, name, &packages, &include_dirs, &c_macros);
                }
            }
        }
    }

    // Sample `@dependencies` structure:
    // pub const packages = struct {
    //     pub const @"1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5" = struct {
    //         pub const build_root = "/home/rad/.cache/zig/p/1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5";
    //         pub const build_zig = @import("1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5");
    //         pub const deps: []const struct { []const u8, []const u8 } = &.{};
    //     };
    // ...
    // };
    // pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    //     .{ "known_folders", "1220bb12c9bfe291eed1afe6a2070c7c39918ab1979f24a281bba39dfb23f5bcd544" },
    //     .{ "diffz", "122089a8247a693cad53beb161bde6c30f71376cd4298798d45b32740c3581405864" },
    // };

    var deps_build_roots: ArrayList(BuildConfig.DepsBuildRoots) = .{};
    for (dependencies.root_deps) |root_dep| {
        inline for (comptime std.meta.declarations(dependencies.packages)) |package| blk: {
            if (std.mem.eql(u8, package.name, root_dep[1])) {
                const package_info = @field(dependencies.packages, package.name);
                if (!@hasDecl(package_info, "build_root")) break :blk;
                if (!@hasDecl(package_info, "build_zig")) break :blk;
                try deps_build_roots.append(arena, .{
                    .name = root_dep[0],
                    .path = try std.fs.path.join(arena, &.{ package_info.build_root, "build.zig" }),
                });
            }
        }
    }

    var available_options: std.json.ArrayHashMap(BuildConfig.AvailableOption) = .{};
    try available_options.map.ensureTotalCapacity(arena, b.available_options_map.count());

    var it = b.available_options_map.iterator();
    while (it.next()) |available_option| {
        available_options.map.putAssumeCapacityNoClobber(available_option.key_ptr.*, available_option.value_ptr.*);
    }

    const stringifyValueAlloc = if (@hasDecl(std.json, "Stringify")) std.json.Stringify.valueAlloc else std.json.stringifyAlloc;

    const stringified_build_config = try stringifyValueAlloc(
        gpa,
        BuildConfig{
            .deps_build_roots = deps_build_roots.items,
            .packages = try packages.toPackageList(),
            .include_dirs = include_dirs.keys(),
            .top_level_steps = b.top_level_steps.keys(),
            .available_options = available_options,
            .c_macros = c_macros.keys(),
        },
        .{ .whitespace = .indent_2 },
    );

    var file_writer = std.fs.File.stdout().writer(&.{});
    file_writer.interface.writeAll(stringified_build_config) catch return file_writer.err.?;
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    c_macros: *std.StringArrayHashMapUnmanaged(void),
    exe: *Step.Compile,
) !void {
    for (exe.root_module.link_objects.items) |link_object| {
        if (link_object != .system_lib) continue;
        const system_lib = link_object.system_lib;

        if (system_lib.use_pkg_config == .no) continue;

        const args = copied_from_zig.runPkgConfig(exe, system_lib.name) catch |err| switch (err) {
            error.PkgConfigInvalidOutput,
            error.PkgConfigCrashed,
            error.PkgConfigFailed,
            error.PkgConfigNotInstalled,
            error.PackageNotFound,
            => switch (system_lib.use_pkg_config) {
                .yes => {
                    // pkg-config failed, so zig will not add any include paths
                    continue;
                },
                .force => {
                    std.log.warn("pkg-config failed for library {s}", .{system_lib.name});
                    continue;
                },
                .no => unreachable,
            },
            else => |e| return e,
        };
        for (args) |arg| {
            if (std.mem.startsWith(u8, arg, "-I")) {
                const candidate = arg[2..];
                try include_dirs.put(allocator, candidate, {});
            } else if (std.mem.startsWith(u8, arg, "-D")) {
                try c_macros.put(allocator, arg, {});
            }
        }
    }
}

// TODO: Having a copy of this is not very nice
const copied_from_zig = struct {
    /// Run pkg-config for the given library name and parse the output, returning the arguments
    /// that should be passed to zig to link the given library.
    fn runPkgConfig(self: *Step.Compile, lib_name: []const u8) ![]const []const u8 {
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
                if (mem.eql(u8, pkg.name, lib_name)) {
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
                    if (mem.eql(u8, pkg.name[lib_name.len..], ".0")) {
                        break :match pkg.name;
                    }
                }
            }

            // Trimming "-1.0".
            if (mem.endsWith(u8, lib_name, "-1.0")) {
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
        const stdout = if (b.runAllowFail(&.{
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

        var zig_args = ArrayListManaged([]const u8).init(b.allocator);
        defer zig_args.deinit();

        var it = mem.tokenizeAny(u8, stdout, " \r\n\t");
        while (it.next()) |tok| {
            if (mem.eql(u8, tok, "-I")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&.{ "-I", dir });
            } else if (mem.startsWith(u8, tok, "-I")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-L")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&.{ "-L", dir });
            } else if (mem.startsWith(u8, tok, "-L")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-l")) {
                const lib = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&.{ "-l", lib });
            } else if (mem.startsWith(u8, tok, "-l")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-D")) {
                const macro = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&.{ "-D", macro });
            } else if (mem.startsWith(u8, tok, "-D")) {
                try zig_args.append(tok);
            } else if (b.debug_pkg_config) {
                return self.step.fail("unknown pkg-config flag '{s}'", .{tok});
            }
        }

        return zig_args.toOwnedSlice();
    }

    fn execPkgConfigList(self: *std.Build, out_code: *u8) (std.Build.PkgConfigError || std.Build.RunError)![]const std.Build.PkgConfigPkg {
        const stdout = try self.runAllowFail(&.{ "pkg-config", "--list-all" }, out_code, .Ignore);
        var list = ArrayListManaged(std.Build.PkgConfigPkg).init(self.allocator);
        errdefer list.deinit();
        var line_it = mem.tokenizeAny(u8, stdout, "\r\n");
        while (line_it.next()) |line| {
            if (mem.trim(u8, line, " \t").len == 0) continue;
            var tok_it = mem.tokenizeAny(u8, line, " \t");
            try list.append(.{
                .name = tok_it.next() orelse return error.PkgConfigInvalidOutput,
                .desc = tok_it.rest(),
            });
        }
        return list.toOwnedSlice();
    }

    fn getPkgConfigList(self: *std.Build) ![]const std.Build.PkgConfigPkg {
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
};

fn serveWatchErrorBundle(
    step_id: u32,
    cycle: u32,
    error_bundle: std.zig.ErrorBundle,
) std.posix.WriteError!void {
    const bytes_len = @sizeOf(shared.ServerToClient.ErrorBundle) + @sizeOf(u32) * error_bundle.extra.len + error_bundle.string_bytes.len;

    var header: shared.ServerToClient.Header = .{
        .tag = .watch_error_bundle,
        .bytes_len = @intCast(bytes_len),
    };

    var error_bundle_header: shared.ServerToClient.ErrorBundle = .{
        .step_id = step_id,
        .cycle = cycle,
        .extra_len = @intCast(error_bundle.extra.len),
        .string_bytes_len = @intCast(error_bundle.string_bytes.len),
    };

    const need_bswap = builtin.target.cpu.arch.endian() != .little;

    if (need_bswap) {
        std.mem.byteSwapAllFields(shared.ServerToClient.Header, &header);
        std.mem.byteSwapAllFields(shared.ServerToClient.ErrorBundle, &error_bundle_header);
        std.mem.byteSwapAllElements(u32, @constCast(error_bundle.extra)); // trust me bro
    }

    var file_writer = std.fs.File.stdout().writer(&.{});
    const writer = &file_writer.interface;

    var data = [_][]const u8{
        std.mem.asBytes(&header),
        std.mem.asBytes(&error_bundle_header),
        std.mem.sliceAsBytes(error_bundle.extra),
        error_bundle.string_bytes,
    };
    writer.writeVecAll(&data) catch return file_writer.err.?;
}

/// Initialize a struct with provided values. Any values that are unrecognized
/// will be ignored.
fn structInitIgnoreUnknown(T: type, init: anytype) T {
    var result: T = undefined;
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (@hasField(@TypeOf(init), field.name)) {
            switch (@typeInfo(field.type)) {
                .@"struct" => {
                    @field(result, field.name) = structInitIgnoreUnknown(field.type, @field(init, field.name));
                },
                else => {
                    @field(result, field.name) = @field(init, field.name);
                },
            }
        } else {
            @field(result, field.name) = comptime field.defaultValue() orelse @compileError("missing struct field: " ++ field.name);
        }
    }
    return result;
}
