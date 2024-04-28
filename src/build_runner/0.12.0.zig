//! PLEASE READ THE FOLLOWING MESSAGE BEFORE EDITING THIS FILE:
//! Update the `minimum_runtime_zig_version` field in `build.zig` a breaking change occured.
//!
//! You can test out the build runner on ZLS's `build.zig` with the following command:
//! `zig build --build-runner src/build_runner/0.12.0.zig`
//!
//! You can also test the build runner on any other `build.zig` with the following command:
//! `zig build --build-file /path/to/build.zig --build-runner /path/to/zls/src/build_runner/0.12.0.zig`
//! `zig build --build-runner /path/to/zls/src/build_runner/0.12.0.zig` (if the cwd contains build.zig)

const root = @import("@build");
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const process = std.process;
const ArrayList = std.ArrayList;
const Step = std.Build.Step;

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

    var graph: std.Build.Graph = .{
        .arena = arena,
        .cache = .{
            .gpa = arena,
            .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
        },
        .zig_exe = zig_exe,
        .env_map = try process.getEnvMap(arena),
        .global_cache_root = global_cache_directory,
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolveTargetQuery(.{}),
        },
    };

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

    var debug_log_scopes = ArrayList([]const u8).init(arena);
    var thread_pool_options: std.Thread.Pool.Options = .{ .allocator = arena };

    var install_prefix: ?[]const u8 = null;
    var dir_list = std.Build.DirList{};
    var max_rss: u64 = 0;
    var skip_oom_steps: bool = false;
    var seed: u32 = 0;
    var output_tmp_nonce: ?[16]u8 = null;

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
                    fatal("expected [all|failures|none] after '{s}'", .{arg});
                _ = next_arg;
            } else if (mem.eql(u8, arg, "--zig-lib-dir")) {
                builder.zig_lib_dir = .{ .cwd_relative = nextArgOrFatal(args, &arg_idx) };
            } else if (mem.eql(u8, arg, "--seed")) {
                const next_arg = nextArg(args, &arg_idx) orelse
                    fatal("expected u32 after '{s}'", .{arg});
                seed = std.fmt.parseUnsigned(u32, next_arg, 0) catch |err| {
                    fatal("unable to parse seed '{s}' as 32-bit integer: {s}\n", .{
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
            } else if (mem.eql(u8, arg, "--glibc-runtimes")) {
                builder.glibc_runtimes_dir = nextArgOrFatal(args, &arg_idx);
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
            fatal("can't pass target as arguments: {s}\n\n", .{arg});
        }
    }

    var progress: std.Progress = .{ .terminal = null };
    const main_progress_node = progress.start("", 0);

    builder.debug_log_scopes = debug_log_scopes.items;
    builder.resolveInstallPrefix(install_prefix, dir_list);
    {
        var prog_node = main_progress_node.start("user build.zig logic", 0);
        defer prog_node.end();
        try builder.runBuild(root);
    }

    if (graph.needed_lazy_dependencies.entries.len != 0) {
        var buffer: std.ArrayListUnmanaged(u8) = .{};
        for (graph.needed_lazy_dependencies.keys()) |k| {
            try buffer.appendSlice(arena, k);
            try buffer.append(arena, '\n');
        }
        const s = std.fs.path.sep_str;
        const tmp_sub_path = "tmp" ++ s ++ (output_tmp_nonce orelse fatal("missing -Z arg", .{}));
        local_cache_directory.handle.writeFile2(.{
            .sub_path = tmp_sub_path,
            .data = buffer.items,
            .flags = .{ .exclusive = true },
        }) catch |err| {
            fatal("unable to write configuration results to '{}{s}': {s}", .{
                local_cache_directory, tmp_sub_path, @errorName(err),
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
        .memory_blocked_steps = std.ArrayList(*Step).init(arena),

        .claimed_rss = 0,
    };

    if (run.max_rss == 0) {
        run.max_rss = process.totalSystemMemory() catch std.math.maxInt(u64);
        run.max_rss_is_default = true;
    }

    try extractBuildInformation(
        builder,
        arena,
        main_progress_node,
        thread_pool_options,
        &run,
        seed,
    );
}

const Run = struct {
    max_rss: u64,
    max_rss_is_default: bool,
    max_rss_mutex: std.Thread.Mutex,
    skip_oom_steps: bool,
    memory_blocked_steps: std.ArrayList(*Step),

    claimed_rss: usize,
};

fn runSteps(
    arena: std.mem.Allocator,
    b: *std.Build,
    steps: []const *Step,
    parent_prog_node: *std.Progress.Node,
    thread_pool_options: std.Thread.Pool.Options,
    run: *Run,
    seed: u32,
) error{ OutOfMemory, DependencyLoopDetected, ExceedingMaxRSS }!void {
    const gpa = b.allocator;
    var step_stack: std.AutoArrayHashMapUnmanaged(*Step, void) = .{};
    defer step_stack.deinit(gpa);

    // assert(steps.len != 0);
    try step_stack.ensureUnusedCapacity(gpa, steps.len);
    for (0..steps.len) |i| {
        const step = steps[steps.len - i - 1];
        step_stack.putAssumeCapacity(step, {});
    }

    const starting_steps = try arena.dupe(*Step, step_stack.keys());

    var rng = std.rand.DefaultPrng.init(seed);
    const rand = rng.random();
    rand.shuffle(*Step, starting_steps);

    for (starting_steps) |s| {
        try constructGraphAndCheckForDependencyLoop(b, s, &step_stack, rand);
    }

    {
        // Check that we have enough memory to complete the build.
        for (step_stack.keys()) |s| {
            if (s.max_rss == 0) continue;
            if (s.max_rss > run.max_rss) {
                if (run.skip_oom_steps) {
                    s.state = .skipped_oom;
                } else {
                    return error.ExceedingMaxRSS;
                }
            }
        }
    }

    var thread_pool: std.Thread.Pool = undefined;
    thread_pool.init(thread_pool_options) catch @panic("failed to initialize thread pool");
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
            if (step.state == .skipped_oom) continue;

            wait_group.start();
            thread_pool.spawn(workerMakeOneStep, .{
                &wait_group, &thread_pool, b, step, &step_prog, run,
            }) catch @panic("OOM");
        }
    }
    assert(run.memory_blocked_steps.items.len == 0);

    var test_skip_count: usize = 0;
    var test_fail_count: usize = 0;
    var test_pass_count: usize = 0;
    var test_leak_count: usize = 0;
    var test_count: usize = 0;

    var success_count: usize = 0;
    var skipped_count: usize = 0;
    var failure_count: usize = 0;
    var pending_count: usize = 0;
    var total_compile_errors: usize = 0;
    var compile_error_steps: std.ArrayListUnmanaged(*Step) = .{};
    defer compile_error_steps.deinit(gpa);

    for (step_stack.keys()) |s| {
        test_fail_count += s.test_results.fail_count;
        test_skip_count += s.test_results.skip_count;
        test_leak_count += s.test_results.leak_count;
        test_pass_count += s.test_results.passCount();
        test_count += s.test_results.test_count;

        switch (s.state) {
            .precheck_unstarted => unreachable,
            .precheck_started => unreachable,
            .running => unreachable,
            .precheck_done => {
                // precheck_done is equivalent to dependency_failure in the case of
                // transitive dependencies. For example:
                // A -> B -> C (failure)
                // B will be marked as dependency_failure, while A may never be queued, and thus
                // remain in the initial state of precheck_done.
                s.state = .dependency_failure;
                pending_count += 1;
            },
            .dependency_failure => pending_count += 1,
            .success => success_count += 1,
            .skipped, .skipped_oom => skipped_count += 1,
            .failure => {
                failure_count += 1;
                const compile_errors_len = s.result_error_bundle.errorMessageCount();
                if (compile_errors_len > 0) {
                    s.result_error_bundle.renderToStdErr(.{
                        .ttyconf = .no_color,
                    });
                    total_compile_errors += compile_errors_len;
                    try compile_error_steps.append(gpa, s);
                }
            },
        }
    }

    // TODO report summary
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
    rand: std.rand.Random,
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
    sub_prog_node.activate();
    defer sub_prog_node.end();

    const make_result = s.make(&sub_prog_node);

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

fn nextArg(args: [][:0]const u8, idx: *usize) ?[:0]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

fn nextArgOrFatal(args: [][:0]const u8, idx: *usize) [:0]const u8 {
    return nextArg(args, idx) orelse {
        std.debug.print("expected argument after '{s}'\n  access the help menu with 'zig build -h'\n", .{args[idx.*]});
        process.exit(1);
    };
}

fn argsRest(args: [][:0]const u8, idx: usize) ?[][:0]const u8 {
    if (idx >= args.len) return null;
    return args[idx..];
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

//
//
// ZLS code
//
//

const BuildConfig = @import("BuildConfig.zig");

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

fn extractBuildInformation(
    b: *std.Build,
    arena: std.mem.Allocator,
    main_progress_node: *std.Progress.Node,
    thread_pool_options: std.Thread.Pool.Options,
    run: *Run,
    seed: u32,
) !void {
    var steps = std.AutoArrayHashMapUnmanaged(*Step, void){};
    defer steps.deinit(arena);

    // collect the set of all steps
    {
        var stack = std.ArrayListUnmanaged(*Step){};

        try stack.ensureUnusedCapacity(arena, b.top_level_steps.count());
        for (b.top_level_steps.values()) |tls| {
            stack.appendAssumeCapacity(&tls.step);
        }

        defer stack.deinit(b.allocator);
        while (stack.popOrNull()) |step| {
            const gop = try steps.getOrPut(b.allocator, step);
            if (gop.found_existing) continue;

            try stack.appendSlice(b.allocator, step.dependencies.items);
        }
    }

    var step_dependencies = std.AutoArrayHashMap(*Step, void).init(arena);

    const helper = struct {
        fn addStepDependencies(set: *std.AutoArrayHashMap(*Step, void), lazy_path: std.Build.LazyPath) !void {
            switch (lazy_path) {
                .src_path, .path, .cwd_relative, .dependency => {},
                .generated => |gen| try set.put(gen.step, {}),
                .generated_dirname => |gen| try set.put(gen.generated.step, {}),
            }
        }
    };

    // collect dependencies of all `Step.Compile` steps
    for (steps.keys()) |step| {
        const compile = step.cast(Step.Compile) orelse continue;

        // adding all dependencies would be possible but may add dependencies that
        // are never used to resolve a path.
        //
        // try step_dependencies.ensureUnusedCapacity(arena, step.dependencies.items.len);
        // for (step.dependencies.items) |dependency_step| {
        //     step_dependencies.putAssumeCapacity(dependency_step, {});
        // }

        if (compile.root_module.root_source_file) |root_source_file| {
            try helper.addStepDependencies(&step_dependencies, root_source_file);
        }

        for (compile.root_module.import_table.values()) |module| {
            const root_source_file = module.root_source_file orelse continue;
            try helper.addStepDependencies(&step_dependencies, root_source_file);
        }

        for (compile.root_module.include_dirs.items) |include_dir| {
            switch (include_dir) {
                .path,
                .path_system,
                .path_after,
                .framework_path,
                .framework_path_system,
                => |include_path| try helper.addStepDependencies(&step_dependencies, include_path),
                .config_header_step => |config_header| try step_dependencies.put(config_header.output_file.step, {}),
                .other_step => |other| {
                    if (other.generated_h) |header| {
                        try step_dependencies.put(header.step, {});
                    }
                    if (other.installed_headers_include_tree) |include_tree| {
                        try step_dependencies.put(include_tree.generated_directory.step, {});
                    }
                },
            }
        }
    }

    // run all steps that are dependencies of a `Step.Compile` step
    try runSteps(
        arena,
        b,
        step_dependencies.keys(),
        main_progress_node,
        thread_pool_options,
        run,
        seed,
    );

    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};
    var packages = Packages{ .allocator = arena };

    // iterate through all `Step.Compile` steps and extract the necessary information
    for (steps.keys()) |step| {
        const compile = step.cast(Step.Compile) orelse continue;
        const owner = compile.root_module.owner;

        if (compile.root_module.root_source_file) |root_source_file| {
            _ = try packages.addPackage("root", root_source_file.getPath(owner));
        }

        for (compile.root_module.import_table.keys(), compile.root_module.import_table.values()) |import_name, module| {
            const root_source_file = module.root_source_file orelse continue;
            _ = try packages.addPackage(import_name, root_source_file.getPath(module.owner));
        }

        try processPkgConfig(arena, &include_dirs, compile);

        for (compile.root_module.include_dirs.items) |include_dir| {
            switch (include_dir) {
                .path,
                .path_system,
                .path_after,
                .framework_path,
                .framework_path_system,
                => |include_path| try include_dirs.put(arena, include_path.getPath(owner), {}),

                .other_step => |other| {
                    if (other.generated_h) |header| {
                        try include_dirs.put(
                            arena,
                            std.fs.path.dirname(header.getPath()).?,
                            {},
                        );
                    }
                    if (other.installed_headers_include_tree) |include_tree| {
                        try include_dirs.put(
                            arena,
                            include_tree.generated_directory.getPath(),
                            {},
                        );
                    }
                },
                .config_header_step => |config_header| {
                    const full_file_path = config_header.output_file.getPath();
                    const header_dir_path = full_file_path[0 .. full_file_path.len - config_header.include_path.len];
                    try include_dirs.put(
                        arena,
                        header_dir_path,
                        {},
                    );
                },
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

    var deps_build_roots: std.ArrayListUnmanaged(BuildConfig.DepsBuildRoots) = .{};
    for (dependencies.root_deps) |root_dep| {
        inline for (@typeInfo(dependencies.packages).Struct.decls) |package| blk: {
            if (std.mem.eql(u8, package.name, root_dep[1])) {
                const package_info = @field(dependencies.packages, package.name);
                if (!@hasDecl(package_info, "build_root")) break :blk;
                if (!@hasDecl(package_info, "build_zig")) break :blk;
                try deps_build_roots.append(arena, .{
                    .name = root_dep[0],
                    .path = try std.fs.path.resolve(arena, &[_][]const u8{ package_info.build_root, "./build.zig" }),
                });
            }
        }
    }

    try std.json.stringify(
        BuildConfig{
            .deps_build_roots = deps_build_roots.items,
            .packages = try packages.toPackageList(),
            .include_dirs = include_dirs.keys(),
        },
        .{
            .whitespace = .indent_1,
        },
        std.io.getStdOut().writer(),
    );
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *Step.Compile,
) !void {
    for (exe.root_module.link_objects.items) |link_object| {
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
    exe: *Step.Compile,
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
        const stdout = if (b.runAllowFail(&[_][]const u8{
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

        var zig_args = ArrayList([]const u8).init(b.allocator);
        defer zig_args.deinit();

        var it = mem.tokenizeAny(u8, stdout, " \r\n\t");
        while (it.next()) |tok| {
            if (mem.eql(u8, tok, "-I")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-I", dir });
            } else if (mem.startsWith(u8, tok, "-I")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-L")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-L", dir });
            } else if (mem.startsWith(u8, tok, "-L")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-l")) {
                const lib = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-l", lib });
            } else if (mem.startsWith(u8, tok, "-l")) {
                try zig_args.append(tok);
            } else if (mem.eql(u8, tok, "-D")) {
                const macro = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-D", macro });
            } else if (mem.startsWith(u8, tok, "-D")) {
                try zig_args.append(tok);
            } else if (b.debug_pkg_config) {
                return self.step.fail("unknown pkg-config flag '{s}'", .{tok});
            }
        }

        return zig_args.toOwnedSlice();
    }

    fn execPkgConfigList(self: *std.Build, out_code: *u8) (std.Build.PkgConfigError || std.Build.RunError)![]const std.Build.PkgConfigPkg {
        const stdout = try self.runAllowFail(&[_][]const u8{ "pkg-config", "--list-all" }, out_code, .Ignore);
        var list = ArrayList(std.Build.PkgConfigPkg).init(self.allocator);
        errdefer list.deinit();
        var line_it = mem.tokenizeAny(u8, stdout, "\r\n");
        while (line_it.next()) |line| {
            if (mem.trim(u8, line, " \t").len == 0) continue;
            var tok_it = mem.tokenizeAny(u8, line, " \t");
            try list.append(std.Build.PkgConfigPkg{
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
