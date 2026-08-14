const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Dir = Io.Dir;
const Directory = std.Build.Cache.Directory;
const Configuration = std.Build.Configuration;
const Client = std.zig.Client;
const Server = std.zig.Server;

const log = std.log.scoped(.bsp);

const DiagnosticsCollection = @import("DiagnosticsCollection.zig");
const Uri = @import("Uri.zig");

const protocol_name = "zig build system server";

pub const BuildConfig = struct {
    /// The `dependencies` in `build.zig.zon`.
    dependencies: std.json.ArrayHashMap([]const u8),
    /// The key is the `root_source_file`.
    /// All modules with the same root source file are merged. This limitation may be lifted in the future.
    modules: std.json.ArrayHashMap(Module),
    /// List of all compilations units.
    compilations: []const Compile,

    pub const Module = struct {
        import_table: std.json.ArrayHashMap([]const u8),
    };

    pub const Compile = struct {
        /// Key in `BuildConfig.modules`.
        root_module: []const u8,

        // may contain additional information in the future like `target` or `link_libc`.
    };
};

/// Runs the build.zig and extracts include directories and packages
pub fn loadBuildConfiguration(
    io: Io,
    allocator: Allocator,
    environ_map: *const std.process.Environ.Map,
    zig_exe_path: []const u8,
    zig_lib_directory: Directory,
    diagnostics_collection: *DiagnosticsCollection,
    build_file_uri: Uri,
    build_file_version: u32,
) !std.json.Parsed(BuildConfig) {
    const build_file_path = try build_file_uri.toFsPath(allocator);
    defer allocator.free(build_file_path);

    const cwd_path = Dir.path.dirname(build_file_path).?;
    const cwd: Directory = .{
        .handle = try Dir.cwd().openDir(io, cwd_path, .{}),
        .path = cwd_path,
    };

    const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
        var hasher: std.hash.Wyhash = .init(47); // Chosen by the following prompt: Pwease give a wandom nyumbew
        hasher.update(build_file_uri.raw);
        break :tag @fromBackingInt(@truncate(hasher.final()));
    };

    const argv: []const []const u8 = &.{
        zig_exe_path,
        "build",
        "--listen=-",
    };

    var child_environ_map = try environ_map.clone(allocator);
    defer child_environ_map.deinit();

    try child_environ_map.put("ZIG_DEBUG_CMD", "1");
    try child_environ_map.put("ZIG_LIB_DIR", zig_lib_directory.path.?);

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = cwd.handle },
        .environ_map = &child_environ_map,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore, // TODO
    });
    errdefer child.kill(io);

    const cmd: std.zig.SubprocessCommand = .{
        .argv = argv,
        .cwd = cwd_path,
        .parent_env = environ_map,
        .child_env = &child_environ_map,
    };

    var stdout_buffer: [256]u8 = undefined;
    var stdin_buffer: [256]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buffer);
    var stdin_writer = child.stdin.?.writer(io, &stdin_buffer);

    var client: Client = .{
        .in = &stdout_reader.interface,
        .out = &stdin_writer.interface,
    };

    const handshake: Handshake = while (true) {
        const header = client.receiveMessage() catch |err| switch (err) {
            error.ReadFailed => return stdout_reader.err.?,
            error.EndOfStream => |e| {
                log.err("{t} reading from command:\n{f}", .{ e, cmd });
                return error.AlreadyReported;
            },
        };
        switch (header.tag) {
            .zig_version => {},
            .error_bundle => {
                var error_bundle = try receiveErrorBundle(&client, allocator);
                defer error_bundle.deinit(allocator);
                try diagnostics_collection.pushErrorBundle(diagnostic_tag, build_file_version, cwd_path, error_bundle);
                continue;
            },
            .bsp_handshake => {
                const body = try client.in.readAlloc(allocator, header.bytes_len);
                defer allocator.free(body);
                break try .init(allocator, cwd_path, zig_exe_path, body);
            },
            else => {
                log.warn("unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) });
                return error.EndOfStream;
            },
        }
        try client.in.discardAll(header.bytes_len);
    };
    var arena_allocator = handshake.arena.promote(allocator);
    errdefer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const configuration: Configuration = while (true) {
        const header = client.receiveMessage() catch |err| switch (err) {
            error.ReadFailed => return stdout_reader.err.?,
            error.EndOfStream => |e| {
                log.err("{t} reading from command:\n{f}", .{ e, cmd });
                return error.AlreadyReported;
            },
        };
        if (header.tag != .bsp_configuration) {
            log.err("unexpected {t} message from {s}:\n{f}", .{ fmtEnum(header.tag), protocol_name, cmd });
            return error.AlreadyReported;
        }
        const configuration_file_path = try client.in.readAlloc(allocator, header.bytes_len);
        defer allocator.free(configuration_file_path);
        const configuration_file = cwd.handle.openFile(io, configuration_file_path, .{}) catch |err| {
            std.debug.panic("failed to open configuration file {q}: {t}", .{ configuration_file_path, err });
        };
        defer configuration_file.close(io);
        break try .loadFile(arena, io, configuration_file);
    };

    var maker: Maker = .{
        .configuration = configuration,
        .base_paths = handshake.base_paths,
    };
    const c = &maker.configuration;
    const root_package: Configuration.Package.Index = .root;
    const root_package_instance: Configuration.Package.Instance.Index = .root;

    // The value tracks whether the step is a decendant of the default step step.
    var all_steps: std.array_hash_map.Auto(Configuration.Step.Index, bool) = .empty;
    defer all_steps.deinit(allocator);

    // collect all steps that are decendants of the "install" step.
    {
        try all_steps.putNoClobber(allocator, c.default_step, true);

        var i: usize = 0;
        while (i < all_steps.count()) : (i += 1) {
            const step = all_steps.keys()[i].ptr(c);
            const deps = step.deps.slice(c);

            try all_steps.ensureUnusedCapacity(allocator, deps.len);
            for (deps) |other_step| {
                all_steps.putAssumeCapacity(other_step, true);
            }
        }
    }

    // collect all other steps
    {
        var i: usize = all_steps.count();

        for (configuration.steps, 0..) |*conf_step, step_index_usize| {
            if (conf_step.owner != .root) continue;
            const step_index: Configuration.Step.Index = @fromBackingInt(@intCast(step_index_usize));
            const flags = conf_step.flags(&configuration);
            if (flags.tag != .top_level) continue;
            all_steps.putAssumeCapacity(step_index, true);
        }

        while (i < all_steps.count()) : (i += 1) {
            const step = all_steps.keys()[i].ptr(c);
            const deps = step.deps.slice(c);

            try all_steps.ensureUnusedCapacity(allocator, deps.len);
            for (deps) |other_step| {
                all_steps.putAssumeCapacity(other_step, true);
            }
        }
    }

    // Collect all steps that need to be run so that we can resolve the lazy paths we are interested in (e.g. root_source_file).
    {
        var needed_steps: std.array_hash_map.Auto(Configuration.Step.Index, void) = .empty;
        defer needed_steps.deinit(allocator);

        var modules: std.array_hash_map.Auto(Configuration.Module.Index, void) = .empty;
        defer modules.deinit(allocator);

        // collect all exported modules of the root package
        const root_package_modules = root_package_instance.ptr(c).exported_modules;
        for (root_package_modules.modules.slice(c)) |module| {
            try modules.put(allocator, module, {});
        }

        // collect all root modules of compile steps
        for (all_steps.keys()) |step| {
            const compile = step.ptr(c).extended.cast(c, Configuration.Step.Compile) orelse continue;
            try modules.put(allocator, compile.root_module, {});
        }

        // collect transitively imported modules
        var index: usize = 0;
        while (index < modules.count()) : (index += 1) {
            const mod = modules.keys()[index].get(c);
            const import_table = mod.import_table.get(c).imports.mal;
            try modules.ensureUnusedCapacity(allocator, import_table.len);
            for (import_table.items(.module)) |other_mod| {
                modules.putAssumeCapacity(other_mod, {});
            }
        }

        // collect step dependencies of modules
        for (modules.keys()) |module_index| {
            const module = module_index.get(c);
            const root_source_file = module.root_source_file.unwrap() orelse continue;
            switch (root_source_file.get(c)) {
                .source_path, .relative => {},
                .generated => |gen| {
                    const owner_step = gen.index.owner(c).unwrap().?;
                    try needed_steps.put(allocator, owner_step, {});
                },
            }
        }

        try client.serveBuildSteps(needed_steps.keys(), .{ .watch = false });

        // receive `maker.generated_files` data
        while (true) {
            const header = client.receiveMessage() catch |err| switch (err) {
                error.ReadFailed => return stdout_reader.err.?,
                error.EndOfStream => |e| {
                    log.err("{t} reading from command:\n{f}", .{ e, cmd });
                    return error.AlreadyReported;
                },
            };
            switch (header.tag) {
                .error_bundle => {
                    var error_bundle = try receiveErrorBundle(&client, allocator);
                    defer error_bundle.deinit(allocator);
                    try diagnostics_collection.pushErrorBundle(
                        diagnostic_tag,
                        build_file_version,
                        cwd_path,
                        error_bundle,
                    );
                    continue;
                },
                .bsp_build_started => {},
                .bsp_build_completed => break,
                .bsp_step_started => {},
                .bsp_step_completed => {
                    const body = try client.in.readAlloc(allocator, header.bytes_len);
                    defer allocator.free(body);

                    var message = try receiveBuildStepCompleted(allocator, body);
                    defer message.deinit(allocator);

                    for (
                        message.generated_files.items(.index),
                        message.generated_files.items(.base),
                        message.generated_files.items(.sub_path),
                    ) |gf, base, sub_path| {
                        const path: Configuration.LazyPath.Relative.Unpacked = .{
                            .base = base,
                            .sub_path = try arena.dupe(u8, std.mem.sliceTo(message.string_bytes[sub_path..], 0)),
                        };
                        try maker.generated_files.put(arena, gf, path);
                    }

                    try diagnostics_collection.pushErrorBundle(
                        diagnostic_tag,
                        build_file_version,
                        cwd_path,
                        message.error_bundle,
                    );
                    continue;
                },
                .bsp_configuration => @panic("TODO"),
                else => log.warn("unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
            }
            try client.in.discardAll(header.bytes_len);
        }
    }

    // We collect modules in the following order:
    // - exported modules (`std.Build.addModule`)
    // - modules that are reachable from the "install" step
    // - all other reachable modules
    var modules: std.array_hash_map.Auto(Configuration.Module.Index, void) = .empty;
    defer modules.deinit(allocator);

    const root_package_modules = root_package_instance.ptr(c).exported_modules;
    try modules.ensureUnusedCapacity(allocator, root_package_modules.modules.get(c).modules.slice.len);
    for (root_package_modules.modules.slice(c)) |module| {
        modules.putAssumeCapacity(module, {});
    }

    // We loop twice through all steps so that decendants of the "install" step are processed first.
    for ([_]bool{ true, false }) |want_install_step_decendant| {
        for (all_steps.keys(), all_steps.values()) |step_index, is_install_step_decendant| {
            if (is_install_step_decendant != want_install_step_decendant) continue;
            const step = step_index.ptr(c);
            const compile = step.extended.cast(c, Configuration.Step.Compile) orelse continue;
            try modules.put(allocator, compile.root_module, {});
        }
    }

    var resolved_modules: std.array_hash_map.String(BuildConfig.Module) = .empty;

    var index: usize = 0;
    while (index < modules.count()) : (index += 1) {
        const module = modules.keys()[index].get(c);
        const import_table = module.import_table.get(c).imports.mal;

        for (import_table.items(.module)) |import| try modules.put(allocator, import, {});

        const root_source_file = module.root_source_file.unwrap() orelse continue;
        const root_source_file_path = try maker.resolveLazyPath(arena, root_source_file.get(c)) orelse continue;

        // All modules with the same root source file are merged. This limitation may be lifted in the future.
        const gop = try resolved_modules.getOrPutValue(arena, root_source_file_path, .{
            .import_table = .{},
        });

        for (import_table.items(.name), import_table.items(.module)) |name, import_module| {
            const import_root_source_file = import_module.get(c).root_source_file.unwrap() orelse continue;
            const import_root_source_file_path = try maker.resolveLazyPath(arena, import_root_source_file.get(c)) orelse continue;

            const gop_import = try gop.value_ptr.import_table.map.getOrPut(arena, name.slice(c));
            // This does not account for the possibility of collisions (i.e. modules with same root source file import different modules under the same name).
            if (!gop_import.found_existing) {
                gop_import.value_ptr.* = import_root_source_file_path;
            }
        }
    }

    var compilations: std.ArrayList(BuildConfig.Compile) = .empty;
    for (all_steps.keys()) |step_index| {
        const step = step_index.ptr(c);
        const compile = step.extended.cast(c, Configuration.Step.Compile) orelse continue;
        const root_module = compile.root_module.get(c);
        const root_source_file = root_module.root_source_file.unwrap() orelse continue;
        const root_source_file_path = try maker.resolveLazyPath(arena, root_source_file.get(c)) orelse continue;
        try compilations.append(arena, .{
            .root_module = root_source_file_path,
        });
    }

    var dependencies: std.array_hash_map.String([]const u8) = .empty;
    const root_package_dependencies = root_package.ptr(c).deps.slice(c);
    try dependencies.ensureTotalCapacity(arena, root_package_dependencies.len);
    for (root_package_dependencies) |dependency| {
        const package_name = dependency.name.slice(c);
        const package_path = dependency.package.ptr(c).path.slice(c) orelse continue;
        const resolved_package_path = try Dir.path.resolve(arena, &.{ maker.base_paths.get(.build_root), package_path, "build.zig" });
        dependencies.putAssumeCapacityNoClobber(package_name, resolved_package_path);
    }

    try diagnostics_collection.publishDiagnostics();

    try client.serveBodylessMessage(.exit);

    const term = try child.wait(io);

    if (!term.success()) {
        log.err("Failed to collect build system configuration, command:\n{f}", .{cmd});
        return error.AlreadyReported;
    }

    const build_config: BuildConfig = .{
        .dependencies = .{ .map = dependencies },
        .modules = .{ .map = resolved_modules },
        .compilations = compilations.items,
    };

    // std.debug.print("collected build system configuration:\n{f}\n", .{std.json.fmt(build_config, .{ .whitespace = .indent_2 })});

    const arena_allocator_ptr = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena_allocator_ptr);
    arena_allocator_ptr.* = arena_allocator;

    return .{
        .arena = arena_allocator_ptr,
        .value = build_config,
    };
}

const BasePaths = std.enums.EnumArray(Configuration.LazyPath.Relative.Base, []const u8);

const Handshake = struct {
    arena: std.heap.ArenaAllocator.State,
    flags: Server.Message.Handshake.Flags,
    base_paths: BasePaths,

    fn init(
        gpa: Allocator,
        cwd: []const u8,
        zig_exe: []const u8,
        body: []const u8,
    ) Io.Reader.ReadAllocError!Handshake {
        var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        var r: Io.Reader = .fixed(body);

        const header = try r.takeStruct(Server.Message.Handshake, .little);

        // TODO check protocol version

        const resolve = Dir.path.resolve;
        const bp_header = header.base_paths;
        const base_paths: BasePaths = .init(.{
            .cwd = cwd,
            .zig_exe = zig_exe,
            .global_cache = try resolve(arena, &.{ cwd, try r.take(bp_header.global_cache_len) }),
            .local_cache = try resolve(arena, &.{ cwd, try r.take(bp_header.local_cache_len) }),
            .zig_lib = try resolve(arena, &.{ cwd, try r.take(bp_header.zig_lib_len) }),
            .build_root = try resolve(arena, &.{ cwd, try r.take(bp_header.build_root_len) }),
            .install_prefix = try resolve(arena, &.{ cwd, try r.take(bp_header.install_prefix_len) }),
            .install_lib = try resolve(arena, &.{ cwd, try r.take(bp_header.install_lib_len) }),
            .install_bin = try resolve(arena, &.{ cwd, try r.take(bp_header.install_bin_len) }),
            .install_include = try resolve(arena, &.{ cwd, try r.take(bp_header.install_include_len) }),
        });
        return .{
            .arena = arena_allocator.state,
            .flags = header.flags,
            .base_paths = base_paths,
        };
    }
};

const Maker = struct {
    configuration: Configuration,
    base_paths: BasePaths,
    generated_files: std.array_hash_map.Auto(Configuration.GeneratedFileIndex, Configuration.LazyPath.Relative.Unpacked) = .empty,

    pub fn resolveLazyPath(
        maker: *const Maker,
        arena: Allocator,
        lazy_path: Configuration.LazyPath,
    ) Allocator.Error!?[]const u8 {
        const c = &maker.configuration;
        return switch (lazy_path) {
            .source_path => |sp| try packagePath(maker, arena, sp.owner, sp.sub_path.slice(c)),
            .relative => |relative| try relativePath(maker, arena, relative.unpack(c)),
            .generated => |gen| {
                const base = maker.generated_files.get(gen.index) orelse return null;
                var file_path = base.sub_path;
                for (0..gen.flags.up) |_| {
                    file_path = Dir.path.dirname(file_path) orelse {
                        log.err("invalid LazyPath traversal: up {d} times from {s}", .{ gen.flags.up, base.sub_path });
                        return null;
                    };
                }
                return try Dir.path.join(arena, &.{ maker.base_paths.get(base.base), file_path, gen.sub_path.slice(c) });
            },
        };
    }

    fn packagePath(
        maker: *const Maker,
        arena: Allocator,
        package_index: Configuration.Package.Index,
        sub_path: []const u8,
    ) Allocator.Error![]const u8 {
        const c = &maker.configuration;
        return try Dir.path.join(arena, &.{
            maker.base_paths.get(.build_root),
            package_index.path(c).?,
            sub_path,
        });
    }

    fn relativePath(
        maker: *const Maker,
        arena: Allocator,
        relative: Configuration.LazyPath.Relative.Unpacked,
    ) Allocator.Error![]const u8 {
        const sub_path = relative.sub_path;
        const base_path = maker.base_paths.get(relative.base);
        if (sub_path.len == 0) return base_path;
        return try Dir.path.join(arena, &.{ base_path, sub_path });
    }
};

pub const BuildOnSave = struct {
    io: Io,
    allocator: Allocator,
    worker: Io.Future(void),
    worker_state: *WorkerState,

    const WorkerState = struct {
        mutex: Io.Mutex,
        child_process: std.process.Child,
        build_root: Directory,
        zig_exe_path: []const u8,
        check_step_only: bool,
    };

    pub const Supported = union(enum) {
        supported,
        invalid_linux_kernel_version: if (builtin.os.tag == .linux) @FieldType(std.os.linux.utsname, "release") else noreturn,
        unsupported_linux_kernel_version: if (builtin.os.tag == .linux) std.SemanticVersion else noreturn,
        unsupported_zig_version: if (@TypeOf(os_support) == std.SemanticVersion) void else noreturn,
        unsupported_os: if (@TypeOf(os_support) == bool and !os_support) void else noreturn,

        /// std.build.Watch requires `AT_HANDLE_FID` which is Linux 6.5+
        /// https://github.com/ziglang/zig/issues/20720
        pub const minimum_linux_version: std.SemanticVersion = .{ .major = 6, .minor = 5, .patch = 0 };

        // We can't rely on `std.Build.Watch.have_impl` because we need to
        // check the runtime Zig version instead of Zig version that ZLS
        // has been built with.
        pub const os_support = switch (builtin.os.tag) {
            .linux,
            .windows,
            .dragonfly,
            .freebsd,
            .netbsd,
            .openbsd,
            .ios,
            .macos,
            .tvos,
            .visionos,
            .watchos,
            .haiku,
            => true,
            else => false,
        };
    };

    pub inline fn isSupportedComptime() bool {
        if (!std.process.can_spawn) return false;
        if (builtin.single_threaded) return false;
        return true;
    }

    pub fn isSupportedRuntime(runtime_zig_version: std.SemanticVersion) Supported {
        comptime std.debug.assert(isSupportedComptime());
        _ = runtime_zig_version;
        return .supported;
    }

    pub const InitOptions = struct {
        io: Io,
        gpa: Allocator,
        environ_map: *const std.process.Environ.Map,
        build_root: Directory,
        build_on_save_args: []const []const u8,
        check_step_only: bool,
        zig_exe_path: []const u8,
        zig_lib_dir: Directory,

        diagnostics: *DiagnosticsCollection,
    };

    pub const InitError = error{
        Canceled,
        ConcurrencyUnavailable,
        OutOfMemory,
        AlreadyReported,
    };

    pub fn init(options: InitOptions) InitError!?BuildOnSave {
        const io = options.io;
        const gpa = options.gpa;

        errdefer {
            var dir = options.build_root;
            dir.closeAndFree(gpa, io);
        }

        const base_args: []const []const u8 = &.{
            options.zig_exe_path,
            "build",
            "--listen=-",
        };
        var argv: std.ArrayList([]const u8) = try .initCapacity(
            gpa,
            base_args.len + options.build_on_save_args.len,
        );
        defer argv.deinit(gpa);

        argv.appendSliceAssumeCapacity(base_args);
        argv.appendSliceAssumeCapacity(options.build_on_save_args);

        var child_environ_map = try options.environ_map.clone(gpa);
        defer child_environ_map.deinit();

        try child_environ_map.put("ZIG_DEBUG_CMD", "1");
        try child_environ_map.put("ZIG_LIB_DIR", options.zig_lib_dir.path.?);

        const cmd: std.zig.SubprocessCommand = .{
            .argv = argv.items,
            .cwd = options.build_root.path.?,
            .parent_env = options.environ_map,
            .child_env = &child_environ_map,
        };

        var child_process = std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .dir = options.build_root.handle },
            .environ_map = &child_environ_map,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |e| {
                log.err("{t} from spawning command:\n{f}", .{ e, cmd });
                return error.AlreadyReported;
            },
        };
        errdefer child_process.kill(io);

        const worker_state = try gpa.create(WorkerState);
        errdefer gpa.destroy(worker_state);

        const duped_zig_exe_path = try gpa.dupe(u8, options.zig_exe_path);
        errdefer gpa.free(duped_zig_exe_path);

        worker_state.* = .{
            .mutex = .init,
            .child_process = child_process,
            .build_root = options.build_root,
            .zig_exe_path = duped_zig_exe_path,
            .check_step_only = options.check_step_only,
        };

        const worker = try io.concurrent(loop, .{
            io,
            gpa,
            worker_state,
            options.diagnostics,
        });
        errdefer comptime unreachable;

        return .{
            .io = io,
            .allocator = gpa,
            .worker = worker,
            .worker_state = worker_state,
        };
    }

    pub fn deinit(self: *BuildOnSave) void {
        self.worker.cancel(self.io);
        var dir = self.worker_state.build_root;
        dir.closeAndFree(self.allocator, self.io);
        self.allocator.free(self.worker_state.zig_exe_path);
        self.allocator.destroy(self.worker_state);
        self.* = undefined;
    }

    pub fn sendManualWatchUpdate(build_on_save: *BuildOnSave) void {
        const io = build_on_save.io;

        if (true) @panic("TODO: sendManualWatchUpdate");

        build_on_save.worker_state.mutex.lockUncancelable(io);
        defer build_on_save.worker_state.mutex.unlock(io);
        const stdin = build_on_save.worker_state.child_process.stdin orelse return;
        const selected_step = build_on_save.worker_state.selected_step;

        var stdin_writer_buffer: [256]u8 = undefined;
        var stdin_writer = stdin.writer(io, &stdin_writer_buffer);
        var client: Client = .{
            .in = undefined,
            .out = &stdin_writer.interface,
        };

        const old_cancel_protect = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(old_cancel_protect);

        client.serveBuildSteps(
            &.{selected_step},
            .{ .watch = false },
        ) catch |err| switch (err) {
            error.WriteFailed => switch (stdin_writer.err.?) {
                error.Canceled => unreachable,
                else => @panic("TODO"),
            },
        };
    }

    fn loop(
        io: Io,
        gpa: Allocator,
        state: *WorkerState,
        diagnostics: *DiagnosticsCollection,
    ) void {
        defer state.child_process.kill(io);

        var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: Io.File.MultiReader = undefined;
        multi_reader.init(
            gpa,
            io,
            multi_reader_buffer.toStreams(),
            &.{ state.child_process.stdout.?, state.child_process.stderr.? },
        );
        defer multi_reader.deinit();
        const stdout = multi_reader.reader(0);
        const stderr = multi_reader.reader(1);

        var stdin_writer_buffer: [256]u8 = undefined;
        var stdin_writer = state.child_process.stdin.?.writer(io, &stdin_writer_buffer);
        var client: Client = .{
            .in = stdout,
            .out = &stdin_writer.interface,
        };

        loopCatchReportError(
            io,
            gpa,
            &client,
            &multi_reader,
            diagnostics,
            state.build_root,
            state.zig_exe_path,
            state.check_step_only,
        ) catch |err| switch (err) {
            error.Canceled => {},
            error.AlreadyReported => {},
            error.WriteFailed => switch (stdin_writer.err.?) {
                error.Canceled => return,
                else => |e| log.err("failed to send message to {s} in {f}: {t}", .{ protocol_name, state.build_root, e }),
            },
            else => |e| log.err("{t} from {s} in {f}", .{ e, protocol_name, state.build_root }),
        };

        client.serveBodylessMessage(.exit) catch |err| switch (err) {
            error.WriteFailed => switch (stdin_writer.err.?) {
                error.Canceled => return,
                else => |e| log.err("failed to send message to {s} in {f}: {t}", .{ protocol_name, state.build_root, e }),
            },
        };

        multi_reader.fillRemaining(.none) catch |err| switch (err) {
            error.Canceled => {},
            else => |e| log.err("{t} from {s} in {f}", .{ e, protocol_name, state.build_root }),
        };

        const old_cancel_protect = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(old_cancel_protect);

        state.mutex.lockUncancelable(io);
        defer state.mutex.unlock(io);

        state.child_process.stdin.?.close(io);
        state.child_process.stdin = null;

        const term = state.child_process.wait(io) catch |err| {
            log.warn("Failed to await {s} in {f}: {t}", .{ protocol_name, state.build_root, err });
            return;
        };

        // if (!term.success()) {
        // }
        const stderr_msg_prefix = if (stderr.bufferedLen() > 0) " with stderr:\n" else "";
        log.err("{s} in {f} {f}{s}{s}", .{ protocol_name, state.build_root, term, stderr_msg_prefix, stderr.buffered() });
    }

    fn loopCatchReportError(
        io: Io,
        gpa: Allocator,
        client: *std.zig.Client,
        multi_reader: *Io.File.MultiReader,
        diagnostics: *DiagnosticsCollection,
        build_root: Directory,
        zig_exe_path: []const u8,
        check_step_only: bool,
    ) !void {
        // TODO send LSP progress report

        const handshake: Handshake = while (true) {
            const header: Server.Message.Header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.Timeout => unreachable,
                else => |e| {
                    log.err("failed to receive message from {s}: {t}", .{ protocol_name, e });
                    return error.AlreadyReported;
                },
            };
            const body = client.in.take(header.bytes_len) catch unreachable;

            switch (header.tag) {
                .zig_version => {},
                .error_bundle => {},
                .bsp_handshake => {
                    break Handshake.init(
                        gpa,
                        build_root.path.?,
                        zig_exe_path,
                        body,
                    ) catch |err| {
                        log.err("failed to receive message from {s}: {t}", .{ protocol_name, err });
                        return error.AlreadyReported;
                    };
                },
                else => log.warn("received unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
            }
        };

        var did_log_start = false;
        defer if (did_log_start) log.info("Build-On-Save stopped for '{f}'", .{build_root});

        var arena_allocator = handshake.arena.promote(gpa);
        defer arena_allocator.deinit();

        var cycle: u32 = 0;
        conf_loop: while (true) {
            defer _ = arena_allocator.reset(.retain_capacity);
            const arena = arena_allocator.allocator();

            const configuration: Configuration = while (true) {
                const header: Server.Message.Header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
                    error.Canceled => |e| return e,
                    error.Timeout => unreachable,
                    else => |e| {
                        log.err("failed to receive message from {s}: {t}", .{ protocol_name, e });
                        return error.AlreadyReported;
                    },
                };
                if (header.tag != .bsp_configuration) {
                    log.err("unexpected message from {s}: {f}", .{ protocol_name, fmtEnum(header.tag) });
                    return error.AlreadyReported;
                }
                const configuration_file_path = client.in.take(header.bytes_len) catch unreachable;
                const configuration_file = build_root.handle.openFile(io, configuration_file_path, .{}) catch |err| {
                    log.err("failed to open configuration file {q}: {t}", .{ configuration_file_path, err });
                    return error.AlreadyReported;
                };
                defer configuration_file.close(io);
                break Configuration.loadFile(arena, io, configuration_file) catch |err| {
                    log.err("failed to load configuration file {q}: {t}", .{ configuration_file_path, err });
                    return error.AlreadyReported;
                };
            };

            var top_level_steps: std.array_hash_map.String(Configuration.Step.Index) = .empty;
            for (configuration.steps, 0..) |*conf_step, step_index_usize| {
                if (conf_step.owner != .root) continue;
                const step_index: Configuration.Step.Index = @fromBackingInt(@intCast(step_index_usize));
                const flags = conf_step.flags(&configuration);
                if (flags.tag != .top_level) continue;
                const name = step_index.ptr(&configuration).name.slice(&configuration);
                try top_level_steps.put(arena, name, step_index);
            }

            const selected_step = top_level_steps.get("check") orelse
                if (!check_step_only)
                    configuration.default_step
                else {
                    // This will ignore future `.bsp_configuration` notifications that could introduce a check step.
                    return error.AlreadyReported;
                };

            if (!did_log_start) {
                log.info("Build-On-Save is running for '{f}'", .{build_root});
                did_log_start = true;
            }

            client.serveBuildSteps(
                &.{selected_step},
                .{ .watch = handshake.flags.file_system_watch_supported },
            ) catch |err| switch (err) {
                error.WriteFailed => |e| return e,
            };

            var diagnostic_tags: std.array_hash_map.Auto(DiagnosticsCollection.Tag, void) = .empty;
            defer diagnostic_tags.deinit(gpa);

            defer {
                for (diagnostic_tags.keys()) |tag| diagnostics.clearErrorBundle(tag);
                diagnostics.publishDiagnostics() catch |err| switch (err) {
                    error.Canceled => {}, // TODO cancellation should be fine since we are returning anyway
                    else => log.err("failed to publish diagnostics: {t}", .{err}),
                };
            }

            while (true) {
                const header: Server.Message.Header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
                    error.Canceled => |e| return e, // TODO try to cleanly exit child process
                    error.Timeout => unreachable,
                    error.EndOfStream => break :conf_loop,
                    else => std.debug.panic("failed to receive message from {s}: {t}", .{ protocol_name, err }), // TODO
                };
                const body = client.in.take(header.bytes_len) catch unreachable;

                log.debug("received build-on-save message: {f}", .{fmtEnum(header.tag)});

                switch (header.tag) {
                    .bsp_configuration => break,
                    .bsp_build_started => {},
                    .bsp_build_completed => cycle += 1,
                    .bsp_step_started => {},
                    .bsp_step_completed => {
                        var message = receiveBuildStepCompleted(gpa, body) catch @panic("TODO");
                        defer message.deinit(gpa);

                        const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
                            var hasher: std.hash.Wyhash = .init(0);

                            hasher.update(build_root.path.?);
                            std.hash.autoHash(&hasher, message.step_index);
                            break :tag @fromBackingInt(@truncate(hasher.final()));
                        };

                        diagnostic_tags.put(gpa, diagnostic_tag, {}) catch @panic("TODO");

                        diagnostics.pushErrorBundle(
                            diagnostic_tag,
                            cycle,
                            build_root.path.?,
                            message.error_bundle,
                        ) catch @panic("TODO");

                        // TODO debounce this
                        diagnostics.publishDiagnostics() catch |err| switch (err) {
                            error.Canceled => |e| return e, // TODO try to cleanly exit child process
                            else => log.err("failed to publish diagnostics: {t}", .{err}),
                        };
                    },
                    else => log.warn("received unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
                }
            }
        }
    }
};

const BuildStepCompleted = struct {
    step_index: std.Build.Configuration.Step.Index,
    status: Server.Message.BuildStepCompleted.Status,
    error_bundle: std.zig.ErrorBundle,
    generated_files: std.MultiArrayList(GeneratedFile),
    string_bytes: []const u8,

    const GeneratedFile = struct {
        index: Configuration.GeneratedFileIndex,
        base: Configuration.LazyPath.Relative.Base,
        sub_path: u32,
    };

    fn deinit(result: *BuildStepCompleted, gpa: Allocator) void {
        gpa.free(result.error_bundle.extra);
        gpa.free(result.error_bundle.string_bytes);
        result.generated_files.deinit(gpa);
        gpa.free(result.string_bytes);
    }
};

fn receiveBuildStepCompleted(gpa: Allocator, body: []const u8) !BuildStepCompleted {
    var reader: Io.Reader = .fixed(body);
    const header = try reader.takeStruct(Server.Message.BuildStepCompleted, .little);

    const eb_extra = try reader.readSliceEndianAlloc(gpa, u32, header.error_bundle.extra_len, .little);
    errdefer gpa.free(eb_extra);

    const eb_string_bytes = try reader.readAlloc(gpa, header.error_bundle.string_bytes_len);
    errdefer gpa.free(eb_string_bytes);

    var generated_files: std.MultiArrayList(BuildStepCompleted.GeneratedFile) = try .initCapacity(gpa, header.generated_file_count);
    errdefer generated_files.deinit(gpa);
    generated_files.len = header.generated_file_count;

    try reader.readSliceEndian(Configuration.GeneratedFileIndex, generated_files.items(.index), .little);
    try reader.readSliceEndian(Configuration.LazyPath.Relative.Base, generated_files.items(.base), .little);
    try reader.readSliceEndian(u32, generated_files.items(.sub_path), .little);
    const string_bytes = try reader.readAlloc(gpa, header.string_bytes_len);

    return .{
        .step_index = header.step_index,
        .status = header.status,
        .error_bundle = .{ .extra = eb_extra, .string_bytes = eb_string_bytes },
        .generated_files = generated_files,
        .string_bytes = string_bytes,
    };
}

pub fn receiveErrorBundle(c: *const Client, gpa: Allocator) Io.Reader.ReadAllocError!std.zig.ErrorBundle {
    const header = try c.in.takeStruct(Server.Message.ErrorBundle, .little);
    const extra = try c.in.readSliceEndianAlloc(gpa, u32, header.extra_len, .little);
    errdefer gpa.free(extra);
    const string_bytes = try c.in.readAlloc(gpa, header.string_bytes_len);
    errdefer gpa.free(string_bytes);
    return .{
        .string_bytes = string_bytes,
        .extra = extra,
    };
}

const FormatEnum = union(enum) {
    named: []const u8,
    unnamed: usize,

    pub fn format(
        e: FormatEnum,
        writer: *Io.Writer,
    ) Io.Writer.Error!void {
        switch (e) {
            .named => |name| {
                try writer.writeByte('.');
                try writer.writeAll(name);
            },
            .unnamed => |number| try writer.print("0x{x}", .{number}),
        }
    }
};

fn fmtEnum(e: anytype) FormatEnum {
    if (std.enums.tagName(@TypeOf(e), e)) |name| {
        return .{ .named = name };
    } else {
        return .{ .unnamed = @backingInt(e) };
    }
}
