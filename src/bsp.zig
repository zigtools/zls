//! A client for the build system protocol to integrate with the Zig build system.

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

const protocol_name = "build system server";

pub const BuildConfig = struct {
    arena: std.heap.ArenaAllocator.State,
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

    pub fn deinit(config: *BuildConfig, gpa: Allocator) void {
        config.arena.promote(gpa).deinit();
        config.* = undefined;
    }
};

pub const LoadBuildConfigOptions = struct {
    zig_exe_path: []const u8,
    zig_lib_dir: Directory,
    zig_global_cache_dir: Directory,
    diagnostics: *DiagnosticsCollection,
    build_file_uri: Uri,
    build_file_version: u32,
};

/// Runs the build.zig and extracts include directories and packages
pub fn loadBuildConfiguration(
    io: Io,
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    options: *const LoadBuildConfigOptions,
) error{ Canceled, AlreadyReported, OutOfMemory }!BuildConfig {
    const build_file_path = options.build_file_uri.toFsPath(gpa) catch |err| switch (err) {
        error.UnsupportedScheme => unreachable,
        error.OutOfMemory => |e| return e,
    };
    defer gpa.free(build_file_path);

    const build_root_path = Dir.path.dirname(build_file_path) orelse {
        log.err("failed to open build root for {q}", .{build_file_path});
        return error.AlreadyReported;
    };
    const build_root_handle = Dir.cwd().openDir(io, build_root_path, .{}) catch |err| {
        log.err("failed to open {q}: {t}", .{ build_root_path, err });
        return error.AlreadyReported;
    };
    defer build_root_handle.close(io);

    const build_root: Directory = .{
        .handle = build_root_handle,
        .path = build_root_path,
    };

    const argv: []const []const u8 = &.{
        options.zig_exe_path,
        "build",
        "--listen=-",
    };

    var child_environ_map = try environ_map.clone(gpa);
    defer child_environ_map.deinit();

    try child_environ_map.put("ZIG_DEBUG_CMD", "1");
    try child_environ_map.put("ZIG_LIB_DIR", options.zig_lib_dir.path orelse ".");

    const cmd: std.zig.SubprocessCommand = .{
        .argv = argv,
        .cwd = build_root.path,
        .parent_env = environ_map,
        .child_env = &child_environ_map,
    };

    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = build_root.handle },
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
    errdefer child.kill(io);

    var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(
        gpa,
        io,
        multi_reader_buffer.toStreams(),
        &.{ child.stdout.?, child.stderr.? },
    );
    defer multi_reader.deinit();
    const stdout = multi_reader.reader(0);
    const stderr = multi_reader.reader(1);

    var stdin_buffer: [256]u8 = undefined;
    var stdin_writer = child.stdin.?.writer(io, &stdin_buffer);

    var client: Client = .{
        .in = stdout,
        .out = &stdin_writer.interface,
    };

    const build_config = loadBuildConfigurationInner(
        io,
        gpa,
        environ_map,
        &client,
        &multi_reader,
        cmd,
        build_root,
        options,
    ) catch |err| switch (err) {
        error.Canceled, error.AlreadyReported => |e| return e,
        error.WriteFailed => switch (stdin_writer.err.?) {
            error.Canceled => |e| return e,
            else => |e| {
                log.err("failed to send message to {s} in {qf}: {t}", .{ protocol_name, build_root, e });
                return error.AlreadyReported;
            },
        },
        error.EndOfStream, error.OutOfMemory => |e| {
            log.err("{t} from {s} in {qf}", .{ e, protocol_name, build_root });
            return error.AlreadyReported;
        },
    };

    client.serveBodylessMessage(.exit) catch |err| switch (err) {
        error.WriteFailed => switch (stdin_writer.err.?) {
            error.Canceled => |e| return e,
            else => |e| log.err("failed to send message to {s} in {qf}: {t}", .{ protocol_name, build_root, e }),
        },
    };

    const term = child.wait(io) catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => |e| {
            log.err("failed to await {s} in {qf}: {t}", .{ protocol_name, build_root, e });
            return error.AlreadyReported;
        },
    };

    if (!term.success()) {
        const stderr_msg_prefix = if (stderr.bufferedLen() > 0) " with stderr:\n" else "";
        log.err("{s} in {qf} {f}{s}{s}\ncommand:\n{f}", .{ protocol_name, build_root, term, stderr_msg_prefix, stderr.buffered(), cmd });
        return error.AlreadyReported;
    }

    return build_config;
}

fn loadBuildConfigurationInner(
    io: Io,
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    client: *std.zig.Client,
    multi_reader: *Io.File.MultiReader,
    cmd: std.zig.SubprocessCommand,
    build_root: Directory,
    options: *const LoadBuildConfigOptions,
) error{ Canceled, AlreadyReported, WriteFailed, EndOfStream, OutOfMemory }!BuildConfig {
    var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
        var hasher: std.hash.Wyhash = .init(47); // Chosen by the following prompt: Pwease give a wandom nyumbew
        hasher.update(options.build_file_uri.raw);
        break :tag @fromBackingInt(@truncate(hasher.final()));
    };

    while (true) {
        const header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.Timeout => unreachable,
            else => |e| {
                log.err("{t} reading from {s}:\n{f}", .{ e, protocol_name, cmd });
                return error.AlreadyReported;
            },
        };
        const body = client.in.take(header.bytes_len) catch unreachable;
        _ = body;
        switch (header.tag) {
            .bsp_handshake => break,
            else => {
                log.err("unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) });
                return error.AlreadyReported;
            },
        }
    }

    const configuration: Configuration = conf: {
        const header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.Timeout => unreachable,
            else => |e| {
                log.err("{t} reading from {s}:\n{f}", .{ e, protocol_name, cmd });
                return error.AlreadyReported;
            },
        };
        const body = client.in.take(header.bytes_len) catch unreachable;

        switch (header.tag) {
            .bsp_configuration => {
                const configuration_file_path = body;
                const configuration_file = build_root.handle.openFile(io, configuration_file_path, .{}) catch |err| {
                    log.err("failed to open configuration file {q}: {t}", .{ configuration_file_path, err });
                    return error.AlreadyReported;
                };
                defer configuration_file.close(io);
                break :conf Configuration.loadFile(arena, io, configuration_file) catch |err| {
                    log.err("failed to load configuration file {q}: {t}", .{ configuration_file_path, err });
                    return error.AlreadyReported;
                };
            },
            .bsp_configuration_failed => {
                var reader: Io.Reader = .fixed(body);
                const hdr = reader.takeStruct(Server.Message.ErrorBundle, .little) catch |err| switch (err) {
                    error.ReadFailed => unreachable,
                    error.EndOfStream => |e| return e,
                };

                var error_bundle = std.zig.ErrorBundle.readAlloc(
                    &reader,
                    gpa,
                    hdr.extra_len,
                    hdr.string_bytes_len,
                ) catch |err| switch (err) {
                    error.ReadFailed => unreachable,
                    error.OutOfMemory, error.EndOfStream => |e| return e,
                };
                defer error_bundle.deinit(gpa);

                try options.diagnostics.pushErrorBundle(
                    diagnostic_tag,
                    options.build_file_version,
                    build_root.path.?,
                    error_bundle,
                );

                options.diagnostics.publishDiagnostics() catch |err| switch (err) {
                    error.Canceled => |e| return e,
                    else => log.err("failed to publish diagnostics: {t}", .{err}),
                };

                return error.AlreadyReported;
            },
            else => {
                log.err("unexpected {f} message from {s}:\n{f}", .{ fmtEnum(header.tag), protocol_name, cmd });
                return error.AlreadyReported;
            },
        }
    };
    const c = &configuration;

    const local_cache_path = path: {
        if (std.zig.EnvVar.ZIG_LOCAL_CACHE_DIR.get(environ_map)) |p| {
            const cwd = std.process.currentPathAlloc(io, gpa) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => |e| {
                    log.err("failed to resolve current working directory: {}", .{e});
                    return error.AlreadyReported;
                },
            };
            defer gpa.free(cwd);
            break :path try Dir.path.resolve(gpa, &.{ cwd, p });
        }
        break :path try Dir.path.resolve(arena, &.{ build_root.path.?, std.zig.default_local_zig_cache_basename });
    };

    const base_paths: BasePaths = .init(.{
        .cwd = build_root.path.?,
        .local_cache = local_cache_path,
        .global_cache = options.zig_global_cache_dir.path.?,
        .build_root = build_root.path.?,
        .zig_exe = options.zig_exe_path,
        .zig_lib = options.zig_lib_dir.path.?,
        // unavailable base paths:
        // .install_prefix
        // .install_lib
        // .install_bin
        // .install_include
        // .libc_runtimes
    });
    // const root_package: Configuration.Package.Index = .root;
    // const root_package_instance: Configuration.Package.Instance.Index = .root;

    // The value tracks whether the step is a decendant of the default step step.
    var all_steps: std.array_hash_map.Auto(Configuration.Step.Index, bool) = .empty;
    defer all_steps.deinit(gpa);

    // collect all steps that are decendants of the "install" step.
    {
        try all_steps.putNoClobber(gpa, c.default_step, true);

        var i: usize = 0;
        while (i < all_steps.count()) : (i += 1) {
            const step = all_steps.keys()[i].ptr(c);
            const deps = step.deps.slice(c);

            try all_steps.ensureUnusedCapacity(gpa, deps.len);
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

            try all_steps.ensureUnusedCapacity(gpa, deps.len);
            for (deps) |other_step| {
                all_steps.putAssumeCapacity(other_step, true);
            }
        }
    }

    var resolved_generated_files: std.array_hash_map.Auto(Configuration.GeneratedFileIndex, GeneratedFile) = .empty;
    defer resolved_generated_files.deinit(gpa);

    // Collect all steps that need to be run so that we can resolve the lazy paths we are interested in (e.g. root_source_file).
    {
        var needed_steps: std.array_hash_map.Auto(Configuration.Step.Index, void) = .empty;
        defer needed_steps.deinit(gpa);

        var modules: std.array_hash_map.Auto(Configuration.Module.Index, void) = .empty;
        defer modules.deinit(gpa);

        // collect all exported modules of the root package
        // const root_package_modules = root_package_instance.ptr(c).exported_modules;
        // for (root_package_modules.modules.slice(c)) |module| {
        //     try modules.put(gpa, module, {});
        // }

        // collect all root modules of compile steps
        for (all_steps.keys()) |step| {
            const compile = step.ptr(c).extended.cast(c, Configuration.Step.Compile) orelse continue;
            try modules.put(gpa, compile.root_module, {});
        }

        // collect transitively imported modules
        var index: usize = 0;
        while (index < modules.count()) : (index += 1) {
            const mod = modules.keys()[index].get(c);
            const import_table = mod.import_table.get(c).imports.mal;
            try modules.ensureUnusedCapacity(gpa, import_table.len);
            for (import_table.items(.module)) |other_mod| {
                modules.putAssumeCapacity(other_mod, {});
            }
        }

        var generated_file_owner_map: std.array_hash_map.Auto(Configuration.GeneratedFileIndex, Configuration.Step.Index) = .empty;
        defer generated_file_owner_map.deinit(gpa);

        for (c.steps, 0..) |*step, i| {
            const step_index: Configuration.Step.Index = @fromBackingInt(@intCast(i));
            switch (step.extended.get(c.extra)) {
                .check_file,
                .fail,
                .fmt,
                .install_artifact,
                .install_dir,
                .install_file,
                .top_level,
                .update_source_files,
                => {},

                .compile => |compile| {
                    if (compile.emit_directory.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_docs.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_asm.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_bin.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_pdb.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_implib.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_llvm_bc.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_llvm_ir.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                    if (compile.generated_h.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                },
                .config_header => |config_header| {
                    try generated_file_owner_map.putNoClobber(gpa, config_header.generated_dir, step_index);
                },
                .find_program => |find_program| {
                    try generated_file_owner_map.putNoClobber(gpa, find_program.found_path, step_index);
                },
                .obj_copy => |obj_copy| {
                    try generated_file_owner_map.putNoClobber(gpa, obj_copy.output_file, step_index);
                    if (obj_copy.debug_file.value) |gf| try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                },
                .options => |options_step| {
                    try generated_file_owner_map.putNoClobber(gpa, options_step.generated_file, step_index);
                },
                .run => |run| {
                    if (run.captured_stdout.value) |v| try generated_file_owner_map.putNoClobber(gpa, v.generated_file, step_index);
                    if (run.captured_stderr.value) |v| try generated_file_owner_map.putNoClobber(gpa, v.generated_file, step_index);
                    for (run.args.slice) |arg| {
                        if (arg.get(c).generated.value) |gf| {
                            try generated_file_owner_map.putNoClobber(gpa, gf, step_index);
                        }
                    }
                },
                .translate_c => |translate_c| {
                    try generated_file_owner_map.putNoClobber(gpa, translate_c.output_file, step_index);
                },
                .write_file => |write_file| {
                    try generated_file_owner_map.putNoClobber(gpa, write_file.generated_directory, step_index);
                },
            }
        }

        // collect step dependencies of modules
        for (modules.keys()) |module_index| {
            const module = module_index.get(c);
            const root_source_file = module.root_source_file.unwrap() orelse continue;
            switch (root_source_file.get(c)) {
                .source_path, .relative => {},
                .generated => |gen| {
                    const owner_step = generated_file_owner_map.get(gen.index).?;
                    try needed_steps.put(gpa, owner_step, {});
                },
            }
        }

        try client.serveBuildSteps(needed_steps.keys(), .{ .watch = false });

        // populate `resolved_generated_files`
        while (true) {
            const header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.Timeout => unreachable,
                else => |e| {
                    log.err("{t} reading from {s}:\n{f}", .{ e, protocol_name, cmd });
                    return error.AlreadyReported;
                },
            };
            const body = client.in.take(header.bytes_len) catch unreachable;

            switch (header.tag) {
                .bsp_build_started => {},
                .bsp_build_completed => break,
                .bsp_step_started => {},
                .bsp_step_completed => {
                    var reader: Io.Reader = .fixed(body);
                    const bsc = reader.takeStruct(Server.Message.BuildStepCompleted, .little) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.EndOfStream => |e| return e,
                    };

                    var error_bundle = std.zig.ErrorBundle.readAlloc(
                        &reader,
                        gpa,
                        bsc.error_bundle.extra_len,
                        bsc.error_bundle.string_bytes_len,
                    ) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.OutOfMemory, error.EndOfStream => |e| return e,
                    };
                    defer error_bundle.deinit(gpa);

                    const generated_files_data = reader.take(bsc.generated_files_len * @sizeOf(Server.Message.GeneratedFile)) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.EndOfStream => |e| return e,
                    };
                    const generated_files: []align(1) Server.Message.GeneratedFile = @ptrCast(generated_files_data);
                    for (generated_files) |gf| {
                        const prefix = reader.takeEnum(Server.Message.PathPrefix, .little) catch |err| switch (err) {
                            error.ReadFailed, error.InvalidEnumTag => unreachable,
                            error.EndOfStream => |e| return e,
                        };
                        const sub_path = reader.take(gf.path_len) catch |err| switch (err) {
                            error.ReadFailed => unreachable,
                            error.EndOfStream => |e| return e,
                        };
                        try resolved_generated_files.put(gpa, gf.index, .{
                            .prefix = prefix,
                            .sub_path = try arena.dupe(u8, sub_path),
                        });
                    }

                    try options.diagnostics.pushErrorBundle(
                        diagnostic_tag,
                        options.build_file_version,
                        build_root.path,
                        error_bundle,
                    );
                    continue;
                },
                .bsp_configuration,
                .bsp_configuration_failed,
                => {
                    log.err("TODO configuration unexpectedly invalidated", .{});
                    return error.AlreadyReported;
                },
                else => log.warn("unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
            }
        }
    }

    // We collect modules in the following order:
    // - exported modules (`std.Build.addModule`)
    // - modules that are reachable from the "install" step
    // - all other reachable modules
    var modules: std.array_hash_map.Auto(Configuration.Module.Index, void) = .empty;
    defer modules.deinit(gpa);

    // const root_package_modules = root_package_instance.ptr(c).exported_modules;
    // try modules.ensureUnusedCapacity(gpa, root_package_modules.modules.get(c).modules.slice.len);
    // for (root_package_modules.modules.slice(c)) |module| {
    //     modules.putAssumeCapacity(module, {});
    // }

    // We loop twice through all steps so that decendants of the "install" step are processed first.
    for ([_]bool{ true, false }) |want_install_step_decendant| {
        for (all_steps.keys(), all_steps.values()) |step_index, is_install_step_decendant| {
            if (is_install_step_decendant != want_install_step_decendant) continue;
            const step = step_index.ptr(c);
            const compile = step.extended.cast(c, Configuration.Step.Compile) orelse continue;
            try modules.put(gpa, compile.root_module, {});
        }
    }

    var resolved_modules: std.array_hash_map.String(BuildConfig.Module) = .empty;

    var index: usize = 0;
    while (index < modules.count()) : (index += 1) {
        const module = modules.keys()[index].get(c);
        const import_table = module.import_table.get(c).imports.mal;

        for (import_table.items(.module)) |import| try modules.put(gpa, import, {});

        const root_source_file = module.root_source_file.unwrap() orelse continue;
        const root_source_file_path = try resolveLazyPath(
            arena,
            root_source_file.get(c),
            base_paths,
            resolved_generated_files,
            c,
        ) orelse continue;

        // All modules with the same root source file are merged. This limitation may be lifted in the future.
        const gop = try resolved_modules.getOrPutValue(arena, root_source_file_path, .{
            .import_table = .{},
        });

        for (import_table.items(.name), import_table.items(.module)) |name, import_module| {
            const import_root_source_file = import_module.get(c).root_source_file.unwrap() orelse continue;
            const import_root_source_file_path = try resolveLazyPath(
                arena,
                import_root_source_file.get(c),
                base_paths,
                resolved_generated_files,
                c,
            ) orelse continue;

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
        const root_source_file_path = try resolveLazyPath(
            arena,
            root_source_file.get(c),
            base_paths,
            resolved_generated_files,
            c,
        ) orelse continue;
        try compilations.append(arena, .{
            .root_module = root_source_file_path,
        });
    }

    var dependencies: std.array_hash_map.String([]const u8) = .empty;
    _ = &dependencies;
    // const root_package_dependencies = root_package.ptr(c).deps.slice(c);
    // try dependencies.ensureTotalCapacity(arena, root_package_dependencies.len);
    // for (root_package_dependencies) |dependency| {
    //     const package_name = dependency.name.slice(c);
    //     const package_path = dependency.package.ptr(c).path.slice(c) orelse continue;
    //     const resolved_package_path = try Dir.path.resolve(arena, &.{ maker.base_paths.get(.build_root), package_path, "build.zig" });
    //     dependencies.putAssumeCapacityNoClobber(package_name, resolved_package_path);
    // }

    options.diagnostics.publishDiagnostics() catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => log.err("failed to publish diagnostics: {t}", .{err}),
    };

    return .{
        .arena = arena_allocator.state,
        .dependencies = .{ .map = dependencies },
        .modules = .{ .map = resolved_modules },
        .compilations = compilations.items,
    };
}

const BasePaths = std.enums.EnumMap(Configuration.LazyPath.Relative.Base, []const u8);

const GeneratedFile = struct {
    prefix: Server.Message.PathPrefix,
    sub_path: []const u8,
};

fn resolveLazyPath(
    arena: Allocator,
    lazy_path: Configuration.LazyPath,
    base_paths: BasePaths,
    generated_files: std.array_hash_map.Auto(Configuration.GeneratedFileIndex, GeneratedFile),
    c: *const Configuration,
) Allocator.Error!?[]const u8 {
    return switch (lazy_path) {
        .source_path => |source_path| {
            const base_path = base_paths.get(.build_root) orelse return null;
            const package_path = if (source_path.owner.get(c)) |package| package.root_path.slice(c) else "";
            const sub_path = source_path.sub_path.slice(c);
            return try Dir.path.join(arena, &.{ base_path, package_path, sub_path });
        },
        .relative => |relative| {
            const base_path = base_paths.get(relative.flags.base) orelse return null;
            const sub_path = relative.sub_path.slice(c);
            if (sub_path.len == 0) return base_path;
            return try Dir.path.join(arena, &.{ base_path, sub_path });
        },
        .generated => |gen| {
            const gf = generated_files.get(gen.index) orelse return null;
            const base = switch (gf.prefix) {
                inline else => |t| @field(Configuration.LazyPath.Relative.Base, @tagName(t)),
            };
            const base_path = base_paths.get(base) orelse return null;
            var file_path = gf.sub_path;
            for (0..gen.flags.up) |_| {
                file_path = Dir.path.dirname(file_path) orelse return null;
            }
            return try Dir.path.join(arena, &.{ base_path, file_path, gen.sub_path.slice(c) });
        },
    };
}

pub const BuildOnSave = struct {
    io: Io,
    allocator: Allocator,
    worker: Io.Future(void),
    worker_state: *WorkerState,

    const WorkerState = struct {
        mutex: Io.Mutex,
        child_process: std.process.Child,
        manual_save: Io.Event = .unset,
    };

    pub const Supported = union(enum) {
        supported,
        invalid_linux_kernel_version: if (builtin.os.tag == .linux) @FieldType(std.os.linux.utsname, "release") else noreturn,
        unsupported_linux_kernel_version: if (builtin.os.tag == .linux) std.SemanticVersion else noreturn,

        /// std.build.Watch requires `AT_HANDLE_FID` which is Linux 6.5+
        /// https://github.com/ziglang/zig/issues/20720
        pub const minimum_linux_version: std.SemanticVersion = .{ .major = 6, .minor = 5, .patch = 0 };
    };

    pub inline fn isSupportedComptime() bool {
        if (!std.process.can_spawn) return false;
        // This checks assumes that the io implementation is `std.Io.Threaded`. `std.Io.Evented` should support concurrency in single threaded mode.
        if (builtin.single_threaded) return false;
        return true;
    }

    pub fn isSupportedRuntime(runtime_zig_version: std.SemanticVersion) Supported {
        comptime std.debug.assert(isSupportedComptime());
        _ = runtime_zig_version;

        if (builtin.os.tag == .linux) blk: {
            var utsname: std.os.linux.utsname = undefined;
            std.debug.assert(std.os.linux.uname(&utsname) == 0);
            const unparsed_version = std.mem.sliceTo(&utsname.release, 0);
            const version = parseUnameKernelVersion(unparsed_version) catch
                return .{ .invalid_linux_kernel_version = utsname.release };

            if (version.order(Supported.minimum_linux_version) != .lt) break :blk;
            std.debug.assert(version.build == null and version.pre == null); // Otherwise, returning the `std.SemanticVersion` would be unsafe
            return .{
                .unsupported_linux_kernel_version = version,
            };
        }

        return .supported;
    }

    /// Parses a Linux Kernel Version. The result will ignore pre-release and build metadata.
    fn parseUnameKernelVersion(kernel_version: []const u8) !std.SemanticVersion {
        const extra_index = for (kernel_version, 0..) |c, i| {
            switch (c) {
                '-', '+' => break i,
                else => continue,
            }
        } else null;
        const required = kernel_version[0..(extra_index orelse kernel_version.len)];
        var it = std.mem.splitScalar(u8, required, '.');
        return .{
            .major = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
            .minor = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
            .patch = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
        };
    }

    test parseUnameKernelVersion {
        try std.testing.expectFmt("5.17.0", "{f}", .{try parseUnameKernelVersion("5.17.0")});
        try std.testing.expectFmt("6.12.9", "{f}", .{try parseUnameKernelVersion("6.12.9-rc7")});
        try std.testing.expectFmt("6.6.71", "{f}", .{try parseUnameKernelVersion("6.6.71-42-generic")});
        try std.testing.expectFmt("5.15.167", "{f}", .{try parseUnameKernelVersion("5.15.167.4-microsoft-standard-WSL2")}); // WSL2
        try std.testing.expectFmt("4.4.0", "{f}", .{try parseUnameKernelVersion("4.4.0-20241-Microsoft")}); // WSL1

        try std.testing.expectError(error.InvalidCharacter, parseUnameKernelVersion(""));
        try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5"));
        try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5.5"));
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

        worker_state.* = .{
            .mutex = .init,
            .child_process = child_process,
        };

        const worker = try io.concurrent(loop, .{
            io,
            gpa,
            worker_state,
            options.build_root,
            options.check_step_only,
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
        self.allocator.destroy(self.worker_state);
        self.* = undefined;
    }

    pub fn sendManualWatchUpdate(build_on_save: *BuildOnSave) void {
        const io = build_on_save.io;
        build_on_save.worker_state.manual_save.set(io);
    }

    fn loop(
        io: Io,
        gpa: Allocator,
        state: *WorkerState,
        build_root: Directory,
        check_step_only: bool,
        diagnostics: *DiagnosticsCollection,
    ) void {
        defer {
            state.child_process.kill(io);
            var dir = build_root;
            dir.closeAndFree(gpa, io);
        }

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
            build_root,
            check_step_only,
            state,
        ) catch |err| switch (err) {
            error.Canceled => {},
            error.AlreadyReported => {},
            error.WriteFailed => switch (stdin_writer.err.?) {
                error.Canceled => return,
                else => |e| log.err("failed to send message to {s} in {qf}: {t}", .{ protocol_name, build_root, e }),
            },
            error.EndOfStream, error.OutOfMemory => |e| log.err("{t} from {s} in {qf}", .{ e, protocol_name, build_root }),
        };

        const old_cancel_protect = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(old_cancel_protect);

        client.serveBodylessMessage(.exit) catch |err| switch (err) {
            error.WriteFailed => switch (stdin_writer.err.?) {
                error.Canceled => unreachable,
                else => |e| return log.err("failed to send message to {s} in {qf}: {t}", .{ protocol_name, build_root, e }),
            },
        };

        multi_reader.fillRemaining(.none) catch |err| switch (err) {
            error.Canceled => unreachable,
            else => |e| return log.err("{t} from {s} in {qf}", .{ e, protocol_name, build_root }),
        };

        const term = state.child_process.wait(io) catch |err| switch (err) {
            error.Canceled => unreachable,
            else => |e| return log.err("failed to await {s} in {qf}: {t}", .{ protocol_name, build_root, e }),
        };

        if (term.success()) return;

        const stderr_msg_prefix = if (stderr.bufferedLen() > 0) " with stderr:\n" else "";
        log.err("{s} in {qf} {f}{s}{s}", .{ protocol_name, build_root, term, stderr_msg_prefix, stderr.buffered() });
    }

    fn loopCatchReportError(
        io: Io,
        gpa: Allocator,
        client: *std.zig.Client,
        multi_reader: *Io.File.MultiReader,
        diagnostics: *DiagnosticsCollection,
        build_root: Directory,
        check_step_only: bool,
        worker_state: *WorkerState,
    ) error{ Canceled, AlreadyReported, WriteFailed, EndOfStream, OutOfMemory }!void {
        // TODO send LSP progress report

        const handshake: Server.Message.Handshake = while (true) {
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
                .bsp_handshake => {
                    var r: Io.Reader = .fixed(body);
                    break r.takeStruct(Server.Message.Handshake, .little) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.EndOfStream => |e| return e,
                    };
                },
                else => log.warn("received unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
            }
        };

        var did_log_start = false;
        defer if (did_log_start) log.info("Build-On-Save stopped for {qf}", .{build_root});

        var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
        defer arena_allocator.deinit();

        var header: Server.Message.Header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.Timeout => unreachable,
            else => |e| {
                log.err("failed to receive message from {s}: {t}", .{ protocol_name, e });
                return error.AlreadyReported;
            },
        };
        var body = client.in.take(header.bytes_len) catch unreachable;

        var cycle: u32 = 0;
        conf_loop: while (true) {
            defer _ = arena_allocator.reset(.retain_capacity);
            const arena = arena_allocator.allocator();

            const configuration: Configuration = conf: switch (header.tag) {
                .bsp_configuration => {
                    const configuration_file_path = body;
                    const configuration_file = build_root.handle.openFile(io, configuration_file_path, .{}) catch |err| {
                        log.err("failed to open configuration file {q}: {t}", .{ configuration_file_path, err });
                        return error.AlreadyReported;
                    };
                    defer configuration_file.close(io);
                    break :conf Configuration.loadFile(arena, io, configuration_file) catch |err| {
                        log.err("failed to load configuration file {q}: {t}", .{ configuration_file_path, err });
                        return error.AlreadyReported;
                    };
                },
                .bsp_configuration_failed => {
                    var reader: Io.Reader = .fixed(body);
                    const hdr = reader.takeStruct(Server.Message.ErrorBundle, .little) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.EndOfStream => |e| return e,
                    };

                    var error_bundle = std.zig.ErrorBundle.readAlloc(
                        &reader,
                        gpa,
                        hdr.extra_len,
                        hdr.string_bytes_len,
                    ) catch |err| switch (err) {
                        error.ReadFailed => unreachable,
                        error.OutOfMemory, error.EndOfStream => |e| return e,
                    };
                    defer error_bundle.deinit(gpa);

                    error_bundle.renderToStderr(io, .{}, .off) catch |err| {
                        log.err("failed to write configure compilation errors to stderr: {t}", .{err});
                        return error.AlreadyReported;
                    };

                    // The maker will terminate unexpectedly because it doesn't yet stay running
                    // when the build.zig compilation failed.
                    return error.AlreadyReported;
                },
                else => {
                    log.err("unexpected message from {s}: {f}", .{ protocol_name, fmtEnum(header.tag) });
                    return error.AlreadyReported;
                },
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
                log.info("Build-On-Save is running for {qf}", .{build_root});
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
                    error.Canceled => {}, // cancellation should be fine since we are returning anyway
                    else => log.err("failed to publish diagnostics: {t}", .{err}),
                };
            }

            while (true) {
                header = client.receiveMessageWithMultiReader(multi_reader, .none) catch |err| switch (err) {
                    error.Canceled => |e| return e,
                    error.Timeout => unreachable,
                    error.EndOfStream => break :conf_loop,
                    else => {
                        log.err("failed to receive message from {s}: {t}", .{ protocol_name, err });
                        return error.AlreadyReported;
                    },
                };
                body = client.in.take(header.bytes_len) catch unreachable;

                // log.debug("received Build-On-Save message: {f}", .{fmtEnum(header.tag)});

                switch (header.tag) {
                    .bsp_configuration, .bsp_configuration_failed => break,
                    .bsp_build_started => continue,
                    .bsp_build_completed => {
                        cycle += 1;
                        if (handshake.flags.file_system_watch_supported) continue;

                        try worker_state.manual_save.wait(io);
                        worker_state.manual_save.reset();

                        client.serveBuildSteps(
                            &.{selected_step},
                            .{ .watch = false },
                        ) catch |err| switch (err) {
                            error.WriteFailed => |e| return e,
                        };
                    },
                    .bsp_step_started => continue,
                    .bsp_step_completed => {
                        var reader: Io.Reader = .fixed(body);
                        const bsc = reader.takeStruct(Server.Message.BuildStepCompleted, .little) catch |err| switch (err) {
                            error.ReadFailed => unreachable,
                            error.EndOfStream => |e| return e,
                        };

                        var error_bundle = std.zig.ErrorBundle.readAlloc(
                            &reader,
                            gpa,
                            bsc.error_bundle.extra_len,
                            bsc.error_bundle.string_bytes_len,
                        ) catch |err| switch (err) {
                            error.ReadFailed => unreachable,
                            error.OutOfMemory, error.EndOfStream => |e| return e,
                        };
                        defer error_bundle.deinit(gpa);

                        const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
                            var hasher: std.hash.Wyhash = .init(0);

                            hasher.update(build_root.path.?);
                            std.hash.autoHash(&hasher, bsc.step_index);
                            break :tag @fromBackingInt(@truncate(hasher.final()));
                        };

                        try diagnostic_tags.put(gpa, diagnostic_tag, {});

                        try diagnostics.pushErrorBundle(
                            diagnostic_tag,
                            cycle,
                            build_root.path.?,
                            error_bundle,
                        );

                        diagnostics.publishDiagnostics() catch |err| switch (err) {
                            error.Canceled => |e| return e,
                            else => log.err("failed to publish diagnostics: {t}", .{err}),
                        };
                    },
                    else => log.warn("received unexpected message from {s} with tag {f}", .{ protocol_name, fmtEnum(header.tag) }),
                }
            }
        }
    }
};

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

comptime {
    _ = &BuildOnSave;
}
