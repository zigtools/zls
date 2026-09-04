//! read and resolve configuration options.

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("Config.zig");

const log = std.log.scoped(.config);

pub const Manager = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    config: Config,
    zig_exe: ?struct {
        /// Same as `Manager.config.zig_exe_path.?`
        path: []const u8,
        version: std.SemanticVersion,
        env: Env,
        /// Whether the `version` satifies the minimum runtime zig version.
        supported: bool,
    },
    zig_lib_dir: ?std.Build.Cache.Directory,
    global_cache_dir: ?std.Build.Cache.Directory,
    wasi_preopens: switch (builtin.os.tag) {
        .wasi => std.process.Preopens,
        else => void,
    },
    impl: struct {
        is_dirty: bool,
        configs: std.EnumArray(Tag, UnresolvedConfig),
        /// Every changed configuration will increase the amount of memory
        /// allocated by the arena. This is unlikely to cause high memory
        /// consumption since the user is probably not going set settings
        /// often in one session.
        arena: std.heap.ArenaAllocator.State,
    },

    pub fn init(io: std.Io, allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) error{ OutOfMemory, Unexpected }!Manager {
        var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena_allocator.deinit();
        return .{
            .io = io,
            .allocator = allocator,
            .environ_map = environ_map,
            .zig_exe = null,
            .zig_lib_dir = null,
            .global_cache_dir = null,
            .wasi_preopens = switch (builtin.os.tag) {
                .wasi => try std.process.Preopens.init(arena_allocator.allocator()),
                else => {},
            },
            .config = .{},
            .impl = .{
                .is_dirty = true,
                .configs = .initFill(.{}),
                .arena = arena_allocator.state,
            },
        };
    }

    pub fn deinit(manager: *Manager) void {
        const io = manager.io;
        const allocator = manager.allocator;
        if (builtin.os.tag != .wasi) {
            if (manager.zig_lib_dir) |*zig_lib_dir| zig_lib_dir.handle.close(io);
            if (manager.global_cache_dir) |*global_cache_dir| global_cache_dir.handle.close(io);
        }
        manager.impl.arena.promote(allocator).deinit();
        manager.* = undefined;
    }

    /// Defines independent configuration option providers. Ordered in increasing priority.
    pub const Tag = enum {
        /// Configuration provided when the server has been created (`main.zig`).
        frontend,
        /// `initializationOptions` during `initialize`
        lsp_initialization,
        /// `workspace/didChangeConfiguration` or `workspace/configuration`
        lsp_configuration,
    };

    /// Does not resolve or validate config options until `resolveConfiguration` has been called.
    pub fn setConfiguration(
        manager: *Manager,
        tag: Tag,
        config: *const UnresolvedConfig,
    ) error{OutOfMemory}!void {
        var arena_allocator: std.heap.ArenaAllocator = manager.impl.arena.promote(manager.allocator);
        defer manager.impl.arena = arena_allocator.state;

        var duped: UnresolvedConfig = .{};
        inline for (comptime std.meta.fieldNames(UnresolvedConfig), comptime std.meta.fieldTypes(UnresolvedConfig)) |field_name, FieldType| {
            @field(duped, field_name) = try option.dupe(FieldType, @field(config, field_name), arena_allocator.allocator());
        }
        manager.impl.configs.set(tag, duped);
        manager.impl.is_dirty = true;
    }

    /// Does not resolve or validate config options until `resolveConfiguration` has been called.
    pub fn setConfiguration2(
        manager: *Manager,
        tag: Tag,
        config: *const Config,
    ) error{OutOfMemory}!void {
        var cfg: UnresolvedConfig = .{};
        inline for (comptime std.meta.fieldNames(Config)) |field_name| {
            @field(cfg, field_name) = @field(config, field_name);
        }
        try manager.setConfiguration(tag, &cfg);
    }

    pub const ResolveConfigurationResult = struct {
        did_change: DidConfigChange,
        messages: [][]const u8,

        pub fn deinit(result: *ResolveConfigurationResult, allocator: std.mem.Allocator) void {
            for (result.messages) |msg| allocator.free(msg);
            allocator.free(result.messages);
            result.* = undefined;
        }
    };

    pub fn resolveConfiguration(
        manager: *Manager,
        result_allocator: std.mem.Allocator,
    ) error{ Canceled, OutOfMemory }!ResolveConfigurationResult {
        if (!manager.impl.is_dirty) {
            return .{
                .did_change = .{},
                .messages = &.{},
            };
        }

        var arena_allocator: std.heap.ArenaAllocator = manager.impl.arena.promote(manager.allocator);
        const arena = arena_allocator.allocator();
        defer manager.impl.arena = arena_allocator.state;

        const io = manager.io;

        var config: Config = .{
            .zig_lib_path = if (builtin.os.tag == .wasi) "/lib" else null,
            .global_cache_path = if (builtin.os.tag == .wasi) "/cache" else null,
        };
        for (manager.impl.configs.values) |unresolved_config| {
            inline for (comptime std.meta.fieldNames(UnresolvedConfig)) |field_name| {
                if (@field(unresolved_config, field_name)) |new_value| {
                    @field(config, field_name) = new_value;
                }
            }
        }

        var messages: std.ArrayList([]const u8) = .empty;
        defer {
            for (messages.items) |msg| result_allocator.free(msg);
            messages.deinit(result_allocator);
        }

        try validateConfiguration(io, result_allocator, &config, &messages);

        if (config.zig_exe_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe_path = try findZig(io, manager.allocator, manager.environ_map) orelse break :blk;
            defer manager.allocator.free(zig_exe_path);
            config.zig_exe_path = try arena.dupe(u8, zig_exe_path);
        }

        if (config.zig_exe_path) |exe_path| unresolved_zig: {
            if (!std.process.can_spawn) break :unresolved_zig;

            const zig_env = try getZigEnv(io, manager.allocator, arena, exe_path) orelse break :unresolved_zig;

            const zig_version = std.SemanticVersion.parse(zig_env.version) catch |err| {
                log.err("zig env returned a zig version that is an invalid semantic version: {}", .{err});
                break :unresolved_zig;
            };

            const build_options = @import("build_options");
            const is_zls_version_tagged = build_options.version.pre == null;
            const min_runtime_zig_version = comptime std.SemanticVersion.parse(build_options.minimum_runtime_zig_version_string) catch unreachable;

            manager.zig_exe = .{
                .path = zig_env.zig_exe,
                .version = zig_version,
                .env = zig_env,
                .supported = zigVersionCheck(min_runtime_zig_version, zig_version, is_zls_version_tagged),
            };
        }
        config.zig_exe_path = if (manager.zig_exe) |exe| exe.path else null;

        if (config.zig_lib_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe = manager.zig_exe orelse break :blk;
            const zig_lib_dir = zig_exe.env.lib_dir orelse break :blk;

            if (std.Io.Dir.path.isAbsolute(zig_lib_dir)) {
                config.zig_lib_path = try arena.dupe(u8, zig_lib_dir);
            } else {
                const cwd = std.process.currentPathAlloc(io, manager.allocator) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        log.err("failed to resolve current working directory: {}", .{e});
                        break :blk;
                    },
                };
                defer manager.allocator.free(cwd);
                config.zig_lib_path = try std.Io.Dir.path.join(arena, &.{ cwd, zig_lib_dir });
            }
        }

        for (
            [_]*?[]const u8{ &config.zig_lib_path, &config.global_cache_path },
            [_]*?std.Build.Cache.Directory{ &manager.zig_lib_dir, &manager.global_cache_dir },
            [_]enum { open, create }{ .open, .create },
            [_][]const u8{ "zig library", "global cache" },
        ) |opt_path, result_dir, action, name| {
            const path = opt_path.* orelse continue;
            if (builtin.target.os.tag == .wasi) {
                // TODO The path could be a subdirectory of a preopen directory
                const resource = manager.wasi_preopens.get(path) orelse {
                    log.warn("failed to resolve '{s}' WASI preopen", .{path});
                    opt_path.* = null;
                    continue;
                };
                switch (resource) {
                    .dir => |dir| {
                        result_dir.* = .{ .handle = dir, .path = path };
                        continue;
                    },
                    .file => {
                        log.err("failed to resolve {s} directory '{s}': {}", .{ name, path, std.Io.File.OpenError.NotDir });
                        opt_path.* = null;
                        continue;
                    },
                }
            } else {
                const dir = switch (action) {
                    .open => std.Io.Dir.cwd().openDir(io, path, .{}),
                    .create => std.Io.Dir.cwd().createDirPathOpen(io, path, .{}),
                } catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    else => {
                        log.err("failed to open {s} directory '{s}': {}", .{ name, path, err });
                        opt_path.* = null;
                        continue;
                    },
                };
                result_dir.* = .{ .handle = dir, .path = path };
                continue;
            }
            comptime unreachable;
        }

        if (config.builtin_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe = manager.zig_exe orelse break :blk;
            const global_cache_dir = manager.global_cache_dir orelse break :blk;

            const argv = [_][]const u8{
                zig_exe.path,
                "build-exe",
                "--show-builtin",
            };

            const run_result = std.process.run(
                manager.allocator,
                io,
                .{
                    .argv = &argv,
                    .stderr_limit = .limited(16 * 1024 * 1024),
                    .stdout_limit = .limited(16 * 1024 * 1024),
                },
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    const args = std.mem.join(manager.allocator, " ", &argv) catch break :blk;
                    log.err("failed to run command '{s}': {}", .{ args, err });
                    break :blk;
                },
            };
            defer manager.allocator.free(run_result.stdout);
            defer manager.allocator.free(run_result.stderr);

            global_cache_dir.handle.writeFile(io, .{
                .sub_path = "builtin.zig",
                .data = run_result.stdout,
            }) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    log.err("failed to write file '{f}builtin.zig': {}", .{ global_cache_dir, err });
                    break :blk;
                },
            };

            config.builtin_path = try global_cache_dir.join(arena, &.{"builtin.zig"});
        }

        var did_change: DidConfigChange = .{};

        inline for (comptime std.meta.fieldNames(Config), comptime std.meta.fieldTypes(Config)) |field_name, FieldType| {
            const old_value = &@field(manager.config, field_name);
            const new_value = @field(config, field_name);

            const is_eql = option.eql(FieldType, old_value.*, new_value);
            @field(did_change, field_name) = !is_eql;

            if (!is_eql) {
                old_value.* = try option.dupe(FieldType, new_value, arena_allocator.allocator());
            }
        }

        manager.impl.is_dirty = false;
        return .{
            .did_change = did_change,
            .messages = try messages.toOwnedSlice(result_allocator),
        };
    }

    fn validateConfiguration(
        io: std.Io,
        allocator: std.mem.Allocator,
        config: *Config,
        messages: *std.ArrayList([]const u8),
    ) error{ Canceled, OutOfMemory }!void {
        if (builtin.os.tag == .wasi) return;

        var values: [file_system_config_options.len]*?[]const u8 = undefined;
        inline for (file_system_config_options, &values) |file_config, *value| {
            value.* = &@field(config, file_config.name);
        }

        for (file_system_config_options, &values) |file_config, value| {
            const is_ok = if (value.*) |path| ok: {
                // Convert `""` to `null`
                if (path.len == 0) {
                    // Thank you Visual Studio Trash Code
                    value.* = null;
                    break :ok true;
                }

                if (!std.Io.Dir.path.isAbsolute(path)) {
                    try messages.ensureUnusedCapacity(allocator, 1);
                    messages.appendAssumeCapacity(try std.fmt.allocPrint(
                        allocator,
                        "config option '{s}': expected absolute path but got '{s}'",
                        .{ file_config.name, path },
                    ));
                    break :ok false;
                }

                switch (file_config.kind) {
                    .file => {
                        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
                            error.Canceled => return error.Canceled,
                            else => {
                                if (file_config.is_accessible) {
                                    try messages.ensureUnusedCapacity(allocator, 1);
                                    messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                        allocator,
                                        "config option '{s}': invalid file path '{s}': {}",
                                        .{ file_config.name, path, err },
                                    ));
                                    break :ok false;
                                }
                                break :ok true;
                            },
                        };
                        defer file.close(io);

                        const stat = file.stat(io) catch |err| switch (err) {
                            error.Canceled => return error.Canceled,
                            else => {
                                try messages.ensureUnusedCapacity(allocator, 1);
                                messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                    allocator,
                                    "config option '{s}': failed to access '{s}': {}",
                                    .{ file_config.name, path, err },
                                ));
                                break :ok true;
                            },
                        };
                        switch (stat.kind) {
                            .directory => {
                                try messages.ensureUnusedCapacity(allocator, 1);
                                messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                    allocator,
                                    "config option '{s}': expected file path but '{s}' is a directory",
                                    .{ file_config.name, path },
                                ));
                                break :ok false;
                            },
                            .file => {},
                            // are there file kinds that should warn?
                            // what about symlinks?
                            else => {},
                        }
                        break :ok true;
                    },
                    .directory => {
                        var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch |err| switch (err) {
                            error.Canceled => return error.Canceled,
                            else => {
                                if (file_config.is_accessible) {
                                    try messages.ensureUnusedCapacity(allocator, 1);
                                    messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                        allocator,
                                        "config option '{s}': invalid directory path '{s}': {}",
                                        .{ file_config.name, path, err },
                                    ));
                                    break :ok false;
                                }
                                break :ok true;
                            },
                        };
                        defer dir.close(io);
                        const stat = dir.stat(io) catch |err| switch (err) {
                            error.Canceled => return error.Canceled,
                            else => {
                                log.err("failed to get stat of '{s}': {}", .{ path, err });
                                break :ok true;
                            },
                        };
                        switch (stat.kind) {
                            .file => {
                                try messages.ensureUnusedCapacity(allocator, 1);
                                messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                    allocator,
                                    "config option '{s}': expected directory path but '{s}' is a file",
                                    .{ file_config.name, path },
                                ));
                                break :ok false;
                            },
                            .directory => {},
                            // are there file kinds that should warn?
                            // what about symlinks?
                            else => {},
                        }
                        break :ok true;
                    },
                }
            } else true;

            if (!is_ok) {
                value.* = null;
            }
        }
    }
};

/// Helper functions to manage a single config option.
pub const option = struct {
    fn free(comptime T: type, value: T, allocator: std.mem.Allocator) void {
        const val = switch (@typeInfo(T)) {
            .optional => if (value) |val| val else return,
            else => value,
        };
        switch (@typeInfo(@TypeOf(val))) {
            .pointer => switch (@TypeOf(val)) {
                []const []const u8 => {
                    for (val) |str| allocator.free(str);
                    allocator.free(val);
                },
                []const u8 => allocator.free(val),
                else => comptime unreachable,
            },
            .bool, .int, .float, .@"enum" => {},
            else => comptime unreachable,
        }
    }

    fn dupe(comptime T: type, value: T, allocator: std.mem.Allocator) error{OutOfMemory}!T {
        const val = switch (@typeInfo(T)) {
            .optional => if (value) |val| val else return null,
            else => value,
        };
        switch (@TypeOf(val)) {
            []const []const u8 => {
                const copy = try allocator.alloc([]const u8, val.len);
                @memset(copy, "");
                errdefer {
                    for (copy) |str| allocator.free(str);
                    allocator.free(copy);
                }
                for (copy, val) |*duped, original| duped.* = try allocator.dupe(u8, original);
                return copy;
            },
            []const u8 => return try allocator.dupe(u8, val),
            else => return val,
        }
    }

    fn eql(comptime T: type, a: T, b: T) bool {
        const a_val, const b_val = switch (@typeInfo(T)) {
            .optional => blk: {
                if (a == null and b == null) return true;
                if ((a == null) != (b == null)) return false;
                break :blk .{ a.?, b.? };
            },
            else => .{ a, b },
        };

        switch (@TypeOf(a_val)) {
            []const []const u8 => {
                if (a_val.len != b_val.len) return false;
                for (a_val, b_val) |a_elem, b_elem| if (!std.mem.eql(u8, a_elem, b_elem)) return false;
                return true;
            },
            []const u8 => return std.mem.eql(u8, a_val, b_val),
            else => return a_val == b_val,
        }
    }
};

pub const Env = struct {
    zig_exe: []const u8,
    lib_dir: ?[]const u8,
    std_dir: []const u8,
    global_cache_dir: []const u8,
    version: []const u8,
    target: ?[]const u8 = null,
};

pub fn getZigEnv(
    io: std.Io,
    allocator: std.mem.Allocator,
    result_arena: std.mem.Allocator,
    zig_exe_path: []const u8,
) error{ Canceled, OutOfMemory }!?Env {
    const zig_env_result = std.process.run(
        allocator,
        io,
        .{ .argv = &.{ zig_exe_path, "env" } },
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.err("Failed to run 'zig env': {}", .{err});
            return null;
        },
    };

    defer {
        allocator.free(zig_env_result.stdout);
        allocator.free(zig_env_result.stderr);
    }

    switch (zig_env_result.term) {
        .exited => |code| {
            if (code != 0) {
                log.err("zig env command exited with error code {d}.", .{code});
                if (zig_env_result.stderr.len != 0) {
                    log.err("stderr: {s}", .{zig_env_result.stderr});
                }
                return null;
            }
        },
        .signal, .stopped, .unknown => {
            log.err("zig env command terminated unexpectedly.", .{});
            if (zig_env_result.stderr.len != 0) {
                log.err("stderr: {s}", .{zig_env_result.stderr});
            }
            return null;
        },
    }

    if (std.mem.startsWith(u8, zig_env_result.stdout, "{")) {
        return std.json.parseFromSliceLeaky(
            Env,
            result_arena,
            zig_env_result.stdout,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.err("Failed to parse 'zig env' output as JSON: {}", .{err});
                return null;
            },
        };
    } else {
        const source = try allocator.dupeSentinel(u8, zig_env_result.stdout, 0);
        defer allocator.free(source);

        return std.zon.parse.fromSliceAlloc(
            Env,
            result_arena,
            source,
            null,
            .{ .ignore_unknown_fields = true },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.err("Failed to parse 'zig env' output as Zon: {}", .{err});
                return null;
            },
        };
    }
}

pub const FileConfigInfo = struct {
    name: []const u8,
    kind: enum { file, directory },
    is_accessible: bool,
};

/// A list of config options that represent file system paths.
pub const file_system_config_options: []const FileConfigInfo = &.{
    .{ .name = "zig_exe_path", .kind = .file, .is_accessible = true },
    .{ .name = "builtin_path", .kind = .file, .is_accessible = true },
    .{ .name = "zig_lib_path", .kind = .directory, .is_accessible = true },
    .{ .name = "global_cache_path", .kind = .directory, .is_accessible = false },
};

comptime {
    skip: for (std.meta.fieldNames(Config)) |field_name| {
        @setEvalBranchQuota(2_000);
        if (std.mem.find(u8, field_name, "path") == null) continue;

        for (file_system_config_options) |file_config| {
            if (std.mem.eql(u8, file_config.name, field_name)) continue :skip;
        }

        @compileError(std.fmt.comptimePrint(
            \\config option '{s}' contains the word 'path'.
            \\Please add config option validation checks below if necessary.
            \\If not necessary, just add a check above to ignore this error.
            \\
        , .{field_name}));
    }
}

/// The same struct as `Config` but every field is optional.
pub const UnresolvedConfig = blk: {
    const struct_info: std.lang.Type.Struct = @typeInfo(Config).@"struct";
    var field_types = struct_info.field_types[0..].*;
    var field_attrs: [field_types.len]std.lang.Type.Struct.FieldAttributes = undefined;
    for (&field_types, &field_attrs) |*field_type, *attr| {
        field_type.* = if (@typeInfo(field_type.*) != .optional) ?field_type.* else field_type.*;
        attr.* = .{ .default_value_ptr = &@as(field_type.*, null) };
    }
    break :blk @Struct(.auto, null, std.meta.fieldNames(Config), &field_types, &field_attrs);
};

/// A packed struct where every field name is copied from `Config` but the field type is `bool`.
pub const DidConfigChange = @Struct(
    .@"packed",
    null,
    std.meta.fieldNames(Config),
    &@splat(bool),
    &@splat(.{ .default_value_ptr = &false }),
);

pub fn findZig(
    io: std.Io,
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
) error{ Canceled, OutOfMemory }!?[]const u8 {
    const is_windows = builtin.target.os.tag == .windows;

    const env_path = environ_map.get("PATH") orelse return null;
    const env_path_ext = if (is_windows) environ_map.get("PATHEXT") orelse return null;

    var filename_buffer: std.ArrayList(u8) = .empty;
    defer filename_buffer.deinit(allocator);

    var path_it = std.mem.tokenizeScalar(u8, env_path, std.Io.Dir.path.delimiter);
    var ext_it = if (is_windows) std.mem.tokenizeScalar(u8, env_path_ext, std.Io.Dir.path.delimiter);

    while (path_it.next()) |path| : (if (is_windows) ext_it.reset()) {
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.FileNotFound => continue,
            else => |e| {
                log.warn("failed to open entry in PATH '{s}': {}", .{ path, e });
                continue;
            },
        };
        defer dir.close(io);

        var cont = true;
        while (cont) : (cont = is_windows) {
            const filename = if (!is_windows) "zig" else filename: {
                const ext = ext_it.next() orelse break;

                filename_buffer.clearRetainingCapacity();
                try filename_buffer.ensureTotalCapacity(allocator, "zig".len + ext.len);
                filename_buffer.appendSliceAssumeCapacity("zig");
                filename_buffer.appendSliceAssumeCapacity(ext);

                break :filename filename_buffer.items;
            };

            const stat = dir.statFile(io, filename, .{}) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.FileNotFound => continue,
                else => |e| {
                    log.warn("failed to access entry in PATH '{f}': {}", .{ std.Io.Dir.path.fmtJoin(&.{ path, filename }), e });
                    continue;
                },
            };

            if (stat.kind == .directory) {
                log.warn("ignoring entry in PATH '{f}' because it is a directory", .{std.Io.Dir.path.fmtJoin(&.{ path, filename })});
                continue;
            }

            return try std.Io.Dir.path.join(allocator, &.{ path, filename });
        }
    }
    return null;
}

fn zigVersionCheck(
    minimum_zig_version: std.SemanticVersion,
    param_zig_version: std.SemanticVersion,
    /// If set, a non-tagged zig version cannot be used when `minimum_runtime_zig_version` is a tagged version.
    /// Example: Zig `0.13.0-dev` cannot be used when the minimum Zig version is `0.12.0`.
    ///
    /// Will be set iff ZLS is a tagged release.
    strict: bool,
) bool {
    const minimum_version_is_tagged = minimum_zig_version.pre == null;

    var zig_version = param_zig_version;
    var version_is_tagged = zig_version.pre == null;

    if (!version_is_tagged and zig_version.patch != 0) {
        // A zig version like `0.12.2-dev` has the same compatibility as `0.12.1`
        zig_version.patch -= 1;
        zig_version.pre = null;
        version_is_tagged = true;
    }

    if (strict and !version_is_tagged) {
        std.debug.assert(minimum_version_is_tagged);
        // A tagged release of ZLS must be used with a tagged release of Zig.
        return false;
    }

    if (zig_version.major != minimum_zig_version.major) return false;

    if (minimum_version_is_tagged) {
        if (version_is_tagged) {
            if (zig_version.order(minimum_zig_version) == .lt) return false;
            const next_minor_release: std.SemanticVersion = .{
                .major = minimum_zig_version.major,
                .minor = minimum_zig_version.minor + 1,
                .patch = 0,
            };
            return zig_version.order(next_minor_release) == .lt;
        } else {
            std.debug.assert(zig_version.patch == 0);
            return zig_version.minor == 1 + minimum_zig_version.minor;
        }
    } else {
        if (version_is_tagged) return false;
        if (zig_version.minor != minimum_zig_version.minor) return false;
        return zig_version.order(minimum_zig_version) != .lt;
    }
}

test {
    const build_options = @import("build_options");
    const current_zig_version = @import("builtin").zig_version;
    const is_zls_version_tagged = build_options.version.pre == null;
    const min_runtime_zig_version = comptime std.SemanticVersion.parse(build_options.minimum_runtime_zig_version_string) catch unreachable;

    // The build runner must support the Zig version that ZLS is being built with
    try std.testing.expect(zigVersionCheck(
        min_runtime_zig_version,
        current_zig_version,
        is_zls_version_tagged,
    ));

    if (is_zls_version_tagged) {
        // A tagged release of ZLS should support the same tagged release of Zig
        // Example: ZLS 0.12.0 should support Zig 0.12.x -- It is possible that ZLS requires a minimum patch version
        try std.testing.expect(zigVersionCheck(
            .{ .major = current_zig_version.major, .minor = current_zig_version.minor, .patch = 999 },
            min_runtime_zig_version,
            is_zls_version_tagged,
        ));
    }
}

// Version order for reference:
// 0.11.0-dev < 0.11.0 < 0.12.0-dev < 0.12.0 < 0.13.0-dev < 0.13.0

test zigVersionCheck {
    var did_fail = false;
    for (test_cases) |test_case| {
        const minimum_runtime_zig_version: std.SemanticVersion = try .parse(test_case.minimum_runtime_zig_version);
        const runtime_zig_version: std.SemanticVersion = try .parse(test_case.runtime_zig_version);
        const minimum_runtime_version_is_tagged = minimum_runtime_zig_version.pre == null;
        const expected_if_strict, const expected_if_not_strict = switch (test_case.is_supported) {
            .yes => .{ true, true },
            .no => .{ false, false },
            .if_not_strict => .{ false, true },
        };

        const actual_if_not_strict = zigVersionCheck(minimum_runtime_zig_version, runtime_zig_version, false);
        if (expected_if_not_strict != actual_if_not_strict) {
            std.debug.print("minimum={f}, actual={f}, strict={} -> expected {} but got {}\n", .{
                minimum_runtime_zig_version,
                runtime_zig_version,
                false,
                expected_if_not_strict,
                actual_if_not_strict,
            });
            did_fail = true;
        }

        if (minimum_runtime_version_is_tagged) {
            const actual_if_strict = zigVersionCheck(minimum_runtime_zig_version, runtime_zig_version, true);
            if (expected_if_strict != actual_if_strict) {
                std.debug.print("minimum={f}, actual={f}, strict={} -> expected {} but got {}\n", .{
                    minimum_runtime_zig_version,
                    runtime_zig_version,
                    true,
                    expected_if_strict,
                    actual_if_strict,
                });
                did_fail = true;
            }
        }
    }
    if (did_fail) return error.Unexpected;
}

const test_cases: []const struct {
    minimum_runtime_zig_version: []const u8,
    runtime_zig_version: []const u8,
    is_supported: enum { yes, no, if_not_strict },
} = &.{
    // Minimum Zig Version: 0.12.0
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.11.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.0",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.1-dev",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.1",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.0-dev",
        .is_supported = .if_not_strict,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.1-dev",
        .is_supported = .no,
    },
    // Minimum Zig Version: 0.12.1
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.11.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.1-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.1",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.2-dev",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.2",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.0-dev",
        .is_supported = .if_not_strict,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.1-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.1",
        .is_supported = .no,
    },
    // Minimum Zig Version: 0.12.0-dev.5
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.11.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.4",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.5",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.10",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.13.0-dev.10",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
};
