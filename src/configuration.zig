//! read and resolve configuration options.

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("Config.zig");

const log = std.log.scoped(.config);

pub const Manager = struct {
    allocator: std.mem.Allocator,
    config: Config,
    zig_exe: ?struct {
        /// Same as `Manager.config.zig_exe_path.?`
        path: []const u8,
        version: std.SemanticVersion,
        env: Env,
    },
    zig_lib_dir: ?std.Build.Cache.Directory,
    global_cache_dir: ?std.Build.Cache.Directory,
    build_runner_supported: union(enum) {
        /// If returned, guarantees `zig_exe != null`.
        yes,
        /// no suitable build runner could be resolved based on the `zig_exe`
        /// If returned, guarantees `zig_exe != null`.
        no,
        no_dont_error,
    },
    impl: struct {
        is_dirty: bool,
        configs: std.EnumArray(Tag, UnresolvedConfig),
        /// Every changed configuration will increase the amount of memory
        /// allocated by the arena. This is unlikely to cause high memory
        /// consumption since the user is probably not going set settings
        /// often in one session.
        arena: std.heap.ArenaAllocator.State,
        cached_wasi_preopens: switch (builtin.os.tag) {
            .wasi => ?std.fs.wasi.Preopens,
            else => void,
        },
    },

    pub fn init(allocator: std.mem.Allocator) Manager {
        return .{
            .allocator = allocator,
            .zig_exe = null,
            .zig_lib_dir = null,
            .global_cache_dir = null,
            .build_runner_supported = .no_dont_error,
            .config = .{},
            .impl = .{
                .is_dirty = true,
                .configs = .initFill(.{}),
                .arena = .{},
                .cached_wasi_preopens = switch (builtin.os.tag) {
                    .wasi => null,
                    else => {},
                },
            },
        };
    }

    pub fn deinit(manager: *Manager) void {
        const allocator = manager.allocator;
        switch (builtin.os.tag) {
            .wasi => {
                if (manager.impl.cached_wasi_preopens) |wasi_preopens| {
                    for (wasi_preopens.names[3..]) |name| allocator.free(name);
                    allocator.free(wasi_preopens.names);
                }
            },
            else => {
                if (manager.zig_lib_dir) |*zig_lib_dir| zig_lib_dir.handle.close();
                if (manager.global_cache_dir) |*global_cache_dir| global_cache_dir.handle.close();
            },
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
        inline for (std.meta.fields(UnresolvedConfig)) |field| {
            @field(duped, field.name) = try option.dupe(field.type, @field(config, field.name), arena_allocator.allocator());
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
        inline for (std.meta.fields(Config)) |field| {
            @field(cfg, field.name) = @field(config, field.name);
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
    ) error{OutOfMemory}!ResolveConfigurationResult {
        if (!manager.impl.is_dirty) {
            return .{
                .did_change = .{},
                .messages = &.{},
            };
        }

        var arena_allocator: std.heap.ArenaAllocator = manager.impl.arena.promote(manager.allocator);
        const arena = arena_allocator.allocator();
        defer manager.impl.arena = arena_allocator.state;

        var config: Config = .{
            .zig_lib_path = if (builtin.os.tag == .wasi) "/lib" else null,
            .global_cache_path = if (builtin.os.tag == .wasi) "/cache" else null,
        };
        for (manager.impl.configs.values) |unresolved_config| {
            inline for (std.meta.fields(UnresolvedConfig)) |field| {
                if (@field(unresolved_config, field.name)) |new_value| {
                    @field(config, field.name) = new_value;
                }
            }
        }

        var messages: std.ArrayList([]const u8) = .empty;
        defer {
            for (messages.items) |msg| result_allocator.free(msg);
            messages.deinit(result_allocator);
        }

        try validateConfiguration(&config, result_allocator, &messages);

        if (config.zig_exe_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe_path = try findZig(manager.allocator) orelse break :blk;
            defer manager.allocator.free(zig_exe_path);
            config.zig_exe_path = try arena.dupe(u8, zig_exe_path);
        }

        if (config.zig_exe_path) |exe_path| unresolved_zig: {
            if (!std.process.can_spawn) break :unresolved_zig;

            const zig_env = try getZigEnv(manager.allocator, arena, exe_path) orelse break :unresolved_zig;

            const zig_version = std.SemanticVersion.parse(zig_env.version) catch |err| {
                log.err("zig env returned a zig version that is an invalid semantic version: {}", .{err});
                break :unresolved_zig;
            };

            manager.zig_exe = .{
                .path = exe_path,
                .version = zig_version,
                .env = zig_env,
            };
        }

        if (config.zig_lib_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe = manager.zig_exe orelse break :blk;
            const zig_lib_dir = zig_exe.env.lib_dir orelse break :blk;

            if (std.fs.path.isAbsolute(zig_lib_dir)) {
                config.zig_lib_path = try arena.dupe(u8, zig_lib_dir);
            } else {
                const cwd = std.process.getCwdAlloc(manager.allocator) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        log.err("failed to resolve current working directory: {}", .{e});
                        break :blk;
                    },
                };
                defer manager.allocator.free(cwd);
                config.zig_lib_path = try std.fs.path.join(arena, &.{ cwd, zig_lib_dir });
            }
        }

        const wasi_preopens = switch (builtin.os.tag) {
            .wasi => manager.impl.cached_wasi_preopens orelse wasi_preopens: {
                manager.impl.cached_wasi_preopens = try std.fs.wasi.preopensAlloc(manager.allocator);
                break :wasi_preopens manager.impl.cached_wasi_preopens.?;
            },
            else => {},
        };

        if (config.zig_lib_path) |zig_lib_path| blk: {
            const zig_lib_dir: std.fs.Dir = switch (builtin.target.os.tag) {
                // TODO The `zig_lib_path` could be a subdirectory of a preopen directory
                .wasi => .{ .fd = wasi_preopens.find(zig_lib_path) orelse {
                    log.warn("failed to resolve '{s}' WASI preopen", .{zig_lib_path});
                    config.zig_lib_path = null;
                    break :blk;
                } },
                else => std.fs.openDirAbsolute(zig_lib_path, .{}) catch |err| {
                    log.err("failed to open zig library directory '{s}': {}", .{ zig_lib_path, err });
                    config.zig_lib_path = null;
                    break :blk;
                },
            };
            errdefer if (builtin.target.os.tag != .wasi) zig_lib_dir.close();

            manager.zig_lib_dir = .{
                .handle = zig_lib_dir,
                .path = zig_lib_path,
            };
        }

        if (config.global_cache_path) |global_cache_path| blk: {
            const global_cache_dir: std.fs.Dir = switch (builtin.target.os.tag) {
                // TODO The `global_cache_path` could be a subdirectory of a preopen directory
                .wasi => .{ .fd = wasi_preopens.find(global_cache_path) orelse {
                    log.warn("failed to resolve '{s}' WASI preopen", .{global_cache_path});
                    config.global_cache_path = null;
                    break :blk;
                } },
                else => std.fs.cwd().makeOpenPath(global_cache_path, .{}) catch |err| {
                    log.err("failed to open global cache directory '{s}': {}", .{ global_cache_path, err });
                    config.global_cache_path = null;
                    break :blk;
                },
            };
            errdefer if (builtin.target.os.tag != .wasi) global_cache_dir.close();

            manager.global_cache_dir = .{
                .handle = global_cache_dir,
                .path = global_cache_path,
            };
        }

        if (config.build_runner_path == null) blk: {
            if (!std.process.can_spawn) break :blk;
            const zig_exe = manager.zig_exe orelse break :blk;
            const global_cache_dir = manager.global_cache_dir orelse break :blk;

            if (!@import("build_runner/check.zig").isBuildRunnerSupported(zig_exe.version)) {
                manager.build_runner_supported = .no;
                break :blk;
            }

            const build_runner_source = @embedFile("build_runner/build_runner.zig");
            const build_runner_config_source = @embedFile("build_runner/shared.zig");

            const build_runner_hash = get_hash: {
                const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);

                var hasher: Hasher = .init(&@splat(0));
                hasher.update(build_runner_source);
                hasher.update(build_runner_config_source);
                break :get_hash hasher.finalResult();
            };

            const cache_path = try global_cache_dir.join(manager.allocator, &.{ "build_runner", &std.fmt.bytesToHex(build_runner_hash, .lower) });
            defer manager.allocator.free(cache_path);

            std.debug.assert(std.fs.path.isAbsolute(cache_path));
            var cache_dir = std.fs.cwd().makeOpenPath(cache_path, .{}) catch |err| {
                log.err("failed to open directory '{s}': {}", .{ cache_path, err });
                break :blk;
            };
            defer cache_dir.close();

            cache_dir.writeFile(.{
                .sub_path = "shared.zig",
                .data = build_runner_config_source,
                .flags = .{ .exclusive = true },
            }) catch |err| if (err != error.PathAlreadyExists) {
                log.err("failed to write file '{s}/shared.zig': {}", .{ cache_path, err });
                break :blk;
            };

            cache_dir.writeFile(.{
                .sub_path = "build_runner.zig",
                .data = build_runner_source,
                .flags = .{ .exclusive = true },
            }) catch |err| if (err != error.PathAlreadyExists) {
                log.err("failed to write file '{s}/build_runner.zig': {}", .{ cache_path, err });
                break :blk;
            };

            config.build_runner_path = try std.fs.path.join(arena, &.{ cache_path, "build_runner.zig" });
            manager.build_runner_supported = .yes;
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

            const run_result = std.process.Child.run(.{
                .allocator = manager.allocator,
                .argv = &argv,
                .max_output_bytes = 16 * 1024 * 1024,
            }) catch |err| {
                const args = std.mem.join(manager.allocator, " ", &argv) catch break :blk;
                log.err("failed to run command '{s}': {}", .{ args, err });
                break :blk;
            };
            defer manager.allocator.free(run_result.stdout);
            defer manager.allocator.free(run_result.stderr);

            global_cache_dir.handle.writeFile(.{
                .sub_path = "builtin.zig",
                .data = run_result.stdout,
            }) catch |err| {
                log.err("failed to write file '{f}builtin.zig': {}", .{ global_cache_dir, err });
                break :blk;
            };

            config.builtin_path = try global_cache_dir.join(arena, &.{"builtin.zig"});
        }

        var did_change: DidConfigChange = .{};

        inline for (std.meta.fields(Config)) |field| {
            const old_value = &@field(manager.config, field.name);
            const new_value = @field(config, field.name);

            const is_eql = option.eql(field.type, old_value.*, new_value);
            @field(did_change, field.name) = !is_eql;

            if (!is_eql) {
                old_value.* = try option.dupe(field.type, new_value, arena_allocator.allocator());
            }
        }

        manager.impl.is_dirty = false;
        return .{
            .did_change = did_change,
            .messages = try messages.toOwnedSlice(result_allocator),
        };
    }

    fn validateConfiguration(
        config: *Config,
        allocator: std.mem.Allocator,
        messages: *std.ArrayList([]const u8),
    ) error{OutOfMemory}!void {
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

                if (!std.fs.path.isAbsolute(path)) {
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
                        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
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
                        };
                        defer file.close();

                        const stat = file.stat() catch |err| {
                            try messages.ensureUnusedCapacity(allocator, 1);
                            messages.appendAssumeCapacity(try std.fmt.allocPrint(
                                allocator,
                                "config option '{s}': failed to access '{s}': {}",
                                .{ file_config.name, path, err },
                            ));
                            break :ok true;
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
                        var dir = std.fs.openDirAbsolute(path, .{}) catch |err| {
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
                        };
                        defer dir.close();
                        const stat = dir.stat() catch |err| {
                            log.err("failed to get stat of '{s}': {}", .{ path, err });
                            break :ok true;
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
    allocator: std.mem.Allocator,
    result_arena: std.mem.Allocator,
    zig_exe_path: []const u8,
) error{OutOfMemory}!?Env {
    const zig_env_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ zig_exe_path, "env" },
    }) catch |err| {
        log.err("Failed to run 'zig env': {}", .{err});
        return null;
    };

    defer {
        allocator.free(zig_env_result.stdout);
        allocator.free(zig_env_result.stderr);
    }

    switch (zig_env_result.term) {
        .Exited => |code| {
            if (code != 0) {
                log.err("zig env command exited with error code {d}.", .{code});
                if (zig_env_result.stderr.len != 0) {
                    log.err("stderr: {s}", .{zig_env_result.stderr});
                }
                return null;
            }
        },
        .Signal, .Stopped, .Unknown => {
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
        const source = try allocator.dupeZ(u8, zig_env_result.stdout);
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
    .{ .name = "build_runner_path", .kind = .file, .is_accessible = true },
    .{ .name = "zig_lib_path", .kind = .directory, .is_accessible = true },
    .{ .name = "global_cache_path", .kind = .directory, .is_accessible = false },
};

comptime {
    skip: for (std.meta.fieldNames(Config)) |field_name| {
        @setEvalBranchQuota(2_000);
        if (std.mem.indexOf(u8, field_name, "path") == null) continue;

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
    var config_info: std.builtin.Type = @typeInfo(Config);
    var fields: [config_info.@"struct".fields.len]std.builtin.Type.StructField = undefined;
    for (config_info.@"struct".fields, &fields) |field, *new_field| {
        new_field.* = field;
        if (@typeInfo(field.type) != .optional) {
            new_field.type = @Type(.{
                .optional = .{ .child = field.type },
            });
        }
        new_field.default_value_ptr = &@as(new_field.type, null);
    }
    config_info.@"struct".fields = fields[0..];
    config_info.@"struct".decls = &.{};
    break :blk @Type(config_info);
};

/// A packed struct where every field name is copied from `Config` but the field type is `bool`.
pub const DidConfigChange = blk: {
    const config_fields = std.meta.fields(Config);
    var fields: [config_fields.len]std.builtin.Type.StructField = undefined;
    for (config_fields, &fields) |field, *new_field| {
        new_field.* = .{
            .name = field.name,
            .type = bool,
            .default_value_ptr = &false,
            .is_comptime = false,
            .alignment = 0,
        };
    }
    break :blk @Type(.{
        .@"struct" = .{
            .layout = .@"packed",
            .fields = &fields,
            .decls = &.{},
            .is_tuple = false,
        },
    });
};

pub fn findZig(allocator: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
    const is_windows = builtin.target.os.tag == .windows;

    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        error.OutOfMemory => |e| return e,
        error.InvalidWtf8 => |e| {
            log.err("failed to load 'PATH' environment variable: {}", .{e});
            return null;
        },
    };
    defer allocator.free(env_path);

    const env_path_ext = if (is_windows)
        std.process.getEnvVarOwned(allocator, "PATHEXT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return null,
            error.OutOfMemory => |e| return e,
            error.InvalidWtf8 => |e| {
                log.err("failed to load 'PATH' environment variable: {}", .{e});
                return null;
            },
        };
    defer if (is_windows) allocator.free(env_path_ext);

    var filename_buffer: std.ArrayList(u8) = .empty;
    defer filename_buffer.deinit(allocator);

    var path_it = std.mem.tokenizeScalar(u8, env_path, std.fs.path.delimiter);
    var ext_it = if (is_windows) std.mem.tokenizeScalar(u8, env_path_ext, std.fs.path.delimiter);

    while (path_it.next()) |path| : (if (is_windows) ext_it.reset()) {
        var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| {
                log.warn("failed to open entry in PATH '{s}': {}", .{ path, e });
                continue;
            },
        };
        defer dir.close();

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

            const stat = dir.statFile(filename) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| {
                    log.warn("failed to access entry in PATH '{f}': {}", .{ std.fs.path.fmtJoin(&.{ path, filename }), e });
                    continue;
                },
            };

            if (stat.kind == .directory) {
                log.warn("ignoring entry in PATH '{f}' because it is a directory", .{std.fs.path.fmtJoin(&.{ path, filename })});
                continue;
            }

            return try std.fs.path.join(allocator, &.{ path, filename });
        }
    }
    return null;
}
