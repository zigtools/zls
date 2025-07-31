//! read and resolve configuration options.

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("Config.zig");

const log = std.log.scoped(.config);

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
    zig_exe_path: []const u8,
) error{OutOfMemory}!?std.json.Parsed(Env) {
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
                log.err("zig env failed with error_code: {}", .{code});
                return null;
            }
        },
        else => {
            log.err("zig env invocation failed", .{});
            return null;
        },
    }

    if (std.mem.startsWith(u8, zig_env_result.stdout, "{")) {
        return std.json.parseFromSlice(
            Env,
            allocator,
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
        var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena_allocator.deinit();

        const source = try allocator.dupeZ(u8, zig_env_result.stdout);
        defer allocator.free(source);

        const value = std.zon.parse.fromSlice(
            Env,
            arena_allocator.allocator(),
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

        const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena_ptr);

        arena_ptr.* = arena_allocator;

        return .{
            .arena = arena_ptr,
            .value = value,
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

/// the same struct as Config but every field is optional
pub const Configuration = getConfigurationType();

// returns a Struct which is the same as `Config` except that every field is optional.
fn getConfigurationType() type {
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
    return @Type(config_info);
}

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
        std.process.getEnvVarOwned(allocator, "PATH_EXT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return null,
            error.OutOfMemory => |e| return e,
            error.InvalidWtf8 => |e| {
                log.err("failed to load 'PATH' environment variable: {}", .{e});
                return null;
            },
        };
    defer if (is_windows) allocator.free(env_path_ext);

    var filename_buffer: std.ArrayListUnmanaged(u8) = .empty;
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
                const ext = ext_it.next() orelse continue;

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
