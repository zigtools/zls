//! read and resolve configuration options.

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("Config.zig");

const logger = std.log.scoped(.config);

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
        logger.err("Failed to run 'zig env': {}", .{err});
        return null;
    };

    defer {
        allocator.free(zig_env_result.stdout);
        allocator.free(zig_env_result.stderr);
    }

    switch (zig_env_result.term) {
        .Exited => |code| {
            if (code != 0) {
                logger.err("zig env failed with error_code: {}", .{code});
                return null;
            }
        },
        else => {
            logger.err("zig env invocation failed", .{});
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
                logger.err("Failed to parse 'zig env' output as JSON: {}", .{err});
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
                logger.err("Failed to parse 'zig env' output as Zon: {}", .{err});
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
    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        error.OutOfMemory => |e| return e,
        error.InvalidWtf8 => |e| {
            logger.err("failed to load 'PATH' environment variable: {}", .{e});
            return null;
        },
    };
    defer allocator.free(env_path);

    const zig_exe = "zig" ++ comptime builtin.target.exeFileExt();

    var it = std.mem.tokenizeScalar(u8, env_path, std.fs.path.delimiter);
    while (it.next()) |path| {
        var full_path = try std.fs.path.join(allocator, &.{ path, zig_exe });
        defer allocator.free(full_path);

        if (!std.fs.path.isAbsolute(full_path)) {
            logger.warn("ignoring entry in PATH '{s}' because it is not an absolute file path", .{full_path});
            continue;
        }

        const file = std.fs.openFileAbsolute(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| {
                logger.warn("failed to open entry in PATH '{s}': {}", .{ full_path, e });
                continue;
            },
        };
        defer file.close();

        stat_failed: {
            const stat = file.stat() catch break :stat_failed;
            if (stat.kind == .directory) {
                logger.warn("ignoring entry in PATH '{s}' because it is a directory", .{full_path});
                continue;
            }
        }

        defer full_path = "";
        return full_path;
    }
    return null;
}
