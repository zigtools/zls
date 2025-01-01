//! read and resolve configuration options.

const std = @import("std");
const builtin = @import("builtin");

const tracy = @import("tracy");
const known_folders = @import("known-folders");

const Config = @import("Config.zig");

const logger = std.log.scoped(.config);

pub fn getLocalConfigPath(allocator: std.mem.Allocator) known_folders.Error!?[]const u8 {
    const folder_path = try known_folders.getPath(allocator, .local_configuration) orelse return null;
    defer allocator.free(folder_path);
    return try std.fs.path.join(allocator, &.{ folder_path, "zls.json" });
}

pub fn getGlobalConfigPath(allocator: std.mem.Allocator) known_folders.Error!?[]const u8 {
    const folder_path = try known_folders.getPath(allocator, .global_configuration) orelse return null;
    defer allocator.free(folder_path);
    return try std.fs.path.join(allocator, &.{ folder_path, "zls.json" });
}

pub fn load(allocator: std.mem.Allocator) error{OutOfMemory}!LoadConfigResult {
    const local_config_path = getLocalConfigPath(allocator) catch |err| blk: {
        logger.warn("failed to resolve local configuration path: {}", .{err});
        break :blk null;
    };
    defer if (local_config_path) |path| allocator.free(path);

    const global_config_path = getGlobalConfigPath(allocator) catch |err| blk: {
        logger.warn("failed to resolve global configuration path: {}", .{err});
        break :blk null;
    };
    defer if (global_config_path) |path| allocator.free(path);

    for ([_]?[]const u8{ local_config_path, global_config_path }) |config_path| {
        const result = try loadFromFile(allocator, config_path orelse continue);
        switch (result) {
            .success, .failure => return result,
            .not_found => {},
        }
    }

    return .not_found;
}

pub const LoadConfigResult = union(enum) {
    success: struct {
        config: std.json.Parsed(Config),
        /// file path of the config.json
        path: []const u8,
    },
    failure: struct {
        /// `null` indicates that the error has already been logged
        error_bundle: ?std.zig.ErrorBundle,

        pub fn toMessage(self: @This(), allocator: std.mem.Allocator) error{OutOfMemory}!?[]u8 {
            const error_bundle = self.error_bundle orelse return null;
            var msg: std.ArrayListUnmanaged(u8) = .empty;
            errdefer msg.deinit(allocator);
            error_bundle.renderToWriter(.{ .ttyconf = .no_color }, msg.writer(allocator)) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                else => unreachable, // why does renderToWriter return `anyerror!void`?
            };
            return try msg.toOwnedSlice(allocator);
        }
    },
    not_found,

    pub fn deinit(self: *LoadConfigResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*config_with_path| {
                config_with_path.config.deinit();
                allocator.free(config_with_path.path);
            },
            .failure => |*payload| {
                if (payload.error_bundle) |*error_bundle| error_bundle.deinit(allocator);
            },
            .not_found => {},
        }
    }
};

pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) error{OutOfMemory}!LoadConfigResult {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_buf = std.fs.cwd().readFileAlloc(allocator, file_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return .not_found,
        error.OutOfMemory => |e| return e,
        else => {
            logger.warn("Error while reading configuration file: {}", .{err});
            return .{ .failure = .{ .error_bundle = null } };
        },
    };
    defer allocator.free(file_buf);

    const parse_options: std.json.ParseOptions = .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    var parse_diagnostics: std.json.Diagnostics = .{};

    var scanner: std.json.Scanner = .initCompleteInput(allocator, file_buf);
    defer scanner.deinit();
    scanner.enableDiagnostics(&parse_diagnostics);

    @setEvalBranchQuota(10000);
    const config = std.json.parseFromTokenSource(
        Config,
        allocator,
        &scanner,
        parse_options,
    ) catch |err| {
        var eb: std.zig.ErrorBundle.Wip = undefined;
        try eb.init(allocator);
        errdefer eb.deinit();

        const src_path = try eb.addString(file_path);
        const msg = try eb.addString(@errorName(err));

        const src_loc = try eb.addSourceLocation(.{
            .src_path = src_path,
            .line = @intCast(parse_diagnostics.getLine()),
            .column = @intCast(parse_diagnostics.getColumn()),
            .span_start = @intCast(parse_diagnostics.getByteOffset()),
            .span_main = @intCast(parse_diagnostics.getByteOffset()),
            .span_end = @intCast(parse_diagnostics.getByteOffset()),
        });
        try eb.addRootErrorMessage(.{
            .msg = msg,
            .src_loc = src_loc,
        });

        return .{ .failure = .{ .error_bundle = try eb.toOwnedBundle("") } };
    };

    return .{ .success = .{
        .config = config,
        .path = try allocator.dupe(u8, file_path),
    } };
}

pub const Env = struct {
    zig_exe: []const u8,
    lib_dir: ?[]const u8,
    std_dir: []const u8,
    global_cache_dir: []const u8,
    version: []const u8,
    target: ?[]const u8 = null,
};

pub fn getZigEnv(allocator: std.mem.Allocator, zig_exe_path: []const u8) ?std.json.Parsed(Env) {
    const zig_env_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ zig_exe_path, "env" },
    }) catch {
        logger.err("Failed to execute zig env", .{});
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
        else => logger.err("zig env invocation failed", .{}),
    }

    return std.json.parseFromSlice(
        Env,
        allocator,
        zig_env_result.stdout,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    ) catch {
        logger.err("Failed to parse zig env JSON result", .{});
        return null;
    };
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
            new_field.type = @Type(std.builtin.Type{
                .optional = .{ .child = field.type },
            });
        }
        new_field.default_value = &@as(new_field.type, null);
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
        var full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, zig_exe });
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
            }
        }

        defer full_path = "";
        return full_path;
    }
    return null;
}
