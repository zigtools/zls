const std = @import("std");
const builtin = @import("builtin");

const ZigVersionWrapper = @import("ZigVersionWrapper.zig");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");

const Config = @import("Config.zig");
const offsets = @import("offsets.zig");

const logger = std.log.scoped(.zls_config);

pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) ?Config {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        if (err != error.FileNotFound)
            logger.warn("Error while reading configuration file: {}", .{err});
        return null;
    };

    defer file.close();

    const file_buf = file.readToEndAlloc(allocator, 0x1000000) catch return null;
    defer allocator.free(file_buf);
    @setEvalBranchQuota(10000);

    const parse_options = std.json.ParseOptions{ .ignore_unknown_fields = true };
    var parse_diagnostics: std.json.Diagnostics = undefined;

    var scanner = std.json.Scanner.initCompleteInput(allocator, file_buf);
    defer scanner.deinit();
    scanner.enableDiagnostics(&parse_diagnostics);

    // TODO: report errors using "textDocument/publishDiagnostics"
    var config = std.json.parseFromTokenSource(Config, allocator, &scanner, parse_options) catch |err| {
        logger.warn(
            "{s}:{d}:{d}: Error while parsing configuration file {}",
            .{ file_path, parse_diagnostics.getLine(), parse_diagnostics.getColumn(), err },
        );
        return null;
    };

    if (config.zig_lib_path) |zig_lib_path| {
        if (!std.fs.path.isAbsolute(zig_lib_path)) {
            logger.warn("zig library path is not absolute, defaulting to null.", .{});
            allocator.free(zig_lib_path);
            config.zig_lib_path = null;
        }
    }

    return config;
}

pub fn loadFromFolder(allocator: std.mem.Allocator, folder_path: []const u8) ?Config {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const full_path = std.fs.path.resolve(allocator, &.{ folder_path, "zls.json" }) catch return null;
    defer allocator.free(full_path);
    return loadFromFile(allocator, full_path);
}

/// Invoke this once all config values have been changed.
pub fn configChanged(config: *Config, runtime_zig_version: *?ZigVersionWrapper, allocator: std.mem.Allocator, builtin_creation_dir: ?[]const u8) !void {
    if (!std.process.can_spawn) return;
    // Find the zig executable in PATH
    find_zig: {
        if (config.zig_exe_path) |exe_path| {
            if (std.fs.path.isAbsolute(exe_path)) not_valid: {
                std.fs.cwd().access(exe_path, .{}) catch break :not_valid;
                break :find_zig;
            }
            logger.debug("zig path `{s}` is not absolute, will look in path", .{exe_path});
            allocator.free(exe_path);
        }
        config.zig_exe_path = try findZig(allocator);
    }

    if (config.zig_exe_path) |exe_path| blk: {
        logger.info("Using zig executable '{s}'", .{exe_path});

        var env = getZigEnv(allocator, exe_path) orelse break :blk;
        defer std.json.parseFree(Env, allocator, env);

        if (config.zig_lib_path) |lib_path| allocator.free(lib_path);
        // Make sure the path is absolute
        config.zig_lib_path = try std.fs.realpathAlloc(allocator, env.lib_dir.?);
        logger.info("Using zig lib path '{s}'", .{config.zig_lib_path.?});

        if (config.build_runner_global_cache_path) |global_cache_path| allocator.free(global_cache_path);
        config.build_runner_global_cache_path = try allocator.dupe(u8, env.global_cache_dir);
        logger.info("Using build runner global cache path '{s}'", .{config.build_runner_global_cache_path.?});

        if (runtime_zig_version.*) |current_version| current_version.free();
        errdefer runtime_zig_version.* = null;

        const duped_zig_version_string = try allocator.dupe(u8, env.version);
        errdefer allocator.free(duped_zig_version_string);

        logger.info("Detected runtime zig version: '{s}'", .{duped_zig_version_string});

        runtime_zig_version.* = .{
            .version = try std.SemanticVersion.parse(duped_zig_version_string),
            .allocator = allocator,
            .raw_string = duped_zig_version_string,
        };
    } else {
        if (runtime_zig_version.*) |version| version.free();
        runtime_zig_version.* = null;
        logger.warn("Zig executable path not specified in zls.json and could not be found in PATH", .{});
    }

    if (config.zig_lib_path == null) {
        logger.warn("Zig standard library path not specified in zls.json and could not be resolved from the zig executable", .{});
    }

    if (config.builtin_path == null and config.zig_exe_path != null and builtin_creation_dir != null) blk: {
        const result = try std.ChildProcess.exec(.{
            .allocator = allocator,
            .argv = &.{
                config.zig_exe_path.?,
                "build-exe",
                "--show-builtin",
            },
            .max_output_bytes = 1024 * 1024 * 50,
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        var d = try std.fs.cwd().openDir(builtin_creation_dir.?, .{});
        defer d.close();

        const f = d.createFile("builtin.zig", .{}) catch |err| switch (err) {
            error.AccessDenied => break :blk,
            else => |e| return e,
        };
        defer f.close();

        try f.writer().writeAll(result.stdout);

        config.builtin_path = try std.fs.path.join(allocator, &.{ builtin_creation_dir.?, "builtin.zig" });
    }

    if (null == config.global_cache_path) {
        const cache_dir_path = (try known_folders.getPath(allocator, .cache)) orelse {
            logger.warn("Known-folders could not fetch the cache path", .{});
            return;
        };
        defer allocator.free(cache_dir_path);

        config.global_cache_path = try std.fs.path.resolve(allocator, &[_][]const u8{ cache_dir_path, "zls" });

        std.fs.cwd().makePath(config.global_cache_path.?) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    if (null == config.build_runner_path) {
        config.build_runner_path = try std.fs.path.resolve(allocator, &[_][]const u8{ config.global_cache_path.?, "build_runner.zig" });

        const file = try std.fs.createFileAbsolute(config.build_runner_path.?, .{});
        defer file.close();

        try file.writeAll(@embedFile("special/build_runner.zig"));
    }
}

pub const Env = struct {
    zig_exe: []const u8,
    lib_dir: ?[]const u8,
    std_dir: []const u8,
    global_cache_dir: []const u8,
    version: []const u8,
    target: ?[]const u8 = null,
};

/// result has to be freed with `std.json.parseFree`
pub fn getZigEnv(allocator: std.mem.Allocator, zig_exe_path: []const u8) ?Env {
    const zig_env_result = std.ChildProcess.exec(.{
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
        .{ .ignore_unknown_fields = true },
    ) catch {
        logger.err("Failed to parse zig env JSON result", .{});
        return null;
    };
}

pub const Configuration = getConfigurationType();
pub const DidChangeConfigurationParams = struct {
    settings: ?Configuration,
};

// returns a Struct which is the same as `Config` except that every field is optional.
fn getConfigurationType() type {
    var config_info: std.builtin.Type = @typeInfo(Config);
    var fields: [config_info.Struct.fields.len]std.builtin.Type.StructField = undefined;
    for (config_info.Struct.fields, &fields) |field, *new_field| {
        new_field.* = field;
        if (@typeInfo(field.type) != .Optional) {
            new_field.type = @Type(std.builtin.Type{
                .Optional = .{ .child = field.type },
            });
        }
    }
    config_info.Struct.fields = fields[0..];
    config_info.Struct.decls = &.{};
    return @Type(config_info);
}

pub fn findZig(allocator: std.mem.Allocator) !?[]const u8 {
    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            return null;
        },
        else => return err,
    };
    defer allocator.free(env_path);

    const exe_extension = builtin.target.exeFileExt();
    const zig_exe = try std.fmt.allocPrint(allocator, "zig{s}", .{exe_extension});
    defer allocator.free(zig_exe);

    var it = std.mem.tokenize(u8, env_path, &[_]u8{std.fs.path.delimiter});
    while (it.next()) |path| {
        if (builtin.os.tag == .windows) {
            if (std.mem.indexOfScalar(u8, path, '/') != null) continue;
        }
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, zig_exe });
        defer allocator.free(full_path);

        if (!std.fs.path.isAbsolute(full_path)) continue;

        const file = std.fs.openFileAbsolute(full_path, .{}) catch continue;
        defer file.close();
        const stat = file.stat() catch continue;
        if (stat.kind == .Directory) continue;

        return try allocator.dupe(u8, full_path);
    }
    return null;
}
