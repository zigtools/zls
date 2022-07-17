//! Configuration options for zls.

const Config = @This();

const std = @import("std");
const setup = @import("setup.zig");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");

const logger = std.log.scoped(.config);

/// Whether to enable snippet completions
enable_snippets: bool = false,

/// Whether to enable unused variable warnings
enable_unused_variable_warnings: bool = false,

/// Whether to enable import/embedFile argument completions (NOTE: these are triggered manually as updating the autotrigger characters may cause issues)
enable_import_embedfile_argument_completions: bool = false,

/// Zig library path
zig_lib_path: ?[]const u8 = null,

/// Zig executable path used to run the custom build runner.
/// May be used to find a lib path if none is provided.
zig_exe_path: ?[]const u8 = null,

/// Whether to pay attention to style issues. This is opt-in since the style
/// guide explicitly states that the style info provided is a guideline only.
warn_style: bool = false,

/// Path to the build_runner.zig file.
build_runner_path: ?[]const u8 = null,

/// Path to a directory that will be used as cache when `zig run`ning the build runner
build_runner_cache_path: ?[]const u8 = null,

/// Semantic token support
enable_semantic_tokens: bool = true,

/// Whether to enable `*` and `?` operators in completion lists
operator_completions: bool = true,

/// Whether the @ sign should be part of the completion of builtins
include_at_in_builtins: bool = false,

/// The detail field of completions is truncated to be no longer than this (in bytes).
max_detail_length: usize = 1048576,

/// Skips references to std. This will improve lookup speeds.
/// Going to definition however will continue to work
skip_std_references: bool = false,

/// Path to "builtin;" useful for debugging, automatically set if let null
builtin_path: ?[]const u8 = null,

pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) ?Config {
    @setEvalBranchQuota(5000);

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
    @setEvalBranchQuota(3000);
    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{ .allocator = allocator }) catch |err| {
        logger.warn("Error while parsing configuration file: {}", .{err});
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
pub fn configChanged(config: *Config, allocator: std.mem.Allocator, builtin_creation_dir: ?[]const u8) !void {
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
        config.zig_exe_path = try setup.findZig(allocator);
    }

    if (config.zig_exe_path) |exe_path| {
        logger.info("Using zig executable {s}", .{exe_path});

        if (config.zig_lib_path == null) find_lib_path: {
            // Use `zig env` to find the lib path
            const zig_env_result = try std.ChildProcess.exec(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ exe_path, "env" },
            });

            defer {
                allocator.free(zig_env_result.stdout);
                allocator.free(zig_env_result.stderr);
            }

            switch (zig_env_result.term) {
                .Exited => |exit_code| {
                    if (exit_code == 0) {
                        const Env = struct {
                            zig_exe: []const u8,
                            lib_dir: ?[]const u8,
                            std_dir: []const u8,
                            global_cache_dir: []const u8,
                            version: []const u8,
                        };

                        var json_env = std.json.parse(
                            Env,
                            &std.json.TokenStream.init(zig_env_result.stdout),
                            .{ .allocator = allocator },
                        ) catch {
                            logger.err("Failed to parse zig env JSON result", .{});
                            break :find_lib_path;
                        };
                        defer std.json.parseFree(Env, json_env, .{ .allocator = allocator });
                        // We know this is allocated with `allocator`, we just steal it!
                        config.zig_lib_path = json_env.lib_dir.?;
                        json_env.lib_dir = null;
                        logger.info("Using zig lib path '{s}'", .{config.zig_lib_path});
                    }
                },
                else => logger.err("zig env invocation failed", .{}),
            }
        }
    } else {
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

    config.build_runner_path = if (config.build_runner_path) |p|
        try allocator.dupe(u8, p)
    else blk: {
        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = try std.fs.selfExeDirPath(&exe_dir_bytes);
        break :blk try std.fs.path.resolve(allocator, &[_][]const u8{ exe_dir_path, "build_runner.zig" });
    };

    config.build_runner_cache_path = if (config.build_runner_cache_path) |p|
        try allocator.dupe(u8, p)
    else blk: {
        const cache_dir_path = (try known_folders.getPath(allocator, .cache)) orelse {
            logger.warn("Known-folders could not fetch the cache path", .{});
            return;
        };
        defer allocator.free(cache_dir_path);
        break :blk try std.fs.path.resolve(allocator, &[_][]const u8{ cache_dir_path, "zls" });
    };
}
