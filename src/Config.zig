//! Configuration options for zls.
//! Keep in sync with schema.json and zls-vscode's package.json!

const Config = @This();

const std = @import("std");
const setup = @import("setup.zig");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");

const logger = std.log.scoped(.config);

/// Whether to enable snippet completions
enable_snippets: bool = false,

/// Whether to enable ast-check diagnostics
enable_ast_check_diagnostics: bool = true,

/// Whether to automatically fix errors on save.
/// Currently supports adding and removing discards.
enable_autofix: bool = false,

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

/// Path to the global cache directory
global_cache_path: ?[]const u8 = null,

/// Semantic token support
enable_semantic_tokens: bool = true,

/// Inlay hint support
enable_inlay_hints: bool = false,

/// enable inlay hints for builtin functions
inlay_hints_show_builtin: bool = true,

/// don't show inlay hints for single argument calls
inlay_hints_exclude_single_argument: bool = true,

/// don't show inlay hints when parameter name matches the identifier
/// for example: `foo: foo`
inlay_hints_hide_redundant_param_names: bool = false,

/// don't show inlay hints when parameter names matches the last
/// for example: `foo: bar.foo`, `foo: &foo`
inlay_hints_hide_redundant_param_names_last_token: bool = false,

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

/// Whether to highlight global var declarations.
highlight_global_var_declarations: bool = false,

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

    var token_stream = std.json.TokenStream.init(file_buf);
    const parse_options = std.json.ParseOptions{ .allocator = allocator, .ignore_unknown_fields = true };

    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &token_stream, parse_options) catch |err| {
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

    if (config.zig_exe_path) |exe_path| blk: {
        logger.info("Using zig executable {s}", .{exe_path});

        if (config.zig_lib_path != null) break :blk;

        var env = getZigEnv(allocator, exe_path) orelse break :blk;
        defer std.json.parseFree(Env, env, .{ .allocator = allocator });

        // We know this is allocated with `allocator`, we just steal it!
        config.zig_lib_path = env.lib_dir.?;
        env.lib_dir = null;
        logger.info("Using zig lib path '{s}'", .{config.zig_lib_path.?});
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

    var token_stream = std.json.TokenStream.init(zig_env_result.stdout);
    return std.json.parse(
        Env,
        &token_stream,
        .{
            .allocator = allocator,
            .ignore_unknown_fields = true,
        },
    ) catch {
        logger.err("Failed to parse zig env JSON result", .{});
        return null;
    };
}

pub const Configuration = Config.getConfigurationType();
pub const DidChangeConfigurationParams = struct {
    settings: ?Configuration,
};

// returns a Struct which is the same as `Config` except that every field is optional.
fn getConfigurationType() type {
    var config_info: std.builtin.Type = @typeInfo(Config);
    var fields: [config_info.Struct.fields.len]std.builtin.Type.StructField = undefined;
    for (config_info.Struct.fields) |field, i| {
        fields[i] = field;
        if (@typeInfo(field.field_type) != .Optional) {
            fields[i].field_type = @Type(std.builtin.Type{
                .Optional = .{ .child = field.field_type },
            });
        }
    }
    config_info.Struct.fields = fields[0..];
    config_info.Struct.decls = &.{};
    return @Type(config_info);
}
