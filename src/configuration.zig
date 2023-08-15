const std = @import("std");
const builtin = @import("builtin");

const ZigVersionWrapper = @import("ZigVersionWrapper.zig");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");

const Config = @import("Config.zig");
const offsets = @import("offsets.zig");

const logger = std.log.scoped(.zls_config);

pub const ConfigWithPath = struct {
    config: Config,
    arena: std.heap.ArenaAllocator.State,
    /// The path to the file from which the config was read.
    config_path: ?[]const u8,

    pub fn deinit(self: *ConfigWithPath, allocator: std.mem.Allocator) void {
        self.arena.promote(allocator).deinit();
        if (self.config_path) |path| allocator.free(path);
        self.* = undefined;
    }
};

pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) ?ConfigWithPath {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_buf = std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => {
            logger.warn("Error while reading configuration file: {}", .{err});
            return null;
        },
    };
    defer allocator.free(file_buf);

    const parse_options = std.json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    var parse_diagnostics: std.json.Diagnostics = .{};

    var scanner = std.json.Scanner.initCompleteInput(allocator, file_buf);
    defer scanner.deinit();
    scanner.enableDiagnostics(&parse_diagnostics);

    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_allocator.deinit();

    @setEvalBranchQuota(10000);
    // TODO: report errors using "textDocument/publishDiagnostics"
    const config = std.json.parseFromTokenSourceLeaky(
        Config,
        arena_allocator.allocator(),
        &scanner,
        parse_options,
    ) catch |err| {
        logger.warn(
            "{s}:{d}:{d}: Error while parsing configuration file {}",
            .{ file_path, parse_diagnostics.getLine(), parse_diagnostics.getColumn(), err },
        );
        return null;
    };

    return .{
        .config = config,
        .arena = arena_allocator.state,
        .config_path = file_path,
    };
}

pub fn getConfig(allocator: std.mem.Allocator, config_path: ?[]const u8) !ConfigWithPath {
    if (config_path) |path| {
        if (loadFromFile(allocator, path)) |config| {
            var cfg = config;
            errdefer cfg.deinit(allocator);
            cfg.config_path = try allocator.dupe(u8, path);
            return cfg;
        }
        logger.info(
            \\Could not open configuration file '{s}'
            \\Falling back to a lookup in the local and global configuration folders
            \\
        , .{path});
    }

    if (try known_folders.getPath(allocator, .local_configuration)) |folder_path| {
        defer allocator.free(folder_path);
        const file_path = try std.fs.path.resolve(allocator, &.{ folder_path, "zls.json" });
        if (loadFromFile(allocator, file_path)) |config| return config;
        allocator.free(file_path);
    }

    if (try known_folders.getPath(allocator, .global_configuration)) |folder_path| {
        defer allocator.free(folder_path);
        const file_path = try std.fs.path.resolve(allocator, &.{ folder_path, "zls.json" });
        if (loadFromFile(allocator, file_path)) |config| return config;
        allocator.free(file_path);
    }

    return ConfigWithPath{
        .config = .{},
        .arena = .{},
        .config_path = null,
    };
}

pub const Env = struct {
    zig_exe: []const u8,
    lib_dir: ?[]const u8,
    std_dir: []const u8,
    global_cache_dir: []const u8,
    version: []const u8,
    target: ?[]const u8 = null,
};

/// result has to be freed with `json_compat.parseFree`
pub fn getZigEnv(allocator: std.mem.Allocator, zig_exe_path: []const u8) ?std.json.Parsed(Env) {
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

    var parsed = std.json.parseFromSlice(
        Env,
        allocator,
        zig_env_result.stdout,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    ) catch {
        logger.err("Failed to parse zig env JSON result", .{});
        return null;
    };
    if (parsed.value.lib_dir) |d| {
        parsed.value.lib_dir = std.fs.realpathAlloc(parsed.arena.allocator(), d) catch d;
    }
    parsed.value.std_dir = std.fs.realpathAlloc(parsed.arena.allocator(), parsed.value.std_dir) catch parsed.value.std_dir;

    return parsed;
}

/// the same struct as Config but every field is optional
pub const Configuration = getConfigurationType();

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
        new_field.default_value = &@as(new_field.type, null);
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
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, zig_exe });
        defer allocator.free(full_path);

        if (!std.fs.path.isAbsolute(full_path)) continue;

        const file = std.fs.openFileAbsolute(full_path, .{}) catch continue;
        defer file.close();
        const stat = file.stat() catch continue;
        if (stat.kind == .directory) continue;

        return try allocator.dupe(u8, full_path);
    }
    return null;
}
