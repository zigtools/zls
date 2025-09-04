const std = @import("std");
const zig_builtin = @import("builtin");
const zls = @import("zls");
const exe_options = @import("exe_options");

const tracy = @import("tracy");
const known_folders = @import("known-folders");

const log = std.log.scoped(.main);

const usage =
    \\ZLS - A non-official language server for Zig
    \\
    \\Commands:
    \\  help, --help,             Print this help and exit
    \\  version, --version        Print version number and exit
    \\  env                       Print config path, log path and version
    \\
    \\General Options:
    \\  --config-path [path]      Set path to the 'zls.json' configuration file
    \\  --log-file [path]         Set path to the 'zls.log' log file
    \\  --log-level [enum]        The Log Level to be used.
    \\                              Supported Values:
    \\                                err
    \\                                warn
    \\                                info (default)
    \\                                debug
    \\
    \\Advanced Options:
    \\  --enable-stderr-logs      Write log message to stderr
    \\  --disable-lsp-logs        Disable LSP 'window/logMessage' messages
    \\
;

pub const std_options: std.Options = .{
    // Always set this to debug to make std.log call into our handler, then control the runtime
    // value in logFn itself
    .log_level = .debug,
    .logFn = logFn,
};

/// Log messages with the LSP 'window/logMessage' message.
var log_transport: ?*zls.lsp.Transport = null;
/// Log messages to stderr.
var log_stderr: bool = true;
/// Log messages to the given file.
var log_file: ?std.fs.File = null;
var log_level: std.log.Level = if (zig_builtin.mode == .Debug) .debug else .info;

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    var buffer: [4096]u8 = undefined;
    comptime std.debug.assert(buffer.len >= zls.lsp.minimum_logging_buffer_size);

    if (log_transport) |transport| {
        const lsp_message_type: zls.lsp.types.MessageType = switch (level) {
            .err => .Error,
            .warn => .Warning,
            .info => .Info,
            .debug => .Debug,
        };
        const json_message = zls.lsp.bufPrintLogMessage(&buffer, lsp_message_type, format, args);
        transport.writeJsonMessage(json_message) catch {};
    }

    if (@intFromEnum(level) > @intFromEnum(log_level)) return;
    if (!log_stderr and log_file == null) return;

    const level_txt: []const u8 = switch (level) {
        .err => "error",
        .warn => "warn ",
        .info => "info ",
        .debug => "debug",
    };
    const scope_txt: []const u8 = comptime @tagName(scope);

    var writer: std.Io.Writer = .fixed(&buffer);
    const no_space_left = blk: {
        writer.print("{s} ({s:^6}): ", .{ level_txt, scope_txt }) catch break :blk true;
        writer.print(format, args) catch break :blk true;
        writer.writeByte('\n') catch break :blk true;
        break :blk false;
    };
    if (no_space_left) {
        const trailing = "...\n".*;
        writer.undo(trailing.len -| writer.unusedCapacityLen());
        (writer.writableArray(trailing.len) catch unreachable).* = trailing;
    }

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();

    if (log_stderr) {
        var stderr_writer = std.fs.File.stderr().writer(&.{});
        stderr_writer.interface.writeAll(writer.buffered()) catch {};
    }

    if (log_file) |file| {
        var log_writer = file.writerStreaming(&.{});
        file.seekFromEnd(0) catch {};
        log_writer.interface.writeAll(writer.buffered()) catch {};
    }
}

fn defaultLogFilePath(allocator: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
    if (zig_builtin.target.os.tag == .wasi) return null;
    const cache_path = known_folders.getPath(allocator, .cache) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => return null,
    } orelse return null;
    defer allocator.free(cache_path);
    return try std.fs.path.join(allocator, &.{ cache_path, "zls", "zls.log" });
}

fn createLogFile(allocator: std.mem.Allocator, override_log_file_path: ?[]const u8) ?struct { std.fs.File, []const u8 } {
    const log_file_path = if (override_log_file_path) |log_file_path|
        allocator.dupe(u8, log_file_path) catch return null
    else
        defaultLogFilePath(allocator) catch null orelse return null;
    errdefer allocator.free(log_file_path);

    if (std.fs.path.dirname(log_file_path)) |dirname| {
        std.fs.cwd().makePath(dirname) catch {};
    }

    const file = std.fs.cwd().createFile(log_file_path, .{ .truncate = false }) catch {
        allocator.free(log_file_path);
        return null;
    };
    errdefer file.close();

    return .{ file, log_file_path };
}

/// Output format of `zls env`
const Env = struct {
    /// The ZLS version. Guaranteed to be a [semantic version](https://semver.org/).
    ///
    /// The semantic version can have one of the following formats:
    /// - `MAJOR.MINOR.PATCH` is a tagged release of ZLS
    /// - `MAJOR.MINOR.PATCH-dev.COMMIT_HEIGHT+SHORT_COMMIT_HASH` is a development build of ZLS
    /// - `MAJOR.MINOR.PATCH-dev` is a development build of ZLS where the exact version could not be resolved.
    ///
    version: []const u8,
    global_cache_dir: ?[]const u8,
    /// Path to a global configuration directory relative to which ZLS configuration files will be searched.
    /// Not `null` unless [known-folders](https://github.com/ziglibs/known-folders) was unable to find a global configuration directory.
    global_config_dir: ?[]const u8,
    /// Path to a user specific configuration directory relative to which configuration files will be searched.
    /// Not `null` unless [known-folders](https://github.com/ziglibs/known-folders) was unable to find a local configuration directory.
    local_config_dir: ?[]const u8,
    /// Path to a `zls.json` config file. Will be resolved by looking in the local configuration directory and then falling back to the global directory.
    /// Can be null if no `zls.json` was found in the global/local config directory.
    config_file: ?[]const u8,
    /// Path to a `zls.log` file where ZLS will append logging output. The file may be truncated or cleared by ZLS.
    /// Not `null` unless [known-folders](https://github.com/ziglibs/known-folders) was unable to find a cache directory.
    log_file: ?[]const u8,
};

fn @"zls env"(allocator: std.mem.Allocator) (std.mem.Allocator.Error || std.fs.File.WriteError)!noreturn {
    const global_cache_dir = known_folders.getPath(allocator, .cache) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => null,
    };
    defer if (global_cache_dir) |path| allocator.free(path);

    const zls_global_cache_dir = if (global_cache_dir) |cache_dir| try std.fs.path.join(allocator, &.{ cache_dir, "zls" }) else null;
    defer if (zls_global_cache_dir) |path| allocator.free(path);

    const global_config_dir = known_folders.getPath(allocator, .global_configuration) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => null,
    };
    defer if (global_config_dir) |path| allocator.free(path);

    const local_config_dir = known_folders.getPath(allocator, .local_configuration) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => null,
    };
    defer if (local_config_dir) |path| allocator.free(path);

    var config_result = try loadConfigFromSystem(allocator);
    defer config_result.deinit(allocator);

    const config_file_path: ?[]const u8 = switch (config_result) {
        .success => |config_with_path| config_with_path.path,
        .failure => |payload| blk: {
            const message = try payload.toMessage(allocator) orelse break :blk null;
            defer allocator.free(message);
            log.err("Failed to load configuration options.", .{});
            log.err("{s}", .{message});
            break :blk null;
        },
        .not_found => null,
    };

    const log_file_path = try defaultLogFilePath(allocator);
    defer if (log_file_path) |path| allocator.free(path);

    var buffer: [512]u8 = undefined;
    var file_writer = std.fs.File.stdout().writer(&buffer);
    const writer = &file_writer.interface;

    const env: Env = .{
        .version = zls.build_options.version_string,
        .global_cache_dir = zls_global_cache_dir,
        .global_config_dir = global_config_dir,
        .local_config_dir = local_config_dir,
        .config_file = config_file_path,
        .log_file = log_file_path,
    };
    std.json.Stringify.value(env, .{ .whitespace = .indent_1 }, writer) catch return file_writer.err.?;
    writer.writeAll("\n") catch return file_writer.err.?;
    writer.flush() catch return file_writer.err.?;

    std.process.exit(0);
}

const LoadConfigResult = union(enum) {
    success: struct {
        config: zls.Config,
        config_arena: std.heap.ArenaAllocator.State,
        /// file path of the config.json
        path: []const u8,
    },
    failure: struct {
        /// `null` indicates that the error has already been logged
        error_bundle: ?std.zig.ErrorBundle,

        pub fn toMessage(self: @This(), allocator: std.mem.Allocator) error{OutOfMemory}!?[]u8 {
            const error_bundle = self.error_bundle orelse return null;
            var aw: std.Io.Writer.Allocating = .init(allocator);
            defer aw.deinit();
            error_bundle.renderToWriter(.{ .ttyconf = .no_color }, &aw.writer) catch |err| switch (err) {
                error.WriteFailed => return error.OutOfMemory,
                error.Unexpected => unreachable, // no tty
            };
            return try aw.toOwnedSlice();
        }
    },
    not_found,

    pub fn deinit(self: *LoadConfigResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*config_with_path| {
                config_with_path.config_arena.promote(allocator).deinit();
                allocator.free(config_with_path.path);
            },
            .failure => |*payload| {
                if (payload.error_bundle) |*error_bundle| error_bundle.deinit(allocator);
            },
            .not_found => {},
        }
    }
};

fn loadConfigFromFile(allocator: std.mem.Allocator, file_path: []const u8) error{OutOfMemory}!LoadConfigResult {
    const file_buf = std.fs.cwd().readFileAlloc(file_path, allocator, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return .not_found,
        error.OutOfMemory => |e| return e,
        else => {
            log.warn("Error while reading configuration file: {}", .{err});
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

    var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena_allocator.deinit();

    @setEvalBranchQuota(10000);
    const config = std.json.parseFromTokenSourceLeaky(
        zls.Config,
        arena_allocator.allocator(),
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
        .config_arena = arena_allocator.state,
        .path = try allocator.dupe(u8, file_path),
    } };
}

fn loadConfigFromSystem(allocator: std.mem.Allocator) error{OutOfMemory}!LoadConfigResult {
    if (zig_builtin.target.os.tag == .wasi) return .not_found;

    for (
        [_]known_folders.KnownFolder{ .local_configuration, .global_configuration },
        [_][]const u8{ "local", "global" },
    ) |folder, name| {
        const folder_path = known_folders.getPath(allocator, folder) catch |err| switch (err) {
            error.ParseError => {
                log.warn("failed to resolve {s} configuration path: {}", .{ name, err });
                continue;
            },
            error.OutOfMemory => return error.OutOfMemory,
        } orelse continue;
        defer allocator.free(folder_path);

        const config_path = try std.fs.path.join(allocator, &.{ folder_path, "zls.json" });
        defer allocator.free(config_path);

        const result = try loadConfigFromFile(allocator, config_path);
        switch (result) {
            .success, .failure => return result,
            .not_found => continue,
        }
    }

    return .not_found;
}

fn loadConfiguration(
    allocator: std.mem.Allocator,
    server: *zls.Server,
    maybe_config_path: ?[]const u8,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var config_arena: std.heap.ArenaAllocator = .init(allocator);
    defer config_arena.deinit();
    var config: zls.Config = .{};

    blk: {
        var config_result = if (maybe_config_path) |config_path|
            loadConfigFromFile(allocator, config_path) catch |err| {
                log.err("failed to load configuration from '{s}': {}", .{ config_path, err });
                break :blk;
            }
        else
            loadConfigFromSystem(allocator) catch |err| {
                log.err("failed to load configuration: {}", .{err});
                break :blk;
            };
        defer config_result.deinit(allocator);

        switch (config_result) {
            .success => |*config_with_path| {
                log.info("Loaded config:    {s}", .{config_with_path.path});
                config = config_with_path.config;
                config_arena.state = config_with_path.config_arena;
                config_with_path.config_arena = .{};
            },
            .failure => |payload| {
                const message = try payload.toMessage(allocator) orelse break :blk;
                defer allocator.free(message);
                server.showMessage(.Error, "Failed to load configuration options:\n{s}", .{message});
            },
            .not_found => {},
        }
    }

    if (config.global_cache_path == null) blk: {
        if (zig_builtin.target.os.tag == .wasi) {
            // will default to `/cache`
            break :blk;
        }

        const cache_dir_path = known_folders.getPath(allocator, .cache) catch null orelse {
            server.showMessage(.Error, "Failed to resolve global cache directory", .{});
            break :blk;
        };
        defer allocator.free(cache_dir_path);

        config.global_cache_path = try std.fs.path.join(config_arena.allocator(), &.{ cache_dir_path, "zls" });
    }

    try server.config_manager.setConfiguration2(.frontend, &config);
}

const ParseArgsResult = struct {
    config_path: ?[]const u8 = null,
    log_level: ?std.log.Level = null,
    log_file_path: ?[]const u8 = null,
    zls_exe_path: []const u8 = "",
    enable_stderr_logs: bool = false,
    disable_lsp_logs: bool = false,

    fn deinit(self: ParseArgsResult, allocator: std.mem.Allocator) void {
        defer if (self.config_path) |path| allocator.free(path);
        defer if (self.log_file_path) |path| allocator.free(path);
        defer allocator.free(self.zls_exe_path);
    }
};

const ParseArgsError = std.process.ArgIterator.InitError || std.mem.Allocator.Error || std.fs.File.WriteError;

fn parseArgs(allocator: std.mem.Allocator) ParseArgsError!ParseArgsResult {
    var result: ParseArgsResult = .{};
    errdefer result.deinit(allocator);

    var args_it: std.process.ArgIterator = try .initWithAllocator(allocator);
    defer args_it.deinit();

    const zls_exe_path = args_it.next() orelse "";
    result.zls_exe_path = try allocator.dupe(u8, zls_exe_path);

    var arg_index: usize = 0;
    while (args_it.next()) |arg| : (arg_index += 1) {
        if ((arg_index == 0 and std.mem.eql(u8, arg, "help")) or
            std.mem.eql(u8, arg, "-h") or
            std.mem.eql(u8, arg, "--help"))
        {
            try std.fs.File.stderr().writeAll(usage);
            std.process.exit(0);
        } else if ((arg_index == 0 and std.mem.eql(u8, arg, "version")) or std.mem.eql(u8, arg, "--version")) {
            try std.fs.File.stdout().writeAll(zls.build_options.version_string ++ "\n");
            std.process.exit(0);
        } else if (arg_index == 0 and std.mem.eql(u8, arg, "env")) {
            try @"zls env"(allocator);
        }

        if (std.mem.eql(u8, arg, "--config-path")) { // --config-path
            const path = args_it.next() orelse {
                log.err("Expected configuration file path after --config-path argument.", .{});
                std.process.exit(1);
            };
            if (result.config_path) |old_config_path| allocator.free(old_config_path);
            result.config_path = try allocator.dupe(u8, path);
        } else if (std.mem.eql(u8, arg, "--log-file")) { // --log-file
            const path = args_it.next() orelse {
                log.err("Expected configuration file path after --log-file argument.", .{});
                std.process.exit(1);
            };
            if (result.log_file_path) |old_file_path| allocator.free(old_file_path);
            result.log_file_path = try allocator.dupe(u8, path);
        } else if (std.mem.eql(u8, arg, "--log-level")) { // --log-level
            const log_level_name = args_it.next() orelse {
                log.err("Expected argument after --log-level", .{});
                std.process.exit(1);
            };
            result.log_level = std.meta.stringToEnum(std.log.Level, log_level_name) orelse {
                log.err("Invalid --log-level argument. Expected one of {{'debug', 'info', 'warn', 'err'}} but got '{s}'", .{log_level_name});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--enable-stderr-logs")) { // --enable-stderr-logs
            result.enable_stderr_logs = true;
        } else if (std.mem.eql(u8, arg, "--disable-lsp-logs")) { // --disable-lsp-logs
            result.disable_lsp_logs = true;
        } else {
            log.err("Unrecognized argument: '{s}'", .{arg});
            std.process.exit(1);
        }
    }

    if (zig_builtin.target.os.tag != .wasi and std.fs.File.stdin().isTty()) {
        log.warn("ZLS is not a CLI tool, it communicates over the Language Server Protocol.", .{});
        log.warn("Did you mean to run 'zls --help'?", .{});
        log.warn("", .{});
    }

    return result;
}

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

pub fn main() !u8 {
    const base_allocator, const is_debug = gpa: {
        if (exe_options.debug_gpa) break :gpa .{ debug_allocator.allocator(), true };
        if (zig_builtin.target.os.tag == .wasi) break :gpa .{ std.heap.wasm_allocator, false };
        break :gpa switch (zig_builtin.mode) {
            .Debug => .{ debug_allocator.allocator(), true },
            .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        _ = debug_allocator.deinit();
    };

    var tracy_state = if (tracy.enable_allocation) tracy.tracyAllocator(base_allocator) else {};
    const inner_allocator: std.mem.Allocator = if (tracy.enable_allocation) tracy_state.allocator() else base_allocator;

    var failing_allocator_state = if (exe_options.enable_failing_allocator) zls.testing.FailingAllocator.init(inner_allocator, exe_options.enable_failing_allocator_likelihood) else {};
    const allocator: std.mem.Allocator = if (exe_options.enable_failing_allocator) failing_allocator_state.allocator() else inner_allocator;

    const result = try parseArgs(allocator);
    defer result.deinit(allocator);

    log_file, const log_file_path = createLogFile(allocator, result.log_file_path) orelse .{ null, null };
    defer if (log_file_path) |path| allocator.free(path);
    defer if (log_file) |file| {
        file.close();
        log_file = null;
    };

    var read_buffer: [256]u8 = undefined;
    var stdio_transport: zls.lsp.Transport.Stdio = .init(&read_buffer, .stdin(), .stdout());

    var thread_safe_transport: zls.lsp.ThreadSafeTransport(.{
        .thread_safe_read = false,
        .thread_safe_write = true,
    }) = .init(&stdio_transport.transport);

    const transport: *zls.lsp.Transport = &thread_safe_transport.transport;

    log_transport = if (result.disable_lsp_logs) null else transport;
    log_stderr = result.enable_stderr_logs;
    log_level = result.log_level orelse log_level;
    defer {
        log_transport = null;
        log_stderr = true;
    }

    log.info("Starting ZLS      {s} @ '{s}'", .{ zls.build_options.version_string, result.zls_exe_path });
    if (log_file_path) |path| {
        log.info("Log File:         {s} ({t})", .{ path, log_level });
    } else {
        log.info("Log File:         none", .{});
    }

    const server: *zls.Server = try .create(.{
        .allocator = allocator,
        .transport = transport,
        .config = null,
    });
    defer server.destroy();

    try loadConfiguration(allocator, server, result.config_path);

    try server.loop();

    switch (server.status) {
        .exiting_failure => return 1,
        .exiting_success => return 0,
        else => unreachable,
    }
}
