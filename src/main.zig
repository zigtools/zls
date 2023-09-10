const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const Server = @import("Server.zig");
const Header = @import("Header.zig");
const Transport = @import("Transport.zig");
const debug = @import("debug.zig");
const binned_allocator = @import("binned_allocator");

const logger = std.log.scoped(.zls_main);

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @enumFromInt(@intFromEnum(build_options.log_level)), // temporary fix to build failing on release-safe due to a Zig bug
};

pub const std_options = struct {
    // Always set this to debug to make std.log call into our handler, then control the runtime
    // value in the definition below.
    pub const log_level = .debug;

    pub fn logFn(
        comptime level: std.log.Level,
        comptime scope: @TypeOf(.EnumLiteral),
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(level) > @intFromEnum(actual_log_level)) return;

        const level_txt = comptime level.asText();
        const scope_txt = comptime @tagName(scope);

        const stderr = std.io.getStdErr().writer();
        std.debug.getStderrMutex().lock();
        defer std.debug.getStderrMutex().unlock();

        stderr.print("{s:<5}: ({s:^6}): ", .{ level_txt, if (comptime std.mem.startsWith(u8, scope_txt, "zls_")) scope_txt[4..] else scope_txt }) catch return;
        stderr.print(format, args) catch return;
        stderr.writeByte('\n') catch return;
    }
};

fn getRecordFile(config: Config) ?std.fs.File {
    if (!config.record_session) return null;

    if (config.record_session_path) |record_path| {
        if (std.fs.createFileAbsolute(record_path, .{})) |file| {
            logger.info("recording to {s}\n", .{record_path});
            return file;
        } else |err| {
            logger.err("failed to create record file at {s}: {}", .{ record_path, err });
            return null;
        }
    } else {
        logger.err("`record_session` is set but `record_session_path` is unspecified", .{});
        return null;
    }
}

fn getReplayFile(config: Config) ?std.fs.File {
    const replay_path = config.replay_session_path orelse config.record_session_path orelse return null;

    if (std.fs.openFileAbsolute(replay_path, .{})) |file| {
        logger.info("replaying from {s}\n", .{replay_path});
        return file;
    } else |err| {
        logger.err("failed to open replay file at {s}: {}", .{ replay_path, err });
        return null;
    }
}

/// when recording we add a message that saves the current configuration in the replay
/// when replaying we read this message and replace the current config
fn updateConfig(
    allocator: std.mem.Allocator,
    transport: *Transport,
    config: *configuration.ConfigWithPath,
    record_file: ?std.fs.File,
    replay_file: ?std.fs.File,
) !void {
    std.debug.assert(record_file == null or replay_file == null);
    if (record_file) |file| {
        var cfg = config.config;
        cfg.record_session = false;
        cfg.record_session_path = null;
        cfg.replay_session_path = null;

        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);
        try std.json.stringify(cfg, .{}, buffer.writer(allocator));

        var header = Header{ .content_length = buffer.items.len };
        try header.write(file.writer());
        try file.writeAll(buffer.items);
    }

    if (replay_file != null) {
        const json_message = try transport.readJsonMessage(allocator);
        defer allocator.free(json_message);

        const new_config = try std.json.parseFromSlice(Config, allocator, json_message, .{});
        defer allocator.destroy(new_config.arena);
        config.arena.promote(allocator).deinit();
        config.arena = new_config.arena.state;
        config.config = new_config.value;
    }
}

const ParseArgsResult = struct {
    action: enum { proceed, exit },
    config_path: ?[]const u8,
    replay_enabled: bool,
    message_tracing_enabled: bool,

    zls_exe_path: []const u8,
};

fn parseArgs(allocator: std.mem.Allocator) !ParseArgsResult {
    var result = ParseArgsResult{
        .action = .exit,
        .config_path = null,
        .replay_enabled = false,
        .message_tracing_enabled = false,
        .zls_exe_path = undefined,
    };

    const ArgId = enum {
        help,
        version,
        @"compiler-version",
        replay,
        @"enable-debug-log",
        @"enable-message-tracing",
        @"show-config-path",
        @"config-path",
    };
    const help_message: []const u8 = comptime help_message: {
        var help_message: []const u8 =
            \\Usage: zls [command]
            \\
            \\Commands:
            \\
            \\
        ;
        const InfoMap = std.enums.EnumArray(ArgId, []const u8);
        var cmd_infos: InfoMap = InfoMap.init(.{
            .help = "Prints this message.",
            .version = "Prints the version.",
            .@"compiler-version" = "Prints the compiler version with which the server was compiled.",
            .replay = "Replay a previous recorded zls session",
            .@"enable-debug-log" = "Enables debug logs.",
            .@"enable-message-tracing" = "Enables message tracing.",
            .@"config-path" = "Specify the path to a configuration file specifying LSP behaviour.",
            .@"show-config-path" = "Prints the path to the configuration file to stdout",
        });
        var info_it = cmd_infos.iterator();
        while (info_it.next()) |entry| {
            help_message = help_message ++ std.fmt.comptimePrint("  --{s}: {s}\n", .{ @tagName(entry.key), entry.value.* });
        }
        help_message = help_message ++ "\n";
        break :help_message help_message;
    };

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();

    const zls_exe_path = args_it.next() orelse @panic("");
    result.zls_exe_path = try allocator.dupe(u8, zls_exe_path);

    // Makes behavior of enabling debug more logging consistent regardless of argument order.
    var specified = std.enums.EnumArray(ArgId, bool).initFill(false);
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    while (args_it.next()) |tok| {
        if (!std.mem.startsWith(u8, tok, "--") or tok.len == 2) {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Unexpected positional argument '{s}'.\n", .{tok});
            return result;
        }

        const argname = tok["--".len..];
        const id = std.meta.stringToEnum(ArgId, argname) orelse {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Unrecognized argument '{s}'.\n", .{argname});
            return result;
        };

        if (specified.get(id)) {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Duplicate argument '{s}'.\n", .{argname});
            return result;
        }
        specified.set(id, true);

        switch (id) {
            .help,
            .version,
            .@"compiler-version",
            .@"enable-debug-log",
            .@"enable-message-tracing",
            .@"show-config-path",
            => {},
            .@"config-path" => {
                const path = args_it.next() orelse {
                    try stderr.print("Expected configuration file path after --config-path argument.\n", .{});
                    return result;
                };
                result.config_path = try allocator.dupe(u8, path);
            },
            .replay => {
                result.replay_enabled = true;
            },
        }
    }

    if (specified.get(.help)) {
        try stderr.print("{s}\n", .{help_message});
        return result;
    }
    if (specified.get(.version)) {
        try stdout.writeAll(build_options.version_string ++ "\n");
        return result;
    }
    if (specified.get(.@"compiler-version")) {
        try stdout.writeAll(zig_builtin.zig_version_string ++ "\n");
        return result;
    }
    if (specified.get(.@"enable-debug-log")) {
        actual_log_level = .debug;
        logger.info("Enabled debug logging.", .{});
    }
    if (specified.get(.@"enable-message-tracing")) {
        result.message_tracing_enabled = true;
        logger.info("Enabled message tracing.\n", .{});
    }
    if (specified.get(.@"config-path")) {
        std.debug.assert(result.config_path != null);
    }
    if (specified.get(.@"show-config-path")) {
        var new_config = try configuration.getConfig(allocator, result.config_path);
        defer new_config.deinit(allocator);

        if (new_config.config_path) |path| {
            try stdout.writeAll(path);
            try stdout.writeByte('\n');
            return result;
        } else {
            const local_config_path = try known_folders.getPath(allocator, .local_configuration) orelse {
                logger.err("failed to find local configuration folder", .{});
                return result;
            };
            defer allocator.free(local_config_path);
            const full_path = try std.fs.path.join(allocator, &.{ local_config_path, "zls.json" });
            defer allocator.free(full_path);
            try stdout.writeAll(full_path);
            try stdout.writeByte('\n');
            return result;
        }
    }

    result.action = .proceed;
    return result;
}

const stack_frames = switch (zig_builtin.mode) {
    .Debug => 10,
    else => 0,
};

pub fn main() !void {
    var allocator_state = if (build_options.use_gpa)
        std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){}
    else
        binned_allocator.BinnedAllocator(.{}){};

    defer {
        if (build_options.use_gpa)
            std.debug.assert(allocator_state.deinit() == .ok)
        else
            allocator_state.deinit();
    }

    var tracy_state = if (tracy.enable_allocation) tracy.tracyAllocator(allocator_state.allocator()) else void{};
    const inner_allocator: std.mem.Allocator = if (tracy.enable_allocation) tracy_state.allocator() else allocator_state.allocator();

    var failing_allocator_state = if (build_options.enable_failing_allocator) debug.FailingAllocator.init(inner_allocator, build_options.enable_failing_allocator_likelihood) else void{};
    const allocator: std.mem.Allocator = if (build_options.enable_failing_allocator) failing_allocator_state.allocator() else inner_allocator;

    const result = try parseArgs(allocator);
    defer allocator.free(result.zls_exe_path);
    defer if (result.config_path) |path| allocator.free(path);
    switch (result.action) {
        .proceed => {},
        .exit => return,
    }

    logger.info("Starting ZLS {s} @ '{s}'", .{ build_options.version_string, result.zls_exe_path });

    var config = try configuration.getConfig(allocator, result.config_path);
    defer config.deinit(allocator);

    if (result.replay_enabled and config.config.record_session_path == null) {
        logger.err("No replay file specified", .{});
        return;
    }

    if (config.config_path == null) {
        logger.info("No config file zls.json found.", .{});
    }

    const record_file = if (!result.replay_enabled) getRecordFile(config.config) else null;
    defer if (record_file) |file| file.close();

    const replay_file = if (result.replay_enabled) getReplayFile(config.config) else null;
    defer if (replay_file) |file| file.close();

    var transport = Transport.init(
        if (replay_file) |file| file.reader() else std.io.getStdIn().reader(),
        std.io.getStdOut().writer(),
    );
    transport.message_tracing = result.message_tracing_enabled;
    if (record_file) |file| transport.record_file = file.writer();

    try updateConfig(allocator, &transport, &config, record_file, replay_file);

    const server = try Server.create(allocator);
    defer server.destroy();
    try server.updateConfiguration2(config.config);
    server.recording_enabled = record_file != null;
    server.replay_enabled = replay_file != null;
    server.transport = &transport;

    try server.loop();

    if (server.status == .exiting_failure) {
        if (zig_builtin.mode == .Debug) {
            // make sure that GeneralPurposeAllocator.deinit gets run to detect leaks
            return;
        } else {
            std.process.exit(1);
        }
    }
}
