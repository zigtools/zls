const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const Server = @import("Server.zig");
const setup = @import("setup.zig");
const Header = @import("Header.zig");

const logger = std.log.scoped(.main);

// Always set this to debug to make std.log call into our handler, then control the runtime
// value in the definition below.
pub const log_level = .debug;

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @intToEnum(std.log.Level, @enumToInt(build_options.log_level)), // temporary fix to build failing on release-safe due to a Zig bug
};

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@enumToInt(level) > @enumToInt(actual_log_level)) return;

    const level_txt = comptime level.asText();

    std.debug.print("{s:<5}: ({s:^6}): ", .{ level_txt, @tagName(scope) });
    std.debug.print(format ++ "\n", args);
}

fn loop(
    server: *Server,
    record_file: ?std.fs.File,
    replay_file: ?std.fs.File,
) !void {
    const std_in = std.io.getStdIn().reader();
    const std_out = std.io.getStdOut().writer();

    var buffered_reader = std.io.bufferedReader(if (replay_file) |file| file.reader() else std_in);
    const reader = buffered_reader.reader();

    var buffered_writer = std.io.bufferedWriter(std_out);
    const writer = buffered_writer.writer();

    while (true) {
        var arena = std.heap.ArenaAllocator.init(server.allocator);
        defer arena.deinit();

        // write server -> client messages
        for (server.outgoing_messages.items) |outgoing_message| {
            const header = Header{ .content_length = outgoing_message.len };
            try header.write(true, writer);
            try writer.writeAll(outgoing_message);
        }
        try buffered_writer.flush();
        for (server.outgoing_messages.items) |outgoing_message| {
            server.allocator.free(outgoing_message);
        }
        server.outgoing_messages.clearRetainingCapacity();

        // read and handle client -> server message
        const header = try Header.parse(arena.allocator(), replay_file == null, reader);

        const json_message = try arena.allocator().alloc(u8, header.content_length);
        try reader.readNoEof(json_message);

        if (record_file) |file| {
            try header.write(false, file.writer());
            try file.writeAll(json_message);
        }

        server.processJsonRpc(&arena, json_message);
    }
}

fn getRecordFile(config: Config) ?std.fs.File {
    if (!config.record_session) return null;

    if (config.record_session_path) |record_path| {
        if (std.fs.createFileAbsolute(record_path, .{})) |file| {
            std.debug.print("recording to {s}\n", .{record_path});
            return file;
        } else |err| {
            std.log.err("failed to create record file at {s}: {}", .{ record_path, err });
            return null;
        }
    } else {
        std.log.err("`record_session` is set but `record_session_path` is unspecified", .{});
        return null;
    }
}

fn getReplayFile(config: Config) ?std.fs.File {
    const replay_path = config.replay_session_path orelse config.record_session_path orelse return null;

    if (std.fs.openFileAbsolute(replay_path, .{})) |file| {
        std.debug.print("replaying from {s}\n", .{replay_path});
        return file;
    } else |err| {
        std.log.err("failed to open replay file at {s}: {}", .{ replay_path, err });
        return null;
    }
}

/// when recording we add a message that saves the current configuration in the replay
/// when replaying we read this message and replace the current config
fn updateConfig(
    allocator: std.mem.Allocator,
    config: *Config,
    record_file: ?std.fs.File,
    replay_file: ?std.fs.File,
) !void {
    if (record_file) |file| {
        var cfg = config.*;
        cfg.record_session = false;
        cfg.record_session_path = null;
        cfg.replay_session_path = null;

        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);

        try std.json.stringify(cfg, .{}, buffer.writer(allocator));
        const header = Header{ .content_length = buffer.items.len };
        try header.write(false, file.writer());
        try file.writeAll(buffer.items);
    }

    if (replay_file) |file| {
        const header = try Header.parse(allocator, false, file.reader());
        defer header.deinit(allocator);
        const json_message = try allocator.alloc(u8, header.content_length);
        defer allocator.free(json_message);
        try file.reader().readNoEof(json_message);

        var token_stream = std.json.TokenStream.init(json_message);
        const new_config = try std.json.parse(Config, &token_stream, .{ .allocator = allocator });
        std.json.parseFree(Config, config.*, .{ .allocator = allocator });
        config.* = new_config;
    }
}

const ConfigWithPath = struct {
    config: Config,
    config_path: ?[]const u8,
};

fn getConfig(
    allocator: std.mem.Allocator,
    config_path: ?[]const u8,
) !ConfigWithPath {
    if (config_path) |path| {
        if (configuration.loadFromFile(allocator, path)) |config| {
            return ConfigWithPath{ .config = config, .config_path = path };
        }
        std.debug.print(
            \\Could not open configuration file '{s}'
            \\Falling back to a lookup in the local and global configuration folders
            \\
        , .{path});
    }

    if (try known_folders.getPath(allocator, .local_configuration)) |path| {
        if (configuration.loadFromFolder(allocator, path)) |config| {
            return ConfigWithPath{ .config = config, .config_path = path };
        }
        allocator.free(path);
    }

    if (try known_folders.getPath(allocator, .global_configuration)) |path| {
        if (configuration.loadFromFolder(allocator, path)) |config| {
            return ConfigWithPath{ .config = config, .config_path = path };
        }
        allocator.free(path);
    }

    return ConfigWithPath{
        .config = Config{},
        .config_path = null,
    };
}

const ParseArgsResult = struct {
    action: enum { proceed, exit },
    config_path: ?[]const u8,
    replay_enabled: bool,
    replay_session_path: ?[]const u8,
};

fn parseArgs(allocator: std.mem.Allocator) !ParseArgsResult {
    var result = ParseArgsResult{
        .action = .exit,
        .config_path = null,
        .replay_enabled = false,
        .replay_session_path = null,
    };

    const ArgId = enum {
        help,
        version,
        config,
        replay,
        @"enable-debug-log",
        @"show-config-path",
        @"config-path",
    };
    const arg_id_map = std.ComptimeStringMap(ArgId, comptime blk: {
        const fields = @typeInfo(ArgId).Enum.fields;
        const KV = struct { []const u8, ArgId };
        var pairs: [fields.len]KV = undefined;
        for (pairs) |*pair, i| pair.* = .{ fields[i].name, @intToEnum(ArgId, fields[i].value) };
        break :blk pairs[0..];
    });
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
            .version = "Prints the compiler version with which the server was compiled.",
            .config = "Run the ZLS configuration wizard.",
            .replay = "Replay a previous recorded zls session",
            .@"enable-debug-log" = "Enables debug logs.",
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
    if (!args_it.skip()) @panic("Could not find self argument");

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
        const id = arg_id_map.get(argname) orelse {
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
            .help, .version, .@"enable-debug-log", .config, .@"show-config-path" => {},
            .@"config-path" => {
                const path = args_it.next() orelse {
                    try stderr.print("Expected configuration file path after --config-path argument.\n", .{});
                    return result;
                };
                result.config_path = try allocator.dupe(u8, path);
            },
            .replay => {
                result.replay_enabled = true;
                const path = args_it.next() orelse break;
                result.replay_session_path = try allocator.dupe(u8, path);
            },
        }
    }

    if (specified.get(.help)) {
        try stderr.print("{s}\n", .{help_message});
        return result;
    }
    if (specified.get(.version)) {
        try stdout.writeAll(build_options.version ++ "\n");
        return result;
    }
    if (specified.get(.config)) {
        try setup.wizard(allocator);
        return result;
    }
    if (specified.get(.@"enable-debug-log")) {
        actual_log_level = .debug;
        logger.info("Enabled debug logging.\n", .{});
    }
    if (specified.get(.@"config-path")) {
        std.debug.assert(result.config_path != null);
    }
    if (specified.get(.@"show-config-path")) {
        const new_config = try getConfig(allocator, result.config_path);
        defer if (new_config.config_path) |path| allocator.free(path);
        defer std.json.parseFree(Config, new_config.config, .{ .allocator = allocator });

        if (new_config.config_path) |path| {
            const full_path = try std.fs.path.resolve(allocator, &.{ path, "zls.json" });
            defer allocator.free(full_path);

            try stdout.writeAll(full_path);
            try stdout.writeByte('\n');
        } else {
            logger.err("Failed to find zls.json!\n", .{});
        }
        return result;
    }

    result.action = .proceed;
    return result;
}

const stack_frames = switch (zig_builtin.mode) {
    .Debug => 10,
    else => 0,
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){};
    defer _ = gpa_state.deinit();
    var tracy_state = if (tracy.enable_allocation) tracy.tracyAllocator(gpa_state.allocator()) else void{};

    const allocator: std.mem.Allocator = if (tracy.enable_allocation) tracy_state.allocator() else gpa_state.allocator();

    const result = try parseArgs(allocator);
    defer if (result.config_path) |path| allocator.free(path);
    defer if (result.replay_session_path) |path| allocator.free(path);
    switch (result.action) {
        .proceed => {},
        .exit => return,
    }

    var config = try getConfig(allocator, result.config_path);
    defer std.json.parseFree(Config, config.config, .{ .allocator = allocator });
    defer if (config.config_path) |path| allocator.free(path);

    if (result.replay_enabled and config.config.replay_session_path == null and config.config.record_session_path == null) {
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

    std.debug.assert(record_file == null or replay_file == null);

    try updateConfig(allocator, &config.config, record_file, replay_file);

    var server = try Server.init(
        allocator,
        &config.config,
        config.config_path,
        record_file != null,
        replay_file != null,
    );
    defer server.deinit();

    try loop(&server, record_file, replay_file);
}
