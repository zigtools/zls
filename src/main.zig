const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");
const tres = @import("tres");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const Server = @import("Server.zig");
const Header = @import("Header.zig");
const debug = @import("debug.zig");

const protobuf = @import("protobuf");
const common = @import("otel/common/v1/common.pb.zig");
const collector = @import("otel/collector/trace/v1/trace_service.pb.zig");
const resource = @import("otel/resource/v1/resource.pb.zig");
const trace = @import("otel/trace/v1/trace.pb.zig");

const otel_schema_url = "https://opentelemetry.io/schemas/1.19.0";

const logger = std.log.scoped(.zls_main);
const message_logger = std.log.scoped(.message);

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @intToEnum(std.log.Level, @enumToInt(build_options.log_level)), // temporary fix to build failing on release-safe due to a Zig bug
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
        if (@enumToInt(level) > @enumToInt(actual_log_level)) return;

        const level_txt = comptime level.asText();
        const scope_txt = comptime @tagName(scope);

        std.debug.print("{s:<5}: ({s:^6}): ", .{ level_txt, if (comptime std.mem.startsWith(u8, scope_txt, "zls_")) scope_txt[4..] else scope_txt });
        std.debug.print(format ++ "\n", args);
    }
};

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
        defer server.maybeFreeArena();

        // write server -> client messages
        for (server.outgoing_messages.items) |outgoing_message| {
            const header = Header{ .content_length = outgoing_message.len };
            try header.write(true, writer);
            try writer.writeAll(outgoing_message);
            if (server.message_tracing_enabled) message_logger.info("sent: {s}\n", .{outgoing_message});
        }
        try buffered_writer.flush();
        for (server.outgoing_messages.items) |outgoing_message| {
            server.allocator.free(outgoing_message);
        }
        server.outgoing_messages.clearRetainingCapacity();

        // read and handle client -> server message
        const header = try Header.parse(server.arena.allocator(), replay_file == null, reader);

        const json_message = try server.arena.allocator().alloc(u8, header.content_length);
        try reader.readNoEof(json_message);

        if (record_file) |file| {
            try header.write(false, file.writer());
            try file.writeAll(json_message);
        }

        if (server.message_tracing_enabled) message_logger.info("received: {s}\n", .{json_message});
        server.processJsonRpc(json_message);

        if (server.status == .exiting_success or server.status == .exiting_failure) return;
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

        try tres.stringify(cfg, .{}, buffer.writer(allocator));
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
            return ConfigWithPath{ .config = config, .config_path = try allocator.dupe(u8, path) };
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
    message_tracing_enabled: bool,

    zls_exe_path: []const u8,
};

fn parseArgs(allocator: std.mem.Allocator) !ParseArgsResult {
    var result = ParseArgsResult{
        .action = .exit,
        .config_path = null,
        .replay_enabled = false,
        .replay_session_path = null,
        .message_tracing_enabled = false,
        .zls_exe_path = undefined,
    };

    const ArgId = enum {
        help,
        version,
        replay,
        @"enable-debug-log",
        @"enable-message-tracing",
        @"show-config-path",
        @"config-path",
    };
    const arg_id_map = std.ComptimeStringMap(ArgId, comptime blk: {
        const fields = @typeInfo(ArgId).Enum.fields;
        const KV = struct { []const u8, ArgId };
        var pairs: [fields.len]KV = undefined;
        for (&pairs, fields) |*pair, field| {
            pair.* = .{ field.name, @intToEnum(ArgId, field.value) };
        }
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

    if (args_it.next()) |zls_path| {
        result.zls_exe_path = try allocator.dupe(u8, zls_path);
    } else unreachable;

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
            .help,
            .version,
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
    if (specified.get(.@"enable-debug-log")) {
        actual_log_level = .debug;
        logger.info("Enabled debug logging.\n", .{});
    }
    if (specified.get(.@"enable-message-tracing")) {
        result.message_tracing_enabled = true;
        logger.info("Enabled message tracing.\n", .{});
    }
    if (specified.get(.@"config-path")) {
        std.debug.assert(result.config_path != null);
    }
    if (specified.get(.@"show-config-path")) {
        const new_config = try getConfig(allocator, result.config_path);
        defer if (new_config.config_path) |path| allocator.free(path);
        defer std.json.parseFree(Config, new_config.config, .{ .allocator = allocator });

        const full_path = if (new_config.config_path) |path| blk: {
            break :blk try std.fs.path.resolve(allocator, &.{ path, "zls.json" });
        } else blk: {
            const local_config_path = try known_folders.getPath(allocator, .local_configuration) orelse {
                logger.err("failed to find local configuration folder", .{});
                return result;
            };
            defer allocator.free(local_config_path);
            break :blk try std.fs.path.resolve(allocator, &.{ local_config_path, "zls.json" });
        };
        defer allocator.free(full_path);
        try stdout.writeAll(full_path);
        try stdout.writeByte('\n');
        return result;
    }

    result.action = .proceed;
    return result;
}

const stack_frames = switch (zig_builtin.mode) {
    .Debug => 10,
    else => 0,
};

fn pbInit(comptime T: type, values: anytype) T {
    var inited = T.init();

    inline for (@typeInfo(@TypeOf(values)).Struct.fields) |field| {
        inited.set(@field(protobuf.types.FieldEnum(T), field.name), @field(values, field.name));
    }

    return inited;
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){};
    defer std.debug.assert(gpa_state.deinit() == .ok);

    var tracy_state = if (tracy.enable_allocation) tracy.tracyAllocator(gpa_state.allocator()) else void{};
    const inner_allocator: std.mem.Allocator = if (tracy.enable_allocation) tracy_state.allocator() else gpa_state.allocator();

    var failing_allocator_state = if (build_options.enable_failing_allocator) debug.FailingAllocator.init(inner_allocator, build_options.enable_failing_allocator_likelihood) else void{};
    const allocator: std.mem.Allocator = if (build_options.enable_failing_allocator) failing_allocator_state.allocator() else inner_allocator;

    const result = try parseArgs(allocator);
    defer allocator.free(result.zls_exe_path);
    defer if (result.config_path) |path| allocator.free(path);
    defer if (result.replay_session_path) |path| allocator.free(path);
    switch (result.action) {
        .proceed => {},
        .exit => return,
    }

    logger.info("Starting ZLS {s} @ '{s}'", .{ build_options.version, result.zls_exe_path });

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

    const server = try Server.create(
        allocator,
        &config.config,
        config.config_path,
        record_file != null,
        replay_file != null,
        result.message_tracing_enabled,
    );
    defer server.destroy();

    var pb_arena = std.heap.ArenaAllocator.init(allocator);
    defer pb_arena.deinit();
    var pb_allocator = pb_arena.allocator();

    var req = pbInit(collector.ExportTraceServiceRequest, .{
        .resource_spans = .{},
    });

    var ress = pbInit(resource.Resource, .{
        .attributes = .{},
        .dropped_attributes_count = 0,
    });

    var val = pbInit(common.AnyValue, .{
        .value__string_value = protobuf.extern_types.String.init("VSCode"),
    });

    var val2 = pbInit(common.AnyValue, .{
        .value__string_value = protobuf.extern_types.String.init("zls"),
    });

    var kv1 = pbInit(common.KeyValue, .{
        .key = protobuf.extern_types.String.init("editor"),
        .value = &val,
    });
    var kv2 = pbInit(common.KeyValue, .{
        .key = protobuf.extern_types.String.init("service.name"),
        .value = &val2,
    });
    try ress.attributes.appendSlice(pb_allocator, &.{ &kv1, &kv2 });

    var scope = pbInit(common.InstrumentationScope, .{
        .name = protobuf.extern_types.String.init("otel-zig"),
        .version = protobuf.extern_types.String.init("0.0.1"),
        .attributes = .{},
        .dropped_attributes_count = 0,
    });

    var status = pbInit(trace.Status, .{
        .message = protobuf.extern_types.String.init("lets' goo!!!"),
        .code = .STATUS_CODE_OK,
    });

    var span = pbInit(trace.Span, .{
        .trace_id = protobuf.extern_types.String.init("abcdefghabcdefgh"),
        .span_id = protobuf.extern_types.String.init("zyxwzyxw"),
        .trace_state = protobuf.extern_types.String.empty,
        .parent_span_id = protobuf.extern_types.String.empty,
        .name = protobuf.extern_types.String.init("HELLO"),
        .kind = .SPAN_KIND_SERVER,
        .start_time_unix_nano = @intCast(u64, std.time.nanoTimestamp()),
        .end_time_unix_nano = @intCast(u64, std.time.nanoTimestamp()),
        .attributes = .{},
        .dropped_attributes_count = 0,
        .events = .{},
        .dropped_events_count = 0,
        .links = .{},
        .dropped_links_count = 0,
        .status = &status,
    });

    var spans = protobuf.extern_types.ArrayListMut(*trace.Span){};
    try spans.append(pb_allocator, &span);

    var scope_spans = protobuf.extern_types.ArrayListMut(*trace.ScopeSpans){};

    var scope_span = pbInit(trace.ScopeSpans, .{
        .scope = &scope,
        .spans = spans,
        .schema_url = protobuf.extern_types.String.init(otel_schema_url),
    });

    try scope_spans.append(pb_allocator, &scope_span);

    var resource_spans = pbInit(trace.ResourceSpans, .{
        .resource = &ress,
        .scope_spans = scope_spans,
        .schema_url = protobuf.extern_types.String.init(otel_schema_url),
    });

    try req.resource_spans.append(pb_allocator, &resource_spans);

    var http_client: std.http.Client = .{ .allocator = pb_allocator };
    defer http_client.deinit();

    var h = std.http.Headers{ .allocator = pb_allocator };
    try h.append("Content-Type", "application/x-protobuf");
    defer h.deinit();

    try protobuf.json.serialize(&req.base, std.io.getStdOut().writer(), .{ .pretty_print = .{} });

    var http_req = try http_client.request(.POST, try std.Uri.parse("https://telemetry.zigtools.org:4318/v1/traces"), h, .{});
    // var http_req = try http_client.request(.POST, try std.Uri.parse("https://httpdump.app/dumps/29afed7c-6b9a-42ee-9950-850ee2c04d63"), h, .{});
    defer http_req.deinit();

    http_req.transfer_encoding = .chunked;

    try http_req.start();
    var bufw = std.io.bufferedWriter(http_req.writer());
    try protobuf.protobuf.serialize(&req.base, bufw.writer());
    try bufw.flush();
    try http_req.finish();

    try http_req.wait();

    std.log.info("{any}", .{http_req.response});

    var buf: [1024]u8 = undefined;
    var len = try http_req.reader().read(&buf);
    std.log.info("body: {s}", .{buf[0..len]});

    std.log.info("DONE!", .{});

    try loop(server, record_file, replay_file);

    if (server.status == .exiting_failure) {
        std.process.exit(1);
    }
}
