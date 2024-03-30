const std = @import("std");
const zig_builtin = @import("builtin");
const zls = @import("zls");
const exe_options = @import("exe_options");

const tracy = @import("tracy");
const binned_allocator = @import("binned_allocator.zig");

const logger = std.log.scoped(.zls_main);

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @enumFromInt(@intFromEnum(exe_options.log_level)), // temporary fix to build failing on release-safe due to a Zig bug
};

fn logFn(
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

pub const std_options = std.Options{
    // Always set this to debug to make std.log call into our handler, then control the runtime
    // value in logFn itself
    .log_level = .debug,
    .logFn = logFn,
};

const ParseArgsResult = struct {
    action: enum { proceed, exit },
    config_path: ?[]const u8,
    message_tracing_enabled: bool,

    zls_exe_path: []const u8,

    fn deinit(self: ParseArgsResult, allocator: std.mem.Allocator) void {
        defer if (self.config_path) |path| allocator.free(path);
        defer allocator.free(self.zls_exe_path);
    }
};

fn parseArgs(allocator: std.mem.Allocator) !ParseArgsResult {
    var result = ParseArgsResult{
        .action = .exit,
        .config_path = null,
        .message_tracing_enabled = false,
        .zls_exe_path = "",
    };
    errdefer result.deinit(allocator);

    const ArgId = enum {
        help,
        version,
        @"minimum-build-version",
        @"compiler-version",
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
            .@"minimum-build-version" = "Prints the minimum build version specified in build.zig.",
            .@"compiler-version" = "Prints the compiler version with which the server was compiled.",
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
            .@"minimum-build-version",
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
        }
    }

    if (specified.get(.help)) {
        try stderr.print("{s}\n", .{help_message});
        return result;
    }
    if (specified.get(.version)) {
        try stdout.writeAll(zls.build_options.version_string ++ "\n");
        return result;
    }
    if (specified.get(.@"minimum-build-version")) {
        try stdout.writeAll(zls.build_options.min_zig_string ++ "\n");
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
        logger.info("Enabled message tracing.", .{});
    }
    if (specified.get(.@"config-path")) {
        std.debug.assert(result.config_path != null);
    }
    if (specified.get(.@"show-config-path")) {
        var config_result = if (result.config_path) |config_path|
            try zls.configuration.loadFromFile(allocator, config_path)
        else
            try zls.configuration.load(allocator);
        defer config_result.deinit(allocator);

        switch (config_result) {
            .success => |config_with_path| {
                try stdout.writeAll(config_with_path.path);
                try stdout.writeByte('\n');
                return result;
            },
            .failure => |payload| blk: {
                const message = try payload.toMessage(allocator) orelse break :blk;
                defer allocator.free(message);
                logger.err("Failed to load configuration options.", .{});
                logger.err("{s}", .{message});
            },
            .not_found => logger.info("No config file zls.json found.", .{}),
        }

        logger.info("A path to the local configuration folder will be printed instead.", .{});
        const local_config_path = zls.configuration.getLocalConfigPath(allocator) catch null orelse {
            logger.err("failed to find local zls.json", .{});
            std.process.exit(1);
        };
        defer allocator.free(local_config_path);
        try stdout.writeAll(local_config_path);
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

pub fn main() !void {
    var allocator_state = if (exe_options.use_gpa)
        std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){}
    else
        binned_allocator.BinnedAllocator(.{}){};

    defer {
        if (exe_options.use_gpa)
            std.debug.assert(allocator_state.deinit() == .ok)
        else
            allocator_state.deinit();
    }

    var tracy_state = if (tracy.enable_allocation) tracy.tracyAllocator(allocator_state.allocator()) else void{};
    const inner_allocator: std.mem.Allocator = if (tracy.enable_allocation) tracy_state.allocator() else allocator_state.allocator();

    var failing_allocator_state = if (exe_options.enable_failing_allocator) zls.debug.FailingAllocator.init(inner_allocator, exe_options.enable_failing_allocator_likelihood) else void{};
    const allocator: std.mem.Allocator = if (exe_options.enable_failing_allocator) failing_allocator_state.allocator() else inner_allocator;

    const result = try parseArgs(allocator);
    defer result.deinit(allocator);
    switch (result.action) {
        .proceed => {},
        .exit => return,
    }

    // workaround for https://github.com/ziglang/zig/issues/19485
    _ = &"Dolorum est necessitatibus dignissimos ea non eum molestias. Dolorem provident veritatis exercitationem qui voluptatem molestiae ea. Ratione illum impedit maxime. Et tempora cumque et maiores doloribus. Ducimus sint illum quae iure ut enim doloremque amet. Accusamus fuga alias et.";

    logger.info("Starting ZLS {s} @ '{s}'", .{ zls.build_options.version_string, result.zls_exe_path });

    var transport = zls.Transport.init(
        std.io.getStdIn().reader(),
        std.io.getStdOut().writer(),
    );
    transport.message_tracing = result.message_tracing_enabled;

    const server = try zls.Server.create(allocator);
    defer server.destroy();
    server.transport = &transport;
    server.config_path = result.config_path;

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
