const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const tracy = @import("tracy.zig");
const known_folders = @import("known-folders");
const Config = @import("Config.zig");
const Server = @import("Server.zig");
const setup = @import("setup.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;

const logger = std.log.scoped(.main);

// Always set this to debug to make std.log call into our handler, then control the runtime
// value in the definition below.
pub const log_level = .debug;

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @intToEnum(std.log.Level, @enumToInt(build_options.log_level)), // temporary fix to build failing on release-safe due to a Zig bug
};

fn loop(server: *Server) !void {
    var reader = std.io.getStdIn().reader();

    while (server.keep_running) {
        const headers = readRequestHeader(server.allocator, reader) catch |err| {
            logger.err("{s}; exiting!", .{@errorName(err)});
            return;
        };
        const buffer = try server.allocator.alloc(u8, headers.content_length);
        defer server.allocator.free(buffer);

        try reader.readNoEof(buffer);

        const writer = std.io.getStdOut().writer();
        try server.processJsonRpc(writer, buffer);
    }
}

const ConfigWithPath = struct {
    config: Config,
    config_path: ?[]const u8,
};

fn getConfig(
    allocator: std.mem.Allocator,
    config_path: ?[]const u8,
    /// If true, and the provided config_path is non-null, frees
    /// the aforementioned path, in the case that it is
    /// not returned.
    free_old_config_path: bool,
) !ConfigWithPath {
    if (config_path) |path| {
        if (Config.loadFromFile(allocator, path)) |conf| {
            return ConfigWithPath{
                .config = conf,
                .config_path = path,
            };
        }
        std.debug.print(
            \\Could not open configuration file '{s}'
            \\Falling back to a lookup in the local and global configuration folders
            \\
        , .{path});
        if (free_old_config_path) {
            allocator.free(path);
        }
    }

    if (try known_folders.getPath(allocator, .local_configuration)) |path| {
        if (Config.loadFromFolder(allocator, path)) |conf| {
            return ConfigWithPath{
                .config = conf,
                .config_path = path,
            };
        }
        allocator.free(path);
    }

    if (try known_folders.getPath(allocator, .global_configuration)) |path| {
        if (Config.loadFromFolder(allocator, path)) |conf| {
            return ConfigWithPath{
                .config = conf,
                .config_path = path,
            };
        }
        allocator.free(path);
    }

    return ConfigWithPath{
        .config = Config{},
        .config_path = null,
    };
}

const ParseArgsResult = enum { proceed, exit };
fn parseArgs(
    allocator: std.mem.Allocator,
    out: struct {
        /// must start off pointing at a sring of length 0.
        /// must be freed by the caller.
        /// ```
        /// var config_path: []const u8 = "";
        /// defer allocator.free(config_path);
        /// switch (try parseArgs(allocator, .{ .config_path = &config_path })) {
        ///     .exit => return,
        ///     .proceed => {},
        /// }
        /// ```
        ///
        config_path: *[]const u8,
    },
) !ParseArgsResult {
    std.debug.assert(out.config_path.len == 0);
    const ArgId = enum {
        help,
        version,
        config,
        @"enable-debug-log",
        @"config-path",
    };
    const arg_id_map = std.ComptimeStringMap(ArgId, comptime blk: {
        const fields = @typeInfo(ArgId).Enum.fields;
        const KV = std.meta.Tuple(&.{ []const u8, ArgId });
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
            .@"enable-debug-log" = "Enables debug logs.",
            .@"config-path" = "Specify the path to a configuration file specifying LSP behaviour.",
            .config = "Run the ZLS configuration wizard.",
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

    // Use stderr during CLI interaction, so that messages aren't filtered by log level
    const stderr = std.io.getStdErr().writer();

    while (args_it.next()) |tok| {
        if (!std.mem.startsWith(u8, tok, "--") or tok.len == 2) {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Unexpected positional argument '{s}'.\n", .{tok});
            return .exit;
        }

        const argname = tok["--".len..];
        const id = arg_id_map.get(argname) orelse {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Unrecognized argument '{s}'.\n", .{argname});
            return .exit;
        };

        if (specified.get(id)) {
            try stderr.print("{s}\n", .{help_message});
            try stderr.print("Duplicate argument '{s}'.\n", .{argname});
            return .exit;
        }
        specified.set(id, true);

        switch (id) {
            .help => {},
            .version => {},
            .@"enable-debug-log" => {},
            .config => {},
            .@"config-path" => {
                const path = args_it.next() orelse {
                    try stderr.print("Expected configuration file path after --config-path argument.\n", .{});
                    return .exit;
                };
                std.debug.assert(out.config_path.len == 0);
                out.config_path.* = try allocator.dupe(u8, path);
            },
        }
    }

    if (specified.get(.help)) {
        try stderr.print("{s}\n", .{help_message});
        return .exit;
    }
    if (specified.get(.version)) {
        try std.io.getStdOut().writer().print("Data Version: {s}\n", .{@tagName(build_options.data_version)});
        return .exit;
    }
    if (specified.get(.config)) {
        try setup.wizard(allocator);
        return .exit;
    }
    if (specified.get(.@"enable-debug-log")) {
        actual_log_level = .debug;
        logger.info("Enabled debug logging.\n", .{});
    }
    if (specified.get(.@"config-path")) {
        std.debug.assert(out.config_path.len != 0);
    }

    return .proceed;
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

    var server: Server = blk: {
        var config_path: []const u8 = "";
        defer allocator.free(config_path);

        switch (try parseArgs(allocator, .{ .config_path = &config_path })) {
            .proceed => {},
            .exit => return,
        }

        const config = try getConfig(allocator, config_path, false);
        errdefer config.config.deinit(allocator);
        defer allocator.free(config.config_path orelse "");

        if (config.config_path == null) {
            logger.info("No config file zls.json found.", .{});
        }

        break :blk try Server.init(
            allocator,
            config.config,
            config.config_path,
            actual_log_level,
        );
    };
    defer server.deinit();

    try loop(&server);
}
