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

        var writer = std.io.getStdOut().writer();

        try server.processJsonRpc(writer, buffer);
    }
}

const ConfigWithPath = struct {
    config: Config,
    config_path: ?[]const u8,
};

fn getConfig(allocator: std.mem.Allocator, config: ConfigWithPath) !ConfigWithPath {
    if (config.config_path) |path| {
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
    }

    if (try known_folders.getPath(allocator, .local_configuration)) |path| {
        if (Config.loadFromFolder(allocator, path)) |conf| {
            return ConfigWithPath{
                .config = conf,
                .config_path = path,
            };
        }
    }

    if (try known_folders.getPath(allocator, .global_configuration)) |path| {
        if (Config.loadFromFolder(allocator, path)) |conf| {
            return ConfigWithPath{
                .config = conf,
                .config_path = path,
            };
        }
    }

    return ConfigWithPath{
        .config = Config{},
        .config_path = null,
    };
}

const stack_frames = switch (zig_builtin.mode) {
    .Debug => 10,
    else => 0,
};

pub fn main() anyerror!void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){};
    defer _ = gpa_state.deinit();

    var allocator = gpa_state.allocator();
    if (tracy.enable_allocation) {
        allocator = tracy.tracyAllocator(allocator).allocator();
    }

    var config = ConfigWithPath{
        .config = undefined,
        .config_path = null,
    };
    defer if (config.config_path) |path| allocator.free(path);

    // Check arguments.
    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    if (!args_it.skip()) @panic("Could not find self argument");

    while (args_it.next()) |arg| {
        // TODO add --help --version
        if (std.mem.eql(u8, arg, "--debug-log")) {
            actual_log_level = .debug;
            std.debug.print("Enabled debug logging\n", .{});
        } else if (std.mem.eql(u8, arg, "--config-path")) {
            var path = args_it.next() orelse {
                std.debug.print("Expected configuration file path after --config-path argument\n", .{});
                std.os.exit(1);
            };
            config.config_path = try allocator.dupe(u8, path);
        } else if (std.mem.eql(u8, arg, "config") or std.mem.eql(u8, arg, "configure")) {
            try setup.wizard(allocator);
            return;
        } else {
            std.debug.print("Unrecognized argument {s}\n", .{arg});
            std.os.exit(1);
        }
    }

    config = try getConfig(allocator, config);
    if (config.config_path == null) {
        logger.info("No config file zls.json found.", .{});
    }

    var server = try Server.init(
        allocator,
        config.config,
        config.config_path,
        actual_log_level,
    );
    defer server.deinit();

    try loop(&server);
}
