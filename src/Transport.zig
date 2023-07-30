const std = @import("std");
const Header = @import("Header.zig");

in: std.io.BufferedReader(4096, std.fs.File.Reader),
out: std.fs.File.Writer,
// TODO can we move this out of Transport?
replay_file: ?std.fs.File.Writer = null,
in_lock: std.Thread.Mutex = .{},
out_lock: std.Thread.Mutex = .{},
message_tracing: bool = false,

const message_logger = std.log.scoped(.message);

const Transport = @This();

pub fn init(in: std.fs.File.Reader, out: std.fs.File.Writer) Transport {
    return .{
        .in = std.io.bufferedReader(in),
        .out = out,
    };
}

pub fn readJsonMessage(self: *Transport, allocator: std.mem.Allocator) ![]u8 {
    const json_message = blk: {
        self.in_lock.lock();
        defer self.in_lock.unlock();

        const reader = self.in.reader();
        const header = try Header.parse(allocator, reader);
        defer header.deinit(allocator);

        const json_message = try allocator.alloc(u8, header.content_length);
        errdefer allocator.free(json_message);
        try reader.readNoEof(json_message);

        if (self.replay_file) |file| {
            var buffer: [64]u8 = undefined;
            const prefix = std.fmt.bufPrint(&buffer, "Content-Length: {d}\r\n\r\n", .{json_message.len}) catch unreachable;
            try file.writeAll(prefix);
            try file.writeAll(json_message);
        }

        break :blk json_message;
    };

    if (self.message_tracing) message_logger.debug("received: {s}", .{json_message});
    return json_message;
}

pub fn writeJsonMessage(self: *Transport, json_message: []const u8) !void {
    var buffer: [64]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buffer, "Content-Length: {d}\r\n\r\n", .{json_message.len}) catch unreachable;

    {
        self.out_lock.lock();
        defer self.out_lock.unlock();

        try self.out.writeAll(prefix);
        try self.out.writeAll(json_message);
    }
    if (self.message_tracing) message_logger.debug("sent: {s}", .{json_message});
}
