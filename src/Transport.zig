//! Implementation of the LSP Base Protocol.
//!
//! https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#baseProtocol

const std = @import("std");
const lsp = @import("lsp");

in: std.io.BufferedReader(4096, std.fs.File.Reader),
out: std.fs.File,
in_lock: std.Thread.Mutex = .{},
out_lock: std.Thread.Mutex = .{},
message_tracing: bool = false,

const message_logger = std.log.scoped(.message);

const Transport = @This();

pub fn init(in: std.fs.File, out: std.fs.File) Transport {
    return .{
        .in = std.io.bufferedReader(in.reader()),
        .out = out,
    };
}

pub fn readJsonMessage(self: *Transport, allocator: std.mem.Allocator) ![]u8 {
    const json_message = blk: {
        self.in_lock.lock();
        defer self.in_lock.unlock();

        const reader = self.in.reader();
        const header = try lsp.BaseProtocolHeader.parse(reader);

        const json_message = try allocator.alloc(u8, header.content_length);
        errdefer allocator.free(json_message);
        try reader.readNoEof(json_message);

        break :blk json_message;
    };

    if (self.message_tracing) message_logger.debug("received: {s}", .{json_message});
    return json_message;
}

pub fn writeJsonMessage(self: *Transport, json_message: []const u8) !void {
    const header = lsp.BaseProtocolHeader{ .content_length = json_message.len };

    var buffer: [64]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buffer, "{}", .{header}) catch unreachable;

    {
        self.out_lock.lock();
        defer self.out_lock.unlock();

        var iovecs = [_]std.posix.iovec_const{
            .{ .base = prefix.ptr, .len = prefix.len },
            .{ .base = json_message.ptr, .len = json_message.len },
        };
        try self.out.writevAll(&iovecs);
    }
    if (self.message_tracing) message_logger.debug("sent: {s}", .{json_message});
}
