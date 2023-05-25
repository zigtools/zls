const std = @import("std");

const zls = @import("zls");

const offsets = zls.offsets;

const ErrorBuilder = @This();

allocator: std.mem.Allocator,
files: std.StringArrayHashMapUnmanaged(File) = .{},
message_count: usize = 0,

pub fn init(allocator: std.mem.Allocator) ErrorBuilder {
    return ErrorBuilder{ .allocator = allocator };
}

pub fn deinit(builder: *ErrorBuilder) void {
    for (builder.files.values()) |*file| {
        for (file.messages.items) |item| {
            builder.allocator.free(item.message);
        }
        file.messages.deinit(builder.allocator);
    }
    builder.files.deinit(builder.allocator);
}

/// assumes `name` and `source` outlives the `ErrorBuilder`
pub fn addFile(builder: *ErrorBuilder, name: []const u8, source: []const u8) error{OutOfMemory}!void {
    const gop = try builder.files.getOrPutValue(builder.allocator, name, .{ .source = source });
    if (gop.found_existing)
        std.debug.panic("file '{s}' already exists", .{name});
}

pub fn removeFile(builder: *ErrorBuilder, name: []const u8) error{OutOfMemory}!void {
    const found = builder.files.remove(name);
    if (!found)
        std.debug.panic("file '{s}' doesn't exist", .{name});
    builder.message_count -= found.messages.items.len;
}

pub fn msgAtLoc(
    builder: *ErrorBuilder,
    comptime fmt: []const u8,
    file_name: []const u8,
    loc: offsets.Loc,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    if (loc.start > loc.end)
        std.debug.panic("invalid source location {}", .{loc});
    const file = builder.files.getPtr(file_name) orelse
        std.debug.panic("file '{s}' doesn't exist", .{file_name});
    if (loc.end > file.source.len)
        std.debug.panic("source location {} is outside file source (len: {d})", .{ loc, file.source.len });
    const message = try std.fmt.allocPrint(builder.allocator, fmt, args);
    errdefer builder.allocator.free(message);

    try file.messages.append(builder.allocator, .{
        .loc = loc,
        .level = level,
        .message = message,
    });
    builder.message_count += 1;
}

pub fn msgAtIndex(
    builder: *ErrorBuilder,
    comptime fmt: []const u8,
    file: []const u8,
    source_index: usize,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    return msgAtLoc(builder, fmt, file, .{ .start = source_index, .end = source_index }, level, args);
}

pub fn hasMessages(builder: *ErrorBuilder) bool {
    return builder.message_count != 0;
}

pub fn clearMessages(builder: *ErrorBuilder) void {
    for (builder.files.values()) |*file| {
        for (file.messages.items) |item| {
            builder.allocator.free(item.message);
        }
        file.messages.clearAndFree(builder.allocator);
    }
    builder.message_count = 0;
}

pub fn write(builder: *ErrorBuilder, writer: anytype, tty_config: std.io.tty.Config) !void {
    for (builder.files.keys(), builder.files.values()) |file_name, file| {
        if (file.messages.items.len == 0) continue;

        std.mem.sort(MsgItem, file.messages.items, file.source, ErrorBuilder.lessThan);

        try writer.writeByte('\n');
        if (builder.files.count() > 1) {
            try writer.print("{s}:\n", .{file_name});
        }

        var start: usize = 0;
        for (file.messages.items) |item| {
            const line = offsets.lineLocAtIndex(file.source, item.loc.start);
            defer start = line.end;

            try writer.writeAll(file.source[start..line.end]);
            try writer.writeByte('\n');
            for (line.start..item.loc.start) |_| try writer.writeByte(' ');
            for (item.loc.start..item.loc.end) |_| try writer.writeByte('^');
            if (item.loc.start == item.loc.end) try writer.writeByte('^');

            const level_txt: []const u8 = switch (item.level) {
                .err => "error",
                .warn => "warning",
                .info => "info",
                .debug => "debug",
            };
            const color: std.io.tty.Color = switch (item.level) {
                .err => .red,
                .warn => .yellow,
                .info => .white,
                .debug => .white,
            };
            try tty_config.setColor(writer, color);
            try writer.print(" {s}: ", .{level_txt});
            try tty_config.setColor(writer, .reset);
            try writer.writeAll(item.message);
        }

        try writer.writeAll(file.source[start..file.source.len]);
        try writer.writeByte('\n');
    }
}

pub fn writeDebug(builder: *ErrorBuilder) void {
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    const stderr = std.io.getStdErr();
    const tty_config = std.io.tty.detectConfig(stderr);
    // does zig trim the output or why is this needed?
    stderr.writeAll(" ") catch return;
    nosuspend builder.write(stderr.writer(), tty_config) catch return;
}

const File = struct {
    source: []const u8,
    messages: std.ArrayListUnmanaged(MsgItem) = .{},
};

const MsgItem = struct {
    loc: offsets.Loc,
    level: std.log.Level,
    message: []const u8,
};

fn lessThan(source: []const u8, lhs: MsgItem, rhs: MsgItem) bool {
    const is_less = lhs.loc.start < rhs.loc.start;
    const text = if (is_less) source[lhs.loc.start..rhs.loc.start] else source[rhs.loc.start..lhs.loc.start];

    // report messages on the same line in reverse order
    if (std.mem.indexOfScalar(u8, text, '\n') == null) {
        return !is_less;
    }

    return is_less;
}
