const std = @import("std");

const zls = @import("zls");

const offsets = zls.offsets;

const ErrorBuilder = @This();

allocator: std.mem.Allocator,
items: std.ArrayListUnmanaged(MsgItem) = .{},
source: []const u8,

pub fn init(allocator: std.mem.Allocator, source: []const u8) ErrorBuilder {
    return ErrorBuilder{
        .allocator = allocator,
        .source = source,
    };
}

pub fn deinit(builder: *ErrorBuilder) void {
    for (builder.items.items) |item| {
        builder.allocator.free(item.message);
    }
    builder.items.deinit(builder.allocator);
}

pub fn msgAtLoc(builder: *ErrorBuilder, comptime fmt: []const u8, loc: offsets.Loc, level: std.log.Level, args: anytype) !void {
    try builder.items.append(builder.allocator, .{
        .loc = loc,
        .level = level,
        .message = try std.fmt.allocPrint(builder.allocator, fmt, args),
    });
}

pub fn msgAtIndex(builder: *ErrorBuilder, comptime fmt: []const u8, index: usize, level: std.log.Level, args: anytype) !void {
    return msgAtLoc(builder, fmt, .{ .start = index, .end = index }, level, args);
}

pub fn hasMessages(builder: *ErrorBuilder) bool {
    return builder.items.items.len != 0;
}

pub fn write(builder: *ErrorBuilder, writer: anytype) !void {
    if (!builder.hasMessages()) return;

    std.sort.sort(MsgItem, builder.items.items, builder, ErrorBuilder.lessThan);

    try writer.writeByte('\n');

    var start: usize = 0;
    for (builder.items.items) |item| {
        const line = offsets.lineLocAtIndex(builder.source, item.loc.start);
        defer start = line.end;

        try writer.writeAll(builder.source[start..line.end]);
        try writer.writeByte('\n');
        {
            var i: usize = line.start;
            while (i < item.loc.start) : (i += 1) try writer.writeByte(' ');
            while (i < item.loc.end) : (i += 1) try writer.writeByte('^');
            if (item.loc.start == item.loc.end) try writer.writeByte('^');
        }
        const level_txt: []const u8 = switch (item.level) {
            .err => "error",
            .warn => "warning",
            .info => "info",
            .debug => "debug",
        };
        try writer.print(" {s}: {s}", .{ level_txt, item.message });
    }

    try writer.writeAll(builder.source[start..builder.source.len]);
    try writer.writeByte('\n');
}

pub fn writeDebug(builder: *ErrorBuilder) void {
    if (!builder.hasMessages()) return;
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    nosuspend builder.write(std.io.getStdErr().writer()) catch return;
}

const MsgItem = struct {
    loc: offsets.Loc,
    level: std.log.Level,
    message: []const u8,
};

fn lessThan(builder: *ErrorBuilder, lhs: MsgItem, rhs: MsgItem) bool {
    const is_less = lhs.loc.start < rhs.loc.start;
    const text = if (is_less) builder.source[lhs.loc.start..rhs.loc.start] else builder.source[rhs.loc.start..lhs.loc.start];

    // report messages on the same line in reverse order
    if (std.mem.indexOfScalar(u8, text, '\n') == null) {
        return !is_less;
    }

    return is_less;
}
