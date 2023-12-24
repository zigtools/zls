const std = @import("std");
const builtin = @import("builtin");

const zls = @import("zls");

const offsets = zls.offsets;

const ErrorBuilder = @This();

allocator: std.mem.Allocator,
files: std.StringArrayHashMapUnmanaged(File) = .{},
message_count: usize = 0,
/// similar to `git diff --unified`
/// show error messages with n lines of context.
/// null will show the whole file
unified: ?usize = 3,
file_name_visibility: enum {
    never,
    multi_file,
    always,
} = .multi_file,

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
    builder.* = undefined;
}

/// assumes `name` and `source` outlives the `ErrorBuilder`
pub fn addFile(builder: *ErrorBuilder, name: []const u8, source: []const u8) error{OutOfMemory}!void {
    const gop = try builder.files.getOrPutValue(builder.allocator, name, .{ .source = source });
    assertFmt(!gop.found_existing, "file '{s}' already exists", .{name});
}

/// preserves insertion order
pub fn removeFile(builder: *ErrorBuilder, name: []const u8) void {
    const found = builder.files.fetchOrderedRemove(name);
    assertFmt(found != null, "file '{s}' doesn't exist", .{name});
    builder.message_count -= found.?.value.messages.items.len;
}

pub fn msgAtLoc(
    builder: *ErrorBuilder,
    comptime fmt: []const u8,
    file_name: []const u8,
    loc: offsets.Loc,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    const message = try std.fmt.allocPrint(builder.allocator, fmt, args);
    errdefer builder.allocator.free(message);
    try builder.appendMessage(message, file_name, loc, level);
}

pub fn msgAtIndex(
    builder: *ErrorBuilder,
    comptime fmt: []const u8,
    file_name: []const u8,
    source_index: usize,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    return msgAtLoc(builder, fmt, file_name, .{ .start = source_index, .end = source_index }, level, args);
}

pub fn hasMessages(builder: ErrorBuilder) bool {
    return builder.message_count != 0;
}

/// remove every message from all files
pub fn clearMessages(builder: *ErrorBuilder) void {
    for (builder.files.values()) |*file| {
        for (file.messages.items) |item| {
            builder.allocator.free(item.message);
        }
        file.messages.clearAndFree(builder.allocator);
    }
    builder.message_count = 0;
}

/// remove all files that contain no messages
pub fn removeUnusedFiles(builder: *ErrorBuilder) void {
    var i: usize = 0;
    while (i < builder.files.count()) : (i += 1) {
        const file: *File = &builder.files.values()[i];
        if (file.messages.items.len == 0) {
            file.messages.deinit(builder.allocator); // there may still be capacity remaining
            builder.files.swapRemoveAt(i);
        } else {
            i += 1;
        }
    }
}

pub const FormatContext = struct {
    builder: *const ErrorBuilder,
    tty_config: ?std.io.tty.Config = null,
};

pub fn format(
    builder: *const ErrorBuilder,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    _ = options;
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, builder.*);
    try write(.{ .builder = builder }, writer);
}

pub fn formatContext(
    context: FormatContext,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    _ = options;
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, context.builder.*);
    try write(context, writer);
}

pub fn fmtContext(builder: *const ErrorBuilder, tty_config: std.io.tty.Config) std.fmt.Formatter(formatContext) {
    return .{ .data = .{
        .builder = builder,
        .tty_config = tty_config,
    } };
}

pub fn writeDebug(builder: *const ErrorBuilder) void {
    const stderr = std.io.getStdErr();
    const tty_config = std.io.tty.detectConfig(stderr);
    // does zig trim the output or why is this needed?
    stderr.writeAll(" ") catch return;
    std.debug.print("\n{}\n", .{builder.fmtContext(tty_config)});
}

//
//
//

fn assertFmt(ok: bool, comptime fmt: []const u8, args: anytype) void {
    if (builtin.mode == .Debug or builtin.is_test) {
        if (!ok) std.debug.panic(fmt, args);
    } else {
        std.debug.assert(ok);
    }
}

fn appendMessage(
    builder: *ErrorBuilder,
    message: []const u8,
    file_name: []const u8,
    loc: offsets.Loc,
    level: std.log.Level,
) error{OutOfMemory}!void {
    assertFmt(loc.start <= loc.end, "invalid source location [{d}..{d}]", .{ loc.start, loc.end });
    const file: *File = blk: {
        const file = builder.files.getPtr(file_name);
        assertFmt(file != null, "file '{s}' doesn't exist", .{file_name});
        break :blk file.?;
    };
    assertFmt(
        loc.end <= file.source.len,
        "source location [{d}..{d}] is outside file source (len: {d})",
        .{ loc.start, loc.end, file.source.len },
    );
    assertFmt(
        std.mem.count(u8, offsets.locToSlice(file.source, loc), "\n") == 0,
        "source location [{d}..{d}] must span a single line",
        .{ loc.start, loc.end },
    );

    const Context = struct {
        items: []MsgItem,
        source: []const u8,

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return MsgItem.lessThan(ctx.source, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return std.mem.swap(MsgItem, &ctx.items[a], &ctx.items[b]);
        }
    };

    try file.messages.append(builder.allocator, .{
        .loc = loc,
        .level = level,
        .message = message,
    });
    std.sort.insertionContext(
        file.messages.items.len -| 2,
        file.messages.items.len,
        Context{ .items = file.messages.items, .source = file.source },
    );
    builder.message_count += 1;
}

fn write(context: FormatContext, writer: anytype) @TypeOf(writer).Error!void {
    const builder = context.builder;
    for (builder.files.keys(), builder.files.values()) |file_name, file| {
        if (file.messages.items.len == 0) continue;

        std.debug.assert(std.sort.isSorted(MsgItem, file.messages.items, file.source, MsgItem.lessThan));

        if (builder.file_name_visibility == .always or
            builder.file_name_visibility == .multi_file and builder.files.count() > 1)
        {
            try writer.print("{s}:\n", .{file_name});
        }

        var it = MsgItemIterator{
            .source = file.source,
            .messages = file.messages.items,
        };

        var last_line_end: usize = 0;
        var last_line_end_with_unified: usize = 0;

        while (it.next()) |line_messages| {
            std.debug.assert(line_messages.len > 0);

            const some_line_source_index = line_messages[0].loc.start;
            const line_loc = offsets.lineLocAtIndex(file.source, some_line_source_index);
            defer last_line_end = line_loc.end;

            const unified_loc = if (builder.unified) |n|
                offsets.multilineLocAtIndex(file.source, some_line_source_index, n)
            else
                offsets.Loc{
                    .start = 0,
                    .end = file.source.len,
                };
            defer last_line_end_with_unified = unified_loc.end;

            if (last_line_end_with_unified == 0) { // start
                try writer.writeAll(file.source[unified_loc.start..line_loc.end]);
            } else if (last_line_end_with_unified < unified_loc.start) { // no intersection
                try writer.writeAll(file.source[last_line_end..@min(last_line_end_with_unified + 1, file.source.len)]);
                try writer.writeAll(file.source[unified_loc.start..line_loc.end]);
            } else { // intersection (we can merge)
                try writer.writeAll(file.source[last_line_end..line_loc.end]);
            }

            for (line_messages) |item| {
                try writer.writeByte('\n');
                for (line_loc.start..item.loc.start) |_| try writer.writeByte(' ');
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
                if (context.tty_config) |tty| tty.setColor(writer, color) catch {};
                try writer.print(" {s}: ", .{level_txt});
                if (context.tty_config) |tty| tty.setColor(writer, .reset) catch {};
                try writer.writeAll(item.message);
            }
        }

        try writer.writeAll(file.source[last_line_end..last_line_end_with_unified]);
    }
}

const File = struct {
    source: []const u8,
    messages: std.ArrayListUnmanaged(MsgItem) = .{},
};

const MsgItem = struct {
    loc: offsets.Loc,
    level: std.log.Level,
    message: []const u8,

    fn lessThan(source: []const u8, lhs: MsgItem, rhs: MsgItem) bool {
        const is_less = lhs.loc.start < rhs.loc.start;
        const text = if (is_less) source[lhs.loc.start..rhs.loc.start] else source[rhs.loc.start..lhs.loc.start];

        // report messages on the same line in reverse order
        if (std.mem.indexOfScalar(u8, text, '\n') == null) {
            return !is_less;
        }

        return is_less;
    }
};

/// iterates through MsgItem's grouped by lines
/// assumes that `messages` is sorted
const MsgItemIterator = struct {
    source: []const u8,
    messages: []const MsgItem,
    msg_index: usize = 0,

    fn next(it: *MsgItemIterator) ?[]const MsgItem {
        std.debug.assert(it.msg_index <= it.messages.len);
        if (it.msg_index == it.messages.len) return null;

        const msg = it.messages[it.msg_index];
        const line_loc = offsets.lineLocAtIndex(it.source, msg.loc.start);

        const start = it.msg_index;
        const end = while (it.msg_index < it.messages.len) : (it.msg_index += 1) {
            const loc = it.messages[it.msg_index].loc;
            if (line_loc.start <= loc.start and loc.end <= line_loc.end) continue;
            break it.msg_index;
        } else it.messages.len;

        it.msg_index = end;
        return it.messages[start..end];
    }
};

//
//
//

test ErrorBuilder {
    var eb = ErrorBuilder.init(std.testing.allocator);
    defer eb.deinit();
    try std.testing.expect(!eb.hasMessages());

    try eb.addFile("example.zig", "");
    try eb.msgAtIndex("", "example.zig", 0, .info, .{});
    try std.testing.expect(eb.hasMessages());

    eb.clearMessages();
    try std.testing.expect(!eb.hasMessages());
    eb.removeUnusedFiles();
    try std.testing.expectEqual(@as(usize, 0), eb.files.count());
}

test "ErrorBuilder - write" {
    var eb = ErrorBuilder.init(std.testing.allocator);
    defer eb.deinit();

    try std.testing.expectFmt("", "{}", .{eb});

    try eb.addFile("",
        \\The missile knows where it is at all times.
        \\It knows this because it knows where it isn't.
        \\By subtracting where it is from where it isn't, or where it isn't from where it is
        \\(whichever is greater), it obtains a difference, or deviation.
        \\The guidance subsystem uses deviations to generate corrective commands to drive
        \\the missile from a position where it is to a position where it isn't, and
        \\arriving at a position where it wasn't, it now is.
        \\Consequently, the position where it is, is now the position that it wasn't, and it
        \\follows that the position that it was, is now the position that it isn't.
        \\In the event that the position that it is in is not the position that it wasn't,
        \\the system has acquired a variation, the variation being the difference between where
        \\the missile is, and where it wasn't.
        \\If variation is considered to be a significant factor, it too may be correcte by the GEA.
        \\However, the missile must also know where it was.
        \\The missile guidance computer scenario works as follows.
        \\Because a variation has modified some of the information the missile has obtained,
        \\it is not sure just where it is.
        \\However, it is sure where it isn't, within reason, and it knows where it was.
        \\It now subtracts where it should be from where it wasn't, or vice-versa, and by
        \\differentiating this from the algebraic sum of where it shouldn't be, and where
        \\it was, it is able to obtain the deviation and its variation, which is called error.
    );

    try std.testing.expectFmt("", "{}", .{eb});

    {
        eb.clearMessages();
        eb.unified = 0;
        try eb.msgAtLoc("what about equallity?", "", .{ .start = 175, .end = 195 }, .warn, .{});

        try std.testing.expectFmt(
            \\(whichever is greater), it obtains a difference, or deviation.
            \\ ^^^^^^^^^^^^^^^^^^^^ warning: what about equallity?
        , "{}", .{eb});
    }

    {
        eb.clearMessages();
        eb.unified = 1;
        try eb.msgAtLoc("are safety checks enabled?", "", .{ .start = 94, .end = 105 }, .info, .{});

        try std.testing.expectFmt(
            \\It knows this because it knows where it isn't.
            \\By subtracting where it is from where it isn't, or where it isn't from where it is
            \\   ^^^^^^^^^^^ info: are safety checks enabled?
            \\(whichever is greater), it obtains a difference, or deviation.
        , "{}", .{eb});
    }

    {
        eb.clearMessages();
        eb.unified = 1;
        try eb.msgAtLoc("AAM or ASM?", "", .{ .start = 4, .end = 11 }, .info, .{});

        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\    ^^^^^^^ info: AAM or ASM?
            \\It knows this because it knows where it isn't.
        , "{}", .{eb});
    }

    {
        eb.clearMessages();
        eb.unified = 2;
        try eb.msgAtLoc("reserved keyword!", "", .{ .start = 1432, .end = 1437 }, .err, .{});

        try std.testing.expectFmt(
            \\It now subtracts where it should be from where it wasn't, or vice-versa, and by
            \\differentiating this from the algebraic sum of where it shouldn't be, and where
            \\it was, it is able to obtain the deviation and its variation, which is called error.
            \\                                                                              ^^^^^ error: reserved keyword!
        , "{}", .{eb});
    }

    {
        eb.clearMessages();
        try eb.msgAtLoc("redeclaration of work 'knows'", "", .{ .start = 69, .end = 74 }, .err, .{});
        try eb.msgAtLoc("declared here", "", .{ .start = 12, .end = 17 }, .info, .{});

        eb.unified = 0;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
        , "{}", .{eb});

        eb.unified = 1;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
            \\By subtracting where it is from where it isn't, or where it isn't from where it is
        , "{}", .{eb});
    }

    {
        eb.clearMessages();
        try eb.msgAtLoc("redeclaration of work 'knows'", "", .{ .start = 69, .end = 74 }, .err, .{});
        try eb.msgAtLoc("declared here", "", .{ .start = 12, .end = 17 }, .info, .{});

        eb.unified = 0;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
        , "{}", .{eb});

        eb.unified = 1;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
            \\By subtracting where it is from where it isn't, or where it isn't from where it is
        , "{}", .{eb});
    }
}

test "ErrorBuilder - write on empty file" {
    var eb = ErrorBuilder.init(std.testing.allocator);
    defer eb.deinit();

    try eb.addFile("empty.zig", "");
    try eb.msgAtIndex("why is this empty?", "empty.zig", 0, .warn, .{});

    eb.unified = null;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{}", .{eb});

    eb.unified = 0;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{}", .{eb});

    eb.unified = 2;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{}", .{eb});
}
