const std = @import("std");
const builtin = @import("builtin");

const zls = @import("zls");

const offsets = zls.offsets;

const ErrorBuilder = @This();

allocator: std.mem.Allocator,
encoding: offsets.Encoding = .@"utf-16",
files: std.StringArrayHashMapUnmanaged(File) = .empty,
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
    return .{ .allocator = allocator };
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
    comptime fmt_str: []const u8,
    file_name: []const u8,
    loc: offsets.Loc,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    const message = try std.fmt.allocPrint(builder.allocator, fmt_str, args);
    errdefer builder.allocator.free(message);
    try builder.appendMessage(message, file_name, loc, level);
}

pub fn msgAtIndex(
    builder: *ErrorBuilder,
    comptime fmt_str: []const u8,
    file_name: []const u8,
    source_index: usize,
    level: std.log.Level,
    args: anytype,
) error{OutOfMemory}!void {
    return msgAtLoc(builder, fmt_str, file_name, .{ .start = source_index, .end = source_index }, level, args);
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

//
//
//

fn assertFmt(ok: bool, comptime fmt_str: []const u8, args: anytype) void {
    if (builtin.mode == .Debug or builtin.is_test) {
        if (!ok) std.debug.panic(fmt_str, args);
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
    // the `a` parameter of this function makes no sense.
    std.sort.insertionContext(
        0,
        file.messages.items.len,
        Context{ .items = file.messages.items, .source = file.source },
    );
    builder.message_count += 1;
}

pub const FormatContext = struct {
    builder: *const ErrorBuilder,
    tty_config: ?std.Io.tty.Config,
};

pub fn fmt(builder: *const ErrorBuilder, tty_config: std.Io.tty.Config) std.fmt.Alt(FormatContext, render) {
    return .{ .data = .{
        .builder = builder,
        .tty_config = tty_config,
    } };
}

pub fn writeDebug(builder: *const ErrorBuilder) void {
    const stderr = std.fs.File.stderr();
    const tty_config = std.Io.tty.detectConfig(stderr);
    // does zig trim the output or why is this needed?
    stderr.writeAll(" ") catch return;
    std.debug.print("\n{f}\n", .{builder.fmt(tty_config)});
}

pub fn format(builder: *const ErrorBuilder, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try render(.{ .builder = builder, .tty_config = null }, writer);
}

fn render(context: FormatContext, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const builder = context.builder;
    var first = true;
    for (builder.files.keys(), builder.files.values()) |file_name, file| {
        if (file.messages.items.len == 0) continue;
        defer first = false;

        std.debug.assert(std.sort.isSorted(MsgItem, file.messages.items, file.source, MsgItem.lessThan));

        switch (builder.file_name_visibility) {
            .never => {
                if (!first) {
                    try writer.writeByte('\n');
                }
            },
            .multi_file => {
                if (!first) {
                    try writer.writeAll("\n\n");
                }
                if (builder.files.count() > 1) {
                    try writer.print("{s}:\n", .{file_name});
                }
            },
            .always => {
                if (!first) {
                    try writer.writeAll("\n\n");
                }
            },
        }

        var it: MsgItemIterator = .{
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

            const unified_loc: offsets.Loc = if (builder.unified) |n|
                offsets.multilineLocAtIndex(file.source, some_line_source_index, n)
            else
                .{
                    .start = 0,
                    .end = file.source.len,
                };
            defer last_line_end_with_unified = unified_loc.end;

            const intersection_state: enum {
                start,
                no_intersection,
                intersection,
            } = if (last_line_end_with_unified == 0)
                .start
            else if (last_line_end_with_unified + 1 < unified_loc.start)
                .no_intersection
            else
                .intersection;

            switch (intersection_state) {
                .start => {},
                .no_intersection => {
                    try writer.writeAll(file.source[last_line_end..last_line_end_with_unified]);
                    switch (builder.file_name_visibility) {
                        .never => try writer.writeByte('\n'),
                        .multi_file => try writer.writeAll("\n...\n"),
                        .always => try writer.writeAll("\n\n"),
                    }
                },
                .intersection => { // (we can merge)
                    try writer.writeAll(file.source[last_line_end..line_loc.end]);
                },
            }

            switch (intersection_state) {
                .start,
                .no_intersection,
                => {
                    if (builder.file_name_visibility == .always) {
                        const pos = offsets.indexToPosition(file.source, some_line_source_index, builder.encoding);
                        try writer.print("{s}:{}:{}:\n", .{ file_name, pos.line + 1, pos.character + 1 });
                    }
                    try writer.writeAll(file.source[unified_loc.start..line_loc.end]);
                },
                .intersection => {},
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
                const color: std.Io.tty.Color = switch (item.level) {
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
    messages: std.ArrayList(MsgItem) = .empty,
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
            return lhs.loc.start > rhs.loc.start;
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
    var eb: ErrorBuilder = .init(std.testing.allocator);
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
    var eb: ErrorBuilder = .init(std.testing.allocator);
    defer eb.deinit();

    try std.testing.expectFmt("", "{f}", .{eb});

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

    try std.testing.expectFmt("", "{f}", .{eb});

    {
        eb.clearMessages();
        eb.unified = 0;
        try eb.msgAtLoc("what about equality?", "", .{ .start = 175, .end = 195 }, .warn, .{});

        try std.testing.expectFmt(
            \\(whichever is greater), it obtains a difference, or deviation.
            \\ ^^^^^^^^^^^^^^^^^^^^ warning: what about equality?
        , "{f}", .{eb});
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
        , "{f}", .{eb});
    }

    {
        eb.clearMessages();
        eb.unified = 1;
        try eb.msgAtLoc("AAM or ASM?", "", .{ .start = 4, .end = 11 }, .info, .{});

        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\    ^^^^^^^ info: AAM or ASM?
            \\It knows this because it knows where it isn't.
        , "{f}", .{eb});
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
        , "{f}", .{eb});
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
        , "{f}", .{eb});

        eb.unified = 1;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
            \\By subtracting where it is from where it isn't, or where it isn't from where it is
        , "{f}", .{eb});
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
        , "{f}", .{eb});

        eb.unified = 1;
        try std.testing.expectFmt(
            \\The missile knows where it is at all times.
            \\            ^^^^^ info: declared here
            \\It knows this because it knows where it isn't.
            \\                         ^^^^^ error: redeclaration of work 'knows'
            \\By subtracting where it is from where it isn't, or where it isn't from where it is
        , "{f}", .{eb});
    }
}

test "ErrorBuilder - write on empty file" {
    var eb: ErrorBuilder = .init(std.testing.allocator);
    defer eb.deinit();

    try eb.addFile("empty.zig", "");
    try eb.msgAtIndex("why is this empty?", "empty.zig", 0, .warn, .{});

    eb.unified = null;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{f}", .{eb});

    eb.unified = 0;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{f}", .{eb});

    eb.unified = 2;
    try std.testing.expectFmt(
        \\
        \\^ warning: why is this empty?
    , "{f}", .{eb});
}

test "ErrorBuilder - file name visibility" {
    var eb: ErrorBuilder = .init(std.testing.allocator);
    defer eb.deinit();

    try eb.addFile("basic.zig",
        \\// comment
        \\const alpha: bool = true;
        \\// comment
        \\const beta: bool = false;
        \\// comment
        \\const gamma: type = bool;
    );

    try eb.addFile("array.zig",
        \\// comment
        \\const array_slice_open_runtime = some_array[runtime_index..];
        \\// comment
        \\const array_slice_0_2 = some_array[0..2];
        \\// comment
        \\const array_slice_0_2_sentinel = some_array[0..2 :0];
        \\// comment
        \\const array_slice_0_5 = some_array[0..5];
        \\// comment
        \\const array_slice_3_2 = some_array[3..2];
        \\// comment
        \\const array_slice_0_runtime = some_array[0..runtime_index];
        \\// comment
        \\const array_slice_with_sentinel = some_array[0..runtime_index :0];
        \\// comment
        \\const array_init = [length]u8{};
        \\// comment
        \\const array_init_inferred_len_0 = [_]u8{};
        \\// comment
        \\const array_init_inferred_len_3 = [_]u8{ 1, 2, 3 };
    );

    try eb.addFile("sentinel_value.zig",
        \\// comment
        \\const hw = "Hello, World!";
        \\// comment
        \\const h = hw[0..5];
        \\// comment
        \\const w = hw[7..];
    );

    try eb.msgAtLoc("this should be `*const [2:0]u8`", "array.zig", .{ .start = 143, .end = 167 }, .err, .{});
    try eb.msgAtLoc("this should be `[:0]const u8`", "array.zig", .{ .start = 385, .end = 410 }, .err, .{});

    try eb.msgAtLoc("this should be `*const [5]u8`", "sentinel_value.zig", .{ .start = 56, .end = 57 }, .err, .{});
    try eb.msgAtLoc("this should be `*const [6:0]u8`", "sentinel_value.zig", .{ .start = 87, .end = 88 }, .err, .{});

    eb.file_name_visibility = .multi_file;
    try std.testing.expectFmt(
        \\array.zig:
        \\// comment
        \\const array_slice_0_2 = some_array[0..2];
        \\// comment
        \\const array_slice_0_2_sentinel = some_array[0..2 :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `*const [2:0]u8`
        \\// comment
        \\const array_slice_0_5 = some_array[0..5];
        \\// comment
        \\...
        \\// comment
        \\const array_slice_0_runtime = some_array[0..runtime_index];
        \\// comment
        \\const array_slice_with_sentinel = some_array[0..runtime_index :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `[:0]const u8`
        \\// comment
        \\const array_init = [length]u8{};
        \\// comment
        \\
        \\sentinel_value.zig:
        \\// comment
        \\const hw = "Hello, World!";
        \\// comment
        \\const h = hw[0..5];
        \\      ^ error: this should be `*const [5]u8`
        \\// comment
        \\const w = hw[7..];
        \\      ^ error: this should be `*const [6:0]u8`
    , "{f}", .{eb});

    eb.file_name_visibility = .always;
    try std.testing.expectFmt(
        \\array.zig:6:7:
        \\// comment
        \\const array_slice_0_2 = some_array[0..2];
        \\// comment
        \\const array_slice_0_2_sentinel = some_array[0..2 :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `*const [2:0]u8`
        \\// comment
        \\const array_slice_0_5 = some_array[0..5];
        \\// comment
        \\
        \\array.zig:14:7:
        \\// comment
        \\const array_slice_0_runtime = some_array[0..runtime_index];
        \\// comment
        \\const array_slice_with_sentinel = some_array[0..runtime_index :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `[:0]const u8`
        \\// comment
        \\const array_init = [length]u8{};
        \\// comment
        \\
        \\sentinel_value.zig:4:7:
        \\// comment
        \\const hw = "Hello, World!";
        \\// comment
        \\const h = hw[0..5];
        \\      ^ error: this should be `*const [5]u8`
        \\// comment
        \\const w = hw[7..];
        \\      ^ error: this should be `*const [6:0]u8`
    , "{f}", .{eb});

    eb.file_name_visibility = .never;
    try std.testing.expectFmt(
        \\// comment
        \\const array_slice_0_2 = some_array[0..2];
        \\// comment
        \\const array_slice_0_2_sentinel = some_array[0..2 :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `*const [2:0]u8`
        \\// comment
        \\const array_slice_0_5 = some_array[0..5];
        \\// comment
        \\// comment
        \\const array_slice_0_runtime = some_array[0..runtime_index];
        \\// comment
        \\const array_slice_with_sentinel = some_array[0..runtime_index :0];
        \\      ^^^^^^^^^^^^^^^^^^^^^^^^^ error: this should be `[:0]const u8`
        \\// comment
        \\const array_init = [length]u8{};
        \\// comment
        \\// comment
        \\const hw = "Hello, World!";
        \\// comment
        \\const h = hw[0..5];
        \\      ^ error: this should be `*const [5]u8`
        \\// comment
        \\const w = hw[7..];
        \\      ^ error: this should be `*const [6:0]u8`
    , "{f}", .{eb});
}
