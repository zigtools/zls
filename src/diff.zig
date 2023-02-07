const std = @import("std");
const types = @import("lsp.zig");
const offsets = @import("offsets.zig");

pub const Error = error{ OutOfMemory, InvalidRange, UnknownError };

// https://cs.opensource.google/go/x/tools/+/master:internal/lsp/diff/myers/diff.go

pub const Operation = struct {
    pub const Kind = enum {
        delete,
        insert,
        equal,
    };

    kind: Kind,
    /// content from b
    content: []const []const u8,

    // indices of the line in a
    i_1: isize,
    i_2: isize,
    // indices of the line in b, j_2 implied by len(content)
    j_1: isize,
};

pub fn edits(
    allocator: std.mem.Allocator,
    before: []const u8,
    after: []const u8,
) Error!std.ArrayListUnmanaged(types.TextEdit) {
    var ops = try operations(allocator, try splitLines(allocator, before), try splitLines(allocator, after)) orelse return error.UnknownError;
    var eds = std.ArrayListUnmanaged(types.TextEdit){};

    for (ops) |op| {
        const s = types.Range{
            .start = .{
                .line = @intCast(u32, op.i_1),
                .character = 0,
            },
            .end = .{
                .line = @intCast(u32, op.i_2),
                .character = 0,
            },
        };
        switch (op.kind) {
            .delete => try eds.append(allocator, .{ .range = s, .newText = "" }),
            .insert => {
                // Insert: formatted[j_1..j_2] is inserted at unformatted[i_1..i_1].
                const content = try std.mem.join(allocator, "", op.content);
                if (content.len != 0) {
                    try eds.append(allocator, .{ .range = s, .newText = content });
                }
            },
            else => {},
        }
    }
    return eds;
}

fn add(
    solution: []Operation,
    op: ?*Operation,
    i_2: isize,
    j_2: isize,
    b: []const []const u8,
    i: *usize,
) void {
    if (op == null) {
        return;
    }
    op.?.i_2 = i_2;
    if (op.?.kind == .insert) {
        op.?.content = b[@intCast(usize, op.?.j_1)..@intCast(usize, j_2)];
    }
    solution[i.*] = op.?.*;
    i.* += 1;
}

// operations returns the list of operations to convert a into b, consolidating
// operations for multiple lines and not including equal lines.
fn operations(allocator: std.mem.Allocator, a: []const []const u8, b: []const []const u8) Error!?[]Operation {
    if (a.len == 0 and b.len == 0) {
        return null;
    }

    const ses_res = try shortestEditSequence(allocator, a, b);
    var trace = ses_res[0] orelse return null;
    var offset = ses_res[1];

    var snakes = try backtrack(allocator, trace, @intCast(isize, a.len), @intCast(isize, b.len), offset);

    var m = a.len;
    var n = b.len;

    var i: usize = 0;
    var solution = try allocator.alloc(Operation, a.len + b.len);

    var x: isize = 0;
    var y: isize = 0;

    for (snakes) |maybe_snake| {
        if (maybe_snake == null) {
            continue;
        }

        const snake = maybe_snake.?;

        var op: ?Operation = null;
        // delete (horizontal)
        while (snake[0] - snake[1] > x - y) {
            if (op == null) {
                op = .{
                    .kind = .delete,
                    .i_1 = x,
                    .i_2 = 0,
                    .j_1 = y,
                    .content = &.{},
                };
            }
            x += 1;
            if (x == m) {
                break;
            }
        }
        add(solution, if (op) |*o| o else null, x, y, b, &i);
        op = null;
        // insert (vertical)
        while (snake[0] - snake[1] < x - y) {
            if (op == null) {
                op = .{
                    .kind = .insert,
                    .i_1 = x,
                    .i_2 = 0,
                    .j_1 = y,
                    .content = &.{},
                };
            }
            y += 1;
        }
        add(solution, if (op) |*o| o else null, x, y, b, &i);
        op = null;
        // equal (diagonal)
        while (x < snake[0]) {
            x += 1;
            y += 1;
        }
        if (x >= m and y >= n) {
            break;
        }
    }
    return solution[0..i];
}

// backtrack uses the trace for the edit sequence computation and returns the
// "snakes" that make up the solution. A "snake" is a single deletion or
// insertion followed by zero or diagonals.
fn backtrack(
    allocator: std.mem.Allocator,
    trace: []const ?[]const isize,
    x_in: isize,
    y_in: isize,
    offset: isize,
) Error![]const ?[2]isize {
    var snakes = try allocator.alloc(?[2]isize, trace.len);
    for (snakes) |*s| s.* = null;

    var x = x_in;
    var y = y_in;
    var d = @intCast(isize, trace.len) - 1;

    while (x > 0 and y > 0 and d > 0) : (d -= 1) {
        const cast_d = @intCast(usize, d);
        const v = trace[cast_d] orelse continue;
        snakes[cast_d] = .{ x, y };

        const k = x - y;
        var kPrev: isize = 0;

        if (k == -d or (k != d and v[@intCast(usize, k - 1 + offset)] < v[@intCast(usize, k + 1 + offset)])) {
            kPrev = k + 1;
        } else {
            kPrev = k - 1;
        }

        x = v[@intCast(usize, kPrev + offset)];
        y = x - kPrev;
    }

    if (x < 0 or y < 0) {
        return snakes;
    }

    snakes[@intCast(usize, d)] = .{ x, y };
    return snakes;
}

// shortestEditSequence returns the shortest edit sequence that converts a into b.
const SesTuple = struct { ?[]const ?[]const isize, isize };
fn shortestEditSequence(
    allocator: std.mem.Allocator,
    a: []const []const u8,
    b: []const []const u8,
) Error!SesTuple {
    var m = a.len;
    var n = b.len;

    var v = try allocator.alloc(isize, 2 * (n + m) + 1);
    for (v) |*z| z.* = 0;
    var offset = @intCast(isize, n + m);
    var trace = try allocator.alloc(?[]isize, n + m + 1);
    for (trace) |*z| z.* = null;

    // Iterate through the maximum possible length of the SES (N+M).
    var d: usize = 0;
    while (d <= n + m) : (d += 1) {
        var copyV = try allocator.alloc(isize, v.len);
        for (copyV) |*z| z.* = 0;

        // k lines are represented by the equation y = x - k. We move in
        // increments of 2 because end points for even d are on even k lines.
        var k: isize = -@intCast(isize, d);
        while (k <= d) : (k += 2) {
            // At each point, we either go down or to the right. We go down if
            // k == -d, and we go to the right if k == d. We also prioritize
            // the maximum x value, because we prefer deletions to insertions.
            var x: isize = 0;
            if (k == -@intCast(isize, d) or (k != @intCast(isize, d) and v[@intCast(usize, k - 1 + offset)] < v[@intCast(usize, k + 1 + offset)])) {
                x = v[@intCast(usize, k + 1 + offset)]; // down
            } else {
                x = v[@intCast(usize, k - 1 + offset)] + 1; // right
            }

            var y = x - k;

            // Diagonal moves while we have equal contents.
            while (x < m and y < n and std.mem.eql(u8, a[@intCast(usize, x)], b[@intCast(usize, y)])) {
                x += 1;
                y += 1;
            }

            v[@intCast(usize, k + offset)] = x;

            // Return if we've exceeded the maximum values.
            if (x == m and y == n) {
                // Makes sure to save the state of the array before returning.
                std.mem.copy(isize, copyV, v);
                trace[d] = copyV;
                return .{ trace, offset };
            }
        }

        // Save the state of the array.
        std.mem.copy(isize, copyV, v);
        trace[d] = copyV;
    }
    return .{ null, 0 };
}

fn splitLines(allocator: std.mem.Allocator, str: []const u8) error{OutOfMemory}![]const []const u8 {
    var lines = std.ArrayListUnmanaged([]const u8){};

    var index: ?usize = 0;

    while (true) {
        const start = index orelse break;
        const end = if (std.mem.indexOfPos(u8, str, start, "\n")) |delim_start| blk: {
            index = delim_start + 1;
            break :blk delim_start + 1;
        } else blk: {
            index = null;
            break :blk str.len;
        };
        try lines.append(allocator, str[start..end]);
    }

    if (lines.items[lines.items.len - 1].len == 0) _ = lines.pop();

    return lines.toOwnedSlice(allocator);
}

/// Caller owns returned memory.
/// NOTE: As far as I know, this implementation is actually incorrect
/// as we use intermediate state, but at the same time, it works so
/// I really don't want to touch it right now. TODO: Investigate + fix.
pub fn applyContentChanges(
    allocator: std.mem.Allocator,
    text: []const u8,
    content_changes: []const types.TextDocumentContentChangeEvent,
    encoding: offsets.Encoding,
) ![:0]const u8 {
    var last_full_text_change: ?usize = null;
    var i: usize = content_changes.len;
    while (i > 0) {
        i -= 1;
        if (content_changes[i] == .literal_1) {
            last_full_text_change = i;
            continue;
        }
    }

    var text_array = std.ArrayListUnmanaged(u8){};
    errdefer text_array.deinit(allocator);

    try text_array.appendSlice(allocator, if (last_full_text_change) |index| content_changes[index].literal_1.text else text);

    // don't even bother applying changes before a full text change
    const changes = content_changes[if (last_full_text_change) |index| index + 1 else 0..];

    for (changes) |item| {
        const range = item.literal_0.range;

        const loc = offsets.rangeToLoc(text_array.items, range, encoding);
        try text_array.replaceRange(allocator, loc.start, loc.end - loc.start, item.literal_0.text);
    }

    return try text_array.toOwnedSliceSentinel(allocator, 0);
}

// https://cs.opensource.google/go/x/tools/+/master:internal/lsp/diff/diff.go;l=40

fn textEditLessThan(_: void, lhs: types.TextEdit, rhs: types.TextEdit) bool {
    return offsets.rangeLessThan(lhs.range, rhs.range);
}

/// Caller owns returned memory.
pub fn applyTextEdits(
    allocator: std.mem.Allocator,
    text: []const u8,
    text_edits: []const types.TextEdit,
    encoding: offsets.Encoding,
) ![]const u8 {
    var text_edits_sortable = try allocator.alloc(types.TextEdit, text_edits.len);
    defer allocator.free(text_edits_sortable);

    std.mem.copy(types.TextEdit, text_edits_sortable, text_edits);
    std.sort.sort(types.TextEdit, text_edits_sortable, {}, textEditLessThan);

    var final_text = std.ArrayListUnmanaged(u8){};

    var last: usize = 0;
    for (text_edits_sortable) |te| {
        const start = offsets.maybePositionToIndex(text, te.range.start, encoding) orelse text.len;
        if (start > last) {
            try final_text.appendSlice(allocator, text[last..start]);
            last = start;
        }
        try final_text.appendSlice(allocator, te.newText);
        last = offsets.maybePositionToIndex(text, te.range.end, encoding) orelse text.len;
    }
    if (last < text.len) {
        try final_text.appendSlice(allocator, text[last..]);
    }

    return try final_text.toOwnedSlice(allocator);
}
