const std = @import("std");
const types = @import("types.zig");

// This is essentially the same as `types.TextEdit`, but we use an
// ArrayList(u8) here to be able to clean up the memory later on
pub const Edit = struct {
    range: types.Range,
    newText: std.ArrayList(u8),
};

// Whether the `Change` is an addition, deletion, or no change from the
// original string to the new string
const Operation = enum { Deletion, Addition, Nothing };

/// A single character difference between two strings
const Change = struct {
    operation: Operation,
    pos: usize,
    value: ?u8,
};

/// Given two input strings, `a` and `b`, return a list of Edits that
/// describe the changes from `a` to `b`
pub fn edits(
    allocator: std.mem.Allocator,
    a: []const u8,
    b: []const u8,
) !std.ArrayList(Edit) {
    // Given the input strings A and B, we skip over the first N characters
    // where A[0..N] == B[0..N]. We want to trim the start (and end) of the
    // strings that have the same text. This decreases the size of the LCS
    // table and makes the diff comparison more efficient
    var a_trim: []const u8 = a;
    var b_trim: []const u8 = b;
    const a_trim_offset = trim_input(&a_trim, &b_trim);
    _ = a_trim_offset;

    const rows = a_trim.len + 1;
    const cols = b_trim.len + 1;

    var lcs = try Array2D.new(allocator, rows, cols);
    defer lcs.deinit();

    calculate_lcs(&lcs, a_trim, b_trim);

    return try get_changes(
        &lcs,
        a,
        a_trim_offset,
        a_trim,
        b_trim,
        allocator,
    );
}

fn trim_input(a_out: *[]const u8, b_out: *[]const u8) usize {
    if (a_out.len == 0 or b_out.len == 0) return 0;

    var a: []const u8 = a_out.*;
    var b: []const u8 = b_out.*;

    // Trim the beginning of the string
    var start: usize = 0;
    while (start < a.len and start < b.len and a[start] == b[start]) : ({
        start += 1;
    }) {}

    // Trim the end of the string
    var end: usize = 1;
    while (end < a.len and end < b.len and a[a.len - end] == b[b.len - end]) : ({
        end += 1;
    }) {}
    end -= 1;

    var a_start = start;
    var a_end = a.len - end;
    var b_start = start;
    var b_end = b.len - end;

    // In certain situations, the trimmed range can be "negative" where
    // `a_start` ends up being after `a_end` in the byte stream. If you
    // consider the following inputs:
    //     a: "xx    gg  xx"
    //     b: "xx  gg  xx"
    //
    // This will lead to the following calculations:
    //     a_start: 4
    //     a_end: 4
    //     b_start: 4
    //     b_end: 2
    //
    // In negative range situations, we add the absolute value of the
    // the negative range's length (`b_start - b_end` in this case) to the
    // other range's length (a_end + (b_start - b_end)), and then set the
    // negative range end to the negative range start (b_end = b_start)
    if (a_start > a_end) {
        const difference = a_start - a_end;
        a_end = a_start;
        b_end += difference;
    }
    if (b_start > b_end) {
        const difference = b_start - b_end;
        b_end = b_start;
        a_end += difference;
    }

    a_out.* = a[a_start..a_end];
    b_out.* = b[b_start..b_end];

    return start;
}

/// A 2D array that is addressable as a[row, col]
pub const Array2D = struct {
    const Self = @This();

    data: [*]usize,
    allocator: std.mem.Allocator,
    rows: usize,
    cols: usize,

    pub fn new(
        allocator: std.mem.Allocator,
        rows: usize,
        cols: usize,
    ) !Self {
        const data = try allocator.alloc(usize, rows * cols);

        return Self{
            .data = data.ptr,
            .allocator = allocator,
            .rows = rows,
            .cols = cols,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data[0 .. self.rows * self.cols]);
    }

    pub fn get(self: *Self, row: usize, col: usize) *usize {
        return @ptrCast(*usize, self.data + (row * self.cols) + col);
    }
};

/// Build a Longest Common Subsequence table
fn calculate_lcs(
    lcs: *Array2D,
    astr: []const u8,
    bstr: []const u8,
) void {
    const rows = astr.len + 1;
    const cols = bstr.len + 1;

    std.mem.set(usize, lcs.data[0 .. rows * cols], 0);

    // This approach is a dynamic programming technique to calculate the
    // longest common subsequence between two strings, `a` and `b`. We start
    // at 1 for `i` and `j` because the first column and first row are always
    // set to zero
    //
    // You can find more information about this at the following url:
    // https://en.wikipedia.org/wiki/Longest_common_subsequence_problem
    var i: usize = 1;
    while (i < rows) : (i += 1) {
        var j: usize = 1;
        while (j < cols) : (j += 1) {
            if (astr[i - 1] == bstr[j - 1]) {
                lcs.get(i, j).* = lcs.get(i - 1, j - 1).* + 1;
            } else {
                lcs.get(i, j).* = std.math.max(
                    lcs.get(i - 1, j).*,
                    lcs.get(i, j - 1).*,
                );
            }
        }
    }
}

pub fn get_changes(
    lcs: *Array2D,
    a: []const u8,
    a_trim_offset: usize,
    a_trim: []const u8,
    b_trim: []const u8,
    allocator: std.mem.Allocator,
) !std.ArrayList(Edit) {
    // First we get a list of changes between strings at the character level:
    // "addition", "deletion", and "no change" for each character
    var changes = try std.ArrayList(Change).initCapacity(allocator, a_trim.len);
    defer changes.deinit();
    try recur_changes(
        lcs,
        &changes,
        a_trim,
        b_trim,
        @intCast(i64, a_trim.len),
        @intCast(i64, b_trim.len),
    );

    // We want to group runs of deletions and additions, and separate them by
    // runs of `.Nothing` changes. This will allow us to calculate the
    // `TextEdit` ranges
    var groups = std.ArrayList([]Change).init(allocator);
    defer groups.deinit();
    var active_change: ?[]Change = null;
    for (changes.items) |ch, i| {
        switch (ch.operation) {
            .Addition, .Deletion => {
                if (active_change == null) {
                    active_change = changes.items[i..];
                }
            },
            .Nothing => {
                if (active_change) |*ac| {
                    ac.* = ac.*[0..(i - (changes.items.len - ac.*.len))];
                    try groups.append(ac.*);
                    active_change = null;
                }
            },
        }
    }
    if (active_change) |*ac| {
        ac.* = ac.*[0..(changes.items.len - (changes.items.len - ac.*.len))];
        try groups.append(ac.*);
    }

    // The LCS algorithm works "in reverse", so we're putting everything back
    // in ascending order
    var a_lines = std.mem.split(u8, a, "\n");
    std.mem.reverse([]Change, groups.items);
    for (groups.items) |group| std.mem.reverse(Change, group);

    var edit_results = std.ArrayList(Edit).init(allocator);
    errdefer edit_results.deinit();

    // Convert our grouped changes into `Edit`s
    for (groups.items) |group| {
        var range_start = group[0].pos;
        var range_len: usize = 0;
        var newText = std.ArrayList(u8).init(allocator);
        _ = range_start;
        _ = range_len;
        for (group) |ch| {
            switch (ch.operation) {
                .Addition => try newText.append(ch.value.?),
                .Deletion => range_len += 1,
                else => {},
            }
        }
        var range = try char_pos_to_range(
            &a_lines,
            a_trim_offset + range_start,
            a_trim_offset + range_start + range_len,
        );
        a_lines.reset();
        try edit_results.append(Edit{
            .range = range,
            .newText = newText,
        });
    }

    return edit_results;
}

fn recur_changes(
    lcs: *Array2D,
    changes: *std.ArrayList(Change),
    a: []const u8,
    b: []const u8,
    i: i64,
    j: i64,
) anyerror!void {
    // This function recursively works backwards through the LCS table in
    // order to figure out what kind of changes took place to transform `a`
    // into `b`

    const ii = @intCast(usize, i);
    const jj = @intCast(usize, j);

    if (i > 0 and j > 0 and a[ii - 1] == b[jj - 1]) {
        try changes.append(.{
            .operation = .Nothing,
            .pos = ii - 1,
            .value = null,
        });
        try recur_changes(lcs, changes, a, b, i - 1, j - 1);
    } else if (j > 0 and (i == 0 or lcs.get(ii, jj - 1).* >= lcs.get(ii - 1, jj).*)) {
        try changes.append(.{
            .operation = .Addition,
            .pos = ii,
            .value = b[jj - 1],
        });
        try recur_changes(lcs, changes, a, b, i, j - 1);
    } else if (i > 0 and (j == 0 or lcs.get(ii, jj - 1).* < lcs.get(ii - 1, jj).*)) {
        try changes.append(.{
            .operation = .Deletion,
            .pos = ii - 1,
            .value = a[ii - 1],
        });
        try recur_changes(lcs, changes, a, b, i - 1, j);
    }
}

/// Accept a range that is solely based on buffer/character position and
/// convert it to line number & character position range
fn char_pos_to_range(
    lines: *std.mem.SplitIterator(u8),
    start: usize,
    end: usize,
) !types.Range {
    var char_pos: usize = 0;
    var line_pos: usize = 0;
    var result_start_pos: ?types.Position = null;
    var result_end_pos: ?types.Position = null;

    while (lines.next()) |line| : ({
        char_pos += line.len + 1;
        line_pos += 1;
    }) {
        if (start >= char_pos and start <= char_pos + line.len) {
            result_start_pos = .{
                .line = @intCast(i64, line_pos),
                .character = @intCast(i64, start - char_pos),
            };
        }
        if (end >= char_pos and end <= char_pos + line.len) {
            result_end_pos = .{
                .line = @intCast(i64, line_pos),
                .character = @intCast(i64, end - char_pos),
            };
        }
    }

    if (result_start_pos == null) return error.InvalidRange;

    // If we did not find an end position, it is outside the range of the
    // string for some reason so clamp it to the string end position
    if (result_end_pos == null) {
        result_end_pos = types.Position{
            .line = @intCast(i64, line_pos),
            .character = @intCast(i64, char_pos),
        };
    }

    return types.Range{
        .start = result_start_pos.?,
        .end = result_end_pos.?,
    };
}
