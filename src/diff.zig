//! Text diffing between source files.

const std = @import("std");
const types = @import("lsp").types;
const offsets = @import("offsets.zig");
const tracy = @import("tracy");
const DiffMatchPatch = @import("diffz");

const dmp: DiffMatchPatch = .{
    .diff_timeout = 250,
};

pub fn edits(
    allocator: std.mem.Allocator,
    before: []const u8,
    after: []const u8,
    encoding: offsets.Encoding,
) error{OutOfMemory}!std.ArrayList(types.TextEdit) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var diffs = try dmp.diff(allocator, before, after, true);
    defer DiffMatchPatch.deinitDiffList(allocator, &diffs);

    var edit_count: usize = 0;
    for (diffs.items) |diff| {
        switch (diff.operation) {
            .delete => edit_count += 1,
            .equal => continue,
            .insert => edit_count += 1,
        }
    }

    var eds: std.ArrayList(types.TextEdit) = try .initCapacity(allocator, edit_count);
    errdefer {
        for (eds.items) |edit| allocator.free(edit.newText);
        eds.deinit(allocator);
    }

    var offset: usize = 0;
    for (diffs.items) |diff| {
        const start = offset;
        switch (diff.operation) {
            .delete => {
                offset += diff.text.len;
                eds.appendAssumeCapacity(.{
                    .range = offsets.locToRange(before, .{ .start = start, .end = offset }, encoding),
                    .newText = "",
                });
            },
            .equal => {
                offset += diff.text.len;
            },
            .insert => {
                eds.appendAssumeCapacity(.{
                    .range = offsets.locToRange(before, .{ .start = start, .end = start }, encoding),
                    .newText = try allocator.dupe(u8, diff.text),
                });
            },
        }
    }
    return eds;
}

/// Caller owns returned memory.
pub fn applyContentChanges(
    allocator: std.mem.Allocator,
    text: []const u8,
    content_changes: []const types.TextDocumentContentChangeEvent,
    encoding: offsets.Encoding,
) error{OutOfMemory}![:0]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const last_full_text_index, const last_full_text = blk: {
        var i: usize = content_changes.len;
        while (i != 0) {
            i -= 1;
            switch (content_changes[i]) {
                .literal_1 => |content_change| break :blk .{ i, content_change.text }, // TextDocumentContentChangeWholeDocument
                .literal_0 => continue, // TextDocumentContentChangePartial
            }
        }
        break :blk .{ null, text };
    };

    var text_array: std.ArrayList(u8) = .empty;
    errdefer text_array.deinit(allocator);

    try text_array.appendSlice(allocator, last_full_text);

    // don't even bother applying changes before a full text change
    const changes = content_changes[if (last_full_text_index) |index| index + 1 else 0..];

    for (changes) |item| {
        const content_change = item.literal_0; // TextDocumentContentChangePartial

        const loc = offsets.rangeToLoc(text_array.items, content_change.range, encoding);
        try text_array.replaceRange(allocator, loc.start, loc.end - loc.start, content_change.text);
    }

    return try text_array.toOwnedSliceSentinel(allocator, 0);
}

// https://cs.opensource.google/go/x/tools/+/master:internal/lsp/diff/diff.go;l=40

fn textEditLessThan(_: void, lhs: types.TextEdit, rhs: types.TextEdit) bool {
    return offsets.orderPosition(lhs.range.start, rhs.range.start) == .lt or offsets.orderPosition(lhs.range.end, rhs.range.end) == .lt;
}

/// Caller owns returned memory.
pub fn applyTextEdits(
    allocator: std.mem.Allocator,
    text: []const u8,
    text_edits: []const types.TextEdit,
    encoding: offsets.Encoding,
) ![]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const text_edits_sortable = try allocator.dupe(types.TextEdit, text_edits);
    defer allocator.free(text_edits_sortable);

    std.mem.sort(types.TextEdit, text_edits_sortable, {}, textEditLessThan);

    var final_text: std.ArrayList(u8) = .empty;
    errdefer final_text.deinit(allocator);

    var last: usize = 0;
    for (text_edits_sortable) |te| {
        const start = offsets.positionToIndex(text, te.range.start, encoding);
        if (start > last) {
            try final_text.appendSlice(allocator, text[last..start]);
            last = start;
        }
        try final_text.appendSlice(allocator, te.newText);
        last = offsets.positionToIndex(text, te.range.end, encoding);
    }
    if (last < text.len) {
        try final_text.appendSlice(allocator, text[last..]);
    }

    return try final_text.toOwnedSlice(allocator);
}
