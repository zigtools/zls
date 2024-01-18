const std = @import("std");
const zls = @import("zls");

const offsets = zls.offsets;

/// returns an array of all placeholder locations
pub fn collectPlaceholderLocs(allocator: std.mem.Allocator, source: []const u8) ![]offsets.Loc {
    var locations = std.ArrayListUnmanaged(offsets.Loc){};
    errdefer locations.deinit(allocator);

    var source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        const end_index = 1 + (std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid);

        try locations.append(allocator, .{
            .start = start_index,
            .end = end_index,
        });

        source_index = end_index;
    }

    return locations.toOwnedSlice(allocator);
}

/// returns `source` where every placeholder is replaced with `new_name`
pub fn replacePlaceholders(allocator: std.mem.Allocator, source: []const u8, new_name: []const u8) ![]const u8 {
    var output = std.ArrayListUnmanaged(u8){};
    errdefer output.deinit(allocator);

    var source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        try output.appendSlice(allocator, source[source_index..start_index]);
        try output.appendSlice(allocator, new_name);

        source_index = 1 + (std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid);
    }
    try output.appendSlice(allocator, source[source_index..source.len]);

    return output.toOwnedSlice(allocator);
}

/// returns `source` without any placeholders
pub fn clearPlaceholders(allocator: std.mem.Allocator, source: []const u8) ![]const u8 {
    return replacePlaceholders(allocator, source, "");
}

pub const CollectPlaceholdersResult = struct {
    /// list of all placeholder with old and new location
    locations: std.MultiArrayList(LocPair),
    /// equivalent to calling `replacePlaceholders(source, new_name)`
    new_source: []const u8,

    pub const LocPair = struct {
        /// placeholder location relative to the `source` parameter
        old: offsets.Loc,
        /// placeholder location relative to `new_source`
        new: offsets.Loc,
    };

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.locations.deinit(allocator);
        allocator.free(self.new_source);
    }
};

pub fn collectClearPlaceholders(allocator: std.mem.Allocator, source: []const u8) !CollectPlaceholdersResult {
    return collectReplacePlaceholders(allocator, source, "");
}

pub fn collectReplacePlaceholders(allocator: std.mem.Allocator, source: []const u8, new_name: []const u8) !CollectPlaceholdersResult {
    var locations = std.MultiArrayList(CollectPlaceholdersResult.LocPair){};
    errdefer locations.deinit(allocator);

    var new_source = std.ArrayListUnmanaged(u8){};
    errdefer new_source.deinit(allocator);

    var source_index: usize = 0;
    var new_source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        const end_index = 1 + (std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid);

        const old_loc: offsets.Loc = .{
            .start = start_index,
            .end = end_index,
        };
        defer source_index = old_loc.end;

        const text = source[source_index..start_index];

        const new_loc: offsets.Loc = .{
            .start = new_source_index + text.len,
            .end = new_source_index + text.len + new_name.len,
        };
        defer new_source_index = new_loc.end;

        try locations.append(allocator, .{
            .old = old_loc,
            .new = new_loc,
        });
        try new_source.appendSlice(allocator, text);
        try new_source.appendSlice(allocator, new_name);
    }
    try new_source.appendSlice(allocator, source[source_index..source.len]);

    return CollectPlaceholdersResult{
        .locations = locations,
        .new_source = try new_source.toOwnedSlice(allocator),
    };
}

fn testCollectReplacePlaceholders(
    source: []const u8,
    expected_source: []const u8,
    expected_old_locs: []const offsets.Loc,
    expected_new_locs: []const offsets.Loc,
) !void {
    const allocator = std.testing.allocator;
    const new_name = "foo";

    var result = try collectReplacePlaceholders(allocator, source, new_name);
    defer result.deinit(allocator);

    const expected_old_locs2 = try collectPlaceholderLocs(allocator, source);
    defer allocator.free(expected_old_locs2);

    const expected_source2 = try replacePlaceholders(allocator, source, new_name);
    defer allocator.free(expected_source2);

    try std.testing.expectEqualStrings(expected_source, expected_source2);
    try std.testing.expectEqualSlices(offsets.Loc, expected_old_locs, expected_old_locs2);

    try std.testing.expectEqualStrings(expected_source, result.new_source);
    try std.testing.expectEqualSlices(offsets.Loc, expected_old_locs, result.locations.items(.old));
    try std.testing.expectEqualSlices(offsets.Loc, expected_new_locs, result.locations.items(.new));
}

test "helper - collectReplacePlaceholders" {
    try testCollectReplacePlaceholders("", "", &.{}, &.{});
    try testCollectReplacePlaceholders("text", "text", &.{}, &.{});

    try testCollectReplacePlaceholders("<>", "foo", &.{
        .{ .start = 0, .end = 2 },
    }, &.{
        .{ .start = 0, .end = 3 },
    });

    try testCollectReplacePlaceholders("a<>b", "afoob", &.{
        .{ .start = 1, .end = 3 },
    }, &.{
        .{ .start = 1, .end = 4 },
    });

    try testCollectReplacePlaceholders("<><>", "foofoo", &.{
        .{ .start = 0, .end = 2 },
        .{ .start = 2, .end = 4 },
    }, &.{
        .{ .start = 0, .end = 3 },
        .{ .start = 3, .end = 6 },
    });
}

pub const AnnotatedSourceLoc = struct {
    loc: offsets.Loc,
    content: []const u8,
};

/// extract a list of special comment from a source file
/// **Example**
/// ```
/// Some text where we want to highlight some locations
/// //   ^^^^ some content
/// in the text file.
/// //          ^^^^ something else here
/// ```
/// passing the above content to this function will yield the following:
/// ```zig
/// [2]AnnotatedSourceLoc{
///     .{
///         .loc = .{ .start = 5, .end = 9 }, // this is the location of `text` in the source
///         .content = "some content",
///     },
///     .{
///         .loc = .{ .start = 87, .end = 91 }, // this is the location of `file` in the source
///         .content = "something else here",
///     },
/// },
/// ```
pub fn collectAnnotatedSourceLocations(allocator: std.mem.Allocator, source: []const u8) error{ OutOfMemory, InvalidSourceLoc }![]AnnotatedSourceLoc {
    var items = std.ArrayListUnmanaged(AnnotatedSourceLoc){};
    errdefer items.deinit(allocator);

    var i: usize = 0;
    while (i < source.len) {
        defer i = std.mem.indexOfScalarPos(u8, source, i, '\n') orelse source.len;

        i = skipWhitespace(source, i);
        if (!std.mem.startsWith(u8, source[i..], "//")) continue;
        i += 2;

        i = skipWhitespace(source, i);
        if (!std.mem.startsWith(u8, source[i..], "^")) continue;
        var loc: offsets.Loc = .{ .start = i, .end = undefined };
        i += 1;
        while (i < source.len) : (i += 1) {
            if (source[i] != '^') break;
        }
        loc.end = i;

        const content_start = i;
        const content_end = std.mem.indexOfScalarPos(u8, source, i, '\n') orelse source.len;
        const content = source[content_start..content_end];

        const loc_length = offsets.locLength(source, loc, .@"utf-8");
        const start_pos = offsets.indexToPosition(source, loc.start, .@"utf-8");
        if (start_pos.line == 0) return error.InvalidSourceLoc; // there is no previous line

        var previous_line_start_pos = start_pos;
        previous_line_start_pos.line -= 1;
        const previous_line_start_index = offsets.positionToIndex(source, previous_line_start_pos, .@"utf-8");

        const previous_line_loc = offsets.Loc{
            .start = previous_line_start_index,
            .end = previous_line_start_index + loc_length,
        };

        if (previous_line_loc.end >= source.len) return error.InvalidSourceLoc;
        if (std.mem.indexOfScalar(u8, offsets.locToSlice(source, previous_line_loc), '\n') != null) return error.InvalidSourceLoc;

        try items.append(allocator, .{
            .loc = previous_line_loc,
            .content = std.mem.trim(u8, content, &std.ascii.whitespace),
        });
    }
    return items.toOwnedSlice(allocator);
}

fn testCollectAnnotatedSourceLocations(
    source: []const u8,
    expected: []const AnnotatedSourceLoc,
) !void {
    const allocator = std.testing.allocator;
    const actual = try collectAnnotatedSourceLocations(allocator, source);
    defer allocator.free(actual);

    if (expected.len == actual.len) failed: {
        for (expected, actual) |expected_item, actual_item| {
            if (!std.meta.eql(expected_item.loc, actual_item.loc)) break :failed;
            if (!std.mem.eql(u8, expected_item.content, actual_item.content)) break :failed;
        }
        return;
    }
    try std.testing.expectEqualSlices(AnnotatedSourceLoc, expected, actual);
    unreachable; // expectEqualSlices is supposed to fail
}

test "helper - collectAnnotatedSourceLocations" {
    const allocator = std.testing.allocator;

    try testCollectAnnotatedSourceLocations("", &.{});
    try testCollectAnnotatedSourceLocations("hello", &.{});
    try testCollectAnnotatedSourceLocations(
        \\ hello
        \\^^^^ world
        \\// and goodbye
    , &.{});
    try testCollectAnnotatedSourceLocations(
        \\hello world
        \\//    ^^^^^ here
    , &[_]AnnotatedSourceLoc{
        .{ .loc = .{ .start = 6, .end = 11 }, .content = "here" },
    });
    try testCollectAnnotatedSourceLocations(
        \\
        \\hello   rld
        \\//    ^^^^^ here 
        \\
    , &[_]AnnotatedSourceLoc{
        .{ .loc = .{ .start = 7, .end = 12 }, .content = "here" },
    });
    try testCollectAnnotatedSourceLocations(
        \\Some text where we want to highlight some locations
        \\//   ^^^^ some content
        \\in the text file.
        \\//          ^^^^ something else here
    , &[_]AnnotatedSourceLoc{
        .{ .loc = .{ .start = 5, .end = 9 }, .content = "some content" },
        .{ .loc = .{ .start = 87, .end = 91 }, .content = "something else here" },
    });

    try std.testing.expectError(
        error.InvalidSourceLoc,
        collectAnnotatedSourceLocations(allocator,
            \\hello worl
            \\//    ^^^^^
        ),
    );
    try std.testing.expectError(
        error.InvalidSourceLoc,
        collectAnnotatedSourceLocations(allocator,
            \\//    ^^^^^
        ),
    );
}

fn skipWhitespace(source: []const u8, pos: usize) usize {
    var i = pos;
    while (i < source.len) : (i += 1) {
        if (std.mem.indexOfScalar(u8, &std.ascii.whitespace, source[i]) == null) break;
    }
    return i;
}
