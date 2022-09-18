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

const CollectPlaceholdersResult = struct {
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
        .new_source = new_source.toOwnedSlice(allocator),
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
