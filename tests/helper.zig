const std = @import("std");

pub const Placeholder = struct {
    loc: Loc,

    pub const Loc = std.zig.Token.Loc;

    pub fn placeholderSlice(self: Placeholder, source: []const u8) []const u8 {
        return source[self.loc.start..self.loc.end];
    }
};

/// returns an array of all placeholder locations
pub fn collectPlaceholder(allocator: std.mem.Allocator, source: []const u8) ![]Placeholder {
    var placeholders = std.ArrayListUnmanaged(Placeholder){};
    errdefer placeholders.deinit(allocator);

    var source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        const end_index = std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid;

        try placeholders.append(allocator, .{ .loc = .{
            .start = start_index,
            .end = end_index,
        } });

        source_index = end_index + 1;
    }

    return placeholders.toOwnedSlice(allocator);
}

/// returns `source` without any placeholders
pub fn clearPlaceholders(allocator: std.mem.Allocator, source: []const u8) ![]const u8 {
    var output = std.ArrayListUnmanaged(u8){};
    errdefer output.deinit(allocator);

    var source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        try output.appendSlice(allocator, source[source_index..start_index]);

        source_index = std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid;
        source_index += 1;
    }
    try output.appendSlice(allocator, source[source_index..source.len]);

    return output.toOwnedSlice(allocator);
}

const CollectClearPlaceholdersResult = struct {
    /// placeholders relative to the `source` parameter in `collectClearPlaceholders`
    placeholders: []Placeholder,
    /// placeholders locations to `source`
    placeholder_locations: []usize,
    /// source without any placeholders
    source: []const u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.placeholders);
        allocator.free(self.placeholder_locations);
        allocator.free(self.source);
    }
};

/// see `CollectClearPlaceholdersResult`
pub fn collectClearPlaceholders(allocator: std.mem.Allocator, source: []const u8) !CollectClearPlaceholdersResult {
    var placeholders = std.ArrayListUnmanaged(Placeholder){};
    errdefer placeholders.deinit(allocator);

    var locations = std.ArrayListUnmanaged(usize){};
    errdefer locations.deinit(allocator);

    var new_source = std.ArrayListUnmanaged(u8){};
    errdefer new_source.deinit(allocator);

    var source_index: usize = 0;
    var new_source_index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, source_index, '<')) |start_index| {
        const end_index = std.mem.indexOfScalarPos(u8, source, start_index + 1, '>') orelse return error.Invalid;

        const placeholder = Placeholder{ .loc = .{
            .start = start_index + 1,
            .end = end_index,
        } };

        try placeholders.append(allocator, placeholder);

        new_source_index = new_source_index + (start_index - source_index);
        try locations.append(allocator, new_source_index);
        try new_source.appendSlice(allocator, source[source_index..start_index]);

        source_index = end_index + 1;
    }
    try new_source.appendSlice(allocator, source[source_index..source.len]);

    return CollectClearPlaceholdersResult{
        .placeholders = placeholders.toOwnedSlice(allocator),
        .placeholder_locations = locations.toOwnedSlice(allocator),
        .source = new_source.toOwnedSlice(allocator),
    };
}

