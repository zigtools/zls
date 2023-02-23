const std = @import("std");
const Self = @This();

// This is necessary as `std.SemanticVersion` keeps pointers into the parsed string

version: std.SemanticVersion,

allocator: std.mem.Allocator,
raw_string: []const u8,

pub fn free(self: Self) void {
    self.allocator.free(self.raw_string);
}
