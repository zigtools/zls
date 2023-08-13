//! Configuration options related to a specific `BuildFile`.
const std = @import("std");

const Self = @This();

pub const BuildOption = struct {
    name: []const u8,
    value: ?[]const u8 = null,

    /// Duplicates the `BuildOption`, copying internal strings. Caller owns returned option with contents
    /// allocated using `allocator`.
    pub fn dupe(self: BuildOption, allocator: std.mem.Allocator) !BuildOption {
        const copy_name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(copy_name);
        const copy_value = if (self.value) |val|
            try allocator.dupe(u8, val)
        else
            null;
        return BuildOption{
            .name = copy_name,
            .value = copy_value,
        };
    }

    /// Formats the `BuildOption` as a command line parameter compatible with `zig build`. This will either be
    /// `-Dname=value` or `-Dname`. Caller owns returned slice allocated using `allocator`.
    pub fn formatParam(self: BuildOption, allocator: std.mem.Allocator) ![]const u8 {
        if (self.value) |val| {
            return try std.fmt.allocPrint(allocator, "-D{s}={s}", .{ self.name, val });
        } else {
            return try std.fmt.allocPrint(allocator, "-D{s}", .{self.name});
        }
    }
};

/// If provided this path is used when resolving `@import("builtin")`
/// It is relative to the directory containing the `build.zig`
///
/// This file should contain the output of:
/// `zig build-exe/build-lib/build-obj --show-builtin <options>`
relative_builtin_path: ?[]const u8 = null,

/// If provided, this list of options will be passed to `build.zig`.
build_options: ?[]BuildOption = null,
