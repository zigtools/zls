//! Type definition for the per-project `zls.build.json` configuration file.

const std = @import("std");

pub const BuildOption = struct {
    name: []const u8,
    value: ?[]const u8 = null,

    /// Duplicates the `BuildOption`, copying internal strings. Caller owns returned option with contents
    /// allocated using `allocator`.
    pub fn dupe(self: BuildOption, allocator: std.mem.Allocator) error{OutOfMemory}!BuildOption {
        const copy_name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(copy_name);
        const copy_value = if (self.value) |val|
            try allocator.dupe(u8, val)
        else
            null;
        return .{
            .name = copy_name,
            .value = copy_value,
        };
    }

    /// Formats to a CLI argument compatible with `zig build`. Either `-Dname=value` or `-Dname`.
    pub fn format(
        option: BuildOption,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        if (option.value) |val| {
            return try writer.print("-D{s}={s}", .{ option.name, val });
        } else {
            return try writer.print("-D{s}", .{option.name});
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
