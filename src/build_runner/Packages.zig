const std = @import("std");
const BuildConfig = @import("BuildConfig.zig");

const Packages = @This();

allocator: std.mem.Allocator,

/// Outer key is the package name, inner key is the file path.
packages: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .{},

/// Returns true if the package was already present.
pub fn addPackage(self: *Packages, name: []const u8, path: []const u8) !bool {
    const name_gop_result = try self.packages.getOrPut(self.allocator, name);
    if (!name_gop_result.found_existing) {
        name_gop_result.value_ptr.* = .{};
    }

    const path_gop_result = try name_gop_result.value_ptr.getOrPut(self.allocator, path);
    return path_gop_result.found_existing;
}

pub fn toPackageList(self: *Packages) ![]BuildConfig.Pkg {
    var result: std.ArrayListUnmanaged(BuildConfig.Pkg) = .{};
    errdefer result.deinit(self.allocator);

    var name_iter = self.packages.iterator();
    while (name_iter.next()) |path_hashmap| {
        var path_iter = path_hashmap.value_ptr.iterator();
        while (path_iter.next()) |path| {
            try result.append(self.allocator, .{ .name = path_hashmap.key_ptr.*, .path = path.key_ptr.* });
        }
    }

    return try result.toOwnedSlice(self.allocator);
}

pub fn deinit(self: *Packages) void {
    var outer_iter = self.packages.iterator();
    while (outer_iter.next()) |inner| {
        inner.value_ptr.deinit(self.allocator);
    }
    self.packages.deinit(self.allocator);
}
