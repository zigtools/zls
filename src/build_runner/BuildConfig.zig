const std = @import("std");

deps_build_roots: []DepsBuildRoots,
packages: []Package,
include_dirs: []const []const u8,
top_level_steps: []const []const u8,
available_options: std.json.ArrayHashMap(AvailableOption),

pub const DepsBuildRoots = Package;
pub const Package = struct {
    name: []const u8,
    path: []const u8,
};
pub const AvailableOption = std.meta.FieldType(std.meta.FieldType(std.Build, .available_options_map).KV, .value);
