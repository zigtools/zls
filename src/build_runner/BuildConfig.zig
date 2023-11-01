pub const BuildConfig = @This();

deps_build_roots: []DepsBuildRoots,
packages: []Pkg,
include_dirs: []const []const u8,

pub const DepsBuildRoots = Pkg;
pub const Pkg = struct {
    name: []const u8,
    path: []const u8,
};
