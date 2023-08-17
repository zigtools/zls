pub const BuildConfig = @This();

packages: []Pkg,
include_dirs: []const []const u8,

pub const Pkg = struct {
    name: []const u8,
    path: []const u8,
};
