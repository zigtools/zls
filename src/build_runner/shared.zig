//! Contains shared code between ZLS and it's custom build runner

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const need_bswap = native_endian != .little;

pub const BuildConfig = struct {
    deps_build_roots: []DepsBuildRoots,
    packages: []Package,
    include_dirs: []const []const u8,
    top_level_steps: []const []const u8,
    available_options: std.json.ArrayHashMap(AvailableOption),
    c_macros: []const []const u8 = &.{},

    pub const DepsBuildRoots = Package;
    pub const Package = struct {
        name: []const u8,
        path: []const u8,
    };
    pub const AvailableOption = @FieldType(@FieldType(std.Build, "available_options_map").KV, "value");
};

pub const ServerToClient = struct {
    pub const Header = extern struct {
        tag: Tag,
        bytes_len: u32,

        pub const Tag = enum(u32) {
            /// Body is an ErrorBundle.
            watch_error_bundle,

            _,
        };
    };

    /// Trailing:
    /// * extra: [extra_len]u32,
    /// * string_bytes: [string_bytes_len]u8,
    /// See `std.zig.ErrorBundle`.
    pub const ErrorBundle = extern struct {
        step_id: u32,
        cycle: u32,
        extra_len: u32,
        string_bytes_len: u32,
    };
};

pub const BuildOnSaveSupport = union(enum) {
    supported,
    invalid_linux_kernel_version: if (builtin.os.tag == .linux) @FieldType(std.posix.utsname, "release") else noreturn,
    unsupported_linux_kernel_version: if (builtin.os.tag == .linux) std.SemanticVersion else noreturn,
    unsupported_zig_version: if (@TypeOf(os_support) == std.SemanticVersion) void else noreturn,
    unsupported_os: if (@TypeOf(os_support) == bool and !os_support) void else noreturn,

    // We can't rely on `std.Build.Watch.have_impl` because we need to
    // check the runtime Zig version instead of Zig version that ZLS
    // has been built with.
    pub const os_support = switch (builtin.os.tag) {
        .linux,
        .windows,
        .dragonfly,
        .freebsd,
        .netbsd,
        .openbsd,
        .ios,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        .haiku,
        => true,
        else => false,
    };

    /// std.build.Watch requires `AT_HANDLE_FID` which is Linux 6.5+
    /// https://github.com/ziglang/zig/issues/20720
    pub const minimum_linux_version: std.SemanticVersion = .{ .major = 6, .minor = 5, .patch = 0 };

    /// Returns true if is comptime known that build on save is supported.
    pub inline fn isSupportedComptime() bool {
        if (!std.process.can_spawn) return false;
        if (builtin.single_threaded) return false;
        return true;
    }

    pub fn isSupportedRuntime(runtime_zig_version: std.SemanticVersion) BuildOnSaveSupport {
        comptime std.debug.assert(isSupportedComptime());

        if (builtin.os.tag == .linux) blk: {
            const utsname = std.posix.uname();
            const unparsed_version = std.mem.sliceTo(&utsname.release, 0);
            const version = parseUnameKernelVersion(unparsed_version) catch
                return .{ .invalid_linux_kernel_version = utsname.release };

            if (version.order(minimum_linux_version) != .lt) break :blk;
            std.debug.assert(version.build == null and version.pre == null); // Otherwise, returning the `std.SemanticVersion` would be unsafe
            return .{
                .unsupported_linux_kernel_version = version,
            };
        }

        switch (@TypeOf(os_support)) {
            bool => {
                if (!os_support) {
                    return .unsupported_os;
                }
            },
            std.SemanticVersion => {
                if (runtime_zig_version.order(os_support) == .lt) {
                    return .unsupported_zig_version;
                }
            },
            else => unreachable,
        }

        return .supported;
    }
};

/// Parses a Linux Kernel Version. The result will ignore pre-release and build metadata.
fn parseUnameKernelVersion(kernel_version: []const u8) !std.SemanticVersion {
    const extra_index = std.mem.indexOfAny(u8, kernel_version, "-+");
    const required = kernel_version[0..(extra_index orelse kernel_version.len)];
    var it = std.mem.splitScalar(u8, required, '.');
    return .{
        .major = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
        .minor = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
        .patch = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
    };
}

test parseUnameKernelVersion {
    try std.testing.expectFmt("5.17.0", "{f}", .{try parseUnameKernelVersion("5.17.0")});
    try std.testing.expectFmt("6.12.9", "{f}", .{try parseUnameKernelVersion("6.12.9-rc7")});
    try std.testing.expectFmt("6.6.71", "{f}", .{try parseUnameKernelVersion("6.6.71-42-generic")});
    try std.testing.expectFmt("5.15.167", "{f}", .{try parseUnameKernelVersion("5.15.167.4-microsoft-standard-WSL2")}); // WSL2
    try std.testing.expectFmt("4.4.0", "{f}", .{try parseUnameKernelVersion("4.4.0-20241-Microsoft")}); // WSL1

    try std.testing.expectError(error.InvalidCharacter, parseUnameKernelVersion(""));
    try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5"));
    try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5.5"));
}
