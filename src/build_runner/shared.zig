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
    pub const AvailableOption = std.meta.FieldType(std.meta.FieldType(std.Build, .available_options_map).KV, .value);
};

pub const Transport = struct {
    in: std.fs.File,
    out: std.fs.File,
    poller: std.io.Poller(StreamEnum),

    const StreamEnum = enum { in };

    pub const Header = extern struct {
        tag: u32,
        /// Size of the body only; does not include this Header.
        bytes_len: u32,
    };

    pub const Options = struct {
        gpa: std.mem.Allocator,
        in: std.fs.File,
        out: std.fs.File,
    };

    pub fn init(options: Options) Transport {
        return .{
            .in = options.in,
            .out = options.out,
            .poller = std.io.poll(options.gpa, StreamEnum, .{ .in = options.in }),
        };
    }

    pub fn deinit(transport: *Transport) void {
        transport.poller.deinit();
        transport.* = undefined;
    }

    pub fn receiveMessage(transport: *Transport, timeout_ns: ?u64) !Header {
        const fifo = transport.poller.fifo(.in);

        poll: while (true) {
            while (fifo.readableLength() < @sizeOf(Header)) {
                if (!(if (timeout_ns) |timeout| try transport.poller.pollTimeout(timeout) else try transport.poller.poll())) break :poll;
            }
            const header = fifo.reader().readStructEndian(Header, .little) catch unreachable;
            while (fifo.readableLength() < header.bytes_len) {
                if (!(if (timeout_ns) |timeout| try transport.poller.pollTimeout(timeout) else try transport.poller.poll())) break :poll;
            }
            return header;
        }
        return error.EndOfStream;
    }

    pub fn reader(transport: *Transport) std.io.PollFifo.Reader {
        return transport.poller.fifo(.in).reader();
    }

    pub fn discard(transport: *Transport, bytes: usize) void {
        transport.poller.fifo(.in).discard(bytes);
    }

    pub fn receiveBytes(
        transport: *Transport,
        allocator: std.mem.Allocator,
        len: usize,
    ) (std.mem.Allocator.Error || std.fs.File.ReadError || error{EndOfStream})![]u8 {
        return try transport.receiveSlice(allocator, u8, len);
    }

    pub fn receiveSlice(
        transport: *Transport,
        allocator: std.mem.Allocator,
        comptime T: type,
        len: usize,
    ) (std.mem.Allocator.Error || std.fs.File.ReadError || error{EndOfStream})![]T {
        const bytes = try allocator.alignedAlloc(u8, .of(T), len * @sizeOf(T));
        errdefer allocator.free(bytes);
        const amt = try transport.reader().readAll(bytes);
        if (amt != len * @sizeOf(T)) return error.EndOfStream;
        const result = std.mem.bytesAsSlice(T, bytes);
        std.debug.assert(result.len == len);
        if (need_bswap) {
            for (result) |*item| {
                item.* = @byteSwap(item.*);
            }
        }
        return result;
    }

    pub fn serveMessage(
        client: *const Transport,
        header: Header,
        bufs: []const []const u8,
    ) std.fs.File.WriteError!void {
        std.debug.assert(bufs.len < 10);
        var iovecs: [10]std.posix.iovec_const = undefined;
        var header_le = header;
        if (need_bswap) std.mem.byteSwapAllFields(Header, &header_le);
        const header_bytes = std.mem.asBytes(&header_le);
        iovecs[0] = .{ .base = header_bytes.ptr, .len = header_bytes.len };
        for (bufs, iovecs[1 .. bufs.len + 1]) |buf, *iovec| {
            iovec.* = .{
                .base = buf.ptr,
                .len = buf.len,
            };
        }
        try client.out.writevAll(iovecs[0 .. bufs.len + 1]);
    }
};

pub const ServerToClient = struct {
    pub const Tag = enum(u32) {
        /// Body is an ErrorBundle.
        watch_error_bundle,

        _,
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
    invalid_linux_kernel_version: if (builtin.os.tag == .linux) std.meta.FieldType(std.posix.utsname, .release) else noreturn,
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
    try std.testing.expectFmt("5.17.0", "{}", .{try parseUnameKernelVersion("5.17.0")});
    try std.testing.expectFmt("6.12.9", "{}", .{try parseUnameKernelVersion("6.12.9-rc7")});
    try std.testing.expectFmt("6.6.71", "{}", .{try parseUnameKernelVersion("6.6.71-42-generic")});
    try std.testing.expectFmt("5.15.167", "{}", .{try parseUnameKernelVersion("5.15.167.4-microsoft-standard-WSL2")}); // WSL2
    try std.testing.expectFmt("4.4.0", "{}", .{try parseUnameKernelVersion("4.4.0-20241-Microsoft")}); // WSL1

    try std.testing.expectError(error.InvalidCharacter, parseUnameKernelVersion(""));
    try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5"));
    try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5.5"));
}
