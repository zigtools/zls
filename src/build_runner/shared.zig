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
        const bytes = try allocator.alignedAlloc(u8, @alignOf(T), len * @sizeOf(T));
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
