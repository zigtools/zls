//! modified version of https://github.com/ziglang/zig/blob/master/lib/std/zig/Server.zig
//! I don't know why but this code seems to work
//! zig binary serialization library in stdlib, when?

in: std.fs.File,
out: std.fs.File,
pooler: std.io.Poller(StreamEnum),

const StreamEnum = enum { in };

pub const Options = struct {
    gpa: Allocator,
    in: std.fs.File,
    out: std.fs.File,
};

pub fn init(options: Options) Client {
    var s: Client = .{
        .in = options.in,
        .out = options.out,
        .pooler = std.io.poll(options.gpa, StreamEnum, .{ .in = options.in }),
    };
    return s;
}

pub fn deinit(s: *Client) void {
    s.pooler.deinit();
    s.* = undefined;
}

pub fn receiveMessage(client: *Client) !InMessage.Header {
    const Header = InMessage.Header;
    const fifo = client.pooler.fifo(.in);

    var first_run = true;
    var header: ?Header = null;
    while (first_run or try client.pooler.poll()) {
        first_run = false;

        if (header == null) {
            if (fifo.readableLength() < @sizeOf(Header)) continue;
            const buf = fifo.readableSlice(0);
            const bytes_len = bswap_and_workaround_u32(buf[4..][0..4]);
            const tag = bswap_and_workaround_tag(buf[0..][0..4]);
            header = Header{
                .tag = tag,
                .bytes_len = bytes_len,
            };
            fifo.discard(@sizeOf(Header));
        }

        if (header) |h| {
            if (fifo.readableLength() < h.bytes_len) continue;
            return h;
        }
    }
    return error.Timeout;
}

pub fn receiveEmitBinPath(client: *Client) !InMessage.EmitBinPath {
    const reader = client.pooler.fifo(.in).reader();
    return reader.readStruct(InMessage.EmitBinPath);
}

pub fn receiveErrorBundle(client: *Client) !InMessage.ErrorBundle {
    const reader = client.pooler.fifo(.in).reader();
    return .{
        .extra_len = try reader.readIntLittle(u32),
        .string_bytes_len = try reader.readIntLittle(u32),
    };
}

pub fn receiveBytes(client: *Client, allocator: std.mem.Allocator, len: usize) ![]u8 {
    const reader = client.pooler.fifo(.in).reader();
    const result = try allocator.alloc(u8, len);
    errdefer allocator.free(result);
    const amt = try reader.readAll(result);
    if (amt != len) return error.UnexpectedEOF;
    return result;
}

pub fn receiveIntArray(client: *Client, allocator: std.mem.Allocator, len: usize) ![]u32 {
    const reader = client.pooler.fifo(.in).reader();
    const bytes = try allocator.alignedAlloc(u8, @alignOf(u32), len * @sizeOf(u32));
    errdefer allocator.free(bytes);
    const amt = try reader.readAll(bytes);
    if (amt != bytes.len) return error.UnexpectedEOF;
    const result = std.mem.bytesAsSlice(u32, bytes);
    if (need_bswap) {
        bswap_u32_array(result);
    }
    return result;
}

pub fn serveMessage(
    client: *const Client,
    header: OutMessage.Header,
    bufs: []const []const u8,
) !void {
    var iovecs: [10]std.os.iovec_const = undefined;
    const header_le = bswap(header);
    iovecs[0] = .{
        .iov_base = @as([*]const u8, @ptrCast(&header_le)),
        .iov_len = @sizeOf(OutMessage.Header),
    };
    for (bufs, iovecs[1 .. bufs.len + 1]) |buf, *iovec| {
        iovec.* = .{
            .iov_base = buf.ptr,
            .iov_len = buf.len,
        };
    }
    try client.out.writevAll(iovecs[0 .. bufs.len + 1]);
}

fn bswap(x: anytype) @TypeOf(x) {
    if (!need_bswap) return x;

    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .Enum => return @as(T, @enumFromInt(@byteSwap(@intFromEnum(x)))),
        .Int => return @byteSwap(x),
        .Struct => |info| switch (info.layout) {
            .Extern => {
                var result: T = undefined;
                inline for (info.fields) |field| {
                    @field(result, field.name) = bswap(@field(x, field.name));
                }
                return result;
            },
            .Packed => {
                const I = info.backing_integer.?;
                return @as(T, @bitCast(@byteSwap(@as(I, @bitCast(x)))));
            },
            .Auto => @compileError("auto layout struct"),
        },
        else => @compileError("bswap on type " ++ @typeName(T)),
    }
}

fn bswap_u32_array(slice: []u32) void {
    comptime assert(need_bswap);
    for (slice) |*elem| elem.* = @byteSwap(elem.*);
}

/// workaround for https://github.com/ziglang/zig/issues/14904
fn bswap_and_workaround_u32(bytes_ptr: *const [4]u8) u32 {
    return std.mem.readIntLittle(u32, bytes_ptr);
}

/// workaround for https://github.com/ziglang/zig/issues/14904
fn bswap_and_workaround_tag(bytes_ptr: *const [4]u8) InMessage.Tag {
    const int = std.mem.readIntLittle(u32, bytes_ptr);
    return @as(InMessage.Tag, @enumFromInt(int));
}

const OutMessage = std.zig.Client.Message;
const InMessage = std.zig.Server.Message;

const Client = @This();
const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const native_endian = builtin.target.cpu.arch.endian();
const need_bswap = native_endian != .Little;
