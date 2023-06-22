const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Index = usize;

pub fn encode(extra: *std.ArrayList(u8), comptime T: type, data: anytype) Allocator.Error!void {
    switch (@typeInfo(T)) {
        .Type,
        .NoReturn,
        .ComptimeFloat,
        .ComptimeInt,
        .Undefined,
        .Null,
        .ErrorUnion,
        .ErrorSet,
        .Fn,
        .Opaque,
        .Frame,
        .AnyFrame,
        .EnumLiteral,
        => @compileError("Unable to encode type " ++ @typeName(T)),

        .Void => {},
        .Bool => try encode(extra, u1, @intFromBool(data)),
        .Int => try extra.appendSlice(std.mem.asBytes(&data)),
        .Float => |info| switch (info.bits) {
            16 => try encode(extra, u16, @bitCast(u16, data)),
            32 => try encode(extra, u32, @bitCast(u32, data)),
            64 => try encode(extra, u64, @bitCast(u64, data)),
            80 => try encode(extra, u80, @bitCast(u80, data)),
            128 => try encode(extra, u128, @bitCast(u128, data)),
            else => @compileError("Unable to encode type " ++ @typeName(T)),
        },
        .Pointer => |info| {
            switch (info.size) {
                .One => {
                    if (comptime canEncodeAsBytes(info.child)) {
                        try extra.appendNTimes(undefined, std.mem.alignPointerOffset(extra.items.ptr + extra.items.len, info.alignment).?);
                        try encode(extra, info.child, data.*);
                    } else {
                        @compileError("Encoding " ++ @typeName(T) ++ " would require allocation");
                    }
                },
                .Slice => {
                    if (comptime canEncodeAsBytes(info.child)) {
                        try encode(extra, u32, @intCast(u32, data.len));
                        try extra.appendNTimes(undefined, std.mem.alignPointerOffset(extra.items.ptr + extra.items.len, info.alignment).?);
                        try extra.appendSlice(std.mem.sliceAsBytes(data));
                    } else {
                        @compileError("Encoding " ++ @typeName(T) ++ " would require allocation");
                    }
                },

                .Many,
                .C,
                => @compileError("Unable to encode type " ++ @typeName(T)),
            }
        },
        .Array => |info| {
            for (data) |item| {
                try encode(extra, info.child, item);
            }
        },
        .Struct => |info| {
            switch (info.layout) {
                .Packed,
                .Extern,
                => return try extra.appendSlice(std.mem.asBytes(&data)),
                .Auto => {
                    inline for (info.fields) |field| {
                        try encode(extra, field.type, @field(data, field.name));
                    }
                },
            }
        },
        .Optional => {
            try encode(extra, bool, data == null);
            if (data) |item| {
                try encode(extra, item);
            }
        },
        .Enum => |info| try encode(extra, info.tag_type, @intFromEnum(data)),
        .Union => @compileError("TODO"),
        .Vector => |info| {
            const array: [info.len]info.child = data;
            try encode(extra, array);
        },
    }
}

pub fn decode(extra: *[]const u8, comptime T: type) T {
    return switch (@typeInfo(T)) {
        .Type,
        .NoReturn,
        .ComptimeFloat,
        .ComptimeInt,
        .Undefined,
        .Null,
        .ErrorUnion,
        .ErrorSet,
        .Fn,
        .Opaque,
        .Frame,
        .AnyFrame,
        .EnumLiteral,
        => @compileError("Unable to decode type " ++ @typeName(T)),

        .Void => {},
        .Bool => decode(extra, u1) == 1,
        .Int => std.mem.bytesToValue(T, readArray(extra, @sizeOf(T))),
        .Float => |info| switch (info.bits) {
            16 => @bitCast(T, decode(extra, u16)),
            32 => @bitCast(T, decode(extra, u32)),
            64 => @bitCast(T, decode(extra, u64)),
            80 => @bitCast(T, decode(extra, u80)),
            128 => @bitCast(T, decode(extra, u128)),
            else => @compileError("Unable to decode type " ++ @typeName(T)),
        },
        .Pointer => |info| {
            switch (info.size) {
                .One => {
                    if (comptime canEncodeAsBytes(info.child)) {
                        extra.* = alignForward(extra.*, info.alignment);
                        return std.mem.bytesAsValue(T, readArray(extra, @sizeOf(info.child)));
                    } else {
                        @compileError("Decoding " ++ @typeName(T) ++ " would require allocation");
                    }
                },
                .Slice => {
                    if (comptime canEncodeAsBytes(info.child)) {
                        const len = decode(extra, u32);
                        extra.* = alignForward(extra.*, info.alignment);
                        const bytes = readBytes(extra, len * @sizeOf(info.child));
                        return std.mem.bytesAsSlice(info.child, @alignCast(info.alignment, bytes));
                    } else {
                        @compileError("Decoding " ++ @typeName(T) ++ " would require allocation");
                    }
                },

                .Many,
                .C,
                => @compileError("Unable to decode type " ++ @typeName(T)),
            }
        },
        .Array => |info| blk: {
            var array: T = undefined;
            var i: usize = 0;
            while (i < info.len) {
                array[i] = decode(extra, info.child);
            }
            break :blk array;
        },
        .Struct => |info| {
            switch (info.layout) {
                .Packed,
                .Extern,
                => return std.mem.bytesToValue(T, readArray(extra, @sizeOf(T))),
                .Auto => {
                    var result: T = undefined;
                    inline for (info.fields) |field| {
                        @field(result, field.name) = decode(extra, field.type);
                    }
                    return result;
                },
            }
        },
        .Optional => |info| blk: {
            const is_null = decode(extra, bool);
            if (is_null) {
                break :blk null;
            } else {
                break :blk decode(extra, info.child);
            }
        },
        .Enum => |info| @enumFromInt(T, decode(extra, info.tag_type)),
        .Union => @compileError("TODO"),
        .Vector => |info| decode(extra, [info.len]info.child),
    };
}

pub fn canEncodeAsBytes(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .Void, .Bool, .Int, .Float, .Enum, .Vector => true,
        .Array => |info| canEncodeAsBytes(info.child),
        .Struct => |info| info.layout != .Auto,
        .Union => |info| info.layout != .Auto,
        else => false,
    };
}

/// forward aligns `extra` until it has the given alignment
pub fn alignForward(extra: []const u8, alignment: usize) []const u8 {
    const unaligned = @intFromPtr(extra.ptr);
    const offset = std.mem.alignForward(usize, unaligned, alignment) - unaligned;
    const result = extra[offset..];
    std.debug.assert(std.mem.isAligned(@intFromPtr(result.ptr), alignment));
    return result;
}

pub fn readBytes(extra: *[]const u8, n: usize) []const u8 {
    defer extra.* = extra.*[n..];
    return extra.*[0..n];
}

pub fn readArray(extra: *[]const u8, comptime n: usize) *const [n]u8 {
    defer extra.* = extra.*[n..];
    return extra.*[0..n];
}
