const std = @import("std");
const Allocator = std.mem.Allocator;
const ParseError = std.json.ParseError;
const Scanner = std.json.Scanner;
const ParseOptions = std.json.ParseOptions;
pub fn parseFromSlice(
    comptime T: type,
    allocator: Allocator,
    s: []const u8,
    options: ParseOptions,
) (ParseError(Scanner) || std.mem.Allocator.Error)!T {
    const json = try std.json.parseFromSlice(T, allocator, s, options);
    defer json.deinit();
    return deepCopy(T, allocator, json.value);
}
pub fn parseFromTokenSource(
    comptime T: type,
    allocator: Allocator,
    scanner_or_reader: anytype,
    options: ParseOptions,
) (ParseError(@TypeOf(scanner_or_reader.*)) || std.mem.Allocator.Error)!T {
    const json = try std.json.parseFromTokenSource(T, allocator, scanner_or_reader, options);
    defer json.deinit();
    return try deepCopy(T, allocator, json.value);
}

/// Recursively copies a struct, reallocating pointers and slices
fn deepCopy(comptime T: type, allocator: Allocator, value: T) !T {
    switch (@typeInfo(T)) {
        .Bool, .Float, .ComptimeFloat, .Int, .ComptimeInt, .Enum => return value,
        .Optional => {
            if (value) |v| {
                return try deepCopy(@TypeOf(v), allocator, v);
            }
            return null;
        },
        .Union => |unionInfo| {
            if (unionInfo.tag_type) |UnionTagType| {
                inline for (unionInfo.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        return @unionInit(T, u_field.name, deepCopy(u_field.type, allocator, @field(value, u_field.name)));
                    }
                }
            } else {
                unreachable;
            }
        },
        .Struct => |structInfo| {
            var result: T = undefined;
            inline for (structInfo.fields) |field| {
                if (field.is_comptime) @compileError("comptime fields are not supported: " ++ @typeName(T) ++ "." ++ field.name);
                const field_value = @field(value, field.name);
                @field(result, field.name) = try deepCopy(@TypeOf(field_value), allocator, field_value);
            }
            return result;
        },
        .Array, .Vector => {
            var r: T = undefined;
            for (value, 0..) |v, i| {
                r[i] = try deepCopy(@TypeOf(v), allocator, v);
            }
            return r;
        },
        .Pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .One => {
                    const r: *ptrInfo.child = try allocator.create(ptrInfo.child);
                    errdefer allocator.destroy(r);
                    r.* = try deepCopy(ptrInfo.child, allocator, value.*);
                    return r;
                },
                .Slice => {
                    var result = std.ArrayList(ptrInfo.child).init(allocator);
                    errdefer result.deinit();
                    for (value) |v| {
                        try result.append(try deepCopy(ptrInfo.child, allocator, v));
                    }
                    if (ptrInfo.sentinel) |some| {
                        const sentinel_value = @ptrCast(*align(1) const ptrInfo.child, some).*;
                        return try result.toOwnedSliceSentinel(sentinel_value);
                    }
                    return try result.toOwnedSlice();
                },

                else => @compileError("Unable to deepCopy type '" ++ @typeName(T) ++ "'"),
            }
        },

        else => @compileError("Unable to deepCopy type '" ++ @typeName(T) ++ "'"),
    }
}
/// Releases resources created by parseFromSlice() or parseFromTokenSource().
pub fn parseFree(comptime T: type, allocator: Allocator, value: T) void {
    switch (@typeInfo(T)) {
        .Bool, .Float, .ComptimeFloat, .Int, .ComptimeInt, .Enum => {},
        .Optional => {
            if (value) |v| {
                return parseFree(@TypeOf(v), allocator, v);
            }
        },
        .Union => |unionInfo| {
            if (unionInfo.tag_type) |UnionTagType| {
                inline for (unionInfo.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        parseFree(u_field.type, allocator, @field(value, u_field.name));
                        break;
                    }
                }
            } else {
                unreachable;
            }
        },
        .Struct => |structInfo| {
            inline for (structInfo.fields) |field| {
                var should_free = true;
                if (field.default_value) |default| {
                    switch (@typeInfo(field.type)) {
                        // We must not attempt to free pointers to struct default values
                        .Pointer => |fieldPtrInfo| {
                            const field_value = @field(value, field.name);
                            const field_ptr = switch (fieldPtrInfo.size) {
                                .One => field_value,
                                .Slice => field_value.ptr,
                                else => unreachable, // Other pointer types are not parseable
                            };
                            const field_addr = @intFromPtr(field_ptr);

                            const casted_default = @ptrCast(*const field.type, @alignCast(@alignOf(field.type), default)).*;
                            const default_ptr = switch (fieldPtrInfo.size) {
                                .One => casted_default,
                                .Slice => casted_default.ptr,
                                else => unreachable, // Other pointer types are not parseable
                            };
                            const default_addr = @intFromPtr(default_ptr);

                            if (field_addr == default_addr) {
                                should_free = false;
                            }
                        },
                        else => {},
                    }
                }
                if (should_free) {
                    parseFree(field.type, allocator, @field(value, field.name));
                }
            }
        },
        .Array => |arrayInfo| {
            for (value) |v| {
                parseFree(arrayInfo.child, allocator, v);
            }
        },
        .Vector => |vecInfo| {
            var i: usize = 0;
            while (i < vecInfo.len) : (i += 1) {
                parseFree(vecInfo.child, allocator, value[i]);
            }
        },
        .Pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .One => {
                    parseFree(ptrInfo.child, allocator, value.*);
                    allocator.destroy(value);
                },
                .Slice => {
                    for (value) |v| {
                        parseFree(ptrInfo.child, allocator, v);
                    }
                    allocator.free(value);
                },
                else => unreachable,
            }
        },
        else => unreachable,
    }
}
