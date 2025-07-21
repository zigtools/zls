//! Converts a Zig type into a english description of the type.
//!
//! Example:
//! `[*:0]const u8` -> 0 terminated many-item pointer to to const u8

const std = @import("std");
const InternPool = @import("InternPool.zig");

const FormatDegibberishData = struct {
    ip: *InternPool,
    ty: InternPool.Index,
};

pub fn fmtDegibberish(ip: *InternPool, ty: InternPool.Index) std.fmt.Alt(FormatDegibberishData, formatDegibberish) {
    const data: FormatDegibberishData = .{ .ip = ip, .ty = ty };
    return .{ .data = data };
}

fn formatDegibberish(data: FormatDegibberishData, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const ip = data.ip;
    var ty = data.ty;

    while (ty != .none) {
        switch (ip.indexToKey(ty)) {
            .simple_type,
            .int_type,
            => try writer.print("{f}", .{ty.fmt(ip)}),

            .pointer_type => |pointer_info| {
                // ignored attributes:
                // - address_space
                // - is_allowzero
                // - is_volatile
                // - packed_offset

                if (pointer_info.sentinel != .none) {
                    try writer.print("{f} terminated ", .{pointer_info.sentinel.fmt(ip)});
                }

                // single pointer
                const size_prefix = switch (pointer_info.flags.size) {
                    .one => "single-item pointer",
                    .many => "many-item pointer",
                    .slice => "slice (pointer + length)",
                    .c => "C pointer",
                };

                try writer.writeAll(size_prefix);

                if (pointer_info.flags.alignment != 0) {
                    try writer.print(" with alignment {d}", .{pointer_info.flags.alignment});
                }

                try writer.writeAll(" to ");

                if (pointer_info.flags.is_const) {
                    try writer.writeAll("const ");
                }

                ty = pointer_info.elem_type;
                continue;
            },
            .array_type => |array_info| {
                if (array_info.sentinel != .none) {
                    try writer.print("{f} terminated ", .{array_info.sentinel.fmt(ip)});
                }
                try writer.print("array {d} of ", .{array_info.len});
                ty = array_info.child;
                continue;
            },
            .struct_type => try writer.print("struct {f}", .{ty.fmt(ip)}),
            .optional_type => |optional_info| {
                try writer.writeAll("optional of ");
                ty = optional_info.payload_type;
                continue;
            },
            .error_union_type => |error_union_info| {
                try writer.writeAll("error union with ");
                try writer.print("{f}", .{fmtDegibberish(ip, error_union_info.error_set_type)});
                try writer.writeAll(" and payload ");
                ty = error_union_info.payload_type;
                continue;
            },
            .error_set_type => |error_set_info| {
                try writer.writeAll("error set of (");
                for (0..error_set_info.names.len) |i| {
                    if (i != 0) try writer.writeByte(',');
                    const name = error_set_info.names.at(@intCast(i), ip);
                    try writer.print("{f}", .{InternPool.fmtId(ip, name)});
                }
                try writer.writeAll(")");
            },
            .enum_type => try writer.print("enum {f}", .{ty.fmt(ip)}),
            .function_type => |function_info| {
                try writer.writeAll("function (");
                for (0..function_info.args.len) |i| {
                    if (i != 0) try writer.writeAll(", ");
                    const arg_ty = function_info.args.at(@intCast(i), ip);
                    try writer.print("{f}", .{fmtDegibberish(ip, arg_ty)});
                }
                try writer.writeAll(") returning ");
                ty = function_info.return_type;
                continue;
            },
            .union_type => try writer.print("union {f}", .{ty.fmt(ip)}),
            .tuple_type => |tuple_info| {
                std.debug.assert(tuple_info.types.len == tuple_info.values.len);
                try writer.writeAll("tuple of (");
                for (0..tuple_info.types.len) |i| {
                    if (i != 0) try writer.writeAll(", ");
                    const field_ty = tuple_info.types.at(@intCast(i), ip);
                    try writer.print("{f}", .{fmtDegibberish(ip, field_ty)});
                }
                try writer.writeAll(")");
            },
            .vector_type => |vector_info| {
                try writer.print("vector {d} of ", .{vector_info.len});
                ty = vector_info.child;
                continue;
            },
            .anyframe_type => |anyframe_info| {
                try writer.writeAll("function frame returning ");
                ty = anyframe_info.child;
                continue;
            },

            .simple_value,
            .int_u64_value,
            .int_i64_value,
            .int_big_value,
            .float_16_value,
            .float_32_value,
            .float_64_value,
            .float_80_value,
            .float_128_value,
            .float_comptime_value,
            .optional_value,
            .slice,
            .aggregate,
            .union_value,
            .error_value,
            .null_value,
            .undefined_value,
            .unknown_value,
            => unreachable,
        }
        break;
    }
}

test "degibberish - simple types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    try std.testing.expectFmt("u32", "{f}", .{fmtDegibberish(&ip, .u32_type)});
    try std.testing.expectFmt("comptime_float", "{f}", .{fmtDegibberish(&ip, .comptime_float_type)});
}

test "degibberish - pointer types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    try std.testing.expectFmt("many-item pointer to u8", "{f}", .{fmtDegibberish(&ip, .manyptr_u8_type)});
    try std.testing.expectFmt("many-item pointer to const u8", "{f}", .{fmtDegibberish(&ip, .manyptr_const_u8_type)});
    try std.testing.expectFmt("0 terminated many-item pointer to const u8", "{f}", .{fmtDegibberish(&ip, .manyptr_const_u8_sentinel_0_type)});
    try std.testing.expectFmt("single-item pointer to const comptime_int", "{f}", .{fmtDegibberish(&ip, .single_const_pointer_to_comptime_int_type)});
    try std.testing.expectFmt("slice (pointer + length) to const u8", "{f}", .{fmtDegibberish(&ip, .slice_const_u8_type)});
    try std.testing.expectFmt("0 terminated slice (pointer + length) to const u8", "{f}", .{fmtDegibberish(&ip, .slice_const_u8_sentinel_0_type)});
}

test "degibberish - array types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"[3:0]u8" = try ip.get(gpa, .{ .array_type = .{ .len = 3, .child = .u8_type, .sentinel = .zero_u8 } });
    const @"[0]u32" = try ip.get(gpa, .{ .array_type = .{ .len = 0, .child = .u32_type } });

    try std.testing.expectFmt("0 terminated array 3 of u8", "{f}", .{fmtDegibberish(&ip, @"[3:0]u8")});
    try std.testing.expectFmt("array 0 of u32", "{f}", .{fmtDegibberish(&ip, @"[0]u32")});
}

test "degibberish - optional types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"?u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .u32_type } });

    try std.testing.expectFmt("optional of u32", "{f}", .{fmtDegibberish(&ip, @"?u32")});
}

test "degibberish - error union types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const foo_string = try ip.string_pool.getOrPutString(gpa, "foo");
    const bar_string = try ip.string_pool.getOrPutString(gpa, "bar");
    const baz_string = try ip.string_pool.getOrPutString(gpa, "baz");

    const @"error{foo,bar,baz}" = try ip.get(gpa, .{ .error_set_type = .{
        .names = try ip.getStringSlice(gpa, &.{ foo_string, bar_string, baz_string }),
        .owner_decl = .none,
    } });

    const @"error{foo,bar,baz}!u32" = try ip.get(gpa, .{ .error_union_type = .{
        .error_set_type = @"error{foo,bar,baz}",
        .payload_type = .u32_type,
    } });

    try std.testing.expectFmt("error union with error set of (foo,bar,baz) and payload u32", "{f}", .{fmtDegibberish(&ip, @"error{foo,bar,baz}!u32")});
}

test "degibberish - error set types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const foo_string = try ip.string_pool.getOrPutString(gpa, "foo");
    const bar_string = try ip.string_pool.getOrPutString(gpa, "bar");
    const baz_string = try ip.string_pool.getOrPutString(gpa, "baz");

    const @"error{foo,bar,baz}" = try ip.get(gpa, .{ .error_set_type = .{
        .names = try ip.getStringSlice(gpa, &.{ foo_string, bar_string, baz_string }),
        .owner_decl = .none,
    } });

    try std.testing.expectFmt("error set of (foo,bar,baz)", "{f}", .{fmtDegibberish(&ip, @"error{foo,bar,baz}")});
}

test "degibberish - function types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"fn(u32, void) type" = try ip.get(gpa, .{ .function_type = .{
        .args = try ip.getIndexSlice(gpa, &.{ .u32_type, .void_type }),
        .return_type = .type_type,
    } });

    try std.testing.expectFmt("function () returning noreturn", "{f}", .{fmtDegibberish(&ip, .fn_noreturn_no_args_type)});
    try std.testing.expectFmt("function () returning void", "{f}", .{fmtDegibberish(&ip, .fn_void_no_args_type)});
    try std.testing.expectFmt("function (u32, void) returning type", "{f}", .{fmtDegibberish(&ip, @"fn(u32, void) type")});
}

test "degibberish - tuple types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"struct{u32, comptime_float, c_int}" = try ip.get(gpa, .{ .tuple_type = .{
        .types = try ip.getIndexSlice(gpa, &.{ .u32_type, .comptime_float_type, .c_int_type }),
        .values = try ip.getIndexSlice(gpa, &.{ .none, .none, .none }),
    } });

    try std.testing.expectFmt("tuple of (u32, comptime_float, c_int)", "{f}", .{fmtDegibberish(&ip, @"struct{u32, comptime_float, c_int}")});
}

test "degibberish - vector types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"@Vector(3, u8)" = try ip.get(gpa, .{ .vector_type = .{ .len = 3, .child = .u8_type } });
    const @"@Vector(0, u32)" = try ip.get(gpa, .{ .vector_type = .{ .len = 0, .child = .u32_type } });

    try std.testing.expectFmt("vector 3 of u8", "{f}", .{fmtDegibberish(&ip, @"@Vector(3, u8)")});
    try std.testing.expectFmt("vector 0 of u32", "{f}", .{fmtDegibberish(&ip, @"@Vector(0, u32)")});
}

test "degibberish - anyframe types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"anyframe->u32" = try ip.get(gpa, .{ .anyframe_type = .{ .child = .u32_type } });
    try std.testing.expectFmt("function frame returning u32", "{f}", .{fmtDegibberish(&ip, @"anyframe->u32")});
}
