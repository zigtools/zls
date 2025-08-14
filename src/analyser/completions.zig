//! Completions based on a `InternPool.Index`.
//! This is not the main implementation of code completions of ZLS!

const std = @import("std");
const InternPool = @import("InternPool.zig");
const types = @import("lsp").types;

/// generates a list of dot completions for the given typed-value in `index`
/// the given `index` must belong to the given InternPool
pub fn dotCompletions(
    arena: std.mem.Allocator,
    completions: *std.ArrayList(types.CompletionItem),
    ip: *InternPool,
    index: InternPool.Index,
) error{OutOfMemory}!void {
    std.debug.assert(index != .none);

    const val: InternPool.Index = index;
    const ty: InternPool.Index = ip.typeOf(index);

    const inner_ty, const is_indirect = switch (ip.indexToKey(ty)) {
        .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
            .one => blk: {
                try completions.append(arena, .{
                    .label = "*",
                    .kind = .Operator,
                    .detail = try std.fmt.allocPrint(arena, "{f}", .{pointer_info.elem_type.fmt(ip)}),
                });
                break :blk .{ pointer_info.elem_type, true };
            },
            else => .{ ty, false },
        },
        else => .{ ty, false },
    };

    switch (ip.indexToKey(inner_ty)) {
        .simple_type => |simple| switch (simple) {
            .type => {
                if (val == .none) return;

                const namespace = ip.getNamespace(val);
                if (namespace != .none) {
                    // TODO lookup in namespace
                }

                switch (ip.indexToKey(val)) {
                    .error_set_type => |error_set_info| {
                        const names = try error_set_info.names.dupe(arena, ip);
                        try completions.ensureUnusedCapacity(arena, names.len);
                        for (names) |name| {
                            completions.appendAssumeCapacity(.{
                                .label = try std.fmt.allocPrint(arena, "{f}", .{ip.fmtId(name)}),
                                .kind = .Constant,
                                .detail = try std.fmt.allocPrint(arena, "error.{f}", .{ip.fmtId(name)}),
                            });
                        }
                    },
                    .union_type => {}, // TODO
                    .enum_type => |enum_index| {
                        const enum_info = ip.getEnum(enum_index);
                        try completions.ensureUnusedCapacity(arena, enum_info.fields.count());
                        for (enum_info.fields.keys()) |name| {
                            completions.appendAssumeCapacity(.{
                                .label = try std.fmt.allocPrint(arena, "{f}", .{name.fmt(&ip.string_pool)}),
                                .kind = .EnumMember,
                                // include field.val?
                            });
                        }
                    },
                    else => {},
                }
            },
            else => {},
        },
        .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
            .one, .many => {},
            .c => {
                if (!is_indirect) {
                    try completions.appendSlice(arena, &.{
                        .{
                            .label = "*",
                            .kind = .Operator,
                            .detail = try std.fmt.allocPrint(arena, "{f}", .{pointer_info.elem_type.fmt(ip)}),
                        },
                        .{
                            .label = "?",
                            .kind = .Operator,
                            .detail = try std.fmt.allocPrint(arena, "{f}", .{inner_ty.fmt(ip)}),
                        },
                    });
                }
            },
            .slice => {
                const formatted = try std.fmt.allocPrint(arena, "{f}", .{inner_ty.fmt(ip)});
                std.debug.assert(std.mem.startsWith(u8, formatted, "[]"));

                try completions.appendSlice(arena, &.{
                    .{
                        .label = "ptr",
                        .kind = .Field,
                        .detail = try std.fmt.allocPrint(arena, "ptr: [*]{s}", .{formatted["[]".len..]}),
                    },
                    .{
                        .label = "len",
                        .kind = .Field,
                        .detail = "len: usize",
                    },
                });
            },
        },
        .array_type => |array_info| {
            try completions.append(arena, .{
                .label = "len",
                .kind = .Field,
                .detail = try std.fmt.allocPrint(arena, "usize = {d}", .{array_info.len}),
            });
        },
        .struct_type => |struct_index| {
            const struct_info = ip.getStruct(struct_index);
            try completions.ensureUnusedCapacity(arena, struct_info.fields.count());
            for (struct_info.fields.keys(), struct_info.fields.values()) |name, field| {
                completions.appendAssumeCapacity(.{
                    .label = try std.fmt.allocPrint(arena, "{f}", .{ip.fmtId(name)}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{f}: {f}", .{
                        name.fmt(&ip.string_pool),
                        fmtFieldDetail(ip, field),
                    }),
                });
            }
        },
        .optional_type => |optional_info| {
            try completions.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = try std.fmt.allocPrint(arena, "{f}", .{optional_info.payload_type.fmt(ip)}),
            });
        },
        .enum_type => |enum_index| {
            const enum_info = ip.getEnum(enum_index);
            try completions.ensureUnusedCapacity(arena, enum_info.fields.count());
            for (enum_info.fields.keys(), enum_info.values.keys()) |name, field_value| {
                completions.appendAssumeCapacity(.{
                    .label = try std.fmt.allocPrint(arena, "{f}", .{ip.fmtId(name)}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{f}", .{field_value.fmt(ip)}),
                });
            }
        },
        .union_type => |union_index| {
            const union_info = ip.getUnion(union_index);
            try completions.ensureUnusedCapacity(arena, union_info.fields.count());
            for (union_info.fields.keys(), union_info.fields.values()) |name, field| {
                completions.appendAssumeCapacity(.{
                    .label = try std.fmt.allocPrint(arena, "{f}", .{ip.fmtId(name)}),
                    .kind = .Field,
                    .detail = if (field.alignment != 0)
                        try std.fmt.allocPrint(arena, "{f}: align({d}) {f}", .{ ip.fmtId(name), field.alignment, field.ty.fmt(ip) })
                    else
                        try std.fmt.allocPrint(arena, "{f}: {f}", .{ ip.fmtId(name), field.ty.fmt(ip) }),
                });
            }
        },
        .tuple_type => |tuple_info| {
            std.debug.assert(tuple_info.types.len == tuple_info.values.len);
            const tuple_types = try tuple_info.types.dupe(arena, ip);

            try completions.ensureUnusedCapacity(arena, tuple_info.types.len);
            for (tuple_types, 0..) |tuple_ty, i| {
                completions.appendAssumeCapacity(.{
                    .label = try std.fmt.allocPrint(arena, "{d}", .{i}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{d}: {f}", .{ i, tuple_ty.fmt(ip) }),
                });
            }
        },
        .int_type,
        .error_set_type,
        .error_union_type,
        .function_type,
        .vector_type,
        .anyframe_type,
        => {},

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
        => {},

        .optional_value,
        .slice,
        .aggregate,
        .union_value,
        .error_value,
        .null_value,
        .undefined_value,
        .unknown_value,
        => {},
    }
}

const FormatFieldDetail = struct {
    ip: *InternPool,
    item: InternPool.Struct.Field,
};

fn formatFieldDetail(ctx: FormatFieldDetail, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const field = ctx.item;
    if (field.is_comptime) {
        try writer.writeAll("comptime ");
    }
    if (field.alignment != 0) {
        try writer.print("align({d}) ", .{field.alignment});
    }
    try writer.print("{f}", .{field.ty.fmt(ctx.ip)});
    if (field.default_value != .none) {
        try writer.print(" = {f},", .{field.default_value.fmt(ctx.ip)});
    }
}

pub fn fmtFieldDetail(ip: *InternPool, field: InternPool.Struct.Field) std.fmt.Alt(FormatFieldDetail, formatFieldDetail) {
    return .{ .data = .{ .ip = ip, .item = field } };
}

test "dotCompletions - primitives" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    try testCompletion(&ip, .bool_type, &.{});
    try testCompletion(&ip, .bool_true, &.{});
    try testCompletion(&ip, .zero_comptime_int, &.{});
    try testCompletion(&ip, .unknown_type, &.{});
    try testCompletion(&ip, .unknown_unknown, &.{});
}

test "dotCompletions - optional types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"?u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .u32_type } });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"?u32"), &.{
        .{
            .label = "?",
            .kind = .Operator,
            .detail = "u32",
        },
    });
}

test "dotCompletions - array types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"[3]u32" = try ip.get(gpa, .{ .array_type = .{ .child = .u32_type, .len = 3 } });
    const @"[1]u8" = try ip.get(gpa, .{ .array_type = .{ .child = .u8_type, .len = 1 } });

    try testCompletion(&ip, try ip.getUnknown(gpa, @"[3]u32"), &.{
        .{
            .label = "len",
            .kind = .Field,
            .detail = "usize = 3",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"[1]u8"), &.{
        .{
            .label = "len",
            .kind = .Field,
            .detail = "usize = 1",
        },
    });
}

test "dotCompletions - pointer types" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .flags = .{
            .size = .one,
        },
    } });
    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .flags = .{
            .size = .slice,
        },
    } });
    const @"[]const u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .flags = .{
            .size = .slice,
            .is_const = true,
        },
    } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .flags = .{
            .size = .c,
        },
    } });

    try testCompletion(&ip, try ip.getUnknown(gpa, @"*u32"), &.{
        .{
            .label = "*",
            .kind = .Operator,
            .detail = "u32",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"[]u32"), &.{
        .{
            .label = "ptr",
            .kind = .Field,
            .detail = "ptr: [*]u32",
        },
        .{
            .label = "len",
            .kind = .Field,
            .detail = "len: usize",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"[]const u32"), &.{
        .{
            .label = "ptr",
            .kind = .Field,
            .detail = "ptr: [*]const u32",
        },
        .{
            .label = "len",
            .kind = .Field,
            .detail = "len: usize",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"[*c]u32"), &.{
        .{
            .label = "*",
            .kind = .Operator,
            .detail = "u32",
        },
        .{
            .label = "?",
            .kind = .Operator,
            .detail = "[*c]u32",
        },
    });
}

test "dotCompletions - single pointer indirection" {
    const gpa = std.testing.allocator;
    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    const @"[1]u32" = try ip.get(gpa, .{ .array_type = .{ .child = .u32_type, .len = 1 } });
    const @"*[1]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = @"[1]u32",
        .flags = .{
            .size = .one,
        },
    } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .flags = .{
            .size = .c,
        },
    } });
    const @"**[1]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = @"*[1]u32",
        .flags = .{
            .size = .one,
        },
    } });
    const @"[*][1]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = @"[1]u32",
        .flags = .{
            .size = .many,
        },
    } });
    const @"*[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = @"[*c]u32",
        .flags = .{
            .size = .one,
        },
    } });

    try testCompletion(&ip, try ip.getUnknown(gpa, @"*[1]u32"), &.{
        .{
            .label = "*",
            .kind = .Operator,
            .detail = "[1]u32",
        },
        .{
            .label = "len",
            .kind = .Field,
            .detail = "usize = 1",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"**[1]u32"), &.{
        .{
            .label = "*",
            .kind = .Operator,
            .detail = "*[1]u32",
        },
    });
    try testCompletion(&ip, try ip.getUnknown(gpa, @"[*][1]u32"), &.{});

    try testCompletion(&ip, try ip.getUnknown(gpa, @"*[*c]u32"), &.{
        .{
            .label = "*",
            .kind = .Operator,
            .detail = "[*c]u32",
        },
    });
}

fn testCompletion(
    ip: *InternPool,
    index: InternPool.Index,
    expected: []const types.CompletionItem,
) !void {
    const gpa = std.testing.allocator;
    var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();
    var completions: std.ArrayList(types.CompletionItem) = .empty;

    try dotCompletions(arena, &completions, ip, index);

    try std.testing.expectEqualDeep(expected, completions.items);
}
