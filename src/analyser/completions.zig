const std = @import("std");
const InternPool = @import("InternPool.zig");
const types = @import("../lsp.zig");

const Ast = std.zig.Ast;

pub fn dotCompletions(
    arena: std.mem.Allocator,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    ip: *InternPool,
    ty: InternPool.Index,
    val: InternPool.Index,
    node: ?Ast.Node.Index,
) error{OutOfMemory}!void {
    _ = node;

    const key = ip.indexToKey(ty);
    const inner_key = switch (key) {
        .pointer_type => |info| if (info.size == .One) ip.indexToKey(info.elem_type) else key,
        else => key,
    };

    switch (inner_key) {
        .simple_type => |simple| switch (simple) {
            .type => {
                const ty_key = ip.indexToKey(val);
                const namespace = ty_key.getNamespace(ip.*);
                if (namespace != .none) {
                    // TODO lookup in namespace
                }
                switch (ty_key) {
                    .error_set_type => |error_set_info| {
                        for (error_set_info.names) |name| {
                            const error_name = ip.indexToKey(name).bytes;
                            try completions.append(arena, .{
                                .label = error_name,
                                .kind = .Constant,
                                .detail = try std.fmt.allocPrint(arena, "error.{s}", .{std.zig.fmtId(error_name)}),
                            });
                        }
                    },
                    .union_type => {}, // TODO
                    .enum_type => |enum_index| {
                        const enum_info = ip.getEnum(enum_index);
                        var field_it = enum_info.fields.iterator();
                        while (field_it.next()) |entry| {
                            try completions.append(arena, .{
                                .label = entry.key_ptr.*,
                                .kind = .Constant,
                                // include field.val?
                            });
                        }
                    },
                    else => {},
                }
            },
            else => {},
        },
        .pointer_type => |pointer_info| {
            if (pointer_info.size == .Slice) {
                var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                many_ptr_info.pointer_type.size = .Many;

                try completions.append(arena, .{
                    .label = "ptr",
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "ptr: {}", .{many_ptr_info.fmt(ip.*)}),
                });
                try completions.append(arena, .{
                    .label = "len",
                    .kind = .Field,
                    .detail = "len: usize",
                });
            } else if (ip.indexToKey(pointer_info.elem_type) == .array_type) {
                try completions.append(arena, .{
                    .label = "len",
                    .kind = .Field,
                    .detail = "len: usize",
                });
            }
        },
        .array_type => |array_info| {
            try completions.append(arena, types.CompletionItem{
                .label = "len",
                .kind = .Field,
                .detail = try std.fmt.allocPrint(arena, "const len: usize ({d})", .{array_info.len}), // TODO how should this be displayed
            });
        },
        .struct_type => |struct_index| {
            const struct_info = ip.getStruct(struct_index);
            try completions.ensureUnusedCapacity(arena, struct_info.fields.count());
            var field_it = struct_info.fields.iterator();
            while (field_it.next()) |entry| {
                const label = entry.key_ptr.*;
                const field = entry.value_ptr.*;
                completions.appendAssumeCapacity(types.CompletionItem{
                    .label = label,
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{s}: {}", .{
                        label,
                        fmtFieldDetail(field, ip),
                    }),
                });
            }
        },
        .optional_type => |optional_info| {
            try completions.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = try std.fmt.allocPrint(arena, "{}", .{optional_info.payload_type.fmt(ip.*)}),
            });
        },
        .enum_type => |enum_index| {
            const enum_info = ip.getEnum(enum_index);
            for (enum_info.fields.keys(), enum_info.values.keys()) |field_name, field_value| {
                try completions.append(arena, .{
                    .label = field_name,
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{}", .{field_value.fmt(ip.*)}),
                });
            }
        },
        .union_type => |union_index| {
            const union_info = ip.getUnion(union_index);
            var field_it = union_info.fields.iterator();
            while (field_it.next()) |entry| {
                const label = entry.key_ptr.*;
                const field = entry.value_ptr.*;
                try completions.append(arena, .{
                    .label = label,
                    .kind = .Field,
                    .detail = if (field.alignment != 0)
                        try std.fmt.allocPrint(arena, "{s}: align({d}) {}", .{ label, field.alignment, field.ty.fmt(ip.*) })
                    else
                        try std.fmt.allocPrint(arena, "{s}: {}", .{ label, field.ty.fmt(ip.*) }),
                });
            }
        },
        .tuple_type => |tuple_info| {
            for (tuple_info.types, 0..) |tuple_ty, i| {
                try completions.append(arena, .{
                    .label = try std.fmt.allocPrint(arena, "{d}", .{i}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{d}: {}", .{ i, tuple_ty.fmt(ip.*) }),
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
        => unreachable,

        .bytes,
        .optional_value,
        .slice,
        .aggregate,
        .union_value,
        .unknown_value,
        => unreachable,
    }
}

fn FormatContext(comptime T: type) type {
    return struct {
        ip: *InternPool,
        item: T,
    };
}

fn formatFieldDetail(
    ctx: FormatContext(InternPool.Struct.Field),
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    _ = options;
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, InternPool.Struct.Field);

    const field = ctx.item;
    if (field.is_comptime) {
        try writer.writeAll("comptime ");
    }
    if (field.alignment != 0) {
        try writer.print("align({d}) ", .{field.alignment});
    }
    try writer.print("{}", .{field.ty.fmt(ctx.ip.*)});
    if (field.default_value != .none) {
        try writer.print(" = {},", .{field.default_value.fmt(ctx.ip.*)});
    }
}

pub fn fmtFieldDetail(field: InternPool.Struct.Field, ip: *InternPool) std.fmt.Formatter(formatFieldDetail) {
    return .{ .data = .{
        .ip = ip,
        .item = field,
    } };
}
