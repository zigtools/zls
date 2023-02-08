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
                    .detail = try std.fmt.allocPrint(arena, "{}", .{many_ptr_info.fmtType(ip.*)}),
                });
                try completions.append(arena, .{
                    .label = "len",
                    .kind = .Field,
                    .detail = "usize",
                });
            } else if (ip.indexToKey(pointer_info.elem_type) == .array_type) {
                try completions.append(arena, .{
                    .label = "len",
                    .kind = .Field,
                    .detail = "usize",
                });
            }
        },
        .array_type => |array_info| {
            try completions.append(arena, types.CompletionItem{
                .label = "len",
                .kind = .Field,
                .detail = try std.fmt.allocPrint(arena, "usize ({d})", .{array_info.len}), // TODO how should this be displayed
            });
        },
        .struct_type => |struct_index| {
            const struct_info = ip.getStruct(struct_index);
            var field_it = struct_info.fields.iterator();
            while (field_it.next()) |entry| {
                try completions.append(arena, types.CompletionItem{
                    .label = entry.key_ptr.*,
                    .kind = .Field,
                    // TODO include alignment and comptime
                    .detail = try std.fmt.allocPrint(arena, "{}", .{entry.value_ptr.ty.fmtType(ip.*)}),
                });
            }
        },
        .optional_type => |optional_info| {
            try completions.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = try std.fmt.allocPrint(arena, "{}", .{optional_info.payload_type.fmtType(ip.*)}),
            });
        },
        .enum_type => |enum_index| {
            const enum_info = ip.getEnum(enum_index);
            for (enum_info.fields.keys()) |field_name, i| {
                const field_val = enum_info.values.keys()[i];
                try completions.append(arena, .{
                    .label = field_name,
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{}", .{field_val.fmtValue(enum_info.tag_type, ip.*)}),
                });
            }
        },
        .union_type => |union_index| {
            const union_info = ip.getUnion(union_index);
            var field_it = union_info.fields.iterator();
            while (field_it.next()) |entry| {
                try completions.append(arena, .{
                    .label = entry.key_ptr.*,
                    .kind = .Field,
                    .detail = if (entry.value_ptr.alignment != 0)
                        try std.fmt.allocPrint(arena, "align({d}) {}", .{ entry.value_ptr.alignment, entry.value_ptr.ty.fmtType(ip.*) })
                    else
                        try std.fmt.allocPrint(arena, "{}", .{entry.value_ptr.ty.fmtType(ip.*)}),
                });
            }
        },
        .tuple_type => |tuple_info| {
            for (tuple_info.types) |tuple_ty, i| {
                try completions.append(arena, .{
                    .label = try std.fmt.allocPrint(arena, "{d}", .{i}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(arena, "{}", .{tuple_ty.fmtType(ip.*)}),
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
        .aggregate,
        .union_value,
        => unreachable,
    }
}
