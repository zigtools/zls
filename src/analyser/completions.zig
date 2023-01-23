const std = @import("std");
const InternPool = @import("../InternPool.zig");
const types = @import("../lsp.zig");

const Ast = std.zig.Ast;

pub fn dotCompletions(
    arena: std.mem.Allocator,
    ip: *InternPool,
    ty: InternPool.Index,
    val: InternPool.Index,
    node: ?Ast.Node.Index
) error{OutOfMemory}![]types.CompletionItem {
    _ = node;

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const key = ip.indexToKey(ty);
    const inner_key = switch (key) {
        .pointer_type => |info| if (info.size == .One) ip.indexToKey(info.elem_type) else key,
        else => key,
    };

    switch (inner_key) {
        .simple => |simple| switch (simple) {
            .type => {
                const ty_key = ip.indexToKey(val);
                if (ty_key.getNamespace()) {
                    // TODO lookup in namespace
                }
                switch (ty_key) {
                    .error_set_type => |error_set_info| {
                        for (error_set_info.names) |name| {
                            const error_name = ip.indexToKey(name).bytes;
                            try completions.append(arena, .{
                                .label = error_name,
                                .kind = .Constant,
                                .detail = std.fmt.allocPrint(arena, "error.{s}", .{std.zig.fmtId(error_name)}),
                            });
                        }
                    },
                    .union_type => {}, // TODO
                    .enum_type => |enum_info|{
                        for (enum_info.fields) |field| {
                            const field_name = ip.indexToKey(field.name).bytes;
                            try completions.append(arena, .{
                                .label = field_name,
                                .kind = .Constant,
                                // include field.val?
                            });
                        }
                    },
                    else => {},
                }
            },
            else => false,
        },
        .pointer_type => |pointer_info| {
            if (pointer_info == .Slice) {
                var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                many_ptr_info.pointer_type.size = .Many;

                try completions.append(arena, .{
                    .label = "ptr",
                    .kind = .Field,
                    .detail = std.fmt.allocPrint(arena, "{}", .{many_ptr_info.fmtType(ip)}),
                });
                try completions.append(arena, .{
                    .label = "len",
                    .kind = .Field,
                    .detail = "usize",
                });
            } else if(ip.indexToKey(pointer_info.elem_type) == .array_type) {
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
                .labelDetails = std.fmt.allocPrint(arena, "{d}", .{array_info.len}),
                .kind = .Field,
                .detail = "usize",
            });
        },
        .struct_type => |struct_info| {
            for (struct_info.fields) |field| {
                const field_name = ip.indexToKey(field.name).bytes;
                try completions.append(arena, types.CompletionItem{
                    .label = field_name,
                    .kind = .Field,
                    // TODO include alignment and comptime
                    .detail = std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
        },
        .optional_type => |optional_info| {
            try completions.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = std.fmt.allocPrint(arena, "{}", .{optional_info.payload_type.fmtType(ip)}),
            });
        },
        .enum_type => |enum_info| {
            for (enum_info.fields) |field| {
                const field_name = ip.indexToKey(field.name).bytes;
                try completions.append(arena, .{
                    .label = field_name,
                    .kind = .Field,
                    .detail = std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
        },
        .union_type => |union_info| {
            for (union_info.fields) |field| {
                const field_name = ip.indexToKey(field.name).bytes;
                try completions.append(arena, .{
                    .label = field_name,
                    .kind = .Field,
                    .detail = if (field.alignment != 0)
                        std.fmt.allocPrint(arena, "align({d}) {}", .{ field.alignment, field.ty.fmtType(ip) })
                    else
                        std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
        },
        .tuple_type => |tuple_info| {
            for (tuple_info.types) |tuple_ty,i| {
                try completions.append(arena, .{
                    .label = std.fmt.allocPrint(arena, "{d}", .{i}),
                    .kind = .Field,
                    .detail = std.fmt.allocPrint(arena, "{}", .{tuple_ty.fmtType(ip)}),
                });
            }
        },
        .int_type,
        .error_union_type,
        .function_type,
        .vector_type,
        .anyframe_type => {},

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
    return try completions.toOwnedSlice(arena);
}
