const std = @import("std");
const InternPool = @import("InternPool.zig");
const types = @import("lsp.zig");

const Ast = std.zig.Ast;

pub fn dotCompletions(
    arena: std.mem.Allocator,
    ip: *InternPool,
    ty: InternPool.Index,
    /// used for extracting doc comments
    node: ?Ast.Node.Index,
) error{OutOfMemory}![]types.CompletionItem {
    return try dotCompletionsInternal(arena, ip, ty, node);
}

pub fn dotCompletionsInternal(
    arena: std.mem.Allocator,
    ip: *InternPool,
    ty: InternPool.Index,
    node: ?Ast.Node.Index,
    follow_one_pointer: bool,
) error{OutOfMemory}![]types.CompletionItem {
    _ = node;

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};
    switch (ip.indexToKey(ty)) {
        .simple => {},

        .int_type => {},
        .pointer_type => |pointer_info| {
            switch (pointer_info.size) {
                .One => {
                    try completions.append(arena, .{
                        .label = "*",
                        .kind = .Operator,
                        .detail = std.fmt.allocPrint(arena, "{}", .{pointer_info.elem_type.fmtType(ip)}),
                    });
                    if (follow_one_pointer) {
                        try dotCompletionsInternal(arena, ip, pointer_info.elem_type, false);
                    }
                },
                .Slice => {
                    var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                    many_ptr_info.pointer_info.size = .Many;

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
                },
                .Many,
                .C,
                => {},
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
                try completions.append(arena, types.CompletionItem{
                    .label = field.name,
                    .kind = .Field,
                    // TODO include alignment and comptime
                    .detail = std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
            // TODO namespace
        },
        .optional_type => |optional_info| {
            try completions.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = std.fmt.allocPrint(arena, "{}", .{optional_info.payload_type.fmtType(ip)}),
            });
        },
        .error_union_type => {},
        .error_set_type => |error_set_info| {
            for (error_set_info.names) |name| {
                try completions.append(arena, .{
                    .label = name,
                    .kind = .Constant,
                    .detail = std.fmt.allocPrint(arena, "error.{s}", .{name}),
                });
            }
        },
        .enum_type => |enum_info| {
            for (enum_info.fields) |field| {
                try completions.append(arena, .{
                    .label = field.name,
                    .kind = .Field,
                    .detail = std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
            // TODO namespace
        },
        .function_type => {},
        .union_type => |union_info| {
            for (union_info.fields) |field| {
                try completions.append(arena, .{
                    .label = field.name,
                    .kind = .Field,
                    .detail = if (field.alignment != 0)
                        std.fmt.allocPrint(arena, "align({d}) {}", .{ field.alignment, field.ty.fmtType(ip) })
                    else
                        std.fmt.allocPrint(arena, "{}", .{field.ty.fmtType(ip)}),
                });
            }
            // TODO namespace
        },
        .tuple_type => {
            // TODO
        },
        .vector_type => {},
        .anyframe_type => {},

        .int_u64_value,
        .int_i64_value,
        .int_big_value,
        .float_16_value,
        .float_32_value,
        .float_64_value,
        .float_80_value,
        .float_128_value,
        => {},

        .bytes,
        .aggregate,
        .union_value,
        => {},
    }
    return try completions.toOwnedSlice(arena);
}
