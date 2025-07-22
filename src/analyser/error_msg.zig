const std = @import("std");

const InternPool = @import("InternPool.zig");
const Index = InternPool.Index;

pub const ErrorMsg = union(enum) {
    /// zig: expected type '{}', found '{}'
    expected_type: struct {
        expected: Index,
        actual: Index,
    },
    /// zig: expected optional type, found '{}'
    /// zig: expected error set type, found '{}'
    /// zig: expected pointer, found '{}'
    expected_tag_type: struct {
        expected_tag: std.builtin.TypeId,
        actual: Index,
    },
    /// zig: comparison of '{}' with null
    compare_eq_with_null: struct {
        non_null_type: Index,
    },
    /// zig: tried to unwrap optional of type `{}` which was '{}'
    invalid_optional_unwrap: struct {
        operand: Index,
    },
    /// zig: type '{}' cannot represent integer value '{}'
    integer_out_of_range: struct {
        dest_ty: Index,
        actual: Index,
    },
    /// zig: expected {d} array elements; found 0
    wrong_array_elem_count: struct {
        expected: u32,
        actual: u32,
    },
    /// zig: type '{}' does not support indexing
    /// zig: operand must be an array, slice, tuple, or vector
    expected_indexable_type: struct {
        actual: Index,
    },
    /// zig: duplicate struct field: '{}'
    duplicate_struct_field: struct {
        name: InternPool.StringPool.String,
    },
    /// zig: `{}` has no member '{s}'
    /// zig: `{}` does not support field access
    unknown_field: struct {
        accessed: Index,
        field_name: []const u8,
    },

    const FormatContext = struct {
        error_msg: ErrorMsg,
        ip: *InternPool,
    };

    pub fn fmt(self: ErrorMsg, ip: *InternPool) std.fmt.Alt(FormatContext, format) {
        return .{ .data = .{ .error_msg = self, .ip = ip } };
    }

    pub fn format(ctx: FormatContext, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const ip = ctx.ip;
        switch (ctx.error_msg) {
            .expected_type => |info| try writer.print(
                "expected type '{f}', found '{f}'",
                .{ info.expected.fmt(ip), ip.typeOf(info.actual).fmt(ip) },
            ),
            .expected_tag_type => |info| {
                const expected_tag_str = switch (info.expected_tag) {
                    .type => "type",
                    .void => "void",
                    .bool => "bool",
                    .noreturn => "noreturn",
                    .int => "integer",
                    .float => "float",
                    .pointer => "pointer",
                    .array => "array",
                    .@"struct" => "struct",
                    .comptime_float => "comptime_float",
                    .comptime_int => "comptime_int",
                    .undefined => "undefined",
                    .null => "null",
                    .optional => "optional",
                    .error_union => "error union",
                    .error_set => "error set",
                    .@"enum" => "enum",
                    .@"union" => "union",
                    .@"fn" => "function",
                    .@"opaque" => "opaque",
                    .frame => "frame",
                    .@"anyframe" => "anyframe",
                    .vector => "vector",
                    .enum_literal => "enum literal",
                };
                try writer.print(
                    "expected {s} type, found '{f}'",
                    .{ expected_tag_str, info.actual.fmt(ip) },
                );
            },
            .compare_eq_with_null => |info| try writer.print(
                "comparison of '{f}' with null",
                .{info.non_null_type.fmt(ip)},
            ),
            .invalid_optional_unwrap => |info| {
                const operand_ty = ip.typeOf(info.operand);
                const payload_ty = ip.indexToKey(operand_ty).optional_type.payload_type;
                try writer.print(
                    "tried to unwrap optional of type `{f}` which was {f}",
                    .{ payload_ty.fmt(ip), info.operand.fmt(ip) },
                );
            },
            .integer_out_of_range => |info| try writer.print(
                "type '{f}' cannot represent integer value '{f}'",
                .{ info.dest_ty.fmt(ip), info.actual.fmt(ip) },
            ),
            .wrong_array_elem_count => |info| try writer.print(
                "expected {d} array elements; found {d}",
                .{ info.expected, info.actual },
            ),
            .expected_indexable_type => |info| try writer.print(
                "type '{f}' does not support indexing",
                .{info.actual.fmt(ip)},
            ),
            .duplicate_struct_field => |info| try writer.print(
                "duplicate struct field: '{f}'",
                .{info.name.fmt(&ip.string_pool)},
            ),
            .unknown_field => |info| {
                const accessed_ty = ip.typeOf(info.accessed);
                if (ip.canHaveFields(accessed_ty)) {
                    try writer.print(
                        "'{f}' has no member '{s}'",
                        .{ accessed_ty.fmt(ip), info.field_name },
                    );
                } else {
                    try writer.print(
                        "'{f}' does not support field access",
                        .{accessed_ty.fmt(ip)},
                    );
                }
            },
        }
    }
};
