/// Based on src/InternPool.zig from the zig codebase
/// https://github.com/ziglang/zig/blob/master/src/InternPool.zig
map: std.AutoArrayHashMapUnmanaged(void, void) = .{},
items: std.MultiArrayList(Item) = .{},
extra: std.ArrayListUnmanaged(u8) = .{},

decls: std.SegmentedList(InternPool.Decl, 0) = .{},
structs: std.SegmentedList(InternPool.Struct, 0) = .{},
enums: std.SegmentedList(InternPool.Enum, 0) = .{},
unions: std.SegmentedList(InternPool.Union, 0) = .{},

const InternPool = @This();
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const encoding = @import("encoding.zig");

pub const Int = packed struct {
    signedness: std.builtin.Signedness,
    bits: u16,
};

pub const Pointer = packed struct {
    elem_type: Index,
    sentinel: Index = .none,
    alignment: u16 = 0,
    size: std.builtin.Type.Pointer.Size,
    bit_offset: u16 = 0,
    host_size: u16 = 0,
    is_const: bool = false,
    is_volatile: bool = false,
    is_allowzero: bool = false,
    address_space: std.builtin.AddressSpace = .generic,
};

pub const Array = packed struct {
    len: u64,
    child: Index,
    sentinel: Index = .none,
};

pub const FieldStatus = enum {
    none,
    field_types_wip,
    have_field_types,
    layout_wip,
    have_layout,
    fully_resolved_wip,
    fully_resolved,
};

pub const StructIndex = enum(u32) { _ };

pub const Struct = struct {
    fields: std.StringArrayHashMapUnmanaged(Field),
    namespace: NamespaceIndex,
    layout: std.builtin.Type.ContainerLayout = .Auto,
    backing_int_ty: Index,
    status: FieldStatus,

    pub const Field = packed struct {
        ty: Index,
        default_value: Index = .none,
        alignment: u16 = 0,
        is_comptime: bool = false,
    };
};

pub const Optional = packed struct {
    payload_type: Index,
};

pub const ErrorUnion = packed struct {
    error_set_type: Index,
    payload_type: Index,
};

pub const ErrorSet = struct {
    /// every element is guaranteed to be .bytes
    names: []const Index,
};

pub const EnumIndex = enum(u32) { _ };

pub const Enum = struct {
    tag_type: Index,
    fields: std.StringArrayHashMapUnmanaged(void),
    values: std.AutoArrayHashMapUnmanaged(Index, void),
    namespace: NamespaceIndex,
    tag_type_infered: bool,
};

pub const Function = struct {
    args: []const Index,
    /// zig only lets the first 32 arguments be `comptime`
    args_is_comptime: std.StaticBitSet(32) = std.StaticBitSet(32).initEmpty(),
    /// zig only lets the first 32 arguments be generic
    args_is_generic: std.StaticBitSet(32) = std.StaticBitSet(32).initEmpty(),
    /// zig only lets the first 32 arguments be `noalias`
    args_is_noalias: std.StaticBitSet(32) = std.StaticBitSet(32).initEmpty(),
    return_type: Index,
    alignment: u16 = 0,
    calling_convention: std.builtin.CallingConvention = .Unspecified,
    is_generic: bool = false,
    is_var_args: bool = false,
};

pub const UnionIndex = enum(u32) { _ };

pub const Union = struct {
    tag_type: Index,
    fields: std.StringArrayHashMapUnmanaged(Field),
    namespace: NamespaceIndex,
    layout: std.builtin.Type.ContainerLayout = .Auto,
    status: FieldStatus,

    pub const Field = packed struct {
        ty: Index,
        alignment: u16,
    };
};

pub const Tuple = struct {
    types: []const Index,
    /// Index.none elements are used to indicate runtime-known.
    values: []const Index,
};

pub const Vector = packed struct {
    len: u32,
    child: Index,
};

pub const AnyFrame = packed struct {
    child: Index,
};

pub const BigInt = std.math.big.int.Const;

pub const Bytes = []const u8;

pub const Aggregate = []const Index;

pub const UnionValue = packed struct {
    field_index: u32,
    val: Index,
};

pub const DeclIndex = enum(u32) { _ };

pub const Decl = struct {
    name: []const u8,
    ty: Index,
    val: Index,
    alignment: u16,
    address_space: std.builtin.AddressSpace,
    is_pub: bool,
    is_exported: bool,
};

pub const Key = union(enum) {
    simple_type: SimpleType,
    simple_value: SimpleValue,

    int_type: Int,
    pointer_type: Pointer,
    array_type: Array,
    /// TODO consider *Struct instead of StructIndex
    struct_type: StructIndex,
    optional_type: Optional,
    error_union_type: ErrorUnion,
    error_set_type: ErrorSet,
    /// TODO consider *Enum instead of EnumIndex
    enum_type: EnumIndex,
    function_type: Function,
    /// TODO consider *Union instead of UnionIndex
    union_type: UnionIndex,
    tuple_type: Tuple,
    vector_type: Vector,
    anyframe_type: AnyFrame,

    int_u64_value: u64,
    int_i64_value: i64,
    int_big_value: BigInt,
    float_16_value: f16,
    float_32_value: f32,
    float_64_value: f64,
    float_80_value: f80,
    float_128_value: f128,

    bytes: Bytes,
    aggregate: Aggregate,
    union_value: UnionValue,

    // slice
    // error
    // error union

    pub fn eql(a: Key, b: Key) bool {
        return deepEql(a, b);
    }

    pub fn hash(a: Key) u32 {
        var hasher = std.hash.Wyhash.init(0);
        deepHash(&hasher, a);
        return @truncate(u32, hasher.final());
    }

    pub fn tag(key: Key) Tag {
        return switch (key) {
            .simple_type => .simple_type,
            .simple_value => .simple_value,

            .int_type => |int_info| switch (int_info.signedness) {
                .signed => .type_int_signed,
                .unsigned => .type_int_unsigned,
            },
            .pointer_type => .type_pointer,
            .array_type => .type_array,
            .struct_type => .type_struct,
            .optional_type => .type_optional,
            .error_union_type => .type_error_union,
            .error_set_type => .type_error_set,
            .enum_type => .type_enum,
            .function_type => .type_function,
            .union_type => .type_union,
            .tuple_type => .type_tuple,
            .vector_type => .type_vector,
            .anyframe_type => .type_anyframe,

            .int_u64_value => |int| if (int <= std.math.maxInt(u32)) .int_u32 else .int_u64,
            .int_i64_value => |int| if (std.math.minInt(i32) <= int and int <= std.math.maxInt(i32)) .int_i32 else .int_i64,
            .int_big_value => |big_int| if (big_int.positive) .int_big_positive else .int_big_negative,
            .float_16_value => .float_f16,
            .float_32_value => .float_f32,
            .float_64_value => .float_f64,
            .float_80_value => .float_f80,
            .float_128_value => .float_f128,

            .bytes => .bytes,
            .aggregate => .aggregate,
            .union_value => .union_value,
        };
    }

    pub fn zigTypeTag(key: Key) std.builtin.TypeId {
        return switch (key) {
            .simple_type => |simple| switch (simple) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .c_longdouble,
                => .Float,

                .usize,
                .isize,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                => .Int,

                .comptime_int => .ComptimeInt,
                .comptime_float => .ComptimeFloat,

                .anyopaque => .Opaque,
                .bool => .Bool,
                .void => .Void,
                .type => .Type,
                .anyerror => .ErrorSet,
                .noreturn => .NoReturn,
                .@"anyframe" => .AnyFrame,
                .null_type => .Null,
                .undefined_type => .Undefined,
                .enum_literal_type => .EnumLiteral,
            },

            .int_type => .Int,
            .pointer_type => .Pointer,
            .array_type => .Array,
            .struct_type => .Struct,
            .optional_type => .Optional,
            .error_union_type => .ErrorUnion,
            .error_set_type => .ErrorSet,
            .enum_type => .Enum,
            .function_type => .Fn,
            .union_type => .Union,
            .tuple_type => .Struct, // TODO this correct?
            .vector_type => .Vector,
            .anyframe_type => .AnyFrame,

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
        };
    }

    pub fn isType(key: Key) bool {
        return switch (key) {
            .simple_type,
            .int_type,
            .pointer_type,
            .array_type,
            .struct_type,
            .optional_type,
            .error_union_type,
            .error_set_type,
            .enum_type,
            .function_type,
            .union_type,
            .tuple_type,
            .vector_type,
            .anyframe_type,
            => true,

            .simple_value,
            .int_u64_value,
            .int_i64_value,
            .int_big_value,
            .float_16_value,
            .float_32_value,
            .float_64_value,
            .float_80_value,
            .float_128_value,
            => false,

            .bytes,
            .aggregate,
            .union_value,
            => false,
        };
    }

    pub fn isValue(key: Key) bool {
        return !key.isValue();
    }

    /// Asserts the type is an integer, enum, error set, packed struct, or vector of one of them.
    pub fn intInfo(ty: Key, target: std.Target, ip: *const InternPool) Int {
        var key: Key = ty;

        while (true) switch (key) {
            .simple_type => |simple| switch (simple) {
                .usize => return .{ .signedness = .signed, .bits = target.cpu.arch.ptrBitWidth() },
                .isize => return .{ .signedness = .unsigned, .bits = target.cpu.arch.ptrBitWidth() },

                .c_short => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.short) },
                .c_ushort => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ushort) },
                .c_int => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.int) },
                .c_uint => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.uint) },
                .c_long => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.long) },
                .c_ulong => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ulong) },
                .c_longlong => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.longlong) },
                .c_ulonglong => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ulonglong) },
                .c_longdouble => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.longdouble) },

                // TODO revisit this when error sets support custom int types (comment taken from zig codebase)
                .anyerror => return .{ .signedness = .unsigned, .bits = 16 },

                else => unreachable,
            },
            .int_type => |int_info| return int_info,
            .enum_type => return panicOrElse("TODO", .{ .signedness = .unsigned, .bits = 0 }),
            .struct_type => |struct_index| {
                const struct_info = ip.getStruct(struct_index);
                assert(struct_info.layout == .Packed);
                key = ip.indexToKey(struct_info.backing_int_ty);
            },
            // TODO revisit this when error sets support custom int types (comment taken from zig codebase)
            .error_set_type => return .{ .signedness = .unsigned, .bits = 16 },
            .vector_type => |vector_info| {
                assert(vector_info.len == 1);
                key = ip.indexToKey(vector_info.child);
            },
            else => unreachable,
        };
    }

    /// Asserts the type is a fixed-size float or comptime_float.
    /// Returns 128 for comptime_float types.
    pub fn floatBits(ty: Key, target: std.Target) u16 {
        return switch (ty.simple_type) {
            .f16 => 16,
            .f32 => 32,
            .f64 => 64,
            .f80 => 80,
            .f128, .comptime_float => 128,
            .c_longdouble => target.c_type_bit_size(.longdouble),

            else => unreachable,
        };
    }

    pub fn isConstPtr(ty: Key) bool {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.is_const,
            else => false,
        };
    }

    /// For pointer-like optionals, returns true, otherwise returns the allowzero property
    /// of pointers.
    pub fn ptrAllowsZero(ty: Key, ip: *const InternPool) bool {
        if (ty.pointer_type.is_allowzero) return true;
        return ty.isPtrLikeOptional(ip);
    }

    /// Returns true if the type is optional and would be lowered to a single pointer
    /// address value, using 0 for null. Note that this returns true for C pointers.
    pub fn isPtrLikeOptional(ty: Key, ip: *const InternPool) bool {
        switch (ty) {
            .optional_type => |optional_info| {
                const child_ty = optional_info.payload_type;
                const child_key = ip.indexToKey(child_ty);
                if (child_key != .pointer_type) return false;
                const info = child_key.pointer_type;
                switch (info.size) {
                    .Slice, .C => return false,
                    .Many, .One => return !info.is_allowzero,
                }
            },
            .pointer_type => |pointer_info| return pointer_info.size == .C,
            else => return false,
        }
    }

    pub fn elemType2(ty: Key) Index {
        return switch (ty) {
            .simple_type => |simple| switch (simple) {
                .@"anyframe" => Index.void,
                else => unreachable,
            },
            .pointer_type => |pointer_info| pointer_info.elem_type,
            .array_type => |array_info| array_info.child,
            .optional_type => |optional_info| optional_info.payload_type,
            .vector_type => |vector_info| vector_info.child,
            .anyframe_type => |anyframe_info| anyframe_info.child,
            else => unreachable,
        };
    }

    /// Asserts the type is an array, pointer or vector.
    pub fn sentinel(ty: Key) Index {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.sentinel,
            .array_type => |array_info| array_info.sentinel,
            .vector_type => Index.none,
            else => unreachable,
        };
    }

    pub fn getNamespace(ty: Key, ip: InternPool) NamespaceIndex {
        return switch (ty) {
            .struct_type => |struct_index| ip.getStruct(struct_index).namespace,
            .enum_type => |enum_index| ip.getEnum(enum_index).namespace,
            .union_type => |union_index| ip.getUnion(union_index).namespace,
            else => .none,
        };
    }

    pub fn onePossibleValue(ty: Key, ip: InternPool) Index {
        return switch (ty) {
            .simple_type => |simple| switch (simple) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                .anyopaque,
                .bool,
                .type,
                .anyerror,
                .comptime_int,
                .comptime_float,
                .@"anyframe",
                .enum_literal_type,
                => Index.none,

                .void => Index.void_value,
                .noreturn => Index.unreachable_value,
                .null_type => Index.null_value,
                .undefined_type => Index.undefined_value,
            },
            .int_type => |int_info| {
                if (int_info.bits == 0) {
                    switch (int_info.signedness) {
                        .unsigned => return Index.zero,
                        .signed => return Index.zero, // do we need a signed zero?
                    }
                }
                return Index.none;
            },
            .pointer_type => Index.none,
            .array_type => |array_info| {
                if (array_info.len == 0) {
                    return panicOrElse("TODO return empty array value", Index.none);
                }
                return ip.indexToKey(array_info.child).onePossibleValue(ip);
            },
            .struct_type => |struct_index| {
                const struct_info = ip.getStruct(struct_index);
                var field_it = struct_info.fields.iterator();
                while (field_it.next()) |entry| {
                    if (entry.value_ptr.is_comptime) continue;
                    if (ip.indexToKey(entry.value_ptr.ty).onePossibleValue(ip) != Index.none) continue;
                    return Index.none;
                }
                return panicOrElse("TODO return empty struct value", Index.none);
            },
            .optional_type => |optional_info| {
                if (optional_info.payload_type == Index.noreturn) {
                    return Index.null_value;
                }
                return Index.none;
            },
            .error_union_type => Index.none,
            .error_set_type => Index.none,
            .enum_type => |enum_index| {
                const enum_info = ip.getEnum(enum_index);
                return switch (enum_info.fields.count()) {
                    0 => Index.unreachable_value,
                    1 => enum_info.values.keys()[0],
                    else => Index.none,
                };
            },
            .function_type => Index.none,
            .union_type => panicOrElse("TODO", Index.none),
            .tuple_type => panicOrElse("TODO", Index.none),
            .vector_type => |vector_info| {
                if (vector_info.len == 0) {
                    return panicOrElse("TODO return empty array value", Index.none);
                }
                return ip.indexToKey(vector_info.child).onePossibleValue(ip);
            },
            .anyframe_type => Index.none,

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
        };
    }

    pub const TypeFormatContext = struct {
        ty: Key,
        options: FormatOptions = .{},
        ip: InternPool,
    };

    pub const ValueFormatContext = struct {
        value: Key,
        /// for most values the type is not needed which is why we use an index
        ty: Index,
        options: FormatOptions = .{},
        ip: InternPool,
    };

    pub const FormatOptions = struct {};

    fn formatType(
        ctx: TypeFormatContext,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, Key);
        try printTypeKey(ctx.ty, ctx.ip, writer);
    }

    fn printType(ty: Index, ip: InternPool, writer: anytype) @TypeOf(writer).Error!void {
        try printTypeKey(ip.indexToKey(ty), ip, writer);
    }

    fn printTypeKey(ty: Key, ip: InternPool, writer: anytype) @TypeOf(writer).Error!void {
        var key = ty;
        while (try printTypeInternal(key, ip, writer)) |index| {
            key = ip.indexToKey(index);
        }
    }

    fn printTypeInternal(ty: Key, ip: InternPool, writer: anytype) @TypeOf(writer).Error!?Index {
        switch (ty) {
            .simple_type => |simple| switch (simple) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                .anyopaque,
                .bool,
                .void,
                .type,
                .anyerror,
                .comptime_int,
                .comptime_float,
                .noreturn,
                .@"anyframe",
                => try writer.writeAll(@tagName(simple)),

                .null_type => try writer.writeAll("@TypeOf(null)"),
                .undefined_type => try writer.writeAll("@TypeOf(undefined)"),
                .enum_literal_type => try writer.writeAll("@TypeOf(.enum_literal)"),
            },
            .int_type => |int_info| switch (int_info.signedness) {
                .signed => try writer.print("i{}", .{int_info.bits}),
                .unsigned => try writer.print("u{}", .{int_info.bits}),
            },
            .pointer_type => |pointer_info| {
                if (pointer_info.sentinel != Index.none) {
                    switch (pointer_info.size) {
                        .One, .C => unreachable,
                        .Many => try writer.print("[*:{}]", .{pointer_info.sentinel.fmtValue(pointer_info.elem_type, ip)}),
                        .Slice => try writer.print("[:{}]", .{pointer_info.sentinel.fmtValue(pointer_info.elem_type, ip)}),
                    }
                } else switch (pointer_info.size) {
                    .One => try writer.writeAll("*"),
                    .Many => try writer.writeAll("[*]"),
                    .C => try writer.writeAll("[*c]"),
                    .Slice => try writer.writeAll("[]"),
                }

                if (pointer_info.alignment != 0) {
                    try writer.print("align({d}", .{pointer_info.alignment});

                    if (pointer_info.bit_offset != 0 or pointer_info.host_size != 0) {
                        try writer.print(":{d}:{d}", .{ pointer_info.bit_offset, pointer_info.host_size });
                    }

                    try writer.writeAll(") ");
                }

                if (pointer_info.address_space != .generic) {
                    try writer.print("addrspace(.{s}) ", .{@tagName(pointer_info.address_space)});
                }

                if (pointer_info.is_const) try writer.writeAll("const ");
                if (pointer_info.is_volatile) try writer.writeAll("volatile ");
                if (pointer_info.is_allowzero and pointer_info.size != .C) try writer.writeAll("allowzero ");

                return pointer_info.elem_type;
            },
            .array_type => |array_info| {
                try writer.print("[{d}", .{array_info.len});
                if (array_info.sentinel != Index.none) {
                    try writer.print(":{}", .{array_info.sentinel.fmtValue(array_info.child, ip)});
                }
                try writer.writeByte(']');

                return array_info.child;
            },
            .struct_type => return panicOrElse("TODO", null),
            .optional_type => |optional_info| {
                try writer.writeByte('?');
                return optional_info.payload_type;
            },
            .error_union_type => |error_union_info| {
                try printType(error_union_info.error_set_type, ip, writer);
                try writer.writeByte('!');
                return error_union_info.payload_type;
            },
            .error_set_type => |error_set_info| {
                const names = error_set_info.names;
                try writer.writeAll("error{");
                for (names) |name, i| {
                    if (i != 0) try writer.writeByte(',');
                    try writer.writeAll(ip.indexToKey(name).bytes);
                }
                try writer.writeByte('}');
            },
            .enum_type => return panicOrElse("TODO", null),
            .function_type => |function_info| {
                try writer.writeAll("fn(");

                for (function_info.args) |arg_ty, i| {
                    if (i != 0) try writer.writeAll(", ");

                    if (i < 32) {
                        if (function_info.args_is_comptime.isSet(i)) {
                            try writer.writeAll("comptime ");
                        }
                        if (function_info.args_is_noalias.isSet(i)) {
                            try writer.writeAll("noalias ");
                        }
                    }

                    try printType(arg_ty, ip, writer);
                }

                if (function_info.is_var_args) {
                    if (function_info.args.len != 0) {
                        try writer.writeAll(", ");
                    }
                    try writer.writeAll("...");
                }
                try writer.writeAll(") ");

                if (function_info.alignment != 0) {
                    try writer.print("align({d}) ", .{function_info.alignment});
                }
                if (function_info.calling_convention != .Unspecified) {
                    try writer.print("callconv(.{s}) ", .{@tagName(function_info.calling_convention)});
                }

                return function_info.return_type;
            },
            .union_type => return panicOrElse("TODO", null),
            .tuple_type => |tuple_info| {
                try writer.writeAll("tuple{");
                for (tuple_info.types) |field_ty, i| {
                    if (i != 0) try writer.writeAll(", ");
                    const val = tuple_info.values[i];
                    if (val != Index.none) {
                        try writer.writeAll("comptime ");
                    }
                    try printType(field_ty, ip, writer);
                    if (val != Index.none) {
                        try writer.print(" = {}", .{val.fmtValue(field_ty, ip)});
                    }
                }
                try writer.writeByte('}');
            },
            .vector_type => |vector_info| {
                try writer.print("@Vector({d},{})", .{
                    vector_info.len,
                    vector_info.child.fmtType(ip),
                });
            },
            .anyframe_type => |anyframe_info| {
                try writer.writeAll("anyframe->");
                return anyframe_info.child;
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
            => unreachable,

            .bytes,
            .aggregate,
            .union_value,
            => unreachable,
        }
        return null;
    }

    fn formatValue(
        ctx: ValueFormatContext,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, Key);
        return printValue(ctx.value, ctx.ty, ctx.ip, writer);
    }

    fn printValue(
        value: Key,
        ty: Index,
        ip: InternPool,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (value) {
            .simple_type => |simple| switch (simple) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                .anyopaque,
                .bool,
                .void,
                .type,
                .anyerror,
                .comptime_int,
                .comptime_float,
                .noreturn,
                .@"anyframe",
                => try writer.writeAll(@tagName(simple)),

                .null_type => try writer.writeAll("@TypeOf(null)"),
                .undefined_type => try writer.writeAll("@TypeOf(undefined)"),
                .enum_literal_type => try writer.writeAll("@TypeOf(.enum_literal)"),
            },
            .simple_value => |simple| switch (simple) {
                .undefined_value => try writer.writeAll("@Type(.Undefined)"),
                .void_value => try writer.writeAll("void"),
                .unreachable_value => try writer.writeAll("unreachable"),
                .null_value => try writer.writeAll("null"),
                .bool_true => try writer.writeAll("true"),
                .bool_false => try writer.writeAll("false"),
            },

            .int_type,
            .pointer_type,
            .array_type,
            .struct_type,
            .optional_type,
            .error_union_type,
            .error_set_type,
            .enum_type,
            .function_type,
            .union_type,
            .tuple_type,
            .vector_type,
            .anyframe_type,
            => unreachable,

            .int_u64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_i64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_big_value => |big_int| try big_int.format("", .{}, writer),
            .float_16_value => |float| try writer.print("{d}", .{float}),
            .float_32_value => |float| try writer.print("{d}", .{float}),
            .float_64_value => |float| try writer.print("{d}", .{float}),
            .float_80_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),
            .float_128_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),

            .bytes => |bytes| try writer.print("\"{}\"", .{std.zig.fmtEscapes(bytes)}),
            .aggregate => |aggregate| {
                const struct_info = ip.getStruct(ip.indexToKey(ty).struct_type);
                assert(aggregate.len == struct_info.fields.count());

                try writer.writeAll(".{");
                var i: u32 = 0;
                while (i < aggregate.len) : (i += 1) {
                    if (i != 0) try writer.writeAll(", ");

                    const field_name = struct_info.fields.keys()[i];
                    try writer.print(".{s} = ", .{field_name});
                    try printValue(ip.indexToKey(aggregate[i]), struct_info.fields.values()[i].ty, ip, writer);
                }
                try writer.writeByte('}');
            },
            .union_value => |union_value| {
                const union_info = ip.getUnion(ip.indexToKey(ty).union_type);

                const name = union_info.fields.keys()[union_value.field_index];
                try writer.print(".{{ .{} = {} }}", .{
                    std.zig.fmtId(name),
                    union_value.val.fmtValue(union_info.fields.values()[union_value.field_index].ty, ip),
                });
            },
        }
    }

    pub fn fmtType(ty: Key, ip: InternPool) std.fmt.Formatter(formatType) {
        return .{ .data = .{
            .ty = ty,
            .ip = ip,
        } };
    }

    pub fn fmtValue(value: Key, ty: Index, ip: InternPool) std.fmt.Formatter(formatValue) {
        return .{ .data = .{
            .value = value,
            .ty = ty,
            .ip = ip,
        } };
    }
};

pub const Item = struct {
    tag: Tag,
    /// The doc comments on the respective Tag explain how to interpret this.
    data: u32,
};

/// Represents an index into `map`. It represents the canonical index
/// of a `Value` within this `InternPool`. The values are typed.
/// Two values which have the same type can be equality compared simply
/// by checking if their indexes are equal, provided they are both in
/// the same `InternPool`.
/// TODO split this into an Optional and non-Optional Index
pub const Index = enum(u32) {
    f16,
    f32,
    f64,
    f80,
    f128,
    usize,
    isize,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_ulonglong,
    c_longdouble,
    anyopaque,
    bool,
    void,
    type,
    anyerror,
    comptime_int,
    comptime_float,
    noreturn,
    @"anyframe",
    null_type,
    undefined_type,
    enum_literal_type,

    undefined_value,
    void_value,
    unreachable_value,
    null_value,
    bool_true,
    bool_false,

    zero,

    none = std.math.maxInt(u32),
    _,

    pub fn fmtType(ty: Index, ip: InternPool) std.fmt.Formatter(Key.formatType) {
        return .{ .data = .{
            .ty = ip.indexToKey(ty),
            .ip = ip,
        } };
    }

    pub fn fmtValue(value_index: Index, type_index: Index, ip: InternPool) std.fmt.Formatter(Key.formatValue) {
        return .{ .data = .{
            .value = ip.indexToKey(value_index),
            .ty = type_index,
            .ip = ip,
        } };
    }
};

pub const NamespaceIndex = enum(u32) {
    none = std.math.maxInt(u32),
    _,
};

pub const Tag = enum(u8) {
    /// A type that can be represented with only an enum tag.
    /// data is SimpleType enum value
    simple_type,
    /// A value that can be represented with only an enum tag.
    /// data is SimpleValue enum value
    simple_value,

    /// An integer type.
    /// data is number of bits
    type_int_signed,
    /// An integer type.
    /// data is number of bits
    type_int_unsigned,
    /// A pointer type.
    /// data is payload to Pointer.
    type_pointer,
    /// An array type.
    /// data is payload to Array.
    type_array,
    /// An struct type.
    /// data is payload to Struct.
    type_struct,
    /// An optional type.
    /// data is index to type
    type_optional,
    /// An error union type.
    /// data is payload to ErrorUnion.
    type_error_union,
    /// An error set type.
    /// data is payload to ErrorSet.
    type_error_set,
    /// An enum type.
    /// data is payload to Enum.
    type_enum,
    /// An function type.
    /// data is payload to Function.
    type_function,
    /// An union type.
    /// data is payload to Union.
    type_union,
    /// An tuple type.
    /// data is payload to Tuple.
    type_tuple,
    /// An vector type.
    /// data is payload to Vector.
    type_vector,
    /// An anyframe->T type.
    /// data is index to type
    type_anyframe,

    /// An unsigned integer value that can be represented by u32.
    /// data is integer value
    int_u32,
    /// An unsigned integer value that can be represented by i32.
    /// data is integer value bitcasted to u32.
    int_i32,
    /// An unsigned integer value that can be represented by u64.
    /// data is payload to u64
    int_u64,
    /// An unsigned integer value that can be represented by u64.
    /// data is payload to i64 bitcasted to u64
    int_i64,
    /// A positive integer value that does not fit in 64 bits.
    /// data is a extra index to BigInt limbs.
    int_big_positive,
    /// A negative integer value that does not fit in 64 bits.
    /// data is a extra index to BigInt limbs.
    int_big_negative,
    /// A float value that can be represented by f16.
    /// data is f16 bitcasted to u16 cast to u32.
    float_f16,
    /// A float value that can be represented by f32.
    /// data is f32 bitcasted to u32.
    float_f32,
    /// A float value that can be represented by f64.
    /// data is payload to f64.
    float_f64,
    /// A float value that can be represented by f80.
    /// data is payload to f80.
    float_f80,
    /// A float value that can be represented by f128.
    /// data is payload to f128.
    float_f128,

    /// A byte sequence value.
    /// data is payload to data begin and length.
    bytes,
    /// A aggregate (struct) value.
    /// data is index to Aggregate.
    aggregate,
    /// A union value.
    /// data is index to UnionValue.
    union_value,
};

pub const SimpleType = enum(u32) {
    f16,
    f32,
    f64,
    f80,
    f128,
    usize,
    isize,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_ulonglong,
    c_longdouble,
    anyopaque,
    bool,
    void,
    type,
    anyerror,
    comptime_int,
    comptime_float,
    noreturn,
    @"anyframe",
    null_type,
    undefined_type,
    enum_literal_type,
};

pub const SimpleValue = enum(u32) {
    undefined_value,
    void_value,
    unreachable_value,
    null_value,
    bool_true,
    bool_false,
};

comptime {
    std.debug.assert(@sizeOf(SimpleType) == @sizeOf(SimpleValue));
}

pub fn init(gpa: Allocator) Allocator.Error!InternPool {
    var ip: InternPool = .{};

    const simple_count = std.meta.fields(SimpleType).len + std.meta.fields(SimpleValue).len;
    const count = simple_count + 1;
    const extra_count = @sizeOf(u64);

    try ip.map.ensureTotalCapacity(gpa, count);
    try ip.items.ensureTotalCapacity(gpa, count);
    try ip.extra.ensureTotalCapacity(gpa, extra_count);

    _ = ip.get(undefined, .{ .simple_type = .f16 }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .f32 }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .f64 }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .f80 }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .f128 }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .usize }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .isize }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_short }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_ushort }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_int }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_uint }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_long }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_ulong }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_longlong }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_ulonglong }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .c_longdouble }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .anyopaque }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .bool }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .void }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .type }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .anyerror }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .comptime_int }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .comptime_float }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .noreturn }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .@"anyframe" }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .null_type }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .undefined_type }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_type = .enum_literal_type }) catch unreachable;

    _ = ip.get(undefined, .{ .simple_value = .undefined_value }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_value = .void_value }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_value = .unreachable_value }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_value = .null_value }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_value = .bool_true }) catch unreachable;
    _ = ip.get(undefined, .{ .simple_value = .bool_false }) catch unreachable;

    _ = ip.get(undefined, .{ .int_u64_value = 0 }) catch unreachable;

    return ip;
}

pub fn deinit(ip: *InternPool, gpa: Allocator) void {
    ip.map.deinit(gpa);
    ip.items.deinit(gpa);
    ip.extra.deinit(gpa);

    var struct_it = ip.structs.iterator(0);
    while (struct_it.next()) |item| {
        item.fields.deinit(gpa);
    }
    var enum_it = ip.enums.iterator(0);
    while (enum_it.next()) |item| {
        item.fields.deinit(gpa);
        item.values.deinit(gpa);
    }
    var union_it = ip.unions.iterator(0);
    while (union_it.next()) |item| {
        item.fields.deinit(gpa);
    }
    ip.decls.deinit(gpa);
    ip.structs.deinit(gpa);
    ip.enums.deinit(gpa);
    ip.unions.deinit(gpa);
}

pub fn indexToKey(ip: InternPool, index: Index) Key {
    const item = ip.items.get(@enumToInt(index));
    const data = item.data;
    return switch (item.tag) {
        .simple_type => .{ .simple_type = @intToEnum(SimpleType, data) },
        .simple_value => .{ .simple_value = @intToEnum(SimpleValue, data) },

        .type_int_signed => .{ .int_type = .{
            .signedness = .signed,
            .bits = @intCast(u16, data),
        } },
        .type_int_unsigned => .{ .int_type = .{
            .signedness = .unsigned,
            .bits = @intCast(u16, data),
        } },
        .type_pointer => .{ .pointer_type = ip.extraData(Pointer, data) },
        .type_array => .{ .array_type = ip.extraData(Array, data) },
        .type_optional => .{ .optional_type = .{ .payload_type = @intToEnum(Index, data) } },
        .type_anyframe => .{ .anyframe_type = .{ .child = @intToEnum(Index, data) } },
        .type_error_union => .{ .error_union_type = ip.extraData(ErrorUnion, data) },
        .type_error_set => .{ .error_set_type = ip.extraData(ErrorSet, data) },
        .type_function => .{ .function_type = ip.extraData(Function, data) },
        .type_tuple => .{ .tuple_type = ip.extraData(Tuple, data) },
        .type_vector => .{ .vector_type = ip.extraData(Vector, data) },

        .type_struct => .{ .struct_type = @intToEnum(StructIndex, data) },
        .type_enum => .{ .enum_type = @intToEnum(EnumIndex, data) },
        .type_union => .{ .union_type = @intToEnum(UnionIndex, data) },

        .int_u32 => .{ .int_u64_value = @intCast(u32, data) },
        .int_i32 => .{ .int_i64_value = @bitCast(i32, data) },
        .int_u64 => .{ .int_u64_value = ip.extraData(u64, data) },
        .int_i64 => .{ .int_i64_value = ip.extraData(i64, data) },
        .int_big_positive => .{ .int_big_value = .{
            .positive = true,
            .limbs = ip.extraData([]const std.math.big.Limb, data),
        } },
        .int_big_negative => .{ .int_big_value = .{
            .positive = false,
            .limbs = ip.extraData([]const std.math.big.Limb, data),
        } },
        .float_f16 => .{ .float_16_value = @bitCast(f16, @intCast(u16, data)) },
        .float_f32 => .{ .float_32_value = @bitCast(f32, data) },
        .float_f64 => .{ .float_64_value = ip.extraData(f64, data) },
        .float_f80 => .{ .float_80_value = ip.extraData(f80, data) },
        .float_f128 => .{ .float_128_value = ip.extraData(f128, data) },

        .bytes => .{ .bytes = ip.extraData([]const u8, data) },
        .aggregate => .{ .aggregate = ip.extraData(Aggregate, data) },
        .union_value => .{ .union_value = ip.extraData(UnionValue, data) },
    };
}

pub fn indexToTag(ip: InternPool, index: Index) std.builtin.TypeId {
    const item = ip.items.get(@enumToInt(index));
    const data = item.data;
    return switch (item.tag) {
        .simple_type => {
            const key = Key{ .simple_type = @intToEnum(SimpleType, data) };
            return key.zigTypeTag();
        },

        .type_int_signed => .Int,
        .type_int_unsigned => .Int,
        .type_pointer => .Pointer,
        .type_array => .Array,
        .type_struct => .Struct,
        .type_optional => .Optional,
        .type_anyframe => .AnyFrame,
        .type_error_union => .ErrorUnion,
        .type_error_set => .ErrorSet,
        .type_enum => .Enum,
        .type_function => .Fn,
        .type_union => .Union,
        .type_tuple => .Struct,
        .type_vector => .Vector,

        .simple_value,
        .int_u32,
        .int_i32,
        .int_u64,
        .int_i64,
        .int_big_positive,
        .int_big_negative,
        .float_f16,
        .float_f32,
        .float_f64,
        .float_f80,
        .float_f128,
        => unreachable,

        .bytes => unreachable,
        .aggregate => unreachable,
        .union_value => unreachable,
    };
}

pub fn get(ip: *InternPool, gpa: Allocator, key: Key) Allocator.Error!Index {
    const adapter: KeyAdapter = .{ .ip = ip };
    const gop = try ip.map.getOrPutAdapted(gpa, key, adapter);
    if (gop.found_existing) return @intToEnum(Index, gop.index);

    const tag: Tag = key.tag();
    const data: u32 = switch (key) {
        .simple_type => |simple| @enumToInt(simple),
        .simple_value => |simple| @enumToInt(simple),

        .int_type => |int_ty| int_ty.bits,
        .optional_type => |optional_ty| @enumToInt(optional_ty.payload_type),
        .anyframe_type => |anyframe_ty| @enumToInt(anyframe_ty.child),

        .struct_type => |struct_index| @enumToInt(struct_index),
        .enum_type => |enum_index| @enumToInt(enum_index),
        .union_type => |union_index| @enumToInt(union_index),

        .int_u64_value => |int_val| if (tag == .int_u32) @intCast(u32, int_val) else try ip.addExtra(gpa, int_val),
        .int_i64_value => |int_val| if (tag == .int_i32) @bitCast(u32, @intCast(u32, int_val)) else try ip.addExtra(gpa, int_val),
        .int_big_value => |big_int_val| try ip.addExtra(gpa, big_int_val.limbs),
        .float_16_value => |float_val| @bitCast(u16, float_val),
        .float_32_value => |float_val| @bitCast(u32, float_val),
        inline else => |data| try ip.addExtra(gpa, data), // TODO sad stage1 noises :(
    };

    try ip.items.append(gpa, .{
        .tag = tag,
        .data = data,
    });
    return @intToEnum(Index, ip.items.len - 1);
}

pub fn contains(ip: InternPool, key: Key) ?Index {
    const adapter: KeyAdapter = .{ .ip = &ip };
    const index = ip.map.getIndexAdapted(key, adapter) orelse return null;
    return @intToEnum(Index, index);
}

pub fn getDecl(ip: InternPool, index: InternPool.DeclIndex) *InternPool.Decl {
    var decls = ip.decls;
    return decls.at(@enumToInt(index));
}
pub fn getStruct(ip: InternPool, index: InternPool.StructIndex) *InternPool.Struct {
    var structs = ip.structs;
    return structs.at(@enumToInt(index));
}
pub fn getEnum(ip: InternPool, index: InternPool.EnumIndex) *InternPool.Enum {
    var enums = ip.enums;
    return enums.at(@enumToInt(index));
}
pub fn getUnion(ip: InternPool, index: InternPool.UnionIndex) *InternPool.Union {
    var unions = ip.unions;
    return unions.at(@enumToInt(index));
}

pub fn createDecl(ip: *InternPool, gpa: Allocator, decl: InternPool.Decl) error{OutOfMemory}!InternPool.DeclIndex {
    try ip.decls.append(gpa, decl);
    return @intToEnum(InternPool.DeclIndex, ip.decls.count() - 1);
}
pub fn createStruct(ip: *InternPool, gpa: Allocator, struct_info: InternPool.Struct) error{OutOfMemory}!InternPool.StructIndex {
    try ip.structs.append(gpa, struct_info);
    return @intToEnum(InternPool.StructIndex, ip.structs.count() - 1);
}
pub fn createEnum(ip: *InternPool, gpa: Allocator, enum_info: InternPool.Enum) error{OutOfMemory}!InternPool.EnumIndex {
    try ip.enums.append(gpa, enum_info);
    return @intToEnum(InternPool.EnumIndex, ip.enums.count() - 1);
}
pub fn createUnion(ip: *InternPool, gpa: Allocator, union_info: InternPool.Union) error{OutOfMemory}!InternPool.UnionIndex {
    try ip.unions.append(gpa, union_info);
    return @intToEnum(InternPool.UnionIndex, ip.unions.count() - 1);
}

fn addExtra(ip: *InternPool, gpa: Allocator, extra: anytype) Allocator.Error!u32 {
    const T = @TypeOf(extra);
    comptime if (@sizeOf(T) <= 4) {
        @compileError(@typeName(T) ++ " fits into a u32! Consider directly storing this extra in Item's data field");
    };

    const result = @intCast(u32, ip.extra.items.len);
    var managed = ip.extra.toManaged(gpa);
    defer ip.extra = managed.moveToUnmanaged();
    try encoding.encode(&managed, T, extra);
    return result;
}

fn extraData(ip: InternPool, comptime T: type, index: usize) T {
    var bytes: []const u8 = ip.extra.items[index..];
    return encoding.decode(&bytes, T);
}

const KeyAdapter = struct {
    ip: *const InternPool,

    pub fn eql(ctx: @This(), a: Key, b_void: void, b_map_index: usize) bool {
        _ = b_void;
        return a.eql(ctx.ip.indexToKey(@intToEnum(Index, b_map_index)));
    }

    pub fn hash(ctx: @This(), a: Key) u32 {
        _ = ctx;
        return a.hash();
    }
};

fn deepEql(a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);

    switch (@typeInfo(T)) {
        .Struct => |info| {
            if (info.layout == .Packed and comptime std.meta.trait.hasUniqueRepresentation(T)) {
                return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
            }
            inline for (info.fields) |field_info| {
                if (!deepEql(@field(a, field_info.name), @field(b, field_info.name))) return false;
            }
            return true;
        },
        .Union => |info| {
            const UnionTag = info.tag_type.?;

            const tag_a = std.meta.activeTag(a);
            const tag_b = std.meta.activeTag(b);
            if (tag_a != tag_b) return false;

            inline for (info.fields) |field_info| {
                if (@field(UnionTag, field_info.name) == tag_a) {
                    return deepEql(@field(a, field_info.name), @field(b, field_info.name));
                }
            }
            return false;
        },
        .Pointer => |info| switch (info.size) {
            .One => return deepEql(a.*, b.*),
            .Slice => {
                if (a.len != b.len) return false;

                var i: usize = 0;
                while (i < a.len) : (i += 1) {
                    if (!deepEql(a[i], b[i])) return false;
                }
                return true;
            },
            .Many,
            .C,
            => @compileError("Unable to equality compare pointer " ++ @typeName(T)),
        },
        .Float => {
            const I = std.meta.Int(.unsigned, @bitSizeOf(T));
            return @bitCast(I, a) == @bitCast(I, b);
        },
        .Bool,
        .Int,
        .Enum,
        => return a == b,
        else => @compileError("Unable to equality compare type " ++ @typeName(T)),
    }
}

fn deepHash(hasher: anytype, key: anytype) void {
    const T = @TypeOf(key);

    switch (@typeInfo(T)) {
        .Int => {
            if (comptime std.meta.trait.hasUniqueRepresentation(Tuple)) {
                hasher.update(std.mem.asBytes(&key));
            } else {
                const byte_size = comptime std.math.divCeil(comptime_int, @bitSizeOf(T), 8) catch unreachable;
                hasher.update(std.mem.asBytes(&key)[0..byte_size]);
            }
        },

        .Bool => deepHash(hasher, @boolToInt(key)),
        .Enum => deepHash(hasher, @enumToInt(key)),
        .Float => |info| deepHash(hasher, switch (info.bits) {
            16 => @bitCast(u16, key),
            32 => @bitCast(u32, key),
            64 => @bitCast(u64, key),
            80 => @bitCast(u80, key),
            128 => @bitCast(u128, key),
            else => unreachable,
        }),

        .Pointer => |info| switch (info.size) {
            .One => {
                deepHash(hasher, key.*);
            },
            .Slice => {
                if (info.child == u8) {
                    hasher.update(key);
                } else {
                    for (key) |item| {
                        deepHash(hasher, item);
                    }
                }
            },
            .Many,
            .C,
            => @compileError("Unable to hash pointer " ++ @typeName(T)),
        },
        .Struct => |info| {
            if (info.layout == .Packed and comptime std.meta.trait.hasUniqueRepresentation(T)) {
                hasher.update(std.mem.asBytes(&key));
            } else {
                inline for (info.fields) |field| {
                    deepHash(hasher, @field(key, field.name));
                }
            }
        },

        .Union => |info| {
            const TagType = info.tag_type.?;

            const tag = std.meta.activeTag(key);
            deepHash(hasher, tag);
            inline for (info.fields) |field| {
                if (@field(TagType, field.name) == tag) {
                    deepHash(hasher, @field(key, field.name));
                    break;
                }
            }
        },
        else => @compileError("Unable to hash type " ++ @typeName(T)),
    }
}

// ---------------------------------------------
//                    UTILITY
// ---------------------------------------------

pub fn cast(ip: *InternPool, gpa: Allocator, destination_ty: Index, source_ty: Index, target: std.Target) Allocator.Error!Index {
    return resolvePeerTypes(ip, gpa, &.{ destination_ty, source_ty }, target);
}

pub fn resolvePeerTypes(ip: *InternPool, gpa: Allocator, types: []const Index, target: std.Target) Allocator.Error!Index {
    switch (types.len) {
        0 => return Index.noreturn,
        1 => return types[0],
        else => {},
    }

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    var arena = arena_allocator.allocator();

    var chosen = types[0];
    // If this is non-null then it does the following thing, depending on the chosen zigTypeTag().
    //  * ErrorSet: this is an override
    //  * ErrorUnion: this is an override of the error set only
    //  * other: at the end we make an ErrorUnion with the other thing and this
    var err_set_ty: Index = Index.none;
    var any_are_null = false;
    var seen_const = false;
    var convert_to_slice = false;
    var chosen_i: usize = 0;
    for (types[1..]) |candidate, candidate_i| {
        if (candidate == chosen) continue;

        const candidate_key: Key = ip.indexToKey(candidate);
        const chosen_key = ip.indexToKey(chosen);

        // If the candidate can coerce into our chosen type, we're done.
        // If the chosen type can coerce into the candidate, use that.
        if ((try ip.coerceInMemoryAllowed(gpa, arena, chosen, candidate, true, target)) == .ok) {
            continue;
        }
        if ((try ip.coerceInMemoryAllowed(gpa, arena, candidate, chosen, true, target)) == .ok) {
            chosen = candidate;
            chosen_i = candidate_i + 1;
            continue;
        }

        switch (candidate_key) {
            .simple_type => |candidate_simple| switch (candidate_simple) {
                .f16, .f32, .f64, .f80, .f128 => switch (chosen_key) {
                    .simple_type => |chosen_simple| switch (chosen_simple) {
                        .f16, .f32, .f64, .f80, .f128 => {
                            if (chosen_key.floatBits(target) < candidate_key.floatBits(target)) {
                                chosen = candidate;
                                chosen_i = candidate_i + 1;
                            }
                            continue;
                        },
                        .comptime_int, .comptime_float => {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        },
                        else => {},
                    },
                    else => {},
                },

                .usize,
                .isize,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                => switch (chosen_key) {
                    .simple_type => |chosen_simple| switch (chosen_simple) {
                        .usize,
                        .isize,
                        .c_short,
                        .c_ushort,
                        .c_int,
                        .c_uint,
                        .c_long,
                        .c_ulong,
                        .c_longlong,
                        .c_ulonglong,
                        .c_longdouble,
                        => {
                            const chosen_bits = chosen_key.intInfo(target, ip).bits;
                            const candidate_bits = candidate_key.intInfo(target, ip).bits;

                            if (chosen_bits < candidate_bits) {
                                chosen = candidate;
                                chosen_i = candidate_i + 1;
                            }
                            continue;
                        },
                        .comptime_int => {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        },
                        else => {},
                    },
                    .int_type => |chosen_info| {
                        if (chosen_info.bits < candidate_key.intInfo(target, ip).bits) {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                        }
                        continue;
                    },
                    .pointer_type => |chosen_info| if (chosen_info.size == .C) continue,
                    else => {},
                },

                .noreturn, .undefined_type => continue,

                .comptime_int => switch (chosen_key) {
                    .simple_type => |chosen_simple| switch (chosen_simple) {
                        .f16,
                        .f32,
                        .f64,
                        .f80,
                        .f128,
                        .usize,
                        .isize,
                        .c_short,
                        .c_ushort,
                        .c_int,
                        .c_uint,
                        .c_long,
                        .c_ulong,
                        .c_longlong,
                        .c_ulonglong,
                        .c_longdouble,
                        .comptime_float,
                        => continue,
                        .comptime_int => unreachable,
                        else => {},
                    },
                    .int_type => continue,
                    .pointer_type => |chosen_info| if (chosen_info.size == .C) continue,
                    else => {},
                },
                .comptime_float => switch (chosen_key) {
                    .simple_type => |chosen_simple| switch (chosen_simple) {
                        .f16, .f32, .f64, .f80, .f128 => continue,
                        .comptime_int => {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        },
                        .comptime_float => unreachable,
                        else => {},
                    },
                    else => {},
                },
                .null_type => {
                    any_are_null = true;
                    continue;
                },
                else => {},
            },
            .int_type => |candidate_info| switch (chosen_key) {
                .simple_type => |chosen_simple| switch (chosen_simple) {
                    .usize,
                    .isize,
                    .c_short,
                    .c_ushort,
                    .c_int,
                    .c_uint,
                    .c_long,
                    .c_ulong,
                    .c_longlong,
                    .c_ulonglong,
                    .c_longdouble,
                    => {
                        const chosen_bits = chosen_key.intInfo(target, ip).bits;
                        const candidate_bits = candidate_key.intInfo(target, ip).bits;

                        if (chosen_bits < candidate_bits) {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                        }
                        continue;
                    },
                    .comptime_int => {
                        chosen = candidate;
                        chosen_i = candidate_i + 1;
                        continue;
                    },
                    else => {},
                },
                .int_type => |chosen_info| {
                    if (chosen_info.bits < candidate_info.bits) {
                        chosen = candidate;
                        chosen_i = candidate_i + 1;
                    }
                    continue;
                },
                .pointer_type => |chosen_info| if (chosen_info.size == .C) continue,
                else => {},
            },
            .pointer_type => |candidate_info| switch (chosen_key) {
                .simple_type => |chosen_simple| switch (chosen_simple) {
                    .comptime_int => {
                        if (candidate_info.size == .C) {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        }
                    },
                    else => {},
                },
                .pointer_type => |chosen_info| {
                    seen_const = seen_const or chosen_info.is_const or candidate_info.is_const;

                    const candidate_elem_info = ip.indexToKey(candidate_info.elem_type);
                    const chosen_elem_info = ip.indexToKey(chosen_info.elem_type);

                    // *[N]T to [*]T
                    // *[N]T to []T
                    if ((candidate_info.size == .Many or candidate_info.size == .Slice) and
                        chosen_info.size == .One and
                        chosen_elem_info == .array_type)
                    {
                        // In case we see i.e.: `*[1]T`, `*[2]T`, `[*]T`
                        convert_to_slice = false;
                        chosen = candidate;
                        chosen_i = candidate_i + 1;
                        continue;
                    }
                    if (candidate_info.size == .One and
                        candidate_elem_info == .array_type and
                        (chosen_info.size == .Many or chosen_info.size == .Slice))
                    {
                        // In case we see i.e.: `*[1]T`, `*[2]T`, `[*]T`
                        convert_to_slice = false;
                        continue;
                    }

                    // *[N]T and *[M]T
                    // Verify both are single-pointers to arrays.
                    // Keep the one whose element type can be coerced into.
                    if (chosen_info.size == .One and
                        candidate_info.size == .One and
                        chosen_elem_info == .array_type and
                        candidate_elem_info == .array_type)
                    {
                        const chosen_elem_ty = chosen_elem_info.array_type.child;
                        const cand_elem_ty = candidate_elem_info.array_type.child;

                        const chosen_ok = .ok == try ip.coerceInMemoryAllowed(gpa, arena, chosen_elem_ty, cand_elem_ty, chosen_info.is_const, target);
                        if (chosen_ok) {
                            convert_to_slice = true;
                            continue;
                        }

                        const cand_ok = .ok == try ip.coerceInMemoryAllowed(gpa, arena, cand_elem_ty, chosen_elem_ty, candidate_info.is_const, target);
                        if (cand_ok) {
                            convert_to_slice = true;
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        }

                        // They're both bad. Report error.
                        // In the future we probably want to use the
                        // coerceInMemoryAllowed error reporting mechanism,
                        // however, for now we just fall through for the
                        // "incompatible types" error below.
                    }

                    // [*c]T and any other pointer size
                    // Whichever element type can coerce to the other one, is
                    // the one we will keep. If they're both OK then we keep the
                    // C pointer since it matches both single and many pointers.
                    if (candidate_info.size == .C or chosen_info.size == .C) {
                        const cand_ok = .ok == try ip.coerceInMemoryAllowed(gpa, arena, candidate_info.elem_type, chosen_info.elem_type, candidate_info.is_const, target);
                        const chosen_ok = .ok == try ip.coerceInMemoryAllowed(gpa, arena, chosen_info.elem_type, candidate_info.elem_type, chosen_info.is_const, target);

                        if (cand_ok) {
                            if (!chosen_ok or chosen_info.size != .C) {
                                chosen = candidate;
                                chosen_i = candidate_i + 1;
                            }
                            continue;
                        } else {
                            if (chosen_ok) continue;
                            // They're both bad. Report error.
                            // In the future we probably want to use the
                            // coerceInMemoryAllowed error reporting mechanism,
                            // however, for now we just fall through for the
                            // "incompatible types" error below.
                        }
                    }
                },
                .int_type => {
                    if (candidate_info.size == .C) {
                        chosen = candidate;
                        chosen_i = candidate_i + 1;
                        continue;
                    }
                },
                .optional_type => |chosen_info| switch (ip.indexToKey(chosen_info.payload_type)) {
                    .pointer_type => |chosen_ptr_info| {
                        seen_const = seen_const or chosen_ptr_info.is_const or candidate_info.is_const;

                        // *[N]T to ?![*]T
                        // *[N]T to ?![]T
                        if (candidate_info.size == .One and
                            ip.indexToKey(candidate_info.elem_type) == .array_type and
                            (chosen_ptr_info.size == .Many or chosen_ptr_info.size == .Slice))
                        {
                            continue;
                        }
                    },
                    else => {},
                },
                .error_union_type => |chosen_info| {
                    const chosen_ptr_key = ip.indexToKey(chosen_info.payload_type);

                    if (chosen_ptr_key == .pointer_type) {
                        const chosen_ptr_info = chosen_ptr_key.pointer_type;
                        seen_const = seen_const or chosen_ptr_info.is_const or candidate_info.is_const;

                        // *[N]T to E![*]T
                        // *[N]T to E![]T
                        if (candidate_info.size == .One and
                            (chosen_ptr_info.size == .Many or chosen_ptr_info.size == .Slice) and
                            ip.indexToKey(candidate_info.elem_type) == .array_type)
                        {
                            continue;
                        }
                    }
                },
                .function_type => |chosen_info| {
                    if (candidate_info.is_const) {
                        const candidate_elem_key = ip.indexToKey(candidate_info.elem_type);
                        if (candidate_elem_key == .function_type and
                            .ok == try ip.coerceInMemoryAllowedFns(gpa, arena, chosen_info, candidate_elem_key.function_type, target))
                        {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        }
                    }
                },
                else => {},
            },
            .array_type => switch (chosen_key) {
                .vector_type => continue,
                else => {},
            },
            .optional_type => |candidate_info| {
                if ((try ip.coerceInMemoryAllowed(gpa, arena, chosen, candidate_info.payload_type, true, target)) == .ok) {
                    seen_const = seen_const or ip.indexToKey(candidate_info.payload_type).isConstPtr();
                    any_are_null = true;
                    continue;
                }

                seen_const = seen_const or chosen_key.isConstPtr();
                any_are_null = false;
                chosen = candidate;
                chosen_i = candidate_i + 1;
                continue;
            },
            .vector_type => switch (chosen_key) {
                .array_type => {
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                },
                else => {},
            },
            else => {},
        }

        switch (chosen_key) {
            .simple_type => |simple| switch (simple) {
                .noreturn,
                .undefined_type,
                => {
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                },
                .null_type => {
                    any_are_null = true;
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                },
                else => {},
            },
            .optional_type => |chosen_info| {
                if ((try ip.coerceInMemoryAllowed(gpa, arena, chosen_info.payload_type, candidate, true, target)) == .ok) {
                    continue;
                }
                if ((try ip.coerceInMemoryAllowed(gpa, arena, candidate, chosen_info.payload_type, true, target)) == .ok) {
                    any_are_null = true;
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                }
            },
            .error_union_type => |chosen_info| {
                if ((try ip.coerceInMemoryAllowed(gpa, arena, chosen_info.payload_type, candidate, true, target)) == .ok) {
                    continue;
                }
            },
            else => {},
        }

        return Index.none;
    }

    if (chosen == .none) return chosen;
    const chosen_key = ip.indexToKey(chosen);

    if (convert_to_slice) {
        // turn *[N]T => []T
        const chosen_elem_key = ip.indexToKey(chosen_key.pointer_type.elem_type);
        var info = chosen_key.pointer_type;
        info.sentinel = chosen_elem_key.sentinel();
        info.size = .Slice;
        info.is_const = seen_const or chosen_elem_key.isConstPtr();
        info.elem_type = chosen_elem_key.elemType2();

        const new_ptr_ty = try ip.get(gpa, .{ .pointer_type = info });
        const opt_ptr_ty = if (any_are_null) try ip.get(gpa, .{ .optional_type = .{ .payload_type = new_ptr_ty } }) else new_ptr_ty;
        const set_ty = if (err_set_ty != .none) err_set_ty else return opt_ptr_ty;
        return try ip.get(gpa, .{ .error_union_type = .{
            .error_set_type = set_ty,
            .payload_type = opt_ptr_ty,
        } });
    }

    if (seen_const) {
        // turn []T => []const T
        switch (chosen_key) {
            .error_union_type => |error_union_info| {
                var info: Pointer = ip.indexToKey(error_union_info.payload_type).pointer_type;
                info.is_const = true;

                const new_ptr_ty = try ip.get(gpa, .{ .pointer_type = info });
                const opt_ptr_ty = if (any_are_null) try ip.get(gpa, .{ .optional_type = .{ .payload_type = new_ptr_ty } }) else new_ptr_ty;
                const set_ty = if (err_set_ty != .none) err_set_ty else error_union_info.error_set_type;
                return try ip.get(gpa, .{ .error_union_type = .{
                    .error_set_type = set_ty,
                    .payload_type = opt_ptr_ty,
                } });
            },
            .pointer_type => |pointer_info| {
                var info = pointer_info;
                info.is_const = true;

                const new_ptr_ty = try ip.get(gpa, .{ .pointer_type = info });
                const opt_ptr_ty = if (any_are_null) try ip.get(gpa, .{ .optional_type = .{ .payload_type = new_ptr_ty } }) else new_ptr_ty;
                const set_ty = if (err_set_ty != .none) err_set_ty else return opt_ptr_ty;
                return try ip.get(gpa, .{ .error_union_type = .{
                    .error_set_type = set_ty,
                    .payload_type = opt_ptr_ty,
                } });
            },
            else => return chosen,
        }
    }

    if (any_are_null) {
        const opt_ty = switch (chosen_key) {
            .simple_type => |simple| switch (simple) {
                .null_type => chosen,
                else => try ip.get(gpa, .{ .optional_type = .{ .payload_type = chosen } }),
            },
            .optional_type => chosen,
            else => try ip.get(gpa, .{ .optional_type = .{ .payload_type = chosen } }),
        };
        const set_ty = if (err_set_ty != .none) err_set_ty else return opt_ty;
        return try ip.get(gpa, .{ .error_union_type = .{
            .error_set_type = set_ty,
            .payload_type = opt_ty,
        } });
    }

    return chosen;
}

const InMemoryCoercionResult = union(enum) {
    ok,
    no_match: Pair,
    int_not_coercible: IntMismatch,
    error_union_payload: PairAndChild,
    array_len: IntPair,
    array_sentinel: Sentinel,
    array_elem: PairAndChild,
    vector_len: IntPair,
    vector_elem: PairAndChild,
    optional_shape: Pair,
    optional_child: PairAndChild,
    from_anyerror,
    missing_error: []const []const u8,
    /// true if wanted is var args
    fn_var_args: bool,
    /// true if wanted is generic
    fn_generic: bool,
    fn_param_count: IntPair,
    fn_param_noalias: IntPair,
    fn_param_comptime: ComptimeParam,
    fn_param: Param,
    fn_cc: CC,
    fn_return_type: PairAndChild,
    ptr_child: PairAndChild,
    ptr_addrspace: AddressSpace,
    ptr_sentinel: Sentinel,
    ptr_size: Size,
    ptr_qualifiers: Qualifiers,
    ptr_allowzero: Pair,
    ptr_bit_range: BitRange,
    ptr_alignment: IntPair,

    const Pair = struct {
        actual: Index, // type
        wanted: Index, // type
    };

    const PairAndChild = struct {
        child: *InMemoryCoercionResult,
        actual: Index, // type
        wanted: Index, // type
    };

    const Param = struct {
        child: *InMemoryCoercionResult,
        actual: Index, // type
        wanted: Index, // type
        index: u64,
    };

    const ComptimeParam = struct {
        index: u64,
        wanted: bool,
    };

    const Sentinel = struct {
        // Index.none indicates no sentinel
        actual: Index, // value
        wanted: Index, // value
        ty: Index,
    };

    const IntMismatch = struct {
        actual_signedness: std.builtin.Signedness,
        wanted_signedness: std.builtin.Signedness,
        actual_bits: u16,
        wanted_bits: u16,
    };

    const IntPair = struct {
        actual: u64,
        wanted: u64,
    };

    const Size = struct {
        actual: std.builtin.Type.Pointer.Size,
        wanted: std.builtin.Type.Pointer.Size,
    };

    const Qualifiers = struct {
        actual_const: bool,
        wanted_const: bool,
        actual_volatile: bool,
        wanted_volatile: bool,
    };

    const AddressSpace = struct {
        actual: std.builtin.AddressSpace,
        wanted: std.builtin.AddressSpace,
    };

    const CC = struct {
        actual: std.builtin.CallingConvention,
        wanted: std.builtin.CallingConvention,
    };

    const BitRange = struct {
        actual_host: u16,
        wanted_host: u16,
        actual_offset: u16,
        wanted_offset: u16,
    };

    fn dupe(child: *const InMemoryCoercionResult, arena: Allocator) !*InMemoryCoercionResult {
        const res = try arena.create(InMemoryCoercionResult);
        res.* = child.*;
        return res;
    }
};

/// If types have the same representation in runtime memory
/// * int/float: same number of bits
/// * pointer: see `coerceInMemoryAllowedPtrs`
/// * error union: coerceable error set and payload
/// * error set: sub-set to super-set
/// * array: same shape and coerceable child
fn coerceInMemoryAllowed(
    ip: *InternPool,
    gpa: Allocator,
    arena: Allocator,
    dest_ty: Index,
    src_ty: Index,
    dest_is_const: bool,
    target: std.Target,
) error{OutOfMemory}!InMemoryCoercionResult {
    if (dest_ty == src_ty) return .ok;

    const dest_key = ip.indexToKey(dest_ty);
    const src_key = ip.indexToKey(src_ty);

    const dest_tag = dest_key.zigTypeTag();
    const src_tag = src_key.zigTypeTag();

    if (dest_tag != src_tag) {
        return InMemoryCoercionResult{ .no_match = .{
            .actual = dest_ty,
            .wanted = src_ty,
        } };
    }

    switch (dest_tag) {
        .Int => {
            const dest_info = dest_key.intInfo(target, ip);
            const src_info = src_key.intInfo(target, ip);

            if (dest_info.signedness == src_info.signedness and dest_info.bits == src_info.bits) return .ok;

            if ((src_info.signedness == dest_info.signedness and dest_info.bits < src_info.bits) or
                // small enough unsigned ints can get casted to large enough signed ints
                (dest_info.signedness == .signed and (src_info.signedness == .unsigned or dest_info.bits <= src_info.bits)) or
                (dest_info.signedness == .unsigned and src_info.signedness == .signed))
            {
                return InMemoryCoercionResult{ .int_not_coercible = .{
                    .actual_signedness = src_info.signedness,
                    .wanted_signedness = dest_info.signedness,
                    .actual_bits = src_info.bits,
                    .wanted_bits = dest_info.bits,
                } };
            }
            return .ok;
        },
        .Float => {
            const dest_bits = dest_key.floatBits(target);
            const src_bits = src_key.floatBits(target);
            if (dest_bits == src_bits) return .ok;
            // TODO return float_not_coercible
            return InMemoryCoercionResult{ .no_match = .{
                .actual = dest_ty,
                .wanted = src_ty,
            } };
        },
        .Pointer => {
            return try ip.coerceInMemoryAllowedPtrs(gpa, arena, dest_ty, src_ty, dest_key, src_key, dest_is_const, target);
        },
        .Optional => {
            // Pointer-like Optionals
            const maybe_dest_ptr_ty = try ip.optionalPtrTy(dest_key);
            const maybe_src_ptr_ty = try ip.optionalPtrTy(src_key);
            if (maybe_dest_ptr_ty != .none and maybe_src_ptr_ty != .none) {
                const dest_ptr_info = ip.indexToKey(maybe_dest_ptr_ty);
                const src_ptr_info = ip.indexToKey(maybe_src_ptr_ty);
                return try ip.coerceInMemoryAllowedPtrs(gpa, arena, dest_ty, src_ty, dest_ptr_info, src_ptr_info, dest_is_const, target);
            }

            if (maybe_dest_ptr_ty != maybe_src_ptr_ty) {
                return InMemoryCoercionResult{ .optional_shape = .{
                    .actual = src_ty,
                    .wanted = dest_ty,
                } };
            }

            const dest_child_type = dest_key.optional_type.payload_type;
            const src_child_type = src_key.optional_type.payload_type;

            const child = try ip.coerceInMemoryAllowed(gpa, arena, dest_child_type, src_child_type, dest_is_const, target);
            if (child != .ok) {
                return InMemoryCoercionResult{ .optional_child = .{
                    .child = try child.dupe(arena),
                    .actual = src_child_type,
                    .wanted = dest_child_type,
                } };
            }

            return .ok;
        },
        .Fn => {
            return try ip.coerceInMemoryAllowedFns(gpa, arena, dest_key.function_type, src_key.function_type, target);
        },
        .ErrorUnion => {
            const dest_payload = dest_key.error_union_type.payload_type;
            const src_payload = src_key.error_union_type.payload_type;
            const child = try ip.coerceInMemoryAllowed(gpa, arena, dest_payload, src_payload, dest_is_const, target);
            if (child != .ok) {
                return InMemoryCoercionResult{ .error_union_payload = .{
                    .child = try child.dupe(arena),
                    .actual = src_payload,
                    .wanted = dest_payload,
                } };
            }
            const dest_set = dest_key.error_union_type.error_set_type;
            const src_set = src_key.error_union_type.error_set_type;
            return try ip.coerceInMemoryAllowed(gpa, arena, dest_set, src_set, dest_is_const, target);
        },
        .ErrorSet => {
            return .ok;
            // TODO: implement coerceInMemoryAllowedErrorSets
            // return try ip.coerceInMemoryAllowedErrorSets(dest_ty, src_ty);
        },
        .Array => {
            const dest_info = dest_key.array_type;
            const src_info = src_key.array_type;
            if (dest_info.len != src_info.len) {
                return InMemoryCoercionResult{ .array_len = .{
                    .actual = src_info.len,
                    .wanted = dest_info.len,
                } };
            }

            const child = try ip.coerceInMemoryAllowed(gpa, arena, dest_info.child, src_info.child, dest_is_const, target);
            if (child != .ok) {
                return InMemoryCoercionResult{ .array_elem = .{
                    .child = try child.dupe(arena),
                    .actual = src_info.child,
                    .wanted = dest_info.child,
                } };
            }

            const ok_sent = dest_info.sentinel == Index.none or
                (src_info.sentinel != Index.none and
                dest_info.sentinel == src_info.sentinel // is this enough for a value equality check?
            );
            if (!ok_sent) {
                return InMemoryCoercionResult{ .array_sentinel = .{
                    .actual = src_info.sentinel,
                    .wanted = dest_info.sentinel,
                    .ty = dest_info.child,
                } };
            }
            return .ok;
        },
        .Vector => {
            const dest_len = dest_key.vector_type.len;
            const src_len = src_key.vector_type.len;

            if (dest_len != src_len) {
                return InMemoryCoercionResult{ .vector_len = .{
                    .actual = src_len,
                    .wanted = dest_len,
                } };
            }

            const dest_elem_ty = dest_key.vector_type.child;
            const src_elem_ty = src_key.vector_type.child;
            const child = try ip.coerceInMemoryAllowed(gpa, arena, dest_elem_ty, src_elem_ty, dest_is_const, target);
            if (child != .ok) {
                return InMemoryCoercionResult{ .vector_elem = .{
                    .child = try child.dupe(arena),
                    .actual = src_elem_ty,
                    .wanted = dest_elem_ty,
                } };
            }

            return .ok;
        },
        else => {
            return InMemoryCoercionResult{ .no_match = .{
                .actual = dest_ty,
                .wanted = src_ty,
            } };
        },
    }
}

// fn coerceInMemoryAllowedErrorSets(
//     ip: *InternPool,
//     gpa: Allocator,
//     arena: Allocator,
//     dest_ty: Index,
//     src_ty: Index,
// ) !InMemoryCoercionResult {
//     if(dest_ty == src_ty) return .ok;

//     const dest_key = ip.indexToKey(dest_ty);

//     // Coercion to `anyerror`. Note that this check can return false negatives
//     // in case the error sets did not get resolved.
//     if(dest_key.simple) |simple| if(simple == .anyerror) return .ok;

//     const src_key = ip.indexToKey(src_ty);

//     // const dest_tag = dest_key.zigTypeTag();
//     // const src_tag = src_key.zigTypeTag();

//     if (dest_ty.castTag(.error_set_inferred)) |dst_payload| {
//         const dst_ies = dst_payload.data;
//         // We will make an effort to return `ok` without resolving either error set, to
//         // avoid unnecessary "unable to resolve error set" dependency loop errors.
//         switch (src_ty.tag()) {
//             .error_set_inferred => {
//                 // If both are inferred error sets of functions, and
//                 // the dest includes the source function, the coercion is OK.
//                 // This check is important because it works without forcing a full resolution
//                 // of inferred error sets.
//                 const src_ies = src_ty.castTag(.error_set_inferred).?.data;

//                 if (dst_ies.inferred_error_sets.contains(src_ies)) {
//                     return .ok;
//                 }
//             },
//             .error_set_single => {
//                 const name = src_ty.castTag(.error_set_single).?.data;
//                 if (dst_ies.errors.contains(name)) return .ok;
//             },
//             .error_set_merged => {
//                 const names = src_ty.castTag(.error_set_merged).?.data.keys();
//                 for (names) |name| {
//                     if (!dst_ies.errors.contains(name)) break;
//                 } else return .ok;
//             },
//             .error_set => {
//                 const names = src_ty.castTag(.error_set).?.data.names.keys();
//                 for (names) |name| {
//                     if (!dst_ies.errors.contains(name)) break;
//                 } else return .ok;
//             },
//             .anyerror => {},
//             else => unreachable,
//         }

//         if (dst_ies.func == sema.owner_func) {
//             // We are trying to coerce an error set to the current function's
//             // inferred error set.
//             try dst_ies.addErrorSet(sema.gpa, src_ty);
//             return .ok;
//         }

//         try sema.resolveInferredErrorSet(block, dest_src, dst_payload.data);
//         // isAnyError might have changed from a false negative to a true positive after resolution.
//         if (dest_ty.isAnyError()) {
//             return .ok;
//         }
//     }

//     var missing_error_buf = std.ArrayList([]const u8).init(sema.gpa);
//     defer missing_error_buf.deinit();

//     switch (src_ty.tag()) {
//         .error_set_inferred => {
//             const src_data = src_ty.castTag(.error_set_inferred).?.data;

//             try sema.resolveInferredErrorSet(block, src_src, src_data);
//             // src anyerror status might have changed after the resolution.
//             if (src_ty.isAnyError()) {
//                 // dest_ty.isAnyError() == true is already checked for at this point.
//                 return .from_anyerror;
//             }

//             for (src_data.errors.keys()) |key| {
//                 if (!dest_ty.errorSetHasField(key)) {
//                     try missing_error_buf.append(key);
//                 }
//             }

//             if (missing_error_buf.items.len != 0) {
//                 return InMemoryCoercionResult{
//                     .missing_error = try sema.arena.dupe([]const u8, missing_error_buf.items),
//                 };
//             }

//             return .ok;
//         },
//         .error_set_single => {
//             const name = src_ty.castTag(.error_set_single).?.data;
//             if (dest_ty.errorSetHasField(name)) {
//                 return .ok;
//             }
//             const list = try sema.arena.alloc([]const u8, 1);
//             list[0] = name;
//             return InMemoryCoercionResult{ .missing_error = list };
//         },
//         .error_set_merged => {
//             const names = src_ty.castTag(.error_set_merged).?.data.keys();
//             for (names) |name| {
//                 if (!dest_ty.errorSetHasField(name)) {
//                     try missing_error_buf.append(name);
//                 }
//             }

//             if (missing_error_buf.items.len != 0) {
//                 return InMemoryCoercionResult{
//                     .missing_error = try sema.arena.dupe([]const u8, missing_error_buf.items),
//                 };
//             }

//             return .ok;
//         },
//         .error_set => {
//             const names = src_ty.castTag(.error_set).?.data.names.keys();
//             for (names) |name| {
//                 if (!dest_ty.errorSetHasField(name)) {
//                     try missing_error_buf.append(name);
//                 }
//             }

//             if (missing_error_buf.items.len != 0) {
//                 return InMemoryCoercionResult{
//                     .missing_error = try sema.arena.dupe([]const u8, missing_error_buf.items),
//                 };
//             }

//             return .ok;
//         },
//         .anyerror => switch (dest_ty.tag()) {
//             .error_set_inferred => unreachable, // Caught by dest_ty.isAnyError() above.
//             .error_set_single, .error_set_merged, .error_set => return .from_anyerror,
//             .anyerror => unreachable, // Filtered out above.
//             else => unreachable,
//         },
//         else => unreachable,
//     }

//     unreachable;
// }

fn coerceInMemoryAllowedFns(
    ip: *InternPool,
    gpa: Allocator,
    arena: Allocator,
    dest_info: Function,
    src_info: Function,
    target: std.Target,
) error{OutOfMemory}!InMemoryCoercionResult {
    if (dest_info.is_var_args != src_info.is_var_args) {
        return InMemoryCoercionResult{ .fn_var_args = dest_info.is_var_args };
    }

    if (dest_info.is_generic != src_info.is_generic) {
        return InMemoryCoercionResult{ .fn_generic = dest_info.is_generic };
    }

    if (dest_info.calling_convention != src_info.calling_convention) {
        return InMemoryCoercionResult{ .fn_cc = .{
            .actual = src_info.calling_convention,
            .wanted = dest_info.calling_convention,
        } };
    }

    if (src_info.return_type != Index.noreturn) {
        const rt = try ip.coerceInMemoryAllowed(gpa, arena, dest_info.return_type, src_info.return_type, true, target);
        if (rt != .ok) {
            return InMemoryCoercionResult{ .fn_return_type = .{
                .child = try rt.dupe(arena),
                .actual = src_info.return_type,
                .wanted = dest_info.return_type,
            } };
        }
    }

    if (dest_info.args.len != src_info.args.len) {
        return InMemoryCoercionResult{ .fn_param_count = .{
            .actual = src_info.args.len,
            .wanted = dest_info.args.len,
        } };
    }

    if (!dest_info.args_is_noalias.eql(src_info.args_is_noalias)) {
        return InMemoryCoercionResult{ .fn_param_noalias = .{
            .actual = src_info.args_is_noalias.mask,
            .wanted = dest_info.args_is_noalias.mask,
        } };
    }

    if (!dest_info.args_is_comptime.eql(src_info.args_is_comptime)) {
        const index = dest_info.args_is_comptime.xorWith(src_info.args_is_comptime).findFirstSet().?;
        return InMemoryCoercionResult{ .fn_param_comptime = .{
            .index = index,
            .wanted = dest_info.args_is_comptime.isSet(index),
        } };
    }

    for (dest_info.args) |dest_arg_ty, i| {
        const src_arg_ty = src_info.args[i];

        // Note: Cast direction is reversed here.
        const param = try ip.coerceInMemoryAllowed(gpa, arena, src_arg_ty, dest_arg_ty, true, target);
        if (param != .ok) {
            return InMemoryCoercionResult{ .fn_param = .{
                .child = try param.dupe(arena),
                .actual = src_arg_ty,
                .wanted = dest_arg_ty,
                .index = i,
            } };
        }
    }

    return .ok;
}

/// If pointers have the same representation in runtime memory
/// * `const` attribute can be gained
/// * `volatile` attribute can be gained
/// * `allowzero` attribute can be gained (whether from explicit attribute, C pointer, or optional pointer) but only if dest_is_const
/// * alignment can be decreased
/// * bit offset attributes must match exactly
/// * `*`/`[*]` must match exactly, but `[*c]` matches either one
/// * sentinel-terminated pointers can coerce into `[*]`
fn coerceInMemoryAllowedPtrs(
    ip: *InternPool,
    gpa: Allocator,
    arena: Allocator,
    dest_ty: Index,
    src_ty: Index,
    dest_ptr_info: Key,
    src_ptr_info: Key,
    dest_is_const: bool,
    target: std.Target,
) error{OutOfMemory}!InMemoryCoercionResult {
    const dest_info = dest_ptr_info.pointer_type;
    const src_info = src_ptr_info.pointer_type;

    const ok_ptr_size = src_info.size == dest_info.size or
        src_info.size == .C or dest_info.size == .C;
    if (!ok_ptr_size) {
        return InMemoryCoercionResult{ .ptr_size = .{
            .actual = src_info.size,
            .wanted = dest_info.size,
        } };
    }

    const ok_cv_qualifiers =
        (!src_info.is_const or dest_info.is_const) and
        (!src_info.is_volatile or dest_info.is_volatile);

    if (!ok_cv_qualifiers) {
        return InMemoryCoercionResult{ .ptr_qualifiers = .{
            .actual_const = src_info.is_const,
            .wanted_const = dest_info.is_const,
            .actual_volatile = src_info.is_volatile,
            .wanted_volatile = dest_info.is_volatile,
        } };
    }

    if (dest_info.address_space != src_info.address_space) {
        return InMemoryCoercionResult{ .ptr_addrspace = .{
            .actual = src_info.address_space,
            .wanted = dest_info.address_space,
        } };
    }

    const child = try ip.coerceInMemoryAllowed(gpa, arena, dest_info.elem_type, src_info.elem_type, dest_info.is_const, target);
    if (child != .ok) {
        return InMemoryCoercionResult{ .ptr_child = .{
            .child = try child.dupe(arena),
            .actual = src_info.elem_type,
            .wanted = dest_info.elem_type,
        } };
    }

    const dest_allow_zero = dest_ptr_info.ptrAllowsZero(ip);
    const src_allow_zero = src_ptr_info.ptrAllowsZero(ip);

    const ok_allows_zero = (dest_allow_zero and (src_allow_zero or dest_is_const)) or (!dest_allow_zero and !src_allow_zero);
    if (!ok_allows_zero) {
        return InMemoryCoercionResult{ .ptr_allowzero = .{
            .actual = src_ty,
            .wanted = dest_ty,
        } };
    }

    if (src_info.host_size != dest_info.host_size or
        src_info.bit_offset != dest_info.bit_offset)
    {
        return InMemoryCoercionResult{ .ptr_bit_range = .{
            .actual_host = src_info.host_size,
            .wanted_host = dest_info.host_size,
            .actual_offset = src_info.bit_offset,
            .wanted_offset = dest_info.bit_offset,
        } };
    }

    const ok_sent = dest_info.sentinel == .none or src_info.size == .C or dest_info.sentinel == src_info.sentinel; // is this enough for a value equality check?
    if (!ok_sent) {
        return InMemoryCoercionResult{ .ptr_sentinel = .{
            .actual = src_info.sentinel,
            .wanted = dest_info.sentinel,
            .ty = dest_info.elem_type,
        } };
    }

    // If both pointers have alignment 0, it means they both want ABI alignment.
    // In this case, if they share the same child type, no need to resolve
    // pointee type alignment. Otherwise both pointee types must have their alignment
    // resolved and we compare the alignment numerically.
    alignment: {
        if (src_info.alignment == 0 and dest_info.alignment == 0 and
            dest_info.elem_type == src_info.elem_type // is this enough for a value equality check?
        ) {
            break :alignment;
        }

        // const src_align = if (src_info.alignment != 0)
        //     src_info.alignment
        // else
        //     src_info.elem_type.abiAlignment(target);

        // const dest_align = if (dest_info.alignment != 0)
        //     dest_info.alignment
        // else
        //     dest_info.elem_type.abiAlignment(target);

        // if (dest_align > src_align) {
        //     return InMemoryCoercionResult{ .ptr_alignment = .{
        //         .actual = src_align,
        //         .wanted = dest_align,
        //     } };
        // }

        break :alignment;
    }

    return .ok;
}

fn optionalPtrTy(
    ip: InternPool,
    ty: Key,
) !Index {
    switch (ty) {
        .optional_type => |optional_info| {
            const child_type = optional_info.payload_type;
            const child_key = ip.indexToKey(child_type);

            if (child_key != .pointer_type) return Index.none;
            const child_ptr_key = child_key.pointer_type;

            switch (child_ptr_key.size) {
                .Slice, .C => return Index.none,
                .Many, .One => {
                    if (child_ptr_key.is_allowzero) return Index.none;

                    // optionals of zero sized types behave like bools, not pointers
                    if (child_key.onePossibleValue(ip) != Index.none) return Index.none;

                    return child_type;
                },
            }
        },
        else => unreachable,
    }
}

/// will panic in during testing else will return `value`
inline fn panicOrElse(message: []const u8, value: anytype) @TypeOf(value) {
    if (builtin.is_test) {
        @panic(message);
    }
    return value;
}

// ---------------------------------------------
//                     TESTS
// ---------------------------------------------

fn testExpectFmtType(ip: InternPool, index: Index, expected: []const u8) !void {
    try std.testing.expectFmt(expected, "{}", .{index.fmtType(ip)});
}

fn testExpectFmtValue(ip: InternPool, val: Index, ty: Index, expected: []const u8) !void {
    try std.testing.expectFmt(expected, "{}", .{val.fmtValue(ty, ip)});
}

test "simple types" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const null_type = try ip.get(gpa, .{ .simple_type = .null_type });
    const undefined_type = try ip.get(gpa, .{ .simple_type = .undefined_type });
    const enum_literal_type = try ip.get(gpa, .{ .simple_type = .enum_literal_type });

    const undefined_value = try ip.get(gpa, .{ .simple_value = .undefined_value });
    const void_value = try ip.get(gpa, .{ .simple_value = .void_value });
    const unreachable_value = try ip.get(gpa, .{ .simple_value = .unreachable_value });
    const null_value = try ip.get(gpa, .{ .simple_value = .null_value });
    const bool_true = try ip.get(gpa, .{ .simple_value = .bool_true });
    const bool_false = try ip.get(gpa, .{ .simple_value = .bool_false });

    try testExpectFmtType(ip, null_type, "@TypeOf(null)");
    try testExpectFmtType(ip, undefined_type, "@TypeOf(undefined)");
    try testExpectFmtType(ip, enum_literal_type, "@TypeOf(.enum_literal)");

    try testExpectFmtValue(ip, undefined_value, Index.none, "@Type(.Undefined)");
    try testExpectFmtValue(ip, void_value, Index.none, "void");
    try testExpectFmtValue(ip, unreachable_value, Index.none, "unreachable");
    try testExpectFmtValue(ip, null_value, Index.none, "null");
    try testExpectFmtValue(ip, bool_true, Index.none, "true");
    try testExpectFmtValue(ip, bool_false, Index.none, "false");
}

test "int type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });
    const u7_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 7 } });
    const another_i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });

    try std.testing.expect(i32_type == another_i32_type);
    try std.testing.expect(i32_type != u7_type);

    try std.testing.expect(i16_type != another_i32_type);
    try std.testing.expect(i16_type != u7_type);

    try testExpectFmtType(ip, i32_type, "i32");
    try testExpectFmtType(ip, i16_type, "i16");
    try testExpectFmtType(ip, u7_type, "u7");
}

test "int value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const unsigned_zero_value = try ip.get(gpa, .{ .int_u64_value = 0 });
    const unsigned_one_value = try ip.get(gpa, .{ .int_u64_value = 1 });
    const signed_zero_value = try ip.get(gpa, .{ .int_i64_value = 0 });
    const signed_one_value = try ip.get(gpa, .{ .int_i64_value = 1 });

    const u64_max_value = try ip.get(gpa, .{ .int_u64_value = std.math.maxInt(u64) });
    const i64_max_value = try ip.get(gpa, .{ .int_i64_value = std.math.maxInt(i64) });
    const i64_min_value = try ip.get(gpa, .{ .int_i64_value = std.math.minInt(i64) });

    const tags = ip.items.items(.tag);
    try std.testing.expect(tags[@enumToInt(unsigned_one_value)] == .int_u32);
    try std.testing.expect(tags[@enumToInt(signed_one_value)] == .int_i32);
    try std.testing.expect(tags[@enumToInt(u64_max_value)] == .int_u64);
    try std.testing.expect(tags[@enumToInt(i64_max_value)] == .int_i64);
    try std.testing.expect(tags[@enumToInt(i64_min_value)] == .int_i64);

    try std.testing.expect(unsigned_zero_value != unsigned_one_value);
    try std.testing.expect(unsigned_one_value != signed_zero_value);
    try std.testing.expect(signed_zero_value != signed_one_value);

    try std.testing.expect(signed_one_value != u64_max_value);
    try std.testing.expect(u64_max_value != i64_max_value);
    try std.testing.expect(i64_max_value != i64_min_value);

    try testExpectFmtValue(ip, unsigned_zero_value, undefined, "0");
    try testExpectFmtValue(ip, unsigned_one_value, undefined, "1");
    try testExpectFmtValue(ip, signed_zero_value, undefined, "0");
    try testExpectFmtValue(ip, signed_one_value, undefined, "1");

    try testExpectFmtValue(ip, u64_max_value, undefined, "18446744073709551615");
    try testExpectFmtValue(ip, i64_max_value, undefined, "9223372036854775807");
    try testExpectFmtValue(ip, i64_min_value, undefined, "-9223372036854775808");
}

test "big int value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    var result = try std.math.big.int.Managed.init(gpa);
    defer result.deinit();
    var a = try std.math.big.int.Managed.initSet(gpa, 2);
    defer a.deinit();

    try result.pow(&a, 128);

    const positive_big_int_value = try ip.get(gpa, .{ .int_big_value = result.toConst() });
    const negative_big_int_value = try ip.get(gpa, .{ .int_big_value = result.toConst().negate() });

    try testExpectFmtValue(ip, positive_big_int_value, Index.none, "340282366920938463463374607431768211456");
    try testExpectFmtValue(ip, negative_big_int_value, Index.none, "-340282366920938463463374607431768211456");
}

test "float type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const f16_type = try ip.get(gpa, .{ .simple_type = .f16 });
    const f32_type = try ip.get(gpa, .{ .simple_type = .f32 });
    const f64_type = try ip.get(gpa, .{ .simple_type = .f64 });
    const f80_type = try ip.get(gpa, .{ .simple_type = .f80 });
    const f128_type = try ip.get(gpa, .{ .simple_type = .f128 });

    const another_f32_type = try ip.get(gpa, .{ .simple_type = .f32 });
    const another_f64_type = try ip.get(gpa, .{ .simple_type = .f64 });

    try std.testing.expect(f16_type != f32_type);
    try std.testing.expect(f32_type != f64_type);
    try std.testing.expect(f64_type != f80_type);
    try std.testing.expect(f80_type != f128_type);

    try std.testing.expect(f32_type == another_f32_type);
    try std.testing.expect(f64_type == another_f64_type);

    try testExpectFmtType(ip, f16_type, "f16");
    try testExpectFmtType(ip, f32_type, "f32");
    try testExpectFmtType(ip, f64_type, "f64");
    try testExpectFmtType(ip, f80_type, "f80");
    try testExpectFmtType(ip, f128_type, "f128");
}

test "float value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const f16_value = try ip.get(gpa, .{ .float_16_value = 0.25 });
    const f32_value = try ip.get(gpa, .{ .float_32_value = 0.5 });
    const f64_value = try ip.get(gpa, .{ .float_64_value = 1.0 });
    const f80_value = try ip.get(gpa, .{ .float_80_value = 2.0 });
    const f128_value = try ip.get(gpa, .{ .float_128_value = 2.75 });

    const f32_nan_value = try ip.get(gpa, .{ .float_32_value = std.math.nan_f32 });
    const f32_qnan_value = try ip.get(gpa, .{ .float_32_value = std.math.qnan_f32 });

    const f32_inf_value = try ip.get(gpa, .{ .float_32_value = std.math.inf_f32 });
    const f32_ninf_value = try ip.get(gpa, .{ .float_32_value = -std.math.inf_f32 });

    const f32_zero_value = try ip.get(gpa, .{ .float_32_value = 0.0 });
    const f32_nzero_value = try ip.get(gpa, .{ .float_32_value = -0.0 });

    try std.testing.expect(f16_value != f32_value);
    try std.testing.expect(f32_value != f64_value);
    try std.testing.expect(f64_value != f80_value);
    try std.testing.expect(f80_value != f128_value);

    try std.testing.expect(f32_nan_value != f32_qnan_value);
    try std.testing.expect(f32_inf_value != f32_ninf_value);
    try std.testing.expect(f32_zero_value != f32_nzero_value);

    try std.testing.expect(!ip.indexToKey(f16_value).eql(ip.indexToKey(f32_value)));
    try std.testing.expect(ip.indexToKey(f32_value).eql(ip.indexToKey(f32_value)));

    try std.testing.expect(ip.indexToKey(f32_nan_value).eql(ip.indexToKey(f32_nan_value)));
    try std.testing.expect(!ip.indexToKey(f32_nan_value).eql(ip.indexToKey(f32_qnan_value)));

    try std.testing.expect(ip.indexToKey(f32_inf_value).eql(ip.indexToKey(f32_inf_value)));
    try std.testing.expect(!ip.indexToKey(f32_inf_value).eql(ip.indexToKey(f32_ninf_value)));

    try std.testing.expect(ip.indexToKey(f32_zero_value).eql(ip.indexToKey(f32_zero_value)));
    try std.testing.expect(!ip.indexToKey(f32_zero_value).eql(ip.indexToKey(f32_nzero_value)));

    try testExpectFmtValue(ip, f16_value, undefined, "0.25");
    try testExpectFmtValue(ip, f32_value, undefined, "0.5");
    try testExpectFmtValue(ip, f64_value, undefined, "1");
    try testExpectFmtValue(ip, f80_value, undefined, "2");
    try testExpectFmtValue(ip, f128_value, undefined, "2.75");

    try testExpectFmtValue(ip, f32_nan_value, undefined, "nan");
    try testExpectFmtValue(ip, f32_qnan_value, undefined, "nan");

    try testExpectFmtValue(ip, f32_inf_value, undefined, "inf");
    try testExpectFmtValue(ip, f32_ninf_value, undefined, "-inf");

    try testExpectFmtValue(ip, f32_zero_value, undefined, "0");
    try testExpectFmtValue(ip, f32_nzero_value, undefined, "-0");
}

test "pointer type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    const zero_value = try ip.get(gpa, .{ .int_u64_value = 0 });

    const @"*i32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = i32_type,
        .size = .One,
    } });
    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
    } });
    const @"*const volatile u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
        .is_const = true,
        .is_volatile = true,
    } });
    const @"*align(4:2:3) u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
        .alignment = 4,
        .bit_offset = 2,
        .host_size = 3,
    } });
    const @"*addrspace(.shared) const u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
        .is_const = true,
        .address_space = .shared,
    } });

    const @"[*]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .Many,
    } });
    const @"[*:0]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .Many,
        .sentinel = zero_value,
    } });
    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .Slice,
    } });
    const @"[:0]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .Slice,
        .sentinel = zero_value,
    } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .C,
    } });

    try std.testing.expect(@"*i32" != @"*u32");
    try std.testing.expect(@"*u32" != @"*const volatile u32");
    try std.testing.expect(@"*const volatile u32" != @"*align(4:2:3) u32");
    try std.testing.expect(@"*align(4:2:3) u32" != @"*addrspace(.shared) const u32");

    try std.testing.expect(@"[*]u32" != @"[*:0]u32");
    try std.testing.expect(@"[*:0]u32" != @"[]u32");
    try std.testing.expect(@"[*:0]u32" != @"[:0]u32");
    try std.testing.expect(@"[:0]u32" != @"[*c]u32");

    try testExpectFmtType(ip, @"*i32", "*i32");
    try testExpectFmtType(ip, @"*u32", "*u32");
    try testExpectFmtType(ip, @"*const volatile u32", "*const volatile u32");
    try testExpectFmtType(ip, @"*align(4:2:3) u32", "*align(4:2:3) u32");
    try testExpectFmtType(ip, @"*addrspace(.shared) const u32", "*addrspace(.shared) const u32");

    try testExpectFmtType(ip, @"[*]u32", "[*]u32");
    try testExpectFmtType(ip, @"[*:0]u32", "[*:0]u32");
    try testExpectFmtType(ip, @"[]u32", "[]u32");
    try testExpectFmtType(ip, @"[:0]u32", "[:0]u32");
    try testExpectFmtType(ip, @"[*c]u32", "[*c]u32");
}

test "optional type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type_0 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i32_type_1 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    const null_value = try ip.get(gpa, .{ .simple_value = .null_value });
    const u64_42_value = try ip.get(gpa, .{ .int_u64_value = 42 });

    const i32_optional_type_0 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_0 } });
    const i32_optional_type_1 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_1 } });
    const u32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = u32_type } });

    try std.testing.expect(i32_optional_type_0 == i32_optional_type_1);
    try std.testing.expect(i32_optional_type_0 != u32_optional_type);

    try testExpectFmtType(ip, i32_optional_type_0, "?i32");
    try testExpectFmtType(ip, u32_optional_type, "?u32");

    try testExpectFmtValue(ip, null_value, u32_optional_type, "null");
    try testExpectFmtValue(ip, u64_42_value, u32_optional_type, "42");
}

test "error set type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const foo_name = try ip.get(gpa, .{ .bytes = "foo" });
    const bar_name = try ip.get(gpa, .{ .bytes = "bar" });
    const baz_name = try ip.get(gpa, .{ .bytes = "baz" });

    const empty_error_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{} } });

    const error_set_0 = try ip.get(gpa, .{ .error_set_type = .{
        .names = &.{ foo_name, bar_name, baz_name },
    } });

    const error_set_1 = try ip.get(gpa, .{ .error_set_type = .{
        .names = &.{ foo_name, bar_name },
    } });

    try std.testing.expect(empty_error_set != error_set_0);
    try std.testing.expect(error_set_0 != error_set_1);

    try testExpectFmtType(ip, empty_error_set, "error{}");
    try testExpectFmtType(ip, error_set_0, "error{foo,bar,baz}");
    try testExpectFmtType(ip, error_set_1, "error{foo,bar}");
}

test "error union type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const empty_error_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{} } });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const @"error{}!bool" = try ip.get(gpa, .{ .error_union_type = .{
        .error_set_type = empty_error_set,
        .payload_type = bool_type,
    } });

    try testExpectFmtType(ip, @"error{}!bool", "error{}!bool");
}

test "array type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type_0 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i32_type_1 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const zero_value = try ip.get(gpa, .{ .int_u64_value = 0 });

    const i32_3_array_type_0 = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = i32_type_0,
    } });
    const i32_3_array_type_1 = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = i32_type_1,
    } });
    const u32_0_0_array_type = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = u32_type,
        .sentinel = zero_value,
    } });

    try std.testing.expect(i32_3_array_type_0 == i32_3_array_type_1);
    try std.testing.expect(i32_3_array_type_1 != u32_0_0_array_type);

    try testExpectFmtType(ip, i32_3_array_type_0, "[3]i32");
    try testExpectFmtType(ip, u32_0_0_array_type, "[3:0]u32");
}

test "struct value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const struct_index = try ip.createStruct(gpa, .{
        .fields = .{},
        .namespace = .none,
        .layout = .Auto,
        .backing_int_ty = .none,
        .status = .none,
    });
    const struct_type = try ip.get(gpa, .{ .struct_type = struct_index });
    const struct_info = ip.getStruct(struct_index);
    try struct_info.fields.put(gpa, "foo", .{ .ty = i32_type });
    try struct_info.fields.put(gpa, "bar", .{ .ty = bool_type });

    const one_value = try ip.get(gpa, .{ .int_i64_value = 1 });
    const true_value = try ip.get(gpa, .{ .simple_value = .bool_true });

    const aggregate_value = try ip.get(gpa, Key{ .aggregate = &.{ one_value, true_value } });

    try ip.testExpectFmtValue(aggregate_value, struct_type, ".{.foo = 1, .bar = true}");
}

test "function type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });
    const type_type = try ip.get(gpa, .{ .simple_type = .type });

    const @"fn(i32) bool" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{i32_type},
        .return_type = bool_type,
    } });

    var args_is_comptime = std.StaticBitSet(32).initEmpty();
    args_is_comptime.set(0);
    var args_is_noalias = std.StaticBitSet(32).initEmpty();
    args_is_noalias.set(1);

    const @"fn(comptime type, noalias i32) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{ type_type, i32_type },
        .args_is_comptime = args_is_comptime,
        .args_is_noalias = args_is_noalias,
        .return_type = type_type,
    } });

    const @"fn(i32, ...) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{i32_type},
        .return_type = type_type,
        .is_var_args = true,
    } });

    const @"fn() align(4) callconv(.C) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{},
        .return_type = type_type,
        .alignment = 4,
        .calling_convention = .C,
    } });

    try testExpectFmtType(ip, @"fn(i32) bool", "fn(i32) bool");
    try testExpectFmtType(ip, @"fn(comptime type, noalias i32) type", "fn(comptime type, noalias i32) type");
    try testExpectFmtType(ip, @"fn(i32, ...) type", "fn(i32, ...) type");
    try testExpectFmtType(ip, @"fn() align(4) callconv(.C) type", "fn() align(4) callconv(.C) type");
}

test "union value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const f16_type = try ip.get(gpa, .{ .simple_type = .f16 });

    const int_value = try ip.get(gpa, .{ .int_u64_value = 1 });
    const f16_value = try ip.get(gpa, .{ .float_16_value = 0.25 });

    const union_index = try ip.createUnion(gpa, .{
        .tag_type = .none,
        .fields = .{},
        .namespace = .none,
        .layout = .Auto,
        .status = .none,
    });
    const union_type = try ip.get(gpa, .{ .union_type = union_index });
    const union_info = ip.getUnion(union_index);
    try union_info.fields.put(gpa, "int", .{ .ty = u32_type, .alignment = 0 });
    try union_info.fields.put(gpa, "float", .{ .ty = f16_type, .alignment = 0 });

    const union_value1 = try ip.get(gpa, .{ .union_value = .{
        .field_index = 0,
        .val = int_value,
    } });
    const union_value2 = try ip.get(gpa, .{ .union_value = .{
        .field_index = 1,
        .val = f16_value,
    } });

    try testExpectFmtValue(ip, union_value1, union_type, ".{ .int = 1 }");
    try testExpectFmtValue(ip, union_value2, union_type, ".{ .float = 0.25 }");
}

test "anyframe type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const @"anyframe->i32" = try ip.get(gpa, .{ .anyframe_type = .{ .child = i32_type } });
    const @"anyframe->bool" = try ip.get(gpa, .{ .anyframe_type = .{ .child = bool_type } });

    try std.testing.expect(@"anyframe->i32" != @"anyframe->bool");

    try testExpectFmtType(ip, @"anyframe->i32", "anyframe->i32");
    try testExpectFmtType(ip, @"anyframe->bool", "anyframe->bool");
}

test "vector type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const @"@Vector(2,u32)" = try ip.get(gpa, .{ .vector_type = .{
        .len = 2,
        .child = u32_type,
    } });
    const @"@Vector(2,bool)" = try ip.get(gpa, .{ .vector_type = .{
        .len = 2,
        .child = bool_type,
    } });

    try std.testing.expect(@"@Vector(2,u32)" != @"@Vector(2,bool)");

    try testExpectFmtType(ip, @"@Vector(2,u32)", "@Vector(2,u32)");
    try testExpectFmtType(ip, @"@Vector(2,bool)", "@Vector(2,bool)");
}

test "bytes value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    var str1: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value1 = try ip.get(gpa, .{ .bytes = &str1 });
    @memset(&str1, 0, str1.len);

    var str2: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value2 = try ip.get(gpa, .{ .bytes = &str2 });
    @memset(&str2, 0, str2.len);

    var str3: [26]u8 = "https://www.duckduckgo.com".*;
    const bytes_value3 = try ip.get(gpa, .{ .bytes = &str3 });
    @memset(&str3, 0, str3.len);

    try std.testing.expect(bytes_value1 == bytes_value2);
    try std.testing.expect(bytes_value2 != bytes_value3);

    try std.testing.expect(@ptrToInt(&str1) != @ptrToInt(ip.indexToKey(bytes_value1).bytes.ptr));
    try std.testing.expect(@ptrToInt(&str2) != @ptrToInt(ip.indexToKey(bytes_value2).bytes.ptr));
    try std.testing.expect(@ptrToInt(&str3) != @ptrToInt(ip.indexToKey(bytes_value3).bytes.ptr));

    try std.testing.expectEqual(ip.indexToKey(bytes_value1).bytes.ptr, ip.indexToKey(bytes_value2).bytes.ptr);

    try std.testing.expectEqualStrings("https://www.youtube.com/watch?v=dQw4w9WgXcQ", ip.indexToKey(bytes_value1).bytes);
    try std.testing.expectEqualStrings("https://www.youtube.com/watch?v=dQw4w9WgXcQ", ip.indexToKey(bytes_value2).bytes);
    try std.testing.expectEqualStrings("https://www.duckduckgo.com", ip.indexToKey(bytes_value3).bytes);
}

test "coerceInMemoryAllowed integers and floats" {
    const gpa = std.testing.allocator;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const u16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 16 } });
    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });

    const f32_type = try ip.get(gpa, .{ .simple_type = .f32 });
    const f64_type = try ip.get(gpa, .{ .simple_type = .f64 });

    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u32_type, u32_type, true, builtin.target) == .ok);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u32_type, u16_type, true, builtin.target) == .ok);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u16_type, u32_type, true, builtin.target) == .int_not_coercible);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, i32_type, u32_type, true, builtin.target) == .int_not_coercible);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u32_type, i32_type, true, builtin.target) == .int_not_coercible);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u32_type, i16_type, true, builtin.target) == .int_not_coercible);

    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, f32_type, f32_type, true, builtin.target) == .ok);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, f64_type, f32_type, true, builtin.target) == .no_match);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, f32_type, f64_type, true, builtin.target) == .no_match);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, u32_type, f32_type, true, builtin.target) == .no_match);
    try std.testing.expect(try ip.coerceInMemoryAllowed(gpa, arena, f32_type, u32_type, true, builtin.target) == .no_match);
}

test "resolvePeerTypes" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });
    const type_type = try ip.get(gpa, .{ .simple_type = .type });
    const noreturn_type = try ip.get(gpa, .{ .simple_type = .noreturn });
    const undefined_type = try ip.get(gpa, .{ .simple_type = .undefined_type });

    try std.testing.expect(noreturn_type == try ip.resolvePeerTypes(std.testing.allocator, &.{}, builtin.target));
    try std.testing.expect(type_type == try ip.resolvePeerTypes(std.testing.allocator, &.{type_type}, builtin.target));

    try ip.testResolvePeerTypes(Index.none, Index.none, Index.none);
    try ip.testResolvePeerTypes(bool_type, bool_type, bool_type);
    try ip.testResolvePeerTypes(bool_type, noreturn_type, bool_type);
    try ip.testResolvePeerTypes(bool_type, undefined_type, bool_type);
    try ip.testResolvePeerTypes(type_type, noreturn_type, type_type);
    try ip.testResolvePeerTypes(type_type, undefined_type, type_type);
}

test "resolvePeerTypes integers and floats" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });
    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i64_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 64 } });
    const u16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 16 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const u64_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 64 } });

    const usize_type = try ip.get(gpa, .{ .simple_type = .usize });
    const isize_type = try ip.get(gpa, .{ .simple_type = .isize });

    const c_short_type = try ip.get(gpa, .{ .simple_type = .c_short });
    const c_int_type = try ip.get(gpa, .{ .simple_type = .c_int });
    const c_long_type = try ip.get(gpa, .{ .simple_type = .c_long });

    const comptime_int_type = try ip.get(gpa, .{ .simple_type = .comptime_int });
    const comptime_float_type = try ip.get(gpa, .{ .simple_type = .comptime_float });

    const f16_type = try ip.get(gpa, .{ .simple_type = .f16 });
    const f32_type = try ip.get(gpa, .{ .simple_type = .f32 });
    const f64_type = try ip.get(gpa, .{ .simple_type = .f64 });

    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    try ip.testResolvePeerTypes(i16_type, i16_type, i16_type);
    try ip.testResolvePeerTypes(i16_type, i32_type, i32_type);
    try ip.testResolvePeerTypes(i32_type, i64_type, i64_type);

    try ip.testResolvePeerTypes(u16_type, u16_type, u16_type);
    try ip.testResolvePeerTypes(u16_type, u32_type, u32_type);
    try ip.testResolvePeerTypes(u32_type, u64_type, u64_type);

    try ip.testResolvePeerTypesInOrder(i16_type, u16_type, i16_type);
    try ip.testResolvePeerTypesInOrder(u16_type, i16_type, u16_type);
    try ip.testResolvePeerTypesInOrder(i32_type, u32_type, i32_type);
    try ip.testResolvePeerTypesInOrder(u32_type, i32_type, u32_type);
    try ip.testResolvePeerTypesInOrder(isize_type, usize_type, isize_type);
    try ip.testResolvePeerTypesInOrder(usize_type, isize_type, usize_type);

    try ip.testResolvePeerTypes(i16_type, u32_type, u32_type);
    try ip.testResolvePeerTypes(u16_type, i32_type, i32_type);
    try ip.testResolvePeerTypes(i32_type, u64_type, u64_type);
    try ip.testResolvePeerTypes(u32_type, i64_type, i64_type);

    try ip.testResolvePeerTypes(i16_type, usize_type, usize_type);
    try ip.testResolvePeerTypes(i16_type, isize_type, isize_type);
    try ip.testResolvePeerTypes(u16_type, usize_type, usize_type);
    try ip.testResolvePeerTypes(u16_type, isize_type, isize_type);

    try ip.testResolvePeerTypes(c_short_type, usize_type, usize_type);
    try ip.testResolvePeerTypes(c_short_type, isize_type, isize_type);

    try ip.testResolvePeerTypes(i16_type, c_long_type, c_long_type);
    try ip.testResolvePeerTypes(i16_type, c_long_type, c_long_type);
    try ip.testResolvePeerTypes(u16_type, c_long_type, c_long_type);
    try ip.testResolvePeerTypes(u16_type, c_long_type, c_long_type);

    try ip.testResolvePeerTypes(comptime_int_type, i16_type, i16_type);
    try ip.testResolvePeerTypes(comptime_int_type, u64_type, u64_type);
    try ip.testResolvePeerTypes(comptime_int_type, isize_type, isize_type);
    try ip.testResolvePeerTypes(comptime_int_type, usize_type, usize_type);
    try ip.testResolvePeerTypes(comptime_int_type, c_short_type, c_short_type);
    try ip.testResolvePeerTypes(comptime_int_type, c_int_type, c_int_type);
    try ip.testResolvePeerTypes(comptime_int_type, c_long_type, c_long_type);

    try ip.testResolvePeerTypes(comptime_float_type, i16_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, u64_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, isize_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, usize_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, c_short_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, c_int_type, Index.none);
    try ip.testResolvePeerTypes(comptime_float_type, c_long_type, Index.none);

    try ip.testResolvePeerTypes(comptime_float_type, comptime_int_type, comptime_float_type);

    try ip.testResolvePeerTypes(f16_type, f32_type, f32_type);
    try ip.testResolvePeerTypes(f32_type, f64_type, f64_type);

    try ip.testResolvePeerTypes(comptime_int_type, f16_type, f16_type);
    try ip.testResolvePeerTypes(comptime_int_type, f32_type, f32_type);
    try ip.testResolvePeerTypes(comptime_int_type, f64_type, f64_type);

    try ip.testResolvePeerTypes(comptime_float_type, f16_type, f16_type);
    try ip.testResolvePeerTypes(comptime_float_type, f32_type, f32_type);
    try ip.testResolvePeerTypes(comptime_float_type, f64_type, f64_type);

    try ip.testResolvePeerTypes(f16_type, i16_type, Index.none);
    try ip.testResolvePeerTypes(f32_type, u64_type, Index.none);
    try ip.testResolvePeerTypes(f64_type, isize_type, Index.none);
    try ip.testResolvePeerTypes(f16_type, usize_type, Index.none);
    try ip.testResolvePeerTypes(f32_type, c_short_type, Index.none);
    try ip.testResolvePeerTypes(f64_type, c_int_type, Index.none);
    try ip.testResolvePeerTypes(f64_type, c_long_type, Index.none);

    try ip.testResolvePeerTypes(bool_type, i16_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, u64_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, usize_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, c_int_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, comptime_int_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, comptime_float_type, Index.none);
    try ip.testResolvePeerTypes(bool_type, f32_type, Index.none);
}

test "resolvePeerTypes optionals" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const null_type = try ip.get(gpa, .{ .simple_type = .null_type });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const @"?u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = u32_type } });
    const @"?bool" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = bool_type } });

    try ip.testResolvePeerTypes(u32_type, null_type, @"?u32");
    try ip.testResolvePeerTypes(bool_type, null_type, @"?bool");
}

test "resolvePeerTypes pointers" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const comptime_int_type = try ip.get(gpa, .{ .simple_type = .comptime_int });
    const comptime_float_type = try ip.get(gpa, .{ .simple_type = .comptime_float });
    const bool_type = try ip.get(gpa, .{ .simple_type = .bool });

    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .One } });
    const @"[*]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Many } });
    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Slice } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .C } });

    const @"?*u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*u32" } });
    const @"?[*]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[*]u32" } });
    const @"?[]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[]u32" } });

    const @"**u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"*u32", .size = .One } });
    const @"*[*]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[*]u32", .size = .One } });
    const @"*[]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[]u32", .size = .One } });
    const @"*[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[*c]u32", .size = .One } });

    const @"?*[*]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[*]u32" } });
    const @"?*[]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[]u32" } });

    const @"[1]u32" = try ip.get(gpa, .{ .array_type = .{ .len = 1, .child = u32_type, .sentinel = .none } });
    const @"[2]u32" = try ip.get(gpa, .{ .array_type = .{ .len = 2, .child = u32_type, .sentinel = .none } });

    const @"*[1]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[1]u32", .size = .One } });
    const @"*[2]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[2]u32", .size = .One } });

    const @"?*[1]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[1]u32" } });
    const @"?*[2]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[2]u32" } });

    const @"*const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .One, .is_const = true } });
    const @"[*]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Many, .is_const = true } });
    const @"[]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Slice, .is_const = true } });
    const @"[*c]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .C, .is_const = true } });

    const @"?*const u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*const u32" } });
    const @"?[*]const u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[*]const u32" } });
    const @"?[]const u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[]const u32" } });

    _ = @"**u32";
    _ = @"*[*c]u32";
    _ = @"?*[]u32";
    _ = @"?*[2]u32";
    _ = @"?[*]const u32";
    _ = @"?[]const u32";

    // gain const
    try ip.testResolvePeerTypes(@"*u32", @"*u32", @"*u32");
    try ip.testResolvePeerTypes(@"*u32", @"*const u32", @"*const u32");
    try ip.testResolvePeerTypes(@"[*]u32", @"[*]const u32", @"[*]const u32");
    try ip.testResolvePeerTypes(@"[]u32", @"[]const u32", @"[]const u32");
    try ip.testResolvePeerTypes(@"[*c]u32", @"[*c]const u32", @"[*c]const u32");

    // array to slice
    try ip.testResolvePeerTypes(@"*[1]u32", @"*[2]u32", @"[]u32");
    try ip.testResolvePeerTypes(@"[]u32", @"*[1]u32", @"[]u32");

    // pointer like optionals
    try ip.testResolvePeerTypes(@"*u32", @"?*u32", @"?*u32");
    try ip.testResolvePeerTypesInOrder(@"*u32", @"?[*]u32", @"?[*]u32");
    try ip.testResolvePeerTypesInOrder(@"[*]u32", @"?*u32", @"?*u32");

    try ip.testResolvePeerTypes(@"[*c]u32", comptime_int_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", u32_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", comptime_float_type, Index.none);
    try ip.testResolvePeerTypes(@"[*c]u32", bool_type, Index.none);

    try ip.testResolvePeerTypes(@"[*c]u32", @"*u32", @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", @"[*]u32", @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", @"[]u32", @"[*c]u32");

    try ip.testResolvePeerTypes(@"[*c]u32", @"*[1]u32", Index.none);
    try ip.testResolvePeerTypesInOrder(@"[*c]u32", @"?*[1]u32", @"?*[1]u32");
    try ip.testResolvePeerTypesInOrder(@"?*[1]u32", @"[*c]u32", Index.none);
    try ip.testResolvePeerTypes(@"[*c]u32", @"*[*]u32", Index.none);
    try ip.testResolvePeerTypesInOrder(@"[*c]u32", @"?*[*]u32", @"?*[*]u32");
    try ip.testResolvePeerTypesInOrder(@"?*[*]u32", @"[*c]u32", Index.none);
    try ip.testResolvePeerTypes(@"[*c]u32", @"[]u32", @"[*c]u32");
    // TODO try ip.testResolvePeerTypesInOrder(@"[*c]u32", @"?[]u32", @"?[]u32");
    // TODO try ip.testResolvePeerTypesInOrder(@"?[]u32", @"[*c]u32", Index.none);

    // TODO try ip.testResolvePeerTypesInOrder(@"*u32", @"?[*]const u32", @"?[*]const u32");
    try ip.testResolvePeerTypesInOrder(@"*const u32", @"?[*]u32", @"?[*]u32");
    try ip.testResolvePeerTypesInOrder(@"[*]const u32", @"?*u32", @"?*u32");
    try ip.testResolvePeerTypesInOrder(@"[*]u32", @"?*const u32", @"?*const u32");

    try ip.testResolvePeerTypes(@"?[*]u32", @"*[2]u32", @"?[*]u32");
    try ip.testResolvePeerTypes(@"?[]u32", @"*[2]u32", @"?[]u32");
    try ip.testResolvePeerTypes(@"[*]u32", @"*[2]u32", @"[*]u32");
}

test "resolvePeerTypes function pointers" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const void_type = try ip.get(gpa, .{ .simple_type = .void });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .One } });
    const @"*const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .One, .is_const = true } });

    const @"fn(*u32) void" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{@"*u32"},
        .return_type = void_type,
    } });

    const @"fn(*const u32) void" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{@"*const u32"},
        .return_type = void_type,
    } });

    try ip.testResolvePeerTypes(@"fn(*u32) void", @"fn(*u32) void", @"fn(*u32) void");
    try ip.testResolvePeerTypes(@"fn(*u32) void", @"fn(*const u32) void", @"fn(*u32) void");
}

fn testResolvePeerTypes(ip: *InternPool, a: Index, b: Index, expected: Index) !void {
    try ip.testResolvePeerTypesInOrder(a, b, expected);
    try ip.testResolvePeerTypesInOrder(b, a, expected);
}

fn testResolvePeerTypesInOrder(ip: *InternPool, lhs: Index, rhs: Index, expected: Index) !void {
    const actual = try resolvePeerTypes(ip, std.testing.allocator, &.{ lhs, rhs }, builtin.target);
    try expectEqualTypes(ip, expected, actual);
}

fn expectEqualTypes(ip: *InternPool, expected: Index, actual: Index) !void {
    if (expected == actual) return;
    const allocator = std.testing.allocator;

    const expected_type = if (expected == .none) @tagName(Index.none) else try std.fmt.allocPrint(allocator, "{}", .{expected.fmtType(ip.*)});
    defer if (expected != .none) allocator.free(expected_type);
    const actual_type = if (actual == .none) @tagName(Index.none) else try std.fmt.allocPrint(allocator, "{}", .{actual.fmtType(ip.*)});
    defer if (actual != .none) allocator.free(actual_type);

    std.debug.print("expected `{s}`, found `{s}`\n", .{ expected_type, actual_type });
    return error.TestExpectedEqual;
}
