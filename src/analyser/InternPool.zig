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
const expect = std.testing.expect;
const expectFmt = std.testing.expectFmt;

const encoding = @import("encoding.zig");

pub const Int = packed struct {
    signedness: std.builtin.Signedness,
    bits: u16,
};

pub const Pointer = packed struct {
    elem_type: Index,
    sentinel: Index = .none,
    size: std.builtin.Type.Pointer.Size,
    alignment: u16 = 0,
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
    tag_type_inferred: bool,
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

const U64Value = packed struct {
    ty: Index,
    int: u64,
};

const I64Value = packed struct {
    ty: Index,
    int: i64,
};

pub const BigInt = struct {
    ty: Index,
    int: std.math.big.int.Const,
};

pub const Bytes = []const u8;

pub const OptionalValue = packed struct {
    ty: Index,
    val: Index,
};

pub const Slice = packed struct {
    ty: Index,
    ptr: Index,
    len: Index,
};

pub const Aggregate = struct {
    ty: Index,
    values: []const Index,
};

pub const UnionValue = packed struct {
    ty: Index,
    field_index: u32,
    val: Index,
};

pub const NullValue = packed struct {
    ty: Index,
};

pub const UndefinedValue = packed struct {
    ty: Index,
};

pub const UnknownValue = packed struct {
    ty: Index,
};

pub const DeclIndex = enum(u32) { _ };

pub const Decl = struct {
    name: []const u8,
    node_idx: u32,
    /// this stores both the type and the value
    index: Index,
    alignment: u16,
    address_space: std.builtin.AddressSpace,
    is_pub: bool,
    is_exported: bool,
};

const BigIntInternal = struct {
    ty: Index,
    limbs: []const std.math.big.Limb,
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

    int_u64_value: U64Value,
    int_i64_value: I64Value,
    int_big_value: BigInt,
    float_16_value: f16,
    float_32_value: f32,
    float_64_value: f64,
    float_80_value: f80,
    float_128_value: f128,
    float_comptime_value: f128,

    bytes: Bytes,
    optional_value: OptionalValue,
    slice: Slice,
    aggregate: Aggregate,
    union_value: UnionValue,
    null_value: NullValue,
    undefined_value: UndefinedValue,
    unknown_value: UnknownValue,

    // error
    // error union

    pub fn eql(a: Key, b: Key) bool {
        return deepEql(a, b);
    }

    pub fn hash(a: Key) u32 {
        var hasher = std.hash.Wyhash.init(0);
        deepHash(&hasher, a);
        return @truncate(hasher.final());
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

            .int_u64_value => .int_u64,
            .int_i64_value => .int_i64,
            .int_big_value => |big_int| if (big_int.int.positive) .int_big_positive else .int_big_negative,
            .float_16_value => .float_f16,
            .float_32_value => .float_f32,
            .float_64_value => .float_f64,
            .float_80_value => .float_f80,
            .float_128_value => .float_f128,
            .float_comptime_value => .float_comptime,

            .bytes => .bytes,
            .optional_value => .optional_value,
            .slice => .slice,
            .aggregate => .aggregate,
            .union_value => .union_value,
            .null_value => .null_value,
            .undefined_value => .undefined_value,
            .unknown_value => .unknown_value,
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
                .c_char,
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
                .anyframe_type => .AnyFrame,
                .empty_struct_type => .Struct,
                .null_type => .Null,
                .undefined_type => .Undefined,
                .enum_literal_type => .EnumLiteral,

                .atomic_order => .Enum,
                .atomic_rmw_op => .Enum,
                .calling_convention => .Enum,
                .address_space => .Enum,
                .float_mode => .Enum,
                .reduce_op => .Enum,
                .modifier => .Enum,
                .prefetch_options => .Struct,
                .export_options => .Struct,
                .extern_options => .Struct,
                .type_info => .Union,

                .unknown => unreachable,
                .generic_poison => unreachable,
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
            .tuple_type => .Struct,
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
            .float_comptime_value,
            => unreachable,

            .bytes,
            .optional_value,
            .slice,
            .aggregate,
            .union_value,
            .null_value,
            .undefined_value,
            .unknown_value,
            => unreachable,
        };
    }

    pub fn typeOf(key: Key) Index {
        return switch (key) {
            .simple_type => .type_type,
            .simple_value => |simple| switch (simple) {
                .undefined_value => .undefined_type,
                .void_value => .void_type,
                .unreachable_value => .noreturn_type,
                .null_value => .null_type,
                .bool_true => .bool_type,
                .bool_false => .bool_type,
                .the_only_possible_value => unreachable,
                .generic_poison => .generic_poison_type,
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
            => .type_type,

            .int_u64_value => |int| int.ty,
            .int_i64_value => |int| int.ty,
            .int_big_value => |int| int.ty,
            .float_16_value => .f16_type,
            .float_32_value => .f32_type,
            .float_64_value => .f64_type,
            .float_80_value => .f80_type,
            .float_128_value => .f128_type,
            .float_comptime_value => .comptime_float_type,

            .bytes => .unknown_type, // TODO
            .optional_value => |optional_info| optional_info.ty,
            .slice => |slice_info| slice_info.ty,
            .aggregate => |aggregate_info| aggregate_info.ty,
            .union_value => |union_info| union_info.ty,
            .null_value => |null_info| null_info.ty,
            .undefined_value => |undefined_info| undefined_info.ty,
            .unknown_value => |unknown_info| unknown_info.ty,
        };
    }

    /// Asserts the type is an integer, enum, error set, packed struct, or vector of one of them.
    pub fn intInfo(ty: Key, target: std.Target, ip: InternPool) Int {
        var key: Key = ty;
        while (true) switch (key) {
            .simple_type => |simple| switch (simple) {
                .usize => return .{ .signedness = .signed, .bits = target.ptrBitWidth() },
                .isize => return .{ .signedness = .unsigned, .bits = target.ptrBitWidth() },

                .c_char => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.char) },
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
            .enum_type => |enum_index| {
                const enum_info = ip.getEnum(enum_index);
                key = ip.indexToKey(enum_info.tag_type);
            },
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

    pub fn isSinglePointer(ty: Key) bool {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.size == .One,
            else => false,
        };
    }

    pub fn isCPtr(ty: Key) bool {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.size == .C,
            else => false,
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

    pub fn isPtrAtRuntime(ty: Key, ip: *const InternPool) bool {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.size != .Slice,
            .optional_type => |optional_info| {
                const child_type = ip.indexToKey(optional_info.payload_type);
                switch (child_type) {
                    .pointer_type => |pointer_info| switch (pointer_info.size) {
                        .Slice, .C => return false,
                        .Many, .One => return !pointer_info.is_allowzero,
                    },
                    else => return false,
                }
            },
            else => false,
        };
    }

    pub fn elemType2(ty: Key) Index {
        return switch (ty) {
            .simple_type => |simple| switch (simple) {
                .anyframe_type => Index.void_type,
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
                .c_char,
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
                .anyframe_type,
                .enum_literal_type,
                => Index.none,

                .empty_struct_type => Index.empty_aggregate,
                .void => Index.void_value,
                .noreturn => Index.unreachable_value,
                .null_type => Index.null_value,
                .undefined_type => Index.undefined_value,

                .atomic_order,
                .atomic_rmw_op,
                .calling_convention,
                .address_space,
                .float_mode,
                .reduce_op,
                .modifier,
                .prefetch_options,
                .export_options,
                .extern_options,
                .type_info,
                => Index.none,

                .unknown => Index.unknown_unknown,
                .generic_poison => unreachable,
            },
            .int_type => |int_info| {
                if (int_info.bits == 0) {
                    switch (int_info.signedness) {
                        .unsigned => return Index.zero_comptime_int,
                        .signed => return Index.zero_comptime_int, // do we need a signed zero?
                    }
                }
                return Index.none;
            },
            .pointer_type => Index.none,
            .array_type => |array_info| {
                if (array_info.len == 0) {
                    return Index.empty_aggregate;
                } else if (ip.indexToKey(array_info.child).onePossibleValue(ip) != Index.none) {
                    return Index.the_only_possible_value;
                }
                return Index.none;
            },
            .struct_type => |struct_index| {
                const struct_info = ip.getStruct(struct_index);
                var field_it = struct_info.fields.iterator();
                while (field_it.next()) |entry| {
                    if (entry.value_ptr.is_comptime) continue;
                    if (ip.indexToKey(entry.value_ptr.ty).onePossibleValue(ip) != Index.none) continue;
                    return Index.none;
                }
                return Index.empty_aggregate;
            },
            .optional_type => |optional_info| {
                if (optional_info.payload_type == Index.noreturn_type) {
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
            .float_comptime_value,
            => unreachable,

            .bytes,
            .optional_value,
            .slice,
            .aggregate,
            .union_value,
            .null_value,
            .undefined_value,
            .unknown_value,
            => unreachable,
        };
    }

    pub fn isNull(val: Key) bool {
        return switch (val) {
            .simple_value => |simple| switch (simple) {
                .null_value => true,
                .bool_true => false,
                .bool_false => true,
                .the_only_possible_value => true,
                else => unreachable,
            },
            .int_u64_value => |int_value| int_value.int == 0,
            .int_i64_value => |int_value| int_value.int == 0,
            .int_big_value => |int_value| int_value.int.orderAgainstScalar(0).compare(.eq),

            .null_value => true,
            .optional_value => false,
            .unknown_value => unreachable,

            else => unreachable,
        };
    }

    /// If the value fits in a u64, return it, otherwise null.
    /// Asserts not undefined.
    pub fn getUnsignedInt(val: Key) !?u64 {
        return switch (val) {
            .simple_value => |simple| switch (simple) {
                .null_value => 0,
                .bool_true => 1,
                .bool_false => 0,
                .the_only_possible_value => 0,
                else => null,
            },
            .int_u64_value => |int_value| int_value.int,
            .int_i64_value => |int_value| @intCast(int_value.int),
            .int_big_value => |int_value| int_value.int.to(u64) catch null,
            .null_value => 0,
            else => null,
        };
    }

    pub const FormatContext = struct {
        key: Key,
        options: FormatOptions = .{},
        ip: InternPool,
    };

    // TODO add options for controling how types show be formatted
    pub const FormatOptions = struct {};

    fn format(
        ctx: FormatContext,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, Key);
        try print(ctx.key, ctx.ip, writer);
    }

    pub fn print(key: Key, ip: InternPool, writer: anytype) @TypeOf(writer).Error!void {
        var k = key;
        while (try printInternal(k, ip, writer)) |index| {
            k = ip.indexToKey(index);
        }
    }

    fn printInternal(ty: Key, ip: InternPool, writer: anytype) @TypeOf(writer).Error!?Index {
        switch (ty) {
            .simple_type => |simple| switch (simple) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_char,
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
                .anyframe_type,
                => try writer.writeAll(@tagName(simple)),

                .null_type => try writer.writeAll("@TypeOf(null)"),
                .undefined_type => try writer.writeAll("@TypeOf(undefined)"),
                .empty_struct_type => try writer.writeAll("@TypeOf(.{})"),
                .enum_literal_type => try writer.writeAll("@TypeOf(.enum_literal)"),

                .atomic_order => try writer.writeAll("std.builtin.AtomicOrder"),
                .atomic_rmw_op => try writer.writeAll("std.builtin.AtomicRmwOp"),
                .calling_convention => try writer.writeAll("std.builtin.CallingConvention"),
                .address_space => try writer.writeAll("std.builtin.AddressSpace"),
                .float_mode => try writer.writeAll("std.builtin.FloatMode"),
                .reduce_op => try writer.writeAll("std.builtin.ReduceOp"),
                .modifier => try writer.writeAll("std.builtin.CallModifier"),
                .prefetch_options => try writer.writeAll("std.builtin.PrefetchOptions"),
                .export_options => try writer.writeAll("std.builtin.ExportOptions"),
                .extern_options => try writer.writeAll("std.builtin.ExternOptions"),
                .type_info => try writer.writeAll("std.builtin.Type"),
                .unknown => try writer.writeAll("(unknown type)"),
                .generic_poison => unreachable,
            },
            .int_type => |int_info| switch (int_info.signedness) {
                .signed => try writer.print("i{}", .{int_info.bits}),
                .unsigned => try writer.print("u{}", .{int_info.bits}),
            },
            .pointer_type => |pointer_info| {
                if (pointer_info.sentinel != Index.none) {
                    switch (pointer_info.size) {
                        .One, .C => unreachable,
                        .Many => try writer.print("[*:{}]", .{pointer_info.sentinel.fmt(ip)}),
                        .Slice => try writer.print("[:{}]", .{pointer_info.sentinel.fmt(ip)}),
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
                    try writer.print(":{}", .{array_info.sentinel.fmt(ip)});
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
                try print(ip.indexToKey(error_union_info.error_set_type), ip, writer);
                try writer.writeByte('!');
                return error_union_info.payload_type;
            },
            .error_set_type => |error_set_info| {
                const names = error_set_info.names;
                try writer.writeAll("error{");
                for (names, 0..) |name, i| {
                    if (i != 0) try writer.writeByte(',');
                    try writer.writeAll(ip.indexToKey(name).bytes);
                }
                try writer.writeByte('}');
            },
            .enum_type => return panicOrElse("TODO", null),
            .function_type => |function_info| {
                try writer.writeAll("fn(");

                for (function_info.args, 0..) |arg_ty, i| {
                    if (i != 0) try writer.writeAll(", ");

                    if (i < 32) {
                        if (function_info.args_is_comptime.isSet(i)) {
                            try writer.writeAll("comptime ");
                        }
                        if (function_info.args_is_noalias.isSet(i)) {
                            try writer.writeAll("noalias ");
                        }
                    }

                    try print(ip.indexToKey(arg_ty), ip, writer);
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
                for (tuple_info.types, 0..) |field_ty, i| {
                    if (i != 0) try writer.writeAll(", ");
                    const val = tuple_info.values[i];
                    if (val != Index.none) {
                        try writer.writeAll("comptime ");
                    }
                    try print(ip.indexToKey(field_ty), ip, writer);
                    if (val != Index.none) {
                        try writer.print(" = {}", .{val.fmt(ip)});
                    }
                }
                try writer.writeByte('}');
            },
            .vector_type => |vector_info| {
                try writer.print("@Vector({d},{})", .{
                    vector_info.len,
                    vector_info.child.fmt(ip),
                });
            },
            .anyframe_type => |anyframe_info| {
                try writer.writeAll("anyframe->");
                return anyframe_info.child;
            },

            .simple_value => |simple| switch (simple) {
                .undefined_value => try writer.writeAll("undefined"),
                .void_value => try writer.writeAll("{}"),
                .unreachable_value => try writer.writeAll("unreachable"),
                .null_value => try writer.writeAll("null"),
                .bool_true => try writer.writeAll("true"),
                .bool_false => try writer.writeAll("false"),
                .the_only_possible_value => try writer.writeAll("(the only possible value)"),
                .generic_poison => try writer.writeAll("(generic poison)"),
            },
            .int_u64_value => |i| try std.fmt.formatIntValue(i.int, "", .{}, writer),
            .int_i64_value => |i| try std.fmt.formatIntValue(i.int, "", .{}, writer),
            .int_big_value => |i| try i.int.format("", .{}, writer),
            .float_16_value => |float| try writer.print("{d}", .{float}),
            .float_32_value => |float| try writer.print("{d}", .{float}),
            .float_64_value => |float| try writer.print("{d}", .{float}),
            .float_80_value => |float| try writer.print("{d}", .{@as(f64, @floatCast(float))}),
            .float_128_value,
            .float_comptime_value,
            => |float| try writer.print("{d}", .{@as(f64, @floatCast(float))}),

            .bytes => |bytes| try writer.print("\"{}\"", .{std.zig.fmtEscapes(bytes)}),
            .optional_value => |optional| {
                return optional.val;
            },
            .slice => |slice_value| {
                _ = slice_value;
                try writer.writeAll(".{");
                try writer.writeAll(" TODO "); // TODO
                try writer.writeByte('}');
            },
            .aggregate => |aggregate| {
                if (aggregate.values.len == 0) {
                    try writer.writeAll(".{}");
                    return null;
                }
                const struct_info = ip.getStruct(ip.indexToKey(aggregate.ty).struct_type);
                assert(aggregate.values.len == struct_info.fields.count());

                try writer.writeAll(".{");
                var i: u32 = 0;
                while (i < aggregate.values.len) : (i += 1) {
                    if (i != 0) try writer.writeAll(", ");

                    const field_name = struct_info.fields.keys()[i];
                    try writer.print(".{s} = {}", .{ field_name, aggregate.values[i].fmt(ip) });
                }
                try writer.writeByte('}');
            },
            .union_value => |union_value| {
                const union_info = ip.getUnion(ip.indexToKey(union_value.ty).union_type);

                const name = union_info.fields.keys()[union_value.field_index];
                try writer.print(".{{ .{} = {} }}", .{
                    std.zig.fmtId(name),
                    union_value.val.fmt(ip),
                });
            },
            .null_value => try writer.print("null", .{}),
            .undefined_value => try writer.print("undefined", .{}),
            .unknown_value => try writer.print("(unknown value)", .{}),
        }
        return null;
    }

    pub fn fmt(key: Key, ip: InternPool) std.fmt.Formatter(format) {
        return .{ .data = .{
            .key = key,
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
pub const Index = enum(u32) {
    u1_type,
    u8_type,
    i8_type,
    u16_type,
    i16_type,
    u29_type,
    u32_type,
    i32_type,
    u64_type,
    i64_type,
    u128_type,
    i128_type,
    usize_type,
    isize_type,
    c_char_type,
    c_short_type,
    c_ushort_type,
    c_int_type,
    c_uint_type,
    c_long_type,
    c_ulong_type,
    c_longlong_type,
    c_ulonglong_type,
    c_longdouble_type,
    f16_type,
    f32_type,
    f64_type,
    f80_type,
    f128_type,
    anyopaque_type,
    bool_type,
    void_type,
    type_type,
    anyerror_type,
    comptime_int_type,
    comptime_float_type,
    noreturn_type,
    anyframe_type,
    empty_struct_type,
    null_type,
    undefined_type,
    enum_literal_type,
    atomic_order_type,
    atomic_rmw_op_type,
    calling_convention_type,
    address_space_type,
    float_mode_type,
    reduce_op_type,
    call_modifier_type,
    prefetch_options_type,
    export_options_type,
    extern_options_type,
    type_info_type,
    manyptr_u8_type,
    manyptr_const_u8_type,
    manyptr_const_u8_sentinel_0_type,
    fn_noreturn_no_args_type,
    fn_void_no_args_type,
    fn_naked_noreturn_no_args_type,
    fn_ccc_void_no_args_type,
    single_const_pointer_to_comptime_int_type,
    slice_const_u8_type,
    slice_const_u8_sentinel_0_type,
    optional_noreturn_type,
    anyerror_void_error_union_type,
    generic_poison_type,
    unknown_type,

    /// `undefined` (untyped)
    undefined_value,
    /// `0` (comptime_int)
    zero_comptime_int,
    /// `0` (u8)
    zero_u8,
    /// `0` (usize)
    zero_usize,
    /// `1` (comptime_int)
    one_comptime_int,
    /// `1` (u8)
    one_u8,
    /// `1` (usize)
    one_usize,
    /// `{}`
    void_value,
    /// `unreachable` (noreturn type)
    unreachable_value,
    /// `null` (untyped)
    null_value,
    /// `true`
    bool_true,
    /// `false`
    bool_false,
    /// `.{}` (untyped)
    empty_aggregate,
    the_only_possible_value,
    generic_poison,
    // unknown value of unknown type
    unknown_unknown,

    none = std.math.maxInt(u32),
    _,

    pub fn fmt(index: Index, ip: InternPool) std.fmt.Formatter(Key.format) {
        return .{ .data = .{
            .key = ip.indexToKey(index),
            .ip = ip,
        } };
    }

    pub fn fmtDebug(index: Index, ip: InternPool) std.fmt.Formatter(formatDebug) {
        return .{ .data = .{
            .index = index,
            .ip = ip,
        } };
    }

    const FormatContext = struct {
        index: Index,
        ip: InternPool,
    };

    fn formatDebug(
        ctx: FormatContext,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (ctx.index == .none) {
            return writer.writeAll(".none");
        } else {
            return Key.format(.{
                .key = ctx.ip.indexToKey(ctx.index),
                .ip = ctx.ip,
            }, fmt_str, options, writer);
        }
    }
};

comptime {
    const Zir = @import("../stage2/Zir.zig");
    assert(@intFromEnum(Zir.Inst.Ref.generic_poison_type) == @intFromEnum(Index.generic_poison_type));
    assert(@intFromEnum(Zir.Inst.Ref.undef) == @intFromEnum(Index.undefined_value));
    assert(@intFromEnum(Zir.Inst.Ref.one_usize) == @intFromEnum(Index.one_usize));
}

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

    // TODO use a more efficient encoding for small integers
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
    /// A comptime float value.
    /// data is payload to f128.
    float_comptime,

    /// A byte sequence value.
    /// data is payload to data begin and length.
    bytes,
    /// A optional value that is not null.
    /// data is index to OptionalValue.
    optional_value,
    /// A aggregate (struct) value.
    /// data is index to Aggregate.
    aggregate,
    /// A slice value.
    /// data is index to Slice.
    slice,
    /// A union value.
    /// data is index to UnionValue.
    union_value,
    /// A null value.
    /// data is index to type which may be unknown.
    null_value,
    /// A undefined value.
    /// data is index to type which may be unknown.
    undefined_value,
    /// A unknown value.
    /// data is index to type which may also be unknown.
    unknown_value,
};

pub const SimpleType = enum(u32) {
    f16,
    f32,
    f64,
    f80,
    f128,
    usize,
    isize,
    c_char,
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
    anyframe_type,
    empty_struct_type,
    null_type,
    undefined_type,
    enum_literal_type,

    atomic_order,
    atomic_rmw_op,
    calling_convention,
    address_space,
    float_mode,
    reduce_op,
    modifier,
    prefetch_options,
    export_options,
    extern_options,
    type_info,

    unknown,
    generic_poison,
};

pub const SimpleValue = enum(u32) {
    undefined_value,
    void_value,
    unreachable_value,
    null_value,
    bool_true,
    bool_false,
    the_only_possible_value,
    generic_poison,
};

comptime {
    assert(@sizeOf(SimpleType) == @sizeOf(SimpleValue));
}

pub fn init(gpa: Allocator) Allocator.Error!InternPool {
    var ip: InternPool = .{};

    const items = [_]struct { index: Index, key: Key }{
        .{ .index = .u1_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 1 } } },
        .{ .index = .u8_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 8 } } },
        .{ .index = .i8_type, .key = .{ .int_type = .{ .signedness = .signed, .bits = 8 } } },
        .{ .index = .u16_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 16 } } },
        .{ .index = .i16_type, .key = .{ .int_type = .{ .signedness = .signed, .bits = 16 } } },
        .{ .index = .u29_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 29 } } },
        .{ .index = .u32_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } } },
        .{ .index = .i32_type, .key = .{ .int_type = .{ .signedness = .signed, .bits = 32 } } },
        .{ .index = .u64_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 64 } } },
        .{ .index = .i64_type, .key = .{ .int_type = .{ .signedness = .signed, .bits = 64 } } },
        .{ .index = .u128_type, .key = .{ .int_type = .{ .signedness = .unsigned, .bits = 128 } } },
        .{ .index = .i128_type, .key = .{ .int_type = .{ .signedness = .signed, .bits = 128 } } },

        .{ .index = .usize_type, .key = .{ .simple_type = .usize } },
        .{ .index = .isize_type, .key = .{ .simple_type = .isize } },
        .{ .index = .c_char_type, .key = .{ .simple_type = .c_char } },
        .{ .index = .c_short_type, .key = .{ .simple_type = .c_short } },
        .{ .index = .c_ushort_type, .key = .{ .simple_type = .c_ushort } },
        .{ .index = .c_int_type, .key = .{ .simple_type = .c_int } },
        .{ .index = .c_uint_type, .key = .{ .simple_type = .c_uint } },
        .{ .index = .c_long_type, .key = .{ .simple_type = .c_long } },
        .{ .index = .c_ulong_type, .key = .{ .simple_type = .c_ulong } },
        .{ .index = .c_longlong_type, .key = .{ .simple_type = .c_longlong } },
        .{ .index = .c_ulonglong_type, .key = .{ .simple_type = .c_ulonglong } },
        .{ .index = .c_longdouble_type, .key = .{ .simple_type = .c_longdouble } },
        .{ .index = .f16_type, .key = .{ .simple_type = .f16 } },
        .{ .index = .f32_type, .key = .{ .simple_type = .f32 } },
        .{ .index = .f64_type, .key = .{ .simple_type = .f64 } },
        .{ .index = .f80_type, .key = .{ .simple_type = .f80 } },
        .{ .index = .f128_type, .key = .{ .simple_type = .f128 } },
        .{ .index = .anyopaque_type, .key = .{ .simple_type = .anyopaque } },
        .{ .index = .bool_type, .key = .{ .simple_type = .bool } },
        .{ .index = .void_type, .key = .{ .simple_type = .void } },
        .{ .index = .type_type, .key = .{ .simple_type = .type } },
        .{ .index = .anyerror_type, .key = .{ .simple_type = .anyerror } },
        .{ .index = .comptime_int_type, .key = .{ .simple_type = .comptime_int } },
        .{ .index = .comptime_float_type, .key = .{ .simple_type = .comptime_float } },
        .{ .index = .noreturn_type, .key = .{ .simple_type = .noreturn } },
        .{ .index = .anyframe_type, .key = .{ .simple_type = .anyframe_type } },
        .{ .index = .empty_struct_type, .key = .{ .simple_type = .empty_struct_type } },
        .{ .index = .null_type, .key = .{ .simple_type = .null_type } },
        .{ .index = .undefined_type, .key = .{ .simple_type = .undefined_type } },
        .{ .index = .enum_literal_type, .key = .{ .simple_type = .enum_literal_type } },

        .{ .index = .atomic_order_type, .key = .{ .simple_type = .atomic_order } },
        .{ .index = .atomic_rmw_op_type, .key = .{ .simple_type = .atomic_rmw_op } },
        .{ .index = .calling_convention_type, .key = .{ .simple_type = .calling_convention } },
        .{ .index = .address_space_type, .key = .{ .simple_type = .address_space } },
        .{ .index = .float_mode_type, .key = .{ .simple_type = .float_mode } },
        .{ .index = .reduce_op_type, .key = .{ .simple_type = .reduce_op } },
        .{ .index = .call_modifier_type, .key = .{ .simple_type = .modifier } },
        .{ .index = .prefetch_options_type, .key = .{ .simple_type = .prefetch_options } },
        .{ .index = .export_options_type, .key = .{ .simple_type = .export_options } },
        .{ .index = .extern_options_type, .key = .{ .simple_type = .extern_options } },
        .{ .index = .type_info_type, .key = .{ .simple_type = .type_info } },
        .{ .index = .manyptr_u8_type, .key = .{ .pointer_type = .{ .elem_type = .u8_type, .size = .Many } } },
        .{ .index = .manyptr_const_u8_type, .key = .{ .pointer_type = .{ .elem_type = .u8_type, .size = .Many, .is_const = true } } },
        .{ .index = .manyptr_const_u8_sentinel_0_type, .key = .{ .pointer_type = .{ .elem_type = .u8_type, .sentinel = .zero_u8, .size = .Many, .is_const = true } } },
        .{ .index = .fn_noreturn_no_args_type, .key = .{ .function_type = .{ .args = &.{}, .return_type = .noreturn_type } } },
        .{ .index = .fn_void_no_args_type, .key = .{ .function_type = .{ .args = &.{}, .return_type = .void_type } } },
        .{ .index = .fn_naked_noreturn_no_args_type, .key = .{ .function_type = .{ .args = &.{}, .return_type = .void_type, .calling_convention = .Naked } } },
        .{ .index = .fn_ccc_void_no_args_type, .key = .{ .function_type = .{ .args = &.{}, .return_type = .void_type, .calling_convention = .C } } },
        .{ .index = .single_const_pointer_to_comptime_int_type, .key = .{ .pointer_type = .{ .elem_type = .comptime_int_type, .size = .One, .is_const = true } } },
        .{ .index = .slice_const_u8_type, .key = .{ .pointer_type = .{ .elem_type = .u8_type, .size = .Slice, .is_const = true } } },
        .{ .index = .slice_const_u8_sentinel_0_type, .key = .{ .pointer_type = .{ .elem_type = .u8_type, .sentinel = .zero_u8, .size = .Slice, .is_const = true } } },
        .{ .index = .optional_noreturn_type, .key = .{ .optional_type = .{ .payload_type = .noreturn_type } } },
        .{ .index = .anyerror_void_error_union_type, .key = .{ .error_union_type = .{ .error_set_type = .anyerror_type, .payload_type = .void_type } } },
        .{ .index = .generic_poison_type, .key = .{ .simple_type = .generic_poison } },
        .{ .index = .unknown_type, .key = .{ .simple_type = .unknown } },

        .{ .index = .undefined_value, .key = .{ .simple_value = .undefined_value } },
        .{ .index = .zero_comptime_int, .key = .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 0 } } },
        .{ .index = .zero_u8, .key = .{ .int_u64_value = .{ .ty = .u8_type, .int = 0 } } },
        .{ .index = .zero_usize, .key = .{ .int_u64_value = .{ .ty = .usize_type, .int = 0 } } },
        .{ .index = .one_comptime_int, .key = .{ .int_u64_value = .{ .ty = .comptime_int_type, .int = 1 } } },
        .{ .index = .one_u8, .key = .{ .int_u64_value = .{ .ty = .u8_type, .int = 1 } } },
        .{ .index = .one_usize, .key = .{ .int_u64_value = .{ .ty = .usize_type, .int = 1 } } },
        .{ .index = .void_value, .key = .{ .simple_value = .void_value } },
        .{ .index = .unreachable_value, .key = .{ .simple_value = .unreachable_value } },
        .{ .index = .null_value, .key = .{ .simple_value = .null_value } },
        .{ .index = .bool_true, .key = .{ .simple_value = .bool_true } },
        .{ .index = .bool_false, .key = .{ .simple_value = .bool_false } },
        .{ .index = .empty_aggregate, .key = .{ .aggregate = .{ .ty = .empty_struct_type, .values = &.{} } } },
        .{ .index = .the_only_possible_value, .key = .{ .simple_value = .the_only_possible_value } },
        .{ .index = .generic_poison, .key = .{ .simple_value = .generic_poison } },
        .{ .index = .unknown_unknown, .key = .{ .unknown_value = .{ .ty = .unknown_type } } },
    };

    const extra_count = 6 * @sizeOf(Pointer) + @sizeOf(ErrorUnion) + 4 * @sizeOf(Function) + 6 * @sizeOf(InternPool.U64Value);

    try ip.map.ensureTotalCapacity(gpa, items.len);
    try ip.items.ensureTotalCapacity(gpa, items.len);
    try ip.extra.ensureTotalCapacity(gpa, extra_count);

    for (items) |item| {
        if (builtin.is_test or builtin.mode == .Debug) {
            var failing_allocator = std.testing.FailingAllocator.init(undefined, 0);
            std.testing.expectEqual(item.index, ip.get(failing_allocator.allocator(), item.key) catch unreachable) catch unreachable;
        } else {
            assert(item.index == ip.get(undefined, item.key) catch unreachable);
        }
    }

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
    assert(index != .none);
    const item = ip.items.get(@intFromEnum(index));
    const data = item.data;
    return switch (item.tag) {
        .simple_type => .{ .simple_type = @enumFromInt(data) },
        .simple_value => .{ .simple_value = @enumFromInt(data) },

        .type_int_signed => .{ .int_type = .{
            .signedness = .signed,
            .bits = @as(u16, @intCast(data)),
        } },
        .type_int_unsigned => .{ .int_type = .{
            .signedness = .unsigned,
            .bits = @as(u16, @intCast(data)),
        } },
        .type_pointer => .{ .pointer_type = ip.extraData(Pointer, data) },
        .type_array => .{ .array_type = ip.extraData(Array, data) },
        .type_optional => .{ .optional_type = .{ .payload_type = @enumFromInt(data) } },
        .type_anyframe => .{ .anyframe_type = .{ .child = @enumFromInt(data) } },
        .type_error_union => .{ .error_union_type = ip.extraData(ErrorUnion, data) },
        .type_error_set => .{ .error_set_type = ip.extraData(ErrorSet, data) },
        .type_function => .{ .function_type = ip.extraData(Function, data) },
        .type_tuple => .{ .tuple_type = ip.extraData(Tuple, data) },
        .type_vector => .{ .vector_type = ip.extraData(Vector, data) },

        .type_struct => .{ .struct_type = @enumFromInt(data) },
        .type_enum => .{ .enum_type = @enumFromInt(data) },
        .type_union => .{ .union_type = @enumFromInt(data) },

        .int_u64 => .{ .int_u64_value = ip.extraData(U64Value, data) },
        .int_i64 => .{ .int_i64_value = ip.extraData(I64Value, data) },
        .int_big_positive,
        .int_big_negative,
        => .{ .int_big_value = blk: {
            const big_int = ip.extraData(BigIntInternal, data);
            break :blk .{
                .ty = big_int.ty,
                .int = .{
                    .positive = item.tag == .int_big_positive,
                    .limbs = big_int.limbs,
                },
            };
        } },
        .float_f16 => .{ .float_16_value = @bitCast(@as(u16, @intCast(data))) },
        .float_f32 => .{ .float_32_value = @bitCast(data) },
        .float_f64 => .{ .float_64_value = ip.extraData(f64, data) },
        .float_f80 => .{ .float_80_value = ip.extraData(f80, data) },
        .float_f128 => .{ .float_128_value = ip.extraData(f128, data) },
        .float_comptime => .{ .float_comptime_value = ip.extraData(f128, data) },

        .bytes => .{ .bytes = ip.extraData([]const u8, data) },
        .optional_value => .{ .optional_value = ip.extraData(OptionalValue, data) },
        .slice => .{ .slice = ip.extraData(Slice, data) },
        .aggregate => .{ .aggregate = ip.extraData(Aggregate, data) },
        .union_value => .{ .union_value = ip.extraData(UnionValue, data) },
        .null_value => .{ .null_value = .{ .ty = @as(Index, @enumFromInt(data)) } },
        .undefined_value => .{ .undefined_value = .{ .ty = @as(Index, @enumFromInt(data)) } },
        .unknown_value => .{ .unknown_value = .{ .ty = @as(Index, @enumFromInt(data)) } },
    };
}

pub fn get(ip: *InternPool, gpa: Allocator, key: Key) Allocator.Error!Index {
    const adapter: KeyAdapter = .{ .ip = ip };
    const gop = try ip.map.getOrPutAdapted(gpa, key, adapter);
    if (gop.found_existing) return @as(Index, @enumFromInt(gop.index));

    const tag: Tag = key.tag();
    const data: u32 = switch (key) {
        .simple_type => |simple| @intFromEnum(simple),
        .simple_value => |simple| @intFromEnum(simple),

        .int_type => |int_ty| int_ty.bits,
        .optional_type => |optional_ty| @intFromEnum(optional_ty.payload_type),
        .anyframe_type => |anyframe_ty| @intFromEnum(anyframe_ty.child),

        .struct_type => |struct_index| @intFromEnum(struct_index),
        .enum_type => |enum_index| @intFromEnum(enum_index),
        .union_type => |union_index| @intFromEnum(union_index),

        .int_u64_value => |int_val| try ip.addExtra(gpa, int_val),
        .int_i64_value => |int_val| try ip.addExtra(gpa, int_val),
        .int_big_value => |big_int_val| try ip.addExtra(gpa, BigIntInternal{
            .ty = big_int_val.ty,
            .limbs = big_int_val.int.limbs,
        }),
        .float_16_value => |float_val| @as(u16, @bitCast(float_val)),
        .float_32_value => |float_val| @as(u32, @bitCast(float_val)),
        .null_value => |null_val| @intFromEnum(null_val.ty),
        .undefined_value => |undefined_val| @intFromEnum(undefined_val.ty),
        .unknown_value => |unknown_val| @intFromEnum(unknown_val.ty),
        inline else => |data| try ip.addExtra(gpa, data), // TODO sad stage1 noises :(
    };

    try ip.items.append(gpa, .{
        .tag = tag,
        .data = data,
    });
    return @as(Index, @enumFromInt(ip.items.len - 1));
}

pub fn contains(ip: InternPool, key: Key) ?Index {
    const adapter: KeyAdapter = .{ .ip = &ip };
    const index = ip.map.getIndexAdapted(key, adapter) orelse return null;
    return @as(Index, @enumFromInt(index));
}

pub fn getDecl(ip: InternPool, index: InternPool.DeclIndex) *InternPool.Decl {
    var decls = ip.decls;
    return decls.at(@intFromEnum(index));
}
pub fn getStruct(ip: InternPool, index: InternPool.StructIndex) *InternPool.Struct {
    var structs = ip.structs;
    return structs.at(@intFromEnum(index));
}
pub fn getEnum(ip: InternPool, index: InternPool.EnumIndex) *InternPool.Enum {
    var enums = ip.enums;
    return enums.at(@intFromEnum(index));
}
pub fn getUnion(ip: InternPool, index: InternPool.UnionIndex) *InternPool.Union {
    var unions = ip.unions;
    return unions.at(@intFromEnum(index));
}

pub fn createDecl(ip: *InternPool, gpa: Allocator, decl: InternPool.Decl) Allocator.Error!InternPool.DeclIndex {
    try ip.decls.append(gpa, decl);
    return @as(InternPool.DeclIndex, @enumFromInt(ip.decls.count() - 1));
}
pub fn createStruct(ip: *InternPool, gpa: Allocator, struct_info: InternPool.Struct) Allocator.Error!InternPool.StructIndex {
    try ip.structs.append(gpa, struct_info);
    return @as(InternPool.StructIndex, @enumFromInt(ip.structs.count() - 1));
}
pub fn createEnum(ip: *InternPool, gpa: Allocator, enum_info: InternPool.Enum) Allocator.Error!InternPool.EnumIndex {
    try ip.enums.append(gpa, enum_info);
    return @as(InternPool.EnumIndex, @enumFromInt(ip.enums.count() - 1));
}
pub fn createUnion(ip: *InternPool, gpa: Allocator, union_info: InternPool.Union) Allocator.Error!InternPool.UnionIndex {
    try ip.unions.append(gpa, union_info);
    return @as(InternPool.UnionIndex, @enumFromInt(ip.unions.count() - 1));
}

fn addExtra(ip: *InternPool, gpa: Allocator, extra: anytype) Allocator.Error!u32 {
    const T = @TypeOf(extra);
    comptime if (@sizeOf(T) <= 4) {
        @compileError(@typeName(T) ++ " fits into a u32! Consider directly storing this extra in Item's data field");
    };

    const result = @as(u32, @intCast(ip.extra.items.len));
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
        return a.eql(ctx.ip.indexToKey(@as(Index, @enumFromInt(b_map_index))));
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
            return @as(I, @bitCast(a)) == @as(I, @bitCast(b));
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

        .Bool => deepHash(hasher, @intFromBool(key)),
        .Enum => deepHash(hasher, @intFromEnum(key)),
        .Float => |info| deepHash(hasher, switch (info.bits) {
            16 => @as(u16, @bitCast(key)),
            32 => @as(u32, @bitCast(key)),
            64 => @as(u64, @bitCast(key)),
            80 => @as(u80, @bitCast(key)),
            128 => @as(u128, @bitCast(key)),
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
        0 => return Index.noreturn_type,
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
    for (types[1..], 1..) |candidate, candidate_i| {
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
            chosen_i = candidate_i;
            continue;
        }

        switch (candidate_key) {
            .simple_type => |candidate_simple| switch (candidate_simple) {
                .f16, .f32, .f64, .f80, .f128 => switch (chosen_key) {
                    .simple_type => |chosen_simple| switch (chosen_simple) {
                        .f16, .f32, .f64, .f80, .f128 => {
                            if (chosen_key.floatBits(target) < candidate_key.floatBits(target)) {
                                chosen = candidate;
                                chosen_i = candidate_i;
                            }
                            continue;
                        },
                        .comptime_int, .comptime_float => {
                            chosen = candidate;
                            chosen_i = candidate_i;
                            continue;
                        },
                        else => {},
                    },
                    else => {},
                },

                .usize,
                .isize,
                .c_char,
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
                        .c_char,
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
                            const chosen_bits = chosen_key.intInfo(target, ip.*).bits;
                            const candidate_bits = candidate_key.intInfo(target, ip.*).bits;

                            if (chosen_bits < candidate_bits) {
                                chosen = candidate;
                                chosen_i = candidate_i;
                            }
                            continue;
                        },
                        .comptime_int => {
                            chosen = candidate;
                            chosen_i = candidate_i;
                            continue;
                        },
                        else => {},
                    },
                    .int_type => |chosen_info| {
                        if (chosen_info.bits < candidate_key.intInfo(target, ip.*).bits) {
                            chosen = candidate;
                            chosen_i = candidate_i;
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
                        .c_char,
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
                            chosen_i = candidate_i;
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
                    .c_char,
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
                        const chosen_bits = chosen_key.intInfo(target, ip.*).bits;
                        const candidate_bits = candidate_key.intInfo(target, ip.*).bits;

                        if (chosen_bits < candidate_bits) {
                            chosen = candidate;
                            chosen_i = candidate_i;
                        }
                        continue;
                    },
                    .comptime_int => {
                        chosen = candidate;
                        chosen_i = candidate_i;
                        continue;
                    },
                    else => {},
                },
                .int_type => |chosen_info| {
                    if (chosen_info.bits < candidate_info.bits) {
                        chosen = candidate;
                        chosen_i = candidate_i;
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
                            chosen_i = candidate_i;
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
                        chosen_i = candidate_i;
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
                            chosen_i = candidate_i;
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
                                chosen_i = candidate_i;
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
                        chosen_i = candidate_i;
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
                            chosen_i = candidate_i;
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
                chosen_i = candidate_i;
                continue;
            },
            .vector_type => switch (chosen_key) {
                .array_type => {
                    chosen = candidate;
                    chosen_i = candidate_i;
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
                    chosen_i = candidate_i;
                    continue;
                },
                .null_type => {
                    any_are_null = true;
                    chosen = candidate;
                    chosen_i = candidate_i;
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
                    chosen_i = candidate_i;
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
    missing_error: []const Index,
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
    double_ptr_to_anyopaque: Pair,

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
) Allocator.Error!InMemoryCoercionResult {
    if (dest_ty == src_ty) return .ok;
    if (dest_ty == .unknown_type or src_ty == .unknown_type) return .ok;

    const dest_key = ip.indexToKey(dest_ty);
    const src_key = ip.indexToKey(src_ty);
    assert(dest_key.typeOf() == .type_type);
    assert(src_key.typeOf() == .type_type);

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
            const dest_info = dest_key.intInfo(target, ip.*);
            const src_info = src_key.intInfo(target, ip.*);

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
            return try ip.coerceInMemoryAllowedErrorSets(gpa, arena, dest_ty, src_ty);
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

fn coerceInMemoryAllowedErrorSets(
    ip: *InternPool,
    gpa: Allocator,
    arena: Allocator,
    dest_ty: Index,
    src_ty: Index,
) !InMemoryCoercionResult {
    if (dest_ty == src_ty) return .ok;

    const dest_key = ip.indexToKey(dest_ty);
    assert(dest_key.zigTypeTag() == .ErrorSet);

    if (dest_ty == .anyerror_type) return .ok;

    const src_key = ip.indexToKey(src_ty);
    assert(src_key.zigTypeTag() == .ErrorSet);

    if (src_ty == .anyerror_type) return .from_anyerror;

    var missing_error_buf = std.ArrayListUnmanaged(Index){};
    defer missing_error_buf.deinit(gpa);

    for (src_key.error_set_type.names) |name| {
        if (std.mem.indexOfScalar(Index, dest_key.error_set_type.names, name) == null) {
            try missing_error_buf.append(gpa, name);
        }
    }

    if (missing_error_buf.items.len == 0) return .ok;

    return InMemoryCoercionResult{
        .missing_error = try arena.dupe(Index, missing_error_buf.items),
    };
}

fn coerceInMemoryAllowedFns(
    ip: *InternPool,
    gpa: Allocator,
    arena: Allocator,
    dest_info: Function,
    src_info: Function,
    target: std.Target,
) Allocator.Error!InMemoryCoercionResult {
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

    if (src_info.return_type != Index.noreturn_type) {
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

    for (dest_info.args, src_info.args, 0..) |dest_arg_ty, src_arg_ty, i| {
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
) Allocator.Error!InMemoryCoercionResult {
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

    try expectFmt("@TypeOf(null)", "{}", .{null_type.fmt(ip)});
    try expectFmt("@TypeOf(undefined)", "{}", .{undefined_type.fmt(ip)});
    try expectFmt("@TypeOf(.enum_literal)", "{}", .{enum_literal_type.fmt(ip)});

    try expectFmt("undefined", "{}", .{undefined_value.fmt(ip)});
    try expectFmt("{}", "{}", .{void_value.fmt(ip)});
    try expectFmt("unreachable", "{}", .{unreachable_value.fmt(ip)});
    try expectFmt("null", "{}", .{null_value.fmt(ip)});
    try expectFmt("true", "{}", .{bool_true.fmt(ip)});
    try expectFmt("false", "{}", .{bool_false.fmt(ip)});
}

test "int type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });
    const u7_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 7 } });
    const another_i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });

    try expect(i32_type == another_i32_type);
    try expect(i32_type != u7_type);

    try expect(i16_type != another_i32_type);
    try expect(i16_type != u7_type);

    try expectFmt("i32", "{}", .{i32_type.fmt(ip)});
    try expectFmt("i16", "{}", .{i16_type.fmt(ip)});
    try expectFmt("u7", "{}", .{u7_type.fmt(ip)});
}

test "int value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const unsigned_zero_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .u64_type, .int = 0 } });
    const unsigned_one_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .u64_type, .int = 1 } });
    const signed_zero_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .i64_type, .int = 0 } });
    const signed_one_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .i64_type, .int = 1 } });

    const u64_max_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .u64_type, .int = std.math.maxInt(u64) } });
    const i64_max_value = try ip.get(gpa, .{ .int_i64_value = .{ .ty = .i64_type, .int = std.math.maxInt(i64) } });
    const i64_min_value = try ip.get(gpa, .{ .int_i64_value = .{ .ty = .i64_type, .int = std.math.minInt(i64) } });

    try expect(unsigned_zero_value != unsigned_one_value);
    try expect(unsigned_one_value != signed_zero_value);
    try expect(signed_zero_value != signed_one_value);

    try expect(signed_one_value != u64_max_value);
    try expect(u64_max_value != i64_max_value);
    try expect(i64_max_value != i64_min_value);

    try expectFmt("0", "{}", .{unsigned_zero_value.fmt(ip)});
    try expectFmt("1", "{}", .{unsigned_one_value.fmt(ip)});
    try expectFmt("0", "{}", .{signed_zero_value.fmt(ip)});
    try expectFmt("1", "{}", .{signed_one_value.fmt(ip)});

    try expectFmt("18446744073709551615", "{}", .{u64_max_value.fmt(ip)});
    try expectFmt("9223372036854775807", "{}", .{i64_max_value.fmt(ip)});
    try expectFmt("-9223372036854775808", "{}", .{i64_min_value.fmt(ip)});
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

    const positive_big_int_value = try ip.get(gpa, .{ .int_big_value = .{
        .ty = .comptime_int_type,
        .int = result.toConst(),
    } });
    const negative_big_int_value = try ip.get(gpa, .{ .int_big_value = .{
        .ty = .comptime_int_type,
        .int = result.toConst().negate(),
    } });

    try expectFmt("340282366920938463463374607431768211456", "{}", .{positive_big_int_value.fmt(ip)});
    try expectFmt("-340282366920938463463374607431768211456", "{}", .{negative_big_int_value.fmt(ip)});
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

    try expect(f16_type != f32_type);
    try expect(f32_type != f64_type);
    try expect(f64_type != f80_type);
    try expect(f80_type != f128_type);

    try expect(f32_type == another_f32_type);
    try expect(f64_type == another_f64_type);

    try expectFmt("f16", "{}", .{f16_type.fmt(ip)});
    try expectFmt("f32", "{}", .{f32_type.fmt(ip)});
    try expectFmt("f64", "{}", .{f64_type.fmt(ip)});
    try expectFmt("f80", "{}", .{f80_type.fmt(ip)});
    try expectFmt("f128", "{}", .{f128_type.fmt(ip)});
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

    const f32_snan_value = try ip.get(gpa, .{ .float_32_value = std.math.snan(f32) });
    const f32_qnan_value = try ip.get(gpa, .{ .float_32_value = std.math.nan(f32) });

    const f32_inf_value = try ip.get(gpa, .{ .float_32_value = std.math.inf(f32) });
    const f32_ninf_value = try ip.get(gpa, .{ .float_32_value = -std.math.inf(f32) });

    const f32_zero_value = try ip.get(gpa, .{ .float_32_value = 0.0 });
    const f32_nzero_value = try ip.get(gpa, .{ .float_32_value = -0.0 });

    try expect(f16_value != f32_value);
    try expect(f32_value != f64_value);
    try expect(f64_value != f80_value);
    try expect(f80_value != f128_value);

    try expect(f32_snan_value != f32_qnan_value);
    try expect(f32_inf_value != f32_ninf_value);
    try expect(f32_zero_value != f32_nzero_value);

    try expect(!ip.indexToKey(f16_value).eql(ip.indexToKey(f32_value)));
    try expect(ip.indexToKey(f32_value).eql(ip.indexToKey(f32_value)));

    try expect(ip.indexToKey(f32_snan_value).eql(ip.indexToKey(f32_snan_value)));
    try expect(!ip.indexToKey(f32_snan_value).eql(ip.indexToKey(f32_qnan_value)));

    try expect(ip.indexToKey(f32_inf_value).eql(ip.indexToKey(f32_inf_value)));
    try expect(!ip.indexToKey(f32_inf_value).eql(ip.indexToKey(f32_ninf_value)));

    try expect(ip.indexToKey(f32_zero_value).eql(ip.indexToKey(f32_zero_value)));
    try expect(!ip.indexToKey(f32_zero_value).eql(ip.indexToKey(f32_nzero_value)));

    try expectFmt("0.25", "{}", .{f16_value.fmt(ip)});
    try expectFmt("0.5", "{}", .{f32_value.fmt(ip)});
    try expectFmt("1", "{}", .{f64_value.fmt(ip)});
    try expectFmt("2", "{}", .{f80_value.fmt(ip)});
    try expectFmt("2.75", "{}", .{f128_value.fmt(ip)});

    try expectFmt("nan", "{}", .{f32_snan_value.fmt(ip)});
    try expectFmt("nan", "{}", .{f32_qnan_value.fmt(ip)});

    try expectFmt("inf", "{}", .{f32_inf_value.fmt(ip)});
    try expectFmt("-inf", "{}", .{f32_ninf_value.fmt(ip)});

    try expectFmt("0", "{}", .{f32_zero_value.fmt(ip)});
    try expectFmt("-0", "{}", .{f32_nzero_value.fmt(ip)});
}

test "pointer type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"*i32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .i32_type,
        .size = .One,
    } });
    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .One,
    } });
    const @"*const volatile u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .One,
        .is_const = true,
        .is_volatile = true,
    } });
    const @"*align(4:2:3) u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .One,
        .alignment = 4,
        .bit_offset = 2,
        .host_size = 3,
    } });
    const @"*addrspace(.shared) const u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .One,
        .is_const = true,
        .address_space = .shared,
    } });

    const @"[*]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .Many,
    } });
    const @"[*:0]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .Many,
        .sentinel = .zero_comptime_int,
    } });
    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .Slice,
    } });
    const @"[:0]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .Slice,
        .sentinel = .zero_comptime_int,
    } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = .u32_type,
        .size = .C,
    } });

    try expect(@"*i32" != @"*u32");
    try expect(@"*u32" != @"*const volatile u32");
    try expect(@"*const volatile u32" != @"*align(4:2:3) u32");
    try expect(@"*align(4:2:3) u32" != @"*addrspace(.shared) const u32");

    try expect(@"[*]u32" != @"[*:0]u32");
    try expect(@"[*:0]u32" != @"[]u32");
    try expect(@"[*:0]u32" != @"[:0]u32");
    try expect(@"[:0]u32" != @"[*c]u32");

    try expectFmt("*i32", "{}", .{@"*i32".fmt(ip)});
    try expectFmt("*u32", "{}", .{@"*u32".fmt(ip)});
    try expectFmt("*const volatile u32", "{}", .{@"*const volatile u32".fmt(ip)});
    try expectFmt("*align(4:2:3) u32", "{}", .{@"*align(4:2:3) u32".fmt(ip)});
    try expectFmt("*addrspace(.shared) const u32", "{}", .{@"*addrspace(.shared) const u32".fmt(ip)});

    try expectFmt("[*]u32", "{}", .{@"[*]u32".fmt(ip)});
    try expectFmt("[*:0]u32", "{}", .{@"[*:0]u32".fmt(ip)});
    try expectFmt("[]u32", "{}", .{@"[]u32".fmt(ip)});
    try expectFmt("[:0]u32", "{}", .{@"[:0]u32".fmt(ip)});
    try expectFmt("[*c]u32", "{}", .{@"[*c]u32".fmt(ip)});
}

test "optional type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .i32_type } });
    const u32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .u32_type } });

    try expect(i32_optional_type != u32_optional_type);

    try expectFmt("?i32", "{}", .{i32_optional_type.fmt(ip)});
    try expectFmt("?u32", "{}", .{u32_optional_type.fmt(ip)});
}

test "optional value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const u32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .u32_type } });

    const u64_42_value = try ip.get(gpa, .{ .int_u64_value = .{ .ty = .u64_type, .int = 42 } });
    const optional_42_value = try ip.get(gpa, .{ .optional_value = .{ .ty = u32_optional_type, .val = u64_42_value } });

    try expectFmt("42", "{}", .{optional_42_value.fmt(ip)});
}

test "error set type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const foo_name = try ip.get(gpa, .{ .bytes = "foo" });
    const bar_name = try ip.get(gpa, .{ .bytes = "bar" });
    const baz_name = try ip.get(gpa, .{ .bytes = "baz" });

    const empty_error_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{} } });

    const foo_bar_baz_set = try ip.get(gpa, .{ .error_set_type = .{
        .names = &.{ foo_name, bar_name, baz_name },
    } });

    const foo_bar_set = try ip.get(gpa, .{ .error_set_type = .{
        .names = &.{ foo_name, bar_name },
    } });

    try expect(empty_error_set != foo_bar_baz_set);
    try expect(foo_bar_baz_set != foo_bar_set);

    try expectFmt("error{}", "{}", .{empty_error_set.fmt(ip)});
    try expectFmt("error{foo,bar,baz}", "{}", .{foo_bar_baz_set.fmt(ip)});
    try expectFmt("error{foo,bar}", "{}", .{foo_bar_set.fmt(ip)});
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

    try expectFmt("error{}!bool", "{}", .{@"error{}!bool".fmt(ip)});
}

test "array type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const i32_3_array_type = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = .i32_type,
    } });
    const u32_0_0_array_type = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = .u32_type,
        .sentinel = .zero_comptime_int,
    } });

    try expect(i32_3_array_type != u32_0_0_array_type);

    try expectFmt("[3]i32", "{}", .{i32_3_array_type.fmt(ip)});
    try expectFmt("[3:0]u32", "{}", .{u32_0_0_array_type.fmt(ip)});
}

test "struct value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const struct_index = try ip.createStruct(gpa, .{
        .fields = .{},
        .namespace = .none,
        .layout = .Auto,
        .backing_int_ty = .none,
        .status = .none,
    });
    const struct_type = try ip.get(gpa, .{ .struct_type = struct_index });
    const struct_info = ip.getStruct(struct_index);
    try struct_info.fields.put(gpa, "foo", .{ .ty = .usize_type });
    try struct_info.fields.put(gpa, "bar", .{ .ty = .bool_type });

    const aggregate_value = try ip.get(gpa, .{ .aggregate = .{
        .ty = struct_type,
        .values = &.{ .one_usize, .bool_true },
    } });

    try expectFmt(".{.foo = 1, .bar = true}", "{}", .{aggregate_value.fmt(ip)});
}

test "function type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"fn(i32) bool" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{.i32_type},
        .return_type = .bool_type,
    } });

    var args_is_comptime = std.StaticBitSet(32).initEmpty();
    args_is_comptime.set(0);
    var args_is_noalias = std.StaticBitSet(32).initEmpty();
    args_is_noalias.set(1);

    const @"fn(comptime type, noalias i32) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{ .type_type, .i32_type },
        .args_is_comptime = args_is_comptime,
        .args_is_noalias = args_is_noalias,
        .return_type = .type_type,
    } });

    const @"fn(i32, ...) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{.i32_type},
        .return_type = .type_type,
        .is_var_args = true,
    } });

    const @"fn() align(4) callconv(.C) type" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{},
        .return_type = .type_type,
        .alignment = 4,
        .calling_convention = .C,
    } });

    try expectFmt("fn(i32) bool", "{}", .{@"fn(i32) bool".fmt(ip)});
    try expectFmt("fn(comptime type, noalias i32) type", "{}", .{@"fn(comptime type, noalias i32) type".fmt(ip)});
    try expectFmt("fn(i32, ...) type", "{}", .{@"fn(i32, ...) type".fmt(ip)});
    try expectFmt("fn() align(4) callconv(.C) type", "{}", .{@"fn() align(4) callconv(.C) type".fmt(ip)});
}

test "union value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

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
    try union_info.fields.put(gpa, "int", .{ .ty = .usize_type, .alignment = 0 });
    try union_info.fields.put(gpa, "float", .{ .ty = .f16_type, .alignment = 0 });

    const union_value1 = try ip.get(gpa, .{ .union_value = .{
        .ty = union_type,
        .field_index = 0,
        .val = .one_usize,
    } });
    const union_value2 = try ip.get(gpa, .{ .union_value = .{
        .ty = union_type,
        .field_index = 1,
        .val = f16_value,
    } });

    try expectFmt(".{ .int = 1 }", "{}", .{union_value1.fmt(ip)});
    try expectFmt(".{ .float = 0.25 }", "{}", .{union_value2.fmt(ip)});
}

test "anyframe type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"anyframe->i32" = try ip.get(gpa, .{ .anyframe_type = .{ .child = .i32_type } });
    const @"anyframe->bool" = try ip.get(gpa, .{ .anyframe_type = .{ .child = .bool_type } });

    try expect(@"anyframe->i32" != @"anyframe->bool");

    try expectFmt("anyframe->i32", "{}", .{@"anyframe->i32".fmt(ip)});
    try expectFmt("anyframe->bool", "{}", .{@"anyframe->bool".fmt(ip)});
}

test "vector type" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"@Vector(2,u32)" = try ip.get(gpa, .{ .vector_type = .{
        .len = 2,
        .child = .u32_type,
    } });
    const @"@Vector(2,bool)" = try ip.get(gpa, .{ .vector_type = .{
        .len = 2,
        .child = .bool_type,
    } });

    try expect(@"@Vector(2,u32)" != @"@Vector(2,bool)");

    try expectFmt("@Vector(2,u32)", "{}", .{@"@Vector(2,u32)".fmt(ip)});
    try expectFmt("@Vector(2,bool)", "{}", .{@"@Vector(2,bool)".fmt(ip)});
}

test "bytes value" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    var str1: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value1 = try ip.get(gpa, .{ .bytes = &str1 });
    @memset(&str1, 0);

    var str2: [43]u8 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ".*;
    const bytes_value2 = try ip.get(gpa, .{ .bytes = &str2 });
    @memset(&str2, 0);

    var str3: [26]u8 = "https://www.duckduckgo.com".*;
    const bytes_value3 = try ip.get(gpa, .{ .bytes = &str3 });
    @memset(&str3, 0);

    try expect(bytes_value1 == bytes_value2);
    try expect(bytes_value2 != bytes_value3);

    try expect(@intFromPtr(&str1) != @intFromPtr(ip.indexToKey(bytes_value1).bytes.ptr));
    try expect(@intFromPtr(&str2) != @intFromPtr(ip.indexToKey(bytes_value2).bytes.ptr));
    try expect(@intFromPtr(&str3) != @intFromPtr(ip.indexToKey(bytes_value3).bytes.ptr));

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

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u32_type, .u32_type, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u32_type, .u16_type, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u16_type, .u32_type, true, builtin.target) == .int_not_coercible);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .i32_type, .u32_type, true, builtin.target) == .int_not_coercible);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u32_type, .i32_type, true, builtin.target) == .int_not_coercible);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u32_type, .i16_type, true, builtin.target) == .int_not_coercible);

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .f32_type, .f32_type, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .f64_type, .f32_type, true, builtin.target) == .no_match);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .f32_type, .f64_type, true, builtin.target) == .no_match);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .u32_type, .f32_type, true, builtin.target) == .no_match);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .f32_type, .u32_type, true, builtin.target) == .no_match);
}

test "coerceInMemoryAllowed error set" {
    const gpa = std.testing.allocator;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const foo_name = try ip.get(gpa, .{ .bytes = "foo" });
    const bar_name = try ip.get(gpa, .{ .bytes = "bar" });
    const baz_name = try ip.get(gpa, .{ .bytes = "baz" });

    const foo_bar_baz_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{ baz_name, bar_name, foo_name } } });
    const foo_bar_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{ foo_name, bar_name } } });
    const foo_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{foo_name} } });
    const empty_set = try ip.get(gpa, .{ .error_set_type = .{ .names = &.{} } });

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .anyerror_type, foo_bar_baz_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .anyerror_type, foo_bar_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .anyerror_type, foo_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .anyerror_type, empty_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, .anyerror_type, .anyerror_type, true, builtin.target) == .ok);

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_baz_set, .anyerror_type, true, builtin.target) == .from_anyerror);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, empty_set, .anyerror_type, true, builtin.target) == .from_anyerror);

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_baz_set, foo_bar_baz_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_baz_set, foo_bar_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_baz_set, foo_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_baz_set, empty_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_set, foo_bar_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_set, foo_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_set, empty_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_set, foo_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_set, empty_set, true, builtin.target) == .ok);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, empty_set, empty_set, true, builtin.target) == .ok);

    try expect(try ip.coerceInMemoryAllowed(gpa, arena, empty_set, foo_set, true, builtin.target) == .missing_error);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, empty_set, foo_bar_baz_set, true, builtin.target) == .missing_error);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_set, foo_bar_set, true, builtin.target) == .missing_error);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_set, foo_bar_baz_set, true, builtin.target) == .missing_error);
    try expect(try ip.coerceInMemoryAllowed(gpa, arena, foo_bar_set, foo_bar_baz_set, true, builtin.target) == .missing_error);
}

test "resolvePeerTypes" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    try expect(.noreturn_type == try ip.resolvePeerTypes(std.testing.allocator, &.{}, builtin.target));
    try expect(.type_type == try ip.resolvePeerTypes(std.testing.allocator, &.{.type_type}, builtin.target));

    try ip.testResolvePeerTypes(.none, .none, .none);
    try ip.testResolvePeerTypes(.bool_type, .bool_type, .bool_type);
    try ip.testResolvePeerTypes(.bool_type, .noreturn_type, .bool_type);
    try ip.testResolvePeerTypes(.bool_type, .undefined_type, .bool_type);
    try ip.testResolvePeerTypes(.type_type, .noreturn_type, .type_type);
    try ip.testResolvePeerTypes(.type_type, .undefined_type, .type_type);
}

test "resolvePeerTypes integers and floats" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    try ip.testResolvePeerTypes(.i16_type, .i16_type, .i16_type);
    try ip.testResolvePeerTypes(.i16_type, .i32_type, .i32_type);
    try ip.testResolvePeerTypes(.i32_type, .i64_type, .i64_type);

    try ip.testResolvePeerTypes(.u16_type, .u16_type, .u16_type);
    try ip.testResolvePeerTypes(.u16_type, .u32_type, .u32_type);
    try ip.testResolvePeerTypes(.u32_type, .u64_type, .u64_type);

    try ip.testResolvePeerTypesInOrder(.i16_type, .u16_type, .i16_type);
    try ip.testResolvePeerTypesInOrder(.u16_type, .i16_type, .u16_type);
    try ip.testResolvePeerTypesInOrder(.i32_type, .u32_type, .i32_type);
    try ip.testResolvePeerTypesInOrder(.u32_type, .i32_type, .u32_type);
    try ip.testResolvePeerTypesInOrder(.isize_type, .usize_type, .isize_type);
    try ip.testResolvePeerTypesInOrder(.usize_type, .isize_type, .usize_type);

    try ip.testResolvePeerTypes(.i16_type, .u32_type, .u32_type);
    try ip.testResolvePeerTypes(.u16_type, .i32_type, .i32_type);
    try ip.testResolvePeerTypes(.i32_type, .u64_type, .u64_type);
    try ip.testResolvePeerTypes(.u32_type, .i64_type, .i64_type);

    try ip.testResolvePeerTypes(.i16_type, .usize_type, .usize_type);
    try ip.testResolvePeerTypes(.i16_type, .isize_type, .isize_type);
    try ip.testResolvePeerTypes(.u16_type, .usize_type, .usize_type);
    try ip.testResolvePeerTypes(.u16_type, .isize_type, .isize_type);

    try ip.testResolvePeerTypes(.c_short_type, .usize_type, .usize_type);
    try ip.testResolvePeerTypes(.c_short_type, .isize_type, .isize_type);

    try ip.testResolvePeerTypes(.i16_type, .c_long_type, .c_long_type);
    try ip.testResolvePeerTypes(.i16_type, .c_long_type, .c_long_type);
    try ip.testResolvePeerTypes(.u16_type, .c_long_type, .c_long_type);
    try ip.testResolvePeerTypes(.u16_type, .c_long_type, .c_long_type);

    try ip.testResolvePeerTypes(.comptime_int_type, .i16_type, .i16_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .u64_type, .u64_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .isize_type, .isize_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .usize_type, .usize_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .c_short_type, .c_short_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .c_int_type, .c_int_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .c_long_type, .c_long_type);

    try ip.testResolvePeerTypes(.comptime_float_type, .i16_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .u64_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .isize_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .usize_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .c_short_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .c_int_type, .none);
    try ip.testResolvePeerTypes(.comptime_float_type, .c_long_type, .none);

    try ip.testResolvePeerTypes(.comptime_float_type, .comptime_int_type, .comptime_float_type);

    try ip.testResolvePeerTypes(.f16_type, .f32_type, .f32_type);
    try ip.testResolvePeerTypes(.f32_type, .f64_type, .f64_type);

    try ip.testResolvePeerTypes(.comptime_int_type, .f16_type, .f16_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .f32_type, .f32_type);
    try ip.testResolvePeerTypes(.comptime_int_type, .f64_type, .f64_type);

    try ip.testResolvePeerTypes(.comptime_float_type, .f16_type, .f16_type);
    try ip.testResolvePeerTypes(.comptime_float_type, .f32_type, .f32_type);
    try ip.testResolvePeerTypes(.comptime_float_type, .f64_type, .f64_type);

    try ip.testResolvePeerTypes(.f16_type, .i16_type, .none);
    try ip.testResolvePeerTypes(.f32_type, .u64_type, .none);
    try ip.testResolvePeerTypes(.f64_type, .isize_type, .none);
    try ip.testResolvePeerTypes(.f16_type, .usize_type, .none);
    try ip.testResolvePeerTypes(.f32_type, .c_short_type, .none);
    try ip.testResolvePeerTypes(.f64_type, .c_int_type, .none);
    try ip.testResolvePeerTypes(.f64_type, .c_long_type, .none);

    try ip.testResolvePeerTypes(.bool_type, .i16_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .u64_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .usize_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .c_int_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .comptime_int_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .comptime_float_type, .none);
    try ip.testResolvePeerTypes(.bool_type, .f32_type, .none);
}

test "resolvePeerTypes optionals" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"?u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .u32_type } });
    const @"?bool" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = .bool_type } });

    try ip.testResolvePeerTypes(.u32_type, .null_type, @"?u32");
    try ip.testResolvePeerTypes(.bool_type, .null_type, @"?bool");
}

test "resolvePeerTypes pointers" {
    const gpa = std.testing.allocator;

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .One } });
    const @"[*]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .Many } });
    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .Slice } });
    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .C } });

    const @"?*u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*u32" } });
    const @"?[*]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[*]u32" } });
    const @"?[]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"[]u32" } });

    const @"**u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"*u32", .size = .One } });
    const @"*[*]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[*]u32", .size = .One } });
    const @"*[]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[]u32", .size = .One } });
    const @"*[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[*c]u32", .size = .One } });

    const @"?*[*]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[*]u32" } });
    const @"?*[]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[]u32" } });

    const @"[1]u32" = try ip.get(gpa, .{ .array_type = .{ .len = 1, .child = .u32_type, .sentinel = .none } });
    const @"[2]u32" = try ip.get(gpa, .{ .array_type = .{ .len = 2, .child = .u32_type, .sentinel = .none } });

    const @"*[1]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[1]u32", .size = .One } });
    const @"*[2]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[2]u32", .size = .One } });

    const @"?*[1]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[1]u32" } });
    const @"?*[2]u32" = try ip.get(gpa, .{ .optional_type = .{ .payload_type = @"*[2]u32" } });

    const @"*const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .One, .is_const = true } });
    const @"[*]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .Many, .is_const = true } });
    const @"[]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .Slice, .is_const = true } });
    const @"[*c]const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .C, .is_const = true } });

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

    try ip.testResolvePeerTypes(@"[*c]u32", .comptime_int_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", .u32_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", .comptime_float_type, .none);
    try ip.testResolvePeerTypes(@"[*c]u32", .bool_type, .none);

    try ip.testResolvePeerTypes(@"[*c]u32", @"*u32", @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", @"[*]u32", @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", @"[]u32", @"[*c]u32");

    try ip.testResolvePeerTypes(@"[*c]u32", @"*[1]u32", .none);
    try ip.testResolvePeerTypesInOrder(@"[*c]u32", @"?*[1]u32", @"?*[1]u32");
    try ip.testResolvePeerTypesInOrder(@"?*[1]u32", @"[*c]u32", .none);
    try ip.testResolvePeerTypes(@"[*c]u32", @"*[*]u32", .none);
    try ip.testResolvePeerTypesInOrder(@"[*c]u32", @"?*[*]u32", @"?*[*]u32");
    try ip.testResolvePeerTypesInOrder(@"?*[*]u32", @"[*c]u32", .none);
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

    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .One } });
    const @"*const u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = .u32_type, .size = .One, .is_const = true } });

    const @"fn(*u32) void" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{@"*u32"},
        .return_type = .void_type,
    } });

    const @"fn(*const u32) void" = try ip.get(gpa, .{ .function_type = .{
        .args = &.{@"*const u32"},
        .return_type = .void_type,
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
    try expectEqualTypes(ip.*, expected, actual);
}

fn expectEqualTypes(ip: InternPool, expected: Index, actual: Index) !void {
    if (expected == actual) return;
    const allocator = std.testing.allocator;

    const expected_type = if (expected == .none) @tagName(Index.none) else try std.fmt.allocPrint(allocator, "{}", .{expected.fmt(ip)});
    defer if (expected != .none) allocator.free(expected_type);
    const actual_type = if (actual == .none) @tagName(Index.none) else try std.fmt.allocPrint(allocator, "{}", .{actual.fmt(ip)});
    defer if (actual != .none) allocator.free(actual_type);

    std.debug.print("expected `{s}`, found `{s}`\n", .{ expected_type, actual_type });
    return error.TestExpectedEqual;
}
