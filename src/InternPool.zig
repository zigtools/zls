/// Based on src/InternPool.zig from the zig codebase
/// https://github.com/ziglang/zig/blob/master/src/InternPool.zig
map: std.AutoArrayHashMapUnmanaged(void, void) = .{},
items: std.MultiArrayList(Item) = .{},
extra: std.ArrayListUnmanaged(u8) = .{},

const InternPool = @This();
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const KeyAdapter = struct {
    intern_pool: *const InternPool,

    pub fn eql(ctx: @This(), a: Key, b_void: void, b_map_index: usize) bool {
        _ = b_void;
        return ctx.intern_pool.indexToKey(@intToEnum(Index, b_map_index)).eql(a);
    }

    pub fn hash(ctx: @This(), a: Key) u32 {
        _ = ctx;
        return a.hash();
    }
};

pub const Int = struct {
    signedness: std.builtin.Signedness,
    bits: u16,
};

pub const Pointer = struct {
    elem_type: Index,
    sentinel: Index = .none,
    alignment: u16 = 0,
    size: std.builtin.Type.Pointer.Size,
    is_const: bool = false,
    is_volatile: bool = false,
    is_allowzero: bool = false,
    address_space: std.builtin.AddressSpace = .generic,
};

pub const Array = struct {
    // TODO support big int
    len: u32,
    child: Index,
    sentinel: Index = .none,
};

pub const Struct = struct {
    fields: []const Field,
    namespace: NamespaceIndex,
    layout: std.builtin.Type.ContainerLayout = .Auto,
    backing_int_ty: Index,

    pub const Field = struct {
        name: []const u8,
        ty: Index,
        default_value: Index = .none,
        alignment: u16 = 0,
        is_comptime: bool = false,
    };
};

pub const Optional = struct {
    payload_type: Index,
};

pub const ErrorUnion = struct {
    error_set_type: Index,
    payload_type: Index,
};

// pub const Error = struct {
//     name: []const u8,
// };

pub const ErrorSet = struct {
    /// must be sorted
    names: [][]const u8,

    pub fn sort(self: *ErrorSet) void {
        std.sort.sort([][]const u8, self.names, u8, std.mem.lessThan);
    }
};

pub const Enum = struct {
    tag_type: Index,
    fields: []const Field,
    namespace: NamespaceIndex,
    tag_type_infered: bool,

    pub const Field = struct {
        name: []const u8,
        ty: Index,
    };
};

pub const Fn = struct {
    calling_convention: std.builtin.CallingConvention = .Unspecified,
    alignment: u16 = 0,
    is_generic: bool = false,
    is_var_args: bool = false,
    return_type: Index,
    args: []const Param,

    pub const Param = struct {
        is_comptime: bool,
        is_generic: bool,
        is_noalias: bool,
        arg_type: Index,
    };
};

pub const Union = struct {
    tag_type: Index,
    fields: []const Field,
    namespace: NamespaceIndex,
    layout: std.builtin.Type.ContainerLayout = .Auto,

    pub const Field = struct {
        name: []const u8,
        ty: Index,
        alignment: u16,
    };
};

pub const Tuple = struct {
    types: []const Index,
    /// unreachable_value elements are used to indicate runtime-known.
    values: []const Index,
};

pub const Vector = struct {
    // TODO support big int
    len: u32,
    child: Index,
};

pub const AnyFrame = struct {
    child: Index,
};

pub const BigInt = std.math.big.int.Const;

pub const Bytes = struct {
    data: []const u8,
};

pub const Aggregate = struct {
    data: []const Index,
};

pub const UnionValue = struct {
    tag: Index,
    val: Index,
};

pub const Key = union(enum) {
    simple: Simple,

    int_type: Int,
    pointer_type: Pointer,
    array_type: Array,
    struct_type: Struct,
    optional_type: Optional,
    error_union_type: ErrorUnion,
    // error_type: Error,
    error_set_type: ErrorSet,
    enum_type: Enum,
    function_type: Fn,
    union_type: Union,
    tuple_type: Tuple,
    vector_type: Vector,
    anyframe_t_type: AnyFrame,

    int_u64_value: u64,
    int_i64_value: i64,
    int_big_value: BigInt,
    float_16_value: f16,
    float_32_value: f32,
    float_64_value: f64,
    float_80_value: f80,
    float_128_value: f128,
    // type_value: Index,

    bytes: Bytes,
    // one_pointer: Index,
    aggregate: Aggregate,
    union_value: UnionValue,

    // slice
    // error
    // error union

    pub fn hash(key: Key) u32 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, std.meta.activeTag(key));
        switch (key) {
            .float_16_value => |f| std.hash.autoHash(&hasher, @bitCast(u16, f)),
            .float_32_value => |f| std.hash.autoHash(&hasher, @bitCast(u32, f)),
            .float_64_value => |f| std.hash.autoHash(&hasher, @bitCast(u64, f)),
            .float_80_value => |f| std.hash.autoHash(&hasher, @bitCast(u80, f)),
            .float_128_value => |f| std.hash.autoHash(&hasher, @bitCast(u128, f)),
            inline else => |info| std.hash.autoHashStrat(&hasher, info, .Deep), // TODO sad stage1 noises :(
        }
        return @truncate(u32, hasher.final());
    }

    pub fn eql(a: Key, b: Key) bool {
        const KeyTag = std.meta.Tag(Key);
        const a_tag: KeyTag = a;
        const b_tag: KeyTag = b;
        if (a_tag != b_tag) return false;
        return switch (a) {
            .struct_type => |struct_info| {
                if (struct_info.layout != b.struct_type.layout) return false;
                if (struct_info.fields.len != b.struct_type.fields.len) return false;
                for (struct_info.fields) |field, i| {
                    if (!std.meta.eql(field, b.struct_type.fields[i])) return false;
                }
                return true;
            },
            // .error_type => |error_info| std.mem.eql(u8, error_info.name, b.error_type.name),
            .error_set_type => |error_set_info| {
                if (error_set_info.names.len != b.error_set_type.names.len) return false;
                for (error_set_info.names) |a_name, i| {
                    const b_name = b.error_set_type.names[i];
                    if (!std.mem.eql(u8, a_name, b_name)) return false;
                }
                return true;
            },
            .enum_type => |enum_info| {
                if (enum_info.tag_type != b.enum_type.tag_type) return false;
                if (enum_info.tag_type_infered != b.enum_type.tag_type_infered) return false;
                if (enum_info.fields.len != b.enum_type.fields.len) return false;
                @panic("TODO: implement field equality check");
            },
            .function_type => |function_info| {
                if (function_info.calling_convention != b.function_type.calling_convention) return false;
                if (function_info.alignment != b.function_type.alignment) return false;
                if (function_info.is_generic != b.function_type.is_generic) return false;
                if (function_info.is_var_args != b.function_type.is_var_args) return false;
                if (function_info.return_type != b.function_type.return_type) return false;
                if (function_info.args.len != b.function_type.args.len) return false;

                for (function_info.args) |arg, i| {
                    if (!std.meta.eql(arg, b.function_type.args[i])) return false;
                }
                return true;
            },
            .union_type => |union_info| {
                if (union_info.tag_type != b.union_type.tag_type) return false;
                if (union_info.layout != b.union_type.layout) return false;
                if (union_info.fields.len != b.union_type.fields.len) return false;
                for (union_info.fields) |field, i| {
                    if (!std.meta.eql(field, b.union_type.fields[i])) return false;
                }
                return true;
            },
            .tuple_type => |tuple_info| {
                std.debug.assert(tuple_info.types.len == tuple_info.values.len);
                std.debug.assert(b.tuple_type.types.len == b.tuple_type.values.len);
                if (tuple_info.types.len != b.tuple_type.types.len) return false;
                for (tuple_info.types) |ty, i| {
                    if (ty != b.tuple_type.types[i]) return false;
                }
                for (tuple_info.values) |val, i| {
                    if (val != b.tuple_type.values[i]) return false;
                }
                return true;
            },
            .bytes => |bytes| std.mem.eql(u8, bytes.data, b.bytes.data),
            .aggregate => |aggregate| {
                if (aggregate.data.len != b.aggregate.data.len) return false;
                for (aggregate.data) |ty, i| {
                    if (ty != b.aggregate.data[i]) return false;
                }
                return true;
            },
            else => std.meta.eql(a, b),
        };
    }

    pub fn tag(key: Key) Tag {
        return switch (key) {
            .simple => .simple,
            .int_type => |int_info| switch (int_info.signedness) {
                .signed => .type_int_signed,
                .unsigned => .type_int_unsigned,
            },
            .pointer_type => .type_pointer,
            .array_type => .type_array,
            .struct_type => .type_struct,
            .optional_type => .type_optional,
            .error_union_type => .type_error_union,
            // .error_type => .type_error,
            .error_set_type => .type_error_set,
            .enum_type => .type_enum,
            .function_type => .type_function,
            .union_type => .type_union,
            .tuple_type => .type_tuple,
            .vector_type => .type_vector,
            .anyframe_t_type => .type_anyframe_t,

            .int_u64_value => |int| if (int <= std.math.maxInt(u32)) .int_u32 else .int_u64,
            .int_i64_value => |int| if (std.math.maxInt(i32) <= int and int <= std.math.maxInt(i32)) .int_i32 else .int_i64,
            .int_big_value => |big_int| if (big_int.positive) .int_big_positive else .int_big_negative,
            .float_16_value => .float_f16,
            .float_32_value => .float_f32,
            .float_64_value => .float_f64,
            .float_80_value => .float_f80,
            .float_128_value => .float_f128,
            // .type_value => .type,

            .bytes => .bytes,
            // .one_pointer => .one_pointer,
            .aggregate => .aggregate,
            .union_value => .union_value,
        };
    }

    pub fn zigTypeTag(key: Key) std.builtin.TypeId {
        return switch (key) {
            .simple => |simple| switch (simple) {
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

                .undefined_value,
                .void_value,
                .unreachable_value,
                .null_value,
                .bool_true,
                .bool_false,
                => unreachable,
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
            .anyframe_t_type => .AnyFrame,

            .int_u64_value,
            .int_i64_value,
            .int_big_value,
            .float_16_value,
            .float_32_value,
            .float_64_value,
            .float_80_value,
            .float_128_value,
            // .type_value,
            => unreachable,

            .bytes,
            // .one_pointer,
            .aggregate,
            .union_value,
            => unreachable,
        };
    }

    /// Asserts the type is an integer, enum, error set, packed struct, or vector of one of them.
    pub fn intInfo(ty: Key, target: std.Target, ip: *const InternPool) Int {
        var key: Key = ty;

        while (true) switch (key) {
            .simple => |simple| switch (simple) {
                .usize => return .{ .signedness = .signed, .bits = target.cpu.arch.ptrBitWidth() },
                .isize => return .{ .signedness = .unsigned, .bits = target.cpu.arch.ptrBitWidth() },

                // TODO correctly resolve size based on `target`
                .c_short => return .{ .signedness = .signed, .bits = @bitSizeOf(c_short) },
                .c_ushort => return .{ .signedness = .unsigned, .bits = @bitSizeOf(c_ushort) },
                .c_int => return .{ .signedness = .signed, .bits = @bitSizeOf(c_int) },
                .c_uint => return .{ .signedness = .unsigned, .bits = @bitSizeOf(c_uint) },
                .c_long => return .{ .signedness = .signed, .bits = @bitSizeOf(c_long) },
                .c_ulong => return .{ .signedness = .unsigned, .bits = @bitSizeOf(c_ulong) },
                .c_longlong => return .{ .signedness = .signed, .bits = @bitSizeOf(c_longlong) },
                .c_ulonglong => return .{ .signedness = .unsigned, .bits = @bitSizeOf(c_ulonglong) },
                .c_longdouble => return .{ .signedness = .signed, .bits = @bitSizeOf(c_longdouble) },

                // TODO revisit this when error sets support custom int types (comment taken from zig codebase)
                .anyerror => return .{ .signedness = .unsigned, .bits = 16 },

                else => unreachable,
            },
            .int_type => |int_info| return int_info,
            .enum_type => @panic("TODO"),
            .struct_type => |struct_info| {
                std.debug.assert(struct_info.layout == .Packed);
                key = ip.indexToKey(struct_info.backing_int_ty);
            },
            // TODO revisit this when error sets support custom int types (comment taken from zig codebase)
            .error_set_type => return .{ .signedness = .unsigned, .bits = 16 },
            .vector_type => |vector_info| {
                std.debug.assert(vector_info.len == 1);
                key = ip.indexToKey(vector_info.child);
            },
            else => unreachable,
        };
    }

    /// Asserts the type is a fixed-size float or comptime_float.
    /// Returns 128 for comptime_float types.
    pub fn floatBits(ty: Key, target: std.Target) u16 {
        _ = target;
        return switch (ty.simple) {
            .f16 => 16,
            .f32 => 32,
            .f64 => 64,
            .f80 => 80,
            .f128, .comptime_float => 128,
            // TODO correctly resolve size based on `target`
            .c_longdouble => @bitSizeOf(c_longdouble),

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
            .simple => |simple| switch (simple) {
                .@"anyframe" => @panic("TODO: return void type"),
                else => unreachable,
            },
            .pointer_type => |pointer_info| pointer_info.elem_type,
            .array_type => |array_info| array_info.child,
            .optional_type => |optional_info| optional_info.payload_type,
            .vector_type => |vector_info| vector_info.child,
            .anyframe_t_type => |anyframe_t_info| anyframe_t_info.child,
            else => unreachable,
        };
    }

    /// Asserts the type is an array, pointer or vector.
    pub fn sentinel(ty: Key) Index {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.sentinel,
            .array_type => |array_info| array_info.sentinel,
            .struct_type,
            .tuple_type,
            .vector_type,
            => Index.none,
            else => unreachable,
        };
    }

    pub fn getNamespace(ty: Key) NamespaceIndex {
        return switch (ty) {
            .struct_type => |struct_info| struct_info.namespace,
            .enum_type => |enum_info| enum_info.namespace,
            .union_type => |union_info| union_info.namespace,
            else => .none,
        };
    }

    pub const TypeFormatContext = struct {
        ty: Index,
        options: FormatOptions = .{},
        ip: *const InternPool,
    };

    pub const ValueFormatContext = struct {
        value: Index,
        ty: Index,
        options: FormatOptions = .{},
        ip: *const InternPool,
    };

    // TODO implement options
    pub const FormatOptions = struct {
        include_fields: bool = true,
        include_declarations: bool = true,
    };

    pub fn formatType(
        ctx: TypeFormatContext,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        comptime assert(unused_format_string.len == 0);
        _ = options;
        return printType(ctx.ty, ctx.ip, writer);
    }

    pub fn printType(ty: Index, ip: *const InternPool, writer: anytype) @TypeOf(writer).Error!void {
        const key: Key = ip.indexToKey(ty);
        switch (key) {
            .simple => |simple| switch (simple) {
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

                .undefined_value,
                .void_value,
                .unreachable_value,
                .null_value,
                .bool_true,
                .bool_false,
                => unreachable,
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

                    // TODO bit offset
                    // TODO host size
                    try writer.writeAll(") ");
                }

                if (pointer_info.address_space != .generic) {
                    try writer.print("addrspace(.{s}) ", .{@tagName(pointer_info.address_space)});
                }

                if (pointer_info.is_const) try writer.writeAll("const ");
                if (pointer_info.is_volatile) try writer.writeAll("volatile ");
                if (pointer_info.is_allowzero and pointer_info.size != .C) try writer.writeAll("allowzero ");

                try printType(pointer_info.elem_type, ip, writer);
            },
            .array_type => |array_info| {
                try writer.print("[{d}", .{array_info.len});
                if (array_info.sentinel != Index.none) {
                    try writer.print(":{}", .{array_info.sentinel.fmtValue(array_info.child, ip)});
                }
                try writer.writeByte(']');
                try printType(array_info.child, ip, writer);
            },
            .struct_type => @panic("TODO"),
            .optional_type => |optional_info| {
                try writer.writeByte('?');
                try printType(optional_info.payload_type, ip, writer);
            },
            .error_union_type => |error_union_info| {
                try writer.print("{}!{}", .{
                    error_union_info.error_set_type.fmtType(ip),
                    error_union_info.payload_type.fmtType(ip),
                });
            },
            // .error_type => @panic("TODO"),
            .error_set_type => |error_set_info| {
                const names = error_set_info.names;
                try writer.writeAll("error{");
                for (names) |name, i| {
                    if (i != 0) try writer.writeByte(',');
                    try writer.writeAll(name);
                }
                try writer.writeByte('}');
            },
            .enum_type => @panic("TODO"),
            .function_type => |function_info| {
                try writer.writeAll("fn(");

                for (function_info.args) |arg, i| {
                    if (i != 0) try writer.writeAll(", ");

                    if (arg.is_comptime) {
                        try writer.writeAll("comptime ");
                    }
                    // TODO noalias
                    try printType(arg.arg_type, ip, writer);
                }

                if (function_info.is_var_args) {
                    if (function_info.args.len != 0) {
                        try writer.writeAll(", ");
                    }
                    try writer.writeAll("...");
                }
                try writer.writeAll(") ");

                if (function_info.calling_convention != .Unspecified) {
                    try writer.print("callconv(.{s})", .{@tagName(function_info.calling_convention)});
                }
                if (function_info.alignment != 0) {
                    try writer.print("align({d}) ", .{function_info.alignment});
                }
                try printType(function_info.return_type, ip, writer);
            },
            .union_type => @panic("TODO"),
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
            .anyframe_t_type => |anyframe_info| {
                try writer.writeAll("anyframe->");
                try printType(anyframe_info.child, ip, writer);
            },

            .int_u64_value,
            .int_i64_value,
            .int_big_value,
            .float_16_value,
            .float_32_value,
            .float_64_value,
            .float_80_value,
            .float_128_value,
            => unreachable,

            // .type_value,
            .bytes,
            // .one_pointer,
            .aggregate,
            .union_value,
            => unreachable,
        }
    }

    pub fn formatValue(
        ctx: ValueFormatContext,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        comptime assert(unused_format_string.len == 0);
        _ = options;
        return printValue(ctx.value, ctx.ty, ctx.ip, writer);
    }

    pub fn printValue(
        value: Index,
        ty: Index,
        ip: *const InternPool,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        const value_key: Key = ip.indexToKey(value);
        switch (value_key) {
            .simple => |simple| switch (simple) {
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

                // values
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
            .anyframe_t_type,
            => unreachable,

            .int_u64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_i64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_big_value => |big_int| try big_int.format("", .{}, writer),
            .float_16_value => |float| try writer.print("{d}", .{float}),
            .float_32_value => |float| try writer.print("{d}", .{float}),
            .float_64_value => |float| try writer.print("{d}", .{float}),
            .float_80_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),
            .float_128_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),

            // .type_value => |tty| tty.fmtType(ip),
            .bytes => |data| try writer.print("\"{}\"", .{std.zig.fmtEscapes(data.data)}),
            // .one_pointer => unreachable,
            .aggregate => |aggregate| {
                const struct_info = ip.indexToKey(ty).struct_type;
                std.debug.assert(aggregate.data.len == struct_info.fields.len);

                try writer.writeAll(".{");
                var i: u32 = 0;
                while (i < aggregate.data.len) : (i += 1) {
                    if (i != 0) try writer.writeAll(", ");

                    try writer.print(".{s} = ", .{struct_info.fields[i].name});
                    try printValue(aggregate.data[i], struct_info.fields[i].ty, ip, writer);
                }
                try writer.writeByte('}');
            },
            .union_value => |union_value| {
                const union_info = ip.indexToKey(ty).union_type;

                try writer.writeAll(".{ ");
                try printValue(union_info.tag_type, union_value.tag, ip, writer);
                try writer.writeAll(" = ");
                try printValue(union_value.val, @panic("TODO"), ip, writer);
                try writer.writeAll(" }");
            },
        }
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
    none = std.math.maxInt(u32),
    _,

    pub fn fmtType(ty: Index, ip: *const InternPool) std.fmt.Formatter(Key.formatType) {
        return .{ .data = .{
            .ty = ty,
            .ip = ip,
        } };
    }

    pub fn fmtValue(value_index: Index, type_index: Index, ip: *const InternPool) std.fmt.Formatter(Key.formatValue) {
        return .{ .data = .{
            .value = value_index,
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
    /// A type or value that can be represented with only an enum tag.
    /// data is Simple enum value
    simple,

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
    /// An error type.
    /// data is payload to Error.
    type_error,
    /// An error set type.
    /// data is payload to ErrorSet.
    type_error_set,
    /// An enum type.
    /// data is payload to Enum.
    type_enum,
    /// An function type.
    /// data is payload to Fn.
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
    type_anyframe_t,

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
    // /// A type value.
    // /// data is Index.
    // type,

    /// A byte sequence value.
    /// data is payload to data begin and length.
    bytes,
    // /// A single pointer value.
    // /// data is index to value.
    // one_pointer,
    /// A aggregate (struct) value.
    /// data is index to Aggregate.
    aggregate,
    /// A union value.
    /// data is index to UnionValue.
    union_value,
};

pub const Simple = enum(u32) {
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

    // values
    undefined_value,
    void_value,
    unreachable_value,
    null_value,
    bool_true,
    bool_false,
};

pub fn deinit(ip: *InternPool, gpa: Allocator) void {
    ip.map.deinit(gpa);
    ip.items.deinit(gpa);
    ip.extra.deinit(gpa);

    // TODO deinit fields
}

pub fn indexToKey(ip: InternPool, index: Index) Key {
    const item = ip.items.get(@enumToInt(index));
    const data = item.data;
    return switch (item.tag) {
        .simple => .{ .simple = @intToEnum(Simple, data) },
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
        .type_struct => .{ .struct_type = ip.extraData(Struct, data) },
        .type_optional => .{ .optional_type = .{ .payload_type = @intToEnum(Index, data) } },
        .type_anyframe_t => .{ .anyframe_t_type = .{ .child = @intToEnum(Index, data) } },
        .type_error_union => .{ .error_union_type = ip.extraData(ErrorUnion, data) },
        // .type_error => .{ .error_type = ip.extraData(Error, data) },
        .type_error_set => .{ .error_set_type = ip.extraData(ErrorSet, data) },
        .type_enum => .{ .enum_type = ip.extraData(Enum, data) },
        .type_function => .{ .function_type = ip.extraData(Fn, data) },
        .type_union => .{ .union_type = ip.extraData(Union, data) },
        .type_tuple => .{ .tuple_type = ip.extraData(Tuple, data) },
        .type_vector => .{ .vector_type = ip.extraData(Vector, data) },

        .int_u32 => .{ .int_u64_value = @intCast(u32, data) },
        .int_i32 => .{ .int_i64_value = @bitCast(i32, data) },
        .int_u64 => .{ .int_u64_value = ip.extraData(u64, data) },
        .int_i64 => .{ .int_i64_value = ip.extraData(i64, data) },
        .int_big_positive => unreachable,
        .int_big_negative => unreachable,
        .float_f16 => .{ .float_16_value = @bitCast(f16, @intCast(u16, data)) },
        .float_f32 => .{ .float_32_value = @bitCast(f32, data) },
        .float_f64 => .{ .float_64_value = ip.extraData(f64, data) },
        .float_f80 => .{ .float_80_value = ip.extraData(f80, data) },
        .float_f128 => .{ .float_128_value = ip.extraData(f128, data) },
        // .type => .{ .type_value = @intToEnum(Index, data) },

        .bytes => unreachable, // TODO
        // .one_pointer => .{ .one_pointer = @intToEnum(Index, data) },
        else => @panic("TODO"),
    };
}

pub fn get(ip: *InternPool, gpa: Allocator, key: Key) Allocator.Error!Index {
    const adapter: KeyAdapter = .{ .intern_pool = ip };
    const gop = try ip.map.getOrPutAdapted(gpa, key, adapter);
    if (gop.found_existing) return @intToEnum(Index, gop.index);

    const item: Item = switch (key) {
        .simple => |simple| .{ .tag = .simple, .data = @enumToInt(simple) },
        .int_type => |int_ty| .{
            .tag = switch (int_ty.signedness) {
                .signed => .type_int_signed,
                .unsigned => .type_int_unsigned,
            },
            .data = int_ty.bits,
        },
        .optional_type => |optional_ty| .{ .tag = .type_optional, .data = @enumToInt(optional_ty.payload_type) },
        .anyframe_t_type => |anyframe_t| .{ .tag = .type_anyframe_t, .data = @enumToInt(anyframe_t.child) },
        .int_u64_value => |int_val| if (int_val <= std.math.maxInt(u32)) .{
            .tag = .int_u32,
            .data = @intCast(u32, int_val),
        } else .{
            .tag = .int_u64,
            .data = try ip.addExtra(gpa, int_val),
        },
        .int_i64_value => |int_val| if (std.math.maxInt(i32) <= int_val and int_val <= std.math.maxInt(i32)) .{
            .tag = .int_i32,
            .data = @bitCast(u32, @intCast(u32, int_val)),
        } else .{
            .tag = .int_i64,
            .data = try ip.addExtra(gpa, int_val),
        },
        .float_16_value => |float_val| .{ .tag = .float_f16, .data = @bitCast(u16, float_val) },
        .float_32_value => |float_val| .{ .tag = .float_f32, .data = @bitCast(u32, float_val) },
        // .type_value => |ty| .{ .tag = .type, .data = @enumToInt(ty) },
        .bytes => unreachable, // TODO
        // .one_pointer => |val| .{ .tag = .one_pointer, .data = @enumToInt(val) },
        inline else => |data| .{ .tag = key.tag(), .data = try ip.addExtra(gpa, data) }, // TODO sad stage1 noises :(
    };
    try ip.items.append(gpa, item);
    return @intToEnum(Index, ip.items.len - 1);
}

fn addExtra(ip: *InternPool, gpa: Allocator, extra: anytype) Allocator.Error!u32 {
    comptime if (@sizeOf(@TypeOf(extra)) <= 4) {
        @compileError(@typeName(@TypeOf(extra)) ++ " fits into a u32! Consider directly storing this extra in Item's data field");
    };
    const result = @intCast(u32, ip.extra.items.len);
    try ip.extra.appendSlice(gpa, &std.mem.toBytes(extra));
    return result;
}

fn extraData(ip: InternPool, comptime T: type, index: usize) T {
    const size = @sizeOf(T);
    const bytes = @ptrCast(*const [size]u8, ip.extra.items.ptr + index);
    return std.mem.bytesToValue(T, bytes);
}

// ---------------------------------------------
//                    UTILITY
// ---------------------------------------------

pub fn cast(ip: *InternPool, gpa: Allocator, destination_ty: Index, source_ty: Index, target: std.Target) Allocator.Error!Index {
    return resolvePeerTypes(ip, gpa, &.{ destination_ty, source_ty }, target);
}

pub fn resolvePeerTypes(ip: *InternPool, gpa: Allocator, types: []const Index, target: std.Target) Allocator.Error!Index {
    switch (types.len) {
        0 => return try ip.get(gpa, .{ .simple = .noreturn }),
        1 => return types[0],
        else => {},
    }

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    var arena = arena_allocator.allocator();

    var chosen = types[0];
    // // If this is non-null then it does the following thing, depending on the chosen zigTypeTag().
    // //  * ErrorSet: this is an override
    // //  * ErrorUnion: this is an override of the error set only
    // //  * other: at the end we make an ErrorUnion with the other thing and this
    // var err_set_ty: Index = Index.none;
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
            .simple => |candidate_simple| switch (candidate_simple) {
                .f16, .f32, .f64, .f80, .f128 => switch (chosen_key) {
                    .simple => |chosen_simple| switch (chosen_simple) {
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
                    .simple => |chosen_simple| switch (chosen_simple) {
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
                    .simple => |chosen_simple| switch (chosen_simple) {
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
                    .simple => |chosen_simple| switch (chosen_simple) {
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
                .simple => |chosen_simple| switch (chosen_simple) {
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
                .simple => |chosen_simple| switch (chosen_simple) {
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
            .simple => |simple| switch (simple) {
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
        return opt_ptr_ty;
        // const set_ty = if(err_set_ty != .none) err_set_ty else return opt_ptr_ty;
        // return try ip.get(gpa, .{ .error_union_type = .{
        //     .error_set_type = set_ty,
        //     .payload_type = opt_ptr_ty,
        // } });
    }

    if (seen_const) {
        // turn []T => []const T
        switch (chosen_key) {
            .error_union_type => |error_union_info| {
                var info: Pointer = ip.indexToKey(error_union_info.payload_type).pointer_type;
                info.is_const = true;

                const new_ptr_ty = try ip.get(gpa, .{ .pointer_type = info });
                const opt_ptr_ty = if (any_are_null) try ip.get(gpa, .{ .optional_type = .{ .payload_type = new_ptr_ty } }) else new_ptr_ty;
                // const set_ty = if(err_set_ty != .none) err_set_ty else error_union_info.error_set_type;
                const set_ty = error_union_info.error_set_type;
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
                return opt_ptr_ty;
                // const set_ty = if(err_set_ty != .none) err_set_ty else return opt_ptr_ty;
                // return try ip.get(gpa, .{ .error_union_type = .{
                //     .error_set_type = set_ty,
                //     .payload_type = opt_ptr_ty,
                // } });
            },
            else => return chosen,
        }
    }

    if (any_are_null) {
        const opt_ty = switch (chosen_key) {
            .simple => |simple| switch (simple) {
                .null_type => chosen,
                else => try ip.get(gpa, .{ .optional_type = .{ .payload_type = chosen } }),
            },
            .optional_type => chosen,
            else => try ip.get(gpa, .{ .optional_type = .{ .payload_type = chosen } }),
        };
        return opt_ty;
        // const set_ty = if(err_set_ty != .none) err_set_ty else return opt_ty;
        // return try ip.get(gpa, .{ .error_union_type = .{
        //     .error_set_type = set_ty,
        //     .payload_type = opt_ty,
        // } });
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
        // unreachable_value indicates no sentinel
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

/// If pointers have the same representation in runtime memory
/// * `const` attribute can be gained
/// * `volatile` attribute can be gained
/// * `allowzero` attribute can be gained (whether from explicit attribute, C pointer, or optional pointer) but only if dest_is_const
/// * alignment can be decreased
/// * bit offset attributes must match exactly
/// * `*`/`[*]` must match exactly, but `[*c]` matches either one
/// * sentinel-terminated pointers can coerce into `[*]`
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

            return InMemoryCoercionResult{ .int_not_coercible = .{
                .actual_signedness = src_info.signedness,
                .wanted_signedness = dest_info.signedness,
                .actual_bits = src_info.bits,
                .wanted_bits = dest_info.bits,
            } };
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
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    dest_info: Fn,
    src_info: Fn,
    target: std.Target,
) !InMemoryCoercionResult {
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

    const return_type_key = ip.indexToKey(src_info.return_type);
    const is_noreturn = return_type_key == .simple and return_type_key.simple == .noreturn;

    if (!is_noreturn) {
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

    // TODO

    // if (dest_info.noalias_bits != src_info.noalias_bits) {
    //     return InMemoryCoercionResult{ .fn_param_noalias = .{
    //         .actual = src_info.noalias_bits,
    //         .wanted = dest_info.noalias_bits,
    //     } };
    // }

    // for (dest_info.param_types) |dest_param_ty, i| {
    //     const src_param_ty = src_info.param_types[i];

    //     if (dest_info.comptime_params[i] != src_info.comptime_params[i]) {
    //         return InMemoryCoercionResult{ .fn_param_comptime = .{
    //             .index = i,
    //             .wanted = dest_info.comptime_params[i],
    //         } };
    //     }

    //     // Note: Cast direction is reversed here.
    //     const param = try ip.coerceInMemoryAllowed(gpa, src_param_ty, dest_param_ty, true, target);
    //     if (param != .ok) {
    //         return InMemoryCoercionResult{ .fn_param = .{
    //             .child = try param.dupe(arena),
    //             .actual = src_param_ty,
    //             .wanted = dest_param_ty,
    //             .index = i,
    //         } };
    //     }
    // }

    return .ok;
}

fn coerceInMemoryAllowedPtrs(
    ip: *InternPool,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    dest_ty: Index,
    src_ty: Index,
    dest_ptr_info: Key,
    src_ptr_info: Key,
    dest_is_const: bool,
    target: std.Target,
) !InMemoryCoercionResult {
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

    // if (src_info.host_size != dest_info.host_size or
    //     src_info.bit_offset != dest_info.bit_offset)
    // {
    //     return InMemoryCoercionResult{ .ptr_bit_range = .{
    //         .actual_host = src_info.host_size,
    //         .wanted_host = dest_info.host_size,
    //         .actual_offset = src_info.bit_offset,
    //         .wanted_offset = dest_info.bit_offset,
    //     } };
    // }

    const ok_sent = dest_info.sentinel == .none or src_info.size == .C or dest_info.sentinel == src_info.sentinel; // is this enough for a value equality check?
    if (!ok_sent) {
        return InMemoryCoercionResult{ .ptr_sentinel = .{
            .actual = if (src_info.sentinel != .none) src_info.sentinel else try ip.get(gpa, .{ .simple = .unreachable_value }),
            .wanted = if (dest_info.sentinel != .none) dest_info.sentinel else try ip.get(gpa, .{ .simple = .unreachable_value }),
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

                    // TODO optionals of zero sized types behave like bools, not pointers
                    // if ((try sema.typeHasOnePossibleValue(child_type)) != null) {
                    //     return null;
                    // }

                    return child_type;
                },
            }
        },
        else => unreachable,
    }
}

// ---------------------------------------------
//                     TESTS
// ---------------------------------------------

fn testExpectFmtType(ip: *const InternPool, index: Index, expected: []const u8) !void {
    try std.testing.expectFmt(expected, "{}", .{index.fmtType(ip)});
}

fn testExpectFmtValue(ip: *const InternPool, val: Index, ty: Index, expected: []const u8) !void {
    try std.testing.expectFmt(expected, "{}", .{val.fmtValue(ty, ip)});
}

test "int type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });
    const u7_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 7 } });
    const another_i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });

    try std.testing.expect(i32_type == another_i32_type);
    try std.testing.expect(i32_type != u7_type);

    try std.testing.expect(i16_type != another_i32_type);
    try std.testing.expect(i16_type != u7_type);

    try testExpectFmtType(&ip, i32_type, "i32");
    try testExpectFmtType(&ip, i16_type, "i16");
    try testExpectFmtType(&ip, u7_type, "u7");
}

test "int value" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const unsigned_zero_value = try ip.get(gpa, .{ .int_u64_value = 0 });
    const unsigned_one_value = try ip.get(gpa, .{ .int_u64_value = 1 });
    const signed_zero_value = try ip.get(gpa, .{ .int_i64_value = 0 });
    const signed_one_value = try ip.get(gpa, .{ .int_i64_value = 1 });

    const u64_max_value = try ip.get(gpa, .{ .int_u64_value = std.math.maxInt(u64) });
    const i64_max_value = try ip.get(gpa, .{ .int_i64_value = std.math.maxInt(i64) });

    try std.testing.expect(unsigned_zero_value != unsigned_one_value);
    try std.testing.expect(unsigned_one_value != signed_zero_value);
    try std.testing.expect(signed_zero_value != signed_one_value);

    try std.testing.expect(signed_one_value != u64_max_value);
    try std.testing.expect(u64_max_value != i64_max_value);

    try testExpectFmtValue(&ip, unsigned_zero_value, undefined, "0");
    try testExpectFmtValue(&ip, unsigned_one_value, undefined, "1");
    try testExpectFmtValue(&ip, signed_zero_value, undefined, "0");
    try testExpectFmtValue(&ip, signed_one_value, undefined, "1");

    try testExpectFmtValue(&ip, u64_max_value, undefined, "18446744073709551615");
    try testExpectFmtValue(&ip, i64_max_value, undefined, "9223372036854775807");
}

test "pointer type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i32_type_0 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i32_type_1 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    try std.testing.expect(i32_type_0 == i32_type_1);
    try std.testing.expect(i32_type_0 != u32_type);

    const i32_pointer_type_0 = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = i32_type_0,
        .size = .One,
    } });
    const i32_pointer_type_1 = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = i32_type_0,
        .size = .One,
    } });
    const i32_pointer_type_2 = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = i32_type_1,
        .size = .One,
    } });
    const u32_pointer_type = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
    } });

    try std.testing.expect(i32_pointer_type_0 == i32_pointer_type_1);
    try std.testing.expect(i32_pointer_type_1 == i32_pointer_type_2);
    try std.testing.expect(i32_pointer_type_0 != u32_pointer_type);

    const const_u32_pointer_type = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
        .is_const = true,
    } });

    try std.testing.expect(const_u32_pointer_type != u32_pointer_type);

    try testExpectFmtType(&ip, i32_pointer_type_0, "*i32");
    try testExpectFmtType(&ip, u32_pointer_type, "*u32");
    try testExpectFmtType(&ip, const_u32_pointer_type, "*const u32");
}

test "optional type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i32_type_0 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i32_type_1 = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });

    const null_value = try ip.get(gpa, .{ .simple = .null_value });
    const u64_42_value = try ip.get(gpa, .{ .int_u64_value = 42 });

    const i32_optional_type_0 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_0 } });
    const i32_optional_type_1 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_1 } });
    const u32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = u32_type } });

    try std.testing.expect(i32_optional_type_0 == i32_optional_type_1);
    try std.testing.expect(i32_optional_type_0 != u32_optional_type);

    try testExpectFmtType(&ip, i32_optional_type_0, "?i32");
    try testExpectFmtType(&ip, u32_optional_type, "?u32");

    try testExpectFmtValue(&ip, null_value, u32_optional_type, "null");
    try testExpectFmtValue(&ip, u64_42_value, u32_optional_type, "42");
}

test "array type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
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

    try testExpectFmtType(&ip, i32_3_array_type_0, "[3]i32");
    try testExpectFmtType(&ip, u32_0_0_array_type, "[3:0]u32");
}

test "struct type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const u64_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 64 } });
    const bool_type = try ip.get(gpa, .{ .simple = .bool });

    const field1 = Struct.Field{ .name = "foo", .ty = u64_type };
    const field2 = Struct.Field{ .name = "bar", .ty = i32_type };
    const field3 = Struct.Field{ .name = "baz", .ty = bool_type };

    const struct_type_0 = try ip.get(gpa, Key{
        .struct_type = Struct{
            .fields = &.{ field1, field2, field3 },
            .namespace = .none,
            .layout = .Auto,
            .backing_int_ty = .none,
        },
    });

    _ = try ip.get(gpa, .{ .simple = .unreachable_value });

    const struct_type_1 = try ip.get(gpa, Key{
        .struct_type = Struct{
            .fields = &.{ field1, field2, field3 },
            .namespace = .none,
            .layout = .Auto,
            .backing_int_ty = .none,
        },
    });
    std.debug.assert(struct_type_0 == struct_type_1);
}

test "anyframe type" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const bool_type = try ip.get(gpa, .{ .simple = .bool });

    const @"anyframe->i32" = try ip.get(gpa, Key{ .anyframe_t_type = .{ .child = i32_type } });
    const @"anyframe->bool" = try ip.get(gpa, Key{ .anyframe_t_type = .{ .child = bool_type } });

    try testExpectFmtType(&ip, @"anyframe->i32", "anyframe->i32");
    try testExpectFmtType(&ip, @"anyframe->bool", "anyframe->bool");
}

test "resolvePeerTypes" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const bool_type = try ip.get(gpa, .{ .simple = .bool });
    const type_type = try ip.get(gpa, .{ .simple = .type });
    const noreturn_type = try ip.get(gpa, .{ .simple = .noreturn });
    const undefined_type = try ip.get(gpa, .{ .simple = .undefined_type });

    try ip.testResolvePeerTypes(Index.none, Index.none, Index.none);
    try ip.testResolvePeerTypes(bool_type, bool_type, bool_type);
    try ip.testResolvePeerTypes(bool_type, noreturn_type, bool_type);
    try ip.testResolvePeerTypes(bool_type, undefined_type, bool_type);
    try ip.testResolvePeerTypes(type_type, noreturn_type, type_type);
    try ip.testResolvePeerTypes(type_type, undefined_type, type_type);
}

test "resolvePeerTypes integers and floats" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const i16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 16 } });
    const i32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 32 } });
    const i64_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .signed, .bits = 64 } });
    const u16_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 16 } });
    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const u64_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 64 } });

    const usize_type = try ip.get(gpa, .{ .simple = .usize });
    const isize_type = try ip.get(gpa, .{ .simple = .isize });

    const c_short_type = try ip.get(gpa, .{ .simple = .c_short });
    const c_int_type = try ip.get(gpa, .{ .simple = .c_int });
    const c_long_type = try ip.get(gpa, .{ .simple = .c_long });

    const comptime_int_type = try ip.get(gpa, .{ .simple = .comptime_int });
    const comptime_float_type = try ip.get(gpa, .{ .simple = .comptime_float });

    const f16_type = try ip.get(gpa, .{ .simple = .f16 });
    const f32_type = try ip.get(gpa, .{ .simple = .f32 });
    const f64_type = try ip.get(gpa, .{ .simple = .f64 });

    const bool_type = try ip.get(gpa, .{ .simple = .bool });

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

test "resolvePeerTypes pointers" {
    const gpa = std.testing.allocator;

    var ip: InternPool = .{};
    defer ip.deinit(gpa);

    const u32_type = try ip.get(gpa, .{ .int_type = .{ .signedness = .unsigned, .bits = 32 } });
    const comptime_int_type = try ip.get(gpa, .{ .simple = .comptime_int });
    const comptime_float_type = try ip.get(gpa, .{ .simple = .comptime_float });
    const bool_type = try ip.get(gpa, .{ .simple = .bool });

    const @"[*c]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .C } });

    const @"[1]u32" = try ip.get(gpa, .{ .array_type = .{
        .len = 1,
        .child = u32_type,
        .sentinel = Index.none,
    } });
    const @"[2]u32" = try ip.get(gpa, .{ .array_type = .{
        .len = 2,
        .child = u32_type,
        .sentinel = Index.none,
    } });

    const @"*[1]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[1]u32", .size = .One } });
    const @"*[2]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = @"[2]u32", .size = .One } });

    const @"*u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .One } });

    const @"*const u32" = try ip.get(gpa, .{ .pointer_type = .{
        .elem_type = u32_type,
        .size = .One,
        .is_const = true,
    } });

    const @"[*]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Many } });

    const @"[]u32" = try ip.get(gpa, .{ .pointer_type = .{ .elem_type = u32_type, .size = .Slice } });

    try ip.testResolvePeerTypes(@"[*c]u32", comptime_int_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", u32_type, @"[*c]u32");
    try ip.testResolvePeerTypes(@"[*c]u32", comptime_float_type, Index.none);
    try ip.testResolvePeerTypes(@"[*c]u32", bool_type, Index.none);

    try ip.testResolvePeerTypes(@"[*]u32", @"*[2]u32", @"[*]u32");
    try ip.testResolvePeerTypes(@"[]u32", @"*[2]u32", @"[]u32");

    try ip.testResolvePeerTypes(@"*u32", @"*u32", @"*u32");
    try ip.testResolvePeerTypes(@"*u32", @"*u32", @"*u32");
    try ip.testResolvePeerTypes(@"*u32", @"*const u32", @"*const u32");

    try ip.testResolvePeerTypes(@"*[1]u32", @"*[2]u32", @"[]u32");
}

fn testResolvePeerTypes(ip: *InternPool, a: Index, b: Index, expected: Index) !void {
    try ip.testResolvePeerTypesInOrder(a, b, expected);
    try ip.testResolvePeerTypesInOrder(b, a, expected);
}

fn testResolvePeerTypesInOrder(ip: *InternPool, lhs: Index, rhs: Index, expected: Index) !void {
    const actual = try resolvePeerTypes(ip, std.testing.allocator, &.{ lhs, rhs }, builtin.target);
    try std.testing.expectEqual(expected, actual);
}
