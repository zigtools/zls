/// Based on src/InternPool.zig from the zig codebase
/// https://github.com/ziglang/zig/blob/master/src/InternPool.zig
map: std.AutoArrayHashMapUnmanaged(void, void) = .{},
items: std.MultiArrayList(Item) = .{},
extra: std.ArrayListUnmanaged(u8) = .{},

const InternPool = @This();
const std = @import("std");
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
    sentinel: Index,
    alignment: u16,
    size: std.builtin.Type.Pointer.Size,
    is_const: bool,
    is_volatile: bool,
    is_allowzero: bool,
    address_space: std.builtin.AddressSpace,
};

pub const Array = struct {
    // TODO support big int
    len: u32,
    child: Index,
    sentinel: Index,
};

pub const Struct = struct {
    fields: std.StringArrayHashMapUnmanaged(Field),
    /// always points to Namespace
    namespace: Index,
    layout: std.builtin.Type.ContainerLayout,
    backing_int_ty: Index,

    pub const Field = struct {
        ty: Index,
        default_value: Index,
        alignent: u16,
        is_comptime: bool,
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
    names: std.StringArrayHashMapUnmanaged(void),

    pub fn sort(self: *ErrorSet) void {
        const Context = struct {
            keys: [][]const u8,
            pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
            }
        };
        self.names.sort(Context{ .keys = self.names.keys() });
    }
};

pub const Enum = struct {
    tag_type: Index,
    fields: std.StringArrayHashMapUnmanaged(Index),
    /// this always points to Namespace
    namespace: Index,
    tag_type_infered: bool,
};

pub const Fn = struct {
    calling_convention: std.builtin.CallingConvention,
    alignment: u16,
    is_generic: bool,
    is_var_args: bool,
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
    fields: std.StringArrayHashMapUnmanaged(Field),
    /// always points to Namespace
    namespace: Index,
    layout: std.builtin.Type.ContainerLayout,

    pub const Field = struct {
        ty: Index,
        alignment: u16,
    };
};

pub const Tuple = struct {
    types: []Index,
    /// unreachable_value elements are used to indicate runtime-known.
    values: []Index,
};

pub const Vector = struct {
    // TODO support big int
    len: u32,
    child: Index,
};

pub const BigInt = std.math.big.int.Const;

pub const Decl = struct {
    name: []const u8,
    ty: Index,
    val: Index,
    alignment: u16,
    address_space: std.builtin.AddressSpace,
    is_pub: bool,
    is_exported: bool,
};

pub const Namespace = struct {
    /// always points to Namespace or Index.none
    parent: Index,
    /// Will be a struct, enum, union, or opaque.
    ty: Index,
    /// always points to Decl
    decls: []const Index,
    usingnamespaces: []const Index,
};

pub const Bytes = struct {
    data: []const u8,
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

    declaration: Decl,
    namespace: Namespace,

    int_u64_value: u64,
    int_i64_value: i64,
    int_big_value: BigInt,
    float_16_value: f16,
    float_32_value: f32,
    float_64_value: f64,
    float_80_value: f80,
    float_128_value: f128,
    type_value: Index,

    bytes: Bytes,

    // slice
    // error
    // error union
    // optional
    // aggregate
    // union

    pub fn hash(key: Key) u32 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, std.meta.activeTag(key));
        switch (key) {
            .struct_type => |struct_info| {
                var field_it = struct_info.fields.iterator();
                while (field_it.next()) |item| {
                    hasher.update(item.key_ptr.*);
                    std.hash.autoHash(&hasher, item.value_ptr.*);
                }
                std.hash.autoHash(&hasher, struct_info.layout);
            },
            // .error_type => |error_info| hasher.update(error_info.name),
            .error_set_type => |error_set_info| {
                const names = error_set_info.names.keys();
                std.debug.assert(std.sort.isSorted([]const u8, names, u8, std.mem.lessThan));
                for (names) |error_name| {
                    hasher.update(error_name);
                }
            },
            .enum_type => |enum_info| {
                std.hash.autoHash(&hasher, enum_info.tag_type);
                var field_it = enum_info.fields.iterator();
                while (field_it.next()) |item| {
                    hasher.update(item.key_ptr.*);
                    std.hash.autoHash(&hasher, item.value_ptr.*);
                }
                std.hash.autoHash(&hasher, enum_info.tag_type_infered);
            },
            .function_type => |function_info| std.hash.autoHashStrat(&hasher, function_info, .Deep),
            .union_type => |union_info| {
                std.hash.autoHash(&hasher, union_info.tag_type);
                var field_it = union_info.fields.iterator();
                while (field_it.next()) |item| {
                    hasher.update(item.key_ptr.*);
                    std.hash.autoHash(&hasher, item.value_ptr.*);
                }
                std.hash.autoHash(&hasher, union_info.layout);
            },
            .tuple_type => |tuple_info| std.hash.autoHashStrat(&hasher, tuple_info, .Deep),
            .declaration => |decl_info| std.hash.autoHashStrat(&hasher, decl_info, .Deep),
            .namespace => |namespace_info| std.hash.autoHashStrat(&hasher, namespace_info, .Deep),
            .int_big_value => |big_int| {
                std.hash.autoHash(&hasher, big_int.positive);
                hasher.update(std.mem.sliceAsBytes(big_int.limbs));
            },
            .float_16_value => |f| std.hash.autoHash(&hasher, @bitCast(u16, f)),
            .float_32_value => |f| std.hash.autoHash(&hasher, @bitCast(u32, f)),
            .float_64_value => |f| std.hash.autoHash(&hasher, @bitCast(u64, f)),
            .float_80_value => |f| std.hash.autoHash(&hasher, @bitCast(u80, f)),
            .float_128_value => |f| std.hash.autoHash(&hasher, @bitCast(u128, f)),
            inline else => |info| std.hash.autoHash(&hasher, info), // TODO sad stage1 noises :(
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
                if (struct_info.fields.count() != b.struct_type.fields.count()) return false;
                @panic("TODO: implement field equality check");
            },
            // .error_type => |error_info| std.mem.eql(u8, error_info.name, b.error_type.name),
            .error_set_type => |error_set_info| {
                const a_names = error_set_info.names.keys();
                const b_names = b.error_set_type.names.keys();

                if (a_names.len != b_names.len) return false;
                for (a_names) |a_name, i| {
                    const b_name = b_names[i];
                    if (!std.mem.eql(u8, a_name, b_name)) return false;
                }
                return true;
            },
            .enum_type => |enum_info| {
                if (enum_info.tag_type != b.enum_type.tag_type) return false;
                if (enum_info.tag_type_infered != b.enum_type.tag_type_infered) return false;
                if (enum_info.fields.count() != b.enum_type.fields.count()) return false;
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
                if (union_info.tag_type != b.union_info.tag_type) return false;
                if (union_info.layout != b.union_info.layout) return false;
                if (union_info.fields.count() != b.union_info.fields.count()) return false;
                @panic("TODO: implement union equality");
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
            .declaration => |decl_info| {
                if (!std.mem.eql(u8, decl_info.name, b.declaration.name)) return false;
                if (decl_info.ty != b.declaration.ty) return false;
                if (decl_info.val != b.declaration.val) return false;
                if (decl_info.alignment != b.declaration.alignment) return false;
                if (decl_info.address_space != b.declaration.address_space) return false;
                if (decl_info.is_pub != b.declaration.is_pub) return false;
                if (decl_info.is_exported != b.declaration.is_exported) return false;
                return true;
            },
            .namespace => |namespace_info| {
                if (!std.meta.eql(namespace_info.parent, b.namespace.parent)) return false;
                if (namespace_info.ty != b.namespace.ty) return false;

                if (namespace_info.decls.len != b.namespace.decls.len) return false;
                if (namespace_info.usingnamespaces.len != b.namespace.usingnamespaces.len) return false;

                for (namespace_info.decls) |decl, i| {
                    if (!decl != b.namespace.decls[i]) return false;
                }
                for (namespace_info.usingnamespaces) |namespace, i| {
                    if (!namespace != b.namespace.usingnamespaces[i]) return false;
                }
                return false;
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

            .int_u64_value => |int| if (int <= std.math.maxInt(u32)) .int_u32 else .int_u64,
            .int_i64_value => |int| if (std.math.maxInt(i32) <= int and int <= std.math.maxInt(i32)) .int_i32 else .int_i64,
            .int_big_value => |big_int| if (big_int.positive) .int_big_positive else .int_big_negative,
            .float_16_value => .float_f16,
            .float_32_value => .float_f32,
            .float_64_value => .float_f64,
            .float_80_value => .float_f80,
            .float_128_value => .float_f128,
            .type_value => .type,
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
        };
    }

    /// Asserts the type is an integer, enum, error set, packed struct, or vector of one of them.
    pub fn intInfo(ty: Key, target: std.Target, ip: InternPool) Int {
        var key: Key = ty;

        while (true) switch (key) {
            .simple => |simple| switch (simple) {
                .usize => return .{ .signdness = .signed, .bits = target.cpu.arch.ptrBitWidth() },
                .isize => return .{ .signdness = .unsigned, .bits = target.cpu.arch.ptrBitWidth() },

                // TODO correctly resolve size based on `target`
                .c_short => return .{ .signdness = .signed, .bits = @bitSizeOf(c_short) },
                .c_ushort => return .{ .signdness = .unsigned, .bits = @bitSizeOf(c_ushort) },
                .c_int => return .{ .signdness = .signed, .bits = @bitSizeOf(c_int) },
                .c_uint => return .{ .signdness = .unsigned, .bits = @bitSizeOf(c_uint) },
                .c_long => return .{ .signdness = .signed, .bits = @bitSizeOf(c_long) },
                .c_ulong => return .{ .signdness = .unsigned, .bits = @bitSizeOf(c_ulong) },
                .c_longlong => return .{ .signdness = .signed, .bits = @bitSizeOf(c_longlong) },
                .c_ulonglong => return .{ .signdness = .unsigned, .bits = @bitSizeOf(c_ulonglong) },
                .c_longdouble => return .{ .signdness = .signed, .bits = @bitSizeOf(c_longdouble) },

                // TODO revisit this when error sets support custom int types (comment taken from zig codebase)
                .anyerror => return .{ .signedness = .unsigned, .bits = 16 },
            },
            .int_type => |int_info| return int_info,
            .enum_type => @panic("TODO"),
            .struct_type => |struct_info| {
                std.debug.assert(struct_info.layout == .Packed);
                key = struct_info.backing_int_ty;
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
        std.debug.assert(ty == .simple);
        _ = target;
        return switch (ty.simple) {
            .f16 => 16,
            .f32 => 32,
            .f64 => 64,
            .f80 => 80,
            .f128, .comptime_float => 128,
            // TODO correctly resolve size based on `target`
            .c_longdouble => 80,

            else => unreachable,
        };
    }

    pub fn isCType(ty: Key) bool {
        return switch (ty) {
            .simple => |simple| switch (simple) {
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                => true,
                else => false,
            },
            else => false,
        };
    }

    pub fn isSlice(ty: Key) bool {
        return switch (ty) {
            .pointer_type => |pointer_info| pointer_info.size == .Slice,
            else => false,
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
            .error_set_type => @panic("TODO"),
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
            .tuple_type => @panic("TODO"),
            .vector_type => |vector_info| {
                try writer.print("@Vector({d},{})", .{
                    vector_info.len,
                    vector_info.child.fmtType(ip),
                });
            },

            .declaration, .namespace => unreachable,

            .int_u64_value,
            .int_i64_value,
            .int_big_value,
            .float_16_value,
            .float_32_value,
            .float_64_value,
            .float_80_value,
            .float_128_value,
            => unreachable,

            .type_value,
            .bytes,
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
        _ = ty;
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
            => unreachable,

            .declaration => unreachable,
            .namespace => unreachable,

            .int_u64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_i64_value => |int| try std.fmt.formatIntValue(int, "", .{}, writer),
            .int_big_value => |big_int| try big_int.format("", .{}, writer),
            .float_16_value => |float| try writer.print("{d}", .{float}),
            .float_32_value => |float| try writer.print("{d}", .{float}),
            .float_64_value => |float| try writer.print("{d}", .{float}),
            .float_80_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),
            .float_128_value => |float| try writer.print("{d}", .{@floatCast(f64, float)}),

            .type_value,
            .bytes,
            => unreachable,
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
    /// A type value.
    /// data is Index.
    type,
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
        .type_optional => .{ .optional_type = .{
            .payload_type = @intToEnum(Index, data),
        } },
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
        .type => .{ .type_value = @intToEnum(Index, data) },
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
        .type_value => |ty| .{ .tag = .type, .data = ty },
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

pub fn resolvePeerTypes(ip: *InternPool, gpa: Allocator, types: []const Index, target: std.Target) Allocator.Error!Index {
    switch (types.len) {
        0 => return Key{ .simple = .noreturn },
        1 => types[0],
    }

    var chosen = types[0];
    var any_are_null = false;
    var seen_const = false;
    var convert_to_slice = false;
    var chosen_i: usize = 0;
    for (types[1..]) |candidate, candidate_i| {
        const candidate_key: Key = ip.indexToKey(candidate);
        const chosen_key = ip.indexToKey(chosen);

        if (candidate_key == chosen_key) continue;

        switch (candidate_key) {
            .simple => |candidate_simple| switch (candidate_simple) {
                // TODO usize, isize
                // TODO c integer types
                .f16, .f32, .f64, .f80, .f128 => switch (chosen_key) {
                    .simple => |chosen_simple| switch (chosen_simple) {
                        .f16, .f32, .f64, .f80, .f128 => {
                            // NOTE we don't have to handle the equality case

                            @panic("TODO: choose larger");
                        },
                        .comptime_int, .comptime_float => {
                            chosen = candidate;
                            chosen_i = candidate_i + 1;
                            continue;
                        },
                        else => {},
                    },
                },

                .noreturn, .undefined_type => continue,

                .comptime_int => switch (chosen_key) {
                    .simple => |chosen_simple| switch (chosen_simple) {
                        .f16,
                        .f32,
                        .f64,
                        .f80,
                        .f128,
                        => continue,
                        .usize, .isize => continue,
                        .comptime_int => unreachable,
                        .comptime_float => continue,
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
                    .usize, .isize => {
                        // TODO
                    },
                    // TODO c integer types
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

                        const chosen_ok = .ok == try ip.coerceInMemoryAllowed(gpa, chosen_elem_ty, cand_elem_ty, chosen_info.mutable, target);
                        if (chosen_ok) {
                            convert_to_slice = true;
                            continue;
                        }

                        const cand_ok = .ok == try ip.coerceInMemoryAllowed(gpa, cand_elem_ty, chosen_elem_ty, candidate_info.mutable, target);
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
                        const cand_ok = .ok == try ip.coerceInMemoryAllowed(candidate_info.elem_type, chosen_info.elem_type, candidate_info.mutable, target);
                        const chosen_ok = .ok == try ip.coerceInMemoryAllowed(chosen_info.elem_type, candidate_info.elem_type, chosen_info.mutable, target);

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
                    // TODO
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
                .function_type => {
                    if (candidate_info.is_const and
                        ip.indexToKey(candidate_info.elem_type) == .function_type and
                        .ok == try ip.coerceInMemoryAllowedFns(chosen, candidate_info.pointee_type, target))
                    {
                        chosen = candidate;
                        chosen_i = candidate_i + 1;
                        continue;
                    }
                },
                else => {},
            },
            .array_type => switch (chosen_key) {
                .vector_type => continue,
                else => {},
            },
            .optional_type => |candidate_info| {
                const is_chosen_const_ptr = switch (chosen_key) {
                    .pointer_type => |chosen_info| chosen_info.is_const,
                    else => false,
                };

                if ((try ip.coerceInMemoryAllowed(chosen, candidate_info.payload_type, false, target)) == .ok) {
                    seen_const = seen_const or candidate_info.payload_type.isConstPtr();
                    any_are_null = true;
                    continue;
                }

                seen_const = seen_const or is_chosen_const_ptr;
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
                .noreturn, .undefined_type => {
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                },
            }
                .NoReturn,
            .Undefined => {
                chosen = candidate;
                chosen_i = candidate_i + 1;
                continue;
            },
            .Null => {
                any_are_null = true;
                chosen = candidate;
                chosen_i = candidate_i + 1;
                continue;
            },
            .Optional => {
                if ((try ip.coerceInMemoryAllowed(chosen_key.optional_type.payload_type, candidate, false, target)) == .ok) {
                    continue;
                }
                if ((try ip.coerceInMemoryAllowed(candidate, chosen_key.optional_type.payload_type, false, target)) == .ok) {
                    any_are_null = true;
                    chosen = candidate;
                    chosen_i = candidate_i + 1;
                    continue;
                }
            },
            .ErrorUnion => {
                const payload_ty = chosen_key.error_union_type.payload_type;
                if ((try ip.coerceInMemoryAllowed(payload_ty, candidate, false, target)) == .ok) {
                    continue;
                }
            },
            else => {},
        }
    }
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

/// If pointers have the same representation in runtime memory, a bitcast AIR instruction
/// may be used for the coercion.
/// * `const` attribute can be gained
/// * `volatile` attribute can be gained
/// * `allowzero` attribute can be gained (whether from explicit attribute, C pointer, or optional pointer) but only if !dest_is_mut
/// * alignment can be decreased
/// * bit offset attributes must match exactly
/// * `*`/`[*]` must match exactly, but `[*c]` matches either one
/// * sentinel-terminated pointers can coerce into `[*]`
fn coerceInMemoryAllowed(
    ip: *InternPool,
    // gpa: Allocator,
    arena: Allocator,
    dest_ty: Index,
    src_ty: Index,
    dest_is_mut: bool,
    target: std.Target,
) !InMemoryCoercionResult {
    if (dest_ty == src_ty) return .ok;

    const dest_key = ip.indexToKey(dest_ty);
    const src_key = ip.indexToKey(src_ty);

    const dest_tag = dest_key.zigTypeTag();
    const src_tag = src_key.zigTypeTag();

    // integers with the same number of bits.
    if (dest_tag == .Int and src_tag == .Int) {
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
    }

    // floats with the same number of bits.
    if (dest_tag == .Float and src_tag == .Float and
        // this is an optimization because only a long double can have the same size as a other Float
        // SAFETY: every Float is a Simple
        dest_key.simple == .c_longdouble or src_tag.simple == .c_longdouble)
    {
        const dest_bits = dest_key.floatBits(target);
        const src_bits = src_key.floatBits(target);
        if (dest_bits == src_bits) return .ok;
    }

    // Pointers / Pointer-like Optionals
    const maybe_dest_ptr_ty = try ip.typePtrOrOptionalPtrTy(dest_ty);
    const maybe_src_ptr_ty = try ip.typePtrOrOptionalPtrTy(src_ty);
    if (maybe_dest_ptr_ty != Index.none and maybe_src_ptr_ty != Index.none) {
        return try ip.coerceInMemoryAllowedPtrs(dest_ty, src_ty, maybe_dest_ptr_ty, maybe_src_ptr_ty, dest_is_mut, target);
    }

    // Slices
    if (dest_key.isSlice() and src_key.isSlice()) {
        return try ip.coerceInMemoryAllowedPtrs(dest_ty, src_ty, dest_ty, src_ty, dest_is_mut, target);
    }

    // Functions
    if (dest_tag == .Fn and src_tag == .Fn) {
        return try ip.coerceInMemoryAllowedFns(dest_ty, src_ty, target);
    }

    // Error Unions
    if (dest_tag == .ErrorUnion and src_tag == .ErrorUnion) {
        const dest_payload = dest_key.error_union_type.payload_type;
        const src_payload = src_key.error_union_type.payload_type;
        const child = try ip.coerceInMemoryAllowed(dest_payload, src_payload, dest_is_mut, target);
        if (child != .ok) {
            return InMemoryCoercionResult{ .error_union_payload = .{
                .child = try child.dupe(arena),
                .actual = src_payload,
                .wanted = dest_payload,
            } };
        }
        return try ip.coerceInMemoryAllowed(dest_ty.errorUnionSet(), src_ty.errorUnionSet(), dest_is_mut, target);
    }

    // Error Sets
    if (dest_tag == .ErrorSet and src_tag == .ErrorSet) {
        return .ok; // TODO: implement coerceInMemoryAllowedErrorSets
        // return try ip.coerceInMemoryAllowedErrorSets(dest_ty, src_ty);
    }

    // Arrays
    if (dest_tag == .Array and src_tag == .Array) {
        const dest_info = dest_key.array_type.len;
        const src_info = src_key.array_type.len;
        if (dest_info.len != src_info.len) {
            return InMemoryCoercionResult{ .array_len = .{
                .actual = src_info.len,
                .wanted = dest_info.len,
            } };
        }

        const child = try ip.coerceInMemoryAllowed(dest_key.array_type.child, src_key.array_type.child, dest_is_mut, target);
        if (child != .ok) {
            return InMemoryCoercionResult{ .array_elem = .{
                .child = try child.dupe(arena),
                .actual = src_key.array_type.child,
                .wanted = dest_key.array_type.child,
            } };
        }

        const ok_sent = dest_key.array_type.sentinel == Index.none or
            (src_key.array_type.sentinel != Index.none and
            dest_key.array_type.sentinel == src_key.array_type.sentinel // is this enough for a value equality check?
        );
        if (!ok_sent) {
            return InMemoryCoercionResult{ .array_sentinel = .{
                .actual = src_info.sentinel,
                .wanted = dest_info.sentinel,
                .ty = dest_key.array_type.child,
            } };
        }
        return .ok;
    }

    // Vectors
    if (dest_tag == .Vector and src_tag == .Vector) {
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
        const child = try ip.coerceInMemoryAllowed(dest_elem_ty, src_elem_ty, dest_is_mut, target);
        if (child != .ok) {
            return InMemoryCoercionResult{ .vector_elem = .{
                .child = try child.dupe(arena),
                .actual = src_elem_ty,
                .wanted = dest_elem_ty,
            } };
        }

        return .ok;
    }

    // Optionals
    if (dest_tag == .Optional and src_tag == .Optional) {
        if (maybe_dest_ptr_ty != maybe_src_ptr_ty) {
            return InMemoryCoercionResult{ .optional_shape = .{
                .actual = src_ty,
                .wanted = dest_ty,
            } };
        }

        const dest_child_type = dest_key.optional_type.payload_type;
        const src_child_type = src_key.optional_type.payload_type;

        const child = try ip.coerceInMemoryAllowed(dest_child_type, src_child_type, dest_is_mut, target);
        if (child != .ok) {
            return InMemoryCoercionResult{ .optional_child = .{
                .child = try child.dupe(arena),
                .actual = src_child_type,
                .wanted = dest_child_type,
            } };
        }

        return .ok;
    }

    return InMemoryCoercionResult{ .no_match = .{
        .actual = dest_ty,
        .wanted = src_ty,
    } };
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
    arena: std.mem.Allocator,
    dest_ty: Index,
    src_ty: Index,
    target: std.Target,
) !InMemoryCoercionResult {
    const dest_info = dest_ty.fnInfo();
    const src_info = src_ty.fnInfo();

    if (dest_info.is_var_args != src_info.is_var_args) {
        return InMemoryCoercionResult{ .fn_var_args = dest_info.is_var_args };
    }

    if (dest_info.is_generic != src_info.is_generic) {
        return InMemoryCoercionResult{ .fn_generic = dest_info.is_generic };
    }

    if (dest_info.cc != src_info.cc) {
        return InMemoryCoercionResult{ .fn_cc = .{
            .actual = src_info.cc,
            .wanted = dest_info.cc,
        } };
    }

    if (!src_info.return_type.isNoReturn()) {
        const rt = try ip.coerceInMemoryAllowed(dest_info.return_type, src_info.return_type, false, target);
        if (rt != .ok) {
            return InMemoryCoercionResult{ .fn_return_type = .{
                .child = try rt.dupe(arena),
                .actual = src_info.return_type,
                .wanted = dest_info.return_type,
            } };
        }
    }

    if (dest_info.param_types.len != src_info.param_types.len) {
        return InMemoryCoercionResult{ .fn_param_count = .{
            .actual = src_info.param_types.len,
            .wanted = dest_info.param_types.len,
        } };
    }

    if (dest_info.noalias_bits != src_info.noalias_bits) {
        return InMemoryCoercionResult{ .fn_param_noalias = .{
            .actual = src_info.noalias_bits,
            .wanted = dest_info.noalias_bits,
        } };
    }

    for (dest_info.param_types) |dest_param_ty, i| {
        const src_param_ty = src_info.param_types[i];

        if (dest_info.comptime_params[i] != src_info.comptime_params[i]) {
            return InMemoryCoercionResult{ .fn_param_comptime = .{
                .index = i,
                .wanted = dest_info.comptime_params[i],
            } };
        }

        // Note: Cast direction is reversed here.
        const param = try ip.coerceInMemoryAllowed(src_param_ty, dest_param_ty, false, target);
        if (param != .ok) {
            return InMemoryCoercionResult{ .fn_param = .{
                .child = try param.dupe(arena),
                .actual = src_param_ty,
                .wanted = dest_param_ty,
                .index = i,
            } };
        }
    }

    return .ok;
}

/// For pointer-like optionals, it returns the pointer type. For pointers,
/// the type is returned unmodified.
/// This can return `error.AnalysisFail` because it sometimes requires resolving whether
/// a type has zero bits, which can cause a "foo depends on itself" compile error.
/// This logic must be kept in sync with `Type.isPtrLikeOptional`.
fn typePtrOrOptionalPtrTy(
    ty: Index,
    ip: InternPool,
) !Index {
    const key = ip.indexToKey(ty);
    switch (key) {
        .pointer_type => |pointer_info| switch (pointer_info.size) {
            .Slice => return Index.none,
            else => return ty,
        },

        .optional_type => |optional_info| {
            const child_type = optional_info.payload_type;
            const child_key = ip.indexToKey(child_type);

            if (child_key != .pointer_type) return Index.none;
            const child_ptr_key = child_key.pointer_type;

            switch (child_ptr_key) {
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

        else => return Index.none,
    }
}

// ---------------------------------------------
//                     TESTS
// ---------------------------------------------

fn testExpectFmtType(ip: *const InternPool, index: Index, expected: []const u8) !void {
    const gpa = std.testing.allocator;
    const actual = try std.fmt.allocPrint(gpa, "{}", .{index.fmtType(ip)});
    defer gpa.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

fn testExpectFmtValue(ip: *const InternPool, val: Index, ty: Index, expected: []const u8) !void {
    const gpa = std.testing.allocator;
    const actual = try std.fmt.allocPrint(gpa, "{}", .{val.fmtValue(ty, ip)});
    defer gpa.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
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

    var ptr: Pointer = .{
        .elem_type = undefined,
        .sentinel = Index.none,
        .alignment = 0, // TODO
        .size = std.builtin.Type.Pointer.Size.One,
        .is_const = false,
        .is_volatile = false,
        .is_allowzero = false,
        .address_space = std.builtin.AddressSpace.generic,
    };

    ptr.elem_type = i32_type_0;
    const i32_pointer_type_0 = try ip.get(gpa, .{ .pointer_type = ptr });
    ptr.elem_type = i32_type_0;
    const i32_pointer_type_1 = try ip.get(gpa, .{ .pointer_type = ptr });
    ptr.elem_type = i32_type_1;
    const i32_pointer_type_2 = try ip.get(gpa, .{ .pointer_type = ptr });
    ptr.elem_type = u32_type;
    const u32_pointer_type = try ip.get(gpa, .{ .pointer_type = ptr });

    try std.testing.expect(i32_pointer_type_0 == i32_pointer_type_1);
    try std.testing.expect(i32_pointer_type_1 == i32_pointer_type_2);
    try std.testing.expect(i32_pointer_type_0 != u32_pointer_type);

    ptr.is_const = true;
    const const_u32_pointer_type = try ip.get(gpa, .{ .pointer_type = ptr });

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

    const i32_optional_type_0 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_0 } });
    const i32_optional_type_1 = try ip.get(gpa, .{ .optional_type = .{ .payload_type = i32_type_1 } });
    const u32_optional_type = try ip.get(gpa, .{ .optional_type = .{ .payload_type = u32_type } });

    try std.testing.expect(i32_optional_type_0 == i32_optional_type_1);
    try std.testing.expect(i32_optional_type_0 != u32_optional_type);

    try testExpectFmtType(&ip, i32_optional_type_0, "?i32");
    try testExpectFmtType(&ip, u32_optional_type, "?u32");
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
        .sentinel = Index.none,
    } });
    const i32_3_array_type_1 = try ip.get(gpa, .{ .array_type = .{
        .len = 3,
        .child = i32_type_1,
        .sentinel = Index.none,
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
