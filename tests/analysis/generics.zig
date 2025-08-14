fn Foo(T: type) type {
    return struct {
        fn bar(U: type, t: ?T, u: ?U) void {
            _ = .{ t, u };
        }

        fn baz(U: type, t: T, u: U) T {
            return t + u;
        }

        fn qux(U: type, t: T, u: U) @TypeOf(t, u) {
            return t + u;
        }
    };
}

const foo = Foo(u8){};
//    ^^^ (Foo(u8))()

// TODO this should be `fn (U: type, ?u8, ?U) void`
const bar_fn = Foo(u8).bar;
//    ^^^^^^ (fn (type, ?u8, ?U) void)()

const bar_call = Foo(u8).bar(i32, null, null);
//    ^^^^^^^^ (void)()

// TODO this should be `fn (U: type, i32, U) i32`
const baz_fn = Foo(i32).baz;
//    ^^^^^^ (fn (type, i32, U) i32)()

const baz_call = Foo(i32).baz(u8, -42, 42);
//    ^^^^^^^^ (i32)()

// TODO this should be `fn (U: type, u8, U) anytype`
const qux_fn = Foo(u8).qux;
//    ^^^^^^ (fn (type, u8, U) u8)()

// TODO this should be `i32`
const qux_call = Foo(u8).qux(i32, 42, -42);
//    ^^^^^^^^ (u8)()

fn fizz(T: type) ?fn () error{}!struct { ??T } {
    return null;
}

// TODO this should be `fn (T: type) ?fn () error{}!struct { ??T })()`
const fizz_fn = fizz;
//    ^^^^^^^ (fn (type) ?fn () error{}!struct { ??T })()

const fizz_call = fizz(u8);
//    ^^^^^^^^^ (?fn () error{}!struct { ??u8 })()

fn Point1(comptime T: type) type {
    return struct {
        x: T,
        y: T,
        fn normSquared(self: Point1(T)) T {
            _ = self;
            //  ^^^^ (Point1(T))()
        }
    };
}

fn parameter(comptime T: type, in: T) void {
    _ = in;
    //  ^^ (T)()
}

fn taggedUnion(comptime T: type, in: union(enum) { a: T, b: T }) void {
    switch (in) {
        .a => |a| {
            _ = a;
            //  ^ (T)()
        },
        .b => |b| {
            _ = b;
            //  ^ (T)()
        },
    }
}

fn Option(comptime T: type) type {
    return struct {
        item: ?T,
        const none: @This() = undefined;
        const alias = none;
        const default = init();
        fn init() @This() {}
    };
}

const option_none: Option(u8) = .none;
//                              ^^^^^ (Option(u8))()

const option_alias: Option(u8) = .alias;
//                               ^^^^^^ (Option(u8))()

const option_default: Option(u8) = .default;
//                                 ^^^^^^^^ (Option(u8))()

const option_init: Option(u8) = .init();
//                              ^^^^^ (fn () Option(u8))()

fn GenericUnion(T: type) type {
    return union {
        field: T,
        const decl: T = undefined;
    };
}

const generic_union_decl = GenericUnion(u8).decl;
//    ^^^^^^^^^^^^^^^^^^ (u8)()

const generic_union: GenericUnion(u8) = .{ .field = 1 };
//    ^^^^^^^^^^^^^ (GenericUnion(u8))()

const generic_union_field = generic_union.field;
//    ^^^^^^^^^^^^^^^^^^^ (u8)()

const generic_union_tag = GenericUnion(u8).field;
//    ^^^^^^^^^^^^^^^^^ (unknown)()

fn GenericTaggedUnion(T: type) type {
    return union(enum) {
        field: T,
        const decl: T = undefined;
    };
}

const generic_tagged_union_decl = GenericTaggedUnion(u8).decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

const generic_tagged_union: GenericTaggedUnion(u8) = .{ .field = 1 };
//    ^^^^^^^^^^^^^^^^^^^^ (GenericTaggedUnion(u8))()

const generic_tagged_union_field = generic_tagged_union.field;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

const generic_tagged_union_tag = GenericTaggedUnion(u8).field;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (@typeInfo(GenericTaggedUnion(u8)).@"union".tag_type.?)()

fn GenericEnum(T: type) type {
    return enum {
        field,
        const decl: T = undefined;
    };
}

const generic_enum_decl = GenericEnum(u8).decl;
//    ^^^^^^^^^^^^^^^^^ (u8)()

const generic_enum: GenericEnum(u8) = .field;
//    ^^^^^^^^^^^^ (GenericEnum(u8))()

const generic_enum_field = generic_enum.field;
//    ^^^^^^^^^^^^^^^^^^ (unknown)()

const generic_enum_tag = GenericEnum(u8).field;
//    ^^^^^^^^^^^^^^^^ (GenericEnum(u8))()

fn GenericStruct(T: type) type {
    return struct {
        field: T,
        const decl: T = undefined;
    };
}

const generic_struct_decl = GenericStruct(u8).decl;
//    ^^^^^^^^^^^^^^^^^^^ (u8)()

const generic_struct: GenericStruct(u8) = .{ .field = 1 };
//    ^^^^^^^^^^^^^^ (GenericStruct(u8))()

const generic_struct_field = generic_struct.field;
//    ^^^^^^^^^^^^^^^^^^^^ (u8)()

const generic_struct_tag = GenericStruct(u8).field;
//    ^^^^^^^^^^^^^^^^^^ (unknown)()

fn Map(Context: type) type {
    return struct {
        unmanaged: MapUnmanaged(Context),
        ctx: Context,
        const Self = @This();
        fn clone(self: Self) Self {
            const unmanaged = self.unmanaged.cloneContext(self.ctx);
            //    ^^^^^^^^^ (MapUnmanaged(Context))()
            return .{ .unmanaged = unmanaged, .ctx = self.ctx };
        }
        fn clone2(self: Self) Self {
            const unmanaged = self.unmanaged.cloneContext2(self.ctx);
            //    ^^^^^^^^^ (MapUnmanaged(*Context))()
            return .{ .unmanaged = unmanaged, .ctx = self.ctx };
        }
    };
}

fn MapUnmanaged(Context: type) type {
    return struct {
        size: u32,
        const Self = @This();
        fn clone(self: Self) Self {
            const cloned = self.cloneContext(@as(Context, undefined));
            //    ^^^^^^ (MapUnmanaged(Context))()
            return cloned;
        }
        fn cloneContext(self: Self, new_ctx: anytype) MapUnmanaged(@TypeOf(new_ctx)) {
            _ = self;
        }
        fn clone2(self: Self) Self {
            const cloned = self.cloneContext2(@as(Context, undefined));
            //    ^^^^^^ (MapUnmanaged(*Context))()
            return cloned;
        }
        fn cloneContext2(self: Self, new_ctx: anytype) MapUnmanaged(*@TypeOf(new_ctx)) {
            _ = self;
        }
    };
}

const some_list: std.ArrayList(u8) = .empty;
//    ^^^^^^^^^ (Aligned(u8))()

const some_list_items = some_list.items;
//    ^^^^^^^^^^^^^^^ ([]u8)()

const std = @import("std");

// TODO this should be `fn (T: type) T`
fn Identity(comptime T: type) T {}
// ^^^^^^^^ (fn (comptime type) T)()

const identity_of_i32 = Identity(i32);
//    ^^^^^^^^^^^^^^^ (i32)()

const identity_of_f64 = Identity(f64);
//    ^^^^^^^^^^^^^^^ (f64)()

const identity_of_unknown_type = Identity(@as(type, undefined));
//    ^^^^^^^^^^^^^^^^^^^^^^^^ ((unknown type))()

fn anytypeFn1(a: anytype) @TypeOf(a) {
    return a;
}
const anytype_1_int = anytypeFn1(42);
//    ^^^^^^^^^^^^^ (comptime_int)()
const anytype_1_bool = anytypeFn1(true);
//    ^^^^^^^^^^^^^^ (bool)()

fn anytypeFn2(a: anytype, b: anytype) @TypeOf(a, b) {
    return a + b;
}
const anytype_2_u8_u16 = anytypeFn2(@as(u8, 42), @as(u16, 42));
//    ^^^^^^^^^^^^^^^^ (u8)() TODO this should be `u16`
const anytype_2_i8_i16 = anytypeFn2(@as(i8, 42), @as(i16, 42));
//    ^^^^^^^^^^^^^^^^ (i8)() TODO this should be `i16`

comptime {
    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(anytype_2_i8_i16);
}
