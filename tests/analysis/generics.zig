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

// TODO this should be `fn (type, ?u8, anytype) void`
const bar_fn = Foo(u8).bar;
//    ^^^^^^ (fn (type, ?u8, ?U) void)()

const bar_call = Foo(u8).bar(i32, null, null);
//    ^^^^^^^^ (void)()

// TODO this should be `fn (type, i32, anytype) i32`
const baz_fn = Foo(i32).baz;
//    ^^^^^^ (fn (type, i32, U) i32)()

const baz_call = Foo(i32).baz(u8, -42, 42);
//    ^^^^^^^^ (i32)()

// TODO this should be `fn (type, u8, anytype) anytype`
const qux_fn = Foo(u8).qux;
//    ^^^^^^ (fn (type, u8, U) u8)()

// TODO this should be `i32`
const qux_call = Foo(u8).qux(i32, 42, -42);
//    ^^^^^^^^ (u8)()

fn fizz(T: type) ?fn () error{}!struct { ??T } {
    return null;
}

// TODO this should be `fn (type) anytype`
const fizz_fn = fizz;
//    ^^^^^^^ (fn (type) ?fn () error{}!struct { ??T })()

const fizz_call = fizz(u8);
//    ^^^^^^^^^ (?fn () error{}!struct { ??u8 })()

comptime {
    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(foo);
}
