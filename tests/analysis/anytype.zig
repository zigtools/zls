// zig fmt: off

fn anytype_0(foo: anytype, bar: @TypeOf(foo)) void {
// ^^^^^^^^^ (fn (anytype, anytype) void)()
    _ = bar;
}

fn anytype_1(foo: anytype) @TypeOf(foo) {
// ^^^^^^^^^ (fn (anytype) anytype)()
    return foo;
}

fn anytype_2(
// ^^^^^^^^^ (fn (anytype, i32, anytype) anytype)()
    foo: anytype,
    bar: i32,
    baz: @TypeOf(foo, bar),
) @TypeOf(baz) {
    return foo + bar + baz;
}

// TODO this should be `i32`
const anytype_2_result = anytype_2(1, 2, 3);
//    ^^^^^^^^^^^^^^^^ (comptime_int)()

// TODO this should be `fn (i32, anytype, anytype) anytype`
fn anytype_3(
// ^^^^^^^^^ (fn (i32, anytype, i32) i32)()
    foo: i32,
    bar: anytype,
    baz: @TypeOf(foo, bar),
) @TypeOf(baz) {
    return foo + bar + baz;
}

const anytype_3_result = anytype_3(1, 2, 3);
//    ^^^^^^^^^^^^^^^^ (i32)()

// zig fmt: on
