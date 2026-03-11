fn assign_destructure_0() void {
    const foo, const bar, const baz = .{ @as(u8, 1), @as(u16, 2), @as(u24, 3) };
    //    ^^^ (u8)()
    //               ^^^ (u16)()
    //                          ^^^ (u24)()
    _ = .{ foo, bar, baz };
}

fn assign_destructure_1() void {
    const foo, const bar: u32 = .{ 1, 2 };
    //    ^^^ (comptime_int)()
    //               ^^^ (u32)()
    _ = .{ foo, bar };
}

fn assign_destructure_2() void {
    const S = struct {
        fn thing() !struct { usize, isize } {}
    };
    const foo, const bar = try S.thing();
    //    ^^^ (usize)()
    //               ^^^ (isize)()
    _ = .{ foo, bar };
}

fn assign_destructure_3() void {
    // zig fmt: off
       var foo: u32 = undefined;
       var bar: u64 = undefined;
       foo, bar = .{ 3, 4 };
    // ^^^ (u32)()
    //      ^^^ (u64)()
    // zig fmt: on
}

fn assign_destructure_int_vector() void {
    const vector: @Vector(3, i32) = .{ 1, 2, 3 };
    const foo, const bar, const baz = vector;
    //    ^^^ (i32)()
    //               ^^^ (i32)()
    //                          ^^^ (i32)()
    _ = .{ foo, bar, baz };
}

fn assign_destructure_int_array() void {
    const array = [3]i32{ 1, 2, 3 };
    const foo, const bar, const baz = array;
    //    ^^^ (i32)()
    //               ^^^ (i32)()
    //                          ^^^ (i32)()
    _ = .{ foo, bar, baz };
}

fn assign_destructure_struct_array() void {
    const S = struct { x: i32 = 0 };
    const array = [3]S{ .{}, .{}, .{} };
    const foo, const bar, const baz = array;
    //    ^^^ (S)()
    //               ^^^ (S)()
    //                          ^^^ (S)()
    _ = .{ foo, bar, baz };
}
