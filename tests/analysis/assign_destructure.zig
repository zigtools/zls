fn assign_destructure_0() void {
    const foo, const bar, const baz = .{ @as(u8, 1), @as(u16, 2), @as(u24, 3) };
    //    ^^^ (u8)()
    //               ^^^ (u16)()
    //                          ^^^ (u24)()
    _ = foo;
    _ = bar;
    _ = baz;
}

fn assign_destructure_1() void {
    const foo, const bar: u32 = .{ 1, 2 };
    //    ^^^ (comptime_int)()
    //               ^^^ (u32)()
    _ = foo;
    _ = bar;
}

fn assign_destructure_2() void {
    const S = struct {
        fn thing() !struct { usize, isize } {}
    };
    const foo, const bar = try S.thing();
    //    ^^^ (usize)()
    //               ^^^ (isize)()
    _ = foo;
    _ = bar;
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
