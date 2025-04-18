fn orelse_0() void {
    const foo: ?i32 = 5;
    const bar = foo orelse 0;
    //    ^^^ (i32)()
    _ = bar;
}

fn orelse_1() void {
    const foo: ?i32 = 5;
    const bar = foo orelse foo;
    //    ^^^ (?i32)()
    _ = bar;
}

fn orelse_2() void {
    const foo: ?i32 = 5;
    const bar = foo orelse unreachable;
    //    ^^^ (i32)()
    _ = bar;
}

fn orelse_3(a: ?i32) void {
    const bar = a orelse return;
    //    ^^^ (i32)()
    _ = bar;
}

fn orelse_4() void {
    const array: [1]?i32 = [1]?i32{4};
    for (array) |elem| {
        const bar = elem orelse continue;
        //    ^^^ (i32)()
        _ = bar;
    }
}

fn orelse_5() void {
    var value: u32 = 123;
    const ptr: [*c]u32 = &value;
    const foo = ptr orelse unreachable;
    //    ^^^ ([*c]u32)()
    _ = foo;
}

fn orelse_6() void {
    const S = struct {
        alpha: u32,
    };
    const v: ?*const S = &S{ .alpha = 5 };
    const foo = v orelse {
        return;
    };
    _ = foo;
    //  ^^^ (*const S)()
}
