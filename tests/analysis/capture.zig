//
// if
//

fn if_capture_0() void {
    const foo: ?i32 = undefined;
    if (foo) |bar| {
        //    ^^^ (i32)()
        _ = bar;
        //  ^^^ (i32)()
    }
}

fn if_capture_1() void {
    const foo: ?i32 = undefined;
    if (foo) |bar| {
        //    ^^^ (i32)()
        _ = bar;
        //  ^^^ (i32)()
    } else {}
}

fn if_capture_2() void {
    const foo: error{A}!i32 = undefined;
    if (foo) |fizz| {
        //    ^^^^ (i32)()
        _ = fizz;
        //  ^^^^ (i32)()
    } else |buzz| {
        //  ^^^^ (error{A})()
        _ = buzz;
        //  ^^^^ (error{A})()
    }
}

//
// while
//

fn while_capture_0() void {
    const foo: ?i32 = undefined;
    while (foo) |bar| {
        //       ^^^ (i32)()
        _ = bar;
        //  ^^^ (i32)()
    }
}

fn while_capture_1() void {
    const foo: ?i32 = undefined;
    while (foo) |bar| {
        //       ^^^ (i32)()
        _ = bar;
        //  ^^^ (i32)()
    } else {}
}

fn while_capture_2() void {
    const foo: error{A}!i32 = undefined;
    while (foo) |fizz| {
        //       ^^^^ (i32)()
        _ = fizz;
        //  ^^^^ (i32)()
    } else |buzz| {
        //  ^^^^ (error{A})()
        _ = buzz;
        //  ^^^^ (error{A})()
    }
}

//
// catch
//

fn catch_capture() void {
    const foo: error{A}!i32 = undefined;
    const bar = foo catch |baz| {
        //                 ^^^ (error{A})()
        _ = baz;
        //  ^^^ (error{A})()
    };
    _ = bar;
    //  ^^^ (i32)()
}

//
// for
//

fn for_capture_0() void {
    const foo: []i32 = undefined;
    for (foo) |bar| {
        //     ^^^ (i32)()
        _ = bar;
        //  ^^^ (i32)()
    }
}

fn for_capture_1() void {
    const foo: []i32 = undefined;
    for (foo, 0..) |bar, index| {
        //          ^^^ (i32)()
        //               ^^^^^ (usize)()
        _ = bar;
        //  ^^^ (i32)()
        _ = index;
        //  ^^^^^ (usize)()
    }
}

//
// switch
//

fn switch_capture_0() void {
    const U = union(enum) { a: i32 };
    const foo: U = undefined;
    switch (foo) {
        .a => |bar| {
            // ^^^ (i32)()
            _ = bar;
            //  ^^^ (i32)()
        },
    }
}

fn switch_capture_1() void {
    const E = enum { foo };
    const e: E = undefined;
    switch (e) {
        .foo => |bar| {
            //   ^^^ (E)()
            _ = bar;
            //  ^^^ (E)()
        },
    }
}

//
// errdefer
//

fn func() error{A}!void {
    errdefer |foo| {
        //    ^^^ (unknown)()
        _ = foo;
        //  ^^^ (unknown)()
    }
}
