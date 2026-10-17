const S = struct {
    x: u32,
};

const ses: []const S = &.{ .{ .x = 1 }, .{ .x = 2 } };

// A `for` expression whose `else` clause is `noreturn` gets its type from a
// `break <value>` inside the loop body, not from the `else` clause.
// https://github.com/zigtools/zls/issues/3272
fn loop_noreturn_else() !void {
    const x = for (ses) |s| {
        //^ (u32)()
        if (s.x == 2) break s.x;
    } else {
        return;
    };
    _ = x;
}

fn loop_noreturn_else_with_value() u32 {
    const result = for (ses) |s| {
        //^^^^^^ (u32)()
        break s.x;
    } else {
        return 0;
    };
    return result;
}
