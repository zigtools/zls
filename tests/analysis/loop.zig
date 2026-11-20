fn forElseReturn(items: []const u32) void {
    const result = for (items) |item| {
        if (item == 4) break item;
    } else {
        return;
    };
    _ = result;
    //  ^^^^^^ (u32)()
}

fn forElseLiteral(items: []const u32) void {
    const result = for (items) |item| {
        if (item != 0) break item;
    } else 0;
    _ = result;
    //  ^^^^^^ (u32)()
}

fn forElseWidening(items: []const u64) void {
    const result = for (items) |item| {
        if (item != 0) break item;
    } else @as(u32, 0);
    _ = result;
    //  ^^^^^^ (u64)()
}

fn forStructFieldBreak() void {
    const S = struct { x: u32 };
    const ses: []const S = &.{ .{ .x = 1 }, .{ .x = 2 }, .{ .x = 4 } };
    const result = for (ses) |s| {
        if (s.x == 4) break s.x;
    } else {
        return;
    };
    _ = result;
    //  ^^^^^^ (u32)()
}

fn unlabeledBreakBindsToInnerLoop(condition: bool) void {
    const result = outer: while (condition) {
        var i: u32 = 0;
        _ = while (i < 10) : (i += 1) {
            if (condition) break :outer @as(u32, 1);
            if (i == 9) break @as(u64, 2);
        } else 0;
    } else 0;
    _ = result;
    //  ^^^^^^ (u32)()
}

fn forUnlabeledBreakInLabeledLoop(items: []const u16) void {
    const result = outer: for (items) |item| {
        if (item == 0) break :outer item;
        if (item == 1) break @as(u32, 1);
    } else 0;
    _ = result;
    //  ^^^^^^ (u32)()
}

fn forIfElseBothBreak(items: []const u16) void {
    const result = for (items) |item| {
        if (item == 0) {
            break item;
        } else {
            break @as(u32, 1);
        }
    } else 0;
    _ = result;
    //  ^^^^^^ (u32)()
}

fn forEitherFallback(items: []const u8) void {
    const result = for (items) |item| {
        if (item == 0) {
            break @as(u32, 1);
        } else {
            break true;
        }
    } else unreachable;
    _ = result;
    //  ^^^^^^ (either type)()
}

fn whileNoElse() void {
    const result = while (true) {
        break @as(u32, 42);
    };
    _ = result;
    //  ^^^^^^ (u32)(unknown)
}

fn whileCanComplete(condition: bool) void {
    const result = while (condition) {
        break error.Fail;
    };
    _ = result;
    //  ^^^^^^ (error{Fail}!void)()
}

fn whileCannotComplete() void {
    const result = while (true) {
        break error.Fail;
    };
    _ = result;
    //  ^^^^^^ (error{Fail})()
}

fn forCanComplete(items: []const u8) void {
    const result = for (items) |item| {
        _ = item;
        break error.Fail;
    };
    _ = result;
    //  ^^^^^^ (error{Fail}!void)()
}

fn whileCompletionOnly(condition: bool) void {
    const result = while (condition) {};
    _ = result;
    //  ^^^^^^ (void)()
}
