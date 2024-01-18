const fn_type0 = fn () void;
//    ^^^^^^^^ (type)(fn() void)

const fn_type1 = fn () u32;
//    ^^^^^^^^ (type)(fn() u32)

const fn_type2 = fn (u32) u32;
//    ^^^^^^^^ (type)(fn(u32) u32)

const fn_type3 = fn (a: u32, b: []const u8) ?bool;
//    ^^^^^^^^ (type)(fn(u32, []const u8) ?bool)

// zig fmt: off
fn foo() void {
// ^^^ (type)(fn() void)
// zig fmt: on
    var some_variable = 3;
    // TODO //  ^^^^^^^^^^^^^ (comptime_int)(3)
    _ = &some_variable;
}

fn bar() void {
    const DeclInFunction = struct {
        const Inner = u32;
        //    ^^^^^ (type)(u32)
    };
    _ = DeclInFunction;
}

// zig fmt: off
fn baz() !void {
// ^^^ (type)(fn() !void)
}
// zig fmt: on
