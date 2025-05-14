const empty_block = {};
//    ^^^^^^^^^^^ (void)()

// zig fmt: off
const void_block = { _ = 1; };
//    ^^^^^^^^^^ (void)()

const compile_error_block = { @compileError("foo"); };
//    ^^^^^^^^^^^^^^^^^^^ (noreturn)()

const panic_block = { @panic("foo"); };
//    ^^^^^^^^^^^ (noreturn)()

const labeled_block_0 = blk: { break :blk @as(i32, 1); };
//    ^^^^^^^^^^^^^^^ (i32)()

// TODO this should be `i64`
const labeled_block_1 = blk: {
//    ^^^^^^^^^^^^^^^ (i32)()
    if (false) break :blk @as(i32, 1);
    break :blk @as(i64, 2);
};
// zig fmt: on

pub fn main() void {
    const return_block = {
        return;
    };
    _ = return_block;
    //  ^^^^^^^^^^^^ (noreturn)()

    for (0..1) |_| {
        const break_block = {
            break;
        };
        _ = break_block;
        //  ^^^^^^^^^^^ (noreturn)()

        const continue_block = {
            continue;
        };
        _ = continue_block;
        //  ^^^^^^^^^^^^^^ (noreturn)()
    }
}
