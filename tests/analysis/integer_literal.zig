const comptime_integer = 42;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(42)

const comptime_plus = 2 + 3;
//    ^^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `5`

const comptime_sub = 2 - 3;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `-1`

const comptime_mul = 2 * 3;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `6`

const comptime_div = 2 / 3;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `0`

const comptime_and = 2 & 3;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `2`

const comptime_shl = 2 << 3;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `16`

const one_plus_one = 1 + 1;
//    ^^^^^^^^^^^^ (comptime_int)((unknown value)) TODO this should be `2`

const const_u8: u8 = 42;
//    ^^^^^^^^ (u8)((unknown value)) TODO this should be `42`

var var_u8: u8 = 42;
//  ^^^^^^ (u8)((unknown value))

const as_u8 = @as(u8, 42);
//    ^^^^^ (u8)((unknown value)) TODO this should be `42`

const as_u8_too_big = @as(u8, 256);
//    ^^^^^^^^^^^^^ (u8)((unknown value))

const as_u8_negative = @as(u8, -1);
//    ^^^^^^^^^^^^^^ (u8)((unknown value))

var var_as_u8 = @as(u8, 42);
//  ^^^^^^^^^ (u8)((unknown value))

const comptime_plus_u8 = 2 + @as(u8, 3);
//    ^^^^^^^^^^^^^^^^ (u8)((unknown value)) TODO this should be `5`

const u8_plus_comptime = @as(u8, 2) + 3;
//    ^^^^^^^^^^^^^^^^ (u8)((unknown value)) TODO this should be `5`

comptime {
    @compileLog(comptime_div);
}
