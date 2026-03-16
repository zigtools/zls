const comptime_integer = 42;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(42)

const comptime_add = 2 + 3;
//    ^^^^^^^^^^^^ (comptime_int)(5)

const comptime_add_sat = 2 +| 3;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(5)

const comptime_add_wrap = 2 +% 3;
//    ^^^^^^^^^^^^^^^^^ (comptime_int)(5)

const comptime_sub = 2 - 3;
//    ^^^^^^^^^^^^ (comptime_int)(-1)

const comptime_sub_sat = 2 -| 3;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(-1)

const comptime_sub_wrap = 2 -% 3;
//    ^^^^^^^^^^^^^^^^^ (comptime_int)(-1)

const comptime_mul = 2 * 3;
//    ^^^^^^^^^^^^ (comptime_int)(6)

const comptime_mul_sat = 2 *| 3;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(6)

const comptime_mul_wrap = 2 *% 3;
//    ^^^^^^^^^^^^^^^^^ (comptime_int)(6)

const comptime_div = 2 / 3;
//    ^^^^^^^^^^^^ (comptime_int)(0)

const comptime_mod = 2 % 3;
//    ^^^^^^^^^^^^ (comptime_int)(2)

const comptime_and = 2 & 3;
//    ^^^^^^^^^^^^ (comptime_int)(2)

const comptime_or = 2 | 3;
//    ^^^^^^^^^^^ (comptime_int)(3)

const comptime_xor = 2 ^ 3;
//    ^^^^^^^^^^^^ (comptime_int)(1)

const comptime_shl = 2 << 3;
//    ^^^^^^^^^^^^ (comptime_int)(16)

const comptime_shl_sat = 2 <<| 3;
//    ^^^^^^^^^^^^^^^^ (comptime_int)(16)

const comptime_shr = 2 >> 3;
//    ^^^^^^^^^^^^ (comptime_int)(0)

const one_plus_one = 1 + 1;
//    ^^^^^^^^^^^^ (comptime_int)(2)

const negation_one = -1;
//    ^^^^^^^^^^^^ (comptime_int)(-1)

const negation_wrap_one = -%1;
//    ^^^^^^^^^^^^^^^^^ (comptime_int)(-1)

const bit_not_one = ~1;
//    ^^^^^^^^^^^ (comptime_int)((unknown value))

const negative_three_div_two = -3 / 2;
//    ^^^^^^^^^^^^^^^^^^^^^^ (comptime_int)(-1)

const three_div_negative_two = 3 / -2;
//    ^^^^^^^^^^^^^^^^^^^^^^ (comptime_int)(-1)

const const_u8: u8 = 42;
//    ^^^^^^^^ (u8)(42)

var var_u8: u8 = 42;
//  ^^^^^^ (u8)((unknown value))

const as_u8 = @as(u8, 42);
//    ^^^^^ (u8)(42)

const as_u8_too_big = @as(u8, 256);
//    ^^^^^^^^^^^^^ (u8)((unknown value))

const as_u8_negative = @as(u8, -1);
//    ^^^^^^^^^^^^^^ (u8)((unknown value))

var var_as_u8 = @as(u8, 42);
//  ^^^^^^^^^ (u8)((unknown value))

const comptime_plus_u8 = 2 + @as(u8, 3);
//    ^^^^^^^^^^^^^^^^ (u8)(5)

const u8_plus_comptime = @as(u8, 2) + 3;
//    ^^^^^^^^^^^^^^^^ (u8)(5)

const u4_add = @as(u4, 2) + 3;
//    ^^^^^^ (u4)(5)

const u4_add_sat = @as(u4, 2) +| 15;
//    ^^^^^^^^^^ (u4)(15)

const u4_add_wrap = @as(u4, 2) +% 15;
//    ^^^^^^^^^^^ (u4)(1)

const u4_sub = @as(u4, 2) - 3;
//    ^^^^^^ (u4)((unknown value))

const u4_sub_sat = @as(u4, 2) -| 3;
//    ^^^^^^^^^^ (u4)(0)

const u4_sub_wrap = @as(u4, 2) -% 3;
//    ^^^^^^^^^^^ (u4)(15)

const u4_mul = @as(u4, 2) * 3;
//    ^^^^^^ (u4)(6)

const u4_mul_sat = @as(u4, 2) *| 8;
//    ^^^^^^^^^^ (u4)(15)

const u4_mul_wrap = @as(u4, 2) *% 8;
//    ^^^^^^^^^^^ (u4)(0)

const u4_div = @as(u4, 2) / 3;
//    ^^^^^^ (u4)(0)

const u4_mod = @as(u4, 2) % 3;
//    ^^^^^^ (u4)(2)

const u4_and = @as(u4, 2) & 3;
//    ^^^^^^ (u4)(2)

const u4_or = @as(u4, 2) | 3;
//    ^^^^^ (u4)(3)

const u4_xor = @as(u4, 2) ^ 3;
//    ^^^^^^ (u4)(1)

const u4_shl = @as(u4, 2) << 2;
//    ^^^^^^ (u4)(8)

const u4_shl_sat = @as(u4, 2) <<| 3;
//    ^^^^^^^^^^ (u4)(15)

const u4_shr = @as(u4, 2) >> 3;
//    ^^^^^^ (u4)(0)

const u4_bit_not = ~@as(u4, 2);
//    ^^^^^^^^^^ (u4)(13)

const u4_negation = -@as(u4, 2);
//    ^^^^^^^^^^^ (u4)((unknown value))

const u4_negation_wrap = -%@as(u4, 2);
//    ^^^^^^^^^^^^^^^^ (u4)((unknown value)) TODO this should be `14`

const i4_bit_not = ~@as(i4, 2);
//    ^^^^^^^^^^ (i4)(-3)

const i4_negation = -@as(i4, 2);
//    ^^^^^^^^^^^ (i4)(-2)

const i4_negation_wrap = -%@as(i4, 2);
//    ^^^^^^^^^^^^^^^^ (i4)((unknown value)) TODO this should be `-2`

const i4_negation_wrap_min = -%@as(i4, -8);
//    ^^^^^^^^^^^^^^^^^^^^ (i4)((unknown value)) TODO this should be `-8`

comptime {
    @compileLog(comptime_div);
}
