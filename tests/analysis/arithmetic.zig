pub fn main() void {
    var some_u4: u4 = 4;
    var some_u8: u8 = 8;
    var some_u16: u16 = 16;
    var some_i16: i16 = -16;

    const add_u8_i16 = some_u8 + some_i16;
    //    ^^^^^^^^^^ (i16)()

    const add_wrap_u8_i16 = some_u8 +% some_i16;
    //    ^^^^^^^^^^^^^^^ (i16)()

    const add_sat_u8_i16 = some_u8 +| some_i16;
    //    ^^^^^^^^^^^^^^ (i16)()

    const sub_u8_i16 = some_u8 - some_i16;
    //    ^^^^^^^^^^ (i16)()

    const sub_wrap_u8_i16 = some_u8 -% some_i16;
    //    ^^^^^^^^^^^^^^^ (i16)()

    const sub_sat_u8_i16 = some_u8 -| some_i16;
    //    ^^^^^^^^^^^^^^ (i16)()

    const negation_i16 = -some_i16;
    //    ^^^^^^^^^^^^ (i16)()

    const negation_wrap_i16 = -%some_i16;
    //    ^^^^^^^^^^^^^^^^^ (i16)()

    const mul_u8_i16 = some_u8 * some_i16;
    //    ^^^^^^^^^^ (i16)()

    const mul_wrap_u8_i16 = some_u8 *% some_i16;
    //    ^^^^^^^^^^^^^^^ (i16)()

    const mul_sat_u8_i16 = some_u8 *| some_i16;
    //    ^^^^^^^^^^^^^^ (i16)()

    const div_u8_u16 = some_u8 / some_u16;
    //    ^^^^^^^^^^ (u16)()

    const mod_u8_u16 = some_u8 % some_u16;
    //    ^^^^^^^^^^ (u16)()

    // TODO this should be `i16`
    const shl_i16_u4 = some_i16 << some_u4;
    //    ^^^^^^^^^^ (unknown)()

    // TODO this should be `i16`
    const shl_sat_i16_u16 = some_i16 <<| some_u16;
    //    ^^^^^^^^^^^^^^^ (unknown)()

    // TODO this should be `i16`
    const shr_i16_u4 = some_i16 >> some_u4;
    //    ^^^^^^^^^^ (unknown)()

    const bit_and_u8_i16 = some_u8 & some_i16;
    //    ^^^^^^^^^^^^^^ (i16)()

    const bit_or_u8_i16 = some_u8 | some_i16;
    //    ^^^^^^^^^^^^^ (i16)()

    const bit_xor_u8_i16 = some_u8 ^ some_i16;
    //    ^^^^^^^^^^^^^^ (i16)()

    const bit_not_u8 = ~some_u8;
    //    ^^^^^^^^^^ (u8)()

    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(shl_sat_i16_u16);

    _ = .{
        .{ &some_u4, &some_u8, &some_u16, &some_i16 },
        .{ add_u8_i16, add_wrap_u8_i16, add_sat_u8_i16 },
        .{ sub_u8_i16, sub_wrap_u8_i16, sub_sat_u8_i16 },
        .{ negation_i16, negation_wrap_i16 },
        .{ mul_u8_i16, mul_wrap_u8_i16, mul_sat_u8_i16 },
        .{ div_u8_u16, mod_u8_u16 },
        .{ shl_i16_u4, shl_sat_i16_u16, shr_i16_u4 },
        .{ bit_and_u8_i16, bit_or_u8_i16, bit_xor_u8_i16, bit_not_u8 },
    };
}

fn invalid() void {
    var some_u8: u8 = 8;
    var some_i16: i16 = -16;

    // TODO this should be `unknown`
    const div_u8_i16 = some_u8 / some_i16;
    //    ^^^^^^^^^^ (i16)()

    // TODO this should be `unknown`
    const mod_u8_i16 = some_u8 % some_i16;
    //    ^^^^^^^^^^ (i16)()

    const shl_i16_u8 = some_i16 << some_u8;
    //    ^^^^^^^^^^ (unknown)()

    const shr_i16_u8 = some_i16 >> some_u8;
    //    ^^^^^^^^^^ (unknown)()

    _ = .{
        .{ &some_u8, &some_i16 },
        .{ div_u8_i16, mod_u8_i16 },
        .{ shl_i16_u8, shr_i16_u8 },
    };
}
