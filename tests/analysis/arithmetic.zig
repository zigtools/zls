const add_u8_i16 = runtime_u8 + runtime_i16;
//    ^^^^^^^^^^ (i16)()

const add_wrap_u8_i16 = runtime_u8 +% runtime_i16;
//    ^^^^^^^^^^^^^^^ (i16)()

const add_sat_u8_i16 = runtime_u8 +| runtime_i16;
//    ^^^^^^^^^^^^^^ (i16)()

const sub_u8_i16 = runtime_u8 - runtime_i16;
//    ^^^^^^^^^^ (i16)()

const sub_wrap_u8_i16 = runtime_u8 -% runtime_i16;
//    ^^^^^^^^^^^^^^^ (i16)()

const sub_sat_u8_i16 = runtime_u8 -| runtime_i16;
//    ^^^^^^^^^^^^^^ (i16)()

const negation_i16 = -runtime_i16;
//    ^^^^^^^^^^^^ (i16)()

const negation_wrap_i16 = -%runtime_i16;
//    ^^^^^^^^^^^^^^^^^ (i16)()

const mul_u8_i16 = runtime_u8 * runtime_i16;
//    ^^^^^^^^^^ (i16)()

const mul_wrap_u8_i16 = runtime_u8 *% runtime_i16;
//    ^^^^^^^^^^^^^^^ (i16)()

const mul_sat_u8_i16 = runtime_u8 *| runtime_i16;
//    ^^^^^^^^^^^^^^ (i16)()

const div_u8_u16 = runtime_u8 / runtime_u16;
//    ^^^^^^^^^^ (u16)()

// TODO this should be `unknown`
const div_u8_i16 = runtime_u8 / runtime_i16;
//    ^^^^^^^^^^ (i16)()

const mod_u8_u16 = runtime_u8 % runtime_u16;
//    ^^^^^^^^^^ (u16)()

// TODO this should be `unknown`
const mod_u8_i16 = runtime_u8 % runtime_i16;
//    ^^^^^^^^^^ (i16)()

const shl_i16_u4 = runtime_i16 << runtime_u4;
//    ^^^^^^^^^^ (i16)()

// TODO this should be `unknown`
const shl_i16_u8 = runtime_i16 << runtime_u8;
//    ^^^^^^^^^^ (i16)()

const shl_sat_i16_u16 = runtime_i16 <<| runtime_u16;
//    ^^^^^^^^^^^^^^^ (i16)()

const shr_i16_u4 = runtime_i16 >> runtime_u4;
//    ^^^^^^^^^^ (i16)()

// TODO this should be `unknown`
const shr_i16_u8 = runtime_i16 >> runtime_u8;
//    ^^^^^^^^^^ (i16)()

const bit_and_u8_i16 = runtime_u8 & runtime_i16;
//    ^^^^^^^^^^^^^^ (i16)()

const bit_or_u8_i16 = runtime_u8 | runtime_i16;
//    ^^^^^^^^^^^^^ (i16)()

const bit_xor_u8_i16 = runtime_u8 ^ runtime_i16;
//    ^^^^^^^^^^^^^^ (i16)()

const bit_not_u8 = ~runtime_u8;
//    ^^^^^^^^^^ (u8)()

var runtime_u4: u4 = 4;
var runtime_u8: u8 = 8;
var runtime_u16: u16 = 16;
var runtime_i16: i16 = -16;
