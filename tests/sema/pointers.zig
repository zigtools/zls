const ptr_to_u32 = *u32;
//    ^^^^^^^^^^ (type)(*u32)
const slice_of_u32 = []u32;
//    ^^^^^^^^^^^^ (type)([]u32)
const ptr_with_alignment = [*:3]align(4:2:1) u32;
//    ^^^^^^^^^^^^^^^^^^ (type)([*:3]align(4:2:1) u32)
// TODO addresspace

const string: [:0]const u8 = "hello world";
//    ^^^^^^ ([:0]const u8)()
const string_len = string.len;
//    ^^^^^^^^^^ (usize)()
const string_ptr = string.ptr;
//    ^^^^^^^^^^ ([*:0]const u8)()
const string_elem = string[0];
//    ^^^^^^^^^^^ (u8)()
// const string_subslice = string[0..];
// //    ^^^^^^^^^^^^^^^ (u8)()

const ptr_to_int = &2;
//    ^^^^^^^^^^ (*comptime_int)()
const int = ptr_to_int.*;
//    ^^^ (comptime_int)()
