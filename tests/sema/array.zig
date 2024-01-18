const ArrayType = [3]u32;
//    ^^^^^^^^^ (type)([3]u32)
const ArrayTypeWithSentinel = [3:0]u32;
//    ^^^^^^^^^^^^^^^^^^^^^ (type)([3:0]u32)

const empty_array: [0]u8 = undefined;
//    ^^^^^^^^^^^ ([0]u8)()

const zero = @as([0]u8, undefined).len;
//    ^^^^ (usize)(0)
const five = @as([7]u8, undefined).len;
//    ^^^^ (usize)(7)
