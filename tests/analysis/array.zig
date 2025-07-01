const ArrayType = [3]u8;
//    ^^^^^^^^^ (type)([3]u8)
const ArrayTypeWithSentinel = [3:0]u8;
//    ^^^^^^^^^^^^^^^^^^^^^ (type)([3:0]u8)

const InvalidArrayTypeAccess0 = ArrayType[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()
const InvalidArrayTypeAccess1 = ArrayType[1];
//    ^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const empty_array: [0]u8 = undefined;
//    ^^^^^^^^^^^ ([0]u8)()
const empty_array_len = empty_array.len;
//    ^^^^^^^^^^^^^^^ (usize)()

const length = 3;
const unknown_length: usize = undefined;
var runtime_index: usize = 5;

const some_array: [length]u8 = undefined;
//    ^^^^^^^^^^ ([3]u8)()

const some_array_pointer = &[3]u8{ 1, 2, 3 };
//    ^^^^^^^^^^^^^^^^^^ (*const [3]u8)()

const some_unsized_array: [unknown_length]u8 = undefined;
//    ^^^^^^^^^^^^^^^^^^ ([?]u8)()

const some_array_len = some_array.len;
//    ^^^^^^^^^^^^^^ (usize)(3)

const some_unsized_array_len = some_unsized_array.len;
//    ^^^^^^^^^^^^^^^^^^^^^^ (usize)()

const array_indexing = some_array[0];
//    ^^^^^^^^^^^^^^ (u8)()

const array_indexing_pointer = &some_array[0];
//    ^^^^^^^^^^^^^^^^^^^^^^ (*const u8)()

const array_slice_open_1 = some_array[1..];
//    ^^^^^^^^^^^^^^^^^^ (*const [2]u8)()

const array_slice_open_3 = some_array[3..];
//    ^^^^^^^^^^^^^^^^^^ (*const [0]u8)()

const array_slice_open_4 = some_array[4..];
//    ^^^^^^^^^^^^^^^^^^ (*const [?]u8)()

const array_slice_open_runtime = some_array[runtime_index..];
//    ^^^^^^^^^^^^^^^^^^^^^^^^ ([]const u8)()

const array_slice_0_2 = some_array[0..2];
//    ^^^^^^^^^^^^^^^ (*const [2]u8)()

const array_slice_0_2_sentinel = some_array[0..2 :0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (*const [2:0]u8)()

const array_slice_0_5 = some_array[0..5];
//    ^^^^^^^^^^^^^^^ (*const [?]u8)()

const array_slice_3_2 = some_array[3..2];
//    ^^^^^^^^^^^^^^^ (*const [?]u8)()

const array_slice_0_runtime = some_array[0..runtime_index];
//    ^^^^^^^^^^^^^^^^^^^^^ ([]const u8)()

const array_slice_with_sentinel = some_array[0..runtime_index :0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ ([:0]const u8)()

//
// Array init
//

const array_init = [length]u8{};
//    ^^^^^^^^^^ ([3]u8)()
const array_init_inferred_len_0 = [_]u8{};
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ ([0]u8)()
const array_init_inferred_len_3 = [_]u8{ 1, 2, 3 };
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ ([3]u8)()

//
// Array concatenation
//

const array_cat_0 = [_]u8{0} ++ [_]u8{1};
//    ^^^^^^^^^^^ ([2]u8)()

const array_cat_1 = [1]u8{0} ++ [_]u8{1};
//    ^^^^^^^^^^^ ([2]u8)()

const array_cat_2 = [_]u8{0} ++ [1]u8{1};
//    ^^^^^^^^^^^ ([2]u8)()

const array_cat_3 = [1]u8{0} ++ [1]u8{1};
//    ^^^^^^^^^^^ ([2]u8)()

const array_cat_4 = &[2]u8{ 0, 1 } ++ &[3]u8{ 2, 3, 4 };
//    ^^^^^^^^^^^ (*const [5]u8)()

//
// Array multiplication
//

const array_mult_0 = [_]u8{0} ** 2;
//    ^^^^^^^^^^^^ ([2]u8)()

const array_mult_1 = [1]u8{0} ** 2;
//    ^^^^^^^^^^^^ ([2]u8)()

const array_mult_2 = &[3]u8{ 0, 1, 2 } ** 2;
//    ^^^^^^^^^^^^ (*const [6]u8)()

comptime {
    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(some_array);
}
