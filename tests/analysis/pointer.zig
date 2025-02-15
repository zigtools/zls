//
// single item pointer *T
//

const one_u32: *const u32 = &@as(u32, 5);
//    ^^^^^^^ (*const u32)()

const one_u32_deref = one_u32.*;
//    ^^^^^^^^^^^^^ (u32)()

const one_u32_indexing = one_u32[0];
//    ^^^^^^^^^^^^^^^^ (unknown)()

const one_u32_slice_len_0_5 = one_u32[0..5];
//    ^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const one_u32_slice_len_0_0 = one_u32[0..0];
//    ^^^^^^^^^^^^^^^^^^^^^ (*const [0]u32)()

const one_u32_slice_len_0_1 = one_u32[0..1];
//    ^^^^^^^^^^^^^^^^^^^^^ (*const [1]u32)()

const one_u32_slice_len_1_1 = one_u32[1..1];
//    ^^^^^^^^^^^^^^^^^^^^^ (*const [0]u32)()

const one_u32_slice_open = one_u32[1..];
//    ^^^^^^^^^^^^^^^^^^ (unknown)()

const one_u32_orelse = one_u32 orelse unreachable;
//    ^^^^^^^^^^^^^^ (unknown)()

const one_u32_unwrap = one_u32.?;
//    ^^^^^^^^^^^^^^ (unknown)()

//
// many item pointer [*]T
//

const many_u32: [*]const u32 = &[_]u32{ 1, 2 };
//    ^^^^^^^^ ([*]const u32)()

const many_u32_deref = many_u32.*;
//    ^^^^^^^^^^^^^^ (unknown)()

const many_u32_indexing = many_u32[0];
//    ^^^^^^^^^^^^^^^^^ (u32)()

const many_u32_slice_len_comptime = many_u32[0..2];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*const [2]u32)()

const many_u32_slice_len_runtime = many_u32[0..runtime_index];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^ ([]const u32)()

const many_u32_slice_open = many_u32[1..];
//    ^^^^^^^^^^^^^^^^^^^ ([*]const u32)()

const many_u32_orelse = many_u32 orelse unreachable;
//    ^^^^^^^^^^^^^^^ (unknown)()

const many_u32_unwrap = many_u32.?;
//    ^^^^^^^^^^^^^^^ (unknown)()

//
// slice []T
//

const slice_u32: []const u32 = &.{ 1, 2 };
//    ^^^^^^^^^ ([]const u32)()

const slice_u32_deref = slice_u32.*;
//    ^^^^^^^^^^^^^^^ (unknown)()

const slice_u32_indexing = slice_u32[0];
//    ^^^^^^^^^^^^^^^^^^ (u32)()

const slice_u32_slice_len_comptime = slice_u32[0..2];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*const [2]u32)()

const slice_u32_slice_len_runtime = slice_u32[0..runtime_index];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ ([]const u32)()

// TODO this should be `*const [1]u32`
const slice_u32_slice_open = slice_u32[1..];
//    ^^^^^^^^^^^^^^^^^^^^ ([]const u32)()

const slice_u32_orelse = slice_u32 orelse unreachable;
//    ^^^^^^^^^^^^^^^^ (unknown)()

const slice_u32_unwrap = slice_u32.?;
//    ^^^^^^^^^^^^^^^^ (unknown)()

//
// C pointer [*c]T
//

const c_u32: [*c]const u32 = &[_]u32{ 1, 2 };
//    ^^^^^ ([*c]const u32)()

const c_u32_deref = c_u32.*;
//    ^^^^^^^^^^^ (u32)()

const c_u32_indexing = c_u32[0];
//    ^^^^^^^^^^^^^^ (u32)()

const c_u32_slice_len_comptime = c_u32[0..2];
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (*const [2]u32)()

const c_u32_slice_len_runtime = c_u32[0..runtime_index];
//    ^^^^^^^^^^^^^^^^^^^^^^^ ([]const u32)()

const c_u32_slice_open = c_u32[1..];
//    ^^^^^^^^^^^^^^^^ ([*c]const u32)()

const c_u32_orelse = c_u32 orelse unreachable;
//    ^^^^^^^^^^^^ ([*c]const u32)()

const c_u32_unwrap = c_u32.?;
//    ^^^^^^^^^^^^ ([*c]const u32)()

var runtime_index: usize = 5;

comptime {
    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(many_u32_slice_len_comptime);
}
