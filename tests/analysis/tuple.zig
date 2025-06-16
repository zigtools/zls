const TupleType = struct { i64, f32 };
//    ^^^^^^^^^ (type)(struct { i64, f32 })

const InvalidTupleTypeAccess0 = TupleType[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()
const InvalidTupleTypeAccess1 = TupleType[1];
//    ^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const some_tuple: struct { i64, f32 } = undefined;
//    ^^^^^^^^^^ (struct { i64, f32 })()

const some_tuple_array_access_0 = some_tuple[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (i64)()
const some_tuple_array_access_1 = some_tuple[1];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (f32)()
const some_tuple_array_access_2 = some_tuple[2];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const some_tuple_field_access_0 = some_tuple.@"0";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (i64)()
const some_tuple_field_access_1 = some_tuple.@"1";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (f32)()
const some_tuple_field_access_2 = some_tuple.@"2";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const some_tuple_len = some_tuple.len;
//    ^^^^^^^^^^^^^^ (usize)(2)

const either_tuple = if (true) .{undefined} else .{ undefined, undefined };
//    ^^^^^^^^^^^^ (either type)()

comptime {
    const some_tuple_0, const some_tuple_1 = some_tuple;
    //    ^^^^^^^^^^^^ (i64)()
    //                        ^^^^^^^^^^^^ (f32)()
    _ = some_tuple_0;
    _ = some_tuple_1;
}

const int: i64 = undefined;
const float: f32 = undefined;
const inferred_tuple = .{ int, float };
//    ^^^^^^^^^^^^^^ (struct { i64, f32 })()
//                     ^ (struct { i64, f32 })()

const inferred_tuple_array_access_0 = inferred_tuple[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (i64)()
const inferred_tuple_array_access_1 = inferred_tuple[1];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (f32)()
const inferred_tuple_array_access_2 = inferred_tuple[2];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const inferred_tuple_field_access_0 = inferred_tuple.@"0";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (i64)()
const inferred_tuple_field_access_1 = inferred_tuple.@"1";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (f32)()
const inferred_tuple_field_access_2 = inferred_tuple.@"2";
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const inferred_tuple_len = inferred_tuple.len;
//    ^^^^^^^^^^^^^^^^^^ (usize)(2)

comptime {
    const inferred_tuple_0, const inferred_tuple_1 = inferred_tuple;
    //    ^^^^^^^^^^^^^^^^ (i64)()
    //                            ^^^^^^^^^^^^^^^^ (f32)()
    _ = inferred_tuple_0;
    _ = inferred_tuple_1;
}

comptime {
    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(some_tuple);
}
