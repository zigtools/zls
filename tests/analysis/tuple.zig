const TupleType = struct { i64, f32 };
//    ^^^^^^^^^ (type)(struct { i64, f32 })

const some_tuple: struct { i64, f32 } = undefined;
//    ^^^^^^^^^^ (struct { i64, f32 })()

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
