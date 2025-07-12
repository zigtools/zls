const S = struct {
    int: i64,
    float: f32,
};
const s: S = .{
    .int = 0,
    .float = 1.2,
};

pub fn main() !void {
    var runtime_bool: bool = true;

    const widened_int_0 = if (runtime_bool) @as(i8, 0) else @as(i16, 0);
    _ = widened_int_0;
    //  ^^^^^^^^^^^^^ (i16)()

    const widened_int_1 = if (runtime_bool) @as(i16, 0) else @as(i8, 0);
    _ = widened_int_1;
    //  ^^^^^^^^^^^^^ (i16)()

    const optional_0 = if (runtime_bool) s else @as(?S, s);
    _ = optional_0;
    //  ^^^^^^^^^^ (?S)()

    const optional_1 = if (runtime_bool) @as(?S, s) else s;
    _ = optional_1;
    //  ^^^^^^^^^^ (?S)()

    const optional_2 = if (runtime_bool) null else s;
    _ = optional_2;
    //  ^^^^^^^^^^ (?S)()

    const optional_3 = if (runtime_bool) s else null;
    _ = optional_3;
    //  ^^^^^^^^^^ (?S)()

    const optional_4 = if (runtime_bool) null else @as(?S, s);
    _ = optional_4;
    //  ^^^^^^^^^^ (?S)()

    const optional_5 = if (runtime_bool) @as(?S, s) else null;
    _ = optional_5;
    //  ^^^^^^^^^^ (?S)()

    const error_set_0 = if (runtime_bool) error.A else @as(error{ A, B }, error.A);
    _ = error_set_0 catch {};
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_1 = if (runtime_bool) @as(error{ A, B }, error.A) else error.A;
    _ = error_set_1 catch {};
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_2 = if (runtime_bool) error.B else error.A;
    _ = error_set_2 catch {};
    //  ^^^^^^^^^^^ (error{B,A})()

    const error_set_3 = if (runtime_bool) error.A else error.B;
    _ = error_set_3 catch {};
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_4 = if (runtime_bool) @as(error{ B, C }, error.B) else @as(error{ A, B }, error.A);
    _ = error_set_4 catch {};
    //  ^^^^^^^^^^^ (error{B,C,A})()

    const error_set_5 = if (runtime_bool) @as(error{ A, B }, error.A) else @as(error{ B, C }, error.B);
    _ = error_set_5 catch {};
    //  ^^^^^^^^^^^ (error{A,B,C})()

    const error_union_0 = if (runtime_bool) s else @as(error{A}!S, s);
    _ = error_union_0 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!S)()

    const error_union_1 = if (runtime_bool) @as(error{A}!S, s) else s;
    _ = error_union_1 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!S)()

    const error_union_2 = if (runtime_bool) @as(?S, s) else @as(error{A}!S, s);
    _ = error_union_2 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_3 = if (runtime_bool) @as(error{A}!S, s) else @as(?S, s);
    _ = error_union_3 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_4 = if (runtime_bool) null else @as(error{A}!S, s);
    _ = error_union_4 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_5 = if (runtime_bool) @as(error{A}!S, s) else null;
    _ = error_union_5 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_6 = if (runtime_bool) @as(error{B}!S, s) else @as(error{A}!S, s);
    _ = error_union_6 catch {};
    //  ^^^^^^^^^^^^^ (error{B,A}!S)()

    const error_union_7 = if (runtime_bool) @as(error{A}!S, s) else @as(error{B}!S, s);
    _ = error_union_7 catch {};
    //  ^^^^^^^^^^^^^ (error{A,B}!S)()

    const error_union_8 = if (runtime_bool) @as(error{A}!?S, s) else @as(error{A}!S, s);
    _ = error_union_8 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_9 = if (runtime_bool) @as(error{A}!S, s) else @as(error{A}!?S, s);
    _ = error_union_9 catch {};
    //  ^^^^^^^^^^^^^ (error{A}!?S)()

    const error_union_10 = if (runtime_bool) @as(error{B}!?S, s) else @as(error{A}!S, s);
    _ = error_union_10 catch {};
    //  ^^^^^^^^^^^^^^ (error{B,A}!?S)()

    const error_union_11 = if (runtime_bool) @as(error{A}!S, s) else @as(error{B}!?S, s);
    _ = error_union_11 catch {};
    //  ^^^^^^^^^^^^^^ (error{A,B}!?S)()

    const error_union_12 = if (runtime_bool) @as(error{B}!error{A}!S, s) else @as(error{A}!?S, s);
    _ = try try error_union_12;
    //          ^^^^^^^^^^^^^^ (error{B,A}!error{A}!?S)()

    const error_union_13 = if (runtime_bool) @as(error{A}!?S, s) else @as(error{B}!error{A}!S, s);
    _ = try try error_union_13;
    //          ^^^^^^^^^^^^^^ (error{A,B}!error{A}!?S)()

    const error_union_14 = if (runtime_bool) @as(error{B}!error{A}!S, s) else @as(error{A}!error{B}!?S, s);
    _ = try try error_union_14;
    //          ^^^^^^^^^^^^^^ (error{B,A}!error{A,B}!?S)()

    const error_union_15 = if (runtime_bool) @as(error{A}!error{B}!?S, s) else @as(error{B}!error{A}!S, s);
    _ = try try error_union_15;
    //          ^^^^^^^^^^^^^^ (error{A,B}!error{B,A}!?S)()

    const error_union_16 = if (runtime_bool) error.A else s;
    _ = error_union_16;
    //  ^^^^^^^^^^^^^^ (error{A}!S)()

    const error_union_17 = if (runtime_bool) s else error.A;
    _ = error_union_17;
    //  ^^^^^^^^^^^^^^ (error{A}!S)()

    const error_union_18 = if (runtime_bool) error.A else @as(i32, 0);
    _ = error_union_18;
    //  ^^^^^^^^^^^^^^ (error{A}!i32)()

    const error_union_19 = if (runtime_bool) @as(i32, 0) else error.A;
    _ = error_union_19;
    //  ^^^^^^^^^^^^^^ (error{A}!i32)()

    const error_union_20 = if (runtime_bool) error.A else @as(error{B}!S, s);
    _ = error_union_20;
    //  ^^^^^^^^^^^^^^ (error{A,B}!S)()

    const error_union_21 = if (runtime_bool) @as(error{B}!S, s) else error.A;
    _ = error_union_21;
    //  ^^^^^^^^^^^^^^ (error{A,B}!S)()

    const error_union_22 = if (runtime_bool) error.A else @as(error{B}!i32, 0);
    _ = error_union_22;
    //  ^^^^^^^^^^^^^^ (error{A,B}!i32)()

    const error_union_23 = if (runtime_bool) @as(error{B}!i32, 0) else error.A;
    _ = error_union_23;
    //  ^^^^^^^^^^^^^^ (error{A,B}!i32)()

    const noreturn_0 = if (runtime_bool) s else return;
    _ = noreturn_0;
    //  ^^^^^^^^^^ (S)()

    const noreturn_1 = if (runtime_bool) return else s;
    _ = noreturn_1;
    //  ^^^^^^^^^^ (S)()

    // Use @compileLog to verify the expected type with the compiler:
    // @compileLog(error_union_0);

    _ = &runtime_bool;
}

const comptime_bool: bool = true;

const comptime_int_and_void = if (comptime_bool) 0 else {};
//    ^^^^^^^^^^^^^^^^^^^^^ (either type)()

const compile_error_0 = if (comptime_bool) s else @compileError("Foo");
//    ^^^^^^^^^^^^^^^ (S)()

const compile_error_1 = if (comptime_bool) @compileError("Foo") else s;
//    ^^^^^^^^^^^^^^^ (S)()
