const S = struct {
    int: i64,
    float: f32,
};
const s: S = .{
    .int = 0,
    .float = 1.2,
};

pub fn main() void {
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
    _ = error_set_0;
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_1 = if (runtime_bool) @as(error{ A, B }, error.A) else error.A;
    _ = error_set_1;
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_2 = if (runtime_bool) error.B else error.A;
    _ = error_set_2;
    //  ^^^^^^^^^^^ (error{B,A})()

    const error_set_3 = if (runtime_bool) error.A else error.B;
    _ = error_set_3;
    //  ^^^^^^^^^^^ (error{A,B})()

    const error_set_4 = if (runtime_bool) @as(error{ B, C }, error.B) else @as(error{ A, B }, error.A);
    _ = error_set_4;
    //  ^^^^^^^^^^^ (error{B,C,A})()

    const error_set_5 = if (runtime_bool) @as(error{ A, B }, error.A) else @as(error{ B, C }, error.B);
    _ = error_set_5;
    //  ^^^^^^^^^^^ (error{A,B,C})()

    _ = &runtime_bool;
}

const comptime_bool: bool = true;

const comptime_int_and_void = if (comptime_bool) 0 else {};
//    ^^^^^^^^^^^^^^^^^^^^^ (either type)()
