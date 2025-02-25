const S = struct {
    int: i64,
    float: f32,
};

pub fn main() void {
    var runtime_bool: bool = undefined;

    const widened_int_0 = if (runtime_bool) @as(i8, undefined) else @as(i16, undefined);
    _ = widened_int_0;
    //  ^^^^^^^^^^^^^ (i16)()

    const widened_int_1 = if (runtime_bool) @as(i16, undefined) else @as(i8, undefined);
    _ = widened_int_1;
    //  ^^^^^^^^^^^^^ (i16)()

    const optional_0 = if (runtime_bool) @as(S, undefined) else @as(?S, undefined);
    _ = optional_0;
    //  ^^^^^^^^^^ (?S)()

    const optional_1 = if (runtime_bool) @as(?S, undefined) else @as(S, undefined);
    _ = optional_1;
    //  ^^^^^^^^^^ (?S)()

    const optional_2 = if (runtime_bool) null else @as(S, undefined);
    _ = optional_2;
    //  ^^^^^^^^^^ (?S)()

    const optional_3 = if (runtime_bool) @as(S, undefined) else null;
    _ = optional_3;
    //  ^^^^^^^^^^ (?S)()

    const optional_4 = if (runtime_bool) null else @as(?S, undefined);
    _ = optional_4;
    //  ^^^^^^^^^^ (?S)()

    const optional_5 = if (runtime_bool) @as(?S, undefined) else null;
    _ = optional_5;
    //  ^^^^^^^^^^ (?S)()

    const comptime_int_and_void = if (runtime_bool) 0 else {};
    _ = comptime_int_and_void;
    //  ^^^^^^^^^^^^^^^^^^^^^ (either type)()

    runtime_bool = undefined;
}
