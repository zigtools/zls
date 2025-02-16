const S = struct {
    int: i64,
    float: f32,
};

pub fn main() void {
    var runtime_bool: bool = undefined;

    const widened_int_0 = if (runtime_bool) @as(i8, undefined) else @as(i16, undefined);
    //    ^^^^^^^^^^^^^ (i16)()

    const widened_int_1 = if (runtime_bool) @as(i16, undefined) else @as(i8, undefined);
    //    ^^^^^^^^^^^^^ (i16)()

    const optional_0 = if (runtime_bool) @as(S, undefined) else @as(?S, undefined);
    //    ^^^^^^^^^^ (?S)()

    const optional_1 = if (runtime_bool) @as(?S, undefined) else @as(S, undefined);
    //    ^^^^^^^^^^ (?S)()

    const optional_2 = if (runtime_bool) null else @as(S, undefined);
    //    ^^^^^^^^^^ (?S)()

    const optional_3 = if (runtime_bool) @as(S, undefined) else null;
    //    ^^^^^^^^^^ (?S)()

    const optional_4 = if (runtime_bool) null else @as(?S, undefined);
    //    ^^^^^^^^^^ (?S)()

    const optional_5 = if (runtime_bool) @as(?S, undefined) else null;
    //    ^^^^^^^^^^ (?S)()

    // Use @compileLog to verify the expected type with the compiler:
    @compileLog(widened_int_0);
    @compileLog(widened_int_1);
    @compileLog(optional_0);
    @compileLog(optional_1);
    @compileLog(optional_2);
    @compileLog(optional_3);
    @compileLog(optional_4);
    @compileLog(optional_5);

    runtime_bool = undefined;
}
