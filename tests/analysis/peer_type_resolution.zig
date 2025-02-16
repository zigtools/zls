const S = struct {
    int: i64,
    float: f32,
};

pub fn main() void {
    var runtime_bool: bool = undefined;

    const optional_0 = if (runtime_bool) @as(S, undefined) else @as(?S, undefined);
    //    ^^^^^^^^^^ (?S)()

    const optional_1 = if (runtime_bool) @as(?S, undefined) else @as(S, undefined);
    //    ^^^^^^^^^^ (?S)()

    // Use @compileLog to verify the expected type with the compiler:
    @compileLog(optional_0);
    @compileLog(optional_1);

    runtime_bool = undefined;
}
