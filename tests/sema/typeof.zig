const alpha = @TypeOf(5);
//    ^^^^^ (type)(comptime_int)

const beta = @TypeOf(5, null);
//    ^^^^ (type)(?comptime_int)
