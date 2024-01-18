const a: bool = 5;
//              ^ error: expected type 'bool', found 'comptime_int'

const b = @as(bool, 5);
//                  ^ error: expected type 'bool', found 'comptime_int'
