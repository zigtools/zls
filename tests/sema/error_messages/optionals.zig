const some_value: ?u32 = 5;
const no_value: ?u32 = null;
const undefined_value: ?u32 = undefined;
const not_opt_value: u32 = 0;

const null_unwrap = no_value.?;
//                  ^^^^^^^^^^ error: tried to unwrap optional of type `u32` which was null

const undefined_unwrap = undefined_value.?;
//                       ^^^^^^^^^^^^^^^^^ error: tried to unwrap optional of type `u32` which was undefined

const invalid_unwrap = not_opt_value.?;
//                     ^^^^^^^^^^^^^^^ error: expected optional type, found 'u32'
