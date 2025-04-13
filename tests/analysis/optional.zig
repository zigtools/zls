const OptionalType = ?u32;
//    ^^^^^^^^^^^^ (type)()

const InvalidOptionalTypeUnwrap = OptionalType.?;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()

const alpha: ?u32 = undefined;
//    ^^^^^ (?u32)()

const beta = alpha.?;
//    ^^^^ (u32)()

const gamma = if (alpha) |value| value else null;
//                        ^^^^^ (u32)()

const delta = alpha orelse unreachable;
//    ^^^^^ (u32)()

const epsilon = alpha.?;
//    ^^^^^^^ (u32)()

const zeta = alpha orelse null;
// TODO   ^^^^ (?u32)()

const eta = alpha orelse 5;
//    ^^^ (u32)()
