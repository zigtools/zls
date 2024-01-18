const optional_type = ?u32;
//    ^^^^^^^^^^^^^ (type)(?u32)
const null_optional: ?u32 = null;
//    ^^^^^^^^^^^^^ (?u32)(null)
const non_null_optional: ?u32 = 3;
//    ^^^^^^^^^^^^^^^^^ (?u32)(3)

const NullEqNull = null == null;
//    ^^^^^^^^^^ (bool)(true)
const NullNeqNull = null != null;
//    ^^^^^^^^^^^ (bool)(false)

const OptNullEqNull = @as(?u32, null) == null;
//    ^^^^^^^^^^^^^ (bool)(true)
const NullEqOptNull = null == @as(?u32, null);
//    ^^^^^^^^^^^^^ (bool)(true)

const OptNullNeqNull = @as(?u32, null) != null;
//    ^^^^^^^^^^^^^^ (bool)(false)
const NullNeqOptNull = null != @as(?u32, null);
//    ^^^^^^^^^^^^^^ (bool)(false)

const OptValEqNull = @as(?u32, 3) == null;
//    ^^^^^^^^^^^^ (bool)(false)
const NullEqOptVal = null == @as(?u32, 3);
//    ^^^^^^^^^^^^ (bool)(false)

const OptValNeqNull = @as(?u32, 3) != null;
//    ^^^^^^^^^^^^^ (bool)(true)
const NullNeqOptVal = null != @as(?u32, 3);
//    ^^^^^^^^^^^^^ (bool)(true)

// TODO
// const Opt3EqOpt3 = @as(?u32, 3) == @as(?u32, 3);
// //    ^^^^^^^^^^ (bool)(true)
// const Opt2EqOpt3 = @as(?u32, 2) == @as(?u32, 3);
// //    ^^^^^^^^^^ (bool)(false)
//
// const Opt3NeqOpt3 = @as(?u32, 3) != @as(?u32, 3);
// //    ^^^^^^^^^^ (bool)(false)
// const Opt2NeqOpt3 = @as(?u32, 2) != @as(?u32, 3);
// //    ^^^^^^^^^^ (bool)(true)
