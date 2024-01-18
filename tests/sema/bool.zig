const True: bool = true;
//    ^^^^ (bool)(true)
const False: bool = false;
//    ^^^^^ (bool)(false)

const TrueEqTrue = true == true;
//    ^^^^^^^^^^ (bool)(true)
const FalseEqFalse = false == false;
//    ^^^^^^^^^^^^ (bool)(true)

const TrueEqFalse = true == false;
//    ^^^^^^^^^^^ (bool)(false)
const FalsEeqTrue = false == true;
//    ^^^^^^^^^^^ (bool)(false)

const TrueNeqTrue = true != true;
//    ^^^^^^^^^^^ (bool)(false)
const FalseNeqFalse = false != false;
//    ^^^^^^^^^^^^^ (bool)(false)

const TrueNeqFalse = true != false;
//    ^^^^^^^^^^^^ (bool)(true)
const FalsNeqTrue = false != true;
//    ^^^^^^^^^^^ (bool)(true)

const TrueToInt = @intFromBool(true);
//    ^^^^^^^^^ (u1)(1)
const FalseToInt = @intFromBool(false);
//    ^^^^^^^^^^ (u1)(0)

const NotTrue = !true;
//    ^^^^^^^ (bool)(false)
const NotFalse = !false;
//    ^^^^^^^^ (bool)(true)

const UndefinedToInt = @intFromBool(@as(bool, undefined));
//    ^^^^^^^^^^^^^^ (u1)(undefined)

const NotUndefined = !@as(bool, undefined);
//    ^^^^^^^^^^^^ (bool)(undefined)

const UndefinedEqTrue = @as(bool, undefined) == true;
//    ^^^^^^^^^^^^^^^ (bool)(undefined)
const UndefinedNeqTrue = @as(bool, undefined) != true;
//    ^^^^^^^^^^^^^^^^ (bool)(undefined)

const UndefinedEqFalse = @as(bool, undefined) == false;
//    ^^^^^^^^^^^^^^^^ (bool)(undefined)
const UndefinedNeqFalse = @as(bool, undefined) != false;
//    ^^^^^^^^^^^^^^^^^ (bool)(undefined)

const TrueEqUndefined = true == @as(bool, undefined);
//    ^^^^^^^^^^^^^^^ (bool)(undefined)
const TrueNeqUndefined = true != @as(bool, undefined);
//    ^^^^^^^^^^^^^^^^ (bool)(undefined)

const FalseEqUndefined = false == @as(bool, undefined);
//    ^^^^^^^^^^^^^^^^ (bool)(undefined)
const FalseNeqUndefined = false != @as(bool, undefined);
//    ^^^^^^^^^^^^^^^^^ (bool)(undefined)

const UndefinedEqUndefined = @as(bool, undefined) == @as(bool, undefined);
//    ^^^^^^^^^^^^^^^^^^^^ (bool)(undefined)

const UndefinedNeqUndefined = @as(bool, undefined) != @as(bool, undefined);
//    ^^^^^^^^^^^^^^^^^^^^^ (bool)(undefined)

const TypeOfBool = @TypeOf(bool);
//    ^^^^^^^^^^ (type)(type)
const TypeOfTrue = @TypeOf(true);
//    ^^^^^^^^^^ (type)(bool)
const TypeOfFalse = @TypeOf(false);
//    ^^^^^^^^^^^ (type)(bool)
