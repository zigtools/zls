const EmptyError = error{};
//    ^^^^^^^^^^ (type)(error{})

const SomeError = error{
    //^^^^^^^^^ (type)(error{OutOfMemory,OutOfOrder,OutOfTheBox})
    OutOfMemory,
    OutOfOrder,
    OutOfTheBox,
};

const ParseResult = error{ Overflow, InvalidCharacter }!u32;
//    ^^^^^^^^^^^ (type)(error{Overflow,InvalidCharacter}!u32)

const MergedError1 = error{OutOfMemory} || error{ Overflow, OutOfMemory };
//    ^^^^^^^^^^^^ (type)(error{OutOfMemory,Overflow})

const MergedError2 = anyerror || error{ Overflow, OutOfMemory };
//    ^^^^^^^^^^^^ (type)(anyerror)

const MergedError3 = error{OutOfMemory} || anyerror;
//    ^^^^^^^^^^^^ (type)(anyerror)

const error_set_field_access = error{ OutOfMemory, Overflow }.OutOfMemory;
//    ^^^^^^^^^^^^^^^^^^^^^^ (error{OutOfMemory,Overflow})(error.OutOfMemory)

const single_value_error_set_shortcut = error.OutOfMemory;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (error{OutOfMemory})(error.OutOfMemory)
