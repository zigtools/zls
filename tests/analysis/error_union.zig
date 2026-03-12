const Error = error{ Foo, Bar };
//    ^^^^^ (type)(error{Foo,Bar})

const Unknown: type = undefined.Unknown;
//    ^^^^^^^ (type)((unknown type))

const ErrorUnionType = Error!u32;
//    ^^^^^^^^^^^^^^ (type)()

const InvalidErrorUnionTypeUnwrap = ErrorUnionType catch |err| err;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()
//                                                        ^^^ (unknown)()

const DuplicateErrorName = error{ Foo, Foo } || error{Bar};
//    ^^^^^^^^^^^^^^^^^^ (type)(error{Foo,Bar})

const ErrorUnionUnknownError = Unknown!u32;
//    ^^^^^^^^^^^^^^^^^^^^^^ (type)((unknown type)!u32)

const ErrorUnionUnknownPayload = Error!Unknown;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (type)(error{Foo,Bar}!(unknown type))
