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
//    ^^^^^^^^^^^^^^^^^^ (type)(error{Bar,Foo})

const ErrorUnionUnknownError = Unknown!u32;
//    ^^^^^^^^^^^^^^^^^^^^^^ (type)((unknown type)!u32)

const ErrorUnionUnknownPayload = Error!Unknown;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (type)(error{Foo,Bar}!(unknown type))

const ErrorSet = error{A} || error{B};
//    ^^^^^^^^ (type)(error{A,B})

const ErrorSetWithUnknown = error{A} || undefined.Unknown;
//    ^^^^^^^^^^^^^^^^^^^ (type)(error{A, ... })

const ErrorSetWithUnknown2 = undefined.Unknown || error{B};
//    ^^^^^^^^^^^^^^^^^^^^ (type)(error{B, ... })

const ErrorSetWithUnknown3 = undefined.Unknown || error{A} || error{B};
//    ^^^^^^^^^^ (type)(error{A,B, ... })

const AllUnknown = undefined.Unknown || undefined.Unknown;
//    ^^^^^^^^^^ (type)(error{ ... })
