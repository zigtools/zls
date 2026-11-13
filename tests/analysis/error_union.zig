const UnknownType: type = UnknownType;
//    ^^^^^^^^^^^ (type)(unknown)

const Error = error{ Foo, Bar };
//    ^^^^^ (type)(error{Foo,Bar})

const ErrorUnionType = Error!u32;
//    ^^^^^^^^^^^^^^ (type)()

const InvalidErrorUnionTypeUnwrap = ErrorUnionType catch |err| err;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()
//                                                        ^^^ (unknown)()

const DuplicateErrorName = error{ Foo, Foo } || error{Bar};
//    ^^^^^^^^^^^^^^^^^^ (type)(error{Bar,Foo})

const ErrorUnionUnknownError = UnknownType!u32;
//    ^^^^^^^^^^^^^^^^^^^^^^ (type)((unknown type)!u32)

const ErrorUnionUnknownPayload = Error!UnknownType;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (type)(error{Foo,Bar}!(unknown type))
