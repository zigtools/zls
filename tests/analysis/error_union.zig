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

const ErrorSet = error{A} || error{B};
//    ^^^^^^^^ (type)(error{A,B})

const ErrorSetWithUnknown = error{A} || UnknownType;
//    ^^^^^^^^^^^^^^^^^^^ (type)(error{A, ... })

const ErrorSetWithUnknown2 = UnknownType || error{B};
//    ^^^^^^^^^^^^^^^^^^^^ (type)(error{B, ... })

const ErrorSetWithUnknown3 = UnknownType || error{A} || error{B};
//    ^^^^^^^^^^^^^^^^^^^^ (type)(error{A,B, ... })

const AllUnknown = UnknownType || UnknownType;
//    ^^^^^^^^^^ (type)(error{ ... })

const AnyerrorUnknown = anyerror || UnknownType;
//    ^^^^^^^^^^^^^^^ (type)(anyerror)

const UnknownAnyerror = UnknownType || anyerror;
//    ^^^^^^^^^^^^^^^ (type)(anyerror)

const AnyerrorPartiallyUnknown = anyerror || error{A} || UnknownType;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (type)(anyerror)
