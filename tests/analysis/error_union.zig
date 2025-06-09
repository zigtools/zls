const Error = error{ Foo, Bar };

const ErrorUnionType = Error!u32;
//    ^^^^^^^^^^^^^^ (type)()

const InvalidErrorUnionTypeUnwrap = ErrorUnionType catch |err| err;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (unknown)()
//                                                        ^^^ (unknown)()

const DuplicateErrorName = error{ Foo, Foo } || error{Bar};
//    ^^^^^^^^^^^^^^^^^^ (type)(error{Foo,Bar})
