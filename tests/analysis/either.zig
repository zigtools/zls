const UnknownType: type = undefined;
const unknown_value: UnknownType = undefined;

const non_type_and_type: if (true) undefined else i32 = unknown_value;
//    ^^^^^^^^^^^^^^^^^ (unknown)()

const type_and_non_type: if (true) i32 else undefined = unknown_value;
//    ^^^^^^^^^^^^^^^^^ (unknown)()

const compile_error_and_type: if (true) @compileError("Foo") else i32 = 1;
//    ^^^^^^^^^^^^^^^^^^^^^^ (either type)()

const type_and_compile_error: if (true) i32 else @compileError("Foo") = 1;
//    ^^^^^^^^^^^^^^^^^^^^^^ (either type)()
