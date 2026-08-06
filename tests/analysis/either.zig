const UnknownType: type = undefined;
const unknown_value: UnknownType = undefined;

const non_type_and_type: if (true) undefined else i32 = unknown_value;
//    ^^^^^^^^^^^^^^^^^ (i32)()

const type_and_non_type: if (true) i32 else undefined = unknown_value;
//    ^^^^^^^^^^^^^^^^^ (i32)()

const compile_error_and_type: if (true) @compileError("Foo") else i32 = 1;
//    ^^^^^^^^^^^^^^^^^^^^^^ (i32)()

const type_and_compile_error: if (true) i32 else @compileError("Foo") = 1;
//    ^^^^^^^^^^^^^^^^^^^^^^ (i32)()

// The literal type values `noreturn`/`undefined` are valid peers and must
// not be mistaken for value-level branches that never produce a value.
const type_and_noreturn_type: if (true) u8 else noreturn = unknown_value;
//    ^^^^^^^^^^^^^^^^^^^^^^ (either type)()

const StructU32 = struct {
    field: u32 = 42,
    fn function(self: @This()) @This() {
        return self;
    }
};

const StructF64 = struct {
    field: f64 = 3.14,
    fn function(self: @This()) @This() {
        return self;
    }
};

fn GenericStruct(T: type) type {
    return struct { field: T };
}

const EitherType = if (true) StructU32 else StructF64;
//    ^^^^^^^^^^ (type)()

const EitherError = if (true) error{Foo} else error{Bar};
//    ^^^^^^^^^^^ (type)()

const either: EitherType = .{};
//    ^^^^^^ (either type)()

// TODO this should be `either type`
const field = either.field;
//    ^^^^^ (u32)()

const pointer = &either;
//    ^^^^^^^ (*const either type)()

const array = [_]EitherType{either};
//    ^^^^^ ([1]either type)()

const tuple: struct { EitherType } = .{either};
//    ^^^^^ (struct { either type })()

const optional: ?EitherType = null;
//    ^^^^^^^^ (?either type)()

const error_union: EitherError!EitherType = error.Foo;
//    ^^^^^^^^^^^ (either type!either type)()

const generic: GenericStruct(EitherType) = .{ .field = either };
//    ^^^^^^^ (GenericStruct(either type))()

// TODO this should be `either type`
const function0 = EitherType.function;
//    ^^^^^^^^^ (fn (StructU32) StructU32)()

fn function1() EitherType {}
// ^^^^^^^^^ (fn () either type)()

fn function2(_: EitherType) void {}
// ^^^^^^^^^ (fn (either type) void)()

fn function3(_: EitherType) EitherType {}
// ^^^^^^^^^ (fn (either type) either type)()
