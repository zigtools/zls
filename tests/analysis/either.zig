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

const condition = true;

const EitherType = if (condition) StructU32 else StructF64;
//    ^^^^^^^^^^ (type)()

const EitherError = if (condition) error{Foo} else error{Bar};
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

// TODO this should be `fn (either type) either type`
const function0 = EitherType.function;
//    ^^^^^^^^^ (fn (StructU32) StructU32)()

fn function1() EitherType {}
// ^^^^^^^^^ (fn () either type)()

fn function2(_: EitherType) void {}
// ^^^^^^^^^ (fn (either type) void)()

fn function3(_: EitherType) EitherType {}
// ^^^^^^^^^ (fn (either type) either type)()
