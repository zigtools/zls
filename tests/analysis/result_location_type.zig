const Error = error{ Foo, Bar };

const StructType = struct {
    foo: u32,
    fn init() StructType {}
    fn initChecked() !StructType {}
};

const NestedStructType = struct {
    bar: StructType = .{ .foo = 1 },
    //                   ^^^^ (u32)()
    fn init(_: StructType) NestedStructType {}
};

const EnumType = enum { bar, baz };

const TaggedUnionType = union(EnumType) { bar: u16, baz: u8 };

const TupleType = struct { StructType, TaggedUnionType };

const some_optional: ?StructType = .{ .foo = 1 };
//                                    ^^^^ (u32)()

const some_error_union: error{}!StructType = .{ .foo = 1 };
//                                              ^^^^ (u32)()

const some_error_union_optional: error{}!?StructType = .{ .foo = 1 };
//                                                        ^^^^ (u32)()

const some_optional_error_union: ?error{}!StructType = .{ .foo = 1 };
//                                                        ^^^^ (u32)()

const some_optional_optional: ??StructType = .{ .foo = 1 };
//                                              ^^^^ (u32)()

//
// var_decl
//

const some_struct: StructType = .{ .foo = 1 };
//                                 ^^^^ (u32)()

const some_enum: EnumType = .bar;
//                          ^^^^ (EnumType)()

const some_tagged_union: TaggedUnionType = .{ .bar = 1 };
//                                            ^^^^ (u16)()

//
// struct_init
//

const struct_init = StructType{ .foo = 1 };
//                              ^^^^ (u32)()

const nested_struct_init = NestedStructType{ .bar = .{ .foo = 1 } };
//                                           ^^^^ (StructType)()
//                                                     ^^^^ (u32)()

//
// call
//

const struct_decl_literal_call: StructType = .init();
//                                           ^^^^^ (fn () StructType)()

const nested_struct_decl_literal_call: NestedStructType = .init(.{ .foo = 1 });
//                                                                 ^^^^ (u32)()

fn call(_: StructType, _: StructType) void {}

test "call" {
    call(.{ .foo = 1 }, .{ .foo = 2 });
    //      ^^^^ (u32)()
    //                     ^^^^ (u32)()
}

//
// array_init
//

const some_array = [_]StructType{
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .foo = 2 },
    // ^^^^ (u32)()
};

const some_tuple = TupleType{
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .bar = 2 },
    // ^^^^ (u16)()
};

//
// address_of
//

const some_slice: []StructType = &.{
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .foo = 2 },
    // ^^^^ (u32)()
};

const some_tuple_pointer: *const TupleType = &.{
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .bar = 2 },
    // ^^^^ (u16)()
};

//
// if
//

const conditional: StructType =
    if (undefined) .{ .foo = 1 } else .{ .foo = 2 };
//                    ^^^^ (u32)()
//                                       ^^^^ (u32)()

//
// for
//

const for_loop: StructType =
    for (some_slice) |_| {} else .{ .foo = 1 };
//                                  ^^^^ (u32)()

//
// while
//

const while_loop: StructType =
    while (some_optional) |_| {} else .{ .foo = 1 };
//                                       ^^^^ (u32)()

//
// switch_case
//

// zig fmt: off
const switch_cases: StructType = switch (some_tagged_union) {
    .bar => |bar| .{ .foo = bar },
  //^^^^ (u16)()
  //                 ^^^^ (u32)()
    .baz => |baz| .{ .foo = baz },
  //^^^^ (u8)()
  //                 ^^^^ (u32)()
};
// zig fmt: on

//
// assign
//

test "assign" {
    var mutable_struct: StructType = undefined;
    mutable_struct = .{ .foo = 1 };
    //                  ^^^^ (u32)()
}

//
// equal_equal, bang_equal
//

const equal_0 = .bar == some_enum;
//              ^^^^ (EnumType)()

const equal_1 = some_enum == .bar;
//                           ^^^^ (EnumType)()

const not_equal_0 = .bar != some_enum;
//                  ^^^^ (EnumType)()

const not_equal_1 = some_enum != .bar;
//                               ^^^^ (EnumType)()

//
// return
//

fn return_0() StructType {
    return .{ .foo = 1 };
    //        ^^^^ (u32)()
}

fn return_1() ?StructType {
    return .{ .foo = 1 };
    //        ^^^^ (u32)()
}

fn return_2() Error!?StructType {
    return .{ .foo = 1 };
    //        ^^^^ (u32)()
}

//
// break
//

const break_for_0: StructType =
    for (some_slice) |_| {
        break .{ .foo = 1 };
        //       ^^^^ (u32)()
    };

const break_for_1: StructType =
    blk: for (some_slice) |_| {
        break :blk .{ .foo = 1 };
        //            ^^^^ (u32)()
    };

const break_while_0: StructType =
    while (some_optional) |_| {
        break .{ .foo = 1 };
        //       ^^^^ (u32)()
    };

const break_while_1: StructType =
    blk: while (some_optional) |_| {
        break :blk .{ .foo = 1 };
        //            ^^^^ (u32)()
    };

const break_block: StructType =
    blk: {
        break :blk .{ .foo = 1 };
        //            ^^^^ (u32)()
    };

//
// grouped_expression
//

const grouped_expression: StructType = (.{ .foo = 1 });
//                                         ^^^^ (u32)()

//
// try
//

test "try" {
    const s: StructType = try .initChecked();
    //                        ^^^^^^^^^^^^ (fn () !StructType)()
    _ = s;
}
