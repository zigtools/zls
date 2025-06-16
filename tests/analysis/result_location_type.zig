const Error = error{ Foo, Bar };

const StructType = struct {
    foo: u32 = 0,
    fn init() StructType {
        return .{};
    }
    fn initChecked() !StructType {
        return .{};
    }
};

const NestedStructType = struct {
    bar: StructType = .{ .foo = 1 },
    //                ^ (StructType)()
    //                   ^^^^ (u32)()
    fn init(bar: StructType) NestedStructType {
        return .{ .bar = bar };
    }
};

const EnumType = enum { bar, baz };

const TaggedUnionType = union(EnumType) { bar: u16, baz: u8 };

const TupleType = struct { StructType, TaggedUnionType };

const some_optional: ?StructType = .{ .foo = 1 };
//                                 ^ (StructType)()
//                                    ^^^^ (u32)()

const some_error_union: error{}!StructType = .{ .foo = 1 };
//                                           ^ (StructType)()
//                                              ^^^^ (u32)()

const some_error_union_optional: error{}!?StructType = .{ .foo = 1 };
//                                                     ^ (StructType)()
//                                                        ^^^^ (u32)()

const some_optional_error_union: ?error{}!StructType = .{ .foo = 1 };
//                                                     ^ (StructType)()
//                                                        ^^^^ (u32)()

const some_optional_optional: ??StructType = .{ .foo = 1 };
//                                           ^ (StructType)()
//                                              ^^^^ (u32)()

//
// var_decl
//

const some_struct: StructType = .{ .foo = 1 };
//                              ^ (StructType)()
//                                 ^^^^ (u32)()

const some_enum: EnumType = .bar;
//                          ^^^^ (EnumType)()

const some_tagged_union: TaggedUnionType = .{ .bar = 1 };
//                                         ^ (TaggedUnionType)()
//                                            ^^^^ (u16)()

//
// struct_init
//

const struct_init = StructType{ .foo = 1 };
//                              ^^^^ (u32)()

const nested_struct_init = NestedStructType{ .bar = .{ .foo = 1 } };
//                                           ^^^^ (StructType)()
//                                                  ^ (StructType)()
//                                                     ^^^^ (u32)()

//
// call
//

const struct_decl_literal_call: StructType = .init();
//                                           ^^^^^ (fn () StructType)()

const nested_struct_decl_literal_call: NestedStructType = .init(.{ .foo = 1 });
//                                                              ^ (StructType)()
//                                                                 ^^^^ (u32)()

fn func(_: StructType, _: StructType) void {}
fn generic_func(T: type, _: T) void {}

const call = func(.{ .foo = 1 }, .{ .foo = 2 });
//                ^ (StructType)()
//                   ^^^^ (u32)()
//                               ^ (StructType)()
//                                  ^^^^ (u32)()

const generic_call_struct = generic_func(StructType, .{ .foo = 1 });
//                                                   ^ (StructType)()
//                                                      ^^^^ (u32)()

const generic_call_enum = generic_func(EnumType, .bar);
//                                               ^^^^ (EnumType)()

const generic_call_tagged_union = generic_func(TaggedUnionType, .{ .bar = 1 });
//                                                              ^ (TaggedUnionType)()
//                                                                 ^^^^ (u16)()

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

const some_slice: []StructType = &.{
    //                            ^ ([2]StructType)()
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .foo = 2 },
    // ^^^^ (u32)()
};

const some_tuple_pointer: *const TupleType = &.{
    //                                        ^ (struct { StructType, TaggedUnionType })()
    .{ .foo = 1 },
    // ^^^^ (u32)()
    .{ .bar = 2 },
    // ^^^^ (u16)()
};

const some_enum_array: [2]EnumType = .{ .bar, .baz };
//                                   ^ ([2]EnumType)()
//                                      ^^^^ (EnumType)()
//                                            ^^^^ (EnumType)()

const some_enum_slice: []const EnumType = &.{ .bar, .baz };
//                                         ^ ([2]EnumType)()
//                                            ^^^^ (EnumType)()
//                                                  ^^^^ (EnumType)()

//
// if
//

const conditional: StructType =
    if (undefined) .{ .foo = 1 } else .{ .foo = 2 };
//                 ^ (StructType)()
//                    ^^^^ (u32)()
//                                    ^ (StructType)()
//                                       ^^^^ (u32)()

//
// for
//

const for_loop: StructType =
    for (some_slice) |_| {} else .{ .foo = 1 };
//                               ^ (StructType)()
//                                  ^^^^ (u32)()

//
// while
//

const while_loop: StructType =
    while (some_optional) |_| {} else .{ .foo = 1 };
//                                    ^ (StructType)()
//                                       ^^^^ (u32)()

//
// switch_case
//

// zig fmt: off
const switch_cases: StructType = switch (some_tagged_union) {
    .bar => |bar| .{ .foo = bar },
  //^^^^ (u16)()
  //              ^ (StructType)()
  //                 ^^^^ (u32)()
    .baz => |baz| .{ .foo = baz },
  //^^^^ (u8)()
  //              ^ (StructType)()
  //                 ^^^^ (u32)()
};
// zig fmt: on

//
// assign
//

test "assign" {
    var mutable_struct: StructType = undefined;
    mutable_struct = .{ .foo = 1 };
    //               ^ (StructType)()
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
    //     ^ (StructType)()
    //        ^^^^ (u32)()
}

fn return_1() ?StructType {
    return .{ .foo = 1 };
    //     ^ (StructType)()
    //        ^^^^ (u32)()
}

fn return_2() Error!?StructType {
    return .{ .foo = 1 };
    //     ^ (StructType)()
    //        ^^^^ (u32)()
}

//
// continue
//

const continue_switch: StructType = blk: switch (some_tagged_union) {
    .bar => |bar| continue :blk .{ .baz = @truncate(bar) },
    //                          ^ (TaggedUnionType)()
    //                             ^^^^ (u8)()
    .baz => |baz| .{ .foo = baz },
    //            ^ (StructType)()
    //               ^^^^ (u32)()
};

//
// break
//

const break_for_0: StructType =
    for (some_slice) |_| {
        break .{ .foo = 1 };
        //    ^ (StructType)()
        //       ^^^^ (u32)()
    };

const break_for_1: StructType =
    blk: for (some_slice) |_| {
        break :blk .{ .foo = 1 };
        //         ^ (StructType)()
        //            ^^^^ (u32)()
    };

const break_while_0: StructType =
    while (some_optional) |_| {
        break .{ .foo = 1 };
        //    ^ (StructType)()
        //       ^^^^ (u32)()
    };

const break_while_1: StructType =
    blk: while (some_optional) |_| {
        break :blk .{ .foo = 1 };
        //         ^ (StructType)()
        //            ^^^^ (u32)()
    };

const break_switch: StructType = blk: switch (some_tagged_union) {
    .bar => |bar| break :blk .{ .foo = bar },
    //                       ^ (StructType)()
    //                          ^^^^ (u32)()
    .baz => |baz| .{ .foo = baz },
    //            ^ (StructType)()
    //               ^^^^ (u32)()
};

const break_block: StructType =
    blk: {
        break :blk .{ .foo = 1 };
        //         ^ (StructType)()
        //            ^^^^ (u32)()
    };

//
// grouped_expression
//

const grouped_expression: StructType = (.{ .foo = 1 });
//                                      ^ (StructType)()
//                                         ^^^^ (u32)()

//
// try
//

test "try" {
    const s: StructType = try .initChecked();
    //                        ^^^^^^^^^^^^ (fn () !StructType)()
    _ = s;
}

//
// comptime
//

test "comptime" {
    const s: StructType = comptime .init();
    //                             ^^^^^ (fn () StructType)()
    _ = s;
}

//
// builtin_call
//

const builtin_as = @as(StructType, .{ .foo = 1 });
//                                 ^ (StructType)()
//                                    ^^^^ (u32)()

//
// orelse
//

const @"orelse" = some_optional orelse .{ .foo = 1 };
//                                     ^ (StructType)()
//                                        ^^^^ (u32)()

//
// catch
//

const @"catch" = some_error_union catch .{ .foo = 1 };
//                                      ^ (StructType)()
//                                         ^^^^ (u32)()

//
// address_of
//

const address_of_struct: *const StructType = &.{ .foo = 1 };
//                                            ^ (StructType)()
//                                               ^^^^ (u32)()

const address_of_nested_struct: *const NestedStructType = &.{ .bar = .{ .foo = 1 } };
//                                                         ^ (NestedStructType)()
//                                                            ^^^^ (StructType)()
//                                                                   ^ (StructType)()
//                                                                      ^^^^ (u32)()

const address_of_enum: *const EnumType = &.bar;
//                                        ^^^^ (EnumType)()

const address_of_tagged_union: *const TaggedUnionType = &.{ .bar = 1 };
//                                                       ^ (TaggedUnionType)()
//                                                          ^^^^ (u16)()
