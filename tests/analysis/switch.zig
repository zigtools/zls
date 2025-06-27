const Enum = enum {
    foo,
    bar,
    baz,
    qux,
};

const TaggedUnion = union(Enum) {
    foo: i32,
    bar: bool,
    baz: f64,
    qux: void,
};

const NonExhaustiveEnum = enum(u8) {
    fizz = 0,
    buzz = 1,
    _,
};

const some_u8: u8 = 'e';
const some_enum: Enum = .baz;
const some_tagged_union: TaggedUnion = .{ .baz = 3.14 };
const some_non_exhaustive_enum: NonExhaustiveEnum = @enumFromInt(42);

const switch_u8 = switch (some_u8) {
    'x' => |a| a,
    //      ^ (u8)()
    'y' => |a| a,
    //      ^ (u8)()
    else => |a| a,
    //       ^ (u8)()
};

const switch_enum = switch (some_enum) {
    .foo => |a| a,
    //       ^ (Enum)()
    .bar => |a| a,
    //       ^ (Enum)()
    else => |a| a,
    //       ^ (Enum)()
};

const switch_tagged_union = switch (some_tagged_union) {
    .foo => |a| a,
    //       ^ (i32)()
    .bar => |a| a,
    //       ^ (bool)()
    else => |a| a,
    //       ^ (TaggedUnion)()
};

const switch_non_exhaustive_enum = switch (some_non_exhaustive_enum) {
    .fizz,
    .buzz,
    => |a| a,
    //  ^ (NonExhaustiveEnum)()
    _ => |a| a,
    //    ^ (NonExhaustiveEnum)()
};

const switch_null = switch (null) {
    .foo => |a| a,
    //       ^ (@TypeOf(null))() TODO this should be `unknown`
    .bar => |a| a,
    //       ^ (@TypeOf(null))() TODO this should be `unknown`
    else => |a| a,
    //       ^ (@TypeOf(null))() TODO this should be `unknown`
};

const switch_u8_inline = switch (some_u8) {
    inline 'x' => |a, b| .{ a, b },
    //             ^ (u8)()
    //                ^ (unknown)()
    inline 'y' => |a, b| .{ a, b },
    //             ^ (u8)()
    //                ^ (unknown)()
    inline else => |a, b| .{ a, b },
    //              ^ (u8)()
    //                 ^ (unknown)()
};

const switch_enum_inline = switch (some_enum) {
    inline .foo => |a, b| .{ a, b },
    //              ^ (Enum)()
    //                 ^ (unknown)()
    inline .bar => |a, b| .{ a, b },
    //              ^ (Enum)()
    //                 ^ (unknown)()
    inline else => |a, b| .{ a, b },
    //              ^ (Enum)()
    //                 ^ (unknown)()
};

const switch_tagged_union_inline = switch (some_tagged_union) {
    inline .foo => |a, b| .{ a, b },
    //              ^ (i32)()
    //                 ^ (Enum)()
    inline .bar => |a, b| .{ a, b },
    //              ^ (bool)()
    //                 ^ (Enum)()
    inline else => |a, b| .{ a, b },
    //              ^ (unknown)() TODO this should be `either type`
    //                 ^ (Enum)()
};

const switch_null_inline = switch (null) {
    inline .foo => |a, b| .{ a, b },
    //              ^ (@TypeOf(null))() TODO this should be `unknown`
    //                 ^ (unknown)()
    inline .bar => |a, b| .{ a, b },
    //              ^ (@TypeOf(null))() TODO this should be `unknown`
    //                 ^ (unknown)()
    inline else => |a, b| .{ a, b },
    //              ^ (@TypeOf(null))() TODO this should be `unknown`
    //                 ^ (unknown)()
};
