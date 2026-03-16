const std = @import("std");

const EnumA = enum {
    foo,
    bar,
};

const TaggedUnionA = union(EnumA) {
    foo: u8,
    bar: i32,
};

const TaggedUnionB = union(enum) {
    fizz: u16,
    buzz: i64,
};

const TagA = std.meta.Tag(TaggedUnionA);
//    ^^^^ (type)(EnumA)

const TagB = std.meta.Tag(TaggedUnionB);
//    ^^^^ (type)(@typeInfo(TaggedUnionB).@"union".tag_type.?)

const tag_a: TagA = .foo;
//                  ^^^^ (EnumA)()

const tag_b: TagB = .fizz;
//                  ^^^^^ (@typeInfo(TaggedUnionB).@"union".tag_type.?)()

const ArgsTupleA = std.meta.ArgsTuple(fn (u8, i32) void);
//    ^^^^^^^^^^ (type)(struct { u8, i32 })

fn function(_: u16, _: i64) void {}

const ArgsTupleB = std.meta.ArgsTuple(@TypeOf(function));
//    ^^^^^^^^^^ (type)(struct { u16, i64 })
