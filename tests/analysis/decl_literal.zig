const StructType = struct {
    foo: i32,
    bar: i64,
    const baz: StructType = .{ .foo = 1, .bar = 2 };
};

const EnumType = enum {
    foo,
    bar,
    const baz: EnumType = .foo;
};

const UnionType = union {
    foo: i32,
    bar: i64,
    const baz: UnionType = .{ .foo = 1 };
};

const TaggedUnionType = union(EnumType) {
    foo: i32,
    bar: i64,
    const baz: TaggedUnionType = .{ .foo = 1 };
};

const some_struct: StructType = .baz;
//                              ^^^^ (StructType)()

const some_enum: EnumType = .baz;
//                          ^^^^ (EnumType)()

const some_union: UnionType = .baz;
//                            ^^^^ (UnionType)()

const some_tagged_union: TaggedUnionType = .baz;
//                                         ^^^^ (TaggedUnionType)()
