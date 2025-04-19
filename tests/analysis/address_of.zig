const StructType = struct {
    foo: i32,
    const const_decl: bool = true;
    var var_decl: bool = false;
};

const UnionType = union {
    foo: i32,
    const const_decl: bool = true;
    var var_decl: bool = false;
};

const EnumType = enum {
    foo,
    const const_decl: bool = true;
    var var_decl: bool = false;
};

const TaggedUnionType = union(EnumType) {
    foo: i32,
    const const_decl: bool = true;
    var var_decl: bool = false;
};

const some_struct: StructType = .{ .foo = 1 };

var mutable_struct: StructType = .{ .foo = 1 };

const some_struct_pointer = &some_struct;
//    ^^^^^^^^^^^^^^^^^^^ (*const StructType)()

const mutable_struct_pointer = &mutable_struct;
//    ^^^^^^^^^^^^^^^^^^^^^^ (*StructType)()

const some_field_pointer = &some_struct.foo;
//    ^^^^^^^^^^^^^^^^^^ (*const i32)()

const mutable_field_pointer = &mutable_struct.foo;
//    ^^^^^^^^^^^^^^^^^^^^^ (*i32)()

const struct_field_pointer = &StructType.foo;
//    ^^^^^^^^^^^^^^^^^^^^ (unknown)()

const struct_const_decl_pointer = &StructType.const_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (*const bool)()

const struct_var_decl_pointer = &StructType.var_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^ (*bool)()

const union_field_pointer = &UnionType.foo;
//    ^^^^^^^^^^^^^^^^^^^ (unknown)()

const union_const_decl_pointer = &UnionType.const_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (*const bool)()

const union_var_decl_pointer = &UnionType.var_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^ (*bool)()

const enum_value_pointer = &EnumType.foo;
//    ^^^^^^^^^^^^^^^^^^ (*const EnumType)()

const enum_const_decl_pointer = &EnumType.const_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^ (*const bool)()

const enum_var_decl_pointer = &EnumType.var_decl;
//    ^^^^^^^^^^^^^^^^^^^^^ (*bool)()

const tagged_union_tag_pointer = &TaggedUnionType.foo;
//    ^^^^^^^^^^^^^^^^^^^^^^^^ (*const EnumType)()

const tagged_union_const_decl_pointer = &TaggedUnionType.const_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*const bool)()

const tagged_union_var_decl_pointer = &TaggedUnionType.var_decl;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*bool)()
