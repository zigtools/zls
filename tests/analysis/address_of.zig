const StructType = struct {
    foo: i32,
};

const some_struct: StructType = .{ .foo = 1 };

var mutable_struct: StructType = .{ .foo = 1 };

const some_struct_pointer = &some_struct;
//    ^^^^^^^^^^^^^^^^^^^ (*const StructType)()

const mutable_struct_pointer = &mutable_struct;
//    ^^^^^^^^^^^^^^^^^^^^^^ (*StructType)()

const some_struct_pointer_pointer = &&some_struct;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*const *const StructType)()

const mutable_struct_pointer_pointer = &&mutable_struct;
//    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (*const *StructType)()
