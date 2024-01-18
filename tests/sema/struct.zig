pub const SomeStruct = struct {};
//        ^^^^^^^^^^ (type)(SomeStruct)

pub const OtherStruct = struct { alpha: u32 };
//        ^^^^^^^^^^^ (type)(OtherStruct)

const other_struct: OtherStruct = undefined;
//    ^^^^^^^^^^^^ (OtherStruct)()
const alpha = other_struct.alpha;
//    ^^^^^ (u32)()

const OuterStruct = struct {
    const InnerStruct = struct {
        const T = u32;
        //    ^ (type)(u32)
    };
    const V = ?u0;
    //    ^ (type)(?u0)
};

const some_struct_init = SomeStruct{};
//    ^^^^^^^^^^^^^^^^ (SomeStruct)()

const other_struct_init = OtherStruct{ .alpha = 5 };
//    ^^^^^^^^^^^^^^^^^ (OtherStruct)()
