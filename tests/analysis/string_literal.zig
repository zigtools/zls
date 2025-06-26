const string_literal_0 = "ipsum lorem";
//    ^^^^^^^^^^^^^^^^ (*const [11:0]u8)()

const string_literal_1 =
    //^^^^^^^^^^^^^^^^ (*const [11:0]u8)()
    \\ipsum lorem
;

const string_literal_2 =
    //^^^^^^^^^^^^^^^^ (*const [28:0]u8)()
    \\ipsum lorem
    \\\\dolor sit amet
;

const string_literal_3 = "hello".*;
//    ^^^^^^^^^^^^^^^^ ([5:0]u8)()

const string_literal_0_indexing = string_literal_0[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

const string_literal_1_indexing = string_literal_1[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

const string_literal_2_indexing = string_literal_2[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

const string_literal_3_indexing = string_literal_3[0];
//    ^^^^^^^^^^^^^^^^^^^^^^^^^ (u8)()

pub fn main() void {
    for (string_literal_0) |elem| {
        _ = elem;
        //  ^^^^ (u8)()
    }

    for (string_literal_1) |elem| {
        _ = elem;
        //  ^^^^ (u8)()
    }

    for (string_literal_2) |elem| {
        _ = elem;
        //  ^^^^ (u8)()
    }

    for (string_literal_3) |elem| {
        _ = elem;
        //  ^^^^ (u8)()
    }
}
