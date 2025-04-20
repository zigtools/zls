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
