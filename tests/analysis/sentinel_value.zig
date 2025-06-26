const array = [_:0]u8{ 1, 2, 3, 4 };
//    ^^^^^ ([4:0]u8)()

const slice0: [:0]i1 = undefined;
//    ^^^^^^ ([:0]i1)()

const slice1: [:42]u8 = undefined;
//    ^^^^^^ ([:42]u8)()

const slice2 = array[0..2];
//    ^^^^^^ (*const [2]u8)()

const slice3 = array[1..];
//    ^^^^^^ (*const [3:0]u8)()

const hw = "Hello, World!";
//    ^^ (*const [13:0]u8)()

const h = hw[0..5];
//    ^ (*const [5]u8)()

const w = hw[7..];
//    ^ (*const [6:0]u8)()
