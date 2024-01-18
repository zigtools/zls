const alpha = switch (true) {
    //^^^^^ (bool)(false)
    true => false,
    false => true,
};

const beta = switch (false) {
    //^^^^ (bool)(true)
    true => false,
    false => true,
};

const gamma = switch (true) {
    //^^^^^ (bool)(false)
    true => false,
    else => true,
};

const delta = switch (false) {
    //^^^^^ (bool)(true)
    true => false,
    else => true,
};

const epsilon = switch (0) {
    //^^^^^^^ (comptime_int)(1)
    0 => 1,
    else => 0,
};

const zeta = switch (0) {
    //^^^^ (comptime_int)(1)
    else => 1,
};

const eta = switch (@as(u8, 1)) {
    //^^^ (u16)(1)
    0 => @as(u32, 0),
    1 => @as(u16, 1),
    else => @as(u8, 3),
};

const theta = switch (@as(u32, 2)) {
    //^^^^^ (u8)(3)
    0 => @as(u32, 0),
    1 => @as(u16, 1),
    else => @as(u8, 3),
};
