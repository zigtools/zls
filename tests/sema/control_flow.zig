const alpha = blk: {
    //^^^^^ (comptime_int)(3)
    break :blk 3;
};

const beta = blk: {
    //^^^^ (bool)(false)
    if (true) {
        break :blk false;
    } else {
        break :blk true;
    }
};

const gamma = blk: {
    //^^^^^ (@TypeOf(null))(null)
    if (true) {
        break :blk null;
    } else {
        break :blk true;
    }
};

const delta = blk: {
    //^^^^^ ()()
    if (false) {
        break :blk false;
    }
    unreachable;
};

// TODO
// const epsilon = blk: {
//     //^^^^^^^ (?bool)((unknown value))
//     const unknown: bool = undefined;
//     if (unknown) {
//         break :blk null;
//     } else {
//         break :blk true;
//     }
// };
