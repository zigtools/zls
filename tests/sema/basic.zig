const alpha: bool = true;
//    ^^^^^ (bool)(true)
const beta: bool = false;
//    ^^^^ (bool)(false)
const gamma: type = bool;
//    ^^^^^ (type)(bool)
const delta: comptime_int = 4;
//    ^^^^^ (comptime_int)(4)
const epsilon = null;
//    ^^^^^^^ (@TypeOf(null))(null)
const zeta: type = u32;
//    ^^^^ (type)(u32)
const eta: type = isize;
//    ^^^ (type)(isize)
const theta = true;
//    ^^^^^ (bool)(true)
const iota = false;
//    ^^^^ (bool)(false)
const kappa = bool;
//    ^^^^^ (type)(bool)
const lambda = 4;
//    ^^^^^^ (comptime_int)(4)
const mu = undefined;
//    ^^ (@TypeOf(undefined))(undefined)
const nu: type = i1;
//    ^^ (type)(i1)
const xi: type = usize;
//    ^^ (type)(usize)
const omicron = 0;
//    ^^^^^^^ ()()
const pi = 3.14159;
//    ^^ (comptime_float)(3.14159)
const rho: type = anyopaque;
//    ^^^ (type)(anyopaque)
const sigma = noreturn;
//    ^^^^^ (type)(noreturn)
const tau = anyerror;
//    ^^^ (type)(anyerror)
const upsilon = 0;
//    ^^^^^^^ ()()
const phi = 0;
//    ^^^ ()()
const chi = 0;
//    ^^^ ()()
const psi = 0;
//    ^^^ ()()
const omega = 0;
//    ^^^^^ ()()
