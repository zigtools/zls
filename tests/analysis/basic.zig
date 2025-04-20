const alpha: bool = true;
//    ^^^^^ (bool)()
const beta: bool = false;
//    ^^^^ (bool)()
const gamma: type = bool;
//    ^^^^^ (type)(bool)
const delta: comptime_int = 4;
//    ^^^^^ (comptime_int)()
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
//    ^^^^^^ (comptime_int)()
const mu = undefined;
//    ^^ (@TypeOf(undefined))(undefined)
const nu: type = i1;
//    ^^ (type)(i1)
const xi: type = usize;
//    ^^ (type)(usize)
const omicron = 'e';
//    ^^^^^^^ (comptime_int)()
const pi = 3.14159;
//    ^^ (comptime_float)()
const rho: type = anyopaque;
//    ^^^ (type)(anyopaque)
const sigma = noreturn;
//    ^^^^^ (type)(noreturn)
const tau = anyerror;
//    ^^^ (type)(anyerror)
const upsilon = unreachable;
//    ^^^^^^^ (noreturn)()
const phi = {};
//    ^^^ (void)()
const chi = -lambda;
//    ^^^ (comptime_int)()
const psi = -%lambda;
//    ^^^ (comptime_int)()
const omega: @Vector(4, u32) = .{ 1, 2, 3, 4 };
//    ^^^^^ (@Vector(4,u32))()
