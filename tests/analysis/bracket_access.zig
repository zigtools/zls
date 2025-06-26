// Also see:
// - array.zig
// - builtins.zig
// - string_literal.zig

const foo: type = undefined;
const bar = foo[5];
//    ^^^ (unknown)()
