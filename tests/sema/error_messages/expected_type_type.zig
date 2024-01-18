const a: true = 5;
//       ^^^^ error: expected type 'type', found 'bool'
// TODO: add suggestion to replace `true` with `comptime_int` based on the init expression

const b: null = null;
//       ^^^^ error: expected type 'type', found '@TypeOf(null)'

const d = []const 5;
//                ^ error: expected type 'type', found 'comptime_int'

const e = anyframe->true;
//                  ^^^^ error: expected type 'type', found 'bool'

const f = ?2;
//         ^ error: expected type 'type', found 'comptime_int'

const G = struct {
    alpha: 52,
    //     ^^ error: expected type 'type', found 'comptime_int'
};

comptime {
    _ = @as(G, undefined).alpha; // force field resolution of G
}
