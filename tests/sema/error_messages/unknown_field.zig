const S = struct {
    alpha: void,
    beta: void,
};

const s: S = undefined;
//    ^ (S)(undefined)
const alpha = s.alpha;
//    ^^^^^ (void)(undefined)
const gamma = s.gamma;
//            ^^^^^^^ error: 'S' has no member 'gamma'
const beta = s.beta;
//    ^^^^ (void)(undefined)
