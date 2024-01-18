const T: type = u32;
//    ^ (type)(u32)
const OptionalT = ?T;
//    ^^^^^^^^^ (type)(?u32)

// TODO lazy analysis for top-level declarations
const A = B;
//    ^ ()()
const B = u32;
//    ^ (type)(u32)
