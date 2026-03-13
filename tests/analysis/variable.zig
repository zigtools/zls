const variable addrspace(.generic) linksection(.{}) = 0;
//                       ^^^^^^^^ (AddressSpace)()
//                                             ^ ([]const u8)()

var bool_var = true;
//  ^^^^^^^^ (bool)((unknown value))
