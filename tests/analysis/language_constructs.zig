fn func() addrspace(.generic) linksection(.{}) callconv(.auto) void {}
//                  ^^^^^^^^ (AddressSpace)()
//                                        ^ ([]const u8)()
//                                                      ^^^^^ (void)()
const variable addrspace(.generic) linksection(.{}) = 0;
//                       ^^^^^^^^ (AddressSpace)()
//                                             ^ ([]const u8)()

const pointer = [*:.{}]addrspace(.generic) const struct {};
//                 ^ (struct {})()
//                               ^^^^^^^^ (AddressSpace)()
const array = [0:.{}]struct {};
//               ^ (struct {})()

const assembly = asm ("" ::: .{ .memory = true });
//                           ^ (either type)()
//                              ^^^^^^^ (bool)()
