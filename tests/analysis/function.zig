fn func() addrspace(.generic) linksection(.{}) callconv(.auto) void {}
//                  ^^^^^^^^ (AddressSpace)()
//                                        ^ ([]const u8)()
//                                                      ^^^^^ (void)()
