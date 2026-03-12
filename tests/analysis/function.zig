fn func() addrspace(.generic) linksection(.{}) callconv(.auto) void {}
//                  ^^^^^^^^ (AddressSpace)()
//                                        ^ ([]const u8)()
//                                                      ^^^^^ (void)()

// zig fmt: off
fn Unknown() type { return undefined.Unknown; }
// ^^^^^^^ (fn () type)()
// zig fmt: on

const UnknownCall = Unknown();
//    ^^^^^^^^^^^ (type)((unknown type))
