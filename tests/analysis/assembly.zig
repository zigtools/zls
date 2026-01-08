const assembly = asm ("" ::: .{ .memory = true });
//                           ^ (either type)()
//                              ^^^^^^^ (bool)()
