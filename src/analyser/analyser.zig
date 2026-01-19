pub const completions = @import("completions.zig");
pub const InternPool = @import("InternPool.zig");
pub const string_pool = @import("string_pool.zig");
pub const StringPool = string_pool.StringPool;
pub const degibberish = @import("degibberish.zig");

comptime {
    const std = @import("std");
    std.testing.refAllDecls(completions);
    std.testing.refAllDecls(InternPool);
    std.testing.refAllDecls(string_pool);
    std.testing.refAllDecls(degibberish);
}
