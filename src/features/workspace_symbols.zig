const std = @import("std");
const DeclarationIndex = @import("../analysis.zig").Declaration.Index;

/// Asserts `@min(a.len, b.len) <= out.len`.
pub fn mergeIntersection(a: []const DeclarationIndex, b: []const DeclarationIndex, out: []DeclarationIndex) u32 {
    std.debug.assert(@min(a.len, b.len) <= out.len);

    var out_idx: u32 = 0;

    var a_idx: u32 = 0;
    var b_idx: u32 = 0;

    while (a_idx < a.len and b_idx < b.len) {
        const a_val = a[a_idx];
        const b_val = b[b_idx];

        if (a_val == b_val) {
            out[out_idx] = a_val;
            out_idx += 1;
            a_idx += 1;
            b_idx += 1;
        } else if (@intFromEnum(a_val) < @intFromEnum(b_val)) {
            a_idx += 1;
        } else {
            b_idx += 1;
        }
    }

    return out_idx;
}
