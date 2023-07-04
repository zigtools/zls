const std = @import("std");

const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");

pub fn printTree(tree: std.zig.Ast) void {
    if (!std.debug.runtime_safety) @compileError("this function should only be used in debug mode!");

    std.debug.print(
        \\
        \\nodes   tag                  lhs rhs token
        \\-----------------------------------------------
        \\
    , .{});
    for (
        tree.nodes.items(.tag),
        tree.nodes.items(.data),
        tree.nodes.items(.main_token),
        0..,
    ) |tag, data, main_token, i| {
        std.debug.print(
            "    {d:<3} {s:<20} {d:<3} {d:<3} {d:<3} {s}\n",
            .{ i, @tagName(tag), data.lhs, data.rhs, main_token, offsets.tokenToSlice(tree, main_token) },
        );
    }

    std.debug.print(
        \\
        \\tokens  tag                  start
        \\----------------------------------
        \\
    , .{});
    for (tree.tokens.items(.tag), tree.tokens.items(.start), 0..) |tag, start, i| {
        std.debug.print(
            "    {d:<3} {s:<20} {d:<}\n",
            .{ i, @tagName(tag), start },
        );
    }
}

pub fn printDocumentScope(doc_scope: analysis.DocumentScope) void {
    if (!std.debug.runtime_safety) @compileError("this function should only be used in debug mode!");

    for (0..doc_scope.scopes.len) |index| {
        const scope = doc_scope.scopes.get(index);
        if (index != 0) std.debug.print("\n\n", .{});
        std.debug.print(
            \\[{d}, {d}]
            \\  data: {}
            \\  parent: {}
            \\  child scopes: {any}
            \\  usingnamespaces: {any}
            \\  tests: {any}
            \\  decls:
            \\
        , .{
            scope.loc.start,
            scope.loc.end,
            scope.data,
            scope.parent,
            scope.child_scopes.items,
            scope.uses,
            scope.tests,
        });

        var decl_it = scope.decls.iterator();
        while (decl_it.next()) |entry| {
            std.debug.print("    - {s:<8} {}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
    }
}

pub const FailingAllocator = struct {
    internal_allocator: std.mem.Allocator,
    random: std.rand.DefaultPrng,
    likelihood: u32,

    /// the chance that an allocation will fail is `1/likelihood`
    /// `likelihood == 0` means that every allocation will fail
    /// `likelihood == std.math.intMax(u32)` means that no allocation will be forced to fail
    pub fn init(internal_allocator: std.mem.Allocator, likelihood: u32) FailingAllocator {
        var seed = std.mem.zeroes([8]u8);
        std.os.getrandom(&seed) catch {};

        return FailingAllocator{
            .internal_allocator = internal_allocator,
            .random = std.rand.DefaultPrng.init(@bitCast(seed)),
            .likelihood = likelihood,
        };
    }

    pub fn allocator(self: *FailingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        log2_ptr_align: u8,
        return_address: usize,
    ) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (shouldFail(self)) return null;
        return self.internal_allocator.rawAlloc(len, log2_ptr_align, return_address);
    }

    fn resize(
        ctx: *anyopaque,
        old_mem: []u8,
        log2_old_align: u8,
        new_len: usize,
        ra: usize,
    ) bool {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.internal_allocator.rawResize(old_mem, log2_old_align, new_len, ra))
            return false;
        return true;
    }

    fn free(
        ctx: *anyopaque,
        old_mem: []u8,
        log2_old_align: u8,
        ra: usize,
    ) void {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        self.internal_allocator.rawFree(old_mem, log2_old_align, ra);
    }

    fn shouldFail(self: *FailingAllocator) bool {
        if (self.likelihood == std.math.maxInt(u32)) return false;
        return 0 == self.random.random().intRangeAtMostBiased(u32, 0, self.likelihood);
    }
};

comptime {
    if (std.debug.runtime_safety) {
        std.testing.refAllDeclsRecursive(@This());
    }
}
