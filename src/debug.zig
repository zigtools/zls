//! A set of helper functions that assist in debugging.

const std = @import("std");

const offsets = @import("offsets.zig");
const DocumentScope = @import("DocumentScope.zig");

pub fn printDocumentScope(doc_scope: DocumentScope) void {
    if (!std.debug.runtime_safety) @compileError("this function should only be used in debug mode!");

    for (0..doc_scope.scopes.len) |index| {
        const scope_index: DocumentScope.Scope.Index = @enumFromInt(index);
        const scope = doc_scope.scopes.get(index);
        if (index != 0) std.debug.print("\n\n", .{});
        std.debug.print(
            \\[{d}, {d}]
            \\  tag: {}
            \\  ast node: {?}
            \\  parent: {}
            \\  child scopes: {any}
            \\  usingnamespaces: {any}
            \\  decls:
            \\
        , .{
            scope.loc.start,
            scope.loc.end,
            scope.data.tag,
            doc_scope.getScopeAstNode(scope_index),
            doc_scope.getScopeParent(scope_index),
            doc_scope.getScopeChildScopesConst(scope_index),
            doc_scope.getScopeUsingnamespaceNodesConst(scope_index),
        });

        for (doc_scope.getScopeDeclarationsConst(scope_index)) |decl| {
            std.debug.print("    - {s:<8} {}\n", .{
                doc_scope.declaration_lookup_map.keys()[@intFromEnum(decl)].name,
                doc_scope.declarations.get(@intFromEnum(decl)),
            });
        }
    }
}

pub const FailingAllocator = struct {
    internal_allocator: std.mem.Allocator,
    random: std.Random.DefaultPrng,
    likelihood: u32,

    /// the chance that an allocation will fail is `1/likelihood`
    /// `likelihood == 0` means that every allocation will fail
    /// `likelihood == std.math.intMax(u32)` means that no allocation will be forced to fail
    pub fn init(internal_allocator: std.mem.Allocator, likelihood: u32) FailingAllocator {
        return .{
            .internal_allocator = internal_allocator,
            .random = .init(std.crypto.random.int(u64)),
            .likelihood = likelihood,
        };
    }

    pub fn allocator(self: *FailingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (shouldFail(self)) return null;
        return self.internal_allocator.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        return self.internal_allocator.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        return self.internal_allocator.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        self.internal_allocator.rawFree(memory, alignment, ret_addr);
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
