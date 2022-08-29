const std = @import("std");
const DocumentStore = @import("DocumentStore.zig");
const analysis = @import("analysis.zig");
const references = @import("references.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");

// TODO Use a map to array lists and collect at the end instead?
const RefHandlerContext = struct {
    allocator: std.mem.Allocator,
    edits: *std.StringHashMapUnmanaged(std.ArrayListUnmanaged(types.TextEdit)),
    new_name: []const u8,
};

fn refHandler(context: RefHandlerContext, loc: types.Location) !void {
    const gop = try context.edits.getOrPutValue(context.allocator, loc.uri, .{});
    try gop.value_ptr.append(context.allocator, .{
        .range = loc.range,
        .newText = context.new_name,
    });
}

pub fn renameSymbol(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    decl_handle: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.StringHashMapUnmanaged(std.ArrayListUnmanaged(types.TextEdit)),
    encoding: offsets.Encoding,
) !void {
    std.debug.assert(decl_handle.decl.* != .label_decl);
    try references.symbolReferences(arena, store, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = arena.allocator(),
        .new_name = new_name,
    }, refHandler, true, true);
}

pub fn renameLabel(
    arena: *std.heap.ArenaAllocator,
    decl_handle: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.StringHashMapUnmanaged(std.ArrayListUnmanaged(types.TextEdit)),
    encoding: offsets.Encoding,
) !void {
    std.debug.assert(decl_handle.decl.* == .label_decl);
    try references.labelReferences(arena, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = arena.allocator(),
        .new_name = new_name,
    }, refHandler);
}
