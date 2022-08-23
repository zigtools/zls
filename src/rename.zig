const std = @import("std");
const DocumentStore = @import("DocumentStore.zig");
const analysis = @import("analysis.zig");
const references = @import("references.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");

// TODO Use a map to array lists and collect at the end instead?
const RefHandlerContext = struct {
    allocator: std.mem.Allocator,
    edits: *std.StringHashMapUnmanaged([]types.TextEdit),
    new_name: []const u8,
};

fn refHandler(context: RefHandlerContext, loc: types.Location) !void {
    var text_edits = if (context.edits.get(loc.uri)) |slice|
        std.ArrayListUnmanaged(types.TextEdit){ .items = slice }
    else
        std.ArrayListUnmanaged(types.TextEdit){};

    (try text_edits.addOne(context.allocator)).* = .{
        .range = loc.range,
        .newText = context.new_name,
    };
    try context.edits.put(context.allocator, loc.uri, text_edits.toOwnedSlice(context.allocator));
}

pub fn renameSymbol(arena: *std.heap.ArenaAllocator, store: *DocumentStore, decl_handle: analysis.DeclWithHandle, new_name: []const u8, edits: *std.StringHashMapUnmanaged([]types.TextEdit), encoding: offsets.Encoding) !void {
    std.debug.assert(decl_handle.decl.* != .label_decl);
    try references.symbolReferences(arena, store, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = arena.allocator(),
        .new_name = new_name,
    }, refHandler, true, true);
}

pub fn renameLabel(arena: *std.heap.ArenaAllocator, decl_handle: analysis.DeclWithHandle, new_name: []const u8, edits: *std.StringHashMapUnmanaged([]types.TextEdit), encoding: offsets.Encoding) !void {
    std.debug.assert(decl_handle.decl.* == .label_decl);
    try references.labelReferences(arena, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = arena.allocator(),
        .new_name = new_name,
    }, refHandler);
}
