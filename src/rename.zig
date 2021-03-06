const std = @import("std");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const references = @import("references.zig");
const types = @import("types.zig");
const offsets = @import("offsets.zig");

const ast = std.zig.ast;

// TODO Use a map to array lists and collect at the end instead?
const RefHandlerContext = struct {
    edits: *std.StringHashMap([]types.TextEdit),
    allocator: *std.mem.Allocator,
    new_name: []const u8,
};

fn refHandler(context: RefHandlerContext, loc: types.Location) !void {
    var text_edits = if (context.edits.get(loc.uri)) |slice|
        std.ArrayList(types.TextEdit).fromOwnedSlice(context.allocator, slice)
    else
        std.ArrayList(types.TextEdit).init(context.allocator);

    (try text_edits.addOne()).* = .{
        .range = loc.range,
        .newText = context.new_name,
    };
    try context.edits.put(loc.uri, text_edits.toOwnedSlice());
}

pub fn renameSymbol(
    arena: *std.heap.ArenaAllocator,
    store: *DocumentStore,
    decl_handle: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.StringHashMap([]types.TextEdit),
    encoding: offsets.Encoding,
) !void {
    std.debug.assert(decl_handle.decl.* != .label_decl);
    try references.symbolReferences(arena, store, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = &arena.allocator,
        .new_name = new_name,
    }, refHandler, true);
}

pub fn renameLabel(
    arena: *std.heap.ArenaAllocator,
    decl_handle: analysis.DeclWithHandle,
    new_name: []const u8,
    edits: *std.StringHashMap([]types.TextEdit),
    encoding: offsets.Encoding,
) !void {
    std.debug.assert(decl_handle.decl.* == .label_decl);
    try references.labelReferences(arena, decl_handle, encoding, true, RefHandlerContext{
        .edits = edits,
        .allocator = &arena.allocator,
        .new_name = new_name,
    }, refHandler);
}
