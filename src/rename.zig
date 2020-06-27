const std = @import("std");
const DocumentStore = @import("document_store.zig");
const analysis = @import("analysis.zig");
const types = @import("types.zig");

fn renameToken(handle: *DocumentStore.Handle, tok: std.zig.ast.TokenIndex, new_name: []const u8, edits: *std.ArrayList(types.TextEdit)) !void {
    // const handle.tree.tokenLocation(start_index: usize, token: Token.Loc)
    const loc = handle.tree.tokenLocation(0, tok);
    (try edits.addOne()).* = .{
        .range = .{
            .start = .{
                .line = @intCast(types.Integer, loc.line),
                .character = @intCast(types.Integer, loc.column),
            },
            .end = .{
                .line = @intCast(types.Integer, loc.line),
                .character = @intCast(types.Integer, loc.column + handle.tree.token_locs[tok].end - handle.tree.token_locs[tok].start),
            },
        },
        .newText = new_name,
    };
}

pub fn renameLabel(arena: *std.heap.ArenaAllocator, decl: analysis.DeclWithHandle, new_name: []const u8, edits: *std.StringHashMap([]types.TextEdit)) !void {
    std.debug.assert(decl.decl.* == .label_decl);
    const handle = decl.handle;

    var text_edits = std.ArrayList(types.TextEdit).init(&arena.allocator);

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.decl.label_decl.firstToken();
    const last_tok = decl.decl.label_decl.lastToken();

    // The first token is always going to be the label
    try renameToken(handle, first_tok, new_name, &text_edits);

    var curr_tok = first_tok + 1;
    while (curr_tok < last_tok - 2) : (curr_tok += 1) {
        if (handle.tree.token_ids[curr_tok] == .Keyword_break and handle.tree.token_ids[curr_tok + 1] == .Colon and
            handle.tree.token_ids[curr_tok + 2] == .Identifier)
        {
            if (std.mem.eql(u8, handle.tree.tokenSlice(curr_tok + 2), handle.tree.tokenSlice(first_tok))) {
                try renameToken(handle, curr_tok + 2, new_name, &text_edits);
            }
        }
    }

    try edits.putNoClobber(handle.uri(), text_edits.items);
}
