const std = @import("std");

/// REALLY BAD CODE, PLEASE DON'T USE THIS!!!!!!! (only for testing)
pub fn getFunctionByName(tree: *std.zig.ast.Tree, name: []const u8) ?*std.zig.ast.Node.FnProto {
    
    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {

        var decl = decl_ptr.*;
        switch (decl.id) {
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                if (std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return func;
            },
            else => {}
        }

    }

    return null;

}

/// Gets a function's doc comments, caller must free memory when a value is returned
/// Like:
///```zig
///var comments = getFunctionDocComments(allocator, tree, func);
///defer if (comments) |comments_pointer| allocator.free(comments_pointer);
///```
pub fn getFunctionDocComments(allocator: *std.mem.Allocator, tree: *std.zig.ast.Tree, func: *std.zig.ast.Node.FnProto) !?[]const u8 {

    if (func.doc_comments) |doc_comments| {
        var doc_it = doc_comments.lines.iterator(0);
        var lines = std.ArrayList([]const u8).init(allocator);

        while (doc_it.next()) |doc_comment| {
            _ = try lines.append(std.fmt.trim(tree.tokenSlice(doc_comment.*)[3..]));
        }

        return try std.mem.join(allocator, "\n", lines.toOwnedSlice());
    } else {
        return null;
    }

}
