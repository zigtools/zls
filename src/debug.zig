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
    var i: usize = 0;
    while (i < tree.nodes.len) : (i += 1) {
        std.debug.print("    {d:<3} {s:<20} {d:<3} {d:<3} {d:<3} {s}\n", .{
            i,
            @tagName(tree.nodes.items(.tag)[i]),
            tree.nodes.items(.data)[i].lhs,
            tree.nodes.items(.data)[i].rhs,
            tree.nodes.items(.main_token)[i],
            offsets.tokenToSlice(tree, tree.nodes.items(.main_token)[i]),
        });
    }

    std.debug.print(
        \\
        \\tokens  tag                  start
        \\----------------------------------
        \\
    , .{});
    i = 0;
    while (i < tree.tokens.len) : (i += 1) {
        std.debug.print("    {d:<3} {s:<20} {d:<}\n", .{
            i,
            @tagName(tree.tokens.items(.tag)[i]),
            tree.tokens.items(.start)[i],
        });
    }
}

pub fn printDocumentScope(doc_scope: analysis.DocumentScope) void {
    if (!std.debug.runtime_safety) @compileError("this function should only be used in debug mode!");

    for (doc_scope.scopes.items) |scope, i| {
        if (i != 0) std.debug.print("\n\n", .{});
        std.debug.print(
            \\[{d}, {d}] {}
            \\usingnamespaces: {d}
            \\Decls:
            \\
        , .{
            scope.loc.start,
            scope.loc.end,
            scope.data,
            scope.uses.items.len,
        });

        var decl_it = scope.decls.iterator();
        var idx: usize = 0;
        while (decl_it.next()) |entry| : (idx += 1) {
            std.debug.print("    {s:<8} {}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
    }
}
