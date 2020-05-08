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
pub fn getDocComments(allocator: *std.mem.Allocator, tree: *std.zig.ast.Tree, node: *std.zig.ast.Node) !?[]const u8 {
    switch (node.id) {
        .FnProto => {
            const func = node.cast(std.zig.ast.Node.FnProto).?;
            if (func.doc_comments) |doc_comments| {
                var doc_it = doc_comments.lines.iterator(0);
                var lines = std.ArrayList([]const u8).init(allocator);
                defer lines.deinit();

                while (doc_it.next()) |doc_comment| {
                    _ = try lines.append(std.fmt.trim(tree.tokenSlice(doc_comment.*)[3..]));
                }

                return try std.mem.join(allocator, "\n", lines.items);
            } else {
                return null;
            }
        },
        .VarDecl => {
            const var_decl = node.cast(std.zig.ast.Node.VarDecl).?;
            if (var_decl.doc_comments) |doc_comments| {
                var doc_it = doc_comments.lines.iterator(0);
                var lines = std.ArrayList([]const u8).init(allocator);
                defer lines.deinit();

                while (doc_it.next()) |doc_comment| {
                    _ = try lines.append(std.fmt.trim(tree.tokenSlice(doc_comment.*)[3..]));
                }

                return try std.mem.join(allocator, "\n", lines.items);
            } else {
                return null;
            }
        },
        else => return null
    }
}

/// Gets a function signature (keywords, name, return value)
pub fn getFunctionSignature(tree: *std.zig.ast.Tree, func: *std.zig.ast.Node.FnProto) []const u8 {
    const start = tree.tokens.at(func.firstToken()).start;
    const end = 
        if (func.body_node) |body| tree.tokens.at(body.firstToken()).start
        else tree.tokens.at(switch (func.return_type) {
            .Explicit, .InferErrorSet => |node| node.lastToken()
        }).end;
    return tree.source[start..end];
}

/// Gets a function signature (keywords, name, return value)
pub fn getVariableSignature(tree: *std.zig.ast.Tree, var_decl: *std.zig.ast.Node.VarDecl) []const u8 {
    const start = tree.tokens.at(var_decl.firstToken()).start;
    const end = tree.tokens.at(var_decl.semicolon_token).start;
    // var end = 
        // if (var_decl.init_n) |body| tree.tokens.at(body.firstToken()).start
        // else tree.tokens.at(var_decl.name_token).end;
    return tree.source[start..end];
}

// STYLE

pub fn isCamelCase(name: []const u8) bool {
    return !std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name, "_") == null;
}

pub fn isPascalCase(name: []const u8) bool {
    return std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name, "_") == null;
}
