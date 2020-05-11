const std = @import("std");

const ast = std.zig.ast;

/// REALLY BAD CODE, PLEASE DON'T USE THIS!!!!!!! (only for testing)
pub fn getFunctionByName(tree: *ast.Tree, name: []const u8) ?*ast.Node.FnProto {
    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {
        var decl = decl_ptr.*;
        switch (decl.id) {
            .FnProto => {
                const func = decl.cast(ast.Node.FnProto).?;
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
pub fn getDocComments(allocator: *std.mem.Allocator, tree: *ast.Tree, node: *ast.Node) !?[]const u8 {
    switch (node.id) {
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
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
            const var_decl = node.cast(ast.Node.VarDecl).?;
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
pub fn getFunctionSignature(tree: *ast.Tree, func: *ast.Node.FnProto) []const u8 {
    const start = tree.tokens.at(func.firstToken()).start;
    const end = tree.tokens.at(switch (func.return_type) {
        .Explicit, .InferErrorSet => |node| node.lastToken()
    }).end;
    return tree.source[start..end];
}

/// Gets a function snippet insert text
pub fn getFunctionSnippet(allocator: *std.mem.Allocator, tree: *ast.Tree, func: *ast.Node.FnProto) ![]const u8 {
    const name_tok = func.name_token orelse unreachable;

    var buffer = std.ArrayList(u8).init(allocator);
    try buffer.ensureCapacity(128);

    try buffer.appendSlice(tree.tokenSlice(name_tok));
    try buffer.append('(');

    var buf_stream = buffer.outStream();

    var param_num = @as(usize, 1);
    var param_it = func.params.iterator(0);
    while (param_it.next()) |param_ptr| : (param_num += 1) {
        const param = param_ptr.*;

        if (param_num != 1) try buffer.appendSlice(", ${")
        else try buffer.appendSlice("${");

        try buf_stream.print("{}:", .{param_num});
        var curr_tok = param.firstToken();
        const end_tok = param.lastToken();

        var first_tok = true;
        while (curr_tok <= end_tok) : (curr_tok += 1) {
            try buffer.appendSlice(tree.tokenSlice(curr_tok));
            if (!first_tok and curr_tok != end_tok) try buffer.append(' ')
            else first_tok = false;
        }

        try buffer.append('}');
    }
    try buffer.append(')');

    return buffer.toOwnedSlice();
}

/// Gets a function signature (keywords, name, return value)
pub fn getVariableSignature(tree: *ast.Tree, var_decl: *ast.Node.VarDecl) []const u8 {
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

// ANALYSIS ENGINE
// Very WIP, only works on global values at the moment

// TODO Major rework needed. This works in a sandbox, but not in the actual editor as completion
// stubs (e.g. "completeThis", "completeThis.", etc.) causes errors in the Zig parser.

pub fn getDecl(tree: *std.zig.ast.Tree, name: []const u8) ?*std.zig.ast.Node {
    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {
        var decl = decl_ptr.*;
        switch (decl.id) {
            .VarDecl => {
                const vari = decl.cast(std.zig.ast.Node.VarDecl).?;
                if (std.mem.eql(u8, tree.tokenSlice(vari.name_token), name)) return decl;
            },
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                if (func.name_token != null and std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return decl;
            },
            else => {}
        }
    }
    return null;
}

pub fn getContainerField(tree: *std.zig.ast.Tree, container: *std.zig.ast.ContainerDecl, name: []const u8) ?*std.zig.ast.Node {
    var decls = container.decls.iterator(0);
    while (decls.next()) |decl_ptr| {
        var decl = decl_ptr.*;
        switch (decl.id) {
            .VarDecl => {
                const vari = decl.cast(std.zig.ast.Node.VarDecl).?;
                if (std.mem.eql(u8, tree.tokenSlice(vari.name_token), name)) return decl;
            },
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                if (func.name_token != null and std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return decl;
            },
            else => {}
        }
    }
    return null;
}

pub fn resolveNode(tree: *std.zig.ast.Tree, node: *std.zig.ast.Node) ?*std.zig.ast.Node {
    switch (node.id) {
        .Identifier => {
            var id = node.cast(std.zig.ast.Node.Identifier).?;
            var maybe_decl = getDecl(tree, tree.tokenSlice(id.token));
            if (maybe_decl) |decl| {
                return decl;
            }
        },
        else => {}
    }
    
    return null;
}

pub fn getCompletionsForValue(allocator: *std.mem.Allocator, tree: *std.zig.ast.Tree, node: *std.zig.ast.Node) ![]*std.zig.ast.Node {
    var nodes = std.ArrayList(*std.zig.ast.Node).init(allocator);

    switch (node.id) {
        .ContainerDecl => {
            var cont = node.cast(std.zig.ast.Node.ContainerDecl).?;
            var decl_it = cont.fields_and_decls.iterator(0);

            while (decl_it.next()) |decl| {
                try nodes.append(decl.*);
            }
        },
        .ContainerField => {
            var field = node.cast(std.zig.ast.Node.ContainerField).?;
            
        },
        .VarDecl => {
            var vari = node.cast(std.zig.ast.Node.VarDecl).?;
            // if (vari.type_node) |type_node| return getCompletionsForValue(allocator, tree, type_node);
            // if (vari.init_node) |init_node| return getCompletionsForValue(allocator, tree, init_node);
            return getCompletionsForValue(allocator, tree, vari.type_node orelse vari.init_node.?);
        },
        .Identifier => {
            var id = node.cast(std.zig.ast.Node.Identifier).?;
            var maybe_decl = getDecl(tree, tree.tokenSlice(id.token));
            if (maybe_decl) |decl| return getCompletionsForValue(allocator, tree, decl);
        },
        .FnProto => {
            var func = node.cast(std.zig.ast.Node.FnProto).?;
            // std.debug.warn("{}", .{func.return_type});
            switch (func.return_type) {
                .Explicit, .InferErrorSet => |return_node| {
                    if (resolveNode(tree, return_node)) |resolved_node| {
                        return getCompletionsForValue(allocator, tree, resolved_node);
                    }
                }
            }
        },
        .InfixOp => {
            var infix = node.cast(std.zig.ast.Node.InfixOp).?;

            // std.debug.warn("{}", .{infix});
            // switch (infix.op) {
            //     .Period => {
            //         std.debug.warn("\n{}.{}\n", .{
            //             getCompletionsForValue(allocator, tree, infix.lhs),
            //             infix.rhs
            //         });
            //         return getCompletionsForValue(allocator, tree, infix.lhs);
            //     },
            //     else => {}
            // }
        },
        .SuffixOp => {
            var suffix = node.cast(std.zig.ast.Node.SuffixOp).?;

            // std.debug.warn("{}", .{suffix});

            switch (suffix.op) {
                .Call => {
                    if (resolveNode(tree, suffix.lhs.node)) |rnode| {
                        return getCompletionsForValue(allocator, tree, rnode);
                    }
                },
                else => {}
            }
        },
        else => {
            std.debug.warn("{}\n\n", .{node.id});
        }
    }

    return nodes.toOwnedSlice();
}
