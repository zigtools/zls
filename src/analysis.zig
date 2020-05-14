const std = @import("std");
const AnalysisContext = @import("document_store.zig").AnalysisContext;
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
        const param_decl = param.cast(ast.Node.ParamDecl).?;

        if (param_num != 1) try buffer.appendSlice(", ${")
        else try buffer.appendSlice("${");

        try buf_stream.print("{}:", .{param_num});

        if (param_decl.comptime_token) |_| {
            try buffer.appendSlice("comptime ");
        }

        if (param_decl.noalias_token) |_| {
            try buffer.appendSlice("noalias ");
        }

        if (param_decl.name_token) |name_token| {
            try buffer.appendSlice(tree.tokenSlice(name_token));
            try buffer.appendSlice(": ");
        }

        if (param_decl.var_args_token) |_| {
            try buffer.appendSlice("...");
            continue;
        }

        var curr_tok = param_decl.type_node.firstToken();
        var end_tok = param_decl.type_node.lastToken();
        while (curr_tok <= end_tok) : (curr_tok += 1) {
            const id = tree.tokens.at(curr_tok).id;
            const is_comma = tree.tokens.at(curr_tok).id == .Comma;

            if (curr_tok == end_tok and is_comma) continue;

            try buffer.appendSlice(tree.tokenSlice(curr_tok));
            if (is_comma or id == .Keyword_const) try buffer.append(' ');
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

/// Gets the child of node
pub fn getChild(tree: *ast.Tree, node: *ast.Node, name: []const u8) ?*ast.Node {
    var index: usize = 0;
    while (node.iterate(index)) |child| {
        switch (child.id) {
            .VarDecl => {
                const vari = child.cast(ast.Node.VarDecl).?;
                if (std.mem.eql(u8, tree.tokenSlice(vari.name_token), name)) return child;
            },
            .FnProto => {
                const func = child.cast(ast.Node.FnProto).?;
                if (func.name_token != null and std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return child;
            },
            .ContainerField => {
                const field = child.cast(ast.Node.ContainerField).?;
                if (std.mem.eql(u8, tree.tokenSlice(field.name_token), name)) return child;
            },
            else => {}
        }
        index += 1;
    }
    return null;
}

/// Resolves the type of a node
pub fn resolveTypeOfNode(analysis_ctx: *AnalysisContext, node: *ast.Node) ?*ast.Node {
    switch (node.id) {
        .VarDecl => {
            const vari = node.cast(ast.Node.VarDecl).?;
            return resolveTypeOfNode(analysis_ctx, vari.type_node orelse vari.init_node.?) orelse null;
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
            switch (func.return_type) {
                .Explicit, .InferErrorSet => |return_type| return resolveTypeOfNode(analysis_ctx, return_type),
            }
        },
        .Identifier => {
            if (getChild(analysis_ctx.tree, &analysis_ctx.tree.root_node.base, analysis_ctx.tree.getNodeSource(node))) |child| {
                return resolveTypeOfNode(analysis_ctx, child);
            } else return null;
        },
        .ContainerDecl => {
            return node;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return resolveTypeOfNode(analysis_ctx, field.type_expr.?);
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            switch (suffix_op.op) {
                .Call => {
                    return resolveTypeOfNode(analysis_ctx, suffix_op.lhs.node);
                },
                else => {}
            }
        },
        .InfixOp => {
            const infix_op = node.cast(ast.Node.InfixOp).?;
            switch (infix_op.op) {
                .Period => {
                    // Save the child string from this tree since the tree may switch when processing
                    // an import lhs.
                    var rhs_str = nodeToString(analysis_ctx.tree, infix_op.rhs) orelse return null;
                    // Use the analysis context temporary arena to store the rhs string.
                    rhs_str = std.mem.dupe(&analysis_ctx.arena.allocator, u8, rhs_str) catch return null;
                    const left = resolveTypeOfNode(analysis_ctx, infix_op.lhs) orelse return null;
                    return getChild(analysis_ctx.tree, left, rhs_str);
                },
                else => {}
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .PtrType => {
                    return resolveTypeOfNode(analysis_ctx, prefix_op.rhs);
                },
                else => {}
            }
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            if (!std.mem.eql(u8, analysis_ctx.tree.tokenSlice(builtin_call.builtin_token), "@import")) return null;
            if (builtin_call.params.len > 1) return null;

            const import_param = builtin_call.params.at(0).*;
            if (import_param.id != .StringLiteral) return null;

            const import_str = analysis_ctx.tree.tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
            return analysis_ctx.onImport(import_str[1 .. import_str.len - 1]) catch |err| block: {
                std.debug.warn("Error {} while proessing import {}\n", .{err, import_str});
                break :block null;
            };
        },
        else => {
            std.debug.warn("Type resolution case not implemented; {}\n", .{node.id});
        }
    }
    return null;
}

fn maybeCollectImport(tree: *ast.Tree, builtin_call: *ast.Node.BuiltinCall, arr: *std.ArrayList([]const u8)) !void {
    if (!std.mem.eql(u8, tree.tokenSlice(builtin_call.builtin_token), "@import")) return;
    if (builtin_call.params.len > 1) return;

    const import_param = builtin_call.params.at(0).*;
    if (import_param.id != .StringLiteral) return;

    const import_str = tree.tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
    try arr.append(import_str[1 .. import_str.len - 1]);
}

/// Collects all imports we can find into a slice of import paths (without quotes).
/// The import paths are valid as long as the tree is.
pub fn collectImports(allocator: *std.mem.Allocator, tree: *ast.Tree) ![][]const u8 {
    // TODO: Currently only detects `const smth = @import("string literal")<.SometThing>;`
    var arr = std.ArrayList([]const u8).init(allocator);

    var idx: usize = 0;
    while (tree.root_node.iterate(idx)) |decl| : (idx += 1) {
        if (decl.id != .VarDecl) continue;
        const var_decl = decl.cast(ast.Node.VarDecl).?;
        if (var_decl.init_node == null) continue;
    
        switch(var_decl.init_node.?.id) {
            .BuiltinCall => {
                const builtin_call = var_decl.init_node.?.cast(ast.Node.BuiltinCall).?;
                try maybeCollectImport(tree, builtin_call, &arr);
            },
            .InfixOp => {
                const infix_op = var_decl.init_node.?.cast(ast.Node.InfixOp).?;
                
                switch(infix_op.op) {
                    .Period => {},
                    else => continue,
                }
                if (infix_op.lhs.id != .BuiltinCall) continue;
                try maybeCollectImport(tree, infix_op.lhs.cast(ast.Node.BuiltinCall).?, &arr);
            },
            else => {},
        }
    }

    return arr.toOwnedSlice();
}

pub fn getFieldAccessTypeNode(analysis_ctx: *AnalysisContext, tokenizer: *std.zig.Tokenizer) ?*ast.Node {
    var current_node = &analysis_ctx.tree.root_node.base;

    while (true) {
        var next = tokenizer.next();
        switch (next.id) {
            .Eof => {
                return current_node;
            },
            .Identifier => {
                // var root = current_node.cast(ast.Node.Root).?;
                // current_node.
                if (getChild(analysis_ctx.tree, current_node, tokenizer.buffer[next.start..next.end])) |child| {
                    if (resolveTypeOfNode(analysis_ctx, child)) |node_type| {
                        current_node = node_type;
                    } else return null;
                } else return null;
            },
            .Period => {
                var after_period = tokenizer.next();
                if (after_period.id == .Eof) {
                    return current_node;
                } else if (after_period.id == .Identifier) {
                    if (getChild(analysis_ctx.tree, current_node, tokenizer.buffer[after_period.start..after_period.end])) |child| {
                        if (resolveTypeOfNode(analysis_ctx, child)) |child_type| {
                            current_node = child_type;
                        } else return null;
                    } else return null;
                }
            },
            else => {
                std.debug.warn("Not implemented; {}\n", .{next.id});
            }
        }
    }

    return current_node;
}

pub fn getCompletionsFromNode(allocator: *std.mem.Allocator, tree: *ast.Tree, node: *ast.Node) ![]*ast.Node {
    var nodes = std.ArrayList(*ast.Node).init(allocator);

    var index: usize = 0;
    while (node.iterate(index)) |child_node| {
        try nodes.append(child_node);
    
        index += 1;
    }

    return nodes.items;
}

pub fn nodeToString(tree: *ast.Tree, node: *ast.Node) ?[]const u8 {
    switch (node.id) {
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return tree.tokenSlice(field.name_token);
        },
        .Identifier => {
            const field = node.cast(ast.Node.Identifier).?;
            return tree.tokenSlice(field.token);
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
            if (func.name_token) |name_token| {
                return tree.tokenSlice(name_token);
            }
        },
        else => {
            std.debug.warn("INVALID: {}\n", .{node.id});
        }
    }
    
    return null;
}

pub fn nodesToString(tree: *ast.Tree, maybe_nodes: ?[]*ast.Node) void {
    if (maybe_nodes) |nodes| {
        for (nodes) |node| {
            std.debug.warn("- {}\n", .{nodeToString(tree, node)});
        }
    } else std.debug.warn("No nodes\n", .{});
}
