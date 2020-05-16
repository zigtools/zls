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
            else => {},
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
                return try collectDocComments(allocator, tree, doc_comments);
            }
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.doc_comments) |doc_comments| {
                return try collectDocComments(allocator, tree, doc_comments);
            }
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            if (field.doc_comments) |doc_comments| {
                return try collectDocComments(allocator, tree, doc_comments);
            }
        },
        .ErrorTag => {
            const tag = node.cast(ast.Node.ErrorTag).?;
            if (tag.doc_comments) |doc_comments| {
                return try collectDocComments(allocator, tree, doc_comments);
            }
        },
        .ParamDecl => {
            const param = node.cast(ast.Node.ParamDecl).?;
            if (param.doc_comments) |doc_comments| {
                return try collectDocComments(allocator, tree, doc_comments);
            }
        },
        else => {},
    }
    return null;
}

fn collectDocComments(allocator: *std.mem.Allocator, tree: *ast.Tree, doc_comments: *ast.Node.DocComment) ![]const u8 {
    var doc_it = doc_comments.lines.iterator(0);
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();

    while (doc_it.next()) |doc_comment| {
        _ = try lines.append(std.fmt.trim(tree.tokenSlice(doc_comment.*)[3..]));
    }

    return try std.mem.join(allocator, "\n", lines.items);
}

/// Gets a function signature (keywords, name, return value)
pub fn getFunctionSignature(tree: *ast.Tree, func: *ast.Node.FnProto) []const u8 {
    const start = tree.tokens.at(func.firstToken()).start;
    const end = tree.tokens.at(switch (func.return_type) {
        .Explicit, .InferErrorSet => |node| node.lastToken(),
        .Invalid => |r_paren| r_paren,
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

        if (param_num != 1) try buffer.appendSlice(", ${") else try buffer.appendSlice("${");

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

        switch (param_decl.param_type) {
            .var_args => try buffer.appendSlice("..."),
            .var_type => try buffer.appendSlice("var"),
            .type_expr => |type_expr| {
                var curr_tok = type_expr.firstToken();
                var end_tok = type_expr.lastToken();
                while (curr_tok <= end_tok) : (curr_tok += 1) {
                    const id = tree.tokens.at(curr_tok).id;
                    const is_comma = tree.tokens.at(curr_tok).id == .Comma;

                    if (curr_tok == end_tok and is_comma) continue;

                    try buffer.appendSlice(tree.tokenSlice(curr_tok));
                    if (is_comma or id == .Keyword_const) try buffer.append(' ');
                }
            },
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
            else => {},
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
                .Invalid => {},
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
            return resolveTypeOfNode(analysis_ctx, field.type_expr orelse return null);
        },
        .ErrorSetDecl => {
            return node;
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            switch (suffix_op.op) {
                .Call => {
                    return resolveTypeOfNode(analysis_ctx, suffix_op.lhs.node);
                },
                else => {},
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
                else => {},
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .PtrType => {
                    return resolveTypeOfNode(analysis_ctx, prefix_op.rhs);
                },
                else => {},
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
                std.debug.warn("Error {} while processing import {}\n", .{ err, import_str });
                break :block null;
            };
        },
        else => {
            std.debug.warn("Type resolution case not implemented; {}\n", .{node.id});
        },
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

        switch (var_decl.init_node.?.id) {
            .BuiltinCall => {
                const builtin_call = var_decl.init_node.?.cast(ast.Node.BuiltinCall).?;
                try maybeCollectImport(tree, builtin_call, &arr);
            },
            .InfixOp => {
                const infix_op = var_decl.init_node.?.cast(ast.Node.InfixOp).?;

                switch (infix_op.op) {
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

pub fn getFieldAccessTypeNode(analysis_ctx: *AnalysisContext, start_node: *ast.Node) ?*ast.Node {
    switch (start_node.id) {
        .InfixOp => {
            const infix_op = start_node.cast(ast.Node.InfixOp).?;
            if (infix_op.op == .Period) {
                return resolveTypeOfNode(analysis_ctx, infix_op.lhs);
            } else {
                return resolveTypeOfNode(analysis_ctx, start_node);
            }
        },
        else => {
            return resolveTypeOfNode(analysis_ctx, start_node);
        },
    }
}

pub fn isNodePublic(tree: *ast.Tree, node: *ast.Node) bool {
    switch (node.id) {
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            return var_decl.visib_token != null;
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
            return func.visib_token != null;
        },
        .ContainerField, .ErrorTag => {
            return true;
        },
        else => {
            return false;
        },
    }

    return false;
}

pub fn nodeToString(tree: *ast.Tree, node: *ast.Node) ?[]const u8 {
    switch (node.id) {
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return tree.tokenSlice(field.name_token);
        },
        .ErrorTag => {
            const tag = node.cast(ast.Node.ErrorTag).?;
            return tree.tokenSlice(tag.name_token);
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
        },
    }

    return null;
}

pub const CompletionContext = struct {
    pub const Id = enum {
        builtin,
        var_access,
        field_access,
        enum_literal,
        container_field,
        empty,
        none,
    };

    id: Id,
    node: ?*ast.Node = null,

    fn toId(self: CompletionContext, id: Id) CompletionContext {
        return .{ .id = id, .node = self.node };
    }
};

fn nodeContainsSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.tokens.at(node.firstToken());
    const last_token = tree.tokens.at(node.lastToken());
    return source_index >= first_token.start and source_index <= last_token.end;
}

fn visitNodesAndFindCompletion(tree: *ast.Tree, node: *ast.Node, source_index: usize) CompletionContext {
    switch (node.id) {
        .Identifier => {
            var cc = CompletionContext{ .id = .var_access, .node = node };

            if (nodeToString(tree, node).?[0] == '@') {
                cc.id = .builtin;
            }
            return cc;
        },
        .InfixOp => {
            const infix_op = node.cast(ast.Node.InfixOp).?;
            if (infix_op.op == .Period and nodeContainsSourceIndex(tree, infix_op.rhs, source_index)) {
                return .{ .id = .field_access, .node = node };
            }
        },
        .BuiltinCall => return .{ .id = .builtin, .node = node },
        .EnumLiteral => return .{ .id = .enum_literal, .node = node },
        else => {},
    }

    var node_idx: usize = 0;
    while (node.iterate(node_idx)) |child| : (node_idx += 1) {
        if (!nodeContainsSourceIndex(tree, child, source_index)) continue;
        return visitNodesAndFindCompletion(tree, child, source_index);
    }

    return switch (node.id) {
        .Block, .Root => .{ .id = .empty },
        .ContainerField => .{ .id = .container_field },
        else => .{ .id = .none, .node = node },
    };
}

pub fn completionContext(tree: *ast.Tree, source_index: usize) CompletionContext {
    if (source_index == 0) return .{ .id = .empty };
    const completion_context = visitNodesAndFindCompletion(tree, &tree.root_node.base, source_index);

    // TODO: Can we do this better?
    // Text like `someExpr().` will not get parsed to InfixOp.
    // As a workaround, we check if there if the position corresponds exactly to a
    // period token and adjust the context.
    var token_idx: ast.TokenIndex = 0;
    while (tree.tokens.at(token_idx).end <= source_index and token_idx < tree.tokens.len) : (token_idx += 1) {}
    const tok_before_cursor = tree.tokens.at(token_idx);

    const is_dot = tok_before_cursor.id == .Period and tok_before_cursor.end - 1 == source_index;

    return if (is_dot) switch (completion_context.id) {
        .container_field => completion_context,
        .empty => completion_context.toId(.enum_literal),
        else => completion_context.toId(.field_access),
    } else
        completion_context;
}
