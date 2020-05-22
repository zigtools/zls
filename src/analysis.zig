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
    return tree.source[start..end];
}

/// Gets a param signature
pub fn getParamSignature(tree: *ast.Tree, param: *ast.Node.ParamDecl) []const u8 {
    const start = tree.tokens.at(param.firstToken()).start;
    const end = tree.tokens.at(param.lastToken()).end;
    return tree.source[start..end];
}

pub fn isTypeFunction(tree: *ast.Tree, func: *ast.Node.FnProto) bool {
    switch (func.return_type) {
        .Explicit => |node| return if (node.cast(std.zig.ast.Node.Identifier)) |ident|
            std.mem.eql(u8, tree.tokenSlice(ident.token), "type")
        else
            false,
        .InferErrorSet, .Invalid => return false,
    }
}

// STYLE

pub fn isCamelCase(name: []const u8) bool {
    return !std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name, "_") == null;
}

pub fn isPascalCase(name: []const u8) bool {
    return std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name, "_") == null;
}

// ANALYSIS ENGINE

pub fn getDeclNameToken(tree: *ast.Tree, node: *ast.Node) ?ast.TokenIndex {
    switch (node.id) {
        .VarDecl => {
            const vari = node.cast(ast.Node.VarDecl).?;
            return vari.name_token;
        },
        .ParamDecl => {
            const decl = node.cast(ast.Node.ParamDecl).?;
            if (decl.name_token == null) return null;
            return decl.name_token.?;
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
            if (func.name_token == null) return null;
            return func.name_token.?;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return field.name_token;
        },
        else => {},
    }

    return null;
}

fn getDeclName(tree: *ast.Tree, node: *ast.Node) ?[]const u8 {
    return tree.tokenSlice(getDeclNameToken(tree, node) orelse return null);
}

/// Gets the child of node
pub fn getChild(tree: *ast.Tree, node: *ast.Node, name: []const u8) ?*ast.Node {
    var index: usize = 0;
    while (node.iterate(index)) |child| : (index += 1) {
        const child_name = getDeclName(tree, child) orelse continue;
        if (std.mem.eql(u8, child_name, name)) return child;
    }
    return null;
}

/// Gets the child of slice
pub fn getChildOfSlice(tree: *ast.Tree, nodes: []*ast.Node, name: []const u8) ?*ast.Node {
    for (nodes) |child| {
        const child_name = getDeclName(tree, child) orelse continue;
        if (std.mem.eql(u8, child_name, name)) return child;
    }
    return null;
}

fn findReturnStatementInternal(base_node: *ast.Node, already_found: *bool) ?*ast.Node.ControlFlowExpression {
    var result: ?*ast.Node.ControlFlowExpression = null;
    var idx: usize = 0;
    while (base_node.iterate(idx)) |child_node| : (idx += 1) {
        switch (child_node.id) {
            .ControlFlowExpression => {
                const cfe = child_node.cast(ast.Node.ControlFlowExpression).?;
                if (cfe.kind == .Return) {
                    if (already_found.*) return null;
                    already_found.* = true;
                    result = cfe;
                    continue;
                }
            },
            else => {},
        }

        result = findReturnStatementInternal(child_node, already_found);
    }
    return result;
}

fn findReturnStatement(base_node: *ast.Node) ?*ast.Node.ControlFlowExpression {
    var already_found = false;
    return findReturnStatementInternal(base_node, &already_found);
}

/// Resolves the return type of a function
fn resolveReturnType(analysis_ctx: *AnalysisContext, fn_decl: *ast.Node.FnProto) ?*ast.Node {
    if (isTypeFunction(analysis_ctx.tree, fn_decl) and fn_decl.body_node != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(fn_decl.body_node.?) orelse return null;
        if (ret.rhs) |rhs|
            if (resolveTypeOfNode(analysis_ctx, rhs)) |res_rhs| switch (res_rhs.id) {
                .ContainerDecl => {
                    analysis_ctx.onContainer(res_rhs.cast(ast.Node.ContainerDecl).?) catch return null;
                    return res_rhs;
                },
                else => return null,
            };

        return null;
    }

    return switch (fn_decl.return_type) {
        .Explicit, .InferErrorSet => |return_type| resolveTypeOfNode(analysis_ctx, return_type),
        .Invalid => null,
    };
}

/// Resolves the type of a node
pub fn resolveTypeOfNode(analysis_ctx: *AnalysisContext, node: *ast.Node) ?*ast.Node {
    switch (node.id) {
        .VarDecl => {
            const vari = node.cast(ast.Node.VarDecl).?;

            return resolveTypeOfNode(analysis_ctx, vari.type_node orelse vari.init_node.?) orelse null;
        },
        .ParamDecl => {
            const decl = node.cast(ast.Node.ParamDecl).?;
            switch (decl.param_type) {
                .var_type, .type_expr => |var_type| {
                    return resolveTypeOfNode(analysis_ctx, var_type) orelse null;
                },
                else => {},
            }
        },
        .Identifier => {
            if (getChildOfSlice(analysis_ctx.tree, analysis_ctx.scope_nodes, analysis_ctx.tree.getNodeSource(node))) |child| {
                return resolveTypeOfNode(analysis_ctx, child);
            } else return null;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return resolveTypeOfNode(analysis_ctx, field.type_expr orelse return null);
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            switch (suffix_op.op) {
                .Call, .StructInitializer => {
                    const decl = resolveTypeOfNode(analysis_ctx, suffix_op.lhs.node) orelse return null;
                    return switch (decl.id) {
                        .FnProto => resolveReturnType(analysis_ctx, decl.cast(ast.Node.FnProto).?),
                        else => decl,
                    };
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
                    return resolveTypeOfNode(analysis_ctx, getChild(analysis_ctx.tree, left, rhs_str) orelse return null);
                },
                else => {},
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .SliceType, .ArrayType => return node,
                .PtrType => {
                    const op_token = analysis_ctx.tree.tokens.at(prefix_op.op_token);
                    switch (op_token.id) {
                        .Asterisk => return resolveTypeOfNode(analysis_ctx, prefix_op.rhs),
                        .LBracket, .AsteriskAsterisk => return null,
                        else => unreachable,
                    }
                },
                .Try => {
                    const rhs_type = resolveTypeOfNode(analysis_ctx, prefix_op.rhs) orelse return null;
                    switch (rhs_type.id) {
                        .InfixOp => {
                            const infix_op = rhs_type.cast(ast.Node.InfixOp).?;
                            if (infix_op.op == .ErrorUnion) return infix_op.rhs;
                        },
                        else => {},
                    }
                    return rhs_type;
                },
                else => {},
            }
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            const call_name = analysis_ctx.tree.tokenSlice(builtin_call.builtin_token);
            if (std.mem.eql(u8, call_name, "@This")) {
                if (builtin_call.params.len != 0) return null;
                return analysis_ctx.last_this_node;
            }

            if (!std.mem.eql(u8, call_name, "@import")) return null;
            if (builtin_call.params.len > 1) return null;

            const import_param = builtin_call.params.at(0).*;
            if (import_param.id != .StringLiteral) return null;

            const import_str = analysis_ctx.tree.tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
            return analysis_ctx.onImport(import_str[1 .. import_str.len - 1]) catch |err| block: {
                std.debug.warn("Error {} while processing import {}\n", .{ err, import_str });
                break :block null;
            };
        },
        .ContainerDecl => {
            analysis_ctx.onContainer(node.cast(ast.Node.ContainerDecl).?) catch return null;
            return node;
        },
        .MultilineStringLiteral, .StringLiteral, .ErrorSetDecl, .FnProto => return node,
        else => std.debug.warn("Type resolution case not implemented; {}\n", .{node.id}),
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
pub fn collectImports(import_arr: *std.ArrayList([]const u8), tree: *ast.Tree) !void {
    // TODO: Currently only detects `const smth = @import("string literal")<.SomeThing>;`
    var idx: usize = 0;
    while (tree.root_node.iterate(idx)) |decl| : (idx += 1) {
        if (decl.id != .VarDecl) continue;
        const var_decl = decl.cast(ast.Node.VarDecl).?;
        if (var_decl.init_node == null) continue;

        switch (var_decl.init_node.?.id) {
            .BuiltinCall => {
                const builtin_call = var_decl.init_node.?.cast(ast.Node.BuiltinCall).?;
                try maybeCollectImport(tree, builtin_call, import_arr);
            },
            .InfixOp => {
                const infix_op = var_decl.init_node.?.cast(ast.Node.InfixOp).?;

                switch (infix_op.op) {
                    .Period => {},
                    else => continue,
                }
                if (infix_op.lhs.id != .BuiltinCall) continue;
                try maybeCollectImport(tree, infix_op.lhs.cast(ast.Node.BuiltinCall).?, import_arr);
            },
            else => {},
        }
    }
}

pub fn getFieldAccessTypeNode(
    analysis_ctx: *AnalysisContext,
    tokenizer: *std.zig.Tokenizer,
    line_length: usize,
) ?*ast.Node {
    var current_node = &analysis_ctx.tree.root_node.base;

    while (true) {
        var next = tokenizer.next();
        switch (next.id) {
            .Eof => return current_node,
            .Identifier => {
                if (getChildOfSlice(analysis_ctx.tree, analysis_ctx.scope_nodes, tokenizer.buffer[next.start..next.end])) |child| {
                    if (resolveTypeOfNode(analysis_ctx, child)) |node_type| {
                        current_node = node_type;
                    } else return null;
                } else return null;
            },
            .Period => {
                var after_period = tokenizer.next();
                if (after_period.id == .Eof or after_period.id == .Comma) {
                    return current_node;
                } else if (after_period.id == .Identifier) {
                    // TODO: This works for now, maybe we should filter based on the partial identifier ourselves?
                    if (after_period.end == line_length) return current_node;

                    if (getChild(analysis_ctx.tree, current_node, tokenizer.buffer[after_period.start..after_period.end])) |child| {
                        if (resolveTypeOfNode(analysis_ctx, child)) |child_type| {
                            current_node = child_type;
                        } else return null;
                    } else return null;
                }
            },
            else => std.debug.warn("Not implemented; {}\n", .{next.id}),
        }
    }

    return current_node;
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
        else => return true,
    }
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

pub fn declsFromIndexInternal(decls: *std.ArrayList(*ast.Node), tree: *ast.Tree, node: *ast.Node, source_index: usize) error{OutOfMemory}!void {
    switch (node.id) {
        .Root, .ContainerDecl => {
            var node_index: usize = 0;
            while (node.iterate(node_index)) |child_node| : (node_index += 1) {
                // Skip over container fields, we can only dot access those.
                if (child_node.id == .ContainerField) continue;

                const is_contained = nodeContainsSourceIndex(tree, child_node, source_index);
                // If the cursor is in a variable decls it will insert itself anyway, we don't need to take care of it.
                if ((is_contained and child_node.id != .VarDecl) or !is_contained) try decls.append(child_node); 
                if (is_contained) {
                    try declsFromIndexInternal(decls, tree, child_node, source_index);
                }
            }
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;

            var param_index: usize = 0;
            while (param_index < func.params.len) : (param_index += 1)
                try declsFromIndexInternal(decls, tree, func.params.at(param_index).*, source_index);

            if (func.body_node) |body_node| {
                if (!nodeContainsSourceIndex(tree, body_node, source_index)) return;
                try declsFromIndexInternal(decls, tree, body_node, source_index);
            }
        },
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            if (!nodeContainsSourceIndex(tree, test_decl.body_node, source_index)) return;
            try declsFromIndexInternal(decls, tree, test_decl.body_node, source_index);
        },
        .Block => {
            var index: usize = 0;
            while (node.iterate(index)) |inode| : (index += 1) {
                if (nodeComesAfterSourceIndex(tree, inode, source_index)) return;
                try declsFromIndexInternal(decls, tree, inode, source_index);
            }
        },
        .Comptime => {
            const comptime_stmt = node.cast(ast.Node.Comptime).?;
            if (nodeComesAfterSourceIndex(tree, comptime_stmt.expr, source_index)) return;
            try declsFromIndexInternal(decls, tree, comptime_stmt.expr, source_index);
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            if (nodeContainsSourceIndex(tree, if_node.body, source_index)) {
                if (if_node.payload) |payload| {
                    try declsFromIndexInternal(decls, tree, payload, source_index);
                }
                return try declsFromIndexInternal(decls, tree, if_node.body, source_index);
            }

            if (if_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(decls, tree, else_node.body, source_index);
                }
            }
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            if (nodeContainsSourceIndex(tree, while_node.body, source_index)) {
                if (while_node.payload) |payload| {
                    try declsFromIndexInternal(decls, tree, payload, source_index);
                }
                return try declsFromIndexInternal(decls, tree, while_node.body, source_index);
            }

            if (while_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(decls, tree, else_node.body, source_index);
                }
            }
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            if (nodeContainsSourceIndex(tree, for_node.body, source_index)) {
                try declsFromIndexInternal(decls, tree, for_node.payload, source_index);
                return try declsFromIndexInternal(decls, tree, for_node.body, source_index);
            }

            if (for_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(decls, tree, else_node.body, source_index);
                }
            }
        },
        // TODO: These convey no type information...
        .Payload => try decls.append(node.cast(ast.Node.Payload).?.error_symbol),
        .PointerPayload => try decls.append(node.cast(ast.Node.PointerPayload).?.value_symbol),
        .PointerIndexPayload => {
            const payload = node.cast(ast.Node.PointerIndexPayload).?;
            try decls.append(payload.value_symbol);
            if (payload.index_symbol) |idx| {
                try decls.append(idx);
            }
        },
        .VarDecl => {
            try decls.append(node);
            if (node.cast(ast.Node.VarDecl).?.init_node) |child| {
                if (nodeContainsSourceIndex(tree, child, source_index)) {
                    try declsFromIndexInternal(decls, tree, child, source_index);
                }
            }
        },
        .ParamDecl => try decls.append(node),
        else => {},
    }
}

pub fn addChildrenNodes(decls: *std.ArrayList(*ast.Node), tree: *ast.Tree, node: *ast.Node) !void {
    var index: usize = 0;
    while (node.iterate(index)) |child_node| : (index += 1) {
        try decls.append(child_node);
    }
}

pub fn declsFromIndex(decls: *std.ArrayList(*ast.Node), tree: *ast.Tree, source_index: usize) !void {
    var node = &tree.root_node.base;
    try declsFromIndexInternal(decls, tree, &tree.root_node.base, source_index);
}

fn nodeContainsSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.tokens.at(node.firstToken());
    const last_token = tree.tokens.at(node.lastToken());
    return source_index >= first_token.start and source_index <= last_token.end;
}

fn nodeComesAfterSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.tokens.at(node.firstToken());
    const last_token = tree.tokens.at(node.lastToken());
    return source_index < first_token.start;
}

pub fn getImportStr(tree: *ast.Tree, source_index: usize) ?[]const u8 {
    var node = &tree.root_node.base;
    var index: usize = 0;
    while (node.iterate(index)) |child| {
        if (!nodeContainsSourceIndex(tree, child, source_index)) {
            index += 1;
            continue;
        }
        if (child.cast(ast.Node.BuiltinCall)) |builtin_call| blk: {
            const call_name = tree.tokenSlice(builtin_call.builtin_token);

            if (!std.mem.eql(u8, call_name, "@import")) break :blk;
            if (builtin_call.params.len != 1) break :blk;

            const import_param = builtin_call.params.at(0).*;
            const import_str_node = import_param.cast(ast.Node.StringLiteral) orelse break :blk;
            const import_str = tree.tokenSlice(import_str_node.token);
            return import_str[1 .. import_str.len - 1];
        }
        node = child;
        index = 0;
    }
    return null;
}
