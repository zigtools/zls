const std = @import("std");
const AnalysisContext = @import("document_store.zig").AnalysisContext;
const ast = std.zig.ast;
const types = @import("types.zig");

/// Get a declaration's doc comment node
fn getDocCommentNode(tree: *ast.Tree, node: *ast.Node) ?*ast.Node.DocComment {
    if (node.cast(ast.Node.FnProto)) |func| {
        return func.doc_comments;
    } else if (node.cast(ast.Node.VarDecl)) |var_decl| {
        return var_decl.doc_comments;
    } else if (node.cast(ast.Node.ContainerField)) |field| {
        return field.doc_comments;
    } else if (node.cast(ast.Node.ErrorTag)) |tag| {
        return tag.doc_comments;
    }
    return null;
}

/// Gets a declaration's doc comments, caller must free memory when a value is returned
/// Like:
///```zig
///var comments = getFunctionDocComments(allocator, tree, func);
///defer if (comments) |comments_pointer| allocator.free(comments_pointer);
///```
pub fn getDocComments(allocator: *std.mem.Allocator, tree: *ast.Tree, node: *ast.Node) !?[]const u8 {
    if (getDocCommentNode(tree, node)) |doc_comment_node| {
        return try collectDocComments(allocator, tree, doc_comment_node);
    }
    return null;
}

fn collectDocComments(allocator: *std.mem.Allocator, tree: *ast.Tree, doc_comments: *ast.Node.DocComment) ![]const u8 {
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();

    var curr_line_tok = doc_comments.first_line;
    while (true) : (curr_line_tok += 1) {
        switch (tree.token_ids[curr_line_tok]) {
            .LineComment => continue,
            .DocComment, .ContainerDocComment => {
                try lines.append(std.fmt.trim(tree.tokenSlice(curr_line_tok)[3..]));
            },
            else => break,
        }
    }

    return try std.mem.join(allocator, "\\\n", lines.items);
}

/// Gets a function signature (keywords, name, return value)
pub fn getFunctionSignature(tree: *ast.Tree, func: *ast.Node.FnProto) []const u8 {
    const start = tree.token_locs[func.firstToken()].start;
    const end = tree.token_locs[switch (func.return_type) {
        .Explicit, .InferErrorSet => |node| node.lastToken(),
        .Invalid => |r_paren| r_paren,
    }].end;
    return tree.source[start..end];
}

/// Gets a function snippet insert text
pub fn getFunctionSnippet(allocator: *std.mem.Allocator, tree: *ast.Tree, func: *ast.Node.FnProto, skip_self_param: bool) ![]const u8 {
    const name_tok = func.name_token orelse unreachable;

    var buffer = std.ArrayList(u8).init(allocator);
    try buffer.ensureCapacity(128);

    try buffer.appendSlice(tree.tokenSlice(name_tok));
    try buffer.append('(');

    var buf_stream = buffer.outStream();

    for (func.paramsConst()) |param, param_num| {
        if (skip_self_param and param_num == 0) continue;
        if (param_num != @boolToInt(skip_self_param)) try buffer.appendSlice(", ${") else try buffer.appendSlice("${");

        try buf_stream.print("{}:", .{param_num + 1});

        if (param.comptime_token) |_| {
            try buffer.appendSlice("comptime ");
        }

        if (param.noalias_token) |_| {
            try buffer.appendSlice("noalias ");
        }

        if (param.name_token) |name_token| {
            try buffer.appendSlice(tree.tokenSlice(name_token));
            try buffer.appendSlice(": ");
        }

        switch (param.param_type) {
            .var_args => try buffer.appendSlice("..."),
            .var_type => try buffer.appendSlice("var"),
            .type_expr => |type_expr| {
                var curr_tok = type_expr.firstToken();
                var end_tok = type_expr.lastToken();
                while (curr_tok <= end_tok) : (curr_tok += 1) {
                    const id = tree.token_ids[curr_tok];
                    const is_comma = id == .Comma;

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
    const start = tree.token_locs[var_decl.firstToken()].start;
    const end = tree.token_locs[var_decl.semicolon_token].start;
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
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;
            if (func.name_token == null) return null;
            return func.name_token.?;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return field.name_token;
        },
        // We need identifier for captures
        .Identifier => {
            const ident = node.cast(ast.Node.Identifier).?;
            return ident.token;
        },
        .TestDecl => {
            const decl = node.cast(ast.Node.TestDecl).?;
            return (decl.name.cast(ast.Node.StringLiteral) orelse return null).token;
        },
        else => {},
    }

    return null;
}

fn getDeclName(tree: *ast.Tree, node: *ast.Node) ?[]const u8 {
    const name = tree.tokenSlice(getDeclNameToken(tree, node) orelse return null);
    return switch (node.id) {
        .TestDecl => name[1 .. name.len - 1],
        else => name,
    };
}

/// Gets the child of node
pub fn getChild(tree: *ast.Tree, node: *ast.Node, name: []const u8) ?*ast.Node {
    var child_idx: usize = 0;
    while (node.iterate(child_idx)) |child| : (child_idx += 1) {
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

fn findReturnStatementInternal(
    tree: *ast.Tree,
    fn_decl: *ast.Node.FnProto,
    base_node: *ast.Node,
    already_found: *bool,
) ?*ast.Node.ControlFlowExpression {
    var result: ?*ast.Node.ControlFlowExpression = null;
    var child_idx: usize = 0;
    while (base_node.iterate(child_idx)) |child_node| : (child_idx += 1) {
        switch (child_node.id) {
            .ControlFlowExpression => {
                const cfe = child_node.cast(ast.Node.ControlFlowExpression).?;
                if (cfe.kind == .Return) {
                    // If we are calling ourselves recursively, ignore this return.
                    if (cfe.rhs) |rhs| {
                        if (rhs.cast(ast.Node.Call)) |call_node| {
                            if (call_node.lhs.id == .Identifier) {
                                if (std.mem.eql(u8, getDeclName(tree, call_node.lhs).?, getDeclName(tree, &fn_decl.base).?)) {
                                    continue;
                                }
                            }
                        }
                    }

                    if (already_found.*) return null;
                    already_found.* = true;
                    result = cfe;
                    continue;
                }
            },
            else => {},
        }

        result = findReturnStatementInternal(tree, fn_decl, child_node, already_found);
    }
    return result;
}

fn findReturnStatement(tree: *ast.Tree, fn_decl: *ast.Node.FnProto) ?*ast.Node.ControlFlowExpression {
    var already_found = false;
    return findReturnStatementInternal(tree, fn_decl, fn_decl.body_node.?, &already_found);
}

/// Resolves the return type of a function
fn resolveReturnType(analysis_ctx: *AnalysisContext, fn_decl: *ast.Node.FnProto) ?*ast.Node {
    if (isTypeFunction(analysis_ctx.tree(), fn_decl) and fn_decl.body_node != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(analysis_ctx.tree(), fn_decl) orelse return null;
        if (ret.rhs) |rhs|
            if (resolveTypeOfNode(analysis_ctx, rhs)) |res_rhs| switch (res_rhs.id) {
                .ContainerDecl => {
                    analysis_ctx.onContainer(res_rhs) catch return null;
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

/// Resolves the child type of an optional type
fn resolveUnwrapOptionalType(analysis_ctx: *AnalysisContext, opt: *ast.Node) ?*ast.Node {
    if (opt.cast(ast.Node.PrefixOp)) |prefix_op| {
        if (prefix_op.op == .OptionalType) {
            return resolveTypeOfNode(analysis_ctx, prefix_op.rhs);
        }
    }

    return null;
}

/// Resolves the child type of a defer type
fn resolveDerefType(analysis_ctx: *AnalysisContext, deref: *ast.Node) ?*ast.Node {
    if (deref.cast(ast.Node.PrefixOp)) |pop| {
        if (pop.op == .PtrType) {
            const op_token_id = analysis_ctx.tree().token_ids[pop.op_token];
            switch (op_token_id) {
                .Asterisk => return resolveTypeOfNode(analysis_ctx, pop.rhs),
                .LBracket, .AsteriskAsterisk => return null,
                else => unreachable,
            }
        }
    }
    return null;
}

fn makeSliceType(analysis_ctx: *AnalysisContext, child_type: *ast.Node) ?*ast.Node {
    // TODO: Better values for fields, better way to do this?
    var slice_type = analysis_ctx.arena.allocator.create(ast.Node.PrefixOp) catch return null;
    slice_type.* = .{
        .op_token = child_type.firstToken(),
        .op = .{
            .SliceType = .{
                .allowzero_token = null,
                .align_info = null,
                .const_token = null,
                .volatile_token = null,
                .sentinel = null,
            },
        },
        .rhs = child_type,
    };

    return &slice_type.base;
}

/// Resolves bracket access type (both slicing and array access)
fn resolveBracketAccessType(
    analysis_ctx: *AnalysisContext,
    lhs: *ast.Node,
    rhs: enum { Single, Range },
) ?*ast.Node {
    if (lhs.cast(ast.Node.PrefixOp)) |pop| {
        switch (pop.op) {
            .SliceType => {
                if (rhs == .Single) return resolveTypeOfNode(analysis_ctx, pop.rhs);
                return lhs;
            },
            .ArrayType => {
                if (rhs == .Single) return resolveTypeOfNode(analysis_ctx, pop.rhs);
                return makeSliceType(analysis_ctx, pop.rhs);
            },
            .PtrType => {
                if (pop.rhs.cast(std.zig.ast.Node.PrefixOp)) |child_pop| {
                    switch (child_pop.op) {
                        .ArrayType => {
                            if (rhs == .Single) {
                                return resolveTypeOfNode(analysis_ctx, child_pop.rhs);
                            }
                            return lhs;
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }
    return null;
}

/// Called to remove one level of pointerness before a field access
fn resolveFieldAccessLhsType(analysis_ctx: *AnalysisContext, lhs: *ast.Node) *ast.Node {
    return resolveDerefType(analysis_ctx, lhs) orelse lhs;
}

/// Resolves the type of a node
pub fn resolveTypeOfNode(analysis_ctx: *AnalysisContext, node: *ast.Node) ?*ast.Node {
    switch (node.id) {
        .VarDecl => {
            const vari = node.cast(ast.Node.VarDecl).?;

            return resolveTypeOfNode(analysis_ctx, vari.type_node orelse vari.init_node.?) orelse null;
        },
        .Identifier => {
            if (getChildOfSlice(analysis_ctx.tree(), analysis_ctx.scope_nodes, analysis_ctx.tree().getNodeSource(node))) |child| {
                if (child == node) return null;
                return resolveTypeOfNode(analysis_ctx, child);
            } else return null;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return resolveTypeOfNode(analysis_ctx, field.type_expr orelse return null);
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            const previous_tree = analysis_ctx.tree();

            const decl = resolveTypeOfNode(analysis_ctx, call.lhs) orelse return null;
            if (decl.cast(ast.Node.FnProto)) |fn_decl| {
                if (previous_tree != analysis_ctx.tree()) {
                    return resolveReturnType(analysis_ctx, fn_decl);
                }

                // Add type param values to the scope nodes
                const param_len = std.math.min(call.params_len, fn_decl.params_len);
                var scope_nodes = std.ArrayList(*ast.Node).fromOwnedSlice(&analysis_ctx.arena.allocator, analysis_ctx.scope_nodes);
                var analysis_ctx_clone = analysis_ctx.clone() catch return null;
                for (fn_decl.paramsConst()) |decl_param, param_idx| {
                    if (param_idx >= param_len) break;
                    if (decl_param.name_token == null) continue;

                    const type_param = switch (decl_param.param_type) {
                        .type_expr => |type_node| if (type_node.cast(ast.Node.Identifier)) |ident|
                            std.mem.eql(u8, analysis_ctx.tree().tokenSlice(ident.token), "type")
                        else
                            false,
                        else => false,
                    };
                    if (!type_param) continue;

                    // TODO Handle errors better
                    // TODO This may invalidate the analysis context so we copy it.
                    //      However, if the argument hits an import we just ignore it for now.
                    //      Once we return our own types instead of directly using nodes we can fix this.
                    const call_param_type = resolveTypeOfNode(&analysis_ctx_clone, call.paramsConst()[param_idx]) orelse continue;
                    if (analysis_ctx_clone.handle != analysis_ctx.handle) {
                        analysis_ctx_clone = analysis_ctx.clone() catch return null;
                        continue;
                    }

                    scope_nodes.append(makeVarDeclNode(
                        &analysis_ctx.arena.allocator,
                        decl_param.doc_comments,
                        decl_param.comptime_token,
                        decl_param.name_token.?,
                        null,
                        call_param_type,
                    ) catch return null) catch return null;
                    analysis_ctx.scope_nodes = scope_nodes.items;
                }

                return resolveReturnType(analysis_ctx, fn_decl);
            }
            return decl;
        },
        .StructInitializer => {
            const struct_init = node.cast(ast.Node.StructInitializer).?;
            return resolveTypeOfNode(analysis_ctx, struct_init.lhs);
        },
        .ErrorSetDecl => {
            const set = node.cast(ast.Node.ErrorSetDecl).?;
            var i: usize = 0;
            while (set.iterate(i)) |decl| : (i += 1) {
                // TODO handle errors better?
                analysis_ctx.error_completions.add(analysis_ctx.tree(), decl) catch {};
            }
            return node;
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            switch (suffix_op.op) {
                .UnwrapOptional => {
                    const left_type = resolveTypeOfNode(analysis_ctx, suffix_op.lhs) orelse return null;
                    return resolveUnwrapOptionalType(analysis_ctx, left_type);
                },
                .Deref => {
                    const left_type = resolveTypeOfNode(analysis_ctx, suffix_op.lhs) orelse return null;
                    return resolveDerefType(analysis_ctx, left_type);
                },
                .ArrayAccess => {
                    const left_type = resolveTypeOfNode(analysis_ctx, suffix_op.lhs) orelse return null;
                    return resolveBracketAccessType(analysis_ctx, left_type, .Single);
                },
                .Slice => {
                    const left_type = resolveTypeOfNode(analysis_ctx, suffix_op.lhs) orelse return null;
                    return resolveBracketAccessType(analysis_ctx, left_type, .Range);
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
                    var rhs_str = nodeToString(analysis_ctx.tree(), infix_op.rhs) orelse return null;
                    // Use the analysis context temporary arena to store the rhs string.
                    rhs_str = std.mem.dupe(&analysis_ctx.arena.allocator, u8, rhs_str) catch return null;

                    // If we are accessing a pointer type, remove one pointerness level :)
                    const left_type = resolveFieldAccessLhsType(
                        analysis_ctx,
                        resolveTypeOfNode(analysis_ctx, infix_op.lhs) orelse return null,
                    );

                    const child = getChild(analysis_ctx.tree(), left_type, rhs_str) orelse return null;
                    return resolveTypeOfNode(analysis_ctx, child);
                },
                .UnwrapOptional => {
                    const left_type = resolveTypeOfNode(analysis_ctx, infix_op.lhs) orelse return null;
                    return resolveUnwrapOptionalType(analysis_ctx, left_type);
                },
                else => {},
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .SliceType,
                .ArrayType,
                .OptionalType,
                .PtrType,
                => return node,
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
            const call_name = analysis_ctx.tree().tokenSlice(builtin_call.builtin_token);
            if (std.mem.eql(u8, call_name, "@This")) {
                if (builtin_call.params_len != 0) return null;
                return analysis_ctx.in_container;
            }

            // TODO: https://github.com/ziglang/zig/issues/4335
            const cast_map = std.ComptimeStringMap(void, .{
                .{ .@"0" = "@as" },
                .{ .@"0" = "@bitCast" },
                .{ .@"0" = "@fieldParentPtr" },
                .{ .@"0" = "@floatCast" },
                .{ .@"0" = "@floatToInt" },
                .{ .@"0" = "@intCast" },
                .{ .@"0" = "@intToEnum" },
                .{ .@"0" = "@intToFloat" },
                .{ .@"0" = "@intToPtr" },
                .{ .@"0" = "@truncate" },
                .{ .@"0" = "@ptrCast" },
            });
            if (cast_map.has(call_name)) {
                if (builtin_call.params_len < 1) return null;
                return resolveTypeOfNode(analysis_ctx, builtin_call.paramsConst()[0]);
            }

            if (!std.mem.eql(u8, call_name, "@import")) return null;
            if (builtin_call.params_len < 1) return null;

            const import_param = builtin_call.paramsConst()[0];
            if (import_param.id != .StringLiteral) return null;

            const import_str = analysis_ctx.tree().tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
            return analysis_ctx.onImport(import_str[1 .. import_str.len - 1]) catch |err| block: {
                std.debug.warn("Error {} while processing import {}\n", .{ err, import_str });
                break :block null;
            };
        },
        .ContainerDecl => {
            analysis_ctx.onContainer(node) catch return null;

            const container = node.cast(ast.Node.ContainerDecl).?;
            const kind = analysis_ctx.tree().token_ids[container.kind_token];

            if (kind == .Keyword_struct or (kind == .Keyword_union and container.init_arg_expr == .None)) {
                return node;
            }

            var i: usize = 0;
            while (container.iterate(i)) |decl| : (i += 1) {
                if (decl.id != .ContainerField) continue;
                // TODO handle errors better?
                analysis_ctx.enum_completions.add(analysis_ctx.tree(), decl) catch {};
            }
            return node;
        },
        .MultilineStringLiteral, .StringLiteral, .FnProto => return node,
        else => std.debug.warn("Type resolution case not implemented; {}\n", .{node.id}),
    }
    return null;
}

fn maybeCollectImport(tree: *ast.Tree, builtin_call: *ast.Node.BuiltinCall, arr: *std.ArrayList([]const u8)) !void {
    if (!std.mem.eql(u8, tree.tokenSlice(builtin_call.builtin_token), "@import")) return;
    if (builtin_call.params_len > 1) return;

    const import_param = builtin_call.paramsConst()[0];
    if (import_param.id != .StringLiteral) return;

    const import_str = tree.tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
    try arr.append(import_str[1 .. import_str.len - 1]);
}

/// Collects all imports we can find into a slice of import paths (without quotes).
/// The import paths are valid as long as the tree is.
pub fn collectImports(import_arr: *std.ArrayList([]const u8), tree: *ast.Tree) !void {
    // TODO: Currently only detects `const smth = @import("string literal")<.SomeThing>;`
    for (tree.root_node.decls()) |decl| {
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

fn checkForContainerAndResolveFieldAccessLhsType(analysis_ctx: *AnalysisContext, node: *ast.Node) *ast.Node {
    const current_node = resolveFieldAccessLhsType(analysis_ctx, node);

    if (current_node.id == .ContainerDecl or current_node.id == .Root) {
        // TODO: Handle errors
        analysis_ctx.onContainer(current_node) catch {};
    }

    return current_node;
}

pub fn getFieldAccessTypeNode(
    analysis_ctx: *AnalysisContext,
    tokenizer: *std.zig.Tokenizer,
) ?*ast.Node {
    var current_node = analysis_ctx.in_container;

    while (true) {
        const tok = tokenizer.next();
        switch (tok.id) {
            .Eof => return resolveFieldAccessLhsType(analysis_ctx, current_node),
            .Identifier => {
                if (getChildOfSlice(analysis_ctx.tree(), analysis_ctx.scope_nodes, tokenizer.buffer[tok.loc.start..tok.loc.end])) |child| {
                    if (resolveTypeOfNode(analysis_ctx, child)) |child_type| {
                        current_node = child_type;
                    } else return null;
                } else return null;
            },
            .Period => {
                const after_period = tokenizer.next();
                switch (after_period.id) {
                    .Eof => return resolveFieldAccessLhsType(analysis_ctx, current_node),
                    .Identifier => {
                        if (after_period.loc.end == tokenizer.buffer.len) return resolveFieldAccessLhsType(analysis_ctx, current_node);

                        current_node = checkForContainerAndResolveFieldAccessLhsType(analysis_ctx, current_node);
                        if (getChild(analysis_ctx.tree(), current_node, tokenizer.buffer[after_period.loc.start..after_period.loc.end])) |child| {
                            if (resolveTypeOfNode(analysis_ctx, child)) |child_type| {
                                current_node = child_type;
                            } else return null;
                        } else return null;
                    },
                    .QuestionMark => {
                        if (resolveUnwrapOptionalType(analysis_ctx, current_node)) |child_type| {
                            current_node = child_type;
                        } else return null;
                    },
                    else => {
                        std.debug.warn("Unrecognized token {} after period.\n", .{after_period.id});
                        return null;
                    },
                }
            },
            .PeriodAsterisk => {
                if (resolveDerefType(analysis_ctx, current_node)) |child_type| {
                    current_node = child_type;
                } else return null;
            },
            .LParen => {
                switch (current_node.id) {
                    .FnProto => {
                        const func = current_node.cast(ast.Node.FnProto).?;
                        if (resolveReturnType(analysis_ctx, func)) |ret| {
                            current_node = ret;
                            // Skip to the right paren
                            var paren_count: usize = 1;
                            var next = tokenizer.next();
                            while (next.id != .Eof) : (next = tokenizer.next()) {
                                if (next.id == .RParen) {
                                    paren_count -= 1;
                                    if (paren_count == 0) break;
                                } else if (next.id == .LParen) {
                                    paren_count += 1;
                                }
                            } else return null;
                        } else return null;
                    },
                    else => {},
                }
            },
            .LBracket => {
                var brack_count: usize = 1;
                var next = tokenizer.next();
                var is_range = false;
                while (next.id != .Eof) : (next = tokenizer.next()) {
                    if (next.id == .RBracket) {
                        brack_count -= 1;
                        if (brack_count == 0) break;
                    } else if (next.id == .LBracket) {
                        brack_count += 1;
                    } else if (next.id == .Ellipsis2 and brack_count == 1) {
                        is_range = true;
                    }
                } else return null;

                if (resolveBracketAccessType(
                    analysis_ctx,
                    current_node,
                    if (is_range) .Range else .Single,
                )) |child_type| {
                    current_node = child_type;
                } else return null;
            },
            else => {
                std.debug.warn("Unimplemented token: {}\n", .{tok.id});
                return null;
            },
        }

        if (current_node.id == .ContainerDecl or current_node.id == .Root) {
            analysis_ctx.onContainer(current_node) catch return null;
        }
    }

    return resolveFieldAccessLhsType(analysis_ctx, current_node);
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

fn makeAccessNode(allocator: *std.mem.Allocator, expr: *ast.Node) !*ast.Node {
    const suffix_op_node = try allocator.create(ast.Node.SuffixOp);
    suffix_op_node.* = .{
        .op = .{ .ArrayAccess = expr },
        .lhs = expr,
        .rtoken = expr.lastToken(),
    };
    return &suffix_op_node.base;
}

fn makeUnwrapNode(allocator: *std.mem.Allocator, expr: *ast.Node) !*ast.Node {
    const suffix_op_node = try allocator.create(ast.Node.SuffixOp);
    suffix_op_node.* = .{
        .op = .UnwrapOptional,
        .lhs = expr,
        .rtoken = expr.lastToken(),
    };
    return &suffix_op_node.base;
}

fn makeVarDeclNode(
    allocator: *std.mem.Allocator,
    doc: ?*ast.Node.DocComment,
    comptime_token: ?ast.TokenIndex,
    name_token: ast.TokenIndex,
    type_expr: ?*ast.Node,
    init_expr: ?*ast.Node,
) !*ast.Node {
    // TODO: This will not be needed anymore when we use out own decl type instead of directly
    // repurposing ast nodes.
    const var_decl_node = try allocator.create(ast.Node.VarDecl);
    var_decl_node.* = .{
        .doc_comments = doc,
        .comptime_token = comptime_token,
        .visib_token = null,
        .thread_local_token = null,
        .name_token = name_token,
        .eq_token = null,
        .mut_token = name_token,
        .extern_export_token = null,
        .lib_name = null,
        .type_node = type_expr,
        .align_node = null,
        .section_node = null,
        .init_node = init_expr,
        .semicolon_token = name_token,
    };

    return &var_decl_node.base;
}

fn nodeContainsSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.token_locs[node.firstToken()];
    const last_token = tree.token_locs[node.lastToken()];
    return source_index >= first_token.start and source_index <= last_token.end;
}

pub fn getImportStr(tree: *ast.Tree, source_index: usize) ?[]const u8 {
    var node = &tree.root_node.base;

    var child_idx: usize = 0;
    while (node.iterate(child_idx)) |child| {
        if (!nodeContainsSourceIndex(tree, child, source_index)) {
            child_idx += 1;
            continue;
        }
        if (child.cast(ast.Node.BuiltinCall)) |builtin_call| blk: {
            const call_name = tree.tokenSlice(builtin_call.builtin_token);

            if (!std.mem.eql(u8, call_name, "@import")) break :blk;
            if (builtin_call.params_len != 1) break :blk;

            const import_param = builtin_call.paramsConst()[0];
            const import_str_node = import_param.cast(ast.Node.StringLiteral) orelse break :blk;
            const import_str = tree.tokenSlice(import_str_node.token);
            return import_str[1 .. import_str.len - 1];
        }
        node = child;
        child_idx = 0;
    }
    return null;
}

pub const SourceRange = std.zig.Token.Loc;

pub const PositionContext = union(enum) {
    builtin: SourceRange,
    comment,
    string_literal: SourceRange,
    field_access: SourceRange,
    var_access: SourceRange,
    global_error_set,
    enum_literal,
    other,
    empty,

    pub fn range(self: PositionContext) ?SourceRange {
        return switch (self) {
            .builtin => |r| r,
            .comment => null,
            .string_literal => |r| r,
            .field_access => |r| r,
            .var_access => |r| r,
            .enum_literal => null,
            .other => null,
            .empty => null,
            .global_error_set => null,
        };
    }
};

const StackState = struct {
    ctx: PositionContext,
    stack_id: enum { Paren, Bracket, Global },
};

fn peek(arr: *std.ArrayList(StackState)) !*StackState {
    if (arr.items.len == 0) {
        try arr.append(.{ .ctx = .empty, .stack_id = .Global });
    }
    return &arr.items[arr.items.len - 1];
}

fn tokenRangeAppend(prev: SourceRange, token: std.zig.Token) SourceRange {
    return .{
        .start = prev.start,
        .end = token.loc.end,
    };
}

pub fn documentPositionContext(allocator: *std.mem.Allocator, document: types.TextDocument, position: types.Position) !PositionContext {
    const line = try document.getLine(@intCast(usize, position.line));
    const pos_char = @intCast(usize, position.character) + 1;
    const idx = if (pos_char > line.len) line.len else pos_char;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var tokenizer = std.zig.Tokenizer.init(line[0..idx]);
    var stack = try std.ArrayList(StackState).initCapacity(&arena.allocator, 8);

    while (true) {
        const tok = tokenizer.next();
        // Early exits.
        switch (tok.id) {
            .Invalid, .Invalid_ampersands => {
                // Single '@' do not return a builtin token so we check this on our own.
                if (line[idx - 1] == '@') {
                    return PositionContext{
                        .builtin = .{
                            .start = idx - 1,
                            .end = idx,
                        },
                    };
                }
                return .other;
            },
            .LineComment, .DocComment, .ContainerDocComment => return .comment,
            .Eof => break,
            else => {},
        }

        // State changes
        var curr_ctx = try peek(&stack);
        switch (tok.id) {
            .StringLiteral, .MultilineStringLiteralLine => curr_ctx.ctx = .{ .string_literal = tok.loc },
            .Identifier => switch (curr_ctx.ctx) {
                .empty => curr_ctx.ctx = .{ .var_access = tok.loc },
                else => {},
            },
            .Builtin => switch (curr_ctx.ctx) {
                .empty => curr_ctx.ctx = .{ .builtin = tok.loc },
                else => {},
            },
            .Period, .PeriodAsterisk => switch (curr_ctx.ctx) {
                .empty => curr_ctx.ctx = .enum_literal,
                .enum_literal => curr_ctx.ctx = .empty,
                .field_access => {},
                .other => {},
                .global_error_set => {},
                else => curr_ctx.ctx = .{
                    .field_access = tokenRangeAppend(curr_ctx.ctx.range().?, tok),
                },
            },
            .QuestionMark => switch (curr_ctx.ctx) {
                .field_access => {},
                else => curr_ctx.ctx = .empty,
            },
            .LParen => try stack.append(.{ .ctx = .empty, .stack_id = .Paren }),
            .LBracket => try stack.append(.{ .ctx = .empty, .stack_id = .Bracket }),
            .RParen => {
                _ = stack.pop();
                if (curr_ctx.stack_id != .Paren) {
                    (try peek(&stack)).ctx = .empty;
                }
            },
            .RBracket => {
                _ = stack.pop();
                if (curr_ctx.stack_id != .Bracket) {
                    (try peek(&stack)).ctx = .empty;
                }
            },
            .Keyword_error => curr_ctx.ctx = .global_error_set,
            else => curr_ctx.ctx = .empty,
        }

        switch (curr_ctx.ctx) {
            .field_access => |r| curr_ctx.ctx = .{
                .field_access = tokenRangeAppend(r, tok),
            },
            else => {},
        }
    }

    return block: {
        if (stack.popOrNull()) |state| break :block state.ctx;
        break :block .empty;
    };
}

fn addOutlineNodes(allocator: *std.mem.Allocator, children: *std.ArrayList(types.DocumentSymbol), tree: *ast.Tree, child: *ast.Node) anyerror!void {
    switch (child.id) {
        .StringLiteral, .IntegerLiteral, .BuiltinCall, .Call, .Identifier, .InfixOp, .PrefixOp, .SuffixOp, .ControlFlowExpression, .ArrayInitializerDot, .SwitchElse, .SwitchCase, .For, .EnumLiteral, .PointerIndexPayload, .StructInitializerDot, .PointerPayload, .While, .Switch, .Else, .BoolLiteral, .NullLiteral, .Defer, .StructInitializer, .FieldInitializer, .If, .MultilineStringLiteral, .UndefinedLiteral, .VarType, .Block, .ErrorSetDecl => return,

        .ContainerDecl => {
            const decl = child.cast(ast.Node.ContainerDecl).?;

            for (decl.fieldsAndDecls()) |cchild|
                try addOutlineNodes(allocator, children, tree, cchild);
            return;
        },
        else => {},
    }
    _ = try children.append(try getDocumentSymbolsInternal(allocator, tree, child));
}

fn getDocumentSymbolsInternal(allocator: *std.mem.Allocator, tree: *ast.Tree, node: *ast.Node) anyerror!types.DocumentSymbol {
    // const symbols = std.ArrayList(types.DocumentSymbol).init(allocator);
    const start_loc = tree.tokenLocation(0, node.firstToken());
    const end_loc = tree.tokenLocation(0, node.lastToken());
    const range = types.Range{
        .start = .{
            .line = @intCast(i64, start_loc.line),
            .character = @intCast(i64, start_loc.column),
        },
        .end = .{
            .line = @intCast(i64, end_loc.line),
            .character = @intCast(i64, end_loc.column),
        },
    };

    if (getDeclName(tree, node) == null) {
        std.debug.warn("NULL NAME: {}\n", .{node.id});
    }

    const maybe_name = if (getDeclName(tree, node)) |name|
        name
    else
        "";

    // TODO: Get my lazy bum to fix detail newlines
    return types.DocumentSymbol{
        .name = if (maybe_name.len == 0) switch (node.id) {
            .TestDecl => "Nameless Test",
            else => "no_name",
        } else maybe_name,
        // .detail = (try getDocComments(allocator, tree, node)) orelse "",
        .detail = "",
        .kind = switch (node.id) {
            .FnProto => .Function,
            .VarDecl => .Variable,
            .ContainerField => .Field,
            else => .Variable,
        },
        .range = range,
        .selectionRange = range,
        .children = ch: {
            var children = std.ArrayList(types.DocumentSymbol).init(allocator);

            var index: usize = 0;
            while (node.iterate(index)) |child| : (index += 1) {
                try addOutlineNodes(allocator, &children, tree, child);
            }

            break :ch children.items;
        },
    };

    // return symbols.items;
}

pub fn getDocumentSymbols(allocator: *std.mem.Allocator, tree: *ast.Tree) ![]types.DocumentSymbol {
    var symbols = std.ArrayList(types.DocumentSymbol).init(allocator);

    for (tree.root_node.decls()) |node| {
        _ = try symbols.append(try getDocumentSymbolsInternal(allocator, tree, node));
    }

    return symbols.items;
}

const DocumentStore = @import("document_store.zig");

pub const Declaration = union(enum) {
    ast_node: *ast.Node,
    param_decl: *ast.Node.FnProto.ParamDecl,
    pointer_payload: struct {
        node: *ast.Node.PointerPayload,
        condition: *ast.Node,
    },
    array_payload: struct {
        identifier: *ast.Node,
        array_expr: *ast.Node,
    },
    switch_payload: struct {
        node: *ast.Node.PointerPayload,
        items: []const *ast.Node,
    },
};

pub const DeclWithHandle = struct {
    decl: *Declaration,
    handle: *DocumentStore.Handle,

    pub fn location(self: DeclWithHandle) ast.Tree.Location {
        const tree = self.handle.tree;
        return switch (self.decl.*) {
            .ast_node => |n| block: {
                const name_token = getDeclNameToken(tree, n).?;
                break :block tree.tokenLocation(0, name_token);
            },
            .param_decl => |p| tree.tokenLocation(0, p.name_token.?),
            .pointer_payload => |pp| tree.tokenLocation(0, pp.node.value_symbol.firstToken()),
            .array_payload => |ap| tree.tokenLocation(0, ap.identifier.firstToken()),
            .switch_payload => |sp| tree.tokenLocation(0, sp.node.value_symbol.firstToken()),
        };
    }
};

pub fn iterateSymbolsGlobal(
    store: *DocumentStore,
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: var,
    context: var,
) !void {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            var decl_it = scope.decls.iterator();
            while (decl_it.next()) |entry| {
                try callback(context, DeclWithHandle{ .decl = &entry.value, .handle = handle });
            }

            for (scope.uses) |use| {
                // @TODO Resolve uses, iterate over their symbols.
            }
        }

        if (scope.range.start >= source_index) return;
    }
}

pub fn lookupSymbolGlobal(store: *DocumentStore, handle: *DocumentStore.Handle, symbol: []const u8, source_index: usize) !?DeclWithHandle {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            if (scope.decls.get(symbol)) |candidate| {
                switch (candidate.value) {
                    .ast_node => |node| {
                        if (node.id == .ContainerField) continue;
                    },
                    else => {},
                }
                return DeclWithHandle{
                    .decl = &candidate.value,
                    .handle = handle,
                };
            }

            for (scope.uses) |use| {
                // @TODO Resolve use, lookup symbol in resulting scope.
            }
        }

        if (scope.range.start >= source_index) return null;
    }

    return null;
}

pub fn lookupSymbolContainer(store: *DocumentScope, handle: *DocumentStore.Handle, container: *ast.Node, symbol: []const u8, accept_fields: bool) !?DeclWithHandle {
    std.debug.assert(container.id == .ContainerDecl or container.id == .Root);
    // Find the container scope.
    var maybe_container_scope: ?*Scope = null;
    for (handle.document_scope.scopes) |*scope| {
        switch (scope.*) {
            .container => |node| if (node == container) {
                maybe_container_scope = scope;
                break;
            },
        }
    }

    if (maybe_container_scope) |container_scope| {
        if (container_scope.decls.get(symbol)) |candidate| {
            switch (candidate.value) {
                .ast_node => |node| {
                    if (node.id == .ContainerDecl and !accept_fields) return null;
                },
                else => {},
            }
            return &candidate.value;
        }

        for (container_scope.uses) |use| {
            // @TODO Resolve use, lookup symbol in resulting scope.
        }
        return null;
    }
    unreachable;
}

pub const DocumentScope = struct {
    scopes: []const Scope,

    pub fn debugPrint(self: DocumentScope) void {
        for (self.scopes) |scope| {
            std.debug.warn(
                \\--------------------------
                \\Scope {}, range: [{}, {})
                \\ {} usingnamespaces
                \\Decls: 
            , .{
                scope.data,
                scope.range.start,
                scope.range.end,
                scope.uses.len,
            });

            var decl_it = scope.decls.iterator();
            var idx: usize = 0;
            while (decl_it.next()) |name_decl| : (idx += 1) {
                if (idx != 0) std.debug.warn(", ", .{});
                std.debug.warn("{}", .{name_decl.key});
            }
            std.debug.warn("\n--------------------------\n", .{});
        }
    }

    pub fn deinit(self: DocumentScope, allocator: *std.mem.Allocator) void {
        for (self.scopes) |scope| {
            scope.decls.deinit();
            allocator.free(scope.uses);
        }
        allocator.free(self.scopes);
    }
};

pub const Scope = struct {
    pub const Data = union(enum) {
        container: *ast.Node, // .id is ContainerDecl or Root
        function: *ast.Node, // .id is FnProto
        block: *ast.Node, // .id is Block
        other,
    };

    range: SourceRange,
    decls: std.StringHashMap(Declaration),
    tests: []const *ast.Node,
    uses: []const *ast.Node.Use,

    data: Data,
};

pub fn makeDocumentScope(allocator: *std.mem.Allocator, tree: *ast.Tree) !DocumentScope {
    var scopes = std.ArrayList(Scope).init(allocator);
    errdefer scopes.deinit();

    try makeScopeInternal(allocator, &scopes, tree, &tree.root_node.base);
    return DocumentScope{
        .scopes = scopes.toOwnedSlice(),
    };
}

fn nodeSourceRange(tree: *ast.Tree, node: *ast.Node) SourceRange {
    return SourceRange{
        .start = tree.token_locs[node.firstToken()].start,
        .end = tree.token_locs[node.lastToken()].end,
    };
}

// TODO Make enum and error stores per-document
//      CLear the doc ones before calling this and
//      rebuild them here.

fn makeScopeInternal(
    allocator: *std.mem.Allocator,
    scopes: *std.ArrayList(Scope),
    tree: *ast.Tree,
    node: *ast.Node,
) error{OutOfMemory}!void {
    if (node.id == .Root or node.id == .ContainerDecl) {
        const ast_decls = switch (node.id) {
            .ContainerDecl => node.cast(ast.Node.ContainerDecl).?.fieldsAndDeclsConst(),
            .Root => node.cast(ast.Node.Root).?.declsConst(),
            else => unreachable,
        };

        (try scopes.addOne()).* = .{
            .range = nodeSourceRange(tree, node),
            .decls = std.StringHashMap(Declaration).init(allocator),
            .uses = &[0]*ast.Node.Use{},
            .tests = &[0]*ast.Node{},
            .data = .{ .container = node },
        };
        var scope_idx = scopes.items.len - 1;
        var uses = std.ArrayList(*ast.Node.Use).init(allocator);
        var tests = std.ArrayList(*ast.Node).init(allocator);

        errdefer {
            scopes.items[scope_idx].decls.deinit();
            uses.deinit();
            tests.deinit();
        }

        for (ast_decls) |decl| {
            if (decl.cast(ast.Node.Use)) |use| {
                try uses.append(use);
                continue;
            }

            try makeScopeInternal(allocator, scopes, tree, decl);
            const name = getDeclName(tree, decl) orelse continue;
            if (decl.id == .TestDecl) {
                try tests.append(decl);
                continue;
            }

            if (try scopes.items[scope_idx].decls.put(name, .{ .ast_node = decl })) |existing| {
                // TODO Record a redefinition error.
            }
        }

        scopes.items[scope_idx].uses = uses.toOwnedSlice();
        return;
    }

    switch (node.id) {
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;

            (try scopes.addOne()).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                .uses = &[0]*ast.Node.Use{},
                .data = .{ .function = node },
            };
            var scope_idx = scopes.items.len - 1;
            errdefer scopes.items[scope_idx].decls.deinit();

            for (func.params()) |*param| {
                if (param.name_token) |name_tok| {
                    if (try scopes.items[scope_idx].decls.put(tree.tokenSlice(name_tok), .{ .param_decl = param })) |existing| {
                        // TODO Record a redefinition error
                    }
                }
            }

            if (func.body_node) |body| {
                try makeScopeInternal(allocator, scopes, tree, body);
            }

            return;
        },
        .TestDecl => {
            return try makeScopeInternal(allocator, scopes, tree, node.cast(ast.Node.TestDecl).?.body_node);
        },
        .Block => {
            (try scopes.addOne()).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                .uses = &[0]*ast.Node.Use{},
                .data = .{ .block = node },
            };
            var scope_idx = scopes.items.len - 1;
            var uses = std.ArrayList(*ast.Node.Use).init(allocator);

            errdefer {
                scopes.items[scope_idx].decls.deinit();
                uses.deinit();
            }

            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
                if (child_node.cast(ast.Node.Use)) |use| {
                    try uses.append(use);
                    continue;
                }

                try makeScopeInternal(allocator, scopes, tree, child_node);
                if (child_node.cast(ast.Node.VarDecl)) |var_decl| {
                    const name = tree.tokenSlice(var_decl.name_token);
                    if (try scopes.items[scope_idx].decls.put(name, .{ .ast_node = child_node })) |existing| {
                        // TODO Record a redefinition error.
                    }
                }
            }

            scopes.items[scope_idx].uses = uses.toOwnedSlice();
            return;
        },
        .Comptime => {
            return try makeScopeInternal(allocator, scopes, tree, node.cast(ast.Node.Comptime).?.expr);
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;

            if (if_node.payload) |payload| {
                std.debug.assert(payload.id == .PointerPayload);
                var scope = try scopes.addOne();
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[payload.firstToken()].start,
                        .end = tree.token_locs[if_node.body.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    .uses = &[0]*ast.Node.Use{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const ptr_payload = payload.cast(ast.Node.PointerPayload).?;
                std.debug.assert(ptr_payload.value_symbol.id == .Identifier);
                const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .node = ptr_payload,
                        .condition = if_node.condition,
                    },
                });
            }
            try makeScopeInternal(allocator, scopes, tree, if_node.body);

            if (if_node.@"else") |else_node| {
                if (else_node.payload) |payload| {
                    std.debug.assert(payload.id == .Payload);
                    var scope = try scopes.addOne();
                    scope.* = .{
                        .range = .{
                            .start = tree.token_locs[payload.firstToken()].start,
                            .end = tree.token_locs[else_node.body.lastToken()].end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        .uses = &[0]*ast.Node.Use{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const err_payload = payload.cast(ast.Node.Payload).?;
                    std.debug.assert(err_payload.error_symbol.id == .Identifier);
                    const name = tree.tokenSlice(err_payload.error_symbol.firstToken());
                    try scope.decls.putNoClobber(name, .{ .ast_node = payload });
                }
                try makeScopeInternal(allocator, scopes, tree, else_node.body);
            }
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            if (while_node.payload) |payload| {
                std.debug.assert(payload.id == .PointerPayload);
                var scope = try scopes.addOne();
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[payload.firstToken()].start,
                        .end = tree.token_locs[while_node.body.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    .uses = &[0]*ast.Node.Use{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const ptr_payload = payload.cast(ast.Node.PointerPayload).?;
                std.debug.assert(ptr_payload.value_symbol.id == .Identifier);
                const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .node = ptr_payload,
                        .condition = while_node.condition,
                    },
                });
            }
            try makeScopeInternal(allocator, scopes, tree, while_node.body);

            if (while_node.@"else") |else_node| {
                if (else_node.payload) |payload| {
                    std.debug.assert(payload.id == .Payload);
                    var scope = try scopes.addOne();
                    scope.* = .{
                        .range = .{
                            .start = tree.token_locs[payload.firstToken()].start,
                            .end = tree.token_locs[else_node.body.lastToken()].end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        .uses = &[0]*ast.Node.Use{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const err_payload = payload.cast(ast.Node.Payload).?;
                    std.debug.assert(err_payload.error_symbol.id == .Identifier);
                    const name = tree.tokenSlice(err_payload.error_symbol.firstToken());
                    try scope.decls.putNoClobber(name, .{ .ast_node = payload });
                }
                try makeScopeInternal(allocator, scopes, tree, else_node.body);
            }
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            std.debug.assert(for_node.payload.id == .PointerIndexPayload);
            const ptr_idx_payload = for_node.payload.cast(ast.Node.PointerIndexPayload).?;
            std.debug.assert(ptr_idx_payload.value_symbol.id == .Identifier);

            var scope = try scopes.addOne();
            scope.* = .{
                .range = .{
                    .start = tree.token_locs[ptr_idx_payload.firstToken()].start,
                    .end = tree.token_locs[for_node.body.lastToken()].end,
                },
                .decls = std.StringHashMap(Declaration).init(allocator),
                .uses = &[0]*ast.Node.Use{},
                .data = .other,
            };
            errdefer scope.decls.deinit();

            const value_name = tree.tokenSlice(ptr_idx_payload.value_symbol.firstToken());
            try scope.decls.putNoClobber(value_name, .{
                .array_payload = .{
                    .identifier = ptr_idx_payload.value_symbol,
                    .array_expr = for_node.array_expr,
                },
            });

            if (ptr_idx_payload.index_symbol) |index_symbol| {
                std.debug.assert(index_symbol.id == .Identifier);
                const index_name = tree.tokenSlice(index_symbol.firstToken());
                if (try scope.decls.put(index_name, .{ .ast_node = index_symbol })) |existing| {
                    // TODO Record a redefinition error
                }
            }

            try makeScopeInternal(allocator, scopes, tree, for_node.body);
            if (for_node.@"else") |else_node| {
                std.debug.assert(else_node.payload == null);
                try makeScopeInternal(allocator, scopes, tree, else_node.body);
            }
        },
        .Switch => {
            const switch_node = node.cast(ast.Node.Switch).?;
            for (switch_node.casesConst()) |case| {
                if (case.*.cast(ast.Node.SwitchCase)) |case_node| {
                    if (case_node.payload) |payload| {
                        std.debug.assert(payload.id == .PointerPayload);
                        var scope = try scopes.addOne();
                        scope.* = .{
                            .range = .{
                                .start = tree.token_locs[payload.firstToken()].start,
                                .end = tree.token_locs[case_node.expr.lastToken()].end,
                            },
                            .decls = std.StringHashMap(Declaration).init(allocator),
                            .uses = &[0]*ast.Node.Use{},
                            .data = .other,
                        };
                        errdefer scope.decls.deinit();

                        const ptr_payload = payload.cast(ast.Node.PointerPayload).?;
                        std.debug.assert(ptr_payload.value_symbol.id == .Identifier);
                        const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                        try scope.decls.putNoClobber(name, .{
                            .switch_payload = .{
                                .node = ptr_payload,
                                .items = case_node.itemsConst(),
                            },
                        });
                    }
                    try makeScopeInternal(allocator, scopes, tree, case_node.expr);
                }
            }
        },
        .VarDecl => {
            const var_decl = node.cast(ast.Node.VarDecl).?;
            if (var_decl.type_node) |type_node| {
                try makeScopeInternal(allocator, scopes, tree, type_node);
            }
            if (var_decl.init_node) |init_node| {
                try makeScopeInternal(allocator, scopes, tree, init_node);
            }
        },
        else => {
            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
                try makeScopeInternal(allocator, scopes, tree, child_node);
            }
        },
    }
}
