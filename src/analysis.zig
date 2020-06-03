const std = @import("std");
const AnalysisContext = @import("document_store.zig").AnalysisContext;
const ast = std.zig.ast;
const types = @import("types.zig");

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

    return try std.mem.join(allocator, "\n", lines.items);
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
pub fn getFunctionSnippet(allocator: *std.mem.Allocator, tree: *ast.Tree, func: *ast.Node.FnProto) ![]const u8 {
    const name_tok = func.name_token orelse unreachable;

    var buffer = std.ArrayList(u8).init(allocator);
    try buffer.ensureCapacity(128);

    try buffer.appendSlice(tree.tokenSlice(name_tok));
    try buffer.append('(');

    var buf_stream = buffer.outStream();

    for (func.paramsConst()) |param, param_num| {
        if (param_num != 0) try buffer.appendSlice(", ${") else try buffer.appendSlice("${");

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

                    // @TODO
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

                    const var_decl_node = analysis_ctx.arena.allocator.create(ast.Node.VarDecl) catch return null;
                    var_decl_node.* = .{
                        .doc_comments = decl_param.doc_comments,
                        .comptime_token = decl_param.comptime_token,
                        .visib_token = null,
                        .thread_local_token = null,
                        .name_token = decl_param.name_token.?,
                        .eq_token = null,
                        .mut_token = decl_param.name_token.?,
                        .extern_export_token = null,
                        .lib_name = null,
                        .type_node = null,
                        .align_node = null,
                        .section_node = null,
                        .init_node = call_param_type,
                        .semicolon_token = decl_param.name_token.?,
                    };

                    scope_nodes.append(&var_decl_node.base) catch return null;
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

            if (!std.mem.eql(u8, call_name, "@import")) return null;
            if (builtin_call.params_len > 1) return null;

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

pub fn declsFromIndexInternal(
    arena: *std.heap.ArenaAllocator,
    decls: *std.ArrayList(*ast.Node),
    tree: *ast.Tree,
    node: *ast.Node,
    source_index: usize,
) error{OutOfMemory}!void {
    switch (node.id) {
        .Root, .ContainerDecl => {
            var node_idx: usize = 0;
            while (node.iterate(node_idx)) |child_node| : (node_idx += 1) {
                // Skip over container fields, we can only dot access those.
                if (child_node.id == .ContainerField) continue;

                const is_contained = nodeContainsSourceIndex(tree, child_node, source_index);
                // If the cursor is in a variable decls it will insert itself anyway, we don't need to take care of it.
                if ((is_contained and child_node.id != .VarDecl) or !is_contained) try decls.append(child_node);
                if (is_contained) {
                    try declsFromIndexInternal(arena, decls, tree, child_node, source_index);
                }
            }
        },
        .FnProto => {
            const func = node.cast(ast.Node.FnProto).?;

            // TODO: This is a hack to enable param decls with the new parser
            for (func.paramsConst()) |param| {
                if (param.param_type != .type_expr) continue;
                if (param.name_token) |name_token| {
                    const var_decl_node = try arena.allocator.create(ast.Node.VarDecl);
                    var_decl_node.* = .{
                        .doc_comments = param.doc_comments,
                        .comptime_token = param.comptime_token,
                        .visib_token = null,
                        .thread_local_token = null,
                        .name_token = name_token,
                        .eq_token = null,
                        .mut_token = name_token, // TODO: better tokens for mut_token. semicolon_token?
                        .extern_export_token = null,
                        .lib_name = null,
                        .type_node = switch (param.param_type) {
                            .type_expr => |t| t,
                            else => unreachable,
                        },
                        .align_node = null,
                        .section_node = null,
                        .init_node = null,
                        .semicolon_token = name_token,
                    };

                    try decls.append(&var_decl_node.base);
                }
            }

            if (func.body_node) |body_node| {
                if (!nodeContainsSourceIndex(tree, body_node, source_index)) return;
                try declsFromIndexInternal(arena, decls, tree, body_node, source_index);
            }
        },
        .TestDecl => {
            const test_decl = node.cast(ast.Node.TestDecl).?;
            if (!nodeContainsSourceIndex(tree, test_decl.body_node, source_index)) return;
            try declsFromIndexInternal(arena, decls, tree, test_decl.body_node, source_index);
        },
        .Block => {
            var inode_idx: usize = 0;
            while (node.iterate(inode_idx)) |inode| : (inode_idx += 1) {
                if (nodeComesAfterSourceIndex(tree, inode, source_index)) return;
                try declsFromIndexInternal(arena, decls, tree, inode, source_index);
            }
        },
        .Comptime => {
            const comptime_stmt = node.cast(ast.Node.Comptime).?;
            if (nodeComesAfterSourceIndex(tree, comptime_stmt.expr, source_index)) return;
            try declsFromIndexInternal(arena, decls, tree, comptime_stmt.expr, source_index);
        },
        .If => {
            const if_node = node.cast(ast.Node.If).?;
            if (nodeContainsSourceIndex(tree, if_node.body, source_index)) {
                if (if_node.payload) |payload| {
                    try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                }
                return try declsFromIndexInternal(arena, decls, tree, if_node.body, source_index);
            }

            if (if_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(arena, decls, tree, else_node.body, source_index);
                }
            }
        },
        .While => {
            const while_node = node.cast(ast.Node.While).?;
            if (nodeContainsSourceIndex(tree, while_node.body, source_index)) {
                if (while_node.payload) |payload| {
                    try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                }
                return try declsFromIndexInternal(arena, decls, tree, while_node.body, source_index);
            }

            if (while_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(arena, decls, tree, else_node.body, source_index);
                }
            }
        },
        .For => {
            const for_node = node.cast(ast.Node.For).?;
            if (nodeContainsSourceIndex(tree, for_node.body, source_index)) {
                try declsFromIndexInternal(arena, decls, tree, for_node.payload, source_index);
                return try declsFromIndexInternal(arena, decls, tree, for_node.body, source_index);
            }

            if (for_node.@"else") |else_node| {
                if (nodeContainsSourceIndex(tree, else_node.body, source_index)) {
                    if (else_node.payload) |payload| {
                        try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(arena, decls, tree, else_node.body, source_index);
                }
            }
        },
        .Switch => {
            const switch_node = node.cast(ast.Node.Switch).?;
            for (switch_node.casesConst()) |case| {
                const case_node = case.*.cast(ast.Node.SwitchCase).?;
                if (nodeContainsSourceIndex(tree, case_node.expr, source_index)) {
                    if (case_node.payload) |payload| {
                        try declsFromIndexInternal(arena, decls, tree, payload, source_index);
                    }
                    return try declsFromIndexInternal(arena, decls, tree, case_node.expr, source_index);
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
                    try declsFromIndexInternal(arena, decls, tree, child, source_index);
                }
            }
        },
        else => {},
    }
}

pub fn addChildrenNodes(decls: *std.ArrayList(*ast.Node), tree: *ast.Tree, node: *ast.Node) !void {
    var node_idx: usize = 0;
    while (node.iterate(node_idx)) |child_node| : (node_idx += 1) {
        try decls.append(child_node);
    }
}

pub fn declsFromIndex(arena: *std.heap.ArenaAllocator, decls: *std.ArrayList(*ast.Node), tree: *ast.Tree, source_index: usize) !void {
    try declsFromIndexInternal(arena, decls, tree, &tree.root_node.base, source_index);
}

fn nodeContainsSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.token_locs[node.firstToken()];
    const last_token = tree.token_locs[node.lastToken()];
    return source_index >= first_token.start and source_index <= last_token.end;
}

fn nodeComesAfterSourceIndex(tree: *ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.token_locs[node.firstToken()];
    const last_token = tree.token_locs[node.lastToken()];
    return source_index < first_token.start;
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
        .StringLiteral, .IntegerLiteral, .BuiltinCall, .Call, .Identifier, .InfixOp, .PrefixOp, .SuffixOp, .ControlFlowExpression, .ArrayInitializerDot, .SwitchElse, .SwitchCase, .For, .EnumLiteral, .PointerIndexPayload, .StructInitializerDot, .PointerPayload, .While, .Switch, .Else, .BoolLiteral, .NullLiteral, .Defer, .StructInitializer, .FieldInitializer, .If, .MultilineStringLiteral, .UndefinedLiteral, .VarType, .Block => return,

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

    // TODO: Get my lazy bum to fix detail newlines
    return types.DocumentSymbol{
        .name = getDeclName(tree, node) orelse "no_name",
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
