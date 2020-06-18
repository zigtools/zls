const std = @import("std");
const DocumentStore = @import("document_store.zig");
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
pub fn getDocComments(
    allocator: *std.mem.Allocator,
    tree: *ast.Tree,
    node: *ast.Node,
    format: types.MarkupKind,
) !?[]const u8 {
    if (getDocCommentNode(tree, node)) |doc_comment_node| {
        return try collectDocComments(allocator, tree, doc_comment_node, format);
    }
    return null;
}

pub fn collectDocComments(
    allocator: *std.mem.Allocator,
    tree: *ast.Tree,
    doc_comments: *ast.Node.DocComment,
    format: types.MarkupKind,
) ![]const u8 {
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

    return try std.mem.join(allocator, if (format == .Markdown) "  \n" else "\n", lines.items);
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

// analysis.getContainerFieldSignature(handle.tree, field)
pub fn getContainerFieldSignature(tree: *ast.Tree, field: *ast.Node.ContainerField) []const u8 {
    const start = tree.token_locs[field.firstToken()].start;
    const end = tree.token_locs[field.lastToken()].end;
    return tree.source[start..end];
}

/// The type node is "type"
fn typeIsType(tree: *ast.Tree, node: *ast.Node) bool {
    if (node.cast(ast.Node.Identifier)) |ident| {
        return std.mem.eql(u8, tree.tokenSlice(ident.token), "type");
    }
    return false;
}

pub fn isTypeFunction(tree: *ast.Tree, func: *ast.Node.FnProto) bool {
    switch (func.return_type) {
        .Explicit => |node| return typeIsType(tree, node),
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
        .ErrorTag => {
            const tag = node.cast(ast.Node.ErrorTag).?;
            return tag.name_token;
        },
        // We need identifier for captures and error set tags
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

fn isContainerDecl(decl_handle: DeclWithHandle) bool {
    return switch (decl_handle.decl.*) {
        .ast_node => |inner_node| inner_node.id == .ContainerDecl or inner_node.id == .Root,
        else => false,
    };
}

fn resolveVarDeclAliasInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    node_handle: NodeWithHandle,
    root: bool,
) error{OutOfMemory}!?DeclWithHandle {
    const handle = node_handle.handle;
    if (node_handle.node.cast(ast.Node.Identifier)) |ident| {
        return try lookupSymbolGlobal(store, arena, handle, handle.tree.tokenSlice(ident.token), handle.tree.token_locs[ident.token].start);
    }

    if (node_handle.node.cast(ast.Node.InfixOp)) |infix_op| {
        if (infix_op.op != .Period) return null;

        const container_node = if (infix_op.lhs.cast(ast.Node.BuiltinCall)) |builtin_call| block: {
            if (!std.mem.eql(u8, handle.tree.tokenSlice(builtin_call.builtin_token), "@import"))
                return null;
            const inner_node = (try resolveTypeOfNode(store, arena, .{ .node = infix_op.lhs, .handle = handle })) orelse return null;
            std.debug.assert(inner_node.type.data.other.id == .Root);
            break :block NodeWithHandle{ .node = inner_node.type.data.other, .handle = inner_node.handle };
        } else if (try resolveVarDeclAliasInternal(store, arena, .{ .node = infix_op.lhs, .handle = handle }, false)) |decl_handle| block: {
            if (decl_handle.decl.* != .ast_node) return null;
            const resolved = (try resolveTypeOfNode(store, arena, .{ .node = decl_handle.decl.ast_node, .handle = decl_handle.handle })) orelse return null;
            const resolved_node = switch (resolved.type.data) {
                .other => |n| n,
                else => return null,
            };

            if (resolved_node.id != .ContainerDecl and resolved_node.id != .Root) return null;
            break :block NodeWithHandle{ .node = resolved_node, .handle = resolved.handle };
        } else return null;

        if (try lookupSymbolContainer(store, arena, container_node, handle.tree.tokenSlice(infix_op.rhs.firstToken()), false)) |inner_decl| {
            if (root) return inner_decl;
            return inner_decl;
        }
    }
    return null;
}

/// Resolves variable declarations consisting of chains of imports and field accesses of containers, ending with the same name as the variable decl's name
/// Examples:
///```zig
/// const decl = @import("decl-file.zig").decl;
/// const other = decl.middle.other;
///```
pub fn resolveVarDeclAlias(store: *DocumentStore, arena: *std.heap.ArenaAllocator, decl_handle: NodeWithHandle) !?DeclWithHandle {
    const decl = decl_handle.node;
    const handle = decl_handle.handle;

    if (decl.cast(ast.Node.VarDecl)) |var_decl| {
        if (var_decl.init_node == null) return null;
        if (handle.tree.token_ids[var_decl.mut_token] != .Keyword_const) return null;

        const base_expr = var_decl.init_node.?;
        if (base_expr.cast(ast.Node.InfixOp)) |infix_op| {
            if (infix_op.op != .Period) return null;
            const name = handle.tree.tokenSlice(infix_op.rhs.firstToken());
            if (!std.mem.eql(u8, handle.tree.tokenSlice(var_decl.name_token), name))
                return null;

            return try resolveVarDeclAliasInternal(store, arena, .{ .node = base_expr, .handle = handle }, true);
        }
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
            .ControlFlowExpression => blk: {
                const cfe = child_node.cast(ast.Node.ControlFlowExpression).?;
                if (cfe.kind != .Return) break :blk;

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
fn resolveReturnType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    fn_decl: *ast.Node.FnProto,
    handle: *DocumentStore.Handle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    if (isTypeFunction(handle.tree, fn_decl) and fn_decl.body_node != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(handle.tree, fn_decl) orelse return null;
        if (ret.rhs) |rhs| {
            return try resolveTypeOfNodeInternal(store, arena, .{
                .node = rhs,
                .handle = handle,
            }, bound_type_params);
        }

        return null;
    }

    return switch (fn_decl.return_type) {
        .InferErrorSet => |return_type| block: {
            const child_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = return_type,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            const child_type_node = switch (child_type.type.data) {
                .other => |n| n,
                else => return null,
            };
            break :block TypeWithHandle{ .type = .{ .data = .{ .error_union = child_type_node }, .is_type_val = false }, .handle = child_type.handle };
        },
        .Explicit => |return_type| ((try resolveTypeOfNodeInternal(store, arena, .{
            .node = return_type,
            .handle = handle,
        }, bound_type_params)) orelse return null).instanceTypeVal(),
        .Invalid => null,
    };
}

/// Resolves the child type of an optional type
fn resolveUnwrapOptionalType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    opt: TypeWithHandle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    const opt_node = switch (opt.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (opt_node.cast(ast.Node.PrefixOp)) |prefix_op| {
        if (prefix_op.op == .OptionalType) {
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = prefix_op.rhs,
                .handle = opt.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        }
    }

    return null;
}

fn resolveUnwrapErrorType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    rhs: TypeWithHandle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    const rhs_node = switch (rhs.type.data) {
        .other => |n| n,
        .error_union => |n| return TypeWithHandle{
            .type = .{ .data = .{ .other = n }, .is_type_val = rhs.type.is_type_val },
            .handle = rhs.handle,
        },
        .primitive, .slice => return null,
    };

    if (rhs_node.cast(ast.Node.InfixOp)) |infix_op| {
        if (infix_op.op == .ErrorUnion) {
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = infix_op.rhs,
                .handle = rhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        }
    }

    return null;
}

/// Resolves the child type of a defer type
fn resolveDerefType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    deref: TypeWithHandle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    const deref_node = switch (deref.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (deref_node.cast(ast.Node.PrefixOp)) |pop| {
        if (pop.op == .PtrType) {
            const op_token_id = deref.handle.tree.token_ids[pop.op_token];
            switch (op_token_id) {
                .Asterisk => {
                    return ((try resolveTypeOfNodeInternal(store, arena, .{
                        .node = pop.rhs,
                        .handle = deref.handle,
                    }, bound_type_params)) orelse return null).instanceTypeVal();
                },
                .LBracket, .AsteriskAsterisk => return null,
                else => unreachable,
            }
        }
    }
    return null;
}

/// Resolves bracket access type (both slicing and array access)
fn resolveBracketAccessType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    lhs: TypeWithHandle,
    rhs: enum { Single, Range },
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    const lhs_node = switch (lhs.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (lhs_node.cast(ast.Node.PrefixOp)) |pop| {
        switch (pop.op) {
            .SliceType => {
                if (rhs == .Single)
                    return ((try resolveTypeOfNodeInternal(store, arena, .{
                        .node = pop.rhs,
                        .handle = lhs.handle,
                    }, bound_type_params)) orelse return null).instanceTypeVal();
                return lhs;
            },
            .ArrayType => {
                if (rhs == .Single)
                    return ((try resolveTypeOfNodeInternal(store, arena, .{
                        .node = pop.rhs,
                        .handle = lhs.handle,
                    }, bound_type_params)) orelse return null).instanceTypeVal();
                return TypeWithHandle{
                    .type = .{ .data = .{ .slice = pop.rhs }, .is_type_val = false },
                    .handle = lhs.handle,
                };
            },
            .PtrType => {
                if (pop.rhs.cast(std.zig.ast.Node.PrefixOp)) |child_pop| {
                    switch (child_pop.op) {
                        .ArrayType => {
                            if (rhs == .Single) {
                                return ((try resolveTypeOfNodeInternal(store, arena, .{
                                    .node = child_pop.rhs,
                                    .handle = lhs.handle,
                                }, bound_type_params)) orelse return null).instanceTypeVal();
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
fn resolveFieldAccessLhsType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    lhs: TypeWithHandle,
    bound_type_params: *BoundTypeParams,
) !TypeWithHandle {
    return (try resolveDerefType(store, arena, lhs, bound_type_params)) orelse lhs;
}

pub const BoundTypeParams = std.AutoHashMap(*const ast.Node.FnProto.ParamDecl, TypeWithHandle);

fn allDigits(str: []const u8) bool {
    for (str) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

pub fn isTypeIdent(tree: *ast.Tree, token_idx: ast.TokenIndex) bool {
    const PrimitiveTypes = std.ComptimeStringMap(void, .{
        .{"isize"},          .{"usize"},
        .{"c_short"},        .{"c_ushort"},
        .{"c_int"},          .{"c_uint"},
        .{"c_long"},         .{"c_ulong"},
        .{"c_longlong"},     .{"c_ulonglong"},
        .{"c_longdouble"},   .{"c_void"},
        .{"f16"},            .{"f32"},
        .{"f64"},            .{"f128"},
        .{"bool"},           .{"void"},
        .{"noreturn"},       .{"type"},
        .{"anyerror"},       .{"comptime_int"},
        .{"comptime_float"}, .{"anyframe"},
    });

    const text = tree.tokenSlice(token_idx);
    if (PrimitiveTypes.has(text)) return true;
    if (text.len > 1 and (text[0] == 'u' or text[0] == 'i') and allDigits(text[1..]))
        return true;

    return false;
}

/// Resolves the type of a node
fn resolveTypeOfNodeInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    node_handle: NodeWithHandle,
    bound_type_params: *BoundTypeParams,
) error{OutOfMemory}!?TypeWithHandle {
    const node = node_handle.node;
    const handle = node_handle.handle;

    switch (node.id) {
        .VarDecl => {
            const vari = node.cast(ast.Node.VarDecl).?;
            if (vari.type_node) |type_node| block: {
                return ((try resolveTypeOfNodeInternal(
                    store,
                    arena,
                    .{ .node = vari.type_node orelse break :block, .handle = handle },
                    bound_type_params,
                )) orelse break :block).instanceTypeVal();
            }

            return try resolveTypeOfNodeInternal(store, arena, .{ .node = vari.init_node.?, .handle = handle }, bound_type_params);
        },
        .Identifier => {
            if (isTypeIdent(handle.tree, node.firstToken())) {
                return TypeWithHandle{
                    .type = .{ .data = .primitive, .is_type_val = true },
                    .handle = handle,
                };
            }

            if (try lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.token_locs[node.firstToken()].start)) |child| {
                switch(child.decl.*) {
                    .ast_node => |n| if (n == node) return null,
                    else => {},
                }
                return try child.resolveType(store, arena, bound_type_params);
            }
            return null;
        },
        .ContainerField => {
            const field = node.cast(ast.Node.ContainerField).?;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = field.type_expr orelse return null, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .Call => {
            const call = node.cast(ast.Node.Call).?;
            const decl = (try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = call.lhs, .handle = handle },
                bound_type_params,
            )) orelse return null;

            if (decl.type.is_type_val) return null;
            const decl_node = switch (decl.type.data) {
                .other => |n| n,
                else => return null,
            };
            if (decl_node.cast(ast.Node.FnProto)) |fn_decl| {
                var has_self_param: u8 = 0;
                if (call.lhs.cast(ast.Node.InfixOp)) |lhs_infix_op| {
                    if (lhs_infix_op.op == .Period) {
                        has_self_param = 1;
                    }
                }

                // Bidn type params to the expressions passed in the calls.
                const param_len = std.math.min(call.params_len + has_self_param, fn_decl.params_len);
                for (fn_decl.paramsConst()) |*decl_param, param_idx| {
                    if (param_idx < has_self_param) continue;
                    if (param_idx >= param_len) break;

                    const type_param = switch (decl_param.param_type) {
                        .type_expr => |type_node| typeIsType(decl.handle.tree, type_node),
                        else => false,
                    };
                    if (!type_param) continue;

                    const call_param_type = (try resolveTypeOfNodeInternal(store, arena, .{
                        .node = call.paramsConst()[param_idx - has_self_param],
                        .handle = handle,
                    }, bound_type_params)) orelse continue;
                    if (!call_param_type.type.is_type_val) continue;

                    _ = try bound_type_params.put(decl_param, call_param_type);
                }

                return try resolveReturnType(store, arena, fn_decl, decl.handle, bound_type_params);
            }
            return null;
        },
        .GroupedExpression => {
            const grouped = node.cast(ast.Node.GroupedExpression).?;
            return try resolveTypeOfNodeInternal(store, arena, .{ .node = grouped.expr, .handle = handle }, bound_type_params);
        },
        .StructInitializer => {
            const struct_init = node.cast(ast.Node.StructInitializer).?;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = struct_init.lhs, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .ErrorSetDecl => {
            const set = node.cast(ast.Node.ErrorSetDecl).?;
            var i: usize = 0;
            while (set.iterate(i)) |decl| : (i += 1) {
                try store.error_completions.add(handle.tree, decl);
            }
            return TypeWithHandle.typeVal(node_handle);
        },
        .SuffixOp => {
            const suffix_op = node.cast(ast.Node.SuffixOp).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = suffix_op.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return switch (suffix_op.op) {
                .UnwrapOptional => try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params),
                .Deref => try resolveDerefType(store, arena, left_type, bound_type_params),
                .ArrayAccess => try resolveBracketAccessType(store, arena, left_type, .Single, bound_type_params),
                .Slice => try resolveBracketAccessType(store, arena, left_type, .Range, bound_type_params),
                else => null,
            };
        },
        .InfixOp => {
            const infix_op = node.cast(ast.Node.InfixOp).?;
            switch (infix_op.op) {
                .Period => {
                    const rhs_str = nodeToString(handle.tree, infix_op.rhs) orelse return null;
                    // If we are accessing a pointer type, remove one pointerness level :)
                    const left_type = try resolveFieldAccessLhsType(
                        store,
                        arena,
                        (try resolveTypeOfNodeInternal(store, arena, .{
                            .node = infix_op.lhs,
                            .handle = handle,
                        }, bound_type_params)) orelse return null,
                        bound_type_params,
                    );

                    const left_type_node = switch (left_type.type.data) {
                        .other => |n| n,
                        else => return null,
                    };

                    if (try lookupSymbolContainer(
                        store,
                        arena,
                        .{ .node = left_type_node, .handle = left_type.handle },
                        rhs_str,
                        !left_type.type.is_type_val,
                    )) |child| {
                        return try child.resolveType(store, arena, bound_type_params);
                    } else return null;
                },
                .UnwrapOptional => {
                    const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                        .node = infix_op.lhs,
                        .handle = handle,
                    }, bound_type_params)) orelse return null;
                    return try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params);
                },
                .Catch => {
                    const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                        .node = infix_op.lhs,
                        .handle = handle,
                    }, bound_type_params)) orelse return null;
                    return try resolveUnwrapErrorType(store, arena, left_type, bound_type_params);
                },
                .ErrorUnion => return TypeWithHandle.typeVal(node_handle),
                else => return null,
            }
        },
        .PrefixOp => {
            const prefix_op = node.cast(ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .SliceType,
                .ArrayType,
                .OptionalType,
                .PtrType,
                => return TypeWithHandle.typeVal(node_handle),
                .Try => {
                    const rhs_type = (try resolveTypeOfNodeInternal(store, arena, .{
                        .node = prefix_op.rhs,
                        .handle = handle,
                    }, bound_type_params)) orelse return null;
                    return try resolveUnwrapErrorType(store, arena, rhs_type, bound_type_params);
                },
                else => {},
            }
        },
        .BuiltinCall => {
            const builtin_call = node.cast(ast.Node.BuiltinCall).?;
            const call_name = handle.tree.tokenSlice(builtin_call.builtin_token);
            if (std.mem.eql(u8, call_name, "@This")) {
                if (builtin_call.params_len != 0) return null;
                return innermostContainer(handle, handle.tree.token_locs[builtin_call.firstToken()].start);
            }

            const cast_map = std.ComptimeStringMap(void, .{
                .{"@as"},
                .{"@bitCast"},
                .{"@fieldParentPtr"},
                .{"@floatCast"},
                .{"@floatToInt"},
                .{"@intCast"},
                .{"@intToEnum"},
                .{"@intToFloat"},
                .{"@intToPtr"},
                .{"@truncate"},
                .{"@ptrCast"},
            });
            if (cast_map.has(call_name)) {
                if (builtin_call.params_len < 1) return null;
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = builtin_call.paramsConst()[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }

            // Almost the same as the above, return a type value though.
            // TODO Do peer type resolution, we just keep the first for now.
            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (builtin_call.params_len < 1) return null;
                var resolved_type = (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = builtin_call.paramsConst()[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null;

                if (resolved_type.type.is_type_val) return null;
                resolved_type.type.is_type_val = true;
                return resolved_type;
            }

            if (!std.mem.eql(u8, call_name, "@import")) return null;
            if (builtin_call.params_len < 1) return null;

            const import_param = builtin_call.paramsConst()[0];
            if (import_param.id != .StringLiteral) return null;

            const import_str = handle.tree.tokenSlice(import_param.cast(ast.Node.StringLiteral).?.token);
            const new_handle = (store.resolveImport(handle, import_str[1 .. import_str.len - 1]) catch |err| block: {
                std.debug.warn("Error {} while processing import {}\n", .{ err, import_str });
                return null;
            }) orelse return null;

            return TypeWithHandle.typeVal(.{ .node = &new_handle.tree.root_node.base, .handle = new_handle });
        },
        .ContainerDecl => {
            const container = node.cast(ast.Node.ContainerDecl).?;
            const kind = handle.tree.token_ids[container.kind_token];

            if (kind == .Keyword_struct or (kind == .Keyword_union and container.init_arg_expr == .None)) {
                return TypeWithHandle.typeVal(node_handle);
            }

            var i: usize = 0;
            while (container.iterate(i)) |decl| : (i += 1) {
                if (decl.id != .ContainerField) continue;
                try store.enum_completions.add(handle.tree, decl);
            }
            return TypeWithHandle.typeVal(node_handle);
        },
        .FnProto => {
            // This is a function type
            if (node.cast(ast.Node.FnProto).?.name_token == null) {
                return TypeWithHandle.typeVal(node_handle);
            }
            return TypeWithHandle{
                .type = .{ .data = .{ .other = node }, .is_type_val = false },
                .handle = handle,
            };
        },
        .MultilineStringLiteral, .StringLiteral => return TypeWithHandle{
            .type = .{ .data = .{ .other = node }, .is_type_val = false },
            .handle = handle,
        },
        else => std.debug.warn("Type resolution case not implemented; {}\n", .{node.id}),
    }
    return null;
}

// TODO Reorganize this file, perhaps split into a couple as well
// TODO Make this better, nested levels of type vals
pub const Type = struct {
    data: union(enum) {
        slice: *ast.Node,
        error_union: *ast.Node,
        other: *ast.Node,
        primitive,
    },
    /// If true, the type `type`, the attached data is the value of the type value.
    is_type_val: bool,
};

pub const TypeWithHandle = struct {
    type: Type,
    handle: *DocumentStore.Handle,

    fn typeVal(node_handle: NodeWithHandle) TypeWithHandle {
        return .{
            .type = .{
                .data = .{ .other = node_handle.node },
                .is_type_val = true,
            },
            .handle = node_handle.handle,
        };
    }

    fn instanceTypeVal(self: TypeWithHandle) ?TypeWithHandle {
        if (!self.type.is_type_val) return null;
        return TypeWithHandle{
            .type = .{ .data = self.type.data, .is_type_val = false },
            .handle = self.handle,
        };
    }

    fn isRoot(self: TypeWithHandle) bool {
        switch (self.type.data) {
            .other => |n| return n.id == .Root,
            else => return false,
        }
    }

    fn isContainer(self: TypeWithHandle, container_kind_tok: std.zig.Token.Id) bool {
        switch (self.type.data) {
            .other => |n| {
                if (n.cast(ast.Node.ContainerDecl)) |cont| {
                    return self.handle.tree.token_ids[cont.kind_token] == container_kind_tok;
                }
                return false;
            },
            else => return false,
        }
    }

    pub fn isStructType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_struct) or self.isRoot();
    }

    pub fn isEnumType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_enum);
    }

    pub fn isUnionType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_union);
    }
};

pub fn resolveTypeOfNode(store: *DocumentStore, arena: *std.heap.ArenaAllocator, node_handle: NodeWithHandle) error{OutOfMemory}!?TypeWithHandle {
    var bound_type_params = BoundTypeParams.init(&arena.allocator);
    return resolveTypeOfNodeInternal(store, arena, node_handle, &bound_type_params);
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

pub const NodeWithHandle = struct {
    node: *ast.Node,
    handle: *DocumentStore.Handle,
};

pub fn getFieldAccessType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    tokenizer: *std.zig.Tokenizer,
) !?TypeWithHandle {
    var current_type = TypeWithHandle.typeVal(.{
        .node = &handle.tree.root_node.base,
        .handle = handle,
    });

    // TODO Actually bind params here when calling functions instead of just skipping args.
    var bound_type_params = BoundTypeParams.init(&arena.allocator);

    while (true) {
        const tok = tokenizer.next();
        switch (tok.id) {
            .Eof => return try resolveFieldAccessLhsType(store, arena, current_type, &bound_type_params),
            .Identifier => {
                if (try lookupSymbolGlobal(store, arena, current_type.handle, tokenizer.buffer[tok.loc.start..tok.loc.end], source_index)) |child| {
                    current_type = (try child.resolveType(store, arena, &bound_type_params)) orelse return null;
                } else return null;
            },
            .Period => {
                const after_period = tokenizer.next();
                switch (after_period.id) {
                    .Eof => return try resolveFieldAccessLhsType(store, arena, current_type, &bound_type_params),
                    .Identifier => {
                        if (after_period.loc.end == tokenizer.buffer.len)
                            return try resolveFieldAccessLhsType(store, arena, current_type, &bound_type_params);

                        current_type = try resolveFieldAccessLhsType(store, arena, current_type, &bound_type_params);
                        const current_type_node = switch (current_type.type.data) {
                            .other => |n| n,
                            else => return null,
                        };

                        if (try lookupSymbolContainer(
                            store,
                            arena,
                            .{ .node = current_type_node, .handle = current_type.handle },
                            tokenizer.buffer[after_period.loc.start..after_period.loc.end],
                            !current_type.type.is_type_val,
                        )) |child| {
                            current_type = (try child.resolveType(store, arena, &bound_type_params)) orelse return null;
                        } else return null;
                    },
                    .QuestionMark => {
                        current_type = (try resolveUnwrapOptionalType(store, arena, current_type, &bound_type_params)) orelse return null;
                    },
                    else => {
                        std.debug.warn("Unrecognized token {} after period.\n", .{after_period.id});
                        return null;
                    },
                }
            },
            .PeriodAsterisk => {
                current_type = (try resolveDerefType(store, arena, current_type, &bound_type_params)) orelse return null;
            },
            .LParen => {
                const current_type_node = switch (current_type.type.data) {
                    .other => |n| n,
                    else => return null,
                };

                // Can't call a function type, we need a function type instance.
                if (current_type.type.is_type_val) return null;
                if (current_type_node.cast(ast.Node.FnProto)) |func| {
                    if (try resolveReturnType(store, arena, func, current_type.handle, &bound_type_params)) |ret| {
                        current_type = ret;
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
                } else return null;
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

                current_type = (try resolveBracketAccessType(store, arena, current_type, if (is_range) .Range else .Single, &bound_type_params)) orelse return null;
            },
            else => {
                std.debug.warn("Unimplemented token: {}\n", .{tok.id});
                return null;
            },
        }
    }

    return try resolveFieldAccessLhsType(store, arena, current_type, &bound_type_params);
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
    pre_label,
    label,
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
            .pre_label => null,
            .label => null,
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
                .empty, .pre_label => curr_ctx.ctx = .{ .var_access = tok.loc },
                else => {},
            },
            .Builtin => switch (curr_ctx.ctx) {
                .empty, .pre_label => curr_ctx.ctx = .{ .builtin = tok.loc },
                else => {},
            },
            .Period, .PeriodAsterisk => switch (curr_ctx.ctx) {
                .empty, .pre_label => curr_ctx.ctx = .enum_literal,
                .enum_literal => curr_ctx.ctx = .empty,
                .field_access => {},
                .other => {},
                .global_error_set => {},
                else => curr_ctx.ctx = .{
                    .field_access = tokenRangeAppend(curr_ctx.ctx.range().?, tok),
                },
            },
            .Keyword_break, .Keyword_continue => curr_ctx.ctx = .pre_label,
            .Colon => if (curr_ctx.ctx == .pre_label) {
                curr_ctx.ctx = .label;
            } else {
                curr_ctx.ctx = .empty;
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
    label_decl: *ast.Node, // .id is While, For or Block (firstToken will be the label)
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
            .label_decl => |ld| tree.tokenLocation(0, ld.firstToken()),
        };
    }

    fn isPublic(self: DeclWithHandle) bool {
        return switch (self.decl.*) {
            .ast_node => |node| isNodePublic(self.handle.tree, node),
            else => true,
        };
    }

    pub fn resolveType(self: DeclWithHandle, store: *DocumentStore, arena: *std.heap.ArenaAllocator, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
        return switch (self.decl.*) {
            .ast_node => |node| try resolveTypeOfNodeInternal(store, arena, .{ .node = node, .handle = self.handle }, bound_type_params),
            .param_decl => |param_decl| switch (param_decl.param_type) {
                .type_expr => |type_node| {
                    if (typeIsType(self.handle.tree, type_node)) {
                        var bound_param_it = bound_type_params.iterator();
                        while (bound_param_it.next()) |entry| {
                            if (entry.key == param_decl) return entry.value;
                        }
                        return null;
                    }
                    return ((try resolveTypeOfNodeInternal(
                        store,
                        arena,
                        .{ .node = type_node, .handle = self.handle },
                        bound_type_params,
                    )) orelse return null).instanceTypeVal();
                },
                else => null,
            },
            .pointer_payload => |pay| try resolveUnwrapOptionalType(
                store,
                arena,
                (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = pay.condition,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null,
                bound_type_params,
            ),
            .array_payload => |pay| try resolveBracketAccessType(
                store,
                arena,
                (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = pay.array_expr,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null,
                .Single,
                bound_type_params,
            ),
            .label_decl => return null,
            // TODO Resolve switch payload types
            .switch_payload => |pay| return null,
        };
    }
};

fn findContainerScope(container_handle: NodeWithHandle) ?*Scope {
    const container = container_handle.node;
    const handle = container_handle.handle;

    if (container.id != .ContainerDecl and container.id != .Root and container.id != .ErrorSetDecl) {
        return null;
    }

    // Find the container scope.
    var container_scope: ?*Scope = null;
    for (handle.document_scope.scopes) |*scope| {
        switch (scope.*.data) {
            .container => |node| if (node == container) {
                container_scope = scope;
                break;
            },
            else => {},
        }
    }
    return container_scope;
}

pub fn iterateSymbolsContainer(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    orig_handle: *DocumentStore.Handle,
    comptime callback: var,
    context: var,
    include_fields: bool,
) error{OutOfMemory}!void {
    const container = container_handle.node;
    const handle = container_handle.handle;

    if (findContainerScope(container_handle)) |container_scope| {
        var decl_it = container_scope.decls.iterator();
        while (decl_it.next()) |entry| {
            if (!include_fields and entry.value == .ast_node and entry.value.ast_node.id == .ContainerField) continue;
            if (entry.value == .label_decl) continue;
            const decl = DeclWithHandle{ .decl = &entry.value, .handle = handle };
            if (handle != orig_handle and !decl.isPublic()) continue;
            try callback(context, decl);
        }

        for (container_scope.uses) |use| {
            if (handle != orig_handle and use.visib_token == null) continue;
            const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
            const use_expr_node = switch (use_expr.type.data) {
                .other => |n| n,
                else => continue,
            };
            try iterateSymbolsContainer(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, orig_handle, callback, context, false);
        }
    }

    std.debug.warn("Did not find container scope when iterating container {} (name: {})\n", .{ container, getDeclName(handle.tree, container) });
}

pub fn iterateLabels(
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: var,
    context: var,
) error{OutOfMemory}!void {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            var decl_it = scope.decls.iterator();
            while (decl_it.next()) |entry| {
                switch (entry.value) {
                    .label_decl => {},
                    else => continue,
                }
                try callback(context, DeclWithHandle{ .decl = &entry.value, .handle = handle });
            }
        }
        if (scope.range.start >= source_index) return;
    }
}

pub fn iterateSymbolsGlobal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: var,
    context: var,
) error{OutOfMemory}!void {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            var decl_it = scope.decls.iterator();
            while (decl_it.next()) |entry| {
                if (entry.value == .ast_node and entry.value.ast_node.id == .ContainerField) continue;
                if (entry.value == .label_decl) continue;
                try callback(context, DeclWithHandle{ .decl = &entry.value, .handle = handle });
            }

            for (scope.uses) |use| {
                const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
                const use_expr_node = switch (use_expr.type.data) {
                    .other => |n| n,
                    else => continue,
                };
                try iterateSymbolsContainer(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, handle, callback, context, false);
            }
        }

        if (scope.range.start >= source_index) return;
    }
}

pub fn innermostContainer(handle: *DocumentStore.Handle, source_index: usize) TypeWithHandle {
    var current = handle.document_scope.scopes[0].data.container;
    if (handle.document_scope.scopes.len == 1) return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });

    for (handle.document_scope.scopes[1..]) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            switch (scope.data) {
                .container => |node| current = node,
                else => {},
            }
        }
        if (scope.range.start > source_index) break;
    }
    return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });
}

fn resolveUse(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    uses: []const *ast.Node.Use,
    symbol: []const u8,
    handle: *DocumentStore.Handle,
) error{OutOfMemory}!?DeclWithHandle {
    for (uses) |use| {
        const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
        const use_expr_node = switch (use_expr.type.data) {
            .other => |n| n,
            else => continue,
        };
        if (try lookupSymbolContainer(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, symbol, false)) |candidate| {
            if (candidate.handle != handle and !candidate.isPublic()) {
                continue;
            }
            return candidate;
        }
    }
    return null;
}

pub fn lookupLabel(
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            if (scope.decls.get(symbol)) |candidate| {
                switch (candidate.value) {
                    .label_decl => {},
                    else => continue,
                }
                return DeclWithHandle{
                    .decl = &candidate.value,
                    .handle = handle,
                };
            }
        }
        if (scope.range.start > source_index) return null;
    }
    return null;
}

pub fn lookupSymbolGlobal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            if (scope.decls.get(symbol)) |candidate| {
                switch (candidate.value) {
                    .ast_node => |node| {
                        if (node.id == .ContainerField) continue;
                    },
                    .label_decl => continue,
                    else => {},
                }
                return DeclWithHandle{
                    .decl = &candidate.value,
                    .handle = handle,
                };
            }

            if (try resolveUse(store, arena, scope.uses, symbol, handle)) |result| return result;
        }

        if (scope.range.start > source_index) return null;
    }

    return null;
}

pub fn lookupSymbolContainer(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    symbol: []const u8,
    accept_fields: bool,
) error{OutOfMemory}!?DeclWithHandle {
    const container = container_handle.node;
    const handle = container_handle.handle;

    if (findContainerScope(container_handle)) |container_scope| {
        if (container_scope.decls.get(symbol)) |candidate| {
            switch (candidate.value) {
                .ast_node => |node| {
                    if (node.id == .ContainerField and !accept_fields) return null;
                },
                .label_decl => unreachable,
                else => {},
            }
            return DeclWithHandle{ .decl = &candidate.value, .handle = handle };
        }

        if (try resolveUse(store, arena, container_scope.uses, symbol, handle)) |result| return result;
        return null;
    }

    std.debug.warn("Did not find container scope when looking up in container {} (name: {})\n", .{ container, getDeclName(handle.tree, container) });
    return null;
}

pub const DocumentScope = struct {
    scopes: []Scope,

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
            allocator.free(scope.tests);
        }
        allocator.free(self.scopes);
    }
};

pub const Scope = struct {
    pub const Data = union(enum) {
        container: *ast.Node, // .id is ContainerDecl or Root or ErrorSetDecl
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
// TODO Possibly collect all imports to diff them on changes
//      as well
fn makeScopeInternal(
    allocator: *std.mem.Allocator,
    scopes: *std.ArrayList(Scope),
    tree: *ast.Tree,
    node: *ast.Node,
) error{OutOfMemory}!void {
    if (node.id == .Root or node.id == .ContainerDecl or node.id == .ErrorSetDecl) {
        const ast_decls = switch (node.id) {
            .ContainerDecl => node.cast(ast.Node.ContainerDecl).?.fieldsAndDeclsConst(),
            .Root => node.cast(ast.Node.Root).?.declsConst(),
            .ErrorSetDecl => node.cast(ast.Node.ErrorSetDecl).?.declsConst(),
            else => unreachable,
        };

        (try scopes.addOne()).* = .{
            .range = nodeSourceRange(tree, node),
            .decls = std.StringHashMap(Declaration).init(allocator),
            .uses = &[0]*ast.Node.Use{},
            .tests = &[0]*ast.Node{},
            .data = .{ .container = node },
        };
        const scope_idx = scopes.items.len - 1;
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

            if (decl.cast(ast.Node.ContainerField)) |field| {
                if (field.type_expr == null and field.value_expr == null) {
                    if (node.id == .Root) continue;
                    if (node.cast(ast.Node.ContainerDecl)) |container| {
                        const kind = tree.token_ids[container.kind_token];
                        if (kind == .Keyword_struct or (kind == .Keyword_union and container.init_arg_expr == .None)) {
                            continue;
                        }
                    }
                }
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
                .tests = &[0]*ast.Node{},
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
            const block = node.cast(ast.Node.Block).?;
            if (block.label) |label| {
                std.debug.assert(tree.token_ids[label] == .Identifier);
                var scope = try scopes.addOne();
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[block.lbrace].start,
                        .end = tree.token_locs[block.rbrace].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{
                    .label_decl = node,
                });
            }

            (try scopes.addOne()).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                .uses = &[0]*ast.Node.Use{},
                .tests = &[0]*ast.Node{},
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
                    .tests = &[0]*ast.Node{},
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
                        .tests = &[0]*ast.Node{},
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
            if (while_node.label) |label| {
                std.debug.assert(tree.token_ids[label] == .Identifier);
                var scope = try scopes.addOne();
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[while_node.while_token].start,
                        .end = tree.token_locs[while_node.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{
                    .label_decl = node,
                });
            }

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
                    .tests = &[0]*ast.Node{},
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
                        .tests = &[0]*ast.Node{},
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
            if (for_node.label) |label| {
                std.debug.assert(tree.token_ids[label] == .Identifier);
                var scope = try scopes.addOne();
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[for_node.for_token].start,
                        .end = tree.token_locs[for_node.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{
                    .label_decl = node,
                });
            }

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
                .tests = &[0]*ast.Node{},
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
                            .tests = &[0]*ast.Node{},
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
