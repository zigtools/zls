const std = @import("std");
const DocumentStore = @import("document_store.zig");
const ast = std.zig.ast;
const types = @import("types.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.analysis);

/// Get a declaration's doc comment token index
pub fn getDocCommentTokenIndex(tree: ast.Tree, node: ast.Node.Index) ?ast.TokenIndex {
    const tags = tree.nodes.items(.tag);
    const tokens = tree.tokens.items(.tag);
    const current = tree.nodes.items(.main_token)[node];

    switch (tags[node]) {
        .fn_proto, .fn_proto_one, .fn_proto_simple, .fn_proto_multi => {
            var idx = current - 1;
            idx -= @boolToInt(tokens[idx] == .keyword_extern);
            idx -= @boolToInt(tokens[idx] == .keyword_pub);
            return if (tokens[idx] == .doc_comment) idx else null;
        },
        .local_var_decl, .global_var_decl, .aligned_var_decl, .simple_var_decl => {
            return if (tokens[current - 1] == .doc_comment) current - 1 else null;
        },
        .container_field, .container_field_init, .container_field_align => {
            var idx = current - 2; // skip '.'
            return if (tokens[idx] == .doc_comment) idx else null;
        },
        else => return null,
    }

    // @TODO: Implement doc comments for tags
    // } else if (node.castTag(.ErrorTag)) |tag| {
    //     return tag.doc_comments;
    // }
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
    tree: ast.Tree,
    node: ast.Node.Index,
    format: types.MarkupContent.Kind,
) !?[]const u8 {
    if (getDocCommentTokenIndex(tree, node)) |doc_comment_index| {
        return try collectDocComments(allocator, tree, doc_comment_index, format);
    }
    return null;
}

pub fn collectDocComments(
    allocator: *std.mem.Allocator,
    tree: ast.Tree,
    doc_comments: ast.TokenIndex,
    format: types.MarkupContent.Kind,
) ![]const u8 {
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();

    const token_tags = tree.tokens.items(.tag);
    const loc = tree.tokenLocation(0, doc_comments);

    var curr_line_tok = doc_comments;
    while (true) : (curr_line_tok += 1) {
        switch (token_tags[curr_line_tok]) {
            .doc_comment, .container_doc_comment => {
                try lines.append(std.mem.trim(u8, tree.tokenSlice(curr_line_tok)[3..], &std.ascii.spaces));
            },
            else => break,
        }
    }

    return try std.mem.join(allocator, if (format == .Markdown) "  \n" else "\n", lines.items);
}

/// Gets a function signature (keywords, name, return value)
pub fn getFunctionSignature(tree: ast.Tree, func: *ast.full.FnProto) []const u8 {
    const start = tree.tokenLocation(func.ast.fn_token).line_start;
    const end = tree.tokenLocation(func.ast.return_type).line_end;
    return tree.source[start..end];
}

/// Gets a function snippet insert text
pub fn getFunctionSnippet(allocator: *std.mem.Allocator, tree: ast.Tree, func: *ast.full.FnProto, skip_self_param: bool) ![]const u8 {
    const name_index = func.name_token orelse unreachable;

    var buffer = std.ArrayList(u8).init(allocator);
    try buffer.ensureCapacity(128);

    try buffer.appendSlice(tree.tokenSlice(name_tok));
    try buffer.append('(');

    var buf_stream = buffer.writer();

    const token_tags = tree.tokens.items(.tag);

    var it = func.iterate(tree);
    while (it.next()) |param| {
        if (skip_self_param and it.param_i == 0) continue;
        if (it.param_i != @boolToInt(skip_self_param)) try buffer.appendSlice(", ${") else try buffer.appendSlice("${");

        try buf_stream.print("{d}", .{it.param_i + 1});

        if (param.comptime_noalias) |token_index| {
            if (token_tags[token_index] == .keyword_comptime)
                try buffer.appendSlice("comptime ")
            else
                try buffer.appendSlice("noalias ");
        }

        if (param.name_token) |name_token| {
            try buffer.appendSlice(tree.tokenSlice(name_token));
            try buffer.appendSlice(": ");
        }

        if (param.anytype_ellipsis3) |token_index| {
            if (token_tags[token_index] == .keyword_anytype)
                try buffer.appendSlice("anytype")
            else
                try buffer.appendSlice("...");
        } else {
            var curr_token = param.type_expr;
            var end_token = tree.lastToken(func.ast.params[it.param_i]);
            while (curr_token <= end_token) : (curr_token += 1) {
                const tag = token_tags[curr_token];
                const is_comma = tag == .comma;

                if (curr_token == end_token and is_comma) continue;
                try buffer.appendSlice(tree.tokenSlice(curr_token));
                if (is_comma or tag == .keyword_const) try buffer.append(' ');
            }
        }
        try buffer.append('}');
    }
    try buffer.append(')');

    return buffer.toOwnedSlice();
}

/// Gets a function signature (keywords, name, return value)
pub fn getVariableSignature(tree: ast.Tree, var_decl: *ast.full.VarDecl) []const u8 {
    const start = tree.tokenLocation(0, var_decl.ast.mut_token).line_start;
    const end = tree.tokenLocation(@truncate(u32, start), tree.lastToken(var_decl.ast.init_node)).line_end;
    return tree.source[start..end];
}

// analysis.getContainerFieldSignature(handle.tree, field)
pub fn getContainerFieldSignature(tree: ast.Tree, field: *ast.full.ContainerField) []const u8 {
    const start = tree.tokenLocation(0, field.ast.name_token).line_start;
    const end = tree.tokenLocation(@truncate(u32, start), tree.lastToken(field.ast.value_expr)).line_start;
    return tree.source[start..end];
}

/// The type node is "type"
fn typeIsType(tree: ast.Tree, node: ast.Node.Index) bool {
    if (tree.nodes.items(.tag)[node] == .identifier) {
        return std.mem.eql(u8, tree.tokenSlice(node), "type");
    }
    return false;
}

pub fn isTypeFunction(tree: ast.Tree, func: ast.full.FnProto) bool {
    return typeIsType(tree, func.ast.return_type);
}

pub fn isGenericFunction(tree: ast.Tree, func: *ast.full.FnProto) bool {
    var it = func.iterate();
    var slice = tree.nodes.items(.tag);
    while (it.next()) |param| {
        if (param.anytype_ellipsis3 != null or param.comptime_noalias != null) {
            return true;
        }
    }
    return false;
}
// STYLE

pub fn isCamelCase(name: []const u8) bool {
    return !std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name[0..(name.len - 1)], "_") == null;
}

pub fn isPascalCase(name: []const u8) bool {
    return std.ascii.isUpper(name[0]) and std.mem.indexOf(u8, name[0..(name.len - 1)], "_") == null;
}

// ANALYSIS ENGINE

pub fn getDeclNameToken(tree: ast.Tree, node: ast.Node.Index) ?ast.TokenIndex {
    const tags = tree.nodes.items(.tag);
    switch (tags[node]) {
        // regular declaration names. + 1 to mut token because name comes after 'const'/'var'
        .local_var_decl => return tree.localVarDecl(node).ast.mut_token + 1,
        .global_var_decl => return tree.globalVarDecl(node).ast.mut_token + 1,
        .simple_var_decl => return tree.simpleVarDecl(node).ast.mut_token + 1,
        .aligned_var_decl => return tree.alignedVarDecl(node).ast.mut_token + 1,

        // function declaration names
        .fn_proto => return tree.fnProto(node).name_token,
        .fn_proto_simple => {
            var params: [1]ast.Node.Index = undefined;
            return tree.fnProtoSimple(&params, node).name_token;
        },
        .fn_proto_one => {
            var params: [1]ast.Node.Index = undefined;
            return tree.fnProtoOne(&params, node).name_token;
        },
        .fn_proto_multi => return tree.fnProtoMulti(node).name_token,

        // containers
        .container_field => return tree.containerField(node).ast.name_token,
        .container_field_init => return tree.containerFieldInit(node).ast.name_token,
        .container_field_align => return tree.containerFieldAlign(node).ast.name_token,

        // @TODO: Errors
        // .error_=> {
        //     const tag = node.castTag(.ErrorTag).?;
        //     return tag.name_token;
        // },

        // lhs of main token is name token, so use `node` - 1
        .test_decl => return getDeclNameToken(tree, node - 1),
        else => {},
    }

    return null;
}

fn getDeclName(tree: ast.Tree, node: ast.Node.Index) ?[]const u8 {
    const name = tree.tokenSlice(getDeclNameToken(tree, node) orelse return null);
    return switch (tree.nodes.items(.tag)[node]) {
        .test_decl => name[1 .. name.len - 1],
        else => name,
    };
}

fn isContainerDecl(decl_handle: DeclWithHandle) bool {
    return switch (decl_handle.decl.*) {
        .ast_node => |inner_node| isContainer(decl_handle.handle.tree.nodes.items(.tag)[inner_node]) or inner_node == 0,
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
    if (node_handle.node.castTag(.Identifier)) |ident| {
        return try lookupSymbolGlobal(store, arena, handle, handle.tree.tokenSlice(ident.token), handle.tree.token_locs[ident.token].start);
    }

    if (node_handle.node.cast(ast.Node.SimpleInfixOp)) |infix_op| {
        if (node_handle.node.tag != .Period) return null;

        const container_node = if (infix_op.lhs.castTag(.BuiltinCall)) |builtin_call| block: {
            if (!std.mem.eql(u8, handle.tree.tokenSlice(builtin_call.builtin_token), "@import"))
                return null;
            const inner_node = (try resolveTypeOfNode(store, arena, .{ .node = infix_op.lhs, .handle = handle })) orelse return null;
            std.debug.assert(inner_node.type.data.other.tag == .Root);
            break :block NodeWithHandle{ .node = inner_node.type.data.other, .handle = inner_node.handle };
        } else if (try resolveVarDeclAliasInternal(store, arena, .{ .node = infix_op.lhs, .handle = handle }, false)) |decl_handle| block: {
            if (decl_handle.decl.* != .ast_node) return null;
            const resolved = (try resolveTypeOfNode(store, arena, .{ .node = decl_handle.decl.ast_node, .handle = decl_handle.handle })) orelse return null;
            const resolved_node = switch (resolved.type.data) {
                .other => |n| n,
                else => return null,
            };

            if (resolved_node.tag != .ContainerDecl and resolved_node.tag != .Root) return null;
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

    if (decl.castTag(.VarDecl)) |var_decl| {
        const base_expr = var_decl.getInitNode() orelse return null;
        if (handle.tree.token_ids[var_decl.mut_token] != .Keyword_const) return null;

        if (base_expr.cast(ast.Node.SimpleInfixOp)) |infix_op| {
            if (base_expr.tag != .Period) return null;
            const name = handle.tree.tokenSlice(infix_op.rhs.firstToken());
            if (!std.mem.eql(u8, handle.tree.tokenSlice(var_decl.name_token), name))
                return null;

            return try resolveVarDeclAliasInternal(store, arena, .{ .node = base_expr, .handle = handle }, true);
        }
    }

    return null;
}

fn findReturnStatementInternal(
    tree: ast.Tree,
    fn_decl: *ast.Node.FnProto,
    base_node: *ast.Node,
    already_found: *bool,
) ?*ast.Node.ControlFlowExpression {
    var result: ?*ast.Node.ControlFlowExpression = null;
    var child_idx: usize = 0;
    while (base_node.iterate(child_idx)) |child_node| : (child_idx += 1) {
        if (child_node.castTag(.Return)) |cfe| {
            // If we are calling ourselves recursively, ignore this return.
            if (cfe.getRHS()) |rhs| {
                if (rhs.castTag(.Call)) |call_node| {
                    if (call_node.lhs.tag == .Identifier) {
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

        result = findReturnStatementInternal(tree, fn_decl, child_node, already_found);
    }
    return result;
}

fn findReturnStatement(tree: ast.Tree, fn_decl: *ast.Node.FnProto) ?*ast.Node.ControlFlowExpression {
    var already_found = false;
    return findReturnStatementInternal(tree, fn_decl, fn_decl.getBodyNode().?, &already_found);
}

/// Resolves the return type of a function
pub fn resolveReturnType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    fn_decl: ast.full.FnProto,
    handle: *DocumentStore.Handle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    // @TODO: Confirm this can handle inferred error sets etc
    return resolveTypeOfNodeInternal(store, arena, .{
        .node = fn_decl.ast.return_type,
        .handle = handle,
    }, bound_type_params);
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

    if (opt.handle.tree.nodes.items(.tag)[opt_node] == .optional_type) {
        return ((try resolveTypeOfNodeInternal(store, arena, .{
            .node = opt.handle.tree.nodes.items(.data)[opt_node].lhs,
            .handle = opt.handle,
        }, bound_type_params)) orelse return null).instanceTypeVal();
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
        .primitive, .slice, .pointer => return null,
    };
    if (rhs.handle.tree.nodes.items(.tag)[rhs_node] == .error_union) {
        return ((try resolveTypeOfNodeInternal(store, arena, .{
            .node = rhs.handle.tree.nodes.items(.data)[rhs_node].rhs,
            .handle = rhs.handle,
        }, bound_type_params)) orelse return null).instanceTypeVal();
    }

    return null;
}

fn isPtrType(tree: ast.Tree, node: ast.Node.Index) bool {
    return switch (tree.nodes.items(.tag)[node]) {
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => true,
        else => false,
    };
}

/// Resolves the child type of a deref type
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
    const tree = deref.handle.tree;
    const main_token = tree.nodes.items(.main_token)[deref_node];
    const token_tag = tree.tokens.items(.tag)[main_token];

    if (isPtrType(tree, deref_node)) {
        switch (token_tag) {
            .asterisk => {
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = tree.nodes.items(.data)[deref_node].rhs,
                    .handle = deref.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            },
            .l_bracket, .asterisk_asterisk => return null,
            else => unreachable,
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

    const tags = lhs.handle.tree.nodes.items(.tag);
    const tag = tags[lhs_node];
    const data = lhs.handle.tree.nodes.items(.data)[lhs_node];
    if (tag == .array_type or tag == .array_type_sentinel) {
        if (rhs == .Single)
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = data.rhs,
                .handle = lhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        return TypeWithHandle{
            .type = .{ .data = .{ .slice = data.rhs }, .is_type_val = false },
            .handle = lhs.handle,
        };
    } else if (isPtrType(tree, lhs_node)) {
        if (tags[data.rhs] == .array_type or tags[data.rhs] == .array_type_sentinel) {
            if (rhs == .Single) {
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = lhs.handle.tree.nodes.items(.data)[data.rhs].rhs,
                    .handle = lhs.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }
        }
    }

    return null;
}

/// Called to remove one level of pointerness before a field access
pub fn resolveFieldAccessLhsType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    lhs: TypeWithHandle,
    bound_type_params: *BoundTypeParams,
) !TypeWithHandle {
    return (try resolveDerefType(store, arena, lhs, bound_type_params)) orelse lhs;
}

pub const BoundTypeParams = std.AutoHashMap(*const ast.full.FnProto.Param, TypeWithHandle);

fn allDigits(str: []const u8) bool {
    for (str) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

pub fn isTypeIdent(tree: ast.Tree, token_idx: ast.TokenIndex) bool {
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
pub fn resolveTypeOfNodeInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    node_handle: NodeWithHandle,
    bound_type_params: *BoundTypeParams,
) error{OutOfMemory}!?TypeWithHandle {
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;

    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);
    const starts = tree.tokens.items(.start);

    switch (node_tags[node]) {
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const var_decl = varDecl(tree, node).?;
            if (var_decl.ast.type_node != 0) block: {
                return ((try resolveTypeOfNodeInternal(
                    store,
                    arena,
                    .{ .node = var_decl.ast.type_node, .handle = handle },
                    bound_type_params,
                )) orelse break :block).instanceTypeVal();
            }
            return if (var_decl.ast.init_node != 0)
                try resolveTypeOfNodeInternal(store, arena, .{ .node = var_decl.ast.init_node, .handle = handle }, bound_type_params)
            else
                null;
        },
        .identifier => {
            if (isTypeIdent(handle.tree, tree.firstToken(node))) {
                return TypeWithHandle{
                    .type = .{ .data = .primitive, .is_type_val = true },
                    .handle = handle,
                };
            }

            if (try lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), starts[tree.firstToken(node)])) |child| {
                switch (child.decl.*) {
                    .ast_node => |n| {
                        if (n == node) return null;
                        if (varDecl(tree, n)) |var_decl| {
                            if (var_decl.ast.init_node == node) return null;
                        }
                    },
                    else => {},
                }
                return try child.resolveType(store, arena, bound_type_params);
            }
            return null;
        },
        .container_field, .container_field_init, .container_field_align => |c| {
            const field: ast.full.ContainerField = switch (c) {
                .container_field => tree.containerField(node),
                .container_field_align => tree.containerFieldAlign(node),
                .container_field_init => tree.containerFieldInit(node),
                else => unreachable,
            };

            if (field.ast.type_expr == 0) return null;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = field.ast.type_expr, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => |c| {
            var params: [1]ast.Node.Index = undefined;
            const call: ast.full.Call = switch (c) {
                .call, .call_comma, .async_call, .async_call_comma => tree.callFull(node),
                .call_one, .call_one_comma, .async_call_one, .async_call_one_comma => tree.callOne(&params, node),
                else => unreachable,
            };

            const decl = (try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = call.ast.fn_expr, .handle = handle },
                bound_type_params,
            )) orelse return null;

            if (decl.type.is_type_val) return null;
            const decl_node = switch (decl.type.data) {
                .other => |n| n,
                else => return null,
            };

            var buf: [1]ast.Node.Index = undefined;
            const func_maybe: ?ast.full.FnProto = switch (node_tags[decl_node]) {
                .fn_proto => tree.fnProto(decl_node),
                .fn_proto_one => tree.fnProtoOne(&buf, decl_node),
                .fn_proto_multi => tree.fnProtoMulti(decl_node),
                .fn_proto_simple => tree.fnProtoSimple(&buf, decl_node),
                else => null,
            };

            if (func_maybe) |fn_decl| {
                // check for x.y(..).  if '.' is found, it means first param should be skipped
                const has_self_param = token_tags[call.ast.lparen - 2] == .period;
                var it = fn_decl.iterate();

                // Bind type params to the expressions passed in the calls.
                const param_len = std.math.min(call.ast.params.len + @boolToInt(has_self_param), fn_decl.ast.params.len);
                while (it.next()) |decl_param| {
                    if (it.param_i == 0 and has_self_param) continue;
                    if (it.param_i >= param_len) break;
                    if (!typeIsType(decl_param.type_expr)) continue;

                    const call_param_type = (try resolveTypeOfNodeInternal(store, arena, .{
                        .node = call.ast.params[it.param_i - @boolToInt(has_self_param)],
                        .handle = handle,
                    }, bound_type_params)) orelse continue;
                    if (!call_param_type.type.is_type_val) continue;

                    _ = try bound_type_params.put(decl_param, call_param_type);
                }

                return try resolveReturnType(store, arena, fn_decl, decl.handle, bound_type_params);
            }
            return null;
        },
        .@"comptime", .@"nosuspend" => {
            return try resolveTypeOfNodeInternal(store, arena, .{ .node = datas[node].lhs, .handle = handle }, bound_type_params);
        },
        .grouped_expression => {
            return try resolveTypeOfNodeInternal(store, arena, .{ .node = datas[node].lhs, .handle = handle }, bound_type_params);
        },
        .struct_init, .struct_init_comma, .struct_init_one, .struct_init_one_comma => {
            const struct_init = node.castTag(.StructInitializer).?;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = datas[node].lhs, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .error_set_decl => {
            return TypeWithHandle.typeVal(node_handle);
        },
        .slice, .slice_sentinel, .slice_open => {
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = dates[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveBracketAccessType(store, arena, left_type, .Range, bound_type_params);
        },
        .deref, .unwrap_optional => {
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = dates[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return switch (node_tags[node]) {
                .unwrap_optional => try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params),
                .deref => try resolveDerefType(store, arena, left_type, bound_type_params),
                else => unreachable,
            };
        },
        .array_access => {
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = datas[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveBracketAccessType(store, arena, left_type, .Single, bound_type_params);
        },
        .field_access => {
            const rhs_str = nodeToString(handle.tree, datas[node].rhs) orelse return null;
            // If we are accessing a pointer type, remove one pointerness level :)
            const left_type = try resolveFieldAccessLhsType(
                store,
                arena,
                (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = datas[node].lhs,
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
        .@"orelse" => {
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = datas[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params);
        },
        .@"catch" => {
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = datas[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapErrorType(store, arena, left_type, bound_type_params);
        },
        .error_union => return TypeWithHandle.typeVal(node_handle),
        .array_type,
        .array_type_sentinel,
        .optional_type,
        .ptr_type_aligned,
        .ptr_type.aligned,
        .ptr_type,
        .ptr_type_bit_range,
        => return TypeWithHandle.typeVal(node_handle),
        .@"try" => {
            const rhs_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = datas[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapErrorType(store, arena, rhs_type, bound_type_params);
        },
        .address_of => {
            const rhs_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = datas[node].lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;

            const rhs_node = switch (rhs_type.type.data) {
                .other => |n| n,
                else => return null,
            };

            return TypeWithHandle{
                .type = .{ .data = .{ .pointer = rhs_node }, .is_type_val = false },
                .handle = rhs_type.handle,
            };
        },
        .builtin_call, .builtin_call_comma, .builtin_call_two, .builtin_call_two_comma => {
            const params = builtinCallParams(tree, node);

            const call_name = tree.tokenSlice(main_tokens[node]);
            if (std.mem.eql(u8, call_name, "@This")) {
                if (params.len != 0) return null;
                return innermostContainer(handle, starts[tree.firstToken(node)]);
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
                if (params.len < 1) return null;
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = params[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }

            // Almost the same as the above, return a type value though.
            // TODO Do peer type resolution, we just keep the first for now.
            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len < 1) return null;
                var resolved_type = (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = params[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null;

                if (resolved_type.type.is_type_val) return null;
                resolved_type.type.is_type_val = true;
                return resolved_type;
            }

            if (!std.mem.eql(u8, call_name, "@import")) return null;
            if (params.len < 1) return null;

            const import_param = params[0];
            if (node_tags[import_param] != .string_literal) return null;

            const import_str = tree.tokenSlice(main_tokens[import_param]);
            const new_handle = (store.resolveImport(handle, import_str[1 .. import_str.len - 1]) catch |err| {
                log.debug("Error {} while processing import {s}", .{ err, import_str });
                return null;
            }) orelse return null;

            // reference to node '0' which is root
            return TypeWithHandle.typeVal(.{ .node = 0, .handle = new_handle });
        },
        .container_decl,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        => {
            return TypeWithHandle.typeVal(node_handle);
        },
        .fn_proto, .fn_proto_multi, .fn_proto_one, .fn_proto_simple => {
            var buf: [1]ast.Node.Index = undefined;
            const fn_proto: ast.full.FnProto = switch (node_tags[node]) {
                .fn_proto => tree.fnProto(node),
                .fn_proto_multi => tree.fnProtoMulti(node),
                .fn_proto_one => tree.fnProtoOne(&buf, node),
                .fn_proto_simple => tree.fnProtoSimple(&buf, node),
                else => unreachable,
            };

            // This is a function type
            if (fn_proto.name_token == null) {
                return TypeWithHandle.typeVal(node_handle);
            }

            return TypeWithHandle{
                .type = .{ .data = .{ .other = node }, .is_type_val = false },
                .handle = handle,
            };
        },
        .multiline_string_literal, .string_literal => return TypeWithHandle{
            .type = .{ .data = .{ .other = node }, .is_type_val = false },
            .handle = handle,
        },
        else => {},
    }
    return null;
}

// TODO Reorganize this file, perhaps split into a couple as well
// TODO Make this better, nested levels of type vals
pub const Type = struct {
    data: union(enum) {
        pointer: ast.Node.Index,
        slice: ast.Node.Index,
        error_union: ast.Node.Index,
        other: ast.Node.Index,
        primitive,
    },
    /// If true, the type `type`, the attached data is the value of the type value.
    is_type_val: bool,
};

pub const TypeWithHandle = struct {
    type: Type,
    handle: *DocumentStore.Handle,

    pub fn typeVal(node_handle: NodeWithHandle) TypeWithHandle {
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
            // root is always index 0
            .other => |n| return n == 0,
            else => return false,
        }
    }

    fn isContainer(self: TypeWithHandle, container_kind_tok: std.zig.Token.Tag, tree: ast.Tree) bool {
        const main_tokens = tree.nodes.items(.main_token);
        const tags = tree.tokens.items(.tag);
        switch (self.type.data) {
            .other => |n| return tags[main_tokens[n]] == container_kind_tok,
            else => return false,
        }
    }

    pub fn isStructType(self: TypeWithHandle, tree: ast.Tree) bool {
        return self.isContainer(.keyword_struct, tree) or self.isRoot();
    }

    pub fn isNamespace(self: TypeWithHandle, tree: ast.Tree) bool {
        if (!self.isStructType()) return false;
        var idx: usize = 0;
        while (self.type.data.other.iterate(idx)) |child| : (idx += 1) {
            if (child.tag == .ContainerField)
                return false;
        }
        return true;
    }

    pub fn isEnumType(self: TypeWithHandle, tree: ast.Tree) bool {
        return self.isContainer(.keyword_enum, tree);
    }

    pub fn isUnionType(self: TypeWithHandle, tree: ast.Tree) bool {
        return self.isContainer(.keyword_union, tree);
    }

    pub fn isOpaqueType(self: TypeWithHandle, tree: ast.Tree) bool {
        return self.isContainer(.keyword_opaque, tree);
    }

    pub fn isTypeFunc(self: TypeWithHandle, tree: ast.Tree) bool {
        var buf: [1]ast.Node.Index = undefined;
        switch (self.type.data) {
            .other => |n| return switch (tree.nodes.items(.tag)[n]) {
                .fn_proto => isTypeFunction(tree, tree.fnProto(n)),
                .fn_proto_multi => isTypeFunction(tree, tree.fnProtoMulti(n)),
                .fn_proto_one => isTypeFunction(tree, tree.fnProtoOne(&buf, n)),
                .fn_proto_simple => isTypeFunction(tree, tree.fnProtoSimple(&buf, n)),
                else => false,
            },
            else => return false,
        }
    }

    pub fn isGenericFunc(self: TypeWithHandle, tree: ast.Tree) bool {
        var buf: [1]ast.Node.Index = undefined;
        switch (self.type.data) {
            .other => |n| return switch (tree.nodes.items(.tag)[n]) {
                .fn_proto => isGenericFunction(tree, tree.fnProto(n)),
                .fn_proto_multi => isGenericFunction(tree, tree.fnProtoMulti(n)),
                .fn_proto_one => isGenericFunction(tree, tree.fnProtoOne(&buf, n)),
                .fn_proto_simple => isGenericFunction(tree, tree.fnProtoSimple(&buf, n)),
                else => false,
            },
            else => return false,
        }
    }

    pub fn isFunc(self: TypeWithHandle, tree: ast.Tree) bool {
        const tags = tree.nodes.items(.tag);
        switch (self.type.data) {
            .other => |n| return switch (tags[n]) {
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                => true,
                else => false,
            },
            else => return false,
        }
    }
};

pub fn resolveTypeOfNode(store: *DocumentStore, arena: *std.heap.ArenaAllocator, node_handle: NodeWithHandle) error{OutOfMemory}!?TypeWithHandle {
    var bound_type_params = BoundTypeParams.init(&arena.allocator);
    return resolveTypeOfNodeInternal(store, arena, node_handle, &bound_type_params);
}

fn maybeCollectImport(tree: ast.Tree, builtin_call: ast.Node.Index, arr: *std.ArrayList([]const u8)) !void {
    const tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);

    const builtin_tag = tags[builtin_call];
    const builtin_data = datas[builtin_call];

    std.debug.assert(builtin_tag == .builtin_call);
    if (!std.mem.eql(u8, tree.tokenSlice(builtin_call), "@import")) return;
    const params = tree.extra_data[builtin_data.lhs..builtin_data.rhs];
    if (params.len > 1) return;

    if (tags[params[0]] != .string_literal) return;

    const import_str = tree.tokenSlice(params[0]);
    try arr.append(import_str[1 .. import_str.len - 1]);
}

/// Collects all imports we can find into a slice of import paths (without quotes).
/// The import paths are valid as long as the tree is.
pub fn collectImports(import_arr: *std.ArrayList([]const u8), tree: ast.Tree) !void {
    // TODO: Currently only detects `const smth = @import("string literal")<.SomeThing>;`
    const tags = tree.nodes.items(.tag);
    for (tree.rootDecls()) |decl_idx| {
        const var_decl_maybe: ?ast.full.VarDecl = switch (tags[decl_idx]) {
            .global_var_decl => tree.globalVarDecl(decl_idx),
            .local_var_decl => tree.localVarDecl(decl_idx),
            .simple_var_decl => tree.simpleVarDecl(decl_idx),
            else => null,
        };
        const var_decl = var_decl_maybe orelse continue;

        const init_node = var_decl.ast.init_node;
        const init_node_tag = tags[init_node];
        switch (init_node_tag) {
            .builtin_call => try maybeCollectImport(tree, init_node, import_arr),
            // @TODO: FIX ME what is the syntax to support for imports using dot notation?
            // .Period => {
            //     const infix_op = init_node.cast(ast.Node.SimpleInfixOp).?;

            //     if (infix_op.lhs.tag != .BuiltinCall) continue;
            //     try maybeCollectImport(tree, infix_op.lhs.castTag(.BuiltinCall).?, import_arr);
            // },
            else => {},
        }
    }
}

pub const NodeWithHandle = struct {
    node: ast.Node.Index,
    handle: *DocumentStore.Handle,
};

pub const FieldAccessReturn = struct {
    original: TypeWithHandle,
    unwrapped: ?TypeWithHandle = null,
};

pub fn getFieldAccessType(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    tokenizer: *std.zig.Tokenizer,
) !?FieldAccessReturn {
    var current_type = TypeWithHandle.typeVal(.{
        .node = undefined,
        .handle = handle,
    });

    // TODO Actually bind params here when calling functions instead of just skipping args.
    var bound_type_params = BoundTypeParams.init(&arena.allocator);

    while (true) {
        const tok = tokenizer.next();
        switch (tok.tag) {
            .eof => return FieldAccessReturn{
                .original = current_type,
                .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
            },
            .identifier => {
                if (try lookupSymbolGlobal(store, arena, current_type.handle, tokenizer.buffer[tok.loc.start..tok.loc.end], source_index)) |child| {
                    current_type = (try child.resolveType(store, arena, &bound_type_params)) orelse return null;
                } else return null;
            },
            .period => {
                const after_period = tokenizer.next();
                switch (after_period.tag) {
                    .Eof => return FieldAccessReturn{
                        .original = current_type,
                        .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
                    },
                    .Identifier => {
                        if (after_period.loc.end == tokenizer.buffer.len) {
                            return FieldAccessReturn{
                                .original = current_type,
                                .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
                            };
                        }

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
                        log.debug("Unrecognized token {} after period.", .{after_period.tag});
                        return null;
                    },
                }
            },
            .period_asterisk => {
                current_type = (try resolveDerefType(store, arena, current_type, &bound_type_params)) orelse return null;
            },
            .l_paren => {
                const current_type_node = switch (current_type.type.data) {
                    .other => |n| n,
                    else => return null,
                };

                // Can't call a function type, we need a function type instance.
                if (current_type.type.is_type_val) return null;
                if (current_type_node.castTag(.FnProto)) |func| {
                    if (try resolveReturnType(store, arena, func, current_type.handle, &bound_type_params)) |ret| {
                        current_type = ret;
                        // Skip to the right paren
                        var paren_count: usize = 1;
                        var next = tokenizer.next();
                        while (next.tag != .Eof) : (next = tokenizer.next()) {
                            if (next.tag == .RParen) {
                                paren_count -= 1;
                                if (paren_count == 0) break;
                            } else if (next.tag == .LParen) {
                                paren_count += 1;
                            }
                        } else return null;
                    } else return null;
                } else return null;
            },
            .l_bracket => {
                var brack_count: usize = 1;
                var next = tokenizer.next();
                var is_range = false;
                while (next.tag != .Eof) : (next = tokenizer.next()) {
                    if (next.tag == .RBracket) {
                        brack_count -= 1;
                        if (brack_count == 0) break;
                    } else if (next.tag == .LBracket) {
                        brack_count += 1;
                    } else if (next.tag == .Ellipsis2 and brack_count == 1) {
                        is_range = true;
                    }
                } else return null;

                current_type = (try resolveBracketAccessType(store, arena, current_type, if (is_range) .Range else .Single, &bound_type_params)) orelse return null;
            },
            else => {
                log.debug("Unimplemented token: {}", .{tok.tag});
                return null;
            },
        }
    }

    return FieldAccessReturn{
        .original = current_type,
        .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
    };
}

pub fn isNodePublic(tree: ast.Tree, node: ast.Node.Index) bool {
    switch (tree.nodes.items(.tag)[node]) {
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const var_decl = node.castTag(.VarDecl).?;
            const var_decl = varDecl(tree, node).?;
            return var_decl.visib_token != null;
        },
        .fn_proto => tree.fnProto(node).visib_token != null,
        .fn_proto_one => tree.fnProtoOne(node).visib_token != null,
        .fn_proto_simple => tree.fnProtoSimple(node).visib_token != null,
        .fn_proto_multi => tree.fnProtoMulti(node).visib_token != null,
        else => return true,
    }
}

pub fn nodeToString(tree: ast.Tree, node: ast.Node.Index) ?[]const u8 {
    switch (tree.nodes.items(.tag)[node]) {
        .container_field => return tree.tokenSlice(tree.containerField(node).ast.name_token),
        .container_field_init => return tree.tokenSlice(tree.containerFieldInit(node).ast.name_token),
        .container_field_align => return tree.tokenSlice(tree.containerFieldAlign(node).ast.name_token),
        // @TODO: Error tag name
        // .ErrorTag => {
        //     const tag = node.castTag(.ErrorTag).?;
        //     return tree.tokenSlice(tag.name_token);
        // },
        .identifier => return tree.tokenSlice(node),
        .fn_proto => if (tree.fnProto(node).name_token) |name| {
            return tree.tokenSlice(name);
        },
        .fn_proto_one => if (tree.fnProtoOne(node).name_token) |name| {
            return tree.tokenSlice(name);
        },
        .fn_proto_multi => if (tree.fnProtoMulti(node).name_token) |name| {
            return tree.tokenSlice(name);
        },
        .fn_proto_simple => if (tree.fnProtoSimple(node).name_token) |name| {
            return tree.tokenSlice(name);
        },
        else => {
            log.debug("INVALID: {}", .{node.tag});
        },
    }

    return null;
}

fn nodeContainsSourceIndex(tree: ast.Tree, node: ast.Node.Index, source_index: usize) bool {
    const first_token = tree.tokenLocation(0, tree.firstToken(node)).line_start;
    const last_token = tree.tokenLocation(@truncate(u32, first_token), tree.lastToken(node)).line_end;
    return source_index >= first_token and source_index <= last_token;
}

fn isBuiltinCall(tree: ast.Tree, node: ast.Node.Index) bool {
    return switch (tree.nodes.items(.tag)[node]) {
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => true,
        else => false,
    };
}

fn builtinCallParams(tree: ast.Tree, node: ast.Node.Index) []const ast.Node.Index {
    std.debug.assert(isBuiltinCall(tree, node));
    const datas = tree.node.items(.data);

    return switch (tree.nodes.items(.tag)[node]) {
        .builtin_call, .builtin_call_comma => tree.extra_data[datas[node].lhs..datas[node].rhs],
        .builtin_call_two, .builtin_call_two_comma => if (datas[node].lhs == 0)
            &.{}
        else if (datas[node].rhs == 0)
            &.{datas[node].lhs}
        else
            &.{ datas[node].lhs, datas[node].rhs },
        else => unreachable,
    };
}

pub fn getImportStr(tree: ast.Tree, node: ast.Node.Index, source_index: usize) ?[]const u8 {
    const node_tags = tree.nodes.items(.tag);
    var buf: [2]ast.Node.Index = undefined;
    const decls = switch (node_tags[node]) {
        .root => tree.rootDecls(),
        .container_decl => tree.containerDecl(node).ast.members,
        .container_decl => tree.containerDeclArg(node).ast.members,
        .container_decl => tree.containerDeclTwo(&buf, node).ast.members,
        else => return null,
    };

    for (decls) |decl_idx| {
        if (!nodeContainsSourceIndex(tree, decl_idx, source_index)) {
            continue;
        }

        if (isBuiltinCall(tree, decl_idx)) {
            const builtin_token = tree.nodes.items(.main_token)[decl_idx];
            const call_name = tree.tokenSlice(builtin_token);

            if (!std.mem.eql(u8, call_name, "@import")) continue;
            const params = builtinCallParams(tree, decl_idx);
            if (params.len != 1) continue;

            const import_str = tree.tokenSlice(tree.firstToken(params[0]));
            return import_str[1 .. import_str.len - 1];
        }

        if (getImportStr(tree, decl_idx, source_index)) |name| {
            return name;
        }
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
    label: bool,
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

const DocumentPosition = @import("offsets.zig").DocumentPosition;

pub fn documentPositionContext(arena: *std.heap.ArenaAllocator, document: types.TextDocument, doc_position: DocumentPosition) !PositionContext {
    const line = doc_position.line;
    var tokenizer = std.zig.Tokenizer.init(line[0..doc_position.line_index]);
    var stack = try std.ArrayList(StackState).initCapacity(&arena.allocator, 8);

    while (true) {
        const tok = tokenizer.next();
        // Early exits.
        switch (tok.tag) {
            .invalid, .invalid_ampersands => {
                // Single '@' do not return a builtin token so we check this on our own.
                if (line[doc_position.line_index - 1] == '@') {
                    return PositionContext{
                        .builtin = .{
                            .start = doc_position.line_index - 1,
                            .end = doc_position.line_index,
                        },
                    };
                }
                return .other;
            },
            .doc_comment, .container_doc_comment => return .comment,
            .eof => break,
            else => {},
        }

        // State changes
        var curr_ctx = try peek(&stack);
        switch (tok.tag) {
            .string_literal, .multiline_string_literal_line => curr_ctx.ctx = .{ .string_literal = tok.loc },
            .identifier => switch (curr_ctx.ctx) {
                .empty, .pre_label => curr_ctx.ctx = .{ .var_access = tok.loc },
                .label => |filled| if (!filled) {
                    curr_ctx.ctx = .{ .label = true };
                } else {
                    curr_ctx.ctx = .{ .var_access = tok.loc };
                },
                else => {},
            },
            .builtin => switch (curr_ctx.ctx) {
                .empty, .pre_label => curr_ctx.ctx = .{ .builtin = tok.loc },
                else => {},
            },
            .period, .period_asterisk => switch (curr_ctx.ctx) {
                .empty, .pre_label => curr_ctx.ctx = .enum_literal,
                .enum_literal => curr_ctx.ctx = .empty,
                .field_access => {},
                .other => {},
                .global_error_set => {},
                else => curr_ctx.ctx = .{
                    .field_access = tokenRangeAppend(curr_ctx.ctx.range().?, tok),
                },
            },
            .keyword_break, .keyword_continue => curr_ctx.ctx = .pre_label,
            .colon => if (curr_ctx.ctx == .pre_label) {
                curr_ctx.ctx = .{ .label = false };
            } else {
                curr_ctx.ctx = .empty;
            },
            .question_mark => switch (curr_ctx.ctx) {
                .field_access => {},
                else => curr_ctx.ctx = .empty,
            },
            .l_paren => try stack.append(.{ .ctx = .empty, .stack_id = .Paren }),
            .l_bracket => try stack.append(.{ .ctx = .empty, .stack_id = .Bracket }),
            .r_paren => {
                _ = stack.pop();
                if (curr_ctx.stack_id != .Paren) {
                    (try peek(&stack)).ctx = .empty;
                }
            },
            .r_bracket => {
                _ = stack.pop();
                if (curr_ctx.stack_id != .Bracket) {
                    (try peek(&stack)).ctx = .empty;
                }
            },
            .keyword_error => curr_ctx.ctx = .global_error_set,
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

fn addOutlineNodes(allocator: *std.mem.Allocator, tree: ast.Tree, parent: ast.Node.Index, context: *GetDocumentSymbolsContext) anyerror!void {
    switch (tree.nodes.items(.tag)[parent]) {
        .StringLiteral,
        .IntegerLiteral,
        .BuiltinCall,
        .Call,
        .Identifier,
        .Add,
        .AddWrap,
        .ArrayCat,
        .ArrayMult,
        .Assign,
        .AssignBitAnd,
        .AssignBitOr,
        .AssignBitShiftLeft,
        .AssignBitShiftRight,
        .AssignBitXor,
        .AssignDiv,
        .AssignSub,
        .AssignSubWrap,
        .AssignMod,
        .AssignAdd,
        .AssignAddWrap,
        .AssignMul,
        .AssignMulWrap,
        .BangEqual,
        .BitAnd,
        .BitOr,
        .BitShiftLeft,
        .BitShiftRight,
        .BitXor,
        .BoolAnd,
        .BoolOr,
        .Div,
        .EqualEqual,
        .ErrorUnion,
        .GreaterOrEqual,
        .GreaterThan,
        .LessOrEqual,
        .LessThan,
        .MergeErrorSets,
        .Mod,
        .Mul,
        .MulWrap,
        .Period,
        .Range,
        .Sub,
        .SubWrap,
        .OrElse,
        .AddressOf,
        .Await,
        .BitNot,
        .BoolNot,
        .OptionalType,
        .Negation,
        .NegationWrap,
        .Resume,
        .Try,
        .ArrayType,
        .ArrayTypeSentinel,
        .PtrType,
        .SliceType,
        .Slice,
        .Deref,
        .UnwrapOptional,
        .ArrayAccess,
        .Return,
        .Break,
        .Continue,
        .ArrayInitializerDot,
        .SwitchElse,
        .SwitchCase,
        .For,
        .EnumLiteral,
        .PointerIndexPayload,
        .StructInitializerDot,
        .PointerPayload,
        .While,
        .Switch,
        .Else,
        .BoolLiteral,
        .NullLiteral,
        .Defer,
        .StructInitializer,
        .FieldInitializer,
        .If,
        .MultilineStringLiteral,
        .UndefinedLiteral,
        .AnyType,
        .Block,
        .ErrorSetDecl,
        => return,

        .ContainerDecl => {
            const decl = child.castTag(.ContainerDecl).?;

            for (decl.fieldsAndDecls()) |cchild|
                try addOutlineNodes(allocator, tree, cchild, context);
            return;
        },
        else => {},
    }
    try getDocumentSymbolsInternal(allocator, tree, child, context);
}

const GetDocumentSymbolsContext = struct {
    prev_loc: offsets.TokenLocation = .{
        .line = 0,
        .column = 0,
        .offset = 0,
    },
    symbols: *std.ArrayList(types.DocumentSymbol),
    encoding: offsets.Encoding,
};

fn getDocumentSymbolsInternal(allocator: *std.mem.Allocator, tree: ast.Tree, node: ast.Node.Index, context: *GetDocumentSymbolsContext) anyerror!void {
    const name = getDeclName(tree, node) orelse return;
    if (name.len == 0)
        return;

    const start_loc = context.prev_loc.add(try offsets.tokenRelativeLocation(tree, context.prev_loc.offset, tree.firstToken(node), context.encoding));
    const end_loc = start_loc.add(try offsets.tokenRelativeLocation(tree, start_loc.offset, tree.lastToken(node), context.encoding));
    context.prev_loc = end_loc;
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

    const tags = tree.nodes.items(.tag);
    (try context.symbols.addOne()).* = .{
        .name = name,
        .kind = switch (tags[node]) {
            .fn_proto,
            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            => .Function,
            .local_var_decl,
            .global_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => .Variable,
            .container_field,
            .container_field_align,
            .container_field_init,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            => .Field,
            else => .Variable,
        },
        .range = range,
        .selectionRange = range,
        .detail = "",
        .children = ch: {
            var children = std.ArrayList(types.DocumentSymbol).init(allocator);

            var child_context = GetDocumentSymbolsContext{
                .prev_loc = start_loc,
                .symbols = &children,
                .encoding = context.encoding,
            };

            var index: usize = 0;
            if (true) @panic("FIX: addOutlineNodes");
            // try addOutlineNodes(allocator, tree, node, &child_context);

            // while (node.iterate(index)) |child| : (index += 1) {
            //     try addOutlineNodes(allocator, tree, child, &child_context);
            // }

            break :ch children.items;
        },
    };
}

pub fn getDocumentSymbols(allocator: *std.mem.Allocator, tree: ast.Tree, encoding: offsets.Encoding) ![]types.DocumentSymbol {
    var symbols = try std.ArrayList(types.DocumentSymbol).initCapacity(allocator, tree.rootDecls().len);

    var context = GetDocumentSymbolsContext{
        .symbols = &symbols,
        .encoding = encoding,
    };

    for (tree.rootDecls()) |idx| {
        try getDocumentSymbolsInternal(allocator, tree, idx, &context);
    }

    return symbols.items;
}

pub const Declaration = union(enum) {
    /// Index of the ast node
    ast_node: ast.Node.Index,
    /// Function parameter
    param_decl: ast.full.FnProto.Param,
    pointer_payload: struct {
        name: ast.TokenIndex,
        condition: ast.Node.Index,
    },
    // array_payload: struct {
    //     identifier: *ast.Node,
    //     array_expr: ast.full.ArrayType,
    // },
    switch_payload: struct {
        node: ast.TokenIndex,
        switch_expr: ast.Node.Index,
        items: []const ast.Node.Index,
    },
    label_decl: ast.TokenIndex, // .id is While, For or Block (firstToken will be the label)
};

pub const DeclWithHandle = struct {
    decl: *Declaration,
    handle: *DocumentStore.Handle,

    pub fn nameToken(self: DeclWithHandle) ast.TokenIndex {
        const tree = self.handle.tree;
        return switch (self.decl.*) {
            .ast_node => |n| getDeclNameToken(tree, n).?,
            .param_decl => |p| p.name_token.?,
            .pointer_payload => |pp| pp.node.value_symbol.firstToken(),
            // .array_payload => |ap| ap.identifier.firstToken(),
            .switch_payload => |sp| sp.node.value_symbol.firstToken(),
            .label_decl => |ld| ld.firstToken(),
        };
    }

    pub fn location(self: DeclWithHandle, encoding: offsets.Encoding) !offsets.TokenLocation {
        const tree = self.handle.tree;
        return try offsets.tokenRelativeLocation(tree, 0, self.nameToken(), encoding);
    }

    fn isPublic(self: DeclWithHandle) bool {
        return switch (self.decl.*) {
            .ast_node => |node| isNodePublic(self.handle.tree, node),
            else => true,
        };
    }

    pub fn resolveType(self: DeclWithHandle, store: *DocumentStore, arena: *std.heap.ArenaAllocator, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
        const tree = self.handle.tree;
        const node_tags = tree.nodes.items(.tag);
        const main_tokens = tree.nodes.items(.main_token);
        return switch (self.decl.*) {
            .ast_node => |node| try resolveTypeOfNodeInternal(store, arena, .{ .node = node, .handle = self.handle }, bound_type_params),
            .param_decl => |*param_decl| {
                if (typeIsType(self.handle.tree, param_decl.type_expr)) {
                    var bound_param_it = bound_type_params.iterator();
                    while (bound_param_it.next()) |entry| {
                        if (entry.key == param_decl) return entry.value;
                    }
                    return null;
                } else if (node_tags[param_decl.type_expr] == .identifier) {
                    if (param_decl.name_token) |name_tok| {
                        if (std.mem.eql(u8, tree.tokenSlice(tree.firstToken(param_decl.type_expr)), tree.tokenSlice(name_tok)))
                            return null;
                    }
                }
                return ((try resolveTypeOfNodeInternal(
                    store,
                    arena,
                    .{ .node = param_decl.type_expr, .handle = self.handle },
                    bound_type_params,
                )) orelse return null).instanceTypeVal();
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
            // .array_payload => |pay| try resolveBracketAccessType(
            //     store,
            //     arena,
            //     (try resolveTypeOfNodeInternal(store, arena, .{
            //         .node = pay.array_expr,
            //         .handle = self.handle,
            //     }, bound_type_params)) orelse return null,
            //     .Single,
            //     bound_type_params,
            // ),
            .label_decl => return null,
            .switch_payload => |pay| {
                if (pay.items.len == 0) return null;
                // TODO Peer type resolution, we just use the first item for now.
                const switch_expr_type = (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = pay.switch_expr,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null;
                if (!switch_expr_type.isUnionType(tree))
                    return null;

                if (node_tags[pay.items[0]] == .enum_literal) {
                    const scope = findContainerScope(.{ .node = switch_expr_type.type.data.other, .handle = switch_expr_type.handle }) orelse return null;
                    if (scope.decls.getEntry(self.handle.tree.tokenSlice(main_tokens[pay.items[0]]))) |candidate| {
                        switch (candidate.value) {
                            .ast_node => |node| {
                                if (containerField(tree, node)) |container_field| {
                                    if (container_field.ast.type_expr != 0) {
                                        return ((try resolveTypeOfNodeInternal(
                                            store,
                                            arena,
                                            .{ .node = container_field.ast.type_expr, .handle = switch_expr_type.handle },
                                            bound_type_params,
                                        )) orelse return null).instanceTypeVal();
                                    }
                                }
                            },
                            else => {},
                        }
                        return null;
                    }
                }
                return null;
            },
        };
    }
};

fn containerField(tree: ast.Tree, node: ast.Node.Index) ?ast.full.ContainerField {
    return switch (tree.nodes.items(.tag)[node]) {
        .container_field => tree.containerField(node),
        .container_field_init => tree.containerFieldInit(node),
        .container_field_align => tree.containerFieldAlign(node),
        else => null,
    };
}

fn findContainerScope(container_handle: NodeWithHandle) ?*Scope {
    const container = container_handle.node;
    const handle = container_handle.handle;

    if (container.tag != .ContainerDecl and container.tag != .Root and container.tag != .ErrorSetDecl) {
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

fn iterateSymbolsContainerInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    orig_handle: *DocumentStore.Handle,
    comptime callback: anytype,
    context: anytype,
    instance_access: bool,
    use_trail: *std.ArrayList(*ast.Node.Use),
) error{OutOfMemory}!void {
    const container = container_handle.node;
    const handle = container_handle.handle;

    const is_enum = if (container.castTag(.ContainerDecl)) |cont_decl|
        handle.tree.token_ids[cont_decl.kind_token] == .Keyword_enum
    else
        false;

    if (findContainerScope(container_handle)) |container_scope| {
        var decl_it = container_scope.decls.iterator();
        while (decl_it.next()) |entry| {
            switch (entry.value) {
                .ast_node => |node| {
                    if (node.tag == .ContainerField) {
                        if (!instance_access and !is_enum) continue;
                        if (instance_access and is_enum) continue;
                    }
                },
                .label_decl => continue,
                else => {},
            }
            const decl = DeclWithHandle{ .decl = &entry.value, .handle = handle };
            if (handle != orig_handle and !decl.isPublic()) continue;
            try callback(context, decl);
        }

        // for (container_scope.uses) |use| {
        //     if (handle != orig_handle and use.visib_token == null) continue;
        //     if (std.mem.indexOfScalar(*ast.Node.Use, use_trail.items, use) != null) continue;
        //     try use_trail.append(use);

        //     const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
        //     const use_expr_node = switch (use_expr.type.data) {
        //         .other => |n| n,
        //         else => continue,
        //     };
        //     try iterateSymbolsContainerInternal(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, orig_handle, callback, context, false, use_trail);
        // }
    }
}

pub fn iterateSymbolsContainer(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    orig_handle: *DocumentStore.Handle,
    comptime callback: anytype,
    context: anytype,
    instance_access: bool,
) error{OutOfMemory}!void {
    var use_trail = std.ArrayList(*ast.Node.Use).init(&arena.allocator);
    return try iterateSymbolsContainerInternal(store, arena, container_handle, orig_handle, callback, context, instance_access, &use_trail);
}

pub fn iterateLabels(
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: anytype,
    context: anytype,
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

fn iterateSymbolsGlobalInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: anytype,
    context: anytype,
    use_trail: *std.ArrayList(*ast.Node.Use),
) error{OutOfMemory}!void {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            var decl_it = scope.decls.iterator();
            while (decl_it.next()) |entry| {
                if (entry.value == .ast_node and entry.value.ast_node.tag == .ContainerField) continue;
                if (entry.value == .label_decl) continue;
                try callback(context, DeclWithHandle{ .decl = &entry.value, .handle = handle });
            }

            // for (scope.uses) |use| {
            //     if (std.mem.indexOfScalar(*ast.Node.Use, use_trail.items, use) != null) continue;
            //     try use_trail.append(use);

            //     const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
            //     const use_expr_node = switch (use_expr.type.data) {
            //         .other => |n| n,
            //         else => continue,
            //     };
            //     try iterateSymbolsContainerInternal(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, handle, callback, context, false, use_trail);
            // }
        }

        if (scope.range.start >= source_index) return;
    }
}

pub fn iterateSymbolsGlobal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    comptime callback: anytype,
    context: anytype,
) error{OutOfMemory}!void {
    var use_trail = std.ArrayList(*ast.Node.Use).init(&arena.allocator);
    return try iterateSymbolsGlobalInternal(store, arena, handle, source_index, callback, context, &use_trail);
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
    // uses: []const *ast.Node.Use,
    symbol: []const u8,
    handle: *DocumentStore.Handle,
    use_trail: *std.ArrayList(*ast.Node.Use),
) error{OutOfMemory}!?DeclWithHandle {
    // for (uses) |use| {
    //     if (std.mem.indexOfScalar(*ast.Node.Use, use_trail.items, use) != null) continue;
    //     try use_trail.append(use);

    //     const use_expr = (try resolveTypeOfNode(store, arena, .{ .node = use.expr, .handle = handle })) orelse continue;
    //     const use_expr_node = switch (use_expr.type.data) {
    //         .other => |n| n,
    //         else => continue,
    //     };
    //     if (try lookupSymbolContainerInternal(store, arena, .{ .node = use_expr_node, .handle = use_expr.handle }, symbol, false, use_trail)) |candidate| {
    //         if (candidate.handle != handle and !candidate.isPublic()) {
    //             continue;
    //         }
    //         return candidate;
    //     }
    // }
    return null;
}

pub fn lookupLabel(
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            if (scope.decls.getEntry(symbol)) |candidate| {
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

fn lookupSymbolGlobalInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
    use_trail: *std.ArrayList(*ast.Node.Use),
) error{OutOfMemory}!?DeclWithHandle {
    for (handle.document_scope.scopes) |scope| {
        if (source_index >= scope.range.start and source_index < scope.range.end) {
            if (scope.decls.getEntry(symbol)) |candidate| {
                switch (candidate.value) {
                    .ast_node => |node| {
                        if (node.tag == .ContainerField) continue;
                    },
                    .label_decl => continue,
                    else => {},
                }
                return DeclWithHandle{
                    .decl = &candidate.value,
                    .handle = handle,
                };
            }

            // if (try resolveUse(store, arena, scope.uses, symbol, handle, use_trail)) |result| return result;
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
    var use_trail = std.ArrayList(*ast.Node.Use).init(&arena.allocator);
    return try lookupSymbolGlobalInternal(store, arena, handle, symbol, source_index, &use_trail);
}

fn lookupSymbolContainerInternal(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    symbol: []const u8,
    /// If true, we are looking up the symbol like we are accessing through a field access
    /// of an instance of the type, otherwise as a field access of the type value itself.
    instance_access: bool,
    use_trail: *std.ArrayList(*ast.Node.Use),
) error{OutOfMemory}!?DeclWithHandle {
    const container = container_handle.node;
    const handle = container_handle.handle;

    const is_enum = if (container.castTag(.ContainerDecl)) |cont_decl|
        handle.tree.token_ids[cont_decl.kind_token] == .Keyword_enum
    else
        false;

    if (findContainerScope(container_handle)) |container_scope| {
        if (container_scope.decls.getEntry(symbol)) |candidate| {
            switch (candidate.value) {
                .ast_node => |node| {
                    if (node.tag == .ContainerField) {
                        if (!instance_access and !is_enum) return null;
                        if (instance_access and is_enum) return null;
                    }
                },
                .label_decl => unreachable,
                else => {},
            }
            return DeclWithHandle{ .decl = &candidate.value, .handle = handle };
        }

        // if (try resolveUse(store, arena, container_scope.uses, symbol, handle, use_trail)) |result| return result;
        return null;
    }

    return null;
}

pub fn lookupSymbolContainer(
    store: *DocumentStore,
    arena: *std.heap.ArenaAllocator,
    container_handle: NodeWithHandle,
    symbol: []const u8,
    /// If true, we are looking up the symbol like we are accessing through a field access
    /// of an instance of the type, otherwise as a field access of the type value itself.
    instance_access: bool,
) error{OutOfMemory}!?DeclWithHandle {
    var use_trail = std.ArrayList(*ast.Node.Use).init(&arena.allocator);
    return try lookupSymbolContainerInternal(store, arena, container_handle, symbol, instance_access, &use_trail);
}

pub const DocumentScope = struct {
    scopes: []Scope,
    error_completions: []types.CompletionItem,
    enum_completions: []types.CompletionItem,

    pub fn debugPrint(self: DocumentScope) void {
        for (self.scopes) |scope| {
            log.debug(
                \\--------------------------
                \\Scope {}, range: [{}, {})
                \\ {} usingnamespaces
                \\Decls: 
            , .{
                scope.data,
                scope.range.start,
                scope.range.end,
                {},
                // scope.uses.len,
            });

            var decl_it = scope.decls.iterator();
            var idx: usize = 0;
            while (decl_it.next()) |name_decl| : (idx += 1) {
                if (idx != 0) log.debug(", ", .{});
            }
            log.debug("{s}", .{name_decl.key});
            log.debug("\n--------------------------\n", .{});
        }
    }

    pub fn deinit(self: DocumentScope, allocator: *std.mem.Allocator) void {
        for (self.scopes) |*scope| {
            scope.decls.deinit();
            // allocator.free(scope.uses);
            allocator.free(scope.tests);
        }
        allocator.free(self.scopes);
        for (self.error_completions) |item| if (item.documentation) |doc| allocator.free(doc.value);
        allocator.free(self.error_completions);
        for (self.enum_completions) |item| if (item.documentation) |doc| allocator.free(doc.value);
        allocator.free(self.enum_completions);
    }
};

pub const Scope = struct {
    pub const Data = union(enum) {
        container: ast.Node.Index, // .tag is ContainerDecl or Root or ErrorSetDecl
        function: ast.Node.Index, // .tag is FnProto
        block: ast.Node.Index, // .tag is Block
        other,
    };

    range: SourceRange,
    decls: std.StringHashMap(Declaration),
    tests: []const ast.Node.Index,
    // uses: []const *ast.Node.Data,

    data: Data,
};

pub fn makeDocumentScope(allocator: *std.mem.Allocator, tree: ast.Tree) !DocumentScope {
    var scopes = std.ArrayListUnmanaged(Scope){};
    var error_completions = std.ArrayListUnmanaged(types.CompletionItem){};
    var enum_completions = std.ArrayListUnmanaged(types.CompletionItem){};

    errdefer {
        scopes.deinit(allocator);
        for (error_completions.items) |item| if (item.documentation) |doc| allocator.free(doc.value);
        error_completions.deinit(allocator);
        for (enum_completions.items) |item| if (item.documentation) |doc| allocator.free(doc.value);
        enum_completions.deinit(allocator);
    }
    // pass root node index ('0')
    try makeScopeInternal(allocator, &scopes, &error_completions, &enum_completions, tree, 0);
    return DocumentScope{
        .scopes = scopes.toOwnedSlice(allocator),
        .error_completions = error_completions.toOwnedSlice(allocator),
        .enum_completions = enum_completions.toOwnedSlice(allocator),
    };
}

fn nodeSourceRange(tree: ast.Tree, node: ast.Node.Index) SourceRange {
    const loc = tree.tokenLocation(0, tree.firstToken(node));
    return SourceRange{
        .start = loc.line_start,
        .end = loc.line_end,
    };
}

fn isContainer(tag: ast.Node.Tag) bool {
    return switch (tag) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .root,
        .error_set_decl,
        => true,
        else => false,
    };
}

/// Returns the member indices of a given declaration container.
/// Asserts given `tag` is a container node
fn declMembers(tree: ast.Tree, tag: ast.Node.Tag, node_idx: ast.Node.Index) []const ast.Node.Index {
    std.debug.assert(isContainer(tag));
    return switch (tag) {
        .container_decl, .container_decl_trailing => tree.containerDecl(node_idx).ast.members,
        .container_decl_arg, .container_decl_arg_trailing => tree.containerDeclArg(node_idx).ast.members,
        .container_decl_two, .container_decl_two_trailing => blk: {
            var buffer: [2]ast.Node.Index = undefined;
            break :blk tree.containerDeclTwo(&buffer, node_idx).ast.members;
        },
        .tagged_union, .tagged_union_trailing => tree.taggedUnion(node_idx).ast.members,
        .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => tree.taggedUnionEnumTag(node_idx).ast.members,
        .tagged_union_two, .tagged_union_two_trailing => blk: {
            var buffer: [2]ast.Node.Index = undefined;
            break :blk tree.taggedUnionTwo(&buffer, node_idx).ast.members;
        },
        .root => tree.rootDecls(),
        // @TODO: Fix error set declarations
        .error_set_decl => &[_]ast.Node.Index{},
        else => unreachable,
    };
}

/// Returns an `ast.full.VarDecl` for a given node index.
/// Returns null if the tag doesn't match
fn varDecl(tree: ast.Tree, node_idx: ast.Node.Index) ?ast.full.VarDecl {
    return switch (tree.nodes.items(.tag)[node_idx]) {
        .global_var_decl => tree.globalVarDecl(node_idx),
        .local_var_decl => tree.localVarDecl(node_idx),
        .aligned_var_decl => tree.alignedVarDecl(node_idx),
        .simple_var_decl => tree.simpleVarDecl(node_idx),
        else => null,
    };
}

// TODO Possibly collect all imports to diff them on changes
//      as well
fn makeScopeInternal(
    allocator: *std.mem.Allocator,
    scopes: *std.ArrayListUnmanaged(Scope),
    error_completions: *std.ArrayListUnmanaged(types.CompletionItem),
    enum_completions: *std.ArrayListUnmanaged(types.CompletionItem),
    tree: ast.Tree,
    node_idx: ast.Node.Index,
) error{OutOfMemory}!void {
    const tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const node = tags[node_idx];

    if (isContainer(node)) {
        const ast_decls = declMembers(tree, node, node_idx);

        (try scopes.addOne(allocator)).* = .{
            .range = nodeSourceRange(tree, node_idx),
            .decls = std.StringHashMap(Declaration).init(allocator),
            // .uses = &[0]*ast.Node.Use{},
            .tests = &.{},
            .data = .{ .container = node_idx },
        };
        const scope_idx = scopes.items.len - 1;
        // var uses = std.ArrayList(*ast.Node.Use).init(allocator);
        var tests = std.ArrayList(ast.Node.Index).init(allocator);

        errdefer {
            scopes.items[scope_idx].decls.deinit();
            // uses.deinit();
            tests.deinit();
        }

        for (ast_decls) |decl| {
            // @TODO: Implement using namespace
            // if (decl.castTag(.Use)) |use| {
            //     try uses.append(use);
            //     continue;
            // }

            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, decl);
            const name = getDeclName(tree, decl) orelse continue;
            // @TODO: implement tests
            // if (decl.tag == .TestDecl) {
            //     try tests.append(decl);
            //     continue;
            // }

            if (tags[decl] == .error_set_decl) {
                (try error_completions.addOne(allocator)).* = .{
                    .label = name,
                    .kind = .Constant,
                    .documentation = if (try getDocComments(allocator, tree, decl, .Markdown)) |docs|
                        .{ .kind = .Markdown, .value = docs }
                    else
                        null,
                };
            }

            const container_field: ?ast.full.ContainerField = switch (tags[decl]) {
                .container_field => tree.containerField(decl),
                .container_field_align => tree.containerFieldAlign(decl),
                .container_field_init => tree.containerFieldInit(decl),
                else => null,
            };

            if (container_field) |field| {
                const empty_field = field.ast.type_expr == 0 and field.ast.value_expr == 0;
                if (empty_field and node == .root) {
                    continue;
                }

                // @TODO: We can probably just use node_idx directly instead of first transforming to container
                const container_decl: ?ast.full.ContainerDecl = switch (node) {
                    .container_decl, .container_decl_trailing => tree.containerDecl(node_idx),
                    .container_decl_arg, .container_decl_arg_trailing => tree.containerDeclArg(node_idx),
                    .container_decl_two, .container_decl_two_trailing => blk: {
                        var buffer: [2]ast.Node.Index = undefined;
                        break :blk tree.containerDeclTwo(&buffer, node_idx);
                    },
                    .tagged_union, .tagged_union_trailing => tree.taggedUnion(node_idx),
                    .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => tree.taggedUnionEnumTag(node_idx),
                    .tagged_union_two, .tagged_union_two_trailing => blk: {
                        var buffer: [2]ast.Node.Index = undefined;
                        break :blk tree.taggedUnionTwo(&buffer, node_idx);
                    },
                    else => null,
                };

                if (container_decl) |container| {
                    const kind = token_tags[container.ast.main_token];
                    if (empty_field and (kind == .keyword_struct or (kind == .keyword_union and container.ast.arg == 0))) {
                        continue;
                    }

                    if (!std.mem.eql(u8, name, "_")) {
                        (try enum_completions.addOne(allocator)).* = .{
                            .label = name,
                            .kind = .Constant,
                            .documentation = if (try getDocComments(allocator, tree, node_idx, .Markdown)) |docs|
                                .{ .kind = .Markdown, .value = docs }
                            else
                                null,
                        };
                    }
                }
            }

            if (try scopes.items[scope_idx].decls.fetchPut(name, .{ .ast_node = decl })) |existing| {
                // TODO Record a redefinition error.
            }
        }

        scopes.items[scope_idx].tests = tests.toOwnedSlice();
        // scopes.items[scope_idx].uses = uses.toOwnedSlice();
        return;
    }

    switch (node) {
        .fn_proto, .fn_proto_one, .fn_proto_simple, .fn_proto_multi, .fn_decl => {
            var buf: [1]ast.Node.Index = undefined;
            const func: ast.full.FnProto = switch (node) {
                .fn_proto => tree.fnProto(node_idx),
                .fn_proto_one => tree.fnProtoOne(&buf, node_idx),
                .fn_proto_simple => tree.fnProtoSimple(&buf, node_idx),
                .fn_proto_multi => tree.fnProtoMulti(node_idx),
                .fn_decl => tree.fnProto(data[node_idx].lhs),
                else => unreachable,
            };

            (try scopes.addOne(allocator)).* = .{
                .range = nodeSourceRange(tree, node_idx),
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &.{},
                .data = .{ .function = node_idx },
            };
            var scope_idx = scopes.items.len - 1;
            errdefer scopes.items[scope_idx].decls.deinit();

            var it = func.iterate(tree);
            while (it.next()) |param| {
                if (param.name_token) |name_token| {
                    if (try scopes.items[scope_idx].decls.fetchPut(tree.tokenSlice(name_token), .{ .param_decl = param })) |existing| {
                        // TODO record a redefinition error
                    }
                }
            }

            if (node == .fn_decl) {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, data[node_idx].rhs);
            }

            return;
        },
        .test_decl => {
            return try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, data[node_idx].rhs);
        },
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            const first_token = tree.firstToken(node_idx);
            const last_token = tree.lastToken(node_idx);

            // if labeled block
            if (token_tags[first_token] == .identifier) {
                const scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.tokenLocation(0, main_tokens[node_idx]).line_start,
                        .end = tree.tokenLocation(0, last_token).line_start,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &.{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();
                try scope.decls.putNoClobber(tree.tokenSlice(first_token), .{ .label_decl = first_token });
            }

            (try scopes.addOne(allocator)).* = .{
                .range = nodeSourceRange(tree, node_idx),
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &.{},
                .data = .{ .block = node_idx },
            };
            var scope_idx = scopes.items.len - 1;
            // var uses = std.ArrayList(*ast.Node.Use).init(allocator);

            errdefer {
                scopes.items[scope_idx].decls.deinit();
                // uses.deinit();
            }

            const statements: []const ast.Node.Index = switch (node) {
                .block, .block_semicolon => tree.extra_data[data[node_idx].lhs..data[node_idx].rhs],
                .block_two, .block_two_semicolon => blk: {
                    const statements = &[_]ast.Node.Index{ data[node_idx].lhs, data[node_idx].rhs };
                    const len: usize = if (data[node_idx].lhs == 0)
                        @as(usize, 0)
                    else if (data[node_idx].rhs == 0)
                        @as(usize, 1)
                    else
                        @as(usize, 2);
                    break :blk statements[0..len];
                },
                else => unreachable,
            };

            for (statements) |idx| {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, idx);
                // if (tags[
                if (varDecl(tree, idx)) |var_decl| {
                    const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                    if (try scopes.items[scope_idx].decls.fetchPut(name, .{ .ast_node = idx })) |existing| {
                        // TODO record a redefinition error.
                    }
                }
            }

            // scopes.items[scope_idx].uses = uses.toOwnedSlice();
            return;
        },
        .@"comptime", .@"nosuspend" => {
            return try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, data[node_idx].lhs);
        },
        .@"if", .if_simple => {
            const if_node: ast.full.If = if (node == .@"if")
                tree.ifFull(node_idx)
            else
                tree.ifSimple(node_idx);

            if (if_node.payload_token) |payload| {
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.tokenLocation(0, payload).line_start,
                        .end = tree.tokenLocation(0, tree.lastToken(if_node.ast.then_expr)).line_end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &.{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .name = name_token,
                        .condition = if_node.ast.cond_expr,
                    },
                });
            }

            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, if_node.ast.then_expr);

            if (if_node.ast.else_expr != 0) {
                if (if_node.error_token) |err_token| {
                    std.debug.assert(token_tags[err_token] == .identifier);
                    var scope = try scopes.addOne(allocator);
                    scope.* = .{
                        .range = .{
                            .start = tree.tokenLocation(0, err_token).line_start,
                            .end = tree.tokenLocation(0, tree.lastToken(if_node.ast.else_expr)).line_end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        // .uses = &[0]*ast.Node.Use{},
                        .tests = &.{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const name = tree.tokenSlice(err_token);
                    try scope.decls.putNoClobber(name, .{ .ast_node = if_node.ast.else_expr });
                }
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, if_node.ast.else_expr);
            }
        },
        .@"while", .while_simple, .while_cont, .@"for", .for_simple => {
            const while_node: ast.full.While = switch (node) {
                .@"while" => tree.whileFull(node_idx),
                .while_simple => tree.whileSimple(node_idx),
                .while_cont => tree.whileCont(node_idx),
                .@"for" => tree.forFull(node_idx),
                .for_simple => tree.forSimple(node_idx),
                else => unreachable,
            };
            if (while_node.label_token) |label| {
                std.debug.assert(tags[label] == .identifier);
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.tokenLocation(0, main_tokens[node_idx]).line_start,
                        .end = tree.tokenLocation(0, tree.lastToken(while_node.ast.then_expr)).line_end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &.{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{ .label_decl = label });
            }

            if (while_node.payload_token) |payload| {
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.tokenLocation(0, payload).line_start,
                        .end = tree.tokenLocation(0, tree.lastToken(while_node.ast.then_expr)).line_end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &.{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .name = name_token,
                        .condition = while_node.ast.cond_expr,
                    },
                });
            }
            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, while_node.ast.then_expr);

            if (while_node.ast.else_expr != 0) {
                if (while_node.error_token) |err_token| {
                    std.debug.assert(token_tags[err_token] == .identifier);
                    var scope = try scopes.addOne(allocator);
                    scope.* = .{
                        .range = .{
                            .start = tree.tokenLocation(0, err_token).line_start,
                            .end = tree.tokenLocation(0, tree.lastToken(while_node.ast.else_expr)).line_end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        // .uses = &[0]*ast.Node.Use{},
                        .tests = &.{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const name = tree.tokenSlice(err_token);
                    try scope.decls.putNoClobber(name, .{ .ast_node = while_node.ast.else_expr });
                }
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, while_node.ast.else_expr);
            }
        },
        .switch_case, .switch_case_one => {
            const switch_case: ast.full.SwitchCase = switch (node) {
                .switch_case => tree.switchCase(node_idx),
                .switch_case_one => tree.switchCaseOne(node_idx),
                else => unreachable,
            };

            if (switch_case.payload_token) |payload| {
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.tokenLocation(0, payload).line_start,
                        .end = tree.tokenLocation(0, tree.lastToken(switch_case.ast.target_expr)).line_end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &.{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                // if payload is *name than get next token
                const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                const name = tree.tokenSlice(name_token);

                try scope.decls.putNoClobber(name, .{
                    .switch_payload = .{
                        .node = payload,
                        .switch_expr = switch_case.ast.target_expr,
                        .items = switch_case.ast.values,
                    },
                });
            }

            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, switch_case.ast.target_expr);
        },
        .global_var_decl, .local_var_decl, .aligned_var_decl, .simple_var_decl => {
            const var_decl = varDecl(tree, node_idx).?;
            if (var_decl.ast.type_node != 0) {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, var_decl.ast.type_node);
            }

            if (var_decl.ast.init_node != 0) {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, var_decl.ast.init_node);
            }
        },
        else => {
            // @TODO: Could we just do node_idx + 1 here?
            // var child_idx: usize = 0;
            // while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
            //     try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, child_node);
            // }
        },
    }
}
