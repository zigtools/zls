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
                if (is_comma or tag == .Keyword_const) try buffer.append(' ');
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
        .ast_node => |inner_node| inner_node.tag == .ContainerDecl or inner_node.tag == .Root,
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
    fn_decl: *ast.Node.FnProto,
    handle: *DocumentStore.Handle,
    bound_type_params: *BoundTypeParams,
) !?TypeWithHandle {
    if (isTypeFunction(handle.tree, fn_decl) and fn_decl.getBodyNode() != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(handle.tree, fn_decl) orelse return null;
        if (ret.getRHS()) |rhs| {
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

    if (opt_node.cast(ast.Node.SimplePrefixOp)) |prefix_op| {
        if (opt_node.tag == .OptionalType) {
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
        .primitive, .slice, .pointer => return null,
    };

    if (rhs_node.cast(ast.Node.SimpleInfixOp)) |infix_op| {
        if (rhs_node.tag == .ErrorUnion) {
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = infix_op.rhs,
                .handle = rhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        }
    }

    return null;
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

    if (deref_node.castTag(.PtrType)) |ptr_type| {
        switch (deref.handle.tree.token_ids[ptr_type.op_token]) {
            .Asterisk => {
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = ptr_type.rhs,
                    .handle = deref.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            },
            .LBracket, .AsteriskAsterisk => return null,
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

    if (lhs_node.castTag(.SliceType)) |slice_type| {
        if (rhs == .Single)
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = slice_type.rhs,
                .handle = lhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        return lhs;
    } else if (lhs_node.castTag(.ArrayType)) |array_type| {
        if (rhs == .Single)
            return ((try resolveTypeOfNodeInternal(store, arena, .{
                .node = array_type.rhs,
                .handle = lhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        return TypeWithHandle{
            .type = .{ .data = .{ .slice = array_type.rhs }, .is_type_val = false },
            .handle = lhs.handle,
        };
    } else if (lhs_node.castTag(.PtrType)) |ptr_type| {
        if (ptr_type.rhs.castTag(.ArrayType)) |child_arr| {
            if (rhs == .Single) {
                return ((try resolveTypeOfNodeInternal(store, arena, .{
                    .node = child_arr.rhs,
                    .handle = lhs.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }
            return lhs;
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

pub const BoundTypeParams = std.AutoHashMap(*const ast.Node.FnProto.ParamDecl, TypeWithHandle);

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

    switch (node.tag) {
        .VarDecl => {
            const vari = node.castTag(.VarDecl).?;
            if (vari.getTypeNode()) |type_node| block: {
                return ((try resolveTypeOfNodeInternal(
                    store,
                    arena,
                    .{ .node = type_node, .handle = handle },
                    bound_type_params,
                )) orelse break :block).instanceTypeVal();
            }
            const init_node = vari.getInitNode() orelse return null;

            return try resolveTypeOfNodeInternal(store, arena, .{ .node = init_node, .handle = handle }, bound_type_params);
        },
        .Identifier => {
            if (isTypeIdent(handle.tree, node.firstToken())) {
                return TypeWithHandle{
                    .type = .{ .data = .primitive, .is_type_val = true },
                    .handle = handle,
                };
            }

            if (try lookupSymbolGlobal(store, arena, handle, handle.tree.getNodeSource(node), handle.tree.token_locs[node.firstToken()].start)) |child| {
                switch (child.decl.*) {
                    .ast_node => |n| {
                        if (n == node) return null;
                        if (n.castTag(.VarDecl)) |var_decl| {
                            if (var_decl.getInitNode()) |init_node|
                                if (init_node == node) return null;
                        }
                    },
                    else => {},
                }
                return try child.resolveType(store, arena, bound_type_params);
            }
            return null;
        },
        .ContainerField => {
            const field = node.castTag(.ContainerField).?;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = field.type_expr orelse return null, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .Call => {
            const call = node.castTag(.Call).?;
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
            if (decl_node.castTag(.FnProto)) |fn_decl| {
                var has_self_param: u8 = 0;
                if (call.lhs.cast(ast.Node.SimpleInfixOp)) |lhs_infix_op| {
                    if (call.lhs.tag == .Period) {
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
        .Comptime => {
            const ct = node.castTag(.Comptime).?;
            return try resolveTypeOfNodeInternal(store, arena, .{ .node = ct.expr, .handle = handle }, bound_type_params);
        },
        .GroupedExpression => {
            const grouped = node.castTag(.GroupedExpression).?;
            return try resolveTypeOfNodeInternal(store, arena, .{ .node = grouped.expr, .handle = handle }, bound_type_params);
        },
        .StructInitializer => {
            const struct_init = node.castTag(.StructInitializer).?;
            return ((try resolveTypeOfNodeInternal(
                store,
                arena,
                .{ .node = struct_init.lhs, .handle = handle },
                bound_type_params,
            )) orelse return null).instanceTypeVal();
        },
        .ErrorSetDecl => {
            return TypeWithHandle.typeVal(node_handle);
        },
        .Slice => {
            const slice = node.castTag(.Slice).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = slice.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveBracketAccessType(store, arena, left_type, .Range, bound_type_params);
        },
        .Deref, .UnwrapOptional => {
            const suffix = node.cast(ast.Node.SimpleSuffixOp).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = suffix.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return switch (node.tag) {
                .UnwrapOptional => try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params),
                .Deref => try resolveDerefType(store, arena, left_type, bound_type_params),
                else => unreachable,
            };
        },
        .ArrayAccess => {
            const arr_acc = node.castTag(.ArrayAccess).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = arr_acc.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveBracketAccessType(store, arena, left_type, .Single, bound_type_params);
        },
        .Period => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;
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
        .OrElse => {
            const infix_op = node.cast(ast.Node.SimpleInfixOp).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = infix_op.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapOptionalType(store, arena, left_type, bound_type_params);
        },
        .Catch => {
            const infix_op = node.cast(ast.Node.Catch).?;
            const left_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = infix_op.lhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapErrorType(store, arena, left_type, bound_type_params);
        },
        .ErrorUnion => return TypeWithHandle.typeVal(node_handle),
        .SliceType,
        .ArrayType,
        .OptionalType,
        .PtrType,
        => return TypeWithHandle.typeVal(node_handle),
        .Try => {
            const prefix_op = node.cast(ast.Node.SimplePrefixOp).?;
            const rhs_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = prefix_op.rhs,
                .handle = handle,
            }, bound_type_params)) orelse return null;
            return try resolveUnwrapErrorType(store, arena, rhs_type, bound_type_params);
        },
        .AddressOf => {
            const prefix_op = node.cast(ast.Node.SimplePrefixOp).?;
            const rhs_type = (try resolveTypeOfNodeInternal(store, arena, .{
                .node = prefix_op.rhs,
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
        .BuiltinCall => {
            const builtin_call = node.castTag(.BuiltinCall).?;
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
            if (import_param.tag != .StringLiteral) return null;

            const import_str = handle.tree.tokenSlice(import_param.castTag(.StringLiteral).?.token);
            const new_handle = (store.resolveImport(handle, import_str[1 .. import_str.len - 1]) catch |err| {
                log.debug("Error {} while processing import {s}", .{ err, import_str });
                return null;
            }) orelse return null;

            return TypeWithHandle.typeVal(.{ .node = &new_handle.tree.root_node.base, .handle = new_handle });
        },
        .ContainerDecl => {
            const container = node.castTag(.ContainerDecl).?;
            const kind = handle.tree.token_ids[container.kind_token];
            return TypeWithHandle.typeVal(node_handle);
        },
        .FnProto => {
            // This is a function type
            if (node.castTag(.FnProto).?.getNameToken() == null) {
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
        else => {},
    }
    return null;
}

// TODO Reorganize this file, perhaps split into a couple as well
// TODO Make this better, nested levels of type vals
pub const Type = struct {
    data: union(enum) {
        pointer: *ast.Node,
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
            .other => |n| return n.tag == .Root,
            else => return false,
        }
    }

    fn isContainer(self: TypeWithHandle, container_kind_tok: std.zig.Token.Id) bool {
        switch (self.type.data) {
            .other => |n| {
                if (n.castTag(.ContainerDecl)) |cont| {
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

    pub fn isNamespace(self: TypeWithHandle) bool {
        if (!self.isStructType()) return false;
        var idx: usize = 0;
        while (self.type.data.other.iterate(idx)) |child| : (idx += 1) {
            if (child.tag == .ContainerField)
                return false;
        }
        return true;
    }

    pub fn isEnumType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_enum);
    }

    pub fn isUnionType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_union);
    }

    pub fn isOpaqueType(self: TypeWithHandle) bool {
        return self.isContainer(.Keyword_opaque);
    }

    pub fn isTypeFunc(self: TypeWithHandle) bool {
        switch (self.type.data) {
            .other => |n| {
                if (n.castTag(.FnProto)) |fn_proto| {
                    return isTypeFunction(self.handle.tree, fn_proto);
                }
                return false;
            },
            else => return false,
        }
    }

    pub fn isGenericFunc(self: TypeWithHandle) bool {
        switch (self.type.data) {
            .other => |n| {
                if (n.castTag(.FnProto)) |fn_proto| {
                    return isGenericFunction(self.handle.tree, fn_proto);
                }
                return false;
            },
            else => return false,
        }
    }

    pub fn isFunc(self: TypeWithHandle) bool {
        switch (self.type.data) {
            .other => |n| {
                return n.tag == .FnProto;
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
    node: *ast.Node,
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
        switch (tok.id) {
            .Eof => return FieldAccessReturn{
                .original = current_type,
                .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
            },
            .Identifier => {
                if (try lookupSymbolGlobal(store, arena, current_type.handle, tokenizer.buffer[tok.loc.start..tok.loc.end], source_index)) |child| {
                    current_type = (try child.resolveType(store, arena, &bound_type_params)) orelse return null;
                } else return null;
            },
            .Period => {
                const after_period = tokenizer.next();
                switch (after_period.id) {
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
                        log.debug("Unrecognized token {} after period.", .{after_period.id});
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
                if (current_type_node.castTag(.FnProto)) |func| {
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
                log.debug("Unimplemented token: {}", .{tok.id});
                return null;
            },
        }
    }

    return FieldAccessReturn{
        .original = current_type,
        .unwrapped = try resolveDerefType(store, arena, current_type, &bound_type_params),
    };
}

pub fn isNodePublic(tree: ast.Tree, node: *ast.Node) bool {
    switch (node.tag) {
        .VarDecl => {
            const var_decl = node.castTag(.VarDecl).?;
            return var_decl.getVisibToken() != null;
        },
        .FnProto => {
            const func = node.castTag(.FnProto).?;
            return func.getVisibToken() != null;
        },
        else => return true,
    }
}

pub fn nodeToString(tree: ast.Tree, node: *ast.Node) ?[]const u8 {
    switch (node.tag) {
        .ContainerField => {
            const field = node.castTag(.ContainerField).?;
            return tree.tokenSlice(field.name_token);
        },
        .ErrorTag => {
            const tag = node.castTag(.ErrorTag).?;
            return tree.tokenSlice(tag.name_token);
        },
        .Identifier => {
            const field = node.castTag(.Identifier).?;
            return tree.tokenSlice(field.token);
        },
        .FnProto => {
            const func = node.castTag(.FnProto).?;
            if (func.getNameToken()) |name_token| {
                return tree.tokenSlice(name_token);
            }
        },
        else => {
            log.debug("INVALID: {}", .{node.tag});
        },
    }

    return null;
}

fn nodeContainsSourceIndex(tree: ast.Tree, node: *ast.Node, source_index: usize) bool {
    const first_token = tree.token_locs[node.firstToken()];
    const last_token = tree.token_locs[node.lastToken()];
    return source_index >= first_token.start and source_index <= last_token.end;
}

pub fn getImportStr(tree: ast.Tree, source_index: usize) ?[]const u8 {
    var node = &tree.root_node.base;

    var child_idx: usize = 0;
    while (node.iterate(child_idx)) |child| {
        if (!nodeContainsSourceIndex(tree, child, source_index)) {
            child_idx += 1;
            continue;
        }
        if (child.castTag(.BuiltinCall)) |builtin_call| blk: {
            const call_name = tree.tokenSlice(builtin_call.builtin_token);

            if (!std.mem.eql(u8, call_name, "@import")) break :blk;
            if (builtin_call.params_len != 1) break :blk;

            const import_param = builtin_call.paramsConst()[0];
            const import_str_node = import_param.castTag(.StringLiteral) orelse break :blk;
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
            .line_comment, .doc_comment, .container_doc_comment => return .comment,
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
            try addOutlineNodes(allocator, tree, node, &child_context);

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
        node: ast.full.PtrType,
        condition: *ast.Node,
    },
    array_payload: struct {
        identifier: *ast.Node,
        array_expr: ast.full.ArrayType,
    },
    switch_payload: struct {
        node: ast.full.PtrType,
        switch_expr: *ast.Node,
        items: []const *ast.Node,
    },
    label_decl: *ast.Node, // .id is While, For or Block (firstToken will be the label)
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
            .array_payload => |ap| ap.identifier.firstToken(),
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
                    } else if (type_node.castTag(.Identifier)) |type_ident| {
                        if (param_decl.name_token) |name_tok| {
                            if (std.mem.eql(u8, self.handle.tree.tokenSlice(type_ident.firstToken()), self.handle.tree.tokenSlice(name_tok)))
                                return null;
                        }
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
            .switch_payload => |pay| {
                if (pay.items.len == 0) return null;
                // TODO Peer type resolution, we just use the first item for now.
                const switch_expr_type = (try resolveTypeOfNodeInternal(store, arena, .{
                    .node = pay.switch_expr,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null;
                if (!switch_expr_type.isUnionType())
                    return null;

                if (pay.items[0].castTag(.EnumLiteral)) |enum_lit| {
                    const scope = findContainerScope(.{ .node = switch_expr_type.type.data.other, .handle = switch_expr_type.handle }) orelse return null;
                    if (scope.decls.getEntry(self.handle.tree.tokenSlice(enum_lit.name))) |candidate| {
                        switch (candidate.value) {
                            .ast_node => |node| {
                                if (node.castTag(.ContainerField)) |container_field| {
                                    if (container_field.type_expr) |type_expr| {
                                        return ((try resolveTypeOfNodeInternal(
                                            store,
                                            arena,
                                            .{ .node = type_expr, .handle = switch_expr_type.handle },
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
fn declMembers(tree: ast.Tree, tag: ast.Node.Tag) []ast.Node.index {
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
    const node = tags[node_idx];

    if (isContainer(node)) {
        const ast_decls = declMembers(tree, node);

        (try scopes.addOne(allocator)).* = .{
            .range = nodeSourceRange(tree, node_idx),
            .decls = std.StringHashMap(Declaration).init(allocator),
            // .uses = &[0]*ast.Node.Use{},
            .tests = &[0]*ast.Node{},
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

            const container_field: ?ast.full.ContainerField = switch (decl) {
                .container_field => tree.containerField(decl),
                .container_field_align => tree.containerFieldAlign(decl),
                .container_field_init => tree.containerFieldInit(decl),
                else => null,
            };

            if (container_field) |field| {
                const empty_field = field.type_expr == 0 and field.value_expr == 0;
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
                    .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => blk: {
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
        .FnProto => {
            const func = node.castTag(.FnProto).?;

            (try scopes.addOne(allocator)).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &[0]*ast.Node{},
                .data = .{ .function = node },
            };
            var scope_idx = scopes.items.len - 1;
            errdefer scopes.items[scope_idx].decls.deinit();

            for (func.params()) |*param| {
                if (param.name_token) |name_tok| {
                    if (try scopes.items[scope_idx].decls.fetchPut(tree.tokenSlice(name_tok), .{ .param_decl = param })) |existing| {
                        // TODO Record a redefinition error
                    }
                }
            }

            if (func.getBodyNode()) |body| {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, body);
            }

            return;
        },
        .TestDecl => {
            return try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, node.castTag(.TestDecl).?.body_node);
        },
        .LabeledBlock => {
            const block = node.castTag(.LabeledBlock).?;
            std.debug.assert(tree.token_ids[block.label] == .Identifier);
            var scope = try scopes.addOne(allocator);
            scope.* = .{
                .range = .{
                    .start = tree.token_locs[block.lbrace].start,
                    .end = tree.token_locs[block.rbrace].end,
                },
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &[0]*ast.Node{},
                .data = .other,
            };
            errdefer scope.decls.deinit();

            try scope.decls.putNoClobber(tree.tokenSlice(block.label), .{
                .label_decl = node,
            });

            (try scopes.addOne(allocator)).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &[0]*ast.Node{},
                .data = .{ .block = node },
            };
            var scope_idx = scopes.items.len - 1;
            // var uses = std.ArrayList(*ast.Node.Use).init(allocator);

            errdefer {
                scopes.items[scope_idx].decls.deinit();
                // uses.deinit();
            }

            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
                // if (child_node.castTag(.Use)) |use| {
                // try uses.append(use);
                // continue;
                // }

                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, child_node);
                if (child_node.castTag(.VarDecl)) |var_decl| {
                    const name = tree.tokenSlice(var_decl.name_token);
                    if (try scopes.items[scope_idx].decls.fetchPut(name, .{ .ast_node = child_node })) |existing| {
                        // TODO Record a redefinition error.
                    }
                }
            }

            // scopes.items[scope_idx].uses = uses.toOwnedSlice();
            return;
        },
        .Block => {
            const block = node.castTag(.Block).?;

            (try scopes.addOne(allocator)).* = .{
                .range = nodeSourceRange(tree, node),
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
                .tests = &[0]*ast.Node{},
                .data = .{ .block = node },
            };
            var scope_idx = scopes.items.len - 1;
            // var uses = std.ArrayList(*ast.Node.Use).init(allocator);

            errdefer {
                scopes.items[scope_idx].decls.deinit();
                // uses.deinit();
            }

            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
                // if (child_node.castTag(.Use)) |use| {
                //     try uses.append(use);
                //     continue;
                // }

                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, child_node);
                if (child_node.castTag(.VarDecl)) |var_decl| {
                    const name = tree.tokenSlice(var_decl.name_token);
                    if (try scopes.items[scope_idx].decls.fetchPut(name, .{ .ast_node = child_node })) |existing| {
                        // TODO Record a redefinition error.
                    }
                }
            }

            // scopes.items[scope_idx].uses = uses.toOwnedSlice();
            return;
        },
        .Comptime => {
            return try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, node.castTag(.Comptime).?.expr);
        },
        .If => {
            const if_node = node.castTag(.If).?;

            if (if_node.payload) |payload| {
                std.debug.assert(payload.tag == .PointerPayload);
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[payload.firstToken()].start,
                        .end = tree.token_locs[if_node.body.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const ptr_payload = payload.castTag(.PointerPayload).?;
                std.debug.assert(ptr_payload.value_symbol.tag == .Identifier);
                const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .node = ptr_payload,
                        .condition = if_node.condition,
                    },
                });
            }
            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, if_node.body);

            if (if_node.@"else") |else_node| {
                if (else_node.payload) |payload| {
                    std.debug.assert(payload.tag == .Payload);
                    var scope = try scopes.addOne(allocator);
                    scope.* = .{
                        .range = .{
                            .start = tree.token_locs[payload.firstToken()].start,
                            .end = tree.token_locs[else_node.body.lastToken()].end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        // .uses = &[0]*ast.Node.Use{},
                        .tests = &[0]*ast.Node{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const err_payload = payload.castTag(.Payload).?;
                    std.debug.assert(err_payload.error_symbol.tag == .Identifier);
                    const name = tree.tokenSlice(err_payload.error_symbol.firstToken());
                    try scope.decls.putNoClobber(name, .{ .ast_node = payload });
                }
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, else_node.body);
            }
        },
        .While => {
            const while_node = node.castTag(.While).?;
            if (while_node.label) |label| {
                std.debug.assert(tree.token_ids[label] == .Identifier);
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[while_node.while_token].start,
                        .end = tree.token_locs[while_node.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{
                    .label_decl = node,
                });
            }

            if (while_node.payload) |payload| {
                std.debug.assert(payload.tag == .PointerPayload);
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[payload.firstToken()].start,
                        .end = tree.token_locs[while_node.body.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                const ptr_payload = payload.castTag(.PointerPayload).?;
                std.debug.assert(ptr_payload.value_symbol.tag == .Identifier);
                const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                try scope.decls.putNoClobber(name, .{
                    .pointer_payload = .{
                        .node = ptr_payload,
                        .condition = while_node.condition,
                    },
                });
            }
            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, while_node.body);

            if (while_node.@"else") |else_node| {
                if (else_node.payload) |payload| {
                    std.debug.assert(payload.tag == .Payload);
                    var scope = try scopes.addOne(allocator);
                    scope.* = .{
                        .range = .{
                            .start = tree.token_locs[payload.firstToken()].start,
                            .end = tree.token_locs[else_node.body.lastToken()].end,
                        },
                        .decls = std.StringHashMap(Declaration).init(allocator),
                        // .uses = &[0]*ast.Node.Use{},
                        .tests = &[0]*ast.Node{},
                        .data = .other,
                    };
                    errdefer scope.decls.deinit();

                    const err_payload = payload.castTag(.Payload).?;
                    std.debug.assert(err_payload.error_symbol.tag == .Identifier);
                    const name = tree.tokenSlice(err_payload.error_symbol.firstToken());
                    try scope.decls.putNoClobber(name, .{ .ast_node = payload });
                }
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, else_node.body);
            }
        },
        .For => {
            const for_node = node.castTag(.For).?;
            if (for_node.label) |label| {
                std.debug.assert(tree.token_ids[label] == .Identifier);
                var scope = try scopes.addOne(allocator);
                scope.* = .{
                    .range = .{
                        .start = tree.token_locs[for_node.for_token].start,
                        .end = tree.token_locs[for_node.lastToken()].end,
                    },
                    .decls = std.StringHashMap(Declaration).init(allocator),
                    // .uses = &[0]*ast.Node.Use{},
                    .tests = &[0]*ast.Node{},
                    .data = .other,
                };
                errdefer scope.decls.deinit();

                try scope.decls.putNoClobber(tree.tokenSlice(label), .{
                    .label_decl = node,
                });
            }

            std.debug.assert(for_node.payload.tag == .PointerIndexPayload);
            const ptr_idx_payload = for_node.payload.castTag(.PointerIndexPayload).?;
            std.debug.assert(ptr_idx_payload.value_symbol.tag == .Identifier);

            var scope = try scopes.addOne(allocator);
            scope.* = .{
                .range = .{
                    .start = tree.token_locs[ptr_idx_payload.firstToken()].start,
                    .end = tree.token_locs[for_node.body.lastToken()].end,
                },
                .decls = std.StringHashMap(Declaration).init(allocator),
                // .uses = &[0]*ast.Node.Use{},
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
                std.debug.assert(index_symbol.tag == .Identifier);
                const index_name = tree.tokenSlice(index_symbol.firstToken());
                if (try scope.decls.fetchPut(index_name, .{ .ast_node = index_symbol })) |existing| {
                    // TODO Record a redefinition error
                }
            }

            try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, for_node.body);
            if (for_node.@"else") |else_node| {
                std.debug.assert(else_node.payload == null);
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, else_node.body);
            }
        },
        .Switch => {
            const switch_node = node.castTag(.Switch).?;
            for (switch_node.casesConst()) |case| {
                if (case.*.castTag(.SwitchCase)) |case_node| {
                    if (case_node.payload) |payload| {
                        std.debug.assert(payload.tag == .PointerPayload);
                        var scope = try scopes.addOne(allocator);
                        scope.* = .{
                            .range = .{
                                .start = tree.token_locs[payload.firstToken()].start,
                                .end = tree.token_locs[case_node.expr.lastToken()].end,
                            },
                            .decls = std.StringHashMap(Declaration).init(allocator),
                            // .uses = &[0]*ast.Node.Use{},
                            .tests = &[0]*ast.Node{},
                            .data = .other,
                        };
                        errdefer scope.decls.deinit();

                        const ptr_payload = payload.castTag(.PointerPayload).?;
                        std.debug.assert(ptr_payload.value_symbol.tag == .Identifier);
                        const name = tree.tokenSlice(ptr_payload.value_symbol.firstToken());
                        try scope.decls.putNoClobber(name, .{
                            .switch_payload = .{
                                .node = ptr_payload,
                                .switch_expr = switch_node.expr,
                                .items = case_node.itemsConst(),
                            },
                        });
                    }
                    try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, case_node.expr);
                }
            }
        },
        .VarDecl => {
            const var_decl = node.castTag(.VarDecl).?;
            if (var_decl.getTypeNode()) |type_node| {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, type_node);
            }
            if (var_decl.getInitNode()) |init_node| {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, init_node);
            }
        },
        else => {
            var child_idx: usize = 0;
            while (node.iterate(child_idx)) |child_node| : (child_idx += 1) {
                try makeScopeInternal(allocator, scopes, error_completions, enum_completions, tree, child_node);
            }
        },
    }
}
