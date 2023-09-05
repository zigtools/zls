const std = @import("std");
const DocumentStore = @import("DocumentStore.zig");
const Ast = std.zig.Ast;
const types = @import("lsp.zig");
const offsets = @import("offsets.zig");
const URI = @import("uri.zig");
const log = std.log.scoped(.zls_analysis);
const ast = @import("ast.zig");
const tracy = @import("tracy.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
const InternPool = ComptimeInterpreter.InternPool;
const references = @import("features/references.zig");

const Analyser = @This();

gpa: std.mem.Allocator,
arena: std.heap.ArenaAllocator,
store: *DocumentStore,
ip: ?*InternPool,
bound_type_params: std.AutoHashMapUnmanaged(Declaration.Param, TypeWithHandle) = .{},
resolved_nodes: std.HashMapUnmanaged(NodeWithUri, ?TypeWithHandle, NodeWithUri.Context, std.hash_map.default_max_load_percentage) = .{},
/// used to detect recursion
node_trail: std.HashMapUnmanaged(NodeWithUri, void, NodeWithUri.Context, std.hash_map.default_max_load_percentage) = .{},

pub fn init(gpa: std.mem.Allocator, store: *DocumentStore, ip: ?*InternPool) Analyser {
    return .{
        .gpa = gpa,
        .arena = std.heap.ArenaAllocator.init(gpa),
        .store = store,
        .ip = ip,
    };
}

pub fn deinit(self: *Analyser) void {
    self.bound_type_params.deinit(self.gpa);
    self.resolved_nodes.deinit(self.gpa);
    self.node_trail.deinit(self.gpa);
    self.arena.deinit();
}

pub fn getDocCommentsBeforeToken(allocator: std.mem.Allocator, tree: Ast, base: Ast.TokenIndex) !?[]const u8 {
    const tokens = tree.tokens.items(.tag);
    const doc_comment_index = getDocCommentTokenIndex(tokens, base) orelse return null;
    return try collectDocComments(allocator, tree, doc_comment_index, false);
}

/// Gets a declaration's doc comments. Caller owns returned memory.
pub fn getDocComments(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) !?[]const u8 {
    const base = tree.nodes.items(.main_token)[node];
    const base_kind = tree.nodes.items(.tag)[node];

    switch (base_kind) {
        .root => return try collectDocComments(allocator, tree, 0, true),
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        .local_var_decl,
        .global_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        .container_field_init,
        .container_field_align,
        .container_field,
        => return try getDocCommentsBeforeToken(allocator, tree, base),
        else => {},
    }
    return null;
}

/// Get the first doc comment of a declaration.
pub fn getDocCommentTokenIndex(tokens: []const std.zig.Token.Tag, base_token: Ast.TokenIndex) ?Ast.TokenIndex {
    var idx = base_token;
    if (idx == 0) return null;
    idx -|= 1;
    if (tokens[idx] == .keyword_threadlocal and idx > 0) idx -|= 1;
    if (tokens[idx] == .string_literal and idx > 1 and tokens[idx -| 1] == .keyword_extern) idx -|= 1;
    if (tokens[idx] == .keyword_extern and idx > 0) idx -|= 1;
    if (tokens[idx] == .keyword_export and idx > 0) idx -|= 1;
    if (tokens[idx] == .keyword_inline and idx > 0) idx -|= 1;
    if (tokens[idx] == .identifier and idx > 0) idx -|= 1;
    if (tokens[idx] == .keyword_pub and idx > 0) idx -|= 1;

    // Find first doc comment token
    if (!(tokens[idx] == .doc_comment))
        return null;
    return while (tokens[idx] == .doc_comment) {
        if (idx == 0) break 0;
        idx -|= 1;
    } else idx + 1;
}

pub fn collectDocComments(allocator: std.mem.Allocator, tree: Ast, doc_comments: Ast.TokenIndex, container_doc: bool) ![]const u8 {
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();
    const tokens = tree.tokens.items(.tag);

    var curr_line_tok = doc_comments;
    while (true) : (curr_line_tok += 1) {
        const comm = tokens[curr_line_tok];
        if ((container_doc and comm == .container_doc_comment) or (!container_doc and comm == .doc_comment)) {
            try lines.append(tree.tokenSlice(curr_line_tok)[3..]);
        } else break;
    }

    return try std.mem.join(allocator, "\n", lines.items);
}

/// Gets a function's keyword, name, arguments and return value.
pub fn getFunctionSignature(tree: Ast, func: Ast.full.FnProto) []const u8 {
    const start = offsets.tokenToLoc(tree, func.ast.fn_token);

    const end = if (func.ast.return_type != 0)
        offsets.tokenToLoc(tree, ast.lastToken(tree, func.ast.return_type))
    else
        start;
    return tree.source[start.start..end.end];
}

fn formatSnippetPlaceholder(
    data: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    var split_it = std.mem.splitScalar(u8, data, '}');
    while (split_it.next()) |segment| {
        try writer.writeAll(segment);
        if (split_it.index) |index|
            if (data[index - 1] == '}') {
                try writer.writeAll("\\}");
            };
    }
}

const SnippetPlaceholderFormatter = std.fmt.Formatter(formatSnippetPlaceholder);

fn fmtSnippetPlaceholder(bytes: []const u8) SnippetPlaceholderFormatter {
    return .{ .data = bytes };
}

/// Creates snippet insert text for a function. Caller owns returned memory.
pub fn getFunctionSnippet(
    allocator: std.mem.Allocator,
    name: []const u8,
    iterator: *Ast.full.FnProto.Iterator,
) ![]const u8 {
    const tree = iterator.tree.*;

    var buffer = std.ArrayListUnmanaged(u8){};
    try buffer.ensureTotalCapacity(allocator, 128);

    var buf_stream = buffer.writer(allocator);

    try buf_stream.writeAll(name);
    try buf_stream.writeByte('(');

    const token_tags = tree.tokens.items(.tag);

    var i: usize = 0;
    while (ast.nextFnParam(iterator)) |param| : (i += 1) {
        if (i != 0)
            try buf_stream.writeAll(", ${")
        else
            try buf_stream.writeAll("${");

        try buf_stream.print("{d}:", .{i + 1});

        if (param.comptime_noalias) |token_index| {
            if (token_tags[token_index] == .keyword_comptime)
                try buf_stream.writeAll("comptime ")
            else
                try buf_stream.writeAll("noalias ");
        }

        if (param.name_token) |name_token| {
            try buf_stream.print("{}", .{fmtSnippetPlaceholder(tree.tokenSlice(name_token))});
            try buf_stream.writeAll(": ");
        }

        if (param.anytype_ellipsis3) |token_index| {
            if (token_tags[token_index] == .keyword_anytype)
                try buf_stream.writeAll("anytype")
            else
                try buf_stream.writeAll("...");
        } else if (param.type_expr != 0) {
            var curr_token = tree.firstToken(param.type_expr);
            var end_token = ast.lastToken(tree, param.type_expr);
            while (curr_token <= end_token) : (curr_token += 1) {
                const tag = token_tags[curr_token];
                const is_comma = tag == .comma;

                if (curr_token == end_token and is_comma) continue;
                try buf_stream.print("{}", .{fmtSnippetPlaceholder(tree.tokenSlice(curr_token))});
                if (is_comma or tag == .keyword_const) try buf_stream.writeByte(' ');
            }
        } // else Incomplete and that's ok :)

        try buf_stream.writeByte('}');
    }
    try buf_stream.writeByte(')');

    return buffer.toOwnedSlice(allocator);
}

pub fn isInstanceCall(
    analyser: *Analyser,
    call_handle: *const DocumentStore.Handle,
    call: Ast.full.Call,
    func_handle: *const DocumentStore.Handle,
    func: Ast.full.FnProto,
) !bool {
    return call_handle.tree.tokens.items(.tag)[call.ast.lparen - 2] == .period and
        try analyser.hasSelfParam(func_handle, func);
}

pub fn hasSelfParam(analyser: *Analyser, handle: *const DocumentStore.Handle, func: Ast.full.FnProto) !bool {
    // Non-decl prototypes cannot have a self parameter.
    if (func.name_token == null) return false;
    if (func.ast.params.len == 0) return false;

    const tree = handle.tree;
    var it = func.iterate(&tree);
    const param = ast.nextFnParam(&it).?;
    if (param.type_expr == 0) return false;

    const token_starts = tree.tokens.items(.start);
    const in_container = innermostContainer(handle, token_starts[func.ast.fn_token]);

    if (try analyser.resolveTypeOfNode(.{
        .node = param.type_expr,
        .handle = handle,
    })) |resolved_type| {
        if (std.meta.eql(in_container, resolved_type))
            return true;
    }

    if (ast.fullPtrType(tree, param.type_expr)) |ptr_type| {
        if (try analyser.resolveTypeOfNode(.{
            .node = ptr_type.ast.child_type,
            .handle = handle,
        })) |resolved_prefix_op| {
            if (std.meta.eql(in_container, resolved_prefix_op))
                return true;
        }
    }
    return false;
}

pub fn getVariableSignature(allocator: std.mem.Allocator, tree: Ast, var_decl: Ast.full.VarDecl) error{OutOfMemory}![]const u8 {
    const node_tags = tree.nodes.items(.tag);

    const start_token = var_decl.ast.mut_token;
    const end_token = blk: {
        const init_node = var_decl.ast.init_node;
        if (init_node == 0)
            break :blk start_token + 1;

        if (node_tags[init_node] == .merge_error_sets)
            return try std.fmt.allocPrint(allocator, "{s} error", .{
                offsets.tokensToSlice(tree, start_token, tree.firstToken(init_node) - 1),
            });

        if (node_tags[init_node] == .error_set_decl)
            break :blk tree.firstToken(init_node);

        var buf: [2]Ast.Node.Index = undefined;
        const container_decl = tree.fullContainerDecl(&buf, init_node) orelse
            break :blk ast.lastToken(tree, init_node);

        var token = container_decl.ast.main_token;
        var offset: Ast.TokenIndex = 0;

        // Tagged union: union(enum)
        if (container_decl.ast.enum_token) |enum_token| {
            token = enum_token;
            offset += 1;
        }

        // Backing integer: struct(u32), union(enum(u32))
        // Tagged union: union(ComplexTypeTag)
        if (container_decl.ast.arg != 0) {
            token = ast.lastToken(tree, container_decl.ast.arg);
            offset += 1;
        }

        break :blk token + offset;
    };
    return offsets.tokensToSlice(tree, start_token, end_token);
}

pub fn getContainerFieldSignature(tree: Ast, field: Ast.full.ContainerField) []const u8 {
    if (field.ast.value_expr == 0 and field.ast.type_expr == 0 and field.ast.align_expr == 0) {
        return ""; // TODO display the container's type
    }
    const start = offsets.tokenToIndex(tree, field.ast.main_token);
    const end_node = if (field.ast.value_expr != 0) field.ast.value_expr else field.ast.type_expr;
    const end = offsets.tokenToLoc(tree, ast.lastToken(tree, end_node)).end;
    return tree.source[start..end];
}

/// The node is the meta-type `type`
pub fn isMetaType(tree: Ast, node: Ast.Node.Index) bool {
    if (tree.nodes.items(.tag)[node] == .identifier) {
        return std.mem.eql(u8, tree.tokenSlice(tree.nodes.items(.main_token)[node]), "type");
    }
    return false;
}

pub fn isTypeFunction(tree: Ast, func: Ast.full.FnProto) bool {
    return isMetaType(tree, func.ast.return_type);
}

pub fn isGenericFunction(tree: Ast, func: Ast.full.FnProto) bool {
    var it = func.iterate(&tree);
    while (ast.nextFnParam(&it)) |param| {
        if (param.anytype_ellipsis3 != null or param.comptime_noalias != null) {
            return true;
        }
    }
    return false;
}

// STYLE

pub fn isCamelCase(name: []const u8) bool {
    return !std.ascii.isUpper(name[0]) and !isSnakeCase(name);
}

pub fn isPascalCase(name: []const u8) bool {
    return std.ascii.isUpper(name[0]) and !isSnakeCase(name);
}

pub fn isSnakeCase(name: []const u8) bool {
    return std.mem.indexOf(u8, name, "_") != null;
}

// ANALYSIS ENGINE

pub fn getDeclNameToken(tree: Ast, node: Ast.Node.Index) ?Ast.TokenIndex {
    return getContainerDeclNameToken(tree, null, node);
}

pub fn getContainerDeclNameToken(tree: Ast, container: ?Ast.Node.Index, node: Ast.Node.Index) ?Ast.TokenIndex {
    const tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const main_token = main_tokens[node];
    const token_tags = tree.tokens.items(.tag);

    return switch (tags[node]) {
        // regular declaration names. + 1 to mut token because name comes after 'const'/'var'
        .local_var_decl,
        .global_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const tok = tree.fullVarDecl(node).?.ast.mut_token + 1;
            return if (tok >= tree.tokens.len)
                null
            else
                tok;
        },
        // function declaration names
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => blk: {
            var params: [1]Ast.Node.Index = undefined;
            break :blk tree.fullFnProto(&params, node).?.name_token;
        },

        // containers
        .container_field,
        .container_field_init,
        .container_field_align,
        => {
            if (container) |container_node| {
                if (token_tags[main_tokens[container_node]] == .keyword_struct and
                    tree.fullContainerField(node).?.ast.tuple_like)
                {
                    return null;
                }
            }
            return main_token;
        },
        .identifier => main_token,
        .error_value => {
            const tok = main_token + 2;
            return if (tok >= tree.tokens.len)
                null
            else
                tok;
        }, // 'error'.<main_token +2>

        .test_decl => datas[node].lhs,

        else => null,
    };
}

pub fn getDeclName(tree: Ast, node: Ast.Node.Index) ?[]const u8 {
    return getContainerDeclName(tree, null, node);
}

pub fn getContainerDeclName(tree: Ast, container: ?Ast.Node.Index, node: Ast.Node.Index) ?[]const u8 {
    const name_token = getContainerDeclNameToken(tree, container, node) orelse return null;
    const name = offsets.tokenToSlice(tree, name_token);

    if (tree.nodes.items(.tag)[node] == .test_decl and
        tree.tokens.items(.tag)[name_token] == .string_literal)
    {
        return name[1 .. name.len - 1];
    }

    return name;
}

/// Resolves variable declarations consisting of chains of imports and field accesses of containers
/// Examples:
///```zig
/// const decl = @import("decl-file.zig").decl;
/// const other = decl.middle.other;
///```
pub fn resolveVarDeclAlias(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?DeclWithHandle {
    analyser.node_trail.clearRetainingCapacity();
    return try analyser.resolveVarDeclAliasInternal(node_handle);
}

fn resolveVarDeclAliasInternal(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?DeclWithHandle {
    const node_with_uri = NodeWithUri{ .node = node_handle.node, .uri = node_handle.handle.uri };

    const gop = try analyser.node_trail.getOrPut(analyser.gpa, node_with_uri);
    if (gop.found_existing) return null;

    return try analyser.resolveVarDeclAliasUncached(node_handle);
}

fn resolveVarDeclAliasUncached(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?DeclWithHandle {
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);

    const resolved = switch (node_tags[node_handle.node]) {
        .identifier => blk: {
            const token = main_tokens[node_handle.node];
            break :blk try analyser.lookupSymbolGlobal(
                handle,
                tree.tokenSlice(token),
                tree.tokens.items(.start)[token],
            );
        },
        .field_access => blk: {
            const lhs = datas[node_handle.node].lhs;
            const resolved = (try analyser.resolveTypeOfNode(.{ .node = lhs, .handle = handle })) orelse return null;
            if (!resolved.type.is_type_val)
                return null;

            const resolved_node = switch (resolved.type.data) {
                .other => |n| n,
                else => return null,
            };

            break :blk try analyser.lookupSymbolContainer(
                .{ .node = resolved_node, .handle = resolved.handle },
                tree.tokenSlice(datas[node_handle.node].rhs),
                .variable,
            );
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = handle.tree.fullVarDecl(node_handle.node).?;

            if (var_decl.ast.init_node == 0) return null;
            const base_exp = var_decl.ast.init_node;
            if (token_tags[var_decl.ast.mut_token] != .keyword_const) return null;

            return try analyser.resolveVarDeclAliasInternal(.{ .node = base_exp, .handle = handle });
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => blk: {
            const lhs = datas[node_handle.node].lhs;
            const name = tree.tokenSlice(main_tokens[lhs]);
            if (!std.mem.eql(u8, name, "@import") and !std.mem.eql(u8, name, "@cImport"))
                return null;

            const inner_node = (try analyser.resolveTypeOfNode(.{ .node = lhs, .handle = handle })) orelse return null;
            // assert root node
            std.debug.assert(inner_node.type.data.other == 0);
            const root_decl = &inner_node.handle.document_scope.decls.items[0];
            break :blk DeclWithHandle{ .decl = root_decl, .handle = inner_node.handle };
        },
        else => return null,
    } orelse return null;

    const resolved_node = switch (resolved.decl.*) {
        .ast_node => |node| node,
        else => return resolved,
    };

    if (analyser.node_trail.contains(.{ .node = resolved_node, .uri = resolved.handle.uri })) {
        return null;
    }

    if (try analyser.resolveVarDeclAliasUncached(.{ .node = resolved_node, .handle = resolved.handle })) |result| {
        return result;
    } else {
        return resolved;
    }
}

fn findReturnStatementInternal(tree: Ast, fn_decl: Ast.full.FnProto, body: Ast.Node.Index, already_found: *bool) ?Ast.Node.Index {
    var result: ?Ast.Node.Index = null;

    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);

    var buffer: [2]Ast.Node.Index = undefined;
    const statements = ast.blockStatements(tree, body, &buffer) orelse return null;

    for (statements) |child_idx| {
        if (node_tags[child_idx] == .@"return") {
            if (datas[child_idx].lhs != 0) {
                const lhs = datas[child_idx].lhs;
                var buf: [1]Ast.Node.Index = undefined;
                if (tree.fullCall(&buf, lhs)) |call| {
                    const call_name = getDeclName(tree, call.ast.fn_expr);
                    if (call_name) |name| {
                        if (std.mem.eql(u8, name, tree.tokenSlice(fn_decl.name_token.?))) {
                            continue;
                        }
                    }
                }
            }

            if (already_found.*) return null;
            already_found.* = true;
            result = child_idx;
            continue;
        }

        result = findReturnStatementInternal(tree, fn_decl, child_idx, already_found);
    }

    return result;
}

fn findReturnStatement(tree: Ast, fn_decl: Ast.full.FnProto, body: Ast.Node.Index) ?Ast.Node.Index {
    var already_found = false;
    return findReturnStatementInternal(tree, fn_decl, body, &already_found);
}

fn resolveReturnType(analyser: *Analyser, fn_decl: Ast.full.FnProto, handle: *const DocumentStore.Handle, fn_body: ?Ast.Node.Index) !?TypeWithHandle {
    const tree = handle.tree;
    if (isTypeFunction(tree, fn_decl) and fn_body != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(tree, fn_decl, fn_body.?) orelse return null;
        const data = tree.nodes.items(.data)[ret];
        if (data.lhs != 0) {
            return try analyser.resolveTypeOfNodeInternal(.{ .node = data.lhs, .handle = handle });
        }

        return null;
    }

    if (fn_decl.ast.return_type == 0) return null;
    const return_type = fn_decl.ast.return_type;
    const ret = .{ .node = return_type, .handle = handle };
    const child_type = (try analyser.resolveTypeOfNodeInternal(ret)) orelse
        return null;

    if (ast.hasInferredError(tree, fn_decl)) {
        const child_type_ptr = try analyser.arena.allocator().create(TypeWithHandle);
        child_type_ptr.* = child_type.instanceTypeVal() orelse return null;
        return TypeWithHandle{
            .type = .{ .data = .{ .error_union = child_type_ptr }, .is_type_val = false },
            .handle = handle,
        };
    } else return child_type.instanceTypeVal();
}

/// Resolves the child type of an optional type
fn resolveUnwrapOptionalType(analyser: *Analyser, opt: TypeWithHandle) !?TypeWithHandle {
    const opt_node = switch (opt.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (opt.handle.tree.nodes.items(.tag)[opt_node] == .optional_type) {
        return ((try analyser.resolveTypeOfNodeInternal(.{
            .node = opt.handle.tree.nodes.items(.data)[opt_node].lhs,
            .handle = opt.handle,
        })) orelse return null).instanceTypeVal();
    }

    return null;
}

fn resolveUnwrapErrorUnionType(analyser: *Analyser, rhs: TypeWithHandle, side: ErrorUnionSide) !?TypeWithHandle {
    const rhs_node = switch (rhs.type.data) {
        .other => |n| n,
        .error_union => |t| return switch (side) {
            .left => null,
            .right => t.*,
        },
        else => return null,
    };

    if (rhs.handle.tree.nodes.items(.tag)[rhs_node] == .error_union) {
        const data = rhs.handle.tree.nodes.items(.data)[rhs_node];
        return ((try analyser.resolveTypeOfNodeInternal(.{
            .node = switch (side) {
                .left => data.lhs,
                .right => data.rhs,
            },
            .handle = rhs.handle,
        })) orelse return null).instanceTypeVal();
    }

    return null;
}

fn resolveTaggedUnionFieldType(analyser: *Analyser, type_handle: TypeWithHandle, symbol: []const u8) !?TypeWithHandle {
    if (!type_handle.type.is_type_val)
        return null;

    const node = switch (type_handle.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (node == 0)
        return null;

    const handle = type_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node) orelse
        return null;

    if (token_tags[container_decl.ast.main_token] != .keyword_union)
        return null;

    const child = try type_handle.lookupSymbol(analyser, symbol) orelse
        return null;

    if (child.decl.* != .ast_node or !node_tags[child.decl.ast_node].isContainerField())
        return try child.resolveType(analyser);

    if (container_decl.ast.enum_token != null) {
        const union_type_ptr = try analyser.arena.allocator().create(TypeWithHandle);
        union_type_ptr.* = type_handle;
        return TypeWithHandle{
            .type = .{ .data = .{ .union_tag = union_type_ptr }, .is_type_val = false },
            .handle = handle,
        };
    }

    if (container_decl.ast.arg != 0) {
        const tag_type = (try analyser.resolveTypeOfNode(.{
            .node = container_decl.ast.arg,
            .handle = handle,
        })) orelse return null;
        return tag_type.instanceTypeVal();
    }

    return null;
}

/// Resolves the child type of a deref type
fn resolveDerefType(analyser: *Analyser, deref: TypeWithHandle) !?TypeWithHandle {
    const deref_node = switch (deref.type.data) {
        .other => |n| n,
        .pointer => |t| return t.*,
        else => return null,
    };
    const tree = deref.handle.tree;
    const main_token = tree.nodes.items(.main_token)[deref_node];
    const token_tag = tree.tokens.items(.tag)[main_token];

    if (ast.fullPtrType(tree, deref_node)) |ptr_type| {
        switch (token_tag) {
            .asterisk => {
                return ((try analyser.resolveTypeOfNodeInternal(.{
                    .node = ptr_type.ast.child_type,
                    .handle = deref.handle,
                })) orelse return null).instanceTypeVal();
            },
            .l_bracket, .asterisk_asterisk => return null,
            else => unreachable,
        }
    }
    return null;
}

/// Resolves slicing and array access
fn resolveBracketAccessType(analyser: *Analyser, lhs: TypeWithHandle, rhs: enum { Single, Range }) !?TypeWithHandle {
    const lhs_node = switch (lhs.type.data) {
        .other => |n| n,
        .multi_pointer => |t| return switch (rhs) {
            .Single => t.*,
            .Range => TypeWithHandle{
                .type = .{ .data = .{ .slice = t }, .is_type_val = lhs.type.is_type_val },
                .handle = lhs.handle,
            },
        },
        .slice => |t| return switch (rhs) {
            .Single => t.*,
            .Range => lhs,
        },
        else => return null,
    };

    const tree = lhs.handle.tree;
    const tags = tree.nodes.items(.tag);
    const tag = tags[lhs_node];
    const data = tree.nodes.items(.data)[lhs_node];

    if (tag == .array_type or tag == .array_type_sentinel) {
        const child_type = (try analyser.resolveTypeOfNodeInternal(.{
            .node = data.rhs,
            .handle = lhs.handle,
        })) orelse return null;
        if (rhs == .Single)
            return child_type.instanceTypeVal();
        const child_type_ptr = try analyser.arena.allocator().create(TypeWithHandle);
        child_type_ptr.* = child_type.instanceTypeVal() orelse return null;
        return TypeWithHandle{
            .type = .{ .data = .{ .slice = child_type_ptr }, .is_type_val = false },
            .handle = lhs.handle,
        };
    } else if (ast.fullPtrType(tree, lhs_node)) |ptr_type| {
        if (ptr_type.size == .Slice) {
            if (rhs == .Single) {
                return ((try analyser.resolveTypeOfNodeInternal(.{
                    .node = ptr_type.ast.child_type,
                    .handle = lhs.handle,
                })) orelse return null).instanceTypeVal();
            }
            return lhs;
        }
    }

    return null;
}

/// Called to remove one level of pointerness before a field access
pub fn resolveFieldAccessLhsType(analyser: *Analyser, lhs: TypeWithHandle) !TypeWithHandle {
    // analyser.bound_type_params.clearRetainingCapacity();
    return (try analyser.resolveDerefType(lhs)) orelse lhs;
}

fn resolveTupleFieldType(analyser: *Analyser, type_handle: TypeWithHandle, index: usize) !?TypeWithHandle {
    const node = switch (type_handle.type.data) {
        .other => |n| n,
        else => return null,
    };
    const handle = type_handle.handle;
    const tree = handle.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    if (token_tags[main_tokens[node]] != .keyword_struct)
        return null;

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node) orelse
        return null;

    if (index >= container_decl.ast.members.len)
        return null;

    const field = tree.fullContainerField(container_decl.ast.members[index]) orelse
        return null;

    if (!field.ast.tuple_like)
        return null;

    if (try analyser.resolveTypeOfNode(.{ .node = field.ast.type_expr, .handle = handle })) |t|
        return t.instanceTypeVal();

    return null;
}

fn resolvePropertyType(analyser: *Analyser, type_handle: TypeWithHandle, name: []const u8) !?TypeWithHandle {
    if (type_handle.type.is_type_val)
        return null;

    const handle = type_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);

    switch (type_handle.type.data) {
        .slice => |t| {
            if (std.mem.eql(u8, "len", name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .primitive = "usize" }, .is_type_val = false },
                    .handle = handle,
                };
            }

            if (std.mem.eql(u8, "ptr", name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .multi_pointer = t }, .is_type_val = false },
                    .handle = handle,
                };
            }
        },

        .other => |n| switch (node_tags[n]) {
            .array_type,
            .array_type_sentinel,
            .multiline_string_literal,
            .string_literal,
            => if (std.mem.eql(u8, "len", name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .primitive = "usize" }, .is_type_val = false },
                    .handle = handle,
                };
            },

            .ptr_type,
            .ptr_type_aligned,
            .ptr_type_bit_range,
            .ptr_type_sentinel,
            => {
                const ptr_type = ast.fullPtrType(tree, n).?;

                if (ptr_type.size == .Slice) {
                    if (std.mem.eql(u8, "len", name)) {
                        return TypeWithHandle{
                            .type = .{ .data = .{ .primitive = "usize" }, .is_type_val = false },
                            .handle = handle,
                        };
                    }

                    if (std.mem.eql(u8, "ptr", name)) {
                        const child_type = (try analyser.resolveTypeOfNodeInternal(.{
                            .node = ptr_type.ast.child_type,
                            .handle = handle,
                        })) orelse return null;

                        const child_type_ptr = try analyser.arena.allocator().create(TypeWithHandle);
                        child_type_ptr.* = child_type.instanceTypeVal() orelse return null;
                        return TypeWithHandle{
                            .type = .{ .data = .{ .multi_pointer = child_type_ptr }, .is_type_val = false },
                            .handle = handle,
                        };
                    }
                }
            },

            .container_decl,
            .container_decl_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            => {
                if (!std.mem.startsWith(u8, name, "@\"")) return null;
                if (!std.mem.endsWith(u8, name, "\"")) return null;

                const text = name[2 .. name.len - 1];
                if (!allDigits(text)) return null;
                const index = std.fmt.parseUnsigned(u16, text, 10) catch return null;

                return analyser.resolveTupleFieldType(type_handle, index);
            },

            else => {},
        },

        else => {},
    }

    return null;
}

fn allDigits(str: []const u8) bool {
    for (str) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

const primitive_types = std.ComptimeStringMap([]const u8, .{
    .{ "true", "bool" },
    .{ "false", "bool" },
    .{ "null", "@TypeOf(null)" },
    .{ "undefined", "@TypeOf(undefined)" },
});

pub fn isValueIdent(text: []const u8) bool {
    return primitive_types.has(text);
}

pub fn isTypeIdent(text: []const u8) bool {
    const PrimitiveTypes = std.ComptimeStringMap(void, .{
        .{"isize"},        .{"usize"},
        .{"c_short"},      .{"c_ushort"},
        .{"c_int"},        .{"c_uint"},
        .{"c_long"},       .{"c_ulong"},
        .{"c_longlong"},   .{"c_ulonglong"},
        .{"c_longdouble"}, .{"anyopaque"},
        .{"f16"},          .{"f32"},
        .{"f64"},          .{"f80"},
        .{"f128"},         .{"bool"},
        .{"void"},         .{"noreturn"},
        .{"type"},         .{"anyerror"},
        .{"comptime_int"}, .{"comptime_float"},
        .{"anyframe"},     .{"anytype"},
        .{"c_char"},
    });

    if (PrimitiveTypes.has(text)) return true;
    if (text.len == 1) return false;
    if (!(text[0] == 'u' or text[0] == 'i')) return false;
    if (!allDigits(text[1..])) return false;
    _ = std.fmt.parseUnsigned(u16, text[1..], 10) catch return false;
    return true;
}

const FindBreaks = struct {
    const Error = error{OutOfMemory};

    label: ?[]const u8,
    allow_unlabeled: bool,
    allocator: std.mem.Allocator,
    break_operands: std.ArrayListUnmanaged(Ast.Node.Index) = .{},

    fn deinit(context: *FindBreaks) void {
        context.break_operands.deinit(context.allocator);
    }

    fn findBreakOperands(context: *FindBreaks, tree: Ast, node: Ast.Node.Index) Error!void {
        if (node == 0)
            return;

        const allow_unlabeled = context.allow_unlabeled;
        const node_tags = tree.nodes.items(.tag);
        const datas = tree.nodes.items(.data);

        switch (node_tags[node]) {
            .@"break" => {
                const label_token = datas[node].lhs;
                const operand = datas[node].rhs;
                if (allow_unlabeled and label_token == 0) {
                    try context.break_operands.append(context.allocator, operand);
                } else if (context.label) |label| {
                    if (label_token != 0 and std.mem.eql(u8, label, tree.tokenSlice(label_token)))
                        try context.break_operands.append(context.allocator, operand);
                }
            },

            .@"while",
            .while_simple,
            .while_cont,
            .@"for",
            .for_simple,
            => {
                context.allow_unlabeled = false;
                try ast.iterateChildren(tree, node, context, Error, findBreakOperands);
                context.allow_unlabeled = allow_unlabeled;
            },

            else => {
                try ast.iterateChildren(tree, node, context, Error, findBreakOperands);
            },
        }
    }
};

/// Resolves the type of a node
fn resolveTypeOfNodeInternal(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?TypeWithHandle {
    const node_with_uri = NodeWithUri{
        .node = node_handle.node,
        .uri = node_handle.handle.uri,
    };
    const gop = try analyser.resolved_nodes.getOrPut(analyser.gpa, node_with_uri);
    if (gop.found_existing) return gop.value_ptr.*;

    // we insert null before resolving the type so that a recursive definition doesn't result in an infinite loop
    gop.value_ptr.* = null;

    const type_handle = try analyser.resolveTypeOfNodeUncached(node_handle);
    if (type_handle != null) {
        analyser.resolved_nodes.getPtr(node_with_uri).?.* = type_handle;
    }

    return type_handle;
}

fn resolveTypeOfNodeUncached(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?TypeWithHandle {
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;

    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);
    const starts = tree.tokens.items(.start);

    switch (node_tags[node]) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?;
            if (var_decl.ast.type_node != 0) {
                const decl_type = .{ .node = var_decl.ast.type_node, .handle = handle };
                if (try analyser.resolveTypeOfNodeInternal(decl_type)) |typ|
                    return typ.instanceTypeVal();
            }
            if (var_decl.ast.init_node == 0)
                return null;

            const value = .{ .node = var_decl.ast.init_node, .handle = handle };
            return try analyser.resolveTypeOfNodeInternal(value);
        },
        .identifier => {
            const name = offsets.nodeToSlice(tree, node);

            if (isTypeIdent(name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .primitive = name }, .is_type_val = true },
                    .handle = handle,
                };
            }

            if (isValueIdent(name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .other = node }, .is_type_val = false },
                    .handle = handle,
                };
            }

            if (try analyser.lookupSymbolGlobal(
                handle,
                name,
                starts[main_tokens[node]],
            )) |child| {
                switch (child.decl.*) {
                    .ast_node => |n| {
                        if (n == node) return null;
                        if (child.handle.tree.fullVarDecl(n)) |var_decl| {
                            if (var_decl.ast.init_node == node)
                                return null;
                        }
                    },
                    else => {},
                }
                return try child.resolveType(analyser);
            }
            return null;
        },
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            var params: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&params, node) orelse unreachable;

            const callee = .{ .node = call.ast.fn_expr, .handle = handle };
            const decl = (try analyser.resolveTypeOfNodeInternal(callee)) orelse
                return null;

            if (decl.type.is_type_val) return null;
            const func_node = switch (decl.type.data) {
                .other => |n| n,
                else => return null,
            };
            var buf: [1]Ast.Node.Index = undefined;
            const fn_decl = decl.handle.tree.fullFnProto(&buf, func_node) orelse return null;

            var expected_params = fn_decl.ast.params.len;
            // If we call as method, the first parameter should be skipped
            // TODO: Back-parse to extract the self argument?
            var it = fn_decl.iterate(&decl.handle.tree);
            if (try analyser.isInstanceCall(handle, call, decl.handle, fn_decl)) {
                _ = ast.nextFnParam(&it);
                expected_params -= 1;
            }

            // Bind type params to the arguments passed in the call.
            const param_len = @min(call.ast.params.len, expected_params);
            var i: usize = 0;
            while (ast.nextFnParam(&it)) |decl_param| : (i += 1) {
                if (i >= param_len) break;
                if (!isMetaType(decl.handle.tree, decl_param.type_expr))
                    continue;

                const argument = .{ .node = call.ast.params[i], .handle = handle };
                const argument_type = (try analyser.resolveTypeOfNodeInternal(
                    argument,
                )) orelse
                    continue;
                if (!argument_type.type.is_type_val) continue;

                try analyser.bound_type_params.put(analyser.gpa, .{
                    .func = func_node,
                    .param_index = @intCast(i),
                }, argument_type);
            }

            const has_body = decl.handle.tree.nodes.items(.tag)[func_node] == .fn_decl;
            const body = decl.handle.tree.nodes.items(.data)[func_node].rhs;
            if (try analyser.resolveReturnType(fn_decl, decl.handle, if (has_body) body else null)) |ret| {
                return ret;
            } else if (analyser.store.config.dangerous_comptime_experiments_do_not_enable) {
                // TODO: Better case-by-case; we just use the ComptimeInterpreter when all else fails,
                // probably better to use it more liberally
                // TODO: Handle non-isolate args; e.g. `const T = u8; TypeFunc(T);`
                // var interpreter = ComptimeInterpreter{ .tree = tree, .allocator = arena.allocator() };

                // var top_decl = try (try interpreter.interpret(0, null, .{})).getValue();
                // var top_scope = interpreter.typeToTypeInfo(top_decl.@"type".info_idx).@"struct".scope;

                // var fn_decl_scope = top_scope.getParentScopeFromNode(node);

                log.info("Invoking interpreter!", .{});

                const interpreter = analyser.store.ensureInterpreterExists(handle.uri, analyser.ip.?) catch |err| {
                    log.err("Failed to interpret file: {s}", .{@errorName(err)});
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                    return null;
                };

                const root_namespace: ComptimeInterpreter.Namespace.Index = @enumFromInt(0);

                // TODO: Start from current/nearest-current scope
                const result = interpreter.interpret(node, root_namespace, .{}) catch |err| {
                    log.err("Failed to interpret node: {s}", .{@errorName(err)});
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                    return null;
                };
                const value = result.getValue() catch |err| {
                    log.err("interpreter return no result: {s}", .{@errorName(err)});
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                    return null;
                };
                const is_type_val = interpreter.ip.indexToKey(value.index).typeOf() == .type_type;

                return TypeWithHandle{
                    .type = .{
                        .data = .{ .@"comptime" = .{
                            .interpreter = interpreter,
                            .value = value,
                        } },
                        .is_type_val = is_type_val,
                    },
                    .handle = node_handle.handle,
                };
            }
        },
        .@"comptime",
        .@"nosuspend",
        .grouped_expression,
        .container_field,
        .container_field_init,
        .container_field_align,
        .array_init,
        .array_init_comma,
        .array_init_one,
        .array_init_one_comma,
        .struct_init,
        .struct_init_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .slice,
        .slice_sentinel,
        .slice_open,
        .deref,
        .unwrap_optional,
        .array_access,
        .@"orelse",
        .@"catch",
        .@"try",
        .address_of,
        => {
            if (node_tags[node].isContainerField()) {
                const container_type = innermostContainer(handle, offsets.tokenToIndex(tree, tree.firstToken(node)));
                if (container_type.isEnumType())
                    return container_type.instanceTypeVal();

                if (container_type.isTaggedUnion()) {
                    var field = tree.fullContainerField(node).?;
                    field.convertToNonTupleLike(tree.nodes);
                    if (field.ast.type_expr == 0)
                        return TypeWithHandle{
                            .type = .{ .data = .{ .primitive = "void" }, .is_type_val = false },
                            .handle = handle,
                        };
                }
            }
            const base = .{ .node = datas[node].lhs, .handle = handle };
            const base_type = (try analyser.resolveTypeOfNodeInternal(base)) orelse
                return null;
            return switch (node_tags[node]) {
                .@"comptime",
                .@"nosuspend",
                .grouped_expression,
                => base_type,
                .container_field,
                .container_field_init,
                .container_field_align,
                .array_init,
                .array_init_comma,
                .array_init_one,
                .array_init_one_comma,
                .struct_init,
                .struct_init_comma,
                .struct_init_one,
                .struct_init_one_comma,
                => base_type.instanceTypeVal(),
                .slice,
                .slice_sentinel,
                .slice_open,
                => try analyser.resolveBracketAccessType(base_type, .Range),
                .deref => try analyser.resolveDerefType(base_type),
                .unwrap_optional => try analyser.resolveUnwrapOptionalType(base_type),
                .array_access => try analyser.resolveBracketAccessType(base_type, .Single),
                .@"orelse" => try analyser.resolveUnwrapOptionalType(base_type),
                .@"catch" => try analyser.resolveUnwrapErrorUnionType(base_type, .right),
                .@"try" => try analyser.resolveUnwrapErrorUnionType(base_type, .right),
                .address_of => {
                    const base_type_ptr = try analyser.arena.allocator().create(TypeWithHandle);
                    base_type_ptr.* = base_type;
                    return TypeWithHandle{
                        .type = .{ .data = .{ .pointer = base_type_ptr }, .is_type_val = base_type.type.is_type_val },
                        .handle = base.handle,
                    };
                },
                else => unreachable,
            };
        },
        .field_access => {
            if (datas[node].rhs == 0) return null;

            const lhs = (try analyser.resolveTypeOfNodeInternal(.{
                .node = datas[node].lhs,
                .handle = handle,
            })) orelse return null;

            const symbol = tree.tokenSlice(datas[node].rhs);

            if (try analyser.resolveTaggedUnionFieldType(lhs, symbol)) |tag_type|
                return tag_type;

            // If we are accessing a pointer type, remove one pointerness level :)
            const left_type = (try analyser.resolveDerefType(lhs)) orelse lhs;

            if (try analyser.resolvePropertyType(left_type, symbol)) |t|
                return t;

            if (try left_type.lookupSymbol(analyser, symbol)) |child| {
                return try child.resolveType(analyser);
            } else return null;
        },
        .anyframe_literal,
        .anyframe_type,
        .array_type,
        .array_type_sentinel,
        .optional_type,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .error_union,
        .error_set_decl,
        .merge_error_sets,
        .container_decl,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => return TypeWithHandle.typeVal(node_handle),
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node, &buffer).?;

            const call_name = tree.tokenSlice(main_tokens[node]);
            if (std.mem.eql(u8, call_name, "@This")) {
                if (params.len != 0) return null;
                return innermostContainer(handle, starts[tree.firstToken(node)]);
            }

            const cast_map = std.ComptimeStringMap(void, .{
                .{"@as"},
                .{"@atomicLoad"},
                .{"@atomicRmw"},
                .{"@atomicStore"},
                .{"@mulAdd"},
                .{"@fieldParentPtr"}, // the return type is actually a pointer
                .{"@unionInit"},
            });
            if (cast_map.has(call_name)) {
                if (params.len < 1) return null;
                return ((try analyser.resolveTypeOfNodeInternal(.{
                    .node = params[0],
                    .handle = handle,
                })) orelse return null).instanceTypeVal();
            }

            // Almost the same as the above, return a type value though.
            // TODO Do peer type resolution, we just keep the first for now.
            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len < 1) return null;
                var resolved_type = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = params[0],
                    .handle = handle,
                })) orelse return null;

                if (resolved_type.type.is_type_val) return null;
                resolved_type.type.is_type_val = true;
                return resolved_type;
            }

            if (std.mem.eql(u8, call_name, "@typeInfo")) {
                const zig_lib_path = try URI.fromPath(analyser.arena.allocator(), analyser.store.config.zig_lib_path orelse return null);

                const builtin_uri = URI.pathRelative(analyser.arena.allocator(), zig_lib_path, "/std/builtin.zig") catch |err| switch (err) {
                    error.OutOfMemory => |e| return e,
                    else => return null,
                };

                const new_handle = analyser.store.getOrLoadHandle(builtin_uri) orelse return null;
                const root_scope_decls = new_handle.document_scope.scopes.items(.decls)[0];
                const decl_key = Declaration.Key{ .kind = .variable, .name = "Type" };
                const decl_index = root_scope_decls.get(decl_key) orelse return null;
                const decl = new_handle.document_scope.decls.items[@intFromEnum(decl_index)];
                if (decl != .ast_node) return null;

                const var_decl = new_handle.tree.fullVarDecl(decl.ast_node) orelse return null;

                return TypeWithHandle{
                    .type = .{
                        .data = .{ .other = var_decl.ast.init_node },
                        .is_type_val = false,
                    },
                    .handle = new_handle,
                };
            }

            if (std.mem.eql(u8, call_name, "@import")) {
                if (params.len == 0) return null;
                const import_param = params[0];
                if (node_tags[import_param] != .string_literal) return null;

                const import_str = tree.tokenSlice(main_tokens[import_param]);
                const import_uri = (try analyser.store.uriFromImportStr(analyser.arena.allocator(), handle.*, import_str[1 .. import_str.len - 1])) orelse return null;

                const new_handle = analyser.store.getOrLoadHandle(import_uri) orelse return null;

                // reference to node '0' which is root
                return TypeWithHandle.typeVal(.{ .node = 0, .handle = new_handle });
            } else if (std.mem.eql(u8, call_name, "@cImport")) {
                const cimport_uri = (try analyser.store.resolveCImport(handle.*, node)) orelse return null;

                const new_handle = analyser.store.getOrLoadHandle(cimport_uri) orelse return null;

                // reference to node '0' which is root
                return TypeWithHandle.typeVal(.{ .node = 0, .handle = new_handle });
            }
        },
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            // This is a function type
            if (tree.fullFnProto(&buf, node).?.name_token == null) {
                return TypeWithHandle.typeVal(node_handle);
            }

            return TypeWithHandle{
                .type = .{ .data = .{ .other = node }, .is_type_val = false },
                .handle = handle,
            };
        },
        .multiline_string_literal,
        .string_literal,
        .char_literal,
        .number_literal,
        .enum_literal,
        .error_value,
        => return TypeWithHandle{
            .type = .{ .data = .{ .other = node }, .is_type_val = false },
            .handle = handle,
        },
        .@"if", .if_simple => {
            const if_node = ast.fullIf(tree, node).?;

            // HACK: resolve std.ArrayList(T).Slice
            if (std.mem.endsWith(u8, node_handle.handle.uri, "array_list.zig") and
                if_node.payload_token != null and
                std.mem.eql(u8, offsets.tokenToSlice(node_handle.handle.tree, if_node.payload_token.?), "a") and
                node_tags[if_node.ast.cond_expr] == .identifier and
                std.mem.eql(u8, offsets.tokenToSlice(node_handle.handle.tree, main_tokens[if_node.ast.cond_expr]), "alignment"))
            blk: {
                return (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.then_expr })) orelse break :blk;
            }

            var either = std.ArrayListUnmanaged(Type.EitherEntry){};
            if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.then_expr })) |t|
                try either.append(analyser.arena.allocator(), .{ .type_with_handle = t, .descriptor = offsets.nodeToSlice(tree, if_node.ast.cond_expr) });
            if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.else_expr })) |t|
                try either.append(analyser.arena.allocator(), .{ .type_with_handle = t, .descriptor = try std.fmt.allocPrint(analyser.arena.allocator(), "!({s})", .{offsets.nodeToSlice(tree, if_node.ast.cond_expr)}) });

            return TypeWithHandle.fromEither(analyser.gpa, try either.toOwnedSlice(analyser.arena.allocator()), handle);
        },
        .@"switch",
        .switch_comma,
        => {
            const extra = tree.extraData(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            var either = std.ArrayListUnmanaged(Type.EitherEntry){};

            for (cases) |case| {
                const switch_case = tree.fullSwitchCase(case).?;
                var descriptor = std.ArrayListUnmanaged(u8){};

                for (switch_case.ast.values, 0..) |values, index| {
                    try descriptor.appendSlice(analyser.arena.allocator(), offsets.nodeToSlice(tree, values));
                    if (index != switch_case.ast.values.len - 1) try descriptor.appendSlice(analyser.arena.allocator(), ", ");
                }

                if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = switch_case.ast.target_expr })) |t|
                    try either.append(analyser.arena.allocator(), .{
                        .type_with_handle = t,
                        .descriptor = try descriptor.toOwnedSlice(analyser.arena.allocator()),
                    });
            }

            return TypeWithHandle.fromEither(analyser.gpa, try either.toOwnedSlice(analyser.arena.allocator()), handle);
        },
        .@"while",
        .while_simple,
        .while_cont,
        .@"for",
        .for_simple,
        => {
            const loop: struct {
                label_token: ?Ast.TokenIndex,
                then_expr: Ast.Node.Index,
                else_expr: Ast.Node.Index,
            } = if (ast.fullWhile(tree, node)) |while_node|
                .{
                    .label_token = while_node.label_token,
                    .then_expr = while_node.ast.then_expr,
                    .else_expr = while_node.ast.else_expr,
                }
            else if (ast.fullFor(tree, node)) |for_node|
                .{
                    .label_token = for_node.label_token,
                    .then_expr = for_node.ast.then_expr,
                    .else_expr = for_node.ast.else_expr,
                }
            else
                unreachable;

            if (loop.else_expr == 0)
                return null;

            // TODO: peer type resolution based on `else` and all `break` statements
            if (try analyser.resolveTypeOfNodeInternal(.{ .node = loop.else_expr, .handle = handle })) |else_type|
                return else_type;

            var context = FindBreaks{
                .label = if (loop.label_token) |token| tree.tokenSlice(token) else null,
                .allow_unlabeled = true,
                .allocator = analyser.gpa,
            };
            defer context.deinit();
            try context.findBreakOperands(tree, loop.then_expr);
            for (context.break_operands.items) |operand| {
                if (try analyser.resolveTypeOfNodeInternal(.{ .node = operand, .handle = handle })) |operand_type|
                    return operand_type;
            }
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            const first_token = tree.firstToken(node);
            if (token_tags[first_token] != .identifier) return null;

            const block_label = tree.tokenSlice(first_token);

            // TODO: peer type resolution based on all `break` statements
            var context = FindBreaks{
                .label = block_label,
                .allow_unlabeled = false,
                .allocator = analyser.gpa,
            };
            defer context.deinit();
            try context.findBreakOperands(tree, node);
            for (context.break_operands.items) |operand| {
                if (try analyser.resolveTypeOfNodeInternal(.{ .node = operand, .handle = handle })) |operand_type|
                    return operand_type;
            }
        },
        else => {},
    }
    return null;
}

// TODO Reorganize this file, perhaps split into a couple as well
// TODO Make this better, nested levels of type vals
pub const Type = struct {
    pub const EitherEntry = struct {
        type_with_handle: TypeWithHandle,
        descriptor: []const u8,
    };

    data: union(enum) {
        /// Type of `foo` in `&foo`
        pointer: *TypeWithHandle,

        /// Element type of `slice` in `slice.ptr`
        multi_pointer: *TypeWithHandle,

        /// Element type of `array` in `array[x..y]`
        slice: *TypeWithHandle,

        /// Return type of `fn foo() !Foo`
        error_union: *TypeWithHandle,

        /// `Foo` in `Foo.bar` where `Foo = union(enum) { bar }`
        union_tag: *TypeWithHandle,

        /// - Container type: `struct {}`, `enum {}`, `union {}`, `opaque {}`, `error {}`
        /// - Pointer type: `*Foo`, `[]Foo`, `?Foo`
        /// - Error type: `Foo || Bar`, `Foo!Bar`
        /// - Function: `fn () Foo`, `fn foo() Foo`
        /// - Literal: `"foo"`, `'x'`, `42`, `.foo`, `error.Foo`
        /// - Primitive value: `true`, `false`, `null`, `undefined`
        other: Ast.Node.Index,

        /// Primitive type: `u8`, `bool`, `type`, etc.
        primitive: []const u8,

        /// Branching types
        either: []const EitherEntry,

        // TODO: Unused?
        array_index,

        @"comptime": struct {
            interpreter: *ComptimeInterpreter,
            value: ComptimeInterpreter.Value,
        },
    },
    /// If true, the type `type`, the attached data is the value of the type value.
    is_type_val: bool,
};

pub const TypeWithHandle = struct {
    type: Type,
    handle: *const DocumentStore.Handle,

    const Context = struct {
        // Note that we don't hash/equate descriptors to remove
        // duplicates

        fn hashType(hasher: *std.hash.Wyhash, ty: Type) void {
            hasher.update(&.{ @intFromBool(ty.is_type_val), @intFromEnum(ty.data) });

            switch (ty.data) {
                inline .pointer,
                .multi_pointer,
                .slice,
                .error_union,
                .union_tag,
                => |t| hashTypeWithHandle(hasher, t.*),
                .other => |idx| hasher.update(&std.mem.toBytes(idx)),
                .primitive => |name| hasher.update(name),
                .either => |entries| {
                    for (entries) |e| {
                        hasher.update(e.descriptor);
                        hashTypeWithHandle(hasher, e.type_with_handle);
                    }
                },
                .array_index => {},
                .@"comptime" => {
                    // TODO
                },
            }
        }

        fn hashTypeWithHandle(hasher: *std.hash.Wyhash, item: TypeWithHandle) void {
            hashType(hasher, item.type);
            hasher.update(item.handle.uri);
        }

        pub fn hash(self: @This(), item: TypeWithHandle) u64 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            hashTypeWithHandle(&hasher, item);
            return hasher.final();
        }

        pub fn eql(self: @This(), a: TypeWithHandle, b: TypeWithHandle) bool {
            if (!std.mem.eql(u8, a.handle.uri, b.handle.uri)) return false;
            if (a.type.is_type_val != b.type.is_type_val) return false;
            if (@intFromEnum(a.type.data) != @intFromEnum(b.type.data)) return false;

            switch (a.type.data) {
                inline .pointer,
                .multi_pointer,
                .slice,
                .error_union,
                .union_tag,
                => |a_type, name| {
                    const b_type = @field(b.type.data, @tagName(name));
                    if (!self.eql(a_type.*, b_type.*)) return false;
                },
                .other => |a_idx| {
                    const b_idx = b.type.data.other;
                    if (a_idx != b_idx) return false;
                },
                .primitive => |a_name| {
                    const b_name = b.type.data.primitive;
                    if (!std.mem.eql(u8, a_name, b_name)) return false;
                },
                .either => |a_entries| {
                    const b_entries = b.type.data.either;

                    if (a_entries.len != b_entries.len) return false;
                    for (a_entries, b_entries) |ae, be| {
                        if (!std.mem.eql(u8, ae.descriptor, be.descriptor)) return false;
                        if (!self.eql(ae.type_with_handle, be.type_with_handle)) return false;
                    }
                },
                .array_index => {},
                .@"comptime" => {
                    // TODO
                },
            }

            return true;
        }
    };

    pub fn typeVal(node_handle: NodeWithHandle) TypeWithHandle {
        return .{
            .type = .{
                .data = .{ .other = node_handle.node },
                .is_type_val = true,
            },
            .handle = node_handle.handle,
        };
    }

    pub const Deduplicator = std.HashMapUnmanaged(TypeWithHandle, void, TypeWithHandle.Context, std.hash_map.default_max_load_percentage);

    pub fn fromEither(allocator: std.mem.Allocator, entries: []const Type.EitherEntry, handle: *const DocumentStore.Handle) error{OutOfMemory}!?TypeWithHandle {
        if (entries.len == 0)
            return null;

        if (entries.len == 1)
            return entries[0].type_with_handle;

        var deduplicator = Deduplicator{};
        defer deduplicator.deinit(allocator);

        for (entries) |e|
            _ = try deduplicator.getOrPut(allocator, e.type_with_handle);

        if (deduplicator.size == 1)
            return entries[0].type_with_handle;

        return .{
            .type = .{
                .data = .{ .either = entries },
                .is_type_val = false,
            },
            .handle = handle,
        };
    }

    /// Resolves possible types of a type (single for all except array_index and either)
    /// Drops duplicates
    pub fn getAllTypesWithHandles(ty: TypeWithHandle, arena: std.mem.Allocator) ![]const TypeWithHandle {
        var all_types = std.ArrayListUnmanaged(TypeWithHandle){};
        try ty.getAllTypesWithHandlesArrayList(arena, &all_types);
        return try all_types.toOwnedSlice(arena);
    }

    pub fn getAllTypesWithHandlesArrayList(ty: TypeWithHandle, arena: std.mem.Allocator, all_types: *std.ArrayListUnmanaged(TypeWithHandle)) !void {
        switch (ty.type.data) {
            .either => |e| for (e) |i| try i.type_with_handle.getAllTypesWithHandlesArrayList(arena, all_types),
            else => try all_types.append(arena, ty),
        }
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

    fn isContainerKind(self: TypeWithHandle, container_kind_tok: std.zig.Token.Tag) bool {
        const tree = self.handle.tree;
        const main_tokens = tree.nodes.items(.main_token);
        const tags = tree.tokens.items(.tag);
        switch (self.type.data) {
            .other => |n| return tags[main_tokens[n]] == container_kind_tok,
            else => return false,
        }
    }

    pub fn isStructType(self: TypeWithHandle) bool {
        return self.isContainerKind(.keyword_struct) or self.isRoot();
    }

    pub fn isNamespace(self: TypeWithHandle) bool {
        if (!self.isStructType()) return false;
        const tree = self.handle.tree;
        const node = self.type.data.other;
        const tags = tree.nodes.items(.tag);
        var buf: [2]Ast.Node.Index = undefined;
        const full = tree.fullContainerDecl(&buf, node) orelse return true;
        for (full.ast.members) |member| {
            if (tags[member].isContainerField()) return false;
        }
        return true;
    }

    pub fn isEnumType(self: TypeWithHandle) bool {
        return self.isContainerKind(.keyword_enum);
    }

    pub fn isUnionType(self: TypeWithHandle) bool {
        return self.isContainerKind(.keyword_union);
    }

    pub fn isOpaqueType(self: TypeWithHandle) bool {
        return self.isContainerKind(.keyword_opaque);
    }

    pub fn isTaggedUnion(self: TypeWithHandle) bool {
        const tree = self.handle.tree;
        return switch (self.type.data) {
            .other => |n| ast.isTaggedUnion(tree, n),
            else => false,
        };
    }

    pub fn isTypeFunc(self: TypeWithHandle) bool {
        var buf: [1]Ast.Node.Index = undefined;
        const tree = self.handle.tree;
        return switch (self.type.data) {
            .other => |n| if (tree.fullFnProto(&buf, n)) |fn_proto| blk: {
                break :blk isTypeFunction(tree, fn_proto);
            } else false,
            else => false,
        };
    }

    pub fn isGenericFunc(self: TypeWithHandle) bool {
        var buf: [1]Ast.Node.Index = undefined;
        const tree = self.handle.tree;
        return switch (self.type.data) {
            .other => |n| if (tree.fullFnProto(&buf, n)) |fn_proto| blk: {
                break :blk isGenericFunction(tree, fn_proto);
            } else false,
            else => false,
        };
    }

    pub fn isFunc(self: TypeWithHandle) bool {
        const tree = self.handle.tree;
        const tags = tree.nodes.items(.tag);
        return switch (self.type.data) {
            .other => |n| switch (tags[n]) {
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => true,
                else => false,
            },
            else => false,
        };
    }

    pub fn typeDefinitionToken(self: TypeWithHandle) ?TokenWithHandle {
        return switch (self.type.data) {
            .other => |n| .{
                .token = self.handle.tree.firstToken(n),
                .handle = self.handle,
            },
            else => null,
        };
    }

    pub fn docComments(self: TypeWithHandle, allocator: std.mem.Allocator) !?[]const u8 {
        if (self.type.is_type_val) {
            switch (self.type.data) {
                .other => |n| return getDocComments(allocator, self.handle.tree, n),
                else => {},
            }
        }
        return null;
    }

    pub fn lookupSymbol(
        self: TypeWithHandle,
        analyser: *Analyser,
        symbol: []const u8,
    ) error{OutOfMemory}!?DeclWithHandle {
        const node = switch (self.type.data) {
            .other => |n| n,
            else => return null,
        };
        const node_handle = NodeWithHandle{ .node = node, .handle = self.handle };
        if (self.type.is_type_val) {
            if (try analyser.lookupSymbolContainer(node_handle, symbol, .variable)) |decl|
                return decl;
            if (self.isEnumType() or self.isTaggedUnion())
                return analyser.lookupSymbolContainer(node_handle, symbol, .field);
            return null;
        }
        if (self.isEnumType())
            return analyser.lookupSymbolContainer(node_handle, symbol, .variable);
        if (try analyser.lookupSymbolContainer(node_handle, symbol, .field)) |decl|
            return decl;
        return analyser.lookupSymbolContainer(node_handle, symbol, .variable);
    }
};

pub fn resolveTypeOfNode(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?TypeWithHandle {
    analyser.bound_type_params.clearRetainingCapacity();
    return analyser.resolveTypeOfNodeInternal(node_handle);
}

/// Collects all `@import`'s we can find into a slice of import paths (without quotes).
pub fn collectImports(allocator: std.mem.Allocator, tree: Ast) error{OutOfMemory}!std.ArrayListUnmanaged([]const u8) {
    var imports = std.ArrayListUnmanaged([]const u8){};
    errdefer imports.deinit(allocator);

    const tags = tree.tokens.items(.tag);

    var i: usize = 0;
    while (i < tags.len) : (i += 1) {
        if (tags[i] != .builtin)
            continue;
        const text = tree.tokenSlice(@intCast(i));

        if (std.mem.eql(u8, text, "@import")) {
            if (i + 3 >= tags.len)
                break;
            if (tags[i + 1] != .l_paren)
                continue;
            if (tags[i + 2] != .string_literal)
                continue;
            if (tags[i + 3] != .r_paren)
                continue;

            const str = tree.tokenSlice(@as(u32, @intCast(i + 2)));
            try imports.append(allocator, str[1 .. str.len - 1]);
        }
    }

    return imports;
}

/// Collects all `@cImport` nodes
/// Caller owns returned memory.
pub fn collectCImportNodes(allocator: std.mem.Allocator, tree: Ast) error{OutOfMemory}![]Ast.Node.Index {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var import_nodes = std.ArrayListUnmanaged(Ast.Node.Index){};
    errdefer import_nodes.deinit(allocator);

    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    var i: usize = 0;
    while (i < node_tags.len) : (i += 1) {
        const node: Ast.Node.Index = @intCast(i);
        if (!ast.isBuiltinCall(tree, node)) continue;

        if (!std.mem.eql(u8, Ast.tokenSlice(tree, main_tokens[node]), "@cImport")) continue;

        try import_nodes.append(allocator, node);
    }

    return import_nodes.toOwnedSlice(allocator);
}

pub const NodeWithUri = struct {
    node: Ast.Node.Index,
    uri: []const u8,

    const Context = struct {
        pub fn hash(self: @This(), item: NodeWithUri) u64 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, item.node);
            hasher.update(item.uri);
            return hasher.final();
        }

        pub fn eql(self: @This(), a: NodeWithUri, b: NodeWithUri) bool {
            _ = self;
            if (a.node != b.node) return false;
            return std.mem.eql(u8, a.uri, b.uri);
        }
    };
};

pub const NodeWithHandle = struct {
    node: Ast.Node.Index,
    handle: *const DocumentStore.Handle,

    pub fn eql(a: NodeWithHandle, b: NodeWithHandle) bool {
        if (a.node != b.node) return false;
        return std.mem.eql(u8, a.handle.uri, b.handle.uri);
    }
};

pub const FieldAccessReturn = struct {
    original: TypeWithHandle,
    unwrapped: ?TypeWithHandle = null,
};

pub fn getFieldAccessType(analyser: *Analyser, handle: *const DocumentStore.Handle, source_index: usize, tokenizer: *std.zig.Tokenizer) !?FieldAccessReturn {
    analyser.bound_type_params.clearRetainingCapacity();

    var current_type: ?TypeWithHandle = null;

    while (true) {
        const tok = tokenizer.next();
        switch (tok.tag) {
            .eof => return FieldAccessReturn{
                .original = current_type orelse return null,
                .unwrapped = try analyser.resolveDerefType(current_type orelse return null),
            },
            .identifier => {
                const ct_handle = if (current_type) |c| c.handle else handle;
                if (try analyser.lookupSymbolGlobal(
                    ct_handle,
                    tokenizer.buffer[tok.loc.start..tok.loc.end],
                    source_index,
                )) |child| {
                    current_type = (try child.resolveType(analyser)) orelse return null;
                } else return null;
            },
            .period => {
                const after_period = tokenizer.next();
                switch (after_period.tag) {
                    .eof => {
                        // function labels cannot be dot accessed
                        if (current_type) |ct| {
                            if (ct.isFunc()) return null;
                            return FieldAccessReturn{
                                .original = ct,
                                .unwrapped = try analyser.resolveDerefType(ct),
                            };
                        } else {
                            return null;
                        }
                    },
                    .identifier => {
                        if (after_period.loc.end == tokenizer.buffer.len) {
                            if (current_type) |ct| {
                                return FieldAccessReturn{
                                    .original = ct,
                                    .unwrapped = try analyser.resolveDerefType(ct),
                                };
                            } else {
                                return null;
                            }
                        }

                        const deref_type = if (current_type) |ty|
                            if (try analyser.resolveDerefType(ty)) |deref_ty| deref_ty else ty
                        else
                            return null;

                        const symbol = tokenizer.buffer[after_period.loc.start..after_period.loc.end];
                        const current_type_nodes = try deref_type.getAllTypesWithHandles(analyser.arena.allocator());

                        // TODO: Return all options instead of first valid one
                        // (this would require a huge rewrite and im lazy)
                        for (current_type_nodes) |ty| {
                            if (try ty.lookupSymbol(analyser, symbol)) |child| {
                                current_type.? = (try child.resolveType(analyser)) orelse continue;
                                break;
                            } else continue;
                        } else {
                            return null;
                        }
                    },
                    .question_mark => {
                        current_type = (try analyser.resolveUnwrapOptionalType(current_type orelse return null)) orelse return null;
                    },
                    else => {
                        log.debug("Unrecognized token {} after period.", .{after_period.tag});
                        return null;
                    },
                }
            },
            .period_asterisk => {
                current_type = (try analyser.resolveDerefType(current_type orelse return null)) orelse return null;
            },
            .l_paren => {
                if (current_type == null) {
                    return null;
                }
                const current_type_node = switch (current_type.?.type.data) {
                    .other => |n| n,
                    else => return null,
                };

                // Can't call a function type, we need a function type instance.
                if (current_type.?.type.is_type_val) return null;
                const cur_tree = current_type.?.handle.tree;
                var buf: [1]Ast.Node.Index = undefined;
                if (cur_tree.fullFnProto(&buf, current_type_node)) |func| {
                    // Check if the function has a body and if so, pass it
                    // so the type can be resolved if it's a generic function returning
                    // an anonymous struct
                    const has_body = cur_tree.nodes.items(.tag)[current_type_node] == .fn_decl;
                    const body = cur_tree.nodes.items(.data)[current_type_node].rhs;

                    // TODO Actually bind params here when calling functions instead of just skipping args.
                    if (try analyser.resolveReturnType(func, current_type.?.handle, if (has_body) body else null)) |ret| {
                        current_type = ret;
                        // Skip to the right paren
                        var paren_count: usize = 1;
                        var next = tokenizer.next();
                        while (next.tag != .eof) : (next = tokenizer.next()) {
                            if (next.tag == .r_paren) {
                                paren_count -= 1;
                                if (paren_count == 0) break;
                            } else if (next.tag == .l_paren) {
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
                while (next.tag != .eof) : (next = tokenizer.next()) {
                    if (next.tag == .r_bracket) {
                        brack_count -= 1;
                        if (brack_count == 0) break;
                    } else if (next.tag == .l_bracket) {
                        brack_count += 1;
                    } else if (next.tag == .ellipsis2 and brack_count == 1) {
                        is_range = true;
                    }
                } else return null;

                current_type = (try analyser.resolveBracketAccessType(current_type orelse return null, if (is_range) .Range else .Single)) orelse return null;
            },
            .builtin => {
                const curr_handle = if (current_type == null) handle else current_type.?.handle;
                if (std.mem.eql(u8, tokenizer.buffer[tok.loc.start..tok.loc.end], "@import")) {
                    if (tokenizer.next().tag != .l_paren) return null;
                    var import_str_tok = tokenizer.next(); // should be the .string_literal
                    if (import_str_tok.tag != .string_literal) return null;
                    if (import_str_tok.loc.end - import_str_tok.loc.start < 2) return null;
                    var import_str = offsets.locToSlice(tokenizer.buffer, .{
                        .start = import_str_tok.loc.start + 1,
                        .end = import_str_tok.loc.end - 1,
                    });
                    const uri = try analyser.store.uriFromImportStr(analyser.arena.allocator(), curr_handle.*, import_str) orelse return null;
                    const node_handle = analyser.store.getOrLoadHandle(uri) orelse return null;
                    current_type = TypeWithHandle.typeVal(NodeWithHandle{ .handle = node_handle, .node = 0 });
                    _ = tokenizer.next(); // eat the .r_paren
                } else {
                    log.debug("Unhandled builtin: {s}", .{offsets.locToSlice(tokenizer.buffer, tok.loc)});
                    return null;
                }
            },
            else => {
                log.debug("Unimplemented token: {}", .{tok.tag});
                return null;
            },
        }
    }

    if (current_type) |ct| {
        return FieldAccessReturn{
            .original = ct,
            .unwrapped = try analyser.resolveDerefType(ct),
        };
    } else {
        return null;
    }
}

pub fn isNodePublic(tree: Ast, node: Ast.Node.Index) bool {
    var buf: [1]Ast.Node.Index = undefined;
    return switch (tree.nodes.items(.tag)[node]) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => tree.fullVarDecl(node).?.visib_token != null,
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => tree.fullFnProto(&buf, node).?.visib_token != null,
        else => true,
    };
}

pub fn nodeToString(tree: Ast, node: Ast.Node.Index) ?[]const u8 {
    const data = tree.nodes.items(.data);
    const main_token = tree.nodes.items(.main_token)[node];
    var buf: [1]Ast.Node.Index = undefined;
    return switch (tree.nodes.items(.tag)[node]) {
        .container_field,
        .container_field_init,
        .container_field_align,
        => {
            const field = tree.fullContainerField(node).?.ast;
            return if (field.tuple_like) null else tree.tokenSlice(field.main_token);
        },
        .error_value => tree.tokenSlice(data[node].rhs),
        .identifier => tree.tokenSlice(main_token),
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => if (tree.fullFnProto(&buf, node).?.name_token) |name| tree.tokenSlice(name) else null,
        .field_access => tree.tokenSlice(data[node].rhs),
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => tree.tokenSlice(tree.callFull(node).ast.lparen - 1),
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => tree.tokenSlice(tree.callOne(&buf, node).ast.lparen - 1),
        .test_decl => if (data[node].lhs != 0) tree.tokenSlice(data[node].lhs) else null,
        else => |tag| {
            log.debug("INVALID: {}", .{tag});
            return null;
        },
    };
}

pub const PositionContext = union(enum) {
    builtin: offsets.Loc,
    comment,
    import_string_literal: offsets.Loc,
    cinclude_string_literal: offsets.Loc,
    embedfile_string_literal: offsets.Loc,
    string_literal: offsets.Loc,
    field_access: offsets.Loc,
    var_access: offsets.Loc,
    global_error_set,
    enum_literal: offsets.Loc,
    pre_label,
    label: bool,
    other,
    empty,

    pub fn loc(self: PositionContext) ?offsets.Loc {
        return switch (self) {
            .builtin => |r| r,
            .comment => null,
            .import_string_literal => |r| r,
            .cinclude_string_literal => |r| r,
            .embedfile_string_literal => |r| r,
            .string_literal => |r| r,
            .field_access => |r| r,
            .var_access => |r| r,
            .enum_literal => |r| r,
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

fn peek(allocator: std.mem.Allocator, arr: *std.ArrayListUnmanaged(StackState)) !*StackState {
    if (arr.items.len == 0) {
        try arr.append(allocator, .{ .ctx = .empty, .stack_id = .Global });
    }
    return &arr.items[arr.items.len - 1];
}

fn tokenLocAppend(prev: offsets.Loc, token: std.zig.Token) offsets.Loc {
    return .{
        .start = prev.start,
        .end = token.loc.end,
    };
}

pub fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_';
}

/// Given a byte index in a document (typically cursor offset), classify what kind of entity is at that index.
///
/// Classification is based on the lexical structure -- we fetch the line containing index, tokenize it,
/// and look at the sequence of tokens just before the cursor. Due to the nice way zig is designed (only line
/// comments, etc) lexing just a single line is always correct.
pub fn getPositionContext(
    allocator: std.mem.Allocator,
    text: []const u8,
    doc_index: usize,
    /// Should we look to the end of the current context? Yes for goto def, no for completions
    lookahead: bool,
) !PositionContext {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var new_index = doc_index;
    if (lookahead and new_index < text.len and isSymbolChar(text[new_index])) {
        new_index += 1;
    } else if (lookahead and new_index + 1 < text.len and text[new_index] == '@') {
        new_index += 2;
    }
    const prev_char = if (new_index > 0) text[new_index - 1] else 0;

    var line_loc = if (!lookahead) offsets.lineLocAtIndex(text, new_index) else offsets.lineLocUntilIndex(text, new_index);

    var line = offsets.locToSlice(text, line_loc);
    if (std.mem.startsWith(u8, std.mem.trimLeft(u8, line, " \t"), "//")) return .comment;

    // Check if the (trimmed) line starts with a '.', ie a continuation
    while (std.mem.startsWith(u8, std.mem.trimLeft(u8, text[line_loc.start..line_loc.end], " \t\r"), ".")) {
        if (line_loc.start > 1) {
            line_loc.start -= 2; // jump over a (potential) preceding '\n'
        } else break;
        while (line_loc.start > 0) : (line_loc.start -= 1) {
            if (text[line_loc.start] == '\n') {
                line_loc.start += 1; // eat the `\n`
                break;
            }
        } else break;
    }

    // Did we end up at a comment?
    line = offsets.locToSlice(text, line_loc);
    if (std.mem.startsWith(u8, std.mem.trimLeft(u8, line, " \t"), "//")) return .other;

    var stack = try std.ArrayListUnmanaged(StackState).initCapacity(allocator, 8);
    defer stack.deinit(allocator);

    {
        var held_line = try allocator.dupeZ(u8, text[0..line_loc.end]);
        defer allocator.free(held_line);

        var tokenizer: std.zig.Tokenizer = .{
            .buffer = held_line,
            .index = line_loc.start,
            .pending_invalid_token = null,
        };

        while (true) {
            var tok = tokenizer.next();
            // Early exits.
            if (tok.loc.start > new_index) break;
            if (tok.loc.start == new_index) {
                // Tie-breaking, the cursor is exactly between two tokens, and
                // `tok` is the latter of the two.
                if (tok.tag != .identifier) break;
            }
            switch (tok.tag) {
                .invalid => {
                    // Single '@' do not return a builtin token so we check this on our own.
                    if (prev_char == '@') {
                        return PositionContext{
                            .builtin = .{
                                .start = line_loc.end - 1,
                                .end = line_loc.end,
                            },
                        };
                    }
                    const s = held_line[tok.loc.start..tok.loc.end];
                    const q = std.mem.indexOf(u8, s, "\"") orelse return .other;
                    if (s[q -| 1] == '@') {
                        tok.tag = .identifier;
                    } else {
                        tok.tag = .string_literal;
                    }
                },
                .doc_comment, .container_doc_comment => return .comment,
                .eof => break,
                else => {},
            }

            // State changes
            var curr_ctx = try peek(allocator, &stack);
            switch (tok.tag) {
                .string_literal, .multiline_string_literal_line => string_lit_block: {
                    if (curr_ctx.stack_id == .Paren and stack.items.len >= 2) {
                        const perhaps_builtin = stack.items[stack.items.len - 2];

                        switch (perhaps_builtin.ctx) {
                            .builtin => |loc| {
                                const builtin_name = tokenizer.buffer[loc.start..loc.end];
                                if (std.mem.eql(u8, builtin_name, "@import")) {
                                    curr_ctx.ctx = .{ .import_string_literal = tok.loc };
                                    break :string_lit_block;
                                } else if (std.mem.eql(u8, builtin_name, "@cInclude")) {
                                    curr_ctx.ctx = .{ .cinclude_string_literal = tok.loc };
                                    break :string_lit_block;
                                } else if (std.mem.eql(u8, builtin_name, "@embedFile")) {
                                    curr_ctx.ctx = .{ .embedfile_string_literal = tok.loc };
                                    break :string_lit_block;
                                }
                            },
                            else => {},
                        }
                    }
                    curr_ctx.ctx = .{ .string_literal = tok.loc };
                },
                .identifier => switch (curr_ctx.ctx) {
                    .empty, .pre_label => curr_ctx.ctx = .{ .var_access = tok.loc },
                    .label => |filled| if (!filled) {
                        curr_ctx.ctx = .{ .label = true };
                    } else {
                        curr_ctx.ctx = .{ .var_access = tok.loc };
                    },
                    .enum_literal => curr_ctx.ctx = .{
                        .enum_literal = tokenLocAppend(curr_ctx.ctx.loc().?, tok),
                    },
                    else => {},
                },
                .builtin => switch (curr_ctx.ctx) {
                    .empty, .pre_label => curr_ctx.ctx = .{ .builtin = tok.loc },
                    else => {},
                },
                .period, .period_asterisk => switch (curr_ctx.ctx) {
                    .empty, .pre_label => curr_ctx.ctx = .{ .enum_literal = tok.loc },
                    .enum_literal => curr_ctx.ctx = .empty,
                    .field_access => {},
                    .other => {},
                    .global_error_set => {},
                    .label => |filled| if (filled) {
                        curr_ctx.ctx = .{ .enum_literal = tok.loc };
                    },
                    else => curr_ctx.ctx = .{
                        .field_access = tokenLocAppend(curr_ctx.ctx.loc().?, tok),
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
                .l_paren => try stack.append(allocator, .{ .ctx = .empty, .stack_id = .Paren }),
                .l_bracket => try stack.append(allocator, .{ .ctx = .empty, .stack_id = .Bracket }),
                .r_paren => {
                    _ = stack.pop();
                    if (curr_ctx.stack_id != .Paren) {
                        (try peek(allocator, &stack)).ctx = .empty;
                    }
                },
                .r_bracket => {
                    _ = stack.pop();
                    if (curr_ctx.stack_id != .Bracket) {
                        (try peek(allocator, &stack)).ctx = .empty;
                    }
                },
                .keyword_error => curr_ctx.ctx = .global_error_set,
                else => curr_ctx.ctx = .empty,
            }

            curr_ctx = try peek(allocator, &stack);
            switch (curr_ctx.ctx) {
                .field_access => |r| curr_ctx.ctx = .{
                    .field_access = tokenLocAppend(r, tok),
                },
                else => {},
            }
        }
    }

    if (stack.popOrNull()) |state| {
        switch (state.ctx) {
            .empty => {},
            .label => |filled| {
                // We need to check this because the state could be a filled
                // label if only a space follows it
                if (!filled or prev_char != ' ') {
                    return state.ctx;
                }
            },
            else => return state.ctx,
        }
    }

    if (line.len == 0) return .empty;

    var held_line = try allocator.dupeZ(u8, offsets.locToSlice(text, line_loc));
    defer allocator.free(held_line);

    switch (line[0]) {
        'a'...'z', 'A'...'Z', '_', '@' => {},
        else => return .empty,
    }
    var tokenizer = std.zig.Tokenizer.init(held_line);
    const tok = tokenizer.next();

    return if (tok.tag == .identifier) PositionContext{ .var_access = tok.loc } else .empty;
}

pub const TokenWithHandle = struct {
    token: Ast.TokenIndex,
    handle: *const DocumentStore.Handle,
};

pub const ErrorUnionSide = enum { left, right };

pub const Declaration = union(enum) {
    /// Index of the ast node
    ast_node: Ast.Node.Index,
    /// Function parameter
    param_payload: Param,
    pointer_payload: struct {
        name: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    error_union_payload: struct {
        name: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    error_union_error: struct {
        name: Ast.TokenIndex,
        /// may be 0
        condition: Ast.Node.Index,
    },
    array_payload: struct {
        identifier: Ast.TokenIndex,
        array_expr: Ast.Node.Index,
    },
    assign_destructure: struct {
        /// tag is .assign_destructure
        node: Ast.Node.Index,
        index: u32,
    },
    array_index: Ast.TokenIndex,
    switch_payload: Switch,
    label_decl: struct {
        label: Ast.TokenIndex,
        block: Ast.Node.Index,
    },
    /// always an identifier
    error_token: Ast.TokenIndex,

    pub const Param = struct {
        param_index: u16,
        func: Ast.Node.Index,

        pub fn get(self: Param, tree: Ast) Ast.full.FnProto.Param {
            var buffer: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buffer, self.func).?;
            var param_index: usize = 0;
            var it = func.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| : (param_index += 1) {
                if (self.param_index == param_index) return param;
            }
            unreachable;
        }
    };

    pub const Switch = struct {
        /// tag is `.@"switch"` or `.switch_comma`
        node: Ast.Node.Index,
        /// is guaranteed to have a payload_token
        case_index: u32,

        pub fn getCase(self: Switch, tree: Ast) Ast.full.SwitchCase {
            const node_datas = tree.nodes.items(.data);
            const extra = tree.extraData(node_datas[self.node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];
            return tree.fullSwitchCase(cases[self.case_index]).?;
        }
    };

    pub const Index = enum(u32) { _ };

    pub fn eql(a: Declaration, b: Declaration) bool {
        return std.meta.eql(a, b);
    }

    pub const Kind = enum { variable, field };

    pub const Key = struct {
        kind: Kind,
        name: []const u8,

        const Context = struct {
            pub fn hash(self: @This(), item: Key) u32 {
                _ = self;
                var hasher = std.hash.Wyhash.init(0);
                hasher.update(&.{@intFromEnum(item.kind)});
                hasher.update(item.name);
                return @truncate(hasher.final());
            }

            pub fn eql(self: @This(), a: Key, b: Key, b_index: usize) bool {
                _ = self;
                _ = b_index;
                return a.kind == b.kind and std.mem.eql(u8, a.name, b.name);
            }
        };
    };
};

pub const DeclWithHandle = struct {
    decl: *Declaration,
    handle: *const DocumentStore.Handle,

    pub fn eql(a: DeclWithHandle, b: DeclWithHandle) bool {
        return a.decl.eql(b.decl.*) and std.mem.eql(u8, a.handle.uri, b.handle.uri);
    }

    pub fn nameToken(self: DeclWithHandle) Ast.TokenIndex {
        const tree = self.handle.tree;
        return switch (self.decl.*) {
            .ast_node => |n| getDeclNameToken(tree, n).?,
            .param_payload => |pp| pp.get(tree).name_token.?,
            .pointer_payload => |pp| pp.name,
            .error_union_payload => |ep| ep.name,
            .error_union_error => |ep| ep.name,
            .array_payload => |ap| ap.identifier,
            .array_index => |ai| ai,
            .label_decl => |ld| ld.label,
            .error_token => |et| et,
            .assign_destructure, => |payload| {
                const lhs_count = tree.extra_data[tree.nodes.items(.data)[payload.node].lhs];
                const lhs_exprs = tree.extra_data[tree.nodes.items(.data)[payload.node].lhs + 1 ..][0..lhs_count];
                const expr = lhs_exprs[payload.index];
                return getDeclNameToken(tree, expr).?;
            },
            .switch_payload => |payload| {
                const case = payload.getCase(tree);
                const payload_token = case.payload_token.?;
                return payload_token + @intFromBool(tree.tokens.items(.tag)[payload_token] == .asterisk);
            },
        };
    }

    pub fn definitionToken(self: DeclWithHandle, analyser: *Analyser, resolve_alias: bool) !TokenWithHandle {
        if (resolve_alias) {
            switch (self.decl.*) {
                .ast_node => |node| {
                    if (try analyser.resolveVarDeclAlias(.{ .node = node, .handle = self.handle })) |result| {
                        return result.definitionToken(analyser, resolve_alias);
                    }
                },
                else => {},
            }
            if (try self.resolveType(analyser)) |resolved_type| {
                if (resolved_type.type.is_type_val) {
                    if (resolved_type.typeDefinitionToken()) |token| {
                        return token;
                    }
                }
            }
        }
        return .{ .token = self.nameToken(), .handle = self.handle };
    }

    pub fn docComments(self: DeclWithHandle, allocator: std.mem.Allocator) !?[]const u8 {
        const tree = self.handle.tree;
        return switch (self.decl.*) {
            // TODO: delete redundant `Analyser.`
            .ast_node => |node| try Analyser.getDocComments(allocator, tree, node),
            .param_payload => |pay| {
                const param = pay.get(tree);
                const doc_comments = param.first_doc_comment orelse return null;
                return try Analyser.collectDocComments(allocator, tree, doc_comments, false);
            },
            .error_token => |token| try Analyser.getDocCommentsBeforeToken(allocator, tree, token),
            else => null,
        };
    }

    fn isPublic(self: DeclWithHandle) bool {
        return switch (self.decl.*) {
            .ast_node => |node| isNodePublic(self.handle.tree, node),
            else => true,
        };
    }

    pub fn resolveType(self: DeclWithHandle, analyser: *Analyser) !?TypeWithHandle {
        const tree = self.handle.tree;
        const node_tags = tree.nodes.items(.tag);
        const main_tokens = tree.nodes.items(.main_token);
        return switch (self.decl.*) {
            .ast_node => |node| try analyser.resolveTypeOfNodeInternal(
                .{ .node = node, .handle = self.handle },
            ),
            .param_payload => |pay| {
                const param = pay.get(tree);

                // handle anytype
                if (param.type_expr == 0) {
                    // protection against recursive callsite resolution
                    const node_with_uri = NodeWithUri{ .node = pay.func, .uri = self.handle.uri };
                    const gop_resolved = try analyser.resolved_nodes.getOrPut(analyser.gpa, node_with_uri);
                    if (gop_resolved.found_existing) return gop_resolved.value_ptr.*;
                    gop_resolved.value_ptr.* = null;

                    var func_decl = Declaration{ .ast_node = pay.func };

                    var func_buf: [1]Ast.Node.Index = undefined;
                    const func = tree.fullFnProto(&func_buf, pay.func).?;

                    var func_params_len: usize = 0;

                    var it = func.iterate(&tree);
                    while (ast.nextFnParam(&it)) |_| {
                        func_params_len += 1;
                    }

                    var refs = try references.callsiteReferences(analyser.arena.allocator(), analyser, .{
                        .decl = &func_decl,
                        .handle = self.handle,
                    }, false, false, false);

                    // TODO: Set `workspace` to true; current problems
                    // - we gather dependencies, not dependents

                    var possible = std.ArrayListUnmanaged(Type.EitherEntry){};
                    var deduplicator = TypeWithHandle.Deduplicator{};
                    defer deduplicator.deinit(analyser.gpa);

                    for (refs.items) |ref| {
                        var handle = analyser.store.getOrLoadHandle(ref.uri).?;

                        var call_buf: [1]Ast.Node.Index = undefined;
                        var call = handle.tree.fullCall(&call_buf, ref.call_node).?;

                        const real_param_idx = if (func_params_len != 0 and pay.param_index != 0 and call.ast.params.len == func_params_len - 1)
                            pay.param_index - 1
                        else
                            pay.param_index;

                        if (real_param_idx >= call.ast.params.len) continue;

                        if (try analyser.resolveTypeOfNode(.{
                            // TODO?: this is a """heuristic based approach"""
                            // perhaps it would be better to use proper self detection
                            // maybe it'd be a perf issue and this is fine?
                            // you figure it out future contributor <3
                            .node = call.ast.params[real_param_idx],
                            .handle = handle,
                        })) |ty| {
                            var gop = try deduplicator.getOrPut(analyser.gpa, ty);
                            if (gop.found_existing) continue;

                            var loc = offsets.tokenToPosition(handle.tree, main_tokens[call.ast.params[real_param_idx]], .@"utf-8");
                            try possible.append(analyser.arena.allocator(), .{ // TODO: Dedup
                                .type_with_handle = ty,
                                .descriptor = try std.fmt.allocPrint(analyser.arena.allocator(), "{s}:{d}:{d}", .{ handle.uri, loc.line + 1, loc.character + 1 }),
                            });
                        }
                    }

                    const maybe_type_handle = try TypeWithHandle.fromEither(analyser.gpa, try possible.toOwnedSlice(analyser.arena.allocator()), self.handle);
                    if (maybe_type_handle) |type_handle| analyser.resolved_nodes.getPtr(node_with_uri).?.* = type_handle;
                    return maybe_type_handle;
                }

                if (isMetaType(self.handle.tree, param.type_expr)) {
                    if (analyser.bound_type_params.get(.{ .func = pay.func, .param_index = pay.param_index })) |resolved_type| {
                        return resolved_type;
                    }
                    return try analyser.resolveTypeOfNodeInternal(.{ .node = param.type_expr, .handle = self.handle });
                } else if (node_tags[param.type_expr] == .identifier) {
                    if (param.name_token) |name_tok| {
                        if (std.mem.eql(u8, tree.tokenSlice(main_tokens[param.type_expr]), tree.tokenSlice(name_tok)))
                            return null;
                    }
                }
                return ((try analyser.resolveTypeOfNodeInternal(
                    .{ .node = param.type_expr, .handle = self.handle },
                )) orelse return null).instanceTypeVal();
            },
            .pointer_payload => |pay| try analyser.resolveUnwrapOptionalType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.condition,
                    .handle = self.handle,
                })) orelse return null,
            ),
            .error_union_payload => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.condition,
                    .handle = self.handle,
                })) orelse return null,
                .right,
            ),
            .error_union_error => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = if (pay.condition == 0) return null else pay.condition,
                    .handle = self.handle,
                })) orelse return null,
                .left,
            ),
            .array_payload => |pay| try analyser.resolveBracketAccessType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.array_expr,
                    .handle = self.handle,
                })) orelse return null,
                .Single,
            ),
            .assign_destructure => null, // TODO
            .array_index => TypeWithHandle{
                .type = .{ .data = .array_index, .is_type_val = false },
                .handle = self.handle,
            },
            .label_decl => |decl| try analyser.resolveTypeOfNodeInternal(.{
                .node = decl.block,
                .handle = self.handle,
            }),
            .switch_payload => |payload| {
                const cond = tree.nodes.items(.data)[payload.node].lhs;
                const case = payload.getCase(tree);
                const values = case.ast.values;

                if (values.len == 0) return null;
                // TODO Peer type resolution, we just use the first item for now.
                const switch_expr_type = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = cond,
                    .handle = self.handle,
                })) orelse return null;
                if (!switch_expr_type.isUnionType())
                    return null;

                if (node_tags[values[0]] != .enum_literal) return null;

                const scope_index = findContainerScopeIndex(.{ .node = switch_expr_type.type.data.other, .handle = switch_expr_type.handle }) orelse return null;
                const scope_decls = switch_expr_type.handle.document_scope.scopes.items(.decls);

                const name = tree.tokenSlice(main_tokens[values[0]]);
                const decl_key = Declaration.Key{ .kind = .field, .name = name };
                const decl_index = scope_decls[scope_index].get(decl_key) orelse return null;
                const decl = switch_expr_type.handle.document_scope.decls.items[@intFromEnum(decl_index)];

                switch (decl) {
                    .ast_node => |node| {
                        if (switch_expr_type.handle.tree.fullContainerField(node)) |container_field| {
                            if (container_field.ast.type_expr != 0) {
                                return ((try analyser.resolveTypeOfNodeInternal(
                                    .{ .node = container_field.ast.type_expr, .handle = switch_expr_type.handle },
                                )) orelse return null).instanceTypeVal();
                            }
                        }
                    },
                    else => {},
                }
                return null;
            },
            .error_token => return null,
        };
    }
};

fn findContainerScopeIndex(container_handle: NodeWithHandle) ?usize {
    const container = container_handle.node;
    const handle = container_handle.handle;

    if (!ast.isContainer(handle.tree, container)) return null;

    return for (handle.document_scope.scopes.items(.data), 0..) |data, scope_index| {
        switch (data) {
            .container => |node| if (node == container) {
                break scope_index;
            },
            else => {},
        }
    } else null;
}

fn iterateSymbolsContainerInternal(
    analyser: *Analyser,
    container_handle: NodeWithHandle,
    orig_handle: *const DocumentStore.Handle,
    comptime callback: anytype,
    context: anytype,
    instance_access: bool,
) error{OutOfMemory}!void {
    const container = container_handle.node;
    const handle = container_handle.handle;

    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const main_token = tree.nodes.items(.main_token)[container];

    const is_enum = token_tags[main_token] == .keyword_enum;

    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);
    const container_scope_index = findContainerScopeIndex(container_handle) orelse return;

    for (scope_decls[container_scope_index].values()) |decl_index| {
        const decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
        switch (decl.*) {
            .ast_node => |node| switch (node_tags[node]) {
                .container_field_init,
                .container_field_align,
                .container_field,
                => {
                    if (is_enum) {
                        if (instance_access) continue;
                        const field_name = offsets.tokenToSlice(tree, tree.nodes.items(.main_token)[node]);
                        if (std.mem.eql(u8, field_name, "_")) continue;
                    } else {
                        if (!instance_access) continue;
                    }
                },
                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl,
                => {
                    if (instance_access) continue;
                },
                else => {},
            },
            .label_decl => continue,
            else => {},
        }

        const decl_with_handle = DeclWithHandle{ .decl = decl, .handle = handle };
        if (handle != orig_handle and !decl_with_handle.isPublic()) continue;
        try callback(context, decl_with_handle);
    }

    for (scope_uses[container_scope_index]) |use| {
        try analyser.iterateUsingnamespaceContainerSymbols(
            .{ .node = use, .handle = handle },
            orig_handle,
            callback,
            context,
            false,
        );
    }
}

fn iterateUsingnamespaceContainerSymbols(
    analyser: *Analyser,
    usingnamespace_node: NodeWithHandle,
    orig_handle: *const DocumentStore.Handle,
    comptime callback: anytype,
    context: anytype,
    instance_access: bool,
) !void {
    const gop = try analyser.node_trail.getOrPut(analyser.gpa, .{ .node = usingnamespace_node.node, .uri = usingnamespace_node.handle.uri });
    if (gop.found_existing) return;

    const handle = usingnamespace_node.handle;

    const use_token = handle.tree.nodes.items(.main_token)[usingnamespace_node.node];
    const is_pub = use_token > 0 and handle.tree.tokens.items(.tag)[use_token - 1] == .keyword_pub;
    if (handle != orig_handle and !is_pub) return;

    const use_expr = (try analyser.resolveTypeOfNode(.{
        .node = handle.tree.nodes.items(.data)[usingnamespace_node.node].lhs,
        .handle = handle,
    })) orelse return;

    switch (use_expr.type.data) {
        .other => |expr| {
            try analyser.iterateSymbolsContainerInternal(
                .{ .node = expr, .handle = use_expr.handle },
                orig_handle,
                callback,
                context,
                instance_access,
            );
        },
        .either => |entries| {
            for (entries) |entry| {
                switch (entry.type_with_handle.type.data) {
                    .other => |expr| {
                        try analyser.iterateSymbolsContainerInternal(
                            .{ .node = expr, .handle = use_expr.handle },
                            orig_handle,
                            callback,
                            context,
                            instance_access,
                        );
                    },
                    else => continue,
                }
            }
        },
        else => return,
    }
}

pub const EnclosingScopeIterator = struct {
    scope_locs: []offsets.Loc,
    scope_children: []const std.ArrayListUnmanaged(Scope.Index),
    current_scope: Scope.Index,
    source_index: usize,

    pub fn next(self: *EnclosingScopeIterator) ?Scope.Index {
        if (self.current_scope == .none) return null;

        const child_scopes = self.scope_children[@intFromEnum(self.current_scope)];
        defer self.current_scope = for (child_scopes.items) |child_scope| {
            const child_loc = self.scope_locs[@intFromEnum(child_scope)];
            if (child_loc.start <= self.source_index and self.source_index <= child_loc.end) {
                break child_scope;
            }
        } else .none;

        return self.current_scope;
    }
};

fn iterateEnclosingScopes(document_scope: DocumentScope, source_index: usize) EnclosingScopeIterator {
    return .{
        .scope_locs = document_scope.scopes.items(.loc),
        .scope_children = document_scope.scopes.items(.child_scopes),
        .current_scope = @enumFromInt(0),
        .source_index = source_index,
    };
}

pub fn iterateSymbolsContainer(
    analyser: *Analyser,
    container_handle: NodeWithHandle,
    orig_handle: *const DocumentStore.Handle,
    comptime callback: anytype,
    context: anytype,
    instance_access: bool,
) error{OutOfMemory}!void {
    analyser.node_trail.clearRetainingCapacity();
    return try analyser.iterateSymbolsContainerInternal(container_handle, orig_handle, callback, context, instance_access);
}

pub fn iterateLabels(handle: *const DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype) error{OutOfMemory}!void {
    const scope_decls = handle.document_scope.scopes.items(.decls);

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        for (scope_decls[@intFromEnum(scope_index)].values()) |decl_index| {
            const decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
            if (decl.* != .label_decl) continue;
            try callback(context, DeclWithHandle{ .decl = decl, .handle = handle });
        }
    }
}

fn iterateSymbolsGlobalInternal(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    comptime callback: anytype,
    context: anytype,
) error{OutOfMemory}!void {
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        for (scope_decls[@intFromEnum(scope_index)].values()) |decl_index| {
            const decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
            if (decl.* == .ast_node and handle.tree.nodes.items(.tag)[decl.ast_node].isContainerField()) continue;
            if (decl.* == .label_decl) continue;
            try callback(context, DeclWithHandle{ .decl = decl, .handle = handle });
        }

        for (scope_uses[@intFromEnum(scope_index)]) |use| {
            try analyser.iterateUsingnamespaceContainerSymbols(
                .{ .node = use, .handle = handle },
                handle,
                callback,
                context,
                false,
            );
        }
    }
}

pub fn iterateSymbolsGlobal(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    comptime callback: anytype,
    context: anytype,
) error{OutOfMemory}!void {
    analyser.node_trail.clearRetainingCapacity();
    return try analyser.iterateSymbolsGlobalInternal(handle, source_index, callback, context);
}

pub fn innermostBlockScopeIndex(handle: DocumentStore.Handle, source_index: usize) Scope.Index {
    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    var scope_index: Scope.Index = .none;
    while (scope_iterator.next()) |inner_scope| {
        scope_index = inner_scope;
    }
    return scope_index;
}

pub fn innermostBlockScope(handle: DocumentStore.Handle, source_index: usize) Ast.Node.Index {
    return innermostBlockScopeInternal(handle, source_index, false);
}

fn innermostBlockScopeInternal(handle: DocumentStore.Handle, source_index: usize, skip_block: bool) Ast.Node.Index {
    const scope_datas = handle.document_scope.scopes.items(.data);
    const scope_parents = handle.document_scope.scopes.items(.parent);

    var scope_index = innermostBlockScopeIndex(handle, source_index);
    while (true) {
        defer scope_index = scope_parents[@intFromEnum(scope_index)];
        const data = scope_datas[@intFromEnum(scope_index)];
        switch (data) {
            .container, .function, .block => {
                if (data == .block and skip_block)
                    continue;
                return data.toNodeIndex().?;
            },
            else => {},
        }
    }
}

pub fn innermostContainer(handle: *const DocumentStore.Handle, source_index: usize) TypeWithHandle {
    const scope_datas = handle.document_scope.scopes.items(.data);

    var current = scope_datas[0].container;
    if (handle.document_scope.scopes.len == 1) return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        switch (scope_datas[@intFromEnum(scope_index)]) {
            .container => |node| current = node,
            else => {},
        }
    }
    return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });
}

fn resolveUse(analyser: *Analyser, uses: []const Ast.Node.Index, symbol: []const u8, handle: *const DocumentStore.Handle) error{OutOfMemory}!?DeclWithHandle {
    analyser.node_trail.clearRetainingCapacity();
    for (uses) |index| {
        const gop = try analyser.node_trail.getOrPut(analyser.gpa, .{ .node = index, .uri = handle.uri });
        if (gop.found_existing) continue;

        if (handle.tree.nodes.items(.data).len <= index) continue;

        const expr = .{ .node = handle.tree.nodes.items(.data)[index].lhs, .handle = handle };
        const expr_type = (try analyser.resolveTypeOfNode(expr)) orelse
            continue;

        if (!expr_type.type.is_type_val) {
            // TODO: publish diagnostic; this is a compile error
            continue;
        }

        if (try expr_type.lookupSymbol(analyser, symbol)) |candidate| {
            if (candidate.handle == handle or candidate.isPublic()) {
                return candidate;
            }
        }
    }
    return null;
}

pub fn lookupLabel(
    handle: *const DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const scope_decls = handle.document_scope.scopes.items(.decls);

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        const decl_key = Declaration.Key{ .kind = .variable, .name = symbol };
        const decl_index = scope_decls[@intFromEnum(scope_index)].get(decl_key) orelse continue;
        const decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];

        if (decl.* != .label_decl) continue;

        return DeclWithHandle{ .decl = decl, .handle = handle };
    }
    return null;
}

pub fn lookupSymbolGlobal(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const field_decl_key = Declaration.Key{ .kind = .field, .name = symbol };
    const var_decl_key = Declaration.Key{ .kind = .variable, .name = symbol };

    const tree = handle.tree;
    const scope_parents = handle.document_scope.scopes.items(.parent);
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);

    var current_scope = innermostBlockScopeIndex(handle.*, source_index);

    while (current_scope != .none) {
        const scope_index = @intFromEnum(current_scope);
        defer current_scope = scope_parents[scope_index];
        if (scope_decls[scope_index].get(field_decl_key)) |decl_index| {
            const field_decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
            std.debug.assert(field_decl.* == .ast_node);

            var field = tree.fullContainerField(field_decl.ast_node).?;
            field.convertToNonTupleLike(tree.nodes);

            const field_name = offsets.tokenToLoc(tree, field.ast.main_token);
            if (field_name.start <= source_index and source_index <= field_name.end)
                return DeclWithHandle{ .decl = field_decl, .handle = handle };
        }
        if (scope_decls[scope_index].get(var_decl_key)) |decl_index| {
            const candidate = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
            return DeclWithHandle{ .decl = candidate, .handle = handle };
        }
        if (try analyser.resolveUse(scope_uses[scope_index], symbol, handle)) |result| return result;
    }

    return null;
}

pub fn lookupSymbolContainer(
    analyser: *Analyser,
    container_handle: NodeWithHandle,
    symbol: []const u8,
    kind: Declaration.Kind,
) error{OutOfMemory}!?DeclWithHandle {
    const handle = container_handle.handle;
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);
    const decl_key = Declaration.Key{ .kind = kind, .name = symbol };

    if (findContainerScopeIndex(container_handle)) |container_scope_index| {
        if (scope_decls[container_scope_index].get(decl_key)) |decl_index| {
            const decl = &handle.document_scope.decls.items[@intFromEnum(decl_index)];
            return DeclWithHandle{ .decl = decl, .handle = handle };
        }

        if (try analyser.resolveUse(scope_uses[container_scope_index], symbol, handle)) |result| return result;
    }

    return null;
}

pub fn lookupSymbolFieldInit(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    field_name: []const u8,
    nodes: []Ast.Node.Index,
) error{OutOfMemory}!?DeclWithHandle {
    if (nodes.len == 0) return null;

    var container_type = (try analyser.resolveExpressionType(
        handle,
        nodes[0],
        nodes[1..],
    )) orelse return null;

    if (try analyser.resolveUnwrapErrorUnionType(container_type, .right)) |unwrapped|
        container_type = unwrapped;

    if (try analyser.resolveUnwrapOptionalType(container_type)) |unwrapped|
        container_type = unwrapped;

    const container_node = switch (container_type.type.data) {
        .other => |n| n,
        else => return null,
    };

    return analyser.lookupSymbolContainer(
        .{ .node = container_node, .handle = container_type.handle },
        field_name,
        .field,
    );
}

pub fn resolveExpressionType(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []Ast.Node.Index,
) error{OutOfMemory}!?TypeWithHandle {
    return (try analyser.resolveExpressionTypeFromAncestors(
        handle,
        node,
        ancestors,
    )) orelse (try analyser.resolveTypeOfNode(.{
        .node = node,
        .handle = handle,
    }));
}

pub fn resolveExpressionTypeFromAncestors(
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []Ast.Node.Index,
) error{OutOfMemory}!?TypeWithHandle {
    if (ancestors.len == 0) return null;

    const tree = handle.tree;
    const node_tags: []Ast.Node.Tag = tree.nodes.items(.tag);
    const datas: []Ast.Node.Data = tree.nodes.items(.data);
    const token_tags: []std.zig.Token.Tag = tree.tokens.items(.tag);

    switch (node_tags[ancestors[0]]) {
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const struct_init = tree.fullStructInit(&buffer, ancestors[0]).?;
            if (std.mem.indexOfScalar(Ast.Node.Index, struct_init.ast.fields, node) != null) {
                const field_name = tree.tokenSlice(tree.firstToken(node) - 2);
                if (try analyser.lookupSymbolFieldInit(handle, field_name, ancestors)) |field_decl| {
                    return try field_decl.resolveType(analyser);
                }
            }
        },
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const array_init = tree.fullArrayInit(&buffer, ancestors[0]).?;
            const element_index = std.mem.indexOfScalar(Ast.Node.Index, array_init.ast.elements, node) orelse
                return null;

            if (try analyser.resolveExpressionType(
                handle,
                ancestors[0],
                ancestors[1..],
            )) |array_type| {
                return (try analyser.resolveBracketAccessType(array_type, .Single)) orelse
                    (try analyser.resolveTupleFieldType(array_type, element_index));
            }

            if (ancestors.len != 1 and node_tags[ancestors[1]] == .address_of) {
                if (try analyser.resolveExpressionType(
                    handle,
                    ancestors[1],
                    ancestors[2..],
                )) |slice_type| {
                    return try analyser.resolveBracketAccessType(slice_type, .Single);
                }
            }
        },
        .container_field_init,
        .container_field_align,
        .container_field,
        => {
            const container_field = tree.fullContainerField(ancestors[0]).?;
            if (node == container_field.ast.value_expr) {
                return try analyser.resolveTypeOfNode(.{
                    .node = ancestors[0],
                    .handle = handle,
                });
            }
        },
        .if_simple,
        .@"if",
        => {
            const if_node = ast.fullIf(tree, ancestors[0]).?;
            if (node == if_node.ast.then_expr or node == if_node.ast.else_expr) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .for_simple,
        .@"for",
        => {
            const for_node = ast.fullFor(tree, ancestors[0]).?;
            if (node == for_node.ast.else_expr) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .while_simple,
        .while_cont,
        .@"while",
        => {
            const while_node = ast.fullWhile(tree, ancestors[0]).?;
            if (node == while_node.ast.else_expr) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => {
            const switch_case = tree.fullSwitchCase(ancestors[0]).?;
            if (ancestors.len == 1) return null;

            switch (node_tags[ancestors[1]]) {
                .@"switch", .switch_comma => {},
                else => return null,
            }

            if (node == switch_case.ast.target_expr) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[1],
                    ancestors[2..],
                );
            }

            for (switch_case.ast.values) |value| {
                if (node == value) {
                    return try analyser.resolveTypeOfNode(.{
                        .node = datas[ancestors[1]].lhs,
                        .handle = handle,
                    });
                }
            }
        },
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            var buffer: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&buffer, ancestors[0]).?;
            const arg_index = std.mem.indexOfScalar(Ast.Node.Index, call.ast.params, node) orelse return null;

            const fn_type = (try analyser.resolveTypeOfNode(.{
                .node = call.ast.fn_expr,
                .handle = handle,
            })) orelse return null;

            if (fn_type.type.is_type_val) return null;

            const fn_handle = fn_type.handle;
            const fn_tree = fn_handle.tree;
            const fn_node = switch (fn_type.type.data) {
                .other => |n| n,
                else => return null,
            };

            var fn_buf: [1]Ast.Node.Index = undefined;
            const fn_proto = fn_tree.fullFnProto(&fn_buf, fn_node) orelse return null;

            var param_iter = fn_proto.iterate(&fn_tree);
            if (try analyser.isInstanceCall(handle, call, fn_handle, fn_proto)) {
                _ = ast.nextFnParam(&param_iter);
            }

            var param_index: usize = 0;
            while (ast.nextFnParam(&param_iter)) |param| : (param_index += 1) {
                if (param_index == arg_index) {
                    return try analyser.resolveTypeOfNode(.{
                        .node = param.type_expr,
                        .handle = fn_handle,
                    });
                }
            }
        },
        .assign => {
            if (node == datas[ancestors[0]].rhs) {
                return try analyser.resolveTypeOfNode(.{
                    .node = datas[ancestors[0]].lhs,
                    .handle = handle,
                });
            }
        },

        .equal_equal, .bang_equal => {
            return (try analyser.resolveTypeOfNode(.{
                .node = datas[ancestors[0]].lhs,
                .handle = handle,
            })) orelse (try analyser.resolveTypeOfNode(.{
                .node = datas[ancestors[0]].rhs,
                .handle = handle,
            }));
        },

        .@"return" => {
            if (node != datas[ancestors[0]].lhs) return null;

            var func_buf: [1]Ast.Node.Index = undefined;
            for (1..ancestors.len) |index| {
                const func = tree.fullFnProto(&func_buf, ancestors[index]) orelse continue;
                return try analyser.resolveTypeOfNode(.{
                    .node = func.ast.return_type,
                    .handle = handle,
                });
            }
        },

        .@"break" => {
            if (node != datas[ancestors[0]].rhs) return null;

            const break_label_maybe: ?[]const u8 = if (datas[ancestors[0]].lhs != 0)
                tree.tokenSlice(datas[ancestors[0]].lhs)
            else
                null;

            const index = blk: for (1..ancestors.len) |index| {
                if (ast.fullFor(tree, ancestors[index])) |for_node| {
                    const break_label = break_label_maybe orelse break :blk index;
                    const for_label = tree.tokenSlice(for_node.label_token orelse continue);
                    if (std.mem.eql(u8, break_label, for_label)) break :blk index;
                } else if (ast.fullWhile(tree, ancestors[index])) |while_node| {
                    const break_label = break_label_maybe orelse break :blk index;
                    const while_label = tree.tokenSlice(while_node.label_token orelse continue);
                    if (std.mem.eql(u8, break_label, while_label)) break :blk index;
                } else switch (node_tags[ancestors[index]]) {
                    .block,
                    .block_semicolon,
                    .block_two,
                    .block_two_semicolon,
                    => {
                        const break_label = break_label_maybe orelse continue;

                        const first_token = tree.firstToken(ancestors[index]);
                        if (token_tags[first_token] != .identifier) continue;
                        const block_label = tree.tokenSlice(first_token);

                        if (std.mem.eql(u8, break_label, block_label)) break :blk index;
                    },

                    else => {},
                }
            } else return null;

            return try analyser.resolveExpressionType(
                handle,
                ancestors[index],
                ancestors[index + 1 ..],
            );
        },

        else => {}, // TODO: Implement more expressions; better safe than sorry
    }

    return null;
}

pub fn identifierLocFromPosition(pos_index: usize, handle: *const DocumentStore.Handle) ?std.zig.Token.Loc {
    if (pos_index + 1 >= handle.text.len) return null;
    var start_idx = pos_index;

    while (start_idx > 0 and Analyser.isSymbolChar(handle.text[start_idx - 1])) {
        start_idx -= 1;
    }

    const token_index = offsets.sourceIndexToTokenIndex(handle.tree, start_idx);
    if (handle.tree.tokens.items(.tag)[token_index] == .identifier)
        return offsets.tokenToLoc(handle.tree, token_index);

    var end_idx = pos_index;
    while (end_idx < handle.text.len and Analyser.isSymbolChar(handle.text[end_idx])) {
        end_idx += 1;
    }

    if (end_idx <= start_idx) return null;
    return .{ .start = start_idx, .end = end_idx };
}

pub fn getLabelGlobal(
    pos_index: usize,
    handle: *const DocumentStore.Handle,
    name: []const u8,
) error{OutOfMemory}!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try lookupLabel(handle, name, pos_index);
}

pub fn getSymbolGlobal(
    analyser: *Analyser,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
    name: []const u8,
) error{OutOfMemory}!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try analyser.lookupSymbolGlobal(handle, name, pos_index);
}

pub fn getSymbolEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    name: []const u8,
) error{OutOfMemory}!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const nodes = try ast.nodesOverlappingIndex(arena, handle.tree, source_index);
    if (nodes.len == 0) return null;
    return analyser.lookupSymbolFieldInit(handle, name, nodes);
}

/// Multiple when using branched types
pub fn getSymbolFieldAccesses(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    held_loc: offsets.Loc,
    name: []const u8,
) error{OutOfMemory}!?[]const DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const held_range = try arena.dupeZ(u8, offsets.locToSlice(handle.text, held_loc));
    var tokenizer = std.zig.Tokenizer.init(held_range);

    var decls_with_handles = std.ArrayListUnmanaged(DeclWithHandle){};

    if (try analyser.getFieldAccessType(handle, source_index, &tokenizer)) |result| {
        const container_handle = result.unwrapped orelse result.original;

        const container_handle_nodes = try container_handle.getAllTypesWithHandles(arena);

        for (container_handle_nodes) |ty| {
            try decls_with_handles.append(arena, (try ty.lookupSymbol(analyser, name)) orelse continue);
        }
    }

    return try decls_with_handles.toOwnedSlice(arena);
}

const CompletionContext = struct {
    pub fn hash(self: @This(), item: types.CompletionItem) u32 {
        _ = self;
        return @truncate(std.hash.Wyhash.hash(0, item.label));
    }

    pub fn eql(self: @This(), a: types.CompletionItem, b: types.CompletionItem, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return std.mem.eql(u8, a.label, b.label);
    }
};

pub const CompletionSet = std.ArrayHashMapUnmanaged(
    types.CompletionItem,
    void,
    CompletionContext,
    false,
);
comptime {
    std.debug.assert(@sizeOf(types.CompletionItem) == @sizeOf(CompletionSet.Data));
}

pub const DocumentScope = struct {
    scopes: std.MultiArrayList(Scope) = .{},
    decls: std.ArrayListUnmanaged(Declaration) = .{},
    error_completions: CompletionSet = .{},
    enum_completions: CompletionSet = .{},

    pub fn deinit(self: *DocumentScope, allocator: std.mem.Allocator) void {
        for (
            self.scopes.items(.decls),
            self.scopes.items(.child_scopes),
            self.scopes.items(.tests),
            self.scopes.items(.uses),
        ) |*decls, *child_scopes, tests, uses| {
            decls.deinit(allocator);
            child_scopes.deinit(allocator);
            allocator.free(tests);
            allocator.free(uses);
        }
        self.scopes.deinit(allocator);
        self.decls.deinit(allocator);

        for (self.error_completions.keys()) |item| {
            if (item.detail) |detail| allocator.free(detail);
            switch (item.documentation orelse continue) {
                .string => |str| allocator.free(str),
                .MarkupContent => |content| allocator.free(content.value),
            }
        }
        self.error_completions.deinit(allocator);
        for (self.enum_completions.keys()) |item| {
            if (item.detail) |detail| allocator.free(detail);
            switch (item.documentation orelse continue) {
                .string => |str| allocator.free(str),
                .MarkupContent => |content| allocator.free(content.value),
            }
        }
        self.enum_completions.deinit(allocator);
    }
};

pub const Scope = struct {
    pub const Data = union(enum) {
        container: Ast.Node.Index, // .tag is ContainerDecl or Root or ErrorSetDecl
        function: Ast.Node.Index, // .tag is FnProto
        block: Ast.Node.Index, // .tag is Block
        other,

        pub fn toNodeIndex(self: Data) ?Ast.Node.Index {
            return switch (self) {
                .container, .function, .block => |idx| idx,
                else => null,
            };
        }
    };

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,
    };

    loc: offsets.Loc,
    parent: Index,
    data: Data,
    decls: std.ArrayHashMapUnmanaged(Declaration.Key, Declaration.Index, Declaration.Key.Context, false) = .{},
    child_scopes: std.ArrayListUnmanaged(Scope.Index) = .{},
    tests: []const Ast.Node.Index = &.{},
    uses: []const Ast.Node.Index = &.{},
};

pub fn makeDocumentScope(allocator: std.mem.Allocator, tree: Ast) !DocumentScope {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var document_scope = DocumentScope{};
    errdefer document_scope.deinit(allocator);

    var current_scope: Scope.Index = .none;

    try makeInnerScope(.{
        .allocator = allocator,
        .doc_scope = &document_scope,
        .current_scope = &current_scope,
    }, tree, 0, 0);

    return document_scope;
}

const ScopeContext = struct {
    allocator: std.mem.Allocator,
    doc_scope: *DocumentScope,
    current_scope: *Scope.Index,

    fn pushScope(context: ScopeContext, loc: offsets.Loc, data: Scope.Data) error{OutOfMemory}!Scope.Index {
        try context.doc_scope.scopes.append(context.allocator, .{
            .parent = context.current_scope.*,
            .loc = loc,
            .data = data,
        });
        const new_scope: Scope.Index = @enumFromInt(context.doc_scope.scopes.len - 1);
        if (context.current_scope.* != .none) {
            try context.doc_scope.scopes.items(.child_scopes)[@intFromEnum(context.current_scope.*)].append(context.allocator, new_scope);
        }
        context.current_scope.* = new_scope;
        return new_scope;
    }

    fn popScope(context: ScopeContext) void {
        const parent_scope = context.doc_scope.scopes.items(.parent)[@intFromEnum(context.current_scope.*)];
        context.current_scope.* = parent_scope;
    }

    fn putVarDecl(context: ScopeContext, scope: Scope.Index, name: []const u8, decl: Declaration) error{OutOfMemory}!void {
        return context.putDecl(scope, name, decl, .variable);
    }

    fn putFieldDecl(context: ScopeContext, scope: Scope.Index, name: []const u8, decl: Declaration) error{OutOfMemory}!void {
        return context.putDecl(scope, name, decl, .field);
    }

    fn putDecl(
        context: ScopeContext,
        scope: Scope.Index,
        name: []const u8,
        decl: Declaration,
        kind: Declaration.Kind,
    ) error{OutOfMemory}!void {
        std.debug.assert(scope != .none);

        try context.doc_scope.decls.append(context.allocator, decl);
        errdefer _ = context.doc_scope.decls.pop();

        const decl_key = Declaration.Key{ .kind = kind, .name = name };
        const decl_index: Declaration.Index = @enumFromInt(context.doc_scope.decls.items.len - 1);

        try context.doc_scope.scopes.items(.decls)[@intFromEnum(scope)].put(context.allocator, decl_key, decl_index);
    }

    fn putDeclLoopLabel(
        context: ScopeContext,
        tree: Ast,
        label: Ast.TokenIndex,
        node_idx: Ast.Node.Index,
    ) error{OutOfMemory}![]const u8 {
        const label_scope = try context.pushScope(offsets.tokenToLoc(tree, label), .other);
        context.popScope();

        const name = tree.tokenSlice(label);
        try context.putVarDecl(label_scope, name, .{ .label_decl = .{ .label = label, .block = node_idx } });
        return name;
    }
};

fn makeInnerScope(
    context: ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = context.allocator;
    const scopes = &context.doc_scope.scopes;
    const tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    const scope_index = try context.pushScope(
        offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
        .{ .container = node_idx },
    );
    defer context.popScope();

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node_idx).?;

    var tests = std.ArrayListUnmanaged(Ast.Node.Index){};
    errdefer tests.deinit(allocator);
    var uses = std.ArrayListUnmanaged(Ast.Node.Index){};
    errdefer uses.deinit(allocator);

    for (container_decl.ast.members) |decl| {
        try makeScopeInternal(context, tree, decl);

        switch (tags[decl]) {
            .@"usingnamespace" => {
                try uses.append(allocator, decl);
                continue;
            },
            .test_decl => {
                try tests.append(allocator, decl);
                continue;
            },
            else => {},
        }

        const name = getContainerDeclName(tree, node_idx, decl) orelse continue;

        if (tags[decl].isContainerField()) {
            try context.putFieldDecl(scope_index, name, .{ .ast_node = decl });
        } else {
            try context.putVarDecl(scope_index, name, .{ .ast_node = decl });
        }

        if ((node_idx != 0 and token_tags[container_decl.ast.main_token] == .keyword_enum) or
            ast.isTaggedUnion(tree, node_idx))
        {
            if (std.mem.eql(u8, name, "_")) continue;

            const doc = try getDocComments(allocator, tree, decl);
            errdefer if (doc) |d| allocator.free(d);
            var gop_res = try context.doc_scope.enum_completions.getOrPut(allocator, .{
                .label = name,
                .kind = .EnumMember,
                .insertText = name,
                .insertTextFormat = .PlainText,
                .documentation = if (doc) |d| .{ .MarkupContent = types.MarkupContent{ .kind = .markdown, .value = d } } else null,
            });
            if (gop_res.found_existing) {
                if (doc) |d| allocator.free(d);
            }
        }
    }

    scopes.items(.tests)[@intFromEnum(scope_index)] = try tests.toOwnedSlice(allocator);
    scopes.items(.uses)[@intFromEnum(scope_index)] = try uses.toOwnedSlice(allocator);
}

/// If `node_idx` is a block it's scope index will be returned
/// Otherwise, a new scope will be created that will enclose `node_idx`
fn makeBlockScopeInternal(context: ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!?Scope.Index {
    return makeBlockScopeAt(context, tree, node_idx, tree.firstToken(node_idx));
}

fn makeBlockScopeAt(
    context: ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!?Scope.Index {
    if (node_idx == 0) return null;
    const tags = tree.nodes.items(.tag);

    // if node_idx is a block, the next scope will be a block so we store its index here
    const block_scope_index = context.doc_scope.scopes.len;
    try makeScopeAt(context, tree, node_idx, start_token);

    switch (tags[node_idx]) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            std.debug.assert(context.doc_scope.scopes.items(.data)[block_scope_index] == .block);
            return @enumFromInt(block_scope_index);
        },
        else => {
            const new_scope = try context.pushScope(
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
                .other,
            );
            context.popScope();
            return new_scope;
        },
    }
}

fn makeScopeInternal(context: ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    return makeScopeAt(context, tree, node_idx, tree.firstToken(node_idx));
}

fn makeScopeAt(
    context: ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!void {
    if (node_idx == 0) return;

    const allocator = context.allocator;

    const tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    const node_tag = tags[node_idx];

    switch (node_tag) {
        .root => unreachable,
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
        => try makeInnerScope(context, tree, node_idx, start_token),
        .error_set_decl => {
            const scope_index = try context.pushScope(
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
                .{ .container = node_idx },
            );
            defer context.popScope();

            // All identifiers in main_token..data.rhs are error fields.
            var tok_i = main_tokens[node_idx] + 2;
            while (tok_i < data[node_idx].rhs) : (tok_i += 1) {
                switch (token_tags[tok_i]) {
                    .doc_comment, .comma => {},
                    .identifier => {
                        const name = offsets.tokenToSlice(tree, tok_i);
                        try context.putVarDecl(scope_index, name, .{ .error_token = tok_i });
                        const gop = try context.doc_scope.error_completions.getOrPut(allocator, .{
                            .label = name,
                            .kind = .Constant,
                            //.detail =
                            .insertText = name,
                            .insertTextFormat = .PlainText,
                        });
                        if (!gop.found_existing) {
                            gop.key_ptr.detail = try std.fmt.allocPrint(allocator, "error.{s}", .{name});
                        }
                    },
                    else => {},
                }
            }
        },
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => |fn_tag| {
            var buf: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buf, node_idx).?;

            const scope_index = try context.pushScope(
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
                .{ .function = node_idx },
            );
            defer context.popScope();

            // NOTE: We count the param index ourselves
            // as param_i stops counting; TODO: change this

            var param_index: usize = 0;

            var it = func.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| {
                // Add parameter decls
                if (param.name_token) |name_token| {
                    try context.putVarDecl(
                        scope_index,
                        tree.tokenSlice(name_token),
                        .{ .param_payload = .{
                            .param_index = @intCast(param_index),
                            .func = node_idx,
                        } },
                    );
                }
                // Visit parameter types to pick up any error sets and enum
                //   completions
                try makeScopeInternal(context, tree, param.type_expr);
                param_index += 1;
            }

            if (fn_tag == .fn_decl) blk: {
                if (data[node_idx].lhs == 0) break :blk;
                const return_type_node = data[data[node_idx].lhs].rhs;

                // Visit the return type
                try makeScopeInternal(context, tree, return_type_node);
            }

            // Visit the function body
            try makeScopeInternal(context, tree, data[node_idx].rhs);
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            const first_token = tree.firstToken(node_idx);
            const last_token = ast.lastToken(tree, node_idx);
            const end_index = offsets.tokenToLoc(tree, last_token).end;

            const scope_index = try context.pushScope(
                .{
                    .start = offsets.tokenToIndex(tree, start_token),
                    .end = end_index,
                },
                .{ .block = node_idx },
            );
            defer context.popScope();

            // if labeled block
            if (token_tags[first_token] == .identifier) {
                try context.putVarDecl(
                    scope_index,
                    tree.tokenSlice(first_token),
                    .{ .label_decl = .{ .label = first_token, .block = node_idx } },
                );
            }

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                try makeScopeInternal(context, tree, idx);
                switch (tags[idx]) {
                    .global_var_decl,
                    .local_var_decl,
                    .aligned_var_decl,
                    .simple_var_decl,
                    => {
                        const var_decl = tree.fullVarDecl(idx).?;
                        const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                        try context.putVarDecl(scope_index, name, .{ .ast_node = idx });
                    },
                    .assign_destructure => {
                        const lhs_count = tree.extra_data[data[idx].lhs];
                        const lhs_exprs = tree.extra_data[data[idx].lhs + 1 ..][0..lhs_count];

                        for (lhs_exprs, 0..) |lhs_node, i| {
                            const var_decl = tree.fullVarDecl(lhs_node) orelse continue;
                            const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                            try context.putVarDecl(scope_index, name, .{
                                .assign_destructure = .{
                                    .node = idx,
                                    .index = @intCast(i),
                                },
                            });
                        }
                    },
                    else => continue,
                }
            }
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node_idx).?;

            const then_start = if_node.payload_token orelse tree.firstToken(if_node.ast.then_expr);
            const then_scope = (try makeBlockScopeAt(context, tree, if_node.ast.then_expr, then_start)).?;

            if (if_node.payload_token) |payload| {
                const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                const decl: Declaration = if (if_node.error_token != null)
                    .{ .error_union_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } }
                else
                    .{ .pointer_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } };
                try context.putVarDecl(then_scope, name, decl);
            }

            if (if_node.ast.else_expr != 0) {
                const else_start = if_node.error_token orelse tree.firstToken(if_node.ast.else_expr);
                const else_scope = (try makeBlockScopeAt(context, tree, if_node.ast.else_expr, else_start)).?;
                if (if_node.error_token) |err_token| {
                    const name = tree.tokenSlice(err_token);
                    try context.putVarDecl(else_scope, name, .{
                        .error_union_error = .{ .name = err_token, .condition = if_node.ast.cond_expr },
                    });
                }
            }
        },
        .@"catch" => {
            try makeScopeInternal(context, tree, data[node_idx].lhs);

            const catch_token = main_tokens[node_idx] + 2;
            if (token_tags.len > catch_token and
                token_tags[catch_token - 1] == .pipe and
                token_tags[catch_token] == .identifier)
            {
                const expr_scope = (try makeBlockScopeAt(context, tree, data[node_idx].rhs, catch_token)).?;
                const name = tree.tokenSlice(catch_token);
                try context.putVarDecl(expr_scope, name, .{
                    .error_union_error = .{ .name = catch_token, .condition = data[node_idx].lhs },
                });
            } else {
                try makeScopeInternal(context, tree, data[node_idx].rhs);
            }
        },
        .@"while",
        .while_simple,
        .while_cont,
        => {
            // label_token: inline_token while (cond_expr) |payload_token| : (cont_expr) then_expr else else_expr
            const while_node = ast.fullWhile(tree, node_idx).?;

            try makeScopeInternal(context, tree, while_node.ast.cond_expr);

            const cont_scope = try makeBlockScopeInternal(context, tree, while_node.ast.cont_expr);

            const then_start = while_node.payload_token orelse tree.firstToken(while_node.ast.then_expr);
            const then_scope = (try makeBlockScopeAt(context, tree, while_node.ast.then_expr, then_start)).?;

            const else_start = while_node.error_token orelse tree.firstToken(while_node.ast.else_expr);
            const else_scope = try makeBlockScopeAt(context, tree, while_node.ast.else_expr, else_start);

            if (while_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);

                const name = try context.putDeclLoopLabel(tree, label, node_idx);
                try context.putVarDecl(then_scope, name, .{ .label_decl = .{ .label = label, .block = while_node.ast.then_expr } });
                if (else_scope) |index| {
                    try context.putVarDecl(index, name, .{ .label_decl = .{ .label = label, .block = while_node.ast.else_expr } });
                }
            }

            if (while_node.payload_token) |payload| {
                const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                const decl: Declaration = if (while_node.error_token != null)
                    .{ .error_union_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } }
                else
                    .{ .pointer_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } };
                if (cont_scope) |index| {
                    try context.putVarDecl(index, name, decl);
                }
                try context.putVarDecl(then_scope, name, decl);
            }

            if (while_node.error_token) |err_token| {
                std.debug.assert(token_tags[err_token] == .identifier);
                const name = tree.tokenSlice(err_token);
                try context.putVarDecl(else_scope.?, name, .{
                    .error_union_error = .{ .name = err_token, .condition = while_node.ast.cond_expr },
                });
            }
        },
        .@"for",
        .for_simple,
        => {
            // label_token: inline_token for (inputs) |capture_tokens| then_expr else else_expr
            const for_node = ast.fullFor(tree, node_idx).?;

            for (for_node.ast.inputs) |input_node| {
                try makeScopeInternal(context, tree, input_node);
            }

            var capture_token = for_node.payload_token;
            const then_scope = (try makeBlockScopeAt(context, tree, for_node.ast.then_expr, capture_token)).?;
            const else_scope = try makeBlockScopeInternal(context, tree, for_node.ast.else_expr);

            for (for_node.ast.inputs) |input| {
                if (capture_token + 1 >= tree.tokens.len) break;
                const capture_is_ref = token_tags[capture_token] == .asterisk;
                const name_token = capture_token + @intFromBool(capture_is_ref);
                capture_token = name_token + 2;

                try context.putVarDecl(
                    then_scope,
                    offsets.tokenToSlice(tree, name_token),
                    .{ .array_payload = .{ .identifier = name_token, .array_expr = input } },
                );
            }

            if (for_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);

                const name = try context.putDeclLoopLabel(tree, label, node_idx);
                try context.putVarDecl(
                    then_scope,
                    name,
                    .{ .label_decl = .{ .label = label, .block = for_node.ast.then_expr } },
                );
                if (else_scope) |index| {
                    try context.putVarDecl(
                        index,
                        name,
                        .{ .label_decl = .{ .label = label, .block = for_node.ast.else_expr } },
                    );
                }
            }
        },
        .@"switch",
        .switch_comma,
        => {
            const extra = tree.extraData(data[node_idx].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases, 0..) |case, case_index| {
                const switch_case: Ast.full.SwitchCase = tree.fullSwitchCase(case).?;

                if (switch_case.payload_token) |payload| {
                    const expr_index = (try makeBlockScopeAt(context, tree, switch_case.ast.target_expr, payload)).?;
                    // if payload is *name than get next token
                    const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                    const name = tree.tokenSlice(name_token);

                    try context.putVarDecl(expr_index, name, .{
                        .switch_payload = .{ .node = node_idx, .case_index = @intCast(case_index) },
                    });
                } else {
                    try makeScopeInternal(context, tree, switch_case.ast.target_expr);
                }
            }
        },
        .@"errdefer" => {
            const payload_token = data[node_idx].lhs;
            const expr_start = if (payload_token != 0) payload_token else tree.firstToken(data[node_idx].rhs);
            const expr_scope = (try makeBlockScopeAt(context, tree, data[node_idx].rhs, expr_start)).?;

            if (payload_token != 0) {
                const name = tree.tokenSlice(payload_token);
                try context.putVarDecl(expr_scope, name, .{
                    .error_union_error = .{ .name = payload_token, .condition = 0 },
                });
            }
        },
        else => {
            try ast.iterateChildren(tree, node_idx, context, error{OutOfMemory}, makeScopeInternal);
        },
    }
}

pub const ReferencedType = struct {
    str: []const u8,
    handle: *const DocumentStore.Handle,
    token: Ast.TokenIndex,

    pub const Collector = struct {
        type_str: ?[]const u8 = null,
        needs_type_reference: bool = true,
        referenced_types: *Set,
        pub fn init(referenced_types: *Set) Collector {
            return .{ .referenced_types = referenced_types };
        }
    };

    pub const Set = std.ArrayHashMap(ReferencedType, void, SetContext, true);

    const SetContext = struct {
        pub fn hash(self: @This(), item: ReferencedType) u32 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(item.str);
            hasher.update(item.handle.uri);
            hasher.update(&std.mem.toBytes(item.token));
            return @truncate(hasher.final());
        }

        pub fn eql(self: @This(), a: ReferencedType, b: ReferencedType, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.mem.eql(u8, a.str, b.str) and
                std.mem.eql(u8, a.handle.uri, b.handle.uri) and
                a.token == b.token;
        }
    };
};

pub fn referencedTypesFromNode(
    analyser: *Analyser,
    node_handle: NodeWithHandle,
    collector: *ReferencedType.Collector,
) error{OutOfMemory}!void {
    analyser.resolved_nodes.clearRetainingCapacity();
    return try analyser.referencedTypesFromNodeInternal(node_handle, collector);
}

fn referencedTypesFromNodeInternal(
    analyser: *Analyser,
    node_handle: NodeWithHandle,
    collector: *ReferencedType.Collector,
) error{OutOfMemory}!void {
    const handle = node_handle.handle;
    const tree = handle.tree;

    var node = node_handle.node;
    collector.type_str = offsets.nodeToSlice(tree, node);

    var call_buf: [1]Ast.Node.Index = undefined;
    const call_maybe = tree.fullCall(&call_buf, node);
    if (call_maybe) |call|
        node = call.ast.fn_expr;

    if (try analyser.resolveVarDeclAlias(.{ .node = node, .handle = handle })) |decl_handle| {
        collector.needs_type_reference = false;
        try collector.referenced_types.put(.{
            .str = offsets.nodeToSlice(tree, node),
            .handle = decl_handle.handle,
            .token = decl_handle.nameToken(),
        }, {});
    }

    if (call_maybe) |call| {
        for (call.ast.params) |param| {
            _ = try analyser.addReferencedTypesFromNode(
                .{ .node = param, .handle = handle },
                collector.referenced_types,
            );
        }
    }
}

pub fn referencedTypes(
    analyser: *Analyser,
    resolved_type: TypeWithHandle,
    resolved_type_str: *[]const u8,
    collector: *ReferencedType.Collector,
) error{OutOfMemory}!void {
    analyser.resolved_nodes.clearRetainingCapacity();
    const allocator = collector.referenced_types.allocator;
    if (resolved_type.type.is_type_val) {
        collector.needs_type_reference = false;
        _ = try analyser.addReferencedTypes(resolved_type, collector.*);
        resolved_type_str.* = switch (resolved_type.type.data) {
            .@"comptime" => |co| try std.fmt.allocPrint(allocator, "{}", .{co.value.index.fmt(co.interpreter.ip.*)}),
            else => "type",
        };
    } else {
        if (try analyser.addReferencedTypes(resolved_type, collector.*)) |str|
            resolved_type_str.* = str;
    }
}

fn addReferencedTypesFromNode(
    analyser: *Analyser,
    node_handle: NodeWithHandle,
    referenced_types: *ReferencedType.Set,
) error{OutOfMemory}!?[]const u8 {
    if (analyser.resolved_nodes.contains(.{ .node = node_handle.node, .uri = node_handle.handle.uri })) return null;
    const type_handle = try analyser.resolveTypeOfNodeInternal(node_handle) orelse return null;
    if (!type_handle.type.is_type_val) return null;
    var collector = ReferencedType.Collector.init(referenced_types);
    try analyser.referencedTypesFromNodeInternal(node_handle, &collector);
    return analyser.addReferencedTypes(type_handle, collector);
}

fn addReferencedTypes(
    analyser: *Analyser,
    type_handle: TypeWithHandle,
    collector: ReferencedType.Collector,
) error{OutOfMemory}!?[]const u8 {
    const type_str = collector.type_str;
    const needs_type_reference = collector.needs_type_reference;
    const referenced_types = collector.referenced_types;
    const allocator = referenced_types.allocator;

    const handle = type_handle.handle;
    const tree = handle.tree;

    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);
    const token_starts = tree.tokens.items(.start);

    switch (type_handle.type.data) {
        .primitive => |name| return name,

        .pointer => |t| {
            const child_type_str = try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types));
            return try std.fmt.allocPrint(allocator, "*{s}", .{child_type_str orelse return null});
        },

        .multi_pointer => |t| {
            const child_type_str = try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types));
            return try std.fmt.allocPrint(allocator, "[*]{s}", .{child_type_str orelse return null});
        },

        .slice => |t| {
            const child_type_str = try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types));
            return try std.fmt.allocPrint(allocator, "[]{s}", .{child_type_str orelse return null});
        },

        .error_union => |t| {
            const rhs_str = try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types));
            return try std.fmt.allocPrint(allocator, "!{s}", .{rhs_str orelse return null});
        },

        .union_tag => |t| {
            const union_type_str = try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types));
            return try std.fmt.allocPrint(allocator, "@typeInfo({s}).Union.tag_type.?", .{union_type_str orelse return null});
        },

        .other => |p| switch (node_tags[p]) {
            .root => {
                const path = URI.parse(allocator, handle.uri) catch |err| switch (err) {
                    error.OutOfMemory => |e| return e,
                    else => return null,
                };
                const str = std.fs.path.stem(path);
                if (needs_type_reference) {
                    try referenced_types.put(.{
                        .str = type_str orelse str,
                        .handle = handle,
                        .token = tree.firstToken(p),
                    }, {});
                }
                return str;
            },

            .container_decl,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .error_set_decl,
            .merge_error_sets,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            => {
                // NOTE: This is a hacky nightmare but it works :P
                const token = tree.firstToken(p);
                if (token >= 2 and token_tags[token - 2] == .identifier and token_tags[token - 1] == .equal) {
                    const str = tree.tokenSlice(token - 2);
                    if (needs_type_reference) {
                        try referenced_types.put(.{
                            .str = type_str orelse str,
                            .handle = handle,
                            .token = token - 2,
                        }, {});
                    }
                    return str;
                }
                if (token >= 1 and token_tags[token - 1] == .keyword_return) {
                    const func_node = innermostBlockScopeInternal(handle.*, token_starts[token - 1], true);
                    var buf: [1]Ast.Node.Index = undefined;
                    const func = tree.fullFnProto(&buf, func_node) orelse return null;
                    const func_name_token = func.name_token orelse return null;
                    const func_name = offsets.tokenToSlice(tree, func_name_token);
                    if (needs_type_reference) {
                        try referenced_types.put(.{
                            .str = type_str orelse func_name,
                            .handle = handle,
                            .token = func_name_token,
                        }, {});
                    }
                    return try std.fmt.allocPrint(allocator, "{s}(...)", .{func_name});
                }
                return offsets.nodeToSlice(tree, p);
            },

            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => {
                var buffer: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buffer, p).?;

                var param_type_strings = std.ArrayList(?[]const u8).init(allocator);
                var it = fn_proto.iterate(&tree);
                while (ast.nextFnParam(&it)) |param| {
                    try param_type_strings.append(try analyser.addReferencedTypesFromNode(
                        .{ .node = param.type_expr, .handle = handle },
                        referenced_types,
                    ));
                }

                const return_type_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = fn_proto.ast.return_type, .handle = handle },
                    referenced_types,
                );

                var str = std.ArrayList(u8).init(allocator);
                const writer = str.writer();
                try writer.print("fn (", .{});
                for (param_type_strings.items, 0..) |param_type_str, param_index| {
                    if (param_index > 0)
                        try writer.print(", ", .{});
                    try writer.print("{s}", .{param_type_str orelse return null});
                }
                try writer.print(") ", .{});
                if (ast.hasInferredError(tree, fn_proto))
                    try writer.print("!", .{});
                try writer.print("{s}", .{return_type_str orelse return null});
                return str.items;
            },

            .array_type,
            .array_type_sentinel,
            => {
                const array_type = tree.fullArrayType(p).?;

                const elem_type_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = array_type.ast.elem_type, .handle = handle },
                    referenced_types,
                );

                const prefix_start = offsets.tokenToIndex(tree, tree.firstToken(p));
                const prefix_end = offsets.tokenToIndex(tree, tree.firstToken(array_type.ast.elem_type));
                return try std.fmt.allocPrint(allocator, "{s}{s}", .{
                    tree.source[prefix_start..prefix_end],
                    elem_type_str orelse return null,
                });
            },

            .ptr_type,
            .ptr_type_aligned,
            .ptr_type_bit_range,
            .ptr_type_sentinel,
            => {
                const ptr_type = ast.fullPtrType(tree, p).?;

                const child_type_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = ptr_type.ast.child_type, .handle = handle },
                    referenced_types,
                );

                const prefix_start = offsets.tokenToIndex(tree, tree.firstToken(p));
                const prefix_end = offsets.tokenToIndex(tree, tree.firstToken(ptr_type.ast.child_type));
                return try std.fmt.allocPrint(allocator, "{s}{s}", .{
                    tree.source[prefix_start..prefix_end],
                    child_type_str orelse return null,
                });
            },

            .optional_type => {
                const child_type_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = datas[p].lhs, .handle = handle },
                    referenced_types,
                );

                return try std.fmt.allocPrint(allocator, "?{s}", .{
                    child_type_str orelse return null,
                });
            },

            .error_union => {
                const lhs_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = datas[p].lhs, .handle = handle },
                    referenced_types,
                );

                const rhs_str = try analyser.addReferencedTypesFromNode(
                    .{ .node = datas[p].rhs, .handle = handle },
                    referenced_types,
                );

                return try std.fmt.allocPrint(allocator, "{s}!{s}", .{
                    lhs_str orelse return null,
                    rhs_str orelse return null,
                });
            },

            .multiline_string_literal => {
                const start = datas[p].lhs;
                const end = datas[p].rhs;
                var len: usize = end - start;
                var tok_i = start;
                while (tok_i <= end) : (tok_i += 1) {
                    const slice = tree.tokenSlice(tok_i);
                    len += slice.len - 3;
                    if (slice[slice.len - 2] == '\r') len -= 1;
                }
                return try std.fmt.allocPrint(allocator, "*const [{d}:0]u8", .{len});
            },

            .string_literal => {
                const token = tree.tokenSlice(main_tokens[p]);
                var counter = std.io.countingWriter(std.io.null_writer);
                return switch (try std.zig.string_literal.parseWrite(counter.writer(), token)) {
                    .success => try std.fmt.allocPrint(allocator, "*const [{d}:0]u8", .{counter.bytes_written}),
                    .failure => null,
                };
            },

            .number_literal, .char_literal => return "comptime_int",

            .enum_literal => return "@TypeOf(.enum_literal)",

            .error_value => {
                const identifier = tree.tokenSlice(datas[p].rhs);
                return try std.fmt.allocPrint(allocator, "error{{{s}}}", .{identifier});
            },

            .identifier => {
                const name = offsets.nodeToSlice(tree, p);
                return primitive_types.get(name);
            },

            else => {}, // TODO: Implement more "other" type expressions; better safe than sorry
        },

        else => {},
    }

    return null;
}
