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

var using_trail: std.ArrayList([*]const u8) = undefined;
var resolve_trail: std.ArrayList(NodeWithHandle) = undefined;
pub fn init(allocator: std.mem.Allocator) void {
    using_trail = std.ArrayList([*]const u8).init(allocator);
    resolve_trail = std.ArrayList(NodeWithHandle).init(allocator);
}
pub fn deinit() void {
    using_trail.deinit();
    resolve_trail.deinit();
}

/// Gets a declaration's doc comments. Caller owns returned memory.
pub fn getDocComments(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index, format: types.MarkupKind) !?[]const u8 {
    const base = tree.nodes.items(.main_token)[node];
    const base_kind = tree.nodes.items(.tag)[node];
    const tokens = tree.tokens.items(.tag);

    switch (base_kind) {
        // As far as I know, this does not actually happen yet, but it
        // may come in useful.
        .root => return try collectDocComments(allocator, tree, 0, format, true),
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
        .container_field,
        => {
            if (getDocCommentTokenIndex(tokens, base)) |doc_comment_index|
                return try collectDocComments(allocator, tree, doc_comment_index, format, false);
        },
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

pub fn collectDocComments(allocator: std.mem.Allocator, tree: Ast, doc_comments: Ast.TokenIndex, format: types.MarkupKind, container_doc: bool) ![]const u8 {
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();
    const tokens = tree.tokens.items(.tag);

    var curr_line_tok = doc_comments;
    while (true) : (curr_line_tok += 1) {
        const comm = tokens[curr_line_tok];
        if ((container_doc and comm == .container_doc_comment) or (!container_doc and comm == .doc_comment)) {
            try lines.append(std.mem.trim(u8, tree.tokenSlice(curr_line_tok)[3..], &std.ascii.whitespace));
        } else break;
    }

    return try std.mem.join(allocator, if (format == .markdown) "  \n" else "\n", lines.items);
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

    var splitit = std.mem.split(u8, data, "}");
    while (splitit.next()) |segment| {
        try writer.writeAll(segment);
        if (splitit.index) |index|
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
pub fn getFunctionSnippet(allocator: std.mem.Allocator, tree: Ast, func: Ast.full.FnProto, skip_self_param: bool) ![]const u8 {
    const name_index = func.name_token.?;

    var buffer = std.ArrayListUnmanaged(u8){};
    try buffer.ensureTotalCapacity(allocator, 128);

    var buf_stream = buffer.writer(allocator);

    try buf_stream.writeAll(tree.tokenSlice(name_index));
    try buf_stream.writeByte('(');

    const token_tags = tree.tokens.items(.tag);

    var it = func.iterate(&tree);
    var i: usize = 0;
    while (ast.nextFnParam(&it)) |param| : (i += 1) {
        if (skip_self_param and i == 0) continue;
        if (i != @boolToInt(skip_self_param))
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

pub fn hasSelfParam(arena: std.mem.Allocator, document_store: *DocumentStore, handle: *const DocumentStore.Handle, func: Ast.full.FnProto) !bool {
    // Non-decl prototypes cannot have a self parameter.
    if (func.name_token == null) return false;
    if (func.ast.params.len == 0) return false;

    const tree = handle.tree;
    var it = func.iterate(&tree);
    const param = ast.nextFnParam(&it).?;
    if (param.type_expr == 0) return false;

    const token_starts = tree.tokens.items(.start);
    const in_container = innermostContainer(handle, token_starts[func.ast.fn_token]);

    if (try resolveTypeOfNode(arena, document_store, .{
        .node = param.type_expr,
        .handle = handle,
    })) |resolved_type| {
        if (std.meta.eql(in_container, resolved_type))
            return true;
    }

    if (ast.fullPtrType(tree, param.type_expr)) |ptr_type| {
        if (try resolveTypeOfNode(arena, document_store, .{
            .node = ptr_type.ast.child_type,
            .handle = handle,
        })) |resolved_prefix_op| {
            if (std.meta.eql(in_container, resolved_prefix_op))
                return true;
        }
    }
    return false;
}

pub fn getVariableSignature(tree: Ast, var_decl: Ast.full.VarDecl) []const u8 {
    const start = offsets.tokenToIndex(tree, var_decl.ast.mut_token);
    const end = offsets.tokenToLoc(tree, ast.lastToken(tree, var_decl.ast.init_node)).end;
    return tree.source[start..end];
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
fn isMetaType(tree: Ast, node: Ast.Node.Index) bool {
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
    const tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_token = tree.nodes.items(.main_token)[node];

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
            const field = tree.fullContainerField(node).?.ast;
            return field.main_token;
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
    const name_token = getDeclNameToken(tree, node) orelse return null;
    const name = offsets.tokenToSlice(tree, name_token);

    if (tree.nodes.items(.tag)[node] == .test_decl and
        tree.tokens.items(.tag)[name_token] == .string_literal)
    {
        return name[1 .. name.len - 1];
    }

    return name;
}

fn resolveVarDeclAliasInternal(arena: std.mem.Allocator, store: *DocumentStore, node_handle: NodeWithHandle, root: bool) error{OutOfMemory}!?DeclWithHandle {
    _ = root;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);

    if (node_tags[node_handle.node] == .identifier) {
        const token = main_tokens[node_handle.node];
        return try lookupSymbolGlobal(
            arena,
            store,
            handle,
            tree.tokenSlice(token),
            tree.tokens.items(.start)[token],
        );
    }

    if (node_tags[node_handle.node] == .field_access) {
        const lhs = datas[node_handle.node].lhs;

        const container_node = if (ast.isBuiltinCall(tree, lhs)) block: {
            const name = tree.tokenSlice(main_tokens[lhs]);
            if (!std.mem.eql(u8, name, "@import") and !std.mem.eql(u8, name, "@cImport"))
                return null;

            const inner_node = (try resolveTypeOfNode(arena, store, .{ .node = lhs, .handle = handle })) orelse return null;
            // assert root node
            std.debug.assert(inner_node.type.data.other == 0);
            break :block NodeWithHandle{ .node = inner_node.type.data.other, .handle = inner_node.handle };
        } else if (try resolveVarDeclAliasInternal(arena, store, .{ .node = lhs, .handle = handle }, false)) |decl_handle| block: {
            if (decl_handle.decl.* != .ast_node) return null;
            const resolved = (try resolveTypeOfNode(arena, store, .{ .node = decl_handle.decl.ast_node, .handle = decl_handle.handle })) orelse return null;
            const resolved_node = switch (resolved.type.data) {
                .other => |n| n,
                else => return null,
            };
            if (!ast.isContainer(resolved.handle.tree, resolved_node)) return null;
            break :block NodeWithHandle{ .node = resolved_node, .handle = resolved.handle };
        } else return null;

        return try lookupSymbolContainer(arena, store, container_node, tree.tokenSlice(datas[node_handle.node].rhs), false);
    }
    return null;
}

/// Resolves variable declarations consisting of chains of imports and field accesses of containers, ending with the same name as the variable decl's name
/// Examples:
///```zig
/// const decl = @import("decl-file.zig").decl;
/// const other = decl.middle.other;
///```
pub fn resolveVarDeclAlias(arena: std.mem.Allocator, store: *DocumentStore, decl_handle: NodeWithHandle) !?DeclWithHandle {
    const decl = decl_handle.node;
    const handle = decl_handle.handle;
    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);
    const node_tags = tree.nodes.items(.tag);

    if (handle.tree.fullVarDecl(decl)) |var_decl| {
        if (var_decl.ast.init_node == 0) return null;
        const base_exp = var_decl.ast.init_node;
        if (token_tags[var_decl.ast.mut_token] != .keyword_const) return null;

        if (node_tags[base_exp] == .field_access) {
            const name = tree.tokenSlice(tree.nodes.items(.data)[base_exp].rhs);
            if (!std.mem.eql(u8, tree.tokenSlice(var_decl.ast.mut_token + 1), name))
                return null;

            return try resolveVarDeclAliasInternal(arena, store, .{ .node = base_exp, .handle = handle }, true);
        }
    }

    return null;
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

pub fn resolveReturnType(arena: std.mem.Allocator, store: *DocumentStore, fn_decl: Ast.full.FnProto, handle: *const DocumentStore.Handle, bound_type_params: *BoundTypeParams, fn_body: ?Ast.Node.Index) !?TypeWithHandle {
    const tree = handle.tree;
    if (isTypeFunction(tree, fn_decl) and fn_body != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(tree, fn_decl, fn_body.?) orelse return null;
        const data = tree.nodes.items(.data)[ret];
        if (data.lhs != 0) {
            return try resolveTypeOfNodeInternal(arena, store, .{
                .node = data.lhs,
                .handle = handle,
            }, bound_type_params);
        }

        return null;
    }

    if (fn_decl.ast.return_type == 0) return null;
    const return_type = fn_decl.ast.return_type;
    const ret = .{ .node = return_type, .handle = handle };
    const child_type = (try resolveTypeOfNodeInternal(arena, store, ret, bound_type_params)) orelse
        return null;

    const is_inferred_error = tree.tokens.items(.tag)[tree.firstToken(return_type) - 1] == .bang;
    if (is_inferred_error) {
        const child_type_node = switch (child_type.type.data) {
            .other => |n| n,
            else => return null,
        };
        return TypeWithHandle{
            .type = .{ .data = .{ .error_union = child_type_node }, .is_type_val = false },
            .handle = child_type.handle,
        };
    } else return child_type.instanceTypeVal();
}

/// Resolves the child type of an optional type
fn resolveUnwrapOptionalType(arena: std.mem.Allocator, store: *DocumentStore, opt: TypeWithHandle, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
    const opt_node = switch (opt.type.data) {
        .other => |n| n,
        else => return null,
    };

    if (opt.handle.tree.nodes.items(.tag)[opt_node] == .optional_type) {
        return ((try resolveTypeOfNodeInternal(arena, store, .{
            .node = opt.handle.tree.nodes.items(.data)[opt_node].lhs,
            .handle = opt.handle,
        }, bound_type_params)) orelse return null).instanceTypeVal();
    }

    return null;
}

fn resolveUnwrapErrorType(arena: std.mem.Allocator, store: *DocumentStore, rhs: TypeWithHandle, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
    const rhs_node = switch (rhs.type.data) {
        .other => |n| n,
        .error_union => |n| return TypeWithHandle{
            .type = .{ .data = .{ .other = n }, .is_type_val = rhs.type.is_type_val },
            .handle = rhs.handle,
        },
        .primitive, .slice, .pointer, .array_index, .@"comptime", .either => return null,
    };

    if (rhs.handle.tree.nodes.items(.tag)[rhs_node] == .error_union) {
        return ((try resolveTypeOfNodeInternal(arena, store, .{
            .node = rhs.handle.tree.nodes.items(.data)[rhs_node].rhs,
            .handle = rhs.handle,
        }, bound_type_params)) orelse return null).instanceTypeVal();
    }

    return null;
}

/// Resolves the child type of a deref type
fn resolveDerefType(arena: std.mem.Allocator, store: *DocumentStore, deref: TypeWithHandle, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
    const deref_node = switch (deref.type.data) {
        .other => |n| n,
        .pointer => |n| return TypeWithHandle{
            .type = .{
                .is_type_val = false,
                .data = .{ .other = n },
            },
            .handle = deref.handle,
        },
        else => return null,
    };
    const tree = deref.handle.tree;
    const main_token = tree.nodes.items(.main_token)[deref_node];
    const token_tag = tree.tokens.items(.tag)[main_token];

    if (ast.fullPtrType(tree, deref_node)) |ptr_type| {
        switch (token_tag) {
            .asterisk => {
                return ((try resolveTypeOfNodeInternal(arena, store, .{
                    .node = ptr_type.ast.child_type,
                    .handle = deref.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            },
            .l_bracket, .asterisk_asterisk => return null,
            else => unreachable,
        }
    }
    return null;
}

/// Resolves slicing and array access
fn resolveBracketAccessType(arena: std.mem.Allocator, store: *DocumentStore, lhs: TypeWithHandle, rhs: enum { Single, Range }, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
    const lhs_node = switch (lhs.type.data) {
        .other => |n| n,
        else => return null,
    };

    const tree = lhs.handle.tree;
    const tags = tree.nodes.items(.tag);
    const tag = tags[lhs_node];
    const data = tree.nodes.items(.data)[lhs_node];

    if (tag == .array_type or tag == .array_type_sentinel) {
        if (rhs == .Single)
            return ((try resolveTypeOfNodeInternal(arena, store, .{
                .node = data.rhs,
                .handle = lhs.handle,
            }, bound_type_params)) orelse return null).instanceTypeVal();
        return TypeWithHandle{
            .type = .{ .data = .{ .slice = data.rhs }, .is_type_val = false },
            .handle = lhs.handle,
        };
    } else if (ast.fullPtrType(tree, lhs_node)) |ptr_type| {
        if (ptr_type.size == .Slice) {
            if (rhs == .Single) {
                return ((try resolveTypeOfNodeInternal(arena, store, .{
                    .node = ptr_type.ast.child_type,
                    .handle = lhs.handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }
            return lhs;
        }
    }

    return null;
}

/// Called to remove one level of pointerness before a field access
pub fn resolveFieldAccessLhsType(arena: std.mem.Allocator, store: *DocumentStore, lhs: TypeWithHandle, bound_type_params: *BoundTypeParams) !TypeWithHandle {
    return (try resolveDerefType(arena, store, lhs, bound_type_params)) orelse lhs;
}

pub const BoundTypeParams = std.AutoHashMapUnmanaged(Ast.full.FnProto.Param, TypeWithHandle);

fn allDigits(str: []const u8) bool {
    for (str) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

pub fn isValueIdent(text: []const u8) bool {
    const PrimitiveTypes = std.ComptimeStringMap(void, .{
        .{"true"},
        .{"false"},
        .{"null"},
        .{"undefined"},
    });
    return PrimitiveTypes.has(text);
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
    });

    if (PrimitiveTypes.has(text)) return true;
    if (text.len == 1) return false;
    if (!(text[0] == 'u' or text[0] == 'i')) return false;
    if (!allDigits(text[1..])) return false;
    _ = std.fmt.parseUnsigned(u16, text[1..], 10) catch return false;
    return true;
}

/// Resolves the type of a node
pub fn resolveTypeOfNodeInternal(
    arena: std.mem.Allocator,
    store: *DocumentStore,
    node_handle: NodeWithHandle,
    bound_type_params: *BoundTypeParams,
) error{OutOfMemory}!?TypeWithHandle {
    // If we were asked to resolve this node before,
    // it is self-referential and we cannot resolve it.
    for (resolve_trail.items) |i| {
        if (std.meta.eql(i, node_handle))
            return null;
    }
    try resolve_trail.append(node_handle);
    defer _ = resolve_trail.pop();

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
                if (try resolveTypeOfNodeInternal(arena, store, decl_type, bound_type_params)) |typ|
                    return typ.instanceTypeVal();
            }
            if (var_decl.ast.init_node == 0)
                return null;

            const value = .{ .node = var_decl.ast.init_node, .handle = handle };
            return try resolveTypeOfNodeInternal(arena, store, value, bound_type_params);
        },
        .identifier => {
            const name = offsets.nodeToSlice(tree, node);

            if (isTypeIdent(name)) {
                return TypeWithHandle{
                    .type = .{ .data = .{ .primitive = node }, .is_type_val = true },
                    .handle = handle,
                };
            }

            if (try lookupSymbolGlobal(
                arena,
                store,
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
                return try child.resolveType(arena, store, bound_type_params);
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
            const decl = (try resolveTypeOfNodeInternal(arena, store, callee, bound_type_params)) orelse
                return null;

            if (decl.type.is_type_val) return null;
            const decl_node = switch (decl.type.data) {
                .other => |n| n,
                else => return null,
            };
            var buf: [1]Ast.Node.Index = undefined;
            const func_maybe = decl.handle.tree.fullFnProto(&buf, decl_node);

            if (func_maybe) |fn_decl| {
                var expected_params = fn_decl.ast.params.len;
                // If we call as method, the first parameter should be skipped
                // TODO: Back-parse to extract the self argument?
                var it = fn_decl.iterate(&decl.handle.tree);
                if (token_tags[call.ast.lparen - 2] == .period) {
                    if (try hasSelfParam(arena, store, decl.handle, fn_decl)) {
                        _ = ast.nextFnParam(&it);
                        expected_params -= 1;
                    }
                }

                // Bind type params to the arguments passed in the call.
                const param_len = std.math.min(call.ast.params.len, expected_params);
                var i: usize = 0;
                while (ast.nextFnParam(&it)) |decl_param| : (i += 1) {
                    if (i >= param_len) break;
                    if (!isMetaType(decl.handle.tree, decl_param.type_expr))
                        continue;

                    const argument = .{ .node = call.ast.params[i], .handle = handle };
                    const argument_type = (try resolveTypeOfNodeInternal(
                        arena,
                        store,
                        argument,
                        bound_type_params,
                    )) orelse
                        continue;
                    if (!argument_type.type.is_type_val) continue;

                    try bound_type_params.put(store.allocator, decl_param, argument_type);
                }

                const has_body = decl.handle.tree.nodes.items(.tag)[decl_node] == .fn_decl;
                const body = decl.handle.tree.nodes.items(.data)[decl_node].rhs;
                if (try resolveReturnType(arena, store, fn_decl, decl.handle, bound_type_params, if (has_body) body else null)) |ret| {
                    return ret;
                } else if (store.config.use_comptime_interpreter) {
                    // TODO: Better case-by-case; we just use the ComptimeInterpreter when all else fails,
                    // probably better to use it more liberally
                    // TODO: Handle non-isolate args; e.g. `const T = u8; TypeFunc(T);`
                    // var interpreter = ComptimeInterpreter{ .tree = tree, .allocator = arena.allocator() };

                    // var top_decl = try (try interpreter.interpret(0, null, .{})).getValue();
                    // var top_scope = interpreter.typeToTypeInfo(top_decl.@"type".info_idx).@"struct".scope;

                    // var fn_decl_scope = top_scope.getParentScopeFromNode(node);

                    log.info("Invoking interpreter!", .{});

                    const interpreter = store.ensureInterpreterExists(handle.uri) catch |err| {
                        log.err("Failed to interpret file: {s}", .{@errorName(err)});
                        if (@errorReturnTrace()) |trace| {
                            std.debug.dumpStackTrace(trace.*);
                        }
                        return null;
                    };

                    const root_namespace = @intToEnum(ComptimeInterpreter.Namespace.Index, 0);

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
            }
            return null;
        },
        .@"comptime",
        .@"nosuspend",
        .grouped_expression,
        .container_field,
        .container_field_init,
        .container_field_align,
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
            const base = .{ .node = datas[node].lhs, .handle = handle };
            const base_type = (try resolveTypeOfNodeInternal(arena, store, base, bound_type_params)) orelse
                return null;
            return switch (node_tags[node]) {
                .@"comptime",
                .@"nosuspend",
                .grouped_expression,
                => base_type,
                .container_field,
                .container_field_init,
                .container_field_align,
                .struct_init,
                .struct_init_comma,
                .struct_init_one,
                .struct_init_one_comma,
                => base_type.instanceTypeVal(),
                .slice,
                .slice_sentinel,
                .slice_open,
                => try resolveBracketAccessType(arena, store, base_type, .Range, bound_type_params),
                .deref => try resolveDerefType(arena, store, base_type, bound_type_params),
                .unwrap_optional => try resolveUnwrapOptionalType(arena, store, base_type, bound_type_params),
                .array_access => try resolveBracketAccessType(arena, store, base_type, .Single, bound_type_params),
                .@"orelse" => try resolveUnwrapOptionalType(arena, store, base_type, bound_type_params),
                .@"catch" => try resolveUnwrapErrorType(arena, store, base_type, bound_type_params),
                .@"try" => try resolveUnwrapErrorType(arena, store, base_type, bound_type_params),
                .address_of => {
                    const lhs_node = switch (base_type.type.data) {
                        .other => |n| n,
                        else => return null,
                    };
                    return TypeWithHandle{
                        .type = .{ .data = .{ .pointer = lhs_node }, .is_type_val = base_type.type.is_type_val },
                        .handle = base_type.handle,
                    };
                },
                else => unreachable,
            };
        },
        .field_access => {
            if (datas[node].rhs == 0) return null;

            // If we are accessing a pointer type, remove one pointerness level :)
            const left_type = try resolveFieldAccessLhsType(
                arena,
                store,
                (try resolveTypeOfNodeInternal(arena, store, .{
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
                arena,
                store,
                .{ .node = left_type_node, .handle = left_type.handle },
                tree.tokenSlice(datas[node].rhs),
                !left_type.type.is_type_val,
            )) |child| {
                return try child.resolveType(arena, store, bound_type_params);
            } else return null;
        },
        .array_type,
        .array_type_sentinel,
        .optional_type,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .error_union,
        .error_set_decl,
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
                return ((try resolveTypeOfNodeInternal(arena, store, .{
                    .node = params[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null).instanceTypeVal();
            }

            // Almost the same as the above, return a type value though.
            // TODO Do peer type resolution, we just keep the first for now.
            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len < 1) return null;
                var resolved_type = (try resolveTypeOfNodeInternal(arena, store, .{
                    .node = params[0],
                    .handle = handle,
                }, bound_type_params)) orelse return null;

                if (resolved_type.type.is_type_val) return null;
                resolved_type.type.is_type_val = true;
                return resolved_type;
            }

            if (std.mem.eql(u8, call_name, "@typeInfo")) {
                const zig_lib_path = try URI.fromPath(store.allocator, store.config.zig_lib_path orelse return null);
                defer store.allocator.free(zig_lib_path);

                const builtin_uri = URI.pathRelative(store.allocator, zig_lib_path, "/std/builtin.zig") catch |err| switch (err) {
                    error.OutOfMemory => |e| return e,
                    else => return null,
                };
                defer store.allocator.free(builtin_uri);

                const new_handle = store.getOrLoadHandle(builtin_uri) orelse return null;
                const root_scope_decls = new_handle.document_scope.scopes.items(.decls)[0];
                const decl = root_scope_decls.get("Type") orelse return null;
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
                const import_uri = (try store.uriFromImportStr(store.allocator, handle.*, import_str[1 .. import_str.len - 1])) orelse return null;
                defer store.allocator.free(import_uri);

                const new_handle = store.getOrLoadHandle(import_uri) orelse return null;

                // reference to node '0' which is root
                return TypeWithHandle.typeVal(.{ .node = 0, .handle = new_handle });
            } else if (std.mem.eql(u8, call_name, "@cImport")) {
                const cimport_uri = (try store.resolveCImport(handle.*, node)) orelse return null;

                const new_handle = store.getOrLoadHandle(cimport_uri) orelse return null;

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
        => return TypeWithHandle{
            .type = .{ .data = .{ .other = node }, .is_type_val = false },
            .handle = handle,
        },
        .@"if", .if_simple => {
            const if_node = ast.fullIf(tree, node).?;

            // TODO: Fix allocator need
            var either = std.ArrayList(Type.EitherEntry).init(arena);
            if (try resolveTypeOfNodeInternal(arena, store, .{ .handle = handle, .node = if_node.ast.then_expr }, bound_type_params)) |t|
                try either.append(.{ .type_with_handle = t, .descriptor = tree.getNodeSource(if_node.ast.cond_expr) });
            if (try resolveTypeOfNodeInternal(arena, store, .{ .handle = handle, .node = if_node.ast.else_expr }, bound_type_params)) |t|
                try either.append(.{ .type_with_handle = t, .descriptor = try std.fmt.allocPrint(arena, "!({s})", .{tree.getNodeSource(if_node.ast.cond_expr)}) });

            return TypeWithHandle{
                .type = .{ .data = .{ .either = try either.toOwnedSlice() }, .is_type_val = false },
                .handle = handle,
            };
        },
        .@"switch",
        .switch_comma,
        => {
            const extra = tree.extraData(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            var either = std.ArrayList(Type.EitherEntry).init(arena);

            for (cases) |case| {
                const switch_case = tree.fullSwitchCase(case).?;
                var descriptor = std.ArrayList(u8).init(arena);

                for (switch_case.ast.values, 0..) |vals, index| {
                    try descriptor.appendSlice(tree.getNodeSource(vals));
                    if (index != switch_case.ast.values.len - 1) try descriptor.appendSlice(", ");
                }

                if (try resolveTypeOfNodeInternal(arena, store, .{ .handle = handle, .node = switch_case.ast.target_expr }, bound_type_params)) |t|
                    try either.append(.{
                        .type_with_handle = t,
                        .descriptor = try descriptor.toOwnedSlice(),
                    });
            }

            return TypeWithHandle{
                .type = .{ .data = .{ .either = try either.toOwnedSlice() }, .is_type_val = false },
                .handle = handle,
            };
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
        pointer: Ast.Node.Index,
        slice: Ast.Node.Index,
        error_union: Ast.Node.Index,
        other: Ast.Node.Index,
        primitive: Ast.Node.Index,
        either: []const EitherEntry,
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

    pub fn typeVal(node_handle: NodeWithHandle) TypeWithHandle {
        return .{
            .type = .{
                .data = .{ .other = node_handle.node },
                .is_type_val = true,
            },
            .handle = node_handle.handle,
        };
    }

    /// Resolves possible types of a type (single for all except array_index and either)
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
};

pub fn resolveTypeOfNode(
    arena: std.mem.Allocator,
    store: *DocumentStore,
    node_handle: NodeWithHandle,
) error{OutOfMemory}!?TypeWithHandle {
    var bound_type_params = BoundTypeParams{};
    defer bound_type_params.deinit(store.allocator);
    return resolveTypeOfNodeInternal(arena, store, node_handle, &bound_type_params);
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
        const text = tree.tokenSlice(@intCast(u32, i));

        if (std.mem.eql(u8, text, "@import")) {
            if (i + 3 >= tags.len)
                break;
            if (tags[i + 1] != .l_paren)
                continue;
            if (tags[i + 2] != .string_literal)
                continue;
            if (tags[i + 3] != .r_paren)
                continue;

            const str = tree.tokenSlice(@intCast(u32, i + 2));
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
        const node = @intCast(Ast.Node.Index, i);
        if (!ast.isBuiltinCall(tree, node)) continue;

        if (!std.mem.eql(u8, Ast.tokenSlice(tree, main_tokens[node]), "@cImport")) continue;

        try import_nodes.append(allocator, node);
    }

    return import_nodes.toOwnedSlice(allocator);
}

pub const NodeWithHandle = struct {
    node: Ast.Node.Index,
    handle: *const DocumentStore.Handle,
};

pub const FieldAccessReturn = struct {
    original: TypeWithHandle,
    unwrapped: ?TypeWithHandle = null,
};

pub fn getFieldAccessType(arena: std.mem.Allocator, store: *DocumentStore, handle: *const DocumentStore.Handle, source_index: usize, tokenizer: *std.zig.Tokenizer) !?FieldAccessReturn {
    var current_type: ?TypeWithHandle = null;

    var bound_type_params = BoundTypeParams{};
    defer bound_type_params.deinit(store.allocator);

    while (true) {
        const tok = tokenizer.next();
        switch (tok.tag) {
            .eof => return FieldAccessReturn{
                .original = current_type orelse return null,
                .unwrapped = try resolveDerefType(arena, store, current_type orelse return null, &bound_type_params),
            },
            .identifier => {
                const ct_handle = if (current_type) |c| c.handle else handle;
                if (try lookupSymbolGlobal(
                    arena,
                    store,
                    ct_handle,
                    tokenizer.buffer[tok.loc.start..tok.loc.end],
                    source_index,
                )) |child| {
                    current_type = (try child.resolveType(arena, store, &bound_type_params)) orelse return null;
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
                                .unwrapped = try resolveDerefType(arena, store, ct, &bound_type_params),
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
                                    .unwrapped = try resolveDerefType(arena, store, ct, &bound_type_params),
                                };
                            } else {
                                return null;
                            }
                        }

                        current_type = try resolveFieldAccessLhsType(arena, store, current_type orelse return null, &bound_type_params);

                        const current_type_nodes = try current_type.?.getAllTypesWithHandles(arena);

                        // TODO: Return all options instead of first valid one
                        // (this would require a huge rewrite and im lazy)
                        for (current_type_nodes) |ty| {
                            const current_type_node = switch (ty.type.data) {
                                .other => |n| n,
                                else => continue,
                            };

                            if (try lookupSymbolContainer(
                                arena,
                                store,
                                .{ .node = current_type_node, .handle = ty.handle },
                                tokenizer.buffer[after_period.loc.start..after_period.loc.end],
                                !current_type.?.type.is_type_val,
                            )) |child| {
                                current_type.? = (try child.resolveType(
                                    arena,
                                    store,
                                    &bound_type_params,
                                )) orelse continue;
                                break;
                            } else continue;
                        } else {
                            return null;
                        }
                    },
                    .question_mark => {
                        current_type = (try resolveUnwrapOptionalType(
                            arena,
                            store,
                            current_type orelse return null,
                            &bound_type_params,
                        )) orelse return null;
                    },
                    else => {
                        log.debug("Unrecognized token {} after period.", .{after_period.tag});
                        return null;
                    },
                }
            },
            .period_asterisk => {
                current_type = (try resolveDerefType(
                    arena,
                    store,
                    current_type orelse return null,
                    &bound_type_params,
                )) orelse return null;
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
                    if (try resolveReturnType(arena, store, func, current_type.?.handle, &bound_type_params, if (has_body) body else null)) |ret| {
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

                current_type = (try resolveBracketAccessType(arena, store, current_type orelse return null, if (is_range) .Range else .Single, &bound_type_params)) orelse return null;
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
            .unwrapped = try resolveDerefType(arena, store, ct, &bound_type_params),
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

fn nodeContainsSourceIndex(tree: Ast, node: Ast.Node.Index, source_index: usize) bool {
    const loc = offsets.nodeToLoc(tree, node);
    return source_index >= loc.start and source_index <= loc.end;
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
    enum_literal,
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
/// Classification is based on the lexical structure -- we fetch the line containin index, tokenize it,
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

    const line_loc = if (!lookahead) offsets.lineLocAtIndex(text, new_index) else offsets.lineLocUntilIndex(text, new_index);
    const line = offsets.locToSlice(text, line_loc);
    const prev_char = if (new_index > 0) text[new_index - 1] else 0;

    const is_comment = std.mem.startsWith(u8, std.mem.trimLeft(u8, line, " \t"), "//");
    if (is_comment) return .comment;

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
                // Tie-breaking, the curosr is exactly between two tokens, and
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
                    .label => {},
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

pub const Declaration = union(enum) {
    /// Index of the ast node
    ast_node: Ast.Node.Index,
    /// Function parameter
    param_payload: struct {
        param: Ast.full.FnProto.Param,
        func: Ast.Node.Index,
    },
    pointer_payload: struct {
        name: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    array_payload: struct {
        identifier: Ast.TokenIndex,
        array_expr: Ast.Node.Index,
    },
    array_index: Ast.TokenIndex,
    switch_payload: struct {
        node: Ast.TokenIndex,
        switch_expr: Ast.Node.Index,
        items: []const Ast.Node.Index,
    },
    label_decl: struct {
        label: Ast.TokenIndex,
        block: Ast.Node.Index,
    },
    /// always an identifier
    error_token: Ast.Node.Index,
};

pub const DeclWithHandle = struct {
    decl: *Declaration,
    handle: *const DocumentStore.Handle,

    pub fn nameToken(self: DeclWithHandle) Ast.TokenIndex {
        const tree = self.handle.tree;
        return switch (self.decl.*) {
            .ast_node => |n| getDeclNameToken(tree, n).?,
            .param_payload => |pp| pp.param.name_token.?,
            .pointer_payload => |pp| pp.name,
            .array_payload => |ap| ap.identifier,
            .array_index => |ai| ai,
            .switch_payload => |sp| sp.node,
            .label_decl => |ld| ld.label,
            .error_token => |et| et,
        };
    }

    fn isPublic(self: DeclWithHandle) bool {
        return switch (self.decl.*) {
            .ast_node => |node| isNodePublic(self.handle.tree, node),
            else => true,
        };
    }

    pub fn resolveType(self: DeclWithHandle, arena: std.mem.Allocator, store: *DocumentStore, bound_type_params: *BoundTypeParams) !?TypeWithHandle {
        const tree = self.handle.tree;
        const node_tags = tree.nodes.items(.tag);
        const main_tokens = tree.nodes.items(.main_token);
        return switch (self.decl.*) {
            .ast_node => |node| try resolveTypeOfNodeInternal(
                arena,
                store,
                .{ .node = node, .handle = self.handle },
                bound_type_params,
            ),
            .param_payload => |pay| {
                const param_decl = pay.param;
                if (isMetaType(self.handle.tree, param_decl.type_expr)) {
                    var bound_param_it = bound_type_params.iterator();
                    while (bound_param_it.next()) |entry| {
                        if (std.meta.eql(entry.key_ptr.*, param_decl)) return entry.value_ptr.*;
                    }
                    return null;
                } else if (node_tags[param_decl.type_expr] == .identifier) {
                    if (param_decl.name_token) |name_tok| {
                        if (std.mem.eql(u8, tree.tokenSlice(main_tokens[param_decl.type_expr]), tree.tokenSlice(name_tok)))
                            return null;
                    }
                }
                return ((try resolveTypeOfNodeInternal(
                    arena,
                    store,
                    .{ .node = param_decl.type_expr, .handle = self.handle },
                    bound_type_params,
                )) orelse return null).instanceTypeVal();
            },
            .pointer_payload => |pay| try resolveUnwrapOptionalType(
                arena,
                store,
                (try resolveTypeOfNodeInternal(arena, store, .{
                    .node = pay.condition,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null,
                bound_type_params,
            ),
            .array_payload => |pay| try resolveBracketAccessType(
                arena,
                store,
                (try resolveTypeOfNodeInternal(arena, store, .{
                    .node = pay.array_expr,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null,
                .Single,
                bound_type_params,
            ),
            .array_index => TypeWithHandle{
                .type = .{ .data = .array_index, .is_type_val = false },
                .handle = self.handle,
            },
            .label_decl => return null,
            .switch_payload => |pay| {
                if (pay.items.len == 0) return null;
                // TODO Peer type resolution, we just use the first item for now.
                const switch_expr_type = (try resolveTypeOfNodeInternal(arena, store, .{
                    .node = pay.switch_expr,
                    .handle = self.handle,
                }, bound_type_params)) orelse return null;
                if (!switch_expr_type.isUnionType())
                    return null;

                if (node_tags[pay.items[0]] != .enum_literal) return null;

                const scope_index = findContainerScopeIndex(.{ .node = switch_expr_type.type.data.other, .handle = switch_expr_type.handle }) orelse return null;
                const scope_decls = switch_expr_type.handle.document_scope.scopes.items(.decls);

                const candidate = scope_decls[scope_index].getEntry(tree.tokenSlice(main_tokens[pay.items[0]])) orelse return null;

                switch (candidate.value_ptr.*) {
                    .ast_node => |node| {
                        if (switch_expr_type.handle.tree.fullContainerField(node)) |container_field| {
                            if (container_field.ast.type_expr != 0) {
                                return ((try resolveTypeOfNodeInternal(
                                    arena,
                                    store,
                                    .{ .node = container_field.ast.type_expr, .handle = switch_expr_type.handle },
                                    bound_type_params,
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

fn iterateSymbolsContainerInternal(arena: std.mem.Allocator, store: *DocumentStore, container_handle: NodeWithHandle, orig_handle: *const DocumentStore.Handle, comptime callback: anytype, context: anytype, instance_access: bool, use_trail: *std.ArrayList(Ast.Node.Index)) error{OutOfMemory}!void {
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

    var decl_it = scope_decls[container_scope_index].iterator();
    while (decl_it.next()) |entry| {
        switch (entry.value_ptr.*) {
            .ast_node => |node| {
                if (node_tags[node].isContainerField()) {
                    if (!instance_access and !is_enum) continue;
                    if (instance_access and is_enum) continue;
                } else if (node_tags[node] == .global_var_decl or
                    node_tags[node] == .local_var_decl or
                    node_tags[node] == .simple_var_decl or
                    node_tags[node] == .aligned_var_decl)
                {
                    if (instance_access) continue;
                }
            },
            .label_decl => continue,
            else => {},
        }

        const decl = DeclWithHandle{ .decl = entry.value_ptr, .handle = handle };
        if (handle != orig_handle and !decl.isPublic()) continue;
        try callback(context, decl);
    }

    for (scope_uses[container_scope_index].items) |use| {
        const use_token = tree.nodes.items(.main_token)[use];
        const is_pub = use_token > 0 and token_tags[use_token - 1] == .keyword_pub;
        if (handle != orig_handle and !is_pub) continue;
        if (std.mem.indexOfScalar(Ast.Node.Index, use_trail.items, use) != null) continue;
        try use_trail.append(use);

        const lhs = tree.nodes.items(.data)[use].lhs;
        const use_expr = (try resolveTypeOfNode(arena, store, .{
            .node = lhs,
            .handle = handle,
        })) orelse continue;

        const use_expr_node = switch (use_expr.type.data) {
            .other => |n| n,
            else => continue,
        };
        try iterateSymbolsContainerInternal(
            arena,
            store,
            .{ .node = use_expr_node, .handle = use_expr.handle },
            orig_handle,
            callback,
            context,
            false,
            use_trail,
        );
    }
}

pub const EnclosingScopeIterator = struct {
    scope_locs: []offsets.Loc,
    current_scope: usize,
    source_index: usize,

    pub fn next(self: *EnclosingScopeIterator) ?usize {
        while (self.current_scope < self.scope_locs.len) : (self.current_scope += 1) {
            const scope_loc = self.scope_locs[self.current_scope];

            if (self.source_index >= scope_loc.start and self.source_index <= scope_loc.end) {
                defer self.current_scope += 1;
                return self.current_scope;
            }
            if (scope_loc.start >= self.source_index) {
                self.current_scope = self.scope_locs.len;
                return null;
            }
        }
        return null;
    }
};

pub fn iterateEnclosingScopes(document_scope: DocumentScope, source_index: usize) EnclosingScopeIterator {
    return .{
        .scope_locs = document_scope.scopes.items(.loc),
        .current_scope = 0,
        .source_index = source_index,
    };
}

pub fn iterateSymbolsContainer(arena: std.mem.Allocator, store: *DocumentStore, container_handle: NodeWithHandle, orig_handle: *const DocumentStore.Handle, comptime callback: anytype, context: anytype, instance_access: bool) error{OutOfMemory}!void {
    var use_trail = std.ArrayList(Ast.Node.Index).init(store.allocator);
    defer use_trail.deinit();
    return try iterateSymbolsContainerInternal(arena, store, container_handle, orig_handle, callback, context, instance_access, &use_trail);
}

pub fn iterateLabels(handle: *const DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype) error{OutOfMemory}!void {
    const scope_decls = handle.document_scope.scopes.items(.decls);

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        var decl_it = scope_decls[scope_index].iterator();
        while (decl_it.next()) |entry| {
            switch (entry.value_ptr.*) {
                .label_decl => {},
                else => continue,
            }
            try callback(context, DeclWithHandle{ .decl = entry.value_ptr, .handle = handle });
        }
    }
}

fn iterateSymbolsGlobalInternal(arena: std.mem.Allocator, store: *DocumentStore, handle: *const DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype, use_trail: *std.ArrayList(Ast.Node.Index)) error{OutOfMemory}!void {
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        var decl_it = scope_decls[scope_index].iterator();
        while (decl_it.next()) |entry| {
            if (entry.value_ptr.* == .ast_node and
                handle.tree.nodes.items(.tag)[entry.value_ptr.*.ast_node].isContainerField()) continue;
            if (entry.value_ptr.* == .label_decl) continue;
            try callback(context, DeclWithHandle{ .decl = entry.value_ptr, .handle = handle });
        }

        for (scope_uses[scope_index].items) |use| {
            if (std.mem.indexOfScalar(Ast.Node.Index, use_trail.items, use) != null) continue;
            try use_trail.append(use);

            const use_expr = (try resolveTypeOfNode(
                arena,
                store,
                .{ .node = handle.tree.nodes.items(.data)[use].lhs, .handle = handle },
            )) orelse continue;
            const use_expr_node = switch (use_expr.type.data) {
                .other => |n| n,
                else => continue,
            };
            try iterateSymbolsContainerInternal(
                arena,
                store,
                .{ .node = use_expr_node, .handle = use_expr.handle },
                handle,
                callback,
                context,
                false,
                use_trail,
            );
        }
    }
}

pub fn iterateSymbolsGlobal(arena: std.mem.Allocator, store: *DocumentStore, handle: *const DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype) error{OutOfMemory}!void {
    var use_trail = std.ArrayList(Ast.Node.Index).init(store.allocator);
    defer use_trail.deinit();
    return try iterateSymbolsGlobalInternal(arena, store, handle, source_index, callback, context, &use_trail);
}

pub fn innermostBlockScopeIndex(handle: DocumentStore.Handle, source_index: usize) usize {
    if (handle.document_scope.scopes.len == 1) return 0;

    const scope_locs = handle.document_scope.scopes.items(.loc);
    const scope_datas = handle.document_scope.scopes.items(.data);

    var innermost: usize = 0;
    var scope_index: usize = 1;
    while (scope_index < handle.document_scope.scopes.len) : (scope_index += 1) {
        const scope_loc = scope_locs[scope_index];
        if (source_index >= scope_loc.start and source_index <= scope_loc.end) {
            switch (scope_datas[scope_index]) {
                .container, .function, .block => innermost = scope_index,
                else => {},
            }
        }
        if (scope_loc.start > source_index) break;
    }
    return innermost;
}

pub fn innermostBlockScope(handle: DocumentStore.Handle, source_index: usize) Ast.Node.Index {
    const scope_index = innermostBlockScopeIndex(handle, source_index);
    return handle.document_scope.scopes.items(.data)[scope_index].toNodeIndex().?;
}

pub fn innermostContainer(handle: *const DocumentStore.Handle, source_index: usize) TypeWithHandle {
    const scope_datas = handle.document_scope.scopes.items(.data);

    var current = scope_datas[0].container;
    if (handle.document_scope.scopes.len == 1) return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });

    var scope_iterator = iterateEnclosingScopes(handle.document_scope, source_index);
    while (scope_iterator.next()) |scope_index| {
        switch (scope_datas[scope_index]) {
            .container => |node| current = node,
            else => {},
        }
    }
    return TypeWithHandle.typeVal(.{ .node = current, .handle = handle });
}

fn resolveUse(arena: std.mem.Allocator, store: *DocumentStore, uses: []const Ast.Node.Index, symbol: []const u8, handle: *const DocumentStore.Handle) error{OutOfMemory}!?DeclWithHandle {
    if (uses.len == 0) return null;

    // If we were asked to resolve this symbol before,
    // it is self-referential and we cannot resolve it.
    if (std.mem.indexOfScalar([*]const u8, using_trail.items, symbol.ptr) != null)
        return null;
    try using_trail.append(symbol.ptr);
    defer _ = using_trail.pop();

    for (uses) |index| {
        if (handle.tree.nodes.items(.data).len <= index) continue;

        const expr = .{ .node = handle.tree.nodes.items(.data)[index].lhs, .handle = handle };
        const expr_type_node = (try resolveTypeOfNode(arena, store, expr)) orelse
            continue;

        const expr_type = .{
            .node = switch (expr_type_node.type.data) {
                .other => |n| n,
                else => continue,
            },
            .handle = expr_type_node.handle,
        };

        if (try lookupSymbolContainer(arena, store, expr_type, symbol, false)) |candidate| {
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
        const candidate = scope_decls[scope_index].getEntry(symbol) orelse continue;

        switch (candidate.value_ptr.*) {
            .label_decl => {},
            else => continue,
        }
        return DeclWithHandle{
            .decl = candidate.value_ptr,
            .handle = handle,
        };
    }
    return null;
}

pub fn lookupSymbolGlobal(arena: std.mem.Allocator, store: *DocumentStore, handle: *const DocumentStore.Handle, symbol: []const u8, source_index: usize) error{OutOfMemory}!?DeclWithHandle {
    const innermost_scope_idx = innermostBlockScopeIndex(handle.*, source_index);

    const scope_locs = handle.document_scope.scopes.items(.loc);
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);

    var curr = innermost_scope_idx;
    while (curr >= 0) : (curr -= 1) {
        const scope_loc = scope_locs[curr];
        if (source_index >= scope_loc.start and source_index <= scope_loc.end) blk: {
            if (scope_decls[curr].getEntry(symbol)) |candidate| {
                switch (candidate.value_ptr.*) {
                    .ast_node => |node| {
                        if (handle.tree.nodes.items(.tag)[node].isContainerField()) break :blk;
                    },
                    .label_decl => break :blk,
                    else => {},
                }
                return DeclWithHandle{
                    .decl = candidate.value_ptr,
                    .handle = handle,
                };
            }
            if (try resolveUse(arena, store, scope_uses[curr].items, symbol, handle)) |result| return result;
        }
        if (curr == 0) break;
    }
    return null;
}

pub fn lookupSymbolContainer(
    arena: std.mem.Allocator,
    store: *DocumentStore,
    container_handle: NodeWithHandle,
    symbol: []const u8,
    /// If true, we are looking up the symbol like we are accessing through a field access
    /// of an instance of the type, otherwise as a field access of the type value itself.
    instance_access: bool,
) error{OutOfMemory}!?DeclWithHandle {
    const container = container_handle.node;
    const handle = container_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const main_token = tree.nodes.items(.main_token)[container];

    const is_enum = token_tags[main_token] == .keyword_enum;
    const scope_decls = handle.document_scope.scopes.items(.decls);
    const scope_uses = handle.document_scope.scopes.items(.uses);

    if (findContainerScopeIndex(container_handle)) |container_scope_index| {
        if (scope_decls[container_scope_index].getEntry(symbol)) |candidate| {
            switch (candidate.value_ptr.*) {
                .ast_node => |node| {
                    if (node_tags[node].isContainerField()) {
                        if (!instance_access and !is_enum) return null;
                        if (instance_access and is_enum) return null;
                    }
                },
                .label_decl => unreachable,
                else => {},
            }
            return DeclWithHandle{ .decl = candidate.value_ptr, .handle = handle };
        }

        if (try resolveUse(arena, store, scope_uses[container_scope_index].items, symbol, handle)) |result| return result;
    }

    return null;
}

const CompletionContext = struct {
    pub fn hash(self: @This(), item: types.CompletionItem) u32 {
        _ = self;
        return @truncate(u32, std.hash.Wyhash.hash(0, item.label));
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
    scopes: std.MultiArrayList(Scope),
    error_completions: CompletionSet,
    enum_completions: CompletionSet,

    pub fn deinit(self: *DocumentScope, allocator: std.mem.Allocator) void {
        var i: usize = 0;
        while (i < self.scopes.len) : (i += 1) {
            self.scopes.items(.decls)[i].deinit(allocator);
            self.scopes.items(.tests)[i].deinit(allocator);
            self.scopes.items(.uses)[i].deinit(allocator);
        }
        self.scopes.deinit(allocator);

        for (self.error_completions.entries.items(.key)) |item| {
            if (item.detail) |detail| allocator.free(detail);
            switch (item.documentation orelse continue) {
                .string => |str| allocator.free(str),
                .MarkupContent => |content| allocator.free(content.value),
            }
        }
        self.error_completions.deinit(allocator);
        for (self.enum_completions.entries.items(.key)) |item| {
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

    loc: offsets.Loc,
    decls: std.StringHashMapUnmanaged(Declaration) = .{},
    tests: std.ArrayListUnmanaged(Ast.Node.Index) = .{},
    uses: std.ArrayListUnmanaged(Ast.Node.Index) = .{},
    data: Data,
};

pub fn makeDocumentScope(allocator: std.mem.Allocator, tree: Ast) !DocumentScope {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var document_scope = DocumentScope{
        .scopes = .{},
        .error_completions = .{},
        .enum_completions = .{},
    };
    errdefer document_scope.deinit(allocator);

    // pass root node index ('0')
    had_root = false;
    try makeScopeInternal(allocator, .{
        .scopes = &document_scope.scopes,
        .errors = &document_scope.error_completions,
        .enums = &document_scope.enum_completions,
        .tree = tree,
    }, 0);

    return document_scope;
}

const ScopeContext = struct {
    scopes: *std.MultiArrayList(Scope),
    enums: *CompletionSet,
    errors: *CompletionSet,
    tree: Ast,
};

fn makeInnerScope(allocator: std.mem.Allocator, context: ScopeContext, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const scopes = context.scopes;
    const tree = context.tree;
    const tags = tree.nodes.items(.tag);

    try scopes.append(allocator, .{
        .loc = offsets.nodeToLoc(tree, node_idx),
        .data = .{ .container = node_idx },
    });
    const scope_index = scopes.len - 1;

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node_idx).?;
    for (container_decl.ast.members) |decl| {
        if (tags[decl] == .@"usingnamespace") {
            try scopes.items(.uses)[scope_index].append(allocator, decl);
            continue;
        }

        try makeScopeInternal(allocator, context, decl);
        const name = getDeclName(tree, decl) orelse continue;

        if (tags[decl] == .test_decl) {
            try scopes.items(.tests)[scope_index].append(allocator, decl);
            continue;
        }
        if (try scopes.items(.decls)[scope_index].fetchPut(allocator, name, .{ .ast_node = decl })) |existing| {
            _ = existing;
            // TODO Record a redefinition error.
        }

        if (container_decl.ast.enum_token != null) {
            if (std.mem.eql(u8, name, "_")) return;
            const Documentation = @TypeOf(@as(types.CompletionItem, undefined).documentation);

            var doc: Documentation = if (try getDocComments(allocator, tree, decl, .markdown)) |docs| .{ .MarkupContent = types.MarkupContent{ .kind = .markdown, .value = docs } } else null;
            var gop_res = try context.enums.getOrPut(allocator, .{
                .label = name,
                .kind = .Constant,
                .insertText = name,
                .insertTextFormat = .PlainText,
                .documentation = doc,
            });
            if (gop_res.found_existing) {
                if (doc) |d| allocator.free(d.MarkupContent.value);
            }
        }
    }
}

// Whether we have already visited the root node.
var had_root = true;
fn makeScopeInternal(allocator: std.mem.Allocator, context: ScopeContext, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    const scopes = context.scopes;
    const tree = context.tree;
    const tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const node_tag = tags[node_idx];

    if (node_idx == 0) {
        if (had_root)
            return
        else
            had_root = true;
    }

    switch (node_tag) {
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
        => {
            try makeInnerScope(allocator, context, node_idx);
        },
        .error_set_decl => {
            try scopes.append(allocator, .{
                .loc = offsets.nodeToLoc(tree, node_idx),
                .data = .{ .container = node_idx },
            });
            const scope_index = scopes.len - 1;

            // All identifiers in main_token..data.rhs are error fields.
            var tok_i = main_tokens[node_idx] + 2;
            while (tok_i < data[node_idx].rhs) : (tok_i += 1) {
                switch (token_tags[tok_i]) {
                    .doc_comment, .comma => {},
                    .identifier => {
                        const name = offsets.tokenToSlice(tree, tok_i);
                        if (try scopes.items(.decls)[scope_index].fetchPut(allocator, name, .{ .error_token = tok_i })) |_| {
                            // TODO Record a redefinition error.
                        }
                        const gop = try context.errors.getOrPut(allocator, .{
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
        .array_type_sentinel => {
            // TODO: ???
            return;
        },
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => |fn_tag| {
            var buf: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buf, node_idx).?;

            try scopes.append(allocator, .{
                .loc = offsets.nodeToLoc(tree, node_idx),
                .data = .{ .function = node_idx },
            });
            const scope_index = scopes.len - 1;

            var it = func.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| {
                // Add parameter decls
                if (param.name_token) |name_token| {
                    if (try scopes.items(.decls)[scope_index].fetchPut(
                        allocator,
                        tree.tokenSlice(name_token),
                        .{ .param_payload = .{ .param = param, .func = node_idx } },
                    )) |existing| {
                        _ = existing;
                        // TODO record a redefinition error
                    }
                }
                // Visit parameter types to pick up any error sets and enum
                //   completions
                try makeScopeInternal(allocator, context, param.type_expr);
            }

            if (fn_tag == .fn_decl) blk: {
                if (data[node_idx].lhs == 0) break :blk;
                const return_type_node = data[data[node_idx].lhs].rhs;

                // Visit the return type
                try makeScopeInternal(allocator, context, return_type_node);
            }

            // Visit the function body
            try makeScopeInternal(allocator, context, data[node_idx].rhs);
        },
        .test_decl => {
            return try makeScopeInternal(allocator, context, data[node_idx].rhs);
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            const first_token = tree.firstToken(node_idx);
            const last_token = ast.lastToken(tree, node_idx);

            // if labeled block
            if (token_tags[first_token] == .identifier) {
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, main_tokens[node_idx]),
                        .end = offsets.tokenToLoc(tree, last_token).start,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;
                try scopes.items(.decls)[scope_index].putNoClobber(allocator, tree.tokenSlice(first_token), .{ .label_decl = .{
                    .label = first_token,
                    .block = node_idx,
                } });
            }

            try scopes.append(allocator, .{
                .loc = offsets.nodeToLoc(tree, node_idx),
                .data = .{ .block = node_idx },
            });
            const scope_index = scopes.len - 1;

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                try makeScopeInternal(allocator, context, idx);
                if (tree.fullVarDecl(idx)) |var_decl| {
                    const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                    if (try scopes.items(.decls)[scope_index].fetchPut(allocator, name, .{ .ast_node = idx })) |existing| {
                        _ = existing;
                        // TODO record a redefinition error.
                    }
                }
            }

            return;
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node_idx).?;

            if (if_node.payload_token) |payload| {
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, payload),
                        .end = offsets.tokenToLoc(tree, ast.lastToken(tree, if_node.ast.then_expr)).end,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;

                const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{
                    .pointer_payload = .{
                        .name = name_token,
                        .condition = if_node.ast.cond_expr,
                    },
                });
            }

            try makeScopeInternal(allocator, context, if_node.ast.then_expr);

            if (if_node.ast.else_expr != 0) {
                if (if_node.error_token) |err_token| {
                    std.debug.assert(token_tags[err_token] == .identifier);
                    try scopes.append(allocator, .{
                        .loc = .{
                            .start = offsets.tokenToIndex(tree, err_token),
                            .end = offsets.tokenToLoc(tree, ast.lastToken(tree, if_node.ast.else_expr)).end,
                        },
                        .data = .other,
                    });
                    const scope_index = scopes.len - 1;

                    const name = tree.tokenSlice(err_token);
                    try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{ .ast_node = if_node.ast.else_expr });
                }
                try makeScopeInternal(allocator, context, if_node.ast.else_expr);
            }
        },
        .@"catch" => {
            try makeScopeInternal(allocator, context, data[node_idx].lhs);

            const catch_token = main_tokens[node_idx];
            const catch_expr = data[node_idx].rhs;

            try scopes.append(allocator, .{
                .loc = .{
                    .start = offsets.tokenToIndex(tree, tree.firstToken(catch_expr)),
                    .end = offsets.tokenToLoc(tree, ast.lastToken(tree, catch_expr)).end,
                },
                .data = .other,
            });
            const scope_index = scopes.len - 1;

            if (token_tags.len > catch_token + 2 and
                token_tags[catch_token + 1] == .pipe and
                token_tags[catch_token + 2] == .identifier)
            {
                const name = tree.tokenSlice(catch_token + 2);
                try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{ .ast_node = catch_expr });
            }
            try makeScopeInternal(allocator, context, catch_expr);
        },
        .@"while",
        .while_simple,
        .while_cont,
        => {
            const while_node = ast.fullWhile(tree, node_idx).?;

            if (while_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, while_node.ast.while_token),
                        .end = offsets.tokenToLoc(tree, ast.lastToken(tree, node_idx)).end,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;

                try scopes.items(.decls)[scope_index].putNoClobber(allocator, tree.tokenSlice(label), .{ .label_decl = .{
                    .label = label,
                    .block = while_node.ast.then_expr,
                } });
            }

            if (while_node.payload_token) |payload| {
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, payload),
                        .end = offsets.tokenToLoc(tree, ast.lastToken(tree, while_node.ast.then_expr)).end,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;

                const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{
                    .pointer_payload = .{
                        .name = name_token,
                        .condition = while_node.ast.cond_expr,
                    },
                });

                // for loop with index as well
                if (token_tags[name_token + 1] == .comma) {
                    const index_token = name_token + 2;
                    std.debug.assert(token_tags[index_token] == .identifier);
                    if (try scopes.items(.decls)[scope_index].fetchPut(
                        allocator,
                        tree.tokenSlice(index_token),
                        .{ .array_index = index_token },
                    )) |existing| {
                        _ = existing;
                        // TODO Record a redefinition error
                    }
                }
            }
            try makeScopeInternal(allocator, context, while_node.ast.then_expr);

            if (while_node.ast.else_expr != 0) {
                if (while_node.error_token) |err_token| {
                    std.debug.assert(token_tags[err_token] == .identifier);
                    try scopes.append(allocator, .{
                        .loc = .{
                            .start = offsets.tokenToIndex(tree, err_token),
                            .end = offsets.tokenToLoc(tree, ast.lastToken(tree, while_node.ast.else_expr)).end,
                        },
                        .data = .other,
                    });
                    const scope_index = scopes.len - 1;

                    const name = tree.tokenSlice(err_token);
                    try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{ .ast_node = while_node.ast.else_expr });
                }
                try makeScopeInternal(allocator, context, while_node.ast.else_expr);
            }
        },
        .@"for",
        .for_simple,
        => {
            const for_node = ast.fullFor(tree, node_idx).?;

            if (for_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, for_node.ast.for_token),
                        .end = offsets.tokenToLoc(tree, ast.lastToken(tree, node_idx)).end,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;

                try scopes.items(.decls)[scope_index].putNoClobber(allocator, tree.tokenSlice(label), .{ .label_decl = .{
                    .label = label,
                    .block = for_node.ast.then_expr,
                } });
            }

            try scopes.append(allocator, .{
                .loc = .{
                    .start = offsets.tokenToIndex(tree, for_node.payload_token),
                    .end = offsets.tokenToLoc(tree, ast.lastToken(tree, for_node.ast.then_expr)).end,
                },
                .data = .other,
            });
            const scope_index = scopes.len - 1;

            var capture_token = for_node.payload_token;
            for (for_node.ast.inputs) |input| {
                if (capture_token + 1 >= tree.tokens.len) break;
                const capture_is_ref = token_tags[capture_token] == .asterisk;
                const name_token = capture_token + @boolToInt(capture_is_ref);
                capture_token = name_token + 2;

                const name = offsets.tokenToSlice(tree, name_token);
                try scopes.items(.decls)[scope_index].put(allocator, name, .{
                    .array_payload = .{
                        .identifier = name_token,
                        .array_expr = input,
                    },
                });
            }

            try makeScopeInternal(allocator, context, for_node.ast.then_expr);

            if (for_node.ast.else_expr != 0) {
                try makeScopeInternal(allocator, context, for_node.ast.else_expr);
            }
        },
        .@"switch",
        .switch_comma,
        => {
            const cond = data[node_idx].lhs;
            const extra = tree.extraData(data[node_idx].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases) |case| {
                const switch_case: Ast.full.SwitchCase = tree.fullSwitchCase(case).?;

                if (switch_case.payload_token) |payload| {
                    try scopes.append(allocator, .{
                        .loc = .{
                            .start = offsets.tokenToIndex(tree, payload),
                            .end = offsets.tokenToLoc(tree, ast.lastToken(tree, switch_case.ast.target_expr)).end,
                        },
                        .data = .other,
                    });
                    const scope_index = scopes.len - 1;

                    // if payload is *name than get next token
                    const name_token = payload + @boolToInt(token_tags[payload] == .asterisk);
                    const name = tree.tokenSlice(name_token);

                    try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{
                        .switch_payload = .{
                            .node = name_token,
                            .switch_expr = cond,
                            .items = switch_case.ast.values,
                        },
                    });
                }

                try makeScopeInternal(allocator, context, switch_case.ast.target_expr);
            }
        },
        .switch_case,
        .switch_case_inline,
        .switch_case_one,
        .switch_case_inline_one,
        .switch_range,
        => {
            return;
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node_idx).?;
            if (var_decl.ast.type_node != 0) {
                try makeScopeInternal(allocator, context, var_decl.ast.type_node);
            }

            if (var_decl.ast.init_node != 0) {
                try makeScopeInternal(allocator, context, var_decl.ast.init_node);
            }
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        .async_call,
        .async_call_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&buf, node_idx).?;

            try makeScopeInternal(allocator, context, call.ast.fn_expr);
            for (call.ast.params) |param|
                try makeScopeInternal(allocator, context, param);
        },
        .struct_init,
        .struct_init_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init: Ast.full.StructInit = tree.fullStructInit(&buf, node_idx).?;

            if (struct_init.ast.type_expr != 0)
                try makeScopeInternal(allocator, context, struct_init.ast.type_expr);

            for (struct_init.ast.fields) |field| {
                try makeScopeInternal(allocator, context, field);
            }
        },
        .array_init,
        .array_init_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_one,
        .array_init_one_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const array_init: Ast.full.ArrayInit = tree.fullArrayInit(&buf, node_idx).?;

            if (array_init.ast.type_expr != 0)
                try makeScopeInternal(allocator, context, array_init.ast.type_expr);
            for (array_init.ast.elements) |elem| {
                try makeScopeInternal(allocator, context, elem);
            }
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = tree.fullContainerField(node_idx).?;

            try makeScopeInternal(allocator, context, field.ast.type_expr);
            try makeScopeInternal(allocator, context, field.ast.align_expr);
            try makeScopeInternal(allocator, context, field.ast.value_expr);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node_idx, &buffer).?;

            for (params) |param| {
                try makeScopeInternal(allocator, context, param);
            }
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type: Ast.full.PtrType = ast.fullPtrType(tree, node_idx).?;

            try makeScopeInternal(allocator, context, ptr_type.ast.sentinel);
            try makeScopeInternal(allocator, context, ptr_type.ast.align_node);
            try makeScopeInternal(allocator, context, ptr_type.ast.child_type);
        },
        .slice,
        .slice_open,
        .slice_sentinel,
        => {
            const slice: Ast.full.Slice = tree.fullSlice(node_idx).?;

            try makeScopeInternal(allocator, context, slice.ast.sliced);
            try makeScopeInternal(allocator, context, slice.ast.start);
            try makeScopeInternal(allocator, context, slice.ast.end);
            try makeScopeInternal(allocator, context, slice.ast.sentinel);
        },
        .@"errdefer" => {
            const expr = data[node_idx].rhs;
            if (data[node_idx].lhs != 0) {
                const payload_token = data[node_idx].lhs;
                try scopes.append(allocator, .{
                    .loc = .{
                        .start = offsets.tokenToIndex(tree, payload_token),
                        .end = offsets.tokenToLoc(tree, ast.lastToken(tree, expr)).end,
                    },
                    .data = .other,
                });
                const scope_index = scopes.len - 1;

                const name = tree.tokenSlice(payload_token);
                try scopes.items(.decls)[scope_index].putNoClobber(allocator, name, .{ .ast_node = expr });
            }

            try makeScopeInternal(allocator, context, expr);
        },

        .@"asm",
        .asm_simple,
        .asm_output,
        .asm_input,
        .error_value,
        .multiline_string_literal,
        .string_literal,
        .enum_literal,
        .identifier,
        .anyframe_type,
        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .@"continue",
        => {},
        .@"break", .@"defer" => {
            try makeScopeInternal(allocator, context, data[node_idx].rhs);
        },

        .@"return",
        .@"resume",
        .field_access,
        .@"suspend",
        .deref,
        .@"try",
        .@"await",
        .optional_type,
        .@"comptime",
        .@"nosuspend",
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .grouped_expression,
        .unwrap_optional,
        .@"usingnamespace",
        => {
            try makeScopeInternal(allocator, context, data[node_idx].lhs);
        },

        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign_shl_sat,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .add_sat,
        .sub_sat,
        .shl,
        .shl_sat,
        .shr,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .array_type,
        .array_access,
        .error_union,
        .for_range,
        => {
            try makeScopeInternal(allocator, context, data[node_idx].lhs);
            try makeScopeInternal(allocator, context, data[node_idx].rhs);
        },
    }
}
