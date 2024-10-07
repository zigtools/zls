//! The ZLS analysis backend.
//!
//! The most frequently used functions are:
//! - `resolveTypeOfNode`
//! - `getPositionContext`
//! - `lookupSymbolGlobal`
//! - `lookupSymbolContainer`
//!

const std = @import("std");
const DocumentStore = @import("DocumentStore.zig");
const Ast = std.zig.Ast;
const offsets = @import("offsets.zig");
const URI = @import("uri.zig");
const log = std.log.scoped(.zls_analysis);
const ast = @import("ast.zig");
const tracy = @import("tracy");
const InternPool = @import("analyser/InternPool.zig");
const references = @import("features/references.zig");

pub const DocumentScope = @import("DocumentScope.zig");
pub const Declaration = DocumentScope.Declaration;
pub const Scope = DocumentScope.Scope;

const Analyser = @This();

gpa: std.mem.Allocator,
arena: std.heap.ArenaAllocator,
store: *DocumentStore,
ip: *InternPool,
bound_type_params: std.AutoHashMapUnmanaged(Declaration.Param, Type) = .{},
resolved_callsites: std.AutoHashMapUnmanaged(Declaration.Param, ?Type) = .{},
resolved_nodes: std.HashMapUnmanaged(NodeWithUri, ?Type, NodeWithUri.Context, std.hash_map.default_max_load_percentage) = .{},
/// used to detect recursion
use_trail: NodeSet = .{},
collect_callsite_references: bool,
/// avoid unnecessarily parsing number literals
resolve_number_literal_values: bool,
/// handle of the doc where the request originated
root_handle: ?*DocumentStore.Handle,

const NodeSet = std.HashMapUnmanaged(NodeWithUri, void, NodeWithUri.Context, std.hash_map.default_max_load_percentage);

pub fn init(
    gpa: std.mem.Allocator,
    store: *DocumentStore,
    ip: *InternPool,
    root_handle: ?*DocumentStore.Handle,
) Analyser {
    return .{
        .gpa = gpa,
        .arena = std.heap.ArenaAllocator.init(gpa),
        .store = store,
        .ip = ip,
        .collect_callsite_references = true,
        .resolve_number_literal_values = false,
        .root_handle = root_handle,
    };
}

pub fn deinit(self: *Analyser) void {
    self.bound_type_params.deinit(self.gpa);
    self.resolved_callsites.deinit(self.gpa);
    self.resolved_nodes.deinit(self.gpa);
    std.debug.assert(self.use_trail.count() == 0);
    self.use_trail.deinit(self.gpa);
    self.arena.deinit();
}

pub fn getDocCommentsBeforeToken(allocator: std.mem.Allocator, tree: Ast, base: Ast.TokenIndex) error{OutOfMemory}!?[]const u8 {
    const tokens = tree.tokens.items(.tag);
    const doc_comment_index = getDocCommentTokenIndex(tokens, base) orelse return null;
    return try collectDocComments(allocator, tree, doc_comment_index, false);
}

/// Gets a declaration's doc comments. Caller owns returned memory.
pub fn getDocComments(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}!?[]const u8 {
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

pub fn collectDocComments(allocator: std.mem.Allocator, tree: Ast, doc_comments: Ast.TokenIndex, container_doc: bool) error{OutOfMemory}![]const u8 {
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
    const first_token = func.ast.fn_token;
    const last_token = if (func.ast.return_type != 0) ast.lastToken(tree, func.ast.return_type) else first_token;
    return offsets.tokensToSlice(tree, first_token, last_token);
}

fn formatSnippetPlaceholder(
    data: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, data);
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

fn fmtSnippetPlaceholder(bytes: []const u8) std.fmt.Formatter(formatSnippetPlaceholder) {
    return .{ .data = bytes };
}

pub const FormatFunctionOptions = struct {
    fn_proto: Ast.full.FnProto,
    tree: *const Ast,

    include_fn_keyword: bool,
    /// only included if available
    include_name: bool,
    override_name: ?[]const u8 = null,
    skip_first_param: bool = false,
    parameters: union(enum) {
        collapse,
        show: struct {
            include_modifiers: bool,
            include_names: bool,
            include_types: bool,
        },
    },
    include_return_type: bool,
    snippet_placeholders: bool,
};

pub fn formatFunction(
    data: FormatFunctionOptions,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, data);
    _ = options;

    const tree = data.tree;
    var it = data.fn_proto.iterate(data.tree);

    if (data.include_fn_keyword) {
        try writer.writeAll("fn ");
    }

    if (data.include_name) {
        if (data.override_name) |name| {
            try writer.writeAll(name);
        } else if (data.fn_proto.name_token) |name_token| {
            try writer.writeAll(tree.tokenSlice(name_token));
        }
    }

    try writer.writeByte('(');

    const token_tags = tree.tokens.items(.tag);

    if (data.skip_first_param) {
        _ = ast.nextFnParam(&it);
    }

    switch (data.parameters) {
        .collapse => {
            const has_arguments = ast.nextFnParam(&it) != null;
            if (has_arguments) {
                if (data.snippet_placeholders) {
                    try writer.writeAll("${1:...}");
                } else {
                    try writer.writeAll("...");
                }
            }
        },
        .show => |parameter_options| {
            var i: usize = 0;
            while (ast.nextFnParam(&it)) |param| : (i += 1) {
                if (i != 0) {
                    try writer.writeAll(", ");
                }

                if (data.snippet_placeholders) {
                    try writer.print("${{{d}:", .{i + 1});
                }

                // Note that parameter doc comments are being skipped

                if (parameter_options.include_modifiers) {
                    if (param.comptime_noalias) |token_index| {
                        switch (token_tags[token_index]) {
                            .keyword_comptime => try writer.writeAll("comptime "),
                            .keyword_noalias => try writer.writeAll("noalias "),
                            else => unreachable,
                        }
                    }
                }

                if (parameter_options.include_names) {
                    if (param.name_token) |name_token| {
                        const name = tree.tokenSlice(name_token);
                        if (data.snippet_placeholders) {
                            try writer.print("{}", .{fmtSnippetPlaceholder(name)});
                        } else {
                            try writer.writeAll(name);
                        }
                    }
                }

                if (parameter_options.include_types) {
                    const has_parameter_name = parameter_options.include_names and param.name_token != null;
                    if (has_parameter_name) try writer.writeAll(": ");

                    if (param.type_expr != 0) {
                        if (data.snippet_placeholders) {
                            var curr_token = tree.firstToken(param.type_expr);
                            const end_token = ast.lastToken(tree.*, param.type_expr);
                            while (curr_token <= end_token) : (curr_token += 1) {
                                const tag = token_tags[curr_token];
                                const is_comma = tag == .comma;

                                if (curr_token == end_token and is_comma) continue;
                                try writer.print("{}", .{fmtSnippetPlaceholder(tree.tokenSlice(curr_token))});
                                if (is_comma or tag == .keyword_const) try writer.writeByte(' ');
                            }
                        } else {
                            try writer.writeAll(offsets.nodeToSlice(tree.*, param.type_expr));
                        }
                    } else if (param.anytype_ellipsis3) |token_index| {
                        switch (token_tags[token_index]) {
                            .keyword_anytype => try writer.writeAll("anytype"),
                            .ellipsis3 => try writer.writeAll("..."),
                            else => unreachable,
                        }
                    }
                }

                if (data.snippet_placeholders) {
                    try writer.writeByte('}');
                }
            }
        },
    }
    try writer.writeByte(')');

    // ignoring align_expr
    // ignoring addrspace_expr
    // ignoring section_expr
    // ignoring callconv_expr

    if (data.include_return_type) {
        if (data.fn_proto.ast.return_type != 0) {
            try writer.writeByte(' ');
            if (ast.hasInferredError(tree.*, data.fn_proto)) {
                try writer.writeByte('!');
            }
            try writer.writeAll(offsets.nodeToSlice(tree.*, data.fn_proto.ast.return_type));
        }
    }
}

pub fn fmtFunction(options: FormatFunctionOptions) std.fmt.Formatter(formatFunction) {
    return .{ .data = options };
}

pub fn isInstanceCall(
    analyser: *Analyser,
    call_handle: *DocumentStore.Handle,
    call: Ast.full.Call,
    func_ty: Type,
) error{OutOfMemory}!bool {
    std.debug.assert(!func_ty.is_type_val);
    if (call_handle.tree.nodes.items(.tag)[call.ast.fn_expr] != .field_access) return false;

    const container_node = NodeWithHandle{ .node = call_handle.tree.nodes.items(.data)[call.ast.fn_expr].lhs, .handle = call_handle };

    const container_ty = if (try analyser.resolveTypeOfNodeInternal(container_node)) |container_instance|
        container_instance.typeOf(analyser)
    else blk: {
        const func_node = func_ty.data.other; // this assumes that function types can only be Ast nodes
        const fn_token = func_node.handle.tree.nodes.items(.main_token)[func_node.node];
        break :blk try innermostContainer(func_node.handle, func_node.handle.tree.tokens.items(.start)[fn_token]);
    };

    std.debug.assert(container_ty.is_type_val);

    return analyser.firstParamIs(func_ty, container_ty);
}

pub fn hasSelfParam(analyser: *Analyser, func_ty: Type) error{OutOfMemory}!bool {
    const func_node = func_ty.data.other; // this assumes that function types can only be Ast nodes
    const fn_token = func_node.handle.tree.nodes.items(.main_token)[func_node.node];
    const in_container = try innermostContainer(func_node.handle, func_node.handle.tree.tokens.items(.start)[fn_token]);
    std.debug.assert(in_container.is_type_val);
    if (in_container.isNamespace()) return false;
    return analyser.firstParamIs(func_ty, in_container);
}

pub fn firstParamIs(
    analyser: *Analyser,
    func_type: Type,
    expected_type: Type,
) error{OutOfMemory}!bool {
    std.debug.assert(func_type.isFunc());
    const func_handle = func_type.data.other;

    var buffer: [1]Ast.Node.Index = undefined;
    const func = func_handle.handle.tree.fullFnProto(&buffer, func_handle.node).?;

    var it = func.iterate(&func_handle.handle.tree);
    const param = ast.nextFnParam(&it) orelse return false;
    if (param.anytype_ellipsis3) |token| {
        if (func_handle.handle.tree.tokens.items(.tag)[token] == .keyword_anytype) return true;
    }
    if (param.type_expr == 0) return false;

    const resolved_type = try analyser.resolveTypeOfNodeInternal(.{
        .node = param.type_expr,
        .handle = func_handle.handle,
    }) orelse return false;
    if (!resolved_type.is_type_val) return false;

    const deref_type = switch (resolved_type.data) {
        .pointer => |info| switch (info.size) {
            .One => info.elem_ty.*,
            .Many, .Slice, .C => return false,
        },
        else => resolved_type,
    };

    const deref_expected_type = switch (expected_type.data) {
        .pointer => |info| switch (info.size) {
            .One => info.elem_ty.*,
            .Many, .Slice, .C => return false,
        },
        else => expected_type,
    };

    return deref_type.eql(deref_expected_type);
}

pub fn getVariableSignature(
    arena: std.mem.Allocator,
    tree: Ast,
    var_decl: Ast.full.VarDecl,
    include_name: bool,
) error{OutOfMemory}![]const u8 {
    const node_tags = tree.nodes.items(.tag);

    const start_token = if (include_name)
        var_decl.ast.mut_token
    else if (var_decl.ast.type_node != 0)
        tree.firstToken(var_decl.ast.type_node)
    else
        tree.firstToken(var_decl.ast.init_node);

    const init_node = var_decl.ast.init_node;
    if (var_decl.ast.init_node == 0) {
        if (var_decl.ast.type_node == 0) return "";
        return offsets.tokensToSlice(tree, start_token, ast.lastToken(tree, var_decl.ast.type_node));
    }

    const end_token = switch (node_tags[init_node]) {
        .merge_error_sets => {
            if (!include_name) return "error";
            return try std.fmt.allocPrint(arena, "{s} error", .{
                offsets.tokensToSlice(tree, start_token, tree.firstToken(init_node) - 1),
            });
        },
        .error_set_decl => tree.firstToken(init_node),
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => end_token: {
            var buf: [2]Ast.Node.Index = undefined;
            const container_decl = tree.fullContainerDecl(&buf, init_node).?;

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

            if (container_decl.ast.members.len == 0) break :end_token token + offset;

            // e.g. 'pub const Mode = enum { zig, zon };'
            if (tree.tokensOnSameLine(tree.firstToken(init_node), tree.lastToken(init_node))) {
                break :end_token ast.lastToken(tree, init_node);
            }

            var members_source = std.ArrayList(u8).init(arena);

            for (container_decl.ast.members) |member| {
                const member_line_start = offsets.lineLocUntilIndex(tree.source, offsets.tokenToIndex(tree, tree.firstToken(member))).start;

                const member_source_indented = switch (tree.nodes.items(.tag)[member]) {
                    .container_field_init,
                    .container_field_align,
                    .container_field,
                    => tree.source[member_line_start..offsets.tokenToLoc(tree, ast.lastToken(tree, member)).end],
                    else => continue,
                };
                try members_source.append('\n');
                try members_source.appendSlice(try trimCommonIndentation(arena, member_source_indented, 4));
                try members_source.append(',');
            }

            if (members_source.items.len == 0) break :end_token token + offset;

            return try std.mem.concat(arena, u8, &.{
                offsets.tokensToSlice(tree, start_token, token + offset),
                " {",
                members_source.items,
                "\n}",
            });
        },
        else => ast.lastToken(tree, init_node),
    };

    return offsets.tokensToSlice(tree, start_token, end_token);
}

fn trimCommonIndentation(allocator: std.mem.Allocator, str: []const u8, preserved_indentation_amount: usize) error{OutOfMemory}![]u8 {
    var line_it = std.mem.splitScalar(u8, str, '\n');

    var non_empty_lines: usize = 0;
    var min_indentation: ?usize = null;
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        const indentation = for (line, 0..) |c, count| {
            if (!std.ascii.isWhitespace(c)) break count;
        } else line.len;
        min_indentation = if (min_indentation) |old| @min(old, indentation) else indentation;
        non_empty_lines += 1;
    }

    var common_indent = min_indentation orelse return try allocator.dupe(u8, str);
    common_indent -|= preserved_indentation_amount;
    if (common_indent == 0) return try allocator.dupe(u8, str);

    const capacity = str.len - non_empty_lines * common_indent;
    var output = try std.ArrayListUnmanaged(u8).initCapacity(allocator, capacity);
    std.debug.assert(capacity == output.capacity);
    errdefer @compileError("error would leak here");

    line_it = std.mem.splitScalar(u8, str, '\n');
    var is_first_line = true;
    while (line_it.next()) |line| {
        if (!is_first_line) output.appendAssumeCapacity('\n');
        if (line.len != 0) {
            output.appendSliceAssumeCapacity(line[common_indent..]);
        }
        is_first_line = false;
    }

    std.debug.assert(output.items.len == output.capacity);
    return output.items;
}

test trimCommonIndentation {
    const cases = [_]struct { []const u8, []const u8, usize }{
        .{ "", "", 0 },
        .{ "\n", "\n", 0 },
        .{ "foo", "foo", 0 },
        .{ "foo", "  foo", 0 },
        .{ "foo  ", "    foo  ", 0 },
        .{ "foo\nbar", "    foo\n    bar", 0 },
        .{ "foo\nbar\n", "  foo\n  bar\n", 0 },
        .{ "  foo\nbar", "    foo\n  bar", 0 },
        .{ "foo\n  bar", "    foo\n      bar", 0 },
        .{ "  foo\n\nbar", "    foo\n\n  bar", 0 },

        .{ "  foo\n  bar", "    foo\n    bar", 2 },
        .{ "    foo\n    bar", "    foo\n    bar", 4 },
        .{ "    foo\n    bar", "    foo\n    bar", 8 },
    };

    for (cases) |case| {
        const actual = try trimCommonIndentation(std.testing.allocator, case[1], case[2]);
        defer std.testing.allocator.free(actual);
        try std.testing.expectEqualStrings(case[0], actual);
    }
}

pub fn getContainerFieldSignature(tree: Ast, field: Ast.full.ContainerField) ?[]const u8 {
    if (field.ast.type_expr == 0) return null;
    const end_node = if (field.ast.value_expr != 0) field.ast.value_expr else if (field.ast.align_expr != 0) field.ast.align_expr else field.ast.type_expr;

    const first_token = tree.firstToken(field.ast.type_expr);
    const last_token = ast.lastToken(tree, end_node);
    return offsets.tokensToSlice(tree, first_token, last_token);
}

/// Returns whether the given `node` is the identifier `type`.
pub fn isMetaType(tree: Ast, node: Ast.Node.Index) bool {
    if (tree.nodes.items(.tag)[node] == .identifier) {
        return std.mem.eql(u8, tree.tokenSlice(tree.nodes.items(.main_token)[node]), "type");
    }
    return false;
}

/// Returns whether the given function returns a `type`.
pub fn isTypeFunction(tree: Ast, func: Ast.full.FnProto) bool {
    return isMetaType(tree, func.ast.return_type);
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

/// if the `source_index` points to `@name`, the source location of `name` without the `@` is returned.
/// if the `source_index` points to `@"name"`, the source location of `name` is returned.
pub fn identifierLocFromIndex(tree: Ast, source_index: usize) ?offsets.Loc {
    const token = offsets.sourceIndexToTokenIndex(tree, source_index);
    switch (tree.tokens.items(.tag)[token]) {
        .identifier,
        .builtin,
        => {
            const token_loc = offsets.tokenToLoc(tree, token);
            if (!(token_loc.start <= source_index and source_index <= token_loc.end)) return null;
            return offsets.identifierIndexToNameLoc(tree.source, tree.tokens.items(.start)[token]);
        },
        else => {},
    }

    var start = source_index;
    while (start > 0 and isSymbolChar(tree.source[start - 1])) {
        start -= 1;
    }

    var end = source_index;
    while (end < tree.source.len and isSymbolChar(tree.source[end])) {
        end += 1;
    }

    if (start == end) return null;
    return .{ .start = start, .end = end };
}

test identifierLocFromIndex {
    var tree = try Ast.parse(std.testing.allocator,
        \\ name  @builtin  @"escaped"  @"s p a c e"  end
    , .zig);
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(
        std.zig.Token.Tag,
        &.{ .identifier, .builtin, .identifier, .identifier, .identifier, .eof },
        tree.tokens.items(.tag),
    );

    {
        const expected_loc: offsets.Loc = .{ .start = 1, .end = 5 };
        std.debug.assert(std.mem.eql(u8, "name", offsets.locToSlice(tree.source, expected_loc)));

        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 1));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 2));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 5));
    }

    {
        const expected_loc: offsets.Loc = .{ .start = 8, .end = 15 };
        std.debug.assert(std.mem.eql(u8, "builtin", offsets.locToSlice(tree.source, expected_loc)));

        try std.testing.expectEqual(@as(?offsets.Loc, null), identifierLocFromIndex(tree, 6));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 7));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 8));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 11));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 15));
        try std.testing.expectEqual(@as(?offsets.Loc, null), identifierLocFromIndex(tree, 16));
    }

    {
        const expected_loc: offsets.Loc = .{ .start = 19, .end = 26 };
        std.debug.assert(std.mem.eql(u8, "escaped", offsets.locToSlice(tree.source, expected_loc)));

        try std.testing.expectEqual(@as(?offsets.Loc, null), identifierLocFromIndex(tree, 16));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 17));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 18));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 19));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 23));
        try std.testing.expectEqual(expected_loc, identifierLocFromIndex(tree, 27));
        try std.testing.expectEqual(@as(?offsets.Loc, null), identifierLocFromIndex(tree, 28));
    }

    {
        const expected_loc: offsets.Loc = .{ .start = 43, .end = 46 };
        std.debug.assert(std.mem.eql(u8, "end", offsets.locToSlice(tree.source, expected_loc)));

        try std.testing.expectEqual(@as(?offsets.Loc, null), identifierLocFromIndex(tree, 42));
        try std.testing.expectEqual(@as(?offsets.Loc, expected_loc), identifierLocFromIndex(tree, 43));
        try std.testing.expectEqual(@as(?offsets.Loc, expected_loc), identifierLocFromIndex(tree, 45));
        try std.testing.expectEqual(@as(?offsets.Loc, expected_loc), identifierLocFromIndex(tree, 46));
    }
}

/// Resolves variable declarations consisting of chains of imports and field accesses of containers
/// Examples:
///```zig
/// const decl = @import("decl-file.zig").decl;
/// const other = decl.middle.other;
///```
pub fn resolveVarDeclAlias(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var node_trail: NodeSet = .{};
    defer node_trail.deinit(analyser.gpa);
    return try analyser.resolveVarDeclAliasInternal(node_handle, &node_trail);
}

fn resolveVarDeclAliasInternal(analyser: *Analyser, node_handle: NodeWithHandle, node_trail: *NodeSet) error{OutOfMemory}!?DeclWithHandle {
    const node_with_uri = NodeWithUri{ .node = node_handle.node, .uri = node_handle.handle.uri };

    const gop = try node_trail.getOrPut(analyser.gpa, node_with_uri);
    if (gop.found_existing) return null;

    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);

    const resolved = switch (node_tags[node_handle.node]) {
        .identifier => blk: {
            const name_token = ast.identifierTokenFromIdentifierNode(tree, node_handle.node) orelse break :blk null;
            const name = offsets.identifierTokenToNameSlice(tree, name_token);
            break :blk try analyser.lookupSymbolGlobal(
                handle,
                name,
                tree.tokens.items(.start)[name_token],
            );
        },
        .field_access => blk: {
            const lhs = datas[node_handle.node].lhs;
            const resolved = (try analyser.resolveTypeOfNode(.{ .node = lhs, .handle = handle })) orelse return null;
            if (!resolved.is_type_val)
                return null;

            const resolved_scope_handle = switch (resolved.data) {
                .container => |s| s,
                else => return null,
            };

            const symbol_name = offsets.identifierTokenToNameSlice(tree, datas[node_handle.node].rhs);

            break :blk try analyser.lookupSymbolContainer(
                resolved_scope_handle,
                symbol_name,
                .other,
            );
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node_handle.node).?;

            if (var_decl.ast.init_node == 0) return null;
            const base_exp = var_decl.ast.init_node;
            if (token_tags[var_decl.ast.mut_token] != .keyword_const) return null;

            return try analyser.resolveVarDeclAliasInternal(.{ .node = base_exp, .handle = handle }, node_trail);
        },
        else => return null,
    } orelse return null;

    const resolved_node = switch (resolved.decl) {
        .ast_node => |node| node,
        else => return resolved,
    };

    if (node_trail.contains(.{ .node = resolved_node, .uri = resolved.handle.uri })) {
        return null;
    }

    if (try analyser.resolveVarDeclAliasInternal(.{ .node = resolved_node, .handle = resolved.handle }, node_trail)) |result| {
        return result;
    } else {
        return resolved;
    }
}

/// resolves `@field(lhs, field_name)`
pub fn resolveFieldAccess(analyser: *Analyser, lhs: Type, field_name: []const u8) !?Type {
    if (try analyser.resolveTaggedUnionFieldType(lhs, field_name)) |tag_type| return tag_type;

    // If we are accessing a pointer type, remove one pointerness level :)
    const left_type = (try analyser.resolveDerefType(lhs)) orelse lhs;

    if (try analyser.resolvePropertyType(left_type, field_name)) |t| return t;

    if (try left_type.lookupSymbol(analyser, field_name)) |child| return try child.resolveType(analyser);

    return null;
}

fn findReturnStatementInternal(tree: Ast, body: Ast.Node.Index, already_found: *bool) ?Ast.Node.Index {
    var result: ?Ast.Node.Index = null;

    const node_tags = tree.nodes.items(.tag);

    var buffer: [2]Ast.Node.Index = undefined;
    const statements = ast.blockStatements(tree, body, &buffer) orelse return null;

    for (statements) |child_idx| {
        if (node_tags[child_idx] == .@"return") {
            if (already_found.*) return null;
            already_found.* = true;
            result = child_idx;
            continue;
        }

        result = findReturnStatementInternal(tree, child_idx, already_found);
    }

    return result;
}

fn findReturnStatement(tree: Ast, body: Ast.Node.Index) ?Ast.Node.Index {
    var already_found = false;
    return findReturnStatementInternal(tree, body, &already_found);
}

pub fn resolveReturnType(analyser: *Analyser, fn_decl: Ast.full.FnProto, handle: *DocumentStore.Handle, fn_body: ?Ast.Node.Index) error{OutOfMemory}!?Type {
    const tree = handle.tree;
    if (isTypeFunction(tree, fn_decl) and fn_body != null) {
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const ret = findReturnStatement(tree, fn_body.?) orelse return null;
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
    if (!child_type.is_type_val) return null;

    if (ast.hasInferredError(tree, fn_decl)) {
        const child_type_ptr = try analyser.arena.allocator().create(Type);
        child_type_ptr.* = child_type;
        return Type{
            .data = .{ .error_union = .{
                .error_set = null,
                .payload = child_type_ptr,
            } },
            .is_type_val = false,
        };
    }

    return try child_type.instanceTypeVal(analyser);
}

/// `optional.?`
pub fn resolveOptionalUnwrap(analyser: *Analyser, optional: Type) error{OutOfMemory}!?Type {
    if (optional.is_type_val) return null;

    switch (optional.data) {
        .optional => |child_ty| {
            std.debug.assert(child_ty.is_type_val);
            return try child_ty.instanceTypeVal(analyser);
        },
        else => return null,
    }
}

pub fn resolveOrelseType(analyser: *Analyser, lhs: Type, rhs: Type) error{OutOfMemory}!?Type {
    return switch (rhs.data) {
        .optional => rhs,
        else => try analyser.resolveOptionalUnwrap(lhs),
    };
}

/// Resolves the child type of an optional type
pub fn resolveOptionalChildType(analyser: *Analyser, optional_type: Type) error{OutOfMemory}!?Type {
    _ = analyser;
    if (!optional_type.is_type_val) return null;
    switch (optional_type.data) {
        .optional => |child_ty| {
            std.debug.assert(child_ty.is_type_val);
            return child_ty.*;
        },
        else => return null,
    }
}

pub fn resolveAddressOf(analyser: *Analyser, ty: Type) error{OutOfMemory}!?Type {
    const base_type_ptr = try analyser.arena.allocator().create(Type);
    base_type_ptr.* = ty.typeOf(analyser);
    return Type{
        .data = .{
            .pointer = .{
                .size = .One,
                .sentinel = .none,
                .is_const = false,
                .elem_ty = base_type_ptr,
            },
        },
        .is_type_val = false,
    };
}

pub const ErrorUnionSide = enum { error_set, payload };

pub fn resolveUnwrapErrorUnionType(analyser: *Analyser, ty: Type, side: ErrorUnionSide) error{OutOfMemory}!?Type {
    return switch (ty.data) {
        .error_union => |info| switch (side) {
            .error_set => try (info.error_set orelse return null).instanceTypeVal(analyser),
            .payload => try info.payload.instanceTypeVal(analyser),
        },
        else => return null,
    };
}

fn resolveTaggedUnionFieldType(analyser: *Analyser, ty: Type, symbol: []const u8) error{OutOfMemory}!?Type {
    if (!ty.is_type_val)
        return null;

    const scope_handle = switch (ty.data) {
        .container => |s| s,
        else => return null,
    };
    const node = scope_handle.toNode();
    const handle = scope_handle.handle;

    if (node == 0)
        return null;

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = handle.tree.fullContainerDecl(&buf, node) orelse
        return null;

    if (handle.tree.tokens.items(.tag)[container_decl.ast.main_token] != .keyword_union)
        return null;

    const child = try ty.lookupSymbol(analyser, symbol) orelse
        return null;

    if (child.decl != .ast_node or !child.handle.tree.nodes.items(.tag)[child.decl.ast_node].isContainerField())
        return try child.resolveType(analyser);

    if (container_decl.ast.enum_token != null) {
        const union_type_ptr = try analyser.arena.allocator().create(Type);
        union_type_ptr.* = ty;
        return Type{ .data = .{ .union_tag = union_type_ptr }, .is_type_val = false };
    }

    if (container_decl.ast.arg != 0) {
        const tag_type = (try analyser.resolveTypeOfNode(.{
            .node = container_decl.ast.arg,
            .handle = handle,
        })) orelse return null;
        return try tag_type.instanceTypeVal(analyser);
    }

    return null;
}

pub fn resolveFuncProtoOfCallable(analyser: *Analyser, ty: Type) error{OutOfMemory}!?Type {
    const deref_type = try analyser.resolveDerefType(ty) orelse ty;
    if (!deref_type.isFunc()) return null;
    return deref_type;
}

/// resolve a pointer dereference
/// `pointer.*`
pub fn resolveDerefType(analyser: *Analyser, pointer: Type) error{OutOfMemory}!?Type {
    if (pointer.is_type_val) return null;

    switch (pointer.data) {
        .pointer => |info| switch (info.size) {
            .One, .C => return try info.elem_ty.instanceTypeVal(analyser),
            .Many, .Slice => return null,
        },
        .ip_index => |payload| {
            const ty = analyser.ip.typeOf(payload.index);
            switch (analyser.ip.indexToKey(ty)) {
                .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
                    .One, .C => return try Type.typeValFromIP(analyser, pointer_info.elem_type),
                    .Many, .Slice => return null,
                },
                else => return null,
            }
        },
        else => return null,
    }
}

const BracketAccessKind = enum {
    /// `lhs[index]`
    Single,
    /// `lhs[start..]`
    Open,
    /// `lhs[start..end]`
    Range,
};

/// Resolves slicing and array access
/// - `lhs[index]` (Single)
/// - `lhs[start..]` (Open)
/// - `lhs[start..end]` (Range)
fn resolveBracketAccessType(analyser: *Analyser, lhs: Type, rhs: BracketAccessKind) error{OutOfMemory}!?Type {
    if (lhs.is_type_val) return null;

    switch (lhs.data) {
        .other => |node_handle| switch (node_handle.handle.tree.nodes.items(.tag)[node_handle.node]) {
            .for_range => return try Type.typeValFromIP(analyser, .usize_type),
            else => return null,
        },
        .array => |info| switch (rhs) {
            .Single => return try info.elem_ty.instanceTypeVal(analyser),
            .Open => {
                return Type{
                    .data = .{
                        .pointer = .{
                            .size = .Slice,
                            .sentinel = info.sentinel,
                            .is_const = false,
                            .elem_ty = info.elem_ty,
                        },
                    },
                    .is_type_val = false,
                };
            },
            .Range => {
                return Type{
                    .data = .{
                        .pointer = .{
                            .size = .Slice,
                            .sentinel = .none,
                            .is_const = false,
                            .elem_ty = info.elem_ty,
                        },
                    },
                    .is_type_val = false,
                };
            },
        },
        .pointer => |info| return switch (info.size) {
            .One => switch (info.elem_ty.data) {
                .array => |array_info| {
                    switch (rhs) {
                        .Single => return try array_info.elem_ty.instanceTypeVal(analyser),
                        .Open => {
                            return Type{
                                .data = .{
                                    .pointer = .{
                                        .size = .Slice,
                                        .sentinel = array_info.sentinel,
                                        .is_const = false,
                                        .elem_ty = array_info.elem_ty,
                                    },
                                },
                                .is_type_val = false,
                            };
                        },
                        .Range => {
                            return Type{
                                .data = .{
                                    .pointer = .{
                                        .size = .Slice,
                                        .sentinel = .none,
                                        .is_const = false,
                                        .elem_ty = array_info.elem_ty,
                                    },
                                },
                                .is_type_val = false,
                            };
                        },
                    }
                },
                else => return null,
            },
            .Many => switch (rhs) {
                .Single => try info.elem_ty.instanceTypeVal(analyser),
                .Open => lhs,
                .Range => {
                    return Type{
                        .data = .{
                            .pointer = .{
                                .size = .Slice,
                                .sentinel = .none,
                                .is_const = info.is_const,
                                .elem_ty = info.elem_ty,
                            },
                        },
                        .is_type_val = false,
                    };
                },
            },
            .Slice => switch (rhs) {
                .Single => try info.elem_ty.instanceTypeVal(analyser),
                .Open, .Range => lhs,
            },
            .C => switch (rhs) {
                .Single => try info.elem_ty.instanceTypeVal(analyser),
                .Open => lhs,
                .Range => Type{
                    .data = .{
                        .pointer = .{
                            .size = .Slice,
                            .sentinel = .none,
                            .is_const = info.is_const,
                            .elem_ty = info.elem_ty,
                        },
                    },
                    .is_type_val = false,
                },
            },
        },
        else => return null,
    }
}

fn resolveTupleFieldType(analyser: *Analyser, tuple: Type, index: usize) error{OutOfMemory}!?Type {
    const scope_handle = switch (tuple.data) {
        .container => |s| s,
        else => return null,
    };
    const node = scope_handle.toNode();
    const handle = scope_handle.handle;
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

    if (try analyser.resolveTypeOfNode(.{ .node = field.ast.type_expr, .handle = handle })) |ty|
        return try ty.instanceTypeVal(analyser);

    return null;
}

fn resolvePropertyType(analyser: *Analyser, ty: Type, name: []const u8) error{OutOfMemory}!?Type {
    if (ty.is_type_val)
        return null;

    switch (ty.data) {
        .pointer => |info| switch (info.size) {
            .One => switch (info.elem_ty.data) {
                .array => {
                    std.debug.assert(!info.elem_ty.is_type_val);
                    if (std.mem.eql(u8, "len", name)) {
                        return try Type.typeValFromIP(analyser, .usize_type);
                    }
                },
                else => {},
            },
            .Slice => {
                if (std.mem.eql(u8, "len", name)) {
                    return try Type.typeValFromIP(analyser, .usize_type);
                }

                if (std.mem.eql(u8, "ptr", name)) {
                    return Type{
                        .data = .{
                            .pointer = .{
                                .size = .Many,
                                .sentinel = info.sentinel,
                                .is_const = info.is_const,
                                .elem_ty = info.elem_ty,
                            },
                        },
                        .is_type_val = false,
                    };
                }
            },
            .Many, .C => {},
        },

        .array => {
            if (std.mem.eql(u8, "len", name)) {
                return try Type.typeValFromIP(analyser, .usize_type);
            }
        },

        .optional => |child_ty| {
            if (std.mem.eql(u8, "?", name)) {
                return child_ty.*;
            }
        },

        .container => |scope_handle| switch (scope_handle.handle.tree.nodes.items(.tag)[scope_handle.toNode()]) {
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

                return analyser.resolveTupleFieldType(ty, index);
            },
            else => {},
        },

        .other => |node_handle| switch (node_handle.handle.tree.nodes.items(.tag)[node_handle.node]) {
            .multiline_string_literal,
            .string_literal,
            => if (std.mem.eql(u8, "len", name)) {
                return try Type.typeValFromIP(analyser, .usize_type);
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

fn resolveInternPoolValue(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?InternPool.Index {
    const old_resolve_number_literal_values = analyser.resolve_number_literal_values;
    analyser.resolve_number_literal_values = true;
    defer analyser.resolve_number_literal_values = old_resolve_number_literal_values;

    const resolved_length = try analyser.resolveTypeOfNode(node_handle) orelse return null;
    switch (resolved_length.data) {
        .ip_index => |payload| return payload.index,
        else => return null,
    }
}

fn resolveIntegerLiteral(analyser: *Analyser, comptime T: type, node_handle: NodeWithHandle) error{OutOfMemory}!?T {
    const ip_index = try analyser.resolveInternPoolValue(node_handle) orelse return null;
    return analyser.ip.toInt(ip_index, T);
}

const primitives = std.StaticStringMap(InternPool.Index).initComptime(.{
    .{ "anyerror", .anyerror_type },
    .{ "anyframe", .anyframe_type },
    .{ "anyopaque", .anyopaque_type },
    .{ "bool", .bool_type },
    .{ "c_int", .c_int_type },
    .{ "c_long", .c_long_type },
    .{ "c_longdouble", .c_longdouble_type },
    .{ "c_longlong", .c_longlong_type },
    .{ "c_char", .c_char_type },
    .{ "c_short", .c_short_type },
    .{ "c_uint", .c_uint_type },
    .{ "c_ulong", .c_ulong_type },
    .{ "c_ulonglong", .c_ulonglong_type },
    .{ "c_ushort", .c_ushort_type },
    .{ "comptime_float", .comptime_float_type },
    .{ "comptime_int", .comptime_int_type },
    .{ "f128", .f128_type },
    .{ "f16", .f16_type },
    .{ "f32", .f32_type },
    .{ "f64", .f64_type },
    .{ "f80", .f80_type },
    .{ "false", .bool_false },
    .{ "i16", .i16_type },
    .{ "i32", .i32_type },
    .{ "i64", .i64_type },
    .{ "i128", .i128_type },
    .{ "i8", .i8_type },
    .{ "isize", .isize_type },
    .{ "noreturn", .noreturn_type },
    .{ "null", .null_value },
    .{ "true", .bool_true },
    .{ "type", .type_type },
    .{ "u16", .u16_type },
    .{ "u29", .u29_type },
    .{ "u32", .u32_type },
    .{ "u64", .u64_type },
    .{ "u128", .u128_type },
    .{ "u1", .u1_type },
    .{ "u8", .u8_type },
    .{ "undefined", .undefined_value },
    .{ "usize", .usize_type },
    .{ "void", .void_type },
});

pub fn resolvePrimitive(analyser: *Analyser, identifier_name: []const u8) error{OutOfMemory}!?InternPool.Index {
    if (primitives.get(identifier_name)) |primitive| return primitive;

    if (identifier_name.len < 2) return null;
    const signedness: std.builtin.Signedness = switch (identifier_name[0]) {
        'i' => .signed,
        'u' => .unsigned,
        else => return null,
    };
    for (identifier_name[1..]) |c| {
        switch (c) {
            '0'...'9' => {},
            else => return null,
        }
    }

    const bits = std.fmt.parseUnsigned(u16, identifier_name[1..], 10) catch return null;

    return try analyser.ip.get(analyser.gpa, .{ .int_type = .{
        .bits = bits,
        .signedness = signedness,
    } });
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

/// Resolves the type of an Ast Node.
/// Returns `null` if the type could not be resolved.
pub fn resolveTypeOfNode(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?Type {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return analyser.resolveTypeOfNodeInternal(node_handle);
}

fn resolveTypeOfNodeInternal(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?Type {
    const node_with_uri = NodeWithUri{
        .node = node_handle.node,
        .uri = node_handle.handle.uri,
    };
    const gop = try analyser.resolved_nodes.getOrPut(analyser.gpa, node_with_uri);
    if (gop.found_existing) return gop.value_ptr.*;

    // we insert null before resolving the type so that a recursive definition doesn't result in an infinite loop
    gop.value_ptr.* = null;

    const ty = try analyser.resolveTypeOfNodeUncached(node_handle);
    if (ty != null) {
        analyser.resolved_nodes.getPtr(node_with_uri).?.* = ty;
    }

    return ty;
}

fn resolveTypeOfNodeUncached(analyser: *Analyser, node_handle: NodeWithHandle) error{OutOfMemory}!?Type {
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
            var fallback_type: ?Type = null;

            if (var_decl.ast.type_node != 0) blk: {
                const type_node = .{ .node = var_decl.ast.type_node, .handle = handle };
                const decl_type = try analyser.resolveTypeOfNodeInternal(type_node) orelse break :blk;
                if (decl_type.isMetaType()) {
                    fallback_type = decl_type;
                    break :blk;
                }
                return try decl_type.instanceTypeVal(analyser);
            }

            if (var_decl.ast.init_node != 0) blk: {
                const value = .{ .node = var_decl.ast.init_node, .handle = handle };
                return try analyser.resolveTypeOfNodeInternal(value) orelse break :blk;
            }

            return fallback_type;
        },
        .identifier => {
            const name_token = ast.identifierTokenFromIdentifierNode(tree, node) orelse return null;
            const name = offsets.identifierTokenToNameSlice(tree, name_token);

            const is_escaped_identifier = tree.source[tree.tokens.items(.start)[name_token]] == '@';
            if (!is_escaped_identifier) {
                if (std.mem.eql(u8, name, "_")) return null;
                if (try analyser.resolvePrimitive(name)) |primitive| {
                    return Type{
                        .data = .{ .ip_index = .{ .index = primitive } },
                        .is_type_val = analyser.ip.typeOf(primitive) == .type_type,
                    };
                }
            }

            const child = try analyser.lookupSymbolGlobal(handle, name, starts[name_token]) orelse return null;
            return try child.resolveType(analyser);
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
            const call = tree.fullCall(&buffer, node).?;

            const callee = .{ .node = call.ast.fn_expr, .handle = handle };
            const ty = try analyser.resolveTypeOfNodeInternal(callee) orelse return null;
            const func_ty = try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
            if (func_ty.is_type_val) return null;

            const func_node_handle = func_ty.data.other; // this assumes that function types can only be Ast nodes
            const func_node = func_node_handle.node;
            const func_handle = func_node_handle.handle;
            const func_tree = func_handle.tree;
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = func_tree.fullFnProto(&buf, func_node).?;

            var params = try std.ArrayListUnmanaged(Ast.full.FnProto.Param).initCapacity(analyser.arena.allocator(), fn_proto.ast.params.len);
            defer params.deinit(analyser.arena.allocator());

            var it = fn_proto.iterate(&func_handle.tree);
            while (ast.nextFnParam(&it)) |param| {
                try params.append(analyser.arena.allocator(), param);
            }

            const has_self_param = call.ast.params.len + 1 == params.items.len and
                try analyser.isInstanceCall(handle, call, func_ty);

            const parameters = params.items[@intFromBool(has_self_param)..];
            const arguments = call.ast.params;
            const min_len = @min(parameters.len, arguments.len);
            for (parameters[0..min_len], arguments[0..min_len], @intFromBool(has_self_param)..) |param, arg, param_index| {
                if (!isMetaType(func_tree, param.type_expr)) continue;

                const argument_type = (try analyser.resolveTypeOfNodeInternal(.{ .node = arg, .handle = handle })) orelse continue;
                if (!argument_type.is_type_val) continue;

                try analyser.bound_type_params.put(analyser.gpa, .{
                    .func = func_node,
                    .param_index = @intCast(param_index),
                }, argument_type);
            }

            const has_body = func_tree.nodes.items(.tag)[func_node] == .fn_decl;
            const body = func_tree.nodes.items(.data)[func_node].rhs;
            if (try analyser.resolveReturnType(fn_proto, func_handle, if (has_body) body else null)) |ret| {
                return ret;
            }
        },
        .container_field,
        .container_field_init,
        .container_field_align,
        => {
            const container_type = try innermostContainer(handle, offsets.tokenToIndex(tree, tree.firstToken(node)));
            if (container_type.isEnumType())
                return try container_type.instanceTypeVal(analyser);

            if (container_type.isTaggedUnion()) {
                var field = tree.fullContainerField(node).?;
                field.convertToNonTupleLike(tree.nodes);
                if (field.ast.type_expr == 0)
                    return try Type.typeValFromIP(analyser, .void_type);
            }

            const base = .{ .node = datas[node].lhs, .handle = handle };
            const base_type = (try analyser.resolveTypeOfNodeInternal(base)) orelse return null;
            return try base_type.instanceTypeVal(analyser);
        },
        .@"comptime",
        .@"nosuspend",
        .grouped_expression,
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
            const base_type = (try analyser.resolveTypeOfNodeInternal(base)) orelse
                return null;
            return switch (node_tags[node]) {
                .@"comptime",
                .@"nosuspend",
                .grouped_expression,
                => base_type,
                .struct_init,
                .struct_init_comma,
                .struct_init_one,
                .struct_init_one_comma,
                => try base_type.instanceTypeVal(analyser),
                .slice,
                .slice_sentinel,
                .slice_open,
                => {
                    const slice_info = tree.fullSlice(node).?;
                    const kind: BracketAccessKind = if (slice_info.ast.end == 0) .Open else .Range;
                    return try analyser.resolveBracketAccessType(base_type, kind);
                },
                .deref => try analyser.resolveDerefType(base_type),
                .unwrap_optional => try analyser.resolveOptionalUnwrap(base_type),
                .array_access => try analyser.resolveBracketAccessType(base_type, .Single),
                .@"orelse" => {
                    const type_right = try analyser.resolveTypeOfNodeInternal(.{ .node = datas[node].rhs, .handle = handle }) orelse return null;
                    return try analyser.resolveOrelseType(base_type, type_right);
                },
                .@"catch" => try analyser.resolveUnwrapErrorUnionType(base_type, .payload),
                .@"try" => try analyser.resolveUnwrapErrorUnionType(base_type, .payload),
                .address_of => try analyser.resolveAddressOf(base_type),
                else => unreachable,
            };
        },
        .field_access => {
            if (datas[node].rhs == 0) return null;

            const lhs = (try analyser.resolveTypeOfNodeInternal(.{
                .node = datas[node].lhs,
                .handle = handle,
            })) orelse return null;

            const symbol = offsets.identifierTokenToNameSlice(tree, datas[node_handle.node].rhs);

            return try resolveFieldAccess(analyser, lhs, symbol);
        },
        .optional_type => {
            const child_ty = try analyser.resolveTypeOfNodeInternal(.{ .node = datas[node].lhs, .handle = handle }) orelse return null;
            if (!child_ty.is_type_val) return null;

            const child_ty_ptr = try analyser.arena.allocator().create(Type);
            child_ty_ptr.* = child_ty;

            return Type{ .data = .{ .optional = child_ty_ptr }, .is_type_val = true };
        },
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const ptr_info = ast.fullPtrType(tree, node).?;

            const sentinel = try analyser.resolveInternPoolValue(.{ .node = ptr_info.ast.sentinel, .handle = handle }) orelse .none;

            const elem_ty = try analyser.resolveTypeOfNodeInternal(.{ .node = ptr_info.ast.child_type, .handle = handle }) orelse return null;
            if (!elem_ty.is_type_val) return null;

            const elem_ty_ptr = try analyser.arena.allocator().create(Type);
            elem_ty_ptr.* = elem_ty;
            return Type{
                .data = .{
                    .pointer = .{
                        .size = ptr_info.size,
                        .sentinel = sentinel,
                        .is_const = ptr_info.const_token != null,
                        .elem_ty = elem_ty_ptr,
                    },
                },
                .is_type_val = true,
            };
        },
        .array_type,
        .array_type_sentinel,
        => {
            const array_info = tree.fullArrayType(node).?;

            const elem_count = try analyser.resolveIntegerLiteral(u64, .{ .node = array_info.ast.elem_count, .handle = handle });
            const sentinel = try analyser.resolveInternPoolValue(.{ .node = array_info.ast.sentinel, .handle = handle }) orelse .none;

            const elem_ty = try analyser.resolveTypeOfNodeInternal(.{ .node = array_info.ast.elem_type, .handle = handle }) orelse return null;
            if (!elem_ty.is_type_val) return null;

            const elem_ty_ptr = try analyser.arena.allocator().create(Type);
            elem_ty_ptr.* = elem_ty;

            return Type{
                .data = .{ .array = .{
                    .elem_count = elem_count,
                    .sentinel = sentinel,
                    .elem_ty = elem_ty_ptr,
                } },
                .is_type_val = true,
            };
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
            const array_init_info = tree.fullArrayInit(&buffer, node).?;

            std.debug.assert(array_init_info.ast.elements.len != 0);

            if (array_init_info.ast.type_expr != 0) blk: {
                const array_ty = try analyser.resolveTypeOfNode(.{ .node = array_init_info.ast.type_expr, .handle = handle }) orelse break :blk;
                return try array_ty.instanceTypeVal(analyser);
            }

            // try to infer the array type
            const maybe_elem_ty = try analyser.resolveTypeOfNodeInternal(.{ .node = array_init_info.ast.elements[0], .handle = handle });
            const elem_ty = if (maybe_elem_ty) |elem_ty| elem_ty.typeOf(analyser) else try Type.typeValFromIP(analyser, .type_type);

            const elem_ty_ptr = try analyser.arena.allocator().create(Type);
            elem_ty_ptr.* = elem_ty;

            return Type{
                .data = .{ .array = .{
                    .elem_count = @intCast(array_init_info.ast.elements.len),
                    .sentinel = .none,
                    .elem_ty = elem_ty_ptr,
                } },
                .is_type_val = false,
            };
        },
        .error_union => {
            const error_set = try analyser.resolveTypeOfNodeInternal(.{ .node = datas[node].lhs, .handle = handle }) orelse return null;
            if (!error_set.is_type_val) return null;

            const payload = try analyser.resolveTypeOfNodeInternal(.{ .node = datas[node].rhs, .handle = handle }) orelse return null;
            if (!payload.is_type_val) return null;

            const error_set_ptr = try analyser.arena.allocator().create(Type);
            error_set_ptr.* = error_set;

            const payload_ptr = try analyser.arena.allocator().create(Type);
            payload_ptr.* = payload;

            return Type{
                .data = .{ .error_union = .{
                    .error_set = error_set_ptr,
                    .payload = payload_ptr,
                } },
                .is_type_val = true,
            };
        },

        // TODO represent through InternPool
        .merge_error_sets => return Type.typeVal(node_handle),

        .error_set_decl, // TODO represent through InternPool
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
        => {
            // TODO: use map? idk
            const document_scope = try handle.getDocumentScope();

            return .{
                .data = .{
                    .container = .{
                        .handle = handle,
                        .scope = for (0..document_scope.scopes.len) |scope_index| {
                            switch (document_scope.getScopeTag(@enumFromInt(scope_index))) {
                                .container, .container_usingnamespace => if (document_scope.getScopeAstNode(@enumFromInt(scope_index)).? == node) {
                                    break @enumFromInt(scope_index);
                                },
                                else => {},
                            }
                        } else unreachable, // is this safe? idk
                    },
                },
                .is_type_val = true,
            };
        },
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
                return try innermostContainer(handle, starts[tree.firstToken(node)]);
            }

            const cast_map = std.StaticStringMap(void).initComptime(.{
                .{"@as"},
                .{"@atomicLoad"},
                .{"@atomicRmw"},
                .{"@atomicStore"},
                .{"@mulAdd"},
                .{"@unionInit"},
            });
            if (cast_map.has(call_name)) {
                if (params.len < 1) return null;
                const ty = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = params[0],
                    .handle = handle,
                })) orelse return null;
                return try ty.instanceTypeVal(analyser);
            }

            // Almost the same as the above, return a type value though.
            // TODO Do peer type resolution, we just keep the first for now.
            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len < 1) return null;
                var resolved_type = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = params[0],
                    .handle = handle,
                })) orelse return null;
                return resolved_type.typeOf(analyser);
            }

            if (std.mem.eql(u8, call_name, "@typeInfo")) {
                return analyser.instanceStdBuiltinType("Type");
            }

            if (std.mem.eql(u8, call_name, "@import")) {
                if (params.len == 0) return null;
                const import_param = params[0];
                if (node_tags[import_param] != .string_literal) return null;

                const import_str = tree.tokenSlice(main_tokens[import_param]);
                const import_uri = (try analyser.store.uriFromImportStr(
                    analyser.arena.allocator(),
                    handle,
                    import_str[1 .. import_str.len - 1],
                )) orelse (try analyser.store.uriFromImportStr(
                    analyser.arena.allocator(),
                    analyser.root_handle orelse return null,
                    import_str[1 .. import_str.len - 1],
                )) orelse return null;

                const new_handle = analyser.store.getOrLoadHandle(import_uri) orelse return null;

                return .{
                    .data = .{
                        .container = .{
                            .handle = new_handle,
                            .scope = Scope.Index.root,
                        },
                    },
                    .is_type_val = true,
                };
            }

            if (std.mem.eql(u8, call_name, "@cImport")) {
                const cimport_uri = (try analyser.store.resolveCImport(handle, node)) orelse return null;

                const new_handle = analyser.store.getOrLoadHandle(cimport_uri) orelse return null;

                return .{
                    .data = .{
                        .container = .{
                            .handle = new_handle,
                            .scope = Scope.Index.root,
                        },
                    },
                    .is_type_val = true,
                };
            }

            if (std.mem.eql(u8, call_name, "@field")) {
                if (params.len < 2) return null;
                var field_name_node: NodeWithHandle = .{ .node = params[1], .handle = handle };
                if (try analyser.resolveVarDeclAlias(field_name_node)) |decl_with_handle| {
                    if (decl_with_handle.decl == .ast_node) {
                        field_name_node = .{
                            .node = decl_with_handle.decl.ast_node,
                            .handle = decl_with_handle.handle,
                        };
                    }
                }
                const string_literal_node = switch (field_name_node.handle.tree.nodes.items(.tag)[field_name_node.node]) {
                    .string_literal => field_name_node.node,
                    .global_var_decl,
                    .local_var_decl,
                    .aligned_var_decl,
                    .simple_var_decl,
                    => blk: {
                        const init_node = field_name_node.handle.tree.fullVarDecl(field_name_node.node).?.ast.init_node;
                        if (field_name_node.handle.tree.nodes.items(.tag)[init_node] != .string_literal) return null;
                        break :blk init_node;
                    },
                    else => return null,
                };
                const field_name_token = field_name_node.handle.tree.nodes.items(.main_token)[string_literal_node];
                const field_name = offsets.tokenToSlice(field_name_node.handle.tree, field_name_token);

                // Need at least one char between the quotes, eg "a"
                if (field_name.len < 2) return null;

                const lhs = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = params[0],
                    .handle = handle,
                })) orelse return null;

                return try analyser.resolveFieldAccess(lhs, field_name[1 .. field_name.len - 1]);
            }

            if (std.mem.eql(u8, call_name, "@src")) {
                return analyser.instanceStdBuiltinType("SourceLocation");
            }
            if (std.mem.eql(u8, call_name, "@compileError")) {
                return Type{ .data = .{ .compile_error = node_handle }, .is_type_val = false };
            }

            if (std.mem.eql(u8, call_name, "@Vector")) {
                if (params.len != 2) return null;

                const child_ty = try analyser.resolveTypeOfNodeInternal(.{ .node = params[1], .handle = handle }) orelse return null;
                if (!child_ty.is_type_val) return null;

                const child_ty_ip_index = switch (child_ty.data) {
                    .ip_index => |payload| payload.index,
                    else => return null,
                };

                const len = try analyser.resolveIntegerLiteral(u32, .{ .node = params[0], .handle = handle }) orelse
                    return null; // `InternPool.Key.Vector.len` can't represent unknown length yet

                const vector_ty_ip_index = try analyser.ip.get(analyser.gpa, .{
                    .vector_type = .{
                        .len = len,
                        .child = child_ty_ip_index,
                    },
                });

                return Type{
                    .data = .{ .ip_index = .{ .index = vector_ty_ip_index } },
                    .is_type_val = true,
                };
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
                return Type.typeVal(node_handle);
            }

            return Type{ .data = .{ .other = .{ .node = node, .handle = handle } }, .is_type_val = false };
        },
        .@"if", .if_simple => {
            const if_node = ast.fullIf(tree, node).?;

            // HACK: resolve std.ArrayList(T).Slice
            if (std.mem.endsWith(u8, node_handle.handle.uri, "array_list.zig") and
                if_node.payload_token != null and
                std.mem.eql(u8, offsets.identifierTokenToNameSlice(tree, if_node.payload_token.?), "a") and
                node_tags[if_node.ast.cond_expr] == .identifier and
                std.mem.eql(u8, offsets.identifierTokenToNameSlice(tree, main_tokens[if_node.ast.cond_expr]), "alignment"))
            blk: {
                return (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.then_expr })) orelse break :blk;
            }

            var either: std.BoundedArray(Type.TypeWithDescriptor, 2) = .{};

            if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.then_expr })) |t|
                either.appendAssumeCapacity(.{ .type = t, .descriptor = offsets.nodeToSlice(tree, if_node.ast.cond_expr) });
            if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = if_node.ast.else_expr })) |t|
                either.appendAssumeCapacity(.{ .type = t, .descriptor = try std.fmt.allocPrint(analyser.arena.allocator(), "!({s})", .{offsets.nodeToSlice(tree, if_node.ast.cond_expr)}) });

            return Type.fromEither(analyser.arena.allocator(), either.constSlice());
        },
        .@"switch",
        .switch_comma,
        => {
            const extra = tree.extraData(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            var either = std.ArrayListUnmanaged(Type.TypeWithDescriptor){};

            for (cases) |case| {
                const switch_case = tree.fullSwitchCase(case).?;
                var descriptor = std.ArrayListUnmanaged(u8){};

                for (switch_case.ast.values, 0..) |values, index| {
                    try descriptor.appendSlice(analyser.arena.allocator(), offsets.nodeToSlice(tree, values));
                    if (index != switch_case.ast.values.len - 1) try descriptor.appendSlice(analyser.arena.allocator(), ", ");
                }

                if (try analyser.resolveTypeOfNodeInternal(.{ .handle = handle, .node = switch_case.ast.target_expr })) |t|
                    try either.append(analyser.arena.allocator(), .{
                        .type = t,
                        .descriptor = try descriptor.toOwnedSlice(analyser.arena.allocator()),
                    });
            }

            return Type.fromEither(analyser.arena.allocator(), either.items);
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
            const has_zero_statements = switch (node_tags[node]) {
                .block_two, .block_two_semicolon => datas[node].lhs == 0,
                .block, .block_semicolon => false,
                else => unreachable,
            };
            if (has_zero_statements) {
                return Type{ .data = .{ .ip_index = .{ .index = .void_value } }, .is_type_val = false };
            }

            const first_token = tree.firstToken(node);
            if (token_tags[first_token] != .identifier) return null;

            const block_label = offsets.identifierTokenToNameSlice(tree, first_token);

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

        .for_range => return Type{ .data = .{ .other = .{ .node = node, .handle = handle } }, .is_type_val = false },

        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        => {
            const ty = try analyser.resolveTypeOfNodeInternal(
                .{ .node = datas[node].lhs, .handle = handle },
            ) orelse return try Type.typeValFromIP(analyser, .bool_type);
            const typeof = ty.typeOf(analyser);

            if (typeof.data == .ip_index) {
                const key = analyser.ip.indexToKey(typeof.data.ip_index.index);
                if (key == .vector_type) {
                    const vector_ty_ip_index = try analyser.ip.get(analyser.gpa, .{
                        .vector_type = .{
                            .len = key.vector_type.len,
                            .child = .bool_type,
                        },
                    });

                    return try Type.typeValFromIP(analyser, vector_ty_ip_index);
                }
            }
            return try Type.typeValFromIP(analyser, .bool_type);
        },

        .bool_and,
        .bool_or,
        .bool_not,
        => return try Type.typeValFromIP(analyser, .bool_type),

        .negation,
        .negation_wrap,
        => return try analyser.resolveTypeOfNodeInternal(.{ .node = datas[node].lhs, .handle = handle }),

        .multiline_string_literal => {
            const start = datas[node].lhs;
            const end = datas[node].rhs;

            var length: u64 = 0;

            for (start..end + 1, 0..) |token_index, i| {
                const slice = tree.tokenSlice(@intCast(token_index));
                length += slice.len - 2 + @intFromBool(i != 0);
            }

            const string_literal_type = try analyser.ip.get(analyser.gpa, .{ .pointer_type = .{
                .elem_type = try analyser.ip.get(analyser.gpa, .{ .array_type = .{
                    .child = .u8_type,
                    .len = length,
                    .sentinel = .zero_u8,
                } }),
                .flags = .{
                    .size = .One,
                    .is_const = true,
                },
            } });
            return try Type.typeValFromIP(analyser, string_literal_type);
        },
        .string_literal => {
            const token_bytes = tree.tokenSlice(main_tokens[node]);

            var counting_writer = std.io.countingWriter(std.io.null_writer);
            const result = try std.zig.string_literal.parseWrite(counting_writer.writer(), token_bytes);
            switch (result) {
                .success => {},
                .failure => return null,
            }

            const string_literal_type = try analyser.ip.get(analyser.gpa, .{ .pointer_type = .{
                .elem_type = try analyser.ip.get(analyser.gpa, .{ .array_type = .{
                    .child = .u8_type,
                    .len = counting_writer.bytes_written,
                    .sentinel = .zero_u8,
                } }),
                .flags = .{
                    .size = .One,
                    .is_const = true,
                },
            } });
            return try Type.typeValFromIP(analyser, string_literal_type);
        },
        .error_value => {
            if (token_tags[datas[node].rhs] != .identifier) return null;
            const name = offsets.identifierTokenToNameSlice(tree, datas[node].rhs);
            const name_index = try analyser.ip.string_pool.getOrPutString(analyser.gpa, name);

            const error_set_type = try analyser.ip.get(analyser.gpa, .{ .error_set_type = .{
                .owner_decl = .none,
                .names = try analyser.ip.getStringSlice(analyser.gpa, &.{name_index}),
            } });
            const error_value = try analyser.ip.get(analyser.gpa, .{ .error_value = .{
                .ty = error_set_type,
                .error_tag_name = name_index,
            } });
            return Type{ .data = .{ .ip_index = .{ .index = error_value } }, .is_type_val = false };
        },

        .char_literal => return try Type.typeValFromIP(analyser, .comptime_int_type),

        .number_literal => {
            const bytes = offsets.tokenToSlice(tree, main_tokens[node]);
            const result = std.zig.parseNumberLiteral(bytes);
            const ty: InternPool.Index = switch (result) {
                .int,
                .big_int,
                => .comptime_int_type,
                .float => .comptime_float_type,
                .failure => return null,
            };
            if (!analyser.resolve_number_literal_values) {
                return try Type.typeValFromIP(analyser, ty);
            }
            const value: ?InternPool.Index = switch (result) {
                .float => blk: {
                    break :blk try analyser.ip.get(
                        analyser.gpa,
                        .{ .float_comptime_value = std.fmt.parseFloat(f128, bytes) catch break :blk null },
                    );
                },
                .int => blk: {
                    break :blk if (bytes[0] == '-')
                        try analyser.ip.get(
                            analyser.gpa,
                            .{ .int_i64_value = .{ .ty = ty, .int = std.fmt.parseInt(i64, bytes, 0) catch break :blk null } },
                        )
                    else
                        try analyser.ip.get(
                            analyser.gpa,
                            .{ .int_u64_value = .{ .ty = ty, .int = std.fmt.parseInt(u64, bytes, 0) catch break :blk null } },
                        );
                },
                .big_int => |base| blk: {
                    var big_int = try std.math.big.int.Managed.init(analyser.gpa);
                    defer big_int.deinit();
                    const prefix_length: usize = if (base != .decimal) 2 else 0;
                    big_int.setString(@intFromEnum(base), bytes[prefix_length..]) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => break :blk null,
                    };
                    std.debug.assert(ty == .comptime_int_type);
                    break :blk try analyser.ip.getBigInt(analyser.gpa, ty, big_int.toConst());
                },
                .failure => unreachable, // checked above
            };

            return Type{
                .data = .{ .ip_index = .{ .index = value orelse try analyser.ip.getUnknown(analyser.gpa, ty) } },
                .is_type_val = false,
            };
        },

        .enum_literal => return try Type.typeValFromIP(analyser, .enum_literal_type),
        .unreachable_literal => return try Type.typeValFromIP(analyser, .noreturn_type),
        .anyframe_literal => return try Type.typeValFromIP(analyser, .anyframe_type),

        .anyframe_type => return try Type.typeValFromIP(analyser, .type_type),

        .mul,
        .div,
        .mod,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
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
        .bit_not,
        => {},

        .array_mult,
        .array_cat,
        => {},

        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shl_sat,
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
        .assign,
        .assign_destructure,
        => {},

        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        => {},

        .root,
        .@"usingnamespace",
        .test_decl,
        .@"errdefer",
        .@"defer",
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        .switch_range,
        => {},
        .@"continue",
        .@"break",
        .@"return",
        => {
            return try Type.typeValFromIP(analyser, .noreturn_type);
        },

        .@"await",
        .@"suspend",
        .@"resume",
        => {},

        .asm_simple,
        .@"asm",
        .asm_output,
        .asm_input,
        => {},
    }
    return null;
}

/// Represents a resolved Zig type.
/// This is the return type of `resolveTypeOfNode`.
pub const Type = struct {
    data: Data,
    /// If true, the type `type`, the attached data is the value of the type value.
    /// ```zig
    /// const foo = u32; // is_type_val == true
    /// const bar = @as(u32, ...); // is_type_val == false
    /// ```
    /// if `data == .ip_index` then this field is equivalent to `typeOf(index) == .type_type`
    is_type_val: bool,

    pub const Data = union(enum) {
        /// - `*const T`
        /// - `[*]T`
        /// - `[]const T`
        /// - `[*c]T`
        pointer: struct {
            size: std.builtin.Type.Pointer.Size,
            /// `.none` means no sentinel
            sentinel: InternPool.Index,
            is_const: bool,
            elem_ty: *Type,
        },

        /// `[elem_count :sentinel]elem_ty`
        array: struct {
            elem_count: ?u64,
            /// `.none` means no sentinel
            sentinel: InternPool.Index,
            elem_ty: *Type,
        },

        /// `?T`
        optional: *Type,

        /// `error_set!payload`
        error_union: struct {
            /// `null` if inferred error
            error_set: ?*Type,
            payload: *Type,
        },

        /// `Foo` in `Foo.bar` where `Foo = union(enum) { bar }`
        union_tag: *Type,

        /// - `struct {}`
        /// - `enum {}`
        /// - `union {}`
        /// - `opaque {}`
        /// - `error {}`
        container: ScopeWithHandle,

        /// - Error type: `Foo || Bar`, `Foo!Bar`
        /// - Function: `fn () Foo`, `fn foo() Foo`
        other: NodeWithHandle,

        /// - `@compileError("")`
        compile_error: NodeWithHandle,

        /// Branching types
        either: []const EitherEntry,

        /// Primitive type: `u8`, `bool`, `type`, etc.
        /// Primitive value: `true`, `false`, `null`, `undefined`
        ip_index: struct {
            node: ?NodeWithHandle = null,
            /// this stores both the type and the value
            index: InternPool.Index,
        },

        pub const EitherEntry = struct {
            /// the `is_type_val` property is inherited from the containing `Type`
            type_data: Data,
            descriptor: []const u8,
        };
    };

    pub fn hash32(self: Type) u32 {
        return @truncate(self.hash64());
    }

    pub fn hash64(self: Type) u64 {
        var hasher = std.hash.Wyhash.init(0);
        self.hashWithHasher(&hasher);
        return hasher.final();
    }

    pub fn hashWithHasher(self: Type, hasher: anytype) void {
        hasher.update(&.{ @intFromBool(self.is_type_val), @intFromEnum(self.data) });

        switch (self.data) {
            .pointer => |info| {
                std.hash.autoHash(hasher, info.size);
                std.hash.autoHash(hasher, info.sentinel);
                std.hash.autoHash(hasher, info.is_const);
                info.elem_ty.hashWithHasher(hasher);
            },
            .array => |info| {
                std.hash.autoHash(hasher, info.elem_count);
                std.hash.autoHash(hasher, info.sentinel);
                info.elem_ty.hashWithHasher(hasher);
            },
            .optional, .union_tag => |t| t.hashWithHasher(hasher),
            .error_union => |info| {
                if (info.error_set) |error_set| {
                    error_set.hashWithHasher(hasher);
                }
                info.payload.hashWithHasher(hasher);
            },
            .container => |scope_handle| {
                hasher.update(scope_handle.handle.uri);
                std.hash.autoHash(hasher, scope_handle.scope);
            },
            .other, .compile_error => |node_handle| {
                std.hash.autoHash(hasher, node_handle.node);
                hasher.update(node_handle.handle.uri);
            },
            .either => |entries| {
                for (entries) |entry| {
                    hasher.update(entry.descriptor);
                    const entry_ty = Type{ .data = entry.type_data, .is_type_val = self.is_type_val };
                    entry_ty.hashWithHasher(hasher);
                }
            },
            .ip_index => |payload| {
                std.hash.autoHash(hasher, payload.node);
                std.hash.autoHash(hasher, payload.index);
            },
        }
    }

    pub fn eql(a: Type, b: Type) bool {
        if (a.is_type_val != b.is_type_val) return false;
        if (@intFromEnum(a.data) != @intFromEnum(b.data)) return false;

        switch (a.data) {
            .pointer => |a_type| {
                const b_type = b.data.pointer;
                if (a_type.size != b_type.size) return false;
                if (a_type.sentinel != b_type.sentinel) return false;
                if (!a_type.elem_ty.eql(b_type.elem_ty.*)) return false;
            },
            .array => |a_type| {
                const b_type = b.data.array;
                if (std.meta.eql(a_type.elem_count, b_type.elem_count)) return false;
                if (a_type.sentinel != b_type.sentinel) return false;
                if (!a_type.elem_ty.eql(b_type.elem_ty.*)) return false;
            },
            inline .optional,
            .union_tag,
            => |a_type, name| {
                const b_type = @field(b.data, @tagName(name));
                if (!a_type.eql(b_type.*)) return false;
            },
            .error_union => |info| {
                const b_info = b.data.error_union;
                if (!info.payload.eql(b_info.payload.*)) return false;
                if ((info.error_set == null) != (b_info.error_set == null)) return false;
                if (info.error_set) |a_error_set| {
                    if (!a_error_set.eql(b_info.error_set.?.*)) return false;
                }
            },
            .container => |a_scope_handle| {
                const b_scope_handle = b.data.container;
                if (a_scope_handle.scope != b_scope_handle.scope) return false;
                if (!std.mem.eql(u8, a_scope_handle.handle.uri, b_scope_handle.handle.uri)) return false;
            },
            .other => |a_node_handle| return a_node_handle.eql(b.data.other),
            .compile_error => |a_node_handle| return a_node_handle.eql(b.data.compile_error),
            .either => |a_entries| {
                const b_entries = b.data.either;

                if (a_entries.len != b_entries.len) return false;
                for (a_entries, b_entries) |a_entry, b_entry| {
                    if (!std.mem.eql(u8, a_entry.descriptor, b_entry.descriptor)) return false;
                    const a_entry_ty = Type{ .data = a_entry.type_data, .is_type_val = a.is_type_val };
                    const b_entry_ty = Type{ .data = b_entry.type_data, .is_type_val = b.is_type_val };
                    if (!a_entry_ty.eql(b_entry_ty)) return false;
                }
            },
            .ip_index => |a_payload| {
                const b_payload = b.data.ip_index;

                if (a_payload.index != b_payload.index) return false;
                if (!std.meta.eql(a_payload.node, b_payload.node)) return false;
            },
        }

        return true;
    }

    pub fn typeVal(node_handle: NodeWithHandle) Type {
        return .{
            .data = .{ .other = node_handle },
            .is_type_val = true,
        };
    }

    pub fn typeValFromIP(analyser: *Analyser, ty: InternPool.Index) error{OutOfMemory}!Type {
        std.debug.assert(analyser.ip.isType(ty));
        return Type{
            .data = .{ .ip_index = .{ .index = try analyser.ip.getUnknown(analyser.gpa, ty) } },
            .is_type_val = ty == .type_type,
        };
    }

    pub const TypeWithDescriptor = struct {
        type: Type,
        descriptor: []const u8,
    };

    pub fn fromEither(arena: std.mem.Allocator, entries: []const TypeWithDescriptor) error{OutOfMemory}!?Type {
        if (entries.len == 0)
            return null;

        if (entries.len == 1)
            return entries[0].type;

        // Note that we don't hash/equate descriptors to remove
        // duplicates

        const DeduplicatorContext = struct {
            pub fn hash(self: @This(), item: Type.Data.EitherEntry) u32 {
                _ = self;
                const ty = Type{ .data = item.type_data, .is_type_val = true };
                return ty.hash32();
            }

            pub fn eql(self: @This(), a: Type.Data.EitherEntry, b: Type.Data.EitherEntry, b_index: usize) bool {
                _ = b_index;
                _ = self;
                const a_ty = Type{ .data = a.type_data, .is_type_val = true };
                const b_ty = Type{ .data = b.type_data, .is_type_val = true };
                return a_ty.eql(b_ty);
            }
        };
        const Deduplicator = std.ArrayHashMapUnmanaged(Type.Data.EitherEntry, void, DeduplicatorContext, true);

        var deduplicator = Deduplicator{};
        defer deduplicator.deinit(arena);

        var has_type_val: bool = false;

        for (entries) |entry| {
            try deduplicator.put(
                arena,
                .{ .type_data = entry.type.data, .descriptor = entry.descriptor },
                {},
            );
            if (entry.type.is_type_val) {
                has_type_val = true;
            }
        }

        if (deduplicator.count() == 1)
            return entries[0].type;

        return .{
            .data = .{ .either = try arena.dupe(Type.Data.EitherEntry, deduplicator.keys()) },
            .is_type_val = has_type_val,
        };
    }

    /// Resolves possible types of a type (single for all except either)
    /// Drops duplicates
    pub fn getAllTypesWithHandles(ty: Type, arena: std.mem.Allocator) ![]const Type {
        var all_types = std.ArrayListUnmanaged(Type){};
        try ty.getAllTypesWithHandlesArrayList(arena, &all_types);
        return try all_types.toOwnedSlice(arena);
    }

    pub fn getAllTypesWithHandlesArrayList(ty: Type, arena: std.mem.Allocator, all_types: *std.ArrayListUnmanaged(Type)) !void {
        switch (ty.data) {
            .either => |entries| {
                for (entries) |entry| {
                    const entry_ty = Type{ .data = entry.type_data, .is_type_val = ty.is_type_val };
                    try entry_ty.getAllTypesWithHandlesArrayList(arena, all_types);
                }
            },
            else => try all_types.append(arena, ty),
        }
    }

    pub fn instanceTypeVal(self: Type, analyser: *Analyser) error{OutOfMemory}!?Type {
        if (!self.is_type_val) return null;
        return switch (self.data) {
            .ip_index => |payload| {
                if (payload.index == .unknown_type) return null;
                return Type{
                    .data = .{
                        .ip_index = .{
                            .index = try analyser.ip.getUnknown(analyser.gpa, payload.index),
                            .node = payload.node,
                        },
                    },
                    .is_type_val = payload.index == .type_type,
                };
            },
            else => Type{ .data = self.data, .is_type_val = false },
        };
    }

    pub fn typeOf(self: Type, analyser: *Analyser) Type {
        if (self.is_type_val) {
            return Type{
                .data = .{ .ip_index = .{ .index = .type_type } },
                .is_type_val = true,
            };
        }

        if (self.data == .ip_index) {
            return Type{
                .data = .{ .ip_index = .{ .index = analyser.ip.typeOf(self.data.ip_index.index) } },
                .is_type_val = true,
            };
        }

        return Type{
            .data = self.data,
            .is_type_val = true,
        };
    }

    fn isRoot(self: Type) bool {
        switch (self.data) {
            .container => |container_scope_handle| return container_scope_handle.scope == Scope.Index.root,
            else => return false,
        }
    }

    fn isContainerKind(self: Type, container_kind_tok: std.zig.Token.Tag) bool {
        const scope_handle = switch (self.data) {
            .container => |s| s,
            else => return false,
        };

        const node = scope_handle.toNode();

        const tree = scope_handle.handle.tree;
        const main_tokens = tree.nodes.items(.main_token);
        const tags = tree.tokens.items(.tag);
        return tags[main_tokens[node]] == container_kind_tok;
    }

    pub fn isStructType(self: Type) bool {
        return self.isContainerKind(.keyword_struct) or self.isRoot();
    }

    pub fn isNamespace(self: Type) bool {
        if (!self.isStructType()) return false;
        const scope_handle = self.data.container;
        const node = scope_handle.toNode();
        const tree = scope_handle.handle.tree;
        const tags = tree.nodes.items(.tag);
        var buf: [2]Ast.Node.Index = undefined;
        const full = tree.fullContainerDecl(&buf, node) orelse return true;
        for (full.ast.members) |member| {
            if (tags[member].isContainerField()) return false;
        }
        return true;
    }

    pub fn isEnumType(self: Type) bool {
        return self.isContainerKind(.keyword_enum);
    }

    pub fn isUnionType(self: Type) bool {
        return self.isContainerKind(.keyword_union);
    }

    pub fn isOpaqueType(self: Type) bool {
        return self.isContainerKind(.keyword_opaque);
    }

    pub fn isTaggedUnion(self: Type) bool {
        return switch (self.data) {
            .container => |scope_handle| ast.isTaggedUnion(scope_handle.handle.tree, scope_handle.toNode()),
            else => false,
        };
    }

    /// returns whether the given type is of type `type`.
    pub fn isMetaType(self: Type) bool {
        if (!self.is_type_val) return false;
        switch (self.data) {
            .other => |node_handle| return Analyser.isMetaType(node_handle.handle.tree, node_handle.node),
            .ip_index => |payload| return payload.index == .type_type,
            else => return false,
        }
    }

    pub fn isEnumLiteral(self: Type, analyser: *Analyser) bool {
        switch (self.data) {
            .ip_index => |payload| return analyser.ip.typeOf(payload.index) == .enum_literal_type,
            else => return false,
        }
    }

    pub fn isTypeFunc(self: Type) bool {
        var buf: [1]Ast.Node.Index = undefined;
        return switch (self.data) {
            .other => |node_handle| if (node_handle.handle.tree.fullFnProto(&buf, node_handle.node)) |fn_proto| blk: {
                break :blk isTypeFunction(node_handle.handle.tree, fn_proto);
            } else false,
            else => false,
        };
    }

    /// Returns whether the given function has a `anytype` parameter.
    pub fn isGenericFunc(self: Type) bool {
        return switch (self.data) {
            .other => |node_handle| {
                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = node_handle.handle.tree.fullFnProto(&buf, node_handle.node) orelse return false;
                var it = fn_proto.iterate(&node_handle.handle.tree);
                while (ast.nextFnParam(&it)) |param| {
                    if (param.anytype_ellipsis3 != null or param.comptime_noalias != null) {
                        return true;
                    }
                }
                return false;
            },
            else => false,
        };
    }

    pub fn isFunc(self: Type) bool {
        return switch (self.data) {
            .other => |node_handle| switch (node_handle.handle.tree.nodes.items(.tag)[node_handle.node]) {
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

    pub fn typeDefinitionToken(self: Type) !?TokenWithHandle {
        return switch (self.data) {
            .container => |scope_handle| .{
                .token = scope_handle.handle.tree.firstToken(scope_handle.toNode()),
                .handle = scope_handle.handle,
            },
            .other => |node_handle| .{
                .token = node_handle.handle.tree.firstToken(node_handle.node),
                .handle = node_handle.handle,
            },
            else => null,
        };
    }

    pub fn docComments(self: Type, allocator: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        if (self.is_type_val) {
            switch (self.data) {
                .container => |scope_handle| return try getDocComments(allocator, scope_handle.handle.tree, scope_handle.toNode()),
                .other => |node_handle| return try getDocComments(allocator, node_handle.handle.tree, node_handle.node),
                else => {},
            }
        }
        return null;
    }

    pub fn lookupSymbol(
        self: Type,
        analyser: *Analyser,
        symbol: []const u8,
    ) error{OutOfMemory}!?DeclWithHandle {
        const scope_handle = switch (self.data) {
            .container => |s| s,
            .either => |entries| {
                // TODO: Return all options instead of first valid one
                for (entries) |entry| {
                    const entry_ty = Type{ .data = entry.type_data, .is_type_val = self.is_type_val };
                    if (try entry_ty.lookupSymbol(analyser, symbol)) |decl| {
                        return decl;
                    }
                }
                return null;
            },
            else => return null,
        };
        if (self.is_type_val) {
            if (try analyser.lookupSymbolContainer(scope_handle, symbol, .other)) |decl|
                return decl;
            if (self.isEnumType() or self.isTaggedUnion())
                return analyser.lookupSymbolContainer(scope_handle, symbol, .field);
            return null;
        }
        if (self.isEnumType())
            return analyser.lookupSymbolContainer(scope_handle, symbol, .other);
        if (try analyser.lookupSymbolContainer(scope_handle, symbol, .field)) |decl|
            return decl;
        return analyser.lookupSymbolContainer(scope_handle, symbol, .other);
    }

    pub fn fmt(ty: Type, analyser: *Analyser, options: FormatOptions) std.fmt.Formatter(format) {
        const typeof = ty.typeOf(analyser);
        return .{ .data = .{ .ty = typeof, .analyser = analyser, .options = options } };
    }

    pub fn fmtTypeVal(ty: Type, analyser: *Analyser, options: FormatOptions) std.fmt.Formatter(format) {
        std.debug.assert(ty.is_type_val);
        return .{ .data = .{ .ty = ty, .analyser = analyser, .options = options } };
    }

    pub const FormatOptions = struct {
        truncate_container_decls: bool,
    };

    const FormatContext = struct {
        ty: Type,
        analyser: *Analyser,
        options: FormatOptions,
    };

    fn format(
        ctx: FormatContext,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, ctx.ty);

        const ty = ctx.ty;
        const analyser = ctx.analyser;

        switch (ty.data) {
            .pointer => |info| {
                switch (info.size) {
                    .One => try writer.writeByte('*'),
                    .Many => {
                        try writer.writeAll("[*");
                        if (info.sentinel != .none) {
                            try writer.print(":{}", .{info.sentinel.fmt(analyser.ip)});
                        }
                        try writer.writeByte(']');
                    },
                    .Slice => {
                        try writer.writeAll("[");
                        if (info.sentinel != .none) {
                            try writer.print(":{}", .{info.sentinel.fmt(analyser.ip)});
                        }
                        try writer.writeByte(']');
                    },
                    .C => try writer.writeAll("[*c]"),
                }
                if (info.is_const) try writer.writeAll("const ");
                return try writer.print("{}", .{info.elem_ty.fmtTypeVal(analyser, ctx.options)});
            },
            .array => |info| {
                try writer.writeByte('[');
                if (info.elem_count) |count| {
                    try writer.print("{d}", .{count});
                } else {
                    try writer.writeAll("?");
                }
                if (info.sentinel != .none) {
                    try writer.print(":{}", .{info.sentinel.fmt(analyser.ip)});
                }
                try writer.writeByte(']');
                try writer.print("{}", .{info.elem_ty.fmtTypeVal(analyser, ctx.options)});
            },
            .optional => |child_ty| try writer.print("?{}", .{child_ty.fmtTypeVal(analyser, ctx.options)}),
            .error_union => |info| {
                if (info.error_set) |error_set| {
                    try writer.print("{}", .{error_set.fmtTypeVal(analyser, ctx.options)});
                }
                try writer.print("!{}", .{info.payload.fmtTypeVal(analyser, ctx.options)});
            },
            .union_tag => |t| try writer.print("@typeInfo({}).Union.tag_type.?", .{t.fmtTypeVal(analyser, ctx.options)}),
            .container => |scope_handle| {
                const handle = scope_handle.handle;
                const tree = handle.tree;

                const doc_scope = try handle.getDocumentScope();
                const node = scope_handle.toNode();

                switch (handle.tree.nodes.items(.tag)[node]) {
                    .root => {
                        const path = URI.parse(analyser.arena.allocator(), handle.uri) catch handle.uri;
                        try writer.writeAll(std.fs.path.stem(path));
                    },

                    .container_decl,
                    .container_decl_arg,
                    .container_decl_arg_trailing,
                    .container_decl_trailing,
                    .container_decl_two,
                    .container_decl_two_trailing,
                    .error_set_decl,
                    .tagged_union,
                    .tagged_union_trailing,
                    .tagged_union_two,
                    .tagged_union_two_trailing,
                    .tagged_union_enum_tag,
                    .tagged_union_enum_tag_trailing,
                    => {
                        const token_tags = tree.tokens.items(.tag);
                        const token_starts = tree.tokens.items(.start);

                        // This is a hacky nightmare but it works :P
                        const token = tree.firstToken(node);
                        if (token >= 2 and token_tags[token - 2] == .identifier and token_tags[token - 1] == .equal) {
                            try writer.writeAll(tree.tokenSlice(token - 2));
                            return;
                        }
                        if (token >= 1 and token_tags[token - 1] == .keyword_return) blk: {
                            const function_scope = innermostFunctionScopeAtIndex(doc_scope, token_starts[token - 1]).unwrap() orelse break :blk;
                            const function_node = doc_scope.getScopeAstNode(function_scope).?;
                            var buf: [1]Ast.Node.Index = undefined;
                            const func = tree.fullFnProto(&buf, function_node).?;
                            const func_name_token = func.name_token orelse break :blk;
                            const func_name = offsets.tokenToSlice(tree, func_name_token);
                            try writer.print("{s}(...)", .{func_name});
                            return;
                        }

                        if (!ctx.options.truncate_container_decls) {
                            try writer.writeAll(offsets.nodeToSlice(tree, node));
                            return;
                        }

                        if (tree.nodes.items(.tag)[node] == .error_set_decl) {
                            const field_count = ast.errorSetFieldCount(tree, node);
                            if (field_count > 2) {
                                try writer.writeAll("error{...}");
                                return;
                            }

                            var it = ast.ErrorSetIterator.init(tree, node);
                            var i: usize = 0;

                            try writer.writeAll("error{");
                            while (it.next()) |identifier_token| : (i += 1) {
                                if (i != 0) {
                                    try writer.writeByte(',');
                                }
                                const name = offsets.tokenToSlice(tree, identifier_token);
                                try writer.writeAll(name);
                            }
                            try writer.writeByte('}');

                            return;
                        }

                        var buffer: [2]Ast.Node.Index = undefined;
                        const container_decl = tree.fullContainerDecl(&buffer, node).?;

                        const start_token = container_decl.layout_token orelse container_decl.ast.main_token;
                        const end_token = if (container_decl.ast.arg != 0)
                            @min(ast.lastToken(tree, container_decl.ast.arg) + 1, tree.tokens.len)
                        else if (container_decl.ast.enum_token) |enum_token|
                            @min(enum_token + 1, tree.tokens.len)
                        else
                            container_decl.ast.main_token;

                        try writer.writeAll(offsets.tokensToSlice(tree, start_token, end_token));
                        if (container_decl.ast.members.len == 0) {
                            try writer.writeAll(" {}");
                        } else {
                            try writer.writeAll(" {...}");
                        }
                    },

                    else => unreachable,
                }
            },
            .other => |node_handle| switch (node_handle.handle.tree.nodes.items(.tag)[node_handle.node]) {
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => {
                    var buf: [1]Ast.Node.Index = undefined;
                    const fn_proto = node_handle.handle.tree.fullFnProto(&buf, node_handle.node).?;

                    try writer.print("{}", .{fmtFunction(.{
                        .fn_proto = fn_proto,
                        .tree = &node_handle.handle.tree,
                        .include_fn_keyword = true,
                        .include_name = false,
                        .skip_first_param = false,
                        .parameters = .{ .show = .{
                            .include_modifiers = true,
                            .include_names = true,
                            .include_types = true,
                        } },
                        .include_return_type = true,
                        .snippet_placeholders = false,
                    })});
                },
                .merge_error_sets => if (ctx.options.truncate_container_decls) try writer.writeAll("error{...}") else try writer.writeAll(offsets.nodeToSlice(node_handle.handle.tree, node_handle.node)),
                else => try writer.writeAll(offsets.nodeToSlice(node_handle.handle.tree, node_handle.node)),
            },
            .ip_index => |payload| try analyser.ip.print(payload.index, writer, .{}),
            .either => try writer.writeAll("either type"), // TODO
            .compile_error => |node_handle| try writer.writeAll(offsets.nodeToSlice(node_handle.handle.tree, node_handle.node)),
        }
    }
};

pub const ScopeWithHandle = struct {
    handle: *DocumentStore.Handle,
    scope: Scope.Index,

    pub fn toNode(scope_handle: ScopeWithHandle) Ast.Node.Index {
        if (scope_handle.scope == Scope.Index.root) return 0;
        var doc_scope = scope_handle.handle.getDocumentScopeCached();
        return doc_scope.getScopeAstNode(scope_handle.scope).?;
    }
};

/// Look up `type_name` in 'zig_lib_path/std/builtin.zig' and return it as an instance
/// Useful for functionality related to builtin fns
pub fn instanceStdBuiltinType(analyser: *Analyser, type_name: []const u8) error{OutOfMemory}!?Type {
    const zig_lib_path = analyser.store.config.zig_lib_path orelse return null;
    const builtin_path = try std.fs.path.join(analyser.arena.allocator(), &.{ zig_lib_path, "std", "builtin.zig" });
    const builtin_uri = try URI.fromPath(analyser.arena.allocator(), builtin_path);

    const builtin_handle = analyser.store.getOrLoadHandle(builtin_uri) orelse return null;
    const builtin_root_struct_type: Type = .{
        .data = .{ .container = .{ .handle = builtin_handle, .scope = Scope.Index.root } },
        .is_type_val = true,
    };

    const builtin_type_decl = try builtin_root_struct_type.lookupSymbol(analyser, type_name) orelse return null;
    const builtin_type = try builtin_type_decl.resolveType(analyser) orelse return null;
    return try builtin_type.instanceTypeVal(analyser);
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
    handle: *DocumentStore.Handle,

    pub fn eql(a: NodeWithHandle, b: NodeWithHandle) bool {
        if (a.node != b.node) return false;
        return std.mem.eql(u8, a.handle.uri, b.handle.uri);
    }

    pub fn resolveType(self: NodeWithHandle, analyser: *Analyser) error{OutOfMemory}!?Type {
        return analyser.resolveTypeOfNodeInternal(self);
    }
};

pub fn getFieldAccessType(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?Type {
    analyser.bound_type_params.clearRetainingCapacity();

    const held_range = try analyser.arena.allocator().dupeZ(u8, offsets.locToSlice(handle.tree.source, loc));
    var tokenizer = std.zig.Tokenizer.init(held_range);
    var current_type: ?Type = null;

    var do_unwrap_error_payload = false; // .keyword_try seen, ie `(try foo())`

    while (true) {
        const tok = tokenizer.next();
        switch (tok.tag) {
            .eof => return current_type,
            .identifier => {
                const symbol_name = offsets.identifierIndexToNameSlice(tokenizer.buffer, tok.loc.start);
                if (try analyser.lookupSymbolGlobal(
                    handle,
                    symbol_name,
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
                            return ct;
                        } else {
                            return null;
                        }
                    },
                    .identifier => {
                        if (after_period.loc.end == tokenizer.buffer.len) {
                            return current_type;
                        }

                        const symbol = offsets.identifierIndexToNameSlice(tokenizer.buffer, after_period.loc.start);

                        current_type = try analyser.resolveFieldAccess(current_type orelse return null, symbol) orelse return null;
                    },
                    .question_mark => {
                        current_type = (try analyser.resolveOptionalUnwrap(current_type orelse return null)) orelse return null;
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
                    // Likely `(expr)`
                    // Look for the corresponding .r_paren to form a slice of the contents
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
                    current_type = try getFieldAccessType(
                        analyser,
                        handle,
                        source_index,
                        .{
                            // tok.loc and next.loc are offsets within held_range,
                            // add to loc.start to get offsets within handle.tree.source
                            .start = loc.start + tok.loc.end,
                            .end = loc.start + next.loc.start,
                        },
                    ) orelse return null;
                    continue;
                }

                const ty = try analyser.resolveFuncProtoOfCallable(current_type.?) orelse return null;

                // Can't call a function type, we need a function type instance.
                if (current_type.?.is_type_val) return null;
                // this assumes that function types can only be Ast nodes
                const current_type_node_handle = ty.data.other;
                const current_type_node = current_type_node_handle.node;
                const current_type_handle = current_type_node_handle.handle;

                const cur_tree = current_type_handle.tree;
                var buf: [1]Ast.Node.Index = undefined;
                const func = cur_tree.fullFnProto(&buf, current_type_node).?;
                // Check if the function has a body and if so, pass it
                // so the type can be resolved if it's a generic function returning
                // an anonymous struct
                const has_body = cur_tree.nodes.items(.tag)[current_type_node] == .fn_decl;
                const body = cur_tree.nodes.items(.data)[current_type_node].rhs;

                // TODO Actually bind params here when calling functions instead of just skipping args.
                current_type = try analyser.resolveReturnType(func, current_type_handle, if (has_body) body else null) orelse return null;

                if (do_unwrap_error_payload) {
                    if (try analyser.resolveUnwrapErrorUnionType(current_type.?, .payload)) |unwrapped| current_type = unwrapped;
                    do_unwrap_error_payload = false;
                }

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
            },
            .l_bracket => {
                var bracket_count: usize = 1;
                var kind: BracketAccessKind = .Single;

                while (true) {
                    const token = tokenizer.next();
                    switch (token.tag) {
                        .eof => return null,
                        .r_bracket => {
                            bracket_count -= 1;
                            if (bracket_count == 0) break;
                        },
                        .l_bracket => {
                            bracket_count += 1;
                        },
                        .ellipsis2 => {
                            if (bracket_count == 1) {
                                kind = .Open;
                            }
                        },
                        else => {
                            if (bracket_count == 1 and kind == .Open) {
                                kind = .Range;
                            }
                        },
                    }
                } else unreachable;

                current_type = (try analyser.resolveBracketAccessType(current_type orelse return null, kind)) orelse return null;
            },
            .builtin => {
                const binfn_name = tokenizer.buffer[tok.loc.start..tok.loc.end];

                if (std.mem.eql(u8, binfn_name, "@import")) {
                    if (tokenizer.next().tag != .l_paren) return null;
                    const import_str_tok = tokenizer.next(); // should be the .string_literal
                    if (import_str_tok.tag != .string_literal) return null;
                    if (import_str_tok.loc.end - import_str_tok.loc.start < 2) return null;
                    const import_str = offsets.locToSlice(tokenizer.buffer, .{
                        .start = import_str_tok.loc.start + 1,
                        .end = import_str_tok.loc.end - 1,
                    });
                    const uri = try analyser.store.uriFromImportStr(analyser.arena.allocator(), handle, import_str) orelse return null;
                    const node_handle = analyser.store.getOrLoadHandle(uri) orelse return null;
                    current_type = .{
                        .data = .{
                            .container = .{
                                .handle = node_handle,
                                .scope = @enumFromInt(0),
                            },
                        },
                        .is_type_val = true,
                    };
                    _ = tokenizer.next(); // eat the .r_paren
                    continue; // Outermost `while`
                }

                if (std.mem.eql(u8, binfn_name, "@typeInfo")) {
                    current_type = try analyser.instanceStdBuiltinType("Type") orelse return null;
                    // Skip to the right paren
                    var paren_count: usize = 0;
                    var next = tokenizer.next();
                    while (next.tag != .eof) : (next = tokenizer.next()) {
                        if (next.tag == .r_paren) {
                            paren_count -= 1;
                            if (paren_count == 0) break;
                        } else if (next.tag == .l_paren) {
                            paren_count += 1;
                        }
                    } else return null;
                    continue; // Outermost `while`
                }

                log.debug("Unhandled builtin: {s}", .{offsets.locToSlice(tokenizer.buffer, tok.loc)});
                return null;
            },
            // only hit when `(try foo())` otherwise getPositionContext never includes the `try` keyword
            .keyword_try => do_unwrap_error_payload = true,
            else => {
                log.debug("Unimplemented token: {}", .{tok.tag});
                return null;
            },
        }
    }

    return current_type;
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
    number_literal: offsets.Loc,
    char_literal: offsets.Loc,
    /// XXX: Internal use only, currently points to the loc of the first l_paren
    parens_expr: offsets.Loc,
    keyword: std.zig.Token.Tag,
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
            .number_literal => |r| r,
            .char_literal => |r| r,
            .parens_expr => |r| r,
            .keyword => null,
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
) error{OutOfMemory}!PositionContext {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var new_index = doc_index;
    if (lookahead) {
        // looking for possible end of char literal
        if (std.mem.indexOf(u8, text[doc_index..@min(doc_index + 2, text.len)], &.{'\''})) |char_index| {
            if (text[new_index + char_index - 1] == '\\') {
                // handles escaped single quotes '\''
                new_index = @min(new_index + char_index + 2, text.len - 1);
            } else {
                new_index += char_index + 1;
            }
        } else if (new_index + 2 < text.len) {
            if (text[new_index] == '@') new_index += 2;
            while (new_index < text.len and isSymbolChar(text[new_index])) : (new_index += 1) {}
            if (new_index < text.len) {
                switch (text[new_index]) {
                    ':' => { // look for `id:`, but avoid `a: T` by checking for a `{` following the ':'
                        var b_index = new_index + 1;
                        while (b_index < text.len and text[b_index] == ' ') : (b_index += 1) {} // eat spaces
                        if (text[b_index] == '{') new_index += 1; // current new_index points to ':', but slc ends are exclusive => `text[0..pos_of_r_brace]`
                    },
                    // ';' => new_index += 1, // XXX: currently given `some;` the last letter gets cut off, ie `som`, but fixing it breaks existing logic.. ?
                    else => {},
                }
            }
        }
    }

    const prev_char = if (new_index > 0) text[new_index - 1] else 0;
    var line_loc = if (!lookahead) offsets.lineLocAtIndex(text, new_index) else offsets.lineLocUntilIndex(text, new_index);
    const line = offsets.locToSlice(text, line_loc);

    if (std.mem.startsWith(u8, std.mem.trimLeft(u8, line, " \t"), "//")) return .comment;

    // Check if the (trimmed) line starts with a '.', ie a continuation
    while (line_loc.start > 0) {
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
        if (line_loc.start != 0 and std.mem.startsWith(u8, std.mem.trimLeft(u8, text[line_loc.start..line_loc.end], " \t"), "//")) {
            const prev_line_loc = offsets.lineLocAtIndex(text, line_loc.start - 1); // `- 1` => prev line's `\n`
            line_loc.start = prev_line_loc.start;
            continue;
        }
        break;
    }

    var stack = try std.ArrayListUnmanaged(StackState).initCapacity(allocator, 8);
    defer stack.deinit(allocator);

    {
        var held_line = try allocator.dupeZ(u8, text[0..line_loc.end]);
        defer allocator.free(held_line);

        var tokenizer: std.zig.Tokenizer = .{
            .buffer = held_line,
            .index = line_loc.start,
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
                    .empty,
                    .pre_label,
                    .var_access,
                    .parens_expr,
                    => curr_ctx.ctx = .{ .var_access = tok.loc },
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
                .builtin => curr_ctx.ctx = .{ .builtin = tok.loc },
                .period, .period_asterisk => switch (curr_ctx.ctx) {
                    .empty, .pre_label => curr_ctx.ctx = .{ .enum_literal = tok.loc },
                    .enum_literal => curr_ctx.ctx = .empty,
                    .field_access => {},
                    .keyword => return .other, // no keyword can be `.`/`.*` accessed
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
                } else if (curr_ctx.ctx == .var_access) {
                    curr_ctx.ctx = .{ .label = true };
                } else {
                    curr_ctx.ctx = .empty;
                },
                .question_mark => switch (curr_ctx.ctx) {
                    .field_access => {},
                    else => curr_ctx.ctx = .empty,
                },
                .l_paren => {
                    if (curr_ctx.ctx == .empty) curr_ctx.ctx = .{ .parens_expr = tok.loc };
                    try stack.append(allocator, .{ .ctx = .empty, .stack_id = .Paren });
                },
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
                .number_literal => {
                    if (tok.loc.start <= doc_index and tok.loc.end >= doc_index) {
                        return PositionContext{ .number_literal = tok.loc };
                    }
                },
                .char_literal => {
                    if (tok.loc.start <= doc_index and tok.loc.end >= doc_index) {
                        return PositionContext{ .char_literal = tok.loc };
                    }
                },
                .keyword_callconv, .keyword_addrspace => curr_ctx.ctx = .{ .keyword = tok.tag },
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
            .parens_expr => |loc| return .{ .var_access = loc },
            else => return state.ctx,
        }
    }

    if (line.len == 0) return .empty;

    const held_line = try allocator.dupeZ(u8, offsets.locToSlice(text, line_loc));
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
    handle: *DocumentStore.Handle,
};

pub const DeclWithHandle = struct {
    decl: Declaration,
    handle: *DocumentStore.Handle,

    pub fn eql(a: DeclWithHandle, b: DeclWithHandle) bool {
        return a.decl.eql(b.decl) and std.mem.eql(u8, a.handle.uri, b.handle.uri);
    }

    /// Returns a `.identifier` or `.builtin` token.
    pub fn nameToken(self: DeclWithHandle) Ast.TokenIndex {
        return self.decl.nameToken(self.handle.tree);
    }

    pub fn definitionToken(self: DeclWithHandle, analyser: *Analyser, resolve_alias: bool) error{OutOfMemory}!TokenWithHandle {
        if (resolve_alias) {
            switch (self.decl) {
                .ast_node => |node| {
                    if (try analyser.resolveVarDeclAlias(.{ .node = node, .handle = self.handle })) |result| {
                        return result.definitionToken(analyser, resolve_alias);
                    }
                },
                else => {},
            }
            if (try self.resolveType(analyser)) |resolved_type| {
                if (resolved_type.is_type_val) {
                    if (try resolved_type.typeDefinitionToken()) |token| {
                        return token;
                    }
                }
            }
        }
        return .{ .token = self.nameToken(), .handle = self.handle };
    }

    pub fn typeDeclarationNode(self: DeclWithHandle) error{OutOfMemory}!?NodeWithHandle {
        const tree = self.handle.tree;
        switch (self.decl) {
            .ast_node => |node| switch (tree.nodes.items(.tag)[node]) {
                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl,
                => {
                    const var_decl = tree.fullVarDecl(node).?;
                    if (var_decl.ast.type_node == 0) return null;
                    return .{ .node = var_decl.ast.type_node, .handle = self.handle };
                },
                .container_field_init,
                .container_field_align,
                .container_field,
                => {
                    const container_field = tree.fullContainerField(node).?;
                    if (container_field.ast.type_expr == 0) return null;
                    return .{ .node = container_field.ast.type_expr, .handle = self.handle };
                },
                else => return null,
            },
            .assign_destructure => |payload| {
                const var_decl = payload.getFullVarDecl(tree);
                if (var_decl.ast.type_node == 0) return null;
                return .{ .node = var_decl.ast.type_node, .handle = self.handle };
            },
            .function_parameter => |payload| {
                const param = payload.get(tree).?;
                if (param.type_expr == 0) return null;
                return .{ .node = param.type_expr, .handle = self.handle };
            },
            .optional_payload,
            .error_union_payload,
            .error_union_error,
            .for_loop_payload,
            .switch_payload,
            => return null, // the payloads can't have a type specifier

            .label,
            .error_token,
            => return null,
        }
    }

    pub fn isConst(self: DeclWithHandle) bool {
        const tree = self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| switch (tree.nodes.items(.tag)[node]) {
                .global_var_decl,
                .local_var_decl,
                .aligned_var_decl,
                .simple_var_decl,
                => {
                    const mut_token = tree.fullVarDecl(node).?.ast.mut_token;
                    switch (tree.tokens.items(.tag)[mut_token]) {
                        .keyword_var => return false,
                        .keyword_const => return true,
                        else => unreachable,
                    }
                },
                // `.container_decl_*`
                // `.tagged_union_*`
                // `.container_field_*`
                // `.fn_proto_*`
                // `.fn_decl`
                else => true,
            },
            .assign_destructure => |payload| {
                const mut_token = payload.getFullVarDecl(tree).ast.mut_token;
                switch (tree.tokens.items(.tag)[mut_token]) {
                    .keyword_var => return false,
                    .keyword_const => return true,
                    else => unreachable,
                }
            },
            // some payload may be capture by ref but the pointer value is constant
            .function_parameter,
            .optional_payload,
            .for_loop_payload,
            .error_union_payload,
            .error_union_error,
            .switch_payload,
            .label,
            .error_token,
            => true,
        };
    }

    pub fn isCaptureByRef(self: DeclWithHandle) bool {
        const tree = self.handle.tree;
        const token_tags = tree.tokens.items(.tag);
        return switch (self.decl) {
            .ast_node,
            .function_parameter,
            .error_union_error,
            .assign_destructure,
            .label,
            .error_token,
            => false,
            inline .optional_payload,
            .for_loop_payload,
            .error_union_payload,
            => |payload| token_tags[payload.identifier - 1] == .asterisk,
            .switch_payload => |payload| token_tags[payload.getCase(tree).payload_token.?] == .asterisk,
        };
    }

    pub fn docComments(self: DeclWithHandle, allocator: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        const tree = self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| try getDocComments(allocator, tree, node),
            .function_parameter => |pay| {
                const param = pay.get(tree).?;
                const doc_comments = param.first_doc_comment orelse return null;
                return try collectDocComments(allocator, tree, doc_comments, false);
            },
            .error_token => |token| try getDocCommentsBeforeToken(allocator, tree, token),
            else => null,
        };
    }

    pub fn isPublic(self: DeclWithHandle) bool {
        const tree = self.handle.tree;
        var buf: [1]Ast.Node.Index = undefined;
        return switch (self.decl) {
            .ast_node => |node| switch (tree.nodes.items(.tag)[node]) {
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
            },
            else => true,
        };
    }

    pub fn resolveType(self: DeclWithHandle, analyser: *Analyser) error{OutOfMemory}!?Type {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const tree = self.handle.tree;
        const resolved_ty = switch (self.decl) {
            .ast_node => |node| try analyser.resolveTypeOfNodeInternal(
                .{ .node = node, .handle = self.handle },
            ),
            .function_parameter => |pay| blk: {
                // the `get` function never fails on declarations from the DocumentScope but
                // there may be manually created Declarations with invalid parameter indices.
                const param = pay.get(tree) orelse return null;

                // handle anytype
                if (param.type_expr == 0) {
                    const tracy_zone_inner = tracy.traceNamed(@src(), "resolveCallsiteReferences");
                    defer tracy_zone_inner.end();

                    const is_cimport = std.mem.eql(u8, std.fs.path.basename(self.handle.uri), "cimport.zig");

                    if (is_cimport or !analyser.collect_callsite_references) return null;

                    // protection against recursive callsite resolution
                    const gop_resolved = try analyser.resolved_callsites.getOrPut(analyser.gpa, pay);
                    if (gop_resolved.found_existing) break :blk gop_resolved.value_ptr.*;
                    gop_resolved.value_ptr.* = null;

                    const func_decl = Declaration{ .ast_node = pay.func };

                    var func_buf: [1]Ast.Node.Index = undefined;
                    const func = tree.fullFnProto(&func_buf, pay.func).?;

                    var func_params_len: usize = 0;

                    var it = func.iterate(&tree);
                    while (ast.nextFnParam(&it)) |_| {
                        func_params_len += 1;
                    }

                    const refs = try references.callsiteReferences(
                        analyser.arena.allocator(),
                        analyser,
                        .{ .decl = func_decl, .handle = self.handle },
                        false,
                        false,
                        false,
                    );

                    // TODO: Set `workspace` to true; current problems
                    // - we gather dependencies, not dependents

                    var possible = std.ArrayListUnmanaged(Type.TypeWithDescriptor){};

                    for (refs.items) |ref| {
                        const handle = analyser.store.getOrLoadHandle(ref.uri).?;

                        var call_buf: [1]Ast.Node.Index = undefined;
                        const call = tree.fullCall(&call_buf, ref.call_node).?;

                        const real_param_idx = if (func_params_len != 0 and pay.param_index != 0 and call.ast.params.len == func_params_len - 1)
                            pay.param_index - 1
                        else
                            pay.param_index;

                        if (real_param_idx >= call.ast.params.len) continue;

                        const ty = resolve_ty: {
                            // don't resolve callsite references while resolving callsite references
                            const old_collect_callsite_references = analyser.collect_callsite_references;
                            defer analyser.collect_callsite_references = old_collect_callsite_references;
                            analyser.collect_callsite_references = false;

                            break :resolve_ty try analyser.resolveTypeOfNode(.{
                                // TODO?: this is a """heuristic based approach"""
                                // perhaps it would be better to use proper self detection
                                // maybe it'd be a perf issue and this is fine?
                                // you figure it out future contributor <3
                                .node = call.ast.params[real_param_idx],
                                .handle = handle,
                            }) orelse continue;
                        };

                        const loc = offsets.tokenToPosition(tree, tree.nodes.items(.main_token)[call.ast.params[real_param_idx]], .@"utf-8");
                        try possible.append(analyser.arena.allocator(), .{
                            .type = ty,
                            .descriptor = try std.fmt.allocPrint(analyser.arena.allocator(), "{s}:{d}:{d}", .{ handle.uri, loc.line + 1, loc.character + 1 }),
                        });
                    }

                    const maybe_type = try Type.fromEither(analyser.arena.allocator(), possible.items);
                    if (maybe_type) |ty| analyser.resolved_callsites.getPtr(pay).?.* = ty;
                    break :blk maybe_type;
                }

                const param_type = try analyser.resolveTypeOfNodeInternal(
                    .{ .node = param.type_expr, .handle = self.handle },
                ) orelse return null;

                if (param_type.isMetaType()) {
                    if (analyser.bound_type_params.get(.{ .func = pay.func, .param_index = pay.param_index })) |resolved_type| {
                        break :blk resolved_type;
                    }
                }

                break :blk try param_type.instanceTypeVal(analyser);
            },
            .optional_payload => |pay| blk: {
                const ty = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.condition,
                    .handle = self.handle,
                })) orelse return null;
                break :blk try analyser.resolveOptionalUnwrap(ty);
            },
            .error_union_payload => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.condition,
                    .handle = self.handle,
                })) orelse return null,
                .payload,
            ),
            .error_union_error => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = if (pay.condition == 0) return null else pay.condition,
                    .handle = self.handle,
                })) orelse return null,
                .error_set,
            ),
            .for_loop_payload => |pay| try analyser.resolveBracketAccessType(
                (try analyser.resolveTypeOfNodeInternal(.{
                    .node = pay.condition,
                    .handle = self.handle,
                })) orelse return null,
                .Single,
            ),
            .assign_destructure => |pay| blk: {
                const type_node = pay.getFullVarDecl(tree).ast.type_node;
                if (type_node != 0) {
                    if (try analyser.resolveTypeOfNode(.{
                        .node = type_node,
                        .handle = self.handle,
                    })) |ty| break :blk try ty.instanceTypeVal(analyser);
                }
                const node = try analyser.resolveTypeOfNode(.{
                    .node = tree.nodes.items(.data)[pay.node].rhs,
                    .handle = self.handle,
                }) orelse return null;
                break :blk switch (node.data) {
                    .array => |array_info| try array_info.elem_ty.instanceTypeVal(analyser),
                    .container => try analyser.resolveTupleFieldType(node, pay.index),
                    else => null,
                };
            },
            .label => |decl| try analyser.resolveTypeOfNodeInternal(.{
                .node = decl.block,
                .handle = self.handle,
            }),
            .switch_payload => |payload| blk: {
                const cond = tree.nodes.items(.data)[payload.node].lhs;
                const case = payload.getCase(tree);

                const switch_expr_type: Type = (try analyser.resolveTypeOfNodeInternal(.{
                    .node = cond,
                    .handle = self.handle,
                })) orelse return null;
                if (switch_expr_type.isEnumType()) break :blk switch_expr_type;
                if (!switch_expr_type.isUnionType()) return null;

                // TODO Peer type resolution, we just use the first resolvable item for now.
                for (case.ast.values) |case_value| {
                    if (tree.nodes.items(.tag)[case_value] != .enum_literal) continue;

                    const name = tree.tokenSlice(tree.nodes.items(.main_token)[case_value]);
                    const decl = try switch_expr_type.lookupSymbol(analyser, name) orelse continue;
                    break :blk (try decl.resolveType(analyser)) orelse continue;
                }

                return null;
            },
            .error_token => return null,
        } orelse return null;

        if (!self.isCaptureByRef()) return resolved_ty;

        const resolved_ty_ptr = try analyser.arena.allocator().create(Type);
        resolved_ty_ptr.* = resolved_ty.typeOf(analyser);

        return Type{
            .data = .{ .pointer = .{
                .elem_ty = resolved_ty_ptr,
                .sentinel = .none,
                .is_const = false,
                .size = .One,
            } },
            .is_type_val = false,
        };
    }
};

/// Collects all symbols/declarations that can be a accessed on the given container type.
pub fn collectDeclarationsOfContainer(
    analyser: *Analyser,
    /// A container type (i.e. `struct`, `union`, `enum`, `opaque`)
    container_scope: ScopeWithHandle,
    original_handle: *DocumentStore.Handle,
    /// Whether or not the container type is a instance of its type.
    /// ```zig
    /// const NotInstance = struct{};
    /// const instance = @as(struct{}, ...);
    /// ```
    instance_access: bool,
    /// allocated with `analyser.arena.allocator()`
    decl_collection: *std.ArrayListUnmanaged(DeclWithHandle),
) error{OutOfMemory}!void {
    const scope = container_scope.scope;
    const handle = container_scope.handle;

    const tree = handle.tree;
    const document_scope = try handle.getDocumentScope();
    const container_node = container_scope.toNode();
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const main_token = tree.nodes.items(.main_token)[container_node];

    const is_enum = token_tags[main_token] == .keyword_enum;

    const scope_decls = document_scope.getScopeDeclarationsConst(scope);

    for (scope_decls) |decl_index| {
        const decl = document_scope.declarations.get(@intFromEnum(decl_index));
        const decl_with_handle = DeclWithHandle{ .decl = decl, .handle = handle };
        if (handle != original_handle and !decl_with_handle.isPublic()) continue;

        switch (decl) {
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
                    if (instance_access) {
                        // allow declarations which evaluate to functions where
                        // the first parameter has the type of the container:
                        const alias_type = try analyser.resolveTypeOfNode(.{ .node = node, .handle = handle }) orelse continue;
                        const func_ty = try analyser.resolveFuncProtoOfCallable(alias_type) orelse continue;

                        if (!try analyser.firstParamIs(func_ty, .{
                            .data = .{
                                .container = .{
                                    .handle = handle,
                                    .scope = scope,
                                },
                            },
                            .is_type_val = true,
                        })) continue;
                    }
                },
                else => {},
            },
            .label => continue,
            else => {},
        }

        try decl_collection.append(analyser.arena.allocator(), decl_with_handle);
    }

    for (document_scope.getScopeUsingnamespaceNodesConst(scope)) |use| {
        try analyser.collectUsingnamespaceDeclarationsOfContainer(
            .{ .node = use, .handle = handle },
            original_handle,
            false,
            decl_collection,
        );
    }
}

fn collectUsingnamespaceDeclarationsOfContainer(
    analyser: *Analyser,
    usingnamespace_node: NodeWithHandle,
    original_handle: *DocumentStore.Handle,
    instance_access: bool,
    decl_collection: *std.ArrayListUnmanaged(DeclWithHandle),
) !void {
    const gop = try analyser.use_trail.getOrPut(analyser.gpa, .{ .node = usingnamespace_node.node, .uri = usingnamespace_node.handle.uri });
    if (gop.found_existing) return;
    defer std.debug.assert(analyser.use_trail.remove(.{ .node = usingnamespace_node.node, .uri = usingnamespace_node.handle.uri }));

    const handle = usingnamespace_node.handle;
    const tree = handle.tree;

    const use_token = tree.nodes.items(.main_token)[usingnamespace_node.node];
    const is_pub = use_token > 0 and tree.tokens.items(.tag)[use_token - 1] == .keyword_pub;
    if (handle != original_handle and !is_pub) return;

    const use_expr = (try analyser.resolveTypeOfNode(.{
        .node = tree.nodes.items(.data)[usingnamespace_node.node].lhs,
        .handle = handle,
    })) orelse return;

    switch (use_expr.data) {
        .container => |container_scope| {
            try analyser.collectDeclarationsOfContainer(
                container_scope,
                original_handle,
                instance_access,
                decl_collection,
            );
        },
        .either => |entries| {
            for (entries) |entry| {
                switch (entry.type_data) {
                    .container => |container_scope| {
                        try analyser.collectDeclarationsOfContainer(
                            container_scope,
                            original_handle,
                            instance_access,
                            decl_collection,
                        );
                    },
                    else => continue,
                }
            }
        },
        else => return,
    }
}

/// Collects all symbols/declarations that are accessible at the given source index.
pub fn collectAllSymbolsAtSourceIndex(
    analyser: *Analyser,
    /// a handle to a Document
    handle: *DocumentStore.Handle,
    /// a byte-index into `handle.tree.source`
    source_index: usize,
    /// allocated with `analyser.arena.allocator()`
    decl_collection: *std.ArrayListUnmanaged(DeclWithHandle),
) error{OutOfMemory}!void {
    std.debug.assert(source_index <= handle.tree.source.len);
    analyser.use_trail.clearRetainingCapacity();

    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        const scope_decls = document_scope.getScopeDeclarationsConst(scope_index);
        for (scope_decls) |decl_index| {
            const decl = document_scope.declarations.get(@intFromEnum(decl_index));
            if (decl == .ast_node and handle.tree.nodes.items(.tag)[decl.ast_node].isContainerField()) continue;
            if (decl == .label) continue;
            try decl_collection.append(analyser.arena.allocator(), .{ .decl = decl, .handle = handle });
        }

        for (document_scope.getScopeUsingnamespaceNodesConst(scope_index)) |use| {
            try analyser.collectUsingnamespaceDeclarationsOfContainer(
                .{ .node = use, .handle = handle },
                handle,
                false,
                decl_collection,
            );
        }
    }
}

pub const EnclosingScopeIterator = struct {
    document_scope: *const DocumentScope,
    current_scope: Scope.OptionalIndex,
    source_index: usize,

    pub fn next(self: *EnclosingScopeIterator) Scope.OptionalIndex {
        const current_scope = self.current_scope.unwrap() orelse return .none;

        defer self.current_scope = for (self.document_scope.getScopeChildScopesConst(current_scope)) |child_scope| {
            const child_loc = self.document_scope.scopes.items(.loc)[@intFromEnum(child_scope)];
            if (child_loc.start <= self.source_index and self.source_index <= child_loc.end) {
                break child_scope.toOptional();
            }
        } else .none;

        return self.current_scope;
    }
};

fn iterateEnclosingScopes(document_scope: *const DocumentScope, source_index: usize) EnclosingScopeIterator {
    return .{
        .document_scope = document_scope,
        .current_scope = @enumFromInt(0),
        .source_index = source_index,
    };
}

pub fn iterateLabels(handle: *DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype) error{OutOfMemory}!void {
    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        for (document_scope.getScopeDeclarationsConst(scope_index)) |decl_index| {
            const decl = document_scope.declarations.get(@intFromEnum(decl_index));
            if (decl != .label) continue;
            try callback(context, DeclWithHandle{ .decl = decl, .handle = handle });
        }
    }
}

pub fn innermostScopeAtIndex(document_scope: DocumentScope, source_index: usize) Scope.Index {
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    var scope_index: Scope.Index = scope_iterator.next().unwrap().?; // the DocumentScope's root scope must exist
    while (scope_iterator.next().unwrap()) |inner_scope| {
        scope_index = inner_scope;
    }
    return scope_index;
}

pub fn innermostFunctionScopeAtIndex(document_scope: DocumentScope, source_index: usize) Scope.OptionalIndex {
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    var scope_index: Scope.OptionalIndex = .none;
    while (scope_iterator.next().unwrap()) |inner_scope| {
        if (document_scope.getScopeTag(inner_scope) != .function) continue;
        scope_index = inner_scope.toOptional();
    }
    return scope_index;
}

pub fn innermostBlockScope(document_scope: DocumentScope, source_index: usize) Ast.Node.Index {
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    var ast_node: Ast.Node.Index = undefined; // the DocumentScope's root scope is guaranteed to have an Ast Node
    while (scope_iterator.next().unwrap()) |inner_scope| {
        if (document_scope.getScopeAstNode(inner_scope)) |node| {
            ast_node = node;
        }
    }
    return ast_node;
}

pub fn innermostContainer(handle: *DocumentStore.Handle, source_index: usize) error{OutOfMemory}!Type {
    const document_scope = try handle.getDocumentScope();
    var current: DocumentScope.Scope.Index = @enumFromInt(0);
    if (document_scope.scopes.len == 1) return .{
        .data = .{
            .container = .{
                .handle = handle,
                .scope = @enumFromInt(0),
            },
        },
        .is_type_val = true,
    };

    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        switch (document_scope.getScopeTag(scope_index)) {
            .container, .container_usingnamespace => current = scope_index,
            else => {},
        }
    }
    return .{
        .data = .{
            .container = .{
                .handle = handle,
                .scope = current,
            },
        },
        .is_type_val = true,
    };
}

fn resolveUse(analyser: *Analyser, uses: []const Ast.Node.Index, symbol: []const u8, handle: *DocumentStore.Handle) error{OutOfMemory}!?DeclWithHandle {
    for (uses) |index| {
        const gop = try analyser.use_trail.getOrPut(analyser.gpa, .{ .node = index, .uri = handle.uri });
        if (gop.found_existing) continue;
        defer std.debug.assert(analyser.use_trail.remove(.{ .node = index, .uri = handle.uri }));

        const tree = handle.tree;

        const expr = .{ .node = tree.nodes.items(.data)[index].lhs, .handle = handle };
        const expr_type = (try analyser.resolveTypeOfNodeUncached(expr)) orelse
            continue;

        if (!expr_type.is_type_val) continue;

        if (try expr_type.lookupSymbol(analyser, symbol)) |candidate| {
            if (candidate.handle == handle or candidate.isPublic()) {
                return candidate;
            }
        }
    }
    return null;
}

pub fn lookupLabel(
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(&document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        const decl_index = document_scope.getScopeDeclaration(.{
            .scope = scope_index,
            .name = symbol,
            .kind = .label,
        }).unwrap() orelse continue;
        const decl = document_scope.declarations.get(@intFromEnum(decl_index));

        std.debug.assert(decl == .label);

        return DeclWithHandle{ .decl = decl, .handle = handle };
    }
    return null;
}

pub fn lookupSymbolGlobal(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const tree = handle.tree;
    const document_scope = try handle.getDocumentScope();
    var current_scope = innermostScopeAtIndex(document_scope, source_index);

    while (true) {
        if (document_scope.getScopeDeclaration(.{
            .scope = current_scope,
            .name = symbol,
            .kind = .field,
        }).unwrap()) |decl_index| {
            const decl = document_scope.declarations.get(@intFromEnum(decl_index));
            std.debug.assert(decl == .ast_node);

            var field = tree.fullContainerField(decl.ast_node).?;
            field.convertToNonTupleLike(tree.nodes);

            const field_name = offsets.tokenToLoc(tree, field.ast.main_token);
            if (field_name.start <= source_index and source_index <= field_name.end)
                return DeclWithHandle{ .decl = decl, .handle = handle };
        }

        if (document_scope.getScopeDeclaration(.{
            .scope = current_scope,
            .name = symbol,
            .kind = .other,
        }).unwrap()) |decl_index| {
            const decl = document_scope.declarations.get(@intFromEnum(decl_index));
            return DeclWithHandle{ .decl = decl, .handle = handle };
        }
        if (try analyser.resolveUse(document_scope.getScopeUsingnamespaceNodesConst(current_scope), symbol, handle)) |result| return result;

        current_scope = document_scope.getScopeParent(current_scope).unwrap() orelse break;
    }

    return null;
}

pub fn lookupSymbolContainer(
    analyser: *Analyser,
    container_scope: ScopeWithHandle,
    symbol: []const u8,
    kind: DocumentScope.DeclarationLookup.Kind,
) error{OutOfMemory}!?DeclWithHandle {
    const handle = container_scope.handle;
    const document_scope = try handle.getDocumentScope();

    if (document_scope.getScopeDeclaration(.{
        .scope = container_scope.scope,
        .name = symbol,
        .kind = kind,
    }).unwrap()) |decl_index| {
        const decl = document_scope.declarations.get(@intFromEnum(decl_index));
        return DeclWithHandle{ .decl = decl, .handle = handle };
    }

    if (try analyser.resolveUse(document_scope.getScopeUsingnamespaceNodesConst(container_scope.scope), symbol, handle)) |result| return result;

    return null;
}

pub fn lookupSymbolFieldInit(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    field_name: []const u8,
    nodes: []Ast.Node.Index,
) error{OutOfMemory}!?DeclWithHandle {
    if (nodes.len == 0) return null;

    var container_type = (try analyser.resolveExpressionType(
        handle,
        nodes[0],
        nodes[1..],
    )) orelse return null;

    if (try analyser.resolveUnwrapErrorUnionType(container_type, .payload)) |unwrapped|
        container_type = unwrapped;

    if (try analyser.resolveOptionalUnwrap(container_type)) |unwrapped|
        container_type = unwrapped;

    const container_scope_handle = switch (container_type.data) {
        .container => |s| s,
        else => return null,
    };

    return analyser.lookupSymbolContainer(
        container_scope_handle,
        field_name,
        .field,
    );
}

pub fn resolveExpressionType(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []Ast.Node.Index,
) error{OutOfMemory}!?Type {
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
    handle: *DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []Ast.Node.Index,
) error{OutOfMemory}!?Type {
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
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(ancestors[0]).?;
            if (node == var_decl.ast.init_node) {
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

            const ty = try analyser.resolveTypeOfNode(.{ .node = call.ast.fn_expr, .handle = handle }) orelse return null;
            const fn_type = try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
            if (fn_type.is_type_val) return null;

            const fn_node_handle = fn_type.data.other; // this assumes that function types can only be Ast nodes
            const fn_node = fn_node_handle.node;
            const fn_handle = fn_node_handle.handle;
            const fn_tree = fn_handle.tree;

            var fn_buf: [1]Ast.Node.Index = undefined;
            const fn_proto = fn_tree.fullFnProto(&fn_buf, fn_node).?;

            var param_iter = fn_proto.iterate(&fn_tree);
            if (try analyser.isInstanceCall(handle, call, fn_type)) {
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

pub fn getSymbolEnumLiteral(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    name: []const u8,
) error{OutOfMemory}!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;
    const nodes = try ast.nodesOverlappingIndex(arena, tree, source_index);
    if (nodes.len == 0) return null;
    return analyser.lookupSymbolFieldInit(handle, name, nodes);
}

/// Multiple when using branched types
pub fn getSymbolFieldAccesses(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    held_loc: offsets.Loc,
    name: []const u8,
) error{OutOfMemory}!?[]const DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var decls_with_handles = std.ArrayListUnmanaged(DeclWithHandle){};

    if (try analyser.getFieldAccessType(handle, source_index, held_loc)) |ty| {
        const container_handle = try analyser.resolveDerefType(ty) orelse ty;

        const container_handle_nodes = try container_handle.getAllTypesWithHandles(arena);

        for (container_handle_nodes) |t| {
            try decls_with_handles.append(arena, (try t.lookupSymbol(analyser, name)) orelse continue);
        }
    }

    return try decls_with_handles.toOwnedSlice(arena);
}

pub const ReferencedType = struct {
    str: []const u8,
    handle: *DocumentStore.Handle,
    token: Ast.TokenIndex,

    pub const Collector = struct {
        type_str: ?[]const u8 = null,
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
    resolved_type: Type,
    collector: *ReferencedType.Collector,
) error{OutOfMemory}!void {
    if (resolved_type.is_type_val) return;
    analyser.resolved_nodes.clearRetainingCapacity();
    try analyser.addReferencedTypes(resolved_type, collector.*);
}

fn addReferencedTypesFromNode(
    analyser: *Analyser,
    node_handle: NodeWithHandle,
    referenced_types: *ReferencedType.Set,
) error{OutOfMemory}!void {
    if (analyser.resolved_nodes.contains(.{ .node = node_handle.node, .uri = node_handle.handle.uri })) return;
    const ty = try analyser.resolveTypeOfNodeInternal(node_handle) orelse return;
    if (!ty.is_type_val) return;
    var collector = ReferencedType.Collector.init(referenced_types);
    try analyser.referencedTypesFromNodeInternal(node_handle, &collector);
    try analyser.addReferencedTypes(ty, collector);
}

fn addReferencedTypes(
    analyser: *Analyser,
    ty: Type,
    collector: ReferencedType.Collector,
) error{OutOfMemory}!void {
    const type_str = collector.type_str;
    const referenced_types = collector.referenced_types;
    const allocator = referenced_types.allocator;

    switch (ty.data) {
        .pointer => |info| try analyser.addReferencedTypes(info.elem_ty.*, ReferencedType.Collector.init(referenced_types)),
        .array => |info| try analyser.addReferencedTypes(info.elem_ty.*, ReferencedType.Collector.init(referenced_types)),
        .optional => |child_ty| try analyser.addReferencedTypes(child_ty.*, ReferencedType.Collector.init(referenced_types)),
        .error_union => |info| {
            if (info.error_set) |error_set| {
                try analyser.addReferencedTypes(error_set.*, ReferencedType.Collector.init(referenced_types));
            }
            try analyser.addReferencedTypes(info.payload.*, ReferencedType.Collector.init(referenced_types));
        },
        .union_tag => |t| try analyser.addReferencedTypes(t.*, ReferencedType.Collector.init(referenced_types)),

        .container => |scope_handle| {
            const handle = scope_handle.handle;
            const tree = handle.tree;

            const doc_scope = try handle.getDocumentScope();
            const node = scope_handle.toNode();

            switch (tree.nodes.items(.tag)[node]) {
                .root => {
                    const path = URI.parse(allocator, handle.uri) catch |err| switch (err) {
                        error.OutOfMemory => |e| return e,
                        else => return,
                    };
                    const str = std.fs.path.stem(path);
                    try referenced_types.put(.{
                        .str = type_str orelse str,
                        .handle = handle,
                        .token = tree.firstToken(node),
                    }, {});
                },
                .container_decl,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .error_set_decl,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                => {
                    const token_tags = tree.tokens.items(.tag);
                    const token_starts = tree.tokens.items(.start);

                    // This is a hacky nightmare but it works :P
                    const token = tree.firstToken(node);
                    if (token >= 2 and token_tags[token - 2] == .identifier and token_tags[token - 1] == .equal) {
                        const str = tree.tokenSlice(token - 2);
                        try referenced_types.put(.{
                            .str = type_str orelse str,
                            .handle = handle,
                            .token = token - 2,
                        }, {});
                    }
                    if (token >= 1 and token_tags[token - 1] == .keyword_return) blk: {
                        const function_scope = innermostFunctionScopeAtIndex(doc_scope, token_starts[token - 1]).unwrap() orelse break :blk;
                        const function_node = doc_scope.getScopeAstNode(function_scope).?;
                        var buf: [1]Ast.Node.Index = undefined;
                        const func = tree.fullFnProto(&buf, function_node).?;
                        const func_name_token = func.name_token orelse break :blk;
                        const func_name = offsets.tokenToSlice(tree, func_name_token);
                        try referenced_types.put(.{
                            .str = type_str orelse func_name,
                            .handle = handle,
                            .token = func_name_token,
                        }, {});
                    }
                },
                else => unreachable,
            }
        },

        .other => |node_handle| switch (node_handle.handle.tree.nodes.items(.tag)[node_handle.node]) {
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => {
                const node = node_handle.node;
                const handle = node_handle.handle;
                const tree = handle.tree;

                var buffer: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buffer, node).?;

                var it = fn_proto.iterate(&tree);
                while (ast.nextFnParam(&it)) |param| {
                    if (param.type_expr == 0) continue;
                    try analyser.addReferencedTypesFromNode(
                        .{ .node = param.type_expr, .handle = handle },
                        referenced_types,
                    );
                }

                try analyser.addReferencedTypesFromNode(
                    .{ .node = fn_proto.ast.return_type, .handle = handle },
                    referenced_types,
                );
            },
            else => {}, // TODO: Implement more "other" type expressions; better safe than sorry
        },

        .ip_index, .compile_error => {},
        .either => {}, // TODO
    }
}
