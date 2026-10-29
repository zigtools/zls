//! The ZLS analysis backend.
//!
//! The most frequently used functions are:
//! - `resolveTypeOfNode`
//! - `getPositionContext`
//! - `lookupSymbolGlobal`
//! - `lookupSymbolContainer`
//!

const builtin = @import("builtin");
const std = @import("std");
const DocumentStore = @import("DocumentStore.zig");
const Ast = @import("zirp").Ast;
const offsets = @import("offsets.zig");
const Uri = @import("Uri.zig");
const log = std.log.scoped(.analysis);
const ast = @import("ast.zig");
const tracy = @import("tracy");
const InternPool = @import("analyser/InternPool.zig");
const ErrorMsg = @import("analyser/error_msg.zig").ErrorMsg;
const references = @import("features/references.zig");

pub const DocumentScope = @import("DocumentScope.zig");
pub const Declaration = DocumentScope.Declaration;
pub const Scope = DocumentScope.Scope;

const version_data = @import("version_data");

const Analyser = @This();

gpa: std.mem.Allocator,
arena: std.mem.Allocator,
store: *DocumentStore,
ip: *InternPool,
resolved_callsites: std.AutoHashMapUnmanaged(Declaration.Param, ?Type) = .empty,
resolved_nodes: std.HashMapUnmanaged(NodeWithUri, ?Binding, NodeWithUri.Context, std.hash_map.default_max_load_percentage) = .empty,
collect_callsite_references: bool,
/// avoid unnecessarily parsing number literals
resolve_number_literal_values: bool,
/// handle of the doc where the request originated
root_handle: ?*DocumentStore.Handle,
max_conditional_combos: usize = 200,

const NodeSet = std.HashMapUnmanaged(NodeWithUri, void, NodeWithUri.Context, std.hash_map.default_max_load_percentage);

pub const Error = std.mem.Allocator.Error || std.Io.Cancelable;

pub fn init(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    store: *DocumentStore,
    ip: *InternPool,
    root_handle: ?*DocumentStore.Handle,
) Analyser {
    return .{
        .gpa = gpa,
        .arena = arena,
        .store = store,
        .ip = ip,
        .collect_callsite_references = true,
        .resolve_number_literal_values = false,
        .root_handle = root_handle,
    };
}

pub fn deinit(self: *Analyser) void {
    self.resolved_callsites.deinit(self.gpa);
    self.resolved_nodes.deinit(self.gpa);
}

fn allocType(analyser: *Analyser, ty: Type) error{OutOfMemory}!*Type {
    const ptr = try analyser.arena.create(Type);
    ptr.* = ty;
    return ptr;
}

pub fn getDocCommentsBeforeToken(allocator: std.mem.Allocator, tree: *const Ast, base: Ast.Token.Index) error{OutOfMemory}!?[]const u8 {
    if (true) return null; // BRANCH_TODO
    const doc_comment_index = getDocCommentTokenIndex(tree, base) orelse return null;
    return try collectDocComments(allocator, tree, doc_comment_index, false);
}

/// Gets a declaration's doc comments. Caller owns returned memory.
pub fn getDocComments(allocator: std.mem.Allocator, tree: *const Ast, node: Ast.Node.Index) error{OutOfMemory}!?[]const u8 {
    if (true) return null; // BRANCH_TODO
    const base = node.mainToken(tree);
    const base_kind = node.tag(tree);

    switch (base_kind) {
        .root => return try collectDocComments(allocator, tree, @fromBackingInt(0), true),
        .decl_fn,
        .var_local,
        .var_global,
        .member_field,
        => return try getDocCommentsBeforeToken(allocator, tree, base),
        else => {},
    }
    return null;
}

/// Get the first doc comment of a declaration.
pub fn getDocCommentTokenIndex(tree: *const Ast, base_token: Ast.Token.Index) ?Ast.Token.Index {
    var idx = base_token;
    if (@backingInt(idx) == 0) return null;
    idx = idx.add(-1);
    if (idx.tag(tree) == .@"threadlocal" and @backingInt(idx) > 0) idx = idx.add(-1);
    if (idx.tag(tree) == .string and @backingInt(idx) > 1 and idx.add(-1).tag(tree) == .@"extern") idx = idx.add(-1);
    if (idx.tag(tree) == .@"extern" and @backingInt(idx) > 0) idx = idx.add(-1);
    if (idx.tag(tree) == .@"export" and @backingInt(idx) > 0) idx = idx.add(-1);
    if (idx.tag(tree) == .@"inline" and @backingInt(idx) > 0) idx = idx.add(-1);
    if (idx.tag(tree) == .name and @backingInt(idx) > 0) idx = idx.add(-1);
    if (idx.tag(tree) == .@"pub" and @backingInt(idx) > 0) idx = idx.add(-1);

    // Find first doc comment token
    if (!(idx.tag(tree) == .doc_comment))
        return null;
    return while (idx.tag(tree) == .doc_comment) {
        if (@backingInt(idx) == 0) break @fromBackingInt(0);
        idx = idx.add(-1);
    } else idx.add(1);
}

pub fn collectDocComments(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    doc_comments: *Ast.TokenIterator(.doc_comment),
    container_doc: bool,
) error{OutOfMemory}!?[]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(allocator);

    var lines_start_with_space = true;

    var curr_line_tok = doc_comments;
    while (true) : (curr_line_tok = curr_line_tok.add(1)) {
        switch (curr_line_tok.tag(tree)) {
            .container_doc_comment => if (!container_doc) break,
            .doc_comment => if (container_doc) break,
            else => break,
        }
        const line = curr_line_tok.slice(tree)[3..];
        if (!std.mem.startsWith(u8, line, " ")) lines_start_with_space = false;
        try lines.append(allocator, line);
    }
    if (lines.items.len == 0) return null;

    // If all of the lines that aren't empty start with a space, remove the first space
    if (lines_start_with_space) {
        for (lines.items, 0..) |line, i| {
            if (line.len > 1 and line[0] == ' ') {
                lines.items[i] = line[1..];
            }
        }
    }

    return try std.mem.join(allocator, "\n", lines.items);
}

pub const FormatParameterOptions = struct {
    referenced: ?*ReferencedType.Set = null,
    info: Type.Data.Parameter,

    include_modifier: bool,
    include_name: bool,
    include_type: bool,
};

pub fn stringifyParameter(analyser: *Analyser, options: FormatParameterOptions) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = .init(analyser.arena);
    defer aw.deinit();
    analyser.rawStringifyParameter(&aw.writer, options) catch |err| switch (err) {
        error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
    };
    return try aw.toOwnedSlice();
}

fn rawStringifyParameter(
    analyser: *Analyser,
    writer: *std.Io.Writer,
    options: FormatParameterOptions,
) error{ OutOfMemory, WriteFailed }!void {
    const referenced = options.referenced;
    const info = options.info;

    // Note that parameter doc comments are being skipped

    if (options.include_modifier) {
        if (info.modifier) |modifier| {
            switch (modifier) {
                .comptime_param => try writer.writeAll("comptime "),
                .noalias_param => try writer.writeAll("noalias "),
            }
        }
    }

    if (options.include_name) {
        if (info.name) |name| {
            try writer.writeAll(name);
        }
    }

    if (options.include_type) {
        const has_parameter_name = options.include_name and info.name != null;
        if (has_parameter_name) try writer.writeAll(": ");

        try info.type.rawStringify(writer, analyser, .{
            .referenced = referenced,
            .truncate_container_decls = true,
        });
    }
}

pub const FormatFunctionOptions = struct {
    referenced: ?*ReferencedType.Set = null,
    info: Type.Data.Function,

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

pub fn stringifyFunction(analyser: *Analyser, options: FormatFunctionOptions) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = .init(analyser.arena);
    defer aw.deinit();
    analyser.rawStringifyFunction(&aw.writer, options) catch |err| switch (err) {
        error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
    };
    return try aw.toOwnedSlice();
}

fn rawStringifyFunction(
    analyser: *Analyser,
    writer: *std.Io.Writer,
    options: FormatFunctionOptions,
) error{ OutOfMemory, WriteFailed }!void {
    const referenced = options.referenced;
    const info = options.info;
    var parameters = info.parameters;

    var snippet_escaping_writer: SnippetEscapingWriter = .init(writer);
    const escaping_writer = if (options.snippet_placeholders) &snippet_escaping_writer.interface else writer;

    if (options.include_fn_keyword) {
        try writer.writeAll("fn ");
    }

    if (options.include_name) no_name: {
        const name = options.override_name orelse info.name orelse break :no_name;
        try escaping_writer.writeAll(name);
    }

    try writer.writeByte('(');

    if (options.skip_first_param) {
        if (parameters.len >= 1) {
            parameters = parameters[1..];
        }
    }

    switch (options.parameters) {
        .collapse => {
            const has_arguments = parameters.len != 0;
            if (has_arguments) {
                if (options.snippet_placeholders) {
                    try writer.writeAll("${1:...}");
                } else {
                    try writer.writeAll("...");
                }
            }
        },
        .show => |parameter_options| {
            for (parameters, 0..) |param_info, index| {
                if (index != 0) try writer.writeAll(", ");
                if (options.snippet_placeholders) {
                    try writer.print("${{{d}:", .{index + 1});
                }

                try analyser.rawStringifyParameter(escaping_writer, .{
                    .referenced = referenced,
                    .info = param_info,
                    .include_modifier = parameter_options.include_modifiers,
                    .include_name = parameter_options.include_names,
                    .include_type = parameter_options.include_types,
                });
                if (options.snippet_placeholders) {
                    try writer.writeByte('}');
                }
            }
        },
    }

    if (info.has_varargs) {
        if (parameters.len != 0) {
            try writer.writeAll(", ");
        }
        try writer.writeAll("...");
    }

    try writer.writeByte(')');

    // ignoring align_expr
    // ignoring addrspace_expr
    // ignoring section_expr
    // ignoring callconv_expr

    if (options.include_return_type) {
        try writer.writeByte(' ');

        const return_type = try options.info.return_value.typeOf(analyser);
        try return_type.rawStringify(escaping_writer, analyser, .{
            .referenced = referenced,
            .truncate_container_decls = true,
        });
    }
}

const SnippetEscapingWriter = struct {
    out: *std.Io.Writer,
    interface: std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) SnippetEscapingWriter {
        return .{
            .out = writer,
            .interface = .{
                .vtable = &.{
                    .drain = &drain,
                    .flush = std.Io.Writer.noopFlush,
                    .rebase = std.Io.Writer.failingRebase,
                },
                .buffer = &.{},
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SnippetEscapingWriter = @fieldParentPtr("interface", w);
        const out = self.out;
        std.debug.assert(w.buffer.len == 0);
        for (data, 0..) |vec, i| {
            const segment_index = std.mem.findAny(u8, vec, "$}\\") orelse continue;
            if (i != 0) {
                return try out.writeSplat(data[0..i], splat);
            }
            const segment = vec[0..segment_index];
            const unescaped_char = vec[segment_index];
            const bytes_written = try out.write(segment);
            if (bytes_written < segment.len) return bytes_written;
            try out.writeAll(&.{ '\\', unescaped_char });
            return bytes_written + 1;
        } else {
            return try out.writeSplat(data, splat);
        }
    }

    fn writeAll(raw_text: []const u8, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var written: usize = 0;
        for (raw_text, 0..) |c, i| {
            switch (c) {
                '$', '}', '\\' => {
                    try writer.writeAll(raw_text[written..i]);
                    try writer.writeAll(&.{ '\\', c });
                    written = i + 1;
                },
                else => continue,
            }
        }
        try writer.writeAll(raw_text[written..]);
    }
};

pub fn fmtEscapedSnippet(raw_text: []const u8) std.fmt.Alt([]const u8, SnippetEscapingWriter.writeAll) {
    return .{ .data = raw_text };
}

pub fn renderBuiltinFunctionSignature(
    arena: std.mem.Allocator,
    name: []const u8,
    builtin_data: version_data.Builtin,
    multi_line: bool,
) error{OutOfMemory}![]u8 {
    var signature: std.ArrayList(u8) = .empty;
    try signature.appendSlice(arena, name);
    try signature.append(arena, '(');
    if (multi_line) try signature.append(arena, '\n');
    for (builtin_data.parameters, 0..) |parameter, i| {
        if (multi_line) {
            try signature.appendSlice(arena, "  ");
        } else if (i != 0) {
            try signature.appendSlice(arena, ", ");
        }
        try signature.appendSlice(arena, parameter.signature);
        if (multi_line) {
            try signature.appendSlice(arena, ",\n");
        }
    }
    try signature.appendSlice(arena, ") ");
    try signature.appendSlice(arena, builtin_data.return_type);
    return signature.items;
}

pub fn isInstanceCall(
    analyser: *Analyser,
    call_handle: *DocumentStore.Handle,
    call: Ast.Expr.Call,
    func_ty: Type,
) Error!bool {
    std.debug.assert(!func_ty.is_type_val);
    const dot_access_node = call.callee.cast(.dot_access, &call_handle.tree) orelse return false;
    const dot_access: Ast.Expr.DotAccess = dot_access_node.get(&call_handle.tree);
    const container_node = dot_access.lhs;

    const container_ty = if (try analyser.resolveTypeOfNodeInternal(.of(container_node.idx, call_handle))) |container_instance|
        try container_instance.typeOf(analyser)
    else
        func_ty.data.function.container_type.*;

    std.debug.assert(container_ty.is_type_val);

    return analyser.firstParamIs(func_ty, container_ty);
}

pub fn hasSelfParam(analyser: *Analyser, func_ty: Type) error{OutOfMemory}!bool {
    std.debug.assert(func_ty.isFunc());
    const container = func_ty.data.function.container_type.*;
    if (container.is_type_val) return false;
    const in_container = try container.typeOf(analyser);
    if (in_container.isNamespace()) return false;
    return analyser.firstParamIs(func_ty, in_container);
}

pub fn firstParamIs(
    analyser: *Analyser,
    func_type: Type,
    expected_type: Type,
) bool {
    _ = analyser;
    std.debug.assert(expected_type.is_type_val);
    std.debug.assert(func_type.isFunc());
    const func_info = func_type.data.function;
    if (func_info.parameters.len == 0) return false;
    const resolved_type = func_info.parameters[0].type;
    if (!resolved_type.is_type_val) return false;
    if (resolved_type.data == .anytype_parameter) return true;
    if (resolved_type.isMetaType()) return false;

    const deref_type = deref: switch (resolved_type.data) {
        .pointer => |info| switch (info.size) {
            .one, .c => info.elem_ty.*,
            .many, .slice => return false,
        },
        .optional => |opt| switch (opt.data) {
            .pointer => continue :deref opt.data,
            else => opt.*,
        },
        else => resolved_type,
    };

    const deref_expected_type = switch (expected_type.data) {
        .pointer => |info| switch (info.size) {
            .one, .c => info.elem_ty.*,
            .many, .slice => return false,
        },
        else => expected_type,
    };

    return switch (deref_type.data) {
        .either => |entries| {
            for (entries) |entry| {
                if (entry.type_data.eql(deref_expected_type.data)) {
                    return true;
                }
            }
            return false;
        },
        else => deref_type.eql(deref_expected_type),
    };
}

pub fn getVariableSignature(
    arena: std.mem.Allocator,
    tree: *const Ast,
    var_decl: Ast.Member.GlobalVar,
    include_name: bool,
) error{OutOfMemory}![]const u8 {
    const mutability_token = switch (var_decl.mutability.get(tree)) {
        .@"const" => |const_leaf| const_leaf.token(tree),
        .@"var" => |var_leaf| var_leaf.token(tree),
    };

    const start_token = if (include_name)
        mutability_token
    else if (var_decl.type) |type_node|
        type_node.idx.firstToken(tree)
    else if (var_decl.init) |init_node|
        init_node.idx.firstToken(tree)
    else
        return "";

    const init_expr = var_decl.init orelse {
        const type_node = var_decl.type orelse return "";
        return offsets.tokensToSlice(tree, start_token, ast.lastToken(tree, type_node.idx));
    };
    const init_node = init_expr.idx;

    const end_token: Ast.Token.Index = end_token: {
        const container_node = init_expr.cast(.container, tree) orelse break :end_token ast.lastToken(tree, init_node);
        const container_decl: Ast.Expr.Container = container_node.get(tree);

        // Tagged union: `union(enum)`, `union(ComplexTypeTag)`
        // Backing integer: `struct(u32)`, `union(enum(u32))`
        const end_token: Ast.Token.Index = switch (container_decl.kind.get(tree)) {
            .@"enum" => |enum_idx| switch (enum_idx.get(tree)) {
                .@"enum" => |v| v.token(tree),
                .with_backing => @panic("BRANCH_TODO"),
            },
            .@"union" => |union_idx| switch (union_idx.get(tree)) {
                .@"union" => |v| v.token(tree),
                .with_backing => @panic("BRANCH_TODO"),
            },
            .@"struct" => |struct_idx| switch (struct_idx.get(tree)) {
                .@"struct" => |v| v.token(tree),
                .with_backing => @panic("BRANCH_TODO"),
            },
            .@"opaque" => |opaque_idx| opaque_idx.token(tree),
        };

        {
            var it = container_decl.members.iter(tree);
            if (it.next(tree) == null) break :end_token end_token;
        }

        // e.g. 'pub const Mode = enum { zig, zon };'
        if (ast.tokensOnSameLine(tree, init_node.firstToken(tree), ast.lastToken(tree, init_node))) {
            break :end_token ast.lastToken(tree, init_node);
        }

        var members_source: std.ArrayList(u8) = .empty;

        var it = container_decl.members.iter(tree);
        while (it.next(tree)) |member| {
            const member_field = member.cast(.field, tree) orelse continue;
            _ = member_field;

            const member_line_start = offsets.lineLocUntilIndex(tree.source, member.idx.firstToken(tree).byteOffset(tree)).start;
            const member_source_indented = tree.source[member_line_start..offsets.tokenToLoc(tree, ast.lastToken(tree, member.idx)).end];

            try members_source.append(arena, '\n');
            try members_source.appendSlice(arena, try trimCommonIndentation(arena, member_source_indented, 4));
            try members_source.append(arena, ',');
        }

        if (members_source.items.len == 0) break :end_token end_token;

        return try std.mem.concat(arena, u8, &.{
            offsets.tokensToSlice(tree, start_token, end_token),
            " {",
            members_source.items,
            "\n}",
        });
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
    var output: std.ArrayList(u8) = try .initCapacity(allocator, capacity);
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

/// Returns whether the given `node` is the identifier `type`.
pub fn isMetaType(tree: *const Ast, node: Ast.Node.Index) bool {
    if (node.tag(tree) != .leaf) return false;
    const leaf_token = node.mainToken(tree);
    if (leaf_token.tag(tree) != .name) return false;
    return std.mem.eql(u8, leaf_token.slice(tree), "type");
}

/// Returns whether the given function returns a `type`.
pub fn isTypeFunction(tree: *const Ast, func: Ast.Expr.Fn) bool {
    return isMetaType(tree, func.return_type.idx);
}

// ANALYSIS ENGINE

/// Resolves variable declarations consisting of chains of imports and field accesses of containers
/// Examples:
///```zig
/// const decl = @import("decl-file.zig").decl;
/// const other = decl.middle.other;
///```
pub fn resolveVarDeclAlias(analyser: *Analyser, decl: DeclWithHandle) Error!?DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const initial_node = switch (decl.decl) {
        .ast_node => |node| node,
        else => return null,
    };

    var node_trail: NodeSet = .empty;
    defer node_trail.deinit(analyser.gpa);

    var current: ResolveOptions = .{
        .node_handle = .of(initial_node.idx, decl.handle),
        .container_type = decl.container_type,
    };
    var result: ?DeclWithHandle = null;
    while (true) {
        const node = current.node_handle.node;
        const handle = current.node_handle.handle;
        const tree = &handle.tree;

        const resolved: DeclWithHandle = switch (node.tag(tree)) {
            .leaf => blk: {
                const name_token = ast.identifierTokenFromIdentifierNode(tree, node) orelse return null;
                const name = offsets.identifierTokenToNameSlice(tree, name_token);
                if (current.container_type) |ty| {
                    break :blk try ty.lookupSymbol(analyser, name);
                }
                break :blk try analyser.lookupSymbolGlobal(
                    handle,
                    name,
                    name_token.byteOffset(tree),
                );
            },
            .expr_dot_access => blk: {
                const expr: Ast.Expr.DotAccess = node.cast(.expr_dot_access, tree).?;
                const field_name = expr.rhs.token(tree);
                if (field_name.tag(tree) != .name) return null;
                const resolved = (try analyser.resolveTypeOfNode(.{
                    .node_handle = .of(expr.lhs.idx, handle),
                    .container_type = current.container_type,
                })) orelse break :blk null;
                if (!resolved.is_type_val)
                    break :blk null;

                const symbol_name = offsets.identifierTokenToNameSlice(tree, field_name);

                break :blk try resolved.lookupSymbol(analyser, symbol_name);
            },
            inline .var_global, .var_local => |tag| {
                const var_decl = node.cast(tag, tree).?;

                const init_expr = unpackOptExpr(var_decl.init) orelse return null;
                switch (var_decl.mutability.get(tree)) {
                    .@"const" => {},
                    .@"var" => return result,
                }

                const gop = try node_trail.getOrPut(analyser.gpa, .{ .node = init_expr, .uri = handle.uri });
                if (gop.found_existing) return null;

                current.node_handle.node = init_expr;
                continue;
            },
            else => null,
        } orelse return result;

        const resolved_node = switch (resolved.decl) {
            .ast_node => |resolved_node| resolved_node,
            else => return resolved,
        };

        const gop = try node_trail.getOrPut(analyser.gpa, .{ .node = resolved_node.idx, .uri = resolved.handle.uri });
        if (gop.found_existing) return null;

        current = .{
            .node_handle = .of(resolved_node.idx, resolved.handle),
            .container_type = resolved.container_type,
        };
        result = resolved;
    }
}

/// resolves `@field(lhs, field_name)`
pub fn resolveFieldAccess(analyser: *Analyser, lhs: Type, field_name: []const u8) Error!?Type {
    const binding = try analyser.resolveFieldAccessBinding(.{ .type = lhs, .is_const = false }, field_name) orelse return null;
    return binding.type;
}

pub fn resolveFieldAccessBinding(analyser: *Analyser, lhs_binding: Binding, field_name: []const u8) Error!?Binding {
    const lhs = lhs_binding.type;

    if (try analyser.resolveUnionTagAccess(lhs, field_name)) |t|
        return .{ .type = t, .is_const = true };

    // If we are accessing a pointer type, remove one pointerness level :)
    const left_type = (try analyser.resolveDerefType(lhs)) orelse lhs;

    if (try analyser.resolvePropertyType(left_type, field_name)) |t|
        return .{
            .type = t,
            .is_const = lhs_binding.is_const,
        };

    if (try left_type.lookupSymbol(analyser, field_name)) |child|
        return .{
            .type = try child.resolveType(analyser) orelse return null,
            .is_const = if (left_type.is_type_val) child.isConst() else lhs_binding.is_const,
        };

    return null;
}

pub fn resolveGenericType(analyser: *Analyser, ty: Type, bound_params: TokenToTypeMap) error{OutOfMemory}!Type {
    var visiting: Type.Data.GenericSet = .empty;
    defer visiting.deinit(analyser.gpa);
    return analyser.resolveGenericTypeInternal(ty, bound_params, &visiting);
}

fn resolveGenericTypeInternal(
    analyser: *Analyser,
    ty: Type,
    bound_params: TokenToTypeMap,
    visiting: *Type.Data.GenericSet,
) error{OutOfMemory}!Type {
    var resolved = ty;
    if (!ty.is_type_val) {
        resolved = try resolved.typeOf(analyser);
    }
    std.debug.assert(resolved.is_type_val);
    resolved.data = try resolved.data.resolveGeneric(analyser, bound_params, visiting);
    if (!ty.is_type_val) {
        resolved = try resolved.instanceUnchecked(analyser);
    }
    return resolved;
}

fn findReturnStatementInternal(tree: *const Ast, body: Ast.Block.Index, already_found: *bool) ?Ast.Expr.Return.Index {
    var result: ?Ast.Expr.Return.Index = null;

    var it = body.get(tree).statements.iter(tree);
    while (it.next(tree)) |statement| {
        const expr = statement.cast(.expr, tree) orelse continue;
        if (expr.cast(.@"return", tree)) |return_expr| {
            if (already_found.*) return null;
            already_found.* = true;
            result = return_expr;
            continue;
        }
        const sub_block = expr.cast(.block, tree) orelse continue;
        result = findReturnStatementInternal(tree, sub_block, already_found);
    }

    return result;
}

fn findReturnStatement(tree: *const Ast, body: Ast.Block.Index) ?Ast.Expr.Return.Index {
    var already_found = false;
    return findReturnStatementInternal(tree, body, &already_found);
}

/// if `func_type_param` is callable, returns an instance of the return type.
/// otherwise, returns null.
pub fn resolveReturnType(analyser: *Analyser, func_type_param: Type) error{OutOfMemory}!?Type {
    const func_type = try analyser.resolveFuncProtoOfCallable(func_type_param) orelse return null;
    const info = func_type.data.function;
    return info.return_value.*;
}

fn resolveReturnValueOfFuncNode(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    fn_proto: Ast.Expr.Fn,
    opt_fn_body: ?Ast.Block.Index,
) Error!?Type {
    const tree = &handle.tree;

    if (isTypeFunction(tree, fn_proto)) {
        const fn_body = opt_fn_body orelse return .unknown_type;
        // If this is a type function and it only contains a single return statement that returns
        // a container declaration, we will return that declaration.
        const return_node = findReturnStatement(tree, fn_body) orelse return .unknown_type;
        if (return_node.get(tree).value) |return_expr| {
            return try analyser.resolveTypeOfNodeInternal(.of(return_expr.idx, handle)) orelse .unknown_type;
        }
        return .unknown_type;
    }

    const child_type = (try analyser.resolveTypeOfNodeInternal(.of(fn_proto.return_type.idx, handle))) orelse
        return null;
    if (!child_type.is_type_val) return null;

    if (ast.hasInferredError(tree, fn_proto)) {
        const ty = try Type.createErrorUnionType(analyser, null, child_type);
        return try ty.instanceUnchecked(analyser);
    }

    return try child_type.instanceTypeVal(analyser);
}

/// `optional.?`
pub fn resolveOptionalUnwrap(analyser: *Analyser, optional: Type) error{OutOfMemory}!?Type {
    if (optional.is_type_val) return null;

    // TODO: some uses of this function don't expect C pointers to be unwrapped
    switch (optional.data) {
        .optional => |child_ty| return try child_ty.instanceUnchecked(analyser),
        .pointer => |ptr| {
            if (ptr.size == .c) return optional;
            return null;
        },
        .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
            .optional_type => |optional_info| return Type.fromIP(analyser, optional_info.payload_type, null),
            .pointer_type => |pointer_info| {
                if (pointer_info.flags.size == .c) return optional;
                return null;
            },
            else => return null,
        },
        else => return null,
    }
}

pub fn resolveOrelseType(analyser: *Analyser, lhs: Type, rhs: Type) error{OutOfMemory}!?Type {
    if (rhs.is_type_val) return null;
    return switch (rhs.data) {
        .optional => rhs,
        .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
            .optional_type => rhs,
            else => try analyser.resolveOptionalUnwrap(lhs),
        },
        else => try analyser.resolveOptionalUnwrap(lhs),
    };
}

pub fn resolveAddressOf(analyser: *Analyser, is_const: bool, ty: Type) error{OutOfMemory}!Type {
    const elem_ty = try ty.typeOf(analyser);
    const pointer_ty = try Type.createPointerType(analyser, .one, .none, is_const, elem_ty);
    return try pointer_ty.instanceUnchecked(analyser);
}

pub const ErrorUnionSide = enum { error_set, payload };

pub fn resolveUnwrapErrorUnionType(analyser: *Analyser, ty: Type, side: ErrorUnionSide) error{OutOfMemory}!?Type {
    if (ty.is_type_val) return null;

    return switch (ty.data) {
        .error_union => |info| switch (side) {
            .error_set => try (info.error_set orelse return null).instanceTypeVal(analyser),
            .payload => try info.payload.instanceTypeVal(analyser),
        },
        .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
            .error_union_type => |error_union_info| switch (side) {
                .error_set => {
                    if (error_union_info.error_set_type == .none) return null;
                    return Type.fromIP(analyser, error_union_info.error_set_type, null);
                },
                .payload => return Type.fromIP(analyser, error_union_info.payload_type, null),
            },
            else => return null,
        },
        else => return null,
    };
}

fn resolveUnionTag(analyser: *Analyser, ty: Type) Error!?Type {
    if (!ty.is_type_val)
        return null;

    if (!ty.isTaggedUnion())
        return null;

    const scope_handle = switch (ty.data) {
        .container => |info| info.scope_handle,
        else => return null,
    };
    const node = scope_handle.toNode();
    const handle = scope_handle.handle;
    const tree = &handle.tree;
    const container_decl: Ast.Expr.Container = node.cast(.type_container, tree).?;
    switch (container_decl.kind.get(tree)) {
        .@"enum" => |e| switch (e.get(tree)) {
            .@"enum" => {
                return .{ .data = .{ .union_tag = try analyser.allocType(ty) }, .is_type_val = false };
            },
            .with_backing => |backing| {
                const tag_type = (try analyser.resolveTypeOfNode(.of(backing.idx, handle))) orelse return null;
                return try tag_type.instanceTypeVal(analyser) orelse return null;
            },
        },
        .@"union" => |u| switch (u.get(tree)) {
            .@"union" => {
                return .{ .data = .{ .union_tag = try analyser.allocType(ty) }, .is_type_val = false };
            },
            .with_backing => @panic("BRANCH_TODO"),
        },
        .@"opaque", .@"struct" => return null,
    }
}

fn resolveUnionTagAccess(analyser: *Analyser, ty: Type, symbol: []const u8) Error!?Type {
    if (!ty.is_type_val)
        return null;

    if (!ty.isTaggedUnion())
        return null;

    const child = try ty.lookupSymbol(analyser, symbol) orelse
        return null;

    if (child.decl != .ast_node or child.decl.ast_node.idx.tag(&child.handle.tree) != .member_field)
        return null;

    return try analyser.resolveUnionTag(ty);
}

pub fn resolveFuncProtoOfCallable(analyser: *Analyser, ty: Type) error{OutOfMemory}!?Type {
    const deref_type = try analyser.resolveDerefType(ty) orelse ty;
    if (!deref_type.isFunc()) return null;
    return deref_type;
}

/// resolve a pointer dereference
/// `pointer.*`
pub fn resolveDerefType(analyser: *Analyser, pointer: Type) error{OutOfMemory}!?Type {
    const binding = try analyser.resolveDerefBinding(pointer) orelse return null;
    return binding.type;
}

pub fn resolveDerefBinding(analyser: *Analyser, pointer: Type) error{OutOfMemory}!?Binding {
    if (pointer.is_type_val) return null;

    switch (pointer.data) {
        .pointer => |info| switch (info.size) {
            .one, .c => return .{
                .type = try info.elem_ty.instanceTypeVal(analyser) orelse return null,
                .is_const = info.is_const,
            },
            .many, .slice => return null,
        },
        .ip_index => |payload| {
            const ty = payload.type;
            switch (analyser.ip.indexToKey(ty)) {
                .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
                    .one, .c => return .{
                        .type = Type.fromIP(analyser, pointer_info.elem_type, null),
                        .is_const = pointer_info.flags.is_const,
                    },
                    .many, .slice => return null,
                },
                else => return null,
            }
        },
        else => return null,
    }
}

pub const BracketAccess = union(enum) {
    /// `lhs[index]`
    single: ?u64,
    /// `lhs[start.. :sentinel]`
    open: struct {
        start: ?u64,
        sentinel: InternPool.Index,
    },
    /// `lhs[start..end :sentinel]`
    range: struct {
        bounds: ?struct { u64, u64 },
        sentinel: InternPool.Index,
    },

    pub fn fromSlice(
        analyser: *Analyser,
        handle: *DocumentStore.Handle,
        slice: Ast.Expr.Slice,
    ) Error!BracketAccess {
        const start = try analyser.resolveIntegerLiteral(u64, .of(slice.start.idx, handle));
        const sentinel = if (slice.sentinel) |sentinel_expr|
            try analyser.resolveInternPoolValue(.of(sentinel_expr.idx, handle)) orelse .unknown_unknown
        else
            .none;

        const end_node = slice.end orelse return .{
            .open = .{
                .start = start,
                .sentinel = sentinel,
            },
        };

        const bounds = bounds: {
            break :bounds .{
                start orelse break :bounds null,
                try analyser.resolveIntegerLiteral(u64, .of(end_node.idx, handle)) orelse break :bounds null,
            };
        };

        return .{
            .range = .{
                .bounds = bounds,
                .sentinel = sentinel,
            },
        };
    }
};

/// Resolves slicing and array access
/// - `lhs[index]` (single)
/// - `lhs[start..]` (open)
/// - `lhs[start..end]` (range)
pub fn resolveBracketAccessType(analyser: *Analyser, lhs: Type, rhs: BracketAccess) error{OutOfMemory}!?Type {
    const binding = try analyser.resolveBracketAccess(.{ .type = lhs, .is_const = false }, rhs) orelse return null;
    return binding.type;
}

// TODO: copy indexing logic from Zig compiler to InternPool, and then delete bracketAccessTypeFromIPIndex
fn bracketAccessTypeFromIPIndex(analyser: *Analyser, ip_index: InternPool.Index) error{OutOfMemory}!Type {
    std.debug.assert(analyser.ip.typeOf(ip_index) == .type_type);
    return switch (analyser.ip.indexToKey(ip_index)) {
        .tuple_type => |info| {
            const types = try info.types.dupe(analyser.gpa, analyser.ip);
            defer analyser.gpa.free(types);

            const elem_ty_slice = try analyser.arena.alloc(Type, types.len);
            for (elem_ty_slice, types) |*elem_ty, ty|
                elem_ty.* = try analyser.bracketAccessTypeFromIPIndex(ty);

            return .{
                .data = .{ .tuple = elem_ty_slice },
                .is_type_val = true,
            };
        },
        .vector_type => |info| .{
            .data = .{
                .array = .{
                    .elem_count = info.len,
                    .sentinel = .none,
                    .elem_ty = try analyser.allocType(try analyser.bracketAccessTypeFromIPIndex(info.child)),
                },
            },
            .is_type_val = true,
        },
        .array_type => |info| .{
            .data = .{
                .array = .{
                    .elem_count = info.len,
                    .sentinel = info.sentinel,
                    .elem_ty = try analyser.allocType(try analyser.bracketAccessTypeFromIPIndex(info.child)),
                },
            },
            .is_type_val = true,
        },
        .pointer_type => |info| .{
            .data = .{
                .pointer = .{
                    .size = info.flags.size,
                    .sentinel = info.sentinel,
                    .is_const = info.flags.is_const,
                    .elem_ty = try analyser.allocType(try analyser.bracketAccessTypeFromIPIndex(info.elem_type)),
                },
            },
            .is_type_val = true,
        },
        else => Type.fromIP(analyser, .type_type, ip_index),
    };
}

pub fn resolveBracketAccess(analyser: *Analyser, lhs_binding: Binding, rhs: BracketAccess) error{OutOfMemory}!?Binding {
    const lhs = lhs_binding.type;
    if (lhs.is_type_val) return null;

    const is_const = switch (lhs.data) {
        .pointer => |info| info.is_const,
        else => lhs_binding.is_const,
    };

    var result: union(enum) { array: ?u64, slice: void } = .slice;
    var sentinel: InternPool.Index = .none;
    const elem_ty = elem: switch (lhs.data) {
        .tuple => |fields| switch (rhs) {
            .single => |index_maybe| {
                const index = index_maybe orelse return null;
                if (index >= fields.len) return null;
                const instance = try fields[@intCast(index)].instanceUnchecked(analyser);
                return .{ .type = instance, .is_const = is_const };
            },
            .open, .range => return null,
        },
        .array => |info| switch (rhs) {
            .single => {
                const instance = try info.elem_ty.instanceUnchecked(analyser);
                return .{ .type = instance, .is_const = is_const };
            },
            .open => |access| {
                if (access.start) |start| {
                    result = .{ .array = null };
                    if (info.elem_count) |elem_count| {
                        if (start <= elem_count) {
                            result = .{ .array = elem_count - start };
                        }
                    }
                }
                sentinel = access.sentinel;
                if (sentinel == .none) sentinel = info.sentinel;
                break :elem info.elem_ty;
            },
            .range => |access| {
                if (access.bounds) |bounds| {
                    result = .{ .array = null };
                    if (info.elem_count) |elem_count| {
                        const start, const end = bounds;
                        if (start <= end and start <= elem_count and end <= elem_count) {
                            result = .{ .array = end - start };
                        }
                    }
                }
                sentinel = access.sentinel;
                break :elem info.elem_ty;
            },
        },
        .pointer => |info| switch (info.size) {
            .one => switch (info.elem_ty.data) {
                .tuple, .array => continue :elem info.elem_ty.data,
                else => switch (rhs) {
                    .single, .open => return null,
                    .range => |access| {
                        if (access.sentinel != .none) return null;
                        const start, const end = access.bounds orelse return null;
                        if (start > end or start > 1 or end > 1) return null;
                        result = .{ .array = end - start };
                        break :elem info.elem_ty;
                    },
                },
            },
            .many, .slice, .c => switch (rhs) {
                .single => {
                    const instance = try info.elem_ty.instanceUnchecked(analyser);
                    return .{ .type = instance, .is_const = is_const };
                },
                .open => |access| {
                    sentinel = access.sentinel;
                    if (sentinel == info.sentinel) return lhs_binding;
                    if (sentinel == .none) sentinel = info.sentinel;
                    break :elem info.elem_ty;
                },
                .range => |access| {
                    if (access.bounds) |bounds| {
                        const start, const end = bounds;
                        result = .{ .array = if (start <= end) end - start else null };
                    }
                    sentinel = access.sentinel;
                    break :elem info.elem_ty;
                },
            },
        },
        .ip_index => |payload| {
            const ty = try analyser.bracketAccessTypeFromIPIndex(payload.type);
            const instance = try ty.instanceUnchecked(analyser);
            const binding: Binding = .{ .type = instance, .is_const = is_const };
            if (lhs.eql(binding.type)) return null;
            return analyser.resolveBracketAccess(binding, rhs);
        },
        else => return null,
    };

    switch (result) {
        .array => |elem_count| {
            const array_ty = try Type.createArrayType(analyser, elem_count, sentinel, elem_ty.*);
            const pointer_ty = try Type.createPointerType(analyser, .one, .none, is_const, array_ty);
            const pointer_instance = try pointer_ty.instanceUnchecked(analyser);
            return .{ .type = pointer_instance, .is_const = true };
        },
        .slice => {
            const slice_ty = try Type.createPointerType(analyser, .slice, sentinel, is_const, elem_ty.*);
            const slice_instance = try slice_ty.instanceUnchecked(analyser);
            return .{ .type = slice_instance, .is_const = true };
        },
    }
}

pub fn resolvePropertyType(analyser: *Analyser, ty: Type, name: []const u8) error{OutOfMemory}!?Type {
    if (ty.is_type_val)
        return null;

    switch (ty.data) {
        .pointer => |info| switch (info.size) {
            .one => {
                if (std.mem.eql(u8, "*", name)) {
                    return info.elem_ty.instanceTypeVal(analyser);
                }
                // One level of indirection is handled by resolveDerefType
            },
            .slice => {
                if (std.mem.eql(u8, "len", name)) {
                    return Type.fromIP(analyser, .usize_type, null);
                }

                if (std.mem.eql(u8, "ptr", name)) {
                    return .{
                        .data = .{
                            .pointer = .{
                                .size = .many,
                                .sentinel = info.sentinel,
                                .is_const = info.is_const,
                                .elem_ty = info.elem_ty,
                            },
                        },
                        .is_type_val = false,
                    };
                }
            },
            .many, .c => {},
        },

        .array => |info| {
            if (std.mem.eql(u8, "len", name)) {
                if (info.elem_count) |elem_count| {
                    const index = try analyser.ip.get(
                        .{ .int_u64_value = .{ .ty = .usize_type, .int = elem_count } },
                    );
                    return Type.fromIP(analyser, .usize_type, index);
                }
                return Type.fromIP(analyser, .usize_type, null);
            }
        },

        .tuple => |info| {
            if (std.mem.eql(u8, "len", name)) {
                const index = try analyser.ip.get(
                    .{ .int_u64_value = .{ .ty = .usize_type, .int = info.len } },
                );
                return Type.fromIP(analyser, .usize_type, index);
            }
            if (!allDigits(name)) return null;
            const index = std.fmt.parseInt(u16, name, 10) catch return null;
            return try analyser.resolveBracketAccessType(ty, .{ .single = index });
        },

        .optional => |child_ty| {
            if (std.mem.eql(u8, "?", name)) {
                return child_ty.instanceTypeVal(analyser);
            }
        },

        .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
            .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
                .one => {
                    if (std.mem.eql(u8, "*", name)) {
                        return Type.fromIP(analyser, pointer_info.elem_type, null);
                    }
                },
                .slice => {
                    if (std.mem.eql(u8, "len", name)) {
                        return Type.fromIP(analyser, .usize_type, null);
                    }

                    if (std.mem.eql(u8, "ptr", name)) {
                        var slice_ptr_info = pointer_info;
                        slice_ptr_info.flags.size = .many;
                        const slice_ptr_ty = try analyser.ip.get(.{ .pointer_type = slice_ptr_info });
                        return Type.fromIP(analyser, slice_ptr_ty, null);
                    }
                },
                .many, .c => {},
            },

            .array_type => |array_info| {
                if (std.mem.eql(u8, "len", name)) {
                    const index = try analyser.ip.get(.{
                        .int_u64_value = .{
                            .ty = .usize_type,
                            .int = array_info.len,
                        },
                    });
                    return Type.fromIP(analyser, .usize_type, index);
                }
            },

            .tuple_type => |tuple_info| {
                if (std.mem.eql(u8, "len", name)) {
                    const index = try analyser.ip.get(.{
                        .int_u64_value = .{
                            .ty = .usize_type,
                            .int = tuple_info.types.len,
                        },
                    });
                    return Type.fromIP(analyser, .usize_type, index);
                }
                if (!allDigits(name)) return null;
                const index = std.fmt.parseInt(u16, name, 10) catch return null;
                return try analyser.resolveBracketAccessType(ty, .{ .single = index });
            },

            .optional_type => |optional_info| {
                if (std.mem.eql(u8, "?", name)) {
                    return Type.fromIP(analyser, optional_info.payload_type, null);
                }
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

fn resolveArrayMult(analyser: *Analyser, ty: Type, mult: ?u64) Error!?Type {
    if (ty.is_type_val) return null;
    const array_info = ty.arrayInfo(analyser) orelse return null;
    const old_count, const sentinel, const elem_ty = array_info;
    const new_count = blk: {
        const c = old_count orelse break :blk null;
        const m = mult orelse break :blk null;
        break :blk std.math.mul(u64, c, m) catch null;
    };
    const array_ty = try Type.createArrayType(analyser, new_count, sentinel, elem_ty);
    return try array_ty.instanceUnchecked(analyser);
}

fn resolveArrayCat(analyser: *Analyser, l_ty: Type, r_ty: Type) Error!?Type {
    if (l_ty.is_type_val) return null;
    if (r_ty.is_type_val) return null;
    const l_info = l_ty.arrayInfo(analyser) orelse return null;
    const r_info = r_ty.arrayInfo(analyser) orelse return null;
    const l_count, const l_sentinel, const l_elem_ty = l_info;
    const r_count, const r_sentinel, const r_elem_ty = r_info;
    _ = r_elem_ty; // TODO: Do peer type resolution
    const elem_count = blk: {
        const l = l_count orelse break :blk null;
        const r = r_count orelse break :blk null;
        break :blk std.math.add(u64, l, r) catch null;
    };
    const sentinel = blk: {
        if (l_sentinel == .unknown_unknown) break :blk .unknown_unknown;
        if (r_sentinel == .unknown_unknown) break :blk .unknown_unknown;
        if (l_sentinel == .none) break :blk r_sentinel;
        if (r_sentinel == .none) break :blk l_sentinel;
        if (l_sentinel == r_sentinel) break :blk l_sentinel;
        break :blk .none;
    };
    const array_ty = try Type.createArrayType(analyser, elem_count, sentinel, l_elem_ty);
    return try array_ty.instanceUnchecked(analyser);
}

fn resolveCoercedIPValue(
    analyser: *Analyser,
    ip_ty: InternPool.Index,
    options: ResolveOptions,
) Error!?InternPool.Index {
    if (!analyser.ip.isType(ip_ty)) return null;
    const ty = try analyser.resolveTypeOfNode(options) orelse return null;
    const ip_index = ty.ipIndex() orelse return null;
    if (analyser.ip.isUndefined(ip_index)) return null;

    var arena_allocator: std.heap.ArenaAllocator = .init(analyser.gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var err_msg: ErrorMsg = undefined;
    const new_index = try analyser.ip.coerce(arena, ip_ty, ip_index, builtin.target, &err_msg);

    if (new_index == .none) return null;
    if (analyser.ip.isUnknown(new_index)) return null;
    return new_index;
}

fn resolveInternPoolValue(analyser: *Analyser, options: ResolveOptions) Error!?InternPool.Index {
    const old_resolve_number_literal_values = analyser.resolve_number_literal_values;
    analyser.resolve_number_literal_values = true;
    defer analyser.resolve_number_literal_values = old_resolve_number_literal_values;

    const resolved_length = try analyser.resolveTypeOfNode(options) orelse return null;
    switch (resolved_length.data) {
        .ip_index => |payload| return payload.index,
        else => return null,
    }
}

fn resolveIntegerLiteral(analyser: *Analyser, comptime T: type, options: ResolveOptions) Error!?T {
    const ip_index = try analyser.resolveInternPoolValue(options) orelse return null;
    return analyser.ip.toInt(ip_index, T);
}

const primitives: std.StaticStringMap(InternPool.Index) = .initComptime(.{
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
    const signedness: std.lang.Signedness = switch (identifier_name[0]) {
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

    return try analyser.ip.get(.{ .int_type = .{
        .bits = bits,
        .signedness = signedness,
    } });
}

fn resolveStringLiteral(analyser: *Analyser, options: ResolveOptions) Error!?[]const u8 {
    var node_with_handle = options.node_handle;
    blk: {
        const decl_node: Declaration.Node.Index = switch (options.node_handle.node.tag(&options.node_handle.handle.tree)) {
            .var_local => .init(.var_local, .{ .idx = options.node_handle.node }, &options.node_handle.handle.tree),
            .var_global => .init(.var_global, .{ .idx = options.node_handle.node }, &options.node_handle.handle.tree),
            else => break :blk,
        };
        if (try analyser.resolveVarDeclAlias(.{
            .decl = .{ .ast_node = decl_node },
            .handle = options.node_handle.handle,
            .container_type = options.container_type,
        })) |decl_with_handle| {
            if (decl_with_handle.decl == .ast_node) {
                node_with_handle = .{
                    .node = decl_with_handle.decl.ast_node.idx,
                    .handle = decl_with_handle.handle,
                };
            }
        }
    }

    const string_literal_node = switch (node_with_handle.node.tag(&node_with_handle.handle.tree)) {
        .leaf => switch (node_with_handle.node.syntaxTag(&node_with_handle.handle.tree)) {
            .string => node_with_handle.node,
            else => return null,
        },
        inline .var_global, .var_local => |tag| blk: {
            const var_decl = node_with_handle.node.cast(tag, &node_with_handle.handle.tree).?;
            const opt_init_expr: ?Ast.Expr.Index = var_decl.init;
            const init_expr = opt_init_expr orelse return null;
            if (init_expr.idx.syntaxTag(&node_with_handle.handle.tree) != .string) return null;
            break :blk init_expr.idx;
        },
        else => return null,
    };
    const field_name_token = string_literal_node.mainToken(&node_with_handle.handle.tree);
    const field_name = offsets.tokenToSlice(&node_with_handle.handle.tree, field_name_token);

    // Need at least one char between the quotes, eg "a"
    if (field_name.len < 2) return null;
    return field_name[1 .. field_name.len - 1];
}

fn resolveErrorSetIPIndex(analyser: *Analyser, options: ResolveOptions) Error!?InternPool.Index {
    const ty = try analyser.resolveTypeOfNodeInternal(options) orelse return null;
    if (!ty.is_type_val) return null;
    const ip_index = switch (ty.data) {
        .ip_index => |payload| payload.index orelse return null,
        else => return null,
    };
    if (analyser.ip.zigTypeTag(ip_index) != .error_set) return null;
    return ip_index;
}

fn coerceIP(analyser: *Analyser, dest_ty: InternPool.Index, inst: InternPool.Index) error{OutOfMemory}!?InternPool.Index {
    if (inst == .none)
        return .none;
    var err_msg: ErrorMsg = undefined;
    const coerced_sentinel = try analyser.ip.coerce(analyser.arena, dest_ty, inst, builtin.target, &err_msg);
    if (coerced_sentinel != .none)
        return coerced_sentinel;
    return null;
}

fn resolvePeerTypes(analyser: *Analyser, a: Type, b: Type) error{OutOfMemory}!?Type {
    if (a.is_type_val or b.is_type_val) return null;
    if (a.eql(b)) return a;

    if (a.data == .ip_index and b.data == .ip_index) {
        const a_type = a.data.ip_index.type;
        const b_type = b.data.ip_index.type;
        if (try analyser.resolvePeerTypesIP(a_type, b_type)) |resolved_type| {
            return Type.fromIP(analyser, resolved_type, null);
        }
    }

    return try analyser.resolvePeerTypesInternal(a, b) orelse try analyser.resolvePeerTypesInternal(b, a);
}

fn resolvePeerTypesIP(analyser: *Analyser, a: InternPool.Index, b: InternPool.Index) error{OutOfMemory}!?InternPool.Index {
    const resolved = try analyser.ip.resolvePeerTypes(&.{ a, b }, builtin.target);
    if (resolved == .none) return null;
    return resolved;
}

fn resolvePeerErrorSets(analyser: *Analyser, a: Type, b: Type) error{OutOfMemory}!?Type {
    if (a.data != .ip_index) return null;
    if (b.data != .ip_index) return null;
    if (a.data.ip_index.type != .type_type) return null;
    if (b.data.ip_index.type != .type_type) return null;
    const a_index = a.data.ip_index.index orelse return null;
    const b_index = b.data.ip_index.index orelse return null;
    if (analyser.ip.zigTypeTag(a_index) != .error_set) return null;
    if (analyser.ip.zigTypeTag(b_index) != .error_set) return null;
    const resolved_index = try analyser.ip.errorSetMerge(a_index, b_index);
    return Type.fromIP(analyser, .type_type, resolved_index);
}

fn resolvePeerTypesInternal(analyser: *Analyser, a: Type, b: Type) error{OutOfMemory}!?Type {
    switch (a.data) {
        .compile_error => return b,
        .optional => |a_type| {
            if (a_type.eql(try b.typeOf(analyser))) {
                return a;
            }
            switch (b.data) {
                .error_union => |b_info| {
                    if (a_type.eql(b_info.payload.*)) {
                        return .{
                            .data = .{
                                .error_union = .{
                                    .error_set = b_info.error_set,
                                    .payload = try analyser.allocType(try a.typeOf(analyser)),
                                },
                            },
                            .is_type_val = false,
                        };
                    }
                },
                else => {},
            }
        },
        .error_union => |a_info| {
            if (a_info.payload.eql(try b.typeOf(analyser))) {
                return a;
            }
            switch (b.data) {
                .error_union => |b_info| {
                    const resolved_error_set = blk: {
                        const a_error_set = a_info.error_set orelse break :blk null;
                        const b_error_set = b_info.error_set orelse break :blk null;
                        if (a_error_set.eql(b_error_set.*)) break :blk a_error_set;
                        const resolved_error_set = try analyser.resolvePeerErrorSets(a_error_set.*, b_error_set.*) orelse break :blk null;
                        break :blk try analyser.allocType(resolved_error_set);
                    };
                    const resolved_payload = blk: {
                        if (a_info.payload.eql(b_info.payload.*)) break :blk a_info.payload;
                        const a_instance = try a_info.payload.instanceTypeVal(analyser) orelse return null;
                        const b_instance = try b_info.payload.instanceTypeVal(analyser) orelse return null;
                        const resolved_instance = try analyser.resolvePeerTypes(a_instance, b_instance) orelse return null;
                        break :blk try analyser.allocType(try resolved_instance.typeOf(analyser));
                    };
                    return .{
                        .data = .{
                            .error_union = .{
                                .error_set = resolved_error_set,
                                .payload = resolved_payload,
                            },
                        },
                        .is_type_val = false,
                    };
                },
                else => {},
            }
        },
        .ip_index => |a_payload| switch (analyser.ip.zigTypeTag(a_payload.type) orelse return null) {
            .noreturn => return b,
            .null => switch (b.data) {
                .optional => return b,
                .error_union => |b_info| {
                    return .{
                        .data = .{
                            .error_union = .{
                                .error_set = b_info.error_set,
                                .payload = try analyser.allocType(.{
                                    .data = .{ .optional = try analyser.allocType(b_info.payload.*) },
                                    .is_type_val = true,
                                }),
                            },
                        },
                        .is_type_val = false,
                    };
                },
                else => return .{
                    .data = .{ .optional = try analyser.allocType(try b.typeOf(analyser)) },
                    .is_type_val = false,
                },
            },
            .error_set => switch (b.data) {
                .error_union => |b_info| {
                    const resolved_error_set = blk: {
                        const a_error_set = try a.typeOf(analyser);
                        const b_error_set = b_info.error_set orelse break :blk null;
                        if (a_error_set.eql(b_error_set.*)) break :blk b_error_set;
                        const resolved_error_set = try analyser.resolvePeerErrorSets(a_error_set, b_error_set.*) orelse break :blk null;
                        break :blk try analyser.allocType(resolved_error_set);
                    };
                    return .{
                        .data = .{
                            .error_union = .{
                                .error_set = resolved_error_set,
                                .payload = b_info.payload,
                            },
                        },
                        .is_type_val = false,
                    };
                },
                else => return .{
                    .data = .{
                        .error_union = .{
                            .error_set = try analyser.allocType(try a.typeOf(analyser)),
                            .payload = try analyser.allocType(try b.typeOf(analyser)),
                        },
                    },
                    .is_type_val = false,
                },
            },
            else => {},
        },
        else => {},
    }

    return null;
}

fn resolveCallsiteReferences(analyser: *Analyser, decl_handle: DeclWithHandle) Error!?Type {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const pay = switch (decl_handle.decl) {
        .function_parameter => |pay| pay,
        else => return null,
    };

    const tree = &decl_handle.handle.tree;

    if (!analyser.collect_callsite_references) return null;

    // protection against recursive callsite resolution
    const gop_resolved = try analyser.resolved_callsites.getOrPut(analyser.gpa, pay);
    if (gop_resolved.found_existing) return gop_resolved.value_ptr.*;
    gop_resolved.value_ptr.* = null;

    const func = pay.get(tree);
    const fn_params = func.proto.params.get(tree).items;

    var fn_param_count: usize = 0;
    var fn_param_it = fn_params.iter(tree);
    while (fn_param_it.next(tree)) |_| fn_param_count += 1;

    const decl: Declaration.Node.Index = switch (pay.func.tag(tree)) {
        .type_fn => .init(.type_fn, .{ .idx = pay.func }, tree),
        .decl_fn => .init(.decl_fn, .{ .idx = pay.func }, tree),
        else => unreachable,
    };

    const refs = try references.callsiteReferences(
        analyser,
        .{
            .decl = .{ .ast_node = decl },
            .handle = decl_handle.handle,
            .container_type = decl_handle.container_type,
        },
        false,
    );

    var possible: std.ArrayList(Type.TypeWithDescriptor) = .empty;

    for (refs.items) |ref| {
        const call: Ast.Expr.Call = ref.node.cast(.expr_call, tree).?;

        var call_args_count: usize = 0;
        var call_args_it = call.args.iter(tree);
        while (call_args_it.next(tree)) |_| call_args_count += 1;

        const real_param_idx = if (fn_param_count != 0 and @backingInt(pay.node.idx) != 0 and call_args_count == fn_param_count - 1)
            @backingInt(pay.node.idx) - 1
        else
            @backingInt(pay.node.idx);

        if (real_param_idx >= call_args_count) continue;
        const param = pay.node.get(tree);

        var ty = resolve_ty: {
            // don't resolve callsite references while resolving callsite references
            const old_collect_callsite_references = analyser.collect_callsite_references;
            defer analyser.collect_callsite_references = old_collect_callsite_references;
            analyser.collect_callsite_references = false;

            break :resolve_ty try analyser.resolveTypeOfNode(.of(
                // TODO?: this is a """heuristic based approach"""
                // perhaps it would be better to use proper self detection
                // maybe it'd be a perf issue and this is fine?
                // you figure it out future contributor <3
                param.type.idx,
                ref.handle,
            )) orelse continue;
        };

        ty = try ty.typeOf(analyser);
        std.debug.assert(ty.is_type_val);

        const param_name_node = param.name orelse @panic("BRANCH_TODO: param without name");
        const param_name = param_name_node.token(tree);
        std.debug.assert(param_name.tag(tree) == .name);

        const loc = offsets.tokenToPosition(tree, param_name, .@"utf-8");
        try possible.append(analyser.arena, .{
            .type = ty,
            .descriptor = try analyser.arena.print("{s}:{d}:{d}", .{ ref.handle.uri.raw, loc.line + 1, loc.character + 1 }),
        });
    }

    const maybe_type = try Type.fromEither(analyser, possible.items);
    if (maybe_type) |ty| analyser.resolved_callsites.getPtr(pay).?.* = ty;
    return maybe_type;
}

fn resolveFunctionTypeFromCall(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    call: Ast.Expr.Call,
    func_ty: Type,
) Error!Type {
    if (!func_ty.isGenericType()) {
        return func_ty;
    }

    const func_info = func_ty.data.function;

    var meta_params: TokenToTypeMap = switch (func_info.container_type.data) {
        .container => |info| try info.bound_params.clone(analyser.arena),
        else => .empty,
    };
    errdefer meta_params.deinit(analyser.arena);

    const arg_count = call.args.iter(&handle.tree).count(&handle.tree); // BRANCH_TODO remove call to count

    const has_self_param = arg_count + 1 == func_info.parameters.len and
        try analyser.isInstanceCall(handle, call, func_ty);

    const parameters = func_info.parameters[@intFromBool(has_self_param)..];
    var arguments = call.args.iter(&handle.tree);
    for (parameters) |param| {
        const arg = arguments.next(&handle.tree) orelse break;

        const param_name_token = param.name_token orelse continue;
        const param_type = param.type;
        if (!param_type.is_type_val) continue;

        const argument_type = (try analyser.resolveTypeOfNodeInternal(.of(arg.idx, handle))) orelse continue;

        switch (param_type.data) {
            .ip_index => |info| {
                if (info.index != .type_type) continue;
                if (!argument_type.is_type_val) continue;
                try meta_params.put(analyser.arena, .{ .token = param_name_token, .handle = func_info.handle }, argument_type);
            },
            .anytype_parameter => |info| {
                try meta_params.put(analyser.arena, info.token_handle, try argument_type.typeOf(analyser));
            },
            else => {},
        }
    }

    return try analyser.resolveGenericType(func_ty, meta_params);
}

const BreakIterator = struct {
    walker: ast.Walker,
    label: ?[]const u8,
    allow_unlabeled: bool,
    loop_depth: u32 = 0,

    fn next(
        it: *BreakIterator,
        allocator: std.mem.Allocator,
        tree: *const Ast,
    ) error{OutOfMemory}!?Ast.Node.Index {
        while (true) {
            const event = try it.walker.next(allocator, tree) orelse return null;
            switch (event) {
                .open => |node| switch (node.tag(tree)) {
                    .expr_break => {
                        const expr: Ast.Expr.Break = node.cast(.expr_break, tree).?;

                        const operand = unpackOptExpr(expr.value) orelse {
                            // TODO this is wrong! No operand implies `{}` i.e `void`.
                            continue;
                        };
                        const opt_label_token = expr.label(tree);

                        if (it.label) |label| {
                            const label_token = opt_label_token orelse continue;
                            if (!std.mem.eql(u8, label, offsets.identifierTokenToNameSlice(tree, label_token))) continue;
                            return operand;
                        }

                        if (it.allow_unlabeled and it.loop_depth == 0 and opt_label_token == null) {
                            return operand;
                        }
                    },

                    .expr_while,
                    .expr_for,
                    => {
                        if (it.label == null) {
                            // We can ignore the inner loop
                            it.walker.skip();
                            continue;
                        }
                        it.loop_depth += 1;
                    },
                    else => {},
                },
                .close => |node| switch (node.tag(tree)) {
                    .expr_while,
                    .expr_for,
                    => {
                        it.loop_depth -= 1;
                    },
                    else => {},
                },
            }
        }
    }
};

pub fn resolveInstanceOfNode(analyser: *Analyser, options: ResolveOptions) Error!?Type {
    const ty = try analyser.resolveTypeOfNode(options) orelse return null;
    return ty.instanceTypeVal(analyser);
}

/// Resolves the type of an Ast Node.
/// Returns `null` if the type could not be resolved.
pub fn resolveTypeOfNode(analyser: *Analyser, options: ResolveOptions) Error!?Type {
    const binding = try analyser.resolveBindingOfNode(options) orelse return null;
    return binding.type;
}

fn resolveTypeOfNodeInternal(analyser: *Analyser, options: ResolveOptions) Error!?Type {
    const binding = try analyser.resolveBindingOfNodeInternal(options) orelse return null;
    return binding.type;
}

pub fn resolveBindingOfNode(analyser: *Analyser, options: ResolveOptions) Error!?Binding {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return analyser.resolveBindingOfNodeInternal(options);
}

fn resolveBindingOfNodeInternal(analyser: *Analyser, options: ResolveOptions) Error!?Binding {
    const node_handle = options.node_handle;
    const node_with_uri: NodeWithUri = .{
        .node = node_handle.node,
        .uri = node_handle.handle.uri,
    };
    const gop = try analyser.resolved_nodes.getOrPut(analyser.gpa, node_with_uri);
    if (gop.found_existing) return gop.value_ptr.*;

    // we insert null before resolving the type so that a recursive definition doesn't result in an infinite loop
    gop.value_ptr.* = null;

    const binding = try analyser.resolveBindingOfNodeUncached(options);
    if (binding != null) {
        analyser.resolved_nodes.getPtr(node_with_uri).?.* = binding;
    }

    return binding;
}

fn resolveTypeOfNodeUncached(analyser: *Analyser, options: ResolveOptions) Error!?Type {
    const node_handle = options.node_handle;
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = &handle.tree;

    switch (node.tag(tree)) {
        .missing => return null,
        inline .var_global, .var_local => |tag| {
            const var_decl = node.cast(tag, tree).?;
            const opt_init_expr: ?Ast.Expr.Index = var_decl.init;
            const is_const = switch (var_decl.mutability.get(tree)) {
                .@"const" => true,
                .@"var" => false,
            };
            var fallback_type: ?Type = null;

            if (var_decl.type) |type_node| blk: {
                const decl_type = try analyser.resolveTypeOfNodeInternal(.{
                    .node_handle = .of(type_node.idx, handle),
                    .container_type = options.container_type,
                }) orelse break :blk;
                if (decl_type.isMetaType()) {
                    fallback_type = .unknown_type;
                    break :blk;
                }
                if (is_const) num: {
                    const init_expr = opt_init_expr orelse break :num;
                    const ip_ty = decl_type.ipIndex() orelse break :num;
                    const ip_index = try analyser.resolveCoercedIPValue(ip_ty, .of(init_expr.idx, handle)) orelse break :num;
                    return Type.fromIP(analyser, analyser.ip.typeOf(ip_index), ip_index);
                }
                return try decl_type.instanceTypeVal(analyser);
            }

            if (opt_init_expr) |init_expr| blk: {
                const ty = try analyser.resolveTypeOfNodeInternal(.of(init_expr.idx, handle)) orelse break :blk;
                if (!is_const)
                    return ty.withoutIPIndex(analyser);
                return ty;
            }

            return fallback_type;
        },
        .expr_call => {
            const expr: Ast.Expr.Call = node.cast(.expr_call, tree).?;

            const ty = try analyser.resolveTypeOfNodeInternal(.of(expr.callee.idx, handle)) orelse return null;
            var func_ty = try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
            if (func_ty.is_type_val) return null;

            func_ty = try analyser.resolveFunctionTypeFromCall(handle, expr, func_ty);
            const func_info = func_ty.data.function;
            const func_uri = func_info.handle.uri.raw;

            if (std.mem.endsWith(u8, func_uri, "/std/meta.zig") and func_info.name != null) {
                const func_name = func_info.name.?;

                if (std.mem.eql(u8, func_name, "ArgsTuple")) {
                    var it = expr.args.iter(tree);
                    const arg = it.next(tree) orelse return .unknown_type;
                    const arg_ty = try analyser.resolveTypeOfNodeInternal(.of(arg.idx, handle)) orelse return .unknown_type;
                    if (!arg_ty.is_type_val or arg_ty.data != .function) return .unknown_type;
                    const arg_func_info = arg_ty.data.function;
                    if (arg_func_info.has_varargs) return .unknown_type;
                    const arg_func_params = arg_func_info.parameters;
                    const elem_ty_slice = try analyser.arena.alloc(Type, arg_func_params.len);
                    for (arg_func_params, elem_ty_slice) |param, *elem_ty| {
                        if (param.type.data == .anytype_parameter) return .unknown_type;
                        elem_ty.* = param.type;
                    }
                    return try Type.createTupleType(analyser, elem_ty_slice);
                }

                if (std.mem.eql(u8, func_name, "Tag")) {
                    var it = expr.args.iter(tree);
                    const arg = it.next(tree) orelse return .unknown_type;
                    const arg_ty = try analyser.resolveTypeOfNodeInternal(.of(arg.idx, handle)) orelse return .unknown_type;
                    // TODO: handle enum tag, e.g. `enum(u8)`
                    const tag_type = try analyser.resolveUnionTag(arg_ty) orelse return .unknown_type;
                    return try tag_type.typeOf(analyser);
                }
            }

            return func_info.return_value.*;
        },
        .member_field => {
            const container_type = options.container_type orelse try analyser.innermostContainer(handle, node.firstToken(tree).byteOffset(tree));
            if (container_type.isEnumType())
                return try container_type.instanceTypeVal(analyser);

            const member_field: Ast.Member.Field = node.cast(.member_field, tree).?;

            if (container_type.isTaggedUnion()) {
                if (member_field.type.idx.tag(tree) == .none) // BRANCH_TODO
                    return Type.fromIP(analyser, .void_type, null);
            }

            const base_type = (try analyser.resolveTypeOfNodeInternal(.of(member_field.type.idx, handle))) orelse return null;
            return try base_type.instanceTypeVal(analyser);
        },
        .expr_comptime => return try analyser.resolveTypeOfNodeInternal(.of(node.cast(.expr_comptime, tree).?.inner.idx, handle)),
        .expr_group => return try analyser.resolveTypeOfNodeInternal(.of(node.cast(.expr_group, tree).?.inner.idx, handle)),
        // .expr_init => { // struct init
        //     var buffer: [2]Ast.Node.Index = undefined;
        //     const struct_init = tree.fullStructInit(&buffer, node).?;

        //     const type_expr = struct_init.ast.type_expr.unwrap().?;
        //     const lhs = try analyser.resolveTypeOfNodeInternal(.of(type_expr, handle)) orelse return null;

        //     if (lhs.data == .array and lhs.data.array.elem_count == null) {
        //         var ty = lhs;
        //         ty.data.array.elem_count = struct_init.ast.fields.len;
        //         return try ty.instanceTypeVal(analyser);
        //     }
        //     return try lhs.instanceTypeVal(analyser);
        // },
        .expr_init => { // array init
            const expr: Ast.Expr.Init = node.cast(.expr_init, tree).?;

            if (true) return null; // BRANCH_TODO

            if (expr.type) |type_expr| blk: {
                const array_ty = try analyser.resolveTypeOfNode(.of(type_expr.idx, handle)) orelse break :blk;
                if (array_ty.data == .array and array_ty.data.array.elem_count == null) {
                    var ty = array_ty;
                    ty.data.array.elem_count = expr.fields.iter(tree).count(tree);
                    return try ty.instanceTypeVal(analyser);
                }
                return try array_ty.instanceTypeVal(analyser);
            }

            const elem_ty_slice = try analyser.arena.alloc(Type, expr.fields.iter(tree).count(tree));
            for (elem_ty_slice, expr.fields) |*elem_ty, element| {
                elem_ty.* = try analyser.resolveTypeOfNodeInternal(.of(element, handle)) orelse return null;
                elem_ty.* = try elem_ty.typeOf(analyser);
            }
            const tuple_ty = try Type.createTupleType(analyser, elem_ty_slice);
            return try tuple_ty.instanceUnchecked(analyser);
        },
        .expr_unwrap => {
            const expr: Ast.Expr.Unwrap = node.cast(.expr_unwrap, tree).?;
            const base_type = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            return try analyser.resolveOptionalUnwrap(base_type);
        },

        .expr_prefix => {
            const expr: Ast.Expr.Prefix = node.cast(.expr_prefix, tree).?;
            switch (expr.op.get(tree)) {
                .@"&" => @panic("BRANCH_TODO: call resolveBindingOfNode"),
                .@"try" => {
                    const base_type = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    return try analyser.resolveUnwrapErrorUnionType(base_type, .payload);
                },
                .@"!" => return Type.fromIP(analyser, .bool_type, null),
                .@"~",
                .@"-",
                .@"-%",
                => {
                    const ty = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    if (ty.is_type_val) return null;
                    return ty.withoutIPIndex(analyser);
                },
            }
        },

        .expr_binary => {
            const expr: Ast.Expr.Binary = node.cast(.expr_binary, tree).?;
            switch (expr.op.get(tree)) {
                .@"orelse" => {
                    const lhs = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    const rhs = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return try analyser.resolveOptionalUnwrap(lhs);
                    return try analyser.resolveOrelseType(lhs, rhs);
                },
                .@"||" => {
                    const lhs_index = try analyser.resolveErrorSetIPIndex(.of(expr.lhs.idx, handle)) orelse return null;
                    const rhs_index = try analyser.resolveErrorSetIPIndex(.of(expr.rhs.idx, handle)) orelse return null;
                    const ip_index = try analyser.ip.errorSetMerge(lhs_index, rhs_index);
                    return Type.fromIP(analyser, .type_type, ip_index);
                },

                .@"*",
                .@"/",
                .@"%",
                .@"&",
                .@"^",
                .@"|",
                .@"*%",
                .@"*|",
                .@"+%",
                .@"-%",
                .@"+|",
                .@"-|",
                => {
                    var lhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    if (lhs_ty.is_type_val) return null;
                    var rhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    if (rhs_ty.is_type_val) return null;
                    lhs_ty = lhs_ty.withoutIPIndex(analyser);
                    rhs_ty = rhs_ty.withoutIPIndex(analyser);
                    return analyser.resolvePeerTypes(lhs_ty, rhs_ty);
                },

                .@"+" => {
                    var lhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    if (lhs_ty.is_type_val) return null;
                    var rhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    if (rhs_ty.is_type_val) return null;
                    lhs_ty = lhs_ty.withoutIPIndex(analyser);
                    rhs_ty = rhs_ty.withoutIPIndex(analyser);
                    if (lhs_ty.pointerSize(analyser)) |lhs_size| {
                        return switch (lhs_size) {
                            .many, .c => lhs_ty,
                            else => null,
                        };
                    }
                    return try analyser.resolvePeerTypes(lhs_ty, rhs_ty);
                },

                .@"-" => {
                    var lhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    if (lhs_ty.is_type_val) return null;
                    var rhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    if (rhs_ty.is_type_val) return null;
                    lhs_ty = lhs_ty.withoutIPIndex(analyser);
                    rhs_ty = rhs_ty.withoutIPIndex(analyser);
                    if (lhs_ty.pointerSize(analyser)) |lhs_size| {
                        if (rhs_ty.pointerSize(analyser)) |rhs_size| {
                            if (lhs_size == .slice) return null;
                            if (rhs_size == .slice) return null;
                            return Type.fromIP(analyser, .usize_type, null);
                        } else {
                            return switch (lhs_size) {
                                .many, .c => lhs_ty,
                                else => null,
                            };
                        }
                    }
                    return try analyser.resolvePeerTypes(lhs_ty, rhs_ty);
                },

                .@"<<",
                .@">>",
                .@"<<|",
                => {
                    const lhs_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    if (lhs_ty.is_type_val) return null;
                    return lhs_ty.withoutIPIndex(analyser);
                },

                .@"++" => {
                    var l_elem_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
                    if (l_elem_ty.is_type_val) return null;

                    var r_elem_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    if (r_elem_ty.is_type_val) return null;

                    blk: {
                        l_elem_ty = l_elem_ty.pointerElementType(analyser, .one) orelse break :blk;
                        r_elem_ty = r_elem_ty.pointerElementType(analyser, .one) orelse break :blk;
                        l_elem_ty = try l_elem_ty.instanceUnchecked(analyser);
                        r_elem_ty = try r_elem_ty.instanceUnchecked(analyser);
                        var elem_ty = try analyser.resolveArrayCat(l_elem_ty, r_elem_ty) orelse return null;
                        elem_ty = try elem_ty.typeOf(analyser);
                        const pointer_ty = try Type.createPointerType(analyser, .one, .none, true, elem_ty);
                        return try pointer_ty.instanceUnchecked(analyser);
                    }

                    return try analyser.resolveArrayCat(l_elem_ty, r_elem_ty);
                },

                .@"and",
                .@"or",
                => return Type.fromIP(analyser, .bool_type, null),

                .@"==",
                .@"!=",
                .@"<",
                .@">",
                .@"<=",
                .@">=",
                => {
                    const ty = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse
                        return Type.fromIP(analyser, .bool_type, null);
                    const typeof = try ty.typeOf(analyser);

                    if (typeof.ipIndex()) |index| {
                        const key = analyser.ip.indexToKey(index);
                        if (key == .vector_type) {
                            const vector_ty_ip_index = try analyser.ip.get(.{
                                .vector_type = .{
                                    .len = key.vector_type.len,
                                    .child = .bool_type,
                                },
                            });

                            return Type.fromIP(analyser, vector_ty_ip_index, null);
                        }
                    }
                    return Type.fromIP(analyser, .bool_type, null);
                },
            }
        },

        .expr_catch => {
            const expr: Ast.Expr.Catch = node.cast(.expr_catch, tree).?;
            const lhs = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            return try analyser.resolveUnwrapErrorUnionType(lhs, .payload);
        },

        .type_optional => {
            const expr: Ast.Expr.Optional = node.cast(.type_optional, tree).?;
            const child_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.inner.idx, handle)) orelse return null;
            if (!child_ty.is_type_val) return null;
            return try Type.createOptionalType(analyser, child_ty);
        },

        .type_pointer => {
            const expr: Ast.Expr.Pointer = node.cast(.type_pointer, tree).?;
            const attributes = expr.attributes(tree);

            const size: std.builtin.Type.Pointer.Size = switch (expr.kind.get(tree)) {
                .c => .c,
                .one => .one,
                .many => .many,
                .slice => .slice,
            };
            const is_const = attributes.@"const" != null;

            const sentinel = if (expr.sentinel(tree)) |sentinel_expr|
                try analyser.resolveInternPoolValue(.of(sentinel_expr.idx, handle)) orelse .unknown_unknown
            else
                .none;

            const elem_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.child_type.idx, handle)) orelse return null;
            if (!elem_ty.is_type_val) return null;

            return try Type.createPointerType(analyser, size, sentinel, is_const, elem_ty);
        },

        .type_array => {
            const expr: Ast.Expr.Array = node.cast(.type_array, tree).?;

            const elem_count = try analyser.resolveIntegerLiteral(u64, .of(expr.size.idx, handle));

            const sentinel = if (expr.sentinel) |sentinel_expr|
                try analyser.resolveInternPoolValue(.of(sentinel_expr.idx, handle)) orelse .unknown_unknown
            else
                .none;

            const elem_ty = try analyser.resolveTypeOfNodeInternal(.of(expr.child_type.idx, handle)) orelse return null;
            if (!elem_ty.is_type_val) return null;

            return try Type.createArrayType(analyser, elem_count, sentinel, elem_ty);
        },

        .type_error_union => {
            const expr: Ast.Expr.ErrorUnion = node.cast(.type_error_union, tree).?;

            const error_set = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            if (!error_set.is_type_val) return null;

            const payload = try analyser.resolveTypeOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
            if (!payload.is_type_val) return null;

            return try Type.createErrorUnionType(analyser, error_set, payload);
        },

        .type_error_set => {
            const expr: Ast.Expr.ErrorSet = node.cast(.type_error_set, tree).?;

            var strings: std.array_hash_map.Auto(InternPool.String, void) = .empty;
            defer strings.deinit(analyser.gpa);

            var it = expr.errors.iter(tree);
            while (it.next(tree)) |err| {
                const error_token = err.get(tree).token;
                const name = offsets.tokenToSlice(tree, error_token);
                const index = try analyser.ip.string_pool.getOrPutString(analyser.store.io, analyser.gpa, name);
                try strings.put(analyser.gpa, index, {});
            }
            const names = try analyser.ip.getStringSlice(strings.keys());
            const ip_index = try analyser.ip.get(.{ .error_set_type = .{ .owner_decl = .none, .names = names } });
            return Type.fromIP(analyser, .type_type, ip_index);
        },

        .type_container => {
            const container: Ast.Expr.Container = node.cast(.type_container, tree).?;

            not_a_tuple: {
                switch (container.kind.get(tree)) {
                    .@"struct" => |struct_idx| switch (struct_idx.get(tree)) {
                        .@"struct" => {},
                        .with_backing => break :not_a_tuple,
                    },
                    .@"enum", .@"union", .@"opaque" => break :not_a_tuple,
                }

                var elem_types: std.ArrayList(Type) = .empty;

                var it = container.members.iter(tree);
                while (it.next(tree)) |member| {
                    const member_field_node = member.cast(.field, tree) orelse break :not_a_tuple;
                    const member_field: Ast.Member.Field = member_field_node.get(tree);
                    if (member_field.name != null) break :not_a_tuple;
                    const field_ty = try analyser.resolveTypeOfNodeInternal(.of(member_field.type.idx, handle)) orelse
                        Type.fromIP(analyser, .unknown_type, null);
                    try elem_types.append(analyser.arena, field_ty);
                } else if (elem_types.items.len == 0) {
                    break :not_a_tuple;
                }

                return try Type.createTupleType(analyser, elem_types.items);
            }

            return try analyser.innermostContainer(handle, node.firstToken(tree).byteOffset(tree));
        },
        .expr_builtin_call => {
            const expr: Ast.Expr.Builtin = node.cast(.expr_builtin_call, tree).?;
            const call_name = expr.callee.token(tree).slice(tree);
            var it = expr.args.iter(tree);
            const item = std.zig.BuiltinFn.list.get(call_name) orelse return null;
            switch (item.tag) {
                .This => {
                    if (it.next(tree) != null) return null;
                    return options.container_type orelse try analyser.innermostContainer(handle, node.firstToken(tree).byteOffset(tree));
                },
                .as => {
                    const first_arg = it.next(tree) orelse return null;
                    const ty = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;
                    num: {
                        const second_arg = it.next(tree) orelse return null;
                        const ip_ty = ty.ipIndex() orelse break :num;
                        const ip_index = try analyser.resolveCoercedIPValue(ip_ty, .of(second_arg.idx, handle)) orelse break :num;
                        return Type.fromIP(analyser, analyser.ip.typeOf(ip_index), ip_index);
                    }
                    return try ty.instanceTypeVal(analyser);
                },
                .atomic_load,
                .atomic_rmw,
                .@"extern",
                .mul_add,
                .union_init,
                => {
                    const first_arg = it.next(tree) orelse return null;
                    const ty = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;
                    return try ty.instanceTypeVal(analyser);
                },

                .c_va_arg => {
                    _ = it.next(tree) orelse return null;
                    const second_arg = it.next(tree) orelse return null;
                    const ty = (try analyser.resolveTypeOfNodeInternal(.of(second_arg.idx, handle))) orelse return null;
                    return try ty.instanceTypeVal(analyser);
                },
                .sqrt,
                .sin,
                .cos,
                .tan,
                .exp,
                .exp2,
                .log,
                .log2,
                .log10,
                .floor,
                .ceil,
                .trunc,
                .round,
                => {
                    const first_arg = it.next(tree) orelse return null;
                    if (it.next(tree) != null) return null;
                    const ty = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;
                    const payload = switch (ty.data) {
                        .ip_index => |payload| payload,
                        else => return null,
                    };
                    if (!analyser.ip.isFloat(analyser.ip.scalarType(payload.type))) return null;
                    return Type.fromIP(analyser, payload.type, null);
                },
                .abs => {
                    const first_arg = it.next(tree) orelse return null;
                    if (it.next(tree) != null) return null;

                    const ty = try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle)) orelse return null;

                    const payload = switch (ty.data) {
                        .ip_index => |payload| payload,
                        else => return null,
                    };

                    // Based on Sema.zirAbs
                    const operand_ty = payload.type;
                    const scalar_ty = analyser.ip.scalarType(operand_ty);
                    const scalar_tag = analyser.ip.zigTypeTag(scalar_ty) orelse return null;
                    const result_ty = switch (scalar_tag) {
                        .comptime_float, .float, .comptime_int => operand_ty,
                        .int => if (analyser.ip.isSignedInt(scalar_ty, builtin.target))
                            try analyser.ip.toUnsigned(operand_ty, builtin.target)
                        else
                            operand_ty,
                        else => return null,
                    };

                    return Type.fromIP(analyser, result_ty, null);
                },
                .TypeOf => {
                    // TODO Do peer type resolution, we just keep the first for now.

                    const first_arg = it.next(tree) orelse return null;
                    var resolved_type = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;
                    return try resolved_type.typeOf(analyser);
                },
                .import => {
                    const import_param = it.next(tree) orelse return null;
                    const string_node = import_param.cast(.string, tree) orelse return null;
                    const string_literal = string_node.token(tree).slice(tree);
                    const import_string = string_literal[1 .. string_literal.len - 1];
                    if (std.mem.endsWith(u8, import_string, ".zon")) {
                        // TODO
                        return null;
                    }

                    if (try analyser.resolveImportString(handle, import_string)) |ty| return ty;
                    if (try analyser.resolveImportString(analyser.root_handle orelse return null, import_string)) |ty| return ty;
                    return null;
                },
                .FieldType => {
                    const first_arg = it.next(tree) orelse return null;
                    const second_arg = it.next(tree) orelse return null;

                    const container_type = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;
                    const instance = try container_type.instanceTypeVal(analyser) orelse return null;

                    const field_name = try analyser.resolveStringLiteral(.of(second_arg.idx, handle)) orelse return null;

                    const field = try instance.lookupSymbol(analyser, field_name) orelse return null;
                    const result = try field.resolveType(analyser) orelse return null;
                    return try result.typeOf(analyser);
                },
                .field => {
                    const first_arg = it.next(tree) orelse return null;
                    const second_arg = it.next(tree) orelse return null;

                    const lhs = (try analyser.resolveTypeOfNodeInternal(.of(first_arg.idx, handle))) orelse return null;

                    const field_name = try analyser.resolveStringLiteral(.of(second_arg.idx, handle)) orelse return null;

                    return try analyser.resolveFieldAccess(lhs, field_name);
                },
                .compile_error => {
                    return .{ .data = .{ .compile_error = node_handle }, .is_type_val = false };
                },
                .EnumLiteral => {
                    return Type.fromIP(analyser, .type_type, .enum_literal_type);
                },
                .Vector => {
                    const first_arg = it.next(tree) orelse return null;
                    const second_arg = it.next(tree) orelse return null;

                    const child_ty = try analyser.resolveTypeOfNodeInternal(.of(second_arg.idx, handle)) orelse return null;
                    if (!child_ty.is_type_val) return null;

                    const child_ty_ip_index = switch (child_ty.data) {
                        .ip_index => |payload| payload.index orelse try analyser.ip.getUnknown(payload.type),
                        else => return null,
                    };

                    const len = try analyser.resolveIntegerLiteral(u32, .of(first_arg.idx, handle)) orelse
                        return null; // `InternPool.Key.Vector.len` can't represent unknown length yet

                    const vector_ty_ip_index = try analyser.ip.get(.{
                        .vector_type = .{
                            .len = len,
                            .child = child_ty_ip_index,
                        },
                    });

                    return Type.fromIP(analyser, .type_type, vector_ty_ip_index);
                },
                else => {
                    const data = version_data.builtins.get(call_name) orelse return null;
                    return analyser.resolveLangrefType(data.return_type);
                },
            }
        },
        .type_fn,
        .decl_fn,
        => |tag| {
            const fn_proto: Ast.Expr.Fn, const fn_body: ?Ast.Block.Index = switch (tag) {
                .type_fn => .{ node.cast(.type_fn, tree).?, null },
                .decl_fn => blk: {
                    const decl_fn = node.cast(.decl_fn, tree).?;
                    break :blk .{ decl_fn.proto.get(tree), decl_fn.body };
                },
                else => unreachable,
            };
            const fn_token = fn_proto.@"fn".token(tree);

            const container_type = options.container_type orelse try analyser.innermostContainer(handle, fn_token.byteOffset(tree));
            const doc_comments = try getDocComments(analyser.arena, tree, node);
            const name = if (fn_proto.name(tree)) |t| t.slice(tree) else null;

            var parameters: std.ArrayList(Type.Data.Parameter) = .empty;
            var has_varargs = false;

            var it = fn_proto.params.get(tree).items.iter(tree);
            while (it.next(tree)) |param_idx| {
                const param = param_idx.get(tree);
                const attributes = param.attributes(tree);

                if (has_varargs) {
                    return null;
                }

                var param_comments: ?[]const u8 = null;
                _ = &param_comments; // BRANCH_TODO
                // if (param.docComment(tree)) |dc| {
                //     param_comments = try collectDocComments(analyser.arena, tree, dc, false);
                // }

                const param_modifier: ?Type.Data.Parameter.Modifier = if (attributes.@"noalias" != null)
                    .noalias_param
                else if (attributes.@"comptime" != null)
                    .comptime_param
                else
                    null;

                const param_name: ?[]const u8, const param_name_token = name: {
                    const name_node = param.name orelse break :name .{ null, null };
                    const name_token = name_node.token(tree);
                    break :name .{ name_token.slice(tree), name_token };
                };

                const param_type: Type = param_type: switch (param.type.get(tree)) {
                    .expr => |type_expr| {
                        const ty = try analyser.resolveTypeOfNode(.of(type_expr.idx, handle)) orelse
                            break :param_type .unknown_type;
                        if (!ty.is_type_val) break :param_type .unknown_type;
                        break :param_type ty;
                    },
                    .@"anytype" => |anytype_idx| .{
                        .data = .{
                            .anytype_parameter = .{
                                .token_handle = .{ .token = anytype_idx.token(tree), .handle = handle },
                                .type_from_callsite_references = null,
                            },
                        },
                        .is_type_val = true,
                    },
                    .varargs => {
                        has_varargs = true;
                        continue;
                    },
                };

                try parameters.append(analyser.arena, .{
                    .doc_comments = param_comments,
                    .modifier = param_modifier,
                    .name = param_name,
                    .name_token = param_name_token,
                    .type = param_type,
                });
            }

            const return_value = try analyser.resolveReturnValueOfFuncNode(handle, fn_proto, fn_body) orelse
                Type.fromIP(analyser, .unknown_type, null);

            const info: Type.Data.Function = .{
                .handle = handle,
                .fn_token = fn_token,
                .container_type = try analyser.allocType(container_type),
                .doc_comments = doc_comments,
                .name = name,
                .parameters = parameters.items,
                .has_varargs = has_varargs,
                .return_value = try analyser.allocType(return_value),
            };

            if (fn_proto.name(tree) == null) {
                return .{ .data = .{ .function = info }, .is_type_val = true };
            }

            return .{ .data = .{ .function = info }, .is_type_val = false };
        },
        .expr_if,
        .expr_if_else,
        .expr_if_payload,
        .expr_if_full,
        => {
            const node_index: Ast.Expr.If.Index = .{ .idx = node };
            const expr = node_index.get(tree);

            var either_buffer: [2]Type.TypeWithDescriptor = undefined;
            var either: std.ArrayList(Type.TypeWithDescriptor) = .initBuffer(&either_buffer);

            if (try analyser.resolveTypeOfNodeInternal(.of(expr.then_branch.idx, handle))) |t| {
                either.appendAssumeCapacity(.{ .type = t, .descriptor = offsets.nodeToSlice(tree, expr.condition.idx) });
            }
            if (expr.else_branch) |else_expr| {
                if (try analyser.resolveTypeOfNodeInternal(.of(else_expr.idx, handle))) |t| {
                    either.appendAssumeCapacity(.{ .type = t, .descriptor = try analyser.arena.print("!({s})", .{offsets.nodeToSlice(tree, expr.condition.idx)}) });
                }
            }
            return Type.fromEither(analyser, either.items);
        },
        .expr_switch => {
            const expr: Ast.Expr.Switch = node.cast(.expr_switch, tree).?;

            var either: std.ArrayList(Type.TypeWithDescriptor) = .empty;

            if (expr.label(tree)) |label_token| {
                var it: BreakIterator = .{
                    .walker = try .init(analyser.gpa, tree, node),
                    .label = offsets.identifierTokenToNameSlice(tree, label_token),
                    .allow_unlabeled = false,
                };
                defer it.walker.deinit(analyser.gpa);
                while (try it.next(analyser.gpa, tree)) |operand| {
                    if (try analyser.resolveTypeOfNodeInternal(.of(operand, handle))) |operand_type| {
                        try either.append(analyser.arena, .{
                            .type = operand_type,
                            .descriptor = "break",
                        });
                    }
                }
            }

            var prong_it = expr.prongs.iter(tree);
            while (prong_it.next(tree)) |prong_idx| {
                const prong = prong_idx.get(tree);
                var descriptor: std.ArrayList(u8) = .empty;

                var case_it = prong.cases.iter(tree);
                var case_index: u32 = 0;
                while (case_it.next(tree)) |case| : (case_index += 1) {
                    if (case_index != 0) try descriptor.appendSlice(analyser.arena, ", ");
                    try descriptor.appendSlice(analyser.arena, offsets.nodeToSlice(tree, case.idx));
                }

                if (try analyser.resolveTypeOfNodeInternal(.of(prong.body.idx, handle))) |t|
                    try either.append(analyser.arena, .{
                        .type = t,
                        .descriptor = try descriptor.toOwnedSlice(analyser.arena),
                    });
            }

            return Type.fromEither(analyser, either.items);
        },
        .expr_while,
        .expr_for,
        => |tag| {
            const loop: struct {
                label_token: ?Ast.Token.Index,
                then_expr: Ast.Node.Index,
                else_expr: ?Ast.Node.Index,
            } = switch (tag) {
                inline .expr_while, .expr_for => |t| blk: {
                    const expr = node.cast(t, tree).?;
                    break :blk .{
                        .label_token = expr.label(tree),
                        .then_expr = expr.body.idx,
                        .else_expr = unpackOptExpr(expr.@"else"),
                    };
                },
                else => unreachable,
            };

            const else_expr = loop.else_expr orelse return null;

            // TODO: peer type resolution based on `else` and all `break` statements
            if (try analyser.resolveTypeOfNodeInternal(.of(else_expr, handle))) |else_type|
                return else_type.withoutIPIndex(analyser);

            var it: BreakIterator = .{
                .walker = try .init(analyser.gpa, tree, loop.then_expr),
                .label = if (loop.label_token) |token| offsets.identifierTokenToNameSlice(tree, token) else null,
                .allow_unlabeled = true,
            };
            defer it.walker.deinit(analyser.gpa);

            while (try it.next(analyser.gpa, tree)) |operand| {
                if (try analyser.resolveTypeOfNodeInternal(.of(operand, handle))) |operand_type|
                    return operand_type;
            }
        },
        .block => {
            const block: Ast.Block = node.cast(.block, tree).?;

            var statement_it = block.statements.iter(tree);
            if (statement_it.next(tree) == null) {
                return Type.fromIP(analyser, .void_type, .void_value);
            }

            const label_token = block.label(tree) orelse {
                statement_it = block.statements.iter(tree);
                const last_statement = statement_it.last(tree).?;
                if (try analyser.resolveTypeOfNodeInternal(.of(last_statement.idx, handle))) |ty| {
                    if ((try ty.typeOf(analyser)).isNoreturnType()) {
                        return Type.fromIP(analyser, .noreturn_type, null);
                    }
                }
                return Type.fromIP(analyser, .void_type, .void_value);
            };

            // TODO: peer type resolution based on all `break` statements
            var it: BreakIterator = .{
                .walker = try .init(analyser.gpa, tree, node),
                .label = offsets.identifierTokenToNameSlice(tree, label_token),
                .allow_unlabeled = false,
            };
            defer it.walker.deinit(analyser.gpa);

            while (try it.next(analyser.gpa, tree)) |operand| {
                if (try analyser.resolveTypeOfNodeInternal(.of(operand, handle))) |operand_type|
                    return operand_type.withoutIPIndex(analyser);
            }
        },

        .for_range => {},

        .leaf => {
            const main_token = node.mainToken(tree);
            switch (main_token.tag(tree)) {
                .name => @panic("BRANCH_TODO: call resolveBindingOfNode"),
                .multiline_string_line => {
                    const multiline_string_line: Ast.Expr.MultilineString.Index = .{ .idx = node };

                    var length: u64 = 0;
                    var line: u32 = 0;
                    var it = multiline_string_line.get(tree).iter;
                    while (it.next(tree)) |_| : (line += 1) {
                        const slice = it.current.slice(tree);
                        length += slice.len - 2 + @intFromBool(line != 0);
                    }

                    const string_literal_type = try analyser.ip.get(.{ .pointer_type = .{
                        .elem_type = try analyser.ip.get(.{ .array_type = .{
                            .child = .u8_type,
                            .len = length,
                            .sentinel = .zero_u8,
                        } }),
                        .flags = .{
                            .size = .one,
                            .is_const = true,
                        },
                    } });
                    return Type.fromIP(analyser, string_literal_type, null);
                },
                .string => {
                    const token_bytes = node.mainToken(tree).slice(tree);

                    var discarding_writer: std.Io.Writer.Discarding = .init(&.{});
                    const result = std.zig.string_literal.parseWrite(&discarding_writer.writer, token_bytes) catch |err| switch (err) {
                        error.WriteFailed => unreachable,
                    };
                    switch (result) {
                        .success => {},
                        .failure => return null,
                    }

                    const string_literal_type = try analyser.ip.get(.{ .pointer_type = .{
                        .elem_type = try analyser.ip.get(.{ .array_type = .{
                            .child = .u8_type,
                            .len = discarding_writer.count,
                            .sentinel = .zero_u8,
                        } }),
                        .flags = .{
                            .size = .one,
                            .is_const = true,
                        },
                    } });
                    return Type.fromIP(analyser, string_literal_type, null);
                },
                .char => return Type.fromIP(analyser, .comptime_int_type, null),

                .number => {
                    const bytes = offsets.tokenToSlice(tree, node.mainToken(tree));
                    const result = std.zig.parseNumberLiteral(bytes);
                    const ty: InternPool.Index = switch (result) {
                        .int,
                        .big_int,
                        => .comptime_int_type,
                        .float => .comptime_float_type,
                        .failure => return null,
                    };
                    if (!analyser.resolve_number_literal_values) {
                        return Type.fromIP(analyser, ty, null);
                    }
                    const value: ?InternPool.Index = switch (result) {
                        .float => blk: {
                            break :blk try analyser.ip.get(
                                .{ .float_comptime_value = std.fmt.parseFloat(f128, bytes) catch break :blk null },
                            );
                        },
                        .int => blk: {
                            break :blk if (bytes[0] == '-')
                                try analyser.ip.get(
                                    .{ .int_i64_value = .{ .ty = ty, .int = std.fmt.parseInt(i64, bytes, 0) catch break :blk null } },
                                )
                            else
                                try analyser.ip.get(
                                    .{ .int_u64_value = .{ .ty = ty, .int = std.fmt.parseInt(u64, bytes, 0) catch break :blk null } },
                                );
                        },
                        .big_int => |base| blk: {
                            var big_int: std.math.big.int.Managed = try .init(analyser.gpa);
                            defer big_int.deinit();
                            const prefix_length: usize = if (base != .decimal) 2 else 0;
                            big_int.setString(@backingInt(base), bytes[prefix_length..]) catch |err| switch (err) {
                                error.OutOfMemory => return error.OutOfMemory,
                                else => break :blk null,
                            };
                            std.debug.assert(ty == .comptime_int_type);
                            break :blk try analyser.ip.getBigInt(ty, big_int.toConst());
                        },
                        .failure => unreachable, // checked above
                    };

                    return if (value) |v| Type.fromIP(analyser, ty, v) else Type.fromIP(analyser, ty, null);
                },
                .@"unreachable" => return Type.fromIP(analyser, .noreturn_type, null),
                else => {},
            }
        },
        .leaf_enum_literal => {
            const source_token = node.mainToken(tree).byteOffset(tree);
            const lineage = try ast.nodesOverlappingIndex(analyser.arena, tree, source_token);
            defer analyser.arena.free(lineage);

            const tag = offsets.identifierTokenToNameSlice(tree, node.mainToken(tree));
            const decl, const type_maybe = (try analyser.lookupSymbolFieldInit(handle, tag, node, lineage[1..])) orelse return Type.fromIP(analyser, .enum_literal_type, null);
            return type_maybe orelse decl.resolveType(analyser);
        },

        .expr_error => {
            const expr: Ast.Expr.Error = node.cast(.expr_error, tree).?;
            const name_token = expr.rhs.token(tree);

            const name = offsets.identifierTokenToNameSlice(tree, name_token);
            const name_index = try analyser.ip.string_pool.getOrPutString(analyser.store.io, analyser.gpa, name);

            const error_set_type = try analyser.ip.get(.{ .error_set_type = .{
                .owner_decl = .none,
                .names = try analyser.ip.getStringSlice(&.{name_index}),
            } });
            const error_value = try analyser.ip.get(.{ .error_value = .{
                .ty = error_set_type,
                .error_tag_name = name_index,
            } });
            return Type.fromIP(analyser, error_set_type, error_value);
        },

        .root,
        .decl_test,
        .stmt_defer,
        .switch_prong,
        .switch_range,
        => {},
        .expr_continue,
        .expr_break,
        .expr_return,
        => {
            return Type.fromIP(analyser, .noreturn_type, null);
        },

        .expr_deref,
        .expr_dot_access,
        .expr_slice,
        .expr_index,
        => {
            const binding = try analyser.resolveBindingOfNodeUncached(options) orelse return null;
            return binding.type;
        },

        else => {}, // BRANCH_TODO
    }
    return null;
}

fn resolveBindingOfNodeUncached(analyser: *Analyser, options: ResolveOptions) Error!?Binding {
    const node_handle = options.node_handle;
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = &handle.tree;

    switch (node.tag(tree)) {
        .leaf => {
            const name_token = ast.identifierTokenFromIdentifierNode(tree, node) orelse return null;
            const name = offsets.identifierTokenToNameSlice(tree, name_token);

            const is_escaped_identifier = tree.source[name_token.byteOffset(tree)] == '@';
            if (!is_escaped_identifier) {
                if (std.mem.eql(u8, name, "_")) return null;
                if (try analyser.resolvePrimitive(name)) |primitive| {
                    return .{
                        .type = Type.fromIP(analyser, analyser.ip.typeOf(primitive), primitive),
                        .is_const = true,
                    };
                }
            }

            const child = try analyser.lookupSymbolGlobal(handle, name, name_token.byteOffset(tree)) orelse return null;
            const child_ty = try child.resolveType(analyser) orelse return null;
            return .{
                .type = child_ty,
                .is_const = child.isConst(),
            };
        },

        .expr_prefix => {
            const expr: Ast.Expr.Prefix = node.cast(.expr_prefix, tree).?;
            switch (expr.op.get(tree)) {
                .@"&" => {
                    const base_binding = try analyser.resolveBindingOfNodeInternal(.of(expr.rhs.idx, handle)) orelse return null;
                    return .{
                        .type = try analyser.resolveAddressOf(base_binding.is_const, base_binding.type),
                        .is_const = true,
                    };
                },
                else => return .{
                    .type = try analyser.resolveTypeOfNodeUncached(options) orelse return null,
                    .is_const = true,
                },
            }
        },

        .expr_deref => {
            const expr: Ast.Expr.Deref = node.cast(.expr_deref, tree).?;
            const base_type = try analyser.resolveTypeOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            return try analyser.resolveDerefBinding(base_type);
        },

        .expr_dot_access => {
            const expr: Ast.Expr.DotAccess = node.cast(.expr_dot_access, tree).?;
            const field_name = expr.rhs.token(tree);
            if (field_name.tag(tree) != .name) return null;
            const lhs = (try analyser.resolveBindingOfNodeInternal(.of(expr.lhs.idx, handle))) orelse return null;
            const symbol = offsets.identifierTokenToNameSlice(tree, field_name);
            return try analyser.resolveFieldAccessBinding(lhs, symbol);
        },

        .expr_slice => {
            const expr: Ast.Expr.Slice = node.cast(.expr_slice, tree).?;
            const sliced = try analyser.resolveBindingOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            const kind: BracketAccess = try .fromSlice(analyser, handle, expr);
            return try analyser.resolveBracketAccess(sliced, kind);
        },

        .expr_index => {
            const expr: Ast.Expr.ArrayIndex = node.cast(.expr_index, tree).?;
            const lhs = try analyser.resolveBindingOfNodeInternal(.of(expr.lhs.idx, handle)) orelse return null;
            const index = try analyser.resolveIntegerLiteral(u64, .of(expr.rhs.idx, handle));
            return try analyser.resolveBracketAccess(lhs, .{ .single = index });
        },

        else => return .{
            .type = try analyser.resolveTypeOfNodeUncached(options) orelse return null,
            .is_const = true,
        },
    }
}

pub const ResolveOptions = struct {
    node_handle: NodeWithHandle,
    container_type: ?Type,

    pub fn of(node: Ast.Node.Index, handle: *DocumentStore.Handle) ResolveOptions {
        return .{
            .node_handle = .of(node, handle),
            .container_type = null,
        };
    }
};

pub const Binding = struct {
    type: Type,
    is_const: bool,
};

/// Represents a resolved Zig type.
/// This is the return type of `resolveTypeOfNode`.
pub const Type = struct {
    data: Data,
    /// If true, the type `type`, the attached data is the value of the type value.
    /// ```zig
    /// const foo = u32; // is_type_val == true
    /// const bar = @as(u32, ...); // is_type_val == false
    /// ```
    /// if `data == .ip_index` then this field is equivalent to `data.ip_index.type == .type_type`
    is_type_val: bool,

    pub const Data = union(enum) {
        /// - `*const T`
        /// - `[*]T`
        /// - `[]const T`
        /// - `[*c]T`
        pointer: struct {
            size: std.lang.Type.Pointer.Size,
            /// `.none` means no sentinel, `.unknown_unknown` means unknown sentinel
            sentinel: InternPool.Index,
            is_const: bool,
            elem_ty: *Type,
        },

        /// `[elem_count :sentinel]elem_ty`
        array: struct {
            elem_count: ?u64,
            /// `.none` means no sentinel, `.unknown_unknown` means unknown sentinel
            sentinel: InternPool.Index,
            elem_ty: *Type,
        },

        /// `.{a,b}`
        tuple: []Type,

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
        container: Container,

        /// - Function: `fn () Foo`, `fn foo() Foo`
        function: Function,

        /// - `@compileError("")`
        compile_error: NodeWithHandle,

        /// `T` in `fn Foo(comptime T: type) type`
        type_parameter: TokenWithHandle,

        /// `anytype` in `fn foo(bar: anytype) @TypeOf(bar)`
        anytype_parameter: struct {
            token_handle: TokenWithHandle,
            type_from_callsite_references: ?*Type,
        },

        /// Branching types
        either: []const EitherEntry,

        /// Primitive type: `u8`, `bool`, `type`, etc.
        /// Primitive value: `true`, `false`, `null`, `undefined`
        ip_index: struct {
            type: InternPool.Index,
            index: ?InternPool.Index,
        },

        pub const Container = struct {
            scope_handle: ScopeWithHandle,
            bound_params: TokenToTypeMap,

            pub fn root(handle: *DocumentStore.Handle) Container {
                return .{
                    .scope_handle = .{ .handle = handle, .scope = .root },
                    .bound_params = .empty,
                };
            }
        };

        pub const Function = struct {
            fn_token: Ast.Token.Index,
            handle: *DocumentStore.Handle,

            container_type: *Type,
            doc_comments: ?[]const u8,
            name: ?[]const u8,
            parameters: []Parameter,
            has_varargs: bool,
            return_value: *Type,
        };

        pub const Parameter = struct {
            doc_comments: ?[]const u8,
            modifier: ?Modifier,
            name: ?[]const u8,
            name_token: ?Ast.Token.Index,
            type: Type,

            pub const Modifier = enum {
                comptime_param,
                noalias_param,
            };
        };

        pub const EitherEntry = struct {
            /// the `is_type_val` property is inherited from the containing `Type`
            type_data: Data,
            descriptor: []const u8,
        };

        fn createPointer(
            analyser: *Analyser,
            size: std.lang.Type.Pointer.Size,
            sentinel: InternPool.Index,
            is_const: bool,
            elem_ty: Type,
        ) !Data {
            std.debug.assert(elem_ty.is_type_val);
            blk: {
                const elem_type = elem_ty.ipIndex() orelse break :blk;
                const index = try analyser.ip.get(.{
                    .pointer_type = .{
                        .elem_type = elem_type,
                        .sentinel = try analyser.coerceIP(elem_type, sentinel) orelse break :blk,
                        .flags = .{
                            .size = size,
                            .is_const = is_const,
                        },
                    },
                });
                return .{ .ip_index = .{ .type = .type_type, .index = index } };
            }
            return .{
                .pointer = .{
                    .size = size,
                    .sentinel = sentinel,
                    .is_const = is_const,
                    .elem_ty = try analyser.allocType(elem_ty),
                },
            };
        }

        fn createArray(
            analyser: *Analyser,
            elem_count: ?u64,
            sentinel: InternPool.Index,
            elem_ty: Type,
        ) !Data {
            std.debug.assert(elem_ty.is_type_val);
            blk: {
                const len = elem_count orelse break :blk;
                const child = elem_ty.ipIndex() orelse break :blk;
                const index = try analyser.ip.get(.{
                    .array_type = .{
                        .len = len,
                        .child = child,
                        .sentinel = try analyser.coerceIP(child, sentinel) orelse break :blk,
                    },
                });
                return .{ .ip_index = .{ .type = .type_type, .index = index } };
            }
            return .{
                .array = .{
                    .elem_count = elem_count,
                    .sentinel = sentinel,
                    .elem_ty = try analyser.allocType(elem_ty),
                },
            };
        }

        fn createTuple(analyser: *Analyser, elem_tys: []Type) !Data {
            const tys = try analyser.gpa.alloc(InternPool.Index, elem_tys.len);
            defer analyser.gpa.free(tys);

            const vals = try analyser.gpa.alloc(InternPool.Index, elem_tys.len);
            defer analyser.gpa.free(vals);

            for (tys, vals, elem_tys) |*ty, *val, elem_ty| {
                ty.* = elem_ty.ipIndex() orelse break;
                val.* = .none;
            } else {
                const types = try analyser.ip.getIndexSlice(tys);
                const values = try analyser.ip.getIndexSlice(vals);
                const index = try analyser.ip.get(.{ .tuple_type = .{ .types = types, .values = values } });
                return .{ .ip_index = .{ .type = .type_type, .index = index } };
            }

            return .{ .tuple = elem_tys };
        }

        fn createOptional(analyser: *Analyser, child_ty: Type) !Data {
            std.debug.assert(child_ty.is_type_val);
            if (child_ty.ipIndex()) |payload_type| {
                const index = try analyser.ip.get(.{ .optional_type = .{ .payload_type = payload_type } });
                return .{ .ip_index = .{ .type = .type_type, .index = index } };
            }
            return .{ .optional = try analyser.allocType(child_ty) };
        }

        fn createErrorUnion(
            analyser: *Analyser,
            error_set: ?Type,
            payload: Type,
        ) !Data {
            std.debug.assert(error_set == null or error_set.?.is_type_val);
            std.debug.assert(payload.is_type_val);
            blk: {
                const error_set_type: InternPool.Index =
                    if (error_set) |e|
                        e.ipIndex() orelse break :blk
                    else
                        .none;
                const payload_type = payload.ipIndex() orelse break :blk;
                const index = try analyser.ip.get(.{
                    .error_union_type = .{
                        .error_set_type = error_set_type,
                        .payload_type = payload_type,
                    },
                });
                return .{ .ip_index = .{ .type = .type_type, .index = index } };
            }
            return .{
                .error_union = .{
                    .error_set = if (error_set) |e| try analyser.allocType(e) else null,
                    .payload = try analyser.allocType(payload),
                },
            };
        }

        pub fn hashWithHasher(data: Data, hasher: anytype) void {
            hasher.update(&.{@backingInt(data)});
            switch (data) {
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
                .tuple => |elem_ty_slice| {
                    for (elem_ty_slice) |elem_ty| {
                        elem_ty.hashWithHasher(hasher);
                    }
                },
                .optional, .union_tag => |t| t.hashWithHasher(hasher),
                .error_union => |info| {
                    if (info.error_set) |error_set| {
                        error_set.hashWithHasher(hasher);
                    }
                    info.payload.hashWithHasher(hasher);
                },
                .container => |info| {
                    info.scope_handle.hashWithHasher(hasher);
                    for (info.bound_params.keys(), info.bound_params.values()) |token_handle, ty| {
                        token_handle.hashWithHasher(hasher);
                        ty.hashWithHasher(hasher);
                    }
                },
                .function => |info| {
                    std.hash.autoHash(hasher, info.fn_token);
                    hasher.update(info.handle.uri.raw);
                    info.container_type.hashWithHasher(hasher);
                    for (info.parameters) |param| {
                        param.type.hashWithHasher(hasher);
                    }
                    info.return_value.hashWithHasher(hasher);
                },
                .compile_error => |node_handle| {
                    std.hash.autoHash(hasher, node_handle.node);
                    hasher.update(node_handle.handle.uri.raw);
                },
                .type_parameter => |token_handle| token_handle.hashWithHasher(hasher),
                .anytype_parameter => |info| {
                    info.token_handle.hashWithHasher(hasher);
                    if (info.type_from_callsite_references) |t| {
                        t.hashWithHasher(hasher);
                    }
                },
                .either => |entries| {
                    for (entries) |entry| {
                        hasher.update(entry.descriptor);
                        entry.type_data.hashWithHasher(hasher);
                    }
                },
                .ip_index => |payload| {
                    std.hash.autoHash(hasher, payload.type);
                    std.hash.autoHash(hasher, payload.index);
                },
            }
        }

        pub fn eql(a: Data, b: Data) bool {
            if (@backingInt(a) != @backingInt(b)) return false;

            switch (a) {
                .pointer => |a_type| {
                    const b_type = b.pointer;
                    if (a_type.size != b_type.size) return false;
                    if (a_type.sentinel != b_type.sentinel) return false;
                    if (!a_type.elem_ty.eql(b_type.elem_ty.*)) return false;
                },
                .array => |a_type| {
                    const b_type = b.array;
                    if (!std.meta.eql(a_type.elem_count, b_type.elem_count)) return false;
                    if (a_type.sentinel != b_type.sentinel) return false;
                    if (!a_type.elem_ty.eql(b_type.elem_ty.*)) return false;
                },
                .tuple => |a_slice| {
                    const b_slice = b.tuple;
                    if (a_slice.len != b_slice.len) return false;
                    for (a_slice, b_slice) |a_type, b_type| {
                        if (!a_type.eql(b_type)) return false;
                    }
                },
                inline .optional,
                .union_tag,
                => |a_type, name| {
                    const b_type = @field(b, @tagName(name));
                    if (!a_type.eql(b_type.*)) return false;
                },
                .error_union => |info| {
                    const b_info = b.error_union;
                    if (!info.payload.eql(b_info.payload.*)) return false;
                    if ((info.error_set == null) != (b_info.error_set == null)) return false;
                    if (info.error_set) |a_error_set| {
                        if (!a_error_set.eql(b_info.error_set.?.*)) return false;
                    }
                },
                .container => |a_info| {
                    const b_info = b.container;
                    if (!a_info.scope_handle.eql(b_info.scope_handle)) return false;
                    if (a_info.bound_params.count() != b_info.bound_params.count()) return false;
                    for (a_info.bound_params.keys(), a_info.bound_params.values()) |a_token_handle, a_type| {
                        const b_type = b_info.bound_params.get(a_token_handle) orelse return false;
                        if (!a_type.eql(b_type)) return false;
                    }
                },
                .function => |a_info| {
                    const b_info = b.function;
                    if (a_info.fn_token != b_info.fn_token) return false;
                    if (!a_info.handle.uri.eql(b_info.handle.uri)) return false;
                    if (!a_info.container_type.eql(b_info.container_type.*)) return false;
                    if (a_info.parameters.len != b_info.parameters.len) return false;
                    for (a_info.parameters, b_info.parameters) |a_param, b_param| {
                        if (!a_param.type.eql(b_param.type)) return false;
                    }
                    if (!a_info.return_value.eql(b_info.return_value.*)) return false;
                },
                .compile_error => |a_node_handle| return a_node_handle.eql(b.compile_error),
                .type_parameter => |a_token_handle| return a_token_handle.eql(b.type_parameter),
                .anytype_parameter => |a_info| {
                    const b_info = b.anytype_parameter;
                    if (!a_info.token_handle.eql(b_info.token_handle)) return false;
                    const a_type_maybe = a_info.type_from_callsite_references;
                    const b_type_maybe = b_info.type_from_callsite_references;
                    if (a_type_maybe) |a_type| {
                        const b_type = b_type_maybe orelse return false;
                        if (!a_type.eql(b_type.*)) return false;
                    } else {
                        if (b_type_maybe != null) return false;
                    }
                },
                .either => |a_entries| {
                    const b_entries = b.either;

                    if (a_entries.len != b_entries.len) return false;
                    for (a_entries, b_entries) |a_entry, b_entry| {
                        if (!std.mem.eql(u8, a_entry.descriptor, b_entry.descriptor)) return false;
                        if (!a_entry.type_data.eql(b_entry.type_data)) return false;
                    }
                },
                .ip_index => |a_payload| {
                    const b_payload = b.ip_index;

                    if (a_payload.type != b_payload.type) return false;
                    if (a_payload.index != b_payload.index) return false;
                },
            }

            return true;
        }

        fn isGeneric(data: Data) bool {
            return switch (data) {
                .type_parameter => true,
                .anytype_parameter => true,
                .pointer => |info| info.elem_ty.data.isGeneric(),
                .array => |info| info.elem_ty.data.isGeneric(),
                .tuple => |types| {
                    for (types) |t| {
                        if (t.data.isGeneric()) {
                            return true;
                        }
                    }
                    return false;
                },
                .optional => |t| t.data.isGeneric(),
                .error_union => |info| {
                    if (info.payload.data.isGeneric()) {
                        return true;
                    }
                    if (info.error_set) |t| {
                        if (t.data.isGeneric()) { // is this possible?
                            return true;
                        }
                    }
                    return false;
                },
                .union_tag => |t| t.data.isGeneric(),
                .container => |info| info.bound_params.count() != 0,
                .function => |info| {
                    if (info.container_type.data.isGeneric()) {
                        return true;
                    }
                    if (info.return_value.data.isGeneric()) {
                        return true;
                    }
                    for (info.parameters) |param| {
                        if (param.type.data.isGeneric()) {
                            return true;
                        }
                    }
                    return false;
                },
                .either => |entries| {
                    for (entries) |entry| {
                        if (entry.type_data.isGeneric()) {
                            return true;
                        }
                    }
                    return false;
                },
                .compile_error,
                .ip_index,
                => false,
            };
        }

        const GenericSet = std.HashMapUnmanaged(Data, void, GenericContext, std.hash_map.default_max_load_percentage);

        const GenericContext = struct {
            bound_params: TokenToTypeMap,

            pub fn hash(ctx: GenericContext, data: Data) u64 {
                var hasher: std.hash.Wyhash = .init(0);
                data.hashWithHasher(&hasher);
                for (ctx.bound_params.keys(), ctx.bound_params.values()) |token_handle, ty| {
                    token_handle.hashWithHasher(&hasher);
                    ty.hashWithHasher(&hasher);
                }
                return hasher.final();
            }

            pub fn eql(ctx: GenericContext, a: Data, b: Data) bool {
                _ = ctx;
                return a.eql(b);
            }
        };

        fn resolveGeneric(
            data: Data,
            analyser: *Analyser,
            bound_params: TokenToTypeMap,
            visiting: *GenericSet,
        ) error{OutOfMemory}!Data {
            if (!data.isGeneric()) {
                return data;
            }
            const ctx: GenericContext = .{ .bound_params = bound_params };
            const gop = try visiting.getOrPutContext(analyser.gpa, data, ctx);
            if (gop.found_existing) return data;
            defer std.debug.assert(visiting.removeContext(data, ctx));
            switch (data) {
                .compile_error,
                .ip_index,
                => unreachable,
                .type_parameter => |token_handle| {
                    const t = bound_params.get(token_handle) orelse return data;
                    std.debug.assert(t.is_type_val);
                    return t.data.resolveGeneric(analyser, bound_params, visiting);
                },
                .anytype_parameter => |info| {
                    const t = bound_params.get(info.token_handle) orelse return data;
                    std.debug.assert(t.is_type_val);
                    return t.data.resolveGeneric(analyser, bound_params, visiting);
                },
                .pointer => |info| {
                    const size = info.size;
                    const sentinel = info.sentinel;
                    const is_const = info.is_const;
                    const elem_ty = try analyser.resolveGenericTypeInternal(info.elem_ty.*, bound_params, visiting);
                    return try createPointer(analyser, size, sentinel, is_const, elem_ty);
                },
                .array => |info| {
                    const elem_count = info.elem_count;
                    const sentinel = info.sentinel;
                    const elem_ty = try analyser.resolveGenericTypeInternal(info.elem_ty.*, bound_params, visiting);
                    return try createArray(analyser, elem_count, sentinel, elem_ty);
                },
                .tuple => |info| {
                    const elem_tys = blk: {
                        const types = try analyser.arena.alloc(Type, info.len);
                        for (info, types) |old, *new| {
                            new.* = try analyser.resolveGenericTypeInternal(old, bound_params, visiting);
                        }
                        break :blk types;
                    };
                    return try createTuple(analyser, elem_tys);
                },
                .optional => |info| {
                    const child_ty = try analyser.resolveGenericTypeInternal(info.*, bound_params, visiting);
                    return try createOptional(analyser, child_ty);
                },
                .error_union => |info| {
                    const error_set = if (info.error_set) |t| try analyser.resolveGenericTypeInternal(t.*, bound_params, visiting) else null;
                    const payload = try analyser.resolveGenericTypeInternal(info.payload.*, bound_params, visiting);
                    return try createErrorUnion(analyser, error_set, payload);
                },
                .union_tag => |info| return .{
                    .union_tag = try analyser.allocType(try analyser.resolveGenericTypeInternal(info.*, bound_params, visiting)),
                },
                .container => |info| return .{
                    .container = .{
                        .scope_handle = info.scope_handle,
                        .bound_params = blk: {
                            var new_params: TokenToTypeMap = .empty;
                            try new_params.ensureTotalCapacity(analyser.arena, info.bound_params.count());
                            for (info.bound_params.keys(), info.bound_params.values()) |k, v| {
                                const t = try analyser.resolveGenericTypeInternal(v, bound_params, visiting);
                                new_params.putAssumeCapacity(k, t);
                            }
                            break :blk new_params;
                        },
                    },
                },
                .function => |info| return .{
                    .function = .{
                        .fn_token = info.fn_token,
                        .handle = info.handle,
                        .container_type = try analyser.allocType(try analyser.resolveGenericTypeInternal(info.container_type.*, bound_params, visiting)),
                        .doc_comments = info.doc_comments,
                        .name = info.name,
                        .parameters = blk: {
                            const parameters = try analyser.arena.alloc(Parameter, info.parameters.len);
                            for (info.parameters, parameters) |old, *new| {
                                new.* = .{
                                    .doc_comments = old.doc_comments,
                                    .modifier = old.modifier,
                                    .name = old.name,
                                    .name_token = old.name_token,
                                    .type = try analyser.resolveGenericTypeInternal(old.type, bound_params, visiting),
                                };
                            }
                            break :blk parameters;
                        },
                        .has_varargs = info.has_varargs,
                        .return_value = try analyser.allocType(try analyser.resolveGenericTypeInternal(info.return_value.*, bound_params, visiting)),
                    },
                },
                .either => |info| return .{
                    .either = blk: {
                        const entries = try analyser.arena.alloc(EitherEntry, info.len);
                        for (info, entries) |old, *new| {
                            new.* = .{
                                .type_data = try old.type_data.resolveGeneric(analyser, bound_params, visiting),
                                .descriptor = old.descriptor,
                            };
                        }
                        break :blk entries;
                    },
                },
            }
        }
    };

    pub const unknown_type: Type = .{
        .data = .{
            .ip_index = .{
                .type = .type_type,
                .index = null,
            },
        },
        .is_type_val = true,
    };

    fn createPointerType(
        analyser: *Analyser,
        size: std.lang.Type.Pointer.Size,
        sentinel: InternPool.Index,
        is_const: bool,
        elem_ty: Type,
    ) !Type {
        return .{
            .data = try Data.createPointer(analyser, size, sentinel, is_const, elem_ty),
            .is_type_val = true,
        };
    }

    fn createArrayType(
        analyser: *Analyser,
        elem_count: ?u64,
        sentinel: InternPool.Index,
        elem_ty: Type,
    ) !Type {
        return .{
            .data = try Data.createArray(analyser, elem_count, sentinel, elem_ty),
            .is_type_val = true,
        };
    }

    fn createTupleType(analyser: *Analyser, elem_tys: []Type) !Type {
        return .{
            .data = try Data.createTuple(analyser, elem_tys),
            .is_type_val = true,
        };
    }

    fn createOptionalType(analyser: *Analyser, child_ty: Type) !Type {
        return .{
            .data = try Data.createOptional(analyser, child_ty),
            .is_type_val = true,
        };
    }

    fn createErrorUnionType(
        analyser: *Analyser,
        error_set: ?Type,
        payload: Type,
    ) !Type {
        return .{
            .data = try Data.createErrorUnion(analyser, error_set, payload),
            .is_type_val = true,
        };
    }

    pub fn hash32(self: Type) u32 {
        return @truncate(self.hash64());
    }

    pub fn hash64(self: Type) u64 {
        var hasher: std.hash.Wyhash = .init(0);
        self.hashWithHasher(&hasher);
        return hasher.final();
    }

    pub fn hashWithHasher(self: Type, hasher: anytype) void {
        hasher.update(&.{@intFromBool(self.is_type_val)});
        self.data.hashWithHasher(hasher);
    }

    pub fn eql(a: Type, b: Type) bool {
        if (a.is_type_val != b.is_type_val) return false;
        if (!a.data.eql(b.data)) return false;
        return true;
    }

    pub const ArraySet = ArrayMap(void);

    pub fn ArrayMap(comptime V: type) type {
        return std.array_hash_map.Custom(Type, V, ArrayMapContext, true);
    }

    pub const ArrayMapContext = struct {
        pub fn hash(self: ArrayMapContext, ty: Type) u32 {
            _ = self;
            return ty.hash32();
        }

        pub fn eql(self: ArrayMapContext, a: Type, b: Type, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return a.eql(b);
        }
    };

    pub fn ipIndex(self: Type) ?InternPool.Index {
        return switch (self.data) {
            .ip_index => |payload| payload.index,
            else => null,
        };
    }

    fn withoutIPIndex(self: Type, analyser: *Analyser) Type {
        return switch (self.data) {
            .ip_index => |payload| fromIP(analyser, payload.type, null),
            else => self,
        };
    }

    pub fn fromIP(analyser: *Analyser, ty: InternPool.Index, index: ?InternPool.Index) Type {
        std.debug.assert(analyser.ip.isType(ty));
        if (index) |idx| std.debug.assert(analyser.ip.typeOf(idx) == ty);
        return .{
            .data = .{ .ip_index = .{ .type = ty, .index = index } },
            .is_type_val = ty == .type_type,
        };
    }

    pub const TypeWithDescriptor = struct {
        type: Type,
        descriptor: []const u8,
    };

    pub fn fromEither(analyser: *Analyser, entries: []const TypeWithDescriptor) error{OutOfMemory}!?Type {
        const arena = analyser.arena;
        if (entries.len == 0)
            return null;

        if (entries.len == 1)
            return entries[0].type;

        peer_type_resolution: {
            var chosen = entries[0].type;
            for (entries[1..]) |entry| {
                const candidate = entry.type;
                chosen = try analyser.resolvePeerTypes(chosen, candidate) orelse break :peer_type_resolution;
            }
            return chosen;
        }

        // Note that we don't hash/equate descriptors to remove
        // duplicates

        const DeduplicatorContext = struct {
            pub fn hash(self: @This(), item: Type.Data.EitherEntry) u32 {
                _ = self;
                const ty: Type = .{ .data = item.type_data, .is_type_val = true };
                return ty.hash32();
            }

            pub fn eql(self: @This(), a: Type.Data.EitherEntry, b: Type.Data.EitherEntry, b_index: usize) bool {
                _ = b_index;
                _ = self;
                const a_ty: Type = .{ .data = a.type_data, .is_type_val = true };
                const b_ty: Type = .{ .data = b.type_data, .is_type_val = true };
                return a_ty.eql(b_ty);
            }
        };
        const Deduplicator = std.array_hash_map.Custom(Type.Data.EitherEntry, void, DeduplicatorContext, true);

        var deduplicator: Deduplicator = .empty;
        defer deduplicator.deinit(arena);

        const has_type_val = for (entries) |entry| {
            if (entry.type.data == .compile_error) {
                continue;
            }
            break entry.type.is_type_val;
        } else entries[0].type.is_type_val;

        for (entries) |entry| {
            try deduplicator.put(
                arena,
                .{ .type_data = entry.type.data, .descriptor = entry.descriptor },
                {},
            );
            if (entry.type.data == .compile_error) {
                continue;
            }
            if (entry.type.is_type_val != has_type_val) {
                return null;
            }
        }

        if (deduplicator.count() == 1)
            return entries[0].type;

        return .{
            .data = .{ .either = try arena.dupe(Type.Data.EitherEntry, deduplicator.keys()) },
            .is_type_val = has_type_val,
        };
    }

    /// Resolves all possible types by recursively expanding any conditional types.
    /// Drops duplicates
    pub fn getAllTypesWithHandles(ty: Type, analyser: *Analyser) error{OutOfMemory}![]const Type {
        var all_types: ArraySet = .empty;
        _ = try ty.getAllTypesWithHandlesArraySet(analyser, &all_types);
        return all_types.keys();
    }

    fn isConditional(ty: Type) bool {
        return switch (ty.data) {
            .either => true,
            .anytype_parameter => true,
            .optional => |child_ty| child_ty.isConditional(),
            .pointer => |info| info.elem_ty.isConditional(),
            .array => |info| info.elem_ty.isConditional(),
            .tuple => |types| {
                for (types) |t|
                    if (t.isConditional()) return true;
                return false;
            },
            .container => |info| {
                for (info.bound_params.values()) |t|
                    if (t.isConditional()) return true;
                return false;
            },
            .error_union => |info| {
                if (info.payload.isConditional()) return true;
                if (info.error_set) |e|
                    if (e.isConditional()) return true;
                return false;
            },
            .function => |info| {
                if (info.container_type.isConditional()) return true;
                if (info.return_value.isConditional()) return true;
                for (info.parameters) |param|
                    if (param.type.isConditional()) return true;
                return false;
            },
            .union_tag,
            .compile_error,
            .type_parameter,
            .ip_index,
            => false,
        };
    }

    /// Returns true if we have reached the limit for analyzing combinations
    pub fn getAllTypesWithHandlesArraySet(ty: Type, analyser: *Analyser, all_types: *ArraySet) error{OutOfMemory}!bool {
        if (all_types.count() >= analyser.max_conditional_combos) {
            return true;
        }
        const arena = analyser.arena;
        if (!ty.isConditional()) {
            try all_types.put(arena, ty, {});
            return false;
        }
        switch (ty.data) {
            .union_tag,
            .compile_error,
            .type_parameter,
            .ip_index,
            => unreachable,
            .either => |entries| {
                for (entries) |entry| {
                    const entry_ty: Type = .{ .data = entry.type_data, .is_type_val = ty.is_type_val };
                    if (try entry_ty.getAllTypesWithHandlesArraySet(analyser, all_types)) {
                        return true;
                    }
                }
            },
            .anytype_parameter => |info| {
                if (info.type_from_callsite_references) |t| {
                    if (try t.getAllTypesWithHandlesArraySet(analyser, all_types)) {
                        return true;
                    }
                } else {
                    try all_types.put(arena, ty, {});
                }
            },
            .optional => |child_ty| {
                for (try child_ty.getAllTypesWithHandles(analyser)) |t| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    const new_child_ty = try analyser.allocType(t);
                    try all_types.put(arena, .{ .data = .{ .optional = new_child_ty }, .is_type_val = ty.is_type_val }, {});
                }
            },
            inline .pointer, .array => |info, tag| {
                for (try info.elem_ty.getAllTypesWithHandles(analyser)) |t| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    var new_info = info;
                    new_info.elem_ty = try analyser.allocType(t);
                    const data = @unionInit(Type.Data, @tagName(tag), new_info);
                    try all_types.put(arena, .{ .data = data, .is_type_val = ty.is_type_val }, {});
                }
            },
            .tuple => |types| {
                var possible_types: ArrayMap([]const Type) = .empty;
                for (types) |t| {
                    try possible_types.put(arena, t, try t.getAllTypesWithHandles(analyser));
                }
                var iter: ComboIterator = try .init(arena, &possible_types);
                while (iter.next()) |combo| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    const new_types = try arena.alloc(Type, types.len);
                    for (new_types, types) |*new, old| new.* = combo.get(old).?;
                    try all_types.put(arena, .{ .data = .{ .tuple = new_types }, .is_type_val = ty.is_type_val }, {});
                }
            },
            .container => |info| {
                var possible_types: ArrayMap([]const Type) = .empty;
                const types = info.bound_params.values();
                for (types) |t| {
                    try possible_types.put(arena, t, try t.getAllTypesWithHandles(analyser));
                }
                var iter: ComboIterator = try .init(arena, &possible_types);
                while (iter.next()) |combo| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    const new_types = try arena.alloc(Type, types.len);
                    for (new_types, types) |*new, old| new.* = combo.get(old).?;
                    var new_info = info;
                    new_info.bound_params = try .init(arena, info.bound_params.keys(), new_types);
                    try all_types.put(arena, .{ .data = .{ .container = new_info }, .is_type_val = ty.is_type_val }, {});
                }
            },
            .error_union => |info| {
                var possible_types: ArrayMap([]const Type) = .empty;
                try possible_types.put(arena, info.payload.*, try info.payload.getAllTypesWithHandles(analyser));
                if (info.error_set) |t| {
                    try possible_types.put(arena, t.*, try t.getAllTypesWithHandles(analyser));
                }
                var iter: ComboIterator = try .init(arena, &possible_types);
                while (iter.next()) |combo| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    var new_info = info;
                    new_info.payload = try analyser.allocType(combo.get(info.payload.*).?);
                    if (info.error_set) |t| {
                        new_info.error_set = try analyser.allocType(combo.get(t.*).?);
                    }
                    try all_types.put(arena, .{ .data = .{ .error_union = new_info }, .is_type_val = ty.is_type_val }, {});
                }
            },
            .function => |info| {
                var possible_types: ArrayMap([]const Type) = .empty;
                try possible_types.put(arena, info.container_type.*, try info.container_type.getAllTypesWithHandles(analyser));
                for (info.parameters) |param| {
                    try possible_types.put(arena, param.type, try param.type.getAllTypesWithHandles(analyser));
                }
                if (info.return_value.is_type_val) {
                    try possible_types.put(arena, info.return_value.*, try info.return_value.getAllTypesWithHandles(analyser));
                } else {
                    const return_type = try info.return_value.typeOf(analyser);
                    try possible_types.put(arena, return_type, try return_type.getAllTypesWithHandles(analyser));
                }
                var iter: ComboIterator = try .init(arena, &possible_types);
                while (iter.next()) |combo| {
                    if (all_types.count() >= analyser.max_conditional_combos) {
                        return true;
                    }
                    var new_info = info;
                    new_info.container_type = try analyser.allocType(combo.get(info.container_type.*).?);
                    new_info.parameters = try arena.alloc(Data.Parameter, info.parameters.len);
                    @memcpy(new_info.parameters, info.parameters);
                    for (new_info.parameters, info.parameters) |*new, old| {
                        new.type = combo.get(old.type).?;
                    }
                    if (info.return_value.is_type_val) {
                        new_info.return_value = try analyser.allocType(combo.get(info.return_value.*).?);
                    } else {
                        const return_type = try info.return_value.typeOf(analyser);
                        const return_value = try combo.get(return_type).?.instanceUnchecked(analyser);
                        new_info.return_value = try analyser.allocType(return_value);
                    }
                    try all_types.put(arena, .{ .data = .{ .function = new_info }, .is_type_val = ty.is_type_val }, {});
                }
            },
        }
        return false;
    }

    const ComboIterator = struct {
        possible_types: *const ArrayMap([]const Type),
        current_combo: ArrayMap(Type),
        total_combos: usize,
        counter: usize,

        fn init(
            arena: std.mem.Allocator,
            possible_types: *const ArrayMap([]const Type),
        ) error{OutOfMemory}!ComboIterator {
            var current_combo: ArrayMap(Type) = .empty;
            try current_combo.entries.resize(arena, possible_types.count());
            @memcpy(current_combo.keys(), possible_types.keys());
            try current_combo.reIndex(arena);

            var total_combos: usize = 1;
            for (possible_types.values()) |types| {
                total_combos *= types.len;
            }

            return .{
                .possible_types = possible_types,
                .current_combo = current_combo,
                .total_combos = total_combos,
                .counter = 0,
            };
        }

        fn next(iter: *ComboIterator) ?*const ArrayMap(Type) {
            if (iter.counter == iter.total_combos) return null;
            var x = iter.counter;
            for (iter.current_combo.values(), iter.possible_types.values()) |*t, types| {
                t.* = types[x % types.len];
                x /= types.len;
            }
            iter.counter += 1;
            return &iter.current_combo;
        }
    };

    pub fn instanceTypeVal(self: Type, analyser: *Analyser) error{OutOfMemory}!?Type {
        if (!self.is_type_val) return null;
        return try self.instanceUnchecked(analyser);
    }

    pub fn instanceUnchecked(self: Type, analyser: *Analyser) error{OutOfMemory}!Type {
        std.debug.assert(self.is_type_val);
        return switch (self.data) {
            .ip_index => |payload| fromIP(analyser, payload.index orelse try analyser.ip.getUnknown(payload.type), null),
            .either => |old_entries| {
                const new_entries = try analyser.arena.alloc(Type.Data.EitherEntry, old_entries.len);
                for (old_entries, new_entries) |old, *new| {
                    const old_type: Type = .{ .data = old.type_data, .is_type_val = self.is_type_val };
                    const new_type = try old_type.instanceUnchecked(analyser);
                    new.* = .{
                        .type_data = new_type.data,
                        .descriptor = old.descriptor,
                    };
                }
                return .{
                    .data = .{ .either = new_entries },
                    .is_type_val = false,
                };
            },
            else => .{ .data = self.data, .is_type_val = false },
        };
    }

    pub fn typeOf(self: Type, analyser: *Analyser) error{OutOfMemory}!Type {
        if (self.is_type_val) {
            return fromIP(analyser, .type_type, .type_type);
        }

        if (self.data == .ip_index) {
            return fromIP(analyser, .type_type, self.data.ip_index.type);
        }

        if (self.data == .either) {
            const old_entries = self.data.either;
            const new_entries = try analyser.arena.alloc(Type.Data.EitherEntry, old_entries.len);
            for (old_entries, new_entries) |old, *new| {
                const old_type: Type = .{ .data = old.type_data, .is_type_val = self.is_type_val };
                const new_type = try old_type.typeOf(analyser);
                new.* = .{
                    .type_data = new_type.data,
                    .descriptor = old.descriptor,
                };
            }
            return .{
                .data = .{ .either = new_entries },
                .is_type_val = true,
            };
        }

        return .{
            .data = self.data,
            .is_type_val = true,
        };
    }

    fn isRoot(self: Type) bool {
        switch (self.data) {
            .container => |info| return info.scope_handle.scope == Scope.Index.root,
            else => return false,
        }
    }

    pub fn isGenericType(self: Type) bool {
        return self.data.isGeneric();
    }

    fn getContainerKind(self: Type) ?Ast.Token.Tag {
        const scope_handle = switch (self.data) {
            .container => |info| info.scope_handle,
            else => return null,
        };
        if (scope_handle.scope == .root) return .@"struct";

        const node = scope_handle.toNode();

        const tree = &scope_handle.handle.tree;
        return node.mainToken(tree).tag(tree);
    }

    fn isContainerKind(self: Type, container_kind_tok: Ast.Token.Tag) bool {
        return self.getContainerKind() == container_kind_tok;
    }

    pub fn isStructType(self: Type, analyser: *Analyser) bool {
        if (!self.is_type_val) return false;
        return switch (self.data) {
            .tuple => true,
            .ip_index => |payload| {
                const index = payload.index orelse return false;
                return analyser.ip.zigTypeTag(index) == .@"struct";
            },
            else => self.isContainerKind(.@"struct") or self.isRoot(),
        };
    }

    pub fn isNamespace(self: Type) bool {
        const scope_handle = switch (self.data) {
            .tuple => |fields| return fields.len == 0,
            .container => |info| info.scope_handle,
            else => return false,
        };
        const node = scope_handle.toNode();
        const tree = &scope_handle.handle.tree;
        const expr: Ast.Expr.Container = node.cast(.type_container, tree).?;
        switch (expr.kind.get(tree)) {
            .@"struct" => {},
            else => return false,
        }
        var member_it = expr.members.iter(tree);
        while (member_it.next(tree)) |member| {
            switch (member.get(tree)) {
                .field => return false,
                else => continue,
            }
        }
        return true;
    }

    pub fn isEnumType(self: Type) bool {
        return self.isContainerKind(.@"enum");
    }

    pub fn isUnionType(self: Type) bool {
        return self.isContainerKind(.@"union");
    }

    pub fn isOpaqueType(self: Type) bool {
        return self.isContainerKind(.@"opaque");
    }

    pub fn isTaggedUnion(self: Type) bool {
        return switch (self.data) {
            .container => |info| {
                const node = info.scope_handle.toNode();
                const tree = &info.scope_handle.handle.tree;
                const container = node.cast(.type_container, tree) orelse return false;
                return ast.isTaggedUnion(tree, container);
            },
            else => false,
        };
    }

    /// returns whether the given type is of type `type`.
    pub fn isMetaType(self: Type) bool {
        if (!self.is_type_val) return false;
        switch (self.data) {
            .ip_index => |payload| return payload.index == .type_type,
            else => return false,
        }
    }

    pub fn isErrorSetType(self: Type, analyser: *Analyser) bool {
        if (!self.is_type_val) return false;
        switch (self.data) {
            .ip_index => |payload| {
                const ip_index = payload.index orelse return false;
                return analyser.ip.zigTypeTag(ip_index) == .error_set;
            },
            else => return false,
        }
    }

    pub fn isEnumLiteral(self: Type) bool {
        switch (self.data) {
            .ip_index => |payload| return payload.type == .enum_literal_type,
            else => return false,
        }
    }

    pub fn resolveDeclLiteralResultType(ty: Type) Type {
        std.debug.assert(ty.is_type_val);
        var result_type = ty;
        while (true) {
            result_type = switch (result_type.data) {
                .optional => |child_ty| child_ty.*,
                .error_union => |info| info.payload.*,
                .pointer => |child_ty| child_ty.elem_ty.*,
                else => return result_type,
            };
        }
    }

    pub fn isTypeFunc(self: Type) bool {
        return switch (self.data) {
            .function => |info| info.return_value.is_type_val,
            else => false,
        };
    }

    /// Returns whether the given function has a `anytype` parameter.
    pub fn isGenericFunc(self: Type) bool {
        return switch (self.data) {
            .function => |info| {
                for (info.parameters) |param| {
                    if (param.type.data == .anytype_parameter or param.modifier == .comptime_param) {
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
            .function => true,
            else => false,
        };
    }

    pub fn isNoreturnType(self: Type) bool {
        if (!self.is_type_val) return false;
        return switch (self.data) {
            .compile_error => true,
            .ip_index => |payload| payload.index == .noreturn_type,
            else => false,
        };
    }

    fn pointerSize(self: Type, analyser: *Analyser) ?std.lang.Type.Pointer.Size {
        if (self.is_type_val) return null;
        return switch (self.data) {
            .pointer => |info| info.size,
            .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
                .pointer_type => |pointer_info| pointer_info.flags.size,
                else => null,
            },
            else => null,
        };
    }

    fn pointerElementType(
        self: Type,
        analyser: *Analyser,
        size: std.lang.Type.Pointer.Size,
    ) ?Type {
        if (self.is_type_val) return null;
        return switch (self.data) {
            .pointer => |info| {
                if (info.size != size) return null;
                return info.elem_ty.*;
            },
            .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
                .pointer_type => |pointer_info| {
                    if (pointer_info.flags.size != size) return null;
                    return Type.fromIP(analyser, .type_type, pointer_info.elem_type);
                },
                else => null,
            },
            else => null,
        };
    }

    fn arrayInfo(ty: Type, analyser: *Analyser) ?struct { ?u64, InternPool.Index, Type } {
        if (ty.is_type_val) return null;
        return switch (ty.data) {
            .array => |info| .{
                info.elem_count,
                info.sentinel,
                info.elem_ty.*,
            },
            .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
                .array_type => |array_info| .{
                    array_info.len,
                    array_info.sentinel,
                    Type.fromIP(analyser, .type_type, array_info.child),
                },
                else => null,
            },
            else => null,
        };
    }

    pub fn typeDefinitionToken(self: Type) ?TokenWithHandle {
        return switch (self.data) {
            .container => |info| {
                const fallback: TokenWithHandle = .{
                    .token = info.scope_handle.toNode().firstToken(&info.scope_handle.handle.tree),
                    .handle = info.scope_handle.handle,
                };

                const node = info.scope_handle.toNode();
                const tree = &info.scope_handle.handle.tree;
                const container: Ast.Expr.Container = node.cast(.type_container, tree) orelse
                    return fallback;

                // try to parse something that looks like (and only looks like) `const X = @This();`
                var it = container.members.iter(tree);
                while (it.next(tree)) |member| {
                    const member_field: Ast.Member.Field = (member.cast(.field, tree) orelse continue).get(tree);
                    const member_name = member_field.name orelse continue;

                    const init_node = member_field.init orelse continue;
                    const builtin_call: Ast.Expr.Builtin = (init_node.cast(.builtin, tree) orelse continue).get(tree);
                    const builtin_name = builtin_call.callee.token(tree);
                    std.debug.assert(builtin_name.tag(tree) == .name_builtin);
                    const builtin_name_text = builtin_name.slice(tree);
                    if (!std.mem.eql(u8, builtin_name_text, "@This")) continue;

                    return .{
                        .token = member_name.token(tree),
                        .handle = info.scope_handle.handle,
                    };
                }

                return fallback;
            },
            .function => |info| .{
                .token = info.fn_token,
                .handle = info.handle,
            },
            else => null,
        };
    }

    pub fn docComments(self: Type, allocator: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        if (self.is_type_val) {
            switch (self.data) {
                .container => |info| return try getDocComments(allocator, &info.scope_handle.handle.tree, info.scope_handle.toNode()),
                .function => |info| return info.doc_comments,
                else => {},
            }
        }
        return null;
    }

    pub fn lookupSymbol(
        self: Type,
        analyser: *Analyser,
        symbol: []const u8,
    ) Error!?DeclWithHandle {
        switch (self.data) {
            .either => |entries| {
                // TODO: Return all options instead of first valid one
                for (entries) |entry| {
                    const entry_ty: Type = .{ .data = entry.type_data, .is_type_val = self.is_type_val };
                    if (try entry_ty.lookupSymbol(analyser, symbol)) |decl| {
                        return decl;
                    }
                }
                return null;
            },
            else => {},
        }
        if (self.is_type_val) {
            if (self.isEnumType() or self.isTaggedUnion()) {
                if (try lookupSymbolContainer(self, symbol, .field)) |decl| {
                    return decl;
                }
            }
            return try lookupSymbolContainer(self, symbol, .other);
        } else {
            if (try lookupSymbolContainer(self, symbol, .other)) |decl| {
                const ty = try decl.resolveType(analyser) orelse return null;
                const func_type = try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
                if (analyser.firstParamIs(func_type, try self.typeOf(analyser))) {
                    return decl;
                }
            }
            if (self.isEnumType()) {
                return null;
            }
            return try lookupSymbolContainer(self, symbol, .field);
        }
    }

    pub fn stringifyTypeOf(ty: Type, analyser: *Analyser, options: FormatOptions) error{OutOfMemory}![]const u8 {
        const typeof = try ty.typeOf(analyser);
        var aw: std.Io.Writer.Allocating = .init(analyser.arena);
        defer aw.deinit();
        rawStringify(typeof, &aw.writer, analyser, options) catch |err| switch (err) {
            error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
        };
        return aw.toOwnedSlice();
    }

    pub fn stringifyTypeVal(ty: Type, analyser: *Analyser, options: FormatOptions) error{OutOfMemory}![]const u8 {
        std.debug.assert(ty.data == .ip_index or ty.is_type_val);
        var aw: std.Io.Writer.Allocating = .init(analyser.arena);
        defer aw.deinit();
        rawStringify(ty, &aw.writer, analyser, options) catch |err| switch (err) {
            error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
        };
        return aw.toOwnedSlice();
    }

    fn writeString(str: []const u8, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(str);
    }

    pub const FormatOptions = struct {
        referenced: ?*ReferencedType.Set = null,
        truncate_container_decls: bool,
    };

    fn rawStringify(
        ty: Type,
        writer: *std.Io.Writer,
        analyser: *Analyser,
        options: FormatOptions,
    ) error{ OutOfMemory, WriteFailed }!void {
        const referenced = options.referenced;

        switch (ty.data) {
            .pointer => |info| {
                switch (info.size) {
                    .one => try writer.writeByte('*'),
                    .many => {
                        try writer.writeAll("[*");
                        if (info.sentinel != .none) {
                            try writer.writeByte(':');
                            if (info.sentinel != .unknown_unknown) {
                                try writer.print("{f}", .{info.sentinel.fmt(analyser.ip)});
                            } else {
                                try writer.writeByte('?');
                            }
                        }
                        try writer.writeByte(']');
                    },
                    .slice => {
                        try writer.writeAll("[");
                        if (info.sentinel != .none) {
                            try writer.writeByte(':');
                            if (info.sentinel != .unknown_unknown) {
                                try writer.print("{f}", .{info.sentinel.fmt(analyser.ip)});
                            } else {
                                try writer.writeByte('?');
                            }
                        }
                        try writer.writeByte(']');
                    },
                    .c => try writer.writeAll("[*c]"),
                }
                if (info.is_const) try writer.writeAll("const ");
                try info.elem_ty.rawStringify(writer, analyser, options);
            },
            .array => |info| {
                try writer.writeByte('[');
                if (info.elem_count) |count| {
                    try writer.print("{d}", .{count});
                } else {
                    try writer.writeAll("?");
                }
                if (info.sentinel != .none) {
                    try writer.writeByte(':');
                    if (info.sentinel != .unknown_unknown) {
                        try writer.print("{f}", .{info.sentinel.fmt(analyser.ip)});
                    } else {
                        try writer.writeByte('?');
                    }
                }
                try writer.writeByte(']');
                try info.elem_ty.rawStringify(writer, analyser, options);
            },
            .tuple => |elem_ty_slice| {
                try writer.writeAll("struct { ");
                for (elem_ty_slice, 0..) |elem_ty, i| {
                    if (i != 0) {
                        try writer.writeAll(", ");
                    }
                    try elem_ty.rawStringify(writer, analyser, options);
                }
                try writer.writeAll(" }");
            },
            .optional => |child_ty| {
                try writer.writeByte('?');
                try child_ty.rawStringify(writer, analyser, options);
            },
            .error_union => |info| {
                if (info.error_set) |error_set| {
                    try error_set.rawStringify(writer, analyser, options);
                }
                try writer.writeByte('!');
                try info.payload.rawStringify(writer, analyser, options);
            },
            .union_tag => |t| {
                try writer.writeAll("@typeInfo(");
                try t.rawStringify(writer, analyser, options);
                try writer.writeAll(").@\"union\".tag_type.?");
            },
            .container => |info| {
                const scope_handle = info.scope_handle;
                const handle = scope_handle.handle;
                const tree = &handle.tree;

                const node = scope_handle.toNode();

                switch (node.tag(tree)) {
                    .root => {
                        const path = handle.uri.toFsPath(analyser.arena) catch |err| switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            error.UnsupportedScheme => handle.uri.raw,
                        };
                        const str = std.Io.Dir.path.stem(path);
                        try writer.writeAll(str);
                        if (referenced) |r| try r.put(analyser.arena, .of(str, handle, node.firstToken(tree)), {});
                    },

                    .type_container => {
                        // This is a hacky nightmare but it works :P
                        const token = node.firstToken(tree);
                        // `Foo = struct`
                        if (@backingInt(token) >= 2 and token.add(-2).tag(tree) == .name and token.add(-1).tag(tree) == .@"=") {
                            var str_token = token.add(-2);
                            // `Foo: type = struct`
                            if (@backingInt(token) >= 4 and token.add(-4).tag(tree) == .name and token.add(-3).tag(tree) == .@":") {
                                str_token = token.add(-4);
                            }
                            const str = str_token.slice(tree);
                            try writer.writeAll(str);
                            if (referenced) |r| try r.put(analyser.arena, .of(str, handle, str_token), {});
                            return;
                        }
                        if (@backingInt(token) >= 1 and token.add(-1).tag(tree) == .@"return") blk: {
                            const doc_scope = try handle.getDocumentScope();
                            const function_scope = innermostScopeAtIndexWithTag(doc_scope, token.add(-1).byteOffset(tree), .initOne(.function)).unwrap() orelse break :blk;
                            const function_node = doc_scope.getScopeAstNode(function_scope).?;
                            const fn_proto: Ast.Expr.Fn = switch (function_node.tag(tree)) {
                                .type_fn => function_node.cast(.type_fn, tree).?,
                                .decl_fn => function_node.cast(.decl_fn, tree).?.proto.get(tree),
                                else => unreachable,
                            };
                            const func_name_token = fn_proto.name(tree) orelse break :blk;
                            const func_name = offsets.tokenToSlice(tree, func_name_token);
                            try writer.writeAll(func_name);
                            if (referenced) |r| try r.put(analyser.arena, .of(func_name, handle, func_name_token), {});
                            var first = true;
                            try writer.writeByte('(');
                            var it = fn_proto.params.get(tree).items.iter(tree);
                            while (it.next(tree)) |param_idx| {
                                const param = param_idx.get(tree);
                                switch (param.type.get(tree)) {
                                    .expr => {},
                                    .@"anytype", .varargs => continue,
                                }
                                const param_name_node = param.name orelse continue;
                                const param_name_token = param_name_node.token(tree);
                                if (!first) {
                                    try writer.writeByte(',');
                                }
                                const param_ty = try analyser.resolveGenericType(.{
                                    .data = .{ .type_parameter = .{ .token = param_name_token, .handle = handle } },
                                    .is_type_val = true,
                                }, info.bound_params);

                                try param_ty.rawStringify(writer, analyser, .{
                                    .referenced = referenced,
                                    .truncate_container_decls = options.truncate_container_decls,
                                });
                                first = false;
                            }
                            try writer.writeByte(')');
                            return;
                        }

                        if (!options.truncate_container_decls) {
                            try writer.writeAll(offsets.nodeToSlice(tree, node));
                            return;
                        }

                        const container: Ast.Expr.Container = node.cast(.type_container, tree).?;

                        const start_token = node.firstToken(tree);
                        const end_token: Ast.Token.Index = switch (container.kind.get(tree)) {
                            .@"enum" => |enum_idx| switch (enum_idx.get(tree)) {
                                .@"enum" => |v| v.token(tree),
                                .with_backing => @panic("BRANCH_TODO"),
                            },
                            .@"union" => |union_idx| switch (union_idx.get(tree)) {
                                .@"union" => |v| v.token(tree),
                                .with_backing => @panic("BRANCH_TODO"),
                            },
                            .@"struct" => |struct_idx| switch (struct_idx.get(tree)) {
                                .@"struct" => |v| v.token(tree),
                                .with_backing => @panic("BRANCH_TODO"),
                            },
                            .@"opaque" => |opaque_idx| opaque_idx.token(tree),
                        };

                        var it = container.members.iter(tree);
                        const has_members = it.next(tree) != null;

                        try writer.writeAll(offsets.tokensToSlice(tree, start_token, end_token));
                        if (has_members) {
                            try writer.writeAll(" {}");
                        } else {
                            try writer.writeAll(" {...}");
                        }
                    },

                    else => unreachable,
                }
            },
            .function => |info| {
                try analyser.rawStringifyFunction(writer, .{
                    .referenced = referenced,
                    .info = info,
                    .include_fn_keyword = true,
                    .include_name = false,
                    .skip_first_param = false,
                    .parameters = .{ .show = .{
                        .include_modifiers = true,
                        .include_names = false,
                        .include_types = true,
                    } },
                    .include_return_type = true,
                    .snippet_placeholders = false,
                });
            },
            .ip_index => |payload| {
                const ip_index = payload.index orelse try analyser.ip.getUnknown(payload.type);
                try analyser.ip.print(ip_index, writer, .{
                    .truncate_container = options.truncate_container_decls,
                });
            },
            .either => try writer.writeAll("either type"), // TODO
            .compile_error => |node_handle| {
                if (options.truncate_container_decls) {
                    try writer.writeAll("@compileError(...)");
                } else {
                    try writer.writeAll(offsets.nodeToSlice(&node_handle.handle.tree, node_handle.node));
                }
            },
            .type_parameter => |token_handle| {
                const token = token_handle.token;
                const handle = token_handle.handle;
                const str = token.slice(&handle.tree);
                try writer.writeAll(str);
                if (referenced) |r| try r.put(analyser.arena, .of(str, handle, token), {});
            },
            .anytype_parameter => |info| {
                const token = info.token_handle.token;
                const handle = info.token_handle.handle;
                const str = token.slice(&handle.tree);
                std.debug.assert(std.mem.eql(u8, str, "anytype"));
                try writer.writeAll("anytype");
            },
        }
    }
};

pub const ScopeWithHandle = struct {
    handle: *DocumentStore.Handle,
    scope: Scope.Index,

    pub fn toNode(scope_handle: ScopeWithHandle) Ast.Node.Index {
        if (scope_handle.scope == Scope.Index.root) return .root;
        var doc_scope = scope_handle.handle.document_scope.getCached();
        return doc_scope.getScopeAstNode(scope_handle.scope).?;
    }

    pub fn hashWithHasher(scope_handle: ScopeWithHandle, hasher: anytype) void {
        hasher.update(scope_handle.handle.uri.raw);
        std.hash.autoHash(hasher, scope_handle.scope);
    }

    pub fn eql(a: ScopeWithHandle, b: ScopeWithHandle) bool {
        if (a.scope != b.scope) return false;
        if (!a.handle.uri.eql(b.handle.uri)) return false;
        return true;
    }
};

pub fn resolveImportString(analyser: *Analyser, handle: *DocumentStore.Handle, import_string: []const u8) Error!?Type {
    const result = try analyser.store.uriFromImportStr(analyser.arena, handle, import_string);
    switch (result) {
        .none => return null,
        .one => |uri| {
            const node_handle = try analyser.store.getOrLoadHandle(uri) orelse return null;
            return .{
                .data = .{ .container = .root(node_handle) },
                .is_type_val = true,
            };
        },
        .many => |uris| {
            var entries: std.ArrayList(Type.Data.EitherEntry) = try .initCapacity(analyser.arena, uris.len);
            for (uris) |uri| {
                const node_handle = try analyser.store.getOrLoadHandle(uri) orelse continue;
                entries.appendAssumeCapacity(.{
                    .type_data = .{ .container = .root(node_handle) },
                    .descriptor = "",
                });
            }
            return .{
                .data = .{ .either = entries.items },
                .is_type_val = true,
            };
        },
    }
}

fn resolveLangrefType(analyser: *Analyser, type_str: []const u8) Error!?Type {
    if (try analyser.resolvePrimitive(type_str)) |primitive|
        return Type.fromIP(analyser, primitive, null);

    // e.g. `?type`
    if (std.mem.startsWith(u8, type_str, "?")) {
        const elem_str = type_str[1..];
        const elem_instance = try analyser.resolveLangrefType(elem_str) orelse return null;
        const elem_ty = try elem_instance.typeOf(analyser);
        const optional_ty = try Type.createOptionalType(analyser, elem_ty);
        return try optional_ty.instanceUnchecked(analyser);
    }

    // e.g. `*const anyopaque`
    if (std.mem.startsWith(u8, type_str, "*")) {
        var elem_str = type_str[1..];
        const is_const = std.mem.startsWith(u8, elem_str, "const ");
        if (is_const)
            elem_str = elem_str[6..];
        const elem_instance = try analyser.resolveLangrefType(elem_str) orelse return null;
        const elem_ty = try elem_instance.typeOf(analyser);
        const pointer_ty = try Type.createPointerType(analyser, .one, .none, is_const, elem_ty);
        return try pointer_ty.instanceUnchecked(analyser);
    }

    // e.g. `[]const u8`
    if (std.mem.startsWith(u8, type_str, "[")) {
        const bracket_idx = std.mem.findScalar(u8, type_str, ']') orelse return null;

        var is_slice = bracket_idx == 1;
        var sentinel: InternPool.Index = .none;

        // e.g. `[:0]const u8`
        if (std.mem.findScalarLast(u8, type_str[0..bracket_idx], ':')) |colon_idx| {
            is_slice = colon_idx == 1;
            const sentinel_str = type_str[colon_idx + 1 .. bracket_idx];
            if (std.mem.eql(u8, sentinel_str, "0"))
                sentinel = .zero_comptime_int
            else
                sentinel = .unknown_unknown;
        }

        // e.g. `[N:0]u8`
        if (!is_slice) {
            const elem_str = type_str[bracket_idx + 1 ..];
            const elem_instance = try analyser.resolveLangrefType(elem_str) orelse return null;
            const elem_ty = try elem_instance.typeOf(analyser);
            const array_ty = try Type.createArrayType(analyser, null, sentinel, elem_ty);
            return try array_ty.instanceUnchecked(analyser);
        }

        var elem_str = type_str[bracket_idx + 1 ..];
        const is_const = std.mem.startsWith(u8, elem_str, "const ");
        if (is_const)
            elem_str = elem_str[6..];
        const elem_instance = try analyser.resolveLangrefType(elem_str) orelse return null;
        const elem_ty = try elem_instance.typeOf(analyser);
        const slice_ty = try Type.createPointerType(analyser, .slice, sentinel, is_const, elem_ty);
        return try slice_ty.instanceUnchecked(analyser);
    }

    return analyser.instanceStdBuiltinType(type_str);
}

/// Look up `type_name` in 'zig_lib_dir/std/lang.zig' and return it as an instance
/// Useful for functionality related to builtin fns
pub fn instanceStdBuiltinType(analyser: *Analyser, type_name: []const u8) Error!?Type {
    const zig_lib_dir = analyser.store.config.zig_lib_dir orelse return null;
    const builtin_path = try zig_lib_dir.join(analyser.arena, &.{ "std", "lang.zig" });
    const builtin_uri: Uri = try .fromPath(analyser.arena, builtin_path);

    const builtin_handle = try analyser.store.getOrLoadHandle(builtin_uri) orelse return null;
    const builtin_root_struct_type: Type = .{
        .data = .{ .container = .root(builtin_handle) },
        .is_type_val = true,
    };

    var result_ty = builtin_root_struct_type;
    var i: usize = 0;
    while (i < type_name.len) {
        const end = std.mem.findScalarPos(u8, type_name, i, '.') orelse type_name.len;
        const name = type_name[i..end];
        i = 1 + end;
        const decl = try result_ty.lookupSymbol(analyser, name) orelse return null;
        result_ty = try decl.resolveType(analyser) orelse return null;
    }
    return try result_ty.instanceTypeVal(analyser);
}

pub const NodeWithUri = struct {
    node: Ast.Node.Index,
    uri: Uri,

    const Context = struct {
        pub fn hash(self: Context, item: NodeWithUri) u64 {
            _ = self;
            var hasher: std.hash.Wyhash = .init(0);
            std.hash.autoHash(&hasher, item.node);
            hasher.update(item.uri.raw);
            return hasher.final();
        }

        pub fn eql(self: Context, a: NodeWithUri, b: NodeWithUri) bool {
            _ = self;
            if (a.node != b.node) return false;
            return a.uri.eql(b.uri);
        }
    };
};

pub const NodeWithHandle = struct {
    node: Ast.Node.Index,
    handle: *DocumentStore.Handle,

    pub fn of(node: Ast.Node.Index, handle: *DocumentStore.Handle) NodeWithHandle {
        return .{ .node = node, .handle = handle };
    }

    pub fn eql(a: NodeWithHandle, b: NodeWithHandle) bool {
        if (a.node != b.node) return false;
        return a.handle.uri.eql(b.handle.uri);
    }
};

pub fn getFieldAccessType(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) Error!?Type {
    const held_range = try analyser.arena.dupeSentinel(u8, offsets.locToSlice(handle.tree.source, loc), 0);
    var tokenizer: std.zig.Tokenizer = .init(held_range);
    var current_type: ?Type = null;

    var do_unwrap_error_payload = false; // .@"try" seen, ie `(try foo())`

    while (true) {
        const tok = tokenizer.next();
        switch (tok.tag) {
            .eof => return current_type,
            .identifier => {
                const symbol_name = offsets.identifierIndexToSlice(tokenizer.buffer, tok.loc.start, .name);
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

                        const symbol = offsets.identifierIndexToSlice(tokenizer.buffer, after_period.loc.start, .name);

                        current_type = try analyser.resolveFieldAccess(current_type orelse return null, symbol) orelse return null;
                    },
                    .question_mark => {
                        if (after_period.loc.end == tokenizer.buffer.len) {
                            return current_type;
                        }

                        current_type = (try analyser.resolveOptionalUnwrap(current_type orelse return null)) orelse return null;
                    },
                    else => {
                        log.debug("Unrecognized token {} after period.", .{after_period.tag});
                        return null;
                    },
                }
            },
            .period_asterisk => {
                if (tok.loc.end == tokenizer.buffer.len) {
                    return current_type;
                }

                current_type = (try analyser.resolveDerefType(current_type orelse return null)) orelse return null;
            },
            .l_paren => {
                if (current_type == null) {
                    // Likely `(expr)`
                    // Look for the corresponding .@")" to form a slice of the contents
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

                // TODO Actually bind params here when calling functions instead of just skipping args.
                current_type = try analyser.resolveReturnType(ty) orelse return null;

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
                var kind: BracketAccess = .{ .single = null };

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
                                kind = .{ .open = .{ .start = null, .sentinel = .none } };
                            }
                        },
                        else => {
                            if (bracket_count == 1 and kind == .open) {
                                kind = .{ .range = .{ .bounds = null, .sentinel = .none } };
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
                    current_type = try analyser.resolveImportString(handle, import_str) orelse return null;
                    _ = tokenizer.next(); // eat the .@")"
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
            .l_brace => {
                var brace_count: usize = 1;
                var next = tokenizer.next();
                while (next.tag != .eof) : (next = tokenizer.next()) {
                    if (next.tag == .r_brace) {
                        brace_count -= 1;
                        if (brace_count == 0) break;
                    } else if (next.tag == .l_brace) {
                        brace_count += 1;
                    }
                } else return null;
                if (current_type) |ct| {
                    if (ct.isStructType(analyser) or ct.isUnionType()) {
                        // struct initialization
                        current_type = try ct.instanceTypeVal(analyser);
                    }
                }
            },
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
    import_string_literal: offsets.Loc,
    embedfile_string_literal: offsets.Loc,
    string_literal: offsets.Loc,
    field_access: offsets.Loc,
    var_access: offsets.Loc,
    /// `break :blk`
    /// `continue :blk`
    label_access: offsets.Loc,
    /// - `blk: {`
    /// - `blk: for`
    /// - `blk: while`
    /// - `blk: switch`
    label_decl: offsets.Loc,
    test_doctest_name: offsets.Loc,
    enum_literal: offsets.Loc,
    number_literal: offsets.Loc,
    char_literal: offsets.Loc,
    /// XXX: Internal use only, currently points to the loc of the first l_paren
    parens_expr: offsets.Loc,
    keyword: Ast.Token.Index,
    error_access: offsets.Loc,
    comment,
    other,
    empty,

    pub fn loc(self: PositionContext, tree: *const Ast) ?offsets.Loc {
        return switch (self) {
            .builtin,
            .import_string_literal,
            .embedfile_string_literal,
            .string_literal,
            .field_access,
            .var_access,
            .label_access,
            .label_decl,
            .test_doctest_name,
            .enum_literal,
            .number_literal,
            .char_literal,
            .parens_expr,
            => |l| return l,
            .keyword => |token_index| return offsets.tokenToLoc(tree, token_index),
            .error_access,
            .comment,
            .other,
            .empty,
            => return null,
        };
    }

    /// Asserts that `self` is one of the following:
    ///  - `.import_string_literal`
    ///  - `.embedfile_string_literal`
    ///  - `.string_literal`
    pub fn stringLiteralContentLoc(self: PositionContext, source: []const u8) offsets.Loc {
        var location = switch (self) {
            .import_string_literal,
            .embedfile_string_literal,
            .string_literal,
            => |l| l,
            else => unreachable,
        };

        const string_literal_slice = offsets.locToSlice(source, location);
        if (std.mem.startsWith(u8, string_literal_slice, "\"")) {
            location.start += 1;
            if (std.mem.endsWith(u8, string_literal_slice[1..], "\"")) {
                location.end -= 1;
            }
            location.end = std.mem.findAnyPos(u8, source, location.start, &.{ '\n', '"' }) orelse source.len;
        } else if (std.mem.startsWith(u8, string_literal_slice, "\\")) {
            location.start += 2;
            location.end = std.mem.findScalarPos(u8, source, location.start, '\n') orelse source.len;
        } else {
            location.end = location.start;
        }
        return location;
    }
};

const Stack = struct {
    states: std.ArrayList(State),

    const State = struct {
        ctx: PositionContext,
        scope: State.Scope,

        const Scope = enum { parens, brackets, braces, global };

        /// Indicates whether the current context is an ErrorSet definition, ie `error{...}`
        pub fn isErrSetDef(self: *Stack.State) bool {
            return (self.scope == .braces and self.ctx == .error_access);
        }
    };

    pub fn initCapacity(allocator: std.mem.Allocator, capacity: usize) error{OutOfMemory}!Stack {
        std.debug.assert(capacity > 0); // See `peek`.
        return .{ .states = try .initCapacity(allocator, capacity) };
    }

    pub fn deinit(self: *Stack, allocator: std.mem.Allocator) void {
        self.states.deinit(allocator);
    }

    pub fn push(self: *Stack, allocator: std.mem.Allocator, state: *const State) error{OutOfMemory}!void {
        try self.states.append(allocator, state.*);
    }

    pub fn peek(self: *Stack) *Stack.State {
        if (self.states.items.len == 0) {
            self.states.appendAssumeCapacity(.{ .ctx = .empty, .scope = .global });
        }
        return &self.states.items[self.states.items.len - 1];
    }

    /// Pops the last state off the stack. Sets previous state's ctx to .empty if !scopes_match
    pub fn pop(
        self: *Stack,
        /// Indicate whether the current state's scope matches the one being closed
        scopes_match: bool,
    ) void {
        if (self.states.items.len != 0) self.states.items.len -= 1;
        if (!scopes_match) self.peek().ctx = .empty;
    }
};

fn tokenLocAppend(prev: offsets.Loc, token_loc: offsets.Loc) offsets.Loc {
    return .{
        .start = prev.start,
        .end = token_loc.end,
    };
}

/// Given a byte index in a document (typically cursor offset), classify what kind of entity is at that index.
///
/// Classification is based on the lexical structure -- we fetch the line containing index, and look at the
/// sequence of tokens just before the cursor. Due to the nice way zig is designed (only line comments, etc)
/// lexing just a single line is always correct.
pub fn getPositionContext(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    source_index: usize,
    /// Should we look beyond the `source_index`? `false` for completions, `true` otherwise (hover, goto, etc.)
    lookahead: bool,
) error{OutOfMemory}!PositionContext {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var line_loc = if (lookahead) offsets.lineLocAtIndex(tree.source, source_index) else offsets.lineLocUntilIndex(tree.source, source_index);

    if (std.mem.startsWith(u8, std.mem.trimStart(u8, offsets.locToSlice(tree.source, line_loc), " \t"), "//")) return .comment;

    // Check if the (trimmed) line starts with a '.', ie a continuation
    while (line_loc.start > 0) {
        while (std.mem.startsWith(u8, std.mem.trimStart(u8, offsets.locToSlice(tree.source, line_loc), " \t\r"), ".")) {
            if (line_loc.start > 1) {
                line_loc.start -= 2; // jump over a (potential) preceding '\n'
            } else break;
            while (line_loc.start > 0) : (line_loc.start -= 1) {
                if (tree.source[line_loc.start] == '\n') {
                    line_loc.start += 1; // eat the `\n`
                    break;
                }
            } else break;
        }
        if (line_loc.start != 0 and std.mem.startsWith(u8, std.mem.trimStart(u8, offsets.locToSlice(tree.source, line_loc), " \t"), "//")) {
            const prev_line_loc = offsets.lineLocAtIndex(tree.source, line_loc.start - 1); // `- 1` => prev line's `\n`
            line_loc.start = prev_line_loc.start;
            continue;
        }
        break;
    }

    // Check if the previous line ends with a ',', ie a continuation - targets multiline ErrorSet definitions
    var lloc = line_loc;
    while (true) {
        while (lloc.start > 0) {
            if (tree.source[lloc.start] != '\n') lloc.start -= 1 else break;
        } else break;
        while (lloc.start > 0 and tree.source[lloc.start] == '\n') lloc.start -= 1;
        if (lloc.start == 0) break;
        lloc = offsets.lineLocAtIndex(tree.source, lloc.start);
        // Check if it's a comment first
        while (lloc.start > 0 and std.mem.startsWith(u8, std.mem.trimStart(u8, offsets.locToSlice(tree.source, lloc), " \t"), "//")) {
            const prev_line_loc = offsets.lineLocAtIndex(tree.source, lloc.start - 1); // `- 1` => prev line's `\n`
            lloc = prev_line_loc;
        }
        if (std.mem.endsWith(u8, std.mem.trimEnd(u8, offsets.locToSlice(tree.source, lloc), " \t\r\n"), ",")) continue;
        line_loc.start = lloc.start;
        break;
    }

    var stack: Stack = try .initCapacity(allocator, 8);
    defer stack.deinit(allocator);
    var should_do_lookahead = lookahead;

    var current_token = offsets.sourceIndexToTokenIndex(tree, line_loc.start).preferLeft();
    var previous_token_end = line_loc.start;

    while (true) : (current_token = current_token.add(1)) {
        var token_tag = current_token.tag(tree);
        var token_loc = offsets.tokenToLoc(tree, current_token);

        token_loc.end = @min(token_loc.end, line_loc.end);
        defer previous_token_end = token_loc.end;

        // Single '@' do not return a builtin token so we check this on our own.
        if (token_tag == .invalid and tree.source[token_loc.start] == '@') {
            if (std.mem.startsWith(u8, tree.source[token_loc.start..], "@\"")) {
                token_tag = .name;
                token_loc = .{ .start = token_loc.start, .end = @min(line_loc.end, current_token.add(1).byteOffset(tree)) };
            } else if (std.mem.startsWith(u8, tree.source[token_loc.start..], "@")) {
                token_tag = .name_builtin;
                token_loc = .{ .start = token_loc.start, .end = token_loc.start + 1 };
            }
        }

        if (source_index < token_loc.start) break;
        if (source_index == token_loc.start) {
            // Tie-breaking, the cursor is exactly between two tokens, and
            // `tok` is the latter of the two.
            if (!should_do_lookahead) break;
            should_do_lookahead = false;
            const curr_ctx = stack.peek();
            switch (token_tag) {
                .name,
                .name_builtin,
                .number,
                .string,
                .multiline_string_line,
                => {},
                .@"." => switch (curr_ctx.ctx) {
                    .empty => {},
                    else => if (previous_token_end == token_loc.start) break,
                },
                else => if (previous_token_end == token_loc.start) break,
            }
        }

        switch (token_tag) {
            .invalid => {
                const s = tree.source[token_loc.start..token_loc.end];
                const q = std.mem.find(u8, s, "\"") orelse return .other;
                if (s[q -| 1] == '@') {
                    token_tag = .name;
                } else {
                    token_tag = .string;
                }
            },
            .eof => break,
            else => {},
        }

        const curr_ctx: *Stack.State = stack.peek();
        defer switch (stack.peek().ctx) {
            .field_access => |*loc| loc.* = tokenLocAppend(loc.*, token_loc),
            else => {},
        };
        const new_state: PositionContext = switch (token_tag) {
            .multiline_string_line => .{ .string_literal = token_loc },
            .string => new_state: {
                const string_literal_slice = offsets.locToSlice(tree.source, token_loc);
                var content_loc = token_loc;

                if (std.mem.startsWith(u8, string_literal_slice, "\"")) {
                    content_loc.start += 1;
                    if (std.mem.endsWith(u8, string_literal_slice[1..], "\"")) {
                        content_loc.end -= 1;
                    }
                }

                var new_state: PositionContext = .{ .string_literal = token_loc };
                if (source_index < content_loc.start or content_loc.end < source_index) break :new_state new_state;

                if (curr_ctx.scope == .parens and
                    stack.states.items.len >= 2)
                {
                    const perhaps_builtin = stack.states.items[stack.states.items.len - 2];

                    switch (perhaps_builtin.ctx) {
                        .builtin => |loc| {
                            const builtin_name = tree.source[loc.start..loc.end];
                            if (std.mem.eql(u8, builtin_name, "@import")) {
                                new_state = .{ .import_string_literal = token_loc };
                            } else if (std.mem.eql(u8, builtin_name, "@embedFile")) {
                                new_state = .{ .embedfile_string_literal = token_loc };
                            }
                        },
                        else => {},
                    }
                }
                break :new_state new_state;
            },
            .name => if (curr_ctx.isErrSetDef())
                continue // Intent is to skip everything between the `error{...}` braces
            else switch (curr_ctx.ctx) {
                .enum_literal => |loc| .{ .enum_literal = tokenLocAppend(loc, token_loc) },
                .field_access => |loc| .{ .field_access = tokenLocAppend(loc, token_loc) },
                .label_access => |loc| if (loc.start == loc.end)
                    .{ .label_access = token_loc }
                else
                    .{ .var_access = token_loc },
                .test_doctest_name => .{ .test_doctest_name = token_loc },
                else => .{ .var_access = token_loc },
            },
            .name_builtin => .{ .builtin = token_loc },
            .@"." => switch (curr_ctx.ctx) {
                .empty, .label_access => .{ .enum_literal = token_loc },
                .enum_literal => .empty,
                .keyword => |token_index| switch (token_index.tag(tree)) {
                    .@"break" => .{ .enum_literal = token_loc },
                    else => .other,
                },
                .comment, .other, .error_access => curr_ctx.ctx,
                .test_doctest_name, .var_access, .field_access => |loc| .{ .field_access = tokenLocAppend(loc, token_loc) },
                else => .{ .field_access = tokenLocAppend(curr_ctx.ctx.loc(tree) orelse token_loc, token_loc) },
            },
            .@".*" => .{ .field_access = tokenLocAppend(curr_ctx.ctx.loc(tree) orelse token_loc, token_loc) },
            .@"?" => switch (curr_ctx.ctx) {
                .field_access => |loc| .{ .field_access = tokenLocAppend(loc, token_loc) },
                else => .empty,
            },
            .@":" => switch (curr_ctx.ctx) {
                .keyword => |token_index| switch (token_index.tag(tree)) {
                    .@"break",
                    .@"continue",
                    => .{ .label_access = .{ .start = token_loc.end, .end = token_loc.end } },
                    else => .empty,
                },
                else => .empty,
            },
            .@"(" => {
                if (curr_ctx.ctx == .empty) curr_ctx.ctx = .{ .parens_expr = token_loc };
                const scope: Stack.State.Scope = if (curr_ctx.ctx == .keyword) switch (curr_ctx.ctx.keyword.tag(tree)) {
                    .@"for",
                    .@"if",
                    .@"while",
                    => .global,
                    else => .parens,
                } else .parens;
                try stack.push(allocator, &.{ .ctx = .empty, .scope = scope });
                continue;
            },
            .@")" => {
                stack.pop(curr_ctx.scope == .parens);
                continue;
            },
            .@"[" => {
                try stack.push(allocator, &.{ .ctx = .empty, .scope = .brackets });
                continue;
            },
            .@"]" => {
                stack.pop(curr_ctx.scope == .brackets);
                continue;
            },
            .@"{" => {
                try stack.push(allocator, &.{ .ctx = if (curr_ctx.ctx == .error_access) curr_ctx.ctx else .empty, .scope = .braces });
                continue;
            },
            .@"}" => {
                stack.pop(curr_ctx.scope == .braces);
                continue;
            },
            .@"error" => .{ .error_access = token_loc },
            .number => {
                if (token_loc.start <= source_index and token_loc.end >= source_index) {
                    return .{ .number_literal = token_loc };
                }
                continue;
            },
            .char => {
                if (token_loc.start <= source_index and token_loc.end >= source_index) {
                    return .{ .char_literal = token_loc };
                }
                continue;
            },
            .@"addrspace",
            .@"break",
            .@"callconv",
            .@"continue",
            .@"for",
            .@"if",
            .@"switch",
            .@"while",
            => |tag| new_state: {
                std.debug.assert(current_token.tag(tree) == tag);
                break :new_state .{ .keyword = current_token };
            },
            .@"test" => .{ .test_doctest_name = .{ .start = token_loc.end, .end = token_loc.end } },
            .container_doc_comment => .comment,
            .doc_comment => new_state: {
                if (!curr_ctx.isErrSetDef()) break :new_state .comment; // Intent is to skip everything between the `error{...}` braces
                continue;
            },
            .@"," => new_state: {
                if (!curr_ctx.isErrSetDef()) break :new_state .empty; // Intent is to skip everything between the `error{...}` braces
                continue;
            },
            else => .empty,
        };
        curr_ctx.ctx = new_state;
    }

    if (stack.states.pop()) |state| {
        switch (state.ctx) {
            .parens_expr => |loc| return .{ .var_access = loc },
            .var_access => |loc| {
                if (current_token.tag(tree) == .@":") {
                    switch (current_token.add(1).tag(tree)) {
                        .@"{",
                        .@"for",
                        .@"while",
                        .@"switch",
                        => return .{ .label_decl = loc },
                        else => {},
                    }
                }
                return state.ctx;
            },
            else => return state.ctx,
        }
    }

    return .empty;
}

pub const TokenToTypeMap = std.array_hash_map.Custom(TokenWithHandle, Type, TokenWithHandle.Context, true);

pub const TokenWithHandle = struct {
    token: Ast.Token.Index,
    handle: *DocumentStore.Handle,

    pub fn hashWithHasher(token_handle: TokenWithHandle, hasher: anytype) void {
        std.hash.autoHash(hasher, token_handle.token);
        hasher.update(token_handle.handle.uri.raw);
    }

    pub fn eql(a: TokenWithHandle, b: TokenWithHandle) bool {
        if (a.token != b.token) return false;
        if (!a.handle.uri.eql(b.handle.uri)) return false;
        return true;
    }

    const Context = struct {
        pub fn hash(self: Context, token_handle: TokenWithHandle) u32 {
            _ = self;
            var hasher: std.hash.Wyhash = .init(0);
            token_handle.hashWithHasher(&hasher);
            return @truncate(hasher.final());
        }

        pub fn eql(self: Context, a: TokenWithHandle, b: TokenWithHandle, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return a.eql(b);
        }
    };
};

pub const DeclWithHandle = struct {
    decl: Declaration,
    handle: *DocumentStore.Handle,
    container_type: ?Type = null,

    pub fn eql(a: DeclWithHandle, b: DeclWithHandle) bool {
        return a.decl.eql(b.decl) and a.handle.uri.eql(b.handle.uri);
    }

    /// Returns a `.identifier` or `.builtin` token.
    pub fn nameToken(self: DeclWithHandle) Ast.Token.Index {
        return self.decl.nameToken(&self.handle.tree);
    }

    pub fn definitionToken(self: DeclWithHandle, analyser: *Analyser) Error!TokenWithHandle {
        var decl = try analyser.resolveVarDeclAlias(self) orelse self;
        if (try decl.resolveType(analyser)) |resolved_type| {
            if (resolved_type.is_type_val) {
                if (resolved_type.typeDefinitionToken()) |token| {
                    return token;
                }
            }
        }
        return .{ .token = decl.nameToken(), .handle = decl.handle };
    }

    pub fn typeDeclarationNode(self: DeclWithHandle) error{OutOfMemory}!?NodeWithHandle {
        const tree = &self.handle.tree;
        switch (self.decl) {
            .ast_node => |node| switch (node.get(tree)) {
                inline .var_local, .var_global => |var_idx| {
                    const var_decl = var_idx.get(tree);
                    const type_node = var_decl.type orelse return null;
                    return .of(type_node.idx, self.handle);
                },
                .field => |field_member| {
                    const field_decl = field_member.get(tree);
                    return .of(field_decl.type.idx, self.handle);
                },
                .type_fn, .decl_fn => return null,
            },
            .assign_destructure => |payload| {
                const var_decl = payload.getVarProto(tree).get(tree);
                const type_expr = var_decl.type orelse return null;
                return .of(type_expr.idx, self.handle);
            },
            .function_parameter => |payload| {
                const param_decl = payload.node.get(tree);
                const type_expr = switch (param_decl.type.get(tree)) {
                    .expr => |expr| expr,
                    .@"anytype", .varargs => return null,
                };
                return .of(type_expr.idx, self.handle);
            },
            .optional_payload,
            .error_union_payload,
            .error_union_error,
            .for_loop_payload,
            .switch_payload,
            .switch_inline_tag_payload,
            => return null, // the payloads can't have a type specifier

            .label,
            .error_token,
            => return null,
        }
    }

    pub fn isConst(self: DeclWithHandle) bool {
        const tree = &self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| switch (node.get(tree)) {
                inline .var_local, .var_global => |var_idx| {
                    const var_decl = var_idx.get(tree);
                    return switch (var_decl.mutability.get(tree)) {
                        .@"const" => true,
                        .@"var" => false,
                    };
                },
                .field, .type_fn, .decl_fn => true,
            },
            .assign_destructure => |payload| {
                const var_decl = payload.getVarProto(tree).get(tree);
                return switch (var_decl.mutability.get(tree)) {
                    .@"const" => true,
                    .@"var" => false,
                };
            },
            // some payload may be capture by ref but the pointer value is constant
            .function_parameter,
            .optional_payload,
            .for_loop_payload,
            .error_union_payload,
            .error_union_error,
            .switch_payload,
            .switch_inline_tag_payload,
            .label,
            .error_token,
            => true,
        };
    }

    pub fn isCaptureByRef(self: DeclWithHandle) bool {
        const tree = &self.handle.tree;
        return switch (self.decl) {
            .ast_node,
            .function_parameter,
            .error_union_error,
            .assign_destructure,
            .label,
            .error_token,
            .switch_inline_tag_payload,
            => false,
            inline .optional_payload,
            .for_loop_payload,
            .error_union_payload,
            => |payload| payload.identifier.add(-1).tag(tree) == .@"*",
            .switch_payload => |payload| {
                const switch_payload = payload.prong.get(tree).payload.?.get(tree);
                var switch_bindings = switch_payload.bindings.iter(tree);
                const switch_binding = switch_bindings.next(tree).?.get(tree);
                return switch (switch_binding) {
                    .normal => false,
                    .pointer => true,
                };
            },
        };
    }

    pub fn docComments(self: DeclWithHandle, allocator: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
        const tree = &self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| try getDocComments(allocator, tree, node.idx),
            .function_parameter => |pay| {
                if (true) @panic("BRANCH_TODO");
                const param = pay.node.get(tree);
                var doc_comment_it = param.docComment(tree) orelse return null;
                return try collectDocComments(allocator, tree, &doc_comment_it, false);
            },
            .error_token => |token| try getDocCommentsBeforeToken(allocator, tree, token),
            else => null,
        };
    }

    pub fn isPublic(self: DeclWithHandle) bool {
        const tree = &self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| switch (node.get(tree)) {
                .var_local => false,
                .var_global => |var_decl| var_decl.get(tree).attributes(tree).@"pub" != null,
                .type_fn => |fn_proto| fn_proto.get(tree).attributes(tree).@"pub" != null,
                .decl_fn => |fn_decl| fn_decl.get(tree).attributes(tree).@"pub" != null,
                .field => true,
            },
            else => true,
        };
    }

    pub fn isStatic(self: DeclWithHandle) error{OutOfMemory}!bool {
        const tree = &self.handle.tree;
        return switch (self.decl) {
            .ast_node => |node| switch (node.get(tree)) {
                inline .var_local, .var_global => |var_idx| blk: {
                    const var_decl = var_idx.get(tree);
                    const document_scope = try self.handle.getDocumentScope();
                    const source_index = var_decl.name(tree).?.byteOffset(tree);
                    const scope_index = Analyser.innermostScopeAtIndex(document_scope, source_index);
                    break :blk document_scope.getScopeTag(scope_index).isContainer();
                },
                .field, .type_fn, .decl_fn => false,
            },
            else => false,
        };
    }

    pub fn resolveType(self: DeclWithHandle, analyser: *Analyser) Error!?Type {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const tree = &self.handle.tree;
        var resolved_ty = switch (self.decl) {
            .ast_node => |node| try analyser.resolveTypeOfNodeInternal(.{
                .node_handle = .of(node.idx, self.handle),
                .container_type = self.container_type,
            }),
            .function_parameter => |pay| blk: {
                const param = pay.node.get(tree);

                const type_expr = switch (param.type.get(tree)) {
                    .expr => |expr| expr.idx,
                    .@"anytype" => |anytype_idx| {
                        const ty = try analyser.resolveCallsiteReferences(self);
                        break :blk Type{
                            .data = .{
                                .anytype_parameter = .{
                                    .token_handle = .{ .token = anytype_idx.token(tree), .handle = self.handle },
                                    .type_from_callsite_references = if (ty) |t| try analyser.allocType(t) else null,
                                },
                            },
                            .is_type_val = false,
                        };
                    },
                    .varargs => return null,
                };

                const param_type = try analyser.resolveTypeOfNodeInternal(.of(type_expr, self.handle)) orelse return null;

                if (param_type.isMetaType()) {
                    const name_token = self.decl.nameToken(tree);
                    break :blk Type{
                        .data = .{ .type_parameter = .{ .token = name_token, .handle = self.handle } },
                        .is_type_val = true,
                    };
                }

                break :blk try param_type.instanceTypeVal(analyser);
            },
            .optional_payload => |pay| blk: {
                const ty = (try analyser.resolveTypeOfNodeInternal(.of(pay.condition.idx, self.handle))) orelse return null;
                break :blk try analyser.resolveOptionalUnwrap(ty);
            },
            .error_union_payload => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.of(pay.condition.idx, self.handle))) orelse return null,
                .payload,
            ),
            .error_union_error => |pay| try analyser.resolveUnwrapErrorUnionType(
                (try analyser.resolveTypeOfNodeInternal(.of(
                    pay.condition.unwrap() orelse return null,
                    self.handle,
                ))) orelse return null,
                .error_set,
            ),
            .for_loop_payload => |pay| switch (pay.input.get(tree)) {
                .expr => |expr_node| try analyser.resolveBracketAccessType(
                    (try analyser.resolveTypeOfNodeInternal(.of(expr_node.idx, self.handle))) orelse return null,
                    .{ .single = null },
                ),
                .range => Type.fromIP(analyser, .usize_type, null),
            },
            .assign_destructure => |pay| blk: {
                const var_proto = pay.getVarProto(tree).get(tree);
                if (var_proto.type) |type_node| {
                    if (try analyser.resolveTypeOfNode(.of(type_node.idx, self.handle))) |ty|
                        break :blk try ty.instanceTypeVal(analyser);
                }
                const init_node = pay.node.get(tree).init;

                const node = try analyser.resolveTypeOfNode(.of(init_node.idx, self.handle)) orelse return null;
                if (node.is_type_val) return null;
                break :blk switch (node.data) {
                    .array => |array_info| try array_info.elem_ty.instanceTypeVal(analyser),
                    .tuple => try analyser.resolveBracketAccessType(node, .{ .single = pay.lvalue_index }),
                    .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
                        .vector_type => |vector_info| Type.fromIP(analyser, vector_info.child, null),
                        .array_type => |array_info| Type.fromIP(analyser, array_info.child, null),
                        .tuple_type => try analyser.resolveBracketAccessType(node, .{ .single = pay.lvalue_index }),
                        else => null,
                    },
                    else => null,
                };
            },
            .label => |decl| try analyser.resolveTypeOfNodeInternal(.of(decl.expr.idx, self.handle)),
            .switch_payload,
            .switch_inline_tag_payload,
            => |payload| blk: {
                const switch_expr = payload.node.get(tree);
                const prong = payload.prong.get(tree);

                const switch_expr_type = try analyser.resolveTypeOfNodeInternal(.of(switch_expr.condition.idx, self.handle)) orelse return null;

                if (self.decl == .switch_inline_tag_payload) {
                    return try analyser.resolveUnionTag(try switch_expr_type.typeOf(analyser));
                }

                if (switch_expr_type.isEnumType()) break :blk switch_expr_type;
                if (!switch_expr_type.isUnionType()) return switch_expr_type;

                // TODO Peer type resolution, we just use the first resolvable item for now.
                var case_it = prong.cases.iter(tree);
                var case_count: u32 = 0;
                while (case_it.next(tree)) |case_idx| : (case_count += 1) {
                    const case = case_idx.get(tree);
                    const case_value = switch (case) {
                        .item => |expr| expr,
                        .range, .@"else" => continue,
                    };
                    const leaf_node = case_value.cast(.enum_literal, tree) orelse continue;
                    const name_token = leaf_node.token(tree);
                    const name = offsets.identifierTokenToNameSlice(tree, name_token);
                    const decl = try switch_expr_type.lookupSymbol(analyser, name) orelse continue;
                    break :blk (try decl.resolveType(analyser)) orelse continue;
                } else if (case_count == 0) {
                    const attributes = prong.attributes(tree);
                    if (attributes.@"inline" == null) {
                        return switch_expr_type;
                    }
                    // TODO either type
                    return null;
                }

                return null;
            },
            .error_token => return null,
        } orelse return null;

        if (self.container_type) |container_ty| {
            switch (container_ty.data) {
                .container => |info| {
                    resolved_ty = try analyser.resolveGenericType(resolved_ty, info.bound_params);
                },
                else => {},
            }
        }

        if (!self.isCaptureByRef()) return resolved_ty;

        const elem_ty = try resolved_ty.typeOf(analyser);
        const pointer_ty = try Type.createPointerType(analyser, .one, .none, false, elem_ty);
        return try pointer_ty.instanceUnchecked(analyser);
    }
};

/// Collects all symbols/declarations that can be a accessed on the given container type.
pub fn collectDeclarationsOfContainer(
    analyser: *Analyser,
    /// A container type (i.e. `struct`, `union`, `enum`, `opaque`)
    container_type: Type,
    original_handle: *DocumentStore.Handle,
    /// Whether or not the container type is a instance of its type.
    /// ```zig
    /// const NotInstance = struct{};
    /// const instance = @as(struct{}, ...);
    /// ```
    instance_access: bool,
    /// allocated with `analyser.arena`
    decl_collection: *std.ArrayList(DeclWithHandle),
) Analyser.Error!void {
    const info = switch (container_type.data) {
        .container => |info| info,
        .either => |entries| {
            for (entries) |entry| {
                const ty: Type = .{ .data = entry.type_data, .is_type_val = container_type.is_type_val };
                try analyser.collectDeclarationsOfContainer(ty, original_handle, instance_access, decl_collection);
            }
            return;
        },
        else => return,
    };
    const container_scope = info.scope_handle;
    const scope = container_scope.scope;
    const handle = container_scope.handle;

    const tree = &handle.tree;
    const document_scope = try handle.getDocumentScope();
    const container_node = container_scope.toNode();
    const main_token = container_node.mainToken(tree);

    const is_enum = main_token.tag(tree) == .@"enum";

    const scope_decls = document_scope.getScopeDeclarationsConst(scope);

    for (scope_decls) |decl_index| {
        const decl = document_scope.declarations.get(@backingInt(decl_index));
        const decl_with_handle: DeclWithHandle = .{ .decl = decl, .handle = handle, .container_type = container_type };
        if (handle != original_handle and !decl_with_handle.isPublic()) continue;

        switch (decl) {
            .ast_node => |node| switch (node.get(tree)) {
                .field => |field_member| {
                    if (is_enum) {
                        if (instance_access) continue;
                        const field_name_token = field_member.get(tree).name orelse continue;
                        const field_name = offsets.identifierTokenToNameSlice(tree, field_name_token.token(tree));
                        if (std.mem.eql(u8, field_name, "_")) continue;
                    } else {
                        if (!instance_access) continue;
                    }
                },
                .type_fn,
                .decl_fn,
                .var_local,
                .var_global,
                => {
                    if (instance_access) {
                        // allow declarations which evaluate to functions where
                        // the first parameter has the type of the container:
                        const alias_type = try decl_with_handle.resolveType(analyser) orelse continue;
                        const func_ty = try analyser.resolveFuncProtoOfCallable(alias_type) orelse continue;

                        if (!analyser.firstParamIs(func_ty, .{
                            .data = .{ .container = info },
                            .is_type_val = true,
                        })) continue;
                    }
                },
            },
            .label => continue,
            else => {},
        }

        try decl_collection.append(analyser.arena, decl_with_handle);
    }
}

/// Collects all symbols/declarations that are accessible at the given source index.
pub fn collectAllSymbolsAtSourceIndex(
    analyser: *Analyser,
    /// a handle to a Document
    handle: *DocumentStore.Handle,
    /// a byte-index into `handle.tree.source`
    source_index: usize,
    /// allocated with `analyser.arena`
    decl_collection: *std.ArrayList(DeclWithHandle),
) error{OutOfMemory}!void {
    std.debug.assert(source_index <= handle.tree.source.len);

    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        const scope_decls = document_scope.getScopeDeclarationsConst(scope_index);
        for (scope_decls) |decl_index| {
            const decl = document_scope.declarations.get(@backingInt(decl_index));
            if (decl == .ast_node and decl.ast_node.idx.tag(&handle.tree) == .member_field) continue;
            if (decl == .label) continue;
            try decl_collection.append(analyser.arena, .{ .decl = decl, .handle = handle });
        }
    }
}

pub const EnclosingScopeIterator = struct {
    document_scope: *const DocumentScope,
    current_scope: Scope.OptionalIndex,
    source_index: usize,

    pub fn next(self: *EnclosingScopeIterator) Scope.OptionalIndex {
        const current_scope = self.current_scope.unwrap() orelse return .none;
        const scopes = self.document_scope.getScopeChildScopesConst(current_scope);
        const scope_locs = self.document_scope.scopes.items(.loc);
        const result = self.current_scope;

        const Context = struct {
            scope_locs: []const DocumentScope.Scope.SmallLoc,
            source_index: usize,

            fn compare(ctx: @This(), scope_index: Scope.Index) std.math.Order {
                const child_scope = ctx.scope_locs[@backingInt(scope_index)];
                if (ctx.source_index < child_scope.start) return .lt;
                if (child_scope.end < ctx.source_index) return .gt;
                return .eq;
            }
        };

        self.current_scope = if (std.sort.binarySearch(
            Scope.Index,
            scopes,
            Context{ .scope_locs = scope_locs, .source_index = self.source_index },
            Context.compare,
        )) |scope_index| scopes[scope_index].toOptional() else .none;

        return result;
    }
};

fn iterateEnclosingScopes(document_scope: *const DocumentScope, source_index: usize) EnclosingScopeIterator {
    return .{
        .document_scope = document_scope,
        .current_scope = .root,
        .source_index = source_index,
    };
}

pub fn iterateLabels(handle: *DocumentStore.Handle, source_index: usize, comptime callback: anytype, context: anytype) error{OutOfMemory}!void {
    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        for (document_scope.getScopeDeclarationsConst(scope_index)) |decl_index| {
            const decl = document_scope.declarations.get(@backingInt(decl_index));
            if (decl != .label) continue;
            try callback(context, .{ .decl = decl, .handle = handle });
        }
    }
}

pub fn innermostScopeAtIndex(
    document_scope: *const DocumentScope,
    source_index: usize,
) Scope.Index {
    return innermostScopeAtIndexWithTag(document_scope, source_index, .full).unwrap().?;
}

pub fn innermostScopeAtIndexWithTag(
    document_scope: *const DocumentScope,
    source_index: usize,
    tag_filter: std.EnumSet(Scope.Tag),
) Scope.OptionalIndex {
    var scope_iterator = iterateEnclosingScopes(document_scope, source_index);
    var scope_index: Scope.OptionalIndex = .none;
    while (scope_iterator.next().unwrap()) |inner_scope| {
        const scope_tag = document_scope.getScopeTag(inner_scope);
        if (!tag_filter.contains(scope_tag)) continue;
        scope_index = inner_scope.toOptional();
    }
    return scope_index;
}

pub fn innermostContainer(analyser: *Analyser, handle: *DocumentStore.Handle, source_index: usize) error{OutOfMemory}!Type {
    const tree = &handle.tree;
    const document_scope = try handle.getDocumentScope();
    if (document_scope.scopes.len == 1) return .{
        .data = .{ .container = .root(handle) },
        .is_type_val = true,
    };

    var pending_meta_params: TokenToTypeMap = .empty;
    defer pending_meta_params.deinit(analyser.gpa);

    var current: DocumentScope.Scope.Index = .root;
    var meta_params: TokenToTypeMap = .empty;
    var scope_iterator = iterateEnclosingScopes(document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        switch (document_scope.getScopeTag(scope_index)) {
            .container => {
                current = scope_index;
                for (pending_meta_params.keys(), pending_meta_params.values()) |token_handle, ty| {
                    try meta_params.put(analyser.arena, token_handle, ty);
                }
                pending_meta_params.clearRetainingCapacity();
            },
            .function => {
                const function_node = document_scope.getScopeAstNode(scope_index).?;
                const fn_proto: Ast.Expr.Fn = switch (function_node.tag(tree)) {
                    .type_fn => function_node.cast(.type_fn, tree).?,
                    .decl_fn => function_node.cast(.decl_fn, tree).?.proto.get(tree),
                    else => unreachable,
                };
                var it = fn_proto.params.get(tree).items.iter(tree);
                while (it.next(tree)) |param_idx| {
                    const param = param_idx.get(tree);
                    switch (param.type.get(tree)) {
                        .expr => {},
                        .@"anytype", .varargs => continue,
                    }
                    const param_name_token = (param.name orelse continue).token(tree);
                    const token_handle: TokenWithHandle = .{ .token = param_name_token, .handle = handle };
                    const ty: Type = .{ .data = .{ .type_parameter = token_handle }, .is_type_val = true };
                    try pending_meta_params.put(analyser.gpa, token_handle, ty);
                }
            },
            else => {},
        }
    }
    return .{
        .data = .{
            .container = .{
                .scope_handle = .{
                    .handle = handle,
                    .scope = current,
                },
                .bound_params = meta_params,
            },
        },
        .is_type_val = true,
    };
}

pub fn lookupLabel(
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const document_scope = try handle.getDocumentScope();
    var scope_iterator = iterateEnclosingScopes(document_scope, source_index);
    while (scope_iterator.next().unwrap()) |scope_index| {
        const decl_index = document_scope.getScopeDeclaration(.{
            .scope = scope_index,
            .name = symbol,
            .kind = .label,
        }).unwrap() orelse continue;
        const decl = document_scope.declarations.get(@backingInt(decl_index));

        std.debug.assert(decl == .label);

        return .{ .decl = decl, .handle = handle };
    }
    return null;
}

pub fn lookupSymbolGlobal(
    _: *Analyser,
    handle: *DocumentStore.Handle,
    symbol: []const u8,
    source_index: usize,
) error{OutOfMemory}!?DeclWithHandle {
    const tree = &handle.tree;
    const document_scope = try handle.getDocumentScope();
    var current_scope = innermostScopeAtIndex(document_scope, source_index);

    while (true) {
        if (document_scope.getScopeDeclaration(.{
            .scope = current_scope,
            .name = symbol,
            .kind = .field,
        }).unwrap()) |decl_index| {
            const decl = document_scope.declarations.get(@backingInt(decl_index));
            std.debug.assert(decl == .ast_node);

            const member_field: Ast.Member.Field = decl.ast_node.cast(.field, tree).?.get(tree);
            const field_name_token = member_field.name.?.token(tree);
            std.debug.assert(field_name_token.tag(tree) == .name);

            const field_name = offsets.tokenToLoc(tree, field_name_token);
            if (field_name.start <= source_index and source_index <= field_name.end) {
                return .{ .decl = decl, .handle = handle };
            }
        }

        if (document_scope.getScopeDeclaration(.{
            .scope = current_scope,
            .name = symbol,
            .kind = .other,
        }).unwrap()) |decl_index| {
            const decl = document_scope.declarations.get(@backingInt(decl_index));
            return .{ .decl = decl, .handle = handle };
        }

        current_scope = document_scope.getScopeParent(current_scope).unwrap() orelse break;
    }

    return null;
}

pub fn lookupSymbolContainer(
    container_type: Type,
    symbol: []const u8,
    kind: DocumentScope.DeclarationLookup.Kind,
) error{OutOfMemory}!?DeclWithHandle {
    const info = switch (container_type.data) {
        .container => |info| info,
        else => return null,
    };
    const container_scope = info.scope_handle;
    const handle = container_scope.handle;
    const document_scope = try handle.getDocumentScope();

    if (document_scope.getScopeDeclaration(.{
        .scope = container_scope.scope,
        .name = symbol,
        .kind = kind,
    }).unwrap()) |decl_index| {
        const decl = document_scope.declarations.get(@backingInt(decl_index));
        return .{ .decl = decl, .handle = handle, .container_type = container_type };
    }

    return null;
}

pub fn lookupSymbolFieldInit(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    field_name: []const u8,
    node: Ast.Node.Index,
    ancestors: []const Ast.Node.Index,
) Error!?struct { DeclWithHandle, ?Type } {
    var container_type = (try analyser.resolveExpressionType(
        handle,
        node,
        ancestors,
    )) orelse return null;

    if (container_type.is_type_val) return null;

    container_type = try container_type.typeOf(analyser);
    container_type = container_type.resolveDeclLiteralResultType();
    container_type = try container_type.instanceUnchecked(analyser);

    if (node.cast(.expr_init, &handle.tree) != null) {
        const decl = try container_type.lookupSymbol(analyser, field_name) orelse return null;
        return .{ decl, null };
    }

    switch (container_type.data) {
        .union_tag => |t| {
            const decl = try t.lookupSymbol(analyser, field_name) orelse return null;
            return .{ decl, container_type };
        },
        else => {},
    }

    switch (container_type.getContainerKind() orelse return null) {
        .@"struct", .@"opaque" => {},
        .@"enum" => if (try (try container_type.typeOf(analyser)).lookupSymbol(analyser, field_name)) |decl| return .{ decl, null },
        .@"union" => if (try container_type.lookupSymbol(analyser, field_name)) |decl| return .{ decl, null },
        else => return null,
    }

    // Assume we are doing decl literals
    const decl = try (try container_type.typeOf(analyser)).lookupSymbol(analyser, field_name) orelse return null;
    var resolved_type = try decl.resolveType(analyser) orelse return null;
    resolved_type = try analyser.resolveReturnType(resolved_type) orelse resolved_type;
    resolved_type = try resolved_type.typeOf(analyser);
    resolved_type = resolved_type.resolveDeclLiteralResultType();
    resolved_type = try resolved_type.instanceUnchecked(analyser);
    if (resolved_type.eql(container_type)) return .{ decl, null };
    return null;
}

pub fn resolveExpressionType(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []const Ast.Node.Index,
) Error!?Type {
    return (try analyser.resolveExpressionTypeFromAncestors(
        handle,
        node,
        ancestors,
    )) orelse (try analyser.resolveTypeOfNode(.of(node, handle)));
}

pub fn resolveExpressionTypeFromAncestors(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    node: Ast.Node.Index,
    ancestors: []const Ast.Node.Index,
) Error!?Type {
    if (ancestors.len == 0) return null;

    const tree = &handle.tree;

    switch (ancestors[0].tag(tree)) {
        .expr_init => {
            const expr: Ast.Expr.Init = ancestors[0].cast(.expr_init, tree).?;

            var it = expr.fields.iter(tree);
            var field_index: u32 = 0;
            while (it.next(tree)) |field| : (field_index += 1) {
                if (field.idx != node) continue;
                switch (field.get(tree)) {
                    .struct_field => |struct_field_idx| {
                        const struct_field = struct_field_idx.get(tree);
                        const field_name_token = struct_field.name.token(tree);
                        if (field_name_token.tag(tree) != .name) break;
                        const field_name = offsets.identifierTokenToNameSlice(tree, field_name_token);
                        const decl, const type_maybe = try analyser.lookupSymbolFieldInit(
                            handle,
                            field_name,
                            ancestors[0],
                            ancestors[1..],
                        ) orelse break;
                        return type_maybe orelse try decl.resolveType(analyser);
                    },
                    .tuple_field => {
                        const array_type = try analyser.resolveExpressionType(
                            handle,
                            ancestors[0],
                            ancestors[1..],
                        ) orelse break;
                        return try analyser.resolveBracketAccessType(array_type, .{ .single = field_index });
                    },
                }
            }
        },
        .member_field => {
            const member_field: Ast.Member.Field = ancestors[0].cast(.member_field, tree).?;
            if (node == unpackOptExpr(member_field.init)) {
                return try analyser.resolveTypeOfNode(.of(ancestors[0], handle));
            }
        },
        inline .var_global, .var_local => |tag| {
            const var_decl = ancestors[0].cast(tag, tree).?;
            const attributes = var_decl.attributes(tree);
            if (node == unpackOptExpr(var_decl.init)) {
                return try analyser.resolveTypeOfNode(.of(ancestors[0], handle));
            }
            if (node == unpackOptExpr(attributes.@"addrspace")) {
                return analyser.instanceStdBuiltinType("AddressSpace");
            }
            if (node == unpackOptExpr(attributes.@"linksection")) {
                const ty = try analyser.ip.get(.{
                    .pointer_type = .{
                        .elem_type = .u8_type,
                        .sentinel = .none,
                        .flags = .{
                            .size = .slice,
                            .is_const = true,
                        },
                    },
                });
                return Type.fromIP(analyser, ty, null);
            }
        },
        .expr_if,
        .expr_if_full,
        .expr_if_else,
        .expr_if_payload,
        => {
            const node_index: Ast.Expr.If.Index = .{ .idx = ancestors[0] };
            const expr = node_index.get(tree);
            if (node == expr.then_branch.idx or node == unpackOptExpr(expr.else_branch)) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .expr_for => {
            const expr: Ast.Expr.For = ancestors[0].cast(.expr_for, tree).?;
            if (node == unpackOptExpr(expr.@"else")) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .expr_while => {
            const expr: Ast.Expr.While = ancestors[0].cast(.expr_while, tree).?;
            if (node == unpackOptExpr(expr.@"else")) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }
        },
        .switch_prong => {
            const switch_prong: Ast.Expr.Switch.Prong = ancestors[0].cast(.switch_prong, tree).?;
            if (ancestors.len == 1) return null;

            const ancestor_switch: Ast.Expr.Switch = ancestors[1].cast(.expr_switch, tree).?;

            if (node == switch_prong.body.idx) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[1],
                    ancestors[2..],
                );
            }

            var it = switch_prong.cases.iter(tree);
            while (it.next(tree)) |case| {
                if (node == case.idx) {
                    return try analyser.resolveTypeOfNode(.of(ancestor_switch.condition.idx, handle));
                }
            }
        },
        .expr_call => {
            const expr: Ast.Expr.Call = ancestors[0].cast(.expr_call, tree).?;

            if (expr.callee.idx == node) {
                return try analyser.resolveExpressionType(
                    handle,
                    ancestors[0],
                    ancestors[1..],
                );
            }

            var arg_it = expr.args.iter(tree);
            var arg_index: u32 = 0;
            while (arg_it.next(tree)) |arg| : (arg_index += 1) {
                if (arg.idx == node) break;
            } else return null;

            var fn_type = if (expr.callee.idx.tag(tree) == .leaf_enum_literal) blk: {
                const field_name = offsets.identifierTokenToNameSlice(tree, expr.callee.idx.mainToken(tree));
                const decl, const type_maybe = try analyser.lookupSymbolFieldInit(handle, field_name, expr.callee.idx, ancestors) orelse return null;
                const ty = type_maybe orelse try decl.resolveType(analyser) orelse return null;
                break :blk try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
            } else blk: {
                const ty = try analyser.resolveTypeOfNode(.of(expr.callee.idx, handle)) orelse return null;
                break :blk try analyser.resolveFuncProtoOfCallable(ty) orelse return null;
            };
            if (fn_type.is_type_val) return null;

            fn_type = try analyser.resolveFunctionTypeFromCall(handle, expr, fn_type);
            const has_self_param = try analyser.isInstanceCall(handle, expr, fn_type);
            const parameters = fn_type.data.function.parameters[@intFromBool(has_self_param)..];
            if (arg_index >= parameters.len) return null;
            const param_ty = parameters[arg_index].type;
            return try param_ty.instanceTypeVal(analyser);
        },

        .expr_assign => {
            const expr: Ast.Expr.Assign = ancestors[0].cast(.expr_assign, tree).?;
            if (node == expr.rhs.idx) {
                return try analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle));
            }
        },
        .type_pointer => {
            const expr: Ast.Expr.Pointer = ancestors[0].cast(.type_pointer, tree).?;
            const attributes = expr.attributes(tree);

            if (node == unpackOptExpr(expr.sentinel(tree))) {
                return analyser.resolveInstanceOfNode(.of(expr.child_type.idx, handle));
            }
            if (node == unpackOptExpr(attributes.@"addrspace")) {
                return analyser.instanceStdBuiltinType("AddressSpace");
            }
        },
        .type_array => {
            const expr: Ast.Expr.Array = ancestors[0].cast(.type_array, tree).?;
            if (node == unpackOptExpr(expr.sentinel)) {
                return analyser.resolveInstanceOfNode(.of(expr.child_type.idx, handle));
            }
        },

        .expr_return => {
            const expr: Ast.Expr.Return = ancestors[0].cast(.expr_return, tree).?;

            const return_expr = expr.value orelse return null;
            if (node != return_expr.idx) return null;

            for (ancestors[1..]) |ancestor| {
                const func: Ast.Expr.Fn = ancestor.cast(.type_fn, tree) orelse continue;
                const return_ty = try analyser.resolveTypeOfNode(.of(func.return_type.idx, handle)) orelse return null;
                return try return_ty.instanceTypeVal(analyser);
            }
        },

        .expr_continue => {
            const expr: Ast.Expr.Continue = ancestors[0].cast(.expr_continue, tree).?;

            const target = expr.label(tree) orelse return null;
            const continue_expr = expr.value orelse return null;
            if (node != continue_expr.idx) return null;

            const continue_label = target.slice(tree);

            const ancestor_switch: Ast.Expr.Switch = for (ancestors[1..]) |ancestor| {
                const switch_exr: Ast.Expr.Switch = ancestor.cast(.expr_switch, tree) orelse continue;
                const switch_label_token = switch_exr.label(tree) orelse continue;
                const switch_label = switch_label_token.slice(tree);
                if (std.mem.eql(u8, continue_label, switch_label)) {
                    break switch_exr;
                }
            } else {
                return null;
            };

            return try analyser.resolveTypeOfNode(.of(ancestor_switch.condition.idx, handle));
        },

        .expr_break => {
            const expr: Ast.Expr.Break = ancestors[0].cast(.expr_break, tree).?;

            const break_expr = expr.value orelse return null;
            if (node != break_expr.idx) return null;

            const break_label_maybe: ?[]const u8 = if (expr.label(tree)) |target|
                target.slice(tree)
            else
                null;

            const index = ast.indexOfBreakTarget(tree, ancestors, break_label_maybe) orelse return null;

            return try analyser.resolveExpressionType(
                handle,
                ancestors[index],
                ancestors[index + 1 ..],
            );
        },

        .expr_group,
        .expr_comptime,
        => {
            return try analyser.resolveExpressionType(
                handle,
                ancestors[0],
                ancestors[1..],
            );
        },

        .expr_builtin_call => {
            const expr: Ast.Expr.Builtin = ancestors[0].cast(.expr_builtin_call, tree).?;

            const call_name = expr.callee.token(tree).slice(tree);

            var it = expr.args.iter(tree);

            if (std.mem.eql(u8, call_name, "@as")) {
                const first_arg = it.next(tree) orelse return null;
                const second_arg = it.next(tree) orelse return null;
                if (it.next(tree) != null) return null;
                if (second_arg.idx != node) return null;
                const ty = try analyser.resolveTypeOfNode(.of(first_arg.idx, handle)) orelse return null;
                return try ty.instanceTypeVal(analyser);
            }

            if (version_data.builtins.get(call_name)) |data| {
                var index: u32 = 0;
                while (it.next(tree)) |arg| : (index += 1) {
                    if (arg.idx == node) break;
                } else return null;
                if (index >= data.parameters.len) return null;
                const parameter = data.parameters[index];
                const colon_index = std.mem.findScalar(u8, parameter.signature, ':') orelse return null;
                const type_str = parameter.signature[colon_index + 2 ..];
                return analyser.resolveLangrefType(type_str);
            }
        },

        .expr_binary => {
            const expr: Ast.Expr.Binary = ancestors[0].cast(.expr_binary, tree).?;
            switch (expr.op.get(tree)) {
                .@"orelse" => {
                    if (node == expr.rhs.idx) {
                        const lhs_ty = try analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle)) orelse return null;
                        return try analyser.resolveOptionalUnwrap(lhs_ty);
                    }
                },
                .@"==", .@"!=" => {
                    if (node == expr.lhs.idx) {
                        return try analyser.resolveTypeOfNode(.of(expr.rhs.idx, handle));
                    }
                    if (node == expr.rhs.idx) {
                        return try analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle));
                    }
                },
                else => {},
            }
        },

        .expr_catch => {
            const expr: Ast.Expr.Catch = ancestors[0].cast(.expr_catch, tree).?;
            if (node == expr.rhs.idx) {
                const lhs_ty = try analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle)) orelse return null;
                return try analyser.resolveUnwrapErrorUnionType(lhs_ty, .payload);
            }
        },

        .expr_prefix => {
            const expr: Ast.Expr.Prefix = ancestors[0].cast(.expr_prefix, tree).?;
            switch (expr.op.get(tree)) {
                .@"try" => {
                    return try analyser.resolveExpressionType(
                        handle,
                        ancestors[0],
                        ancestors[1..],
                    );
                },
                .@"&" => {
                    std.debug.assert(node == expr.rhs.idx);

                    const expr_ty = try analyser.resolveExpressionType(
                        handle,
                        ancestors[0],
                        ancestors[1..],
                    ) orelse return null;

                    if (try analyser.resolveDerefType(expr_ty)) |ty| {
                        return ty;
                    }
                    if (try analyser.resolveOptionalUnwrap(expr_ty)) |ty| {
                        if (try analyser.resolveDerefType(ty)) |typ| {
                            return typ;
                        }
                    }

                    switch (expr_ty.data) {
                        .pointer => |info| switch (info.size) {
                            .slice => {
                                const init_expr: Ast.Expr.Init = node.cast(.expr_init, tree) orelse return null;

                                var it = init_expr.fields.iter(tree);
                                var elem_count: u32 = 0;
                                while (it.next(tree)) |field| {
                                    switch (field.get(tree)) {
                                        .struct_field => return null,
                                        .tuple_field => elem_count += 1,
                                    }
                                }

                                return .{
                                    .data = .{
                                        .array = .{
                                            .elem_count = elem_count,
                                            .sentinel = info.sentinel,
                                            .elem_ty = info.elem_ty,
                                        },
                                    },
                                    .is_type_val = false,
                                };
                            },
                            else => {},
                        },
                        .ip_index => |payload| switch (analyser.ip.indexToKey(payload.type)) {
                            .pointer_type => |pointer_info| switch (pointer_info.flags.size) {
                                .slice => {
                                    const init_expr: Ast.Expr.Init = node.cast(.expr_init, tree) orelse return null;

                                    var it = init_expr.fields.iter(tree);
                                    var elem_count: u32 = 0;
                                    while (it.next(tree)) |field| {
                                        switch (field.get(tree)) {
                                            .struct_field => return null,
                                            .tuple_field => elem_count += 1,
                                        }
                                    }

                                    const ty = try analyser.ip.get(.{
                                        .array_type = .{
                                            .len = elem_count,
                                            .child = pointer_info.elem_type,
                                            .sentinel = pointer_info.sentinel,
                                        },
                                    });
                                    return Type.fromIP(analyser, ty, null);
                                },
                                else => {},
                            },
                            else => {},
                        },
                        else => {},
                    }
                },
                else => {},
            }
        },
        .type_fn => {
            const expr: Ast.Expr.Fn = ancestors[0].cast(.type_fn, tree).?;
            const attributes = expr.attributes(tree);

            if (node == unpackOptExpr(attributes.@"addrspace")) {
                return analyser.instanceStdBuiltinType("AddressSpace");
            }
            if (node == unpackOptExpr(attributes.@"callconv")) {
                return analyser.instanceStdBuiltinType("CallingConvention");
            }
            if (node == unpackOptExpr(attributes.@"linksection")) {
                const ty = try analyser.ip.get(.{
                    .pointer_type = .{
                        .elem_type = .u8_type,
                        .sentinel = .none,
                        .flags = .{
                            .size = .slice,
                            .is_const = true,
                        },
                    },
                });
                return Type.fromIP(analyser, ty, null);
            }
        },
        .expr_asm => {
            const expr: Ast.Expr.Asm = ancestors[0].cast(.expr_asm, tree).?;
            if (node == unpackOptExpr(expr.clobbers)) {
                return analyser.instanceStdBuiltinType("assembly.Clobbers");
            }
        },

        else => {},
    }

    return null;
}

pub fn getSymbolEnumLiteral(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    source_index: usize,
    name: []const u8,
) Error!?struct { DeclWithHandle, ?Type } {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = &handle.tree;
    const nodes = try ast.nodesOverlappingIndex(analyser.arena, tree, source_index);
    if (nodes.len == 0) return null;
    return try analyser.lookupSymbolFieldInit(handle, name, nodes[0], nodes[1..]);
}

pub fn resolveStructInitType(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    source_index: usize,
) Error!?Type {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = &handle.tree;
    const nodes = try ast.nodesOverlappingIndex(analyser.arena, tree, source_index);
    if (nodes.len == 0) return null;
    var ty = try analyser.resolveExpressionType(handle, nodes[0], nodes[1..]) orelse return null;
    while (true) {
        const unwrapped =
            try analyser.resolveUnwrapErrorUnionType(ty, .payload) orelse
            try analyser.resolveOptionalUnwrap(ty) orelse
            break;
        ty = unwrapped;
    }
    return ty;
}

/// Multiple when using branched types
pub fn getSymbolFieldAccesses(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    held_loc: offsets.Loc,
    name: []const u8,
) Error!?[]const DeclWithHandle {
    var decls_with_handles: std.ArrayList(DeclWithHandle) = .empty;
    var property_types: std.ArrayList(Type) = .empty;
    try analyser.getSymbolFieldAccessesArrayList(arena, handle, source_index, held_loc, name, &decls_with_handles, &property_types);
    return try decls_with_handles.toOwnedSlice(arena);
}

pub fn getSymbolFieldAccessesArrayList(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    held_loc: offsets.Loc,
    name: []const u8,
    decls_with_handles: *std.ArrayList(DeclWithHandle),
    property_types: *std.ArrayList(Type),
) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (try analyser.getFieldAccessType(handle, source_index, held_loc)) |ty| {
        const container_handle = try analyser.resolveDerefType(ty) orelse ty;

        const container_handle_nodes = try container_handle.getAllTypesWithHandles(analyser);

        for (container_handle_nodes) |t| {
            if (try t.lookupSymbol(analyser, name)) |decl_handle|
                try decls_with_handles.append(arena, decl_handle);
            if (try analyser.resolvePropertyType(ty, name)) |p|
                try property_types.append(arena, p);
        }
    }
}

pub fn getSymbolFieldAccessesHighlight(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    decls_with_handles: *std.ArrayList(DeclWithHandle),
    property_types: *std.ArrayList(Type),
) Error!?offsets.Loc {
    const name_loc, const highlight_loc = blk: {
        const name_token, const name_loc = offsets.identifierTokenAndLocFromIndex(&handle.tree, source_index) orelse {
            const token = offsets.sourceIndexToTokenIndex(&handle.tree, source_index).pickPreferred(&.{ .@"?", .@".*" }, &handle.tree) orelse return null;
            switch (token.tag(&handle.tree)) {
                .@"?" => {
                    const token_loc = offsets.tokenToLoc(&handle.tree, token);
                    break :blk .{ token_loc, token_loc };
                },
                .@".*" => {
                    var name_loc = offsets.tokenToLoc(&handle.tree, token);
                    name_loc.start += 1; // trim the.@"."
                    break :blk .{ name_loc, name_loc };
                },
                else => return null,
            }
        };
        break :blk .{ name_loc, offsets.tokenToLoc(&handle.tree, name_token) };
    };
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const held_loc = offsets.locMerge(loc, name_loc);
    try analyser.getSymbolFieldAccessesArrayList(arena, handle, source_index, held_loc, name, decls_with_handles, property_types);
    return highlight_loc;
}

pub const ReferencedType = struct {
    str: []const u8,
    handle: *DocumentStore.Handle,
    token: Ast.Token.Index,

    pub fn of(
        str: []const u8,
        handle: *DocumentStore.Handle,
        token: Ast.Token.Index,
    ) ReferencedType {
        return .{ .str = str, .handle = handle, .token = token };
    }

    pub const Set = std.array_hash_map.Custom(ReferencedType, void, SetContext, true);

    const SetContext = struct {
        pub fn hash(self: SetContext, item: ReferencedType) u32 {
            _ = self;
            var hasher: std.hash.Wyhash = .init(0);
            hasher.update(item.str);
            hasher.update(item.handle.uri.raw);
            hasher.update(&std.mem.toBytes(item.token));
            return @truncate(hasher.final());
        }

        pub fn eql(self: SetContext, a: ReferencedType, b: ReferencedType, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.mem.eql(u8, a.str, b.str) and
                a.handle.uri.eql(b.handle.uri) and
                a.token == b.token;
        }
    };
};

fn unpackOptExpr(node: ?Ast.UnionNode(Ast.Expr)) ?Ast.Node.Index {
    return if (node) |n| n.idx else null;
}
