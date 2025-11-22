//! Implementation of [`textDocument/documentSymbol`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentSymbol)

const std = @import("std");
const Ast = std.zig.Ast;

const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const analysis = @import("../analysis.zig");
const tracy = @import("tracy");

const Symbol = struct {
    name_token: Ast.TokenIndex,
    detail: ?[]const u8 = null,
    kind: types.SymbolKind,
    loc: offsets.Loc,
    selection_loc: offsets.Loc,
    children: std.ArrayList(Symbol),
};

const Context = struct {
    arena: std.mem.Allocator,
    last_var_decl_name: ?[]const u8,
    parent_container: Ast.Node.Index,
    parent_node: Ast.Node.Index,
    parent_symbols: *std.ArrayList(Symbol),
    total_symbol_count: *usize,
};

fn tokenNameMaybeQuotes(tree: *const Ast, token: Ast.TokenIndex) []const u8 {
    const token_slice = tree.tokenSlice(token);
    switch (tree.tokenTag(token)) {
        .identifier => return token_slice,
        .string_literal => {
            const name = token_slice[1 .. token_slice.len - 1];
            const trimmed = std.mem.trim(u8, name, &std.ascii.whitespace);
            // LSP spec requires that a symbol name not be empty or consisting only of whitespace,
            // don't trim the quotes in that case so there's something to present.
            // Leading and trailing whitespace might cause ambiguity depending on how the client shows symbols
            // so compensate for that as well
            if (name.len == 0 or name.len != trimmed.len)
                return token_slice;

            return name;
        },
        else => unreachable,
    }
}

fn callback(ctx: *Context, tree: *const Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
    std.debug.assert(node != .root);

    var new_ctx = ctx.*;
    const maybe_symbol: ?Symbol = switch (tree.nodeTag(node)) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => blk: {
            if (!ast.isContainer(tree, ctx.parent_node)) break :blk null;

            const var_decl = tree.fullVarDecl(node).?;
            const var_decl_name_token = var_decl.ast.mut_token + 1;
            const var_decl_name = offsets.identifierTokenToNameSlice(tree, var_decl_name_token);

            new_ctx.last_var_decl_name = var_decl_name;

            const kind: types.SymbolKind = switch (tree.tokenTag(tree.nodeMainToken(node))) {
                .keyword_var => .Variable,
                .keyword_const => .Constant,
                else => unreachable,
            };

            break :blk .{
                .name_token = var_decl_name_token,
                .detail = null,
                .kind = kind,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, var_decl_name_token),
                .children = .empty,
            };
        },

        .test_decl => blk: {
            const test_name_token = tree.nodeData(node).opt_token_and_node[0].unwrap() orelse break :blk null;

            break :blk .{
                .name_token = test_name_token,
                .kind = .Method, // there is no SymbolKind that represents a tests
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, test_name_token),
                .children = .empty,
            };
        },

        .fn_decl => blk: {
            var buffer: [1]Ast.Node.Index = undefined;
            const fn_info = tree.fullFnProto(&buffer, node).?;
            const name_token = fn_info.name_token orelse break :blk null;

            break :blk .{
                .name_token = name_token,
                .detail = analysis.getFunctionSignature(tree, fn_info),
                .kind = .Function,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, name_token),
                .children = .empty,
            };
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => blk: {
            const kind: types.SymbolKind, const is_struct = switch (tree.nodeTag(ctx.parent_container)) {
                .root => .{ .Field, true },
                .container_decl,
                .container_decl_trailing,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                => switch (tree.tokenTag(tree.nodeMainToken(ctx.parent_container))) {
                    .keyword_struct => .{ .Field, true },
                    .keyword_union => .{ .Field, false },
                    .keyword_enum => .{ .EnumMember, false },
                    .keyword_opaque => break :blk null,
                    else => unreachable,
                },
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                => .{ .Field, false },
                else => unreachable,
            };

            const container_field = tree.fullContainerField(node).?;
            if (is_struct and container_field.ast.tuple_like) break :blk null;

            const decl_name_token = container_field.ast.main_token;

            break :blk .{
                .name_token = decl_name_token,
                .detail = ctx.last_var_decl_name,
                .kind = kind,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, decl_name_token),
                .children = .empty,
            };
        },
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
        => blk: {
            new_ctx.parent_container = node;
            break :blk null;
        },
        else => null,
    };

    new_ctx.parent_node = node;
    if (maybe_symbol) |symbol| {
        var symbol_ptr = try ctx.parent_symbols.addOne(ctx.arena);
        symbol_ptr.* = symbol;
        new_ctx.parent_symbols = &symbol_ptr.children;
        ctx.total_symbol_count.* += 1;
    }

    try ast.iterateChildren(tree, node, &new_ctx, error{OutOfMemory}, callback);
}

/// converts `Symbol` to `types.DocumentSymbol`
fn convertSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    from: []const Symbol,
    total_symbol_count: usize,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var symbol_buffer: std.ArrayList(types.DocumentSymbol) = .empty;
    try symbol_buffer.ensureTotalCapacityPrecise(arena, total_symbol_count);

    // instead of converting every `offsets.Loc` to `types.Range` by calling `offsets.locToRange`
    // we instead store a mapping from source indices to their desired position, sort them by their source index
    // and then iterate through them which avoids having to re-iterate through the source file to find out the line number
    var mappings: std.ArrayList(offsets.multiple.IndexToPositionMapping) = .empty;
    try mappings.ensureTotalCapacityPrecise(arena, total_symbol_count * 4);

    const result = convertSymbolsInternal(tree, from, &symbol_buffer, &mappings);

    offsets.multiple.indexToPositionWithMappings(tree.source, mappings.items, encoding);

    return result;
}

fn convertSymbolsInternal(
    tree: *const Ast,
    from: []const Symbol,
    symbol_buffer: *std.ArrayList(types.DocumentSymbol),
    mappings: *std.ArrayList(offsets.multiple.IndexToPositionMapping),
) []types.DocumentSymbol {
    // acquire storage for exactly `from.len` symbols
    const prev_len = symbol_buffer.items.len;
    symbol_buffer.items.len += from.len;
    const to: []types.DocumentSymbol = symbol_buffer.items[prev_len..];

    for (from, to) |symbol, *out| {
        out.* = .{
            .name = tokenNameMaybeQuotes(tree, symbol.name_token),
            .detail = symbol.detail,
            .kind = symbol.kind,
            // will be set later through the mapping below
            .range = undefined,
            .selectionRange = undefined,
            .children = convertSymbolsInternal(tree, symbol.children.items, symbol_buffer, mappings),
        };
        mappings.appendSliceAssumeCapacity(&.{
            .{ .output = &out.range.start, .source_index = symbol.loc.start },
            .{ .output = &out.selectionRange.start, .source_index = symbol.selection_loc.start },
            .{ .output = &out.selectionRange.end, .source_index = symbol.selection_loc.end },
            .{ .output = &out.range.end, .source_index = symbol.loc.end },
        });
    }

    return to;
}

pub fn getDocumentSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    var root_symbols: std.ArrayList(Symbol) = .empty;
    var total_symbol_count: usize = 0;

    var ctx: Context = .{
        .arena = arena,
        .last_var_decl_name = null,
        .parent_node = .root,
        .parent_container = .root,
        .parent_symbols = &root_symbols,
        .total_symbol_count = &total_symbol_count,
    };
    try ast.iterateChildren(tree, .root, &ctx, error{OutOfMemory}, callback);

    return try convertSymbols(arena, tree, root_symbols.items, ctx.total_symbol_count.*, encoding);
}
