const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_document_symbol);

const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const analysis = @import("../analysis.zig");
const tracy = @import("../tracy.zig");

const Symbol = struct {
    name: []const u8,
    detail: ?[]const u8 = null,
    kind: types.SymbolKind,
    loc: offsets.Loc,
    selection_loc: offsets.Loc,
    children: std.ArrayListUnmanaged(Symbol),
};

const Context = struct {
    arena: std.mem.Allocator,
    last_var_decl_name: ?[]const u8,
    parent_node: Ast.Node.Index,
    parent_symbols: *std.ArrayListUnmanaged(Symbol),
    total_symbol_count: *usize,
};

fn callback(ctx: *Context, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
    if (node == 0) return;

    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    const decl_name_token = analysis.getDeclNameToken(tree, node);
    const decl_name = analysis.getDeclName(tree, node);

    var new_ctx = ctx.*;
    const maybe_symbol: ?Symbol = switch (node_tags[node]) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => blk: {
            new_ctx.last_var_decl_name = decl_name;
            if (!ast.isContainer(tree, ctx.parent_node)) break :blk null;

            const kind: types.SymbolKind = switch (token_tags[main_tokens[node]]) {
                .keyword_var => .Variable,
                .keyword_const => .Constant,
                else => unreachable,
            };

            break :blk .{
                .name = decl_name.?,
                .detail = null,
                .kind = kind,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, decl_name_token.?),
                .children = .{},
            };
        },

        .test_decl,
        .fn_decl,
        => |tag| blk: {
            const kind: types.SymbolKind = switch (tag) {
                .test_decl => .Method, // there is no SymbolKind that represents a tests
                .fn_decl => .Function,
                else => unreachable,
            };

            var buffer: [1]Ast.Node.Index = undefined;
            const detail = if (tree.fullFnProto(&buffer, node)) |fn_info| analysis.getFunctionSignature(tree, fn_info) else null;

            break :blk .{
                .name = decl_name orelse break :blk null,
                .detail = detail,
                .kind = kind,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, decl_name_token.?),
                .children = .{},
            };
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => blk: {
            const kind: types.SymbolKind = switch (node_tags[ctx.parent_node]) {
                .root => .Field,
                .container_decl,
                .container_decl_trailing,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                => switch (token_tags[main_tokens[ctx.parent_node]]) {
                    .keyword_struct => .Field,
                    .keyword_union => .Field,
                    .keyword_enum => .EnumMember,
                    .keyword_opaque => break :blk null,
                    else => unreachable,
                },
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                => .Field,
                else => unreachable,
            };

            break :blk .{
                .name = decl_name.?,
                .detail = ctx.last_var_decl_name,
                .kind = kind,
                .loc = offsets.nodeToLoc(tree, node),
                .selection_loc = offsets.tokenToLoc(tree, decl_name_token.?),
                .children = .{},
            };
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

/// a mapping from a source index to a line character pair
const IndexToPositionEntry = struct {
    output: *types.Position,
    source_index: usize,

    const Self = @This();

    fn lessThan(_: void, lhs: Self, rhs: Self) bool {
        return lhs.source_index < rhs.source_index;
    }
};

/// converts `Symbol` to `types.DocumentSymbol`
fn convertSymbols(
    arena: std.mem.Allocator,
    tree: Ast,
    from: []const Symbol,
    total_symbol_count: usize,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var symbol_buffer = std.ArrayListUnmanaged(types.DocumentSymbol){};
    try symbol_buffer.ensureTotalCapacityPrecise(arena, total_symbol_count);

    // instead of converting every `offsets.Loc` to `types.Range` by calling `offsets.locToRange`
    // we instead store a mapping from source indices to their desired position, sort them by their source index
    // and then iterate through them which avoids having to re-iterate through the source file to find out the line number
    // this reduces algorithmic complexity from `O(file_size*symbol_count)` to `O(symbol_count*log(symbol_count))`
    var mappings = std.ArrayListUnmanaged(IndexToPositionEntry){};
    try mappings.ensureTotalCapacityPrecise(arena, total_symbol_count * 4);

    const result = convertSymbolsInternal(from, &symbol_buffer, &mappings);

    // sort items based on their source position
    std.mem.sort(IndexToPositionEntry, mappings.items, {}, IndexToPositionEntry.lessThan);

    var last_index: usize = 0;
    var last_position: types.Position = .{ .line = 0, .character = 0 };
    for (mappings.items) |mapping| {
        const index = mapping.source_index;
        const position = offsets.advancePosition(tree.source, last_position, last_index, index, encoding);
        defer last_index = index;
        defer last_position = position;

        mapping.output.* = position;
    }

    return result;
}

fn convertSymbolsInternal(
    from: []const Symbol,
    symbol_buffer: *std.ArrayListUnmanaged(types.DocumentSymbol),
    mappings: *std.ArrayListUnmanaged(IndexToPositionEntry),
) []types.DocumentSymbol {
    // acquire storage for exactly `from.len` symbols
    const prev_len = symbol_buffer.items.len;
    symbol_buffer.items.len += from.len;
    const to: []types.DocumentSymbol = symbol_buffer.items[prev_len..];

    for (from, to) |symbol, *out| {
        out.* = .{
            .name = symbol.name,
            .detail = symbol.detail,
            .kind = symbol.kind,
            // will be set later through the mapping below
            .range = undefined,
            .selectionRange = undefined,
            .children = convertSymbolsInternal(symbol.children.items, symbol_buffer, mappings),
        };
        mappings.appendSliceAssumeCapacity(&[4]IndexToPositionEntry{
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
    tree: Ast,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    var root_symbols = std.ArrayListUnmanaged(Symbol){};
    var total_symbol_count: usize = 0;

    var ctx = Context{
        .arena = arena,
        .last_var_decl_name = null,
        .parent_node = 0, // root-node
        .parent_symbols = &root_symbols,
        .total_symbol_count = &total_symbol_count,
    };
    try ast.iterateChildren(tree, 0, &ctx, error{OutOfMemory}, callback);

    return try convertSymbols(arena, tree, root_symbols.items, ctx.total_symbol_count.*, encoding);
}
