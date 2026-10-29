//! Implementation of [`textDocument/documentSymbol`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentSymbol)

const std = @import("std");
const Ast = @import("zirp").Ast;

const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const analysis = @import("../analysis.zig");
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");
const tracy = @import("tracy");

pub const Error = error{ OutOfMemory, Canceled, InvalidParams };

pub fn @"textDocument/documentSymbol"(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.DocumentSymbol.Params,
) Error!?types.DocumentSymbol.Result {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;
    if (handle.tree.mode == .zon) return null;
    return .{
        .document_symbols = try getDocumentSymbols(arena, &handle.tree, server.offset_encoding),
    };
}

const Symbol = struct {
    name_token: Ast.Token.Index,
    detail: ?[]const u8 = null,
    kind: types.SymbolKind,
    loc: offsets.Loc,
    selection_loc: offsets.Loc,
    children: std.ArrayList(Symbol),
};

pub fn tokenNameMaybeQuotes(tree: *const Ast, token: Ast.Token.Index) []const u8 {
    const token_slice = token.slice(tree);
    switch (token.tag(tree)) {
        .name => return token_slice,
        .string => {
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

pub fn getDocumentSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    var symbols: std.ArrayList(Symbol) = .empty;
    var total_symbol_count: usize = 0;

    const StackEntry = struct {
        current_symbols: *std.ArrayList(Symbol),
        last_var_decl_name_token: Ast.Token.OptionalIndex,
        parent_container: Ast.Expr.Index,
    };
    var stack: std.ArrayList(StackEntry) = try .initCapacity(arena, 16);
    stack.appendAssumeCapacity(.{
        .current_symbols = &symbols,
        .last_var_decl_name_token = .none,
        .parent_container = .{ .idx = .root },
    });

    var walker: ast.Walker = try .init(arena, tree, .root);
    defer walker.deinit(arena);
    while (try walker.next(arena, tree)) |event| {
        const node = switch (event) {
            .open => |node| node,
            .close => {
                stack.items.len -= 1;
                continue;
            },
        };

        try stack.append(arena, stack.last().?);
        const stack_entry = stack.lastPtr().?;

        const symbol: Symbol = switch (node.tag(tree)) {
            // BRANCH_TODO is the `in_function` still necessary since we are excluding `.var_local`
            // .var_local,
            .var_global => blk: {
                if (!ast.isContainer(tree, walker.parentNode())) continue;

                const var_decl: Ast.Member.GlobalVar = node.cast(.var_global, tree).?;
                const var_decl_name_token = var_decl.name(tree) orelse continue;

                stack_entry.last_var_decl_name_token = .fromOptional(var_decl_name_token);

                const kind: types.SymbolKind = switch (node.mainToken(tree).tag(tree)) {
                    .@"var" => .Variable,
                    .@"const" => .Constant,
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

            .decl_test => blk: {
                const decl_test: Ast.Member.Test = node.cast(.decl_test, tree).?;
                const name_token = decl_test.name(tree) orelse continue;

                break :blk .{
                    .name_token = name_token,
                    .kind = .Method, // there is no SymbolKind that represents a tests
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, name_token),
                    .children = .empty,
                };
            },

            .type_fn,
            .decl_fn,
            => |tag| blk: {
                if (tag != .decl_fn and walker.parentNode().tag(tree) == .decl_fn) continue;
                const name_token = switch (tag) {
                    .type_fn => node.cast(.type_fn, tree).?.name(tree),
                    .decl_fn => node.cast(.decl_fn, tree).?.proto.get(tree).name(tree),
                    else => unreachable,
                } orelse continue;

                break :blk .{
                    .name_token = name_token,
                    .detail = offsets.nodeToSlice(tree, node),
                    .kind = .Function,
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, name_token),
                    .children = .empty,
                };
            },

            .member_field => blk: {
                const container_kind: std.meta.Tag(Ast.Expr.Container.Kind) = switch (stack_entry.parent_container.idx.tag(tree)) {
                    .root => .@"struct",
                    .type_container => stack_entry.parent_container.cast(.container, tree).?.get(tree).kind.get(tree),
                    else => unreachable,
                };

                const kind: types.SymbolKind = switch (container_kind) {
                    .@"struct" => .Field,
                    .@"union" => .Field,
                    .@"enum" => .EnumMember,
                    .@"opaque" => continue,
                };

                const member_field: Ast.Member.Field = node.cast(.member_field, tree).?;
                const member_field_name_leaf = member_field.name orelse continue;
                const member_field_name_token = member_field_name_leaf.token(tree);
                std.debug.assert(member_field_name_token.tag(tree) == .name);

                const guessed_container_name = if (stack_entry.last_var_decl_name_token.unwrap()) |name_token|
                    offsets.identifierTokenToNameSlice(tree, name_token)
                else
                    null;

                break :blk .{
                    .name_token = member_field_name_token,
                    .detail = guessed_container_name,
                    .kind = kind,
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, member_field_name_token),
                    .children = .empty,
                };
            },
            .type_container => {
                stack_entry.parent_container = .{ .idx = node };
                continue;
            },
            else => continue,
        };

        switch (symbol.name_token.tag(tree)) {
            .name, .string => {},
            else => unreachable,
        }

        try stack_entry.current_symbols.append(arena, symbol);
        stack_entry.current_symbols = &stack_entry.current_symbols.items[stack_entry.current_symbols.items.len - 1].children;
        total_symbol_count += 1;
    }

    std.debug.assert(stack.items.len == 0);

    return try convertSymbols(
        arena,
        tree,
        symbols.items,
        total_symbol_count,
        encoding,
    );
}

/// converts `Symbol` to `types.DocumentSymbol`
fn convertSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    root_symbols: []const Symbol,
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

    const root_document_symbols = symbol_buffer.addManyAsSliceAssumeCapacity(root_symbols.len);

    var queue: std.ArrayList(struct { []const Symbol, []types.DocumentSymbol }) = .empty;
    try queue.append(arena, .{ root_symbols, root_document_symbols });

    while (queue.pop()) |item| {
        const symbols, const document_symbols = item;
        for (symbols, document_symbols) |symbol, *document_symbol| {
            const symbol_children = symbol.children.items;
            const document_symbol_children = symbol_buffer.addManyAsSliceAssumeCapacity(symbol_children.len);
            try queue.append(arena, .{ symbol.children.items, document_symbol_children });

            document_symbol.* = .{
                .name = tokenNameMaybeQuotes(tree, symbol.name_token),
                .detail = symbol.detail,
                .kind = symbol.kind,
                // will be set later through the mapping below
                .range = undefined,
                .selectionRange = undefined,
                .children = document_symbol_children,
            };
            mappings.appendSliceAssumeCapacity(&.{
                .{ .output = &document_symbol.range.start, .source_index = symbol.loc.start },
                .{ .output = &document_symbol.selectionRange.start, .source_index = symbol.selection_loc.start },
                .{ .output = &document_symbol.selectionRange.end, .source_index = symbol.selection_loc.end },
                .{ .output = &document_symbol.range.end, .source_index = symbol.loc.end },
            });
        }
    }
    std.debug.assert(symbol_buffer.items.len == total_symbol_count);

    offsets.multiple.indexToPositionWithMappings(tree.source, mappings.items, encoding);

    return root_document_symbols;
}
