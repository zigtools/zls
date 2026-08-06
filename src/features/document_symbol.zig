//! Implementation of [`textDocument/documentSymbol`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentSymbol)

const std = @import("std");
const Ast = std.zig.Ast;

const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const analysis = @import("../analysis.zig");
const tracy = @import("tracy");

const Symbol = struct {
    name: union(enum) {
        token: Ast.TokenIndex,
        text: []const u8,
    },
    detail: ?[]const u8 = null,
    kind: types.SymbolKind,
    loc: offsets.Loc,
    selection_loc: offsets.Loc,
    children: std.ArrayList(Symbol),
};

pub fn tokenNameMaybeQuotes(tree: *const Ast, token: Ast.TokenIndex) []const u8 {
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

/// Syntactic heuristic for distinguishing container methods from plain
/// functions: a method's first parameter type is `@This()`, the enclosing
/// container's binding name, or the conventional `Self` alias, possibly
/// behind (nested) single-item or C pointers. `anytype` and aliased self
/// parameters other than `Self` are not detected.
fn isMethod(
    tree: *const Ast,
    fn_info: Ast.full.FnProto,
    container_name_token: Ast.OptionalTokenIndex,
) bool {
    var it = fn_info.iterate(tree);
    const first_param = it.next() orelse return false;
    var type_expr = first_param.type_expr orelse return false;
    while (tree.fullPtrType(type_expr)) |ptr_type| {
        switch (ptr_type.size) {
            // `foo.f()` auto-references `foo` to `*Foo` which also coerces to `[*c]Foo`
            .one, .c => type_expr = ptr_type.ast.child_type,
            // slices and many-item pointers can never be a method receiver
            .many, .slice => return false,
        }
    }
    switch (tree.nodeTag(type_expr)) {
        .identifier => {
            const name = offsets.identifierTokenToNameSlice(tree, tree.nodeMainToken(type_expr));
            if (std.mem.eql(u8, name, "Self")) return true;
            const name_token = container_name_token.unwrap() orelse return false;
            return std.mem.eql(u8, name, offsets.identifierTokenToNameSlice(tree, name_token));
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => return std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(type_expr)), "@This"),
        else => return false,
    }
}

/// Infers the symbol kind of a var decl from its initializer expression,
/// e.g. `const E = enum {...};` is an enumeration rather than a constant.
/// Purely syntactic; aliases like `const A = other.T;` are not resolved.
fn symbolKindFromInitExpr(tree: *const Ast, init_node: Ast.Node.Index) ?types.SymbolKind {
    switch (tree.nodeTag(init_node)) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        => return switch (tree.tokenTag(tree.nodeMainToken(init_node))) {
            .keyword_struct => .Struct,
            .keyword_enum => .Enum,
            // there is no SymbolKind that represents a union or an opaque
            .keyword_union => .Struct,
            .keyword_opaque => .Class,
            else => unreachable,
        },
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => return .Struct,
        .error_set_decl,
        .merge_error_sets,
        => return .Enum,
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const builtin_name = tree.tokenSlice(tree.nodeMainToken(init_node));
            if (std.mem.eql(u8, builtin_name, "@import") or
                std.mem.eql(u8, builtin_name, "@cImport"))
                return .Module;
            return null;
        },
        else => return null,
    }
}

pub fn getDocumentSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    if (tree.mode == .zon) {
        // Workaround: The Ast on .zon files is unusable when an error occured on the root expr
        if (tree.errors.len != 0) return try arena.alloc(types.DocumentSymbol, 0);
        return getZonDocumentSymbols(arena, tree, encoding);
    }

    var symbols: std.ArrayList(Symbol) = .empty;
    var total_symbol_count: usize = 0;

    const StackEntry = struct {
        current_symbols: *std.ArrayList(Symbol),
        last_var_decl_name_token: Ast.OptionalTokenIndex,
        parent_container: Ast.Node.Index,
    };
    var stack: std.ArrayList(StackEntry) = try .initCapacity(arena, 16);
    stack.appendAssumeCapacity(.{
        .current_symbols = &symbols,
        .last_var_decl_name_token = .none,
        .parent_container = .root,
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

        try stack.append(arena, stack.getLast().?);
        const stack_entry: *StackEntry = &stack.items[stack.items.len - 1];

        const symbol: Symbol = switch (tree.nodeTag(node)) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => blk: {
                const var_decl = tree.fullVarDecl(node).?;
                const var_decl_name_token = var_decl.ast.mut_token + 1;

                // record on function-local declarations as well so that method
                // detection inside a local container matches the local binding
                // name instead of the enclosing container's
                stack_entry.last_var_decl_name_token = .fromToken(var_decl_name_token);

                if (!ast.isContainer(tree, walker.parentNode())) continue;

                const kind: types.SymbolKind = kind: {
                    if (var_decl.ast.init_node.unwrap()) |init_node| {
                        if (symbolKindFromInitExpr(tree, init_node)) |kind| break :kind kind;
                    }
                    break :kind switch (tree.tokenTag(tree.nodeMainToken(node))) {
                        .keyword_var => .Variable,
                        .keyword_const => .Constant,
                        else => unreachable,
                    };
                };

                break :blk .{
                    .name = .{ .token = var_decl_name_token },
                    .detail = null,
                    .kind = kind,
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, var_decl_name_token),
                    .children = .empty,
                };
            },

            .test_decl => blk: {
                const test_name_token = tree.nodeData(node).opt_token_and_node[0].unwrap() orelse continue;

                break :blk .{
                    .name = .{ .token = test_name_token },
                    .kind = .Function, // there is no SymbolKind that represents a test
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, test_name_token),
                    .children = .empty,
                };
            },

            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => |tag| blk: {
                if (tag != .fn_decl and tree.nodeTag(walker.parentNode()) == .fn_decl) continue;
                var buffer: [1]Ast.Node.Index = undefined;
                const fn_info = tree.fullFnProto(&buffer, node).?;
                const name_token = fn_info.name_token orelse continue;

                break :blk .{
                    .name = .{ .token = name_token },
                    .detail = analysis.getFunctionSignature(tree, fn_info),
                    .kind = if (isMethod(tree, fn_info, stack_entry.last_var_decl_name_token))
                        .Method
                    else
                        .Function,
                    .loc = offsets.nodeToLoc(tree, node),
                    .selection_loc = offsets.tokenToLoc(tree, name_token),
                    .children = .empty,
                };
            },

            .container_field_init,
            .container_field_align,
            .container_field,
            => blk: {
                const container_kind = switch (tree.nodeTag(stack_entry.parent_container)) {
                    .root => .keyword_struct,
                    .container_decl,
                    .container_decl_trailing,
                    .container_decl_arg,
                    .container_decl_arg_trailing,
                    .container_decl_two,
                    .container_decl_two_trailing,
                    => tree.tokenTag(tree.nodeMainToken(stack_entry.parent_container)),
                    .tagged_union,
                    .tagged_union_trailing,
                    .tagged_union_enum_tag,
                    .tagged_union_enum_tag_trailing,
                    .tagged_union_two,
                    .tagged_union_two_trailing,
                    => .keyword_union,
                    else => unreachable,
                };

                const kind: types.SymbolKind = switch (container_kind) {
                    .keyword_struct => .Field,
                    .keyword_union => .Field,
                    .keyword_enum => .EnumMember,
                    .keyword_opaque => continue,
                    else => unreachable,
                };

                var container_field = tree.fullContainerField(node).?;
                switch (container_kind) {
                    .keyword_struct => {},
                    .keyword_enum, .keyword_union => container_field.convertToNonTupleLike(tree),
                    else => unreachable,
                }
                if (container_field.ast.tuple_like) continue;

                const decl_name_token = container_field.ast.main_token;

                if (tree.tokenTag(decl_name_token) != .identifier) {
                    _ = ast.identifierTokenFromIdentifierNode; // possibly related
                    continue;
                }

                // the `_` marker of a non-exhaustive enum is not a member
                if (kind == .EnumMember and std.mem.eql(u8, tree.tokenSlice(decl_name_token), "_")) continue;

                const guessed_container_name = if (stack_entry.last_var_decl_name_token.unwrap()) |name_token|
                    offsets.identifierTokenToNameSlice(tree, name_token)
                else
                    null;

                break :blk .{
                    .name = .{ .token = decl_name_token },
                    .detail = guessed_container_name,
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
            => {
                stack_entry.parent_container = node;
                continue;
            },
            else => continue,
        };

        switch (tree.tokenTag(symbol.name.token)) {
            .identifier, .string_literal => {},
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

/// The symbol kind of a ZON value, following the mapping that the JSON
/// language service uses for JSON documents (objects are modules).
fn zonSymbolKind(tree: *const Ast, node: Ast.Node.Index) types.SymbolKind {
    switch (tree.nodeTag(node)) {
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        => return .Module,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        => return .Array,
        .string_literal,
        .multiline_string_literal,
        => return .String,
        .number_literal,
        .char_literal,
        .negation,
        => return .Number,
        .enum_literal => return .EnumMember,
        .identifier => {
            const name = offsets.identifierTokenToNameSlice(tree, tree.nodeMainToken(node));
            if (std.mem.eql(u8, name, "true") or std.mem.eql(u8, name, "false")) return .Boolean;
            if (std.mem.eql(u8, name, "null")) return .Null;
            if (std.mem.eql(u8, name, "nan") or std.mem.eql(u8, name, "inf")) return .Number;
            return .Constant;
        },
        else => return .Constant,
    }
}

/// Outlines the value tree of a ZON document: struct init fields become
/// symbols named by their field name, array init elements by their index.
fn getZonDocumentSymbols(
    arena: std.mem.Allocator,
    tree: *const Ast,
    encoding: offsets.Encoding,
) error{OutOfMemory}![]types.DocumentSymbol {
    var symbols: std.ArrayList(Symbol) = .empty;
    var total_symbol_count: usize = 0;

    const StackEntry = struct {
        current_symbols: *std.ArrayList(Symbol),
        naming: enum { skip, struct_fields, array_elements },
        next_element_index: usize,
    };
    var stack: std.ArrayList(StackEntry) = try .initCapacity(arena, 16);
    stack.appendAssumeCapacity(.{
        .current_symbols = &symbols,
        .naming = .skip,
        .next_element_index = 0,
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

        try stack.append(arena, stack.getLast().?);
        const stack_entry: *StackEntry = &stack.items[stack.items.len - 1];
        const parent_entry: *StackEntry = &stack.items[stack.items.len - 2];

        stack_entry.naming = switch (tree.nodeTag(node)) {
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            => .struct_fields,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init_dot_two,
            .array_init_dot_two_comma,
            => .array_elements,
            else => .skip,
        };
        stack_entry.next_element_index = 0;

        const value_loc = offsets.nodeToLoc(tree, node);
        const symbol: Symbol = switch (parent_entry.naming) {
            .skip => continue,
            .struct_fields => blk: {
                const first_token = tree.firstToken(node);
                if (first_token < 2) continue;
                // the value is preceded by `.name = `
                const name_token = first_token - 2;
                if (tree.tokenTag(name_token) != .identifier) continue;
                break :blk .{
                    .name = .{ .token = name_token },
                    .kind = zonSymbolKind(tree, node),
                    .loc = .{
                        .start = offsets.tokenToLoc(tree, name_token - 1).start,
                        .end = value_loc.end,
                    },
                    .selection_loc = offsets.tokenToLoc(tree, name_token),
                    .children = .empty,
                };
            },
            .array_elements => blk: {
                const index = parent_entry.next_element_index;
                parent_entry.next_element_index += 1;
                break :blk .{
                    .name = .{ .text = try std.fmt.allocPrint(arena, "{d}", .{index}) },
                    .kind = zonSymbolKind(tree, node),
                    .loc = value_loc,
                    .selection_loc = value_loc,
                    .children = .empty,
                };
            },
        };

        try parent_entry.current_symbols.append(arena, symbol);
        stack_entry.current_symbols = &parent_entry.current_symbols.items[parent_entry.current_symbols.items.len - 1].children;
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
                .name = switch (symbol.name) {
                    .token => |token| tokenNameMaybeQuotes(tree, token),
                    .text => |text| text,
                },
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
