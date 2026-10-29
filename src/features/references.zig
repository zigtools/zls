//! Implementation of [`textDocument/references`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_references)

const std = @import("std");
const Ast = @import("zirp").Ast;

const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const lsp = @import("lsp");
const types = lsp.types;
const Uri = @import("../Uri.zig");
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const tracy = @import("tracy");

pub const Error = error{ OutOfMemory, Canceled, InvalidParams };

pub fn @"textDocument/rename"(server: *Server, arena: std.mem.Allocator, request: types.rename.Params) Error!?types.WorkspaceEdit {
    const response = try referencesHandler(server, arena, .{ .rename = request });
    return if (response) |rep| rep.rename else null;
}

pub fn @"textDocument/references"(server: *Server, arena: std.mem.Allocator, request: types.reference.Params) Error!?[]types.Location {
    const response = try referencesHandler(server, arena, .{ .references = request });
    return if (response) |rep| rep.references else null;
}

pub fn @"textDocument/documentHighlight"(server: *Server, arena: std.mem.Allocator, request: types.DocumentHighlight.Params) Error!?[]types.DocumentHighlight {
    const response = try referencesHandler(server, arena, .{ .highlight = request });
    return if (response) |rep| rep.highlight else null;
}

pub fn @"textDocument/prepareRename"(server: *Server, arena: std.mem.Allocator, request: types.prepare_rename.Params) Error!?types.prepare_rename.Result {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);
    const name_loc = offsets.identifierLocFromIndex(&handle.tree, source_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    return .{
        .prepare_rename_placeholder = .{
            .range = offsets.locToRange(handle.tree.source, name_loc, server.offset_encoding),
            .placeholder = name,
        },
    };
}

fn labelReferences(
    allocator: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    decl: @FieldType(Analyser.Declaration, "label"),
    encoding: offsets.Encoding,
    include_decl: bool,
) error{OutOfMemory}!std.ArrayList(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = &handle.tree;

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.identifier;
    const last_tok = ast.lastToken(tree, decl.expr.idx);

    var locations: std.ArrayList(types.Location) = .empty;
    errdefer locations.deinit(allocator);

    if (include_decl) {
        // The first token is always going to be the label
        try locations.append(allocator, .{
            .uri = handle.uri.raw,
            .range = offsets.tokenToRange(tree, first_tok, encoding),
        });
    }

    var curr_tok = first_tok.add(1);
    while (@backingInt(curr_tok) < @backingInt(last_tok.add(-2))) : (curr_tok = curr_tok.add(1)) {
        const curr_id = curr_tok.tag(tree);

        if (curr_id != .@"break" and curr_id != .@"continue") continue;
        if (curr_tok.add(1).tag(tree) != .@":") continue;
        if (curr_tok.add(2).tag(tree) != .name) continue;

        if (!std.mem.eql(u8, curr_tok.add(2).slice(tree), first_tok.slice(tree))) continue;

        try locations.append(allocator, .{
            .uri = handle.uri.raw,
            .range = offsets.tokenToRange(tree, curr_tok.add(2), encoding),
        });
    }

    return locations;
}

const Builder = struct {
    locations: std.ArrayList(types.Location) = .empty,
    /// this is the declaration we are searching for
    target_symbol: Analyser.DeclWithHandle,
    /// the decl is local to a function, block, etc
    local_only_decl: bool,
    /// Whether the `target_symbol` has been added
    did_add_target_symbol: bool = false,
    resolve_aliases: bool,
    analyser: *Analyser,
    encoding: offsets.Encoding,

    fn add(self: *Builder, handle: *DocumentStore.Handle, token_index: Ast.Token.Index) error{OutOfMemory}!void {
        if (self.target_symbol.handle == handle and
            self.target_symbol.nameToken() == token_index)
        {
            if (self.did_add_target_symbol) return;
            self.did_add_target_symbol = true;
        }
        try self.locations.append(self.analyser.arena, .{
            .uri = handle.uri.raw,
            .range = offsets.tokenToRange(&handle.tree, token_index, self.encoding),
        });
    }

    fn collectReferences(self: *Builder, handle: *DocumentStore.Handle, node: Ast.Node.Index) Analyser.Error!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const arena = self.analyser.arena;
        try referenceNode(self, handle, node);
        var walker: ast.Walker = try .init(arena, &handle.tree, node);
        defer walker.deinit(arena);
        while (try walker.nextIgnoreClose(arena, &handle.tree)) |child| {
            try referenceNode(self, handle, child);
        }
    }

    fn referenceNode(
        builder: *Builder,
        handle: *DocumentStore.Handle,
        node: Ast.Node.Index,
    ) Analyser.Error!void {
        const tree = &handle.tree;
        const target_symbol_name = offsets.identifierTokenToNameSlice(
            &builder.target_symbol.handle.tree,
            builder.target_symbol.nameToken(),
        );

        var candidate: Analyser.DeclWithHandle, const name_token = candidate: switch (node.tag(tree)) {
            .leaf,
            .decl_test,
            => |tag| {
                const name_token = switch (tag) {
                    .leaf => ast.identifierTokenFromIdentifierNode(tree, node) orelse return,
                    .decl_test => blk: {
                        const decl_test: Ast.Member.Test = node.cast(.decl_test, tree).?;
                        const name_token = decl_test.name(tree) orelse return;
                        if (name_token.tag(tree) != .name) return;
                        break :blk name_token;
                    },
                    else => unreachable,
                };
                const name = offsets.identifierTokenToNameSlice(tree, name_token);
                const is_escaped_identifier = tree.source[name_token.byteOffset(tree)] == '@';

                if (!is_escaped_identifier) {
                    if (std.mem.eql(u8, name, "_")) return;
                    if (std.zig.isPrimitive(name)) return;
                }

                if (!std.mem.eql(u8, name, target_symbol_name)) return;

                const candidate = try builder.analyser.lookupSymbolGlobal(
                    handle,
                    name,
                    name_token.byteOffset(tree),
                ) orelse return;
                break :candidate .{ candidate, name_token };
            },
            .expr_dot_access => {
                if (builder.local_only_decl) return;
                const expr: Ast.Expr.DotAccess = node.cast(.expr_dot_access, tree).?;
                const field_token = expr.rhs.token(tree);
                const name = offsets.identifierTokenToNameSlice(tree, field_token);
                if (!std.mem.eql(u8, name, target_symbol_name)) return;

                const lhs = try builder.analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle)) orelse return;
                const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                const candidate = try deref_lhs.lookupSymbol(builder.analyser, name) orelse return;
                break :candidate .{ candidate, field_token };
            },
            .expr_init => {
                if (builder.local_only_decl) return;
                const expr: Ast.Expr.Init = node.cast(.expr_init, tree).?;
                var it = expr.fields.iter(tree);
                while (it.next(tree)) |field_idx| { // the node of `value` in `.name = value`
                    const field = field_idx.get(tree);
                    const struct_field = switch (field) {
                        .struct_field => |idx| idx.get(tree),
                        .tuple_field => continue,
                    };

                    const name_token = struct_field.name.token(tree);
                    const name = offsets.identifierTokenToNameSlice(tree, name_token);
                    if (!std.mem.eql(u8, name, target_symbol_name)) continue;

                    const nodes = if (expr.type) |type_expr|
                        &.{type_expr.idx}
                    else
                        try ast.nodesOverlappingIndex(
                            builder.analyser.arena,
                            tree,
                            name_token.byteOffset(tree),
                        );

                    const candidate, _ = try builder.analyser.lookupSymbolFieldInit(
                        handle,
                        name,
                        nodes[0],
                        nodes[1..],
                    ) orelse return;

                    // if we get here then we know that the name of the field matched
                    // and duplicate fields are invalid so just return early
                    break :candidate .{ candidate, name_token };
                }
                return;
            },
            .leaf_enum_literal => {
                if (builder.local_only_decl) return;
                const name_token = node.mainToken(tree);
                const name = offsets.identifierTokenToNameSlice(&handle.tree, name_token);
                if (!std.mem.eql(u8, name, target_symbol_name)) return;
                const candidate, _ = try builder.analyser.getSymbolEnumLiteral(handle, name_token.byteOffset(tree), name) orelse return;
                break :candidate .{ candidate, name_token };
            },
            inline .var_local, .var_global => |t| {
                if (builder.local_only_decl) return;
                const var_decl = node.cast(t, tree).?;

                const alias_name_token = var_decl.name(tree) orelse return;
                const alias_name = offsets.identifierTokenToNameSlice(&handle.tree, alias_name_token);
                if (!std.mem.eql(u8, alias_name, target_symbol_name)) return;

                switch (var_decl.mutability.get(tree)) {
                    .@"const" => {},
                    .@"var" => return,
                }

                const opt_init_expr: ?Ast.Expr.Index = var_decl.init;
                const init_expr = opt_init_expr orelse return;

                const dot_access_node = init_expr.cast(.dot_access, tree) orelse return;
                const dot_access: Ast.Expr.DotAccess = dot_access_node.get(tree);

                const field_token = dot_access.rhs.token(tree);
                const field_name = offsets.identifierTokenToNameSlice(tree, field_token);
                if (!std.mem.eql(u8, field_name, target_symbol_name)) return;

                const lhs = try builder.analyser.resolveTypeOfNode(.of(dot_access.lhs.idx, handle)) orelse return;
                const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                const candidate = try deref_lhs.lookupSymbol(builder.analyser, field_name) orelse return;
                break :candidate .{ candidate, alias_name_token };
            },
            else => return,
        };

        if (builder.resolve_aliases) {
            candidate = try builder.analyser.resolveVarDeclAlias(candidate) orelse candidate;
        }

        if (builder.target_symbol.eql(candidate)) {
            try builder.add(handle, name_token);
        }
    }
};

fn symbolReferences(
    analyser: *Analyser,
    request: GeneralReferencesRequest,
    root_symbol: Analyser.DeclWithHandle,
    encoding: offsets.Encoding,
    /// `types.reference.Context.includeDeclaration`
    include_decl: bool,
    /// The file on which the request was initiated.
    current_handle: *DocumentStore.Handle,
) Analyser.Error!std.ArrayList(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(root_symbol.decl != .label); // use `labelReferences` instead

    const dealiased_symbol = try analyser.resolveVarDeclAlias(root_symbol) orelse root_symbol;

    const target_symbol, const resolve_aliases = switch (request) {
        .highlight, .rename => .{ root_symbol, dealiased_symbol.eql(root_symbol) },
        .references => .{ dealiased_symbol, true },
    };

    const doc_scope = try target_symbol.handle.getDocumentScope();
    const source_index = target_symbol.nameToken().byteOffset(&target_symbol.handle.tree);
    const scope_index = Analyser.innermostScopeAtIndexWithTag(doc_scope, source_index, .init(.{
        .block = true,
        .container = true,
        .function = false,
        .other = false,
    })).unwrap().?;
    const scope_node = doc_scope.getScopeAstNode(scope_index).?;

    // If `local_node != null`, references to the declaration can only be
    // found inside of the given ast node.
    const local_node: ?Ast.Node.Index = switch (target_symbol.decl) {
        .ast_node => switch (doc_scope.getScopeTag(scope_index)) {
            .block => scope_node,
            .container => null,
            .function, .other => unreachable,
        },
        .optional_payload,
        .error_union_payload,
        .error_union_error,
        .for_loop_payload,
        .assign_destructure,
        => scope_node,
        .switch_payload,
        .switch_inline_tag_payload,
        => |payload| payload.node.idx,
        .function_parameter => |payload| payload.func,
        .label => unreachable, // handled separately by labelReferences
        .error_token => return .empty,
    };

    var builder: Builder = .{
        .analyser = analyser,
        .target_symbol = target_symbol,
        .local_only_decl = local_node != null,
        .resolve_aliases = resolve_aliases,
        .encoding = encoding,
    };

    blk: {
        if (!include_decl) break :blk;
        if (request == .highlight and !target_symbol.handle.uri.eql(current_handle.uri)) break :blk;
        try builder.add(target_symbol.handle, target_symbol.nameToken());
    }

    try builder.collectReferences(current_handle, local_node orelse .root);

    const workspace = local_node == null and request != .highlight and target_symbol.isPublic();
    if (workspace) {
        var uris = try gatherWorkspaceReferenceCandidates(
            analyser.store,
            analyser.arena,
            current_handle,
            target_symbol.handle,
        );
        for (uris.keys()) |uri| {
            if (uri.eql(current_handle.uri)) continue;
            const dependency_handle = try analyser.store.getOrLoadHandle(uri) orelse continue;
            try builder.collectReferences(dependency_handle, .root);
        }
    }

    return builder.locations;
}

fn gatherWorkspaceReferenceCandidates(
    store: *DocumentStore,
    arena: std.mem.Allocator,
    /// The file on which the request was initiated.
    root_handle: *DocumentStore.Handle,
    /// The file which contains the symbol that is being searched for.
    target_handle: *DocumentStore.Handle,
) Analyser.Error!Uri.ArrayHashMap(void) {
    if (DocumentStore.supports_build_system) no_build_file: {
        const resolved = switch (try root_handle.getAssociatedBuildFile(store)) {
            .unresolved => return .empty, // this should await instead
            .none => break :no_build_file,
            .resolved => |resolved| resolved,
        };

        const root_module_root_uri: Uri = try .fromPath(arena, resolved.root_source_file);

        var found_uris: Uri.ArrayHashMap(void) = .empty;
        try found_uris.put(arena, root_module_root_uri, {});

        if (!root_handle.uri.eql(target_handle.uri)) {
            switch (try target_handle.getAssociatedBuildFile(store)) {
                .unresolved, .none => {},
                .resolved => |resolved2| {
                    const target_module_root_uri: Uri = try .fromPath(arena, resolved2.root_source_file);
                    // also search through the module in which the symbol has been defined
                    try found_uris.put(arena, target_module_root_uri, {});
                },
            }
        }

        var i: usize = 0;
        while (i < found_uris.count()) : (i += 1) {
            const uri = found_uris.keys()[i];
            const handle = try store.getOrLoadHandle(uri) orelse continue;

            try found_uris.ensureUnusedCapacity(arena, handle.file_imports.len);
            for (handle.file_imports) |import_uri| found_uris.putAssumeCapacity(import_uri, {});
        }
        return found_uris;
    }

    var per_file_dependants: Uri.ArrayHashMap(std.ArrayList(Uri)) = .empty;

    var it: DocumentStore.HandleIterator = .{ .store = store };
    while (it.next()) |handle| {
        for (handle.file_imports) |import_uri| {
            const gop = try per_file_dependants.getOrPutValue(arena, import_uri, .empty);
            try gop.value_ptr.append(arena, handle.uri);
        }
    }

    var found_uris: Uri.ArrayHashMap(void) = .empty;
    try found_uris.put(arena, target_handle.uri, {});

    var i: usize = 0;
    while (i < found_uris.count()) : (i += 1) {
        const uri = found_uris.keys()[i];
        const dependants: std.ArrayList(Uri) = per_file_dependants.get(uri) orelse .empty;
        try found_uris.ensureUnusedCapacity(arena, dependants.items.len);
        for (dependants.items) |dependant_uri| found_uris.putAssumeCapacity(dependant_uri, {});
    }

    return found_uris;
}

fn controlFlowReferences(
    allocator: std.mem.Allocator,
    token_handle: Analyser.TokenWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
) error{OutOfMemory}!std.ArrayList(types.Location) {
    const handle = token_handle.handle;
    const tree = &handle.tree;
    const kw_token = token_handle.token;

    var results: std.ArrayList(Ast.Token.Index) = .empty;
    defer results.deinit(allocator);

    switch (kw_token.tag(tree)) {
        .@"continue",
        .@"break",
        => {
            const nodes = try ast.nodesOverlappingIndex(allocator, tree, kw_token.byteOffset(&handle.tree));
            defer allocator.free(nodes);

            const maybe_label = blk: {
                if (@backingInt(kw_token.add(2)) >= tree.tokens.len()) break :blk null;
                if (kw_token.add(1).tag(tree) != .@":") break :blk null;
                if (kw_token.add(2).tag(tree) != .name) break :blk null;
                break :blk offsets.identifierTokenToNameSlice(tree, kw_token.add(2));
            };
            for (nodes) |node| switch (node.tag(tree)) {
                .expr_for,
                .expr_while,
                => {
                    // if the break/continue is unlabeled it must belong to the first loop we encounter
                    const main_token = node.mainToken(tree);
                    const label = maybe_label orelse break try results.append(allocator, main_token);
                    const loop_label = if (ast.isTokenPrecededByTags(tree, main_token, &.{ .name, .@":" }))
                        offsets.identifierTokenToNameSlice(tree, main_token.add(-2))
                    else
                        continue;
                    if (std.mem.eql(u8, label, loop_label)) {
                        try results.append(allocator, main_token);
                    }
                },
                .expr_switch => {
                    const label = maybe_label orelse continue;
                    const main_token = node.mainToken(tree);
                    const switch_label = if (main_token.tag(tree) == .name)
                        offsets.identifierTokenToNameSlice(tree, main_token)
                    else
                        continue;
                    if (std.mem.eql(u8, label, switch_label)) {
                        try results.append(
                            allocator,
                            // we already know the switch is labeled so we can just offset
                            main_token.add(2),
                        );
                    }
                },
                else => {},
            };
        },
        .@"for",
        .@"while",
        .@"switch",
        => |tag| {
            const maybe_label = if (ast.isTokenPrecededByTags(tree, kw_token, &.{ .name, .@":" }))
                offsets.identifierTokenToNameSlice(tree, kw_token.add(-2))
            else
                null;

            if (tag == .@"switch" and maybe_label == null) return .empty;

            const nodes = try ast.nodesOverlappingIndex(allocator, tree, kw_token.byteOffset(tree));
            defer allocator.free(nodes);

            var walker: ast.Walker = try .init(allocator, tree, nodes[0]);
            defer walker.deinit(allocator);

            _ = try walker.nextIgnoreClose(allocator, tree);

            var loop_depth: usize = 1;

            while (try walker.next(allocator, tree)) |event| {
                switch (event) {
                    .open => |node| switch (node.tag(tree)) {
                        inline .expr_break, .expr_continue => |t| {
                            const label_token = node.cast(t, tree).?.label(tree);
                            if (label_token) |actual_label_token| {
                                const actual_label = offsets.identifierTokenToNameSlice(tree, actual_label_token);
                                if (maybe_label) |expected_label| {
                                    if (!std.mem.eql(u8, expected_label, actual_label)) continue;
                                }
                            } else if (loop_depth > 1) continue;
                            try results.append(allocator, node.mainToken(tree));
                        },

                        .expr_while,
                        .expr_for,
                        => {
                            if (maybe_label == null) {
                                walker.skip();
                            } else {
                                loop_depth += 1;
                            }
                        },
                        else => {},
                    },
                    .close => |node| switch (node.tag(tree)) {
                        .expr_while,
                        .expr_for,
                        => {
                            if (maybe_label != null) {
                                loop_depth -= 1;
                            }
                        },
                        else => {},
                    },
                }
            }
        },
        else => return .empty,
    }

    var locations: std.ArrayList(types.Location) = try .initCapacity(allocator, results.items.len + @intFromBool(include_decl));
    errdefer locations.deinit(allocator);

    if (include_decl) {
        locations.appendAssumeCapacity(.{
            .uri = handle.uri.raw,
            .range = offsets.tokenToRange(tree, kw_token, encoding),
        });
    }

    for (results.items) |token| {
        locations.appendAssumeCapacity(.{
            .uri = handle.uri.raw,
            .range = offsets.tokenToRange(tree, token, encoding),
        });
    }
    return locations;
}

const CallBuilder = struct {
    callsites: std.ArrayList(Analyser.NodeWithHandle) = .empty,
    /// this is the declaration we are searching for
    target_decl: Analyser.DeclWithHandle,
    analyser: *Analyser,

    fn add(self: *CallBuilder, handle: *DocumentStore.Handle, call_node: Ast.Node.Index) error{OutOfMemory}!void {
        try self.callsites.append(self.analyser.arena, .{
            .handle = handle,
            .node = call_node,
        });
    }

    fn collectReferences(self: *CallBuilder, handle: *DocumentStore.Handle, node: Ast.Node.Index) Analyser.Error!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const arena = self.analyser.arena;
        var walker: ast.Walker = try .init(arena, &handle.tree, node);
        defer walker.deinit(arena);
        while (try walker.nextIgnoreClose(arena, &handle.tree)) |child| {
            try referenceNode(self, handle, child);
        }
    }

    fn referenceNode(
        builder: *CallBuilder,
        handle: *DocumentStore.Handle,
        node: Ast.Node.Index,
    ) Analyser.Error!void {
        const tree = &handle.tree;
        const call_expr: Ast.Expr.Call = node.cast(.expr_call, tree) orelse return;
        switch (call_expr.callee.idx.tag(tree)) {
            .leaf => {
                const name_token = node.mainToken(tree);
                if (name_token.tag(tree) != .name) return;
                const name = offsets.identifierTokenToNameSlice(tree, name_token);

                const child = (try builder.analyser.lookupSymbolGlobal(
                    handle,
                    name,
                    name_token.byteOffset(tree),
                )) orelse return;

                if (builder.target_decl.eql(child)) {
                    try builder.add(handle, node);
                }
            },
            .expr_dot_access => {
                const expr: Ast.Expr.DotAccess = node.cast(.expr_dot_access, tree).?;
                const field_name = expr.rhs.token(tree);
                const lhs = (try builder.analyser.resolveTypeOfNode(.of(expr.lhs.idx, handle))) orelse return;
                const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                const symbol = offsets.tokenToSlice(tree, field_name);
                const child = (try deref_lhs.lookupSymbol(builder.analyser, symbol)) orelse return;

                if (builder.target_decl.eql(child)) {
                    try builder.add(handle, node);
                }
            },
            else => {},
        }
    }
};

pub fn callsiteReferences(
    analyser: *Analyser,
    decl_handle: Analyser.DeclWithHandle,
    /// search other files for references
    workspace: bool,
) Analyser.Error!std.ArrayList(Analyser.NodeWithHandle) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl_handle.decl == .ast_node);

    var builder: CallBuilder = .{
        .analyser = analyser,
        .target_decl = decl_handle,
    };

    try builder.collectReferences(decl_handle.handle, .root);

    if (workspace) {
        var uris = try gatherWorkspaceReferenceCandidates(
            analyser.store,
            analyser.arena,
            decl_handle.handle,
            decl_handle.handle,
        );
        for (uris.keys()) |uri| {
            if (uri.eql(decl_handle.handle.uri)) continue;
            const dependency_handle = try analyser.store.getOrLoadHandle(uri) orelse continue;
            try builder.collectReferences(dependency_handle, .root);
        }
    }

    return builder.callsites;
}

const GeneralReferencesRequest = union(enum) {
    rename: types.rename.Params,
    references: types.reference.Params,
    highlight: types.DocumentHighlight.Params,

    fn uri(self: @This()) []const u8 {
        return switch (self) {
            .rename => |rename| rename.textDocument.uri,
            .references => |ref| ref.textDocument.uri,
            .highlight => |highlight| highlight.textDocument.uri,
        };
    }

    fn position(self: @This()) types.Position {
        return switch (self) {
            .rename => |rename| rename.position,
            .references => |ref| ref.position,
            .highlight => |highlight| highlight.position,
        };
    }
};

const GeneralReferencesResponse = union {
    rename: types.WorkspaceEdit,
    references: []types.Location,
    highlight: []types.DocumentHighlight,
};

fn referencesHandler(
    server: *Server,
    arena: std.mem.Allocator,
    request: GeneralReferencesRequest,
) Error!?GeneralReferencesResponse {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const uri = Uri.parse(arena, request.uri()) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position(), server.offset_encoding);
    const pos_context = try Analyser.getPositionContext(server.allocator, &handle.tree, source_index, true);

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    const include_decl = switch (request) {
        .references => |ref| ref.context.includeDeclaration,
        else => true,
    };

    // TODO: Make this work with branching types
    const locations = locs: {
        if (pos_context == .keyword and request != .rename) {
            break :locs try controlFlowReferences(
                arena,
                .{ .token = offsets.sourceIndexToTokenIndex(&handle.tree, source_index).preferLeft(), .handle = handle },
                server.offset_encoding,
                include_decl,
            );
        }

        const name_loc = offsets.identifierLocFromIndex(&handle.tree, source_index) orelse return null;
        const name = offsets.locToSlice(handle.tree.source, name_loc);

        const target_decl = switch (pos_context) {
            .var_access, .test_doctest_name => try analyser.lookupSymbolGlobal(handle, name, source_index),
            .field_access => |loc| z: {
                const held_loc = offsets.locMerge(loc, name_loc);
                const a = try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name);
                if (a) |b| {
                    if (b.len != 0) break :z b[0];
                }

                break :z null;
            },
            .label_access, .label_decl => try Analyser.lookupLabel(handle, name, source_index),
            .enum_literal => blk: {
                const decl, _ = try analyser.getSymbolEnumLiteral(handle, source_index, name) orelse break :blk null;
                break :blk decl;
            },
            .keyword => null,
            else => null,
        } orelse return null;

        break :locs switch (target_decl.decl) {
            .label => |payload| try labelReferences(
                arena,
                target_decl.handle,
                payload,
                server.offset_encoding,
                include_decl,
            ),
            else => try symbolReferences(
                &analyser,
                request,
                target_decl,
                server.offset_encoding,
                include_decl,
                handle,
            ),
        };
    };

    switch (request) {
        .rename => |rename| {
            const escaped_rename = try arena.print("{f}", .{std.zig.fmtId(rename.newName)});
            var changes: std.array_hash_map.String(std.ArrayList(types.TextEdit)) = .empty;

            for (locations.items) |loc| {
                const gop = try changes.getOrPutValue(arena, loc.uri, .empty);
                try gop.value_ptr.append(arena, .{
                    .range = loc.range,
                    .newText = escaped_rename,
                });
            }

            var new_changes: lsp.parser.Map(types.DocumentUri, []const types.TextEdit) = .{};
            try new_changes.map.ensureTotalCapacity(arena, changes.count());

            var changes_it = changes.iterator();
            while (changes_it.next()) |entry| {
                new_changes.map.putAssumeCapacityNoClobber(entry.key_ptr.*, try entry.value_ptr.toOwnedSlice(arena));
            }

            return .{ .rename = .{ .changes = new_changes } };
        },
        .references => return .{ .references = locations.items },
        .highlight => {
            var highlights: std.ArrayList(types.DocumentHighlight) = try .initCapacity(arena, locations.items.len);
            for (locations.items) |loc| {
                std.debug.assert(std.mem.eql(u8, handle.uri.raw, loc.uri));
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
            return .{ .highlight = highlights.items };
        },
    }
}
