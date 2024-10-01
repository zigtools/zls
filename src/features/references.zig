//! Implementation of [`textDocument/references`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_references)

const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_references);

const Server = @import("../Server.zig");
const DocumentScope = @import("../DocumentScope.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const lsp = @import("lsp");
const types = lsp.types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const tracy = @import("tracy");

fn labelReferences(
    allocator: std.mem.Allocator,
    decl: Analyser.DeclWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
) error{OutOfMemory}!std.ArrayListUnmanaged(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl.decl == .label); // use `symbolReferences` instead
    const handle = decl.handle;
    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.decl.label.identifier;
    const last_tok = ast.lastToken(tree, decl.decl.label.block);

    var locations = std.ArrayListUnmanaged(types.Location){};
    errdefer locations.deinit(allocator);

    if (include_decl) {
        // The first token is always going to be the label
        try locations.append(allocator, .{
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, first_tok, encoding),
        });
    }

    var curr_tok = first_tok + 1;
    while (curr_tok < last_tok - 2) : (curr_tok += 1) {
        const curr_id = token_tags[curr_tok];

        if (curr_id != .keyword_break and curr_id != .keyword_continue) continue;
        if (token_tags[curr_tok + 1] != .colon) continue;
        if (token_tags[curr_tok + 2] != .identifier) continue;

        if (!std.mem.eql(u8, tree.tokenSlice(curr_tok + 2), tree.tokenSlice(first_tok))) continue;

        try locations.append(allocator, .{
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, curr_tok + 2, encoding),
        });
    }

    return locations;
}

const Builder = struct {
    allocator: std.mem.Allocator,
    locations: std.ArrayListUnmanaged(types.Location) = .{},
    /// this is the declaration we are searching for
    decl_handle: Analyser.DeclWithHandle,
    analyser: *Analyser,
    encoding: offsets.Encoding,

    const Context = struct {
        builder: *Builder,
        handle: *DocumentStore.Handle,
    };

    fn deinit(self: *Builder) void {
        self.locations.deinit(self.allocator);
    }

    fn add(self: *Builder, handle: *DocumentStore.Handle, token_index: Ast.TokenIndex) error{OutOfMemory}!void {
        try self.locations.append(self.allocator, .{
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, token_index, self.encoding),
        });
    }

    fn collectReferences(self: *Builder, handle: *DocumentStore.Handle, node: Ast.Node.Index) error{OutOfMemory}!void {
        const context = Context{
            .builder = self,
            .handle = handle,
        };
        try referenceNode(&context, handle.tree, node);
        try ast.iterateChildrenRecursive(handle.tree, node, &context, error{OutOfMemory}, referenceNode);
    }

    fn referenceNode(self: *const Context, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
        const builder = self.builder;
        const handle = self.handle;

        const node_tags = tree.nodes.items(.tag);
        const datas = tree.nodes.items(.data);

        switch (node_tags[node]) {
            .identifier,
            .test_decl,
            => |tag| {
                const name_token, const name = switch (tag) {
                    .identifier => blk: {
                        const name_token = ast.identifierTokenFromIdentifierNode(tree, node) orelse return;
                        break :blk .{
                            name_token,
                            offsets.identifierTokenToNameSlice(tree, name_token),
                        };
                    },
                    .test_decl => ast.testDeclNameAndToken(tree, node) orelse return,
                    else => unreachable,
                };

                const child = try builder.analyser.lookupSymbolGlobal(
                    handle,
                    name,
                    tree.tokens.items(.start)[name_token],
                ) orelse return;

                // If the lookup result is the same as the identifier being
                // searched, then its the declaration itself, so skip it.
                // This is useful for enums:
                // const Number = enum { zero };
                // Here, `zero` is an `identifier`, but also the lookup result.
                // we shouldn't consider this as a reference.
                const child_name_token = child.nameToken();
                const child_name_loc = offsets.identifierTokenToNameLoc(child.handle.tree, child_name_token);
                const child_name = offsets.locToSlice(child.handle.tree.source, child_name_loc);
                const name_loc = offsets.tokenToLoc(tree, name_token);
                if (child_name_loc.start == name_loc.start and
                    child_name_loc.end == name_loc.end and
                    std.mem.eql(u8, child_name, name))
                {
                    return;
                }

                if (builder.decl_handle.eql(child)) {
                    try builder.add(handle, name_token);
                }
            },
            .field_access => {
                const lhs = try builder.analyser.resolveTypeOfNode(.{ .node = datas[node].lhs, .handle = handle }) orelse return;
                const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                const symbol = offsets.identifierTokenToNameSlice(tree, datas[node].rhs);
                const child = try deref_lhs.lookupSymbol(builder.analyser, symbol) orelse return;

                if (builder.decl_handle.eql(child)) {
                    try builder.add(handle, datas[node].rhs);
                }
            },
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init,
            .struct_init_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const struct_init = tree.fullStructInit(&buffer, node).?;
                for (struct_init.ast.fields) |value_node| { // the node of `value` in `.name = value`
                    const name_token = tree.firstToken(value_node) - 2; // math our way two token indexes back to get the `name`
                    const name_loc = offsets.tokenToLoc(tree, name_token);
                    const name = offsets.locToSlice(tree.source, name_loc);

                    var nodes = [_]Ast.Node.Index{datas[node].lhs};
                    const lookup = try builder.analyser.lookupSymbolFieldInit(handle, name, &nodes) orelse continue;

                    if (builder.decl_handle.eql(lookup)) {
                        try builder.add(handle, name_token);
                    }
                }
            },
            else => {},
        }
    }
};

fn gatherReferences(
    allocator: std.mem.Allocator,
    analyser: *Analyser,
    curr_handle: *DocumentStore.Handle,
    skip_std_references: bool,
    include_decl: bool,
    builder: anytype,
    handle_behavior: enum { get, get_or_load },
) !void {
    var dependencies = std.StringArrayHashMapUnmanaged(void){};
    defer {
        for (dependencies.keys()) |uri| {
            allocator.free(uri);
        }
        dependencies.deinit(allocator);
    }

    for (analyser.store.handles.values()) |handle| {
        if (skip_std_references and std.mem.indexOf(u8, handle.uri, "std") != null) {
            if (!include_decl or !std.mem.eql(u8, handle.uri, curr_handle.uri))
                continue;
        }

        var handle_dependencies = std.ArrayListUnmanaged([]const u8){};
        defer handle_dependencies.deinit(allocator);
        try analyser.store.collectDependencies(allocator, handle, &handle_dependencies);

        try dependencies.ensureUnusedCapacity(allocator, handle_dependencies.items.len);
        for (handle_dependencies.items) |uri| {
            const gop = dependencies.getOrPutAssumeCapacity(uri);
            if (gop.found_existing) {
                allocator.free(uri);
            }
        }
    }

    for (dependencies.keys()) |uri| {
        if (std.mem.eql(u8, uri, curr_handle.uri)) continue;
        const handle = switch (handle_behavior) {
            .get => analyser.store.getHandle(uri),
            .get_or_load => analyser.store.getOrLoadHandle(uri),
        } orelse continue;

        try builder.collectReferences(handle, 0);
    }
}

fn symbolReferences(
    allocator: std.mem.Allocator,
    analyser: *Analyser,
    request: GeneralReferencesRequest,
    decl_handle: Analyser.DeclWithHandle,
    encoding: offsets.Encoding,
    /// add `decl_handle` as a references
    include_decl: bool,
    /// exclude references from the std library
    skip_std_references: bool,
) error{OutOfMemory}!std.ArrayListUnmanaged(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl_handle.decl != .label); // use `labelReferences` instead

    var builder = Builder{
        .allocator = allocator,
        .analyser = analyser,
        .decl_handle = decl_handle,
        .encoding = encoding,
    };
    errdefer builder.deinit();

    const curr_handle = decl_handle.handle;
    if (include_decl) try builder.add(curr_handle, decl_handle.nameToken());

    switch (decl_handle.decl) {
        .ast_node => {
            try builder.collectReferences(curr_handle, 0);

            const source_index = offsets.tokenToIndex(decl_handle.handle.tree, decl_handle.nameToken());
            // highlight requests only pertain to the current document, otherwise we can try to narrow things down
            const workspace = if (request == .highlight) false else blk: {
                const doc_scope = try curr_handle.getDocumentScope();
                const scope_index = Analyser.innermostScopeAtIndex(doc_scope, source_index);
                break :blk switch (doc_scope.getScopeTag(scope_index)) {
                    .function, .block => false,
                    .container, .container_usingnamespace => decl_handle.isPublic(),
                    .other => true,
                };
            };
            if (workspace) {
                try gatherReferences(allocator, analyser, curr_handle, skip_std_references, include_decl, &builder, .get);
            }
        },
        .optional_payload,
        .error_union_payload,
        .error_union_error,
        .for_loop_payload,
        .assign_destructure,
        .switch_payload,
        => {
            try builder.collectReferences(curr_handle, 0);
        },
        .function_parameter => |payload| try builder.collectReferences(curr_handle, payload.func),
        .label => unreachable, // handled separately by labelReferences
        .error_token => {},
    }

    return builder.locations;
}

pub const Callsite = struct {
    uri: []const u8,
    call_node: Ast.Node.Index,
};

const CallBuilder = struct {
    allocator: std.mem.Allocator,
    callsites: std.ArrayListUnmanaged(Callsite) = .{},
    /// this is the declaration we are searching for
    decl_handle: Analyser.DeclWithHandle,
    analyser: *Analyser,

    const Context = struct {
        builder: *CallBuilder,
        handle: *DocumentStore.Handle,
    };

    fn deinit(self: *CallBuilder) void {
        self.callsites.deinit(self.allocator);
    }

    fn add(self: *CallBuilder, handle: *DocumentStore.Handle, call_node: Ast.Node.Index) error{OutOfMemory}!void {
        try self.callsites.append(self.allocator, .{
            .uri = handle.uri,
            .call_node = call_node,
        });
    }

    fn collectReferences(self: *CallBuilder, handle: *DocumentStore.Handle, node: Ast.Node.Index) error{OutOfMemory}!void {
        const context = Context{
            .builder = self,
            .handle = handle,
        };
        try ast.iterateChildrenRecursive(handle.tree, node, &context, error{OutOfMemory}, referenceNode);
    }

    fn referenceNode(self: *const Context, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
        const builder = self.builder;
        const handle = self.handle;

        const node_tags = tree.nodes.items(.tag);
        const datas = tree.nodes.items(.data);
        const starts = tree.tokens.items(.start);

        switch (node_tags[node]) {
            .call,
            .call_comma,
            .async_call,
            .async_call_comma,
            .call_one,
            .call_one_comma,
            .async_call_one,
            .async_call_one_comma,
            => {
                var buf: [1]Ast.Node.Index = undefined;
                const call = tree.fullCall(&buf, node).?;

                const called_node = call.ast.fn_expr;

                switch (node_tags[called_node]) {
                    .identifier => {
                        const identifier_token = ast.identifierTokenFromIdentifierNode(tree, called_node) orelse return;

                        const child = (try builder.analyser.lookupSymbolGlobal(
                            handle,
                            offsets.identifierTokenToNameSlice(tree, identifier_token),
                            starts[identifier_token],
                        )) orelse return;

                        if (builder.decl_handle.eql(child)) {
                            try builder.add(handle, node);
                        }
                    },
                    .field_access => {
                        const lhs = (try builder.analyser.resolveTypeOfNode(.{ .node = datas[called_node].lhs, .handle = handle })) orelse return;
                        const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                        const symbol = offsets.tokenToSlice(tree, datas[called_node].rhs);
                        const child = (try deref_lhs.lookupSymbol(builder.analyser, symbol)) orelse return;

                        if (builder.decl_handle.eql(child)) {
                            try builder.add(handle, node);
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
};

pub fn callsiteReferences(
    allocator: std.mem.Allocator,
    analyser: *Analyser,
    decl_handle: Analyser.DeclWithHandle,
    /// add `decl_handle` as a references
    include_decl: bool,
    /// exclude references from the std library
    skip_std_references: bool,
    /// search other files for references
    workspace: bool,
) error{OutOfMemory}!std.ArrayListUnmanaged(Callsite) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl_handle.decl == .ast_node);

    var builder = CallBuilder{
        .allocator = allocator,
        .analyser = analyser,
        .decl_handle = decl_handle,
    };
    errdefer builder.deinit();

    const curr_handle = decl_handle.handle;
    if (include_decl) try builder.add(curr_handle, decl_handle.nameToken());

    try builder.collectReferences(curr_handle, 0);

    if (!workspace) return builder.callsites;

    try gatherReferences(allocator, analyser, curr_handle, skip_std_references, include_decl, &builder, .get_or_load);

    return builder.callsites;
}

pub const GeneralReferencesRequest = union(enum) {
    rename: types.RenameParams,
    references: types.ReferenceParams,
    highlight: types.DocumentHighlightParams,

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

pub const GeneralReferencesResponse = union {
    rename: types.WorkspaceEdit,
    references: []types.Location,
    highlight: []types.DocumentHighlight,
};

pub fn referencesHandler(server: *Server, arena: std.mem.Allocator, request: GeneralReferencesRequest) Server.Error!?GeneralReferencesResponse {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.uri()) orelse return null;

    if (request.position().character <= 0) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position(), server.offset_encoding);
    const name_loc = Analyser.identifierLocFromIndex(handle.tree, source_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const pos_context = try Analyser.getPositionContext(server.allocator, handle.tree.source, source_index, true);

    var analyser = Analyser.init(
        server.allocator,
        &server.document_store,
        &server.ip,
        handle,
    );
    defer analyser.deinit();

    // TODO: Make this work with branching types
    const decl = switch (pos_context) {
        .var_access => try analyser.lookupSymbolGlobal(handle, name, source_index),
        .field_access => |loc| z: {
            const held_loc = offsets.locMerge(loc, name_loc);
            const a = try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name);
            if (a) |b| {
                if (b.len != 0) break :z b[0];
            }

            break :z null;
        },
        .label => try Analyser.lookupLabel(handle, name, source_index),
        .enum_literal => try analyser.getSymbolEnumLiteral(arena, handle, source_index, name),
        else => null,
    } orelse return null;

    const include_decl = switch (request) {
        .references => |ref| ref.context.includeDeclaration,
        else => true,
    };

    const locations = if (decl.decl == .label)
        try labelReferences(arena, decl, server.offset_encoding, include_decl)
    else
        try symbolReferences(
            arena,
            &analyser,
            request,
            decl,
            server.offset_encoding,
            include_decl,
            server.config.skip_std_references,
        );

    switch (request) {
        .rename => |rename| {
            var changes = std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.TextEdit)){};

            for (locations.items) |loc| {
                const gop = try changes.getOrPutValue(arena, loc.uri, .{});
                try gop.value_ptr.append(arena, .{
                    .range = loc.range,
                    .newText = rename.newName,
                });
            }

            // TODO can we avoid having to move map from `changes` to `new_changes`?
            var new_changes: lsp.parser.Map(types.DocumentUri, []const types.TextEdit) = .{};
            try new_changes.map.ensureTotalCapacity(arena, @intCast(changes.count()));

            var changes_it = changes.iterator();
            while (changes_it.next()) |entry| {
                new_changes.map.putAssumeCapacityNoClobber(entry.key_ptr.*, try entry.value_ptr.toOwnedSlice(arena));
            }

            return .{ .rename = .{ .changes = new_changes } };
        },
        .references => return .{ .references = locations.items },
        .highlight => {
            var highlights = try std.ArrayListUnmanaged(types.DocumentHighlight).initCapacity(arena, locations.items.len);
            const uri = handle.uri;
            for (locations.items) |loc| {
                if (!std.mem.eql(u8, loc.uri, uri)) continue;
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
            return .{ .highlight = highlights.items };
        },
    }
}
