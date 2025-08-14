//! Implementation of [`textDocument/references`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_references)

const std = @import("std");
const Ast = std.zig.Ast;

const Server = @import("../Server.zig");
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
) error{OutOfMemory}!std.ArrayList(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl.decl == .label); // use `symbolReferences` instead
    const handle = decl.handle;
    const tree = handle.tree;

    // Find while / for / block from label -> iterate over children nodes, find break and continues, change their labels if they match.
    // This case can be implemented just by scanning tokens.
    const first_tok = decl.decl.label.identifier;
    const last_tok = ast.lastToken(tree, decl.decl.label.block);

    var locations: std.ArrayList(types.Location) = .empty;
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
        const curr_id = tree.tokenTag(curr_tok);

        if (curr_id != .keyword_break and curr_id != .keyword_continue) continue;
        if (tree.tokenTag(curr_tok + 1) != .colon) continue;
        if (tree.tokenTag(curr_tok + 2) != .identifier) continue;

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
    locations: std.ArrayList(types.Location) = .empty,
    /// this is the declaration we are searching for
    decl_handle: Analyser.DeclWithHandle,
    /// the decl is local to a function, block, etc
    local_only_decl: bool,
    /// Whether the `decl_handle` has been added
    did_add_decl_handle: bool = false,
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
        if (self.decl_handle.handle == handle and
            self.decl_handle.nameToken() == token_index)
        {
            if (self.did_add_decl_handle) return;
            self.did_add_decl_handle = true;
        }
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
        const decl_name = offsets.identifierTokenToNameSlice(
            builder.decl_handle.handle.tree,
            builder.decl_handle.nameToken(),
        );

        switch (tree.nodeTag(node)) {
            .identifier,
            .test_decl,
            => |tag| {
                const name_token = switch (tag) {
                    .identifier => ast.identifierTokenFromIdentifierNode(tree, node) orelse return,
                    .test_decl => blk: {
                        const name_token = tree.nodeData(node).opt_token_and_node[0].unwrap() orelse return;
                        if (tree.tokenTag(name_token) != .identifier) return;
                        break :blk name_token;
                    },
                    else => unreachable,
                };
                const name = offsets.identifierTokenToNameSlice(tree, name_token);
                if (!std.mem.eql(u8, name, decl_name)) return;

                const child = try builder.analyser.lookupSymbolGlobal(
                    handle,
                    name,
                    tree.tokenStart(name_token),
                ) orelse return;

                if (builder.decl_handle.eql(child)) {
                    try builder.add(handle, name_token);
                }
            },
            .field_access => {
                if (builder.local_only_decl) return;
                const lhs_node, const field_token = tree.nodeData(node).node_and_token;
                const name = offsets.identifierTokenToNameSlice(tree, field_token);
                if (!std.mem.eql(u8, name, decl_name)) return;

                const lhs = try builder.analyser.resolveTypeOfNode(.of(lhs_node, handle)) orelse return;
                const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                const child = try deref_lhs.lookupSymbol(builder.analyser, name) orelse return;

                if (builder.decl_handle.eql(child)) {
                    try builder.add(handle, field_token);
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
                if (builder.local_only_decl) return;
                var buffer: [2]Ast.Node.Index = undefined;
                const struct_init = tree.fullStructInit(&buffer, node).?;
                for (struct_init.ast.fields) |value_node| { // the node of `value` in `.name = value`
                    const name_token = tree.firstToken(value_node) - 2; // math our way two token indexes back to get the `name`
                    const name = offsets.identifierTokenToNameSlice(tree, name_token);
                    if (!std.mem.eql(u8, name, decl_name)) continue;

                    const nodes = switch (tree.nodeTag(node)) {
                        .struct_init_dot,
                        .struct_init_dot_comma,
                        .struct_init_dot_two,
                        .struct_init_dot_two_comma,
                        => try ast.nodesOverlappingIndex(
                            builder.allocator,
                            tree,
                            tree.tokenStart(name_token),
                        ),
                        // if this isn't an anonymous struct the type can be determined from the `T{}` directly
                        .struct_init_one,
                        .struct_init_one_comma,
                        .struct_init,
                        .struct_init_comma,
                        => &.{node},
                        else => unreachable,
                    };

                    const lookup = try builder.analyser.lookupSymbolFieldInit(
                        handle,
                        name,
                        nodes[0],
                        nodes[1..],
                    ) orelse return;

                    if (builder.decl_handle.eql(lookup)) {
                        try builder.add(handle, name_token);
                    }
                    // if we get here then we know that the name of the field matched
                    // and duplicate fields are invalid so just return early
                    return;
                }
            },
            .enum_literal => {
                if (builder.local_only_decl) return;
                const name_token = tree.nodeMainToken(node);
                const name = offsets.identifierTokenToNameSlice(handle.tree, name_token);
                if (!std.mem.eql(u8, name, decl_name)) return;
                const lookup = try builder.analyser.getSymbolEnumLiteral(handle, tree.tokenStart(name_token), name) orelse return;

                if (builder.decl_handle.eql(lookup)) {
                    try builder.add(handle, name_token);
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
    var dependencies: std.StringArrayHashMapUnmanaged(void) = .empty;
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

        var handle_dependencies: std.ArrayList([]const u8) = .empty;
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

        try builder.collectReferences(handle, .root);
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
    curr_handle: *DocumentStore.Handle,
) error{OutOfMemory}!std.ArrayList(types.Location) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(decl_handle.decl != .label); // use `labelReferences` instead

    const doc_scope = try decl_handle.handle.getDocumentScope();
    const source_index = decl_handle.handle.tree.tokenStart(decl_handle.nameToken());
    const scope_index = Analyser.innermostScopeAtIndexWithTag(doc_scope, source_index, .init(.{
        .block = true,
        .container = true,
        .function = false,
        .other = false,
    })).unwrap().?;
    const scope_node = doc_scope.getScopeAstNode(scope_index).?;

    // If `local_node != null`, references to the declaration can only be
    // found inside of the given ast node.
    const local_node: ?Ast.Node.Index = switch (decl_handle.decl) {
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
        => |payload| payload.node,
        .function_parameter => |payload| payload.func,
        .label => unreachable, // handled separately by labelReferences
        .error_token => return .empty,
    };

    var builder: Builder = .{
        .allocator = allocator,
        .analyser = analyser,
        .decl_handle = decl_handle,
        .local_only_decl = local_node != null,
        .encoding = encoding,
    };
    errdefer builder.deinit();

    if (include_decl) try builder.add(decl_handle.handle, decl_handle.nameToken());

    try builder.collectReferences(curr_handle, local_node orelse .root);

    const workspace = local_node == null and request != .highlight and decl_handle.isPublic();
    if (workspace) {
        try gatherReferences(
            allocator,
            analyser,
            curr_handle,
            skip_std_references,
            include_decl,
            &builder,
            .get,
        );
    }

    return builder.locations;
}

const ControlFlowBuilder = struct {
    const Error = error{OutOfMemory};
    locations: std.ArrayList(types.Location) = .empty,
    encoding: offsets.Encoding,
    token_handle: Analyser.TokenWithHandle,
    allocator: std.mem.Allocator,
    label: ?[]const u8 = null,
    last_loop: Ast.TokenIndex,
    nodes: []const Ast.Node.Index,
    fn iter(builder: *ControlFlowBuilder, tree: Ast, node: Ast.Node.Index) Error!void {
        const main_token = tree.nodeMainToken(node);
        switch (tree.nodeTag(node)) {
            .@"break", .@"continue" => {
                if (tree.nodeData(node).opt_token_and_opt_node[0].unwrap()) |label_token| {
                    const loop_or_switch_label = builder.label orelse return;
                    const label = offsets.identifierTokenToNameSlice(tree, label_token);
                    if (std.mem.eql(u8, loop_or_switch_label, label)) {
                        try builder.add(main_token);
                    }
                } else for (builder.nodes) |n| switch (tree.nodeTag(n)) {
                    .for_simple,
                    .@"for",
                    .while_cont,
                    .while_simple,
                    .@"while",
                    => if (tree.nodeMainToken(n) == builder.last_loop)
                        try builder.add(main_token),
                    // break/continue on a switch must be labeled
                    .@"switch",
                    .switch_comma,
                    => {},
                    else => {},
                };
            },

            .@"while",
            .while_simple,
            .while_cont,
            .@"for",
            .for_simple,
            => {
                const last_loop = builder.last_loop;
                defer builder.last_loop = last_loop;
                builder.last_loop = main_token;
                try ast.iterateChildren(tree, node, builder, Error, iter);
            },
            else => try ast.iterateChildren(tree, node, builder, Error, iter),
        }
    }

    fn add(builder: *ControlFlowBuilder, token_index: Ast.TokenIndex) Error!void {
        const handle = builder.token_handle.handle;
        try builder.locations.append(builder.allocator, .{
            .uri = handle.uri,
            .range = offsets.tokenToRange(handle.tree, token_index, builder.encoding),
        });
    }

    fn deinit(builder: *ControlFlowBuilder) void {
        builder.locations.deinit(builder.allocator);
    }
};

fn controlFlowReferences(
    allocator: std.mem.Allocator,
    token_handle: Analyser.TokenWithHandle,
    encoding: offsets.Encoding,
    include_decl: bool,
) error{OutOfMemory}!std.ArrayList(types.Location) {
    const handle = token_handle.handle;
    const tree = handle.tree;
    const kw_token = token_handle.token;

    const source_index = handle.tree.tokenStart(kw_token);
    const nodes = try ast.nodesOverlappingIndex(allocator, tree, source_index);
    defer allocator.free(nodes);

    var builder: ControlFlowBuilder = .{
        .allocator = allocator,
        .token_handle = token_handle,
        .encoding = encoding,
        .last_loop = kw_token,
        .nodes = nodes,
    };
    defer builder.deinit();

    if (include_decl) {
        try builder.add(kw_token);
    }

    switch (tree.tokenTag(kw_token)) {
        .keyword_continue,
        .keyword_break,
        => {
            const maybe_label = blk: {
                if (kw_token + 2 >= tree.tokens.len) break :blk null;
                if (tree.tokenTag(kw_token + 1) != .colon) break :blk null;
                if (tree.tokenTag(kw_token + 2) != .identifier) break :blk null;
                break :blk offsets.identifierTokenToNameSlice(tree, kw_token + 2);
            };
            for (nodes) |node| switch (tree.nodeTag(node)) {
                .for_simple,
                .@"for",
                .while_cont,
                .while_simple,
                .@"while",
                => {
                    // if the break/continue is unlabeled it must belong to the first loop we encounter
                    const main_token = tree.nodeMainToken(node);
                    const label = maybe_label orelse break try builder.add(main_token);
                    const loop_label = if (tree.isTokenPrecededByTags(main_token, &.{ .identifier, .colon }))
                        offsets.identifierTokenToNameSlice(tree, main_token - 2)
                    else
                        continue;
                    if (std.mem.eql(u8, label, loop_label)) {
                        try builder.add(main_token);
                    }
                },
                .switch_comma,
                .@"switch",
                => {
                    const label = maybe_label orelse continue;
                    const main_token = tree.nodeMainToken(node);
                    const switch_label = if (tree.tokenTag(main_token) == .identifier)
                        offsets.identifierTokenToNameSlice(tree, main_token)
                    else
                        continue;
                    if (std.mem.eql(u8, label, switch_label)) {
                        try builder.add(
                            // we already know the switch is labeled so we can just offset
                            main_token + 2,
                        );
                    }
                },
                else => {},
            };
        },
        .keyword_for,
        .keyword_while,
        .keyword_switch,
        => {
            if (tree.isTokenPrecededByTags(kw_token, &.{ .identifier, .colon }))
                builder.label = tree.tokenSlice(kw_token - 2);
            try ast.iterateChildren(tree, nodes[0], &builder, ControlFlowBuilder.Error, ControlFlowBuilder.iter);
        },
        else => {},
    }

    defer builder.locations = .empty;
    return builder.locations;
}

pub const Callsite = struct {
    uri: []const u8,
    call_node: Ast.Node.Index,
};

const CallBuilder = struct {
    allocator: std.mem.Allocator,
    callsites: std.ArrayList(Callsite) = .empty,
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

        switch (tree.nodeTag(node)) {
            .call,
            .call_comma,
            .call_one,
            .call_one_comma,
            => {
                var buf: [1]Ast.Node.Index = undefined;
                const call = tree.fullCall(&buf, node).?;

                const called_node = call.ast.fn_expr;

                switch (tree.nodeTag(called_node)) {
                    .identifier => {
                        const identifier_token = ast.identifierTokenFromIdentifierNode(tree, called_node) orelse return;

                        const child = (try builder.analyser.lookupSymbolGlobal(
                            handle,
                            offsets.identifierTokenToNameSlice(tree, identifier_token),
                            tree.tokenStart(identifier_token),
                        )) orelse return;

                        if (builder.decl_handle.eql(child)) {
                            try builder.add(handle, node);
                        }
                    },
                    .field_access => {
                        const lhs_node, const field_name = tree.nodeData(called_node).node_and_token;
                        const lhs = (try builder.analyser.resolveTypeOfNode(.of(lhs_node, handle))) orelse return;
                        const deref_lhs = try builder.analyser.resolveDerefType(lhs) orelse lhs;

                        const symbol = offsets.tokenToSlice(tree, field_name);
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
    /// exclude references from the std library
    skip_std_references: bool,
    /// search other files for references
    workspace: bool,
) error{OutOfMemory}!std.ArrayList(Callsite) {
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

    try builder.collectReferences(curr_handle, .root);

    if (!workspace) return builder.callsites;

    try gatherReferences(allocator, analyser, curr_handle, skip_std_references, false, &builder, .get_or_load);

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
    if (handle.tree.mode == .zon) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position(), server.offset_encoding);
    const pos_context = try Analyser.getPositionContext(server.allocator, handle.tree, source_index, true);

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
                .{ .token = offsets.sourceIndexToTokenIndex(handle.tree, source_index).preferLeft(), .handle = handle },
                server.offset_encoding,
                include_decl,
            );
        }

        const name_loc = Analyser.identifierLocFromIndex(handle.tree, source_index) orelse return null;
        const name = offsets.locToSlice(handle.tree.source, name_loc);

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
            .label_access, .label_decl => try Analyser.lookupLabel(handle, name, source_index),
            .enum_literal => try analyser.getSymbolEnumLiteral(handle, source_index, name),
            .keyword => null,
            else => null,
        } orelse return null;

        break :locs switch (decl.decl) {
            .label => try labelReferences(arena, decl, server.offset_encoding, include_decl),
            else => try symbolReferences(
                arena,
                &analyser,
                request,
                decl,
                server.offset_encoding,
                include_decl,
                server.config_manager.config.skip_std_references,
                handle,
            ),
        };
    };

    switch (request) {
        .rename => |rename| {
            const escaped_rename = try std.fmt.allocPrint(arena, "{f}", .{std.zig.fmtId(rename.newName)});
            var changes: std.StringArrayHashMapUnmanaged(std.ArrayList(types.TextEdit)) = .{};

            for (locations.items) |loc| {
                const gop = try changes.getOrPutValue(arena, loc.uri, .empty);
                try gop.value_ptr.append(arena, .{
                    .range = loc.range,
                    .newText = escaped_rename,
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
            var highlights: std.ArrayList(types.DocumentHighlight) = try .initCapacity(arena, locations.items.len);
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
