//! ZLS has a [DocumentScope](https://github.com/zigtools/zls/blob/61fec01a2006c5d509dee11c6f0d32a6dfbbf44e/src/analysis.zig#L3811) data structure that represents a high-level Ast used for looking up declarations and finding the current scope at a given source location.
//! I recently had a discussion with @SuperAuguste about the DocumentScope and we were both agreed that it was in need of a rework.
//! I took some of his suggestions and this what I came up with:

const std = @import("std");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;
const types = @import("lsp.zig");
const tracy = @import("tracy.zig");
const offsets = @import("offsets.zig");
const Analyser = @import("analysis.zig");
/// this a tagged union.
const Declaration = Analyser.Declaration;

const DocumentScope = @This();

scopes: std.MultiArrayList(Scope) = .{},
declarations: std.MultiArrayList(Declaration) = .{},
/// used for looking up a child declaration in a given scope
scope_and_name_to_decl: ScopeAndNameToDeclMap = .{},
extra: std.ArrayListUnmanaged(u32) = .{},
// TODO: make this lighter;
// error completions: just store the name, the logic has no other moving parts
// enum completions: same, but determine whether to store docs somewhere or fetch them on-demand (on-demand likely better)
error_completions: CompletionSet = .{},
enum_completions: CompletionSet = .{},

const CompletionContext = struct {
    pub fn hash(self: @This(), item: types.CompletionItem) u32 {
        _ = self;
        return @truncate(std.hash.Wyhash.hash(0, item.label));
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

/// alternative representation:
///
/// if we add every `Declaration` to `DocumentScope.declarations` in the same order we
/// insert into this Map then there is no need to store the `Declaration.Index`
/// because it matches the index inside the Map.
/// this only works if every `Declaration` has only added to a single scope
pub const ScopeAndNameToDeclMap = std.ArrayHashMapUnmanaged(ScopeAndName, void, ScopeAndNameToDeclContext, false);

pub const ScopeAndName = struct {
    scope: Scope.Index,
    name: []const u8,
};

pub const ScopeAndNameToDeclContext = struct {
    pub fn hash(self: @This(), s: ScopeAndName) u32 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, s.scope);
        hasher.update(s.name);
        return @truncate(hasher.final());
    }

    pub fn eql(self: @This(), a: ScopeAndName, b: ScopeAndName, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return a.scope == b.scope and std.mem.eql(u8, a.name, b.name);
    }
};

pub const Scope = struct {
    pub const Tag = enum {
        /// `node_tags[ast_node]` is ContainerDecl or Root or ErrorSetDecl
        container,
        /// index into `DocumentScope.extra`
        /// Body:
        ///     ast_node: Ast.Node.Index,
        ///     usingnamespace_start: u32,
        ///     usingnamespace_end: u32,
        /// `node_tags[ast_node]` is ContainerDecl or Root
        container_usingnamespace,
        /// `node_tags[ast_node]` is FnProto
        function,
        /// `node_tags[ast_node]` is Block
        block,
        other,
    };

    pub const Data = union {
        ast_node: Ast.Node.Index,
        container_usingnamespace: u32,
        other: void,
    };

    pub const SmallLoc = struct {
        start: u32,
        end: u32,
    };

    pub const ChildScopes = struct {
        start: Index,
        end: Index,
    };

    pub const ChildDeclarations = union {
        small: [2]Declaration.OptionalIndex,
        other: struct {
            start: u32,
            end: u32,
        },
    };

    tag: Tag,
    // offsets.Loc store `usize` instead of `u32`
    // zig only allows files up to std.math.maxInt(u32) bytes to do this kind of optimization. ZLS should also follow this.
    loc: SmallLoc,
    parent_scope: OptionalIndex,
    // child scopes have contiguous indices
    // used only by the EnclosingScopeIterator
    // https://github.com/zigtools/zls/blob/61fec01a2006c5d509dee11c6f0d32a6dfbbf44e/src/analysis.zig#L3127
    child_scopes: ChildScopes,
    is_small: bool,
    child_declarations: ChildDeclarations,
    data: Data,

    pub const Index = enum(u32) {
        _,
    };

    pub const OptionalIndex = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(index: OptionalIndex) ?Index {
            if (index == .none) return null;
            return @enumFromInt(@intFromEnum(index));
        }
    };
};

const ScopeContext = struct {
    allocator: std.mem.Allocator,
    tree: Ast,
    doc_scope: *DocumentScope,

    current_scope: Scope.OptionalIndex = .none,
    child_scopes_scratch: std.ArrayListUnmanaged(Scope.Index) = .{},
    child_declarations_scratch: std.ArrayListUnmanaged(Declaration.Index) = .{},

    const PushedScope = struct {
        context: *ScopeContext,

        scope: Scope.Index,

        scopes_start: u32,
        declarations_start: u32,

        // TODO: Refactor; we have the node index and the container index
        // so we don't actually need to ask for these I think
        small_strings: [2][]const u8,

        fn pushDeclaration(pushed: PushedScope, name: []const u8, declaration: Declaration) error{OutOfMemory}!void {
            const doc_scope = pushed.context.doc_scope;
            try doc_scope.declarations.append(pushed.context.allocator, declaration);
            pushed.pushDeclarationIndex(name, @enumFromInt(doc_scope.declarations.len));
        }

        fn pushDeclarationIndex(pushed: PushedScope, name: []const u8, declaration: Declaration.Index) error{OutOfMemory}!void {
            const context = pushed.context;
            const allocator = context.allocator;
            _ = allocator;

            var slice = pushed.context.doc_scope.scopes.slice();
            var is_small = slice.items(.is_small)[pushed.scope];
            var child_declarations = slice.items(.child_declarations)[pushed.scope];

            if (is_small) {
                for (&child_declarations.small, &pushed.small_strings) |*scd, *small_string| {
                    if (scd.* == .none) {
                        small_string.* = name;
                        scd.* = @enumFromInt(@intFromEnum(declaration));
                        break;
                    }
                } else {
                    is_small = false;

                    for (&child_declarations.small, &pushed.small_strings) |scd, small_string| {
                        try pushDeclarationIndexNotSmall(small_string, scd.unwrap().?);
                    }
                    try pushDeclarationIndexNotSmall(name, declaration);
                }
            } else {
                try pushDeclarationIndexNotSmall(name, declaration);
            }
        }

        fn pushDeclarationIndexNotSmall(pushed: PushedScope, name: []const u8, declaration: Declaration.Index) error{OutOfMemory}!void {
            const context = pushed.context;
            const allocator = context.allocator;
            try context.child_declarations_scratch.append(allocator, declaration);
            try context.doc_scope.scope_and_name_to_decl.put(
                allocator,
                .{ .scope = pushed.scope, .name = name },
                {},
            );
        }

        fn pushDeclLoopLabel(pushed: PushedScope, label: u32, node_idx: Ast.Node.Index) error{OutOfMemory}![]const u8 {
            var label_scope = try pushed.context.startScope(
                .other,
                .other,
                offsets.tokenToLoc(pushed.context.tree, label),
            );

            const name = pushed.context.tree.tokenSlice(label);
            try label_scope.pushDeclaration(name, .{
                .label_decl = .{
                    .label = label,
                    .block = node_idx,
                },
            });

            try label_scope.finalize();

            return name;
        }

        fn finalize(pushed: PushedScope) error{OutOfMemory}!void {
            const context = pushed.context;
            const allocator = context.allocator;

            const declaration_start = context.doc_scope.extra.len;
            try context.doc_scope.extra.appendSlice(allocator, pushed.context.child_declarations_scratch.items[pushed.declarations_start..]);
            const declaration_end = context.doc_scope.extra.len;
            pushed.context.child_declarations_scratch.items.len = pushed.declarations_start;

            const scope_start = context.doc_scope.extra.len;
            try context.doc_scope.extra.appendSlice(allocator, pushed.context.child_scopes_scratch.items[pushed.scopes_start..]);
            const scope_end = context.doc_scope.extra.len;
            pushed.context.child_scopes_scratch.items.len = pushed.scopes_start;

            var slice = pushed.context.doc_scope.scopes.slice();
            if (!slice.items(.is_small)[pushed.scope]) {
                slice.items(.child_declarations)[pushed.scope].other = .{
                    .start = declaration_start,
                    .end = declaration_end,
                };
            }

            slice.items(.child_scopes)[pushed.scope] = .{
                .start = scope_start,
                .end = scope_end,
            };

            std.debug.assert(pushed.context.current_scope != .none);
            pushed.context.current_scope = slice.items(.parent_scope)[pushed.context.current_scope.unwrap()];
        }
    };

    fn startScope(context: *ScopeContext, tag: Scope.Tag, data: Scope.Data, loc: Scope.SmallLoc) !PushedScope {
        try context.doc_scope.scopes.append(context.allocator, .{
            .tag = tag,
            .loc = loc,
            .parent_scope = context.current_scope,
            .child_scopes = undefined,
            .is_small = true,
            .child_declarations = .{
                .small = &.{
                    Declaration.OptionalIndex.none,
                    Declaration.OptionalIndex.none,
                },
            },
            .data = data,
        });
        context.current_scope = @enumFromInt(context.doc_scope.scopes.len);

        return .{
            .context = context,
            .scope = context.current_scope.unwrap(),
            .scopes_start = @intCast(context.child_scope_scratch.items.len),
            .declarations_start = @intCast(context.child_scope_scratch.items.len),
        };
    }
};

pub fn init(allocator: std.mem.Allocator, tree: Ast) !DocumentScope {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var document_scope = DocumentScope{};
    errdefer document_scope.deinit(allocator);

    var context = ScopeContext{
        .allocator = allocator,
        .tree = tree,
        .doc_scope = &document_scope,
    };
    try walkContainerDecl(&context, tree, 0, 0);

    return document_scope;
}

pub fn deinit(scope: *DocumentScope, allocator: std.mem.Allocator) void {
    // TODO
    _ = scope;
    _ = allocator;
}

fn walkContainerDecl(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!void {
    _ = start_token;
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = context.allocator;
    const scopes = &context.doc_scope.scopes;
    _ = scopes;
    const tags = tree.nodes.items(.tags);
    const token_tags = tree.tokens.items(.tags);
    _ = token_tags;

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node_idx).?;

    const scope = context.startScope();

    // var uses = std.ArrayListUnmanaged(Ast.Node.Index){};
    // errdefer uses.deinit(allocator);

    for (container_decl.ast.members) |decl| {
        try walkNode(context, tree, decl);

        switch (tags[decl]) {
            .@"usingnamespace" => {
                // TODO
                // try uses.append(allocator, decl);
                continue;
            },
            else => {},
        }

        try context.doc_scope.declarations.append(allocator, .{ .ast_node = decl });
        try scope.pushDeclaration(context.doc_scope.declarations.len);

        // TODO: Fix this later
        // if ((node_idx != 0 and token_tags[container_decl.ast.main_token] == .keyword_enum) or
        //     ast.isTaggedUnion(tree, node_idx))
        // {
        //     if (std.mem.eql(u8, name, "_")) continue;

        //     const doc = try Analyser.getDocComments(allocator, tree, decl);
        //     errdefer if (doc) |d| allocator.free(d);
        //     var gop_res = try context.doc_scope.enum_completions.getOrPut(allocator, .{
        //         .label = name,
        //         .kind = .EnumMember,
        //         .insertText = name,
        //         .insertTextFormat = .PlainText,
        //         .documentation = if (doc) |d| .{ .MarkupContent = types.MarkupContent{ .kind = .markdown, .value = d } } else null,
        //     });
        //     if (gop_res.found_existing) {
        //         if (doc) |d| allocator.free(d);
        //     }
        // }
    }

    // scopes.items(.uses)[@intFromEnum(scope)] = try uses.toOwnedSlice(allocator);

    try scope.finalize();
}

/// If `node_idx` is a block its scope index will be returned
/// Otherwise, a new scope will be created that will enclose `node_idx`
fn makeBlockScopeInternal(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!?Scope.Index {
    return makeBlockScopeAt(context, tree, node_idx, tree.firstToken(node_idx));
}

fn makeBlockScopeAt(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!?ScopeContext.PushedScope {
    if (node_idx == 0) return null;
    const tags = tree.nodes.items(.tags);

    // if node_idx is a block, the next scope will be a block so we store its index here
    const block_scope = context.doc_scope.scopes.len;
    try makeScopeAt(context, tree, node_idx, start_token);

    switch (tags[node_idx]) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            std.debug.assert(context.doc_scope.scopes.items(.data)[block_scope] == .block);
            return @enumFromInt(block_scope);
        },
        else => {
            const new_scope = try context.pushScope(
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
                .other,
            );
            context.popScope();
            return new_scope;
        },
    }
}

fn walkNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    return makeScopeAt(context, tree, node_idx, tree.firstToken(node_idx));
}

fn makeScopeAt(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!void {
    if (node_idx == 0) return;

    const allocator = context.allocator;

    const tags = tree.nodes.items(.tags);
    const token_tags = tree.tokens.items(.tags);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    const node_tag = tags[node_idx];

    switch (node_tag) {
        .root => unreachable,
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
        => try walkContainerDecl(context, tree, node_idx, start_token),
        .error_set_decl => {
            const scope = try context.startScope(
                .container,
                .{ .ast_node = node_idx },
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
            );

            // All identifiers in main_token..data.rhs are error fields.
            var tok_i = main_tokens[node_idx] + 2;
            while (tok_i < data[node_idx].rhs) : (tok_i += 1) {
                switch (token_tags[tok_i]) {
                    .doc_comment, .comma => {},
                    .identifier => {
                        const name = offsets.tokenToSlice(tree, tok_i);
                        try scope.pushDeclaration(name, .{ .error_token = tok_i });
                        const gop = try context.doc_scope.error_completions.getOrPut(allocator, .{
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

            try scope.finalize();
        },
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => |fn_tag| {
            var buf: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buf, node_idx).?;

            const scope = try context.startScope(
                .function,
                .{ .ast_node = node_idx },
                offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx)),
            );

            // NOTE: We count the param index ourselves
            // as param_i stops counting; TODO: change this

            var param_index: u16 = 0;

            var it = func.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| : (param_index += 1) {
                // Add parameter decls
                if (param.name_token) |name_token| {
                    try scope.pushDeclaration(
                        tree.tokenSlice(name_token),
                        .{
                            .param_payload = .{
                                .param_index = param_index,
                                .func = node_idx,
                            },
                        },
                    );
                }
                // Visit parameter types to pick up any error sets and enum
                //   completions
                try walkNode(context, tree, param.type_expr);
            }

            if (fn_tag == .fn_decl) blk: {
                if (data[node_idx].lhs == 0) break :blk;
                const return_type_node = data[data[node_idx].lhs].rhs;

                // Visit the return type
                try walkNode(context, tree, return_type_node);
            }

            // Visit the function body
            try walkNode(context, tree, data[node_idx].rhs);

            try scope.finalize();
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            const first_token = tree.firstToken(node_idx);
            const last_token = ast.lastToken(tree, node_idx);
            const end_index = offsets.tokenToLoc(tree, last_token).end;

            const scope = try context.startScope(
                .block,
                .{ .ast_node = node_idx },
                .{
                    .start = offsets.tokenToIndex(tree, start_token),
                    .end = end_index,
                },
            );

            // if labeled block
            if (token_tags[first_token] == .identifier) {
                try scope.pushDeclaration(
                    tree.tokenSlice(first_token),
                    .{
                        .label_decl = .{
                            .label = first_token,
                            .block = node_idx,
                        },
                    },
                );
            }

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                try walkNode(context, tree, idx);
                switch (tags[idx]) {
                    .global_var_decl,
                    .local_var_decl,
                    .aligned_var_decl,
                    .simple_var_decl,
                    => {
                        const var_decl = tree.fullVarDecl(idx).?;
                        const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                        try scope.pushDeclaration(name, .{ .ast_node = idx });
                    },
                    .assign_destructure => {
                        const lhs_count = tree.extra_data[data[idx].lhs];
                        const lhs_exprs = tree.extra_data[data[idx].lhs + 1 ..][0..lhs_count];

                        for (lhs_exprs, 0..) |lhs_node, i| {
                            const var_decl = tree.fullVarDecl(lhs_node) orelse continue;
                            const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
                            try scope.pushDeclaration(name, .{
                                .assign_destructure = .{
                                    .node = idx,
                                    .index = @intCast(i),
                                },
                            });
                        }
                    },
                    else => continue,
                }
            }

            try scope.finalize();
        },
        .@"if",
        .if_simple,
        => {
            const if_node = ast.fullIf(tree, node_idx).?;

            const then_start = if_node.payload_token orelse tree.firstToken(if_node.ast.then_expr);
            const then_scope = (try makeBlockScopeAt(context, tree, if_node.ast.then_expr, then_start)).?;

            if (if_node.payload_token) |payload| {
                const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                const decl: Declaration = if (if_node.error_token != null)
                    .{ .error_union_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } }
                else
                    .{ .pointer_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } };
                try then_scope.pushDeclaration(name, decl);
            }

            if (if_node.ast.else_expr != 0) {
                const else_start = if_node.error_token orelse tree.firstToken(if_node.ast.else_expr);
                const else_scope = (try makeBlockScopeAt(context, tree, if_node.ast.else_expr, else_start)).?;
                if (if_node.error_token) |err_token| {
                    const name = tree.tokenSlice(err_token);
                    try else_scope.pushDeclaration(name, .{
                        .error_union_error = .{ .name = err_token, .condition = if_node.ast.cond_expr },
                    });
                }
            }
        },
        .@"catch" => {
            try walkNode(context, tree, data[node_idx].lhs);

            const catch_token = main_tokens[node_idx] + 2;
            if (token_tags.len > catch_token and
                token_tags[catch_token - 1] == .pipe and
                token_tags[catch_token] == .identifier)
            {
                const expr_scope = (try makeBlockScopeAt(context, tree, data[node_idx].rhs, catch_token)).?;
                const name = tree.tokenSlice(catch_token);
                try expr_scope.pushDeclaration(name, .{
                    .error_union_error = .{ .name = catch_token, .condition = data[node_idx].lhs },
                });
            } else {
                try walkNode(context, tree, data[node_idx].rhs);
            }
        },
        .@"while",
        .while_simple,
        .while_cont,
        => {
            // label_token: inline_token while (cond_expr) |payload_token| : (cont_expr) then_expr else else_expr
            const while_node = ast.fullWhile(tree, node_idx).?;

            try walkNode(context, tree, while_node.ast.cond_expr);

            const cont_scope = try makeBlockScopeInternal(context, tree, while_node.ast.cont_expr);

            const then_start = while_node.payload_token orelse tree.firstToken(while_node.ast.then_expr);
            const then_scope = (try makeBlockScopeAt(context, tree, while_node.ast.then_expr, then_start)).?;

            const else_start = while_node.error_token orelse tree.firstToken(while_node.ast.else_expr);
            const else_scope = try makeBlockScopeAt(context, tree, while_node.ast.else_expr, else_start);

            if (while_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);

                const name = try then_scope.pushDeclLoopLabel(label, node_idx);
                try then_scope.pushDeclaration(name, .{ .label_decl = .{ .label = label, .block = while_node.ast.then_expr } });
                if (else_scope) |scope| {
                    try scope.pushDeclaration(name, .{ .label_decl = .{ .label = label, .block = while_node.ast.else_expr } });
                }
            }

            if (while_node.payload_token) |payload| {
                const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                std.debug.assert(token_tags[name_token] == .identifier);

                const name = tree.tokenSlice(name_token);
                const decl: Declaration = if (while_node.error_token != null)
                    .{ .error_union_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } }
                else
                    .{ .pointer_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } };
                if (cont_scope) |scope| {
                    try scope.pushDeclaration(name, decl);
                }
                try then_scope.pushDeclaration(name, decl);
            }

            if (while_node.error_token) |err_token| {
                std.debug.assert(token_tags[err_token] == .identifier);
                const name = tree.tokenSlice(err_token);
                try else_scope.?.pushDeclaration(name, .{
                    .error_union_error = .{ .name = err_token, .condition = while_node.ast.cond_expr },
                });
            }
        },
        .@"for",
        .for_simple,
        => {
            // label_token: inline_token for (inputs) |capture_tokens| then_expr else else_expr
            const for_node = ast.fullFor(tree, node_idx).?;

            for (for_node.ast.inputs) |input_node| {
                try walkNode(context, tree, input_node);
            }

            var capture_token = for_node.payload_token;
            const then_scope = (try makeBlockScopeAt(context, tree, for_node.ast.then_expr, capture_token)).?;
            const else_scope = try makeBlockScopeInternal(context, tree, for_node.ast.else_expr);

            for (for_node.ast.inputs) |input| {
                if (capture_token + 1 >= tree.tokens.len) break;
                const capture_is_ref = token_tags[capture_token] == .asterisk;
                const name_token = capture_token + @intFromBool(capture_is_ref);
                capture_token = name_token + 2;

                try then_scope.pushDeclaration(
                    offsets.tokenToSlice(tree, name_token),
                    .{ .array_payload = .{ .identifier = name_token, .array_expr = input } },
                );
            }

            if (for_node.label_token) |label| {
                std.debug.assert(token_tags[label] == .identifier);

                const name = try then_scope.pushDeclLoopLabel(label, node_idx);
                try then_scope.pushDeclaration(
                    name,
                    .{ .label_decl = .{ .label = label, .block = for_node.ast.then_expr } },
                );
                if (else_scope) |scope| {
                    try scope.pushDeclaration(
                        name,
                        .{ .label_decl = .{ .label = label, .block = for_node.ast.else_expr } },
                    );
                }
            }
        },
        .@"switch",
        .switch_comma,
        => {
            const extra = tree.extraData(data[node_idx].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];

            for (cases, 0..) |case, case_index| {
                const switch_case: Ast.full.SwitchCase = tree.fullSwitchCase(case).?;

                if (switch_case.payload_token) |payload| {
                    const expr_scope = (try makeBlockScopeAt(context, tree, switch_case.ast.target_expr, payload)).?;
                    // if payload is *name than get next token
                    const name_token = payload + @intFromBool(token_tags[payload] == .asterisk);
                    const name = tree.tokenSlice(name_token);

                    try expr_scope.pushDeclaration(name, .{
                        .switch_payload = .{ .node = node_idx, .case_index = @intCast(case_index) },
                    });
                } else {
                    try walkNode(context, tree, switch_case.ast.target_expr);
                }
            }
        },
        .@"errdefer" => {
            const payload_token = data[node_idx].lhs;
            const expr_start = if (payload_token != 0) payload_token else tree.firstToken(data[node_idx].rhs);
            const expr_scope = (try makeBlockScopeAt(context, tree, data[node_idx].rhs, expr_start)).?;

            if (payload_token != 0) {
                const name = tree.tokenSlice(payload_token);
                try expr_scope.pushDeclaration(name, .{
                    .error_union_error = .{ .name = payload_token, .condition = 0 },
                });
            }
        },
        else => {
            try ast.iterateChildren(tree, node_idx, context, error{OutOfMemory}, walkNode);
        },
    }
}

// Lookup

pub fn getScopeDeclarationsConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Declaration.Index {
    const slice = doc_scope.scopes.slice();

    if (slice.items(.is_small)[@intFromEnum(scope)]) {
        const small = slice.items(.child_declarations)[@intFromEnum(scope)].small;
        if (small[0] == .none) return @ptrCast(small[0..0]);
        if (small[1] == .none) return @ptrCast(small[0..1]);
        return @ptrCast(small[0..2]);
    } else {
        const other = slice.items(.child_declarations)[@intFromEnum(scope)].other;
        return @ptrCast(doc_scope.extra.items[other.start..other.end]);
    }
}

pub fn getScopeDeclarationByName(
    doc_scope: DocumentScope,
    tree: Ast,
    scope: Scope.Index,
    name: []const u8,
) Declaration.OptionalIndex {
    const slice = doc_scope.scopes.slice();
    const decl_slice = doc_scope.declarations.slice();

    if (slice.items(.is_small)[@intFromEnum(scope)]) {
        for (slice.items(.declaration)) |decl_idx| {
            if (decl_idx == .none)
                break;

            const tag = decl_slice.items(.tags)[decl_idx];
            const data = decl_slice.items(.data)[decl_idx];

            switch (tag) {
                .ast_node => |node| {
                    _ = node;
                    if (std.mem.eql(u8, Analyser.getDeclName(tree, data.ast_node), name)) {
                        return decl_idx;
                    }
                },
                else => {
                    // TODO
                },
            }

            return .none;
        }
    } else {
        return if (doc_scope.scope_and_name_to_decl.getIndex(.{
            .scope = scope,
            .name = name,
        })) |idx|
            @enumFromInt(idx)
        else
            .none;
    }
}
