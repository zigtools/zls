const std = @import("std");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;
const types = @import("lsp.zig");
const tracy = @import("tracy.zig");
const offsets = @import("offsets.zig");
const Analyser = @import("analysis.zig");
const Declaration = Analyser.Declaration;

const DocumentScope = @This();

scopes: std.MultiArrayList(Scope) = .{},
declarations: std.MultiArrayList(Declaration) = .{},
/// used for looking up a child declaration in a given scope
declaration_lookup_map: DeclarationLookupMap = .{},
extra: std.ArrayListUnmanaged(u32) = .{},

error_completions: std.AutoArrayHashMapUnmanaged(Declaration.Index, void) = .{},
enum_completions: std.AutoArrayHashMapUnmanaged(Declaration.Index, void) = .{},

/// Every `index` inside this `ArrayhashMap` is equivalent to a `Declaration.Index`
/// This means that every declaration is only the child of a single scope
pub const DeclarationLookupMap = std.ArrayHashMapUnmanaged(
    DeclarationLookup,
    void,
    DeclarationLookupContext,
    false,
);

pub const DeclarationLookup = struct {
    pub const Kind = enum { field, other };
    scope: Scope.Index,
    name: []const u8,
    kind: Kind,
};

pub const DeclarationLookupContext = struct {
    pub fn hash(self: @This(), s: DeclarationLookup) u32 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, s.scope);
        hasher.update(s.name);
        std.hash.autoHash(&hasher, s.kind);
        return @truncate(hasher.final());
    }

    pub fn eql(self: @This(), a: DeclarationLookup, b: DeclarationLookup, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return a.scope == b.scope and a.kind == b.kind and std.mem.eql(u8, a.name, b.name);
    }
};

pub const Scope = struct {
    pub const Tag = enum {
        /// `node_tags[ast_node]` is ContainerDecl or Root or ErrorSetDecl
        container,
        /// index into `DocumentScope.extra`
        /// Body:
        ///     ast_node: Ast.Node.Index,
        ///     usingnamespace_count: u32,
        ///     usingnamespaces: [usingnamespace_count]u32,
        /// `node_tags[ast_node]` is ContainerDecl or Root
        container_usingnamespace,
        /// `node_tags[ast_node]` is FnProto
        function,
        /// `node_tags[ast_node]` is Block
        block,
        other,
    };

    pub const Data = packed union {
        ast_node: Ast.Node.Index,
        container_usingnamespace: u32,
    };

    pub const SmallLoc = packed struct {
        start: u32,
        end: u32,
    };

    pub const ChildScopes = union {
        pub const small_size = 4;

        small: [small_size]Scope.OptionalIndex,
        other: struct {
            start: u32,
            end: u32,
        },
    };

    pub const ChildDeclarations = union {
        pub const small_size = 2;

        small: [small_size]Declaration.OptionalIndex,
        other: struct {
            start: u32,
            end: u32,
        },
    };

    data: packed struct(u64) {
        tag: Tag,
        is_child_scopes_small: bool,
        is_child_decls_small: bool,
        _: u27 = undefined,
        data: Data,
    },
    // offsets.Loc store `usize` instead of `u32`
    // zig only allows files up to `std.math.maxInt(u32)` bytes to do this kind of optimization.
    loc: SmallLoc,
    parent_scope: OptionalIndex,
    // child scopes have contiguous indices
    // used only by the `EnclosingScopeIterator`
    child_scopes: ChildScopes,
    child_declarations: ChildDeclarations,

    pub const Index = enum(u32) {
        _,

        pub fn toOptional(index: Index) OptionalIndex {
            return @enumFromInt(@intFromEnum(index));
        }
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

    fn deinit(context: *ScopeContext) void {
        context.child_scopes_scratch.deinit(context.allocator);
        context.child_declarations_scratch.deinit(context.allocator);
    }

    const PushedScope = struct {
        context: *ScopeContext,

        scope: Scope.Index,

        scopes_start: u32,
        declarations_start: u32,

        fn pushDeclaration(
            pushed: PushedScope,
            name: []const u8,
            declaration: Declaration,
            kind: DeclarationLookup.Kind,
        ) error{OutOfMemory}!void {
            if (std.mem.eql(u8, name, "_")) return;
            defer std.debug.assert(pushed.context.doc_scope.declarations.len == pushed.context.doc_scope.declaration_lookup_map.count());

            const context = pushed.context;
            const doc_scope = context.doc_scope;
            const allocator = context.allocator;

            const gop = try doc_scope.declaration_lookup_map.getOrPut(allocator, .{
                .scope = pushed.scope,
                .name = name,
                .kind = kind,
            });
            if (gop.found_existing) return;

            try doc_scope.declarations.append(allocator, declaration);
            const declaration_index: Declaration.Index = @enumFromInt(doc_scope.declarations.len - 1);

            const data = &doc_scope.scopes.items(.data)[@intFromEnum(pushed.scope)];
            const child_declarations = &doc_scope.scopes.items(.child_declarations)[@intFromEnum(pushed.scope)];

            if (!data.is_child_decls_small) {
                try context.child_declarations_scratch.append(allocator, declaration_index);
                return;
            }

            for (&child_declarations.small) |*scd| {
                if (scd.* == .none) {
                    scd.* = declaration_index.toOptional();
                    break;
                }
            } else {
                data.is_child_decls_small = false;

                try context.child_declarations_scratch.ensureUnusedCapacity(allocator, Scope.ChildDeclarations.small_size + 1);
                context.child_declarations_scratch.appendSliceAssumeCapacity(@ptrCast(&child_declarations.small));
                context.child_declarations_scratch.appendAssumeCapacity(declaration_index);
            }
        }

        fn finalize(pushed: PushedScope) error{OutOfMemory}!void {
            const context = pushed.context;
            const allocator = context.allocator;

            const slice = context.doc_scope.scopes.slice();
            const data = slice.items(.data)[@intFromEnum(pushed.scope)];

            if (!data.is_child_decls_small) {
                const declaration_start = context.doc_scope.extra.items.len;
                try context.doc_scope.extra.appendSlice(allocator, @ptrCast(context.child_declarations_scratch.items[pushed.declarations_start..]));
                const declaration_end = context.doc_scope.extra.items.len;
                context.child_declarations_scratch.items.len = pushed.declarations_start;

                slice.items(.child_declarations)[@intFromEnum(pushed.scope)] = .{
                    .other = .{
                        .start = @intCast(declaration_start),
                        .end = @intCast(declaration_end),
                    },
                };
            }

            if (!data.is_child_scopes_small) {
                const scope_start = context.doc_scope.extra.items.len;
                try context.doc_scope.extra.appendSlice(allocator, @ptrCast(context.child_scopes_scratch.items[pushed.scopes_start..]));
                const scope_end = context.doc_scope.extra.items.len;
                context.child_scopes_scratch.items.len = pushed.scopes_start;

                slice.items(.child_scopes)[@intFromEnum(pushed.scope)] = .{
                    .other = .{
                        .start = @intCast(scope_start),
                        .end = @intCast(scope_end),
                    },
                };
            }

            std.debug.assert(context.current_scope.unwrap().? == pushed.scope);
            context.current_scope = context.doc_scope.getScopeParent(pushed.scope);

            std.debug.assert(context.doc_scope.declarations.len == context.doc_scope.declaration_lookup_map.count());
        }
    };

    fn startScope(context: *ScopeContext, tag: Scope.Tag, data: Scope.Data, loc: Scope.SmallLoc) error{OutOfMemory}!PushedScope {
        try context.doc_scope.scopes.append(context.allocator, .{
            .data = .{
                .tag = tag,
                .is_child_scopes_small = true,
                .is_child_decls_small = true,
                .data = data,
            },
            .loc = loc,
            .parent_scope = context.current_scope,
            .child_scopes = .{
                .small = [_]Scope.OptionalIndex{.none} ** Scope.ChildScopes.small_size,
            },
            .child_declarations = .{
                .small = [_]Declaration.OptionalIndex{.none} ** Scope.ChildDeclarations.small_size,
            },
        });
        const new_scope_index: Scope.Index = @enumFromInt(context.doc_scope.scopes.len - 1);
        if (context.current_scope.unwrap()) |parent_scope| {
            try context.pushChildScope(parent_scope, new_scope_index);
        }

        context.current_scope = new_scope_index.toOptional();
        return .{
            .context = context,
            .scope = context.current_scope.unwrap().?,
            .scopes_start = @intCast(context.child_scopes_scratch.items.len),
            .declarations_start = @intCast(context.child_declarations_scratch.items.len),
        };
    }

    fn pushChildScope(
        context: *ScopeContext,
        scope_index: Scope.Index,
        child_scope_index: Scope.Index,
    ) error{OutOfMemory}!void {
        const doc_scope = context.doc_scope;
        const allocator = context.allocator;

        const data = &doc_scope.scopes.items(.data)[@intFromEnum(scope_index)];
        const child_scopes = &doc_scope.scopes.items(.child_scopes)[@intFromEnum(scope_index)];

        if (!data.is_child_scopes_small) {
            try context.child_scopes_scratch.append(allocator, child_scope_index);
            return;
        }

        for (&child_scopes.small) |*scd| {
            if (scd.* == .none) {
                scd.* = child_scope_index.toOptional();
                break;
            }
        } else {
            data.is_child_scopes_small = false;

            try context.child_scopes_scratch.ensureUnusedCapacity(allocator, Scope.ChildScopes.small_size + 1);
            context.child_scopes_scratch.appendSliceAssumeCapacity(@ptrCast(&child_scopes.small));
            context.child_scopes_scratch.appendAssumeCapacity(child_scope_index);
        }
    }
};

pub fn init(allocator: std.mem.Allocator, tree: Ast) error{OutOfMemory}!DocumentScope {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var document_scope = DocumentScope{};
    errdefer document_scope.deinit(allocator);

    var context = ScopeContext{
        .allocator = allocator,
        .tree = tree,
        .doc_scope = &document_scope,
    };
    defer context.deinit();
    try walkContainerDecl(&context, tree, 0);

    return document_scope;
}

pub fn deinit(scope: *DocumentScope, allocator: std.mem.Allocator) void {
    scope.scopes.deinit(allocator);
    scope.declarations.deinit(allocator);
    scope.declaration_lookup_map.deinit(allocator);
    scope.extra.deinit(allocator);
    scope.enum_completions.deinit(allocator);
    scope.error_completions.deinit(allocator);
}

fn locToSmallLoc(loc: offsets.Loc) Scope.SmallLoc {
    return .{
        .start = @intCast(loc.start),
        .end = @intCast(loc.end),
    };
}

/// Similar to `walkNode` but also returns a new scope.
/// Asserts that `node_idx != 0`
/// Caller must finalize the scope
fn walkNodeEnsureScope(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!ScopeContext.PushedScope {
    std.debug.assert(node_idx != 0);
    const tags = tree.nodes.items(.tag);

    switch (tags[node_idx]) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            // special case where we reuse the block scope
            return try walkBlockNodeKeepOpen(context, tree, node_idx, start_token);
        },
        else => {
            const new_scope = try context.startScope(
                .other,
                undefined,
                locToSmallLoc(offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, node_idx))),
            );
            try walkNode(context, tree, node_idx);
            return new_scope;
        },
    }
}

fn walkNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const tag = tree.nodes.items(.tag)[node_idx];
    try switch (tag) {
        .root => return,
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
        => walkContainerDecl(context, tree, node_idx),
        .error_set_decl => walkErrorSetNode(context, tree, node_idx),
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => walkFuncNode(context, tree, node_idx),
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => walkBlockNode(context, tree, node_idx),
        .@"if",
        .if_simple,
        => walkIfNode(context, tree, node_idx),
        .@"catch" => walkCatchNode(context, tree, node_idx),
        .@"while",
        .while_simple,
        .while_cont,
        => walkWhileNode(context, tree, node_idx),
        .@"for",
        .for_simple,
        => walkForNode(context, tree, node_idx),
        .@"switch",
        .switch_comma,
        => walkSwitchNode(context, tree, node_idx),
        .@"errdefer" => walkErrdeferNode(context, tree, node_idx),

        .@"usingnamespace",
        .field_access,
        .unwrap_optional,
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .deref,
        .@"suspend",
        .@"resume",
        .@"return",
        .grouped_expression,
        .@"comptime",
        .@"nosuspend",
        .asm_simple,
        => walkLhsNode(context, tree, node_idx),

        .test_decl,
        .@"defer",
        .@"break",
        .anyframe_type,
        => walkRhsNode(context, tree, node_idx),

        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
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
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
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
        .@"orelse",
        .bool_and,
        .bool_or,
        .array_type,
        .array_access,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .switch_range,
        .builtin_call_two,
        .builtin_call_two_comma,
        .container_field_init,
        .container_field_align,
        .error_union,
        .for_range,
        => walkLhsRhsNode(context, tree, node_idx),

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        .assign_destructure,
        .array_type_sentinel,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .slice_open,
        .slice,
        .slice_sentinel,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        .builtin_call,
        .builtin_call_comma,
        .container_field,
        .@"asm",
        => walkOtherNode(context, tree, node_idx),

        .asm_output,
        .asm_input,
        => unreachable,

        .@"continue",
        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .identifier,
        .enum_literal,
        .string_literal,
        .multiline_string_literal,
        .error_value,
        => return,
    };
}

noinline fn walkContainerDecl(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = context.allocator;
    const tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node_idx).?;

    const is_enum_or_tagged_union = blk: {
        if (node_idx == 0) break :blk false;
        break :blk switch (token_tags[container_decl.ast.main_token]) {
            .keyword_enum => true,
            .keyword_union => container_decl.ast.enum_token != null or container_decl.ast.arg != 0,
            .keyword_struct, .keyword_opaque => false,
            else => unreachable,
        };
    };

    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    var uses = std.ArrayListUnmanaged(Ast.Node.Index){};
    defer uses.deinit(allocator);

    for (container_decl.ast.members) |decl| {
        try walkNode(context, tree, decl);

        switch (tags[decl]) {
            .@"usingnamespace" => {
                try uses.append(allocator, decl);
            },
            .test_decl,
            .@"comptime",
            => continue,

            .container_field,
            .container_field_init,
            .container_field_align,
            => {
                if (token_tags[main_tokens[node_idx]] == .keyword_struct and
                    tree.fullContainerField(decl).?.ast.tuple_like)
                {
                    continue;
                }

                if (token_tags[main_tokens[decl]] != .identifier) {
                    // TODO this code path should not be reachable
                    continue;
                }
                const name = offsets.identifierTokenToNameSlice(tree, main_tokens[decl]);
                try scope.pushDeclaration(name, .{ .ast_node = decl }, .field);

                if (is_enum_or_tagged_union) {
                    if (std.mem.eql(u8, name, "_")) continue;

                    try context.doc_scope.enum_completions.put(
                        context.allocator,
                        @enumFromInt(context.doc_scope.declarations.len - 1),
                        void{},
                    );
                }
            },
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => {
                var buffer: [1]Ast.Node.Index = undefined;
                const name_token = tree.fullFnProto(&buffer, decl).?.name_token orelse continue;
                const name = offsets.identifierTokenToNameSlice(tree, name_token);
                try scope.pushDeclaration(name, .{ .ast_node = decl }, .other);
            },
            .local_var_decl,
            .global_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const name_token = tree.fullVarDecl(decl).?.ast.mut_token + 1;
                if (name_token >= tree.tokens.len) continue;

                const name = offsets.identifierTokenToNameSlice(tree, name_token);
                try scope.pushDeclaration(name, .{ .ast_node = decl }, .other);
            },

            else => unreachable,
        }
    }

    try scope.finalize();

    if (uses.items.len != 0) {
        const scope_data = &context.doc_scope.scopes.items(.data)[@intFromEnum(scope.scope)];
        scope_data.tag = .container_usingnamespace;
        scope_data.data = .{ .container_usingnamespace = @intCast(context.doc_scope.extra.items.len) };

        try context.doc_scope.extra.ensureUnusedCapacity(allocator, uses.items.len + 2);
        context.doc_scope.extra.appendAssumeCapacity(node_idx);
        context.doc_scope.extra.appendAssumeCapacity(@intCast(uses.items.len));
        context.doc_scope.extra.appendSliceAssumeCapacity(uses.items);
    }
}

noinline fn walkErrorSetNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    // All identifiers in main_token..data.rhs are error fields.
    var tok_i = main_tokens[node_idx] + 2;
    while (tok_i < data[node_idx].rhs) : (tok_i += 1) {
        switch (token_tags[tok_i]) {
            .doc_comment, .comma => {},
            .identifier => {
                const name = offsets.identifierTokenToNameSlice(tree, tok_i);
                try scope.pushDeclaration(name, .{ .error_token = tok_i }, .other);

                try context.doc_scope.error_completions.put(
                    context.allocator,
                    @enumFromInt(context.doc_scope.declarations.len - 1),
                    void{},
                );
            },
            else => {},
        }
    }

    try scope.finalize();
}

noinline fn walkFuncNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const node_tags = tree.nodes.items(.tag);
    const data = tree.nodes.items(.data);

    var buf: [1]Ast.Node.Index = undefined;
    const func = tree.fullFnProto(&buf, node_idx).?;

    const scope = try context.startScope(
        .function,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    var param_index: u16 = 0;
    var it = func.iterate(&tree);
    while (ast.nextFnParam(&it)) |param| : (param_index += 1) {
        if (param.name_token) |name_token| {
            try scope.pushDeclaration(
                offsets.identifierTokenToNameSlice(tree, name_token),
                .{ .param_payload = .{ .param_index = param_index, .func = node_idx } },
                .other,
            );
        }
        try walkNode(context, tree, param.type_expr);
    }

    try walkNode(context, tree, func.ast.return_type);

    if (node_tags[node_idx] == .fn_decl) {
        // Visit the function body
        try walkNode(context, tree, data[node_idx].rhs);
    }

    try scope.finalize();
}

noinline fn walkBlockNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const pushed_scope = try walkBlockNodeKeepOpen(context, tree, node_idx, tree.firstToken(node_idx));
    try pushed_scope.finalize();
}

fn walkBlockNodeKeepOpen(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!ScopeContext.PushedScope {
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);

    const first_token = tree.firstToken(node_idx);
    const last_token = ast.lastToken(tree, node_idx);

    const scope = try context.startScope(
        .block,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.tokensToLoc(tree, start_token, last_token)),
    );

    // if labeled block
    if (token_tags[first_token] == .identifier) {
        try scope.pushDeclaration(
            offsets.identifierTokenToNameSlice(tree, first_token),
            .{ .label_decl = .{ .label = first_token, .block = node_idx } },
            .other,
        );
    }

    var buffer: [2]Ast.Node.Index = undefined;
    const statements = ast.blockStatements(tree, node_idx, &buffer).?;

    for (statements) |idx| {
        try walkNode(context, tree, idx);
        switch (node_tags[idx]) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => {
                const var_decl = tree.fullVarDecl(idx).?;
                const name = offsets.identifierTokenToNameSlice(tree, var_decl.ast.mut_token + 1);
                try scope.pushDeclaration(name, .{ .ast_node = idx }, .other);
            },
            .assign_destructure => {
                const lhs_count = tree.extra_data[data[idx].lhs];
                const lhs_exprs = tree.extra_data[data[idx].lhs + 1 ..][0..lhs_count];

                for (lhs_exprs, 0..) |lhs_node, i| {
                    const var_decl = tree.fullVarDecl(lhs_node) orelse continue;
                    const name = offsets.identifierTokenToNameSlice(tree, var_decl.ast.mut_token + 1);
                    try scope.pushDeclaration(
                        name,
                        .{ .assign_destructure = .{ .node = idx, .index = @intCast(i) } },
                        .other,
                    );
                }
            },
            else => continue,
        }
    }

    return scope;
}

noinline fn walkIfNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);

    const if_node = ast.fullIf(tree, node_idx).?;

    if (if_node.payload_token) |payload_token| {
        const name_token = payload_token + @intFromBool(token_tags[payload_token] == .asterisk);
        const name = offsets.identifierTokenToNameSlice(tree, name_token);

        const decl: Declaration = if (if_node.error_token != null)
            .{ .error_union_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } }
        else
            .{ .pointer_payload = .{ .name = name_token, .condition = if_node.ast.cond_expr } };

        const then_scope = try walkNodeEnsureScope(context, tree, if_node.ast.then_expr, name_token);
        try then_scope.pushDeclaration(name, decl, .other);
        try then_scope.finalize();
    } else {
        try walkNode(context, tree, if_node.ast.then_expr);
    }

    if (if_node.ast.else_expr != 0) {
        if (if_node.error_token) |error_token| {
            const name = offsets.identifierTokenToNameSlice(tree, error_token);

            const else_scope = try walkNodeEnsureScope(context, tree, if_node.ast.else_expr, error_token);
            try else_scope.pushDeclaration(
                name,
                .{ .error_union_error = .{ .name = error_token, .condition = if_node.ast.cond_expr } },
                .other,
            );
            try else_scope.finalize();
        } else {
            try walkNode(context, tree, if_node.ast.else_expr);
        }
    }
}

noinline fn walkCatchNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    try walkNode(context, tree, data[node_idx].lhs);

    const catch_token = main_tokens[node_idx] + 2;
    if (token_tags.len > catch_token and
        token_tags[catch_token - 1] == .pipe and
        token_tags[catch_token] == .identifier)
    {
        const name = offsets.identifierTokenToNameSlice(tree, catch_token);

        const expr_scope = try walkNodeEnsureScope(context, tree, data[node_idx].rhs, catch_token);
        try expr_scope.pushDeclaration(
            name,
            .{ .error_union_error = .{ .name = catch_token, .condition = data[node_idx].lhs } },
            .other,
        );
        try expr_scope.finalize();
    } else {
        try walkNode(context, tree, data[node_idx].rhs);
    }
}

/// label_token: inline_token while (cond_expr) |payload_token| : (cont_expr) then_expr else |error_token| else_expr
noinline fn walkWhileNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);

    const while_node = ast.fullWhile(tree, node_idx).?;

    try walkNode(context, tree, while_node.ast.cond_expr);

    const label_token, const label_name = if (while_node.label_token) |label| blk: {
        std.debug.assert(token_tags[label] == .identifier);
        const name = offsets.tokenToSlice(tree, label);
        break :blk .{ label, name };
    } else .{ null, null };

    const payload_declaration, const payload_name = if (while_node.payload_token) |payload_token| blk: {
        const name_token = payload_token + @intFromBool(token_tags[payload_token] == .asterisk);
        const name = offsets.identifierTokenToNameSlice(tree, name_token);

        const decl: Declaration = if (while_node.error_token != null)
            .{ .error_union_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } }
        else
            .{ .pointer_payload = .{ .name = name_token, .condition = while_node.ast.cond_expr } };
        break :blk .{ decl, name };
    } else .{ null, null };

    if (while_node.ast.cont_expr != 0) {
        if (payload_declaration) |decl| {
            const cont_scope = try walkNodeEnsureScope(context, tree, while_node.ast.cont_expr, tree.firstToken(while_node.ast.cont_expr));
            try cont_scope.pushDeclaration(payload_name.?, decl, .other);
            try cont_scope.finalize();
        } else {
            try walkNode(context, tree, while_node.ast.cont_expr);
        }
    }

    if (payload_declaration != null or label_token != null) {
        const then_start = while_node.payload_token orelse tree.firstToken(while_node.ast.then_expr);
        const then_scope = try walkNodeEnsureScope(context, tree, while_node.ast.then_expr, then_start);

        if (label_token) |label| {
            try then_scope.pushDeclaration(
                label_name.?,
                .{ .label_decl = .{ .label = label, .block = while_node.ast.then_expr } },
                .other,
            );
        }
        if (payload_declaration) |decl| {
            try then_scope.pushDeclaration(payload_name.?, decl, .other);
        }

        try then_scope.finalize();
    } else {
        try walkNode(context, tree, while_node.ast.then_expr);
    }

    if (while_node.ast.else_expr != 0) {
        if (label_token != null or while_node.error_token != null) {
            const else_start = while_node.error_token orelse tree.firstToken(while_node.ast.else_expr);
            const else_scope = try walkNodeEnsureScope(context, tree, while_node.ast.else_expr, else_start);

            if (label_token) |label| {
                try else_scope.pushDeclaration(
                    label_name.?,
                    .{ .label_decl = .{ .label = label, .block = while_node.ast.then_expr } },
                    .other,
                );
            }

            if (while_node.error_token) |error_token| {
                const name = offsets.identifierTokenToNameSlice(tree, error_token);

                try else_scope.pushDeclaration(
                    name,
                    .{ .error_union_error = .{ .name = error_token, .condition = while_node.ast.cond_expr } },
                    .other,
                );
            }

            try else_scope.finalize();
        } else {
            try walkNode(context, tree, while_node.ast.else_expr);
        }
    }
}

/// label_token: inline_token for (inputs) |capture_tokens| then_expr else else_expr
noinline fn walkForNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);

    const for_node = ast.fullFor(tree, node_idx).?;

    for (for_node.ast.inputs) |input_node| {
        try walkNode(context, tree, input_node);
    }

    const then_scope = try walkNodeEnsureScope(context, tree, for_node.ast.then_expr, for_node.payload_token);

    var capture_token = for_node.payload_token;
    for (for_node.ast.inputs) |input| {
        if (capture_token + 1 >= tree.tokens.len) break;
        const capture_is_ref = token_tags[capture_token] == .asterisk;
        const name_token = capture_token + @intFromBool(capture_is_ref);
        capture_token = name_token + 2;

        if (tree.tokens.items(.tag)[name_token] != .identifier) break;
        try then_scope.pushDeclaration(
            offsets.identifierTokenToNameSlice(tree, name_token),
            .{ .array_payload = .{ .identifier = name_token, .array_expr = input } },
            .other,
        );
    }

    const label_name = if (for_node.label_token) |label_token|
        offsets.identifierTokenToNameSlice(context.tree, label_token)
    else
        null;

    if (for_node.label_token) |label_token| {
        try then_scope.pushDeclaration(
            label_name.?,
            .{ .label_decl = .{ .label = label_token, .block = for_node.ast.then_expr } },
            .other,
        );
    }

    try then_scope.finalize();

    if (for_node.ast.else_expr != 0) {
        if (for_node.label_token) |label_token| {
            const else_scope = try walkNodeEnsureScope(context, tree, for_node.ast.else_expr, tree.firstToken(for_node.ast.else_expr));
            try else_scope.pushDeclaration(
                label_name.?,
                .{ .label_decl = .{ .label = label_token, .block = for_node.ast.else_expr } },
                .other,
            );
            try else_scope.finalize();
        } else {
            try walkNode(context, tree, for_node.ast.else_expr);
        }
    }
}

noinline fn walkSwitchNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);
    const data = tree.nodes.items(.data);

    const extra = tree.extraData(data[node_idx].rhs, Ast.Node.SubRange);
    const cases = tree.extra_data[extra.start..extra.end];

    for (cases, 0..) |case, case_index| {
        const switch_case: Ast.full.SwitchCase = tree.fullSwitchCase(case).?;

        if (switch_case.payload_token) |payload_token| {
            const name_token = payload_token + @intFromBool(token_tags[payload_token] == .asterisk);
            const name = offsets.identifierTokenToNameSlice(tree, name_token);

            const expr_scope = try walkNodeEnsureScope(context, tree, switch_case.ast.target_expr, name_token);
            try expr_scope.pushDeclaration(
                name,
                .{ .switch_payload = .{ .node = node_idx, .case_index = @intCast(case_index) } },
                .other,
            );
            try expr_scope.finalize();
        } else {
            try walkNode(context, tree, switch_case.ast.target_expr);
        }
    }
}

noinline fn walkErrdeferNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const data = tree.nodes.items(.data);
    const payload_token = data[node_idx].lhs;

    if (payload_token != 0) {
        const name = offsets.identifierTokenToNameSlice(tree, payload_token);

        const expr_scope = try walkNodeEnsureScope(context, tree, data[node_idx].rhs, payload_token);
        try expr_scope.pushDeclaration(
            name,
            .{ .error_union_error = .{ .name = payload_token, .condition = 0 } },
            .other,
        );
        try expr_scope.finalize();
    } else {
        return try walkNode(context, tree, data[node_idx].rhs);
    }
}

noinline fn walkLhsNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    try walkNode(context, tree, tree.nodes.items(.data)[node_idx].lhs);
}

noinline fn walkRhsNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    try walkNode(context, tree, tree.nodes.items(.data)[node_idx].rhs);
}

noinline fn walkLhsRhsNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    try walkNode(context, tree, tree.nodes.items(.data)[node_idx].lhs);
    try walkNode(context, tree, tree.nodes.items(.data)[node_idx].rhs);
}

noinline fn walkOtherNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    try ast.iterateChildren(tree, node_idx, context, error{OutOfMemory}, walkNode);
}

// Lookup

pub fn getScopeTag(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) Scope.Tag {
    return doc_scope.scopes.items(.data)[@intFromEnum(scope)].tag;
}

pub fn getScopeParent(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) Scope.OptionalIndex {
    return doc_scope.scopes.items(.parent_scope)[@intFromEnum(scope)];
}

pub fn getScopeUsingnamespaceNodesConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Ast.Node.Index {
    const data = doc_scope.scopes.items(.data)[@intFromEnum(scope)];
    switch (data.tag) {
        .container_usingnamespace => {
            const start = data.data.container_usingnamespace;
            const len = doc_scope.extra.items[start + 1];
            return doc_scope.extra.items[start + 2 .. start + 2 + len];
        },
        else => return &.{},
    }
}

pub fn getScopeAstNode(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) ?Ast.Node.Index {
    const slice = doc_scope.scopes.slice();

    const data = slice.items(.data)[@intFromEnum(scope)];

    return switch (data.tag) {
        .container_usingnamespace => doc_scope.extra.items[data.data.container_usingnamespace],
        .container, .function, .block => data.data.ast_node,
        .other => null,
    };
}

pub fn getScopeDeclaration(
    doc_scope: DocumentScope,
    lookup: DeclarationLookup,
) Declaration.OptionalIndex {
    return if (doc_scope.declaration_lookup_map.getIndex(lookup)) |idx|
        @enumFromInt(idx)
    else
        .none;
}

pub fn getScopeDeclarationsConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Declaration.Index {
    const slice = doc_scope.scopes.slice();

    if (slice.items(.data)[@intFromEnum(scope)].is_child_decls_small) {
        const small = &slice.items(.child_declarations)[@intFromEnum(scope)].small;

        for (0..Scope.ChildDeclarations.small_size) |idx| {
            if (small[idx] == .none) {
                return @ptrCast(small[0..idx]);
            }
        }

        return @ptrCast(small[0..Scope.ChildDeclarations.small_size]);
    } else {
        const other = slice.items(.child_declarations)[@intFromEnum(scope)].other;
        return @ptrCast(doc_scope.extra.items[other.start..other.end]);
    }
}

pub fn getScopeChildScopesConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Scope.Index {
    const slice = doc_scope.scopes.slice();

    if (slice.items(.data)[@intFromEnum(scope)].is_child_scopes_small) {
        const small = &slice.items(.child_scopes)[@intFromEnum(scope)].small;

        for (0..Scope.ChildScopes.small_size) |idx| {
            if (small[idx] == .none) {
                return @ptrCast(small[0..idx]);
            }
        }

        return @ptrCast(small[0..Scope.ChildScopes.small_size]);
    } else {
        const other = slice.items(.child_scopes)[@intFromEnum(scope)].other;
        return @ptrCast(doc_scope.extra.items[other.start..other.end]);
    }
}
