//! Stores all Scopes and Declarations/Symbols inside a Zig source file.

const std = @import("std");
const ast = @import("ast.zig");
const Ast = @import("zirp").Ast;
const tracy = @import("tracy");
const offsets = @import("offsets.zig");

const DocumentScope = @This();

scopes: std.MultiArrayList(Scope),
declarations: std.MultiArrayList(Declaration),
/// used for looking up a child declaration in a given scope
declaration_lookup_map: DeclarationLookupMap,
extra: std.ArrayList(u32),

/// Every `index` inside this `ArrayhashMap` is equivalent to a `Declaration.Index`
/// This means that every declaration is only the child of a single scope
pub const DeclarationLookupMap = std.array_hash_map.Custom(
    DeclarationLookup,
    void,
    DeclarationLookupContext,
    false,
);

pub const DeclarationLookup = struct {
    pub const Kind = enum { field, other, label };
    scope: Scope.Index,
    name: []const u8,
    kind: Kind,
};

pub const DeclarationLookupContext = struct {
    pub fn hash(self: @This(), s: DeclarationLookup) u32 {
        _ = self;
        var hasher: std.hash.Wyhash = .init(0);
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

pub const Declaration = union(enum) {
    ast_node: Node.Index,
    /// Function parameter
    function_parameter: Param,
    /// - `if (condition) |identifier| {}`
    /// - `while (condition) |identifier| {}`
    optional_payload: struct {
        identifier: Ast.Token.Index,
        condition: Ast.Expr.Index,
    },
    /// - `for (input) |identifier| {}`
    /// - `for (..., input, ...) |..., identifier, ...| {}`
    for_loop_payload: struct {
        identifier: Ast.Token.Index,
        input: Ast.Expr.For.Input.Index,
    },
    /// - `if (condition) |identifier| {} else |_| {}`
    /// - `while (condition) |identifier| {} else |_| {}`
    error_union_payload: struct {
        identifier: Ast.Token.Index,
        condition: Ast.Expr.Index,
    },
    /// - `if (condition) |_| {} else |identifier| {}`
    /// - `while (condition) |_| {} else |identifier| {}`
    /// - `condition catch |identifier| {}`
    /// - `errdefer |identifier| {}` (condition is `.none`)
    error_union_error: struct {
        identifier: Ast.Token.Index,
        condition: Ast.Node.OptionalIndex,
    },
    assign_destructure: Destructure,
    /// - `switch (condition) { .case => |value| {} }`
    switch_payload: Switch,
    /// - `switch (condition) { inline .case => |_, tag| {} }`
    /// - `switch (condition) { inline else => |_, tag| {} }`
    switch_inline_tag_payload: Switch,
    label: struct {
        identifier: Ast.Token.Index,
        expr: Ast.Expr.Index,
    },
    /// always an identifier
    /// used as child declarations of an error set declaration
    error_token: Ast.Token.Index,

    comptime {
        for (@typeInfo(Declaration).@"union".field_types) |T| {
            std.debug.assert(@sizeOf(T) <= 8); // a Declaration without the union tag must be less than 8 bytes
        }
    }

    pub const Node = union(enum) {
        pub const Index = Ast.UnionNode(@This());

        type_fn: Ast.Expr.Fn.Index,
        decl_fn: Ast.Member.Fn.Index,
        field: Ast.Member.Field.Index,
        var_local: Ast.Statement.LocalVar.Index,
        var_global: Ast.Member.GlobalVar.Index,
    };

    pub const Param = struct {
        node: Ast.Expr.Fn.Param.Index,
        /// BRANCH_TODO should only be `.type_fn` or `.decl_fn`
        func: Ast.Node.Index,

        pub fn get(param: Param, tree: *const Ast) Ast.FnDeclOrFnProto {
            return switch (param.func.tag(tree)) {
                .type_fn => .from(Ast.Expr.Fn.Index{ .idx = param.func }, tree),
                .decl_fn => .from(Ast.Member.Fn.Index{ .idx = param.func }, tree),
                else => unreachable,
            };
        }
    };

    pub const Destructure = struct {
        node: Ast.Expr.Destructure.Index,
        lvalue_index: u32,

        pub fn getVarProto(destructure: Destructure, tree: *const Ast) Ast.Expr.Destructure.LValue.VarProto.Index {
            var lvalue_it = destructure.node.get(tree).lvalues.iter(tree);
            for (0..destructure.lvalue_index -| 1) |_| {
                _ = lvalue_it.next(tree).?;
            }
            return lvalue_it.next(tree).?.cast(.var_proto, tree).?;
        }
    };

    pub const Switch = struct {
        node: Ast.Expr.Switch.Index,
        /// Guaranteed to have a payload with at least one binding.
        prong: Ast.Expr.Switch.Prong.Index,
    };

    pub const Index = enum(u32) {
        _,

        pub fn toOptional(index: Index) OptionalIndex {
            return @fromBackingInt(@backingInt(index));
        }
    };

    pub const OptionalIndex = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(index: OptionalIndex) ?Index {
            if (index == .none) return null;
            return @fromBackingInt(@backingInt(index));
        }
    };

    pub fn eql(a: Declaration, b: Declaration) bool {
        return std.meta.eql(a, b);
    }

    /// Returns a `.identifier` or `.builtin` token.
    pub fn nameToken(decl: Declaration, tree: *const Ast) Ast.Token.Index {
        const name_token: Ast.Token.Index = switch (decl) {
            .ast_node => |node| switch (node.get(tree)) {
                inline .var_local, .var_global => |var_decl| var_decl.get(tree).name(tree).?,
                .field => |field| field.get(tree).name.?.token(tree),
                .type_fn => |fn_proto| fn_proto.get(tree).name(tree).?,
                .decl_fn => |fn_decl| fn_decl.get(tree).proto.get(tree).name(tree).?,
            },
            .function_parameter => |payload| payload.node.get(tree).name.?.token(tree),
            .optional_payload => |payload| payload.identifier,
            .error_union_payload => |payload| payload.identifier,
            .error_union_error => |payload| payload.identifier,
            .for_loop_payload => |payload| payload.identifier,
            .label => |payload| payload.identifier,
            .error_token => |error_token| error_token,
            .assign_destructure => |payload| payload.getVarProto(tree).get(tree).name(tree).?,
            .switch_payload,
            .switch_inline_tag_payload,
            => |payload| blk: {
                const prong = payload.prong.get(tree);
                var bindings = prong.payload.?.get(tree).bindings.iter(tree);
                if (decl == .switch_inline_tag_payload) _ = bindings.next(tree);
                break :blk bindings.next(tree).?.get(tree).name(tree).?;
            },
        };

        switch (name_token.tag(tree)) {
            .name, .name_builtin => return name_token,
            else => unreachable,
        }
    }
};

pub const Scope = struct {
    pub const Tag = enum(u3) {
        /// `ast_node.tag(tree)` is `.type_container` or `.root` or `.type_error_set`
        container,
        /// `ast_node.tag(tree)` is `.type_fn`
        function,
        /// `ast_node.tag(tree)` is `.block`
        block,
        other,

        pub fn isContainer(self: @This()) bool {
            return switch (self) {
                .container => true,
                .block, .function, .other => false,
            };
        }
    };

    pub const Data = packed union {
        ast_node: Ast.Node.Index,
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
        root,
        _,

        pub fn toOptional(index: Index) OptionalIndex {
            return @fromBackingInt(@backingInt(index));
        }
    };

    pub const OptionalIndex = enum(u32) {
        root,
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(index: OptionalIndex) ?Index {
            if (index == .none) return null;
            return @fromBackingInt(@backingInt(index));
        }
    };
};

const ScopeContext = struct {
    allocator: std.mem.Allocator,
    tree: *const Ast,
    doc_scope: *DocumentScope,

    current_scope: Scope.OptionalIndex = .none,
    child_scopes_scratch: std.ArrayList(Scope.Index) = .empty,
    child_declarations_scratch: std.ArrayList(Declaration.Index) = .empty,

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
            identifier_token: Ast.Token.Index,
            declaration: Declaration,
            kind: DeclarationLookup.Kind,
        ) error{OutOfMemory}!void {
            std.debug.assert((declaration == .label) == (kind == .label));
            const name = offsets.identifierTokenToNameSlice(pushed.context.tree, identifier_token);
            if (std.mem.eql(u8, name, "_")) return;
            defer std.debug.assert(pushed.context.doc_scope.declarations.len == pushed.context.doc_scope.declaration_lookup_map.count());

            if (@import("builtin").mode == .debug) {
                // Check that nameToken works
                std.debug.assert(identifier_token == declaration.nameToken(pushed.context.tree));
            }

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
            const declaration_index: Declaration.Index = @fromBackingInt(@intCast(doc_scope.declarations.len - 1));

            const data = &doc_scope.scopes.items(.data)[@backingInt(pushed.scope)];
            const child_declarations = &doc_scope.scopes.items(.child_declarations)[@backingInt(pushed.scope)];

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
            const data = slice.items(.data)[@backingInt(pushed.scope)];

            if (!data.is_child_decls_small) {
                const declaration_start = context.doc_scope.extra.items.len;
                try context.doc_scope.extra.appendSlice(allocator, @ptrCast(context.child_declarations_scratch.items[pushed.declarations_start..]));
                const declaration_end = context.doc_scope.extra.items.len;
                context.child_declarations_scratch.items.len = pushed.declarations_start;

                slice.items(.child_declarations)[@backingInt(pushed.scope)] = .{
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

                slice.items(.child_scopes)[@backingInt(pushed.scope)] = .{
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
                .small = @splat(.none),
            },
            .child_declarations = .{
                .small = @splat(.none),
            },
        });
        const new_scope_index: Scope.Index = @fromBackingInt(@intCast(context.doc_scope.scopes.len - 1));
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

        const data = &doc_scope.scopes.items(.data)[@backingInt(scope_index)];
        const child_scopes = &doc_scope.scopes.items(.child_scopes)[@backingInt(scope_index)];

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

pub fn init(allocator: std.mem.Allocator, tree: *const Ast) error{OutOfMemory}!DocumentScope {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var document_scope: DocumentScope = .{
        .scopes = .empty,
        .declarations = .empty,
        .declaration_lookup_map = .empty,
        .extra = .empty,
    };
    errdefer document_scope.deinit(allocator);

    var context: ScopeContext = .{
        .allocator = allocator,
        .tree = tree,
        .doc_scope = &document_scope,
    };
    defer context.deinit();
    switch (tree.mode) {
        .zig => {
            var container: Ast.ContainerOrRoot = .from(tree.root(), tree);
            try walkContainerOrRoot(&context, tree, .root, &container);
        },
        .zon => {
            if (true) @panic("BRANCH_TODO");
            const new_scope = try context.startScope(
                .container,
                .{ .ast_node = .root },
                .{ .start = 0, .end = @intCast(tree.source.len) },
            );
            try walkExpr(&context, tree, .root);
            try new_scope.finalize();
        },
    }

    return document_scope;
}

pub fn deinit(scope: *DocumentScope, allocator: std.mem.Allocator) void {
    scope.scopes.deinit(allocator);
    scope.declarations.deinit(allocator);
    scope.declaration_lookup_map.deinit(allocator);
    scope.extra.deinit(allocator);
}

fn locToSmallLoc(loc: offsets.Loc) Scope.SmallLoc {
    return .{
        .start = @intCast(loc.start),
        .end = @intCast(loc.end),
    };
}

/// Similar to `walkExpr` but also returns a new scope.
/// Asserts that `node_idx != .root`
/// Caller must finalize the scope
fn walkExprEnsureScope(
    context: *ScopeContext,
    tree: *const Ast,
    expr: Ast.Expr.Index,
    start_token: Ast.Token.Index,
) error{OutOfMemory}!ScopeContext.PushedScope {
    // std.debug.assert(node_idx != .root);
    switch (expr.idx.tag(tree)) {
        .block => {
            // special case where we reuse the block scope
            return try walkBlockNodeKeepOpen(context, tree, expr.cast(.block, tree).?, start_token);
        },
        else => {
            const new_scope = try context.startScope(
                .other,
                undefined,
                locToSmallLoc(offsets.tokensToLoc(tree, start_token, ast.lastToken(tree, expr.idx))),
            );
            try walkExpr(context, tree, expr);
            return new_scope;
        },
    }
}

fn walkExpr(
    context: *ScopeContext,
    tree: *const Ast,
    node: Ast.Expr.Index,
) error{OutOfMemory}!void {
    switch (node.get(tree)) {
        .syntax_error => return,

        .name,
        .char,
        .@"error",
        .string,
        .number,
        .multiline_string,
        .@"unreachable",
        .enum_literal,
        => return,

        .container => {
            var container: Ast.ContainerOrRoot = .from(node.cast(.container, tree).?, tree);
            try walkContainerOrRoot(context, tree, node.idx, &container);
        },
        .error_set => try walkErrorSetNode(context, tree, .{ .idx = node.idx }),
        .block => try walkBlockNode(context, tree, .{ .idx = node.idx }),
        .@"if" => try walkIfNode(context, tree, .{ .idx = node.idx }),
        .@"catch" => try walkCatchNode(context, tree, .{ .idx = node.idx }),
        .@"while" => try walkWhileNode(context, tree, .{ .idx = node.idx }),
        .@"for" => try walkForNode(context, tree, .{ .idx = node.idx }),
        .@"switch" => try walkSwitchNode(context, tree, .{ .idx = node.idx }),
        .@"fn" => try walkFuncNode(context, tree, node.idx),

        .call => |call_idx| {
            const call = call_idx.get(tree);
            try walkExpr(context, tree, call.callee);
            var it = call.args.iter(tree);
            while (it.next(tree)) |arg| try walkExpr(context, tree, arg);
        },
        .init => |init_idx| {
            const init_node = init_idx.get(tree);
            if (init_node.type) |type_expr| try walkExpr(context, tree, type_expr);
            var it = init_node.fields.iter(tree);
            while (it.next(tree)) |field| {
                switch (field.get(tree)) {
                    .struct_field => |struct_field_idx| {
                        const struct_field = struct_field_idx.get(tree);
                        try walkExpr(context, tree, struct_field.init);
                    },
                    .tuple_field => |expr| try walkExpr(context, tree, expr),
                }
            }
        },
        .@"asm" => |asm_idx| {
            const asm_node = asm_idx.get(tree);
            try walkExpr(context, tree, asm_node.instruction_string);
            _ = asm_node.outputs; // TODO
            _ = asm_node.inputs; // TODO
            if (asm_node.clobbers) |clobbers_expr| try walkExpr(context, tree, clobbers_expr);
        },
        .slice => |slice_idx| {
            const slice = slice_idx.get(tree);
            try walkExpr(context, tree, slice.lhs);
            try walkExpr(context, tree, slice.start);
            if (slice.end) |end_expr| try walkExpr(context, tree, end_expr);
            if (slice.sentinel) |sentinel_expr| try walkExpr(context, tree, sentinel_expr);
        },
        .array => |array_idx| {
            const array = array_idx.get(tree);
            try walkExpr(context, tree, array.child_type);
            if (array.sentinel) |sentinel_expr| try walkExpr(context, tree, sentinel_expr);
            try walkExpr(context, tree, array.size);
        },
        .prefix => |prefix_idx| {
            const prefix = prefix_idx.get(tree);
            try walkExpr(context, tree, prefix.rhs);
        },
        .pointer => |pointer_idx| {
            const pointer = pointer_idx.get(tree);
            try walkExpr(context, tree, pointer.child_type);
            var it = pointer.mods.iter(tree);
            while (it.next(tree)) |mod| {
                switch (mod.get(tree).payload.get(tree)) {
                    .expr => |expr| try walkExpr(context, tree, expr),
                    .bitalign => |bitalign_idx| {
                        const bitalign = bitalign_idx.get(tree);
                        try walkExpr(context, tree, bitalign.byte);
                        try walkExpr(context, tree, bitalign.bit_start);
                        try walkExpr(context, tree, bitalign.bit_end);
                    },
                }
            }
        },
        .builtin => |builtin_idx| {
            const builtin = builtin_idx.get(tree);
            var it = builtin.args.iter(tree);
            while (it.next(tree)) |arg| try walkExpr(context, tree, arg);
        },
        .@"comptime" => |comptime_idx| {
            const comptime_node = comptime_idx.get(tree);
            try walkExpr(context, tree, comptime_node.inner);
        },
        .destructure => |destructure_idx| {
            const destructure = destructure_idx.get(tree);
            var it = destructure.lvalues.iter(tree);
            while (it.next(tree)) |lvalue| {
                switch (lvalue.get(tree)) {
                    .expr => |expr| try walkExpr(context, tree, expr),
                    .var_proto => |var_proto_idx| {
                        const var_proto = var_proto_idx.get(tree);
                        if (var_proto.type) |type_expr| try walkExpr(context, tree, type_expr);
                        // TODO var_proto.attributes(tree)
                    },
                }
            }
            try walkExpr(context, tree, destructure.init);
        },

        inline .@"return", .@"continue", .@"break" => |idx| {
            const data = idx.get(tree);
            if (data.value) |expr| try walkExpr(context, tree, expr);
        },
        inline .deref, .unwrap, .dot_access => |idx| {
            const data = idx.get(tree);
            try walkExpr(context, tree, data.lhs);
        },
        inline .optional, .grouping => |idx| {
            const data = idx.get(tree);
            try walkExpr(context, tree, data.inner);
        },
        inline .binary, .assign, .index, .error_union, .compound_assign => |idx| {
            const data = idx.get(tree);
            try walkExpr(context, tree, data.lhs);
            try walkExpr(context, tree, data.rhs);
        },
    }
}

fn walkContainerOrRoot(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Node.Index,
    container: *Ast.ContainerOrRoot,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    while (container.members.next(tree)) |member_idx| {
        _ = &walkExpr;
        // try walkExpr(context, tree, member_idx.idx);
        switch (member_idx.get(tree)) {
            .@"test", .@"comptime" => {},
            .field => |field| {
                const container_field = field.get(tree);
                const field_name = container_field.name orelse return;
                const main_token = field_name.token(tree);
                if (main_token.tag(tree) != .name) return;
                try scope.pushDeclaration(main_token, .{ .ast_node = .init(.field, field, tree) }, .field);
            },
            .@"fn" => |func| {
                const name_token = func.get(tree).proto.get(tree).name(tree) orelse return;
                try scope.pushDeclaration(name_token, .{ .ast_node = .init(.decl_fn, func, tree) }, .other);
            },
            .@"var" => |global_var| {
                const name_token = global_var.get(tree).name(tree) orelse return;
                try scope.pushDeclaration(name_token, .{ .ast_node = .init(.var_global, global_var, tree) }, .other);
            },
        }
    }

    try scope.finalize();
}

fn walkErrorSetNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.ErrorSet.Index,
) error{OutOfMemory}!void {
    const expr = node_idx.get(tree);

    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx.idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx.idx)),
    );

    var it = expr.errors.iter(tree);
    while (it.next(tree)) |err| {
        const error_token = err.get(tree).token;
        try scope.pushDeclaration(error_token, .{ .error_token = error_token }, .other);
    }

    try scope.finalize();
}

fn walkFuncNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const fn_decl: Ast.Member.Fn = switch (node_idx.tag(tree)) {
        .type_fn => .{ .proto = .{ .idx = node_idx }, .body = null },
        .decl_fn => node_idx.cast(.decl_fn, tree).?,
        else => unreachable,
    };
    const fn_proto = fn_decl.proto.get(tree);

    const scope = try context.startScope(
        .function,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    var it = fn_proto.params.get(tree).items.iter(tree);
    while (it.next(tree)) |param_idx| {
        const param = param_idx.get(tree);

        if (param.name) |name_node| {
            const name_token = name_node.token(tree);
            try scope.pushDeclaration(
                name_token,
                .{ .function_parameter = .{ .node = param_idx, .func = node_idx } },
                .other,
            );
        }
        switch (param.type.get(tree)) {
            .expr => |type_expr| try walkExpr(context, tree, type_expr),
            .@"anytype", .varargs => {},
        }
    }

    try walkExpr(context, tree, fn_proto.return_type);

    if (fn_decl.body) |body_expr| {
        try walkExpr(context, tree, .init(.block, body_expr, tree));
    }

    try scope.finalize();
}

fn walkBlockNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Block.Index,
) error{OutOfMemory}!void {
    const pushed_scope = try walkBlockNodeKeepOpen(context, tree, node_idx, node_idx.idx.firstToken(tree));
    try pushed_scope.finalize();
}

fn walkBlockNodeKeepOpen(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Block.Index,
    start_token: Ast.Token.Index,
) error{OutOfMemory}!ScopeContext.PushedScope {
    const last_token = ast.lastToken(tree, node_idx.idx);

    const block = node_idx.get(tree);

    const scope = try context.startScope(
        .block,
        .{ .ast_node = node_idx.idx },
        locToSmallLoc(offsets.tokensToLoc(tree, start_token, last_token)),
    );

    if (block.label(tree)) |label_token| {
        try scope.pushDeclaration(
            label_token,
            .{ .label = .{ .identifier = label_token, .expr = .init(.block, node_idx, tree) } },
            .label,
        );
    }

    var statement_it = block.statements.iter(tree);
    while (statement_it.next(tree)) |statement_idx| {
        // BRANCH_TODO
        // try walkExpr(context, tree, statement_idx);
        switch (statement_idx.get(tree)) {
            .@"var" => |var_decl_idx| {
                const var_decl = var_decl_idx.get(tree);
                const name_token = var_decl.name(tree) orelse continue;
                try scope.pushDeclaration(name_token, .{ .ast_node = .init(.var_local, var_decl_idx, tree) }, .other);
            },
            .expr => |expr_idx| {
                const destructure_idx = expr_idx.cast(.destructure, tree) orelse continue;
                const destructure: Ast.Expr.Destructure = destructure_idx.get(tree);
                var lvalue_it = destructure.lvalues.iter(tree);
                var lvalue_index: u32 = 0;
                while (lvalue_it.next(tree)) |lvalue| : (lvalue_index += 1) {
                    const var_proto = switch (lvalue.get(tree)) {
                        .var_proto => |var_proto| var_proto.get(tree),
                        .expr => continue,
                    };
                    const name_token = var_proto.name(tree) orelse continue;
                    try scope.pushDeclaration(
                        name_token,
                        .{ .assign_destructure = .{ .node = destructure_idx, .lvalue_index = lvalue_index } },
                        .other,
                    );
                }
            },
            .@"defer" => continue,
        }
    }

    return scope;
}

fn walkIfNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.If.Index,
) error{OutOfMemory}!void {
    const if_node = node_idx.get(tree);

    try walkExpr(context, tree, if_node.condition);

    const then_payload_token: ?Ast.Token.Index = blk: {
        const payload_idx = if_node.then_payload orelse break :blk null;
        const payload = payload_idx.get(tree);
        var bindings = payload.bindings.iter(tree);
        const binding = bindings.next(tree) orelse break :blk null;
        break :blk binding.get(tree).name(tree);
    };

    const else_payload_token: ?Ast.Token.Index = blk: {
        const payload_idx = if_node.else_payload orelse break :blk null;
        const payload = payload_idx.get(tree);
        var bindings = payload.bindings.iter(tree);
        const binding = bindings.next(tree) orelse break :blk null;
        break :blk binding.get(tree).name(tree);
    };

    if (then_payload_token) |payload_token| {
        const decl: Declaration = if (else_payload_token != null)
            .{ .error_union_payload = .{ .identifier = payload_token, .condition = if_node.condition } }
        else
            .{ .optional_payload = .{ .identifier = payload_token, .condition = if_node.condition } };

        const then_scope = try walkExprEnsureScope(context, tree, if_node.then_branch, payload_token);
        try then_scope.pushDeclaration(payload_token, decl, .other);
        try then_scope.finalize();
    } else {
        try walkExpr(context, tree, if_node.then_branch);
    }

    if (if_node.else_branch) |else_expr| {
        if (else_payload_token) |error_token| {
            const else_scope = try walkExprEnsureScope(context, tree, else_expr, error_token);
            try else_scope.pushDeclaration(
                error_token,
                .{ .error_union_error = .{ .identifier = error_token, .condition = if_node.condition.idx.toOptional() } },
                .other,
            );
            try else_scope.finalize();
        } else {
            try walkExpr(context, tree, else_expr);
        }
    }
}

fn walkCatchNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.Catch.Index,
) error{OutOfMemory}!void {
    const catch_node = node_idx.get(tree);
    try walkExpr(context, tree, catch_node.lhs);

    const payload_token: ?Ast.Token.Index = blk: {
        const payload_idx = catch_node.payload orelse break :blk null;
        const payload = payload_idx.get(tree);
        var bindings = payload.bindings.iter(tree);
        const binding = bindings.next(tree) orelse break :blk null;
        break :blk binding.get(tree).name(tree);
    };

    if (payload_token) |name_token| {
        const expr_scope = try walkExprEnsureScope(context, tree, catch_node.rhs, name_token);
        try expr_scope.pushDeclaration(
            name_token,
            .{ .error_union_error = .{ .identifier = name_token, .condition = catch_node.lhs.idx.toOptional() } },
            .other,
        );
        try expr_scope.finalize();
    } else {
        try walkExpr(context, tree, catch_node.rhs);
    }
}

/// label_token: inline_token while (cond_expr) |payload_token| : (cont_expr) then_expr else |error_token| else_expr
fn walkWhileNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.While.Index,
) error{OutOfMemory}!void {
    const while_node = node_idx.get(tree);

    try walkExpr(context, tree, while_node.condition);

    const payload_token: ?Ast.Token.Index = blk: {
        const payload_idx = while_node.payload orelse break :blk null;
        const payload = payload_idx.get(tree);
        var bindings = payload.bindings.iter(tree);
        const binding = bindings.next(tree) orelse break :blk null;
        break :blk binding.get(tree).name(tree);
    };

    const else_payload_token: ?Ast.Token.Index = blk: {
        const payload_idx = while_node.else_payload orelse break :blk null;
        const payload = payload_idx.get(tree);
        var bindings = payload.bindings.iter(tree);
        const binding = bindings.next(tree) orelse break :blk null;
        break :blk binding.get(tree).name(tree);
    };

    const payload_declaration: ?Declaration = decl: {
        const name_token = payload_token orelse break :decl null;
        if (else_payload_token != null) {
            break :decl .{ .error_union_payload = .{ .identifier = name_token, .condition = while_node.condition } };
        }
        break :decl .{ .optional_payload = .{ .identifier = name_token, .condition = while_node.condition } };
    };

    if (while_node.advance) |advance_expr| {
        if (payload_declaration) |decl| {
            const cont_scope = try walkExprEnsureScope(context, tree, advance_expr, advance_expr.idx.firstToken(tree));
            try cont_scope.pushDeclaration(payload_token.?, decl, .other);
            try cont_scope.finalize();
        } else {
            try walkExpr(context, tree, advance_expr);
        }
    }

    if (payload_declaration != null or while_node.label(tree) != null) {
        const then_start = payload_token orelse while_node.body.idx.firstToken(tree);
        const then_scope = try walkExprEnsureScope(context, tree, while_node.body, then_start);

        if (while_node.label(tree)) |label| {
            try then_scope.pushDeclaration(
                label,
                .{ .label = .{ .identifier = label, .expr = while_node.body } },
                .label,
            );
        }
        if (payload_declaration) |decl| {
            try then_scope.pushDeclaration(payload_token.?, decl, .other);
        }

        try then_scope.finalize();
    } else {
        try walkExpr(context, tree, while_node.body);
    }

    if (while_node.@"else") |else_expr| {
        if (while_node.label(tree) != null or else_payload_token != null) {
            const else_start = else_payload_token orelse else_expr.idx.firstToken(tree);
            const else_scope = try walkExprEnsureScope(context, tree, else_expr, else_start);

            if (while_node.label(tree)) |label| {
                try else_scope.pushDeclaration(
                    label,
                    .{ .label = .{ .identifier = label, .expr = while_node.body } },
                    .label,
                );
            }

            if (else_payload_token) |error_token| {
                try else_scope.pushDeclaration(
                    error_token,
                    .{ .error_union_error = .{ .identifier = error_token, .condition = while_node.condition.idx.toOptional() } },
                    .other,
                );
            }

            try else_scope.finalize();
        } else {
            try walkExpr(context, tree, else_expr);
        }
    }
}

/// label_token: inline_token for (inputs) |capture_tokens| then_expr else else_expr
fn walkForNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.For.Index,
) error{OutOfMemory}!void {
    const for_node = node_idx.get(tree);

    {
        var it = for_node.inputs.get(tree).items.iter(tree);
        while (it.next(tree)) |input_idx| {
            switch (input_idx.get(tree)) {
                .expr => |expr_idx| try walkExpr(context, tree, expr_idx),
                .range => |range_idx| {
                    const range = range_idx.get(tree);
                    try walkExpr(context, tree, range.start);
                    if (range.end) |end_expr| try walkExpr(context, tree, end_expr);
                },
            }
        }
    }

    const payload = for_node.payload.getFailing(tree) catch return; // BRANCH_TODO

    const then_scope = try walkExprEnsureScope(context, tree, for_node.body, payload.bindings.idx.firstToken(tree));

    var input_it = for_node.inputs.get(tree).items.iter(tree);
    var binding_it = payload.bindings.iter(tree);
    while (true) {
        const input = input_it.next(tree) orelse break;
        const binding = binding_it.next(tree) orelse break;

        const name_token = binding.get(tree).name(tree) orelse continue;
        try then_scope.pushDeclaration(
            name_token,
            .{ .for_loop_payload = .{ .identifier = name_token, .input = input } },
            .other,
        );
    }

    if (for_node.label(tree)) |label_token| {
        try then_scope.pushDeclaration(
            label_token,
            .{ .label = .{ .identifier = label_token, .expr = for_node.body } },
            .label,
        );
    }

    try then_scope.finalize();

    if (for_node.@"else") |else_expr| {
        if (for_node.label(tree)) |label_token| {
            const else_scope = try walkExprEnsureScope(context, tree, else_expr, else_expr.idx.firstToken(tree));
            try else_scope.pushDeclaration(
                label_token,
                .{ .label = .{ .identifier = label_token, .expr = else_expr } },
                .label,
            );
            try else_scope.finalize();
        } else {
            try walkExpr(context, tree, else_expr);
        }
    }
}

fn walkSwitchNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.Switch.Index,
) error{OutOfMemory}!void {
    const switch_node: Ast.Expr.Switch = node_idx.get(tree);

    const switch_scope = if (switch_node.label(tree)) |label_token| blk: {
        const scope = try context.startScope(
            .other,
            .{ .ast_node = node_idx.idx },
            locToSmallLoc(offsets.nodeToLoc(tree, node_idx.idx)),
        );
        try scope.pushDeclaration(
            label_token,
            .{ .label = .{ .identifier = label_token, .expr = .init(.@"switch", node_idx, tree) } },
            .label,
        );
        break :blk scope;
    } else null;

    try walkExpr(context, tree, switch_node.condition);

    var prong_it = switch_node.prongs.iter(tree);
    while (prong_it.next(tree)) |prong_idx| {
        const prong = prong_idx.get(tree);

        var case_it = prong.cases.iter(tree);
        while (case_it.next(tree)) |case| {
            switch (case.get(tree)) {
                .item => |expr| try walkExpr(context, tree, expr),
                .range => |range_idx| {
                    const range = range_idx.get(tree);
                    try walkExpr(context, tree, range.start);
                    try walkExpr(context, tree, range.end);
                },
                .@"else" => {},
            }
        }

        if (prong.payload) |payload_idx| no_payload: {
            const payload = payload_idx.get(tree);

            var bindings = payload.bindings.iter(tree);

            const first_binding = bindings.next(tree) orelse break :no_payload;
            const first_name_token = first_binding.get(tree).name(tree) orelse break :no_payload;
            const expr_scope = try walkExprEnsureScope(context, tree, prong.body, first_name_token);
            try expr_scope.pushDeclaration(
                first_name_token,
                .{ .switch_payload = .{ .node = node_idx, .prong = prong_idx } },
                .other,
            );

            if (bindings.next(tree)) |binding| blk: {
                const second_name_token = binding.get(tree).name(tree) orelse break :blk;
                try expr_scope.pushDeclaration(
                    second_name_token,
                    .{ .switch_inline_tag_payload = .{ .node = node_idx, .prong = prong_idx } },
                    .other,
                );
            }
            try expr_scope.finalize();
        } else {
            try walkExpr(context, tree, prong.body);
        }
    }
    if (switch_scope) |scope| try scope.finalize();
}

fn walkOtherNode(
    context: *ScopeContext,
    tree: *const Ast,
    node_idx: Ast.Expr.Index,
) error{OutOfMemory}!void {
    var it: ast.Iterator = .init(tree, node_idx.idx);
    while (it.next(tree)) |child| try walkExpr(context, tree, child);
}

// Lookup

pub fn getScopeTag(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) Scope.Tag {
    return doc_scope.scopes.items(.data)[@backingInt(scope)].tag;
}

pub fn getScopeParent(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) Scope.OptionalIndex {
    return doc_scope.scopes.items(.parent_scope)[@backingInt(scope)];
}

pub fn getScopeAstNode(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) ?Ast.Node.Index {
    const slice = doc_scope.scopes.slice();

    const data = slice.items(.data)[@backingInt(scope)];

    return switch (data.tag) {
        .container, .function, .block => data.data.ast_node,
        .other => null,
    };
}

pub fn getScopeDeclaration(
    doc_scope: DocumentScope,
    lookup: DeclarationLookup,
) Declaration.OptionalIndex {
    return if (doc_scope.declaration_lookup_map.getIndex(lookup)) |idx|
        @fromBackingInt(@intCast(idx))
    else
        .none;
}

pub fn getScopeDeclarationsConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Declaration.Index {
    const slice = doc_scope.scopes.slice();

    if (slice.items(.data)[@backingInt(scope)].is_child_decls_small) {
        const small = &slice.items(.child_declarations)[@backingInt(scope)].small;

        for (0..Scope.ChildDeclarations.small_size) |idx| {
            if (small[idx] == .none) {
                return @ptrCast(small[0..idx]);
            }
        }

        return @ptrCast(small[0..Scope.ChildDeclarations.small_size]);
    } else {
        const other = slice.items(.child_declarations)[@backingInt(scope)].other;
        return @ptrCast(doc_scope.extra.items[other.start..other.end]);
    }
}

pub fn getScopeChildScopesConst(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) []const Scope.Index {
    const slice = doc_scope.scopes.slice();

    if (slice.items(.data)[@backingInt(scope)].is_child_scopes_small) {
        const small = &slice.items(.child_scopes)[@backingInt(scope)].small;

        for (0..Scope.ChildScopes.small_size) |idx| {
            if (small[idx] == .none) {
                return @ptrCast(small[0..idx]);
            }
        }

        return @ptrCast(small[0..Scope.ChildScopes.small_size]);
    } else {
        const other = slice.items(.child_scopes)[@backingInt(scope)].other;
        return @ptrCast(doc_scope.extra.items[other.start..other.end]);
    }
}
