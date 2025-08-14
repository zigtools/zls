//! Stores all Scopes and Declarations/Symbols inside a Zig source file.

const std = @import("std");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;
const tracy = @import("tracy");
const offsets = @import("offsets.zig");

const DocumentScope = @This();

scopes: std.MultiArrayList(Scope),
declarations: std.MultiArrayList(Declaration),
/// used for looking up a child declaration in a given scope
declaration_lookup_map: DeclarationLookupMap,
extra: std.ArrayList(u32),
/// All identifier token that are in error sets.
/// When there are multiple error sets that contain the same error, only one of them is stored.
/// A token that has a doc comment takes priority.
/// This means that if there a multiple error sets with the same name, only one of them is included.
global_error_set: IdentifierSet,
/// All identifier token that are in enums.
/// When there are multiple enums that contain the field name, only one of them is stored.
/// A token that has a doc comment takes priority.
/// This means that if there a multiple enums with the same name, only one of them is included.
global_enum_set: IdentifierSet,

/// Stores a set of identifier tokens with unique names
pub const IdentifierSet = std.ArrayHashMapUnmanaged(Ast.TokenIndex, void, IdentifierTokenContext, true);

pub const IdentifierTokenContext = struct {
    tree: Ast,

    pub fn eql(self: @This(), a: Ast.TokenIndex, b: Ast.TokenIndex, b_index: usize) bool {
        _ = b_index;
        if (a == b) return true;
        const a_name = offsets.identifierTokenToNameSlice(self.tree, a);
        const b_name = offsets.identifierTokenToNameSlice(self.tree, b);
        return std.mem.eql(u8, a_name, b_name);
    }

    pub fn hash(self: @This(), token: Ast.TokenIndex) u32 {
        const name = offsets.identifierTokenToNameSlice(self.tree, token);
        return std.array_hash_map.hashString(name);
    }
};

/// Every `index` inside this `ArrayhashMap` is equivalent to a `Declaration.Index`
/// This means that every declaration is only the child of a single scope
pub const DeclarationLookupMap = std.ArrayHashMapUnmanaged(
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
    /// Index of the ast node.
    /// Can have one of the following tags:
    ///   - `.container_field`
    ///   - `.fn_proto`
    ///   - `.fn_decl`
    ///   - `.var_decl`
    ast_node: Ast.Node.Index,
    /// Function parameter
    function_parameter: Param,
    /// - `if (condition) |identifier| {}`
    /// - `while (condition) |identifier| {}`
    optional_payload: struct {
        identifier: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    /// - `for (condition) |identifier| {}`
    /// - `for (..., condition, ...) |..., identifier, ...| {}`
    for_loop_payload: struct {
        identifier: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    /// - `if (condition) |identifier| {} else |_| {}`
    /// - `while (condition) |identifier| {} else |_| {}`
    error_union_payload: struct {
        identifier: Ast.TokenIndex,
        condition: Ast.Node.Index,
    },
    /// - `if (condition) |_| {} else |identifier| {}`
    /// - `while (condition) |_| {} else |identifier| {}`
    /// - `condition catch |identifier| {}`
    /// - `errdefer |identifier| {}` (condition is `.none`)
    error_union_error: struct {
        identifier: Ast.TokenIndex,
        condition: Ast.Node.OptionalIndex,
    },
    assign_destructure: AssignDestructure,
    /// - `switch (condition) { .case => |value| {} }`
    switch_payload: Switch,
    /// - `switch (condition) { inline .case => |_, tag| {} }`
    /// - `switch (condition) { inline else => |_, tag| {} }`
    switch_inline_tag_payload: Switch,
    label: struct {
        identifier: Ast.TokenIndex,
        block: Ast.Node.Index,
    },
    /// always an identifier
    /// used as child declarations of an error set declaration
    error_token: Ast.TokenIndex,

    comptime {
        for (std.meta.fields(Declaration)) |field| {
            std.debug.assert(@sizeOf(field.type) <= 8); // a Declaration without the union tag must be less than 8 bytes
        }
    }

    pub const Param = struct {
        param_index: u16,
        func: Ast.Node.Index,

        pub fn get(self: Param, tree: Ast) ?Ast.full.FnProto.Param {
            var buffer: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buffer, self.func).?;
            var param_index: u16 = 0;
            var it = func.iterate(&tree);
            while (ast.nextFnParam(&it)) |param| : (param_index += 1) {
                if (self.param_index == param_index) return param;
            }
            return null;
        }
    };

    pub const AssignDestructure = struct {
        /// tag is .assign_destructure
        node: Ast.Node.Index,
        index: u32,

        pub fn getVarDeclNode(self: AssignDestructure, tree: Ast) Ast.Node.Index {
            const extra_index = tree.nodeData(self.node).extra_and_node[0];
            return @enumFromInt(tree.extra_data[@intFromEnum(extra_index) + 1 ..][self.index]);
        }

        pub fn getFullVarDecl(self: AssignDestructure, tree: Ast) Ast.full.VarDecl {
            return tree.fullVarDecl(self.getVarDeclNode(tree)).?;
        }
    };

    pub const Switch = struct {
        /// tag is `.@"switch"` or `.switch_comma`
        node: Ast.Node.Index,
        /// is guaranteed to have a payload_token
        case_index: u32,

        pub fn getCase(self: Switch, tree: Ast) Ast.full.SwitchCase {
            const extra_index = tree.nodeData(self.node).node_and_extra[1];
            const cases = tree.extraDataSlice(tree.extraData(extra_index, Ast.Node.SubRange), Ast.Node.Index);
            return tree.fullSwitchCase(cases[self.case_index]).?;
        }
    };

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

    pub fn eql(a: Declaration, b: Declaration) bool {
        return std.meta.eql(a, b);
    }

    /// Returns a `.identifier` or `.builtin` token.
    pub fn nameToken(decl: Declaration, tree: Ast) Ast.TokenIndex {
        return switch (decl) {
            .ast_node => |node| {
                var buffer: [1]Ast.Node.Index = undefined;
                const token_index = switch (tree.nodeTag(node)) {
                    .local_var_decl,
                    .global_var_decl,
                    .simple_var_decl,
                    .aligned_var_decl,
                    => tree.nodeMainToken(node) + 1,
                    .fn_proto,
                    .fn_proto_multi,
                    .fn_proto_one,
                    .fn_proto_simple,
                    .fn_decl,
                    => tree.fullFnProto(&buffer, node).?.name_token.?,

                    .container_field,
                    .container_field_init,
                    .container_field_align,
                    => tree.nodeMainToken(node),

                    else => unreachable,
                };

                switch (tree.tokenTag(token_index)) {
                    .identifier, .builtin => return token_index,
                    else => unreachable,
                }
            },
            .function_parameter => |payload| payload.get(tree).?.name_token.?,
            .optional_payload => |payload| payload.identifier,
            .error_union_payload => |payload| payload.identifier,
            .error_union_error => |payload| payload.identifier,
            .for_loop_payload => |payload| payload.identifier,
            .label => |payload| payload.identifier,
            .error_token => |error_token| error_token,
            .assign_destructure => |payload| {
                const var_decl_node = payload.getVarDeclNode(tree);
                const varDecl = tree.fullVarDecl(var_decl_node).?;
                return varDecl.ast.mut_token + 1;
            },
            .switch_payload,
            .switch_inline_tag_payload,
            => |payload| {
                const case = payload.getCase(tree);
                const payload_token = case.payload_token.?;
                return payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk) + @as(Ast.TokenIndex, 2) * @intFromBool(decl == .switch_inline_tag_payload);
            },
        };
    }
};

pub const Scope = struct {
    pub const Tag = enum(u3) {
        /// `tree.nodeTag(ast_node)` is ContainerDecl or Root or ErrorSetDecl
        container,
        /// `tree.nodeTag(ast_node)` is FnProto
        function,
        /// `tree.nodeTag(ast_node)` is Block
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
            return @enumFromInt(@intFromEnum(index));
        }
    };

    pub const OptionalIndex = enum(u32) {
        root,
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
            identifier_token: Ast.TokenIndex,
            declaration: Declaration,
            kind: DeclarationLookup.Kind,
        ) error{OutOfMemory}!void {
            std.debug.assert((declaration == .label) == (kind == .label));
            const name = offsets.identifierTokenToNameSlice(pushed.context.tree, identifier_token);
            if (std.mem.eql(u8, name, "_")) return;
            defer std.debug.assert(pushed.context.doc_scope.declarations.len == pushed.context.doc_scope.declaration_lookup_map.count());

            if (@import("builtin").mode == .Debug) {
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
                .small = @splat(.none),
            },
            .child_declarations = .{
                .small = @splat(.none),
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

    var document_scope: DocumentScope = .{
        .scopes = .empty,
        .declarations = .empty,
        .declaration_lookup_map = .empty,
        .extra = .empty,
        .global_error_set = .empty,
        .global_enum_set = .empty,
    };
    errdefer document_scope.deinit(allocator);

    var context: ScopeContext = .{
        .allocator = allocator,
        .tree = tree,
        .doc_scope = &document_scope,
    };
    defer context.deinit();
    switch (tree.mode) {
        .zig => try walkContainerDecl(&context, tree, .root),
        .zon => {
            const root_node = tree.nodeData(.root).node;
            const new_scope = try context.startScope(
                .container,
                .{ .ast_node = root_node },
                .{ .start = 0, .end = @intCast(tree.source.len) },
            );
            try walkNode(&context, tree, root_node);
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

    scope.global_enum_set.deinit(allocator);
    scope.global_error_set.deinit(allocator);
}

fn locToSmallLoc(loc: offsets.Loc) Scope.SmallLoc {
    return .{
        .start = @intCast(loc.start),
        .end = @intCast(loc.end),
    };
}

/// Similar to `walkNode` but also returns a new scope.
/// Asserts that `node_idx != .root`
/// Caller must finalize the scope
fn walkNodeEnsureScope(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
    start_token: Ast.TokenIndex,
) error{OutOfMemory}!ScopeContext.PushedScope {
    std.debug.assert(node_idx != .root);
    switch (tree.nodeTag(node_idx)) {
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
    const tag = tree.nodeTag(node_idx);
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

        .@"defer",
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .optional_type,
        .deref,
        .@"suspend",
        .@"resume",
        .@"comptime",
        .@"nosuspend",
        => walkUnaryOpNode(context, tree, node_idx),

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
        .switch_range,
        .error_union,
        .container_field_align,
        => walkBinOpNode(context, tree, node_idx),

        .array_init_dot_two,
        .array_init_dot_two_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => walkOptNodeAndOptNode(context, tree, node_idx),

        .struct_init_one,
        .struct_init_one_comma,
        .call_one,
        .call_one_comma,
        .switch_case_one,
        .switch_case_inline_one,
        .container_field_init,
        .for_range,
        => walkNodeAndOptNode(context, tree, node_idx),

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
        .switch_case,
        .switch_case_inline,
        .builtin_call,
        .builtin_call_comma,
        .container_field,
        .asm_legacy,
        .asm_simple,
        .@"asm",

        .grouped_expression,
        .field_access,
        .unwrap_optional,
        .@"return",
        .test_decl,
        .@"break",
        .anyframe_type,
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

    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = tree.fullContainerDecl(&buf, node_idx).?;

    const is_enum_or_tagged_union, const is_struct = blk: {
        if (node_idx == .root) break :blk .{ false, true };
        break :blk switch (tree.tokenTag(container_decl.ast.main_token)) {
            .keyword_enum => .{ true, false },
            .keyword_union => .{ container_decl.ast.enum_token != null or container_decl.ast.arg != .none, false },
            .keyword_struct => .{ false, true },
            .keyword_opaque => .{ false, false },
            else => unreachable,
        };
    };

    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    for (container_decl.ast.members) |decl| {
        try walkNode(context, tree, decl);

        switch (tree.nodeTag(decl)) {
            .test_decl,
            .@"comptime",
            => continue,

            .container_field,
            .container_field_init,
            .container_field_align,
            => {
                var container_field = tree.fullContainerField(decl).?;
                if (is_struct and container_field.ast.tuple_like) continue;

                container_field.convertToNonTupleLike(&tree);
                if (container_field.ast.tuple_like) continue;
                const main_token = container_field.ast.main_token;
                if (tree.tokenTag(main_token) != .identifier) continue;
                try scope.pushDeclaration(main_token, .{ .ast_node = decl }, .field);

                if (is_enum_or_tagged_union) {
                    const name = offsets.identifierTokenToNameSlice(tree, main_token);
                    if (std.mem.eql(u8, name, "_")) continue;

                    const gop = try context.doc_scope.global_enum_set.getOrPutContext(
                        context.allocator,
                        main_token,
                        .{ .tree = tree },
                    );
                    if (!gop.found_existing) {
                        gop.key_ptr.* = main_token;
                    } else if (gop.found_existing and tree.tokenTag(main_token - 1) == .doc_comment) {
                        // a token with a doc comment takes priority.
                        gop.key_ptr.* = main_token;
                    }
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
                try scope.pushDeclaration(name_token, .{ .ast_node = decl }, .other);
            },
            .local_var_decl,
            .global_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const name_token = tree.fullVarDecl(decl).?.ast.mut_token + 1;
                try scope.pushDeclaration(name_token, .{ .ast_node = decl }, .other);
            },

            else => unreachable,
        }
    }

    try scope.finalize();
}

noinline fn walkErrorSetNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const scope = try context.startScope(
        .container,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
    );

    const lbrace, const rbrace = tree.nodeData(node_idx).token_and_token;
    for (lbrace + 1..rbrace) |tok_i| {
        if (tree.tokenTag(@intCast(tok_i)) != .identifier) continue;
        const identifier_token: Ast.TokenIndex = @intCast(tok_i);

        try scope.pushDeclaration(identifier_token, .{ .error_token = identifier_token }, .other);
        const gop = try context.doc_scope.global_error_set.getOrPutContext(
            context.allocator,
            identifier_token,
            .{ .tree = tree },
        );
        if (!gop.found_existing or tree.tokenTag(identifier_token - 1) == .doc_comment) {
            // a token with a doc comment takes priority.
            gop.key_ptr.* = identifier_token;
        }
    }

    try scope.finalize();
}

noinline fn walkFuncNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
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
                name_token,
                .{ .function_parameter = .{ .param_index = param_index, .func = node_idx } },
                .other,
            );
        }
        if (param.type_expr) |type_expr| {
            try walkNode(context, tree, type_expr);
        }
    }

    if (func.ast.return_type.unwrap()) |return_type| {
        try walkNode(context, tree, return_type);
    }

    if (tree.nodeTag(node_idx) == .fn_decl) {
        // Visit the function body
        try walkNode(context, tree, tree.nodeData(node_idx).node_and_node[1]);
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
    const last_token = ast.lastToken(tree, node_idx);

    const scope = try context.startScope(
        .block,
        .{ .ast_node = node_idx },
        locToSmallLoc(offsets.tokensToLoc(tree, start_token, last_token)),
    );

    if (ast.blockLabel(tree, node_idx)) |label_token| {
        try scope.pushDeclaration(
            label_token,
            .{ .label = .{ .identifier = label_token, .block = node_idx } },
            .label,
        );
    }

    var buffer: [2]Ast.Node.Index = undefined;
    const statements = tree.blockStatements(&buffer, node_idx).?;

    for (statements) |idx| {
        try walkNode(context, tree, idx);
        switch (tree.nodeTag(idx)) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => {
                const var_decl = tree.fullVarDecl(idx).?;
                const name_token = var_decl.ast.mut_token + 1;
                try scope.pushDeclaration(name_token, .{ .ast_node = idx }, .other);
            },
            .assign_destructure => {
                const assign_destructure = tree.assignDestructure(idx);

                for (assign_destructure.ast.variables, 0..) |lhs_node, i| {
                    const var_decl = tree.fullVarDecl(lhs_node) orelse continue;
                    const name_token = var_decl.ast.mut_token + 1;
                    try scope.pushDeclaration(
                        name_token,
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
    const if_node = ast.fullIf(tree, node_idx).?;

    try walkNode(context, tree, if_node.ast.cond_expr);

    if (if_node.payload_token) |payload_token| {
        const name_token = payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk);

        const decl: Declaration = if (if_node.error_token != null)
            .{ .error_union_payload = .{ .identifier = name_token, .condition = if_node.ast.cond_expr } }
        else
            .{ .optional_payload = .{ .identifier = name_token, .condition = if_node.ast.cond_expr } };

        const then_scope = try walkNodeEnsureScope(context, tree, if_node.ast.then_expr, name_token);
        try then_scope.pushDeclaration(name_token, decl, .other);
        try then_scope.finalize();
    } else {
        try walkNode(context, tree, if_node.ast.then_expr);
    }

    if (if_node.ast.else_expr.unwrap()) |else_expr| {
        if (if_node.error_token) |error_token| {
            const else_scope = try walkNodeEnsureScope(context, tree, else_expr, error_token);
            try else_scope.pushDeclaration(
                error_token,
                .{ .error_union_error = .{ .identifier = error_token, .condition = if_node.ast.cond_expr.toOptional() } },
                .other,
            );
            try else_scope.finalize();
        } else {
            try walkNode(context, tree, else_expr);
        }
    }
}

noinline fn walkCatchNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const lhs, const rhs = tree.nodeData(node_idx).node_and_node;
    try walkNode(context, tree, lhs);

    const catch_token = tree.nodeMainToken(node_idx) + 2;
    if (catch_token < tree.tokens.len and
        tree.tokenTag(catch_token - 1) == .pipe and
        tree.tokenTag(catch_token) == .identifier)
    {
        const expr_scope = try walkNodeEnsureScope(context, tree, rhs, catch_token);
        try expr_scope.pushDeclaration(
            catch_token,
            .{ .error_union_error = .{ .identifier = catch_token, .condition = lhs.toOptional() } },
            .other,
        );
        try expr_scope.finalize();
    } else {
        try walkNode(context, tree, rhs);
    }
}

/// label_token: inline_token while (cond_expr) |payload_token| : (cont_expr) then_expr else |error_token| else_expr
noinline fn walkWhileNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const while_node = ast.fullWhile(tree, node_idx).?;

    try walkNode(context, tree, while_node.ast.cond_expr);

    const payload_declaration, const payload_name_token = if (while_node.payload_token) |payload_token| blk: {
        const name_token = payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk);

        const decl: Declaration = if (while_node.error_token != null)
            .{ .error_union_payload = .{ .identifier = name_token, .condition = while_node.ast.cond_expr } }
        else
            .{ .optional_payload = .{ .identifier = name_token, .condition = while_node.ast.cond_expr } };
        break :blk .{ decl, name_token };
    } else .{ null, null };

    if (while_node.ast.cont_expr.unwrap()) |cont_expr| {
        if (payload_declaration) |decl| {
            const cont_scope = try walkNodeEnsureScope(context, tree, cont_expr, tree.firstToken(cont_expr));
            try cont_scope.pushDeclaration(payload_name_token.?, decl, .other);
            try cont_scope.finalize();
        } else {
            try walkNode(context, tree, cont_expr);
        }
    }

    if (payload_declaration != null or while_node.label_token != null) {
        const then_start = while_node.payload_token orelse tree.firstToken(while_node.ast.then_expr);
        const then_scope = try walkNodeEnsureScope(context, tree, while_node.ast.then_expr, then_start);

        if (while_node.label_token) |label| {
            try then_scope.pushDeclaration(
                label,
                .{ .label = .{ .identifier = label, .block = while_node.ast.then_expr } },
                .label,
            );
        }
        if (payload_declaration) |decl| {
            try then_scope.pushDeclaration(payload_name_token.?, decl, .other);
        }

        try then_scope.finalize();
    } else {
        try walkNode(context, tree, while_node.ast.then_expr);
    }

    if (while_node.ast.else_expr.unwrap()) |else_expr| {
        if (while_node.label_token != null or while_node.error_token != null) {
            const else_start = while_node.error_token orelse tree.firstToken(else_expr);
            const else_scope = try walkNodeEnsureScope(context, tree, else_expr, else_start);

            if (while_node.label_token) |label| {
                try else_scope.pushDeclaration(
                    label,
                    .{ .label = .{ .identifier = label, .block = while_node.ast.then_expr } },
                    .label,
                );
            }

            if (while_node.error_token) |error_token| {
                try else_scope.pushDeclaration(
                    error_token,
                    .{ .error_union_error = .{ .identifier = error_token, .condition = while_node.ast.cond_expr.toOptional() } },
                    .other,
                );
            }

            try else_scope.finalize();
        } else {
            try walkNode(context, tree, else_expr);
        }
    }
}

/// label_token: inline_token for (inputs) |capture_tokens| then_expr else else_expr
noinline fn walkForNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const for_node = ast.fullFor(tree, node_idx).?;

    for (for_node.ast.inputs) |input_node| {
        try walkNode(context, tree, input_node);
    }

    const then_scope = try walkNodeEnsureScope(context, tree, for_node.ast.then_expr, for_node.payload_token);

    var capture_token = for_node.payload_token;
    for (for_node.ast.inputs) |input| {
        if (capture_token + 1 >= tree.tokens.len) break;
        const capture_is_ref = tree.tokenTag(capture_token) == .asterisk;
        const name_token = capture_token + @intFromBool(capture_is_ref);
        capture_token = name_token + 2;

        if (tree.tokenTag(name_token) != .identifier) break;
        try then_scope.pushDeclaration(
            name_token,
            .{ .for_loop_payload = .{ .identifier = name_token, .condition = input } },
            .other,
        );
    }

    if (for_node.label_token) |label_token| {
        try then_scope.pushDeclaration(
            for_node.label_token.?,
            .{ .label = .{ .identifier = label_token, .block = for_node.ast.then_expr } },
            .label,
        );
    }

    try then_scope.finalize();

    if (for_node.ast.else_expr.unwrap()) |else_expr| {
        if (for_node.label_token) |label_token| {
            const else_scope = try walkNodeEnsureScope(context, tree, else_expr, tree.firstToken(else_expr));
            try else_scope.pushDeclaration(
                for_node.label_token.?,
                .{ .label = .{ .identifier = label_token, .block = else_expr } },
                .label,
            );
            try else_scope.finalize();
        } else {
            try walkNode(context, tree, else_expr);
        }
    }
}

noinline fn walkSwitchNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const full = tree.fullSwitch(node_idx).?;

    const switch_scope = if (full.label_token) |label_token| blk: {
        const scope = try context.startScope(
            .other,
            .{ .ast_node = node_idx },
            locToSmallLoc(offsets.nodeToLoc(tree, node_idx)),
        );
        try scope.pushDeclaration(
            label_token,
            .{ .label = .{ .identifier = label_token, .block = node_idx } },
            .label,
        );
        break :blk scope;
    } else null;

    try walkNode(context, tree, full.ast.condition);

    for (full.ast.cases, 0..) |case, case_index| {
        const switch_case: Ast.full.SwitchCase = tree.fullSwitchCase(case).?;

        for (switch_case.ast.values) |case_value| {
            try walkNode(context, tree, case_value);
        }

        if (switch_case.payload_token) |payload_token| {
            const name_token = payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk);

            const expr_scope = try walkNodeEnsureScope(context, tree, switch_case.ast.target_expr, name_token);
            try expr_scope.pushDeclaration(
                name_token,
                .{ .switch_payload = .{ .node = node_idx, .case_index = @intCast(case_index) } },
                .other,
            );
            if (name_token + 2 < tree.tokens.len and
                tree.tokenTag(name_token + 1) == .comma and
                tree.tokenTag(name_token + 2) == .identifier)
            {
                try expr_scope.pushDeclaration(
                    name_token + 2,
                    .{ .switch_inline_tag_payload = .{ .node = node_idx, .case_index = @intCast(case_index) } },
                    .other,
                );
            }
            try expr_scope.finalize();
        } else {
            try walkNode(context, tree, switch_case.ast.target_expr);
        }
    }
    if (switch_scope) |scope| try scope.finalize();
}

noinline fn walkErrdeferNode(
    context: *ScopeContext,
    tree: Ast,
    node_idx: Ast.Node.Index,
) error{OutOfMemory}!void {
    const opt_payload_token, const rhs = tree.nodeData(node_idx).opt_token_and_node;

    if (opt_payload_token.unwrap()) |payload_token| {
        const expr_scope = try walkNodeEnsureScope(context, tree, rhs, payload_token);
        try expr_scope.pushDeclaration(
            payload_token,
            .{ .error_union_error = .{ .identifier = payload_token, .condition = .none } },
            .other,
        );
        try expr_scope.finalize();
    } else {
        return try walkNode(context, tree, rhs);
    }
}

noinline fn walkUnaryOpNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    try walkNode(context, tree, tree.nodeData(node_idx).node);
}

noinline fn walkBinOpNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    const lhs, const rhs = tree.nodeData(node_idx).node_and_node;
    try walkNode(context, tree, lhs);
    try walkNode(context, tree, rhs);
}

noinline fn walkOptNodeAndOptNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    const opt_lhs, const opt_rhs = tree.nodeData(node_idx).opt_node_and_opt_node;
    if (opt_lhs.unwrap()) |lhs| try walkNode(context, tree, lhs);
    if (opt_rhs.unwrap()) |rhs| try walkNode(context, tree, rhs);
}

noinline fn walkNodeAndOptNode(context: *ScopeContext, tree: Ast, node_idx: Ast.Node.Index) error{OutOfMemory}!void {
    const lhs, const opt_rhs = tree.nodeData(node_idx).node_and_opt_node;
    try walkNode(context, tree, lhs);
    if (opt_rhs.unwrap()) |rhs| try walkNode(context, tree, rhs);
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

pub fn getScopeAstNode(
    doc_scope: DocumentScope,
    scope: Scope.Index,
) ?Ast.Node.Index {
    const slice = doc_scope.scopes.slice();

    const data = slice.items(.data)[@intFromEnum(scope)];

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
