//! ZLS has a [DocumentScope](https://github.com/zigtools/zls/blob/61fec01a2006c5d509dee11c6f0d32a6dfbbf44e/src/analysis.zig#L3811) data structure that represents a high-level Ast used for looking up declarations and finding the current scope at a given source location.
//! I recently had a discussion with @SuperAuguste about the DocumentScope and we were both agreed that it was in need of a rework.
//! I took some of his suggestions and this what I came up with:

const std = @import("std");
const Ast = std.zig.Ast;
const Analyser = @import("analysis.zig");
/// this a tagged union.
const Declaration = Analyser.Declaration;

pub const DocumentScope = struct {
    scopes: std.MultiArrayList(Scope) = .{},
    declarations: std.MultiArrayList(Declaration) = .{},
    // used for looking up a child declaration in a given scope
    child_decl_set: ChildDeclSet1 = .{},
    extra: []u32 = .{},

    //child_decls: std.ArrayListUnmanaged(ChildDeclSet1) = .{},

    const ChildDeclSet1 = std.AutoHashMapUnmanaged(struct {
        scope_index: Scope.Index,
        // alternative representation:
        //   - use a StringPool
        //   - Ast.TokenIndex
        //   - use the pattern used by AstGen
        field_name: []const u8,
    }, Declaration.Index);

    /// alternative representation:
    ///
    /// if we add every `Declaration` to `DocumentScope.declarations` in the same order we
    /// insert into this Map then there is no need to store the `Declaration.Index`
    /// because it matches the index inside the Map.
    /// this only works if every `Declaration` has only added to a single scope
    const ChildDeclSet2 = std.ArrayHashMapUnmanaged(struct {
        scope_index: Scope.Index,
        field_name: []const u8,
    }, void, Context, false);

    pub const Scope = struct {
        tag: enum {
            container_small,
            container,
            container_small_usingnamespace,
            container_usingnamespace,
            function_small,
            function,
            block_small,
            block,
            other_small,
            other,
        },
        // offsets.Loc store `usize` instead of `u32`
        // zig only allows files up to std.math.maxInt(u32) bytes to do this kind of optimization. ZLS should also follow this.
        loc: struct {
            start: u32,
            end: u32,
        },
        parent_scope: Index,
        // child scopes have contiguous indices
        // used only by the EnclosingScopeIterator
        // https://github.com/zigtools/zls/blob/61fec01a2006c5d509dee11c6f0d32a6dfbbf44e/src/analysis.zig#L3127
        child_scopes: struct {
            start: Index,
            end: Index,
        },
        something: union {
            small_size: [2]Declaration.Index,
            other: struct {
                start: Declaration.Index,
                end: Declaration.Index,
            },
        },
        data: union {
            /// `node_tags[ast_node]` is ContainerDecl or Root or ErrorSetDecl
            container: Ast.Node.Index,
            /// index into `DocumentScope.extra`
            /// Body:
            ///     ast_node: Ast.Node.Index,
            ///     usingnamespace_start: u32,
            ///     usingnamespace_end: u32,
            /// `node_tags[ast_node]` is ContainerDecl or Root
            container_usingnamespace: u32,
            /// `node_tags[ast_node]` is FnProto
            function: Ast.Node.Index,
            /// `node_tags[ast_node]` is Block
            block: Ast.Node.Index,
            other: void,
        },

        pub const Index = enum(u32) {
            none = std.math.maxInt(u32),
            _,
        };
    };
};
