//! Helper functions for standard library Zig abstract syntax tree (`std.zig.Ast`)
//!
//! See `./print_ast.zig` to view a human-readable representation of the AST
//! when debugging.
//!
//! Do not use any function in `std.zig.Ast` that has an equilvalent function
//! defined here. The standard library are not meant to be used when the AST
//! has syntax errors.

const std = @import("std");
const offsets = @import("offsets.zig");
const Ast = @import("zirp").Ast;
const Node = Ast.Node;

pub fn globalVarFromLocal(
    node: Ast.Statement.LocalVar.Index,
    tree: *const Ast,
) Ast.Member.GlobalVar {
    const var_decl = node.get(tree);
    return .{
        .mutability = .{ .idx = var_decl.mutability.idx },
        .type = var_decl.type,
        .init = var_decl.init,
        .mods = var_decl.mods,
    };
}

pub fn globalVarFromDestructureProto(
    node: Ast.Expr.Destructure.LValue.VarProto.Index,
    tree: *const Ast,
) Ast.Member.GlobalVar {
    const var_proto = node.get(tree);
    return .{
        .mutability = .{ .idx = var_proto.mutability.idx },
        .type = var_proto.type,
        .init = null,
        .mods = var_proto.mods,
    };
}

pub fn tokensOnSameLine(tree: *const Ast, a: Ast.Token.Index, b: Ast.Token.Index) bool {
    _ = tree;
    _ = a;
    _ = b;
    return false; // BRANCH_TODO
}

pub fn isTokenPrecededByTags(
    tree: *const Ast,
    token: Ast.Token.Index,
    expected_token_tags: []const Ast.Token.Tag,
) bool {
    _ = tree;
    _ = token;
    _ = expected_token_tags;
    return false; // BRANCH_TODO
}

/// Similar to `std.zig.Ast.lastToken` but also handles ASTs with syntax errors.
pub fn lastToken(tree: *const Ast, node: Node.Index) Ast.Token.Index {
    return node.lastToken(tree);
}

pub fn identifierTokenFromIdentifierNode(tree: *const Ast, node: Ast.Node.Index) ?Ast.Token.Index {
    if (node.syntaxTag(tree) != .name) return null;
    return node.mainToken(tree);
}

pub fn hasInferredError(tree: *const Ast, fn_proto: Ast.Expr.Fn) bool {
    return fn_proto.return_type.idx.firstToken(tree).add(-1).tag(tree) == .@"!";
}

pub fn isTaggedUnion(tree: *const Ast, container: Ast.Expr.Container) bool {
    const union_decl = container.kind.cast(.@"union", tree) orelse return false;
    switch (union_decl.get(tree)) {
        .@"union" => return false,
        .with_backing => return true,
    }
}

pub fn isContainer(tree: *const Ast, node: Ast.Node.Index) bool {
    return switch (node.tag(tree)) {
        .type_container, .root, .type_error_set => true,
        else => false,
    };
}

pub const Iterator = union(enum) {
    array: [6]Ast.Node.OptionalIndex,
    list_iter: ListIter,
    fn_proto: struct {
        node: Ast.Expr.Fn.Index,
        iter: union(enum) {
            params: Ast.NodeIterator(Ast.Expr.Fn.Param.Index),
            mods: Ast.Expr.Fn.Attributes,
        },
    },
    @"asm": struct {
        node: Ast.Expr.Asm.Index,
        template: Ast.Node.OptionalIndex,
        iter: ?union(enum) {
            outputs: Ast.NodeIterator(Ast.Expr.Asm.Output.Index),
            inputs: Ast.NodeIterator(Ast.Expr.Asm.Input.Index),
        },
        clobbers: Ast.Node.OptionalIndex,
    },

    const ListIter = struct {
        prefix: Ast.Node.OptionalIndex,
        start: Node.Index,
        offset: u32,
        count_method: Ast.ListCountMethod,
        tag_set: Ast.SyntaxTagSet,
        suffix: [3]Ast.Node.OptionalIndex,

        fn simple(it: anytype) @This() {
            return .{
                .start = it.start,
                .offset = it.offset,
                .count_method = it.count_method,
                .tag_set = @TypeOf(it).tag_set,
                .prefix = .none,
                .suffix = @splat(.none),
            };
        }

        fn fromZirp(prefix: Ast.Node.OptionalIndex, it: anytype, suffix: anytype) @This() {
            return .{
                .start = it.start,
                .offset = it.offset,
                .count_method = it.count_method,
                .tag_set = @TypeOf(it).tag_set,
                .prefix = prefix,
                .suffix = makeArray(3, suffix),
            };
        }
    };

    pub fn init(tree: *const Ast, node: Ast.Node.Index) Iterator {
        return switch (node.toTyped(tree)) {
            .leaf, .missing, .leaf_enum_literal => .{ .array = @splat(.none) },
            // ?
            .none => unreachable,
            .root => |root| .{ .list_iter = .simple(root.members.iter(tree)) },
            .block => |block| .{ .list_iter = .simple(block.statements.iter(tree)) },
            .decl_fn => |decl| .initArray(.{ decl.proto, decl.body }),
            .decl_test => |decl| .initArray(.{decl.block}),
            .member_field => |field| .initArray(.{ field.type, field.@"align", field.init }),
            .stmt_defer => |stmt| .initArray(.{stmt.body}),
            inline .var_local,
            .var_global,
            => |@"var"| {
                const attrs = @"var".attributes(tree);
                return .initArray(.{
                    @"var".type,
                    attrs.@"align",
                    attrs.@"addrspace",
                    attrs.@"linksection",
                    @"var".init,
                });
            },
            .var_proto => |@"var"| {
                const attrs = @"var".attributes(tree);
                return .initArray(.{ @"var".type, attrs.@"align", attrs.@"addrspace", attrs.@"linksection" });
            },
            .expr_if,
            .expr_if_else,
            .expr_if_payload,
            .expr_if_full,
            => |fi| .initArray(.{ fi.condition, fi.then_payload, fi.then_branch, fi.else_payload, fi.else_branch }),
            .expr_for => |four| .{ .list_iter = .fromZirp(
                .none,
                four.inputs.get(tree).items.iter(tree),
                .{
                    four.payload,
                    four.body,
                    four.@"else",
                },
            ) },
            .expr_asm,
            .expr_asm_outputs,
            .expr_asm_outputs_inputs,
            .expr_asm_outputs_inputs_clobbers,
            => |asum| .{ .@"asm" = .{
                .node = .{ .idx = node },
                .template = asum.instruction_string.idx.toOptional(),
                .iter = if (asum.outputs) |out|
                    .{ .outputs = out.get(tree).items.iter(tree) }
                else if (asum.inputs) |in|
                    .{ .inputs = in.get(tree).items.iter(tree) }
                else
                    null,
                .clobbers = if (asum.clobbers) |c| c.idx.toOptional() else .none,
            } },
            .expr_call => |call| .{ .list_iter = .fromZirp(call.callee.idx.toOptional(), call.args.iter(tree), .{}) },
            .expr_catch => |cat| .initArray(.{ cat.lhs, cat.rhs }),
            .expr_group => |group| .initArray(.{group.inner}),
            .expr_index => |index| .initArray(.{ index.lhs, index.rhs }),
            .expr_slice => |slice| .initArray(.{
                slice.lhs,
                slice.start,
                slice.end,
                slice.end,
            }),
            .expr_while => |whil| .initArray(.{
                whil.condition,
                whil.payload,
                whil.advance,
                whil.body,
                whil.else_payload,
                whil.@"else",
            }),
            .expr_error => .{ .array = @splat(.none) },
            .expr_break => |br| .initArray(.{ br.@"break", br.value }),
            .expr_continue => |cont| .initArray(.{ cont.@"continue", cont.value }),
            .expr_deref => |deref| .initArray(.{deref.lhs}),
            .expr_switch => |sw| .{ .list_iter = .fromZirp(sw.condition.idx.toOptional(), sw.prongs.iter(tree), .{}) },
            .expr_binary => |bin| .initArray(.{ bin.lhs, bin.rhs }),
            .expr_assign => |assign| .initArray(.{ assign.lhs, assign.rhs }),
            .expr_unwrap => |unwrap| .initArray(.{unwrap.lhs}),
            .expr_prefix => |prefix| .initArray(.{prefix.rhs}),
            .expr_return => |ret| .initArray(.{ret.value}),
            .expr_comptime => |comp| .initArray(.{comp.inner}),
            .expr_dot_access => |dot| .initArray(.{dot.lhs}),
            .expr_destructure => |destructure| .{
                .list_iter = .fromZirp(.none, destructure.lvalues.iter(tree), .{destructure.init}),
            },
            .expr_builtin_call => |call| .{ .list_iter = .simple(call.args.iter(tree)) },
            .expr_compound_assign => |assign| .initArray(.{ assign.lhs, assign.rhs }),
            .expr_init => |expr| .{ .list_iter = .fromZirp(
                if (expr.type) |t| t.idx.toOptional() else .none,
                expr.fields.iter(tree),
                .{},
            ) },
            .init_field => |field| .initArray(.{field.init}),
            .type_fn => |proto| if (proto.params.idx.tag(tree) == .missing)
                .initArray(.{})
            else
                .{ .fn_proto = .{
                    .node = .{ .idx = node },
                    .iter = .{
                        .params = proto.params.get(tree).items.iter(tree),
                    },
                } },
            .type_array => |array| .initArray(.{ array.size, array.sentinel, array.child_type }),
            .type_pointer => |ptr| {
                var attrs: [6]Ast.Node.OptionalIndex = @splat(.none);
                var i: usize = 0;
                if (ptr.sentinel(tree)) |s| {
                    attrs[i] = s.idx.toOptional();
                    i += 1;
                }
                var it = ptr.mods.iter(tree);
                while (it.next(tree)) |mod_idx| {
                    const mod = mod_idx.get(tree);
                    switch (mod.kind.get(tree)) {
                        .@"align" => switch (mod.payload.get(tree)) {
                            .expr => |expr| {
                                attrs[i] = expr.idx.toOptional();
                                i += 1;
                            },
                            .bitalign => |bitalign_i| {
                                const bitalign = bitalign_i.get(tree);
                                attrs[i] = bitalign.byte.idx.toOptional();
                                i += 1;
                                attrs[i] = bitalign.bit_start.idx.toOptional();
                                i += 1;
                                attrs[i] = bitalign.bit_end.idx.toOptional();
                                i += 1;
                            },
                        },
                        .@"addrspace" => {
                            attrs[i] = mod.payload.get(tree).expr.idx.toOptional();
                            i += 1;
                        },
                    }
                }
                attrs[i] = ptr.child_type.idx.toOptional();
                return .{ .array = attrs };
            },
            .type_optional => |opt| .initArray(.{opt.inner}),
            .type_error_set => |set| .{ .list_iter = .simple(set.errors.iter(tree)) },
            .type_error_union => |eu| .initArray(.{ eu.lhs, eu.rhs }),
            .type_container => |cont| .{ .list_iter = .fromZirp(
                cont.kind.idx.toOptional(),
                cont.members.iter(tree),
                .{},
            ) },
            .container_enum => |e| .initArray(.{ e.@"enum", e.backing_int }),
            .container_union => |onion| .initArray(.{ onion.@"union", onion.backing_enum }),
            .container_struct => |s| .initArray(.{ s.@"struct", s.backing_int }),
            .pointer_many => unreachable,
            .pointer_slice => unreachable,
            .mod => unreachable,
            .mod_bitalign => unreachable,
            .payload => |payload| .{ .list_iter = .simple(payload.bindings.iter(tree)) },
            .param_list => unreachable,
            .param => |param| .initArray(.{ param.name, param.type }),
            .for_range => |range| .initArray(.{ range.start, range.end }),
            .for_iter_list => unreachable,
            .switch_prong => |prong| .{ .list_iter = .fromZirp(
                .none,
                prong.cases.iter(tree),
                .{ prong.payload, prong.body },
            ) },
            .switch_range => |range| .initArray(.{ range.start, range.end }),
            .asm_output => unreachable,
            .asm_output_result_type => |res| .initArray(.{res.type}),
            .asm_output_list => unreachable,
            .asm_input => unreachable,
            .asm_input_list => unreachable,
        };
    }

    fn makeArray(comptime n: usize, tuple: anytype) [n]Ast.Node.OptionalIndex {
        var array: [n]Ast.Node.OptionalIndex = @splat(.none);
        comptime std.debug.assert(tuple.len <= array.len);
        var i: usize = 0;
        inline for (tuple) |item| {
            // std.debug.assert(item != .root);
            switch (@typeInfo(@TypeOf(item))) {
                .optional => {
                    if (item) |it| {
                        array[i] = .fromOptional(it.idx);
                        i += 1;
                    }
                },
                else => {
                    array[i] = item.idx.toOptional();
                    i += 1;
                },
            }
        }
        return array;
    }

    fn initArray(tuple: anytype) Iterator {
        return .{ .array = makeArray(@typeInfo(@FieldType(Iterator, "array")).array.len, tuple) };
    }

    pub fn next(it: *Iterator, tree: *const Ast) ?Ast.Node.Index {
        sw: switch (it.*) {
            .array => |*array| {
                const result = array[0].unwrap() orelse return null;
                @memmove(array[0 .. array.len - 1], array[1..]);
                array[array.len - 1] = .none;
                return result;
            },
            .list_iter => |*list_iter| {
                if (list_iter.prefix.unwrap()) |result| {
                    list_iter.prefix = .none;
                    return result;
                }
                const curr: Ast.Node.Index = @fromBackingInt(@backingInt(list_iter.start) + list_iter.offset);
                const tag = curr.syntaxTag(tree);
                switch (list_iter.count_method) {
                    .terminator => |terminator| sw2: switch (tag) {
                        .missing => switch (curr.repr(tree).missing.err.get(tree).tag.expected) {
                            .token => |v| continue :sw2 Ast.syntaxTag(v),
                            else => return null,
                        },
                        else => |t| if (terminator.contains(t)) {
                            const suffix = list_iter.suffix;
                            it.* = .{ .array = @splat(.none) };
                            it.array[0..3].* = suffix;
                            continue :sw it.*;
                        },
                    },
                    .homogeneous => if (!list_iter.tag_set.contains(tag)) return null,
                }
                const tag_set_with_missing = list_iter.tag_set.combine(.init(&.{.missing}));
                if (!tag_set_with_missing.contains(tag)) {
                    if (@import("builtin").mode == .debug) std.log.err(
                        "{s} cannot iterate over a {}",
                        .{ "", curr.syntaxTag(tree) },
                    );
                    unreachable;
                }
                list_iter.offset += 1;
                return curr;
            },
            .fn_proto => |*fn_proto| {
                const func = fn_proto.node.get(tree);
                switch (fn_proto.iter) {
                    .params => |*params| {
                        var param_it = params;
                        while (param_it.next(tree)) |param| {
                            return param.idx;
                        } else {
                            fn_proto.iter = .{ .mods = func.attributes(tree) };
                            continue :sw it.*;
                        }
                    },
                    .mods => |attr| {
                        it.* = .initArray(.{
                            attr.@"align",
                            attr.@"callconv",
                            attr.@"addrspace",
                            attr.@"linksection",
                            func.return_type,
                        });
                        continue :sw it.*;
                    },
                }
            },
            .@"asm" => |*asm_state| {
                @branchHint(.unlikely);

                if (asm_state.template.unwrap()) |template| {
                    defer asm_state.template = .none;
                    return template;
                }

                if (asm_state.iter) |*iter| switch (iter.*) {
                    .outputs => |*out_it| {
                        while (out_it.next(tree)) |out| {
                            const output_node = out.get(tree);
                            if (output_node.binding.idx.tag(tree) == .missing) continue;
                            return switch (output_node.binding.get(tree)) {
                                inline .result_type, .ident => |binding| binding.idx,
                            };
                        } else {
                            asm_state.iter = if (asm_state.node.get(tree).inputs) |in| .{ .inputs = in.get(tree).items.iter(tree) } else null;
                            continue :sw it.*;
                        }
                    },
                    .inputs => |*in_it| {
                        while (in_it.next(tree)) |in| {
                            if (in.idx.tag(tree) == .missing) continue;
                            return in.get(tree).value.idx;
                        } else {
                            asm_state.iter = null;
                            continue :sw it.*;
                        }
                    },
                };

                if (asm_state.clobbers.unwrap()) |clobbers| {
                    asm_state.clobbers = .none;
                    return clobbers;
                }

                return null;
            },
        }
    }
};

pub const Walker = struct {
    stack: std.ArrayList(Stack),

    pub fn init(allocator: std.mem.Allocator, tree: *const Ast, node: Ast.Node.Index) error{OutOfMemory}!Walker {
        var stack: std.ArrayList(Stack) = .empty;
        try stack.append(allocator, .{
            .node = node,
            .it = .init(tree, node),
        });
        return .{ .stack = stack };
    }

    pub fn deinit(walker: *Walker, allocator: std.mem.Allocator) void {
        walker.stack.deinit(allocator);
        walker.* = undefined;
    }

    pub const Event = union(enum) {
        open: Ast.Node.Index,
        close: Ast.Node.Index,
    };

    pub fn next(walker: *Walker, allocator: std.mem.Allocator, tree: *const Ast) error{OutOfMemory}!?Event {
        while (walker.stack.items.len != 0) {
            const stack: *Stack = &walker.stack.items[walker.stack.items.len - 1];
            const node = stack.it.next(tree) orelse {
                const node = stack.node;
                walker.stack.items.len -= 1;
                return .{ .close = node };
            };
            std.debug.assert(node != .root);
            try walker.stack.append(allocator, .{
                .node = node,
                .it = .init(tree, node),
            });
            return .{ .open = node };
        } else return null;
    }

    pub fn nextIgnoreClose(walker: *Walker, allocator: std.mem.Allocator, tree: *const Ast) error{OutOfMemory}!?Ast.Node.Index {
        while (true) {
            switch (try walker.next(allocator, tree) orelse return null) {
                .open => |node| return node,
                .close => continue,
            }
        }
    }

    pub fn skip(walker: *Walker) void {
        walker.stack.items.len -= 1;
    }

    /// Returns the parent node after a `Event.open` has been returned from `next`.
    pub fn parentNode(walker: *const Walker) Ast.Node.Index {
        return walker.stack.items[walker.stack.items.len - 2].node;
    }

    const Stack = struct {
        node: Ast.Node.Index,
        it: Iterator,
    };
};

/// returns a list of nodes that overlap with the given source code index.
/// sorted from smallest to largest.
/// caller owns the returned memory.
pub fn nodesOverlappingIndex(allocator: std.mem.Allocator, tree: *const Ast, index: usize) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(index <= tree.source.len);

    var nodes: std.ArrayList(Ast.Node.Index) = .empty;
    defer nodes.deinit(allocator);

    var walker: Walker = try .init(allocator, tree, .root);
    defer walker.deinit(allocator);

    while (try walker.nextIgnoreClose(allocator, tree)) |node| {
        const loc = offsets.nodeToLoc(tree, node);
        if (loc.start <= index and index <= loc.end) {
            try nodes.append(allocator, node);
        } else {
            walker.skip();
        }
    }

    std.mem.reverse(Ast.Node.Index, nodes.items);
    try nodes.append(allocator, .root);
    return try nodes.toOwnedSlice(allocator);
}

/// returns a list of nodes that overlap with the given source code index.
/// the list may include nodes that were discarded during error recovery in the Zig parser.
/// sorted from smallest to largest.
/// caller owns the returned memory.
/// this function can be removed when the parser has been improved.
pub fn nodesOverlappingIndexIncludingParseErrors(allocator: std.mem.Allocator, tree: *const Ast, source_index: usize) error{OutOfMemory}![]Ast.Node.Index {
    const NodeLoc = struct {
        node: Ast.Node.Index,
        loc: offsets.Loc,

        fn lessThan(_: void, lhs: @This(), rhs: @This()) bool {
            return rhs.loc.start < lhs.loc.start and lhs.loc.end < rhs.loc.end;
        }
    };

    var node_locs: std.ArrayList(NodeLoc) = .empty;
    defer node_locs.deinit(allocator);
    for (0..tree.nodes.len()) |i| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(i));
        switch (node.tag(tree)) {
            .none,
            .mod,
            .pointer_many,
            .pointer_slice,
            => continue, // BRANCH_TODO
            else => {},
        }
        const loc = offsets.nodeToLoc(tree, node);
        if (loc.start <= source_index and source_index <= loc.end) {
            try node_locs.append(allocator, .{ .node = node, .loc = loc });
        }
    }

    std.mem.sort(NodeLoc, node_locs.items, {}, NodeLoc.lessThan);

    const nodes = try allocator.alloc(Ast.Node.Index, node_locs.items.len);
    for (node_locs.items, nodes) |node_loc, *node| {
        node.* = node_loc.node;
    }
    return nodes;
}

/// returns a list of nodes that together encloses the given source code range
/// caller owns the returned memory
pub fn nodesAtLoc(allocator: std.mem.Allocator, tree: *const Ast, loc: offsets.Loc) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(loc.start <= loc.end and loc.end <= tree.source.len);

    const Context = struct {
        allocator: std.mem.Allocator,
        nodes: std.ArrayList(Ast.Node.Index) = .empty,
        locs: std.ArrayList(offsets.Loc) = .empty,

        pub fn append(self: *@This(), ast: *const Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
            std.debug.assert(node != .root);
            try self.nodes.append(self.allocator, node);
            try self.locs.append(self.allocator, offsets.nodeToLoc(ast, node));
        }
    };
    var context: Context = .{ .allocator = allocator };
    defer context.nodes.deinit(allocator);
    defer context.locs.deinit(allocator);

    try context.nodes.ensureTotalCapacity(allocator, 32);

    var parent: Ast.Node.Index = .root;
    while (true) {
        var it: Iterator = .init(tree, parent);
        while (it.next(tree)) |child| try context.append(tree, child);

        if (smallestEnclosingSubrange(context.locs.items, loc)) |subslice| {
            std.debug.assert(subslice.len != 0);
            const nodes = context.nodes.items[subslice.start .. subslice.start + subslice.len];
            if (nodes.len == 1) { // recurse over single child node
                parent = nodes[0];
                context.nodes.clearRetainingCapacity();
                context.locs.clearRetainingCapacity();
                continue;
            } else { // end-condition: found enclosing children
                return try allocator.dupe(Ast.Node.Index, nodes);
            }
        } else { // the children cannot enclose the given source location
            context.nodes.clearRetainingCapacity();
            context.nodes.appendAssumeCapacity(parent); // capacity is never 0
            return try context.nodes.toOwnedSlice(allocator);
        }
    }
}

/// the following code can be described as the the following problem:
/// @param children a non-intersecting list of source ranges
/// @param loc be a source range
///
/// @return a slice of #children
///
/// Return the smallest possible subrange of #children whose
/// combined source range is inside #loc.
/// If #children cannot contain #loc i.e #loc is too large, return null.
/// @see tests/utility.ast.zig for usage examples
pub fn smallestEnclosingSubrange(children: []const offsets.Loc, loc: offsets.Loc) ?struct {
    start: usize,
    len: usize,
} {
    switch (children.len) {
        0 => return null,
        1 => return if (offsets.locInside(loc, children[0])) .{ .start = 0, .len = 1 } else null,
        else => {
            // TODO re-enable checks once parsing conforms to these assumptions
            // for (children[0 .. children.len - 1], children[1..]) |previous_loc, current_loc| {
            //     std.debug.assert(previous_loc.end <= current_loc.start); // must be sorted
            //     std.debug.assert(!offsets.locIntersect(previous_loc, current_loc)); // must be non-intersecting
            // }
        },
    }

    var i: usize = 0;
    const start: usize = while (i < children.len) : (i += 1) {
        const child_loc = children[i];
        if (child_loc.end < loc.start) continue;

        if (child_loc.start <= loc.start) {
            break i;
        } else if (i != 0) {
            break i - 1;
        } else {
            return null;
        }
    } else return null;

    const end = while (i < children.len) : (i += 1) {
        const child_loc = children[i];
        if (loc.end <= child_loc.end) break i + 1;
    } else return null;

    return .{
        .start = start,
        .len = end - start,
    };
}

test smallestEnclosingSubrange {
    const children = &[_]offsets.Loc{
        .{ .start = 0, .end = 5 },
        .{ .start = 5, .end = 10 },
        .{ .start = 12, .end = 18 },
        .{ .start = 18, .end = 22 },
        .{ .start = 25, .end = 28 },
    };

    try std.testing.expect(smallestEnclosingSubrange(&.{}, undefined) == null);

    // children  <-->
    // loc       <--->
    // result    null
    try std.testing.expect(
        smallestEnclosingSubrange(&.{.{ .start = 0, .end = 4 }}, .{ .start = 0, .end = 5 }) == null,
    );

    // children  <---><--->  <----><-->   <->
    // loc       <---------------------------->
    // result    null
    try std.testing.expect(smallestEnclosingSubrange(children, .{ .start = 0, .end = 30 }) == null);

    // children  <---><--->  <----><-->   <->
    // loc             <--------->
    // result         <--->  <---->
    const result1 = smallestEnclosingSubrange(children, .{ .start = 6, .end = 17 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..3],
        children[result1.start .. result1.start + result1.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc            <------------->
    // result         <--->  <----><-->
    const result2 = smallestEnclosingSubrange(children, .{ .start = 6, .end = 20 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..4],
        children[result2.start .. result2.start + result2.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc                 <----------->
    // result         <--->  <----><-->   <->
    const result3 = smallestEnclosingSubrange(children, .{ .start = 10, .end = 23 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..5],
        children[result3.start .. result3.start + result3.len],
    );

    // children  <---><--->  <----><-->   <->
    // loc                 <>
    // result         <--->  <---->
    const result4 = smallestEnclosingSubrange(children, .{ .start = 10, .end = 12 }).?;
    try std.testing.expectEqualSlices(
        offsets.Loc,
        children[1..3],
        children[result4.start .. result4.start + result4.len],
    );
}

pub fn indexOfBreakTarget(
    tree: *const Ast,
    nodes: []const Ast.Node.Index,
    break_label_maybe: ?[]const u8,
) ?usize {
    for (nodes, 0..) |node, index| {
        const opt_label_token = switch (node.tag(tree)) {
            .expr_for => node.cast(.expr_for, tree).?.label(tree),
            .expr_while => node.cast(.expr_while, tree).?.label(tree),
            .expr_switch => node.cast(.expr_switch, tree).?.label(tree),
            .block => node.cast(.block, tree).?.label(tree),
            else => continue,
        };
        const break_label = break_label_maybe orelse return index;
        const label_token = opt_label_token orelse continue;
        const label = label_token.slice(tree);
        if (std.mem.eql(u8, break_label, label)) return index;
    }
    return null;
}
