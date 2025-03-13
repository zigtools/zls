//! Collection of functions from std.zig.ast that we need
//! and may hit undefined in the standard library implementation
//! when there are parser errors.

const std = @import("std");
const offsets = @import("offsets.zig");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const full = Ast.full;

pub fn testDeclNameToken(tree: Ast, test_decl_node: Ast.Node.Index) ?Ast.TokenIndex {
    std.debug.assert(tree.nodeTag(test_decl_node) == .test_decl);
    const token, _ = tree.nodeData(test_decl_node).opt_token_and_node;
    return token.unwrap();
}

pub fn testDeclNameAndToken(tree: Ast, test_decl_node: Ast.Node.Index) ?struct { Ast.TokenIndex, []const u8 } {
    const test_name_token = testDeclNameToken(tree, test_decl_node) orelse return null;

    switch (tree.tokens.items(.tag)[test_name_token]) {
        .string_literal => {
            const name = offsets.tokenToSlice(tree, test_name_token);
            return .{ test_name_token, name[1 .. name.len - 1] };
        },
        .identifier => return .{ test_name_token, offsets.identifierTokenToNameSlice(tree, test_name_token) },
        else => return null,
    }
}

/// The main token of a identifier node may not be a identifier token.
///
/// Example:
/// ```zig
/// const Foo;
/// @tagName
/// ```
/// TODO investigate the parser to figure out why.
pub fn identifierTokenFromIdentifierNode(tree: Ast, node: Ast.Node.Index) ?Ast.TokenIndex {
    const main_token = tree.nodeMainToken(node);
    if (tree.tokens.items(.tag)[main_token] != .identifier) return null;
    return main_token;
}

pub fn hasInferredError(tree: Ast, fn_proto: Ast.full.FnProto) bool {
    const token_tags = tree.tokens.items(.tag);

    return token_tags[
        tree.firstToken(
            fn_proto.ast.return_type.unwrap() orelse return false,
        ) - 1
    ] == .bang;
}

pub fn paramFirstToken(tree: Ast, param: Ast.full.FnProto.Param, include_doc_comment: bool) Ast.TokenIndex {
    return (if (include_doc_comment) param.first_doc_comment else null) orelse
        param.comptime_noalias orelse
        param.name_token orelse
        tree.firstToken(param.type_expr.?);
}

pub fn paramLastToken(tree: Ast, param: Ast.full.FnProto.Param) Ast.TokenIndex {
    return param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr.?);
}

pub fn paramLoc(tree: Ast, param: Ast.full.FnProto.Param, include_doc_comment: bool) offsets.Loc {
    const first_token = paramFirstToken(tree, param, include_doc_comment);
    const last_token = paramLastToken(tree, param);
    return offsets.tokensToLoc(tree, first_token, last_token);
}

pub fn paramSlice(tree: Ast, param: Ast.full.FnProto.Param, include_doc_comment: bool) []const u8 {
    return offsets.locToSlice(tree.source, paramLoc(tree, param, include_doc_comment));
}

pub fn isTaggedUnion(tree: Ast, node: Ast.Node.Index) bool {
    if (tree.tokenTag(tree.nodeMainToken(node)) != .keyword_union) return false;

    var buf: [2]Ast.Node.Index = undefined;
    const decl = tree.fullContainerDecl(&buf, node) orelse
        return false;

    return decl.ast.enum_token != null or decl.ast.arg.unwrap() != null;
}

pub fn isContainer(tree: Ast, node: Ast.Node.Index) bool {
    return switch (tree.nodeTag(node)) {
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
        .root,
        .error_set_decl,
        => true,
        else => false,
    };
}

pub fn isBuiltinCall(tree: Ast, node: Ast.Node.Index) bool {
    return switch (tree.nodeTag(node)) {
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => true,
        else => false,
    };
}

/// returns a list of parameters
pub fn builtinCallParams(tree: Ast, node: Ast.Node.Index, buf: *[2]Ast.Node.Index) ?[]const Node.Index {
    return switch (tree.nodeTag(node)) {
        .builtin_call_two,
        .builtin_call_two_comma,
        => loadOptionalNodesIntoBuffer(2, buf, tree.nodeData(node).opt_node_and_opt_node),
        .builtin_call,
        .builtin_call_comma,
        => tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index),
        else => return null,
    };
}

pub fn blockLabel(tree: Ast, node: Ast.Node.Index) ?Ast.TokenIndex {
    const main_token = tree.nodeMainToken(node);

    if (main_token < 2) return null;
    if (tree.tokenTag(main_token - 1) != .colon) return null;
    if (tree.tokenTag(main_token - 2) != .identifier) return null;
    return main_token - 2;
}

fn loadOptionalNodesIntoBuffer(
    comptime size: usize,
    buffer: *[size]Ast.Node.Index,
    items: [size]Ast.Node.OptionalIndex,
) []Ast.Node.Index {
    for (buffer, items, 0..) |*node, opt_node, i| {
        node.* = opt_node.unwrap() orelse return buffer[0..i];
    }
    return buffer[0..];
}

/// returns a list of statements
pub fn blockStatements(tree: Ast, node: Ast.Node.Index, buf: *[2]Ast.Node.Index) ?[]const Node.Index {
    return switch (tree.nodeTag(node)) {
        .block_two, .block_two_semicolon => loadOptionalNodesIntoBuffer(
            2,
            buf,
            tree.nodeData(node).opt_node_and_opt_node,
        ),
        .block, .block_semicolon => tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index),
        else => null,
    };
}

pub const ErrorSetIterator = struct {
    token_tags: []const std.zig.Token.Tag,
    current_token: Ast.TokenIndex,
    last_token: Ast.TokenIndex,

    pub fn init(tree: Ast, node: Ast.Node.Index) ErrorSetIterator {
        std.debug.assert(tree.nodeTag(node) == .error_set_decl);
        return .{
            .token_tags = tree.tokens.items(.tag),
            .current_token = tree.nodeMainToken(node) + 2,
            .last_token = tree.lastToken(node),
        };
    }

    pub fn next(it: *ErrorSetIterator) ?Ast.TokenIndex {
        for (it.token_tags[it.current_token..it.last_token], it.current_token..) |tag, token| {
            switch (tag) {
                .doc_comment, .comma => {},
                .identifier => {
                    it.current_token = @min(token + 1, it.last_token);
                    return @intCast(token);
                },
                else => {},
            }
        }
        return null;
    }
};

pub fn errorSetFieldCount(tree: Ast, node: Ast.Node.Index) usize {
    std.debug.assert(tree.nodeTag(node) == .error_set_decl);
    const token_tags = tree.tokens.items(.tag);
    const start, const end = tree.nodeData(node).token_and_token;
    var count: usize = 0;
    for (token_tags[start..end]) |tag| {
        count += @intFromBool(tag == .identifier);
    }
    return count;
}

/// Iterates over FnProto Params w/ added bounds check to support incomplete ast nodes
pub fn nextFnParam(it: *Ast.full.FnProto.Iterator) ?Ast.full.FnProto.Param {
    const token_tags = it.tree.tokens.items(.tag);
    while (true) {
        var first_doc_comment: ?Ast.TokenIndex = null;
        var comptime_noalias: ?Ast.TokenIndex = null;
        var name_token: ?Ast.TokenIndex = null;
        if (!it.tok_flag) {
            if (it.param_i >= it.fn_proto.ast.params.len) {
                return null;
            }
            const param_type = it.fn_proto.ast.params[it.param_i];
            const last_param_type_token = it.tree.lastToken(param_type);
            var tok_i = it.tree.firstToken(param_type) - 1;
            while (true) : (tok_i -= 1) switch (token_tags[tok_i]) {
                .colon => continue,
                .identifier => name_token = tok_i,
                .doc_comment => first_doc_comment = tok_i,
                .keyword_comptime, .keyword_noalias => comptime_noalias = tok_i,
                else => break,
            };
            it.param_i += 1;
            it.tok_i = last_param_type_token + 1;

            // #boundsCheck
            // https://github.com/zigtools/zls/issues/567
            if (last_param_type_token >= it.tree.tokens.len - 1)
                return .{
                    .first_doc_comment = first_doc_comment,
                    .comptime_noalias = comptime_noalias,
                    .name_token = name_token,
                    .anytype_ellipsis3 = null,
                    .type_expr = null,
                };

            // Look for anytype and ... params afterwards.
            if (token_tags[it.tok_i] == .comma) {
                it.tok_i += 1;
            }
            it.tok_flag = true;
            return .{
                .first_doc_comment = first_doc_comment,
                .comptime_noalias = comptime_noalias,
                .name_token = name_token,
                .anytype_ellipsis3 = null,
                .type_expr = param_type,
            };
        }
        if (token_tags[it.tok_i] == .comma) {
            it.tok_i += 1;
        }
        if (token_tags[it.tok_i] == .r_paren) {
            return null;
        }
        if (token_tags[it.tok_i] == .doc_comment) {
            first_doc_comment = it.tok_i;
            while (token_tags[it.tok_i] == .doc_comment) {
                it.tok_i += 1;
            }
        }
        switch (token_tags[it.tok_i]) {
            .ellipsis3 => {
                it.tok_flag = false; // Next iteration should return null.
                return .{
                    .first_doc_comment = first_doc_comment,
                    .comptime_noalias = null,
                    .name_token = null,
                    .anytype_ellipsis3 = it.tok_i,
                    .type_expr = null,
                };
            },
            .keyword_noalias, .keyword_comptime => {
                comptime_noalias = it.tok_i;
                it.tok_i += 1;
            },
            else => {},
        }
        if (token_tags[it.tok_i] == .identifier and
            token_tags[it.tok_i + 1] == .colon)
        {
            name_token = it.tok_i;
            it.tok_i += 2;
        }
        if (token_tags[it.tok_i] == .keyword_anytype) {
            it.tok_i += 1;
            return .{
                .first_doc_comment = first_doc_comment,
                .comptime_noalias = comptime_noalias,
                .name_token = name_token,
                .anytype_ellipsis3 = it.tok_i - 1,
                .type_expr = null,
            };
        }
        it.tok_flag = false;
    }
}

/// calls the given `callback` on every child of the given node
/// see `nodeChildrenAlloc` for a non-callback, allocating variant.
/// see `iterateChildrenRecursive` for recursive-iteration.
/// the order in which children are given corresponds to the order in which they are found in the source text
pub fn iterateChildren(
    tree: Ast,
    node: Ast.Node.Index,
    context: anytype,
    comptime Error: type,
    comptime callback: fn (@TypeOf(context), Ast, Ast.Node.Index) Error!void,
) Error!void {
    const ctx = struct {
        fn inner(ctx: *const anyopaque, t: Ast, n: Ast.Node.Index) anyerror!void {
            return callback(@as(*const @TypeOf(context), @alignCast(@ptrCast(ctx))).*, t, n);
        }
    };
    if (iterateChildrenTypeErased(tree, node, @ptrCast(&context), &ctx.inner)) |_| {
        return;
    } else |err| {
        return @as(Error, @errorCast(err));
    }
}

fn iterateChildrenTypeErased(
    tree: Ast,
    node: Ast.Node.Index,
    context: *const anyopaque,
    callback: *const fn (*const anyopaque, Ast, Ast.Node.Index) anyerror!void,
) anyerror!void {
    const token_tags = tree.tokens.items(.tag);

    const tag = tree.nodeTag(node);
    tag_switch: switch (tag) {
        .@"usingnamespace",
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
        .@"nosuspend",
        .@"comptime",
        .@"defer",
        => {
            try callback(context, tree, tree.nodeData(node).node);
        },

        .field_access,
        .unwrap_optional,
        .asm_simple,
        => try callback(context, tree, tree.nodeData(node).node_and_token.@"0"),

        .@"return",
        .grouped_expression,

        .test_decl,
        .@"errdefer",
        => {
            try callback(context, tree, tree.nodeData(node).opt_token_and_node.@"1");
        },

        .@"break",
        => {
            if (tree.nodeData(node).opt_token_and_opt_node.@"1".unwrap()) |target_node| {
                try callback(context, tree, target_node);
            }
        },

        .anyframe_type,
        => {
            try callback(context, tree, tree.nodeData(node).token_and_node.@"1");
        },

        .@"catch",
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
        .container_field_align,
        .error_union,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try callback(context, tree, lhs);
            try callback(context, tree, rhs);
        },

        .async_call_one,
        .async_call_one_comma,
        .container_field_init,
        => {
            const lhs, const opt_rhs = tree.nodeData(node).node_and_opt_node;
            try callback(context, tree, lhs);
            if (opt_rhs.unwrap()) |rhs| {
                try callback(context, tree, rhs);
            }
        },

        .array_init_dot_two,
        .array_init_dot_two_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .block_two,
        .block_two_semicolon,
        => {
            const opt_lhs, const opt_rhs = tree.nodeData(node).opt_node_and_opt_node;
            if (opt_lhs.unwrap()) |lhs| {
                try callback(context, tree, lhs);
            }
            if (opt_rhs.unwrap()) |rhs| {
                try callback(context, tree, rhs);
            }
        },

        .for_range,
        .call_one,
        .call_one_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => {
            const lhs, const rhs_ = tree.nodeData(node).node_and_opt_node;
            try callback(context, tree, lhs);
            if (rhs_.unwrap()) |rhs| {
                try callback(context, tree, rhs);
            }
        },

        .root => {
            for (tree.rootDecls()) |child| {
                try callback(context, tree, child);
            }
        },

        .array_init_dot,
        .array_init_dot_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .builtin_call,
        .builtin_call_comma,
        .container_decl,
        .container_decl_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .block,
        .block_semicolon,
        => {
            const range = tree.nodeData(node).extra_range;
            for (tree.extraDataSlice(range, Ast.Node.Index)) |child| {
                try callback(context, tree, child);
            }
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?.ast;
            if (var_decl.type_node.unwrap()) |type_node| {
                try callback(context, tree, type_node);
            }
            if (var_decl.align_node.unwrap()) |align_node| {
                try callback(context, tree, align_node);
            }
            if (var_decl.addrspace_node.unwrap()) |addrspace_node| {
                try callback(context, tree, addrspace_node);
            }
            if (var_decl.section_node.unwrap()) |section_node| {
                try callback(context, tree, section_node);
            }
            if (var_decl.init_node.unwrap()) |init_node| {
                try callback(context, tree, init_node);
            }
        },

        .assign_destructure => {
            for (tree.assignDestructure(node).ast.variables) |lhs_node| {
                try callback(context, tree, lhs_node);
            }
            _, const init_node = tree.nodeData(node).extra_and_node;
            try callback(context, tree, init_node);
        },

        .array_type_sentinel => {
            const array_type = tree.arrayTypeSentinel(node).ast;
            try callback(context, tree, array_type.elem_count);
            try callback(context, tree, array_type.sentinel.unwrap().?);
            try callback(context, tree, array_type.elem_type);
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const ptr_type = tree.fullPtrType(node).?.ast;
            if (ptr_type.sentinel.unwrap()) |sentinel| {
                try callback(context, tree, sentinel);
            }
            if (ptr_type.align_node.unwrap()) |align_node| {
                try callback(context, tree, align_node);
            }
            if (ptr_type.bit_range_start.unwrap()) |bit_range_start| {
                try callback(context, tree, bit_range_start);
            }
            if (ptr_type.bit_range_end.unwrap()) |bit_range_end| {
                try callback(context, tree, bit_range_end);
            }
            if (ptr_type.addrspace_node.unwrap()) |addrspace_node| {
                try callback(context, tree, addrspace_node);
            }
            try callback(context, tree, ptr_type.child_type);
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const slice = tree.fullSlice(node).?;
            try callback(context, tree, slice.ast.sliced);
            try callback(context, tree, slice.ast.start);
            if (slice.ast.end.unwrap()) |end| {
                try callback(context, tree, end);
            }
            if (slice.ast.sentinel.unwrap()) |sentinel| {
                try callback(context, tree, sentinel);
            }
        },

        .array_init,
        .array_init_comma,
        => {
            const array_init = tree.arrayInit(node).ast;
            if (array_init.type_expr.unwrap()) |type_expr| {
                try callback(context, tree, type_expr);
            }
            for (array_init.elements) |child| {
                try callback(context, tree, child);
            }
        },

        .struct_init,
        .struct_init_comma,
        => {
            const struct_init = tree.structInit(node).ast;
            if (struct_init.type_expr.unwrap()) |type_expr| {
                try callback(context, tree, type_expr);
            }
            for (struct_init.fields) |child| {
                try callback(context, tree, child);
            }
        },

        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => {
            const call = tree.callFull(node).ast;
            try callback(context, tree, call.fn_expr);
            for (call.params) |child| {
                try callback(context, tree, child);
            }
        },

        .@"switch",
        .switch_comma,
        => {
            const operand, const extra_index = tree.nodeData(node).node_and_extra;
            const range = tree.extraData(extra_index, Ast.Node.SubRange);
            try callback(context, tree, operand);
            for (tree.extraDataSlice(range, Ast.Node.Index)) |child| {
                try callback(context, tree, child);
            }
        },

        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => {
            const switch_case = tree.fullSwitchCase(node).?.ast;
            for (switch_case.values) |child| {
                try callback(context, tree, child);
            }
            try callback(context, tree, switch_case.target_expr);
        },

        .while_simple,
        .while_cont,
        .@"while",
        => {
            const while_ast = tree.fullWhile(node).?.ast;
            try callback(context, tree, while_ast.cond_expr);
            if (while_ast.cont_expr.unwrap()) |cont_expr| {
                try callback(context, tree, cont_expr);
            }
            try callback(context, tree, while_ast.then_expr);
            if (while_ast.else_expr.unwrap()) |else_expr| {
                try callback(context, tree, else_expr);
            }
        },
        .for_simple,
        .@"for",
        => {
            const for_ast = tree.fullFor(node).?.ast;
            for (for_ast.inputs) |child| {
                try callback(context, tree, child);
            }
            try callback(context, tree, for_ast.then_expr);
            if (for_ast.else_expr.unwrap()) |else_expr| {
                try callback(context, tree, else_expr);
            }
        },

        .@"if",
        .if_simple,
        => {
            const if_ast = tree.fullIf(node).?.ast;
            try callback(context, tree, if_ast.cond_expr);
            try callback(context, tree, if_ast.then_expr);
            if (if_ast.else_expr.unwrap()) |else_expr| {
                try callback(context, tree, else_expr);
            }
        },

        .fn_decl => {
            _, const body_block = tree.nodeData(node).node_and_node;
            try callback(context, tree, body_block);
            continue :tag_switch .fn_proto;
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buffer: [1]Node.Index = undefined;
            const fn_proto = tree.fullFnProto(&buffer, node).?;

            var it = fn_proto.iterate(&tree);
            while (nextFnParam(&it)) |param| {
                try callback(context, tree, param.type_expr orelse continue);
            }
            if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
                try callback(context, tree, align_expr);
            }
            if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| {
                try callback(context, tree, addrspace_expr);
            }
            if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
                try callback(context, tree, section_expr);
            }
            if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
                try callback(context, tree, callconv_expr);
            }
            if (fn_proto.ast.return_type.unwrap()) |return_type| {
                try callback(context, tree, return_type);
            }
        },

        .container_decl_arg,
        .container_decl_arg_trailing,
        => {
            const decl = tree.containerDeclArg(node).ast;
            try callback(context, tree, decl.arg.unwrap().?);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            const decl = tree.taggedUnionEnumTag(node).ast;
            try callback(context, tree, decl.arg.unwrap().?);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .container_field => {
            const field = tree.containerField(node).ast;
            try callback(context, tree, field.type_expr.unwrap().?);
            try callback(context, tree, field.align_expr.unwrap().?);
            try callback(context, tree, field.value_expr.unwrap().?);
        },

        .@"asm" => {
            const asm_node = tree.asmFull(node);

            try callback(context, tree, asm_node.ast.template);

            for (asm_node.outputs) |output_node| {
                const has_arrow = token_tags[tree.nodeMainToken(output_node) + 4] == .arrow;
                if (has_arrow) {
                    try callback(context, tree, tree.nodeData(output_node).node_and_extra.@"0");
                }
            }

            for (asm_node.inputs) |input_node| {
                try callback(context, tree, tree.nodeData(input_node).node_and_token.@"0");
            }
        },

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
        .error_set_decl,
        .error_value,
        => {},
    }
}

/// calls the given `callback` on every child of the given node and their children
/// see `nodeChildrenRecursiveAlloc` for a non-iterator allocating variant.
pub fn iterateChildrenRecursive(
    tree: Ast,
    node: Ast.Node.Index,
    context: anytype,
    comptime Error: type,
    comptime callback: fn (@TypeOf(context), Ast, Ast.Node.Index) Error!void,
) Error!void {
    const RecursiveContext = struct {
        fn recursive_callback(ctx: *const anyopaque, ast: Ast, child_node: Ast.Node.Index) anyerror!void {
            if (child_node == .root) return;
            try callback(@as(*const @TypeOf(context), @alignCast(@ptrCast(ctx))).*, ast, child_node);
            try iterateChildrenTypeErased(ast, child_node, ctx, recursive_callback);
        }
    };

    if (iterateChildrenTypeErased(tree, node, @ptrCast(&context), RecursiveContext.recursive_callback)) |_| {
        return;
    } else |err| {
        return @as(Error, @errorCast(err));
    }
}

/// returns the children of the given node.
/// see `iterateChildren` for a callback variant
/// see `nodeChildrenRecursiveAlloc` for a recursive variant.
/// caller owns the returned memory
pub fn nodeChildrenAlloc(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}![]Ast.Node.Index {
    const Context = struct {
        allocator: std.mem.Allocator,
        children: *std.ArrayListUnmanaged(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            if (child_node == 0) return;
            try self.children.append(self.allocator, child_node);
        }
    };

    var children: std.ArrayListUnmanaged(Ast.Node.Index) = .empty;
    errdefer children.deinit();
    try iterateChildren(tree, node, Context{ .allocator = allocator, .children = &children }, error{OutOfMemory}, Context.callback);
    return children.toOwnedSlice();
}

/// returns the children of the given node.
/// see `iterateChildrenRecursive` for a callback variant
/// caller owns the returned memory
pub fn nodeChildrenRecursiveAlloc(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}![]Ast.Node.Index {
    const Context = struct {
        allocator: std.mem.Allocator,
        children: *std.ArrayListUnmanaged(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            if (child_node == 0) return;
            try self.children.append(self.allocator, child_node);
        }
    };

    var children: std.ArrayListUnmanaged(Ast.Node.Index) = .empty;
    errdefer children.deinit();
    try iterateChildrenRecursive(tree, node, .{ .allocator = allocator, .children = &children }, Context.callback);
    return children.toOwnedSlice(allocator);
}

/// returns a list of nodes that overlap with the given source code index.
/// sorted from smallest to largest.
/// caller owns the returned memory.
pub fn nodesOverlappingIndex(allocator: std.mem.Allocator, tree: Ast, index: usize) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(index <= tree.source.len);

    const Context = struct {
        index: usize,
        allocator: std.mem.Allocator,
        nodes: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
            if (node == .root) return;
            const loc = offsets.nodeToLoc(ast, node);
            if (loc.start <= self.index and self.index <= loc.end) {
                try iterateChildren(ast, node, self, error{OutOfMemory}, append);
                try self.nodes.append(self.allocator, node);
            }
        }
    };

    var context: Context = .{ .index = index, .allocator = allocator };
    try iterateChildren(tree, .root, &context, error{OutOfMemory}, Context.append);
    try context.nodes.append(allocator, .root);
    return try context.nodes.toOwnedSlice(allocator);
}

/// returns a list of nodes that together encloses the given source code range
/// caller owns the returned memory
pub fn nodesAtLoc(allocator: std.mem.Allocator, tree: Ast, loc: offsets.Loc) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(loc.start <= loc.end and loc.end <= tree.source.len);

    const Context = struct {
        allocator: std.mem.Allocator,
        nodes: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
        locs: std.ArrayListUnmanaged(offsets.Loc) = .empty,

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) !void {
            if (node == .root) return;
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
        try iterateChildren(tree, parent, &context, error{OutOfMemory}, Context.append);

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
