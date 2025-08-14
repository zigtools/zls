//! Collection of functions from std.zig.ast that we need
//! and may hit undefined in the standard library implementation
//! when there are parser errors.

const std = @import("std");
const offsets = @import("offsets.zig");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const full = Ast.full;

fn fullPtrTypeComponents(tree: Ast, info: full.PtrType.Components) full.PtrType {
    const size: std.builtin.Type.Pointer.Size = switch (tree.tokenTag(info.main_token)) {
        .asterisk,
        .asterisk_asterisk,
        => switch (tree.tokenTag(info.main_token + 1)) {
            .r_bracket, .colon => .many,
            .identifier => if (info.main_token != 0 and tree.tokenTag(info.main_token - 1) == .l_bracket) .c else .one,
            else => .one,
        },
        .l_bracket => switch (tree.tokenTag(info.main_token + 1)) {
            .asterisk => if (tree.tokenTag(info.main_token + 2) == .identifier) .c else .many,
            else => .slice,
        },
        else => unreachable,
    };
    var result: full.PtrType = .{
        .size = size,
        .allowzero_token = null,
        .const_token = null,
        .volatile_token = null,
        .ast = info,
    };
    // We need to be careful that we don't iterate over any sub-expressions
    // here while looking for modifiers as that could result in false
    // positives. Therefore, start after a sentinel if there is one and
    // skip over any align node and bit range nodes.
    var i = if (info.sentinel.unwrap()) |sentinel| lastToken(tree, sentinel) + 1 else switch (size) {
        .many, .c => info.main_token + 1,
        else => info.main_token,
    };
    const end = tree.firstToken(info.child_type);
    while (i < end) : (i += 1) {
        switch (tree.tokenTag(i)) {
            .keyword_allowzero => result.allowzero_token = i,
            .keyword_const => result.const_token = i,
            .keyword_volatile => result.volatile_token = i,
            .keyword_align => {
                const align_node = info.align_node.unwrap().?;
                if (info.bit_range_end.unwrap()) |bit_range_end| {
                    i = lastToken(tree, bit_range_end) + 1;
                } else {
                    i = lastToken(tree, align_node) + 1;
                }
            },
            else => {},
        }
    }
    return result;
}

pub fn ptrTypeSimple(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodeTag(node) == .ptr_type);
    const extra_index, const child_type = tree.nodeData(node).extra_and_node;
    const extra = tree.extraData(extra_index, Node.PtrType);
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodeMainToken(node),
        .align_node = extra.align_node,
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrTypeSentinel(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodeTag(node) == .ptr_type_sentinel);
    const sentinel, const child_type = tree.nodeData(node).opt_node_and_node;
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodeMainToken(node),
        .align_node = .none,
        .addrspace_node = .none,
        .sentinel = sentinel,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrTypeAligned(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodeTag(node) == .ptr_type_aligned);
    const align_node, const child_type = tree.nodeData(node).opt_node_and_node;
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodeMainToken(node),
        .align_node = align_node,
        .addrspace_node = .none,
        .sentinel = .none,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrTypeBitRange(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodeTag(node) == .ptr_type_bit_range);
    const extra_index, const child_type = tree.nodeData(node).extra_and_node;
    const extra = tree.extraData(extra_index, Node.PtrTypeBitRange);
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodeMainToken(node),
        .align_node = extra.align_node.toOptional(),
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = extra.bit_range_start.toOptional(),
        .bit_range_end = extra.bit_range_end.toOptional(),
        .child_type = child_type,
    });
}

fn legacyAsmComponents(tree: Ast, info: full.AsmLegacy.Components) full.AsmLegacy {
    var result: full.AsmLegacy = .{
        .ast = info,
        .volatile_token = null,
        .inputs = &.{},
        .outputs = &.{},
        .first_clobber = null,
    };
    if (info.asm_token + 1 < tree.tokens.len and tree.tokenTag(info.asm_token + 1) == .keyword_volatile) {
        result.volatile_token = info.asm_token + 1;
    }
    const outputs_end: usize = for (info.items, 0..) |item, i| {
        switch (tree.nodeTag(item)) {
            .asm_output => continue,
            else => break i,
        }
    } else info.items.len;

    result.outputs = info.items[0..outputs_end];
    result.inputs = info.items[outputs_end..];

    if (info.items.len == 0) {
        // asm ("foo" ::: "a", "b");
        const template_token = lastToken(tree, info.template);
        if (template_token + 4 < tree.tokens.len and
            tree.tokenTag(template_token + 1) == .colon and
            tree.tokenTag(template_token + 2) == .colon and
            tree.tokenTag(template_token + 3) == .colon and
            tree.tokenTag(template_token + 4) == .string_literal)
        {
            result.first_clobber = template_token + 4;
        }
    } else if (result.inputs.len != 0) {
        // asm ("foo" :: [_] "" (y) : "a", "b");
        const last_input = result.inputs[result.inputs.len - 1];
        const rparen = lastToken(tree, last_input);
        var i = rparen + 1;
        // Allow a (useless) comma right after the closing parenthesis.
        if (tree.tokenTag(i) == .comma) i += 1;
        if (tree.tokenTag(i) == .colon and
            tree.tokenTag(i + 1) == .string_literal)
        {
            result.first_clobber = i + 1;
        }
    } else {
        // asm ("foo" : [_] "" (x) :: "a", "b");
        const last_output = result.outputs[result.outputs.len - 1];
        const rparen = lastToken(tree, last_output);
        var i = rparen + 1;
        // Allow a (useless) comma right after the closing parenthesis.
        if (i + 1 < tree.tokens.len and tree.tokenTag(i) == .comma) i += 1;
        if (i + 2 < tree.tokens.len and
            tree.tokenTag(i) == .colon and
            tree.tokenTag(i + 1) == .colon and
            tree.tokenTag(i + 2) == .string_literal)
        {
            result.first_clobber = i + 2;
        }
    }

    return result;
}

fn fullAsmComponents(tree: Ast, info: full.Asm.Components) full.Asm {
    var result: full.Asm = .{
        .ast = info,
        .volatile_token = null,
        .inputs = &.{},
        .outputs = &.{},
    };
    if (info.asm_token + 1 < tree.tokens.len and tree.tokenTag(info.asm_token + 1) == .keyword_volatile) {
        result.volatile_token = info.asm_token + 1;
    }
    const outputs_end: usize = for (info.items, 0..) |item, i| {
        switch (tree.nodeTag(item)) {
            .asm_output => continue,
            else => break i,
        }
    } else info.items.len;

    result.outputs = info.items[0..outputs_end];
    result.inputs = info.items[outputs_end..];

    return result;
}

pub fn asmLegacy(tree: Ast, node: Node.Index) full.AsmLegacy {
    const template, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.AsmLegacy);
    const items = tree.extraDataSlice(.{ .start = extra.items_start, .end = extra.items_end }, Node.Index);
    return legacyAsmComponents(tree, .{
        .asm_token = tree.nodeMainToken(node),
        .template = template,
        .items = items,
        .rparen = extra.rparen,
    });
}

pub fn asmSimple(tree: Ast, node: Node.Index) full.Asm {
    const template, const rparen = tree.nodeData(node).node_and_token;
    return fullAsmComponents(tree, .{
        .asm_token = tree.nodeMainToken(node),
        .template = template,
        .items = &.{},
        .rparen = rparen,
        .clobbers = .none,
    });
}

pub fn asmFull(tree: Ast, node: Node.Index) full.Asm {
    const template, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.Asm);
    const items = tree.extraDataSlice(.{ .start = extra.items_start, .end = extra.items_end }, Node.Index);
    return fullAsmComponents(tree, .{
        .asm_token = tree.nodeMainToken(node),
        .template = template,
        .items = items,
        .clobbers = extra.clobbers,
        .rparen = extra.rparen,
    });
}

fn fullIfComponents(tree: Ast, info: full.If.Components) full.If {
    var result: full.If = .{
        .ast = info,
        .payload_token = null,
        .error_token = null,
        .else_token = 0,
    };
    // if (cond_expr) |x|
    //              ^  ^
    const possible_payload_token = lastToken(tree, info.cond_expr) + 3;
    const possible_payload_identifier_token = possible_payload_token + @intFromBool(tree.tokenTag(possible_payload_token) == .asterisk);
    if (possible_payload_token < tree.tokens.len and
        tree.tokenTag(possible_payload_token - 1) == .pipe and
        tree.tokenTag(possible_payload_identifier_token) == .identifier)
    {
        result.payload_token = possible_payload_token;
    }
    if (info.else_expr != .none) {
        // then_expr else |x|
        //           ^     ^
        const possible_else_token = lastToken(tree, info.then_expr) + 1;
        if (tree.tokenTag(possible_else_token) == .keyword_else) {
            result.else_token = possible_else_token;
            if (result.else_token + 2 < tree.tokens.len and
                tree.tokenTag(result.else_token + 1) == .pipe and
                tree.tokenTag(result.else_token + 2) == .identifier)
            {
                result.error_token = result.else_token + 2;
            }
        }
    }
    return result;
}

pub fn ifFull(tree: Ast, node: Node.Index) full.If {
    std.debug.assert(tree.nodeTag(node) == .@"if");
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.If);
    return fullIfComponents(tree, .{
        .cond_expr = cond_expr,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr.toOptional(),
        .if_token = tree.nodeMainToken(node),
    });
}

pub fn ifSimple(tree: Ast, node: Node.Index) full.If {
    std.debug.assert(tree.nodeTag(node) == .if_simple);
    const cond_expr, const then_expr = tree.nodeData(node).node_and_node;
    return fullIfComponents(tree, .{
        .cond_expr = cond_expr,
        .then_expr = then_expr,
        .else_expr = .none,
        .if_token = tree.nodeMainToken(node),
    });
}

fn fullWhileComponents(tree: Ast, info: full.While.Components) full.While {
    var result: full.While = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = null,
        .else_token = 0,
        .error_token = null,
    };
    var tok_i = info.while_token -| 1;
    if (tree.tokenTag(tok_i) == .keyword_inline) {
        result.inline_token = tok_i;
        tok_i -= 1;
    }
    if (tree.tokenTag(tok_i) == .colon and
        tree.tokenTag(tok_i -| 1) == .identifier)
    {
        result.label_token = tok_i -| 1;
    }
    // while (cond_expr) |x|
    //                 ^  ^
    const possible_payload_token = lastToken(tree, info.cond_expr) + 3;
    const possible_payload_identifier_token = possible_payload_token + @intFromBool(tree.tokenTag(possible_payload_token) == .asterisk);
    if (possible_payload_token < tree.tokens.len and
        tree.tokenTag(possible_payload_token - 1) == .pipe and
        tree.tokenTag(possible_payload_identifier_token) == .identifier)
    {
        result.payload_token = possible_payload_token;
    }
    if (info.else_expr != .none) {
        // then_expr else |x|
        //           ^     ^
        const possible_else_token = lastToken(tree, info.then_expr) + 1;
        if (tree.tokenTag(possible_else_token) == .keyword_else) {
            result.else_token = possible_else_token;
            if (result.else_token + 2 < tree.tokens.len and
                tree.tokenTag(result.else_token + 1) == .pipe and
                tree.tokenTag(result.else_token + 2) == .identifier)
            {
                result.error_token = result.else_token + 2;
            }
        }
    }
    return result;
}

fn fullForComponents(tree: Ast, info: full.For.Components) full.For {
    var result: full.For = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = undefined,
        .else_token = 0,
    };
    var tok_i = info.for_token -| 1;
    if (tree.tokenTag(tok_i) == .keyword_inline) {
        result.inline_token = tok_i;
        tok_i -|= 1;
    }
    if (tree.tokenTag(tok_i) == .colon and
        tree.tokenTag(tok_i -| 1) == .identifier)
    {
        result.label_token = tok_i -| 1;
    }
    const last_cond_token = lastToken(tree, info.inputs[info.inputs.len - 1]);
    result.payload_token = last_cond_token + 3 + @intFromBool(tree.tokenTag(last_cond_token + 1) == .comma);
    if (info.else_expr != .none) {
        const possible_else_token = lastToken(tree, info.then_expr) + 1;
        if (tree.tokenTag(possible_else_token) == .keyword_else) {
            result.else_token = possible_else_token;
        }
    }
    return result;
}

pub fn whileSimple(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const then_expr = tree.nodeData(node).node_and_node;
    return fullWhileComponents(tree, .{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = .none,
        .then_expr = then_expr,
        .else_expr = .none,
    });
}

pub fn whileCont(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.WhileCont);
    return fullWhileComponents(tree, .{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = extra.cont_expr.toOptional(),
        .then_expr = extra.then_expr,
        .else_expr = .none,
    });
}

pub fn whileFull(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.While);
    return fullWhileComponents(tree, .{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = extra.cont_expr,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr.toOptional(),
    });
}

pub fn forSimple(tree: Ast, node: Node.Index) full.For {
    const data = &tree.nodes.items(.data)[@intFromEnum(node)].node_and_node;
    return fullForComponents(tree, .{
        .for_token = tree.nodeMainToken(node),
        .inputs = (&data[0])[0..1],
        .then_expr = data[1],
        .else_expr = .none,
    });
}

pub fn forFull(tree: Ast, node: Node.Index) full.For {
    const extra_index, const extra = tree.nodeData(node).@"for";
    const inputs = tree.extraDataSliceWithLen(extra_index, extra.inputs, Node.Index);
    const then_expr: Node.Index = @enumFromInt(tree.extra_data[@intFromEnum(extra_index) + extra.inputs]);
    const else_expr: Node.OptionalIndex = if (extra.has_else) @enumFromInt(tree.extra_data[@intFromEnum(extra_index) + extra.inputs + 1]) else .none;
    return fullForComponents(tree, .{
        .for_token = tree.nodeMainToken(node),
        .inputs = inputs,
        .then_expr = then_expr,
        .else_expr = else_expr,
    });
}

pub fn fullPtrType(tree: Ast, node: Node.Index) ?full.PtrType {
    return switch (tree.nodeTag(node)) {
        .ptr_type_aligned => ptrTypeAligned(tree, node),
        .ptr_type_sentinel => ptrTypeSentinel(tree, node),
        .ptr_type => ptrTypeSimple(tree, node),
        .ptr_type_bit_range => ptrTypeBitRange(tree, node),
        else => null,
    };
}

pub fn fullIf(tree: Ast, node: Node.Index) ?full.If {
    return switch (tree.nodeTag(node)) {
        .if_simple => ifSimple(tree, node),
        .@"if" => ifFull(tree, node),
        else => null,
    };
}

pub fn fullWhile(tree: Ast, node: Node.Index) ?full.While {
    return switch (tree.nodeTag(node)) {
        .while_simple => whileSimple(tree, node),
        .while_cont => whileCont(tree, node),
        .@"while" => whileFull(tree, node),
        else => null,
    };
}

pub fn fullFor(tree: Ast, node: Node.Index) ?full.For {
    return switch (tree.nodeTag(node)) {
        .for_simple => forSimple(tree, node),
        .@"for" => forFull(tree, node),
        else => null,
    };
}

pub fn fullAsm(tree: Ast, node: Node.Index) ?full.Asm {
    return switch (tree.nodeTag(node)) {
        .asm_simple => asmSimple(tree, node),
        .@"asm" => asmFull(tree, node),
        else => null,
    };
}

fn findMatchingRBrace(tree: Ast, start: Ast.TokenIndex) ?Ast.TokenIndex {
    return if (std.mem.indexOfScalarPos(std.zig.Token.Tag, tree.tokens.items(.tag), start, .r_brace)) |index| @intCast(index) else null;
}

/// Similar to `std.zig.Ast.lastToken` but also handles ASTs with syntax errors.
pub fn lastToken(tree: Ast, node: Node.Index) Ast.TokenIndex {
    var n = node;
    var end_offset: u32 = 0;
    const last_token = while (true) switch (tree.nodeTag(n)) {
        .root => return @intCast(tree.tokens.len - 1),

        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .optional_type,
        .@"suspend",
        .@"resume",
        .@"nosuspend",
        .@"comptime",
        => n = tree.nodeData(n).node,

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
        .error_union,
        .if_simple,
        .while_simple,
        .for_simple,
        .fn_decl,
        .array_type,
        .switch_range,
        => n = tree.nodeData(n).node_and_node[1],

        .test_decl, .@"errdefer" => n = tree.nodeData(n).opt_token_and_node[1],
        .@"defer" => n = tree.nodeData(n).node,
        .anyframe_type => n = tree.nodeData(n).token_and_node[1],

        .switch_case_one,
        .switch_case_inline_one,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        => n = tree.nodeData(n).opt_node_and_node[1],

        .assign_destructure,
        .ptr_type,
        .ptr_type_bit_range,
        .switch_case,
        .switch_case_inline,
        => n = tree.nodeData(n).extra_and_node[1],

        .for_range => {
            n = tree.nodeData(n).node_and_opt_node[1].unwrap() orelse break tree.nodeMainToken(n);
        },

        .field_access,
        .unwrap_optional,
        .asm_simple,
        => break tree.nodeData(n).node_and_token[1],
        .grouped_expression, .asm_input => break tree.nodeData(n).node_and_token[1],
        .multiline_string_literal, .error_set_decl => break tree.nodeData(n).token_and_token[1],
        .asm_output => break tree.nodeData(n).opt_node_and_token[1],
        .error_value => break @min(tree.nodeMainToken(n) + 2, tree.tokens.len - 1),

        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .identifier,
        .deref,
        .enum_literal,
        .string_literal,
        => break tree.nodeMainToken(n),

        .@"return" => n = tree.nodeData(n).opt_node.unwrap() orelse break tree.nodeMainToken(n),

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(n).?;
            if (var_decl.ast.init_node.unwrap()) |init_node| {
                n = init_node;
            } else if (var_decl.ast.section_node.unwrap()) |section_node| {
                end_offset += 1; // rparen
                n = section_node;
            } else if (var_decl.ast.align_node.unwrap()) |align_node| {
                end_offset += 1; // rparen
                n = align_node;
            } else if (var_decl.ast.type_node.unwrap()) |type_node| {
                n = type_node;
            } else {
                end_offset += 1; // from mut token to name
                break tree.nodeMainToken(n);
            }
        },

        .array_type_sentinel => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.ArrayTypeSentinel);
            n = extra.elem_type;
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const slice = tree.fullSlice(n).?;
            if (slice.ast.sentinel.unwrap()) |sentinel| {
                end_offset += 1; // rbracket
                n = sentinel;
            } else if (slice.ast.end.unwrap()) |end| {
                end_offset += 1; // rbracket
                n = end;
            } else {
                end_offset += 2; // ellipsis2 + rbracket
                n = slice.ast.start;
            }
        },

        .@"switch",
        .switch_comma,
        => |tag| {
            const condition, const extra_index = tree.nodeData(n).node_and_extra;
            const members = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
            if (members.len == 0) {
                const last_token = lastToken(tree, condition) + 3; // rparen + lbrace + rbrace
                break findMatchingRBrace(tree, last_token) orelse last_token;
            } else {
                const has_comma = tag == .switch_comma;
                const last_member = members[members.len - 1];
                const last_token = lastToken(tree, last_member) + @intFromBool(has_comma) + 1; // rbrace
                break findMatchingRBrace(tree, last_token) orelse last_token;
            }
        },

        .array_access => {
            end_offset += 1;
            n = tree.nodeData(n).node_and_node[1];
        },

        .@"continue", .@"break" => {
            const opt_label, const opt_rhs = tree.nodeData(n).opt_token_and_opt_node;
            if (opt_rhs.unwrap()) |rhs| {
                n = rhs;
            } else if (opt_label.unwrap()) |lhs| {
                break lhs;
            } else {
                break tree.nodeMainToken(n);
            }
        },

        .while_cont => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.WhileCont);
            n = extra.then_expr;
        },
        .@"while" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.While);
            n = extra.else_expr;
        },
        .@"if" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.If);
            n = extra.else_expr;
        },
        .@"for" => {
            const extra_index, const extra = tree.nodeData(n).@"for";
            const index = @intFromEnum(extra_index) + extra.inputs + @intFromBool(extra.has_else);
            n = @enumFromInt(tree.extra_data[index]);
        },
        .asm_legacy => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.AsmLegacy);
            break extra.rparen;
        },
        .@"asm" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.Asm);
            break extra.rparen;
        },

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => |tag| {
            const has_comma = switch (tag) {
                .array_init_one, .array_init_dot_two, .array_init_dot, .array_init => false,
                .array_init_one_comma, .array_init_dot_two_comma, .array_init_dot_comma, .array_init_comma => true,
                else => unreachable,
            };
            var buffer: [2]Node.Index = undefined;
            const array_init = tree.fullArrayInit(&buffer, n).?;
            const last_element = array_init.ast.elements[array_init.ast.elements.len - 1];
            end_offset += @intFromBool(has_comma);
            end_offset += 1; // rbrace
            n = last_element;
        },

        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => |tag| {
            var buffer: [2]Node.Index = undefined;
            const struct_init = tree.fullStructInit(&buffer, n).?;
            end_offset += 1; // rbrace
            if (struct_init.ast.fields.len == 0) {
                break tree.nodeMainToken(n);
            } else {
                const has_comma = switch (tag) {
                    .struct_init_one, .struct_init_dot_two, .struct_init_dot, .struct_init => false,
                    .struct_init_one_comma, .struct_init_dot_two_comma, .struct_init_dot_comma, .struct_init_comma => true,
                    else => unreachable,
                };
                end_offset += @intFromBool(has_comma);
                const last_field = struct_init.ast.fields[struct_init.ast.fields.len - 1];
                n = last_field;
            }
        },

        .call_one,
        .call_one_comma,
        .call,
        .call_comma,
        => |tag| {
            var buffer: [1]Node.Index = undefined;
            const call = tree.fullCall(&buffer, n).?;
            end_offset += 1; // rparen
            if (call.ast.params.len == 0) {
                break tree.nodeMainToken(n);
            } else {
                const has_comma = switch (tag) {
                    .call_one, .call => false,
                    .call_one_comma, .call_comma => true,
                    else => unreachable,
                };
                end_offset += @intFromBool(has_comma);
                const last_param = call.ast.params[call.ast.params.len - 1];
                n = last_param;
            }
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buffer: [1]Ast.Node.Index = undefined;
            const fn_proto = tree.fullFnProto(&buffer, n).?;
            if (fn_proto.ast.return_type.unwrap()) |return_type| {
                n = return_type;
            } else {
                // This is not correct
                end_offset += 2; // rparen rparen
                break tree.nodeMainToken(n);
            }
        },

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => |tag| {
            var buffer: [2]Node.Index = undefined;
            const params = tree.builtinCallParams(&buffer, n).?;
            if (params.len == 0) {
                end_offset += 2; // lparen + rparen
                break tree.nodeMainToken(n);
            } else {
                const has_comma = switch (tag) {
                    .builtin_call_two, .builtin_call => false,
                    .builtin_call_two_comma, .builtin_call_comma => true,
                    else => unreachable,
                };
                end_offset += @intFromBool(has_comma);
                end_offset += 1; // rparen
                const last_param = params[params.len - 1];
                n = last_param;
            }
        },

        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => |tag| {
            var buffer: [2]Ast.Node.Index = undefined;
            const container_decl = tree.fullContainerDecl(&buffer, n).?;
            if (container_decl.ast.members.len == 0) {
                if (container_decl.ast.arg.unwrap()) |arg| {
                    end_offset += 4; // rparen + rparen + lbrace + rbrace
                    n = arg;
                } else {
                    var i: u32 = switch (tag) {
                        .container_decl_two, .container_decl_two_trailing => 2, // lbrace + rbrace
                        .tagged_union_two, .tagged_union_two_trailing => 5, // (enum) {}
                        else => unreachable,
                    };
                    while (tree.tokenTag(tree.nodeMainToken(n) + i) == .container_doc_comment) i += 1;
                    end_offset += i;
                    break tree.nodeMainToken(n);
                }
            } else {
                const has_comma = switch (tag) {
                    .container_decl, .container_decl_two, .container_decl_arg, .tagged_union, .tagged_union_two, .tagged_union_enum_tag => false,
                    .container_decl_trailing, .container_decl_two_trailing, .container_decl_arg_trailing, .tagged_union_trailing, .tagged_union_two_trailing, .tagged_union_enum_tag_trailing => true,
                    else => unreachable,
                };
                const last_member = container_decl.ast.members[container_decl.ast.members.len - 1];
                const last_token = lastToken(tree, last_member) + @intFromBool(has_comma) + 1; // rbrace
                break findMatchingRBrace(tree, last_token) orelse last_token;
            }
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => {
            const container_field = tree.fullContainerField(n).?;
            if (container_field.ast.value_expr.unwrap()) |value_expr| {
                n = value_expr;
            } else if (container_field.ast.align_expr.unwrap()) |align_expr| {
                end_offset += 1; // rparen
                n = align_expr;
            } else {
                n = container_field.ast.type_expr.unwrap().?;
            }
        },

        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => |tag| {
            var buffer: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buffer, n).?;
            if (statements.len == 0) {
                const last_token = tree.nodeMainToken(n) + 1; // rbrace
                break findMatchingRBrace(tree, last_token) orelse last_token;
            } else {
                const has_comma = switch (tag) {
                    .block_two, .block => false,
                    .block_two_semicolon, .block_semicolon => true,
                    else => unreachable,
                };
                const last_statement = statements[statements.len - 1];
                const last_token = lastToken(tree, last_statement) + @intFromBool(has_comma) + 1; // rbrace
                break findMatchingRBrace(tree, last_token) orelse last_token;
            }
        },
    };
    return last_token + end_offset;
}

pub fn testDeclNameAndToken(tree: Ast, test_decl_node: Ast.Node.Index) ?struct { Ast.TokenIndex, []const u8 } {
    const test_name_token = tree.nodeData(test_decl_node).opt_token_and_node[0].unwrap() orelse return null;

    switch (tree.tokenTag(test_name_token)) {
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
    if (tree.tokenTag(main_token) != .identifier) return null;
    return main_token;
}

pub fn hasInferredError(tree: Ast, fn_proto: Ast.full.FnProto) bool {
    const return_type = fn_proto.ast.return_type.unwrap() orelse return false;
    return tree.tokenTag(tree.firstToken(return_type) - 1) == .bang;
}

pub fn paramFirstToken(tree: Ast, param: Ast.full.FnProto.Param, include_doc_comment: bool) Ast.TokenIndex {
    return (if (include_doc_comment) param.first_doc_comment else null) orelse
        param.comptime_noalias orelse
        param.name_token orelse
        tree.firstToken(param.type_expr.?);
}

pub fn paramLastToken(tree: Ast, param: Ast.full.FnProto.Param) Ast.TokenIndex {
    return param.anytype_ellipsis3 orelse lastToken(tree, param.type_expr.?);
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
    if (tree.tokenTag(tree.nodeMainToken(node)) != .keyword_union)
        return false;

    var buf: [2]Ast.Node.Index = undefined;
    const decl = tree.fullContainerDecl(&buf, node) orelse
        return false;

    return decl.ast.enum_token != null or decl.ast.arg != .none;
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

pub fn blockLabel(tree: Ast, node: Ast.Node.Index) ?Ast.TokenIndex {
    const main_token = tree.nodeMainToken(node);

    if (main_token < 2) return null;
    if (tree.tokenTag(main_token - 1) != .colon) return null;
    if (tree.tokenTag(main_token - 2) != .identifier) return null;
    return main_token - 2;
}

pub fn errorSetFieldCount(tree: Ast, node: Ast.Node.Index) usize {
    std.debug.assert(tree.nodeTag(node) == .error_set_decl);
    var count: usize = 0;
    const lbrace, const rbrace = tree.nodeData(node).token_and_token;
    for (lbrace + 1..rbrace) |tok_i| {
        count += @intFromBool(tree.tokenTag(@intCast(tok_i)) == .identifier);
    }
    return count;
}

/// Iterates over FnProto Params w/ added bounds check to support incomplete ast nodes
pub fn nextFnParam(it: *Ast.full.FnProto.Iterator) ?Ast.full.FnProto.Param {
    while (true) {
        var first_doc_comment: ?Ast.TokenIndex = null;
        var comptime_noalias: ?Ast.TokenIndex = null;
        var name_token: ?Ast.TokenIndex = null;
        if (!it.tok_flag) {
            if (it.param_i >= it.fn_proto.ast.params.len) {
                return null;
            }
            const param_type = it.fn_proto.ast.params[it.param_i];
            const last_param_type_token = lastToken(it.tree.*, param_type);
            var tok_i = it.tree.firstToken(param_type) - 1;
            while (true) : (tok_i -= 1) switch (it.tree.tokenTag(tok_i)) {
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
            if (it.tree.tokenTag(it.tok_i) == .comma) {
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
        if (it.tree.tokenTag(it.tok_i) == .comma) {
            it.tok_i += 1;
        }
        if (it.tree.tokenTag(it.tok_i) == .r_paren) {
            return null;
        }
        if (it.tree.tokenTag(it.tok_i) == .doc_comment) {
            first_doc_comment = it.tok_i;
            while (it.tree.tokenTag(it.tok_i) == .doc_comment) {
                it.tok_i += 1;
            }
        }
        switch (it.tree.tokenTag(it.tok_i)) {
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
        if (it.tree.tokenTag(it.tok_i) == .identifier and
            it.tree.tokenTag(it.tok_i + 1) == .colon)
        {
            name_token = it.tok_i;
            it.tok_i += 2;
        }
        if (it.tree.tokenTag(it.tok_i) == .keyword_anytype) {
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
            return callback(@as(*const @TypeOf(context), @ptrCast(@alignCast(ctx))).*, t, n);
        }
    };
    if (iterateChildrenTypeErased(tree, node, @ptrCast(&context), &ctx.inner)) |_| {
        return;
    } else |err| {
        return @as(Error, @errorCast(err));
    }
}

test "iterateChildren - fn_proto_* inside of fn_proto" {
    const allocator = std.testing.allocator;

    var tree: std.zig.Ast = try .parse(
        allocator,
        \\pub fn nextAge(age: u32) u32 {
        \\  return age + 1;
        \\}
    ,
        .zig,
    );
    defer tree.deinit(allocator);

    var children_tags: std.ArrayList(Ast.Node.Tag) = .empty;
    defer children_tags.deinit(allocator);

    const Context = struct {
        accumulator: *std.ArrayList(Ast.Node.Tag),
        ally: std.mem.Allocator,

        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) !void {
            try self.accumulator.append(self.ally, ast.nodeTag(child_node));
        }
    };

    const fn_decl = tree.rootDecls()[0];
    try iterateChildren(
        tree,
        fn_decl,
        Context{ .accumulator = &children_tags, .ally = allocator },
        error{OutOfMemory},
        Context.callback,
    );

    try std.testing.expectEqualSlices(Ast.Node.Tag, &.{
        .fn_proto_simple, // i.e., `pub fn nextAge(age: u32) u32`
        .block_two_semicolon, // i.e., `return { return age + 1; }`
    }, children_tags.items);
}

fn iterateChildrenTypeErased(
    tree: Ast,
    node: Ast.Node.Index,
    context: *const anyopaque,
    callback: *const fn (*const anyopaque, Ast, Ast.Node.Index) anyerror!void,
) anyerror!void {
    switch (tree.nodeTag(node)) {
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
        .@"defer",
        => {
            try callback(context, tree, tree.nodeData(node).node);
        },

        .@"return" => {
            if (tree.nodeData(node).opt_node.unwrap()) |lhs| {
                try callback(context, tree, lhs);
            }
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

        .call_one,
        .call_one_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .container_field_init,
        .for_range,
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
        .block_two,
        .block_two_semicolon,
        .builtin_call_two,
        .builtin_call_two_comma,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            const opt_lhs, const opt_rhs = tree.nodeData(node).opt_node_and_opt_node;
            if (opt_lhs.unwrap()) |lhs| {
                try callback(context, tree, lhs);
            }
            if (opt_rhs.unwrap()) |rhs| {
                try callback(context, tree, rhs);
            }
        },

        .field_access,
        .unwrap_optional,
        .grouped_expression,
        .asm_simple,
        => {
            try callback(context, tree, tree.nodeData(node).node_and_token[0]);
        },
        .test_decl, .@"errdefer" => try callback(context, tree, tree.nodeData(node).opt_token_and_node[1]),
        .anyframe_type => try callback(context, tree, tree.nodeData(node).token_and_node[1]),
        .@"break",
        .@"continue",
        => {
            if (tree.nodeData(node).opt_token_and_opt_node[1].unwrap()) |rhs| {
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
            for (tree.extraDataSlice(tree.nodeData(node).extra_range, Ast.Node.Index)) |child| {
                try callback(context, tree, child);
            }
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?.ast;
            if (var_decl.type_node.unwrap()) |type_node| try callback(context, tree, type_node);
            if (var_decl.align_node.unwrap()) |align_node| try callback(context, tree, align_node);
            if (var_decl.addrspace_node.unwrap()) |addrspace_node| try callback(context, tree, addrspace_node);
            if (var_decl.section_node.unwrap()) |section_node| try callback(context, tree, section_node);
            if (var_decl.init_node.unwrap()) |init_node| try callback(context, tree, init_node);
        },

        .assign_destructure => {
            const assign_destructure = tree.assignDestructure(node);
            for (assign_destructure.ast.variables) |lhs_node| {
                try callback(context, tree, lhs_node);
            }
            try callback(context, tree, assign_destructure.ast.value_expr);
        },

        .array_type_sentinel => {
            const array_type = tree.arrayTypeSentinel(node).ast;
            try callback(context, tree, array_type.elem_count);
            if (array_type.sentinel.unwrap()) |sentinel| try callback(context, tree, sentinel);
            try callback(context, tree, array_type.elem_type);
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const ptr_type = fullPtrType(tree, node).?.ast;
            if (ptr_type.sentinel.unwrap()) |sentinel| try callback(context, tree, sentinel);
            if (ptr_type.align_node.unwrap()) |align_node| try callback(context, tree, align_node);
            if (ptr_type.bit_range_start.unwrap()) |bit_range_start| try callback(context, tree, bit_range_start);
            if (ptr_type.bit_range_end.unwrap()) |bit_range_end| try callback(context, tree, bit_range_end);
            if (ptr_type.addrspace_node.unwrap()) |addrspace_node| try callback(context, tree, addrspace_node);
            try callback(context, tree, ptr_type.child_type);
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const slice = tree.fullSlice(node).?;
            try callback(context, tree, slice.ast.sliced);
            try callback(context, tree, slice.ast.start);
            if (slice.ast.end.unwrap()) |end| try callback(context, tree, end);
            if (slice.ast.sentinel.unwrap()) |sentinel| try callback(context, tree, sentinel);
        },

        .array_init,
        .array_init_comma,
        => {
            const array_init = tree.arrayInit(node).ast;
            if (array_init.type_expr.unwrap()) |type_expr| try callback(context, tree, type_expr);
            for (array_init.elements) |child| {
                try callback(context, tree, child);
            }
        },

        .struct_init,
        .struct_init_comma,
        => {
            const struct_init = tree.structInit(node).ast;
            if (struct_init.type_expr.unwrap()) |type_expr| try callback(context, tree, type_expr);
            for (struct_init.fields) |child| {
                try callback(context, tree, child);
            }
        },

        .call,
        .call_comma,
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
            const switch_ast = tree.fullSwitch(node).?;
            try callback(context, tree, switch_ast.ast.condition);
            for (switch_ast.ast.cases) |child| {
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
            const while_ast = fullWhile(tree, node).?.ast;
            try callback(context, tree, while_ast.cond_expr);
            if (while_ast.cont_expr.unwrap()) |cont_expr| try callback(context, tree, cont_expr);
            try callback(context, tree, while_ast.then_expr);
            if (while_ast.else_expr.unwrap()) |else_expr| try callback(context, tree, else_expr);
        },
        .for_simple,
        .@"for",
        => {
            const for_ast = fullFor(tree, node).?.ast;
            for (for_ast.inputs) |child| {
                try callback(context, tree, child);
            }
            try callback(context, tree, for_ast.then_expr);
            if (for_ast.else_expr.unwrap()) |else_expr| try callback(context, tree, else_expr);
        },

        .@"if",
        .if_simple,
        => {
            const if_ast = fullIf(tree, node).?.ast;
            try callback(context, tree, if_ast.cond_expr);
            try callback(context, tree, if_ast.then_expr);
            if (if_ast.else_expr.unwrap()) |else_expr| try callback(context, tree, else_expr);
        },
        .fn_decl => {
            try callback(context, tree, tree.nodeData(node).node_and_node[0]);
            try callback(context, tree, tree.nodeData(node).node_and_node[1]);
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
            if (fn_proto.ast.align_expr.unwrap()) |align_expr| try callback(context, tree, align_expr);
            if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| try callback(context, tree, addrspace_expr);
            if (fn_proto.ast.section_expr.unwrap()) |section_expr| try callback(context, tree, section_expr);
            if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| try callback(context, tree, callconv_expr);
            if (fn_proto.ast.return_type.unwrap()) |return_type| try callback(context, tree, return_type);
        },

        .container_decl_arg,
        .container_decl_arg_trailing,
        => {
            const decl = tree.containerDeclArg(node).ast;
            if (decl.arg.unwrap()) |arg| try callback(context, tree, arg);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            const decl = tree.taggedUnionEnumTag(node).ast;
            if (decl.arg.unwrap()) |arg| try callback(context, tree, arg);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .container_field => {
            const field = tree.containerField(node).ast;
            try callback(context, tree, field.type_expr.unwrap().?);
            if (field.align_expr.unwrap()) |align_expr| try callback(context, tree, align_expr);
            if (field.value_expr.unwrap()) |value_expr| try callback(context, tree, value_expr);
        },

        .asm_legacy,
        .@"asm",
        => {
            const asm_node = tree.asmFull(node);

            try callback(context, tree, asm_node.ast.template);

            for (asm_node.outputs) |output_node| {
                const has_arrow = tree.tokenTag(tree.nodeMainToken(output_node) + 4) == .arrow;
                if (has_arrow) {
                    if (tree.nodeData(output_node).opt_node_and_token[0].unwrap()) |lhs| {
                        try callback(context, tree, lhs);
                    }
                }
            }

            for (asm_node.inputs) |input_node| {
                try callback(context, tree, tree.nodeData(input_node).node_and_token[0]);
            }
        },

        .asm_output,
        .asm_input,
        => unreachable,

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
            std.debug.assert(child_node != .root);
            try callback(@as(*const @TypeOf(context), @ptrCast(@alignCast(ctx))).*, ast, child_node);
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
        children: *std.ArrayList(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            try self.children.append(self.allocator, child_node);
        }
    };

    var children: std.ArrayList(Ast.Node.Index) = .empty;
    errdefer children.deinit(allocator);
    try iterateChildren(tree, node, Context{ .allocator = allocator, .children = &children }, error{OutOfMemory}, Context.callback);
    return children.toOwnedSlice(allocator);
}

test nodeChildrenAlloc {
    const allocator = std.testing.allocator;

    var tree = try std.zig.Ast.parse(
        allocator,
        "const namespace = struct { field_a: u32 };",
        .zig,
    );
    defer tree.deinit(allocator);

    const namespace = tree.rootDecls()[0];

    const children = try nodeChildrenAlloc(
        allocator,
        tree,
        namespace,
    );
    defer allocator.free(children);

    try std.testing.expectEqual(1, children.len);
    try std.testing.expectEqualStrings("struct { field_a: u32 }", tree.getNodeSource(children[0]));
}

/// returns the children of the given node.
/// see `iterateChildrenRecursive` for a callback variant
/// caller owns the returned memory
pub fn nodeChildrenRecursiveAlloc(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}![]Ast.Node.Index {
    const Context = struct {
        allocator: std.mem.Allocator,
        children: *std.ArrayList(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            try self.children.append(self.allocator, child_node);
        }
    };

    var children: std.ArrayList(Ast.Node.Index) = .empty;
    errdefer children.deinit(allocator);
    try iterateChildrenRecursive(tree, node, Context{ .allocator = allocator, .children = &children }, error{OutOfMemory}, Context.callback);
    return children.toOwnedSlice(allocator);
}

test nodeChildrenRecursiveAlloc {
    const allocator = std.testing.allocator;

    var tree = try std.zig.Ast.parse(
        allocator,
        "const namespace = struct { field_a: u32 };",
        .zig,
    );
    defer tree.deinit(allocator);

    const namespace = tree.rootDecls()[0];

    const children = try nodeChildrenRecursiveAlloc(
        allocator,
        tree,
        namespace,
    );
    defer allocator.free(children);

    try std.testing.expectEqual(3, children.len);
    try std.testing.expectEqualStrings("struct { field_a: u32 }", tree.getNodeSource(children[0]));
    try std.testing.expectEqualStrings("field_a: u32", tree.getNodeSource(children[1]));
    try std.testing.expectEqualStrings("u32", tree.getNodeSource(children[2]));
}

/// returns a list of nodes that overlap with the given source code index.
/// sorted from smallest to largest.
/// caller owns the returned memory.
pub fn nodesOverlappingIndex(allocator: std.mem.Allocator, tree: Ast, index: usize) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(index <= tree.source.len);

    const Context = struct {
        index: usize,
        allocator: std.mem.Allocator,
        nodes: std.ArrayList(Ast.Node.Index) = .empty,

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
            std.debug.assert(node != .root);
            const loc = offsets.nodeToLoc(ast, node);
            if (loc.start <= self.index and self.index <= loc.end) {
                try iterateChildren(ast, node, self, error{OutOfMemory}, append);
                try self.nodes.append(self.allocator, node);
            }
        }
    };

    var context: Context = .{ .index = index, .allocator = allocator };
    defer context.nodes.deinit(allocator);
    try iterateChildren(tree, .root, &context, error{OutOfMemory}, Context.append);
    try context.nodes.append(allocator, .root);
    return try context.nodes.toOwnedSlice(allocator);
}

/// returns a list of nodes that overlap with the given source code index.
/// the list may include nodes that were discarded during error recovery in the Zig parser.
/// sorted from smallest to largest.
/// caller owns the returned memory.
/// this function can be removed when the parser has been improved.
pub fn nodesOverlappingIndexIncludingParseErrors(allocator: std.mem.Allocator, tree: Ast, source_index: usize) error{OutOfMemory}![]Ast.Node.Index {
    const NodeLoc = struct {
        node: Ast.Node.Index,
        loc: offsets.Loc,

        fn lessThan(_: void, lhs: @This(), rhs: @This()) bool {
            return rhs.loc.start < lhs.loc.start and lhs.loc.end < rhs.loc.end;
        }
    };

    var node_locs: std.ArrayList(NodeLoc) = .empty;
    defer node_locs.deinit(allocator);
    for (0..tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
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
pub fn nodesAtLoc(allocator: std.mem.Allocator, tree: Ast, loc: offsets.Loc) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(loc.start <= loc.end and loc.end <= tree.source.len);

    const Context = struct {
        allocator: std.mem.Allocator,
        nodes: std.ArrayList(Ast.Node.Index) = .empty,
        locs: std.ArrayList(offsets.Loc) = .empty,

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) !void {
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

pub fn indexOfBreakTarget(
    tree: Ast,
    nodes: []const Ast.Node.Index,
    break_label_maybe: ?[]const u8,
) ?usize {
    for (nodes, 0..) |node, index| {
        if (fullFor(tree, node)) |for_node| {
            const break_label = break_label_maybe orelse return index;
            const for_label = tree.tokenSlice(for_node.label_token orelse continue);
            if (std.mem.eql(u8, break_label, for_label)) return index;
        } else if (fullWhile(tree, node)) |while_node| {
            const break_label = break_label_maybe orelse return index;
            const while_label = tree.tokenSlice(while_node.label_token orelse continue);
            if (std.mem.eql(u8, break_label, while_label)) return index;
        } else if (tree.fullSwitch(node)) |switch_node| {
            const break_label = break_label_maybe orelse continue;
            const switch_label = tree.tokenSlice(switch_node.label_token orelse continue);
            if (std.mem.eql(u8, break_label, switch_label)) return index;
        } else switch (tree.nodeTag(node)) {
            .block,
            .block_semicolon,
            .block_two,
            .block_two_semicolon,
            => {
                const break_label = break_label_maybe orelse continue;
                const block_label_token = blockLabel(tree, node) orelse continue;
                const block_label = tree.tokenSlice(block_label_token);

                if (std.mem.eql(u8, break_label, block_label)) return index;
            },
            else => {},
        }
    }
    return null;
}
