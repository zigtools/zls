//! Collection of functions from std.zig.ast that we need
//! and may hit undefined in the standard library implementation
//! when there are parser errors.

const std = @import("std");
const offsets = @import("offsets.zig");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const full = Ast.full;

fn fullPtrTypeComponents(tree: Ast, info: full.PtrType.Components) full.PtrType {
    const token_tags = tree.tokens.items(.tag);
    const size: std.builtin.Type.Pointer.Size = switch (token_tags[info.main_token]) {
        .asterisk,
        .asterisk_asterisk,
        => switch (token_tags[info.main_token + 1]) {
            .r_bracket, .colon => .Many,
            .identifier => if (info.main_token != 0 and token_tags[info.main_token - 1] == .l_bracket) .C else .One,
            else => .One,
        },
        .l_bracket => .Slice,
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
    var i = if (info.sentinel != 0) lastToken(tree, info.sentinel) + 1 else info.main_token;
    const end = tree.firstToken(info.child_type);
    while (i < end) : (i += 1) {
        switch (token_tags[i]) {
            .keyword_allowzero => result.allowzero_token = i,
            .keyword_const => result.const_token = i,
            .keyword_volatile => result.volatile_token = i,
            .keyword_align => {
                std.debug.assert(info.align_node != 0);
                if (info.bit_range_end != 0) {
                    std.debug.assert(info.bit_range_start != 0);
                    i = lastToken(tree, info.bit_range_end) + 1;
                } else {
                    i = lastToken(tree, info.align_node) + 1;
                }
            },
            else => {},
        }
    }
    return result;
}

pub fn ptrTypeSimple(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodes.items(.tag)[node] == .ptr_type);
    const data = tree.nodes.items(.data)[node];
    const extra = tree.extraData(data.lhs, Node.PtrType);
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodes.items(.main_token)[node],
        .align_node = extra.align_node,
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = 0,
        .bit_range_end = 0,
        .child_type = data.rhs,
    });
}

pub fn ptrTypeSentinel(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodes.items(.tag)[node] == .ptr_type_sentinel);
    const data = tree.nodes.items(.data)[node];
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodes.items(.main_token)[node],
        .align_node = 0,
        .addrspace_node = 0,
        .sentinel = data.lhs,
        .bit_range_start = 0,
        .bit_range_end = 0,
        .child_type = data.rhs,
    });
}

pub fn ptrTypeAligned(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodes.items(.tag)[node] == .ptr_type_aligned);
    const data = tree.nodes.items(.data)[node];
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodes.items(.main_token)[node],
        .align_node = data.lhs,
        .addrspace_node = 0,
        .sentinel = 0,
        .bit_range_start = 0,
        .bit_range_end = 0,
        .child_type = data.rhs,
    });
}

pub fn ptrTypeBitRange(tree: Ast, node: Node.Index) full.PtrType {
    std.debug.assert(tree.nodes.items(.tag)[node] == .ptr_type_bit_range);
    const data = tree.nodes.items(.data)[node];
    const extra = tree.extraData(data.lhs, Node.PtrTypeBitRange);
    return fullPtrTypeComponents(tree, .{
        .main_token = tree.nodes.items(.main_token)[node],
        .align_node = extra.align_node,
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = extra.bit_range_start,
        .bit_range_end = extra.bit_range_end,
        .child_type = data.rhs,
    });
}

fn fullIfComponents(tree: Ast, info: full.If.Components) full.If {
    const token_tags = tree.tokens.items(.tag);
    var result: full.If = .{
        .ast = info,
        .payload_token = null,
        .error_token = null,
        .else_token = undefined,
    };
    // if (cond_expr) |x|
    //              ^ ^
    const payload_pipe = lastToken(tree, info.cond_expr) + 2;
    if (token_tags[payload_pipe] == .pipe) {
        result.payload_token = payload_pipe + 1;
    }
    if (info.else_expr != 0) {
        // then_expr else |x|
        //           ^    ^
        result.else_token = lastToken(tree, info.then_expr) + 1;
        if (token_tags[result.else_token + 1] == .pipe) {
            result.error_token = result.else_token + 2;
        }
    }
    return result;
}

pub fn ifFull(tree: Ast, node: Node.Index) full.If {
    std.debug.assert(tree.nodes.items(.tag)[node] == .@"if");
    const data = tree.nodes.items(.data)[node];
    const extra = tree.extraData(data.rhs, Node.If);
    return fullIfComponents(tree, .{
        .cond_expr = data.lhs,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr,
        .if_token = tree.nodes.items(.main_token)[node],
    });
}

pub fn ifSimple(tree: Ast, node: Node.Index) full.If {
    std.debug.assert(tree.nodes.items(.tag)[node] == .if_simple);
    const data = tree.nodes.items(.data)[node];
    return fullIfComponents(tree, .{
        .cond_expr = data.lhs,
        .then_expr = data.rhs,
        .else_expr = 0,
        .if_token = tree.nodes.items(.main_token)[node],
    });
}

fn fullWhileComponents(tree: Ast, info: full.While.Components) full.While {
    const token_tags = tree.tokens.items(.tag);
    var result: full.While = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = null,
        .else_token = undefined,
        .error_token = null,
    };
    var tok_i = info.while_token -| 1;
    if (token_tags[tok_i] == .keyword_inline) {
        result.inline_token = tok_i;
        tok_i -= 1;
    }
    if (token_tags[tok_i] == .colon and
        token_tags[tok_i -| 1] == .identifier)
    {
        result.label_token = tok_i -| 1;
    }
    const last_cond_token = lastToken(tree, info.cond_expr);
    if (token_tags[last_cond_token + 2] == .pipe) {
        result.payload_token = last_cond_token + 3;
    }
    if (info.else_expr != 0) {
        // then_expr else |x|
        //           ^    ^
        result.else_token = lastToken(tree, info.then_expr) + 1;
        if (token_tags[result.else_token + 1] == .pipe) {
            result.error_token = result.else_token + 2;
        }
    }
    return result;
}

fn fullForComponents(tree: Ast, info: full.For.Components) full.For {
    const token_tags = tree.tokens.items(.tag);
    var result: full.For = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = undefined,
        .else_token = undefined,
    };
    var tok_i = info.for_token -| 1;
    if (token_tags[tok_i] == .keyword_inline) {
        result.inline_token = tok_i;
        tok_i -|= 1;
    }
    if (token_tags[tok_i] == .colon and
        token_tags[tok_i -| 1] == .identifier)
    {
        result.label_token = tok_i -| 1;
    }
    const last_cond_token = lastToken(tree, info.inputs[info.inputs.len - 1]);
    result.payload_token = last_cond_token + 3 + @intFromBool(token_tags[last_cond_token + 1] == .comma);
    if (info.else_expr != 0) {
        result.else_token = lastToken(tree, info.then_expr) + 1;
    }
    return result;
}

pub fn whileSimple(tree: Ast, node: Node.Index) full.While {
    const data = tree.nodes.items(.data)[node];
    return fullWhileComponents(tree, .{
        .while_token = tree.nodes.items(.main_token)[node],
        .cond_expr = data.lhs,
        .cont_expr = 0,
        .then_expr = data.rhs,
        .else_expr = 0,
    });
}

pub fn whileCont(tree: Ast, node: Node.Index) full.While {
    const data = tree.nodes.items(.data)[node];
    const extra = tree.extraData(data.rhs, Node.WhileCont);
    return fullWhileComponents(tree, .{
        .while_token = tree.nodes.items(.main_token)[node],
        .cond_expr = data.lhs,
        .cont_expr = extra.cont_expr,
        .then_expr = extra.then_expr,
        .else_expr = 0,
    });
}

pub fn whileFull(tree: Ast, node: Node.Index) full.While {
    const data = tree.nodes.items(.data)[node];
    const extra = tree.extraData(data.rhs, Node.While);
    return fullWhileComponents(tree, .{
        .while_token = tree.nodes.items(.main_token)[node],
        .cond_expr = data.lhs,
        .cont_expr = extra.cont_expr,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr,
    });
}

pub fn forSimple(tree: Ast, node: Node.Index) full.For {
    const data = &tree.nodes.items(.data)[node];
    const inputs: *[1]Node.Index = &data.lhs;
    return fullForComponents(tree, .{
        .for_token = tree.nodes.items(.main_token)[node],
        .inputs = inputs[0..1],
        .then_expr = data.rhs,
        .else_expr = 0,
    });
}

pub fn forFull(tree: Ast, node: Node.Index) full.For {
    const data = tree.nodes.items(.data)[node];
    const extra = @as(Node.For, @bitCast(data.rhs));
    const inputs = tree.extra_data[data.lhs..][0..extra.inputs];
    const then_expr = tree.extra_data[data.lhs + extra.inputs];
    const else_expr = if (extra.has_else) tree.extra_data[data.lhs + extra.inputs + 1] else 0;
    return fullForComponents(tree, .{
        .for_token = tree.nodes.items(.main_token)[node],
        .inputs = inputs,
        .then_expr = then_expr,
        .else_expr = else_expr,
    });
}

pub fn fullPtrType(tree: Ast, node: Node.Index) ?full.PtrType {
    return switch (tree.nodes.items(.tag)[node]) {
        .ptr_type_aligned => ptrTypeAligned(tree, node),
        .ptr_type_sentinel => ptrTypeSentinel(tree, node),
        .ptr_type => ptrTypeSimple(tree, node),
        .ptr_type_bit_range => ptrTypeBitRange(tree, node),
        else => null,
    };
}

pub fn fullIf(tree: Ast, node: Node.Index) ?full.If {
    return switch (tree.nodes.items(.tag)[node]) {
        .if_simple => ifSimple(tree, node),
        .@"if" => ifFull(tree, node),
        else => null,
    };
}

pub fn fullWhile(tree: Ast, node: Node.Index) ?full.While {
    return switch (tree.nodes.items(.tag)[node]) {
        .while_simple => whileSimple(tree, node),
        .while_cont => whileCont(tree, node),
        .@"while" => whileFull(tree, node),
        else => null,
    };
}

pub fn fullFor(tree: Ast, node: Node.Index) ?full.For {
    return switch (tree.nodes.items(.tag)[node]) {
        .for_simple => forSimple(tree, node),
        .@"for" => forFull(tree, node),
        else => null,
    };
}

pub fn lastToken(tree: Ast, node: Ast.Node.Index) Ast.TokenIndex {
    const TokenIndex = Ast.TokenIndex;
    const tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);
    var n = node;
    var end_offset: TokenIndex = 0;
    while (true) switch (tags[n]) {
        .root => return @as(TokenIndex, @intCast(tree.tokens.len - 1)),
        .@"usingnamespace" => {
            // lhs is the expression
            if (datas[n].lhs == 0) {
                return main_tokens[n] + end_offset;
            } else {
                n = datas[n].lhs;
            }
        },
        .test_decl => {
            // rhs is the block
            // lhs is the name
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .global_var_decl => {
            // rhs is init node
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                const extra = tree.extraData(datas[n].lhs, Node.GlobalVarDecl);
                if (extra.section_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.section_node;
                } else if (extra.align_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.align_node;
                } else if (extra.type_node != 0) {
                    n = extra.type_node;
                } else {
                    end_offset += 1; // from mut token to name
                    return main_tokens[n] + end_offset;
                }
            }
        },
        .local_var_decl => {
            // rhs is init node
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                const extra = tree.extraData(datas[n].lhs, Node.LocalVarDecl);
                if (extra.align_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.align_node;
                } else if (extra.type_node != 0) {
                    n = extra.type_node;
                } else {
                    end_offset += 1; // from mut token to name
                    return main_tokens[n] + end_offset;
                }
            }
        },
        .simple_var_decl => {
            // rhs is init node
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                end_offset += 1; // from mut token to name
                return main_tokens[n] + end_offset;
            }
        },
        .aligned_var_decl => {
            // rhs is init node, lhs is align node
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                end_offset += 1; // for the rparen
                n = datas[n].lhs;
            } else {
                end_offset += 1; // from mut token to name
                return main_tokens[n] + end_offset;
            }
        },
        .@"errdefer" => {
            // lhs is the token payload, rhs is the expression
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                // right pipe
                end_offset += 1;
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .@"defer" => {
            // rhs is the defered expr
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },

        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .@"resume",
        .@"nosuspend",
        .@"comptime",
        => n = datas[n].lhs,

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
        .assign_shl_sat,
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
        .anyframe_type,
        .error_union,
        .if_simple,
        .while_simple,
        .for_simple,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .array_type,
        .switch_case_one,
        .switch_case,
        .switch_case_inline_one,
        .switch_case_inline,
        .switch_range,
        => n = datas[n].rhs,

        .field_access,
        .unwrap_optional,
        .grouped_expression,
        .multiline_string_literal,
        .error_set_decl,
        .asm_simple,
        .asm_output,
        .asm_input,
        => return datas[n].rhs + end_offset,

        .error_value => {
            if (datas[n].rhs != 0) {
                return datas[n].rhs + end_offset;
            } else if (datas[n].lhs != 0) {
                return datas[n].lhs + end_offset;
            } else {
                return main_tokens[n] + end_offset;
            }
        },

        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .identifier,
        .deref,
        .enum_literal,
        .string_literal,
        => return main_tokens[n] + end_offset,

        .@"return" => if (datas[n].lhs != 0) {
            n = datas[n].lhs;
        } else {
            return main_tokens[n] + end_offset;
        },

        .for_range => if (datas[n].rhs != 0) {
            n = datas[n].rhs;
        } else {
            return main_tokens[n] + end_offset;
        },

        .call, .async_call => {
            end_offset += 1; // for the rparen
            const params = tree.extraData(datas[n].rhs, Node.SubRange);
            if (params.end - params.start == 0) {
                return main_tokens[n] + end_offset;
            }
            n = tree.extra_data[params.end - 1]; // last parameter
        },
        .tagged_union_enum_tag => {
            const members = tree.extraData(datas[n].rhs, Node.SubRange);
            if (members.end - members.start == 0) {
                end_offset += 4; // for the rparen + rparen + lbrace + rbrace
                n = datas[n].lhs;
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[members.end - 1]; // last parameter
            }
        },
        .call_comma,
        .async_call_comma,
        .tagged_union_enum_tag_trailing,
        => {
            end_offset += 2; // for the comma/semicolon + rparen/rbrace
            const params = tree.extraData(datas[n].rhs, Node.SubRange);
            if (params.end - params.start == 0) {
                return main_tokens[n] + end_offset;
            }
            n = tree.extra_data[params.end - 1]; // last parameter
        },
        .@"switch" => {
            const cases = tree.extraData(datas[n].rhs, Node.SubRange);
            if (cases.end - cases.start == 0) {
                end_offset += 3; // rparen, lbrace, rbrace
                n = datas[n].lhs; // condition expression
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[cases.end - 1]; // last case
            }
        },
        .container_decl_arg,
        .container_decl_arg_trailing,
        => {
            const members = tree.extraData(datas[n].rhs, Node.SubRange);
            if (members.end - members.start == 0) {
                end_offset += 3; // for the rparen + lbrace + rbrace
                n = datas[n].lhs;
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[members.end - 1]; // last parameter
            }
        },
        .@"asm" => {
            const extra = tree.extraData(datas[n].rhs, Node.Asm);
            return extra.rparen + end_offset;
        },
        .array_init,
        .struct_init,
        => {
            const elements = tree.extraData(datas[n].rhs, Node.SubRange);
            std.debug.assert(elements.end - elements.start > 0);
            end_offset += 1; // for the rbrace
            n = tree.extra_data[elements.end - 1]; // last element
        },
        .array_init_comma,
        .struct_init_comma,
        .switch_comma,
        => {
            if (datas[n].rhs != 0) {
                const members = tree.extraData(datas[n].rhs, Node.SubRange);
                std.debug.assert(members.end - members.start > 0);
                end_offset += 2; // for the comma + rbrace
                n = tree.extra_data[members.end - 1]; // last parameter
            } else {
                end_offset += 1;
                n = datas[n].lhs;
            }
        },
        .array_init_dot,
        .struct_init_dot,
        .block,
        .container_decl,
        .tagged_union,
        .builtin_call,
        => {
            std.debug.assert(datas[n].rhs - datas[n].lhs > 0);
            end_offset += 1; // for the rbrace
            n = tree.extra_data[datas[n].rhs - 1]; // last statement
        },
        .array_init_dot_comma,
        .struct_init_dot_comma,
        .block_semicolon,
        .container_decl_trailing,
        .tagged_union_trailing,
        .builtin_call_comma,
        => {
            std.debug.assert(datas[n].rhs - datas[n].lhs > 0);
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            n = tree.extra_data[datas[n].rhs - 1]; // last member
        },
        .call_one,
        .async_call_one,
        .array_access,
        => {
            end_offset += 1; // for the rparen/rbracket
            if (datas[n].rhs == 0) {
                return main_tokens[n] + end_offset;
            }
            n = datas[n].rhs;
        },
        .array_init_dot_two,
        .block_two,
        .builtin_call_two,
        .struct_init_dot_two,
        .container_decl_two,
        .tagged_union_two,
        => {
            if (datas[n].rhs != 0) {
                end_offset += 1; // for the rparen/rbrace
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                end_offset += 1; // for the rparen/rbrace
                n = datas[n].lhs;
            } else {
                switch (tags[n]) {
                    .array_init_dot_two,
                    .block_two,
                    .struct_init_dot_two,
                    => end_offset += 1, // rbrace
                    .builtin_call_two => end_offset += 2, // lparen/lbrace + rparen/rbrace
                    .container_decl_two => {
                        var i: u32 = 2; // lbrace + rbrace
                        while (token_tags[main_tokens[n] + i] == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    .tagged_union_two => {
                        var i: u32 = 5; // (enum) {}
                        while (token_tags[main_tokens[n] + i] == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    else => unreachable,
                }
                return main_tokens[n] + end_offset;
            }
        },
        .array_init_dot_two_comma,
        .builtin_call_two_comma,
        .block_two_semicolon,
        .struct_init_dot_two_comma,
        .container_decl_two_trailing,
        .tagged_union_two_trailing,
        => {
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset; // returns { }
            }
        },
        .container_field_init => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .container_field_align => {
            if (datas[n].rhs != 0) {
                end_offset += 1; // for the rparen
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .container_field => {
            const extra = tree.extraData(datas[n].rhs, Node.ContainerField);
            if (extra.value_expr != 0) {
                n = extra.value_expr;
            } else if (extra.align_expr != 0) {
                end_offset += 1; // for the rparen
                n = extra.align_expr;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },

        .array_init_one,
        .struct_init_one,
        => {
            end_offset += 1; // rbrace
            if (datas[n].rhs == 0) {
                return main_tokens[n] + end_offset;
            } else {
                n = datas[n].rhs;
            }
        },
        .slice_open,
        .call_one_comma,
        .async_call_one_comma,
        .array_init_one_comma,
        .struct_init_one_comma,
        => {
            end_offset += 2; // ellipsis2 + rbracket, or comma + rparen
            n = datas[n].rhs;
            std.debug.assert(n != 0);
        },
        .slice => {
            const extra = tree.extraData(datas[n].rhs, Node.Slice);
            std.debug.assert(extra.end != 0); // should have used slice_open
            end_offset += 1; // rbracket
            n = extra.end;
        },
        .slice_sentinel => {
            const extra = tree.extraData(datas[n].rhs, Node.SliceSentinel);
            if (extra.sentinel != 0) {
                end_offset += 1; // right bracket
                n = extra.sentinel;
            } else if (extra.end != 0) {
                end_offset += 2; // colon, right bracket
                n = extra.end;
            } else {
                // Assume both sentinel and end are completely devoid of tokens
                end_offset += 3; // ellipsis, colon, right bracket
                n = extra.start;
            }
        },

        .@"continue" => {
            if (datas[n].lhs != 0) {
                return datas[n].lhs + end_offset;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .@"break" => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                return datas[n].lhs + end_offset;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .fn_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                n = datas[n].lhs;
            }
        },
        .fn_proto_multi => {
            const extra = tree.extraData(datas[n].lhs, Node.SubRange);
            // rhs can be 0 when no return type is provided
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                // Use the last argument and skip right paren
                n = tree.extra_data[extra.end - 1];
                end_offset += 1;
            }
        },
        .fn_proto_simple => {
            // rhs can be 0 when no return type is provided
            // lhs can be 0 when no parameter is provided
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
                // Skip right paren
                end_offset += 1;
            } else {
                // Skip left and right paren
                return main_tokens[n] + end_offset + 2;
            }
        },
        .fn_proto_one => {
            const extra = tree.extraData(datas[n].lhs, Node.FnProtoOne);
            // addrspace, linksection, callconv, align can appear in any order, so we
            // find the last one here.
            // rhs can be zero if no return type is provided
            var max_node: Node.Index = 0;
            var max_start: u32 = 0;
            if (datas[n].rhs != 0) {
                max_node = datas[n].rhs;
                max_start = token_starts[main_tokens[max_node]];
            }

            var max_offset: TokenIndex = 0;
            if (extra.align_expr != 0) {
                const start = token_starts[main_tokens[extra.align_expr]];
                if (start > max_start) {
                    max_node = extra.align_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.addrspace_expr != 0) {
                const start = token_starts[main_tokens[extra.addrspace_expr]];
                if (start > max_start) {
                    max_node = extra.addrspace_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.section_expr != 0) {
                const start = token_starts[main_tokens[extra.section_expr]];
                if (start > max_start) {
                    max_node = extra.section_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.callconv_expr != 0) {
                const start = token_starts[main_tokens[extra.callconv_expr]];
                if (start > max_start) {
                    max_node = extra.callconv_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }

            if (max_node == 0) {
                std.debug.assert(max_offset == 0);
                // No linksection, callconv, align, return type
                if (extra.param != 0) {
                    n = extra.param;
                    end_offset += 1;
                } else {
                    // Skip left and right parens
                    return main_tokens[n] + end_offset + 2;
                }
            } else {
                n = max_node;
                end_offset += max_offset;
            }
        },
        .fn_proto => {
            const extra = tree.extraData(datas[n].lhs, Node.FnProto);
            // addrspace, linksection, callconv, align can appear in any order, so we
            // find the last one here.
            // rhs can be zero if no return type is provided
            var max_node: Node.Index = 0;
            var max_start: u32 = 0;
            if (datas[n].rhs != 0) {
                max_node = datas[n].rhs;
                max_start = token_starts[main_tokens[max_node]];
            }

            var max_offset: TokenIndex = 0;
            if (extra.align_expr != 0) {
                const start = token_starts[main_tokens[extra.align_expr]];
                if (start > max_start) {
                    max_node = extra.align_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.addrspace_expr != 0) {
                const start = token_starts[main_tokens[extra.addrspace_expr]];
                if (start > max_start) {
                    max_node = extra.addrspace_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.section_expr != 0) {
                const start = token_starts[main_tokens[extra.section_expr]];
                if (start > max_start) {
                    max_node = extra.section_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.callconv_expr != 0) {
                const start = token_starts[main_tokens[extra.callconv_expr]];
                if (start > max_start) {
                    max_node = extra.callconv_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (max_node == 0) {
                std.debug.assert(max_offset == 0);
                // No linksection, callconv, align, return type
                // Use the last parameter and skip one extra token for the right paren
                n = extra.params_end;
                end_offset += 1;
            } else {
                n = max_node;
                end_offset += max_offset;
            }
        },
        .while_cont => {
            const extra = tree.extraData(datas[n].rhs, Node.WhileCont);
            std.debug.assert(extra.then_expr != 0);
            n = extra.then_expr;
        },
        .@"while" => {
            const extra = tree.extraData(datas[n].rhs, Node.While);
            std.debug.assert(extra.else_expr != 0);
            n = extra.else_expr;
        },
        .@"if" => {
            const extra = tree.extraData(datas[n].rhs, Node.If);
            std.debug.assert(extra.else_expr != 0);
            n = extra.else_expr;
        },
        .@"for" => {
            const extra = @as(Node.For, @bitCast(datas[n].rhs));
            n = tree.extra_data[datas[n].lhs + extra.inputs + @intFromBool(extra.has_else)];
        },
        .@"suspend" => {
            if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .array_type_sentinel => {
            const extra = tree.extraData(datas[n].rhs, Node.ArrayTypeSentinel);
            n = extra.elem_type;
        },
    };
}

pub fn hasInferredError(tree: Ast, fn_proto: Ast.full.FnProto) bool {
    const token_tags = tree.tokens.items(.tag);
    return token_tags[tree.firstToken(fn_proto.ast.return_type) - 1] == .bang;
}

pub fn paramFirstToken(tree: Ast, param: Ast.full.FnProto.Param) Ast.TokenIndex {
    return param.first_doc_comment orelse
        param.comptime_noalias orelse
        param.name_token orelse
        tree.firstToken(param.type_expr);
}

pub fn paramLastToken(tree: Ast, param: Ast.full.FnProto.Param) Ast.TokenIndex {
    return param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);
}

pub fn paramSlice(tree: Ast, param: Ast.full.FnProto.Param) []const u8 {
    const first_token = paramFirstToken(tree, param);
    const last_token = paramLastToken(tree, param);

    const start = offsets.tokenToIndex(tree, first_token);
    const end = offsets.tokenToLoc(tree, last_token).end;
    return tree.source[start..end];
}

pub fn isContainer(tree: Ast, node: Ast.Node.Index) bool {
    return switch (tree.nodes.items(.tag)[node]) {
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
    return switch (tree.nodes.items(.tag)[node]) {
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
    const node_data = tree.nodes.items(.data);
    return switch (tree.nodes.items(.tag)[node]) {
        .builtin_call_two, .builtin_call_two_comma => {
            buf[0] = node_data[node].lhs;
            buf[1] = node_data[node].rhs;
            if (node_data[node].lhs == 0) {
                return buf[0..0];
            } else if (node_data[node].rhs == 0) {
                return buf[0..1];
            } else {
                return buf[0..2];
            }
        },
        .builtin_call,
        .builtin_call_comma,
        => tree.extra_data[node_data[node].lhs..node_data[node].rhs],
        else => return null,
    };
}

/// returns a list of statements
pub fn blockStatements(tree: Ast, node: Ast.Node.Index, buf: *[2]Ast.Node.Index) ?[]const Node.Index {
    const node_data = tree.nodes.items(.data);
    return switch (tree.nodes.items(.tag)[node]) {
        .block_two, .block_two_semicolon => {
            buf[0] = node_data[node].lhs;
            buf[1] = node_data[node].rhs;
            if (node_data[node].lhs == 0) {
                return buf[0..0];
            } else if (node_data[node].rhs == 0) {
                return buf[0..1];
            } else {
                return buf[0..2];
            }
        },
        .block,
        .block_semicolon,
        => tree.extra_data[node_data[node].lhs..node_data[node].rhs],
        else => return null,
    };
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
            var tok_i = it.tree.firstToken(param_type) - 1;
            while (true) : (tok_i -= 1) switch (token_tags[tok_i]) {
                .colon => continue,
                .identifier => name_token = tok_i,
                .doc_comment => first_doc_comment = tok_i,
                .keyword_comptime, .keyword_noalias => comptime_noalias = tok_i,
                else => break,
            };
            it.param_i += 1;
            it.tok_i = it.tree.lastToken(param_type) + 1;

            // #boundsCheck
            // https://github.com/zigtools/zls/issues/567
            if (it.tree.lastToken(param_type) >= it.tree.tokens.len - 1)
                return Ast.full.FnProto.Param{
                    .first_doc_comment = first_doc_comment,
                    .comptime_noalias = comptime_noalias,
                    .name_token = name_token,
                    .anytype_ellipsis3 = null,
                    .type_expr = 0,
                };

            // Look for anytype and ... params afterwards.
            if (token_tags[it.tok_i] == .comma) {
                it.tok_i += 1;
            }
            it.tok_flag = true;
            return Ast.full.FnProto.Param{
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
                return Ast.full.FnProto.Param{
                    .first_doc_comment = first_doc_comment,
                    .comptime_noalias = null,
                    .name_token = null,
                    .anytype_ellipsis3 = it.tok_i,
                    .type_expr = 0,
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
            return Ast.full.FnProto.Param{
                .first_doc_comment = first_doc_comment,
                .comptime_noalias = comptime_noalias,
                .name_token = name_token,
                .anytype_ellipsis3 = it.tok_i - 1,
                .type_expr = 0,
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
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    if (node > tree.nodes.len) return;

    const tag = node_tags[node];
    switch (tag) {
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
        => {
            try callback(context, tree, node_data[node].lhs);
        },

        .test_decl,
        .@"errdefer",
        .@"defer",
        .@"break",
        .anyframe_type,
        => {
            try callback(context, tree, node_data[node].rhs);
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
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .container_field_init,
        .container_field_align,
        .block_two,
        .block_two_semicolon,
        .error_union,
        .for_range,
        => {
            try callback(context, tree, node_data[node].lhs);
            try callback(context, tree, node_data[node].rhs);
        },

        .root,
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
            for (tree.extra_data[node_data[node].lhs..node_data[node].rhs]) |child| {
                try callback(context, tree, child);
            }
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?.ast;
            try callback(context, tree, var_decl.type_node);
            try callback(context, tree, var_decl.align_node);
            try callback(context, tree, var_decl.addrspace_node);
            try callback(context, tree, var_decl.section_node);
            try callback(context, tree, var_decl.init_node);
        },

        .array_type_sentinel => {
            const array_type = tree.arrayTypeSentinel(node).ast;
            try callback(context, tree, array_type.elem_count);
            try callback(context, tree, array_type.sentinel);
            try callback(context, tree, array_type.elem_type);
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const ptr_type = fullPtrType(tree, node).?.ast;
            try callback(context, tree, ptr_type.sentinel);
            try callback(context, tree, ptr_type.align_node);
            try callback(context, tree, ptr_type.bit_range_start);
            try callback(context, tree, ptr_type.bit_range_end);
            try callback(context, tree, ptr_type.addrspace_node);
            try callback(context, tree, ptr_type.child_type);
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const slice = tree.fullSlice(node).?;
            try callback(context, tree, slice.ast.sliced);
            try callback(context, tree, slice.ast.start);
            try callback(context, tree, slice.ast.end);
            try callback(context, tree, slice.ast.sentinel);
        },

        .array_init,
        .array_init_comma,
        => {
            const array_init = tree.arrayInit(node).ast;
            try callback(context, tree, array_init.type_expr);
            for (array_init.elements) |child| {
                try callback(context, tree, child);
            }
        },

        .struct_init,
        .struct_init_comma,
        => {
            const struct_init = tree.structInit(node).ast;
            try callback(context, tree, struct_init.type_expr);
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
            const cond = node_data[node].lhs;
            const extra = tree.extraData(node_data[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];
            try callback(context, tree, cond);
            for (cases) |child| {
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
            try callback(context, tree, while_ast.cont_expr);
            try callback(context, tree, while_ast.then_expr);
            try callback(context, tree, while_ast.else_expr);
        },
        .for_simple,
        .@"for",
        => {
            const for_ast = fullFor(tree, node).?.ast;
            for (for_ast.inputs) |child| {
                try callback(context, tree, child);
            }
            try callback(context, tree, for_ast.then_expr);
            try callback(context, tree, for_ast.else_expr);
        },

        .@"if",
        .if_simple,
        => {
            const if_ast = fullIf(tree, node).?.ast;
            try callback(context, tree, if_ast.cond_expr);
            try callback(context, tree, if_ast.then_expr);
            try callback(context, tree, if_ast.else_expr);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        .fn_decl,
        => {
            var buffer: [1]Node.Index = undefined;
            const fn_proto = tree.fullFnProto(&buffer, node).?;

            var it = fn_proto.iterate(&tree);
            while (nextFnParam(&it)) |param| {
                try callback(context, tree, param.type_expr);
            }
            try callback(context, tree, fn_proto.ast.align_expr);
            try callback(context, tree, fn_proto.ast.addrspace_expr);
            try callback(context, tree, fn_proto.ast.section_expr);
            try callback(context, tree, fn_proto.ast.callconv_expr);
            try callback(context, tree, fn_proto.ast.return_type);
            if (node_tags[node] == .fn_decl) {
                try callback(context, tree, node_data[node].rhs);
            }
        },

        .container_decl_arg,
        .container_decl_arg_trailing,
        => {
            const decl = tree.containerDeclArg(node).ast;
            try callback(context, tree, decl.arg);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            const decl = tree.taggedUnionEnumTag(node).ast;
            try callback(context, tree, decl.arg);
            for (decl.members) |child| {
                try callback(context, tree, child);
            }
        },

        .container_field => {
            const field = tree.containerField(node).ast;
            try callback(context, tree, field.type_expr);
            try callback(context, tree, field.align_expr);
            try callback(context, tree, field.value_expr);
        },

        .@"asm" => {
            const asm_node = tree.asmFull(node);

            try callback(context, tree, asm_node.ast.template);

            for (asm_node.outputs) |output_node| {
                const has_arrow = token_tags[main_tokens[output_node] + 4] == .arrow;
                if (has_arrow) {
                    try callback(context, tree, node_data[output_node].lhs);
                }
            }

            for (asm_node.inputs) |input_node| {
                try callback(context, tree, node_data[input_node].lhs);
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
        fn recursive_callback(ctx: @TypeOf(context), ast: Ast, child_node: Ast.Node.Index) Error!void {
            if (child_node == 0) return;
            try callback(ctx, ast, child_node);
            try iterateChildren(ast, child_node, ctx, Error, recursive_callback);
        }
    };

    try iterateChildren(tree, node, context, Error, RecursiveContext.recursive_callback);
}

/// returns the children of the given node.
/// see `iterateChildren` for a callback variant
/// see `nodeChildrenRecursiveAlloc` for a recursive variant.
/// caller owns the returned memory
pub fn nodeChildrenAlloc(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}![]Ast.Node.Index {
    const Context = struct {
        children: *std.ArrayList(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            if (child_node == 0) return;
            try self.children.append(child_node);
        }
    };

    var children = std.ArrayList(Ast.Node.Index).init(allocator);
    errdefer children.deinit();
    try iterateChildren(tree, node, Context{ .children = &children }, error{OutOfMemory}, Context.callback);
    return children.toOwnedSlice();
}

/// returns the children of the given node.
/// see `iterateChildrenRecursive` for a callback variant
/// caller owns the returned memory
pub fn nodeChildrenRecursiveAlloc(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{OutOfMemory}![]Ast.Node.Index {
    const Context = struct {
        children: *std.ArrayList(Ast.Node.Index),
        fn callback(self: @This(), ast: Ast, child_node: Ast.Node.Index) error{OutOfMemory}!void {
            _ = ast;
            if (child_node == 0) return;
            try self.children.append(child_node);
        }
    };

    var children = std.ArrayList(Ast.Node.Index).init(allocator);
    errdefer children.deinit();
    try iterateChildrenRecursive(tree, node, .{ .children = &children }, Context.callback);
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
        nodes: std.ArrayListUnmanaged(Ast.Node.Index) = .{},

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) error{OutOfMemory}!void {
            if (node == 0) return;
            const loc = offsets.nodeToLoc(ast, node);
            if (loc.start <= self.index and self.index <= loc.end) {
                try iterateChildren(ast, node, self, error{OutOfMemory}, append);
                try self.nodes.append(self.allocator, node);
            }
        }
    };

    var context: Context = .{ .index = index, .allocator = allocator };
    try iterateChildren(tree, 0, &context, error{OutOfMemory}, Context.append);
    try context.nodes.append(allocator, 0);
    return try context.nodes.toOwnedSlice(allocator);
}

/// returns a list of nodes that together encloses the given source code range
/// caller owns the returned memory
pub fn nodesAtLoc(allocator: std.mem.Allocator, tree: Ast, loc: offsets.Loc) error{OutOfMemory}![]Ast.Node.Index {
    std.debug.assert(loc.start <= loc.end and loc.end <= tree.source.len);

    const Context = struct {
        allocator: std.mem.Allocator,
        nodes: std.ArrayListUnmanaged(Ast.Node.Index) = .{},
        locs: std.ArrayListUnmanaged(offsets.Loc) = .{},

        pub fn append(self: *@This(), ast: Ast, node: Ast.Node.Index) !void {
            if (node == 0) return;
            try self.nodes.append(self.allocator, node);
            try self.locs.append(self.allocator, offsets.nodeToLoc(ast, node));
        }
    };
    var context: Context = .{ .allocator = allocator };
    defer context.nodes.deinit(allocator);
    defer context.locs.deinit(allocator);

    try context.nodes.ensureTotalCapacity(allocator, 32);

    var parent: Ast.Node.Index = 0; // root node
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
