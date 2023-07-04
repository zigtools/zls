const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.module);
const Ast = std.zig.Ast;

const Module = @This();
const DocumentStore = @import("../DocumentStore.zig");
const Handle = DocumentStore.Handle;

/// Canonical reference to a position within a source file.
pub const SrcLoc = struct {
    handle: *Handle,
    /// Might be 0 depending on tag of `lazy`.
    parent_decl_node: Ast.Node.Index,
    /// Relative to `parent_decl_node`.
    lazy: LazySrcLoc,

    pub fn declSrcToken(src_loc: SrcLoc) Ast.TokenIndex {
        const tree = src_loc.handle.tree;
        return tree.firstToken(src_loc.parent_decl_node);
    }

    pub fn declRelativeToNodeIndex(src_loc: SrcLoc, offset: i32) Ast.TokenIndex {
        return @as(Ast.Node.Index, @bitCast(offset + @as(i32, @bitCast(src_loc.parent_decl_node))));
    }

    pub const Span = struct {
        start: u32,
        end: u32,
        main: u32,
    };

    pub fn span(src_loc: SrcLoc) Span {
        switch (src_loc.lazy) {
            .unneeded => unreachable,
            .entire_file => return Span{ .start = 0, .end = 1, .main = 0 },

            .byte_abs => |byte_index| return Span{ .start = byte_index, .end = byte_index + 1, .main = byte_index },

            .token_abs => |tok_index| {
                const tree = src_loc.handle.tree;
                const start = tree.tokens.items(.start)[tok_index];
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .node_abs => |node| {
                const tree = src_loc.handle.tree;
                return nodeToSpan(tree, node);
            },
            .byte_offset => |byte_off| {
                const tree = src_loc.handle.tree;
                const tok_index = src_loc.declSrcToken();
                const start = tree.tokens.items(.start)[tok_index] + byte_off;
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .token_offset => |tok_off| {
                const tree = src_loc.handle.tree;
                const tok_index = src_loc.declSrcToken() + tok_off;
                const start = tree.tokens.items(.start)[tok_index];
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .node_offset => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                return nodeToSpan(tree, node);
            },
            .node_offset_main_token => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const main_token = tree.nodes.items(.main_token)[node];
                return tokensToSpan(tree, main_token, main_token, main_token);
            },
            .node_offset_bin_op => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                return nodeToSpan(tree, node);
            },
            .node_offset_initializer => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                return tokensToSpan(
                    tree,
                    tree.firstToken(node) - 3,
                    tree.lastToken(node),
                    tree.nodes.items(.main_token)[node] - 2,
                );
            },
            .node_offset_var_decl_ty => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const node_tags = tree.nodes.items(.tag);
                const full = switch (node_tags[node]) {
                    .global_var_decl,
                    .local_var_decl,
                    .simple_var_decl,
                    .aligned_var_decl,
                    => tree.fullVarDecl(node).?,
                    .@"usingnamespace" => {
                        const node_data = tree.nodes.items(.data);
                        return nodeToSpan(tree, node_data[node].lhs);
                    },
                    else => unreachable,
                };
                if (full.ast.type_node != 0) {
                    return nodeToSpan(tree, full.ast.type_node);
                }
                const tok_index = full.ast.mut_token + 1; // the name token
                const start = tree.tokens.items(.start)[tok_index];
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .node_offset_var_decl_align => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullVarDecl(node).?;
                return nodeToSpan(tree, full.ast.align_node);
            },
            .node_offset_var_decl_section => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullVarDecl(node).?;
                return nodeToSpan(tree, full.ast.section_node);
            },
            .node_offset_var_decl_addrspace => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullVarDecl(node).?;
                return nodeToSpan(tree, full.ast.addrspace_node);
            },
            .node_offset_var_decl_init => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullVarDecl(node).?;
                return nodeToSpan(tree, full.ast.init_node);
            },
            .node_offset_builtin_call_arg0 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 0),
            .node_offset_builtin_call_arg1 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 1),
            .node_offset_builtin_call_arg2 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 2),
            .node_offset_builtin_call_arg3 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 3),
            .node_offset_builtin_call_arg4 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 4),
            .node_offset_builtin_call_arg5 => |n| return src_loc.byteOffsetBuiltinCallArg(n, 5),
            .node_offset_array_access_index => |node_off| {
                const tree = src_loc.handle.tree;
                const node_datas = tree.nodes.items(.data);
                const node = src_loc.declRelativeToNodeIndex(node_off);
                return nodeToSpan(tree, node_datas[node].rhs);
            },
            .node_offset_slice_ptr,
            .node_offset_slice_start,
            .node_offset_slice_end,
            .node_offset_slice_sentinel,
            => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullSlice(node).?;
                const part_node = switch (src_loc.lazy) {
                    .node_offset_slice_ptr => full.ast.sliced,
                    .node_offset_slice_start => full.ast.start,
                    .node_offset_slice_end => full.ast.end,
                    .node_offset_slice_sentinel => full.ast.sentinel,
                    else => unreachable,
                };
                return nodeToSpan(tree, part_node);
            },
            .node_offset_call_func => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullCall(&buf, node).?;
                return nodeToSpan(tree, full.ast.fn_expr);
            },
            .node_offset_field_name => |node_off| {
                const tree = src_loc.handle.tree;
                const node_datas = tree.nodes.items(.data);
                const node_tags = tree.nodes.items(.tag);
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const tok_index = switch (node_tags[node]) {
                    .field_access => node_datas[node].rhs,
                    else => tree.firstToken(node) - 2,
                };
                const start = tree.tokens.items(.start)[tok_index];
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .node_offset_deref_ptr => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                return nodeToSpan(tree, node);
            },
            .node_offset_asm_source => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullAsm(node).?;
                return nodeToSpan(tree, full.ast.template);
            },
            .node_offset_asm_ret_ty => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const full = tree.fullAsm(node).?;
                const asm_output = full.outputs[0];
                const node_datas = tree.nodes.items(.data);
                return nodeToSpan(tree, node_datas[asm_output].lhs);
            },

            .node_offset_if_cond => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const node_tags = tree.nodes.items(.tag);
                const src_node = switch (node_tags[node]) {
                    .if_simple,
                    .@"if",
                    => tree.fullIf(node).?.ast.cond_expr,

                    .while_simple,
                    .while_cont,
                    .@"while",
                    .for_simple,
                    .@"for",
                    => tree.fullWhile(node).?.ast.cond_expr,

                    .@"orelse" => node,
                    .@"catch" => node,
                    else => unreachable,
                };
                return nodeToSpan(tree, src_node);
            },
            .for_input => |for_input| {
                const tree = try src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(for_input.for_node_offset);
                const for_full = tree.fullFor(node).?;
                const src_node = for_full.ast.inputs[for_input.input_index];
                return nodeToSpan(tree, src_node);
            },
            .for_capture_from_input => |node_off| {
                const tree = try src_loc.handle.tree;
                const token_tags = tree.tokens.items(.tag);
                const input_node = src_loc.declRelativeToNodeIndex(node_off);
                // We have to actually linear scan the whole AST to find the for loop
                // that contains this input.
                const node_tags = tree.nodes.items(.tag);
                for (node_tags, 0..) |node_tag, node_usize| {
                    const node = @as(Ast.Node.Index, @intCast(node_usize));
                    switch (node_tag) {
                        .for_simple, .@"for" => {
                            const for_full = tree.fullFor(node).?;
                            for (for_full.ast.inputs, 0..) |input, input_index| {
                                if (input_node == input) {
                                    var count = input_index;
                                    var tok = for_full.payload_token;
                                    while (true) {
                                        switch (token_tags[tok]) {
                                            .comma => {
                                                count -= 1;
                                                tok += 1;
                                            },
                                            .identifier => {
                                                if (count == 0)
                                                    return tokensToSpan(tree, tok, tok + 1, tok);
                                                tok += 1;
                                            },
                                            .asterisk => {
                                                if (count == 0)
                                                    return tokensToSpan(tree, tok, tok + 2, tok);
                                                tok += 1;
                                            },
                                            else => unreachable,
                                        }
                                    }
                                }
                            }
                        },
                        else => continue,
                    }
                } else unreachable;
            },
            .node_offset_bin_lhs => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const node_datas = tree.nodes.items(.data);
                return nodeToSpan(tree, node_datas[node].lhs);
            },
            .node_offset_bin_rhs => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const node_datas = tree.nodes.items(.data);
                return nodeToSpan(tree, node_datas[node].rhs);
            },

            .node_offset_switch_operand => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                const node_datas = tree.nodes.items(.data);
                return nodeToSpan(tree, node_datas[node].lhs);
            },

            .node_offset_switch_special_prong => |node_off| {
                const tree = src_loc.handle.tree;
                const switch_node = src_loc.declRelativeToNodeIndex(node_off);
                const node_datas = tree.nodes.items(.data);
                const node_tags = tree.nodes.items(.tag);
                const main_tokens = tree.nodes.items(.main_token);
                const extra = tree.extraData(node_datas[switch_node].rhs, Ast.Node.SubRange);
                const case_nodes = tree.extra_data[extra.start..extra.end];
                for (case_nodes) |case_node| {
                    const case = tree.fullSwitchCase(case_node).?;
                    const is_special = (case.ast.values.len == 0) or
                        (case.ast.values.len == 1 and
                        node_tags[case.ast.values[0]] == .identifier and
                        std.mem.eql(u8, tree.tokenSlice(main_tokens[case.ast.values[0]]), "_"));
                    if (!is_special) continue;

                    return nodeToSpan(tree, case_node);
                } else unreachable;
            },

            .node_offset_switch_range => |node_off| {
                const tree = src_loc.handle.tree;
                const switch_node = src_loc.declRelativeToNodeIndex(node_off);
                const node_datas = tree.nodes.items(.data);
                const node_tags = tree.nodes.items(.tag);
                const main_tokens = tree.nodes.items(.main_token);
                const extra = tree.extraData(node_datas[switch_node].rhs, Ast.Node.SubRange);
                const case_nodes = tree.extra_data[extra.start..extra.end];
                for (case_nodes) |case_node| {
                    const case = tree.fullSwitchCase(case_node).?;
                    const is_special = (case.ast.values.len == 0) or
                        (case.ast.values.len == 1 and
                        node_tags[case.ast.values[0]] == .identifier and
                        std.mem.eql(u8, tree.tokenSlice(main_tokens[case.ast.values[0]]), "_"));
                    if (is_special) continue;

                    for (case.ast.values) |item_node| {
                        if (node_tags[item_node] == .switch_range) {
                            return nodeToSpan(tree, item_node);
                        }
                    }
                } else unreachable;
            },
            .node_offset_switch_prong_capture => |node_off| {
                const tree = src_loc.handle.tree;
                const case_node = src_loc.declRelativeToNodeIndex(node_off);
                const case = tree.fullSwitchCase(case_node).?;
                const start_tok = case.payload_token.?;
                const token_tags = tree.tokens.items(.tag);
                const end_tok = switch (token_tags[start_tok]) {
                    .asterisk => start_tok + 1,
                    else => start_tok,
                };
                const start = tree.tokens.items(.start)[start_tok];
                const end_start = tree.tokens.items(.start)[end_tok];
                const end = end_start + @as(u32, @intCast(tree.tokenSlice(end_tok).len));
                return Span{ .start = start, .end = end, .main = start };
            },
            .node_offset_fn_type_align => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, node).?;
                return nodeToSpan(tree, full.ast.align_expr);
            },
            .node_offset_fn_type_addrspace => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, node).?;
                return nodeToSpan(tree, full.ast.addrspace_expr);
            },
            .node_offset_fn_type_section => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, node).?;
                return nodeToSpan(tree, full.ast.section_expr);
            },
            .node_offset_fn_type_cc => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, node).?;
                return nodeToSpan(tree, full.ast.callconv_expr);
            },

            .node_offset_fn_type_ret_ty => |node_off| {
                const tree = src_loc.handle.tree;
                const node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, node).?;
                return nodeToSpan(tree, full.ast.return_type);
            },
            .node_offset_param => |node_off| {
                const tree = src_loc.handle.tree;
                const token_tags = tree.tokens.items(.tag);
                const node = src_loc.declRelativeToNodeIndex(node_off);

                var first_tok = tree.firstToken(node);
                while (true) switch (token_tags[first_tok - 1]) {
                    .colon, .identifier, .keyword_comptime, .keyword_noalias => first_tok -= 1,
                    else => break,
                };
                return tokensToSpan(
                    tree,
                    first_tok,
                    tree.lastToken(node),
                    first_tok,
                );
            },
            .token_offset_param => |token_off| {
                const tree = src_loc.handle.tree;
                const token_tags = tree.tokens.items(.tag);
                const main_token = tree.nodes.items(.main_token)[src_loc.parent_decl_node];
                const tok_index = @as(Ast.TokenIndex, @bitCast(token_off + @as(i32, @bitCast(main_token))));

                var first_tok = tok_index;
                while (true) switch (token_tags[first_tok - 1]) {
                    .colon, .identifier, .keyword_comptime, .keyword_noalias => first_tok -= 1,
                    else => break,
                };
                return tokensToSpan(
                    tree,
                    first_tok,
                    tok_index,
                    first_tok,
                );
            },

            .node_offset_anyframe_type => |node_off| {
                const tree = src_loc.handle.tree;
                const node_datas = tree.nodes.items(.data);
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);
                return nodeToSpan(tree, node_datas[parent_node].rhs);
            },

            .node_offset_lib_name => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);
                var buf: [1]Ast.Node.Index = undefined;
                const full = tree.fullFnProto(&buf, parent_node).?;
                const tok_index = full.lib_name.?;
                const start = tree.tokens.items(.start)[tok_index];
                const end = start + @as(u32, @intCast(tree.tokenSlice(tok_index).len));
                return Span{ .start = start, .end = end, .main = start };
            },

            .node_offset_array_type_len => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullArrayType(parent_node).?;
                return nodeToSpan(tree, full.ast.elem_count);
            },
            .node_offset_array_type_sentinel => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullArrayType(parent_node).?;
                return nodeToSpan(tree, full.ast.sentinel);
            },
            .node_offset_array_type_elem => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullArrayType(parent_node).?;
                return nodeToSpan(tree, full.ast.elem_type);
            },
            .node_offset_un_op => |node_off| {
                const tree = src_loc.handle.tree;
                const node_datas = tree.nodes.items(.data);
                const node = src_loc.declRelativeToNodeIndex(node_off);

                return nodeToSpan(tree, node_datas[node].lhs);
            },
            .node_offset_ptr_elem => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.child_type);
            },
            .node_offset_ptr_sentinel => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.sentinel);
            },
            .node_offset_ptr_align => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.align_node);
            },
            .node_offset_ptr_addrspace => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.addrspace_node);
            },
            .node_offset_ptr_bitoffset => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.bit_range_start);
            },
            .node_offset_ptr_hostsize => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full = tree.fullPtrType(parent_node).?;
                return nodeToSpan(tree, full.ast.bit_range_end);
            },
            .node_offset_container_tag => |node_off| {
                const tree = src_loc.handle.tree;
                const node_tags = tree.nodes.items(.tag);
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                switch (node_tags[parent_node]) {
                    .container_decl_arg, .container_decl_arg_trailing => {
                        const full = tree.containerDeclArg(parent_node);
                        return nodeToSpan(tree, full.ast.arg);
                    },
                    .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => {
                        const full = tree.taggedUnionEnumTag(parent_node);

                        return tokensToSpan(
                            tree,
                            tree.firstToken(full.ast.arg) - 2,
                            tree.lastToken(full.ast.arg) + 1,
                            tree.nodes.items(.main_token)[full.ast.arg],
                        );
                    },
                    else => unreachable,
                }
            },
            .node_offset_field_default => |node_off| {
                const tree = src_loc.handle.tree;
                const node_tags = tree.nodes.items(.tag);
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                const full: Ast.full.ContainerField = switch (node_tags[parent_node]) {
                    .container_field => tree.containerField(parent_node),
                    .container_field_init => tree.containerFieldInit(parent_node),
                    else => unreachable,
                };
                return nodeToSpan(tree, full.ast.value_expr);
            },
            .node_offset_init_ty => |node_off| {
                const tree = src_loc.handle.tree;
                const parent_node = src_loc.declRelativeToNodeIndex(node_off);

                var buf: [2]Ast.Node.Index = undefined;
                const full = tree.fullArrayInit(&buf, parent_node).?;
                return nodeToSpan(tree, full.ast.type_expr);
            },
            .node_offset_store_ptr => |node_off| {
                const tree = src_loc.handle.tree;
                const node_tags = tree.nodes.items(.tag);
                const node_datas = tree.nodes.items(.data);
                const node = src_loc.declRelativeToNodeIndex(node_off);

                switch (node_tags[node]) {
                    .assign => {
                        return nodeToSpan(tree, node_datas[node].lhs);
                    },
                    else => return nodeToSpan(tree, node),
                }
            },
            .node_offset_store_operand => |node_off| {
                const tree = src_loc.handle.tree;
                const node_tags = tree.nodes.items(.tag);
                const node_datas = tree.nodes.items(.data);
                const node = src_loc.declRelativeToNodeIndex(node_off);

                switch (node_tags[node]) {
                    .assign => {
                        return nodeToSpan(tree, node_datas[node].rhs);
                    },
                    else => return nodeToSpan(tree, node),
                }
            },
        }
    }

    pub fn byteOffsetBuiltinCallArg(
        src_loc: SrcLoc,
        node_off: i32,
        arg_index: u32,
    ) Span {
        const tree = src_loc.handle.tree;
        const node_datas = tree.nodes.items(.data);
        const node_tags = tree.nodes.items(.tag);
        const node = src_loc.declRelativeToNodeIndex(node_off);
        const param = switch (node_tags[node]) {
            .builtin_call_two, .builtin_call_two_comma => switch (arg_index) {
                0 => node_datas[node].lhs,
                1 => node_datas[node].rhs,
                else => unreachable,
            },
            .builtin_call, .builtin_call_comma => tree.extra_data[node_datas[node].lhs + arg_index],
            else => unreachable,
        };
        return nodeToSpan(tree, param);
    }

    pub fn nodeToSpan(tree: Ast, node: u32) Span {
        return tokensToSpan(
            tree,
            tree.firstToken(node),
            tree.lastToken(node),
            tree.nodes.items(.main_token)[node],
        );
    }

    fn tokensToSpan(tree: Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, main: Ast.TokenIndex) Span {
        const token_starts = tree.tokens.items(.start);
        var start_tok = start;
        var end_tok = end;

        if (tree.tokensOnSameLine(start, end)) {
            // do nothing
        } else if (tree.tokensOnSameLine(start, main)) {
            end_tok = main;
        } else if (tree.tokensOnSameLine(main, end)) {
            start_tok = main;
        } else {
            start_tok = main;
            end_tok = main;
        }
        const start_off = token_starts[start_tok];
        const end_off = token_starts[end_tok] + @as(u32, @intCast(tree.tokenSlice(end_tok).len));
        return Span{ .start = start_off, .end = end_off, .main = token_starts[main] };
    }
};

/// Resolving a source location into a byte offset may require doing work
/// that we would rather not do unless the error actually occurs.
/// Therefore we need a data structure that contains the information necessary
/// to lazily produce a `SrcLoc` as required.
/// Most of the offsets in this data structure are relative to the containing Decl.
/// This makes the source location resolve properly even when a Decl gets
/// shifted up or down in the file, as long as the Decl's contents itself
/// do not change.
pub const LazySrcLoc = union(enum) {
    /// When this tag is set, the code that constructed this `LazySrcLoc` is asserting
    /// that all code paths which would need to resolve the source location are
    /// unreachable. If you are debugging this tag incorrectly being this value,
    /// look into using reverse-continue with a memory watchpoint to see where the
    /// value is being set to this tag.
    unneeded,
    /// Means the source location points to an entire file; not any particular
    /// location within the file. `file_scope` union field will be active.
    entire_file,
    /// The source location points to a byte offset within a source file,
    /// offset from 0. The source file is determined contextually.
    /// Inside a `SrcLoc`, the `file_scope` union field will be active.
    byte_abs: u32,
    /// The source location points to a token within a source file,
    /// offset from 0. The source file is determined contextually.
    /// Inside a `SrcLoc`, the `file_scope` union field will be active.
    token_abs: u32,
    /// The source location points to an AST node within a source file,
    /// offset from 0. The source file is determined contextually.
    /// Inside a `SrcLoc`, the `file_scope` union field will be active.
    node_abs: u32,
    /// The source location points to a byte offset within a source file,
    /// offset from the byte offset of the Decl within the file.
    /// The Decl is determined contextually.
    byte_offset: u32,
    /// This data is the offset into the token list from the Decl token.
    /// The Decl is determined contextually.
    token_offset: u32,
    /// The source location points to an AST node, which is this value offset
    /// from its containing Decl node AST index.
    /// The Decl is determined contextually.
    node_offset: i32,
    /// The source location points to the main token of an AST node, found
    /// by taking this AST node index offset from the containing Decl AST node.
    /// The Decl is determined contextually.
    node_offset_main_token: i32,
    /// The source location points to the beginning of a struct initializer.
    /// The Decl is determined contextually.
    node_offset_initializer: i32,
    /// The source location points to a variable declaration type expression,
    /// found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a variable declaration AST node. Next, navigate
    /// to the type expression.
    /// The Decl is determined contextually.
    node_offset_var_decl_ty: i32,
    /// The source location points to the alignment expression of a var decl.
    /// The Decl is determined contextually.
    node_offset_var_decl_align: i32,
    /// The source location points to the linksection expression of a var decl.
    /// The Decl is determined contextually.
    node_offset_var_decl_section: i32,
    /// The source location points to the addrspace expression of a var decl.
    /// The Decl is determined contextually.
    node_offset_var_decl_addrspace: i32,
    /// The source location points to the initializer of a var decl.
    /// The Decl is determined contextually.
    node_offset_var_decl_init: i32,
    /// The source location points to the first parameter of a builtin
    /// function call, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a builtin call AST node. Next, navigate
    /// to the first parameter.
    /// The Decl is determined contextually.
    node_offset_builtin_call_arg0: i32,
    /// Same as `node_offset_builtin_call_arg0` except arg index 1.
    node_offset_builtin_call_arg1: i32,
    node_offset_builtin_call_arg2: i32,
    node_offset_builtin_call_arg3: i32,
    node_offset_builtin_call_arg4: i32,
    node_offset_builtin_call_arg5: i32,
    /// The source location points to the index expression of an array access
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to an array access AST node. Next, navigate
    /// to the index expression.
    /// The Decl is determined contextually.
    node_offset_array_access_index: i32,
    /// The source location points to the LHS of a slice expression
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a slice AST node. Next, navigate
    /// to the sentinel expression.
    /// The Decl is determined contextually.
    node_offset_slice_ptr: i32,
    /// The source location points to start expression of a slice expression
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a slice AST node. Next, navigate
    /// to the sentinel expression.
    /// The Decl is determined contextually.
    node_offset_slice_start: i32,
    /// The source location points to the end expression of a slice
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a slice AST node. Next, navigate
    /// to the sentinel expression.
    /// The Decl is determined contextually.
    node_offset_slice_end: i32,
    /// The source location points to the sentinel expression of a slice
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a slice AST node. Next, navigate
    /// to the sentinel expression.
    /// The Decl is determined contextually.
    node_offset_slice_sentinel: i32,
    /// The source location points to the callee expression of a function
    /// call expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function call AST node. Next, navigate
    /// to the callee expression.
    /// The Decl is determined contextually.
    node_offset_call_func: i32,
    /// The payload is offset from the containing Decl AST node.
    /// The source location points to the field name of:
    ///  * a field access expression (`a.b`), or
    ///  * the operand ("b" node) of a field initialization expression (`.a = b`)
    /// The Decl is determined contextually.
    node_offset_field_name: i32,
    /// The source location points to the pointer of a pointer deref expression,
    /// found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a pointer deref AST node. Next, navigate
    /// to the pointer expression.
    /// The Decl is determined contextually.
    node_offset_deref_ptr: i32,
    /// The source location points to the assembly source code of an inline assembly
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to inline assembly AST node. Next, navigate
    /// to the asm template source code.
    /// The Decl is determined contextually.
    node_offset_asm_source: i32,
    /// The source location points to the return type of an inline assembly
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to inline assembly AST node. Next, navigate
    /// to the return type expression.
    /// The Decl is determined contextually.
    node_offset_asm_ret_ty: i32,
    /// The source location points to the condition expression of an if
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to an if expression AST node. Next, navigate
    /// to the condition expression.
    /// The Decl is determined contextually.
    node_offset_if_cond: i32,
    /// The source location points to a binary expression, such as `a + b`, found
    /// by taking this AST node index offset from the containing Decl AST node.
    /// The Decl is determined contextually.
    node_offset_bin_op: i32,
    /// The source location points to the LHS of a binary expression, found
    /// by taking this AST node index offset from the containing Decl AST node,
    /// which points to a binary expression AST node. Next, navigate to the LHS.
    /// The Decl is determined contextually.
    node_offset_bin_lhs: i32,
    /// The source location points to the RHS of a binary expression, found
    /// by taking this AST node index offset from the containing Decl AST node,
    /// which points to a binary expression AST node. Next, navigate to the RHS.
    /// The Decl is determined contextually.
    node_offset_bin_rhs: i32,
    /// The source location points to the operand of a switch expression, found
    /// by taking this AST node index offset from the containing Decl AST node,
    /// which points to a switch expression AST node. Next, navigate to the operand.
    /// The Decl is determined contextually.
    node_offset_switch_operand: i32,
    /// The source location points to the else/`_` prong of a switch expression, found
    /// by taking this AST node index offset from the containing Decl AST node,
    /// which points to a switch expression AST node. Next, navigate to the else/`_` prong.
    /// The Decl is determined contextually.
    node_offset_switch_special_prong: i32,
    /// The source location points to all the ranges of a switch expression, found
    /// by taking this AST node index offset from the containing Decl AST node,
    /// which points to a switch expression AST node. Next, navigate to any of the
    /// range nodes. The error applies to all of them.
    /// The Decl is determined contextually.
    node_offset_switch_range: i32,
    /// The source location points to the capture of a switch_prong.
    /// The Decl is determined contextually.
    node_offset_switch_prong_capture: i32,
    /// The source location points to the align expr of a function type
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function type AST node. Next, navigate to
    /// the calling convention node.
    /// The Decl is determined contextually.
    node_offset_fn_type_align: i32,
    /// The source location points to the addrspace expr of a function type
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function type AST node. Next, navigate to
    /// the calling convention node.
    /// The Decl is determined contextually.
    node_offset_fn_type_addrspace: i32,
    /// The source location points to the linksection expr of a function type
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function type AST node. Next, navigate to
    /// the calling convention node.
    /// The Decl is determined contextually.
    node_offset_fn_type_section: i32,
    /// The source location points to the calling convention of a function type
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function type AST node. Next, navigate to
    /// the calling convention node.
    /// The Decl is determined contextually.
    node_offset_fn_type_cc: i32,
    /// The source location points to the return type of a function type
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function type AST node. Next, navigate to
    /// the return type node.
    /// The Decl is determined contextually.
    node_offset_fn_type_ret_ty: i32,
    node_offset_param: i32,
    token_offset_param: i32,
    /// The source location points to the type expression of an `anyframe->T`
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to a `anyframe->T` expression AST node. Next, navigate
    /// to the type expression.
    /// The Decl is determined contextually.
    node_offset_anyframe_type: i32,
    /// The source location points to the string literal of `extern "foo"`, found
    /// by taking this AST node index offset from the containing
    /// Decl AST node, which points to a function prototype or variable declaration
    /// expression AST node. Next, navigate to the string literal of the `extern "foo"`.
    /// The Decl is determined contextually.
    node_offset_lib_name: i32,
    /// The source location points to the len expression of an `[N:S]T`
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to an `[N:S]T` expression AST node. Next, navigate
    /// to the len expression.
    /// The Decl is determined contextually.
    node_offset_array_type_len: i32,
    /// The source location points to the sentinel expression of an `[N:S]T`
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to an `[N:S]T` expression AST node. Next, navigate
    /// to the sentinel expression.
    /// The Decl is determined contextually.
    node_offset_array_type_sentinel: i32,
    /// The source location points to the elem expression of an `[N:S]T`
    /// expression, found by taking this AST node index offset from the containing
    /// Decl AST node, which points to an `[N:S]T` expression AST node. Next, navigate
    /// to the elem expression.
    /// The Decl is determined contextually.
    node_offset_array_type_elem: i32,
    /// The source location points to the operand of an unary expression.
    /// The Decl is determined contextually.
    node_offset_un_op: i32,
    /// The source location points to the elem type of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_elem: i32,
    /// The source location points to the sentinel of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_sentinel: i32,
    /// The source location points to the align expr of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_align: i32,
    /// The source location points to the addrspace expr of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_addrspace: i32,
    /// The source location points to the bit-offset of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_bitoffset: i32,
    /// The source location points to the host size of a pointer.
    /// The Decl is determined contextually.
    node_offset_ptr_hostsize: i32,
    /// The source location points to the tag type of an union or an enum.
    /// The Decl is determined contextually.
    node_offset_container_tag: i32,
    /// The source location points to the default value of a field.
    /// The Decl is determined contextually.
    node_offset_field_default: i32,
    /// The source location points to the type of an array or struct initializer.
    /// The Decl is determined contextually.
    node_offset_init_ty: i32,
    /// The source location points to the LHS of an assignment.
    /// The Decl is determined contextually.
    node_offset_store_ptr: i32,
    /// The source location points to the RHS of an assignment.
    /// The Decl is determined contextually.
    node_offset_store_operand: i32,
    /// The source location points to a for loop input.
    /// The Decl is determined contextually.
    for_input: struct {
        /// Points to the for loop AST node.
        for_node_offset: i32,
        /// Picks one of the inputs from the condition.
        input_index: u32,
    },
    /// The source location points to one of the captures of a for loop, found
    /// by taking this AST node index offset from the containing
    /// Decl AST node, which points to one of the input nodes of a for loop.
    /// Next, navigate to the corresponding capture.
    /// The Decl is determined contextually.
    for_capture_from_input: i32,

    pub fn nodeOffset(node_offset: i32) LazySrcLoc {
        return .{ .node_offset = node_offset };
    }

    pub fn toSrcLoc(lazy: LazySrcLoc, handle: *Handle, src_node: Ast.Node.Index) SrcLoc {
        return switch (lazy) {
            .unneeded,
            .entire_file,
            .byte_abs,
            .token_abs,
            .node_abs,
            => .{
                .handle = handle,
                .parent_decl_node = 0,
                .lazy = lazy,
            },

            .byte_offset,
            .token_offset,
            .node_offset,
            .node_offset_main_token,
            .node_offset_initializer,
            .node_offset_var_decl_ty,
            .node_offset_var_decl_align,
            .node_offset_var_decl_section,
            .node_offset_var_decl_addrspace,
            .node_offset_var_decl_init,
            .node_offset_builtin_call_arg0,
            .node_offset_builtin_call_arg1,
            .node_offset_builtin_call_arg2,
            .node_offset_builtin_call_arg3,
            .node_offset_builtin_call_arg4,
            .node_offset_builtin_call_arg5,
            .node_offset_array_access_index,
            .node_offset_slice_ptr,
            .node_offset_slice_start,
            .node_offset_slice_end,
            .node_offset_slice_sentinel,
            .node_offset_call_func,
            .node_offset_field_name,
            .node_offset_deref_ptr,
            .node_offset_asm_source,
            .node_offset_asm_ret_ty,
            .node_offset_if_cond,
            .node_offset_bin_op,
            .node_offset_bin_lhs,
            .node_offset_bin_rhs,
            .node_offset_switch_operand,
            .node_offset_switch_special_prong,
            .node_offset_switch_range,
            .node_offset_switch_prong_capture,
            .node_offset_fn_type_align,
            .node_offset_fn_type_addrspace,
            .node_offset_fn_type_section,
            .node_offset_fn_type_cc,
            .node_offset_fn_type_ret_ty,
            .node_offset_param,
            .token_offset_param,
            .node_offset_anyframe_type,
            .node_offset_lib_name,
            .node_offset_array_type_len,
            .node_offset_array_type_sentinel,
            .node_offset_array_type_elem,
            .node_offset_un_op,
            .node_offset_ptr_elem,
            .node_offset_ptr_sentinel,
            .node_offset_ptr_align,
            .node_offset_ptr_addrspace,
            .node_offset_ptr_bitoffset,
            .node_offset_ptr_hostsize,
            .node_offset_container_tag,
            .node_offset_field_default,
            .node_offset_init_ty,
            .node_offset_store_ptr,
            .node_offset_store_operand,
            .for_input,
            .for_capture_from_input,
            => .{
                .handle = handle,
                .parent_decl_node = src_node,
                .lazy = lazy,
            },
        };
    }
};
