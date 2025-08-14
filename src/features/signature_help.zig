//! Implementation of [`textDocument/signatureHelp`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_signatureHelp)

const std = @import("std");
const Ast = std.zig.Ast;
const Token = std.zig.Token;

const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");
const types = @import("lsp").types;
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");

const data = @import("version_data");

fn fnProtoToSignatureInfo(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    commas: u32,
    skip_self_param: bool,
    func_type: Analyser.Type,
    markup_kind: types.MarkupKind,
) !types.SignatureInformation {
    const info = func_type.data.function;

    const label = try analyser.stringifyFunction(.{
        .info = info,
        .include_fn_keyword = true,
        .include_name = true,
        .parameters = .{ .show = .{
            .include_modifiers = true,
            .include_names = true,
            .include_types = true,
        } },
        .include_return_type = true,
        .snippet_placeholders = false,
    });

    const arg_idx = if (skip_self_param) blk: {
        const has_self_param = try analyser.hasSelfParam(func_type);
        break :blk commas + @intFromBool(has_self_param);
    } else commas;

    var params: std.ArrayList(types.ParameterInformation) = .empty;
    for (info.parameters) |param| {
        const param_label = try analyser.stringifyParameter(.{
            .info = param,
            .index = 0, // we don't want a comma in the label
            .include_modifier = true,
            .include_name = true,
            .include_type = true,
            .snippet_placeholders = false,
        });

        try params.append(arena, .{
            .label = .{ .string = param_label },
            .documentation = if (param.doc_comments) |comment| .{ .MarkupContent = .{
                .kind = markup_kind,
                .value = comment,
            } } else null,
        });
    }
    return types.SignatureInformation{
        .label = label,
        .documentation = if (info.doc_comments) |comment| .{ .MarkupContent = .{
            .kind = markup_kind,
            .value = comment,
        } } else null,
        .parameters = params.items,
        .activeParameter = if (arg_idx < params.items.len) arg_idx else null,
    };
}

pub fn getSignatureInfo(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    absolute_index: usize,
    markup_kind: types.MarkupKind,
) !?types.SignatureInformation {
    const document_scope = try handle.getDocumentScope();
    const innermost_block_scope = Analyser.innermostScopeAtIndexWithTag(document_scope, absolute_index, .init(.{
        .block = true,
        .container = true,
        .function = true,
        .other = false,
    })).unwrap().?;
    const innermost_block = document_scope.getScopeAstNode(innermost_block_scope).?;
    const tree = handle.tree;

    // Use the innermost scope to determine the earliest token we would need
    //   to scan up to find a function or builtin call
    const first_token = tree.firstToken(innermost_block);
    // We start by finding the token that includes the current cursor position
    const last_token = blk: {
        const last_token = offsets.sourceIndexToTokenIndex(tree, absolute_index).preferRight(&tree);
        // Determine whether index is after the token
        const passed = tree.tokenStart(last_token) < absolute_index;
        switch (tree.tokenTag(last_token)) {
            .l_brace, .l_paren, .l_bracket => break :blk last_token,
            .comma => break :blk if (passed) last_token else last_token -| 1,
            else => break :blk last_token -| 1,
        }
    };

    // We scan the tokens from last to first, adding and removing open and close
    //   delimiter tokens to a stack, while keeping track of commas corresponding
    //   to each of the blocks in a stack.
    // When we encounter a dangling left parenthesis token, we continue scanning
    //   backwards for a compatible possible function call lhs expression or a
    //   single builtin token.
    // When a function call expression is detected, it is resolved to a declaration
    //   or a function type and the resulting function prototype is converted into
    //   a signature information object.
    const StackSymbol = enum {
        l_paren,
        r_paren,
        l_brace,
        r_brace,
        l_bracket,
        r_bracket,

        fn from(tag: Token.Tag) @This() {
            return switch (tag) {
                .l_paren => .l_paren,
                .r_paren => .r_paren,
                .l_brace => .l_brace,
                .r_brace => .r_brace,
                .l_bracket => .l_bracket,
                .r_bracket => .r_bracket,
                else => unreachable,
            };
        }
    };
    var symbol_stack: std.ArrayList(StackSymbol) = try .initCapacity(arena, 8);
    var curr_commas: u32 = 0;
    var comma_stack: std.ArrayList(u32) = try .initCapacity(arena, 4);
    var curr_token = last_token;
    while (curr_token >= first_token and curr_token != 0) : (curr_token -= 1) {
        switch (tree.tokenTag(curr_token)) {
            .comma => curr_commas += 1,
            .l_brace => {
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .r_brace => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .r_bracket, .r_paren => {
                            return null;
                        },
                        else => {},
                    }
                }
                try symbol_stack.append(arena, .l_brace);
            },
            .l_bracket => {
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .r_bracket => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .r_brace, .r_paren => {
                            return null;
                        },
                        else => {},
                    }
                }
                try symbol_stack.append(arena, .l_bracket);
            },
            .l_paren => {
                const paren_commas = curr_commas;
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .r_paren => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .r_brace, .r_bracket => {
                            return null;
                        },
                        else => {},
                    }
                }

                // Try to find a function expression or a builtin identifier
                if (curr_token == first_token)
                    return null;

                const expr_last_token = curr_token - 1;
                if (tree.tokenTag(expr_last_token) == .builtin) {
                    // Builtin token, find the builtin and construct signature information.
                    const builtin = data.builtins.get(tree.tokenSlice(expr_last_token)) orelse return null;
                    const param_infos = try arena.alloc(
                        types.ParameterInformation,
                        builtin.parameters.len,
                    );
                    for (param_infos, builtin.parameters) |*info, parameter| {
                        info.* = .{
                            .label = .{ .string = parameter.signature },
                            .documentation = null,
                        };
                    }
                    return types.SignatureInformation{
                        .label = builtin.signature,
                        .documentation = .{ .string = builtin.documentation },
                        .parameters = param_infos,
                        .activeParameter = paren_commas,
                    };
                }
                // Scan for a function call lhs expression.
                var state: union(enum) {
                    any,
                    in_bracket: u32,
                    in_paren: u32,
                } = .any;
                var i = expr_last_token;
                const expr_first_token = while (i > first_token) : (i -= 1) {
                    switch (state) {
                        .in_bracket => |*count| if (tree.tokenTag(i) == .r_bracket) {
                            count.* += 1;
                        } else if (tree.tokenTag(i) == .l_bracket) {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .in_paren => |*count| if (tree.tokenTag(i) == .r_paren) {
                            count.* += 1;
                        } else if (tree.tokenTag(i) == .l_paren) {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .any => switch (tree.tokenTag(i)) {
                            .r_bracket => state = .{ .in_bracket = 1 },
                            .r_paren => state = .{ .in_paren = 1 },
                            .identifier,
                            .period,
                            .question_mark,
                            .period_asterisk,
                            => {},
                            else => break i + 1,
                        },
                    }
                } else first_token + 1;
                if (state != .any or expr_first_token > expr_last_token) {
                    try symbol_stack.append(arena, .l_paren);
                    continue;
                }

                var loc = offsets.tokensToLoc(tree, expr_first_token, expr_last_token);

                var ty = switch (tree.tokenTag(expr_first_token)) {
                    .period => blk: { // decl literal
                        loc.start += 1;
                        const decl = try analyser.getSymbolEnumLiteral(
                            handle,
                            loc.start,
                            offsets.locToSlice(tree.source, loc),
                        ) orelse continue;
                        break :blk try decl.resolveType(analyser) orelse continue;
                    },
                    else => try analyser.getFieldAccessType(handle, loc.start, loc) orelse continue,
                };

                if (try analyser.resolveFuncProtoOfCallable(ty)) |func_type| {
                    return try fnProtoToSignatureInfo(
                        analyser,
                        arena,
                        paren_commas,
                        false,
                        func_type,
                        markup_kind,
                    );
                }

                const name_loc = Analyser.identifierLocFromIndex(handle.tree, loc.end - 1) orelse {
                    try symbol_stack.append(arena, .l_paren);
                    continue;
                };
                const name = offsets.locToSlice(handle.tree.source, name_loc);

                const skip_self_param = !ty.is_type_val;
                ty = try analyser.resolveFieldAccess(ty, name) orelse {
                    try symbol_stack.append(arena, .l_paren);
                    continue;
                };

                if (try analyser.resolveFuncProtoOfCallable(ty)) |func_type| {
                    return try fnProtoToSignatureInfo(
                        analyser,
                        arena,
                        paren_commas,
                        skip_self_param,
                        func_type,
                        markup_kind,
                    );
                }
            },
            .r_brace, .r_paren, .r_bracket => |tag| {
                try comma_stack.append(arena, curr_commas);
                curr_commas = 0;
                try symbol_stack.append(arena, StackSymbol.from(tag));
            },
            else => {},
        }
    }
    return null;
}
