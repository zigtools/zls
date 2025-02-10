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
    const fn_node_handle = func_type.dynamic.data.other; // this assumes that function types can only be Ast nodes
    const fn_node = fn_node_handle.node;
    const fn_handle = fn_node_handle.handle;
    const tree = fn_handle.tree;
    var buffer: [1]Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&buffer, fn_node).?;

    const label = Analyser.getFunctionSignature(tree, proto);
    const proto_comments = try Analyser.getDocComments(arena, tree, fn_node);

    const arg_idx = if (skip_self_param) blk: {
        const has_self_param = try analyser.hasSelfParam(func_type);
        break :blk commas + @intFromBool(has_self_param);
    } else commas;

    var params: std.ArrayListUnmanaged(types.ParameterInformation) = .empty;
    var param_it = proto.iterate(&tree);
    while (ast.nextFnParam(&param_it)) |param| {
        const param_comments = if (param.first_doc_comment) |dc|
            try Analyser.collectDocComments(arena, tree, dc, false)
        else
            null;

        try params.append(arena, .{
            .label = .{ .string = ast.paramSlice(tree, param, false) },
            .documentation = if (param_comments) |comment| .{ .MarkupContent = .{
                .kind = markup_kind,
                .value = comment,
            } } else null,
        });
    }
    return types.SignatureInformation{
        .label = label,
        .documentation = if (proto_comments) |comment| .{ .MarkupContent = .{
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
    const innermost_block = Analyser.innermostBlockScope(document_scope, absolute_index);
    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);

    // Use the innermost scope to determine the earliest token we would need
    //   to scan up to find a function or builtin call
    const first_token = tree.firstToken(innermost_block);
    // We start by finding the token that includes the current cursor position
    const last_token = blk: {
        const last_token = offsets.sourceIndexToTokenIndex(tree, absolute_index);
        switch (token_tags[last_token]) {
            .l_brace, .l_paren, .l_bracket => break :blk last_token,
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
    var symbol_stack: std.ArrayListUnmanaged(StackSymbol) = try .initCapacity(arena, 8);
    var curr_commas: u32 = 0;
    var comma_stack: std.ArrayListUnmanaged(u32) = try .initCapacity(arena, 4);
    var curr_token = last_token;
    while (curr_token >= first_token and curr_token != 0) : (curr_token -= 1) {
        switch (token_tags[curr_token]) {
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
                if (token_tags[expr_last_token] == .builtin) {
                    // Builtin token, find the builtin and construct signature information.
                    const builtin = data.builtins.get(tree.tokenSlice(expr_last_token)) orelse return null;
                    const param_infos = try arena.alloc(
                        types.ParameterInformation,
                        builtin.arguments.len,
                    );
                    for (param_infos, builtin.arguments) |*info, argument| {
                        info.* = .{
                            .label = .{ .string = argument },
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
                        .in_bracket => |*count| if (token_tags[i] == .r_bracket) {
                            count.* += 1;
                        } else if (token_tags[i] == .l_bracket) {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .in_paren => |*count| if (token_tags[i] == .r_paren) {
                            count.* += 1;
                        } else if (token_tags[i] == .l_paren) {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .any => switch (token_tags[i]) {
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

                var ty = switch (tree.tokens.items(.tag)[expr_first_token]) {
                    .period => blk: { // decl literal
                        loc.start += 1;
                        const decl = try analyser.getSymbolEnumLiteral(
                            arena,
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

                const skip_self_param = !ty.isTypeVal(analyser);
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
