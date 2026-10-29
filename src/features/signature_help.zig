//! Implementation of [`textDocument/signatureHelp`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_signatureHelp)

const std = @import("std");
const Ast = @import("zirp").Ast;
const Token = Ast.Token;

const Analyser = @import("../analysis.zig");
const DocumentStore = @import("../DocumentStore.zig");
const types = @import("lsp").types;
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");

const data = @import("version_data");

pub const Error = Analyser.Error || error{InvalidParams};

pub fn @"textDocument/signatureHelp"(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.SignatureHelp.Params,
) Error!?types.SignatureHelp {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);

    const markup_kind: types.MarkupKind = if (server.client_capabilities.signature_help_supports_md) .markdown else .plaintext;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    const signature_info = try getSignatureInfo(
        &analyser,
        arena,
        handle,
        source_index,
        markup_kind,
    ) orelse return null;

    var signatures = try arena.alloc(types.SignatureHelp.Signature, 1);
    signatures[0] = signature_info;

    return .{
        .signatures = signatures,
        .activeSignature = 0,
        .activeParameter = signature_info.activeParameter,
    };
}

fn fnProtoToSignatureInfo(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    commas: u32,
    container_ty: ?Analyser.Type,
    func_type: Analyser.Type,
    markup_kind: types.MarkupKind,
) error{OutOfMemory}!types.SignatureHelp.Signature {
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

    const arg_idx = if (container_ty) |expected_type| blk: {
        const has_self_param = analyser.firstParamIs(func_type, expected_type);
        break :blk commas + @intFromBool(has_self_param);
    } else commas;

    var params: std.ArrayList(types.SignatureHelp.Signature.Parameter) = .empty;
    for (info.parameters) |param| {
        const param_label = try analyser.stringifyParameter(.{
            .info = param,
            .include_modifier = true,
            .include_name = true,
            .include_type = true,
        });

        try params.append(arena, .{
            .label = .{ .string = param_label },
            .documentation = if (param.doc_comments) |comment| .{ .markup_content = .{
                .kind = markup_kind,
                .value = comment,
            } } else null,
        });
    }
    return types.SignatureHelp.Signature{
        .label = label,
        .documentation = if (info.doc_comments) |comment| .{ .markup_content = .{
            .kind = markup_kind,
            .value = comment,
        } } else null,
        .parameters = params.items,
        .activeParameter = if (arg_idx < params.items.len) arg_idx else null,
    };
}

fn getSignatureInfo(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    absolute_index: usize,
    markup_kind: types.MarkupKind,
) Analyser.Error!?types.SignatureHelp.Signature {
    const document_scope = try handle.getDocumentScope();
    const innermost_block_scope = Analyser.innermostScopeAtIndexWithTag(document_scope, absolute_index, .init(.{
        .block = true,
        .container = true,
        .function = true,
        .other = false,
    })).unwrap().?;
    const innermost_block = document_scope.getScopeAstNode(innermost_block_scope).?;
    const tree = &handle.tree;

    // Use the innermost scope to determine the earliest token we would need
    //   to scan up to find a function or builtin call
    const first_token = innermost_block.firstToken(tree);
    // We start by finding the token that includes the current cursor position
    const last_token = blk: {
        const last_token = offsets.sourceIndexToTokenIndex(tree, absolute_index).preferRight(tree);
        // Determine whether index is after the token
        const passed = last_token.byteOffset(tree) < absolute_index;
        switch (last_token.tag(tree)) {
            .@"{", .@"(", .@"[" => break :blk last_token,
            .@"," => break :blk if (passed) last_token else last_token.addClamp(-1),
            else => break :blk last_token.addClamp(-1),
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
        @"(",
        @")",
        @"{",
        @"}",
        @"[",
        @"]",

        fn from(tag: Token.Tag) @This() {
            return switch (tag) {
                .@"(" => .@"(",
                .@")" => .@")",
                .@"{" => .@"{",
                .@"}" => .@"}",
                .@"[" => .@"[",
                .@"]" => .@"]",
                else => unreachable,
            };
        }
    };
    var symbol_stack: std.ArrayList(StackSymbol) = try .initCapacity(arena, 8);
    var curr_commas: u32 = 0;
    var comma_stack: std.ArrayList(u32) = try .initCapacity(arena, 4);
    var curr_token = last_token;
    while (@backingInt(curr_token) >= @backingInt(first_token) and @backingInt(curr_token) != 0) : (curr_token = curr_token.add(-1)) {
        switch (curr_token.tag(tree)) {
            .@"," => curr_commas += 1,
            .@"{" => {
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .@"}" => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .@"]", .@")" => {
                            return null;
                        },
                        else => {},
                    }
                }
                try symbol_stack.append(arena, .@"{");
            },
            .@"[" => {
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .@"]" => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .@"}", .@")" => {
                            return null;
                        },
                        else => {},
                    }
                }
                try symbol_stack.append(arena, .@"[");
            },
            .@"(" => {
                const paren_commas = curr_commas;
                curr_commas = comma_stack.pop() orelse 0;
                if (symbol_stack.items.len != 0) {
                    const peek_sym = symbol_stack.items[symbol_stack.items.len - 1];
                    switch (peek_sym) {
                        .@")" => {
                            _ = symbol_stack.pop();
                            continue;
                        },
                        .@"}", .@"]" => {
                            return null;
                        },
                        else => {},
                    }
                }

                // Try to find a function expression or a builtin identifier
                if (curr_token == first_token)
                    return null;

                const expr_last_token = curr_token.add(-1);
                if (expr_last_token.tag(tree) == .name_builtin) {
                    const builtin_name = expr_last_token.slice(tree);
                    const builtin = data.builtins.get(builtin_name) orelse return null;

                    const param_infos = try arena.alloc(types.SignatureHelp.Signature.Parameter, builtin.parameters.len);
                    for (param_infos, builtin.parameters) |*info, parameter| {
                        info.* = .{
                            .label = .{ .string = parameter.signature },
                            .documentation = if (parameter.documentation) |doc|
                                .{ .markup_content = .{ .kind = markup_kind, .value = doc } }
                            else
                                null,
                        };
                    }
                    return types.SignatureHelp.Signature{
                        .label = try Analyser.renderBuiltinFunctionSignature(
                            arena,
                            builtin_name,
                            builtin,
                            false,
                        ),
                        .documentation = .{ .markup_content = .{
                            .kind = markup_kind,
                            .value = builtin.documentation,
                        } },
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
                const expr_first_token = while (@backingInt(i) > @backingInt(first_token)) : (i = i.add(-1)) {
                    switch (state) {
                        .in_bracket => |*count| if (i.tag(tree) == .@"]") {
                            count.* += 1;
                        } else if (i.tag(tree) == .@"[") {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .in_paren => |*count| if (i.tag(tree) == .@")") {
                            count.* += 1;
                        } else if (i.tag(tree) == .@"(") {
                            count.* -= 1;
                            if (count.* == 0)
                                state = .any;
                        },
                        .any => switch (i.tag(tree)) {
                            .@"]" => state = .{ .in_bracket = 1 },
                            .@")" => state = .{ .in_paren = 1 },
                            .name,
                            .@".",
                            .@"?",
                            .@".*",
                            => {},
                            else => break i.add(1),
                        },
                    }
                } else first_token.add(1);
                if (state != .any or @backingInt(expr_first_token) > @backingInt(expr_last_token)) {
                    try symbol_stack.append(arena, .@"(");
                    continue;
                }

                var loc = offsets.tokensToLoc(tree, expr_first_token, expr_last_token);

                var ty = switch (expr_first_token.tag(tree)) {
                    .@"." => blk: { // decl literal
                        loc.start += 1;
                        const decl, const type_maybe = try analyser.getSymbolEnumLiteral(
                            handle,
                            loc.start,
                            offsets.locToSlice(tree.source, loc),
                        ) orelse continue;
                        break :blk type_maybe orelse try decl.resolveType(analyser) orelse continue;
                    },
                    else => try analyser.getFieldAccessType(handle, loc.start, loc) orelse continue,
                };

                if (try analyser.resolveFuncProtoOfCallable(ty)) |func_type| {
                    return try fnProtoToSignatureInfo(
                        analyser,
                        arena,
                        paren_commas,
                        null,
                        func_type,
                        markup_kind,
                    );
                }

                const name_loc = offsets.identifierLocFromIndex(&handle.tree, loc.end - 1) orelse {
                    try symbol_stack.append(arena, .@"(");
                    continue;
                };
                const name = offsets.locToSlice(handle.tree.source, name_loc);

                const container_ty = try ty.typeOf(analyser);
                ty = try analyser.resolveFieldAccess(ty, name) orelse {
                    try symbol_stack.append(arena, .@"(");
                    continue;
                };

                if (try analyser.resolveFuncProtoOfCallable(ty)) |func_type| {
                    return try fnProtoToSignatureInfo(
                        analyser,
                        arena,
                        paren_commas,
                        container_ty,
                        func_type,
                        markup_kind,
                    );
                }
            },
            .@"}", .@")", .@"]" => |tag| {
                try comma_stack.append(arena, curr_commas);
                curr_commas = 0;
                try symbol_stack.append(arena, StackSymbol.from(tag));
            },
            else => {},
        }
    }
    return null;
}
