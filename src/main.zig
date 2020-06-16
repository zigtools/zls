const std = @import("std");
const build_options = @import("build_options");

const Config = @import("config.zig");
const DocumentStore = @import("document_store.zig");
const DebugAllocator = @import("debug_allocator.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;
const data = @import("data/" ++ build_options.data_version ++ ".zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const URI = @import("uri.zig");

// Code is largely based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig
var stdout: std.io.BufferedOutStream(4096, std.fs.File.OutStream) = undefined;
var allocator: *std.mem.Allocator = undefined;

var document_store: DocumentStore = undefined;
var workspace_folder_configs: std.StringHashMap(?Config) = undefined;

const ClientCapabilities = struct {
    supports_snippets: bool = false,
    supports_semantic_tokens: bool = false,
    hover_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
    supports_workspace_folders: bool = false,
};

var client_capabilities = ClientCapabilities{};

const initialize_response =
    \\,"result": {"capabilities": {"signatureHelpProvider": {"triggerCharacters": ["(",","]},"textDocumentSync": 1,"completionProvider": {"resolveProvider": false,"triggerCharacters": [".",":","@"]},"documentHighlightProvider": false,"hoverProvider": true,"codeActionProvider": false,"declarationProvider": true,"definitionProvider": true,"typeDefinitionProvider": true,"implementationProvider": false,"referencesProvider": false,"documentSymbolProvider": true,"colorProvider": false,"documentFormattingProvider": true,"documentRangeFormattingProvider": false,"foldingRangeProvider": false,"selectionRangeProvider": false,"workspaceSymbolProvider": false,"rangeProvider": false,"documentProvider": true,"workspace": {"workspaceFolders": {"supported": true,"changeNotifications": true}},"semanticTokensProvider": {"documentProvider": true,"legend": {"tokenTypes": ["type","struct","enum","union","parameter","variable","tagField","field","function","keyword","modifier","comment","string","number","operator","builtin"],"tokenModifiers": ["definition","async","documentation", "generic"]}}}}}
;

const not_implemented_response =
    \\,"error":{"code":-32601,"message":"NotImplemented"}}
;

const null_result_response =
    \\,"result":null}
;
const empty_result_response =
    \\,"result":{}}
;
const empty_array_response =
    \\,"result":[]}
;
const edit_not_applied_response =
    \\,"result":{"applied":false,"failureReason":"feature not implemented"}}
;
const no_completions_response =
    \\,"result":{"isIncomplete":false,"items":[]}}
;
const no_semantic_tokens_response =
    \\,"result":{"data":[]}}
;

/// Sends a request or response
fn send(reqOrRes: var) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var arr = std.ArrayList(u8).init(&arena.allocator);
    try std.json.stringify(reqOrRes, .{}, arr.outStream());

    const stdout_stream = stdout.outStream();
    try stdout_stream.print("Content-Length: {}\r\n\r\n", .{arr.items.len});
    try stdout_stream.writeAll(arr.items);
    try stdout.flush();
}

fn respondGeneric(id: types.RequestId, response: []const u8) !void {
    const id_len = switch (id) {
        .Integer => |id_val| blk: {
            if (id_val == 0) break :blk 1;
            var digits: usize = 1;
            var value = @divTrunc(id_val, 10);
            while (value != 0) : (value = @divTrunc(value, 10)) {
                digits += 1;
            }
            break :blk digits;
        },
        .String => |str_val| str_val.len + 2,
        else => unreachable,
    };

    // Numbers of character that will be printed from this string: len - 1 brackets
    const json_fmt = "{{\"jsonrpc\":\"2.0\",\"id\":";

    const stdout_stream = stdout.outStream();
    try stdout_stream.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{response.len + id_len + json_fmt.len - 1});
    switch (id) {
        .Integer => |int| try stdout_stream.print("{}", .{int}),
        .String => |str| try stdout_stream.print("\"{}\"", .{str}),
        else => unreachable,
    }

    try stdout_stream.writeAll(response);
    try stdout.flush();
}

fn showMessage(@"type": types.MessageType, message: []const u8) !void {
    try send(types.Notification{
        .method = "window/showMessage",
        .params = .{
            .ShowMessageParams = .{
                .@"type" = @"type",
                .message = message,
            },
        },
    });
}

// TODO: Is this correct or can we get a better end?
fn astLocationToRange(loc: std.zig.ast.Tree.Location) types.Range {
    return .{
        .start = .{
            .line = @intCast(i64, loc.line),
            .character = @intCast(i64, loc.column),
        },
        .end = .{
            .line = @intCast(i64, loc.line),
            .character = @intCast(i64, loc.column),
        },
    };
}

fn publishDiagnostics(handle: DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

    // Use an arena for our local memory allocations.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostics = std.ArrayList(types.Diagnostic).init(&arena.allocator);

    for (tree.errors) |*err| {
        const loc = tree.tokenLocation(0, err.loc());

        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        try tree.renderError(err, fbs.outStream());

        try diagnostics.append(.{
            .range = astLocationToRange(loc),
            .severity = .Error,
            .code = @tagName(err.*),
            .source = "zls",
            .message = try std.mem.dupe(&arena.allocator, u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (tree.errors.len == 0) {
        for (tree.root_node.decls()) |decl| {
            switch (decl.id) {
                .FnProto => blk: {
                    const func = decl.cast(std.zig.ast.Node.FnProto).?;
                    const is_extern = func.extern_export_inline_token != null;
                    if (is_extern)
                        break :blk;

                    if (config.warn_style) {
                        if (func.name_token) |name_token| {
                            const loc = tree.tokenLocation(0, name_token);

                            const is_type_function = analysis.isTypeFunction(tree, func);

                            const func_name = tree.tokenSlice(name_token);
                            if (!is_type_function and !analysis.isCamelCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Information,
                                    .code = "BadStyle",
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Information,
                                    .code = "BadStyle",
                                    .source = "zls",
                                    .message = "Type functions should be PascalCase",
                                });
                            }
                        }
                    }
                },
                else => {},
            }
        }
    }

    try send(types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnosticsParams = .{
                .uri = handle.uri(),
                .diagnostics = diagnostics.items,
            },
        },
    });
}

fn nodeToCompletion(
    arena: *std.heap.ArenaAllocator,
    list: *std.ArrayList(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    orig_handle: *DocumentStore.Handle,
    config: Config,
) error{OutOfMemory}!void {
    const node = node_handle.node;
    const handle = node_handle.handle;

    const doc_kind: types.MarkupKind = if (client_capabilities.completion_doc_supports_md) .Markdown else .PlainText;
    const doc = if (try analysis.getDocComments(
        list.allocator,
        handle.tree,
        node,
        doc_kind,
    )) |doc_comments|
        types.MarkupContent{
            .kind = doc_kind,
            .value = doc_comments,
        }
    else
        null;

    switch (node.id) {
        .ErrorSetDecl, .Root, .ContainerDecl => {
            const context = DeclToCompletionContext{
                .completions = list,
                .config = &config,
                .arena = arena,
                .orig_handle = orig_handle,
            };
            try analysis.iterateSymbolsContainer(&document_store, arena, node_handle, orig_handle, declToCompletion, context, true);
        },
        .FnProto => {
            const func = node.cast(std.zig.ast.Node.FnProto).?;
            if (func.name_token) |name_token| {
                const use_snippets = config.enable_snippets and client_capabilities.supports_snippets;

                const insert_text = if (use_snippets) blk: {
                    const skip_self_param = if (func.params_len > 0) param_check: {
                        const in_container = analysis.innermostContainer(handle, handle.tree.token_locs[func.firstToken()].start);
                        switch (func.paramsConst()[0].param_type) {
                            .type_expr => |type_node| {
                                if (try analysis.resolveTypeOfNode(&document_store, arena, .{
                                    .node = type_node,
                                    .handle = handle,
                                })) |resolved_type| {
                                    if (in_container.node == resolved_type.node)
                                        break :param_check true;
                                }

                                if (type_node.cast(std.zig.ast.Node.PrefixOp)) |prefix_op| {
                                    if (prefix_op.op == .PtrType) {
                                        if (try analysis.resolveTypeOfNode(&document_store, arena, .{
                                            .node = prefix_op.rhs,
                                            .handle = handle,
                                        })) |resolved_prefix_op| {
                                            if (in_container.node == resolved_prefix_op.node)
                                                break :param_check true;
                                        }
                                    }
                                }

                                break :param_check false;
                            },
                            else => break :param_check false,
                        }
                    } else
                        false;

                    break :blk try analysis.getFunctionSnippet(&arena.allocator, handle.tree, func, skip_self_param);
                } else
                    null;

                const is_type_function = analysis.isTypeFunction(handle.tree, func);

                try list.append(.{
                    .label = handle.tree.tokenSlice(name_token),
                    .kind = if (is_type_function) .Struct else .Function,
                    .documentation = doc,
                    .detail = analysis.getFunctionSignature(handle.tree, func),
                    .insertText = insert_text,
                    .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
                });
            }
        },
        .VarDecl => {
            const var_decl = node.cast(std.zig.ast.Node.VarDecl).?;
            const is_const = handle.tree.token_ids[var_decl.mut_token] == .Keyword_const;

            if (try analysis.resolveVarDeclAlias(&document_store, arena, node_handle)) |result| {
                const context = DeclToCompletionContext{
                    .completions = list,
                    .config = &config,
                    .arena = arena,
                    .orig_handle = orig_handle,
                };
                return try declToCompletion(context, result);
            }

            try list.append(.{
                .label = handle.tree.tokenSlice(var_decl.name_token),
                .kind = if (is_const) .Constant else .Variable,
                .documentation = doc,
                .detail = analysis.getVariableSignature(handle.tree, var_decl),
            });
        },
        .ContainerField => {
            const field = node.cast(std.zig.ast.Node.ContainerField).?;
            try list.append(.{
                .label = handle.tree.tokenSlice(field.name_token),
                .kind = .Field,
                .documentation = doc,
                .detail = analysis.getContainerFieldSignature(handle.tree, field),
            });
        },
        .PrefixOp => {
            const prefix_op = node.cast(std.zig.ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .ArrayType, .SliceType => {},
                .PtrType => {
                    if (prefix_op.rhs.cast(std.zig.ast.Node.PrefixOp)) |child_pop| {
                        switch (child_pop.op) {
                            .ArrayType => {},
                            else => return,
                        }
                    } else return;
                },
                else => return,
            }

            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
            try list.append(.{
                .label = "ptr",
                .kind = .Field,
            });
        },
        .StringLiteral => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
        },
        else => if (analysis.nodeToString(handle.tree, node)) |string| {
            try list.append(.{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = handle.tree.getNodeSource(node),
            });
        },
    }
}

fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
    const text = handle.document.text;

    if (pos_index + 1 >= text.len) return &[0]u8{};
    var start_idx = pos_index;

    while (start_idx > 0 and
        (std.ascii.isAlNum(text[start_idx]) or text[start_idx] == '_')) : (start_idx -= 1)
    {}

    var end_idx = pos_index;
    while (end_idx < handle.document.text.len and
        (std.ascii.isAlNum(text[end_idx]) or text[end_idx] == '_')) : (end_idx += 1)
    {}

    if (end_idx <= start_idx) return &[0]u8{};
    return text[start_idx + 1 .. end_idx];
}

fn gotoDefinitionSymbol(id: types.RequestId, arena: *std.heap.ArenaAllocator, decl_handle: analysis.DeclWithHandle, resolve_alias: bool) !void {
    var handle = decl_handle.handle;

    const location = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analysis.resolveVarDeclAlias(&document_store, arena, .{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;
                    break :block result.location();
                }
            }

            const name_token = analysis.getDeclNameToken(handle.tree, node) orelse
                return try respondGeneric(id, null_result_response);
            break :block handle.tree.tokenLocation(0, name_token);
        },
        else => decl_handle.location(),
    };

    try send(types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = handle.document.uri,
                .range = astLocationToRange(location),
            },
        },
    });
}

fn hoverSymbol(id: types.RequestId, arena: *std.heap.ArenaAllocator, decl_handle: analysis.DeclWithHandle) (std.os.WriteError || error{OutOfMemory})!void {
    const handle = decl_handle.handle;

    const hover_kind: types.MarkupKind = if (client_capabilities.hover_supports_md) .Markdown else .PlainText;
    const md_string = switch (decl_handle.decl.*) {
        .ast_node => |node| ast_node: {
            if (try analysis.resolveVarDeclAlias(&document_store, arena, .{ .node = node, .handle = handle })) |result| {
                return try hoverSymbol(id, arena, result);
            }

            const doc_str = if (try analysis.getDocComments(&arena.allocator, handle.tree, node, hover_kind)) |str|
                str
            else
                "";

            const signature_str = switch (node.id) {
                .VarDecl => blk: {
                    const var_decl = node.cast(std.zig.ast.Node.VarDecl).?;
                    break :blk analysis.getVariableSignature(handle.tree, var_decl);
                },
                .FnProto => blk: {
                    const fn_decl = node.cast(std.zig.ast.Node.FnProto).?;
                    break :blk analysis.getFunctionSignature(handle.tree, fn_decl);
                },
                .ContainerField => blk: {
                    const field = node.cast(std.zig.ast.Node.ContainerField).?;
                    break :blk analysis.getContainerFieldSignature(handle.tree, field);
                },
                else => analysis.nodeToString(handle.tree, node) orelse return try respondGeneric(id, null_result_response),
            };

            break :ast_node if (hover_kind == .Markdown)
                try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```\n{}", .{ signature_str, doc_str })
            else
                try std.fmt.allocPrint(&arena.allocator, "{}\n{}", .{ signature_str, doc_str });
        },
        .param_decl => |param| param_decl: {
            const doc_str = if (param.doc_comments) |doc_comments|
                try analysis.collectDocComments(&arena.allocator, handle.tree, doc_comments, hover_kind)
            else
                "";

            const signature_str = handle.tree.source[handle.tree.token_locs[param.firstToken()].start..handle.tree.token_locs[param.lastToken()].end];
            break :param_decl if (hover_kind == .Markdown)
                try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```\n{}", .{ signature_str, doc_str })
            else
                try std.fmt.allocPrint(&arena.allocator, "{}\n{}", .{ signature_str, doc_str });
        },
        .pointer_payload => |payload| if (hover_kind == .Markdown)
            try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```", .{handle.tree.tokenSlice(payload.node.value_symbol.firstToken())})
        else
            try std.fmt.allocPrint(&arena.allocator, "{}", .{handle.tree.tokenSlice(payload.node.value_symbol.firstToken())}),
        .array_payload => |payload| if (hover_kind == .Markdown)
            try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```", .{handle.tree.tokenSlice(payload.identifier.firstToken())})
        else
            try std.fmt.allocPrint(&arena.allocator, "{}", .{handle.tree.tokenSlice(payload.identifier.firstToken())}),
        .switch_payload => |payload| if (hover_kind == .Markdown)
            try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```", .{handle.tree.tokenSlice(payload.node.value_symbol.firstToken())})
        else
            try std.fmt.allocPrint(&arena.allocator, "{}", .{handle.tree.tokenSlice(payload.node.value_symbol.firstToken())}),
        .label_decl => |label_decl| block: {
            const source = handle.tree.source[handle.tree.token_locs[label_decl.firstToken()].start..handle.tree.token_locs[label_decl.lastToken()].end];
            break :block if (hover_kind == .Markdown)
                try std.fmt.allocPrint(&arena.allocator, "```zig\n{}\n```", .{source})
            else
                try std.fmt.allocPrint(&arena.allocator, "```{}```", .{source});
        },
    };

    try send(types.Response{
        .id = id,
        .result = .{
            .Hover = .{
                .contents = .{ .value = md_string },
            },
        },
    });
}

fn getLabelGlobal(pos_index: usize, handle: *DocumentStore.Handle) !?analysis.DeclWithHandle {
    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupLabel(handle, name, pos_index);
}

fn getSymbolGlobal(arena: *std.heap.ArenaAllocator, pos_index: usize, handle: *DocumentStore.Handle) !?analysis.DeclWithHandle {
    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupSymbolGlobal(&document_store, arena, handle, name, pos_index);
}

fn gotoDefinitionLabel(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, &arena, decl, false);
}

fn gotoDefinitionGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config, resolve_alias: bool) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolGlobal(&arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, &arena, decl, resolve_alias);
}

fn hoverDefinitionLabel(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, &arena, decl);
}

fn hoverDefinitionGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolGlobal(&arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, &arena, decl);
}

fn getSymbolFieldAccess(
    handle: *DocumentStore.Handle,
    arena: *std.heap.ArenaAllocator,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
) !?analysis.DeclWithHandle {
    const pos_index = try handle.document.positionToIndex(position);
    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    const line = try handle.document.getLine(@intCast(usize, position.line));
    var tokenizer = std.zig.Tokenizer.init(line[range.start..range.end]);

    if (try analysis.getFieldAccessTypeNode(&document_store, arena, handle, pos_index, &tokenizer)) |container_handle| {
        return try analysis.lookupSymbolContainer(&document_store, arena, container_handle, name, true);
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
    resolve_alias: bool,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolFieldAccess(handle, &arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, &arena, decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolFieldAccess(handle, &arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, &arena, decl);
}

fn gotoDefinitionString(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const import_str = analysis.getImportStr(tree, pos_index) orelse return try respondGeneric(id, null_result_response);
    const uri = (try document_store.uriFromImportStr(
        &arena.allocator,
        handle.*,
        import_str,
    )) orelse return try respondGeneric(id, null_result_response);

    try send(types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = uri,
                .range = .{
                    .start = .{ .line = 0, .character = 0 },
                    .end = .{ .line = 0, .character = 0 },
                },
            },
        },
    });
}

const DeclToCompletionContext = struct {
    completions: *std.ArrayList(types.CompletionItem),
    config: *const Config,
    arena: *std.heap.ArenaAllocator,
    orig_handle: *DocumentStore.Handle,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) !void {
    const tree = decl_handle.handle.tree;

    switch (decl_handle.decl.*) {
        .ast_node => |node| try nodeToCompletion(context.arena, context.completions, .{ .node = node, .handle = decl_handle.handle }, context.orig_handle, context.config.*),
        .param_decl => |param| {
            const doc_kind: types.MarkupKind = if (client_capabilities.completion_doc_supports_md) .Markdown else .PlainText;
            const doc = if (param.doc_comments) |doc_comments|
                types.MarkupContent{
                    .kind = doc_kind,
                    .value = try analysis.collectDocComments(&context.arena.allocator, tree, doc_comments, doc_kind),
                }
            else
                null;

            try context.completions.append(.{
                .label = tree.tokenSlice(param.name_token.?),
                .kind = .Constant,
                .documentation = doc,
                .detail = tree.source[tree.token_locs[param.firstToken()].start..tree.token_locs[param.lastToken()].end],
            });
        },
        .pointer_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.node.value_symbol.firstToken()),
                .kind = .Variable,
            });
        },
        .array_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.identifier.firstToken()),
                .kind = .Variable,
            });
        },
        .switch_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.node.value_symbol.firstToken()),
                .kind = .Variable,
            });
        },
        .label_decl => |label_decl| {
            try context.completions.append(.{
                .label = tree.tokenSlice(label_decl.firstToken()),
                .kind = .Variable,
            });
        },
    }
}

fn completeLabel(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    // We use a local arena allocator to deallocate all temporary data without iterating
    var arena = std.heap.ArenaAllocator.init(allocator);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    // Deallocate all temporary data.
    defer arena.deinit();

    const context = DeclToCompletionContext{
        .completions = &completions,
        .config = &config,
        .arena = &arena,
        .orig_handle = handle,
    };
    try analysis.iterateLabels(handle, pos_index, declToCompletion, context);

    try send(types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    // We use a local arena allocator to deallocate all temporary data without iterating
    var arena = std.heap.ArenaAllocator.init(allocator);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    // Deallocate all temporary data.
    defer arena.deinit();

    const context = DeclToCompletionContext{
        .completions = &completions,
        .config = &config,
        .arena = &arena,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&document_store, &arena, handle, pos_index, declToCompletion, context);

    try send(types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(id: types.RequestId, handle: *DocumentStore.Handle, position: types.Position, range: analysis.SourceRange, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);

    const line = try handle.document.getLine(@intCast(usize, position.line));
    var tokenizer = std.zig.Tokenizer.init(line[range.start..range.end]);

    const pos_index = try handle.document.positionToIndex(position);
    if (try analysis.getFieldAccessTypeNode(&document_store, &arena, handle, pos_index, &tokenizer)) |node| {
        try nodeToCompletion(&arena, &completions, node, handle, config);
    }

    try send(types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn documentSymbol(id: types.RequestId, handle: *DocumentStore.Handle) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try send(types.Response{
        .id = id,
        .result = .{ .DocumentSymbols = try analysis.getDocumentSymbols(&arena.allocator, handle.tree) },
    });
}

// Compute builtin completions at comptime.
const builtin_completions = block: {
    @setEvalBranchQuota(3_500);
    const CompletionList = [data.builtins.len]types.CompletionItem;
    var with_snippets: CompletionList = undefined;
    var without_snippets: CompletionList = undefined;

    for (data.builtins) |builtin, i| {
        const cutoff = std.mem.indexOf(u8, builtin, "(") orelse builtin.len;

        const base_completion = types.CompletionItem{
            .label = builtin[0..cutoff],
            .kind = .Function,

            .filterText = builtin[1..cutoff],
            .detail = data.builtin_details[i],
            .documentation = .{
                .kind = .Markdown,
                .value = data.builtin_docs[i],
            },
        };

        with_snippets[i] = base_completion;
        with_snippets[i].insertText = builtin[1..];
        with_snippets[i].insertTextFormat = .Snippet;

        without_snippets[i] = base_completion;
        without_snippets[i].insertText = builtin[1..cutoff];
    }

    break :block [2]CompletionList{
        without_snippets, with_snippets,
    };
};

fn loadConfig(folder_path: []const u8) ?Config {
    var folder = std.fs.cwd().openDir(folder_path, .{}) catch return null;
    defer folder.close();

    const conf_file = folder.openFile("zls.json", .{}) catch return null;
    defer conf_file.close();

    // Max 1MB
    const file_buf = conf_file.inStream().readAllAlloc(allocator, 0x1000000) catch return null;
    defer allocator.free(file_buf);

    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{ .allocator = allocator }) catch |err| {
        std.debug.warn("Error while parsing configuration file: {}\nUsing default config.\n", .{err});
        return null;
    };

    if (config.zig_lib_path) |zig_lib_path| {
        if (!std.fs.path.isAbsolute(zig_lib_path)) {
            std.debug.warn("zig library path is not absolute, defaulting to null.\n", .{});
            allocator.free(zig_lib_path);
            config.zig_lib_path = null;
        }
    }

    return config;
}

fn loadWorkspaceConfigs() !void {
    var folder_config_it = workspace_folder_configs.iterator();
    while (folder_config_it.next()) |entry| {
        if (entry.value) |_| continue;

        const folder_path = try URI.parse(allocator, entry.key);
        defer allocator.free(folder_path);

        entry.value = loadConfig(folder_path);
    }
}

fn configFromUriOr(uri: []const u8, default: Config) Config {
    var folder_config_it = workspace_folder_configs.iterator();
    while (folder_config_it.next()) |entry| {
        if (std.mem.startsWith(u8, uri, entry.key)) {
            return entry.value orelse default;
        }
    }

    return default;
}

fn processJsonRpc(parser: *std.json.Parser, json: []const u8, config: Config) !void {
    var tree = try parser.parse(json);
    defer tree.deinit();

    const root = tree.root;

    const id = if (root.Object.getValue("id")) |id| switch (id) {
        .Integer => |int| types.RequestId{ .Integer = int },
        .String => |str| types.RequestId{ .String = str },
        else => types.RequestId{ .Integer = 0 },
    } else types.RequestId{ .Integer = 0 };

    std.debug.assert(root.Object.getValue("method") != null);
    const method = root.Object.getValue("method").?.String;

    const start_time = std.time.milliTimestamp();
    defer {
        const end_time = std.time.milliTimestamp();
        std.debug.warn("Took {}ms to process method {}\n", .{ end_time - start_time, method });
    }

    // Core
    if (std.mem.eql(u8, method, "initialize")) {
        const params = root.Object.getValue("params").?.Object;
        const client_capabs = params.getValue("capabilities").?.Object;
        if (client_capabs.getValue("workspace")) |workspace_capabs| {
            if (workspace_capabs.Object.getValue("workspaceFolders")) |folders_capab| {
                client_capabilities.supports_workspace_folders = folders_capab.Bool;
            }
        }

        if (client_capabs.getValue("textDocument")) |text_doc_capabs| {
            if (text_doc_capabs.Object.getValue("semanticTokens")) |_| {
                client_capabilities.supports_semantic_tokens = true;
            }

            if (text_doc_capabs.Object.getValue("hover")) |hover_capabs| {
                if (hover_capabs.Object.getValue("contentFormat")) |content_formats| {
                    for (content_formats.Array.items) |format| {
                        if (std.mem.eql(u8, "markdown", format.String)) {
                            client_capabilities.hover_supports_md = true;
                        }
                    }
                }
            }

            if (text_doc_capabs.Object.getValue("completion")) |completion_capabs| {
                if (completion_capabs.Object.getValue("completionItem")) |item_capabs| {
                    const maybe_support_snippet = item_capabs.Object.getValue("snippetSupport");
                    client_capabilities.supports_snippets = maybe_support_snippet != null and maybe_support_snippet.?.Bool;

                    if (item_capabs.Object.getValue("documentationFormat")) |content_formats| {
                        for (content_formats.Array.items) |format| {
                            if (std.mem.eql(u8, "markdown", format.String)) {
                                client_capabilities.completion_doc_supports_md = true;
                            }
                        }
                    }
                }
            }
        }

        if (params.getValue("workspaceFolders")) |workspace_folders| {
            switch (workspace_folders) {
                .Array => |folders| {
                    std.debug.warn("Got workspace folders in initialization.\n", .{});

                    for (folders.items) |workspace_folder| {
                        const folder_uri = workspace_folder.Object.getValue("uri").?.String;
                        std.debug.warn("Loaded folder {}\n", .{folder_uri});
                        const duped_uri = try std.mem.dupe(allocator, u8, folder_uri);
                        try workspace_folder_configs.putNoClobber(duped_uri, null);
                    }
                    try loadWorkspaceConfigs();
                },
                else => {},
            }
        }

        std.debug.warn("{}\n", .{client_capabilities});
        try respondGeneric(id, initialize_response);
    } else if (std.mem.eql(u8, method, "initialized")) {
        // All gucci
    } else if (std.mem.eql(u8, method, "$/cancelRequest")) {
        // noop
    }
    // Workspace folder changes
    else if (std.mem.eql(u8, method, "workspace/didChangeWorkspaceFolders")) {
        const params = root.Object.getValue("params").?.Object;
        const event = params.getValue("event").?.Object;
        const added = event.getValue("added").?.Array;
        const removed = event.getValue("removed").?.Array;

        for (removed.items) |rem| {
            const uri = rem.Object.getValue("uri").?.String;
            if (workspace_folder_configs.remove(uri)) |entry| {
                allocator.free(entry.key);
                if (entry.value) |c| {
                    std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
                }
            }
        }

        for (added.items) |add| {
            const duped_uri = try std.mem.dupe(allocator, u8, add.Object.getValue("uri").?.String);
            if (try workspace_folder_configs.put(duped_uri, null)) |old| {
                allocator.free(old.key);
                if (old.value) |c| {
                    std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
                }
            }
        }

        try loadWorkspaceConfigs();
    }
    // File changes
    else if (std.mem.eql(u8, method, "textDocument/didOpen")) {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const text = document.getValue("text").?.String;

        const handle = try document_store.openDocument(uri, text);
        try publishDiagnostics(handle.*, configFromUriOr(uri, config));
    } else if (std.mem.eql(u8, method, "textDocument/didChange")) {
        const params = root.Object.getValue("params").?.Object;
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const content_changes = params.getValue("contentChanges").?.Array;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to change non existent document {}", .{uri});
            return;
        };

        const local_config = configFromUriOr(uri, config);
        try document_store.applyChanges(handle, content_changes, local_config.zig_lib_path);
        try publishDiagnostics(handle.*, local_config);
    } else if (std.mem.eql(u8, method, "textDocument/didSave")) {
        const params = root.Object.getValue("params").?.Object;
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to save non existent document {}", .{uri});
            return;
        };

        try document_store.applySave(handle);
    } else if (std.mem.eql(u8, method, "textDocument/willSave")) {
        // noop
    } else if (std.mem.eql(u8, method, "textDocument/didClose")) {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        document_store.closeDocument(uri);
    }
    // Semantic highlighting
    else if (std.mem.eql(u8, method, "textDocument/semanticTokens")) {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        const this_config = configFromUriOr(uri, config);
        if (this_config.enable_semantic_tokens) {
            const handle = document_store.getHandle(uri) orelse {
                std.debug.warn("Trying to complete in non existent document {}", .{uri});
                return try respondGeneric(id, no_semantic_tokens_response);
            };

            const semantic_tokens = @import("semantic_tokens.zig");
            const token_array = try semantic_tokens.writeAllSemanticTokens(allocator, handle.*);
            defer allocator.free(token_array);

            return try send(types.Response{
                .id = id,
                .result = .{ .SemanticTokens = .{ .data = token_array } },
            });
        } else
            return try respondGeneric(id, no_semantic_tokens_response);
    }
    // Autocomplete / Signatures
    else if (std.mem.eql(u8, method, "textDocument/completion")) {
        const params = root.Object.getValue("params").?.Object;
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to complete in non existent document {}", .{uri});
            return try respondGeneric(id, no_completions_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            const this_config = configFromUriOr(uri, config);
            const use_snippets = this_config.enable_snippets and client_capabilities.supports_snippets;
            switch (pos_context) {
                .builtin => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = builtin_completions[@boolToInt(use_snippets)][0..],
                        },
                    },
                }),
                .var_access, .empty => try completeGlobal(id, pos_index, handle, this_config),
                .field_access => |range| try completeFieldAccess(id, handle, pos, range, this_config),
                .global_error_set => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = document_store.error_completions.completions.items,
                        },
                    },
                }),
                .enum_literal => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = document_store.enum_completions.completions.items,
                        },
                    },
                }),
                .label => try completeLabel(id, pos_index, handle, this_config),
                else => try respondGeneric(id, no_completions_response),
            }
        } else {
            try respondGeneric(id, no_completions_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/signatureHelp")) {
        // TODO: Implement this
        try respondGeneric(id,
            \\,"result":{"signatures":[]}}
        );
    } else if (std.mem.eql(u8, method, "textDocument/definition") or
        std.mem.eql(u8, method, "textDocument/declaration") or
        std.mem.eql(u8, method, "textDocument/typeDefinition") or
        std.mem.eql(u8, method, "textDocument/implementation"))
    {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const resolve_alias = !std.mem.eql(u8, method, "textDocument/declaration");
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            switch (pos_context) {
                .var_access => try gotoDefinitionGlobal(id, pos_index, handle, configFromUriOr(uri, config), resolve_alias),
                .field_access => |range| try gotoDefinitionFieldAccess(id, handle, pos, range, configFromUriOr(uri, config), resolve_alias),
                .string_literal => try gotoDefinitionString(id, pos_index, handle, config),
                .label => try gotoDefinitionLabel(id, pos_index, handle, configFromUriOr(uri, config)),
                else => try respondGeneric(id, null_result_response),
            }
        } else {
            try respondGeneric(id, null_result_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/hover")) {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            switch (pos_context) {
                .var_access => try hoverDefinitionGlobal(id, pos_index, handle, configFromUriOr(uri, config)),
                .field_access => |range| try hoverDefinitionFieldAccess(id, handle, pos, range, configFromUriOr(uri, config)),
                .label => try hoverDefinitionLabel(id, pos_index, handle, configFromUriOr(uri, config)),
                else => try respondGeneric(id, null_result_response),
            }
        } else {
            try respondGeneric(id, null_result_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/documentSymbol")) {
        const params = root.Object.getValue("params").?.Object;
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        try documentSymbol(id, handle);
    } else if (std.mem.eql(u8, method, "textDocument/formatting")) {
        if (config.zig_exe_path) |zig_exe_path| {
            const params = root.Object.getValue("params").?.Object;
            const document = params.getValue("textDocument").?.Object;
            const uri = document.getValue("uri").?.String;

            const handle = document_store.getHandle(uri) orelse {
                std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
                return try respondGeneric(id, null_result_response);
            };

            var process = try std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, allocator);
            defer process.deinit();
            process.stdin_behavior = .Pipe;
            process.stdout_behavior = .Pipe;

            process.spawn() catch |err| {
                std.debug.warn("Failied to spawn zig fmt process, error: {}\n", .{err});
                return try respondGeneric(id, null_result_response);
            };
            try process.stdin.?.writeAll(handle.document.text);
            process.stdin.?.close();
            process.stdin = null;

            const stdout_bytes = try process.stdout.?.reader().readAllAlloc(allocator, std.math.maxInt(usize));
            defer allocator.free(stdout_bytes);

            switch (try process.wait()) {
                .Exited => |code| if (code == 0) {
                    try send(types.Response{
                        .id = id,
                        .result = .{
                            .TextEdits = &[1]types.TextEdit{
                                .{
                                    .range = handle.document.range(),
                                    .newText = stdout_bytes,
                                },
                            },
                        },
                    });
                },
                else => {},
            }
        }
        return try respondGeneric(id, null_result_response);
    } else if (std.mem.eql(u8, method, "textDocument/references") or
        std.mem.eql(u8, method, "textDocument/documentHighlight") or
        std.mem.eql(u8, method, "textDocument/codeAction") or
        std.mem.eql(u8, method, "textDocument/codeLens") or
        std.mem.eql(u8, method, "textDocument/documentLink") or
        std.mem.eql(u8, method, "textDocument/rangeFormatting") or
        std.mem.eql(u8, method, "textDocument/onTypeFormatting") or
        std.mem.eql(u8, method, "textDocument/rename") or
        std.mem.eql(u8, method, "textDocument/prepareRename") or
        std.mem.eql(u8, method, "textDocument/foldingRange") or
        std.mem.eql(u8, method, "textDocument/selectionRange"))
    {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        try respondGeneric(id, null_result_response);
    } else if (root.Object.getValue("id")) |_| {
        std.debug.warn("Method with return value not implemented: {}", .{method});
        try respondGeneric(id, not_implemented_response);
    } else {
        std.debug.warn("Method without return value not implemented: {}", .{method});
    }
}

var debug_alloc_state: DebugAllocator = undefined;
// We can now use if(leak_count_alloc) |alloc| { ... } as a comptime check.
const debug_alloc: ?*DebugAllocator = if (build_options.allocation_info) &debug_alloc_state else null;

pub fn main() anyerror!void {
    // TODO: Use a better purpose general allocator once std has one.
    // Probably after the generic composable allocators PR?
    // This is not too bad for now since most allocations happen in local arenas.
    allocator = std.heap.page_allocator;

    if (build_options.allocation_info) {
        // TODO: Use a better debugging allocator, track size in bytes, memory reserved etc..
        // Initialize the leak counting allocator.
        debug_alloc_state = DebugAllocator.init(allocator, build_options.max_bytes_allocated);
        allocator = &debug_alloc_state.allocator;
    }

    // Init global vars
    const in_stream = std.io.getStdIn().inStream();
    stdout = std.io.bufferedOutStream(std.io.getStdOut().outStream());

    // Read the configuration, if any.
    const config_parse_options = std.json.ParseOptions{ .allocator = allocator };
    var config = Config{};
    defer std.json.parseFree(Config, config, config_parse_options);

    config_read: {
        const known_folders = @import("known-folders");

        const res = try known_folders.getPath(allocator, .local_configuration);
        if (res) |local_config_path| {
            defer allocator.free(local_config_path);
            if (loadConfig(local_config_path)) |conf| {
                config = conf;
                break :config_read;
            }
        }

        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = std.fs.selfExeDirPath(&exe_dir_bytes) catch break :config_read;

        if (loadConfig(exe_dir_path)) |conf| {
            config = conf;
        }
    }

    // Find the zig executable in PATH
    var zig_exe_path: ?[]const u8 = null;
    defer if (zig_exe_path) |exe_path| allocator.free(exe_path);

    find_zig: {
        if (config.zig_exe_path) |exe_path| {
            if (std.fs.path.isAbsolute(exe_path)) {
                zig_exe_path = try std.mem.dupe(allocator, u8, exe_path);
                break :find_zig;
            }

            std.debug.warn("zig path `{}` is not absolute, will look in path\n", .{exe_path});
        }

        const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => {
                std.debug.warn("Could not get PATH.\n", .{});
                break :find_zig;
            },
            else => return err,
        };
        defer allocator.free(env_path);

        const exe_extension = @as(std.zig.CrossTarget, .{}).exeFileExt();
        const zig_exe = try std.fmt.allocPrint(allocator, "zig{}", .{exe_extension});
        defer allocator.free(zig_exe);

        var it = std.mem.tokenize(env_path, &[_]u8{std.fs.path.delimiter});
        while (it.next()) |path| {
            const full_path = try std.fs.path.join(allocator, &[_][]const u8{
                path,
                zig_exe,
            });
            defer allocator.free(full_path);

            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            zig_exe_path = std.os.realpath(full_path, &buf) catch continue;
            std.debug.warn("Found zig in PATH: {}\n", .{zig_exe_path});
            break :find_zig;
        }
    }

    if (zig_exe_path) |exe_path| {
        config.zig_exe_path = exe_path;
        std.debug.warn("Using zig executable {}\n", .{exe_path});
        if (config.zig_lib_path == null) {
            // Set the lib path relative to the executable path.
            config.zig_lib_path = try std.fs.path.resolve(allocator, &[_][]const u8{
                std.fs.path.dirname(exe_path).?, "./lib/zig",
            });

            std.debug.warn("Resolved standard library from executable: {}\n", .{config.zig_lib_path});
        }
    }

    if (config.build_runner_path) |build_runner_path| {
        try document_store.init(allocator, zig_exe_path, try std.mem.dupe(allocator, u8, build_runner_path), config.zig_lib_path);
    } else {
        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = try std.fs.selfExeDirPath(&exe_dir_bytes);

        const build_runner_path = try std.fs.path.resolve(allocator, &[_][]const u8{ exe_dir_path, "build_runner.zig" });
        try document_store.init(allocator, zig_exe_path, build_runner_path, config.zig_lib_path);
    }

    defer document_store.deinit();

    workspace_folder_configs = std.StringHashMap(?Config).init(allocator);
    defer workspace_folder_configs.deinit();

    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(allocator, false);
    defer json_parser.deinit();

    while (true) {
        const headers = readRequestHeader(allocator, in_stream) catch |err| {
            std.debug.warn("{}; exiting!", .{@errorName(err)});
            return;
        };
        defer headers.deinit(allocator);
        const buf = try allocator.alloc(u8, headers.content_length);
        defer allocator.free(buf);
        try in_stream.readNoEof(buf);
        try processJsonRpc(&json_parser, buf, config);
        json_parser.reset();

        if (debug_alloc) |dbg| {
            std.debug.warn("{}\n", .{dbg.info});
        }
    }
}
