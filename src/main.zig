const std = @import("std");
const build_options = @import("build_options");

const Config = @import("config.zig");
const DocumentStore = @import("document_store.zig");
const DebugAllocator = @import("debug_allocator.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;
const data = @import("data/" ++ build_options.data_version ++ ".zig");
const requests = @import("requests.zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const URI = @import("uri.zig");
const references = @import("references.zig");
const rename = @import("rename.zig");
const offsets = @import("offsets.zig");

const logger = std.log.scoped(.main);

pub const log_level: std.log.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    else => .notice,
};

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var message = std.fmt.allocPrint(&arena.allocator, "[{}-{}] " ++ format, .{ @tagName(message_level), @tagName(scope) } ++ args) catch |err| {
        std.debug.print("Failed to allocPrint message.", .{});
        return;
    };
    if (@enumToInt(message_level) <= @enumToInt(std.log.Level.notice)) {
        const message_type: types.MessageType = switch (message_level) {
            .info => .Log,
            .notice => .Info,
            .warn => .Warning,
            .err => .Error,
            else => .Error,
        };
        send(&arena, types.Notification{
            .method = "window/showMessage",
            .params = types.NotificationParams{
                .ShowMessageParams = .{
                    .type = message_type,
                    .message = message,
                },
            },
        }) catch |err| {
            std.debug.print("Failed to send show message notification (error: {}).", .{err});
        };
    } else {
        const message_type: types.MessageType = if (message_level == .debug)
            .Log
        else
            .Info;

        send(&arena, types.Notification{
            .method = "window/logMessage",
            .params = types.NotificationParams{
                .LogMessageParams = .{
                    .type = message_type,
                    .message = message,
                },
            },
        }) catch |err| {
            std.debug.print("Failed to send show message notification (error: {}).", .{err});
        };
    }
}

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
var offset_encoding = offsets.Encoding.utf16;

const initialize_capabilities =
    \\"capabilities": {"signatureHelpProvider": {"triggerCharacters": ["(",","]},"textDocumentSync": 1,"renameProvider":true,"completionProvider": {"resolveProvider": false,"triggerCharacters": [".",":","@"]},"documentHighlightProvider": false,"hoverProvider": true,"codeActionProvider": false,"declarationProvider": true,"definitionProvider": true,"typeDefinitionProvider": true,"implementationProvider": false,"referencesProvider": true,"documentSymbolProvider": true,"colorProvider": false,"documentFormattingProvider": true,"documentRangeFormattingProvider": false,"foldingRangeProvider": false,"selectionRangeProvider": false,"workspaceSymbolProvider": false,"rangeProvider": false,"documentProvider": true,"workspace": {"workspaceFolders": {"supported": true,"changeNotifications": true}},"semanticTokensProvider": {"documentProvider": true,"legend": {"tokenTypes": ["namespace","type","struct","enum","union","parameter","variable","tagField","field","errorTag","function","keyword","comment","string","number","operator","builtin","label"],"tokenModifiers": ["definition","async","documentation", "generic"]}}}}}
;

const initialize_response = ",\"result\": {" ++ initialize_capabilities;

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
fn send(arena: *std.heap.ArenaAllocator, reqOrRes: anytype) !void {
    var arr = std.ArrayList(u8).init(&arena.allocator);
    try std.json.stringify(reqOrRes, .{}, arr.writer());

    const stdout_stream = stdout.writer();
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

fn publishDiagnostics(arena: *std.heap.ArenaAllocator, handle: DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

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
            switch (decl.tag) {
                .FnProto => blk: {
                    const func = decl.cast(std.zig.ast.Node.FnProto).?;
                    const is_extern = func.trailer_flags.has("extern_export_inline_token");
                    if (is_extern)
                        break :blk;

                    if (config.warn_style) {
                        if (func.getTrailer("name_token")) |name_token| {
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

    try send(arena, types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnosticsParams = .{
                .uri = handle.uri(),
                .diagnostics = diagnostics.items,
            },
        },
    });
}

fn typeToCompletion(
    arena: *std.heap.ArenaAllocator,
    list: *std.ArrayList(types.CompletionItem),
    field_access: analysis.FieldAccessReturn,
    orig_handle: *DocumentStore.Handle,
    config: Config,
) error{OutOfMemory}!void {
    const type_handle = field_access.original;
    switch (type_handle.type.data) {
        .slice => {
            if (!type_handle.type.is_type_val) {
                try list.append(.{
                    .label = "len",
                    .kind = .Field,
                });
                try list.append(.{
                    .label = "ptr",
                    .kind = .Field,
                });
            }
        },
        .error_union => {},
        .pointer => |n| {
            if (config.operator_completions) {
                try list.append(.{
                    .label = "*",
                    .kind = .Operator,
                });
            }
            try nodeToCompletion(
                arena,
                list,
                .{ .node = n, .handle = type_handle.handle },
                null,
                orig_handle,
                type_handle.type.is_type_val,
                config,
            );
        },
        .other => |n| try nodeToCompletion(
            arena,
            list,
            .{ .node = n, .handle = type_handle.handle },
            field_access.unwrapped,
            orig_handle,
            type_handle.type.is_type_val,
            config,
        ),
        .primitive => {},
    }
}

fn nodeToCompletion(
    arena: *std.heap.ArenaAllocator,
    list: *std.ArrayList(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    unwrapped: ?analysis.TypeWithHandle,
    orig_handle: *DocumentStore.Handle,
    is_type_val: bool,
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

    if (node.tag == .ErrorSetDecl or node.tag == .Root or node.tag == .ContainerDecl) {
        const context = DeclToCompletionContext{
            .completions = list,
            .config = &config,
            .arena = arena,
            .orig_handle = orig_handle,
        };
        try analysis.iterateSymbolsContainer(&document_store, arena, node_handle, orig_handle, declToCompletion, context, !is_type_val);
    }

    if (is_type_val) return;

    switch (node.tag) {
        .FnProto => {
            const func = node.cast(std.zig.ast.Node.FnProto).?;
            if (func.getTrailer("name_token")) |name_token| {
                const use_snippets = config.enable_snippets and client_capabilities.supports_snippets;

                const insert_text = if (use_snippets) blk: {
                    // TODO Also check if we are dot accessing from a type val and dont skip in that case.
                    const skip_self_param = if (func.params_len > 0) param_check: {
                        const in_container = analysis.innermostContainer(handle, handle.tree.token_locs[func.firstToken()].start);

                        switch (func.paramsConst()[0].param_type) {
                            .type_expr => |type_node| {
                                if (try analysis.resolveTypeOfNode(&document_store, arena, .{
                                    .node = type_node,
                                    .handle = handle,
                                })) |resolved_type| {
                                    if (std.meta.eql(in_container, resolved_type))
                                        break :param_check true;
                                }

                                if (type_node.castTag(.PtrType)) |ptr_type| {
                                    if (try analysis.resolveTypeOfNode(&document_store, arena, .{
                                        .node = ptr_type.rhs,
                                        .handle = handle,
                                    })) |resolved_prefix_op| {
                                        if (std.meta.eql(in_container, resolved_prefix_op))
                                            break :param_check true;
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
        .SliceType => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
            try list.append(.{
                .label = "ptr",
                .kind = .Field,
            });
        },
        .ArrayType => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
        },
        .PtrType => {
            if (config.operator_completions) {
                try list.append(.{
                    .label = "*",
                    .kind = .Operator,
                });
            }

            const ptr_type = node.castTag(.PtrType).?;
            if (ptr_type.rhs.castTag(.ArrayType) != null) {
                try list.append(.{
                    .label = "len",
                    .kind = .Field,
                });
            } else if (unwrapped) |actual_type| {
                try typeToCompletion(arena, list, .{ .original = actual_type }, orig_handle, config);
            }
            return;
        },
        .OptionalType => {
            if (config.operator_completions) {
                try list.append(.{
                    .label = "?",
                    .kind = .Operator,
                });
            }
            return;
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
                    break :block result.location(offset_encoding) catch return;
                }
            }

            const name_token = analysis.getDeclNameToken(handle.tree, node) orelse
                return try respondGeneric(id, null_result_response);
            break :block offsets.tokenRelativeLocation(handle.tree, 0, name_token, offset_encoding) catch return;
        },
        else => decl_handle.location(offset_encoding) catch return,
    };

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = handle.document.uri,
                .range = .{
                    .start = .{
                        .line = @intCast(i64, location.line),
                        .character = @intCast(i64, location.column),
                    },
                    .end = .{
                        .line = @intCast(i64, location.line),
                        .character = @intCast(i64, location.column),
                    },
                },
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

            const signature_str = switch (node.tag) {
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

    try send(arena, types.Response{
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

fn gotoDefinitionLabel(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, arena, decl, false);
}

fn gotoDefinitionGlobal(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config, resolve_alias: bool) !void {
    const decl = (try getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, arena, decl, resolve_alias);
}

fn hoverDefinitionLabel(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, arena, decl);
}

fn hoverDefinitionGlobal(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const decl = (try getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, arena, decl);
}

fn getSymbolFieldAccess(
    handle: *DocumentStore.Handle,
    arena: *std.heap.ArenaAllocator,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    config: Config,
) !?analysis.DeclWithHandle {
    const name = identifierFromPosition(position.absolute_index, handle.*);
    if (name.len == 0) return null;
    var tokenizer = std.zig.Tokenizer.init(position.line[range.start..range.end]);

    if (try analysis.getFieldAccessType(&document_store, arena, handle, position.absolute_index, &tokenizer)) |result| {
        const container_handle = result.unwrapped orelse result.original;
        const container_handle_node = switch (container_handle.type.data) {
            .other => |n| n,
            else => return null,
        };
        return try analysis.lookupSymbolContainer(
            &document_store,
            arena,
            .{ .node = container_handle_node, .handle = container_handle.handle },
            name,
            true,
        );
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    config: Config,
    resolve_alias: bool,
) !void {
    const decl = (try getSymbolFieldAccess(handle, arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, arena, decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    config: Config,
) !void {
    const decl = (try getSymbolFieldAccess(handle, arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, arena, decl);
}

fn gotoDefinitionString(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

    const import_str = analysis.getImportStr(tree, pos_index) orelse return try respondGeneric(id, null_result_response);
    const uri = (try document_store.uriFromImportStr(
        &arena.allocator,
        handle.*,
        import_str,
    )) orelse return try respondGeneric(id, null_result_response);

    try send(arena, types.Response{
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

fn renameDefinitionGlobal(arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle, pos_index: usize, new_name: []const u8) !void {
    const decl = (try getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(&arena.allocator),
    };
    try rename.renameSymbol(arena, &document_store, decl, new_name, &workspace_edit.changes.?, offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionFieldAccess(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    new_name: []const u8,
    config: Config,
) !void {
    const decl = (try getSymbolFieldAccess(handle, arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(&arena.allocator),
    };
    try rename.renameSymbol(arena, &document_store, decl, new_name, &workspace_edit.changes.?, offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionLabel(arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle, pos_index: usize, new_name: []const u8) !void {
    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(&arena.allocator),
    };
    try rename.renameLabel(arena, decl, new_name, &workspace_edit.changes.?, offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn referencesDefinitionGlobal(arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle, pos_index: usize, include_decl: bool) !void {
    const decl = (try getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(&arena.allocator);
    try references.symbolReferences(arena, &document_store, decl, offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .Locations = locs.items },
    });
}

fn referencesDefinitionFieldAccess(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    include_decl: bool,
    config: Config,
) !void {
    const decl = (try getSymbolFieldAccess(handle, arena, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(&arena.allocator);
    try references.symbolReferences(arena, &document_store, decl, offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .Locations = locs.items },
    });
}

fn referencesDefinitionLabel(arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle, pos_index: usize, include_decl: bool) !void {
    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(&arena.allocator);
    try references.labelReferences(arena, decl, offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .Locations = locs.items },
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
        .ast_node => |node| try nodeToCompletion(context.arena, context.completions, .{ .node = node, .handle = decl_handle.handle }, null, context.orig_handle, false, context.config.*),
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

fn completeLabel(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);

    const context = DeclToCompletionContext{
        .completions = &completions,
        .config = &config,
        .arena = arena,
        .orig_handle = handle,
    };
    try analysis.iterateLabels(handle, pos_index, declToCompletion, context);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeGlobal(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);

    const context = DeclToCompletionContext{
        .completions = &completions,
        .config = &config,
        .arena = arena,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&document_store, arena, handle, pos_index, declToCompletion, context);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    config: Config,
) !void {
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    var tokenizer = std.zig.Tokenizer.init(position.line[range.start..range.end]);
    if (try analysis.getFieldAccessType(&document_store, arena, handle, position.absolute_index, &tokenizer)) |result| {
        try typeToCompletion(arena, &completions, result, handle, config);
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn documentSymbol(arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    try send(arena, types.Response{
        .id = id,
        .result = .{ .DocumentSymbols = try analysis.getDocumentSymbols(&arena.allocator, handle.tree, offset_encoding) },
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

    const file_buf = folder.readFileAlloc(allocator, "zls.json", 0x1000000) catch |err| {
        if (err != error.FileNotFound)
            logger.warn("Error while reading configuration file: {}\n", .{err});
        return null;
    };
    defer allocator.free(file_buf);

    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{ .allocator = allocator }) catch |err| {
        logger.warn("Error while parsing configuration file: {}\n", .{err});
        return null;
    };

    if (config.zig_lib_path) |zig_lib_path| {
        if (!std.fs.path.isAbsolute(zig_lib_path)) {
            logger.warn("zig library path is not absolute, defaulting to null.\n", .{});
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

fn initializeHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Initialize, config: Config) !void {
    var send_encoding = req.params.capabilities.offsetEncoding.value.len != 0;
    for (req.params.capabilities.offsetEncoding.value) |encoding| {
        if (std.mem.eql(u8, encoding, "utf-8")) {
            offset_encoding = .utf8;
        }
    }

    if (req.params.capabilities.workspace) |workspace| {
        client_capabilities.supports_workspace_folders = workspace.workspaceFolders.value;
    }

    if (req.params.capabilities.textDocument) |textDocument| {
        client_capabilities.supports_semantic_tokens = textDocument.semanticTokens.exists;
        if (textDocument.hover) |hover| {
            for (hover.contentFormat.value) |format| {
                if (std.mem.eql(u8, "markdown", format)) {
                    client_capabilities.hover_supports_md = true;
                }
            }
        }
        if (textDocument.completion) |completion| {
            if (completion.completionItem) |completionItem| {
                client_capabilities.supports_snippets = completionItem.snippetSupport.value;
                for (completionItem.documentationFormat.value) |documentationFormat| {
                    if (std.mem.eql(u8, "markdown", documentationFormat)) {
                        client_capabilities.completion_doc_supports_md = true;
                    }
                }
            }
        }
    }

    if (req.params.workspaceFolders) |workspaceFolders| {
        if (workspaceFolders.len != 0) {
            logger.debug("Got workspace folders in initialization.\n", .{});
        }
        for (workspaceFolders) |workspace_folder| {
            logger.debug("Loaded folder {}\n", .{workspace_folder.uri});
            const duped_uri = try std.mem.dupe(allocator, u8, workspace_folder.uri);
            try workspace_folder_configs.putNoClobber(duped_uri, null);
        }
        try loadWorkspaceConfigs();
    }

    if (!send_encoding) {
        try respondGeneric(id, initialize_response);
    } else {
        const response_str = try std.fmt.allocPrint(&arena.allocator, ",\"result\": {{\"offsetEncoding\":\"{}\",{}", .{
            if (offset_encoding == .utf8) @as([]const u8, "utf-8") else @as([]const u8, "utf-16"),
            initialize_capabilities,
        });
        try respondGeneric(id, response_str);
    }
    logger.notice("zls initialized", .{});
    logger.info("{}\n", .{client_capabilities});
    logger.notice("Using offset encoding: {}\n", .{std.meta.tagName(offset_encoding)});
}

var keep_running = true;
fn shutdownHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, config: Config) !void {
    keep_running = false;
    // Technically we should deinitialize first and send possible errors to the client
    try respondGeneric(id, null_result_response);
}

fn workspaceFoldersChangeHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.WorkspaceFoldersChange, config: Config) !void {
    for (req.params.event.removed) |rem| {
        if (workspace_folder_configs.remove(rem.uri)) |entry| {
            allocator.free(entry.key);
            if (entry.value) |c| {
                std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
            }
        }
    }

    for (req.params.event.added) |add| {
        const duped_uri = try std.mem.dupe(allocator, u8, add.uri);
        if (try workspace_folder_configs.fetchPut(duped_uri, null)) |old| {
            allocator.free(old.key);
            if (old.value) |c| {
                std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
            }
        }
    }

    try loadWorkspaceConfigs();
}

fn openDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.OpenDocument, config: Config) !void {
    const handle = try document_store.openDocument(req.params.textDocument.uri, req.params.textDocument.text);
    try publishDiagnostics(arena, handle.*, configFromUriOr(req.params.textDocument.uri, config));

    try semanticTokensHandler(arena, id, .{ .params = .{ .textDocument = .{ .uri = req.params.textDocument.uri } } }, config);
}

fn changeDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.ChangeDocument, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.debug("Trying to change non existent document {}", .{req.params.textDocument.uri});
        return;
    };

    const local_config = configFromUriOr(req.params.textDocument.uri, config);
    try document_store.applyChanges(handle, req.params.contentChanges.Array, local_config.zig_lib_path);
    try publishDiagnostics(arena, handle.*, local_config);
}

fn saveDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SaveDocument, config: Config) error{OutOfMemory}!void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to save non existent document {}", .{req.params.textDocument.uri});
        return;
    };
    try document_store.applySave(handle);
}

fn closeDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.CloseDocument, config: Config) error{}!void {
    document_store.closeDocument(req.params.textDocument.uri);
}

fn semanticTokensHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SemanticTokens, config: Config) (error{OutOfMemory} || std.fs.File.WriteError)!void {
    const this_config = configFromUriOr(req.params.textDocument.uri, config);
    if (this_config.enable_semantic_tokens) {
        const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to get semantic tokens of non existent document {}", .{req.params.textDocument.uri});
            return try respondGeneric(id, no_semantic_tokens_response);
        };

        const semantic_tokens = @import("semantic_tokens.zig");
        const token_array = try semantic_tokens.writeAllSemanticTokens(arena, &document_store, handle, offset_encoding);
        defer allocator.free(token_array);

        return try send(arena, types.Response{
            .id = id,
            .result = .{ .SemanticTokens = .{ .data = token_array } },
        });
    }
}

fn completionHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Completion, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to complete in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, no_completions_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const this_config = configFromUriOr(req.params.textDocument.uri, config);
        const use_snippets = this_config.enable_snippets and client_capabilities.supports_snippets;
        switch (pos_context) {
            .builtin => try send(arena, types.Response{
                .id = id,
                .result = .{
                    .CompletionList = .{
                        .isIncomplete = false,
                        .items = builtin_completions[@boolToInt(use_snippets)][0..],
                    },
                },
            }),
            .var_access, .empty => try completeGlobal(arena, id, doc_position.absolute_index, handle, this_config),
            .field_access => |range| try completeFieldAccess(arena, id, handle, doc_position, range, this_config),
            .global_error_set => try send(arena, types.Response{
                .id = id,
                .result = .{
                    .CompletionList = .{
                        .isIncomplete = false,
                        .items = try document_store.errorCompletionItems(arena, handle),
                    },
                },
            }),
            .enum_literal => try send(arena, types.Response{
                .id = id,
                .result = .{
                    .CompletionList = .{
                        .isIncomplete = false,
                        .items = try document_store.enumCompletionItems(arena, handle),
                    },
                },
            }),
            .label => try completeLabel(arena, id, doc_position.absolute_index, handle, this_config),
            else => try respondGeneric(id, no_completions_response),
        }
    } else {
        try respondGeneric(id, no_completions_response);
    }
}

fn signatureHelperHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, config: Config) !void {
    // TODO Implement this
    try respondGeneric(id,
        \\,"result":{"signatures":[]}}
    );
}

fn gotoHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDefinition, config: Config, resolve_alias: bool) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to go to definition in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const this_config = configFromUriOr(req.params.textDocument.uri, config);
        switch (pos_context) {
            .var_access => try gotoDefinitionGlobal(arena, id, doc_position.absolute_index, handle, this_config, resolve_alias),
            .field_access => |range| try gotoDefinitionFieldAccess(arena, id, handle, doc_position, range, this_config, resolve_alias),
            .string_literal => try gotoDefinitionString(arena, id, doc_position.absolute_index, handle, config),
            .label => try gotoDefinitionLabel(arena, id, doc_position.absolute_index, handle, this_config),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn gotoDefinitionHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDefinition, config: Config) !void {
    try gotoHandler(arena, id, req, config, true);
}

fn gotoDeclarationHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDeclaration, config: Config) !void {
    try gotoHandler(arena, id, req, config, false);
}

fn hoverHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Hover, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get hover in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const this_config = configFromUriOr(req.params.textDocument.uri, config);
        switch (pos_context) {
            .var_access => try hoverDefinitionGlobal(arena, id, doc_position.absolute_index, handle, this_config),
            .field_access => |range| try hoverDefinitionFieldAccess(arena, id, handle, doc_position, range, this_config),
            .label => try hoverDefinitionLabel(arena, id, doc_position.absolute_index, handle, this_config),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn documentSymbolsHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.DocumentSymbols, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get document symbols in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };
    try documentSymbol(arena, id, handle);
}

fn formattingHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Formatting, config: Config) !void {
    if (config.zig_exe_path) |zig_exe_path| {
        const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to got to definition in non existent document {}", .{req.params.textDocument.uri});
            return try respondGeneric(id, null_result_response);
        };

        var process = try std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, allocator);
        defer process.deinit();
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;

        process.spawn() catch |err| {
            logger.warn("Failed to spawn zig fmt process, error: {}\n", .{err});
            return try respondGeneric(id, null_result_response);
        };
        try process.stdin.?.writeAll(handle.document.text);
        process.stdin.?.close();
        process.stdin = null;

        const stdout_bytes = try process.stdout.?.reader().readAllAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(stdout_bytes);

        switch (try process.wait()) {
            .Exited => |code| if (code == 0) {
                return try send(arena, types.Response{
                    .id = id,
                    .result = .{
                        .TextEdits = &[1]types.TextEdit{
                            .{
                                .range = try offsets.documentRange(handle.document, offset_encoding),
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
}

fn renameHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Rename, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to rename in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const this_config = configFromUriOr(req.params.textDocument.uri, config);
        switch (pos_context) {
            .var_access => try renameDefinitionGlobal(arena, id, handle, doc_position.absolute_index, req.params.newName),
            .field_access => |range| try renameDefinitionFieldAccess(arena, id, handle, doc_position, range, req.params.newName, this_config),
            .label => try renameDefinitionLabel(arena, id, handle, doc_position.absolute_index, req.params.newName),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn referencesHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.References, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get references in non existent document {}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const this_config = configFromUriOr(req.params.textDocument.uri, config);
        const include_decl = req.params.context.includeDeclaration;
        switch (pos_context) {
            .var_access => try referencesDefinitionGlobal(arena, id, handle, doc_position.absolute_index, include_decl),
            .field_access => |range| try referencesDefinitionFieldAccess(arena, id, handle, doc_position, range, include_decl, this_config),
            .label => try referencesDefinitionLabel(arena, id, handle, doc_position.absolute_index, include_decl),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

// Needed for the hack seen below.
fn extractErr(val: anytype) anyerror {
    val catch |e| return e;
    return error.HackDone;
}

fn processJsonRpc(arena: *std.heap.ArenaAllocator, parser: *std.json.Parser, json: []const u8, config: Config) !void {
    var tree = try parser.parse(json);
    defer tree.deinit();

    const id = if (tree.root.Object.get("id")) |id| switch (id) {
        .Integer => |int| types.RequestId{ .Integer = int },
        .String => |str| types.RequestId{ .String = str },
        else => types.RequestId{ .Integer = 0 },
    } else types.RequestId{ .Integer = 0 };

    std.debug.assert(tree.root.Object.get("method") != null);
    const method = tree.root.Object.get("method").?.String;

    const start_time = std.time.milliTimestamp();
    defer {
        const end_time = std.time.milliTimestamp();
        logger.debug("Took {}ms to process method {}\n", .{ end_time - start_time, method });
    }

    const method_map = .{
        .{"initialized"},
        .{"$/cancelRequest"},
        .{"textDocument/willSave"},
        .{ "initialize", requests.Initialize, initializeHandler },
        .{ "shutdown", void, shutdownHandler },
        .{ "workspace/didChangeWorkspaceFolders", requests.WorkspaceFoldersChange, workspaceFoldersChangeHandler },
        .{ "textDocument/didOpen", requests.OpenDocument, openDocumentHandler },
        .{ "textDocument/didChange", requests.ChangeDocument, changeDocumentHandler },
        .{ "textDocument/didSave", requests.SaveDocument, saveDocumentHandler },
        .{ "textDocument/didClose", requests.CloseDocument, closeDocumentHandler },
        .{ "textDocument/semanticTokens", requests.SemanticTokens, semanticTokensHandler },
        .{ "textDocument/completion", requests.Completion, completionHandler },
        .{ "textDocument/signatureHelp", void, signatureHelperHandler },
        .{ "textDocument/definition", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/typeDefinition", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/implementation", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/declaration", requests.GotoDeclaration, gotoDeclarationHandler },
        .{ "textDocument/hover", requests.Hover, hoverHandler },
        .{ "textDocument/documentSymbol", requests.DocumentSymbols, documentSymbolsHandler },
        .{ "textDocument/formatting", requests.Formatting, formattingHandler },
        .{ "textDocument/rename", requests.Rename, renameHandler },
        .{ "textDocument/references", requests.References, referencesHandler },
    };

    // Hack to avoid `return`ing in the inline for, which causes bugs.
    var done: ?anyerror = null;
    inline for (method_map) |method_info| {
        if (done == null and std.mem.eql(u8, method, method_info[0])) {
            if (method_info.len == 1) {
                done = error.HackDone;
            } else if (method_info[1] != void) {
                const ReqT = method_info[1];
                if (requests.fromDynamicTree(arena, ReqT, tree.root)) |request_obj| {
                    done = error.HackDone;
                    done = extractErr(method_info[2](arena, id, request_obj, config));
                } else |err| {
                    if (err == error.MalformedJson) {
                        logger.warn("Could not create request type {} from JSON {}\n", .{ @typeName(ReqT), json });
                    }
                    done = err;
                }
            } else {
                done = error.HackDone;
                (method_info[2])(arena, id, config) catch |err| {
                    done = err;
                };
            }
        }
    }
    if (done) |err| switch (err) {
        error.MalformedJson => return try respondGeneric(id, null_result_response),
        error.HackDone => return,
        else => return err,
    };

    const unimplemented_map = std.ComptimeStringMap(void, .{
        .{"textDocument/documentHighlight"},
        .{"textDocument/codeAction"},
        .{"textDocument/codeLens"},
        .{"textDocument/documentLink"},
        .{"textDocument/rangeFormatting"},
        .{"textDocument/onTypeFormatting"},
        .{"textDocument/prepareRename"},
        .{"textDocument/foldingRange"},
        .{"textDocument/selectionRange"},
    });

    if (unimplemented_map.has(method)) {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        return try respondGeneric(id, null_result_response);
    }
    if (tree.root.Object.get("id")) |_| {
        return try respondGeneric(id, not_implemented_response);
    }
    logger.debug("Method without return value not implemented: {}", .{method});
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
        // Initialize the leak counting allocator.
        debug_alloc_state = DebugAllocator.init(allocator, build_options.max_bytes_allocated);
        allocator = &debug_alloc_state.allocator;
    }

    defer if (debug_alloc) |dbg| {
        std.debug.print("Finished cleanup, last allocation info.\n", .{});
        std.debug.print("\n{}\n", .{dbg.info});
        dbg.printRemainingStackTraces();
        dbg.deinit();
    };

    // Init global vars
    const reader = std.io.getStdIn().reader();
    stdout = std.io.bufferedOutStream(std.io.getStdOut().outStream());

    // Read the configuration, if any.
    const config_parse_options = std.json.ParseOptions{ .allocator = allocator };
    var config = Config{};
    var config_had_null_zig_path = config.zig_exe_path == null;
    defer {
        if (config_had_null_zig_path) {
            if (config.zig_exe_path) |exe_path| {
                allocator.free(exe_path);
                config.zig_exe_path = null;
            }
        }
        std.json.parseFree(Config, config, config_parse_options);
    }

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

    find_zig: {
        if (config.zig_exe_path) |exe_path| {
            if (std.fs.path.isAbsolute(exe_path)) {
                zig_exe_path = try std.mem.dupe(allocator, u8, exe_path);
                break :find_zig;
            }

            logger.debug("zig path `{}` is not absolute, will look in path\n", .{exe_path});
        }

        const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => {
                logger.warn("Could not get PATH.\n", .{});
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
            zig_exe_path = try std.mem.dupe(allocator, u8, std.os.realpath(full_path, &buf) catch continue);
            logger.info("Found zig in PATH: {}\n", .{zig_exe_path});
            break :find_zig;
        }
    }

    if (zig_exe_path) |exe_path| {
        config.zig_exe_path = exe_path;
        logger.info("Using zig executable {}\n", .{exe_path});
        if (config.zig_lib_path == null) {
            // Set the lib path relative to the executable path.
            config.zig_lib_path = try std.fs.path.resolve(allocator, &[_][]const u8{
                std.fs.path.dirname(exe_path).?, "./lib/zig",
            });

            logger.info("Resolved standard library from executable: {}\n", .{config.zig_lib_path});
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
    defer {
        var it = workspace_folder_configs.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key);
            if (entry.value) |c| {
                std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
            }
        }
        workspace_folder_configs.deinit();
    }

    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(allocator, false);
    defer json_parser.deinit();

    // Arena used for temporary allocations while handlign a request
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    while (keep_running) {
        const headers = readRequestHeader(&arena.allocator, reader) catch |err| {
            logger.crit("{}; exiting!", .{@errorName(err)});
            return;
        };
        const buf = try arena.allocator.alloc(u8, headers.content_length);
        try reader.readNoEof(buf);

        try processJsonRpc(&arena, &json_parser, buf, config);
        json_parser.reset();
        arena.deinit();
        arena.state = .{};

        if (debug_alloc) |dbg| {
            logger.debug("\n{}\n", .{dbg.info});
        }
    }
}
