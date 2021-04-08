const std = @import("std");
const build_options = @import("build_options");

const Config = @import("config.zig");
const DocumentStore = @import("document_store.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;
const data = @import("data/" ++ build_options.data_version ++ ".zig");
const requests = @import("requests.zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const URI = @import("uri.zig");
const references = @import("references.zig");
const rename = @import("rename.zig");
const offsets = @import("offsets.zig");
const setup = @import("setup.zig");
const semantic_tokens = @import("semantic_tokens.zig");
const known_folders = @import("known-folders");

const logger = std.log.scoped(.main);

// Always set this to debug to make std.log call into our handler, then control the runtime
// value in the definition below.
pub const log_level = .debug;

var actual_log_level: std.log.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    else => .notice,
};

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@enumToInt(message_level) > @enumToInt(actual_log_level)) {
        return;
    }
    // After shutdown, pipe output to stderr
    if (!keep_running) {
        std.debug.print("[{s}-{s}] " ++ format ++ "\n", .{ @tagName(message_level), @tagName(scope) } ++ args);
        return;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var message = std.fmt.allocPrint(&arena.allocator, "[{s}-{s}] " ++ format, .{ @tagName(message_level), @tagName(scope) } ++ args) catch |err| {
        std.debug.print("Failed to allocPrint message.\n", .{});
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
            .params = types.Notification.Params{
                .ShowMessage = .{
                    .type = message_type,
                    .message = message,
                },
            },
        }) catch |err| {
            std.debug.print("Failed to send show message notification (error: {}).\n", .{err});
        };
    } else {
        const message_type: types.MessageType = if (message_level == .debug)
            .Log
        else
            .Info;

        send(&arena, types.Notification{
            .method = "window/logMessage",
            .params = types.Notification.Params{
                .LogMessage = .{
                    .type = message_type,
                    .message = message,
                },
            },
        }) catch |err| {
            std.debug.print("Failed to send show message notification (error: {}).\n", .{err});
        };
    }
}

// Code is largely based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig
var stdout: std.io.BufferedWriter(4096, std.fs.File.Writer) = undefined;
var allocator: *std.mem.Allocator = undefined;

var document_store: DocumentStore = undefined;

const ClientCapabilities = struct {
    supports_snippets: bool = false,
    supports_semantic_tokens: bool = false,
    hover_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
};

var client_capabilities = ClientCapabilities{};
var offset_encoding = offsets.Encoding.utf16;

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
const no_signatures_response =
    \\,"result":{"signatures":[]}}
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

fn truncateCompletions(list: []types.CompletionItem, max_detail_length: usize) void {
    for (list) |*item| {
        if (item.detail) |det| {
            if (det.len > max_detail_length) {
                item.detail = det[0..max_detail_length];
            }
        }
    }
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

    const stdout_stream = stdout.writer();
    try stdout_stream.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{response.len + id_len + json_fmt.len - 1});
    switch (id) {
        .Integer => |int| try stdout_stream.print("{}", .{int}),
        .String => |str| try stdout_stream.print("\"{s}\"", .{str}),
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

    for (tree.errors) |err| {
        const loc = tree.tokenLocation(0, err.token);

        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        try tree.renderError(err, fbs.writer());

        try diagnostics.append(.{
            .range = astLocationToRange(loc),
            .severity = .Error,
            .code = @tagName(err.tag),
            .source = "zls",
            .message = try std.mem.dupe(&arena.allocator, u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (tree.errors.len == 0) {
        for (tree.rootDecls()) |decl_idx| {
            const decl = tree.nodes.items(.tag)[decl_idx];
            switch (decl) {
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => blk: {
                    var buf: [1]std.zig.ast.Node.Index = undefined;
                    const func = analysis.fnProto(tree, decl_idx, &buf).?;
                    if (func.extern_export_token != null) break :blk;

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

    try send(arena, types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnostics = .{
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
                    .insertText = "len",
                    .insertTextFormat = .PlainText,
                });
                try list.append(.{
                    .label = "ptr",
                    .kind = .Field,
                    .insertText = "ptr",
                    .insertTextFormat = .PlainText,
                });
            }
        },
        .error_union => {},
        .pointer => |n| {
            if (config.operator_completions) {
                try list.append(.{
                    .label = "*",
                    .kind = .Operator,
                    .insertText = "*",
                    .insertTextFormat = .PlainText,
                });
            }
            try nodeToCompletion(
                arena,
                list,
                .{ .node = n, .handle = type_handle.handle },
                null,
                orig_handle,
                type_handle.type.is_type_val,
                null,
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
            null,
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
    parent_is_type_val: ?bool,
    config: Config,
) error{OutOfMemory}!void {
    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    const doc_kind: types.MarkupContent.Kind = if (client_capabilities.completion_doc_supports_md)
        .Markdown
    else
        .PlainText;

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

    if (analysis.isContainer(handle.tree, node)) {
        const context = DeclToCompletionContext{
            .completions = list,
            .config = &config,
            .arena = arena,
            .orig_handle = orig_handle,
            .parent_is_type_val = is_type_val,
        };
        try analysis.iterateSymbolsContainer(
            &document_store,
            arena,
            node_handle,
            orig_handle,
            declToCompletion,
            context,
            !is_type_val,
        );
    }

    if (is_type_val) return;

    switch (node_tags[node]) {
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]std.zig.ast.Node.Index = undefined;
            const func = analysis.fnProto(tree, node, &buf).?;
            if (func.name_token) |name_token| {
                const use_snippets = config.enable_snippets and client_capabilities.supports_snippets;
                const insert_text = if (use_snippets) blk: {
                    const skip_self_param = !(parent_is_type_val orelse true) and
                        try analysis.hasSelfParam(arena, &document_store, handle, func);
                    break :blk try analysis.getFunctionSnippet(&arena.allocator, tree, func, skip_self_param);
                } else tree.tokenSlice(func.name_token.?);

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
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = analysis.varDecl(tree, node).?;
            const is_const = token_tags[var_decl.ast.mut_token] == .keyword_const;

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
                .label = handle.tree.tokenSlice(var_decl.ast.mut_token + 1),
                .kind = if (is_const) .Constant else .Variable,
                .documentation = doc,
                .detail = analysis.getVariableSignature(tree, var_decl),
                .insertText = tree.tokenSlice(var_decl.ast.mut_token + 1),
                .insertTextFormat = .PlainText,
            });
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = analysis.containerField(tree, node).?;
            try list.append(.{
                .label = handle.tree.tokenSlice(field.ast.name_token),
                .kind = .Field,
                .documentation = doc,
                .detail = analysis.getContainerFieldSignature(handle.tree, field),
                .insertText = tree.tokenSlice(field.ast.name_token),
                .insertTextFormat = .PlainText,
            });
        },
        .array_type,
        .array_type_sentinel,
        => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = analysis.ptrType(tree, node).?;

            switch (ptr_type.size) {
                .One, .C, .Many => if (config.operator_completions) {
                    try list.append(.{
                        .label = "*",
                        .kind = .Operator,
                        .insertText = "*",
                        .insertTextFormat = .PlainText,
                    });
                },
                .Slice => {
                    try list.append(.{
                        .label = "ptr",
                        .kind = .Field,
                        .insertText = "ptr",
                        .insertTextFormat = .PlainText,
                    });
                    try list.append(.{
                        .label = "len",
                        .kind = .Field,
                        .insertText = "len",
                        .insertTextFormat = .PlainText,
                    });
                    return;
                },
            }

            if (unwrapped) |actual_type| {
                try typeToCompletion(arena, list, .{ .original = actual_type }, orig_handle, config);
            }
            return;
        },
        .optional_type => {
            if (config.operator_completions) {
                try list.append(.{
                    .label = "?",
                    .kind = .Operator,
                    .insertText = "?",
                    .insertTextFormat = .PlainText,
                });
            }
            return;
        },
        .string_literal => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        else => if (analysis.nodeToString(tree, node)) |string| {
            try list.append(.{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = tree.getNodeSource(node),
                .insertText = string,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

pub fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
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
            break :block offsets.tokenRelativeLocation(handle.tree, 0, handle.tree.tokens.items(.start)[name_token], offset_encoding) catch return;
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

fn hoverSymbol(
    id: types.RequestId,
    arena: *std.heap.ArenaAllocator,
    decl_handle: analysis.DeclWithHandle,
) (std.os.WriteError || error{OutOfMemory})!void {
    const handle = decl_handle.handle;
    const tree = handle.tree;

    const hover_kind: types.MarkupContent.Kind = if (client_capabilities.hover_supports_md) .Markdown else .PlainText;
    var doc_str: ?[]const u8 = null;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try analysis.resolveVarDeclAlias(&document_store, arena, .{ .node = node, .handle = handle })) |result| {
                return try hoverSymbol(id, arena, result);
            }
            doc_str = try analysis.getDocComments(&arena.allocator, tree, node, hover_kind);

            var buf: [1]std.zig.ast.Node.Index = undefined;

            if (analysis.varDecl(tree, node)) |var_decl| {
                break :def analysis.getVariableSignature(tree, var_decl);
            } else if (analysis.fnProto(tree, node, &buf)) |fn_proto| {
                break :def analysis.getFunctionSignature(tree, fn_proto);
            } else if (analysis.containerField(tree, node)) |field| {
                break :def analysis.getContainerFieldSignature(tree, field);
            } else {
                break :def analysis.nodeToString(tree, node) orelse
                    return try respondGeneric(id, null_result_response);
            }
        },
        .param_decl => |param| def: {
            if (param.first_doc_comment) |doc_comments| {
                doc_str = try analysis.collectDocComments(&arena.allocator, handle.tree, doc_comments, hover_kind);
            }

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr); // extern fn
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            const start = offsets.tokenLocation(tree, first_token).start;
            const end = offsets.tokenLocation(tree, last_token).end;
            break :def tree.source[start..end];
        },
        .pointer_payload => |payload| tree.tokenSlice(payload.name),
        .array_payload => |payload| handle.tree.tokenSlice(payload.identifier),
        .array_index => |payload| handle.tree.tokenSlice(payload),
        .switch_payload => |payload| tree.tokenSlice(payload.node),
        .label_decl => |label_decl| tree.tokenSlice(label_decl),
    };

    var hover_text: []const u8 = undefined;
    if (hover_kind == .Markdown) {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(&arena.allocator, "```zig\n{s}\n```\n{s}", .{ def_str, doc })
        else
            try std.fmt.allocPrint(&arena.allocator, "```zig\n{s}\n```", .{def_str});
    } else {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(&arena.allocator, "{s}\n{s}", .{ def_str, doc })
        else
            def_str;
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .Hover = .{
                .contents = .{ .value = hover_text },
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

fn hoverDefinitionBuiltin(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return try respondGeneric(id, null_result_response);

    inline for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            try send(arena, types.Response{
                .id = id,
                .result = .{
                    .Hover = .{
                        .contents = .{
                            .value = try std.fmt.allocPrint(
                                &arena.allocator,
                                "```zig\n{s}\n```\n{s}",
                                .{ builtin.signature, builtin.documentation },
                            ),
                        },
                    },
                },
            });
        }
    }
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

    const import_str = analysis.getImportStr(tree, 0, pos_index) orelse return try respondGeneric(id, null_result_response);
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

fn referencesDefinitionGlobal(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    include_decl: bool,
    skip_std_references: bool,
) !void {
    const decl = (try getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(&arena.allocator);
    try references.symbolReferences(
        arena,
        &document_store,
        decl,
        offset_encoding,
        include_decl,
        &locs,
        std.ArrayList(types.Location).append,
        skip_std_references,
    );
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
    try references.symbolReferences(arena, &document_store, decl, offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append, config.skip_std_references);
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

fn hasComment(tree: ast.Tree, start_token: ast.TokenIndex, end_token: ast.TokenIndex) bool {
    const token_starts = tree.tokens.items(.start);

    const start = token_starts[start_token];
    const end = token_starts[end_token];

    return std.mem.indexOf(u8, tree.source[start..end], "//") != null;
}

const DeclToCompletionContext = struct {
    completions: *std.ArrayList(types.CompletionItem),
    config: *const Config,
    arena: *std.heap.ArenaAllocator,
    orig_handle: *DocumentStore.Handle,
    parent_is_type_val: ?bool = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) !void {
    const tree = decl_handle.handle.tree;
    switch (decl_handle.decl.*) {
        .ast_node => |node| try nodeToCompletion(
            context.arena,
            context.completions,
            .{ .node = node, .handle = decl_handle.handle },
            null,
            context.orig_handle,
            false,
            context.parent_is_type_val,
            context.config.*,
        ),
        .param_decl => |param| {
            const doc_kind: types.MarkupContent.Kind = if (client_capabilities.completion_doc_supports_md) .Markdown else .PlainText;
            const doc = if (param.first_doc_comment) |doc_comments|
                types.MarkupContent{
                    .kind = doc_kind,
                    .value = try analysis.collectDocComments(&context.arena.allocator, tree, doc_comments, doc_kind),
                }
            else
                null;

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr);
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            try context.completions.append(.{
                .label = tree.tokenSlice(param.name_token.?),
                .kind = .Constant,
                .documentation = doc,
                .detail = tree.source[offsets.tokenLocation(tree, first_token).start..offsets.tokenLocation(tree, last_token).end],
                .insertText = tree.tokenSlice(param.name_token.?),
                .insertTextFormat = .PlainText,
            });
        },
        .pointer_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.name),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.name),
                .insertTextFormat = .PlainText,
            });
        },
        .array_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.identifier),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.identifier),
                .insertTextFormat = .PlainText,
            });
        },
        .array_index => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload),
                .insertTextFormat = .PlainText,
            });
        },
        .switch_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.node),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.node),
                .insertTextFormat = .PlainText,
            });
        },
        .label_decl => |label_decl| {
            try context.completions.append(.{
                .label = tree.tokenSlice(label_decl),
                .kind = .Variable,
                .insertText = tree.tokenSlice(label_decl),
                .insertTextFormat = .PlainText,
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
    truncateCompletions(completions.items, config.max_detail_length);

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

var builtin_completions: ?[]types.CompletionItem = null;
fn completeBuiltin(arena: *std.heap.ArenaAllocator, id: types.RequestId, config: Config) !void {
    if (builtin_completions == null) {
        builtin_completions = try allocator.alloc(types.CompletionItem, data.builtins.len);
        for (data.builtins) |builtin, idx| {
            builtin_completions.?[idx] = types.CompletionItem{
                .label = builtin.name,
                .kind = .Function,
                .filterText = builtin.name[1..],
                .detail = builtin.signature,
                .documentation = .{
                    .kind = .Markdown,
                    .value = builtin.documentation,
                },
            };

            var insert_text: []const u8 = undefined;
            if (config.enable_snippets) {
                insert_text = builtin.snippet;
                builtin_completions.?[idx].insertTextFormat = .Snippet;
            } else {
                insert_text = builtin.name;
            }
            builtin_completions.?[idx].insertText =
                if (config.include_at_in_builtins)
                insert_text
            else
                insert_text[1..];
        }
        truncateCompletions(builtin_completions.?, config.max_detail_length);
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = builtin_completions.?,
            },
        },
    });
}

fn completeGlobal(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
    config: Config,
) !void {
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);

    const context = DeclToCompletionContext{
        .completions = &completions,
        .config = &config,
        .arena = arena,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&document_store, arena, handle, pos_index, declToCompletion, context);
    truncateCompletions(completions.items, config.max_detail_length);

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
        truncateCompletions(completions.items, config.max_detail_length);
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

fn completeError(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    config: Config,
) !void {
    const completions = try document_store.errorCompletionItems(arena, handle);
    truncateCompletions(completions, config.max_detail_length);
    logger.debug("Completing error:", .{});

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
            },
        },
    });
}

fn completeDot(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    config: Config,
) !void {
    var completions = try document_store.enumCompletionItems(arena, handle);
    truncateCompletions(completions, config.max_detail_length);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
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

fn loadConfig(folder_path: []const u8) ?Config {
    var folder = std.fs.cwd().openDir(folder_path, .{}) catch return null;
    defer folder.close();

    const file_buf = folder.readFileAlloc(allocator, "zls.json", 0x1000000) catch |err| {
        if (err != error.FileNotFound)
            logger.warn("Error while reading configuration file: {}", .{err});
        return null;
    };
    defer allocator.free(file_buf);

    @setEvalBranchQuota(2000);
    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{ .allocator = allocator }) catch |err| {
        logger.warn("Error while parsing configuration file: {}", .{err});
        return null;
    };

    if (config.zig_lib_path) |zig_lib_path| {
        if (!std.fs.path.isAbsolute(zig_lib_path)) {
            logger.warn("zig library path is not absolute, defaulting to null.", .{});
            allocator.free(zig_lib_path);
            config.zig_lib_path = null;
        }
    }

    return config;
}

fn initializeHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Initialize, config: Config) !void {
    for (req.params.capabilities.offsetEncoding.value) |encoding| {
        if (std.mem.eql(u8, encoding, "utf-8")) {
            offset_encoding = .utf8;
        }
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

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .InitializeResult = .{
                .offsetEncoding = if (offset_encoding == .utf8)
                    @as([]const u8, "utf-8")
                else
                    "utf-16",
                .serverInfo = .{
                    .name = "zls",
                    .version = "0.1.0",
                },
                .capabilities = .{
                    .signatureHelpProvider = .{
                        .triggerCharacters = &.{"("},
                        .retriggerCharacters = &.{","},
                    },
                    .textDocumentSync = .Full,
                    .renameProvider = true,
                    .completionProvider = .{
                        .resolveProvider = false,
                        .triggerCharacters = &[_][]const u8{ ".", ":", "@" },
                    },
                    .documentHighlightProvider = false,
                    .hoverProvider = true,
                    .codeActionProvider = false,
                    .declarationProvider = true,
                    .definitionProvider = true,
                    .typeDefinitionProvider = true,
                    .implementationProvider = false,
                    .referencesProvider = true,
                    .documentSymbolProvider = true,
                    .colorProvider = false,
                    .documentFormattingProvider = true,
                    .documentRangeFormattingProvider = false,
                    .foldingRangeProvider = false,
                    .selectionRangeProvider = false,
                    .workspaceSymbolProvider = false,
                    .rangeProvider = false,
                    .documentProvider = true,
                    .workspace = .{
                        .workspaceFolders = .{
                            .supported = false,
                            .changeNotifications = false,
                        },
                    },
                    .semanticTokensProvider = .{
                        .full = true,
                        .range = false,
                        .legend = .{
                            .tokenTypes = comptime block: {
                                const tokTypeFields = std.meta.fields(semantic_tokens.TokenType);
                                var names: [tokTypeFields.len][]const u8 = undefined;
                                for (tokTypeFields) |field, i| {
                                    names[i] = field.name;
                                }
                                break :block &names;
                            },
                            .tokenModifiers = comptime block: {
                                const tokModFields = std.meta.fields(semantic_tokens.TokenModifiers);
                                var names: [tokModFields.len][]const u8 = undefined;
                                for (tokModFields) |field, i| {
                                    names[i] = field.name;
                                }
                                break :block &names;
                            },
                        },
                    },
                },
            },
        },
    });

    logger.notice("zls initialized", .{});
    logger.info("{}", .{client_capabilities});
    logger.notice("Using offset encoding: {s}", .{std.meta.tagName(offset_encoding)});
}

var keep_running = true;
fn shutdownHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, config: Config) !void {
    logger.notice("Server closing...", .{});

    keep_running = false;
    // Technically we should deinitialize first and send possible errors to the client
    try respondGeneric(id, null_result_response);
}

fn openDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.OpenDocument, config: Config) !void {
    const handle = try document_store.openDocument(req.params.textDocument.uri, req.params.textDocument.text);
    try publishDiagnostics(arena, handle.*, config);

    if (client_capabilities.supports_semantic_tokens)
        try semanticTokensFullHandler(arena, id, .{ .params = .{ .textDocument = .{ .uri = req.params.textDocument.uri } } }, config);
}

fn changeDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.ChangeDocument, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.debug("Trying to change non existent document {s}", .{req.params.textDocument.uri});
        return;
    };

    try document_store.applyChanges(handle, req.params.contentChanges.Array, offset_encoding);
    try publishDiagnostics(arena, handle.*, config);
}

fn saveDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SaveDocument, config: Config) error{OutOfMemory}!void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to save non existent document {s}", .{req.params.textDocument.uri});
        return;
    };
    try document_store.applySave(handle);
}

fn closeDocumentHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.CloseDocument, config: Config) error{}!void {
    document_store.closeDocument(req.params.textDocument.uri);
}

fn semanticTokensFullHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SemanticTokensFull, config: Config) (error{OutOfMemory} || std.fs.File.WriteError)!void {
    if (config.enable_semantic_tokens) blk: {
        const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to get semantic tokens of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const token_array = try semantic_tokens.writeAllSemanticTokens(arena, &document_store, handle, offset_encoding);
        defer allocator.free(token_array);

        return try send(arena, types.Response{
            .id = id,
            .result = .{ .SemanticTokensFull = .{ .data = token_array } },
        });
    }
    return try respondGeneric(id, no_semantic_tokens_response);
}

fn completionHandler(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    req: requests.Completion,
    config: Config,
) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to complete in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, no_completions_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(id, no_completions_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
    const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);
    const use_snippets = config.enable_snippets and client_capabilities.supports_snippets;

    switch (pos_context) {
        .builtin => try completeBuiltin(arena, id, config),
        .var_access, .empty => try completeGlobal(arena, id, doc_position.absolute_index, handle, config),
        .field_access => |range| try completeFieldAccess(arena, id, handle, doc_position, range, config),
        .global_error_set => try completeError(arena, id, handle, config),
        .enum_literal => try completeDot(arena, id, handle, config),
        .label => try completeLabel(arena, id, doc_position.absolute_index, handle, config),
        else => try respondGeneric(id, no_completions_response),
    }
}

fn signatureHelpHandler(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    req: requests.SignatureHelp,
    config: Config,
) !void {
    const getSignatureInfo = @import("signature_help.zig").getSignatureInfo;
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get signature help in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, no_signatures_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(id, no_signatures_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
    if (try getSignatureInfo(
        &document_store,
        arena,
        handle,
        doc_position.absolute_index,
        data,
    )) |sig_info| {
        return try send(arena, types.Response{
            .id = id,
            .result = .{
                .SignatureHelp = .{
                    .signatures = &[1]types.SignatureInformation{sig_info},
                    .activeSignature = 0,
                    .activeParameter = sig_info.activeParameter,
                },
            },
        });
    }
    return try respondGeneric(id, no_signatures_response);
}

fn gotoHandler(
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    req: requests.GotoDefinition,
    config: Config,
    resolve_alias: bool,
) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to go to definition in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try gotoDefinitionGlobal(arena, id, doc_position.absolute_index, handle, config, resolve_alias),
            .field_access => |range| try gotoDefinitionFieldAccess(arena, id, handle, doc_position, range, config, resolve_alias),
            .string_literal => try gotoDefinitionString(arena, id, doc_position.absolute_index, handle, config),
            .label => try gotoDefinitionLabel(arena, id, doc_position.absolute_index, handle, config),
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
        logger.warn("Trying to get hover in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);
        switch (pos_context) {
            .builtin => try hoverDefinitionBuiltin(arena, id, doc_position.absolute_index, handle),
            .var_access => try hoverDefinitionGlobal(arena, id, doc_position.absolute_index, handle, config),
            .field_access => |range| try hoverDefinitionFieldAccess(arena, id, handle, doc_position, range, config),
            .label => try hoverDefinitionLabel(arena, id, doc_position.absolute_index, handle, config),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn documentSymbolsHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.DocumentSymbols, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get document symbols in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };
    try documentSymbol(arena, id, handle);
}

fn formattingHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Formatting, config: Config) !void {
    if (config.zig_exe_path) |zig_exe_path| {
        const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to got to definition in non existent document {s}", .{req.params.textDocument.uri});
            return try respondGeneric(id, null_result_response);
        };

        var process = try std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, allocator);
        defer process.deinit();
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;

        process.spawn() catch |err| {
            logger.warn("Failed to spawn zig fmt process, error: {}", .{err});
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
        logger.warn("Trying to rename in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try renameDefinitionGlobal(arena, id, handle, doc_position.absolute_index, req.params.newName),
            .field_access => |range| try renameDefinitionFieldAccess(arena, id, handle, doc_position, range, req.params.newName, config),
            .label => try renameDefinitionLabel(arena, id, handle, doc_position.absolute_index, req.params.newName),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn referencesHandler(arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.References, config: Config) !void {
    const handle = document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get references in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const include_decl = req.params.context.includeDeclaration;
        switch (pos_context) {
            .var_access => try referencesDefinitionGlobal(arena, id, handle, doc_position.absolute_index, include_decl, config.skip_std_references),
            .field_access => |range| try referencesDefinitionFieldAccess(arena, id, handle, doc_position, range, include_decl, config),
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
        logger.debug("Took {}ms to process method {s}", .{ end_time - start_time, method });
    }

    const method_map = .{
        .{"initialized"},
        .{"$/cancelRequest"},
        .{"textDocument/willSave"},
        .{ "initialize", requests.Initialize, initializeHandler },
        .{ "shutdown", void, shutdownHandler },
        .{ "textDocument/didOpen", requests.OpenDocument, openDocumentHandler },
        .{ "textDocument/didChange", requests.ChangeDocument, changeDocumentHandler },
        .{ "textDocument/didSave", requests.SaveDocument, saveDocumentHandler },
        .{ "textDocument/didClose", requests.CloseDocument, closeDocumentHandler },
        .{ "textDocument/semanticTokens/full", requests.SemanticTokensFull, semanticTokensFullHandler },
        .{ "textDocument/completion", requests.Completion, completionHandler },
        .{ "textDocument/signatureHelp", requests.SignatureHelp, signatureHelpHandler },
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
                        logger.warn("Could not create request type {s} from JSON {s}", .{ @typeName(ReqT), json });
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
        .{"textDocument/semanticTokens/range"},
        .{"workspace/didChangeWorkspaceFolders"},
    });

    if (unimplemented_map.has(method)) {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        return try respondGeneric(id, null_result_response);
    }
    if (tree.root.Object.get("id")) |_| {
        return try respondGeneric(id, not_implemented_response);
    }
    logger.debug("Method without return value not implemented: {s}", .{method});
}

const stack_frames = switch (std.builtin.mode) {
    .Debug => 10,
    else => 0,
};
var gpa_state = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){};

pub fn main() anyerror!void {
    defer _ = gpa_state.deinit();
    defer keep_running = false;
    allocator = &gpa_state.allocator;

    analysis.init(allocator);
    defer analysis.deinit();

    // Check arguments.
    var args_it = std.process.args();
    defer args_it.deinit();
    const prog_name = try args_it.next(allocator) orelse @panic("Could not find self argument");
    allocator.free(prog_name);

    while (args_it.next(allocator)) |maybe_arg| {
        const arg = try maybe_arg;
        defer allocator.free(arg);
        if (std.mem.eql(u8, arg, "--debug-log")) {
            actual_log_level = .debug;
            std.debug.print("Enabled debug logging\n", .{});
        } else if (std.mem.eql(u8, arg, "config")) {
            try setup.wizard(allocator);
            return;
        } else {
            std.debug.print("Unrecognized argument {s}\n", .{arg});
            std.os.exit(1);
        }
    }

    // Init global vars
    const reader = std.io.getStdIn().reader();
    stdout = std.io.bufferedWriter(std.io.getStdOut().writer());

    // Read the configuration, if any.
    const config_parse_options = std.json.ParseOptions{ .allocator = allocator };
    var config = Config{};
    defer std.json.parseFree(Config, config, config_parse_options);

    config_read: {
        if (try known_folders.getPath(allocator, .local_configuration)) |path| {
            defer allocator.free(path);
            if (loadConfig(path)) |conf| {
                config = conf;
                break :config_read;
            }
        }
        if (try known_folders.getPath(allocator, .global_configuration)) |path| {
            defer allocator.free(path);
            if (loadConfig(path)) |conf| {
                config = conf;
                break :config_read;
            }
        }
        logger.info("No config file zls.json found.", .{});
    }

    // Find the zig executable in PATH
    find_zig: {
        if (config.zig_exe_path) |exe_path| {
            if (std.fs.path.isAbsolute(exe_path)) not_valid: {
                std.fs.cwd().access(exe_path, .{}) catch break :not_valid;
                break :find_zig;
            }
            logger.debug("zig path `{s}` is not absolute, will look in path", .{exe_path});
            allocator.free(exe_path);
        }
        config.zig_exe_path = try setup.findZig(allocator);
    }

    if (config.zig_exe_path) |exe_path| {
        logger.info("Using zig executable {s}", .{exe_path});

        if (config.zig_lib_path == null) find_lib_path: {
            // Use `zig env` to find the lib path
            const zig_env_result = try std.ChildProcess.exec(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ exe_path, "env" },
            });

            defer {
                allocator.free(zig_env_result.stdout);
                allocator.free(zig_env_result.stderr);
            }

            switch (zig_env_result.term) {
                .Exited => |exit_code| {
                    if (exit_code == 0) {
                        const Env = struct {
                            zig_exe: []const u8,
                            lib_dir: ?[]const u8,
                            std_dir: []const u8,
                            global_cache_dir: []const u8,
                            version: []const u8,
                        };

                        var json_env = std.json.parse(
                            Env,
                            &std.json.TokenStream.init(zig_env_result.stdout),
                            .{ .allocator = allocator },
                        ) catch {
                            logger.alert("Failed to parse zig env JSON result", .{});
                            break :find_lib_path;
                        };
                        defer std.json.parseFree(Env, json_env, .{ .allocator = allocator });
                        // We know this is allocated with `allocator`, we just steal it!
                        config.zig_lib_path = json_env.lib_dir.?;
                        json_env.lib_dir = null;
                        logger.notice("Using zig lib path '{s}'", .{config.zig_lib_path});
                    }
                },
                else => logger.alert("zig env invocation failed", .{}),
            }
        }
    } else {
        logger.warn("Zig executable path not specified in zls.json and could not be found in PATH", .{});
    }

    if (config.zig_lib_path == null) {
        logger.warn("Zig standard library path not specified in zls.json and could not be resolved from the zig executable", .{});
    }

    const build_runner_path = if (config.build_runner_path) |p|
        try allocator.dupe(u8, p)
    else blk: {
        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = try std.fs.selfExeDirPath(&exe_dir_bytes);
        break :blk try std.fs.path.resolve(allocator, &[_][]const u8{ exe_dir_path, "build_runner.zig" });
    };

    const build_runner_cache_path = if (config.build_runner_path) |p|
        try allocator.dupe(u8, p)
    else blk: {
        const cache_dir_path = (try known_folders.getPath(allocator, .cache)) orelse {
            logger.warn("Known-folders could not fetch the cache path", .{});
            return;
        };
        defer allocator.free(cache_dir_path);
        break :blk try std.fs.path.resolve(allocator, &[_][]const u8{ cache_dir_path, "zls" });
    };

    try document_store.init(
        allocator,
        config.zig_exe_path,
        build_runner_path,
        build_runner_cache_path,
        config.zig_lib_path,
    );
    defer document_store.deinit();

    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(allocator, false);
    defer json_parser.deinit();

    // Arena used for temporary allocations while handlign a request
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    while (keep_running) {
        const headers = readRequestHeader(&arena.allocator, reader) catch |err| {
            logger.crit("{s}; exiting!", .{@errorName(err)});
            return;
        };
        const buf = try arena.allocator.alloc(u8, headers.content_length);
        try reader.readNoEof(buf);

        try processJsonRpc(&arena, &json_parser, buf, config);
        json_parser.reset();
        arena.deinit();
        arena.state = .{};
    }

    if (builtin_completions) |compls| {
        allocator.free(compls);
    }
}
