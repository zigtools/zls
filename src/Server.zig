const Server = @This();

const std = @import("std");
const zig_builtin = @import("builtin");
const Config = @import("Config.zig");
const DocumentStore = @import("DocumentStore.zig");
const requests = @import("requests.zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const ast = @import("ast.zig");
const references = @import("references.zig");
const offsets = @import("offsets.zig");
const semantic_tokens = @import("semantic_tokens.zig");
const inlay_hints = @import("inlay_hints.zig");
const shared = @import("shared.zig");
const Ast = std.zig.Ast;
const tracy = @import("tracy.zig");
const uri_utils = @import("uri.zig");
const data = @import("data/data.zig");
const diff = @import("diff.zig");

const log = std.log.scoped(.server);

// Server fields

config: Config,
allocator: std.mem.Allocator = undefined,
arena: std.heap.ArenaAllocator = undefined,
document_store: DocumentStore = undefined,
builtin_completions: ?std.ArrayListUnmanaged(types.CompletionItem) = null,
client_capabilities: ClientCapabilities = .{},
offset_encoding: offsets.Encoding = .utf16,
keep_running: bool = true,

// Code was based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

const ClientCapabilities = struct {
    supports_snippets: bool = false,
    supports_semantic_tokens: bool = false,
    supports_inlay_hints: bool = false,
    hover_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
    label_details_support: bool = false,
    supports_configuration: bool = false,
};

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
fn send(writer: anytype, allocator: std.mem.Allocator, reqOrRes: anytype) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arr = std.ArrayListUnmanaged(u8){};
    defer arr.deinit(allocator);

    try std.json.stringify(reqOrRes, .{}, arr.writer(allocator));

    try writer.print("Content-Length: {}\r\n\r\n", .{arr.items.len});
    try writer.writeAll(arr.items);
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

fn respondGeneric(writer: anytype, id: types.RequestId, response: []const u8) !void {
    var buffered_writer = std.io.bufferedWriter(writer);
    const buf_writer = buffered_writer.writer();

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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

    try buf_writer.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{response.len + id_len + json_fmt.len - 1});
    switch (id) {
        .Integer => |int| try buf_writer.print("{}", .{int}),
        .String => |str| try buf_writer.print("\"{s}\"", .{str}),
        else => unreachable,
    }

    try buf_writer.writeAll(response);
    try buffered_writer.flush();
}

fn showMessage(server: *Server, writer: anytype, message_type: types.MessageType, message: []const u8) !void {
    try send(writer, server.allocator, types.Notification{
        .method = "window/showMessage",
        .params = .{
            .ShowMessageParams = .{
                .type = message_type,
                .message = message,
            },
        },
    });
}

fn publishDiagnostics(server: *Server, writer: anytype, handle: DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;

    var allocator = server.arena.allocator();
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};

    for (tree.errors) |err| {
        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        try tree.renderError(err, fbs.writer());

        try diagnostics.append(allocator, .{
            .range = offsets.tokenToRange(tree, err.token, server.offset_encoding),
            .severity = .Error,
            .code = @tagName(err.tag),
            .source = "zls",
            .message = try server.arena.allocator().dupe(u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (server.config.enable_ast_check_diagnostics and tree.errors.len == 0) diag: {
        if (server.config.zig_exe_path) |zig_exe_path| {
            var process = std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "ast-check", "--color", "off" }, server.allocator);
            process.stdin_behavior = .Pipe;
            process.stderr_behavior = .Pipe;

            process.spawn() catch |err| {
                log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
                break :diag;
            };
            try process.stdin.?.writeAll(handle.document.text);
            process.stdin.?.close();

            process.stdin = null;

            const stderr_bytes = try process.stderr.?.reader().readAllAlloc(server.allocator, std.math.maxInt(usize));
            defer server.allocator.free(stderr_bytes);

            switch (try process.wait()) {
                .Exited => {
                    // NOTE: I believe that with color off it's one diag per line; is this correct?
                    var line_iterator = std.mem.split(u8, stderr_bytes, "\n");

                    while (line_iterator.next()) |line| lin: {
                        var pos_and_diag_iterator = std.mem.split(u8, line, ":");
                        const maybe_first = pos_and_diag_iterator.next();
                        if (maybe_first) |first| {
                            if (first.len <= 1) break :lin;
                        } else break;

                        const utf8_position = types.Position{
                            .line = (try std.fmt.parseInt(u32, pos_and_diag_iterator.next().?, 10)) - 1,
                            .character = (try std.fmt.parseInt(u32, pos_and_diag_iterator.next().?, 10)) - 1,
                        };

                        // zig uses utf-8 encoding for character offsets
                        const position = offsets.convertPositionEncoding(handle.document.text, utf8_position, .utf8, server.offset_encoding);
                        const range = offsets.tokenPositionToRange(handle.document.text, position, server.offset_encoding);

                        const msg = pos_and_diag_iterator.rest()[1..];

                        if (std.mem.startsWith(u8, msg, "error: ")) {
                            try diagnostics.append(allocator, .{
                                .range = range,
                                .severity = .Error,
                                .code = "ast_check",
                                .source = "zls",
                                .message = try server.arena.allocator().dupe(u8, msg["error: ".len..]),
                            });
                        } else if (std.mem.startsWith(u8, msg, "note: ")) {
                            var latestDiag = &diagnostics.items[diagnostics.items.len - 1];

                            var fresh = if (latestDiag.relatedInformation.len == 0)
                                try server.arena.allocator().alloc(types.DiagnosticRelatedInformation, 1)
                            else
                                try server.arena.allocator().realloc(@ptrCast([]types.DiagnosticRelatedInformation, latestDiag.relatedInformation), latestDiag.relatedInformation.len + 1);

                            const location = types.Location{
                                .uri = handle.uri(),
                                .range = range,
                            };

                            fresh[fresh.len - 1] = .{
                                .location = location,
                                .message = try server.arena.allocator().dupe(u8, msg["note: ".len..]),
                            };

                            latestDiag.relatedInformation = fresh;
                        } else {
                            try diagnostics.append(allocator, .{
                                .range = range,
                                .severity = .Error,
                                .code = "ast_check",
                                .source = "zls",
                                .message = try server.arena.allocator().dupe(u8, msg),
                            });
                        }
                    }
                },
                else => {},
            }
        }
    }

    if (server.config.warn_style) {
        var node: u32 = 0;
        while (node < tree.nodes.len) : (node += 1) {
            if (ast.isBuiltinCall(tree, node)) {
                const builtin_token = tree.nodes.items(.main_token)[node];
                const call_name = tree.tokenSlice(builtin_token);

                if (!std.mem.eql(u8, call_name, "@import")) continue;

                var buffer: [2]Ast.Node.Index = undefined;
                const params = ast.builtinCallParams(tree, node, &buffer).?;

                if (params.len != 1) continue;

                const import_str_token = tree.nodes.items(.main_token)[params[0]];
                const import_str = tree.tokenSlice(import_str_token);

                if (std.mem.startsWith(u8, import_str, "\"./")) {
                    try diagnostics.append(allocator, .{
                        .range = offsets.tokenToRange(tree, import_str_token, server.offset_encoding),
                        .severity = .Hint,
                        .code = "dot_slash_import",
                        .source = "zls",
                        .message = "A ./ is not needed in imports",
                    });
                }
            }
        }

        // TODO: style warnings for types, values and declarations below root scope
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
                        var buf: [1]Ast.Node.Index = undefined;
                        const func = ast.fnProto(tree, decl_idx, &buf).?;
                        if (func.extern_export_inline_token != null) break :blk;

                        if (func.name_token) |name_token| {
                            const is_type_function = analysis.isTypeFunction(tree, func);

                            const func_name = tree.tokenSlice(name_token);
                            if (!is_type_function and !analysis.isCamelCase(func_name)) {
                                try diagnostics.append(allocator, .{
                                    .range = offsets.tokenToRange(tree, name_token, server.offset_encoding),
                                    .severity = .Hint,
                                    .code = "bad_style",
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(allocator, .{
                                    .range = offsets.tokenToRange(tree, name_token, server.offset_encoding),
                                    .severity = .Hint,
                                    .code = "bad_style",
                                    .source = "zls",
                                    .message = "Type functions should be PascalCase",
                                });
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    try send(writer, server.arena.allocator(), types.Notification{
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
    server: *Server,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    field_access: analysis.FieldAccessReturn,
    orig_handle: *DocumentStore.Handle,
) error{OutOfMemory}!void {
    var allocator = server.arena.allocator();

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const type_handle = field_access.original;
    switch (type_handle.type.data) {
        .slice => {
            if (!type_handle.type.is_type_val) {
                try list.append(allocator, .{
                    .label = "len",
                    .detail = "const len: usize",
                    .kind = .Field,
                    .insertText = "len",
                    .insertTextFormat = .PlainText,
                });
                try list.append(allocator, .{
                    .label = "ptr",
                    .kind = .Field,
                    .insertText = "ptr",
                    .insertTextFormat = .PlainText,
                });
            }
        },
        .error_union => {},
        .pointer => |n| {
            if (server.config.operator_completions) {
                try list.append(allocator, .{
                    .label = "*",
                    .kind = .Operator,
                    .insertText = "*",
                    .insertTextFormat = .PlainText,
                });
            }
            try server.nodeToCompletion(
                list,
                .{ .node = n, .handle = type_handle.handle },
                null,
                orig_handle,
                type_handle.type.is_type_val,
                null,
            );
        },
        .other => |n| try server.nodeToCompletion(
            list,
            .{ .node = n, .handle = type_handle.handle },
            field_access.unwrapped,
            orig_handle,
            type_handle.type.is_type_val,
            null,
        ),
        .primitive, .array_index => {},
    }
}

fn nodeToCompletion(
    server: *Server,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    unwrapped: ?analysis.TypeWithHandle,
    orig_handle: *DocumentStore.Handle,
    is_type_val: bool,
    parent_is_type_val: ?bool,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var allocator = server.arena.allocator();

    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    const doc_kind: types.MarkupContent.Kind = if (server.client_capabilities.completion_doc_supports_md)
        .Markdown
    else
        .PlainText;

    const doc = if (try analysis.getDocComments(
        allocator,
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

    if (ast.isContainer(handle.tree, node)) {
        const context = DeclToCompletionContext{
            .server = server,
            .completions = list,
            .orig_handle = orig_handle,
            .parent_is_type_val = is_type_val,
        };
        try analysis.iterateSymbolsContainer(
            &server.document_store,
            &server.arena,
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
            var buf: [1]Ast.Node.Index = undefined;
            const func = ast.fnProto(tree, node, &buf).?;
            if (func.name_token) |name_token| {
                const use_snippets = server.config.enable_snippets and server.client_capabilities.supports_snippets;
                const insert_text = if (use_snippets) blk: {
                    const skip_self_param = !(parent_is_type_val orelse true) and
                        try analysis.hasSelfParam(&server.arena, &server.document_store, handle, func);
                    break :blk try analysis.getFunctionSnippet(server.arena.allocator(), tree, func, skip_self_param);
                } else tree.tokenSlice(func.name_token.?);

                const is_type_function = analysis.isTypeFunction(handle.tree, func);

                try list.append(allocator, .{
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
            const var_decl = ast.varDecl(tree, node).?;
            const is_const = token_tags[var_decl.ast.mut_token] == .keyword_const;

            if (try analysis.resolveVarDeclAlias(&server.document_store, &server.arena, node_handle)) |result| {
                const context = DeclToCompletionContext{
                    .server = server,
                    .completions = list,
                    .orig_handle = orig_handle,
                };
                return try declToCompletion(context, result);
            }

            try list.append(allocator, .{
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
            const field = ast.containerField(tree, node).?;
            try list.append(allocator, .{
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
            try list.append(allocator, .{
                .label = "len",
                .detail = "const len: usize",
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
            const ptr_type = ast.ptrType(tree, node).?;

            switch (ptr_type.size) {
                .One, .C, .Many => if (server.config.operator_completions) {
                    try list.append(allocator, .{
                        .label = "*",
                        .kind = .Operator,
                        .insertText = "*",
                        .insertTextFormat = .PlainText,
                    });
                },
                .Slice => {
                    try list.append(allocator, .{
                        .label = "ptr",
                        .kind = .Field,
                        .insertText = "ptr",
                        .insertTextFormat = .PlainText,
                    });
                    try list.append(allocator, .{
                        .label = "len",
                        .detail = "const len: usize",
                        .kind = .Field,
                        .insertText = "len",
                        .insertTextFormat = .PlainText,
                    });
                    return;
                },
            }

            if (unwrapped) |actual_type| {
                try server.typeToCompletion(list, .{ .original = actual_type }, orig_handle);
            }
            return;
        },
        .optional_type => {
            if (server.config.operator_completions) {
                try list.append(allocator, .{
                    .label = "?",
                    .kind = .Operator,
                    .insertText = "?",
                    .insertTextFormat = .PlainText,
                });
            }
            return;
        },
        .string_literal => {
            try list.append(allocator, .{
                .label = "len",
                .detail = "const len: usize",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        else => if (analysis.nodeToString(tree, node)) |string| {
            try list.append(allocator, .{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = offsets.nodeToSlice(tree, node),
                .insertText = string,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

pub fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
    const text = handle.document.text;

    if (pos_index + 1 >= text.len) return "";
    var start_idx = pos_index;

    while (start_idx > 0 and isSymbolChar(text[start_idx - 1])) {
        start_idx -= 1;
    }

    var end_idx = pos_index;
    while (end_idx < handle.document.text.len and isSymbolChar(text[end_idx])) {
        end_idx += 1;
    }

    if (end_idx <= start_idx) return "";
    return text[start_idx..end_idx];
}

fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlNum(char) or char == '_';
}

fn gotoDefinitionSymbol(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    decl_handle: analysis.DeclWithHandle,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle = decl_handle.handle;

    const name_token = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analysis.resolveVarDeclAlias(&server.document_store, &server.arena, .{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;

                    break :block result.nameToken();
                }
            }

            break :block analysis.getDeclNameToken(handle.tree, node) orelse return try respondGeneric(writer, id, null_result_response);
        },
        else => decl_handle.nameToken(),
    };

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = handle.document.uri,
                .range = offsets.tokenToRange(handle.tree, name_token, server.offset_encoding),
            },
        },
    });
}

fn hoverSymbol(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    decl_handle: analysis.DeclWithHandle,
) (std.os.WriteError || error{OutOfMemory})!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = decl_handle.handle;
    const tree = handle.tree;

    const hover_kind: types.MarkupContent.Kind = if (server.client_capabilities.hover_supports_md) .Markdown else .PlainText;
    var doc_str: ?[]const u8 = null;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try analysis.resolveVarDeclAlias(&server.document_store, &server.arena, .{ .node = node, .handle = handle })) |result| {
                return try server.hoverSymbol(writer, id, result);
            }
            doc_str = try analysis.getDocComments(server.arena.allocator(), tree, node, hover_kind);

            var buf: [1]Ast.Node.Index = undefined;

            if (ast.varDecl(tree, node)) |var_decl| {
                break :def analysis.getVariableSignature(tree, var_decl);
            } else if (ast.fnProto(tree, node, &buf)) |fn_proto| {
                break :def analysis.getFunctionSignature(tree, fn_proto);
            } else if (ast.containerField(tree, node)) |field| {
                break :def analysis.getContainerFieldSignature(tree, field);
            } else {
                break :def analysis.nodeToString(tree, node) orelse
                    return try respondGeneric(writer, id, null_result_response);
            }
        },
        .param_decl => |param| def: {
            if (param.first_doc_comment) |doc_comments| {
                doc_str = try analysis.collectDocComments(server.arena.allocator(), handle.tree, doc_comments, hover_kind, false);
            }

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr); // extern fn
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            const start = offsets.tokenToIndex(tree, first_token);
            const end = offsets.tokenToLoc(tree, last_token).end;
            break :def tree.source[start..end];
        },
        .pointer_payload => |payload| tree.tokenSlice(payload.name),
        .array_payload => |payload| handle.tree.tokenSlice(payload.identifier),
        .array_index => |payload| handle.tree.tokenSlice(payload),
        .switch_payload => |payload| tree.tokenSlice(payload.node),
        .label_decl => |label_decl| tree.tokenSlice(label_decl),
    };

    var bound_type_params = analysis.BoundTypeParams{};
    const resolved_type = try decl_handle.resolveType(&server.document_store, &server.arena, &bound_type_params);

    const resolved_type_str = if (resolved_type) |rt|
        if (rt.type.is_type_val) "type" else switch (rt.type.data) { // TODO: Investigate random weird numbers like 897 that cause index of bounds
            .pointer,
            .slice,
            .error_union,
            .primitive,
            => |p| if (p >= tree.nodes.len) "unknown" else offsets.nodeToSlice(tree, p),
            .other => |p| if (p >= tree.nodes.len) "unknown" else switch (tree.nodes.items(.tag)[p]) {
                .container_decl,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                => tree.tokenSlice(tree.nodes.items(.main_token)[p] - 2), // NOTE: This is a hacky nightmare but it works :P
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => "fn", // TODO:(?) Add more info?
                .array_type,
                .array_type_sentinel,
                .ptr_type,
                .ptr_type_aligned,
                .ptr_type_bit_range,
                .ptr_type_sentinel,
                => offsets.nodeToSlice(tree, p),
                else => "unknown", // TODO: Implement more "other" type expressions; better safe than sorry
            },
            else => "unknown",
        }
    else
        "unknown";

    var hover_text: []const u8 = undefined;
    if (hover_kind == .Markdown) {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(server.arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(server.arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```", .{ def_str, resolved_type_str });
    } else {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(server.arena.allocator(), "{s} ({s})\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(server.arena.allocator(), "{s} ({s})", .{ def_str, resolved_type_str });
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .Hover = .{
                .contents = .{ .value = hover_text },
            },
        },
    });
}

fn getLabelGlobal(pos_index: usize, handle: *DocumentStore.Handle) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupLabel(handle, name, pos_index);
}

fn getSymbolGlobal(
    server: *Server,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupSymbolGlobal(&server.document_store, &server.arena, handle, name, pos_index);
}

fn gotoDefinitionLabel(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.gotoDefinitionSymbol(writer, id, decl, false);
}

fn gotoDefinitionGlobal(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.gotoDefinitionSymbol(writer, id, decl, resolve_alias);
}

fn hoverDefinitionLabel(server: *Server, writer: anytype, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.hoverSymbol(writer, id, decl);
}

fn hoverDefinitionBuiltin(server: *Server, writer: anytype, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return try respondGeneric(writer, id, null_result_response);

    inline for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            try send(writer, server.arena.allocator(), types.Response{
                .id = id,
                .result = .{
                    .Hover = .{
                        .contents = .{
                            .value = try std.fmt.allocPrint(
                                server.arena.allocator(),
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

fn hoverDefinitionGlobal(server: *Server, writer: anytype, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.hoverSymbol(writer, id, decl);
}

fn getSymbolFieldAccess(
    server: *Server,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(source_index, handle.*);
    if (name.len == 0) return null;

    var held_range = handle.document.borrowNullTerminatedSlice(loc.start, loc.end);
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    errdefer held_range.release();
    if (try analysis.getFieldAccessType(&server.document_store, &server.arena, handle, source_index, &tokenizer)) |result| {
        held_range.release();
        const container_handle = result.unwrapped orelse result.original;
        const container_handle_node = switch (container_handle.type.data) {
            .other => |n| n,
            else => return null,
        };
        return try analysis.lookupSymbolContainer(
            &server.document_store,
            &server.arena,
            .{ .node = container_handle_node, .handle = container_handle.handle },
            name,
            true,
        );
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, source_index, loc)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.gotoDefinitionSymbol(writer, id, decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, source_index, loc)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.hoverSymbol(writer, id, decl);
}

fn gotoDefinitionString(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;

    const import_str = analysis.getImportStr(tree, 0, pos_index) orelse return try respondGeneric(writer, id, null_result_response);
    const uri = (try server.document_store.uriFromImportStr(
        server.arena.allocator(),
        handle.*,
        import_str,
    )) orelse return try respondGeneric(writer, id, null_result_response);

    try send(writer, server.arena.allocator(), types.Response{
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

fn hasComment(tree: Ast.Tree, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const token_starts = tree.tokens.items(.start);

    const start = token_starts[start_token];
    const end = token_starts[end_token];

    return std.mem.indexOf(u8, tree.source[start..end], "//") != null;
}

const DeclToCompletionContext = struct {
    server: *Server,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    orig_handle: *DocumentStore.Handle,
    parent_is_type_val: ?bool = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var allocator = context.server.arena.allocator();

    const tree = decl_handle.handle.tree;
    switch (decl_handle.decl.*) {
        .ast_node => |node| try context.server.nodeToCompletion(
            context.completions,
            .{ .node = node, .handle = decl_handle.handle },
            null,
            context.orig_handle,
            false,
            context.parent_is_type_val,
        ),
        .param_decl => |param| {
            const doc_kind: types.MarkupContent.Kind = if (context.server.client_capabilities.completion_doc_supports_md) .Markdown else .PlainText;
            const doc = if (param.first_doc_comment) |doc_comments|
                types.MarkupContent{
                    .kind = doc_kind,
                    .value = try analysis.collectDocComments(allocator, tree, doc_comments, doc_kind, false),
                }
            else
                null;

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr);
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(param.name_token.?),
                .kind = .Constant,
                .documentation = doc,
                .detail = tree.source[offsets.tokenToIndex(tree, first_token)..offsets.tokenToLoc(tree, last_token).end],
                .insertText = tree.tokenSlice(param.name_token.?),
                .insertTextFormat = .PlainText,
            });
        },
        .pointer_payload => |payload| {
            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(payload.name),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.name),
                .insertTextFormat = .PlainText,
            });
        },
        .array_payload => |payload| {
            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(payload.identifier),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.identifier),
                .insertTextFormat = .PlainText,
            });
        },
        .array_index => |payload| {
            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(payload),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload),
                .insertTextFormat = .PlainText,
            });
        },
        .switch_payload => |payload| {
            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(payload.node),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.node),
                .insertTextFormat = .PlainText,
            });
        },
        .label_decl => |label_decl| {
            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(label_decl),
                .kind = .Variable,
                .insertText = tree.tokenSlice(label_decl),
                .insertTextFormat = .PlainText,
            });
        },
    }
}

fn completeLabel(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .orig_handle = handle,
    };
    try analysis.iterateLabels(handle, pos_index, declToCompletion, context);
    sortCompletionItems(completions.items, server.arena.allocator());
    truncateCompletions(completions.items, server.config.max_detail_length);

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn populateBuiltinCompletions(builtin_completions: *std.ArrayListUnmanaged(types.CompletionItem), config: Config) !void {
    for (data.builtins) |builtin| {
        const insert_text = if (config.enable_snippets) builtin.snippet else builtin.name;
        builtin_completions.appendAssumeCapacity(.{
            .label = builtin.name,
            .kind = .Function,
            .filterText = builtin.name[1..],
            .detail = builtin.signature,
            .insertText = if (config.include_at_in_builtins) insert_text else insert_text[1..],
            .insertTextFormat = if (config.enable_snippets) .Snippet else .PlainText,
            .documentation = .{
                .kind = .Markdown,
                .value = builtin.documentation,
            },
        });
    }

    truncateCompletions(builtin_completions.items, config.max_detail_length);
}

fn completeBuiltin(server: *Server, writer: anytype, id: types.RequestId) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.builtin_completions == null) {
        server.builtin_completions = try std.ArrayListUnmanaged(types.CompletionItem).initCapacity(server.allocator, data.builtins.len);
        try populateBuiltinCompletions(&server.builtin_completions.?, server.config);
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = server.builtin_completions.?.items,
            },
        },
    });
}

fn completeGlobal(server: *Server, writer: anytype, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&server.document_store, &server.arena, handle, pos_index, declToCompletion, context);
    sortCompletionItems(completions.items, server.arena.allocator());
    truncateCompletions(completions.items, server.config.max_detail_length);

    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailledLabel(item, server.arena.allocator());
        }
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(server: *Server, writer: anytype, id: types.RequestId, handle: *DocumentStore.Handle, source_index: usize, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    var held_range = handle.document.borrowNullTerminatedSlice(loc.start, loc.end);
    defer held_range.release();
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    if (try analysis.getFieldAccessType(&server.document_store, &server.arena, handle, source_index, &tokenizer)) |result| {
        try server.typeToCompletion(&completions, result, handle);
        sortCompletionItems(completions.items, server.arena.allocator());
        truncateCompletions(completions.items, server.config.max_detail_length);
        if (server.client_capabilities.label_details_support) {
            for (completions.items) |*item| {
                try formatDetailledLabel(item, server.arena.allocator());
            }
        }
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn formatDetailledLabel(item: *types.CompletionItem, alloc: std.mem.Allocator) !void {
    // NOTE: this is not ideal, we should build a detailled label like we do for label/detail
    // because this implementation is very loose, nothing is formated properly so we need to clean
    // things a little bit, wich is quite messy
    // but it works, it provide decent results

    if (item.detail == null)
        return;

    var detailLen: usize = item.detail.?.len;
    var it: []u8 = try alloc.alloc(u8, detailLen);

    detailLen -= std.mem.replace(u8, item.detail.?, "    ", " ", it) * 3;
    it = it[0..detailLen];

    // HACK: for enums 'MyEnum.', item.detail shows everything, we don't want that
    const isValue = std.mem.startsWith(u8, item.label, it);

    const isVar = std.mem.startsWith(u8, it, "var ");
    const isConst = std.mem.startsWith(u8, it, "const ");

    // we don't want the entire content of things, see the NOTE above
    if (std.mem.indexOf(u8, it, "{")) |end| {
        it = it[0..end];
    }
    if (std.mem.indexOf(u8, it, "}")) |end| {
        it = it[0..end];
    }
    if (std.mem.indexOf(u8, it, ";")) |end| {
        it = it[0..end];
    }

    // loggerger.info("## label: {s} it: {s} kind: {} isValue: {}", .{item.label, it, item.kind, isValue});

    if (std.mem.startsWith(u8, it, "fn ")) {
        var s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        var e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
        if (e < s) {
            log.warn("something wrong when trying to build label detail for {s} kind: {}", .{ it, item.kind });
            return;
        }

        item.detail = item.label;
        item.labelDetails = .{ .detail = it[s .. e + 1], .description = it[e + 1 ..] };

        if (item.kind == .Constant) {
            if (std.mem.indexOf(u8, it, "= struct")) |_| {
                item.labelDetails.?.description = "struct";
            } else if (std.mem.indexOf(u8, it, "= union")) |_| {
                var us: usize = std.mem.indexOf(u8, it, "(") orelse return;
                var ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
                if (ue < us) {
                    log.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                    return;
                }

                item.labelDetails.?.description = it[us - 5 .. ue + 1];
            }
        }
    } else if ((item.kind == .Variable or item.kind == .Constant) and (isVar or isConst)) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;

        const eqlPos = std.mem.indexOf(u8, it, "=");

        if (std.mem.indexOf(u8, it, ":")) |start| {
            if (eqlPos != null) {
                if (start > eqlPos.?) return;
            }
            var e: usize = eqlPos orelse it.len;
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 1 .. e], // right
            };
        } else if (std.mem.indexOf(u8, it, "= .")) |start| {
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 2 .. it.len], // right
            };
        } else if (eqlPos) |start| {
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 2 .. it.len], // right
            };
        }
    } else if (item.kind == .Variable) {
        var s: usize = std.mem.indexOf(u8, it, ":") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse return;

        if (e < s) {
            log.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // loggerger.info("s: {} -> {}", .{s, e});
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it[s + 1 .. e], // right
        };
    } else if (std.mem.indexOf(u8, it, "@import") != null) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it, // right
        };
    } else if (item.kind == .Constant or item.kind == .Field) {
        var s: usize = std.mem.indexOf(u8, it, " ") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse it.len;
        if (e < s) {
            log.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // loggerger.info("s: {} -> {}", .{s, e});
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it[s + 1 .. e], // right
        };

        if (std.mem.indexOf(u8, it, "= union(")) |_| {
            var us: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ue < us) {
                log.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[us - 5 .. ue + 1];
        } else if (std.mem.indexOf(u8, it, "= enum(")) |_| {
            var es: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ee: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ee < es) {
                log.warn("something wrong when trying to build label detail for a .Constant|enum {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[es - 4 .. ee + 1];
        } else if (std.mem.indexOf(u8, it, "= struct")) |_| {
            item.labelDetails.?.description = "struct";
        } else if (std.mem.indexOf(u8, it, "= union")) |_| {
            item.labelDetails.?.description = "union";
        } else if (std.mem.indexOf(u8, it, "= enum")) |_| {
            item.labelDetails.?.description = "enum";
        }
    } else if (item.kind == .Field and isValue) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = item.label, // right
        };
    } else {
        // TODO: if something is missing, it neecs to be implemented here
    }

    // if (item.labelDetails != null)
    //     logger.info("labelDetails: {s}  ::  {s}", .{item.labelDetails.?.detail, item.labelDetails.?.description});
}

fn completeError(server: *Server, writer: anytype, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = try server.document_store.errorCompletionItems(&server.arena, handle);

    truncateCompletions(completions, server.config.max_detail_length);
    log.debug("Completing error:", .{});

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
            },
        },
    });
}

fn kindToSortScore(kind: types.CompletionItem.Kind) []const u8 {
    return switch (kind) {
        .Constant => "1_",

        .Variable => "2_",
        .Field => "3_",
        .Function => "4_",

        .Keyword, .EnumMember => "5_",

        .Class,
        .Interface,
        .Struct,
        // Union?
        .TypeParameter,
        => "6_",

        else => "9_",
    };
}

fn sortCompletionItems(completions: []types.CompletionItem, alloc: std.mem.Allocator) void {
    // TODO: config for sorting rule?
    for (completions) |*c| {
        c.sortText = kindToSortScore(c.kind);

        if (alloc.alloc(u8, 2 + c.label.len)) |it| {
            std.mem.copy(u8, it, c.sortText.?);
            std.mem.copy(u8, it[2..], c.label);
            c.sortText = it;
        } else |_| {}
    }
}

fn completeDot(server: *Server, writer: anytype, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = try server.document_store.enumCompletionItems(&server.arena, handle);
    sortCompletionItems(completions, server.arena.allocator());
    truncateCompletions(completions, server.config.max_detail_length);

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
            },
        },
    });
}

fn documentSymbol(server: *Server, writer: anytype, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{ .DocumentSymbols = try analysis.getDocumentSymbols(server.arena.allocator(), handle.tree, server.offset_encoding) },
    });
}

fn initializeHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Initialize) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if(req.params.capabilities.general) |general| {
        var supports_utf8 = false;
        var supports_utf16 = false;
        var supports_utf32 = false;
        for(general.positionEncodings.value) |encoding| {
            if (std.mem.eql(u8, encoding, "utf-8")) {
                supports_utf8 = true;
            } else if(std.mem.eql(u8, encoding, "utf-16")) {
                supports_utf16 = true;
            } else if(std.mem.eql(u8, encoding, "utf-32")) {
                supports_utf32 = true;
            }
        }

        if(supports_utf8) {
            server.offset_encoding = .utf8;
        } else if(supports_utf32) {
            server.offset_encoding = .utf32;
        } else {
            server.offset_encoding = .utf16;
        }
    }

    if (req.params.capabilities.textDocument) |textDocument| {
        server.client_capabilities.supports_semantic_tokens = textDocument.semanticTokens.exists;
        server.client_capabilities.supports_inlay_hints = textDocument.inlayHint.exists;
        if (textDocument.hover) |hover| {
            for (hover.contentFormat.value) |format| {
                if (std.mem.eql(u8, "markdown", format)) {
                    server.client_capabilities.hover_supports_md = true;
                }
            }
        }
        if (textDocument.completion) |completion| {
            if (completion.completionItem) |completionItem| {
                server.client_capabilities.label_details_support = completionItem.labelDetailsSupport.value;
                server.client_capabilities.supports_snippets = completionItem.snippetSupport.value;
                for (completionItem.documentationFormat.value) |documentationFormat| {
                    if (std.mem.eql(u8, "markdown", documentationFormat)) {
                        server.client_capabilities.completion_doc_supports_md = true;
                    }
                }
            }
        }
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .InitializeResult = .{
                .offsetEncoding = server.offset_encoding,
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
                    .completionProvider = .{ .resolveProvider = false, .triggerCharacters = &[_][]const u8{ ".", ":", "@", "]" }, .completionItem = .{ .labelDetailsSupport = true } },
                    .documentHighlightProvider = true,
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
                    .inlayHintProvider = true,
                },
            },
        },
    });

    if (req.params.capabilities.workspace) |workspace| {
        server.client_capabilities.supports_configuration = workspace.configuration.value;
        if (workspace.didChangeConfiguration != null and workspace.didChangeConfiguration.?.dynamicRegistration.value) {
            try server.registerCapability(writer, "workspace/didChangeConfiguration");
        }
    }

    log.info("zls initialized", .{});
    log.info("{}", .{server.client_capabilities});
    log.info("Using offset encoding: {s}", .{std.meta.tagName(server.offset_encoding)});
}

fn registerCapability(server: *Server, writer: anytype, method: []const u8) !void {
    // NOTE: stage1 moment occurs if we dont do it like this :(
    // long live stage2's not broken anon structs

    log.debug("Dynamically registering method '{s}'", .{method});

    const id = try std.fmt.allocPrint(server.arena.allocator(), "register-{s}", .{method});
    const reg = types.RegistrationParams.Registration{
        .id = id,
        .method = method,
    };
    const registrations = [1]types.RegistrationParams.Registration{reg};
    const params = types.RegistrationParams{
        .registrations = &registrations,
    };

    const respp = types.ResponseParams{
        .RegistrationParams = params,
    };

    const req = types.Request{
        .id = .{ .String = id },
        .method = "client/registerCapability",
        .params = respp,
    };

    try send(writer, server.arena.allocator(), req);
}

fn requestConfiguration(server: *Server, writer: anytype) !void {
    const configuration_items = comptime confi: {
        var comp_confi: [std.meta.fields(Config).len]types.ConfigurationParams.ConfigurationItem = undefined;
        inline for (std.meta.fields(Config)) |field, index| {
            comp_confi[index] = .{
                .section = "zls." ++ field.name,
            };
        }

        break :confi comp_confi;
    };

    try send(writer, server.arena.allocator(), types.Request{
        .id = .{ .String = "i_haz_configuration" },
        .method = "workspace/configuration",
        .params = .{
            .ConfigurationParams = .{
                .items = &configuration_items,
            },
        },
    });
}

fn initializedHandler(server: *Server, writer: anytype, id: types.RequestId) !void {
    _ = id;

    if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration(writer);
}

fn shutdownHandler(server: *Server, writer: anytype, id: types.RequestId) !void {
    log.info("Server closing...", .{});

    server.keep_running = false;
    // Technically we should deinitialize first and send possible errors to the client
    try respondGeneric(writer, id, null_result_response);
}

fn openDocumentHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.OpenDocument) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = try server.document_store.openDocument(req.params.textDocument.uri, req.params.textDocument.text);
    try server.publishDiagnostics(writer, handle.*);

    if (server.client_capabilities.supports_semantic_tokens) {
        const request: requests.SemanticTokensFull = .{ .params = .{ .textDocument = .{ .uri = req.params.textDocument.uri } } };
        try server.semanticTokensFullHandler(writer, id, request);
    }
}

fn changeDocumentHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.ChangeDocument) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.debug("Trying to change non existent document {s}", .{req.params.textDocument.uri});
        return;
    };

    try server.document_store.applyChanges(handle, req.params.contentChanges.Array, server.offset_encoding);
    try server.publishDiagnostics(writer, handle.*);
}

fn saveDocumentHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.SaveDocument) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;
    _ = writer;

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to save non existent document {s}", .{req.params.textDocument.uri});
        return;
    };
    try server.document_store.applySave(handle);
}

fn closeDocumentHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.CloseDocument) error{}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;
    _ = writer;
    server.document_store.closeDocument(req.params.textDocument.uri);
}

fn semanticTokensFullHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.SemanticTokensFull) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.enable_semantic_tokens) blk: {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            log.warn("Trying to get semantic tokens of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const token_array = try semantic_tokens.writeAllSemanticTokens(&server.arena, &server.document_store, handle, server.offset_encoding);
        defer server.allocator.free(token_array);

        return try send(writer, server.arena.allocator(), types.Response{
            .id = id,
            .result = .{ .SemanticTokensFull = .{ .data = token_array } },
        });
    }
    return try respondGeneric(writer, id, no_semantic_tokens_response);
}

fn completionHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Completion) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to complete in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, no_completions_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(writer, id, no_completions_response);

    const source_index = offsets.positionToIndex(handle.document.text, req.params.position, server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.document, source_index);

    switch (pos_context) {
        .builtin => try server.completeBuiltin(writer, id),
        .var_access, .empty => try server.completeGlobal(writer, id, source_index, handle),
        .field_access => |loc| try server.completeFieldAccess(writer, id, handle, source_index, loc),
        .global_error_set => try server.completeError(writer, id, handle),
        .enum_literal => try server.completeDot(writer, id, handle),
        .label => try server.completeLabel(writer, id, source_index, handle),
        .import_string_literal, .embedfile_string_literal => |loc| {
            if (!server.config.enable_import_embedfile_argument_completions)
                return try respondGeneric(writer, id, no_completions_response);

            const completing = offsets.locToSlice(handle.tree.source, loc);

            var subpath_present = false;
            var fsl_completions = std.ArrayListUnmanaged(types.CompletionItem){};

            fsc: {
                var document_path = try uri_utils.parse(server.arena.allocator(), handle.uri());
                var document_dir_path = std.fs.openIterableDirAbsolute(std.fs.path.dirname(document_path) orelse break :fsc, .{}) catch break :fsc;
                defer document_dir_path.close();

                if (std.mem.lastIndexOfScalar(u8, completing, '/')) |subpath_index| {
                    var subpath = completing[0..subpath_index];

                    if (std.mem.startsWith(u8, subpath, "./") and subpath_index > 2) {
                        subpath = completing[2..subpath_index];
                    } else if (std.mem.startsWith(u8, subpath, ".") and subpath_index > 1) {
                        subpath = completing[1..subpath_index];
                    }

                    var old = document_dir_path;
                    document_dir_path = document_dir_path.dir.openIterableDir(subpath, .{}) catch break :fsc // NOTE: Is this even safe lol?
                    old.close();

                    subpath_present = true;
                }

                var dir_iterator = document_dir_path.iterate();
                while (try dir_iterator.next()) |entry| {
                    if (std.mem.startsWith(u8, entry.name, ".")) continue;
                    if (entry.kind == .File and pos_context == .import_string_literal and !std.mem.endsWith(u8, entry.name, ".zig")) continue;

                    const l = try server.arena.allocator().dupe(u8, entry.name);
                    try fsl_completions.append(server.arena.allocator(), types.CompletionItem{
                        .label = l,
                        .insertText = l,
                        .kind = if (entry.kind == .File) .File else .Folder,
                    });
                }
            }

            if (!subpath_present and pos_context == .import_string_literal) {
                if (handle.associated_build_file) |bf| {
                    try fsl_completions.ensureUnusedCapacity(server.arena.allocator(), bf.config.packages.len);

                    for (bf.config.packages) |pkg| {
                        try fsl_completions.append(server.arena.allocator(), .{
                            .label = pkg.name,
                            .kind = .Module,
                        });
                    }
                }
            }

            truncateCompletions(fsl_completions.items, server.config.max_detail_length);

            try send(writer, server.arena.allocator(), types.Response{
                .id = id,
                .result = .{
                    .CompletionList = .{
                        .isIncomplete = false,
                        .items = fsl_completions.items,
                    },
                },
            });
        },
        else => try respondGeneric(writer, id, no_completions_response),
    }
}

fn signatureHelpHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.SignatureHelp) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const getSignatureInfo = @import("signature_help.zig").getSignatureInfo;
    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to get signature help in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, no_signatures_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(writer, id, no_signatures_response);

    const source_index = offsets.positionToIndex(handle.document.text, req.params.position, server.offset_encoding);
    if (try getSignatureInfo(
        &server.document_store,
        &server.arena,
        handle,
        source_index,
        data,
    )) |sig_info| {
        return try send(writer, server.arena.allocator(), types.Response{
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
    return try respondGeneric(writer, id, no_signatures_response);
}

fn gotoHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.GotoDefinition, resolve_alias: bool) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to go to definition in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const source_index = offsets.positionToIndex(handle.document.text, req.params.position, server.offset_encoding);
        const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.document, source_index);

        switch (pos_context) {
            .var_access => try server.gotoDefinitionGlobal(writer, id, source_index, handle, resolve_alias),
            .field_access => |loc| try server.gotoDefinitionFieldAccess(writer, id, handle, source_index, loc, resolve_alias),
            .import_string_literal => try server.gotoDefinitionString(writer, id, source_index, handle),
            .label => try server.gotoDefinitionLabel(writer, id, source_index, handle),
            else => try respondGeneric(writer, id, null_result_response),
        }
    } else {
        try respondGeneric(writer, id, null_result_response);
    }
}

fn gotoDefinitionHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.GotoDefinition) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try server.gotoHandler(writer, id, req, true);
}

fn gotoDeclarationHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.GotoDeclaration) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try server.gotoHandler(writer, id, req, false);
}

fn hoverHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Hover) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to get hover in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const source_index = offsets.positionToIndex(handle.document.text, req.params.position, server.offset_encoding);
        const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.document, source_index);
        switch (pos_context) {
            .builtin => try server.hoverDefinitionBuiltin(writer, id, source_index, handle),
            .var_access => try server.hoverDefinitionGlobal(writer, id, source_index, handle),
            .field_access => |loc| try server.hoverDefinitionFieldAccess(writer, id, handle, source_index, loc),
            .label => try server.hoverDefinitionLabel(writer, id, source_index, handle),
            else => try respondGeneric(writer, id, null_result_response),
        }
    } else {
        try respondGeneric(writer, id, null_result_response);
    }
}

fn documentSymbolsHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.DocumentSymbols) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        log.warn("Trying to get document symbols in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };
    try server.documentSymbol(writer, id, handle);
}

fn formattingHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Formatting) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.zig_exe_path) |zig_exe_path| {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            log.warn("Trying to got to definition in non existent document {s}", .{req.params.textDocument.uri});
            return try respondGeneric(writer, id, null_result_response);
        };

        var process = std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, server.allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;

        process.spawn() catch |err| {
            log.warn("Failed to spawn zig fmt process, error: {}", .{err});
            return try respondGeneric(writer, id, null_result_response);
        };
        try process.stdin.?.writeAll(handle.document.text);
        process.stdin.?.close();
        process.stdin = null;

        const stdout_bytes = try process.stdout.?.reader().readAllAlloc(server.allocator, std.math.maxInt(usize));
        defer server.allocator.free(stdout_bytes);

        switch (try process.wait()) {
            .Exited => |code| if (code == 0) {
                if (std.mem.eql(u8, handle.document.text, stdout_bytes)) return try respondGeneric(writer, id, null_result_response);

                var edits = diff.edits(server.allocator, handle.document.text, stdout_bytes) catch {
                    const range = offsets.locToRange(handle.document.text, .{ .start = 0, .end = handle.document.text.len }, server.offset_encoding);
                    // If there was an error trying to diff the text, return the formatted response
                    // as the new text for the entire range of the document
                    return try send(writer, server.arena.allocator(), types.Response{
                        .id = id,
                        .result = .{
                            .TextEdits = &[1]types.TextEdit{
                                .{
                                    .range = range,
                                    .newText = stdout_bytes,
                                },
                            },
                        },
                    });
                };
                defer {
                    for (edits.items) |item| item.newText.deinit();
                    edits.deinit();
                }

                // Convert from `[]diff.Edit` to `[]types.TextEdit`
                var text_edits = try std
                    .ArrayList(types.TextEdit)
                    .initCapacity(server.allocator, edits.items.len);
                defer text_edits.deinit();
                for (edits.items) |edit| {
                    try text_edits.append(.{
                        .range = edit.range,
                        .newText = edit.newText.items,
                    });
                }

                return try send(
                    writer,
                    server.arena.allocator(),
                    types.Response{
                        .id = id,
                        .result = .{ .TextEdits = text_edits.items },
                    },
                );
            },
            else => {},
        }
    }
    return try respondGeneric(writer, id, null_result_response);
}

fn didChangeConfigurationHandler(server: *Server, writer: anytype, id: types.RequestId, maybe_req: std.json.Value) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;
    if (maybe_req.Object.get("params").?.Object.get("settings").? == .Object) {
        const req = try requests.fromDynamicTree(&server.arena, requests.Configuration, maybe_req);
        inline for (std.meta.fields(Config)) |field| {
            if (@field(req.params.settings, field.name)) |value| {
                log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, value });
                @field(server.config, field.name) = if (@TypeOf(value) == []const u8) try server.allocator.dupe(u8, value) else value;
            }
        }

        try server.configChanged(null);
    } else if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration(writer);
}

fn renameHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Rename) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try generalReferencesHandler(server, writer, id, .{ .rename = req });
}

fn referencesHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.References) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try generalReferencesHandler(server, writer, id, .{ .references = req });
}

fn documentHighlightHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.DocumentHighlight) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try generalReferencesHandler(server, writer, id, .{ .highlight = req });
}

const GeneralReferencesRequest = union(enum) {
    rename: requests.Rename,
    references: requests.References,
    highlight: requests.DocumentHighlight,

    pub fn uri(self: @This()) []const u8 {
        return switch (self) {
            .rename => |rename| rename.params.textDocument.uri,
            .references => |ref| ref.params.textDocument.uri,
            .highlight => |highlight| highlight.params.textDocument.uri,
        };
    }

    pub fn position(self: @This()) types.Position {
        return switch (self) {
            .rename => |rename| rename.params.position,
            .references => |ref| ref.params.position,
            .highlight => |highlight| highlight.params.position,
        };
    }

    pub fn name(self: @This()) []const u8 {
        return switch (self) {
            .rename => "rename",
            .references => "references",
            .highlight => "highlight references",
        };
    }
};

fn generalReferencesHandler(server: *Server, writer: anytype, id: types.RequestId, req: GeneralReferencesRequest) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();

    const handle = server.document_store.getHandle(req.uri()) orelse {
        log.warn("Trying to get {s} in non existent document {s}", .{ req.name(), req.uri() });
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.position().character <= 0) return try respondGeneric(writer, id, null_result_response);

    const source_index = offsets.positionToIndex(handle.document.text, req.position(), server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.document, source_index);

    const decl = switch (pos_context) {
        .var_access => try server.getSymbolGlobal(source_index, handle),
        .field_access => |range| try server.getSymbolFieldAccess(handle, source_index, range),
        .label => try getLabelGlobal(source_index, handle),
        else => null,
    } orelse return try respondGeneric(writer, id, null_result_response);

    const include_decl = switch (req) {
        .references => |ref| ref.params.context.includeDeclaration,
        else => true,
    };

    const locations = if (pos_context == .label)
        try references.labelReferences(allocator, decl, server.offset_encoding, include_decl)
    else
        try references.symbolReferences(
            &server.arena,
            &server.document_store,
            decl,
            server.offset_encoding,
            include_decl,
            server.config.skip_std_references,
            req != .highlight, // scan the entire workspace except for highlight
        );

    const result: types.ResponseParams = switch (req) {
        .rename => |rename| blk: {
            var edits: types.WorkspaceEdit = .{ .changes = .{} };
            for (locations.items) |loc| {
                const gop = try edits.changes.getOrPutValue(allocator, loc.uri, .{});
                try gop.value_ptr.append(allocator, .{
                    .range = loc.range,
                    .newText = rename.params.newName,
                });
            }
            break :blk .{ .WorkspaceEdit = edits };
        },
        .references => .{ .Locations = locations.items },
        .highlight => blk: {
            var highlights = try std.ArrayListUnmanaged(types.DocumentHighlight).initCapacity(allocator, locations.items.len);
            const uri = handle.uri();
            for (locations.items) |loc| {
                if (!std.mem.eql(u8, loc.uri, uri)) continue;
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
            break :blk .{ .DocumentHighlight = highlights.items };
        },
    };

    try send(writer, allocator, types.Response{
        .id = id,
        .result = result,
    });
}

fn isPositionBefore(lhs: types.Position, rhs: types.Position) bool {
    if (lhs.line == rhs.line) {
        return lhs.character < rhs.character;
    } else {
        return lhs.line < rhs.line;
    }
}

fn inlayHintHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.InlayHint) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.enable_inlay_hints) blk: {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            log.warn("Trying to get inlay hint of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const hover_kind: types.MarkupContent.Kind = if (server.client_capabilities.hover_supports_md) .Markdown else .PlainText;

        // TODO cache hints per document
        // because the function could be stored in a different document
        // we need the regenerate hints when the document itself or its imported documents change
        // with caching it would also make sense to generate all hints instead of only the visible ones
        const hints = try inlay_hints.writeRangeInlayHint(
            &server.arena,
            &server.config,
            &server.document_store,
            handle,
            req.params.range,
            hover_kind,
            server.offset_encoding,
        );
        defer {
            for (hints) |hint| {
                server.allocator.free(hint.tooltip.value);
            }
            server.allocator.free(hints);
        }

        // and only convert and return all hints in range for every request
        var visible_hints = hints;

        // small_hints should roughly be sorted by position
        for (hints) |hint, i| {
            if (isPositionBefore(hint.position, req.params.range.start)) continue;
            visible_hints = hints[i..];
            break;
        }
        for (visible_hints) |hint, i| {
            if (isPositionBefore(hint.position, req.params.range.end)) continue;
            visible_hints = visible_hints[0..i];
            break;
        }

        return try send(writer, server.arena.allocator(), types.Response{
            .id = id,
            .result = .{ .InlayHint = visible_hints },
        });
    }
    return try respondGeneric(writer, id, null_result_response);
}

// Needed for the hack seen below.
fn extractErr(val: anytype) anyerror {
    val catch |e| return e;
    return error.HackDone;
}

pub fn processJsonRpc(server: *Server, writer: anytype, json: []const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    server.arena = std.heap.ArenaAllocator.init(server.allocator);
    defer server.arena.deinit();

    var parser = std.json.Parser.init(server.arena.allocator(), false);
    defer parser.deinit();

    var tree = try parser.parse(json);
    defer tree.deinit();

    const id = if (tree.root.Object.get("id")) |id| switch (id) {
        .Integer => |int| types.RequestId{ .Integer = int },
        .String => |str| types.RequestId{ .String = str },
        else => types.RequestId{ .Integer = 0 },
    } else types.RequestId{ .Integer = 0 };

    if (id == .String and std.mem.startsWith(u8, id.String, "register"))
        return;
    if (id == .String and std.mem.eql(u8, id.String, "i_haz_configuration")) {
        log.info("Setting configuration...", .{});

        // NOTE: Does this work with other editors?
        // Yes, String ids are officially supported by LSP
        // but not sure how standard this "standard" really is

        const result = tree.root.Object.get("result").?.Array;

        inline for (std.meta.fields(Config)) |field, index| {
            const value = result.items[index];
            const ft = if (@typeInfo(field.field_type) == .Optional)
                @typeInfo(field.field_type).Optional.child
            else
                field.field_type;
            const ti = @typeInfo(ft);

            if (value != .Null) {
                const new_value: field.field_type = switch (ft) {
                    []const u8 => switch (value) {
                        .String => |s| blk: {
                            var nv = try server.allocator.dupe(u8, s);
                            if (@field(server.config, field.name)) |prev_val| server.allocator.free(prev_val);
                            break :blk nv;
                        }, // TODO: Allocation model? (same with didChangeConfiguration); imo this isn't *that* bad but still
                        else => @panic("Invalid configuration value"), // TODO: Handle this
                    },
                    else => switch (ti) {
                        .Int => switch (value) {
                            .Integer => |s| std.math.cast(ft, s) orelse @panic("Invalid configuration value"),
                            else => @panic("Invalid configuration value"), // TODO: Handle this
                        },
                        .Bool => switch (value) {
                            .Bool => |b| b,
                            else => @panic("Invalid configuration value"), // TODO: Handle this
                        },
                        else => @compileError("Not implemented for " ++ @typeName(ft)),
                    },
                };
                log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, new_value });
                @field(server.config, field.name) = new_value;
            }
        }

        try server.configChanged(null);

        return;
    }

    const method = tree.root.Object.get("method").?.String;

    const start_time = std.time.milliTimestamp();
    defer {
        // makes `zig build test` look nice
        if (!zig_builtin.is_test and !std.mem.eql(u8, method, "shutdown")) {
            const end_time = std.time.milliTimestamp();
            log.debug("Took {}ms to process method {s}", .{ end_time - start_time, method });
        }
    }

    const method_map = .{
        .{ "initialized", void, initializedHandler },
        .{"$/cancelRequest"},
        .{"textDocument/willSave"},
        .{ "initialize", requests.Initialize, initializeHandler },
        .{ "shutdown", void, shutdownHandler },
        .{ "textDocument/didOpen", requests.OpenDocument, openDocumentHandler },
        .{ "textDocument/didChange", requests.ChangeDocument, changeDocumentHandler },
        .{ "textDocument/didSave", requests.SaveDocument, saveDocumentHandler },
        .{ "textDocument/didClose", requests.CloseDocument, closeDocumentHandler },
        .{ "textDocument/semanticTokens/full", requests.SemanticTokensFull, semanticTokensFullHandler },
        .{ "textDocument/inlayHint", requests.InlayHint, inlayHintHandler },
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
        .{ "textDocument/documentHighlight", requests.DocumentHighlight, documentHighlightHandler },
        .{ "workspace/didChangeConfiguration", std.json.Value, didChangeConfigurationHandler },
    };

    // Hack to avoid `return`ing in the inline for, which causes bugs.
    // TODO: Change once stage2 is shipped and more stable?
    var done: ?anyerror = null;
    inline for (method_map) |method_info| {
        if (done == null and std.mem.eql(u8, method, method_info[0])) {
            if (method_info.len == 1) {
                log.warn("method not mapped: {s}", .{method});
                done = error.HackDone;
            } else if (method_info[1] != void) {
                const ReqT = method_info[1];
                if (requests.fromDynamicTree(&server.arena, ReqT, tree.root)) |request_obj| {
                    done = error.HackDone;
                    done = extractErr(method_info[2](server, writer, id, request_obj));
                } else |err| {
                    if (err == error.MalformedJson) {
                        log.warn("Could not create request type {s} from JSON {s}", .{ @typeName(ReqT), json });
                    }
                    done = err;
                }
            } else {
                done = error.HackDone;
                (method_info[2])(server, writer, id) catch |err| {
                    done = err;
                };
            }
        }
    }
    if (done) |err| switch (err) {
        error.MalformedJson => return try respondGeneric(writer, id, null_result_response),
        error.HackDone => return,
        else => return err,
    };

    // Boolean value is true if the method is a request (and thus the client
    // needs a response) or false if the method is a notification (in which
    // case it should be silently ignored)
    const unimplemented_map = std.ComptimeStringMap(bool, .{
        .{ "textDocument/codeAction", true },
        .{ "textDocument/codeLens", true },
        .{ "textDocument/documentLink", true },
        .{ "textDocument/rangeFormatting", true },
        .{ "textDocument/onTypeFormatting", true },
        .{ "textDocument/prepareRename", true },
        .{ "textDocument/foldingRange", true },
        .{ "textDocument/selectionRange", true },
        .{ "textDocument/semanticTokens/range", true },
        .{ "workspace/didChangeWorkspaceFolders", false },
    });

    if (unimplemented_map.get(method)) |request| {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        if (request) {
            return try respondGeneric(writer, id, null_result_response);
        }

        log.debug("Notification method {s} is not implemented", .{method});
        return;
    }
    if (tree.root.Object.get("id")) |_| {
        return try respondGeneric(writer, id, not_implemented_response);
    }
    log.debug("Method without return value not implemented: {s}", .{method});
}

pub fn configChanged(server: *Server, builtin_creation_dir: ?[]const u8) !void {
    try server.config.configChanged(server.allocator, builtin_creation_dir);
    server.document_store.config = server.config;
}

pub fn init(
    allocator: std.mem.Allocator,
    config: Config,
    config_path: ?[]const u8,
) !Server {
    // TODO replace global with something like an Analyser struct
    // which contains using_trail & resolve_trail and place it inside Server
    // see: https://github.com/zigtools/zls/issues/536
    analysis.init(allocator);

    var cfg = config;

    try cfg.configChanged(allocator, config_path);

    return Server{
        .config = cfg,
        .allocator = allocator,
        .document_store = try DocumentStore.init(allocator, cfg),
    };
}

pub fn deinit(server: *Server) void {
    server.document_store.deinit();
    analysis.deinit();

    const config_parse_options = std.json.ParseOptions{ .allocator = server.allocator };
    defer std.json.parseFree(Config, server.config, config_parse_options);

    if (server.builtin_completions) |*compls| {
        compls.deinit(server.allocator);
    }
}
