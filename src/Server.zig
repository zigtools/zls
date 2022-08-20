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
const rename = @import("rename.zig");
const offsets = @import("offsets.zig");
const semantic_tokens = @import("semantic_tokens.zig");
const inlay_hints = @import("inlay_hints.zig");
const shared = @import("shared.zig");
const Ast = std.zig.Ast;
const tracy = @import("tracy.zig");
const uri_utils = @import("uri.zig");
const data = @import("data/data.zig");

// Server fields

config: Config,
allocator: std.mem.Allocator = undefined,
arena: std.heap.ArenaAllocator = undefined,
document_store: DocumentStore = undefined,
client_capabilities: ClientCapabilities = .{},
offset_encoding: offsets.Encoding = .utf16,
keep_running: bool = true,
log_level: std.log.Level,

pub const Logger = struct {
    pub fn err(server: *Server, writer: anytype, comptime format: []const u8, args: anytype) void {
        @setCold(true);
        log(server, writer, .err, format, args);
    }
    pub fn warn(server: *Server, writer: anytype, comptime format: []const u8, args: anytype) void {
        log(server, writer, .warn, format, args);
    }
    pub fn info(server: *Server, writer: anytype, comptime format: []const u8, args: anytype) void {
        log(server, writer, .info, format, args);
    }
    pub fn debug(server: *Server, writer: anytype, comptime format: []const u8, args: anytype) void {
        log(server, writer, .debug, format, args);
    }
};

fn log(server: *Server, writer: anytype, comptime message_level: std.log.Level, comptime format: []const u8, args: anytype) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const scope = .Server;

    if (@enumToInt(message_level) > @enumToInt(server.log_level)) {
        return;
    }
    // After shutdown, pipe output to stderr
    if (!server.keep_running) {
        std.debug.print("[{?s}-{?s}] " ++ format ++ "\n", .{ @tagName(message_level), @tagName(scope) } ++ args);
        return;
    }

    var message = std.fmt.allocPrint(server.allocator, "[{?s}-{?s}] " ++ format, .{ @tagName(message_level), @tagName(scope) } ++ args) catch {
        std.debug.print("Failed to allocPrint message.\n", .{});
        return;
    };
    defer server.allocator.free(message);

    const message_type: types.MessageType = switch (message_level) {
        .debug => .Log,
        .info => .Info,
        .warn => .Warning,
        .err => .Error,
    };

    send(writer, server.allocator, types.Notification{
        .method = "window/logMessage",
        .params = types.Notification.Params{
            .LogMessage = .{
                .type = message_type,
                .message = message,
            },
        },
    }) catch {
        // TODO: Find a way to handle this error properly
    };
}

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

    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    try std.json.stringify(reqOrRes, .{}, arr.writer());

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

// TODO: Is this correct or can we get a better end?
fn astLocationToRange(loc: Ast.Location) types.Range {
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

fn publishDiagnostics(server: *Server, writer: anytype, handle: DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;

    var diagnostics = std.ArrayList(types.Diagnostic).init(server.arena.allocator());

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
            .message = try server.arena.allocator().dupe(u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (server.config.enable_unused_variable_warnings) {
        scopes: for (handle.document_scope.scopes) |scope| {
            const scope_data = switch (scope.data) {
                .function => |f| b: {
                    if (!ast.fnProtoHasBody(tree, f).?) continue :scopes;
                    break :b f;
                },
                .block => |b| b,
                else => continue,
            };

            var decl_iterator = scope.decls.iterator();
            while (decl_iterator.next()) |decl| {
                var identifier_count: usize = 0;

                const name_token_index = switch (decl.value_ptr.*) {
                    .ast_node => |an| s: {
                        const an_tag = tree.nodes.items(.tag)[an];
                        switch (an_tag) {
                            .simple_var_decl => {
                                break :s tree.nodes.items(.main_token)[an] + 1;
                            },
                            else => continue,
                        }
                    },
                    .param_decl => |param| param.name_token orelse continue,
                    else => continue,
                };

                if (std.mem.eql(u8, tree.tokenSlice(name_token_index), "_"))
                    continue;

                const pit_start = tree.firstToken(scope_data);
                const pit_end = ast.lastToken(tree, scope_data);

                const tags = tree.tokens.items(.tag)[pit_start..pit_end];
                for (tags) |tag, index| {
                    if (tag != .identifier) continue;
                    if (!std.mem.eql(u8, tree.tokenSlice(pit_start + @intCast(u32, index)), tree.tokenSlice(name_token_index))) continue;
                    if (index -| 1 > 0 and tags[index - 1] == .period) continue;
                    if (index +| 2 < tags.len and tags[index + 1] == .colon) switch (tags[index + 2]) {
                        .l_brace,
                        .keyword_inline,
                        .keyword_while,
                        .keyword_for,
                        .keyword_switch,
                        => continue,
                        else => {},
                    };
                    if (index -| 2 > 0 and tags[index - 1] == .colon) switch (tags[index - 2]) {
                        .keyword_break,
                        .keyword_continue,
                        => continue,
                        else => {},
                    };
                    identifier_count += 1;
                }

                if (identifier_count <= 1)
                    try diagnostics.append(.{
                        .range = astLocationToRange(tree.tokenLocation(0, name_token_index)),
                        .severity = .Error,
                        .code = "unused_variable",
                        .source = "zls",
                        .message = "Unused variable; either remove the variable or use '_ = ' on the variable to bypass this error",
                    });
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

                if (std.mem.startsWith(u8, import_str, "\".")) {
                    try diagnostics.append(.{
                        .range = astLocationToRange(tree.tokenLocation(0, import_str_token)),
                        .severity = .Hint,
                        .code = "useless_dot",
                        .source = "zls",
                        .message = "A . or ./ is not needed in imports",
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
                            const loc = tree.tokenLocation(0, name_token);

                            const is_type_function = analysis.isTypeFunction(tree, func);

                            const func_name = tree.tokenSlice(name_token);
                            if (!is_type_function and !analysis.isCamelCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Hint,
                                    .code = "bad_style",
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
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
    list: *std.ArrayList(types.CompletionItem),
    field_access: analysis.FieldAccessReturn,
    orig_handle: *DocumentStore.Handle,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const type_handle = field_access.original;
    switch (type_handle.type.data) {
        .slice => {
            if (!type_handle.type.is_type_val) {
                try list.append(.{
                    .label = "len",
                    .detail = "const len: usize",
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
            if (server.config.operator_completions) {
                try list.append(.{
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
    list: *std.ArrayList(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    unwrapped: ?analysis.TypeWithHandle,
    orig_handle: *DocumentStore.Handle,
    is_type_val: bool,
    parent_is_type_val: ?bool,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
            const field = ast.containerField(tree, node).?;
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
                .detail = "const len: usize",
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

    const location = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analysis.resolveVarDeclAlias(&server.document_store, &server.arena, .{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;
                    break :block result.location(server.offset_encoding) catch return;
                }
            }

            const name_token = analysis.getDeclNameToken(handle.tree, node) orelse
                return try respondGeneric(writer, id, null_result_response);
            break :block offsets.tokenRelativeLocation(handle.tree, 0, handle.tree.tokens.items(.start)[name_token], server.offset_encoding) catch return;
        },
        else => decl_handle.location(server.offset_encoding) catch return,
    };

    try send(writer, server.arena.allocator(), types.Response{
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

    var bound_type_params = analysis.BoundTypeParams.init(server.arena.allocator());
    const resolved_type = try decl_handle.resolveType(&server.document_store, &server.arena, &bound_type_params);

    const resolved_type_str = if (resolved_type) |rt|
        if (rt.type.is_type_val) "type" else switch (rt.type.data) { // TODO: Investigate random weird numbers like 897 that cause index of bounds
            .pointer,
            .slice,
            .error_union,
            .primitive,
            => |p| if (p >= tree.nodes.len) "unknown" else tree.getNodeSource(p),
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
                => tree.getNodeSource(p),
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

    _ = server;

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.hoverSymbol(writer, id, decl);
}

fn getSymbolFieldAccess(
    server: *Server,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(position.absolute_index, handle.*);
    if (name.len == 0) return null;

    const line_mem_start = @ptrToInt(position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
    var held_range = handle.document.borrowNullTerminatedSlice(line_mem_start + range.start, line_mem_start + range.end);
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    errdefer held_range.release();
    if (try analysis.getFieldAccessType(&server.document_store, &server.arena, handle, position.absolute_index, &tokenizer)) |result| {
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
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, position, range)) orelse return try respondGeneric(writer, id, null_result_response);
    return try server.gotoDefinitionSymbol(writer, id, decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, position, range)) orelse return try respondGeneric(writer, id, null_result_response);
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

fn renameDefinitionGlobal(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(server.arena.allocator()),
    };
    try rename.renameSymbol(&server.arena, &server.document_store, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionFieldAccess(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, position, range)) orelse return try respondGeneric(writer, id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(server.arena.allocator()),
    };
    try rename.renameSymbol(&server.arena, &server.document_store, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionLabel(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(server.arena.allocator()),
    };
    try rename.renameLabel(&server.arena, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn referencesDefinitionGlobal(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    var locs = std.ArrayList(types.Location).init(server.arena.allocator());
    try references.symbolReferences(
        &server.arena,
        &server.document_store,
        decl,
        server.offset_encoding,
        include_decl,
        &locs,
        std.ArrayList(types.Location).append,
        server.config.skip_std_references,
        !highlight,
    );

    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(server.arena.allocator(), locs.items.len);
        const uri = handle.uri();
        for (locs.items) |loc| {
            if (std.mem.eql(u8, loc.uri, uri)) {
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = result,
    });
}

fn referencesDefinitionFieldAccess(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, position, range)) orelse return try respondGeneric(writer, id, null_result_response);
    var locs = std.ArrayList(types.Location).init(server.arena.allocator());
    try references.symbolReferences(
        &server.arena,
        &server.document_store,
        decl,
        server.offset_encoding,
        include_decl,
        &locs,
        std.ArrayList(types.Location).append,
        server.config.skip_std_references,
        !highlight,
    );
    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(server.arena.allocator(), locs.items.len);
        const uri = handle.uri();
        for (locs.items) |loc| {
            if (std.mem.eql(u8, loc.uri, uri)) {
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };
    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = result,
    });
}

fn referencesDefinitionLabel(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(writer, id, null_result_response);
    var locs = std.ArrayList(types.Location).init(server.arena.allocator());
    try references.labelReferences(&server.arena, decl, server.offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append);
    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(server.arena.allocator(), locs.items.len);
        const uri = handle.uri();
        for (locs.items) |loc| {
            if (std.mem.eql(u8, loc.uri, uri)) {
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };
    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = result,
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
    completions: *std.ArrayList(types.CompletionItem),
    orig_handle: *DocumentStore.Handle,
    parent_is_type_val: ?bool = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
                    .value = try analysis.collectDocComments(context.server.arena.allocator(), tree, doc_comments, doc_kind, false),
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

fn completeLabel(
    server: *Server,
    writer: anytype,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(server.arena.allocator());

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

var builtin_completions: ?[]types.CompletionItem = null;
fn completeBuiltin(server: *Server, writer: anytype, id: types.RequestId) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (builtin_completions == null) {
        builtin_completions = try server.allocator.alloc(types.CompletionItem, data.builtins.len);
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
            if (server.config.enable_snippets) {
                insert_text = builtin.snippet;
                builtin_completions.?[idx].insertTextFormat = .Snippet;
            } else {
                insert_text = builtin.name;
            }
            builtin_completions.?[idx].insertText =
                if (server.config.include_at_in_builtins)
                insert_text
            else
                insert_text[1..];
        }
        truncateCompletions(builtin_completions.?, server.config.max_detail_length);
    }

    try send(writer, server.arena.allocator(), types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = builtin_completions.?,
            },
        },
    });
}

fn completeGlobal(server: *Server, writer: anytype, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(server.arena.allocator());

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
            try server.formatDetailledLabel(writer, item, server.arena.allocator());
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

fn completeFieldAccess(server: *Server, writer: anytype, id: types.RequestId, handle: *DocumentStore.Handle, position: offsets.DocumentPosition, range: analysis.SourceRange) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(server.arena.allocator());

    const line_mem_start = @ptrToInt(position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
    var held_range = handle.document.borrowNullTerminatedSlice(line_mem_start + range.start, line_mem_start + range.end);
    errdefer held_range.release();
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    if (try analysis.getFieldAccessType(&server.document_store, &server.arena, handle, position.absolute_index, &tokenizer)) |result| {
        held_range.release();
        try server.typeToCompletion(&completions, result, handle);
        sortCompletionItems(completions.items, server.arena.allocator());
        truncateCompletions(completions.items, server.config.max_detail_length);
        if (server.client_capabilities.label_details_support) {
            for (completions.items) |*item| {
                try server.formatDetailledLabel(writer, item, server.arena.allocator());
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

fn formatDetailledLabel(server: *Server, writer: anytype, item: *types.CompletionItem, alloc: std.mem.Allocator) !void {
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

    // logger.info("## label: {s} it: {s} kind: {} isValue: {}", .{item.label, it, item.kind, isValue});

    if (std.mem.startsWith(u8, it, "fn ")) {
        var s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        var e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
        if (e < s) {
            Logger.warn(server, writer, "something wrong when trying to build label detail for {s} kind: {}", .{ it, item.kind });
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
                    Logger.warn(server, writer, "something wrong when trying to build label detail for a .Constant|union {s}", .{it});
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
            Logger.warn(server, writer, "something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // logger.info("s: {} -> {}", .{s, e});
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
            Logger.warn(server, writer, "something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // logger.info("s: {} -> {}", .{s, e});
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
                Logger.warn(server, writer, "something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[us - 5 .. ue + 1];
        } else if (std.mem.indexOf(u8, it, "= enum(")) |_| {
            var es: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ee: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ee < es) {
                Logger.warn(server, writer, "something wrong when trying to build label detail for a .Constant|enum {s}", .{it});
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
    Logger.debug(server, writer, "Completing error:", .{});

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

    for (req.params.capabilities.offsetEncoding.value) |encoding| {
        if (std.mem.eql(u8, encoding, "utf-8")) {
            server.offset_encoding = .utf8;
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
                .offsetEncoding = if (server.offset_encoding == .utf8)
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

    Logger.info(server, writer, "zls initialized", .{});
    Logger.info(server, writer, "{}", .{server.client_capabilities});
    Logger.info(server, writer, "Using offset encoding: {s}", .{std.meta.tagName(server.offset_encoding)});
}

fn registerCapability(server: *Server, writer: anytype, method: []const u8) !void {
    // NOTE: stage1 moment occurs if we dont do it like this :(
    // long live stage2's not broken anon structs

    Logger.debug(server, writer, "Dynamically registering method '{s}'", .{method});

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

    Logger.info(server, writer, "Requesting configuration!", .{});
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
    Logger.info(server, writer, "Server closing...", .{});

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
        Logger.debug(server, writer, "Trying to change non existent document {s}", .{req.params.textDocument.uri});
        return;
    };

    try server.document_store.applyChanges(handle, req.params.contentChanges.Array, server.offset_encoding);
    try server.publishDiagnostics(writer, handle.*);
}

fn saveDocumentHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.SaveDocument) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;
    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        Logger.warn(server, writer, "Trying to save non existent document {s}", .{req.params.textDocument.uri});
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
            Logger.warn(server, writer, "Trying to get semantic tokens of non existent document {s}", .{req.params.textDocument.uri});
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
        Logger.warn(server, writer, "Trying to complete in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, no_completions_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(writer, id, no_completions_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
    const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);

    switch (pos_context) {
        .builtin => try server.completeBuiltin(writer, id),
        .var_access, .empty => try server.completeGlobal(writer, id, doc_position.absolute_index, handle),
        .field_access => |range| try server.completeFieldAccess(writer, id, handle, doc_position, range),
        .global_error_set => try server.completeError(writer, id, handle),
        .enum_literal => try server.completeDot(writer, id, handle),
        .label => try server.completeLabel(writer, id, doc_position.absolute_index, handle),
        .import_string_literal, .embedfile_string_literal => |loc| {
            if (!server.config.enable_import_embedfile_argument_completions)
                return try respondGeneric(writer, id, no_completions_response);

            const line_mem_start = @ptrToInt(doc_position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
            const completing = handle.tree.source[line_mem_start + loc.start + 1 .. line_mem_start + loc.end];

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
                    try fsl_completions.ensureUnusedCapacity(server.arena.allocator(), bf.packages.items.len);

                    for (bf.packages.items) |pkg| {
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
        Logger.warn(server, writer, "Trying to get signature help in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, no_signatures_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(writer, id, no_signatures_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
    if (try getSignatureInfo(
        &server.document_store,
        &server.arena,
        handle,
        doc_position.absolute_index,
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
        Logger.warn(server, writer, "Trying to go to definition in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.gotoDefinitionGlobal(writer, id, doc_position.absolute_index, handle, resolve_alias),
            .field_access => |range| try server.gotoDefinitionFieldAccess(writer, id, handle, doc_position, range, resolve_alias),
            .import_string_literal => try server.gotoDefinitionString(writer, id, doc_position.absolute_index, handle),
            .label => try server.gotoDefinitionLabel(writer, id, doc_position.absolute_index, handle),
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
        Logger.warn(server, writer, "Trying to get hover in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);
        switch (pos_context) {
            .builtin => try server.hoverDefinitionBuiltin(writer, id, doc_position.absolute_index, handle),
            .var_access => try server.hoverDefinitionGlobal(writer, id, doc_position.absolute_index, handle),
            .field_access => |range| try server.hoverDefinitionFieldAccess(writer, id, handle, doc_position, range),
            .label => try server.hoverDefinitionLabel(writer, id, doc_position.absolute_index, handle),
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
        Logger.warn(server, writer, "Trying to get document symbols in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };
    try server.documentSymbol(writer, id, handle);
}

fn formattingHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Formatting) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.zig_exe_path) |zig_exe_path| {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            Logger.warn(server, writer, "Trying to got to definition in non existent document {s}", .{req.params.textDocument.uri});
            return try respondGeneric(writer, id, null_result_response);
        };

        var process = std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, server.allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;

        process.spawn() catch |err| {
            Logger.warn(server, writer, "Failed to spawn zig fmt process, error: {}", .{err});
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

                return try send(writer, server.arena.allocator(), types.Response{
                    .id = id,
                    .result = .{
                        .TextEdits = &[1]types.TextEdit{
                            .{
                                .range = try offsets.documentRange(handle.document, server.offset_encoding),
                                .newText = stdout_bytes,
                            },
                        },
                    },
                });
            },
            else => {},
        }
    }
    return try respondGeneric(writer, id, null_result_response);
}

fn renameHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.Rename) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        Logger.warn(server, writer, "Trying to rename in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.renameDefinitionGlobal(writer, id, handle, doc_position.absolute_index, req.params.newName),
            .field_access => |range| try server.renameDefinitionFieldAccess(writer, id, handle, doc_position, range, req.params.newName),
            .label => try server.renameDefinitionLabel(writer, id, handle, doc_position.absolute_index, req.params.newName),
            else => try respondGeneric(writer, id, null_result_response),
        }
    } else {
        try respondGeneric(writer, id, null_result_response);
    }
}

fn didChangeConfigurationHandler(server: *Server, writer: anytype, id: types.RequestId, maybe_req: std.json.Value) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;
    if (maybe_req.Object.get("params").?.Object.get("settings").? == .Object) {
        const req = try requests.fromDynamicTree(&server.arena, requests.Configuration, maybe_req);
        inline for (std.meta.fields(Config)) |field| {
            if (@field(req.params.settings, field.name)) |value| {
                Logger.debug(server, writer, "setting configuration option '{s}' to '{any}'", .{ field.name, value });
                @field(server.config, field.name) = if (@TypeOf(value) == []const u8) try server.allocator.dupe(u8, value) else value;
            }
        }

        try server.configChanged(null);
    } else if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration(writer);
}

fn referencesHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.References) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        Logger.warn(server, writer, "Trying to get references in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);

        const include_decl = req.params.context.includeDeclaration;
        switch (pos_context) {
            .var_access => try server.referencesDefinitionGlobal(writer, id, handle, doc_position.absolute_index, include_decl, false),
            .field_access => |range| try server.referencesDefinitionFieldAccess(writer, id, handle, doc_position, range, include_decl, false),
            .label => try server.referencesDefinitionLabel(writer, id, handle, doc_position.absolute_index, include_decl, false),
            else => try respondGeneric(writer, id, null_result_response),
        }
    } else {
        try respondGeneric(writer, id, null_result_response);
    }
}

fn documentHighlightHandler(server: *Server, writer: anytype, id: types.RequestId, req: requests.DocumentHighlight) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        Logger.warn(server, writer, "Trying to highlight references in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(writer, id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(&server.arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.referencesDefinitionGlobal(writer, id, handle, doc_position.absolute_index, true, true),
            .field_access => |range| try server.referencesDefinitionFieldAccess(writer, id, handle, doc_position, range, true, true),
            .label => try server.referencesDefinitionLabel(writer, id, handle, doc_position.absolute_index, true, true),
            else => try respondGeneric(writer, id, null_result_response),
        }
    } else {
        try respondGeneric(writer, id, null_result_response);
    }
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
            Logger.warn(server, writer, "Trying to get inlay hint of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const hover_kind: types.MarkupContent.Kind = if (server.client_capabilities.hover_supports_md) .Markdown else .PlainText;

        // TODO cache hints per document
        // because the function could be stored in a different document
        // we need the regenerate hints when the document itself or its imported documents change
        // with caching it would also make sense to generate all hints instead of only the visible ones
        const hints = try inlay_hints.writeRangeInlayHint(&server.arena, &server.config, &server.document_store, handle, req.params.range, hover_kind);
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
        Logger.info(server, writer, "Setting configuration...", .{});

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
                        .String => |s| try server.allocator.dupe(u8, s), // TODO: Allocation model? (same with didChangeConfiguration); imo this isn't *that* bad but still
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
                Logger.debug(server, writer, "setting configuration option '{s}' to '{any}'", .{ field.name, new_value });
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
            Logger.debug(server, writer, "Took {}ms to process method {s}", .{ end_time - start_time, method });
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
                Logger.warn(server, writer, "method not mapped: {s}", .{method});
                done = error.HackDone;
            } else if (method_info[1] != void) {
                const ReqT = method_info[1];
                if (requests.fromDynamicTree(&server.arena, ReqT, tree.root)) |request_obj| {
                    done = error.HackDone;
                    done = extractErr(method_info[2](server, writer, id, request_obj));
                } else |err| {
                    if (err == error.MalformedJson) {
                        Logger.warn(server, writer, "Could not create request type {s} from JSON {s}", .{ @typeName(ReqT), json });
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

        Logger.debug(server, writer, "Notification method {s} is not implemented", .{method});
        return;
    }
    if (tree.root.Object.get("id")) |_| {
        return try respondGeneric(writer, id, not_implemented_response);
    }
    Logger.debug(server, writer, "Method without return value not implemented: {s}", .{method});
}

pub fn configChanged(server: *Server, builtin_creation_dir: ?[]const u8) !void {
    try server.config.configChanged(server.allocator, builtin_creation_dir);
    server.document_store.config = server.config;
}

pub fn init(
    allocator: std.mem.Allocator,
    config: Config,
    config_path: ?[]const u8,
    log_level: std.log.Level,
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
        .log_level = log_level,
    };
}

pub fn deinit(server: *Server) void {
    server.document_store.deinit();
    analysis.deinit();

    const config_parse_options = std.json.ParseOptions{ .allocator = server.allocator };
    defer std.json.parseFree(Config, server.config, config_parse_options);

    if (builtin_completions) |compls| {
        server.allocator.free(compls);
    }
}
