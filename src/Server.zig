const Server = @This();

const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const DocumentStore = @import("DocumentStore.zig");
const types = @import("lsp.zig");
const analysis = @import("analysis.zig");
const ast = @import("ast.zig");
const references = @import("references.zig");
const offsets = @import("offsets.zig");
const semantic_tokens = @import("semantic_tokens.zig");
const inlay_hints = @import("inlay_hints.zig");
const code_actions = @import("code_actions.zig");
const shared = @import("shared.zig");
const Ast = std.zig.Ast;
const tracy = @import("tracy.zig");
const uri_utils = @import("uri.zig");
const diff = @import("diff.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");

const data = @import("data/data.zig");
const snipped_data = @import("data/snippets.zig");

const tres = @import("tres");

const log = std.log.scoped(.server);

// Server fields

config: *Config,
allocator: std.mem.Allocator = undefined,
arena: *std.heap.ArenaAllocator = undefined,
document_store: DocumentStore = undefined,
builtin_completions: std.ArrayListUnmanaged(types.CompletionItem),
client_capabilities: ClientCapabilities = .{},
outgoing_messages: std.ArrayListUnmanaged([]const u8) = .{},
recording_enabled: bool,
replay_enabled: bool,
offset_encoding: offsets.Encoding = .@"utf-16",
status: enum {
    /// the server has not received a `initialize` request
    uninitialized,
    /// the server has recieved a `initialize` request and is awaiting the `initialized` notification
    initializing,
    /// the server has been initialized and is ready to received requests
    initialized,
    /// the server has been shutdown and can't handle any more requests
    shutdown,
    /// the server is received a `exit` notification and has been shutdown
    exiting_success,
    /// the server is received a `exit` notification but has not been shutdown
    exiting_failure,
},

// Code was based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

const ClientCapabilities = packed struct {
    supports_snippets: bool = false,
    supports_apply_edits: bool = false,
    supports_will_save: bool = false,
    supports_will_save_wait_until: bool = false,
    supports_publish_diagnostics: bool = false,
    supports_code_action_fixall: bool = false,
    hover_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
    label_details_support: bool = false,
    supports_configuration: bool = false,
};

pub const Error = std.mem.Allocator.Error || error{
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    /// Error code indicating that a server received a notification or
    /// request before the server has received the `initialize` request.
    ServerNotInitialized,
    /// A request failed but it was syntactically correct, e.g the
    /// method name was known and the parameters were valid. The error
    /// message should contain human readable information about why
    /// the request failed.
    ///
    /// @since 3.17.0
    RequestFailed,
    /// The server cancelled the request. This error code should
    /// only be used for requests that explicitly support being
    /// server cancellable.
    ///
    /// @since 3.17.0
    ServerCancelled,
    /// The server detected that the content of a document got
    /// modified outside normal conditions. A server should
    /// NOT send this error code if it detects a content change
    /// in it unprocessed messages. The result even computed
    /// on an older state might still be useful for the client.
    ///
    /// If a client decides that a result is not of any use anymore
    /// the client should cancel the request.
    ContentModified,
    /// The client has canceled a request and a server as detected
    /// the cancel.
    RequestCancelled,
};

fn sendResponse(server: *Server, id: types.RequestId, result: anytype) void {
    // TODO validate result type is a possible response
    // TODO validate response is from a client to server request
    // TODO validate result type

    server.sendInternal(id, null, null, "result", result) catch {};
}

fn sendRequest(server: *Server, id: types.RequestId, method: []const u8, params: anytype) void {
    // TODO validate method is a request
    // TODO validate method is server to client
    // TODO validate params type

    server.sendInternal(id, method, null, "params", params) catch {};
}

fn sendNotification(server: *Server, method: []const u8, params: anytype) void {
    // TODO validate method is a notification
    // TODO validate method is server to client
    // TODO validate params type

    server.sendInternal(null, method, null, "params", params) catch {};
}

fn sendResponseError(server: *Server, id: types.RequestId, err: ?types.ResponseError) void {
    server.sendInternal(id, null, err, "", void) catch {};
}

fn sendInternal(
    server: *Server,
    maybe_id: ?types.RequestId,
    maybe_method: ?[]const u8,
    maybe_err: ?types.ResponseError,
    extra_name: []const u8,
    extra: anytype,
) error{OutOfMemory}!void {
    var buffer = std.ArrayListUnmanaged(u8){};
    var writer = buffer.writer(server.allocator);
    try writer.writeAll(
        \\{"jsonrpc":"2.0"
    );
    if (maybe_id) |id| {
        try writer.writeAll(
            \\,"id":
        );
        try tres.stringify(id, .{}, writer);
    }
    if (maybe_method) |method| {
        try writer.writeAll(
            \\,"method":
        );
        try tres.stringify(method, .{}, writer);
    }
    if (@TypeOf(extra) != @TypeOf(void)) {
        try writer.print(
            \\,"{s}":
        , .{extra_name});
        try tres.stringify(extra, .{
            .emit_null_optional_fields = false,
        }, writer);
    }
    if (maybe_err) |err| {
        try writer.writeAll(
            \\,"error":
        );
        try tres.stringify(err, .{}, writer);
    }
    try writer.writeByte('}');

    const message = try buffer.toOwnedSlice(server.allocator);
    errdefer server.allocator.free(message);

    try server.outgoing_messages.append(server.allocator, message);
}

fn showMessage(
    server: *Server,
    message_type: types.MessageType,
    comptime fmt: []const u8,
    args: anytype,
) void {
    const message = std.fmt.allocPrint(server.arena.allocator(), fmt, args) catch return;
    switch (message_type) {
        .Error => log.err("{s}", .{message}),
        .Warning => log.warn("{s}", .{message}),
        .Info => log.info("{s}", .{message}),
        .Log => log.debug("{s}", .{message}),
    }
    server.sendNotification("window/showMessage", types.ShowMessageParams{
        .type = message_type,
        .message = message,
    });
}

fn generateDiagnostics(server: *Server, handle: DocumentStore.Handle) error{OutOfMemory}!types.PublishDiagnosticsParams {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(server.client_capabilities.supports_publish_diagnostics);

    const tree = handle.tree;

    var allocator = server.arena.allocator();
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};

    for (tree.errors) |err| {
        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        tree.renderError(err, fbs.writer()) catch if (std.debug.runtime_safety) unreachable else continue; // if an error occurs here increase buffer size

        try diagnostics.append(allocator, .{
            .range = offsets.tokenToRange(tree, err.token, server.offset_encoding),
            .severity = .Error,
            .code = .{ .string = @tagName(err.tag) },
            .source = "zls",
            .message = try server.arena.allocator().dupe(u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (server.config.enable_ast_check_diagnostics and tree.errors.len == 0) {
        getAstCheckDiagnostics(server, handle, &diagnostics) catch |err| {
            log.err("failed to run ast-check: {}", .{err});
        };
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
                        .code = .{ .string = "dot_slash_import" },
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
                                    .code = .{ .string = "bad_style" },
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(allocator, .{
                                    .range = offsets.tokenToRange(tree, name_token, server.offset_encoding),
                                    .severity = .Hint,
                                    .code = .{ .string = "bad_style" },
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

    for (handle.cimports.items(.hash)) |hash, i| {
        const result = server.document_store.cimports.get(hash) orelse continue;
        if (result != .failure) continue;
        const stderr = std.mem.trim(u8, result.failure, " ");

        var pos_and_diag_iterator = std.mem.split(u8, stderr, ":");
        _ = pos_and_diag_iterator.next(); // skip file path
        _ = pos_and_diag_iterator.next(); // skip line
        _ = pos_and_diag_iterator.next(); // skip character

        const node = handle.cimports.items(.node)[i];
        try diagnostics.append(allocator, .{
            .range = offsets.nodeToRange(handle.tree, node, server.offset_encoding),
            .severity = .Error,
            .code = .{ .string = "cImport" },
            .source = "zls",
            .message = try allocator.dupe(u8, pos_and_diag_iterator.rest()),
        });
    }

    if (server.config.highlight_global_var_declarations) {
        const main_tokens = tree.nodes.items(.main_token);
        const tags = tree.tokens.items(.tag);
        for (tree.rootDecls()) |decl| {
            const decl_tag = tree.nodes.items(.tag)[decl];
            const decl_main_token = tree.nodes.items(.main_token)[decl];

            switch (decl_tag) {
                .simple_var_decl,
                .aligned_var_decl,
                .local_var_decl,
                .global_var_decl,
                => {
                    if (tags[main_tokens[decl]] != .keyword_var) continue; // skip anything immutable
                    // uncomment this to get a list :)
                    //log.debug("possible global variable \"{s}\"", .{tree.tokenSlice(decl_main_token + 1)});
                    try diagnostics.append(allocator, .{
                        .range = offsets.tokenToRange(tree, decl_main_token, server.offset_encoding),
                        .severity = .Hint,
                        .code = .{ .string = "highlight_global_var_declarations" },
                        .source = "zls",
                        .message = "Global var declaration",
                    });
                },
                else => {},
            }
        }
    }

    if (handle.interpreter) |int| {
        try diagnostics.ensureUnusedCapacity(allocator, int.errors.count());

        var err_it = int.errors.iterator();

        while (err_it.next()) |err| {
            try diagnostics.append(allocator, .{
                .range = offsets.nodeToRange(tree, err.key_ptr.*, server.offset_encoding),
                .severity = .Error,
                .code = .{ .string = err.value_ptr.code },
                .source = "zls",
                .message = err.value_ptr.message,
            });
        }
    }
    // try diagnostics.appendSlice(allocator, handle.interpreter.?.diagnostics.items);

    return .{
        .uri = handle.uri,
        .diagnostics = diagnostics.items,
    };
}

fn getAstCheckDiagnostics(
    server: *Server,
    handle: DocumentStore.Handle,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
) !void {
    var allocator = server.arena.allocator();

    const zig_exe_path = server.config.zig_exe_path orelse return;

    var process = std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "ast-check", "--color", "off" }, server.allocator);
    process.stdin_behavior = .Pipe;
    process.stderr_behavior = .Pipe;

    process.spawn() catch |err| {
        log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
        return;
    };
    try process.stdin.?.writeAll(handle.text);
    process.stdin.?.close();

    process.stdin = null;

    const stderr_bytes = try process.stderr.?.reader().readAllAlloc(server.allocator, std.math.maxInt(usize));
    defer server.allocator.free(stderr_bytes);

    const term = process.wait() catch |err| {
        log.warn("Failed to await zig ast-check process, error: {}", .{err});
        return;
    };

    if (term != .Exited) return;

    var last_diagnostic: ?types.Diagnostic = null;
    // we dont store DiagnosticRelatedInformation in last_diagnostic instead
    // its stored in last_related_diagnostics because we need an ArrayList
    var last_related_diagnostics: std.ArrayListUnmanaged(types.DiagnosticRelatedInformation) = .{};

    // NOTE: I believe that with color off it's one diag per line; is this correct?
    var line_iterator = std.mem.split(u8, stderr_bytes, "\n");

    while (line_iterator.next()) |line| lin: {
        if (!std.mem.startsWith(u8, line, "<stdin>")) continue;

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
        const position = offsets.convertPositionEncoding(handle.text, utf8_position, .@"utf-8", server.offset_encoding);
        const range = offsets.tokenPositionToRange(handle.text, position, server.offset_encoding);

        const msg = pos_and_diag_iterator.rest()[1..];

        if (std.mem.startsWith(u8, msg, "note: ")) {
            try last_related_diagnostics.append(allocator, .{
                .location = .{
                    .uri = handle.uri,
                    .range = range,
                },
                .message = try server.arena.allocator().dupe(u8, msg["note: ".len..]),
            });
            continue;
        }

        if (last_diagnostic) |*diagnostic| {
            diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(allocator);
            try diagnostics.append(allocator, diagnostic.*);
            last_diagnostic = null;
        }

        if (std.mem.startsWith(u8, msg, "error: ")) {
            last_diagnostic = types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "ast_check" },
                .source = "zls",
                .message = try server.arena.allocator().dupe(u8, msg["error: ".len..]),
            };
        } else {
            last_diagnostic = types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "ast_check" },
                .source = "zls",
                .message = try server.arena.allocator().dupe(u8, msg),
            };
        }
    }

    if (last_diagnostic) |*diagnostic| {
        diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(allocator);
        try diagnostics.append(allocator, diagnostic.*);
        last_diagnostic = null;
    }
}

fn getAutofixMode(server: *Server) enum {
    on_save,
    will_save_wait_until,
    fixall,
    none,
} {
    if (!server.config.enable_autofix) return .none;
    if (server.client_capabilities.supports_code_action_fixall) return .fixall;
    if (server.client_capabilities.supports_apply_edits) {
        if (server.client_capabilities.supports_will_save_wait_until) return .will_save_wait_until;
        return .on_save;
    }
    return .none;
}

/// caller owns returned memory.
fn autofix(server: *Server, allocator: std.mem.Allocator, handle: *const DocumentStore.Handle) error{OutOfMemory}!std.ArrayListUnmanaged(types.TextEdit) {
    if (!server.config.enable_ast_check_diagnostics) return .{};

    if (handle.tree.errors.len != 0) return .{};
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    getAstCheckDiagnostics(server, handle.*, &diagnostics) catch |err| {
        log.err("failed to run ast-check: {}", .{err});
    };

    var builder = code_actions.Builder{
        .arena = server.arena,
        .document_store = &server.document_store,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
    };

    var actions = std.ArrayListUnmanaged(types.CodeAction){};
    for (diagnostics.items) |diagnostic| {
        try builder.generateCodeAction(diagnostic, &actions);
    }

    var text_edits = std.ArrayListUnmanaged(types.TextEdit){};
    for (actions.items) |action| {
        std.debug.assert(action.kind != null);
        std.debug.assert(action.edit != null);
        std.debug.assert(action.edit.?.changes != null);

        if (action.kind.? != .@"source.fixAll") continue;

        const changes = action.edit.?.changes.?;
        if (changes.count() != 1) continue;

        const edits: []const types.TextEdit = changes.get(handle.uri) orelse continue;

        try text_edits.appendSlice(allocator, edits);
    }

    return text_edits;
}

fn typeToCompletion(
    server: *Server,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    field_access: analysis.FieldAccessReturn,
    orig_handle: *const DocumentStore.Handle,
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
        .@"comptime" => |co| {
            const ti = co.type.getTypeInfo();
            switch (ti) {
                .@"struct" => |st| {
                    var fit = st.fields.iterator();
                    while (fit.next()) |entry| {
                        try list.append(allocator, .{
                            .label = entry.key_ptr.*,
                            .kind = .Field,
                            .insertText = entry.key_ptr.*,
                            .insertTextFormat = .PlainText,
                        });
                    }

                    var it = st.scope.declarations.iterator();
                    while (it.next()) |entry| {
                        try list.append(allocator, .{
                            .label = entry.key_ptr.*,
                            .kind = if (entry.value_ptr.isConstant()) .Constant else .Variable,
                            .insertText = entry.key_ptr.*,
                            .insertTextFormat = .PlainText,
                        });
                    }
                },
                else => {},
            }
        },
    }
}

fn nodeToCompletion(
    server: *Server,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    unwrapped: ?analysis.TypeWithHandle,
    orig_handle: *const DocumentStore.Handle,
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

    const doc_kind: types.MarkupKind = if (server.client_capabilities.completion_doc_supports_md)
        .markdown
    else
        .plaintext;

    const Documentation = @TypeOf(@as(types.CompletionItem, undefined).documentation);

    const doc: Documentation = if (try analysis.getDocComments(
        allocator,
        handle.tree,
        node,
        doc_kind,
    )) |doc_comments| .{ .MarkupContent = types.MarkupContent{
        .kind = doc_kind,
        .value = doc_comments,
    } } else null;

    if (ast.isContainer(handle.tree, node)) {
        const context = DeclToCompletionContext{
            .server = server,
            .completions = list,
            .orig_handle = orig_handle,
            .parent_is_type_val = is_type_val,
        };
        try analysis.iterateSymbolsContainer(
            &server.document_store,
            server.arena,
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
                        try analysis.hasSelfParam(server.arena, &server.document_store, handle, func);
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

            if (try analysis.resolveVarDeclAlias(&server.document_store, server.arena, node_handle)) |result| {
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
                .label = handle.tree.tokenSlice(field.ast.main_token),
                .kind = if (field.ast.tuple_like) .Enum else .Field,
                .documentation = doc,
                .detail = analysis.getContainerFieldSignature(handle.tree, field),
                .insertText = tree.tokenSlice(field.ast.main_token),
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
    if (pos_index + 1 >= handle.text.len) return "";
    var start_idx = pos_index;

    while (start_idx > 0 and isSymbolChar(handle.text[start_idx - 1])) {
        start_idx -= 1;
    }

    var end_idx = pos_index;
    while (end_idx < handle.text.len and isSymbolChar(handle.text[end_idx])) {
        end_idx += 1;
    }

    if (end_idx <= start_idx) return "";
    return handle.text[start_idx..end_idx];
}

fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_';
}

fn gotoDefinitionSymbol(
    server: *Server,
    decl_handle: analysis.DeclWithHandle,
    resolve_alias: bool,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle = decl_handle.handle;

    const name_token = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analysis.resolveVarDeclAlias(&server.document_store, server.arena, .{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;

                    break :block result.nameToken();
                }
            }

            break :block analysis.getDeclNameToken(handle.tree, node) orelse return null;
        },
        else => decl_handle.nameToken(),
    };

    return types.Location{
        .uri = handle.uri,
        .range = offsets.tokenToRange(handle.tree, name_token, server.offset_encoding),
    };
}

fn hoverSymbol(server: *Server, decl_handle: analysis.DeclWithHandle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = decl_handle.handle;
    const tree = handle.tree;

    const hover_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    var doc_str: ?[]const u8 = null;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try analysis.resolveVarDeclAlias(&server.document_store, server.arena, .{ .node = node, .handle = handle })) |result| {
                return try server.hoverSymbol(result);
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
                break :def analysis.nodeToString(tree, node) orelse return null;
            }
        },
        .param_payload => |pay| def: {
            const param = pay.param;
            if (param.first_doc_comment) |doc_comments| {
                doc_str = try analysis.collectDocComments(server.arena.allocator(), handle.tree, doc_comments, hover_kind, false);
            }

            const first_token = ast.paramFirstToken(tree, param);
            const last_token = ast.paramLastToken(tree, param);

            const start = offsets.tokenToIndex(tree, first_token);
            const end = offsets.tokenToLoc(tree, last_token).end;
            break :def tree.source[start..end];
        },
        .pointer_payload,
        .array_payload,
        .array_index,
        .switch_payload,
        .label_decl,
        .error_token,
        => tree.tokenSlice(decl_handle.nameToken()),
    };

    var bound_type_params = analysis.BoundTypeParams{};
    const resolved_type = try decl_handle.resolveType(&server.document_store, server.arena, &bound_type_params);

    const resolved_type_str = if (resolved_type) |rt|
        if (rt.type.is_type_val) switch (rt.type.data) {
            .@"comptime" => |*co| try std.fmt.allocPrint(server.arena.allocator(), "{ }", .{co.interpreter.formatTypeInfo(co.type.getTypeInfo())}),
            else => "type",
        } else switch (rt.type.data) { // TODO: Investigate random weird numbers like 897 that cause index of bounds
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
    if (hover_kind == .markdown) {
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

    return types.Hover{
        .contents = .{ .MarkupContent = .{
            .kind = hover_kind,
            .value = hover_text,
        } },
    };
}

fn getLabelGlobal(pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupLabel(handle, name, pos_index);
}

fn getSymbolGlobal(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}!?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupSymbolGlobal(&server.document_store, server.arena, handle, name, pos_index);
}

fn gotoDefinitionLabel(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return null;
    return try server.gotoDefinitionSymbol(decl, false);
}

fn gotoDefinitionGlobal(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
    resolve_alias: bool,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return null;
    return try server.gotoDefinitionSymbol(decl, resolve_alias);
}

fn hoverDefinitionLabel(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return null;
    return try server.hoverSymbol(decl);
}

fn hoverDefinitionBuiltin(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            return types.Hover{
                .contents = .{
                    .MarkupContent = .{
                        .kind = .markdown,
                        .value = try std.fmt.allocPrint(
                            server.arena.allocator(),
                            "```zig\n{s}\n```\n{s}",
                            .{ builtin.signature, builtin.documentation },
                        ),
                    },
                },
            };
        }
    }

    return null;
}

fn hoverDefinitionGlobal(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(pos_index, handle)) orelse return null;
    return try server.hoverSymbol(decl);
}

fn getSymbolFieldAccess(
    server: *Server,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(source_index, handle.*);
    if (name.len == 0) return null;

    var held_range = try server.arena.allocator().dupeZ(u8, offsets.locToSlice(handle.text, loc));
    var tokenizer = std.zig.Tokenizer.init(held_range);

    if (try analysis.getFieldAccessType(&server.document_store, server.arena, handle, source_index, &tokenizer)) |result| {
        const container_handle = result.unwrapped orelse result.original;
        const container_handle_node = switch (container_handle.type.data) {
            .other => |n| n,
            else => return null,
        };
        return try analysis.lookupSymbolContainer(
            &server.document_store,
            server.arena,
            .{ .node = container_handle_node, .handle = container_handle.handle },
            name,
            true,
        );
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    server: *Server,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
    resolve_alias: bool,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, source_index, loc)) orelse return null;
    return try server.gotoDefinitionSymbol(decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    server: *Server,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, source_index, loc)) orelse return null;
    return try server.hoverSymbol(decl);
}

fn gotoDefinitionString(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const import_str = analysis.getImportStr(handle.tree, 0, pos_index) orelse return null;
    const uri = try server.document_store.uriFromImportStr(server.arena.allocator(), handle.*, import_str);

    return types.Location{
        .uri = uri orelse return null,
        .range = .{
            .start = .{ .line = 0, .character = 0 },
            .end = .{ .line = 0, .character = 0 },
        },
    };
}

const DeclToCompletionContext = struct {
    server: *Server,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    orig_handle: *const DocumentStore.Handle,
    parent_is_type_val: ?bool = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) error{OutOfMemory}!void {
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
        .param_payload => |pay| {
            const Documentation = @TypeOf(@as(types.CompletionItem, undefined).documentation);

            const param = pay.param;
            const doc_kind: types.MarkupKind = if (context.server.client_capabilities.completion_doc_supports_md) .markdown else .plaintext;
            const doc: Documentation = if (param.first_doc_comment) |doc_comments| .{ .MarkupContent = types.MarkupContent{
                .kind = doc_kind,
                .value = try analysis.collectDocComments(allocator, tree, doc_comments, doc_kind, false),
            } } else null;

            const first_token = ast.paramFirstToken(tree, param);
            const last_token = ast.paramLastToken(tree, param);

            try context.completions.append(allocator, .{
                .label = tree.tokenSlice(param.name_token.?),
                .kind = .Constant,
                .documentation = doc,
                .detail = tree.source[offsets.tokenToIndex(tree, first_token)..offsets.tokenToLoc(tree, last_token).end],
                .insertText = tree.tokenSlice(param.name_token.?),
                .insertTextFormat = .PlainText,
            });
        },
        .pointer_payload,
        .array_payload,
        .array_index,
        .switch_payload,
        .label_decl,
        => {
            const name = tree.tokenSlice(decl_handle.nameToken());

            try context.completions.append(allocator, .{
                .label = name,
                .kind = .Variable,
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
        .error_token => {
            const name = tree.tokenSlice(decl_handle.decl.error_token);

            try context.completions.append(allocator, .{
                .label = name,
                .kind = .Constant,
                .detail = try std.fmt.allocPrint(allocator, "error.{s}", .{name}),
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

fn completeLabel(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .orig_handle = handle,
    };
    try analysis.iterateLabels(handle, pos_index, declToCompletion, context);

    return completions.toOwnedSlice(server.arena.allocator());
}

fn populateSnippedCompletions(
    allocator: std.mem.Allocator,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    snippets: []const snipped_data.Snipped,
    config: Config,
    start_with: ?[]const u8,
) error{OutOfMemory}!void {
    try completions.ensureUnusedCapacity(allocator, snippets.len);

    for (snippets) |snipped| {
        if (start_with) |needle| {
            if (!std.mem.startsWith(u8, snipped.label, needle)) continue;
        }

        completions.appendAssumeCapacity(.{
            .label = snipped.label,
            .kind = snipped.kind,
            .detail = if (config.enable_snippets) snipped.text else null,
            .insertText = if (config.enable_snippets) snipped.text else null,
            .insertTextFormat = if (config.enable_snippets and snipped.text != null) .Snippet else .PlainText,
        });
    }
}

fn completeGlobal(server: *Server, pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&server.document_store, server.arena, handle, pos_index, declToCompletion, context);
    try populateSnippedCompletions(server.arena.allocator(), &completions, &snipped_data.generic, server.config.*, null);

    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailledLabel(item, server.arena.allocator());
        }
    }

    return completions.toOwnedSlice(server.arena.allocator());
}

fn completeFieldAccess(server: *Server, handle: *const DocumentStore.Handle, source_index: usize, loc: offsets.Loc) error{OutOfMemory}!?[]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    var held_loc = try allocator.dupeZ(u8, offsets.locToSlice(handle.text, loc));
    var tokenizer = std.zig.Tokenizer.init(held_loc);

    const result = (try analysis.getFieldAccessType(&server.document_store, server.arena, handle, source_index, &tokenizer)) orelse return null;
    try server.typeToCompletion(&completions, result, handle);
    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailledLabel(item, allocator);
        }
    }

    return try completions.toOwnedSlice(allocator);
}

fn formatDetailledLabel(item: *types.CompletionItem, arena: std.mem.Allocator) error{OutOfMemory}!void {
    // NOTE: this is not ideal, we should build a detailled label like we do for label/detail
    // because this implementation is very loose, nothing is formated properly so we need to clean
    // things a little bit, wich is quite messy
    // but it works, it provide decent results

    std.debug.assert(item.kind != null);
    if (item.detail == null)
        return;

    var detailLen: usize = item.detail.?.len;
    var it: []u8 = try arena.alloc(u8, detailLen);

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

    if (std.mem.startsWith(u8, it, "fn ") or std.mem.startsWith(u8, it, "@")) {
        var s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        var e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
        if (e < s) {
            log.warn("something wrong when trying to build label detail for {s} kind: {}", .{ it, item.kind.? });
            return;
        }

        item.detail = item.label;
        item.labelDetails = .{ .detail = it[s .. e + 1], .description = it[e + 1 ..] };

        if (item.kind.? == .Constant) {
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
    } else if ((item.kind.? == .Variable or item.kind.? == .Constant) and (isVar or isConst)) {
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
    } else if (item.kind.? == .Variable) {
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
    } else if (item.kind.? == .Constant or item.kind.? == .Field) {
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
    } else if (item.kind.? == .Field and isValue) {
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

fn completeError(server: *Server, handle: *const DocumentStore.Handle) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try server.document_store.errorCompletionItems(server.arena.allocator(), handle.*);
}

fn kindToSortScore(kind: types.CompletionItemKind) ?[]const u8 {
    return switch (kind) {
        .Module => "1_", // use for packages
        .Folder => "2_",
        .File => "3_",

        .Constant => "1_",

        .Variable => "2_",
        .Field => "3_",
        .Function => "4_",

        .Keyword, .Snippet, .EnumMember => "5_",

        .Class,
        .Interface,
        .Struct,
        // Union?
        .TypeParameter,
        => "6_",

        else => {
            log.debug(@typeName(types.CompletionItemKind) ++ "{s} has no sort score specified!", .{@tagName(kind)});
            return null;
        },
    };
}

fn completeDot(server: *Server, handle: *const DocumentStore.Handle) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = try server.document_store.enumCompletionItems(server.arena.allocator(), handle.*);

    return completions;
}

fn completeFileSystemStringLiteral(allocator: std.mem.Allocator, store: *const DocumentStore, handle: *const DocumentStore.Handle, completing: []const u8, is_import: bool) ![]types.CompletionItem {
    var subpath_present = false;
    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    fsc: {
        var document_path = try uri_utils.parse(allocator, handle.uri);
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
            document_dir_path = document_dir_path.dir.openIterableDir(subpath, .{}) catch break :fsc; // NOTE: Is this even safe lol?
            old.close();

            subpath_present = true;
        }

        var dir_iterator = document_dir_path.iterate();
        while (try dir_iterator.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, ".")) continue;
            if (entry.kind == .File and is_import and !std.mem.endsWith(u8, entry.name, ".zig")) continue;

            const l = try allocator.dupe(u8, entry.name);
            try completions.append(allocator, types.CompletionItem{
                .label = l,
                .insertText = l,
                .kind = if (entry.kind == .File) .File else .Folder,
            });
        }
    }

    if (!subpath_present and is_import) {
        if (handle.associated_build_file) |uri| {
            const build_file = store.build_files.get(uri).?;
            try completions.ensureUnusedCapacity(allocator, build_file.config.packages.len);

            for (build_file.config.packages) |pkg| {
                completions.appendAssumeCapacity(.{
                    .label = pkg.name,
                    .kind = .Module,
                });
            }
        }
    }

    return completions.toOwnedSlice(allocator);
}

fn initializeHandler(server: *Server, request: types.InitializeParams) Error!types.InitializeResult {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var skip_set_fixall = false;

    if (request.clientInfo) |clientInfo| {
        log.info("client is '{s}-{s}'", .{ clientInfo.name, clientInfo.version orelse "<no version>" });

        if (std.mem.eql(u8, clientInfo.name, "Sublime Text LSP")) blk: {
            server.config.max_detail_length = 256;
            // TODO investigate why fixall doesn't work in sublime text
            server.client_capabilities.supports_code_action_fixall = false;
            skip_set_fixall = true;

            const version_str = clientInfo.version orelse break :blk;
            const version = std.SemanticVersion.parse(version_str) catch break :blk;
            // this indicates a LSP version for sublime text 3
            // this check can be made more precise if the version that fixed this issue is known
            if (version.major == 0) {
                server.config.include_at_in_builtins = true;
            }
        } else if (std.mem.eql(u8, clientInfo.name, "Visual Studio Code")) {
            server.client_capabilities.supports_code_action_fixall = true;
            skip_set_fixall = true;
        }
    }

    if (request.capabilities.general) |general| {
        var supports_utf8 = false;
        var supports_utf16 = false;
        var supports_utf32 = false;
        if (general.positionEncodings) |position_encodings| {
            for (position_encodings) |encoding| {
                switch (encoding) {
                    .@"utf-8" => supports_utf8 = true,
                    .@"utf-16" => supports_utf16 = true,
                    .@"utf-32" => supports_utf32 = true,
                }
            }
        }

        if (supports_utf8) {
            server.offset_encoding = .@"utf-8";
        } else if (supports_utf32) {
            server.offset_encoding = .@"utf-32";
        } else {
            server.offset_encoding = .@"utf-16";
        }
    }

    if (request.capabilities.textDocument) |textDocument| {
        server.client_capabilities.supports_publish_diagnostics = textDocument.publishDiagnostics != null;
        if (textDocument.hover) |hover| {
            if (hover.contentFormat) |content_format| {
                for (content_format) |format| {
                    if (format == .markdown) {
                        server.client_capabilities.hover_supports_md = true;
                        break;
                    }
                }
            }
        }
        if (textDocument.completion) |completion| {
            if (completion.completionItem) |completionItem| {
                server.client_capabilities.label_details_support = completionItem.labelDetailsSupport orelse false;
                server.client_capabilities.supports_snippets = completionItem.snippetSupport orelse false;
                if (completionItem.documentationFormat) |documentation_format| {
                    for (documentation_format) |format| {
                        if (format == .markdown) {
                            server.client_capabilities.completion_doc_supports_md = true;
                            break;
                        }
                    }
                }
            }
        }
        if (textDocument.synchronization) |synchronization| {
            server.client_capabilities.supports_will_save = synchronization.willSave orelse false;
            server.client_capabilities.supports_will_save_wait_until = synchronization.willSaveWaitUntil orelse false;
        }
        if (textDocument.codeAction) |codeaction| {
            if (codeaction.codeActionLiteralSupport) |literlSupport| {
                if (!skip_set_fixall) {
                    const fixall = std.mem.indexOfScalar(types.CodeActionKind, literlSupport.codeActionKind.valueSet, .@"source.fixAll") != null;
                    server.client_capabilities.supports_code_action_fixall = fixall;
                }
            }
        }
    }

    // NOTE: everything is initialized, we got the client capabilities
    // so we can now format the prebuilt builtins items for labelDetails
    if (server.client_capabilities.label_details_support) {
        for (server.builtin_completions.items) |*item| {
            try formatDetailledLabel(item, server.arena.allocator());
        }
    }

    if (request.capabilities.workspace) |workspace| {
        server.client_capabilities.supports_apply_edits = workspace.applyEdit orelse false;
        server.client_capabilities.supports_configuration = workspace.configuration orelse false;
        if (workspace.didChangeConfiguration) |did_change| {
            if (did_change.dynamicRegistration orelse false) {
                try server.registerCapability("workspace/didChangeConfiguration");
            }
        }
    }

    log.info("zls initializing", .{});
    log.info("{}", .{server.client_capabilities});
    log.info("Using offset encoding: {s}", .{std.meta.tagName(server.offset_encoding)});

    server.status = .initializing;

    if (server.config.zig_exe_path) |exe_path| blk: {
        if (!std.process.can_spawn) break :blk;
        // TODO avoid having to call getZigEnv twice
        // once in init and here
        const env = configuration.getZigEnv(server.allocator, exe_path) orelse break :blk;
        defer std.json.parseFree(configuration.Env, env, .{ .allocator = server.allocator });

        const zig_version = std.SemanticVersion.parse(env.version) catch break :blk;
        const zls_version = comptime std.SemanticVersion.parse(build_options.version) catch unreachable;

        const zig_version_simple = std.SemanticVersion{
            .major = zig_version.major,
            .minor = zig_version.minor,
            .patch = zig_version.patch,
        };
        const zls_version_simple = std.SemanticVersion{
            .major = zls_version.major,
            .minor = zls_version.minor,
            .patch = zls_version.patch,
        };

        switch (zig_version_simple.order(zls_version_simple)) {
            .lt => {
                // ZLS should be backwards compatible with older Zig version which is why we only log
                log.info("Zig {} is older than ZLS {}", .{ zig_version_simple, zls_version_simple });
            },
            .eq => {},
            .gt => {
                server.showMessage(.Warning,
                    \\Zig {} is newer than ZLS {}. Update ZLS to avoid unexpected behavior.
                , .{ zig_version_simple, zls_version_simple });
            },
        }
    } else {
        server.showMessage(.Warning,
            \\ZLS failed to find Zig. Please add Zig to your PATH or set the zig_exe_path config option in your zls.json.
        , .{});
    }

    if (server.recording_enabled) {
        server.showMessage(.Info,
            \\This zls session is being recorded to {?s}.
        , .{server.config.record_session_path});
    }

    return .{
        .serverInfo = .{
            .name = "zls",
            .version = build_options.version,
        },
        .capabilities = .{
            .positionEncoding = server.offset_encoding,
            .signatureHelpProvider = .{
                .triggerCharacters = &.{"("},
                .retriggerCharacters = &.{","},
            },
            .textDocumentSync = .{
                .TextDocumentSyncOptions = .{
                    .openClose = true,
                    .change = .Incremental,
                    .save = .{ .bool = true },
                    .willSave = true,
                    .willSaveWaitUntil = true,
                },
            },
            .renameProvider = .{ .bool = true },
            .completionProvider = .{
                .resolveProvider = false,
                .triggerCharacters = &[_][]const u8{ ".", ":", "@", "]" },
                .completionItem = .{ .labelDetailsSupport = true },
            },
            .documentHighlightProvider = .{ .bool = true },
            .hoverProvider = .{ .bool = true },
            .codeActionProvider = .{ .bool = true },
            .declarationProvider = .{ .bool = true },
            .definitionProvider = .{ .bool = true },
            .typeDefinitionProvider = .{ .bool = true },
            .implementationProvider = .{ .bool = false },
            .referencesProvider = .{ .bool = true },
            .documentSymbolProvider = .{ .bool = true },
            .colorProvider = .{ .bool = false },
            .documentFormattingProvider = .{ .bool = true },
            .documentRangeFormattingProvider = .{ .bool = false },
            .foldingRangeProvider = .{ .bool = true },
            .selectionRangeProvider = .{ .bool = true },
            .workspaceSymbolProvider = .{ .bool = false },
            .workspace = .{
                .workspaceFolders = .{
                    .supported = false,
                    .changeNotifications = .{ .bool = false },
                },
            },
            .semanticTokensProvider = .{
                .SemanticTokensOptions = .{
                    .full = .{ .bool = true },
                    .range = .{ .bool = false },
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
            .inlayHintProvider = .{ .bool = true },
        },
    };
}

fn initializedHandler(server: *Server, notification: types.InitializedParams) Error!void {
    _ = notification;

    if (server.status != .initializing) {
        log.warn("received a initialized notification but the server has not send a initialize request!", .{});
    }

    server.status = .initialized;

    if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration();
}

fn shutdownHandler(server: *Server, _: void) Error!?void {
    defer server.status = .shutdown;
    if (server.status != .initialized) return error.InvalidRequest; // received a shutdown request but the server is not initialized!

    return null;
}

fn exitHandler(server: *Server, _: void) Error!void {
    server.status = switch (server.status) {
        .initialized => .exiting_failure,
        .shutdown => .exiting_success,
        else => unreachable,
    };
}

fn cancelRequestHandler(server: *Server, request: types.CancelParams) Error!void {
    _ = server;
    _ = request;
    // TODO implement $/cancelRequest
}

fn registerCapability(server: *Server, method: []const u8) Error!void {
    const allocator = server.arena.allocator();

    const id = try std.fmt.allocPrint(allocator, "register-{s}", .{method});
    log.debug("Dynamically registering method '{s}'", .{method});

    var registrations = try allocator.alloc(types.Registration, 1);
    registrations[0] = .{
        .id = id,
        .method = method,
    };

    server.sendRequest(
        .{ .string = id },
        "client/registerCapability",
        types.RegistrationParams{ .registrations = registrations },
    );
}

fn requestConfiguration(server: *Server) Error!void {
    if (server.recording_enabled) {
        log.info("workspace/configuration are disabled during a recording session!", .{});
        return;
    }

    const configuration_items = comptime confi: {
        var comp_confi: [std.meta.fields(Config).len]types.ConfigurationItem = undefined;
        inline for (std.meta.fields(Config)) |field, index| {
            comp_confi[index] = .{
                .section = "zls." ++ field.name,
            };
        }

        break :confi comp_confi;
    };

    server.sendRequest(
        .{ .string = "i_haz_configuration" },
        "workspace/configuration",
        types.ConfigurationParams{
            .items = &configuration_items,
        },
    );
}

fn handleConfiguration(server: *Server, json: std.json.Value) error{OutOfMemory}!void {
    if (server.replay_enabled) {
        log.info("workspace/configuration are disabled during a replay!", .{});
        return;
    }
    log.info("Setting configuration...", .{});

    // NOTE: Does this work with other editors?
    // Yes, String ids are officially supported by LSP
    // but not sure how standard this "standard" really is

    const result = json.Array;

    inline for (std.meta.fields(Config)) |field, index| {
        const value = result.items[index];
        const ft = if (@typeInfo(field.type) == .Optional)
            @typeInfo(field.type).Optional.child
        else
            field.type;
        const ti = @typeInfo(ft);

        if (value != .Null) {
            const new_value: field.type = switch (ft) {
                []const u8 => switch (value) {
                    .String => |s| blk: {
                        if (s.len == 0) {
                            if (field.type == ?[]const u8) {
                                break :blk null;
                            } else {
                                break :blk s;
                            }
                        }
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
            // log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, new_value });
            @field(server.config, field.name) = new_value;
        }
    }
    log.debug("{}", .{server.client_capabilities});

    configuration.configChanged(server.config, server.allocator, null) catch |err| {
        log.err("failed to update configuration: {}", .{err});
    };
}

fn openDocumentHandler(server: *Server, notification: types.DidOpenTextDocumentParams) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = try server.document_store.openDocument(notification.textDocument.uri, notification.textDocument.text);

    if (server.client_capabilities.supports_publish_diagnostics) blk: {
        if (!std.process.can_spawn) break :blk;
        const diagnostics = try server.generateDiagnostics(handle);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }
}

fn changeDocumentHandler(server: *Server, notification: types.DidChangeTextDocumentParams) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(notification.textDocument.uri) orelse return;

    const new_text = try diff.applyTextEdits(server.allocator, handle.text, notification.contentChanges, server.offset_encoding);

    try server.document_store.refreshDocument(handle.uri, new_text);

    if (server.client_capabilities.supports_publish_diagnostics) blk: {
        if (!std.process.can_spawn) break :blk;
        const diagnostics = try server.generateDiagnostics(handle.*);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }
}

fn saveDocumentHandler(server: *Server, notification: types.DidSaveTextDocumentParams) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();
    const uri = notification.textDocument.uri;

    const handle = server.document_store.getHandle(uri) orelse return;
    try server.document_store.applySave(handle);

    if (std.process.can_spawn and server.getAutofixMode() == .on_save) {
        var text_edits = try server.autofix(allocator, handle);

        var workspace_edit = types.WorkspaceEdit{ .changes = .{} };
        try workspace_edit.changes.?.putNoClobber(allocator, uri, try text_edits.toOwnedSlice(allocator));

        server.sendRequest(
            .{ .string = "apply_edit" },
            "workspace/applyEdit",
            types.ApplyWorkspaceEditParams{
                .label = "autofix",
                .edit = workspace_edit,
            },
        );
    }
}

fn closeDocumentHandler(server: *Server, notification: types.DidCloseTextDocumentParams) error{}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    server.document_store.closeDocument(notification.textDocument.uri);
}

fn willSaveWaitUntilHandler(server: *Server, request: types.WillSaveTextDocumentParams) Error!?[]types.TextEdit {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();

    if (server.getAutofixMode() != .will_save_wait_until) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (!std.process.can_spawn) return null;
    var text_edits = try server.autofix(allocator, handle);

    return try text_edits.toOwnedSlice(allocator);
}

fn semanticTokensFullHandler(server: *Server, request: types.SemanticTokensParams) Error!?types.SemanticTokens {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!server.config.enable_semantic_tokens) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const token_array = try semantic_tokens.writeAllSemanticTokens(server.arena, &server.document_store, handle, server.offset_encoding);

    return .{ .data = token_array };
}

fn completionHandler(server: *Server, request: types.CompletionParams) Error!?types.CompletionList {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) {
        var completions = std.ArrayListUnmanaged(types.CompletionItem){};
        try populateSnippedCompletions(server.arena.allocator(), &completions, &snipped_data.top_level_decl_data, server.config.*, null);

        return .{ .isIncomplete = false, .items = completions.items };
    }

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.text, source_index);

    const maybe_completions = switch (pos_context) {
        .builtin => server.builtin_completions.items,
        .var_access, .empty => try server.completeGlobal(source_index, handle),
        .field_access => |loc| try server.completeFieldAccess(handle, source_index, loc),
        .global_error_set => try server.completeError(handle),
        .enum_literal => try server.completeDot(handle),
        .label => try server.completeLabel(source_index, handle),
        .import_string_literal, .embedfile_string_literal => |loc| blk: {
            if (!server.config.enable_import_embedfile_argument_completions) break :blk null;

            const completing = offsets.locToSlice(handle.tree.source, loc);
            const is_import = pos_context == .import_string_literal;
            break :blk completeFileSystemStringLiteral(server.arena.allocator(), &server.document_store, handle, completing, is_import) catch |err| {
                log.err("failed to get file system completions: {}", .{err});
                return null;
            };
        },
        else => null,
    };

    const completions = maybe_completions orelse return null;

    // truncate completions
    for (completions) |*item| {
        if (item.detail) |det| {
            if (det.len > server.config.max_detail_length) {
                item.detail = det[0..server.config.max_detail_length];
            }
        }
    }

    // TODO: config for sorting rule?
    for (completions) |*c| {
        const prefix = kindToSortScore(c.kind.?) orelse continue;

        c.sortText = try std.fmt.allocPrint(server.arena.allocator(), "{s}{s}", .{ prefix, c.label });
    }

    return .{ .isIncomplete = false, .items = completions };
}

fn signatureHelpHandler(server: *Server, request: types.SignatureHelpParams) Error!?types.SignatureHelp {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const getSignatureInfo = @import("signature_help.zig").getSignatureInfo;
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    const signature_info = (try getSignatureInfo(
        &server.document_store,
        server.arena,
        handle,
        source_index,
        data,
    )) orelse return null;

    var signatures = try server.arena.allocator().alloc(types.SignatureInformation, 1);
    signatures[0] = signature_info;

    return .{
        .signatures = signatures,
        .activeSignature = 0,
        .activeParameter = signature_info.activeParameter,
    };
}

fn gotoHandler(server: *Server, request: types.TextDocumentPositionParams, resolve_alias: bool) Error!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.text, source_index);

    return switch (pos_context) {
        .var_access => try server.gotoDefinitionGlobal(source_index, handle, resolve_alias),
        .field_access => |loc| try server.gotoDefinitionFieldAccess(handle, source_index, loc, resolve_alias),
        .import_string_literal => try server.gotoDefinitionString(source_index, handle),
        .label => try server.gotoDefinitionLabel(source_index, handle),
        else => null,
    };
}

fn gotoDefinitionHandler(
    server: *Server,
    request: types.TextDocumentPositionParams,
) Error!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try server.gotoHandler(request, true);
}

fn gotoDeclarationHandler(
    server: *Server,
    request: types.TextDocumentPositionParams,
) Error!?types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try server.gotoHandler(request, false);
}

fn hoverHandler(server: *Server, request: types.HoverParams) Error!?types.Hover {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.text, source_index);

    const response = switch (pos_context) {
        .builtin => try server.hoverDefinitionBuiltin(source_index, handle),
        .var_access => try server.hoverDefinitionGlobal(source_index, handle),
        .field_access => |loc| try server.hoverDefinitionFieldAccess(handle, source_index, loc),
        .label => try server.hoverDefinitionLabel(source_index, handle),
        else => null,
    };

    // TODO: Figure out a better solution for comptime interpreter diags
    if (server.client_capabilities.supports_publish_diagnostics) blk: {
        if (!std.process.can_spawn) break :blk;
        const diagnostics = try server.generateDiagnostics(handle.*);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }

    return response;
}

fn documentSymbolsHandler(server: *Server, request: types.DocumentSymbolParams) Error!?[]types.DocumentSymbol {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    return try analysis.getDocumentSymbols(server.arena.allocator(), handle.tree, server.offset_encoding);
}

fn formattingHandler(server: *Server, request: types.DocumentFormattingParams) Error!?[]types.TextEdit {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (handle.tree.errors.len != 0) return null;

    const allocator = server.arena.allocator();

    const formatted = try handle.tree.render(allocator);

    if (std.mem.eql(u8, handle.text, formatted)) return null;

    // avoid computing diffs if the output is small
    const maybe_edits = if (formatted.len <= 512) null else diff.edits(allocator, handle.text, formatted) catch null;

    const edits = maybe_edits orelse {
        // if edits have been computed we replace the entire file with the formatted text
        return &[1]types.TextEdit{.{
            .range = offsets.locToRange(handle.text, .{ .start = 0, .end = handle.text.len }, server.offset_encoding),
            .newText = formatted,
        }};
    };

    // Convert from `[]diff.Edit` to `[]types.TextEdit`
    var text_edits = try std.ArrayListUnmanaged(types.TextEdit).initCapacity(allocator, edits.items.len);
    for (edits.items) |edit| {
        text_edits.appendAssumeCapacity(.{
            .range = edit.range,
            .newText = edit.newText.items,
        });
    }

    return text_edits.items;
}

fn didChangeConfigurationHandler(server: *Server, request: configuration.DidChangeConfigurationParams) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    // NOTE: VS Code seems to always respond with null
    if (request.settings) |cfg| {
        inline for (std.meta.fields(configuration.Configuration)) |field| {
            if (@field(cfg, field.name)) |value| {
                blk: {
                    if (@TypeOf(value) == []const u8) {
                        if (value.len == 0) {
                            break :blk;
                        }
                    }
                    @field(server.config, field.name) = if (@TypeOf(value) == []const u8) try server.allocator.dupe(u8, value) else value;
                    log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, value });
                }
            }
        }

        configuration.configChanged(server.config, server.allocator, null) catch |err| {
            log.err("failed to update config: {}", .{err});
        };
    } else if (server.client_capabilities.supports_configuration) {
        try server.requestConfiguration();
    }
}

fn renameHandler(server: *Server, request: types.RenameParams) Error!?types.WorkspaceEdit {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const response = try generalReferencesHandler(server, .{ .rename = request });
    return if (response) |rep| rep.rename else null;
}

fn referencesHandler(server: *Server, request: types.ReferenceParams) Error!?[]types.Location {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const response = try generalReferencesHandler(server, .{ .references = request });
    return if (response) |rep| rep.references else null;
}

fn documentHighlightHandler(server: *Server, request: types.DocumentHighlightParams) Error!?[]types.DocumentHighlight {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const response = try generalReferencesHandler(server, .{ .highlight = request });
    return if (response) |rep| rep.highlight else null;
}

const GeneralReferencesRequest = union(enum) {
    rename: types.RenameParams,
    references: types.ReferenceParams,
    highlight: types.DocumentHighlightParams,

    pub fn uri(self: @This()) []const u8 {
        return switch (self) {
            .rename => |rename| rename.textDocument.uri,
            .references => |ref| ref.textDocument.uri,
            .highlight => |highlight| highlight.textDocument.uri,
        };
    }

    pub fn position(self: @This()) types.Position {
        return switch (self) {
            .rename => |rename| rename.position,
            .references => |ref| ref.position,
            .highlight => |highlight| highlight.position,
        };
    }
};

const GeneralReferencesResponse = union {
    rename: types.WorkspaceEdit,
    references: []types.Location,
    highlight: []types.DocumentHighlight,
};

fn generalReferencesHandler(server: *Server, request: GeneralReferencesRequest) Error!?GeneralReferencesResponse {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();

    const handle = server.document_store.getHandle(request.uri()) orelse return null;

    if (request.position().character <= 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position(), server.offset_encoding);
    const pos_context = try analysis.getPositionContext(server.arena.allocator(), handle.text, source_index);

    const decl = switch (pos_context) {
        .var_access => try server.getSymbolGlobal(source_index, handle),
        .field_access => |range| try server.getSymbolFieldAccess(handle, source_index, range),
        .label => try getLabelGlobal(source_index, handle),
        else => null,
    } orelse return null;

    const include_decl = switch (request) {
        .references => |ref| ref.context.includeDeclaration,
        else => true,
    };

    const locations = if (pos_context == .label)
        try references.labelReferences(allocator, decl, server.offset_encoding, include_decl)
    else
        try references.symbolReferences(
            server.arena,
            &server.document_store,
            decl,
            server.offset_encoding,
            include_decl,
            server.config.skip_std_references,
            request != .highlight, // scan the entire workspace except for highlight
        );

    switch (request) {
        .rename => |rename| {
            var changes = std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.TextEdit)){};

            for (locations.items) |loc| {
                const gop = try changes.getOrPutValue(allocator, loc.uri, .{});
                try gop.value_ptr.append(allocator, .{
                    .range = loc.range,
                    .newText = rename.newName,
                });
            }

            // TODO can we avoid having to move map from `changes` to `new_changes`?
            var new_changes: types.Map(types.DocumentUri, []const types.TextEdit) = .{};
            try new_changes.ensureTotalCapacity(allocator, @intCast(u32, changes.count()));

            var changes_it = changes.iterator();
            while (changes_it.next()) |entry| {
                new_changes.putAssumeCapacityNoClobber(entry.key_ptr.*, try entry.value_ptr.toOwnedSlice(allocator));
            }

            return .{ .rename = .{ .changes = new_changes } };
        },
        .references => return .{ .references = locations.items },
        .highlight => {
            var highlights = try std.ArrayListUnmanaged(types.DocumentHighlight).initCapacity(allocator, locations.items.len);
            const uri = handle.uri;
            for (locations.items) |loc| {
                if (!std.mem.eql(u8, loc.uri, uri)) continue;
                highlights.appendAssumeCapacity(.{
                    .range = loc.range,
                    .kind = .Text,
                });
            }
            return .{ .highlight = highlights.items };
        },
    }
}

fn isPositionBefore(lhs: types.Position, rhs: types.Position) bool {
    if (lhs.line == rhs.line) {
        return lhs.character < rhs.character;
    } else {
        return lhs.line < rhs.line;
    }
}

fn inlayHintHandler(server: *Server, request: types.InlayHintParams) Error!?[]types.InlayHint {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!server.config.enable_inlay_hints) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const hover_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;

    // TODO cache hints per document
    // because the function could be stored in a different document
    // we need the regenerate hints when the document itself or its imported documents change
    // with caching it would also make sense to generate all hints instead of only the visible ones
    const hints = try inlay_hints.writeRangeInlayHint(
        server.arena,
        server.config.*,
        &server.document_store,
        handle,
        request.range,
        hover_kind,
        server.offset_encoding,
    );

    // and only convert and return all hints in range for every request
    var visible_hints = hints;

    // small_hints should roughly be sorted by position
    for (hints) |hint, i| {
        if (isPositionBefore(hint.position, request.range.start)) continue;
        visible_hints = hints[i..];
        break;
    }
    for (visible_hints) |hint, i| {
        if (isPositionBefore(hint.position, request.range.end)) continue;
        visible_hints = visible_hints[0..i];
        break;
    }

    return visible_hints;
}

fn codeActionHandler(server: *Server, request: types.CodeActionParams) Error!?[]types.CodeAction {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var builder = code_actions.Builder{
        .arena = server.arena,
        .document_store = &server.document_store,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
    };

    // as of right now, only ast-check errors may get a code action
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    if (server.config.enable_ast_check_diagnostics and handle.tree.errors.len == 0) blk: {
        if (!std.process.can_spawn) break :blk;
        getAstCheckDiagnostics(server, handle.*, &diagnostics) catch |err| {
            log.err("failed to run ast-check: {}", .{err});
            return error.InternalError;
        };
    }

    var actions = std.ArrayListUnmanaged(types.CodeAction){};
    for (diagnostics.items) |diagnostic| {
        try builder.generateCodeAction(diagnostic, &actions);
    }

    return actions.items;
}

fn foldingRangeHandler(server: *Server, request: types.FoldingRangeParams) Error!?[]types.FoldingRange {
    const Token = std.zig.Token;
    const Node = Ast.Node;
    const allocator = server.arena.allocator();
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const helper = struct {
        const Inclusivity = enum { inclusive, exclusive };
        /// Returns true if added.
        fn maybeAddTokRange(
            p_ranges: *std.ArrayList(types.FoldingRange),
            tree: Ast,
            start: Ast.TokenIndex,
            end: Ast.TokenIndex,
            end_reach: Inclusivity,
            encoding: offsets.Encoding,
        ) std.mem.Allocator.Error!bool {
            const can_add = start < end and !tree.tokensOnSameLine(start, end);
            if (can_add) {
                try addTokRange(p_ranges, tree, start, end, end_reach, encoding);
            }
            return can_add;
        }
        fn addTokRange(
            p_ranges: *std.ArrayList(types.FoldingRange),
            tree: Ast,
            start: Ast.TokenIndex,
            end: Ast.TokenIndex,
            end_reach: Inclusivity,
            encoding: offsets.Encoding,
        ) std.mem.Allocator.Error!void {
            std.debug.assert(!std.debug.runtime_safety or !tree.tokensOnSameLine(start, end));

            const start_line = offsets.tokenToPosition(tree, start, encoding).line;
            const end_line = offsets.tokenToPosition(tree, end, encoding).line;

            try p_ranges.append(.{
                .startLine = start_line,
                .endLine = end_line - @boolToInt(end_reach == .exclusive),
            });
        }
    };

    // Used to store the result
    var ranges = std.ArrayList(types.FoldingRange).init(allocator);

    const token_tags: []const Token.Tag = handle.tree.tokens.items(.tag);
    const node_tags: []const Node.Tag = handle.tree.nodes.items(.tag);

    if (token_tags.len == 0) return null;
    if (token_tags[0] == .container_doc_comment) {
        var tok: Ast.TokenIndex = 1;
        while (tok < token_tags.len) : (tok += 1) {
            if (token_tags[tok] != .container_doc_comment) {
                break;
            }
        }
        if (tok > 1) { // each container doc comment has its own line, so each one counts for a line
            try ranges.append(.{
                .startLine = 0,
                .endLine = tok - 1,
            });
        }
    }

    for (node_tags) |node_tag, i| {
        const node = @intCast(Node.Index, i);

        switch (node_tag) {
            // only fold the expression pertaining to the if statement, and the else statement, each respectively.
            // TODO: Should folding multiline condition expressions also be supported? Ditto for the other control flow structures.
            .@"if", .if_simple => {
                const if_full = ast.ifFull(handle.tree, node);

                const start_tok_1 = ast.lastToken(handle.tree, if_full.ast.cond_expr);
                const end_tok_1 = ast.lastToken(handle.tree, if_full.ast.then_expr);
                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok_1, end_tok_1, .inclusive, server.offset_encoding);

                if (if_full.ast.else_expr == 0) continue;

                const start_tok_2 = if_full.else_token;
                const end_tok_2 = ast.lastToken(handle.tree, if_full.ast.else_expr);

                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok_2, end_tok_2, .inclusive, server.offset_encoding);
            },

            // same as if/else
            .@"for",
            .for_simple,
            .@"while",
            .while_cont,
            .while_simple,
            => {
                const loop_full = ast.whileAst(handle.tree, node).?;

                const start_tok_1 = ast.lastToken(handle.tree, loop_full.ast.cond_expr);
                const end_tok_1 = ast.lastToken(handle.tree, loop_full.ast.then_expr);
                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok_1, end_tok_1, .inclusive, server.offset_encoding);

                if (loop_full.ast.else_expr == 0) continue;

                const start_tok_2 = loop_full.else_token;
                const end_tok_2 = ast.lastToken(handle.tree, loop_full.ast.else_expr);
                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok_2, end_tok_2, .inclusive, server.offset_encoding);
            },

            .global_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            .container_field_init,
            .container_field_align,
            .container_field,
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => decl_node_blk: {
                doc_comment_range: {
                    const first_tok: Ast.TokenIndex = handle.tree.firstToken(node);
                    if (first_tok == 0) break :doc_comment_range;

                    const end_doc_tok = first_tok - 1;
                    if (token_tags[end_doc_tok] != .doc_comment) break :doc_comment_range;

                    var start_doc_tok = end_doc_tok;
                    while (start_doc_tok != 0) {
                        if (token_tags[start_doc_tok - 1] != .doc_comment) break;
                        start_doc_tok -= 1;
                    }

                    _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_doc_tok, end_doc_tok, .inclusive, server.offset_encoding);
                }

                // Function prototype folding regions
                var fn_proto_buffer: [1]Node.Index = undefined;
                const fn_proto = ast.fnProto(handle.tree, node, fn_proto_buffer[0..]) orelse
                    break :decl_node_blk;

                const list_start_tok: Ast.TokenIndex = fn_proto.lparen;
                const list_end_tok: Ast.TokenIndex = ast.lastToken(handle.tree, fn_proto.ast.proto_node);

                if (handle.tree.tokensOnSameLine(list_start_tok, list_end_tok)) break :decl_node_blk;
                try ranges.ensureUnusedCapacity(1 + fn_proto.ast.params.len); // best guess, doesn't include anytype params
                helper.addTokRange(&ranges, handle.tree, list_start_tok, list_end_tok, .exclusive, server.offset_encoding) catch |err| switch (err) {
                    error.OutOfMemory => unreachable,
                };

                var it = fn_proto.iterate(&handle.tree);
                while (ast.nextFnParam(&it)) |param| {
                    const doc_start_tok = param.first_doc_comment orelse continue;
                    var doc_end_tok = doc_start_tok;

                    while (token_tags[doc_end_tok + 1] == .doc_comment)
                        doc_end_tok += 1;

                    _ = try helper.maybeAddTokRange(&ranges, handle.tree, doc_start_tok, doc_end_tok, .inclusive, server.offset_encoding);
                }
            },

            .@"catch",
            .@"orelse",
            .multiline_string_literal,
            // TODO: Similar to condition expressions in control flow structures, should folding multiline grouped expressions be enabled?
            // .grouped_expression,
            => {
                const start_tok = handle.tree.firstToken(node);
                const end_tok = ast.lastToken(handle.tree, node);
                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok, end_tok, .inclusive, server.offset_encoding);
            },

            // most other trivial cases can go through here.
            else => {
                switch (node_tag) {
                    .array_init,
                    .array_init_one,
                    .array_init_dot_two,
                    .array_init_one_comma,
                    .array_init_dot_two_comma,
                    .array_init_dot,
                    .array_init_dot_comma,
                    .array_init_comma,

                    .struct_init,
                    .struct_init_one,
                    .struct_init_one_comma,
                    .struct_init_dot_two,
                    .struct_init_dot_two_comma,
                    .struct_init_dot,
                    .struct_init_dot_comma,
                    .struct_init_comma,

                    .@"switch",
                    .switch_comma,
                    => {},

                    else => disallow_fold: {
                        if (ast.isBlock(handle.tree, node))
                            break :disallow_fold;

                        if (ast.isCall(handle.tree, node))
                            break :disallow_fold;

                        if (ast.isBuiltinCall(handle.tree, node))
                            break :disallow_fold;

                        if (ast.isContainer(handle.tree, node) and node_tag != .root)
                            break :disallow_fold;

                        continue; // no conditions met, continue iterating without adding this potential folding range
                    },
                }

                const start_tok = handle.tree.firstToken(node);
                const end_tok = ast.lastToken(handle.tree, node);
                _ = try helper.maybeAddTokRange(&ranges, handle.tree, start_tok, end_tok, .exclusive, server.offset_encoding);
            },
        }
    }

    // Iterate over the source code and look for code regions with #region #endregion
    {
        // We add opened folding regions to a stack as we go and pop one off when we find a closing brace.
        // As an optimization we start with a reasonable capacity, which should work well in most cases since
        // people will almost never have nesting that deep.
        var stack = try std.ArrayList(u32).initCapacity(allocator, 10);

        var i: usize = 0;
        var lines_count: u32 = 0;
        while (i < handle.tree.source.len) : (i += 1) {
            const slice = handle.tree.source[i..];

            if (slice[0] == '\n') {
                lines_count += 1;
            }

            if (std.mem.startsWith(u8, slice, "//#region")) {
                try stack.append(lines_count);
            }

            if (std.mem.startsWith(u8, slice, "//#endregion") and stack.items.len > 0) {
                const start_line = stack.pop();
                const end_line = lines_count;

                // Add brace pairs but discard those from the same line, no need to waste memory on them
                if (start_line != end_line) {
                    try ranges.append(.{
                        .startLine = start_line,
                        .endLine = end_line,
                    });
                }
            }
        }
    }

    return ranges.items;
}

pub const SelectionRange = struct {
    range: types.Range,
    parent: ?*SelectionRange,
};

fn selectionRangeHandler(server: *Server, request: types.SelectionRangeParams) Error!?[]*SelectionRange {
    const allocator = server.arena.allocator();
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    // For each of the input positons, we need to compute the stack of AST
    // nodes/ranges which contain the position. At the moment, we do this in a
    // super inefficient way, by iterationg _all_ nodes, selecting the ones that
    // contain position, and then sorting.
    //
    // A faster algorithm would be to walk the tree starting from the root,
    // descending into the child containing the position at every step.
    var result = try allocator.alloc(*SelectionRange, request.positions.len);
    var locs = try std.ArrayListUnmanaged(offsets.Loc).initCapacity(allocator, 32);
    for (request.positions) |position, position_index| {
        const index = offsets.positionToIndex(handle.text, position, server.offset_encoding);

        locs.clearRetainingCapacity();
        for (handle.tree.nodes.items(.data)) |_, i| {
            const node = @intCast(Ast.Node.Index, i);
            const loc = offsets.nodeToLoc(handle.tree, node);
            if (loc.start <= index and index <= loc.end) {
                try locs.append(allocator, loc);
            }
        }

        std.sort.sort(offsets.Loc, locs.items, {}, shorterLocsFirst);
        {
            var i: usize = 0;
            while (i + 1 < locs.items.len) {
                if (std.meta.eql(locs.items[i], locs.items[i + 1])) {
                    _ = locs.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        var selection_ranges = try allocator.alloc(SelectionRange, locs.items.len);
        for (selection_ranges) |*range, i| {
            range.range = offsets.locToRange(handle.text, locs.items[i], server.offset_encoding);
            range.parent = if (i + 1 < selection_ranges.len) &selection_ranges[i + 1] else null;
        }
        result[position_index] = &selection_ranges[0];
    }

    return result;
}

fn shorterLocsFirst(_: void, lhs: offsets.Loc, rhs: offsets.Loc) bool {
    return (lhs.end - lhs.start) < (rhs.end - rhs.start);
}

/// return true if there is a request with the given method name
fn requestMethodExists(method: []const u8) bool {
    const methods = comptime blk: {
        var methods: [types.request_metadata.len][]const u8 = undefined;
        for (types.request_metadata) |meta, i| {
            methods[i] = meta.method;
        }
        break :blk methods;
    };

    return for (methods) |name| {
        if (std.mem.eql(u8, method, name)) break true;
    } else false;
}

/// return true if there is a notification with the given method name
fn notificationMethodExists(method: []const u8) bool {
    const methods = comptime blk: {
        var methods: [types.notification_metadata.len][]const u8 = undefined;
        for (types.notification_metadata) |meta, i| {
            methods[i] = meta.method;
        }
        break :blk methods;
    };

    return for (methods) |name| {
        if (std.mem.eql(u8, method, name)) break true;
    } else false;
}

const Message = union(enum) {
    RequestMessage: struct {
        id: types.RequestId,
        method: []const u8,
        /// may be null
        params: types.LSPAny,
    },
    NotificationMessage: struct {
        method: []const u8,
        /// may be null
        params: types.LSPAny,
    },
    ResponseMessage: struct {
        id: types.RequestId,
        /// non null on success
        result: types.LSPAny,
        @"error": ?types.ResponseError,
    },

    pub fn id(self: Message) ?types.RequestId {
        return switch (self) {
            .RequestMessage => |request| request.id,
            .NotificationMessage => null,
            .ResponseMessage => |response| response.id,
        };
    }

    pub fn method(self: Message) ?[]const u8 {
        return switch (self) {
            .RequestMessage => |request| request.method,
            .NotificationMessage => |notification| notification.method,
            .ResponseMessage => null,
        };
    }

    pub fn params(self: Message) ?types.LSPAny {
        return switch (self) {
            .RequestMessage => |request| request.params,
            .NotificationMessage => |notification| notification.params,
            .ResponseMessage => null,
        };
    }

    pub fn fromJsonValueTree(tree: std.json.ValueTree) error{InvalidRequest}!Message {
        if (tree.root != .Object) return error.InvalidRequest;
        const object = tree.root.Object;

        if (object.get("id")) |id_obj| {
            comptime std.debug.assert(!tres.isAllocatorRequired(types.RequestId));
            const msg_id = tres.parse(types.RequestId, id_obj, null) catch return error.InvalidRequest;

            if (object.get("method")) |method_obj| {
                const msg_method = switch (method_obj) {
                    .String => |str| str,
                    else => return error.InvalidRequest,
                };

                const msg_params = object.get("params") orelse .Null;

                return .{ .RequestMessage = .{
                    .id = msg_id,
                    .method = msg_method,
                    .params = msg_params,
                } };
            } else {
                const result = object.get("result") orelse .Null;
                const error_obj = object.get("error") orelse .Null;

                comptime std.debug.assert(!tres.isAllocatorRequired(?types.ResponseError));
                const err = tres.parse(?types.ResponseError, error_obj, null) catch return error.InvalidRequest;

                if (result != .Null and err != null) return error.InvalidRequest;

                return .{ .ResponseMessage = .{
                    .id = msg_id,
                    .result = result,
                    .@"error" = err,
                } };
            }
        } else {
            const msg_method = switch (object.get("method") orelse return error.InvalidRequest) {
                .String => |str| str,
                else => return error.InvalidRequest,
            };

            const msg_params = object.get("params") orelse .Null;

            return .{ .NotificationMessage = .{
                .method = msg_method,
                .params = msg_params,
            } };
        }
    }
};

pub fn processJsonRpc(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    json: []const u8,
) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    server.arena = arena;

    var parser = std.json.Parser.init(server.arena.allocator(), false);
    defer parser.deinit();

    var tree = parser.parse(json) catch |err| {
        log.err("failed to parse message: {}", .{err});
        return; // maybe panic?
    };
    defer tree.deinit();

    const message = Message.fromJsonValueTree(tree) catch |err| {
        log.err("failed to parse message: {}", .{err});
        return; // maybe panic?
    };

    server.processMessage(message) catch |err| switch (message) {
        .RequestMessage => |request| server.sendResponseError(request.id, .{
            .code = @errorToInt(err),
            .message = @errorName(err),
        }),
        else => {},
    };
}

fn processMessage(server: *Server, message: Message) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    switch (message) {
        .RequestMessage => |request| {
            if (!requestMethodExists(request.method)) return error.MethodNotFound;
        },
        .NotificationMessage => |notification| {
            if (!notificationMethodExists(notification.method)) return error.MethodNotFound;
        },
        .ResponseMessage => |response| {
            if (response.id != .string) return;
            if (std.mem.startsWith(u8, response.id.string, "register")) return;
            if (std.mem.eql(u8, response.id.string, "apply_edit")) return;

            if (std.mem.eql(u8, response.id.string, "i_haz_configuration")) {
                if (response.@"error" != null) return;
                try server.handleConfiguration(response.result);
                return;
            }

            log.warn("received response from client with id '{s}' that has no handler!", .{response.id.string});
            return;
        },
    }

    const method = message.method().?; // message cannot be a ResponseMessage

    switch (server.status) {
        .uninitialized => blk: {
            if (std.mem.eql(u8, method, "initialize")) break :blk;
            if (std.mem.eql(u8, method, "exit")) break :blk;

            return error.ServerNotInitialized; // server received a request before being initialized!
        },
        .initializing => blk: {
            if (std.mem.eql(u8, method, "initialized")) break :blk;
            if (std.mem.eql(u8, method, "$/progress")) break :blk;

            return error.InvalidRequest; // server received a request during initialization!
        },
        .initialized => {},
        .shutdown => blk: {
            if (std.mem.eql(u8, method, "exit")) break :blk;

            return error.InvalidRequest; // server received a request after shutdown!
        },
        .exiting_success,
        .exiting_failure,
        => unreachable,
    }

    const start_time = std.time.milliTimestamp();
    defer {
        // makes `zig build test` look nice
        if (!zig_builtin.is_test) {
            const end_time = std.time.milliTimestamp();
            log.debug("Took {}ms to process method {s}", .{ end_time - start_time, method });
        }
    }

    const method_map = .{
        .{ "initialized", initializedHandler },
        .{ "initialize", initializeHandler },
        .{ "shutdown", shutdownHandler },
        .{ "exit", exitHandler },
        .{ "$/cancelRequest", cancelRequestHandler },
        .{ "textDocument/didOpen", openDocumentHandler },
        .{ "textDocument/didChange", changeDocumentHandler },
        .{ "textDocument/didSave", saveDocumentHandler },
        .{ "textDocument/didClose", closeDocumentHandler },
        .{ "textDocument/willSaveWaitUntil", willSaveWaitUntilHandler },
        .{ "textDocument/semanticTokens/full", semanticTokensFullHandler },
        .{ "textDocument/inlayHint", inlayHintHandler },
        .{ "textDocument/completion", completionHandler },
        .{ "textDocument/signatureHelp", signatureHelpHandler },
        .{ "textDocument/definition", gotoDefinitionHandler },
        .{ "textDocument/typeDefinition", gotoDefinitionHandler },
        .{ "textDocument/implementation", gotoDefinitionHandler },
        .{ "textDocument/declaration", gotoDeclarationHandler },
        .{ "textDocument/hover", hoverHandler },
        .{ "textDocument/documentSymbol", documentSymbolsHandler },
        .{ "textDocument/formatting", formattingHandler },
        .{ "textDocument/rename", renameHandler },
        .{ "textDocument/references", referencesHandler },
        .{ "textDocument/documentHighlight", documentHighlightHandler },
        .{ "textDocument/codeAction", codeActionHandler },
        .{ "workspace/didChangeConfiguration", didChangeConfigurationHandler }, // types.DidChangeConfigurationParams
        .{ "textDocument/foldingRange", foldingRangeHandler },
        .{ "textDocument/selectionRange", selectionRangeHandler },
    };

    comptime {
        inline for (method_map) |method_info| {
            _ = method_info;
            // TODO validate that the method actually exists
            // TODO validate that direction is client_to_server
            // TODO validate that the handler accepts and returns the correct types
            // TODO validate that notification handler return Error!void
            // TODO validate handler parameter names
        }
    }

    @setEvalBranchQuota(10000);
    inline for (method_map) |method_info| {
        if (std.mem.eql(u8, method, method_info[0])) {
            const handler = method_info[1];

            const handler_info: std.builtin.Type.Fn = @typeInfo(@TypeOf(handler)).Fn;
            const ParamsType = handler_info.params[1].type.?; // TODO add error message on null

            const params: ParamsType = tres.parse(ParamsType, message.params().?, server.arena.allocator()) catch return error.InternalError;
            const response = handler(server, params) catch |err| {
                log.err("got {} error while handling {s}", .{ err, method });
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
                return error.InternalError;
            };

            if (@TypeOf(response) == void) return;

            if (message == .RequestMessage) {
                server.sendResponse(message.RequestMessage.id, response);
            }

            return;
        }
    }

    switch (message) {
        .RequestMessage => |request| server.sendResponse(request.id, null),
        .NotificationMessage => return,
        .ResponseMessage => unreachable,
    }
}

pub fn init(
    allocator: std.mem.Allocator,
    config: *Config,
    config_path: ?[]const u8,
    recording_enabled: bool,
    replay_enabled: bool,
) !Server {
    // TODO replace global with something like an Analyser struct
    // which contains using_trail & resolve_trail and place it inside Server
    // see: https://github.com/zigtools/zls/issues/536
    analysis.init(allocator);

    try configuration.configChanged(config, allocator, config_path);

    var document_store = DocumentStore{
        .allocator = allocator,
        .config = config,
    };
    errdefer document_store.deinit();

    var builtin_completions = try std.ArrayListUnmanaged(types.CompletionItem).initCapacity(allocator, data.builtins.len);
    errdefer builtin_completions.deinit(allocator);

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
                .MarkupContent = .{
                    .kind = .markdown,
                    .value = builtin.documentation,
                },
            },
        });
    }

    return Server{
        .config = config,
        .allocator = allocator,
        .document_store = document_store,
        .builtin_completions = builtin_completions,
        .recording_enabled = recording_enabled,
        .replay_enabled = replay_enabled,
        .status = .uninitialized,
    };
}

pub fn deinit(server: *Server) void {
    server.document_store.deinit();
    analysis.deinit();

    server.builtin_completions.deinit(server.allocator);

    for (server.outgoing_messages.items) |message| {
        server.allocator.free(message);
    }
    server.outgoing_messages.deinit(server.allocator);
}
