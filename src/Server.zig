const Server = @This();

const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const DocumentStore = @import("DocumentStore.zig");
const types = @import("lsp.zig");
const Analyser = @import("analysis.zig");
const ast = @import("ast.zig");
const offsets = @import("offsets.zig");
const shared = @import("shared.zig");
const Ast = std.zig.Ast;
const tracy = @import("tracy.zig");
const diff = @import("diff.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
const analyser = @import("analyser/analyser.zig");
const ZigVersionWrapper = @import("ZigVersionWrapper.zig");

const signature_help = @import("features/signature_help.zig");
const references = @import("features/references.zig");
const semantic_tokens = @import("features/semantic_tokens.zig");
const inlay_hints = @import("features/inlay_hints.zig");
const code_actions = @import("features/code_actions.zig");
const folding_range = @import("features/folding_range.zig");
const document_symbol = @import("features/document_symbol.zig");
const completions = @import("features/completions.zig");
const goto = @import("features/goto.zig");
const hover_handler = @import("features/hover.zig");
const selection_range = @import("features/selection_range.zig");
const diagnostics_gen = @import("features/diagnostics.zig");

const tres = @import("tres");

const log = std.log.scoped(.zls_server);

// Server fields

config: *Config,
allocator: std.mem.Allocator,
arena: std.heap.ArenaAllocator,
analyser: Analyser,
document_store: DocumentStore,
builtin_completions: ?std.ArrayListUnmanaged(types.CompletionItem),
client_capabilities: ClientCapabilities = .{},
runtime_zig_version: ?ZigVersionWrapper,
outgoing_messages: std.ArrayListUnmanaged([]const u8) = .{},
recording_enabled: bool,
replay_enabled: bool,
message_tracing_enabled: bool = false,
offset_encoding: offsets.Encoding = .@"utf-16",
status: enum {
    /// the server has not received a `initialize` request
    uninitialized,
    /// the server has received a `initialize` request and is awaiting the `initialized` notification
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
    supports_workspace_did_change_configuration_dynamic_registration: bool = false,
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

fn getAutofixMode(server: *Server) enum {
    on_save,
    will_save_wait_until,
    fixall,
    none,
} {
    if (!server.config.enable_autofix) return .none;
    // TODO https://github.com/zigtools/zls/issues/1093
    // if (server.client_capabilities.supports_code_action_fixall) return .fixall;
    if (server.client_capabilities.supports_apply_edits) {
        if (server.client_capabilities.supports_will_save_wait_until) return .will_save_wait_until;
        return .on_save;
    }
    return .none;
}

/// caller owns returned memory.
pub fn autofix(server: *Server, allocator: std.mem.Allocator, handle: *const DocumentStore.Handle) error{OutOfMemory}!std.ArrayListUnmanaged(types.TextEdit) {
    if (!server.config.enable_ast_check_diagnostics) return .{};
    if (handle.tree.errors.len != 0) return .{};

    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    try diagnostics_gen.getAstCheckDiagnostics(server, handle.*, &diagnostics);
    if (diagnostics.items.len == 0) return .{};

    var builder = code_actions.Builder{
        .arena = server.arena.allocator(),
        .analyser = &server.analyser,
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

pub fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
    if (pos_index + 1 >= handle.text.len) return "";
    var start_idx = pos_index;

    while (start_idx > 0 and Analyser.isSymbolChar(handle.text[start_idx - 1])) {
        start_idx -= 1;
    }

    var end_idx = pos_index;
    while (end_idx < handle.text.len and Analyser.isSymbolChar(handle.text[end_idx])) {
        end_idx += 1;
    }

    if (end_idx <= start_idx) return "";
    return handle.text[start_idx..end_idx];
}

pub fn getLabelGlobal(pos_index: usize, handle: *const DocumentStore.Handle) error{OutOfMemory}!?Analyser.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try Analyser.lookupLabel(handle, name, pos_index);
}

pub fn getSymbolGlobal(
    server: *Server,
    pos_index: usize,
    handle: *const DocumentStore.Handle,
) error{OutOfMemory}!?Analyser.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = Server.identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try server.analyser.lookupSymbolGlobal(handle, name, pos_index);
}

/// Multiple when using branched types
pub fn getSymbolFieldAccesses(
    server: *Server,
    handle: *const DocumentStore.Handle,
    source_index: usize,
    loc: offsets.Loc,
) error{OutOfMemory}!?[]const Analyser.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = Server.identifierFromPosition(source_index, handle.*);
    if (name.len == 0) return null;

    var held_range = try server.arena.allocator().dupeZ(u8, offsets.locToSlice(handle.text, loc));
    var tokenizer = std.zig.Tokenizer.init(held_range);

    var decls_with_handles = std.ArrayListUnmanaged(Analyser.DeclWithHandle){};

    if (try server.analyser.getFieldAccessType(handle, source_index, &tokenizer)) |result| {
        const container_handle = result.unwrapped orelse result.original;

        const container_handle_nodes = try container_handle.getAllTypesWithHandles(server.arena.allocator());

        for (container_handle_nodes) |ty| {
            const container_handle_node = switch (ty.type.data) {
                .other => |n| n,
                else => continue,
            };
            try decls_with_handles.append(server.arena.allocator(), (try server.analyser.lookupSymbolContainer(
                .{ .node = container_handle_node, .handle = ty.handle },
                name,
                true,
            )) orelse continue);
        }
    }

    return try decls_with_handles.toOwnedSlice(server.arena.allocator());
}

fn initializeHandler(server: *Server, request: types.InitializeParams) Error!types.InitializeResult {
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
                    if (format == .plaintext) {
                        break;
                    }
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
                        if (format == .plaintext) {
                            break;
                        }
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
            if (codeaction.codeActionLiteralSupport) |literalSupport| {
                if (!skip_set_fixall) {
                    const fixall = std.mem.indexOfScalar(types.CodeActionKind, literalSupport.codeActionKind.valueSet, .@"source.fixAll") != null;
                    server.client_capabilities.supports_code_action_fixall = fixall;
                }
            }
        }
    }

    if (request.capabilities.workspace) |workspace| {
        server.client_capabilities.supports_apply_edits = workspace.applyEdit orelse false;
        server.client_capabilities.supports_configuration = workspace.configuration orelse false;
        if (workspace.didChangeConfiguration) |did_change| {
            if (did_change.dynamicRegistration orelse false) {
                server.client_capabilities.supports_workspace_did_change_configuration_dynamic_registration = true;
            }
        }
    }

    if (request.trace) |trace| {
        // To support --enable-message-tracing, only allow turning this on here
        if (trace != .off) {
            server.message_tracing_enabled = true;
        }
    }

    log.info("zls initializing", .{});
    log.info("{}", .{server.client_capabilities});
    log.info("Using offset encoding: {s}", .{@tagName(server.offset_encoding)});

    server.status = .initializing;

    if (server.runtime_zig_version) |zig_version_wrapper| {
        const zig_version = zig_version_wrapper.version;
        const zls_version = comptime std.SemanticVersion.parse(build_options.version) catch unreachable;

        const zig_version_simple = std.SemanticVersion{
            .major = zig_version.major,
            .minor = zig_version.minor,
            .patch = 0,
        };
        const zls_version_simple = std.SemanticVersion{
            .major = zls_version.major,
            .minor = zls_version.minor,
            .patch = 0,
        };

        switch (zig_version_simple.order(zls_version_simple)) {
            .lt => {
                server.showMessage(.Warning,
                    \\Zig `{}` is older than ZLS `{}`. Update Zig to avoid unexpected behavior.
                , .{ zig_version, zls_version });
            },
            .eq => {},
            .gt => {
                server.showMessage(.Warning,
                    \\Zig `{}` is newer than ZLS `{}`. Update ZLS to avoid unexpected behavior.
                , .{ zig_version, zls_version });
            },
        }
    }

    if (server.recording_enabled) {
        server.showMessage(.Info,
            \\This zls session is being recorded to {?s}.
        , .{server.config.record_session_path});
    }

    if (server.config.enable_ast_check_diagnostics and
        server.config.prefer_ast_check_as_child_process)
    {
        if (!std.process.can_spawn) {
            log.info("'prefer_ast_check_as_child_process' is ignored because your OS can't spawn a child process", .{});
        } else if (server.config.zig_exe_path == null) {
            log.info("'prefer_ast_check_as_child_process' is ignored because Zig could not be found", .{});
        }
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
                .triggerCharacters = &[_][]const u8{ ".", ":", "@", "]", "/" },
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
                    .range = .{ .bool = true },
                    .legend = .{
                        .tokenTypes = std.meta.fieldNames(semantic_tokens.TokenType),
                        .tokenModifiers = std.meta.fieldNames(semantic_tokens.TokenModifiers),
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

    if (server.client_capabilities.supports_workspace_did_change_configuration_dynamic_registration) {
        try server.registerCapability("workspace/didChangeConfiguration");
    }

    if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration();
}

fn shutdownHandler(server: *Server, _: void) Error!?void {
    defer server.status = .shutdown;
    if (server.status != .initialized) return error.InvalidRequest; // received a shutdown request but the server is not initialized!
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

fn setTraceHandler(server: *Server, request: types.SetTraceParams) Error!void {
    server.message_tracing_enabled = request.value != .off;
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

    const configuration_items = comptime config: {
        var comp_config: [std.meta.fields(Config).len]types.ConfigurationItem = undefined;
        inline for (std.meta.fields(Config), 0..) |field, index| {
            comp_config[index] = .{
                .section = "zls." ++ field.name,
            };
        }

        break :config comp_config;
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
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.replay_enabled) {
        log.info("workspace/configuration are disabled during a replay!", .{});
        return;
    }
    log.info("Setting configuration...", .{});

    // NOTE: Does this work with other editors?
    // Yes, String ids are officially supported by LSP
    // but not sure how standard this "standard" really is

    var new_zig_exe = false;
    const result = json.array;

    inline for (std.meta.fields(Config), result.items) |field, value| {
        const ft = if (@typeInfo(field.type) == .Optional)
            @typeInfo(field.type).Optional.child
        else
            field.type;
        const ti = @typeInfo(ft);

        if (value != .null) {
            const new_value: field.type = switch (ft) {
                []const u8 => switch (value) {
                    .string => |s| blk: {
                        const trimmed = std.mem.trim(u8, s, " ");
                        if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "nil")) {
                            log.warn("Ignoring new value for \"zls.{s}\": the given new value is invalid", .{field.name});
                            break :blk @field(server.config, field.name);
                        }
                        var nv = try server.allocator.dupe(u8, trimmed);

                        if (comptime std.mem.eql(u8, field.name, "zig_exe_path")) {
                            if (server.config.zig_exe_path == null or !std.mem.eql(u8, nv, server.config.zig_exe_path.?)) {
                                new_zig_exe = true;
                            }
                        }

                        if (@field(server.config, field.name)) |prev_val| server.allocator.free(prev_val);

                        break :blk nv;
                    },
                    else => blk: {
                        log.warn("Ignoring new value for \"zls.{s}\": the given new value has an invalid type", .{field.name});
                        break :blk @field(server.config, field.name);
                    },
                },
                else => switch (ti) {
                    .Int => switch (value) {
                        .integer => |val| std.math.cast(ft, val) orelse blk: {
                            log.warn("Ignoring new value for \"zls.{s}\": the given new value is invalid", .{field.name});
                            break :blk @field(server.config, field.name);
                        },
                        else => blk: {
                            log.warn("Ignoring new value for \"zls.{s}\": the given new value has an invalid type", .{field.name});
                            break :blk @field(server.config, field.name);
                        },
                    },
                    .Bool => switch (value) {
                        .bool => |b| b,
                        else => blk: {
                            log.warn("Ignoring new value for \"zls.{s}\": the given new value has an invalid type", .{field.name});
                            break :blk @field(server.config, field.name);
                        },
                    },
                    .Enum => switch (value) {
                        .string => |s| blk: {
                            const trimmed = std.mem.trim(u8, s, " ");
                            break :blk std.meta.stringToEnum(field.type, trimmed) orelse inner: {
                                log.warn("Ignoring new value for \"zls.{s}\": the given new value is invalid", .{field.name});
                                break :inner @field(server.config, field.name);
                            };
                        },
                        else => blk: {
                            log.warn("Ignoring new value for \"zls.{s}\": the given new value has an invalid type", .{field.name});
                            break :blk @field(server.config, field.name);
                        },
                    },
                    else => @compileError("Not implemented for " ++ @typeName(ft)),
                },
            };
            // log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, new_value });
            @field(server.config, field.name) = new_value;
        }
    }
    log.debug("{}", .{server.client_capabilities});

    configuration.configChanged(server.config, &server.runtime_zig_version, server.allocator, null) catch |err| {
        log.err("failed to update configuration: {}", .{err});
    };

    if (new_zig_exe)
        server.document_store.invalidateBuildFiles();
}

fn openDocumentHandler(server: *Server, notification: types.DidOpenTextDocumentParams) Error!void {
    const handle = try server.document_store.openDocument(notification.textDocument.uri, try server.document_store.allocator.dupeZ(u8, notification.textDocument.text));

    if (server.client_capabilities.supports_publish_diagnostics) {
        const diagnostics = try diagnostics_gen.generateDiagnostics(server, handle);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }
}

fn changeDocumentHandler(server: *Server, notification: types.DidChangeTextDocumentParams) Error!void {
    // whenever a document changes, any cached info is invalidated
    server.analyser.invalidate();

    const handle = server.document_store.getHandle(notification.textDocument.uri) orelse return;

    const new_text = try diff.applyContentChanges(server.allocator, handle.text, notification.contentChanges, server.offset_encoding);

    try server.document_store.refreshDocument(handle.uri, new_text);

    if (server.client_capabilities.supports_publish_diagnostics) {
        const diagnostics = try diagnostics_gen.generateDiagnostics(server, handle.*);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }
}

fn saveDocumentHandler(server: *Server, notification: types.DidSaveTextDocumentParams) Error!void {
    const allocator = server.arena.allocator();
    const uri = notification.textDocument.uri;

    const handle = server.document_store.getHandle(uri) orelse return;
    try server.document_store.applySave(handle);

    if (server.getAutofixMode() == .on_save) {
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
    // cached type info may point to a closed handle
    server.analyser.invalidate();

    server.document_store.closeDocument(notification.textDocument.uri);
}

fn willSaveWaitUntilHandler(server: *Server, request: types.WillSaveTextDocumentParams) Error!?[]types.TextEdit {
    const allocator = server.arena.allocator();

    if (server.getAutofixMode() != .will_save_wait_until) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var text_edits = try server.autofix(allocator, handle);

    return try text_edits.toOwnedSlice(allocator);
}

fn semanticTokensFullHandler(server: *Server, request: types.SemanticTokensParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    return try semantic_tokens.writeSemanticTokens(
        server.arena.allocator(),
        &server.analyser,
        handle,
        null,
        server.offset_encoding,
        server.config.semantic_tokens == .partial,
    );
}

fn semanticTokensRangeHandler(server: *Server, request: types.SemanticTokensRangeParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const loc = offsets.rangeToLoc(handle.tree.source, request.range, server.offset_encoding);

    return try semantic_tokens.writeSemanticTokens(
        server.arena.allocator(),
        &server.analyser,
        handle,
        loc,
        server.offset_encoding,
        server.config.semantic_tokens == .partial,
    );
}

pub fn completionHandler(server: *Server, request: types.CompletionParams) Error!?types.CompletionList {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);
    return try completions.completionAtIndex(server, source_index, handle);
}

pub fn signatureHelpHandler(server: *Server, request: types.SignatureHelpParams) Error!?types.SignatureHelp {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    const signature_info = (try signature_help.getSignatureInfo(
        &server.analyser,
        server.arena.allocator(),
        handle,
        source_index,
    )) orelse return null;

    var signatures = try server.arena.allocator().alloc(types.SignatureInformation, 1);
    signatures[0] = signature_info;

    return .{
        .signatures = signatures,
        .activeSignature = 0,
        .activeParameter = signature_info.activeParameter,
    };
}

fn gotoDefinitionHandler(
    server: *Server,
    request: types.TextDocumentPositionParams,
) Error!?types.Definition {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    return try goto.goto(server, source_index, handle, true);
}

fn gotoDeclarationHandler(
    server: *Server,
    request: types.TextDocumentPositionParams,
) Error!?types.Definition {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    return try goto.goto(server, source_index, handle, false);
}

pub fn hoverHandler(server: *Server, request: types.HoverParams) Error!?types.Hover {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    const response = hover_handler.hover(server, source_index, handle);

    // TODO: Figure out a better solution for comptime interpreter diags
    if (server.client_capabilities.supports_publish_diagnostics) {
        const diagnostics = try diagnostics_gen.generateDiagnostics(server, handle.*);
        server.sendNotification("textDocument/publishDiagnostics", diagnostics);
    }

    return response;
}

pub fn documentSymbolsHandler(server: *Server, request: types.DocumentSymbolParams) Error!?[]types.DocumentSymbol {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    return try document_symbol.getDocumentSymbols(server.arena.allocator(), handle.tree, server.offset_encoding);
}

pub fn formattingHandler(server: *Server, request: types.DocumentFormattingParams) Error!?[]types.TextEdit {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (handle.tree.errors.len != 0) return null;

    const allocator = server.arena.allocator();

    const formatted = try handle.tree.render(allocator);

    if (std.mem.eql(u8, handle.text, formatted)) return null;

    return if (diff.edits(allocator, handle.text, formatted, server.offset_encoding)) |text_edits| text_edits.items else |_| null;
}

fn didChangeConfigurationHandler(server: *Server, request: configuration.DidChangeConfigurationParams) Error!void {
    var new_zig_exe = false;

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

                    if (comptime std.mem.eql(u8, field.name, "zig_exe_path")) {
                        if (cfg.zig_exe_path == null or !std.mem.eql(u8, value, cfg.zig_exe_path.?)) {
                            new_zig_exe = true;
                        }
                    }

                    if (@TypeOf(value) == []const u8) {
                        if (@field(server.config, field.name)) |existing| server.allocator.free(existing);
                        @field(server.config, field.name) = try server.allocator.dupe(u8, value);
                    } else {
                        @field(server.config, field.name) = value;
                    }
                    log.debug("setting configuration option '{s}' to '{any}'", .{ field.name, value });
                }
            }
        }

        configuration.configChanged(server.config, &server.runtime_zig_version, server.allocator, null) catch |err| {
            log.err("failed to update config: {}", .{err});
        };

        if (new_zig_exe)
            server.document_store.invalidateBuildFiles();
    } else if (server.client_capabilities.supports_configuration) {
        try server.requestConfiguration();
    }
}

pub fn renameHandler(server: *Server, request: types.RenameParams) Error!?types.WorkspaceEdit {
    const response = try generalReferencesHandler(server, .{ .rename = request });
    return if (response) |rep| rep.rename else null;
}

pub fn referencesHandler(server: *Server, request: types.ReferenceParams) Error!?[]types.Location {
    const response = try generalReferencesHandler(server, .{ .references = request });
    return if (response) |rep| rep.references else null;
}

pub fn documentHighlightHandler(server: *Server, request: types.DocumentHighlightParams) Error!?[]types.DocumentHighlight {
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

pub fn generalReferencesHandler(server: *Server, request: GeneralReferencesRequest) Error!?GeneralReferencesResponse {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const allocator = server.arena.allocator();

    const handle = server.document_store.getHandle(request.uri()) orelse return null;

    if (request.position().character <= 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position(), server.offset_encoding);
    const pos_context = try Analyser.getPositionContext(server.arena.allocator(), handle.text, source_index, true);

    // TODO: Make this work with branching types
    const decl = switch (pos_context) {
        .var_access => try server.getSymbolGlobal(source_index, handle),
        .field_access => |range| z: {
            const a = try server.getSymbolFieldAccesses(handle, source_index, range);
            if (a) |b| {
                if (b.len != 0) break :z b[0];
            }

            break :z null;
        },
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
            allocator,
            &server.analyser,
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

fn inlayHintHandler(server: *Server, request: types.InlayHintParams) Error!?[]types.InlayHint {
    if (!server.config.enable_inlay_hints) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const hover_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const loc = offsets.rangeToLoc(handle.text, request.range, server.offset_encoding);

    // TODO cache hints per document
    // because the function could be stored in a different document
    // we need the regenerate hints when the document itself or its imported documents change
    // with caching it would also make sense to generate all hints instead of only the visible ones
    const hints = try inlay_hints.writeRangeInlayHint(
        server.arena.allocator(),
        server.config.*,
        &server.analyser,
        handle,
        loc,
        hover_kind,
    );

    const helper = struct {
        fn lessThan(_: void, lhs: inlay_hints.InlayHint, rhs: inlay_hints.InlayHint) bool {
            return lhs.token_index < rhs.token_index;
        }
    };

    std.sort.sort(inlay_hints.InlayHint, hints, {}, helper.lessThan);

    var last_index: usize = 0;
    var last_position: types.Position = .{ .line = 0, .character = 0 };

    var converted_hints = try server.arena.allocator().alloc(types.InlayHint, hints.len);
    for (hints, 0..) |hint, i| {
        const index = offsets.tokenToIndex(handle.tree, hint.token_index);
        const position = offsets.advancePosition(
            handle.tree.source,
            last_position,
            last_index,
            index,
            server.offset_encoding,
        );
        defer last_index = index;
        defer last_position = position;
        converted_hints[i] = types.InlayHint{
            .position = position,
            .label = .{ .string = hint.label },
            .kind = hint.kind,
            .tooltip = .{ .MarkupContent = hint.tooltip },
            .paddingLeft = false,
            .paddingRight = true,
        };
    }

    return converted_hints;
}

fn codeActionHandler(server: *Server, request: types.CodeActionParams) Error!?[]types.CodeAction {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var builder = code_actions.Builder{
        .arena = server.arena.allocator(),
        .analyser = &server.analyser,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
    };

    // as of right now, only ast-check errors may get a code action
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    if (server.config.enable_ast_check_diagnostics and handle.tree.errors.len == 0) {
        try diagnostics_gen.getAstCheckDiagnostics(server, handle.*, &diagnostics);
    }

    var actions = std.ArrayListUnmanaged(types.CodeAction){};
    for (diagnostics.items) |diagnostic| {
        try builder.generateCodeAction(diagnostic, &actions);
    }

    return actions.items;
}

fn foldingRangeHandler(server: *Server, request: types.FoldingRangeParams) Error!?[]types.FoldingRange {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const allocator = server.arena.allocator();

    return try folding_range.generateFoldingRanges(allocator, handle.tree, server.offset_encoding);
}

fn selectionRangeHandler(server: *Server, request: types.SelectionRangeParams) Error!?[]*selection_range.SelectionRange {
    const allocator = server.arena.allocator();
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    return try selection_range.generateSelectionRanges(allocator, handle, request.positions, server.offset_encoding);
}

/// return true if there is a request with the given method name
fn requestMethodExists(method: []const u8) bool {
    const methods = comptime blk: {
        var methods: [types.request_metadata.len][]const u8 = undefined;
        for (types.request_metadata, &methods) |meta, *out| {
            out.* = meta.method;
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
        for (types.notification_metadata, 0..) |meta, i| {
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
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        if (tree.root != .object) return error.InvalidRequest;
        const object = tree.root.object;

        if (object.get("id")) |id_obj| {
            comptime std.debug.assert(!tres.isAllocatorRequired(types.RequestId));
            const msg_id = tres.parse(types.RequestId, id_obj, null) catch return error.InvalidRequest;

            if (object.get("method")) |method_obj| {
                const msg_method = switch (method_obj) {
                    .string => |str| str,
                    else => return error.InvalidRequest,
                };

                const msg_params = object.get("params") orelse .null;

                return .{ .RequestMessage = .{
                    .id = msg_id,
                    .method = msg_method,
                    .params = msg_params,
                } };
            } else {
                const result = object.get("result") orelse .null;
                const error_obj = object.get("error") orelse .null;

                comptime std.debug.assert(!tres.isAllocatorRequired(?types.ResponseError));
                const err = tres.parse(?types.ResponseError, error_obj, null) catch return error.InvalidRequest;

                if (result != .null and err != null) return error.InvalidRequest;

                return .{ .ResponseMessage = .{
                    .id = msg_id,
                    .result = result,
                    .@"error" = err,
                } };
            }
        } else {
            const msg_method = switch (object.get("method") orelse return error.InvalidRequest) {
                .string => |str| str,
                else => return error.InvalidRequest,
            };

            const msg_params = object.get("params") orelse .null;

            return .{ .NotificationMessage = .{
                .method = msg_method,
                .params = msg_params,
            } };
        }
    }
};

pub fn processJsonRpc(
    server: *Server,
    json: []const u8,
) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var parser = std.json.Parser.init(server.arena.allocator(), .alloc_always);
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

pub fn maybeFreeArena(server: *Server) void {
    // Mom, can we have garbage collection?
    // No, we already have garbage collection at home.
    // at home:
    if (server.arena.queryCapacity() > 128 * 1024) {
        _ = server.arena.reset(.free_all);
    }
}

pub fn processMessage(server: *Server, message: Message) Error!void {
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
            if (std.mem.startsWith(u8, response.id.string, "register")) {
                if (response.@"error") |err| {
                    log.err("Error response for '{s}': {}, {s}", .{ response.id.string, err.code, err.message });
                }
                return;
            }
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
        .{ "$/setTrace", setTraceHandler },
        .{ "textDocument/didOpen", openDocumentHandler },
        .{ "textDocument/didChange", changeDocumentHandler },
        .{ "textDocument/didSave", saveDocumentHandler },
        .{ "textDocument/didClose", closeDocumentHandler },
        .{ "textDocument/willSaveWaitUntil", willSaveWaitUntilHandler },
        .{ "textDocument/semanticTokens/full", semanticTokensFullHandler },
        .{ "textDocument/semanticTokens/range", semanticTokensRangeHandler },
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

            const response = blk: {
                const tracy_zone2 = tracy.trace(@src());
                defer tracy_zone2.end();
                tracy_zone2.setName(method);

                break :blk handler(server, params) catch |err| {
                    log.err("got {} error while handling {s}", .{ err, method });
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                    return error.InternalError;
                };
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

pub fn create(
    allocator: std.mem.Allocator,
    config: *Config,
    config_path: ?[]const u8,
    recording_enabled: bool,
    replay_enabled: bool,
    message_tracing_enabled: bool,
) !*Server {
    const server = try allocator.create(Server);
    errdefer server.destroy();
    server.* = Server{
        .config = config,
        .runtime_zig_version = null,
        .allocator = allocator,
        .analyser = undefined,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .document_store = .{
            .allocator = allocator,
            .config = config,
            .runtime_zig_version = &server.runtime_zig_version,
        },
        .builtin_completions = null,
        .recording_enabled = recording_enabled,
        .replay_enabled = replay_enabled,
        .message_tracing_enabled = message_tracing_enabled,
        .status = .uninitialized,
    };
    server.analyser = Analyser.init(allocator, &server.document_store);

    var builtin_creation_dir = config_path;
    if (config_path) |path| {
        builtin_creation_dir = std.fs.path.dirname(path);
    }

    try configuration.configChanged(config, &server.runtime_zig_version, allocator, builtin_creation_dir);

    if (config.dangerous_comptime_experiments_do_not_enable) {
        server.analyser.ip = try analyser.InternPool.init(allocator);
    }

    return server;
}

pub fn destroy(server: *Server) void {
    server.document_store.deinit();
    server.analyser.deinit();

    if (server.builtin_completions) |*items| items.deinit(server.allocator);

    for (server.outgoing_messages.items) |message| {
        server.allocator.free(message);
    }
    server.outgoing_messages.deinit(server.allocator);

    if (server.runtime_zig_version) |zig_version| {
        zig_version.free();
    }

    server.arena.deinit();

    server.allocator.destroy(server);
}
