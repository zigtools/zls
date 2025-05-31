//! - Store global state
//! - The main loop
//! - Job/Request scheduling
//! - many Request handlers defined here. Except for the major ones which are in `src/features`

const Server = @This();

const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const Config = @import("Config.zig");
const configuration = @import("configuration.zig");
const DocumentStore = @import("DocumentStore.zig");
const lsp = @import("lsp");
const types = lsp.types;
const Analyser = @import("analysis.zig");
const offsets = @import("offsets.zig");
const tracy = @import("tracy");
const diff = @import("diff.zig");
const Uri = @import("uri.zig");
const InternPool = @import("analyser/analyser.zig").InternPool;
const DiagnosticsCollection = @import("DiagnosticsCollection.zig");
const known_folders = @import("known-folders");
const build_runner_shared = @import("build_runner/shared.zig");
const BuildRunnerVersion = @import("build_runner/BuildRunnerVersion.zig").BuildRunnerVersion;

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

const BuildOnSave = diagnostics_gen.BuildOnSave;
const BuildOnSaveSupport = build_runner_shared.BuildOnSaveSupport;

const log = std.log.scoped(.server);

// public fields
allocator: std.mem.Allocator,
/// use updateConfiguration or updateConfiguration2 for setting config options
config: Config = .{},
/// will default to lookup in the system and user configuration folder provided by known-folders.
config_path: ?[]const u8 = null,
document_store: DocumentStore,
/// Use `setTransport` to set the Transport.
transport: ?lsp.AnyTransport = null,
offset_encoding: offsets.Encoding = .@"utf-16",
status: Status = .uninitialized,

// private fields
thread_pool: if (zig_builtin.single_threaded) void else std.Thread.Pool,
wait_group: if (zig_builtin.single_threaded) void else std.Thread.WaitGroup,
job_queue: std.fifo.LinearFifo(Job, .Dynamic),
job_queue_lock: std.Thread.Mutex = .{},
ip: InternPool = undefined,
/// avoid Zig deadlocking when spawning multiple `zig ast-check` processes at the same time.
/// See https://github.com/ziglang/zig/issues/16369
zig_ast_check_lock: std.Thread.Mutex = .{},
/// Additional information that has been resolved from 'config'.
resolved_config: ResolvedConfiguration = .unresolved,
/// Every changed configuration will increase the amount of memory allocated by the arena,
/// This is unlikely to cause any big issues since the user is probably not going set settings
/// often in one session,
config_arena: std.heap.ArenaAllocator.State = .{},
client_capabilities: ClientCapabilities = .{},
diagnostics_collection: DiagnosticsCollection,
workspaces: std.ArrayListUnmanaged(Workspace) = .empty,

// Code was based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

const ClientCapabilities = struct {
    supports_snippets: bool = false,
    supports_apply_edits: bool = false,
    supports_will_save_wait_until: bool = false,
    supports_publish_diagnostics: bool = false,
    supports_code_action_fixall: bool = false,
    supports_semantic_tokens_overlapping: bool = false,
    semantic_tokens_augment_syntax_tokens: bool = false,
    hover_supports_md: bool = false,
    signature_help_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
    supports_completion_insert_replace_support: bool = false,
    /// deprecated can be marked through the `CompletionItem.deprecated` field
    supports_completion_deprecated_old: bool = false,
    /// deprecated can be marked through the `CompletionItem.tags` field
    supports_completion_deprecated_tag: bool = false,
    label_details_support: bool = false,
    supports_configuration: bool = false,
    supports_workspace_did_change_configuration_dynamic_registration: bool = false,
    supports_workspace_did_change_watched_files: bool = false,
    supports_textDocument_definition_linkSupport: bool = false,
    /// The detail entries for big structs such as std.zig.CrossTarget were
    /// bricking the preview window in Sublime Text.
    /// https://github.com/zigtools/zls/pull/261
    max_detail_length: u32 = 1024 * 1024,
    client_name: ?[]const u8 = null,

    fn deinit(self: *ClientCapabilities, allocator: std.mem.Allocator) void {
        if (self.client_name) |name| allocator.free(name);
        self.* = undefined;
    }
};

pub const Error = error{
    OutOfMemory,
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

pub const Status = enum {
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
};

const Job = union(enum) {
    incoming_message: std.json.Parsed(Message),
    generate_diagnostics: DocumentStore.Uri,

    fn deinit(self: Job, allocator: std.mem.Allocator) void {
        switch (self) {
            .incoming_message => |parsed_message| parsed_message.deinit(),
            .generate_diagnostics => |uri| allocator.free(uri),
        }
    }

    const SynchronizationMode = enum {
        /// this `Job` requires exclusive access to `Server` and `DocumentStore`
        /// all previous jobs will be awaited
        exclusive,
        /// this `Job` requires shared access to `Server` and `DocumentStore`
        /// other non exclusive jobs can be processed in parallel
        shared,
    };

    fn syncMode(self: Job) SynchronizationMode {
        return switch (self) {
            .incoming_message => |parsed_message| if (isBlockingMessage(parsed_message.value)) .exclusive else .shared,
            .generate_diagnostics => .shared,
        };
    }
};

fn sendToClientResponse(server: *Server, id: lsp.JsonRPCMessage.ID, result: anytype) error{OutOfMemory}![]u8 {
    const tracy_zone = tracy.traceNamed(@src(), "sendToClientResponse(" ++ @typeName(@TypeOf(result)) ++ ")");
    defer tracy_zone.end();

    // TODO validate result type is a possible response
    // TODO validate response is from a client to server request
    // TODO validate result type

    const response: lsp.TypedJsonRPCResponse(@TypeOf(result)) = .{
        .id = id,
        .result_or_error = .{ .result = result },
    };
    return try sendToClientInternal(server.allocator, server.transport, response);
}

fn sendToClientRequest(server: *Server, id: lsp.JsonRPCMessage.ID, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    const tracy_zone = tracy.traceNamed(@src(), "sendToClientRequest(" ++ @typeName(@TypeOf(params)) ++ ")");
    defer tracy_zone.end();

    // TODO validate method is a request
    // TODO validate method is server to client
    // TODO validate params type

    const request: lsp.TypedJsonRPCRequest(@TypeOf(params)) = .{
        .id = id,
        .method = method,
        .params = params,
    };
    return try sendToClientInternal(server.allocator, server.transport, request);
}

fn sendToClientNotification(server: *Server, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    const tracy_zone = tracy.traceNamed(@src(), "sendToClientRequest(" ++ @typeName(@TypeOf(params)) ++ ")");
    defer tracy_zone.end();

    // TODO validate method is a notification
    // TODO validate method is server to client
    // TODO validate params type

    const notification: lsp.TypedJsonRPCNotification(@TypeOf(params)) = .{
        .method = method,
        .params = params,
    };
    return try sendToClientInternal(server.allocator, server.transport, notification);
}

fn sendToClientResponseError(server: *Server, id: lsp.JsonRPCMessage.ID, err: lsp.JsonRPCMessage.Response.Error) error{OutOfMemory}![]u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const response: lsp.JsonRPCMessage = .{
        .response = .{ .id = id, .result_or_error = .{ .@"error" = err } },
    };

    return try sendToClientInternal(server.allocator, server.transport, response);
}

fn sendToClientInternal(allocator: std.mem.Allocator, transport: ?lsp.AnyTransport, message: anytype) error{OutOfMemory}![]u8 {
    const message_stringified = try std.json.stringifyAlloc(allocator, message, .{
        .emit_null_optional_fields = false,
    });
    errdefer allocator.free(message_stringified);

    if (transport) |t| {
        const tracy_zone = tracy.traceNamed(@src(), "Transport.writeJsonMessage");
        defer tracy_zone.end();

        t.writeJsonMessage(message_stringified) catch |err| {
            log.err("failed to write message: {}", .{err});
        };
    }

    return message_stringified;
}

fn showMessage(
    server: *Server,
    message_type: types.MessageType,
    comptime fmt: []const u8,
    args: anytype,
) void {
    const message = std.fmt.allocPrint(server.allocator, fmt, args) catch return;
    defer server.allocator.free(message);
    switch (message_type) {
        .Error => log.err("{s}", .{message}),
        .Warning => log.warn("{s}", .{message}),
        .Info => log.info("{s}", .{message}),
        .Log, .Debug => log.debug("{s}", .{message}),
        _ => log.debug("{s}", .{message}),
    }
    switch (server.status) {
        .initializing,
        .initialized,
        => {},
        .uninitialized,
        .shutdown,
        .exiting_success,
        .exiting_failure,
        => return,
    }
    if (server.sendToClientNotification("window/showMessage", types.ShowMessageParams{
        .type = message_type,
        .message = message,
    })) |json_message| {
        server.allocator.free(json_message);
    } else |err| {
        log.warn("failed to show message: {}", .{err});
    }
}

pub fn initAnalyser(server: *Server, arena: std.mem.Allocator, handle: ?*DocumentStore.Handle) Analyser {
    return .init(
        server.allocator,
        arena,
        &server.document_store,
        &server.ip,
        handle,
    );
}

pub fn getAutofixMode(server: *Server) enum {
    /// Autofix is implemented by providing `source.fixall` code actions.
    @"source.fixall",
    /// Autofix is implemented using `textDocument/willSaveWaitUntil`.
    /// Requires `force_autofix` to be enabled.
    will_save_wait_until,
    /// Autofix is implemented by send a `workspace/applyEdit` request after receiving a `textDocument/didSave` notification.
    /// Requires `force_autofix` to be enabled.
    on_save,
    none,
} {
    if (server.client_capabilities.supports_code_action_fixall) return .@"source.fixall";
    if (!server.config.force_autofix) return .none;
    if (server.client_capabilities.supports_will_save_wait_until) return .will_save_wait_until;
    if (server.client_capabilities.supports_apply_edits) return .on_save;
    return .none;
}

/// caller owns returned memory.
fn autofix(server: *Server, arena: std.mem.Allocator, handle: *DocumentStore.Handle) error{OutOfMemory}!std.ArrayListUnmanaged(types.TextEdit) {
    if (handle.tree.errors.len != 0) return .empty;
    if (handle.tree.mode == .zon) return .empty;

    var error_bundle = try diagnostics_gen.getAstCheckDiagnostics(server, handle);
    defer error_bundle.deinit(server.allocator);
    if (error_bundle.errorMessageCount() == 0) return .empty;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    var builder: code_actions.Builder = .{
        .arena = arena,
        .analyser = &analyser,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
        .only_kinds = .init(.{
            .@"source.fixAll" = true,
        }),
    };

    try builder.generateCodeAction(error_bundle);
    for (builder.actions.items) |action| {
        std.debug.assert(action.kind.?.eql(.@"source.fixAll")); // We request only source.fixall code actions
    }

    defer builder.fixall_text_edits = .empty;
    return builder.fixall_text_edits;
}

fn initializeHandler(server: *Server, arena: std.mem.Allocator, request: types.InitializeParams) Error!types.InitializeResult {
    var skip_set_fixall = false;
    var support_full_semantic_tokens = true;

    if (request.clientInfo) |clientInfo| {
        server.client_capabilities.client_name = try server.allocator.dupe(u8, clientInfo.name);

        if (std.mem.startsWith(u8, clientInfo.name, "Visual Studio Code") or
            std.mem.startsWith(u8, clientInfo.name, "VSCodium") or
            std.mem.startsWith(u8, clientInfo.name, "Code - OSS"))
        {
            // VS Code doesn't really utilize `textDocument/semanticTokens/range`.
            // This will cause some visual artifacts when scrolling through the
            // document quickly but will considerably improve performance
            // especially on large files.
            support_full_semantic_tokens = false;
        } else if (std.mem.eql(u8, clientInfo.name, "Sublime Text LSP")) {
            server.client_capabilities.max_detail_length = 256;
        } else if (std.mem.startsWith(u8, clientInfo.name, "emacs")) {
            // Assumes that `emacs` means `emacs-lsp/lsp-mode`. Eglot uses `Eglot`.

            // https://github.com/emacs-lsp/lsp-mode/issues/1842
            server.client_capabilities.supports_code_action_fixall = false;
            skip_set_fixall = true;
        }
    }

    if (request.capabilities.general) |general| {
        if (general.positionEncodings) |position_encodings| {
            server.offset_encoding = outer: for (position_encodings) |encoding| {
                switch (encoding) {
                    .@"utf-8" => break :outer .@"utf-8",
                    .@"utf-16" => break :outer .@"utf-16",
                    .@"utf-32" => break :outer .@"utf-32",
                    .custom_value => {},
                }
            } else server.offset_encoding;
        }
    }
    server.diagnostics_collection.offset_encoding = server.offset_encoding;

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
                server.client_capabilities.supports_completion_deprecated_old = completionItem.deprecatedSupport orelse false;
                server.client_capabilities.supports_completion_insert_replace_support = completionItem.insertReplaceSupport orelse false;
                if (completionItem.tagSupport) |tagSupport| {
                    for (tagSupport.valueSet) |tag| {
                        switch (tag) {
                            .Deprecated => {
                                server.client_capabilities.supports_completion_deprecated_tag = true;
                                break;
                            },
                            _ => {},
                        }
                    }
                }
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
            server.client_capabilities.supports_will_save_wait_until = synchronization.willSaveWaitUntil orelse false;
        }
        if (textDocument.codeAction) |_| {
            if (!skip_set_fixall) {
                // Some clients do not specify `source.fixAll` in
                // `textDocument.codeAction.?.codeActionLiteralSupport.?.codeActionKind.valueSet`
                // so we assume they support it if they support code actions in general.
                server.client_capabilities.supports_code_action_fixall = true;
            }
        }
        if (textDocument.definition) |definition| {
            server.client_capabilities.supports_textDocument_definition_linkSupport = definition.linkSupport orelse false;
        }
        if (textDocument.signatureHelp) |signature_help_capabilities| {
            if (signature_help_capabilities.signatureInformation) |signature_information| {
                if (signature_information.documentationFormat) |content_format| {
                    for (content_format) |format| {
                        if (format == .plaintext) {
                            break;
                        }
                        if (format == .markdown) {
                            server.client_capabilities.signature_help_supports_md = true;
                            break;
                        }
                    }
                }
            }
        }
        if (textDocument.semanticTokens) |semanticTokens| {
            server.client_capabilities.supports_semantic_tokens_overlapping = semanticTokens.overlappingTokenSupport orelse false;
            server.client_capabilities.semantic_tokens_augment_syntax_tokens = semanticTokens.augmentsSyntaxTokens orelse false;
        }
    }

    if (request.capabilities.window) |window| {
        if (window.workDoneProgress) |wdp| {
            server.document_store.lsp_capabilities.supports_work_done_progress = wdp;
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
        if (workspace.didChangeWatchedFiles) |did_change| {
            if (did_change.dynamicRegistration orelse false) {
                server.client_capabilities.supports_workspace_did_change_watched_files = true;
            }
        }
        if (workspace.semanticTokens) |workspace_semantic_tokens| {
            server.document_store.lsp_capabilities.supports_semantic_tokens_refresh = workspace_semantic_tokens.refreshSupport orelse false;
        }
        if (workspace.inlayHint) |inlay_hint| {
            server.document_store.lsp_capabilities.supports_inlay_hints_refresh = inlay_hint.refreshSupport orelse false;
        }
    }

    if (request.clientInfo) |clientInfo| {
        log.info("Client Info:      {s}-{s}", .{ clientInfo.name, clientInfo.version orelse "<no version>" });
    }
    log.info("Autofix Mode:     {s}", .{@tagName(server.getAutofixMode())});
    log.debug("Offset Encoding:  {s}", .{@tagName(server.offset_encoding)});

    if (request.workspaceFolders) |workspace_folders| {
        for (workspace_folders) |src| {
            try server.addWorkspace(src.uri);
        }
    }

    server.status = .initializing;

    if (request.initializationOptions) |initialization_options| {
        if (std.json.parseFromValueLeaky(Config, arena, initialization_options, .{
            .ignore_unknown_fields = true,
        })) |new_cfg| {
            try server.updateConfiguration2(new_cfg, .{});
        } else |err| {
            log.err("failed to read initialization_options: {}", .{err});
        }
    }

    // TODO Instead of checking `is_test`, possible config paths should be provided by the main function.
    if (!zig_builtin.is_test) {
        var maybe_config_result = if (server.config_path) |config_path|
            configuration.loadFromFile(server.allocator, config_path)
        else
            configuration.load(server.allocator);

        if (maybe_config_result) |*config_result| {
            defer config_result.deinit(server.allocator);
            switch (config_result.*) {
                .success => |config_with_path| {
                    log.info("Loaded config:      {s}", .{config_with_path.path});
                    try server.updateConfiguration2(config_with_path.config.value, .{});
                },
                .failure => |payload| blk: {
                    try server.updateConfiguration(.{}, .{});
                    const message = try payload.toMessage(server.allocator) orelse break :blk;
                    defer server.allocator.free(message);
                    server.showMessage(.Error, "Failed to load configuration options:\n{s}", .{message});
                },
                .not_found => try server.updateConfiguration(.{}, .{}),
            }
        } else |err| {
            log.err("failed to load configuration: {}", .{err});
        }
    }

    return .{
        .serverInfo = .{
            .name = "zls",
            .version = build_options.version_string,
        },
        .capabilities = .{
            .positionEncoding = switch (server.offset_encoding) {
                .@"utf-8" => .@"utf-8",
                .@"utf-16" => .@"utf-16",
                .@"utf-32" => .@"utf-32",
            },
            .signatureHelpProvider = .{
                .triggerCharacters = &.{"("},
                .retriggerCharacters = &.{","},
            },
            .textDocumentSync = .{
                .TextDocumentSyncOptions = .{
                    .openClose = true,
                    .change = .Incremental,
                    .save = .{ .bool = true },
                    .willSaveWaitUntil = true,
                },
            },
            .renameProvider = .{
                .RenameOptions = .{ .prepareProvider = true },
            },
            .completionProvider = .{
                .resolveProvider = false,
                .triggerCharacters = &.{ ".", ":", "@", "]", "\"", "/" },
                .completionItem = .{ .labelDetailsSupport = true },
            },
            .documentHighlightProvider = .{ .bool = true },
            .hoverProvider = .{ .bool = true },
            .codeActionProvider = .{ .CodeActionOptions = .{ .codeActionKinds = code_actions.supported_code_actions } },
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
                    .supported = true,
                    .changeNotifications = .{ .bool = true },
                },
            },
            .semanticTokensProvider = .{
                .SemanticTokensOptions = .{
                    .full = .{ .bool = support_full_semantic_tokens },
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

fn initializedHandler(server: *Server, arena: std.mem.Allocator, notification: types.InitializedParams) Error!void {
    _ = notification;

    if (server.status != .initializing) {
        log.warn("received a initialized notification but the server has not send a initialize request!", .{});
    }

    server.status = .initialized;

    if (server.client_capabilities.supports_workspace_did_change_configuration_dynamic_registration) {
        try server.registerCapability("workspace/didChangeConfiguration", null);
    }

    if (server.client_capabilities.supports_workspace_did_change_watched_files) {
        // `{ "watchers": [ { "globPattern": "**/*.{zig,zon}" } ] }`
        var watcher = std.json.ObjectMap.init(arena);
        try watcher.put("globPattern", .{ .string = "**/*.{zig,zon}" });
        var watchers_arr = try std.ArrayList(std.json.Value).initCapacity(arena, 1);
        watchers_arr.appendAssumeCapacity(.{ .object = watcher });
        var fs_watcher_obj: std.json.ObjectMap = std.json.ObjectMap.init(arena);
        try fs_watcher_obj.put("watchers", .{ .array = watchers_arr });
        const json_val: ?std.json.Value = .{ .object = fs_watcher_obj };

        try server.registerCapability("workspace/didChangeWatchedFiles", json_val);
    }

    if (server.client_capabilities.supports_configuration) {
        try server.requestConfiguration();
        // TODO if the `workspace/configuration` request fails to be handled, build on save will not be started
    }

    if (std.crypto.random.intRangeLessThan(usize, 0, 32768) == 0) {
        server.showMessage(.Warning, "HELP ME, I AM STUCK INSIDE AN LSP!", .{});
    }
}

fn shutdownHandler(server: *Server, _: std.mem.Allocator, _: void) Error!?void {
    defer server.status = .shutdown;
    if (server.status != .initialized) return error.InvalidRequest; // received a shutdown request but the server is not initialized!
}

fn exitHandler(server: *Server, _: std.mem.Allocator, _: void) Error!void {
    server.status = switch (server.status) {
        .initialized => .exiting_failure,
        .shutdown => .exiting_success,
        else => unreachable,
    };
}

fn registerCapability(server: *Server, method: []const u8, registersOptions: ?types.LSPAny) Error!void {
    const id = try std.fmt.allocPrint(server.allocator, "register-{s}", .{method});
    defer server.allocator.free(id);

    log.debug("Dynamically registering method '{s}'", .{method});

    const json_message = try server.sendToClientRequest(
        .{ .string = id },
        "client/registerCapability",
        types.RegistrationParams{ .registrations = &.{
            .{
                .id = id,
                .method = method,
                .registerOptions = registersOptions,
            },
        } },
    );
    server.allocator.free(json_message);
}

fn requestConfiguration(server: *Server) Error!void {
    const configuration_items = comptime config: {
        var comp_config: [std.meta.fields(Config).len]types.ConfigurationItem = undefined;
        for (std.meta.fields(Config), 0..) |field, index| {
            comp_config[index] = .{
                .section = "zls." ++ field.name,
            };
        }

        break :config comp_config;
    };

    const json_message = try server.sendToClientRequest(
        .{ .string = "i_haz_configuration" },
        "workspace/configuration",
        types.ConfigurationParams{
            .items = &configuration_items,
        },
    );
    server.allocator.free(json_message);
}

fn handleConfiguration(server: *Server, json: std.json.Value) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const fields = std.meta.fields(configuration.Configuration);
    const result = switch (json) {
        .array => |arr| if (arr.items.len == fields.len) arr.items else {
            log.err("workspace/configuration expects an array of size {d} but received {d}", .{ fields.len, arr.items.len });
            return;
        },
        else => {
            log.err("workspace/configuration expects an array but received {s}", .{@tagName(json)});
            return;
        },
    };

    var arena_allocator: std.heap.ArenaAllocator = .init(server.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var new_config: configuration.Configuration = .{};

    inline for (fields, result) |field, json_value| {
        var runtime_known_field_name: []const u8 = ""; // avoid unnecessary function instantiations of `std.fmt.format`
        runtime_known_field_name = field.name;

        const maybe_new_value = std.json.parseFromValueLeaky(field.type, arena, json_value, .{}) catch |err| blk: {
            log.err("failed to parse configuration option '{s}': {}", .{ runtime_known_field_name, err });
            break :blk null;
        };
        if (maybe_new_value) |new_value| {
            @field(new_config, field.name) = new_value;
        }
    }

    server.updateConfiguration(new_config, .{}) catch |err| {
        log.err("failed to update configuration: {}", .{err});
    };
}

const Workspace = struct {
    uri: types.URI,
    build_on_save: if (BuildOnSaveSupport.isSupportedComptime()) ?BuildOnSave else void,
    build_on_save_mode: if (BuildOnSaveSupport.isSupportedComptime()) ?enum { watch, manual } else void,

    fn init(server: *Server, uri: types.URI) error{OutOfMemory}!Workspace {
        const duped_uri = try server.allocator.dupe(u8, uri);
        errdefer server.allocator.free(duped_uri);

        return .{
            .uri = duped_uri,
            .build_on_save = if (BuildOnSaveSupport.isSupportedComptime()) null else {},
            .build_on_save_mode = if (BuildOnSaveSupport.isSupportedComptime()) null else {},
        };
    }

    fn deinit(workspace: *Workspace, allocator: std.mem.Allocator) void {
        if (BuildOnSaveSupport.isSupportedComptime()) {
            if (workspace.build_on_save) |*build_on_save| build_on_save.deinit();
        }
        allocator.free(workspace.uri);
    }

    fn sendManualWatchUpdate(workspace: *Workspace) void {
        comptime std.debug.assert(BuildOnSaveSupport.isSupportedComptime());

        const build_on_save = if (workspace.build_on_save) |*build_on_save| build_on_save else return;
        const mode = workspace.build_on_save_mode orelse return;
        if (mode != .manual) return;

        build_on_save.sendManualWatchUpdate();
    }

    fn refreshBuildOnSave(workspace: *Workspace, args: struct {
        server: *Server,
        /// Whether the build on save process should be restarted if it is already running.
        restart: bool,
    }) error{OutOfMemory}!void {
        comptime std.debug.assert(BuildOnSaveSupport.isSupportedComptime());

        if (args.server.resolved_config.zig_runtime_version) |runtime_zig_version| {
            workspace.build_on_save_mode = switch (BuildOnSaveSupport.isSupportedRuntime(runtime_zig_version)) {
                .supported => .watch,
                // If if build on save has been explicitly enabled, fallback to the implementation with manual updates
                else => if (args.server.config.enable_build_on_save orelse false) .manual else null,
            };
        } else {
            workspace.build_on_save_mode = null;
        }

        const build_on_save_supported = workspace.build_on_save_mode != null;
        const build_on_save_wanted = args.server.config.enable_build_on_save orelse true;
        const enable = build_on_save_supported and build_on_save_wanted;

        if (workspace.build_on_save) |*build_on_save| {
            if (enable and !args.restart) return;
            log.debug("stopped Build-On-Save for '{s}'", .{workspace.uri});
            build_on_save.deinit();
            workspace.build_on_save = null;
        }

        if (!enable) return;

        const zig_exe_path = args.server.config.zig_exe_path orelse return;
        const zig_lib_path = args.server.config.zig_lib_path orelse return;
        const build_runner_path = args.server.config.build_runner_path orelse return;

        const workspace_path = @import("uri.zig").parse(args.server.allocator, workspace.uri) catch |err| {
            log.err("failed to parse URI '{s}': {}", .{ workspace.uri, err });
            return;
        };
        defer args.server.allocator.free(workspace_path);

        std.debug.assert(workspace.build_on_save == null);
        workspace.build_on_save = BuildOnSave.init(.{
            .allocator = args.server.allocator,
            .workspace_path = workspace_path,
            .build_on_save_args = args.server.config.build_on_save_args,
            .check_step_only = args.server.config.enable_build_on_save == null,
            .zig_exe_path = zig_exe_path,
            .zig_lib_path = zig_lib_path,
            .build_runner_path = build_runner_path,
            .collection = &args.server.diagnostics_collection,
        }) catch |err| {
            log.err("failed to initilize Build-On-Save for '{s}': {}", .{ workspace.uri, err });
            return;
        };

        log.info("trying to start Build-On-Save for '{s}'", .{workspace.uri});
    }
};

fn addWorkspace(server: *Server, uri: types.URI) error{OutOfMemory}!void {
    try server.workspaces.ensureUnusedCapacity(server.allocator, 1);
    server.workspaces.appendAssumeCapacity(try Workspace.init(server, uri));
    log.info("added Workspace Folder: {s}", .{uri});

    if (BuildOnSaveSupport.isSupportedComptime() and
        // Don't initialize build on save until initialization finished.
        // If the client supports the `workspace/configuration` request, wait
        // until we have received workspace configuration from the server.
        (server.status == .initialized and !server.client_capabilities.supports_configuration))
    {
        try server.workspaces.items[server.workspaces.items.len - 1].refreshBuildOnSave(.{
            .server = server,
            .restart = false,
        });
    }
}

fn removeWorkspace(server: *Server, uri: types.URI) void {
    for (server.workspaces.items, 0..) |workspace, i| {
        if (std.mem.eql(u8, workspace.uri, uri)) {
            var removed_workspace = server.workspaces.swapRemove(i);
            removed_workspace.deinit(server.allocator);
            log.info("removed Workspace Folder: {s}", .{uri});
            break;
        }
    } else {
        log.warn("could not remove Workspace Folder: {s}", .{uri});
    }
}

fn didChangeWatchedFilesHandler(server: *Server, arena: std.mem.Allocator, notification: types.DidChangeWatchedFilesParams) Error!void {
    var updated_files: usize = 0;
    for (notification.changes) |change| {
        const file_path = Uri.parse(arena, change.uri) catch |err| switch (err) {
            error.UnsupportedScheme => continue,
            else => {
                log.err("failed to parse URI '{s}': {}", .{ change.uri, err });
                continue;
            },
        };
        const file_extension = std.fs.path.extension(file_path);
        if (!std.mem.eql(u8, file_extension, ".zig") and !std.mem.eql(u8, file_extension, ".zon")) continue;

        // very inefficient way of achieving some basic URI normalization
        const uri = try Uri.fromPath(arena, file_path);

        switch (change.type) {
            .Created, .Changed, .Deleted => {
                const did_update_file = try server.document_store.refreshDocumentFromFileSystem(uri);
                updated_files += @intFromBool(did_update_file);
            },
            else => {},
        }
    }
    if (updated_files != 0) {
        log.info("updated {d} watched file(s)", .{updated_files});
    }
}

fn didChangeWorkspaceFoldersHandler(server: *Server, arena: std.mem.Allocator, notification: types.DidChangeWorkspaceFoldersParams) Error!void {
    _ = arena;

    for (notification.event.added) |folder| {
        try server.addWorkspace(folder.uri);
    }

    for (notification.event.removed) |folder| {
        server.removeWorkspace(folder.uri);
    }
}

fn didChangeConfigurationHandler(server: *Server, arena: std.mem.Allocator, notification: types.DidChangeConfigurationParams) Error!void {
    const settings = switch (notification.settings) {
        .null => {
            if (server.client_capabilities.supports_configuration) {
                try server.requestConfiguration();
            }
            return;
        },
        .object => |object| object.get("zls") orelse notification.settings,
        else => notification.settings,
    };

    const new_config = std.json.parseFromValueLeaky(
        configuration.Configuration,
        arena,
        settings,
        .{ .ignore_unknown_fields = true },
    ) catch |err| {
        log.err("failed to parse 'workspace/didChangeConfiguration' response: {}", .{err});
        return error.ParseError;
    };

    try server.updateConfiguration(new_config, .{});
}

pub const UpdateConfigurationOptions = struct {
    resolve: bool = true,
    leaky_config_arena: bool = false,
};

pub fn updateConfiguration2(
    server: *Server,
    new_config: Config,
    options: UpdateConfigurationOptions,
) error{OutOfMemory}!void {
    var cfg: configuration.Configuration = .{};
    inline for (std.meta.fields(Config)) |field| {
        @field(cfg, field.name) = @field(new_config, field.name);
    }
    try server.updateConfiguration(cfg, options);
}

pub fn updateConfiguration(
    server: *Server,
    param_new_config: configuration.Configuration,
    options: UpdateConfigurationOptions,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const possibly_leaky_allocator = if (zig_builtin.is_test and options.leaky_config_arena) std.heap.page_allocator else server.allocator;

    var config_arena_allocator = server.config_arena.promote(possibly_leaky_allocator);
    defer server.config_arena = config_arena_allocator.state;
    const config_arena = config_arena_allocator.allocator();

    var new_config: configuration.Configuration = param_new_config;
    server.validateConfiguration(&new_config);

    inline for (std.meta.fields(Config)) |field| {
        @field(new_config, field.name) = if (@field(new_config, field.name)) |new_value|
            new_value
        else
            @field(server.config, field.name);
    }

    resolve: {
        if (!options.resolve) break :resolve;
        const resolved_config = try resolveConfiguration(possibly_leaky_allocator, config_arena, &new_config);
        server.validateConfiguration(&new_config);

        server.resolved_config.deinit(possibly_leaky_allocator);
        server.resolved_config = resolved_config;
    }

    // <---------------------------------------------------------->
    //                        apply changes
    // <---------------------------------------------------------->

    var has_changed: [std.meta.fields(Config).len]bool = @splat(false);

    inline for (std.meta.fields(Config), 0..) |field, field_index| {
        if (@field(new_config, field.name)) |new_value| {
            const old_value_maybe_optional = @field(server.config, field.name);

            const override_value = blk: {
                const old_value = if (@typeInfo(@TypeOf(old_value_maybe_optional)) == .optional)
                    if (old_value_maybe_optional) |old_value| old_value else break :blk true
                else
                    old_value_maybe_optional;

                break :blk switch (@TypeOf(old_value)) {
                    []const []const u8 => {
                        if (old_value.len != new_value.len) break :blk true;
                        for (old_value, new_value) |old, new| {
                            if (!std.mem.eql(u8, old, new)) break :blk true;
                        }
                        break :blk false;
                    },
                    []const u8 => !std.mem.eql(u8, old_value, new_value),
                    else => old_value != new_value,
                };
            };

            if (override_value) {
                var runtime_known_field_name: []const u8 = ""; // avoid unnecessary function instantiations of `std.fmt.format`
                runtime_known_field_name = field.name;
                log.info("Set config option '{s}' to {}", .{ runtime_known_field_name, std.json.fmt(new_value, .{}) });
                has_changed[field_index] = true;
                @field(server.config, field.name) = switch (@TypeOf(new_value)) {
                    []const []const u8 => blk: {
                        const copy = try config_arena.alloc([]const u8, new_value.len);
                        for (copy, new_value) |*duped, original| duped.* = try config_arena.dupe(u8, original);
                        break :blk copy;
                    },
                    []const u8 => try config_arena.dupe(u8, new_value),
                    else => new_value,
                };
            }
        }
    }

    const new_zig_exe_path = has_changed[std.meta.fieldIndex(Config, "zig_exe_path").?];
    const new_zig_lib_path = has_changed[std.meta.fieldIndex(Config, "zig_lib_path").?];
    const new_build_runner_path = has_changed[std.meta.fieldIndex(Config, "build_runner_path").?];
    const new_enable_build_on_save = has_changed[std.meta.fieldIndex(Config, "enable_build_on_save").?];
    const new_build_on_save_args = has_changed[std.meta.fieldIndex(Config, "build_on_save_args").?];
    const new_force_autofix = has_changed[std.meta.fieldIndex(Config, "force_autofix").?];

    server.document_store.config = .{
        .zig_exe_path = server.config.zig_exe_path,
        .zig_lib_dir = server.resolved_config.zig_lib_dir,
        .build_runner_path = server.config.build_runner_path,
        .builtin_path = server.config.builtin_path,
        .global_cache_dir = server.resolved_config.global_cache_dir,
    };

    if (new_zig_exe_path or new_build_runner_path) blk: {
        if (!std.process.can_spawn) break :blk;

        for (server.document_store.build_files.keys()) |build_file_uri| {
            server.document_store.invalidateBuildFile(build_file_uri);
        }
    }

    if (BuildOnSaveSupport.isSupportedComptime() and
        options.resolve and
        // If the client supports the `workspace/configuration` request, defer
        // build on save initialization until after we have received workspace
        // configuration from the server
        (!server.client_capabilities.supports_configuration or server.status == .initialized))
    {
        const should_restart =
            new_zig_exe_path or
            new_zig_lib_path or
            new_build_runner_path or
            new_enable_build_on_save or
            new_build_on_save_args;

        for (server.workspaces.items) |*workspace| {
            try workspace.refreshBuildOnSave(.{
                .server = server,
                .restart = should_restart,
            });
        }
    }

    if (DocumentStore.supports_build_system and (new_zig_exe_path or new_zig_lib_path)) {
        for (server.document_store.cimports.values()) |*result| {
            result.deinit(server.document_store.allocator);
        }
        server.document_store.cimports.clearAndFree(server.document_store.allocator);
    }

    if (server.status == .initialized) {
        if (new_zig_exe_path and server.client_capabilities.supports_publish_diagnostics) {
            for (server.document_store.handles.values()) |handle| {
                if (!handle.isOpen()) continue;
                try server.pushJob(.{ .generate_diagnostics = try server.allocator.dupe(u8, handle.uri) });
            }
        }
    }

    // <---------------------------------------------------------->
    //  don't modify config options after here, only show messages
    // <---------------------------------------------------------->

    check: {
        if (!options.resolve) break :check;
        if (!std.process.can_spawn) break :check;
        if (server.status != .initialized) break :check;

        // TODO there should a way to suppress this message
        if (server.config.zig_exe_path == null) {
            server.showMessage(.Warning, "zig executable could not be found", .{});
        } else if (server.resolved_config.zig_lib_dir == null) {
            server.showMessage(.Warning, "zig standard library directory could not be resolved", .{});
        }
    }

    check: {
        if (!options.resolve) break :check;
        if (server.status != .initialized) break :check;

        switch (server.resolved_config.build_runner_version) {
            .resolved, .unresolved_dont_error => break :check,
            .unresolved => {},
        }

        const zig_version = server.resolved_config.zig_runtime_version.?;
        const zls_version = build_options.version;

        const zig_version_is_tagged = zig_version.pre == null and zig_version.build == null;
        const zls_version_is_tagged = zls_version.pre == null and zls_version.build == null;

        if (zig_version_is_tagged) {
            server.showMessage(
                .Warning,
                "ZLS {} does not support Zig {}. A ZLS {}.{} release should be used instead.",
                .{ zls_version, zig_version, zig_version.major, zig_version.minor },
            );
        } else if (zls_version_is_tagged) {
            server.showMessage(
                .Warning,
                "ZLS {} should be used with a Zig {}.{} release but found Zig {}.",
                .{ zls_version, zls_version.major, zls_version.minor, zig_version },
            );
        } else {
            server.showMessage(
                .Warning,
                "ZLS {} requires at least Zig {s} but got Zig {}. Update Zig to avoid unexpected behavior.",
                .{ zls_version, build_options.minimum_runtime_zig_version_string, zig_version },
            );
        }
    }

    if (server.config.enable_build_on_save orelse false) {
        if (!BuildOnSaveSupport.isSupportedComptime()) {
            // This message is not very helpful but it relatively uncommon to happen anyway.
            log.info("'enable_build_on_save' is ignored because build on save is not supported by this ZLS build", .{});
        } else if (server.status == .initialized and (server.config.zig_exe_path == null or server.resolved_config.zig_lib_dir == null)) {
            log.warn("'enable_build_on_save' is ignored because Zig could not be found", .{});
        } else if (!server.client_capabilities.supports_publish_diagnostics) {
            log.warn("'enable_build_on_save' is ignored because it is not supported by {s}", .{server.client_capabilities.client_name orelse "your editor"});
        } else if (server.status == .initialized and options.resolve and server.resolved_config.build_runner_version == .unresolved and server.config.build_runner_path == null) {
            log.warn("'enable_build_on_save' is ignored because no build runner is available", .{});
        } else if (server.status == .initialized and options.resolve and server.resolved_config.zig_runtime_version != null) {
            switch (BuildOnSaveSupport.isSupportedRuntime(server.resolved_config.zig_runtime_version.?)) {
                .supported => {},
                .invalid_linux_kernel_version => |*utsname_release| log.warn("Build-On-Save cannot run in watch mode because it because the Linux version '{s}' could not be parsed", .{std.mem.sliceTo(utsname_release, 0)}),
                .unsupported_linux_kernel_version => |kernel_version| log.warn("Build-On-Save cannot run in watch mode because it is not supported by Linux '{}' (requires at least {})", .{ kernel_version, BuildOnSaveSupport.minimum_linux_version }),
                .unsupported_zig_version => log.warn("Build-On-Save cannot run in watch mode because it is not supported on {s} by Zig {} (requires at least {})", .{ @tagName(zig_builtin.os.tag), server.resolved_config.zig_runtime_version.?, BuildOnSaveSupport.minimum_zig_version }),
                .unsupported_os => log.warn("Build-On-Save cannot run in watch mode because it is not supported on {s}", .{@tagName(zig_builtin.os.tag)}),
            }
        }
    }

    if (server.config.force_autofix and server.getAutofixMode() == .none) {
        log.warn("`force_autofix` is ignored because it is not supported by {s}", .{server.client_capabilities.client_name orelse "your editor"});
    } else if (new_force_autofix) {
        log.info("Autofix Mode: {s}", .{@tagName(server.getAutofixMode())});
    }
}

fn validateConfiguration(server: *Server, config: *configuration.Configuration) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    comptime for (std.meta.fieldNames(Config)) |field_name| {
        @setEvalBranchQuota(2_000);
        if (std.mem.indexOf(u8, field_name, "path") == null) continue;

        if (std.mem.eql(u8, field_name, "zig_exe_path")) continue;
        if (std.mem.eql(u8, field_name, "builtin_path")) continue;
        if (std.mem.eql(u8, field_name, "build_runner_path")) continue;
        if (std.mem.eql(u8, field_name, "zig_lib_path")) continue;
        if (std.mem.eql(u8, field_name, "global_cache_path")) continue;

        @compileError(std.fmt.comptimePrint(
            \\config option '{s}' contains the word 'path'.
            \\Please add config option validation checks below if necessary.
            \\If not necessary, just add a check above to ignore this error.
            \\
        , .{field_name}));
    };

    const FileCheckInfo = struct {
        field_name: []const u8,
        value: *?[]const u8,
        kind: enum { file, directory },
        is_accessible: bool,
    };

    // zig fmt: off
    const checks: []const FileCheckInfo = &.{
        .{ .field_name = "zig_exe_path",      .value = &config.zig_exe_path,      .kind = .file,      .is_accessible = true },
        .{ .field_name = "builtin_path",      .value = &config.builtin_path,      .kind = .file,      .is_accessible = true },
        .{ .field_name = "build_runner_path", .value = &config.build_runner_path, .kind = .file,      .is_accessible = true },
        .{ .field_name = "zig_lib_path",      .value = &config.zig_lib_path,      .kind = .directory, .is_accessible = true },
        .{ .field_name = "global_cache_path", .value = &config.global_cache_path, .kind = .directory, .is_accessible = false },
    };
    // zig fmt: on

    for (checks) |check| {
        const is_ok = if (check.value.*) |path| ok: {
            // Convert `""` to `null`
            if (path.len == 0) {
                // Thank you Visual Studio Trash Code
                check.value.* = null;
                break :ok true;
            }

            if (!std.fs.path.isAbsolute(path)) {
                server.showMessage(.Warning, "config option '{s}': expected absolute path but got '{s}'", .{ check.field_name, path });
                break :ok false;
            }

            switch (check.kind) {
                .file => {
                    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
                        if (check.is_accessible) {
                            server.showMessage(.Warning, "config option '{s}': invalid file path '{s}': {}", .{ check.field_name, path, err });
                            break :ok false;
                        }
                        break :ok true;
                    };
                    defer file.close();

                    const stat = file.stat() catch |err| {
                        log.err("failed to get stat of '{s}': {}", .{ path, err });
                        break :ok true;
                    };
                    switch (stat.kind) {
                        .directory => {
                            server.showMessage(.Warning, "config option '{s}': expected file path but '{s}' is a directory", .{ check.field_name, path });
                            break :ok false;
                        },
                        .file => {},
                        // are there file kinds that should warn?
                        // what about symlinks?
                        else => {},
                    }
                    break :ok true;
                },
                .directory => {
                    var dir = std.fs.openDirAbsolute(path, .{}) catch |err| {
                        if (check.is_accessible) {
                            server.showMessage(.Warning, "config option '{s}': invalid directory path '{s}': {}", .{ check.field_name, path, err });
                            break :ok false;
                        }
                        break :ok true;
                    };
                    defer dir.close();
                    const stat = dir.stat() catch |err| {
                        log.err("failed to get stat of '{s}': {}", .{ path, err });
                        break :ok true;
                    };
                    switch (stat.kind) {
                        .file => {
                            server.showMessage(.Warning, "config option '{s}': expected directory path but '{s}' is a file", .{ check.field_name, path });
                            break :ok false;
                        },
                        .directory => {},
                        // are there file kinds that should warn?
                        // what about symlinks?
                        else => {},
                    }
                    break :ok true;
                },
            }
        } else true;

        if (!is_ok) {
            check.value.* = null;
        }
    }
}

const ResolvedConfiguration = struct {
    zig_env: ?std.json.Parsed(configuration.Env),
    zig_runtime_version: ?std.SemanticVersion,
    zig_lib_dir: ?std.Build.Cache.Directory,
    global_cache_dir: ?std.Build.Cache.Directory,
    build_runner_version: union(enum) {
        /// If returned, guarantees `zig_runtime_version != null`.
        resolved: BuildRunnerVersion,
        /// no suitable build runner could be resolved based on the `zig_runtime_version`
        /// If returned, guarantees `zig_runtime_version != null`.
        unresolved,
        unresolved_dont_error,
    },

    pub const unresolved: ResolvedConfiguration = .{
        .zig_env = null,
        .zig_runtime_version = null,
        .zig_lib_dir = null,
        .global_cache_dir = null,
        .build_runner_version = .unresolved_dont_error,
    };

    fn deinit(result: *ResolvedConfiguration, allocator: std.mem.Allocator) void {
        if (result.zig_env) |parsed| parsed.deinit();
        if (zig_builtin.target.os.tag != .wasi) {
            if (result.zig_lib_dir) |*zig_lib_dir| zig_lib_dir.closeAndFree(allocator);
            if (result.global_cache_dir) |*global_cache_dir| global_cache_dir.closeAndFree(allocator);
        }
    }
};

fn resolveConfiguration(
    allocator: std.mem.Allocator,
    /// try leaking as little memory as possible since the ArenaAllocator is only deinit on exit
    config_arena: std.mem.Allocator,
    config: *configuration.Configuration,
) error{OutOfMemory}!ResolvedConfiguration {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var result: ResolvedConfiguration = .unresolved;
    errdefer result.deinit(allocator);

    if (config.zig_exe_path == null) blk: {
        if (!std.process.can_spawn) break :blk;
        if (zig_builtin.is_test) unreachable;
        const zig_exe_path = try configuration.findZig(allocator) orelse break :blk;
        defer allocator.free(zig_exe_path);
        config.zig_exe_path = try config_arena.dupe(u8, zig_exe_path);
    }

    if (config.zig_exe_path) |exe_path| blk: {
        if (!std.process.can_spawn) break :blk;
        result.zig_env = configuration.getZigEnv(allocator, exe_path);
        const env = result.zig_env orelse break :blk;

        if (config.zig_lib_path == null) {
            if (env.value.lib_dir) |lib_dir| resolve_lib_failed: {
                if (std.fs.path.isAbsolute(lib_dir)) {
                    config.zig_lib_path = try config_arena.dupe(u8, lib_dir);
                } else {
                    const cwd = std.process.getCwdAlloc(allocator) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => |e| {
                            log.err("failed to resolve current working directory: {}", .{e});
                            break :resolve_lib_failed;
                        },
                    };
                    defer allocator.free(cwd);
                    config.zig_lib_path = try std.fs.path.join(config_arena, &.{ cwd, lib_dir });
                }
            }
        }

        result.zig_runtime_version = std.SemanticVersion.parse(env.value.version) catch |err| {
            log.err("zig env returned a zig version that is an invalid semantic version: {}", .{err});
            break :blk;
        };
    }

    if (config.zig_lib_path) |zig_lib_path| blk: {
        if (zig_builtin.target.os.tag == .wasi) {
            log.warn("The 'zig_lib_path' config option is ignored on WASI in favor of preopens.", .{});
            break :blk;
        }
        if (std.fs.openDirAbsolute(zig_lib_path, .{})) |zig_lib_dir| {
            result.zig_lib_dir = .{
                .handle = zig_lib_dir,
                .path = try allocator.dupe(u8, zig_lib_path),
            };
        } else |err| {
            log.err("failed to open zig library directory '{s}': {}", .{ zig_lib_path, err });
            config.zig_lib_path = null;
        }
    }

    if (config.global_cache_path == null) blk: {
        if (zig_builtin.target.os.tag == .wasi) break :blk;
        if (zig_builtin.is_test) unreachable;

        const cache_dir_path = known_folders.getPath(allocator, .cache) catch null orelse {
            log.warn("Known-folders could not fetch the cache path", .{});
            break :blk;
        };
        defer allocator.free(cache_dir_path);

        config.global_cache_path = try std.fs.path.join(config_arena, &.{ cache_dir_path, "zls" });
    }

    if (config.global_cache_path) |global_cache_path| blk: {
        if (zig_builtin.target.os.tag == .wasi) {
            log.warn("The 'global_cache_path' config option is ignored on WASI in favor of preopens.", .{});
            break :blk;
        }
        if (std.fs.cwd().makeOpenPath(global_cache_path, .{})) |global_cache_dir| {
            result.global_cache_dir = .{
                .handle = global_cache_dir,
                .path = try allocator.dupe(u8, global_cache_path),
            };
        } else |err| {
            log.warn("failed to create cache directory '{s}': {}", .{ global_cache_path, err });
            config.global_cache_path = null;
        }
    }

    if (zig_builtin.target.os.tag == .wasi) {
        const wasi_preopens = try std.fs.wasi.preopensAlloc(allocator);
        defer {
            for (wasi_preopens.names[3..]) |name| allocator.free(name);
            allocator.free(wasi_preopens.names);
        }

        zig_lib_dir: {
            const zig_lib_dir_fd = wasi_preopens.find("/lib") orelse {
                log.warn("failed to resolve '/lib' WASI preopen", .{});
                break :zig_lib_dir;
            };
            result.zig_lib_dir = .{ .handle = .{ .fd = zig_lib_dir_fd }, .path = "/lib" };
        }

        global_cache_dir: {
            const global_cache_dir_fd = wasi_preopens.find("/cache") orelse {
                log.warn("failed to resolve '/cache' WASI preopen", .{});
                break :global_cache_dir;
            };
            result.global_cache_dir = .{ .handle = .{ .fd = global_cache_dir_fd }, .path = "/cache" };
        }
    }

    if (config.build_runner_path == null) blk: {
        if (!std.process.can_spawn) break :blk;
        const global_cache_dir = result.global_cache_dir orelse break :blk;
        const zig_version = result.zig_runtime_version orelse break :blk;

        const build_runner_version = BuildRunnerVersion.selectBuildRunnerVersion(zig_version) orelse {
            result.build_runner_version = .unresolved;
            break :blk;
        };
        const build_runner_source = build_runner_version.getBuildRunnerFile();
        const build_runner_config_source = @embedFile("build_runner/shared.zig");

        const build_runner_hash = get_hash: {
            const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);

            var hasher: Hasher = .init(&@splat(0));
            hasher.update(build_runner_source);
            hasher.update(build_runner_config_source);
            break :get_hash hasher.finalResult();
        };

        const cache_path = try global_cache_dir.join(allocator, &.{ "build_runner", &std.fmt.bytesToHex(build_runner_hash, .lower) });
        defer allocator.free(cache_path);

        std.debug.assert(std.fs.path.isAbsolute(cache_path));
        var cache_dir = std.fs.cwd().makeOpenPath(cache_path, .{}) catch |err| {
            log.err("failed to open directory '{s}': {}", .{ cache_path, err });
            break :blk;
        };
        defer cache_dir.close();

        cache_dir.writeFile(.{
            .sub_path = "shared.zig",
            .data = build_runner_config_source,
            .flags = .{ .exclusive = true },
        }) catch |err| if (err != error.PathAlreadyExists) {
            log.err("failed to write file '{s}/shared.zig': {}", .{ cache_path, err });
            break :blk;
        };

        cache_dir.writeFile(.{
            .sub_path = "build_runner.zig",
            .data = build_runner_source,
            .flags = .{ .exclusive = true },
        }) catch |err| if (err != error.PathAlreadyExists) {
            log.err("failed to write file '{s}/build_runner.zig': {}", .{ cache_path, err });
            break :blk;
        };

        config.build_runner_path = try std.fs.path.join(config_arena, &.{ cache_path, "build_runner.zig" });
        result.build_runner_version = .{ .resolved = build_runner_version };
    }

    if (config.builtin_path == null) blk: {
        if (!std.process.can_spawn) break :blk;
        const zig_exe_path = config.zig_exe_path orelse break :blk;
        const global_cache_path = config.global_cache_path orelse break :blk;

        const argv = [_][]const u8{
            zig_exe_path,
            "build-exe",
            "--show-builtin",
        };

        const run_result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &argv,
            .max_output_bytes = 16 * 1024 * 1024,
        }) catch |err| {
            const args = std.mem.join(allocator, " ", &argv) catch break :blk;
            log.err("failed to run command '{s}': {}", .{ args, err });
            break :blk;
        };
        defer allocator.free(run_result.stdout);
        defer allocator.free(run_result.stderr);

        const builtin_path = try std.fs.path.join(config_arena, &.{ global_cache_path, "builtin.zig" });

        std.fs.cwd().writeFile(.{
            .sub_path = builtin_path,
            .data = run_result.stdout,
        }) catch |err| {
            log.err("failed to write file '{s}': {}", .{ builtin_path, err });
            break :blk;
        };

        config.builtin_path = builtin_path;
    }

    return result;
}

fn openDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidOpenTextDocumentParams) Error!void {
    if (notification.textDocument.text.len > DocumentStore.max_document_size) {
        log.err("open document '{s}' failed: text size ({d}) is above maximum length ({d})", .{
            notification.textDocument.uri,
            notification.textDocument.text.len,
            DocumentStore.max_document_size,
        });
        return error.InternalError;
    }

    try server.document_store.openDocument(notification.textDocument.uri, notification.textDocument.text);

    if (server.client_capabilities.supports_publish_diagnostics) {
        try server.pushJob(.{
            .generate_diagnostics = try server.allocator.dupe(u8, notification.textDocument.uri),
        });
    }
}

fn changeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidChangeTextDocumentParams) Error!void {
    const handle = server.document_store.getHandle(notification.textDocument.uri) orelse return;

    const new_text = try diff.applyContentChanges(server.allocator, handle.tree.source, notification.contentChanges, server.offset_encoding);

    if (new_text.len > DocumentStore.max_document_size) {
        log.err("change document '{s}' failed: text size ({d}) is above maximum length ({d})", .{
            notification.textDocument.uri,
            new_text.len,
            DocumentStore.max_document_size,
        });
        return error.InternalError;
    }

    try server.document_store.refreshDocument(handle.uri, new_text);

    if (server.client_capabilities.supports_publish_diagnostics) {
        try server.pushJob(.{
            .generate_diagnostics = try server.allocator.dupe(u8, handle.uri),
        });
    }
}

fn saveDocumentHandler(server: *Server, arena: std.mem.Allocator, notification: types.DidSaveTextDocumentParams) Error!void {
    const uri = notification.textDocument.uri;

    if (std.process.can_spawn and DocumentStore.isBuildFile(uri)) {
        server.document_store.invalidateBuildFile(uri);
    }

    if (server.getAutofixMode() == .on_save) {
        const handle = server.document_store.getHandle(uri) orelse return;
        var text_edits = try server.autofix(arena, handle);

        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try workspace_edit.changes.?.map.putNoClobber(arena, uri, try text_edits.toOwnedSlice(arena));

        const json_message = try server.sendToClientRequest(
            .{ .string = "apply_edit" },
            "workspace/applyEdit",
            types.ApplyWorkspaceEditParams{
                .label = "autofix",
                .edit = workspace_edit,
            },
        );
        server.allocator.free(json_message);
    }

    if (BuildOnSaveSupport.isSupportedComptime()) {
        for (server.workspaces.items) |*workspace| {
            workspace.sendManualWatchUpdate();
        }
    }
}

fn closeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidCloseTextDocumentParams) error{}!void {
    server.document_store.closeDocument(notification.textDocument.uri);

    if (server.client_capabilities.supports_publish_diagnostics) {
        // clear diagnostics on closed file
        const json_message = server.sendToClientNotification("textDocument/publishDiagnostics", .{
            .uri = notification.textDocument.uri,
            .diagnostics = &.{},
        }) catch return;
        server.allocator.free(json_message);
    }
}

fn willSaveWaitUntilHandler(server: *Server, arena: std.mem.Allocator, request: types.WillSaveTextDocumentParams) Error!?[]types.TextEdit {
    if (server.getAutofixMode() != .will_save_wait_until) return null;

    switch (request.reason) {
        .Manual => {},
        .AfterDelay,
        .FocusOut,
        => return null,
        _ => return null,
    }

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var text_edits = try server.autofix(arena, handle);

    return try text_edits.toOwnedSlice(arena);
}

fn semanticTokensFullHandler(server: *Server, arena: std.mem.Allocator, request: types.SemanticTokensParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    // Workaround: The Ast on .zon files is unusable when an error occured on the root expr
    if (handle.tree.mode == .zon and handle.tree.errors.len > 0) return null;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();
    // semantic tokens can be quite expensive to compute on large files
    // and disabling callsite references can help with bringing the cost down.
    analyser.collect_callsite_references = false;

    return try semantic_tokens.writeSemanticTokens(
        arena,
        &analyser,
        handle,
        null,
        server.offset_encoding,
        server.client_capabilities.semantic_tokens_augment_syntax_tokens or server.config.semantic_tokens == .partial,
        server.client_capabilities.supports_semantic_tokens_overlapping,
    );
}

fn semanticTokensRangeHandler(server: *Server, arena: std.mem.Allocator, request: types.SemanticTokensRangeParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    // Workaround: The Ast on .zon files is unusable when an error occured on the root expr
    if (handle.tree.mode == .zon and handle.tree.errors.len > 0) return null;

    const loc = offsets.rangeToLoc(handle.tree.source, request.range, server.offset_encoding);

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    return try semantic_tokens.writeSemanticTokens(
        arena,
        &analyser,
        handle,
        loc,
        server.offset_encoding,
        server.client_capabilities.semantic_tokens_augment_syntax_tokens or server.config.semantic_tokens == .partial,
        server.client_capabilities.supports_semantic_tokens_overlapping,
    );
}

fn completionHandler(server: *Server, arena: std.mem.Allocator, request: types.CompletionParams) Error!lsp.ResultType("textDocument/completion") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    return .{
        .CompletionList = try completions.completionAtIndex(server, &analyser, arena, handle, source_index) orelse return null,
    };
}

fn signatureHelpHandler(server: *Server, arena: std.mem.Allocator, request: types.SignatureHelpParams) Error!?types.SignatureHelp {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);

    const markup_kind: types.MarkupKind = if (server.client_capabilities.signature_help_supports_md) .markdown else .plaintext;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    const signature_info = (try signature_help.getSignatureInfo(
        &analyser,
        arena,
        handle,
        source_index,
        markup_kind,
    )) orelse return null;

    var signatures = try arena.alloc(types.SignatureInformation, 1);
    signatures[0] = signature_info;

    return .{
        .signatures = signatures,
        .activeSignature = 0,
        .activeParameter = signature_info.activeParameter,
    };
}

fn gotoDefinitionHandler(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.DefinitionParams,
) Error!lsp.ResultType("textDocument/definition") {
    return goto.gotoHandler(server, arena, .definition, request);
}

fn gotoTypeDefinitionHandler(server: *Server, arena: std.mem.Allocator, request: types.TypeDefinitionParams) Error!lsp.ResultType("textDocument/typeDefinition") {
    const response = (try goto.gotoHandler(server, arena, .type_definition, .{
        .textDocument = request.textDocument,
        .position = request.position,
        .workDoneToken = request.workDoneToken,
        .partialResultToken = request.partialResultToken,
    })) orelse return null;
    return switch (response) {
        .array_of_DefinitionLink => |adl| .{ .array_of_DefinitionLink = adl },
        .Definition => |def| .{ .Definition = def },
    };
}

fn gotoImplementationHandler(server: *Server, arena: std.mem.Allocator, request: types.ImplementationParams) Error!lsp.ResultType("textDocument/implementation") {
    const response = (try goto.gotoHandler(server, arena, .definition, .{
        .textDocument = request.textDocument,
        .position = request.position,
        .workDoneToken = request.workDoneToken,
        .partialResultToken = request.partialResultToken,
    })) orelse return null;
    return switch (response) {
        .array_of_DefinitionLink => |adl| .{ .array_of_DefinitionLink = adl },
        .Definition => |def| .{ .Definition = def },
    };
}

fn gotoDeclarationHandler(server: *Server, arena: std.mem.Allocator, request: types.DeclarationParams) Error!lsp.ResultType("textDocument/declaration") {
    const response = (try goto.gotoHandler(server, arena, .declaration, .{
        .textDocument = request.textDocument,
        .position = request.position,
        .workDoneToken = request.workDoneToken,
        .partialResultToken = request.partialResultToken,
    })) orelse return null;
    return switch (response) {
        .array_of_DefinitionLink => |adl| .{ .array_of_DeclarationLink = adl },
        .Definition => |def| .{ .Declaration = .{ .Location = def.Location } },
    };
}

fn hoverHandler(server: *Server, arena: std.mem.Allocator, request: types.HoverParams) Error!?types.Hover {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;
    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    return hover_handler.hover(
        &analyser,
        arena,
        handle,
        source_index,
        markup_kind,
        server.offset_encoding,
    );
}

fn documentSymbolsHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentSymbolParams) Error!lsp.ResultType("textDocument/documentSymbol") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;
    return .{
        .array_of_DocumentSymbol = try document_symbol.getDocumentSymbols(arena, handle.tree, server.offset_encoding),
    };
}

fn formattingHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentFormattingParams) Error!?[]types.TextEdit {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (handle.tree.errors.len != 0) return null;

    const formatted = try handle.tree.render(arena);

    if (std.mem.eql(u8, handle.tree.source, formatted)) return null;

    const text_edits = try diff.edits(arena, handle.tree.source, formatted, server.offset_encoding);
    return text_edits.items;
}

fn renameHandler(server: *Server, arena: std.mem.Allocator, request: types.RenameParams) Error!?types.WorkspaceEdit {
    const response = try references.referencesHandler(server, arena, .{ .rename = request });
    return if (response) |rep| rep.rename else null;
}

fn prepareRenameHandler(server: *Server, request: types.PrepareRenameParams) ?types.PrepareRenameResult {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.tree.source, request.position, server.offset_encoding);
    const name_loc = Analyser.identifierLocFromIndex(handle.tree, source_index) orelse return null;
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    return .{
        .literal_1 = .{
            .range = offsets.locToRange(handle.tree.source, name_loc, server.offset_encoding),
            .placeholder = name,
        },
    };
}

fn referencesHandler(server: *Server, arena: std.mem.Allocator, request: types.ReferenceParams) Error!?[]types.Location {
    const response = try references.referencesHandler(server, arena, .{ .references = request });
    return if (response) |rep| rep.references else null;
}

fn documentHighlightHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentHighlightParams) Error!?[]types.DocumentHighlight {
    const response = try references.referencesHandler(server, arena, .{ .highlight = request });
    return if (response) |rep| rep.highlight else null;
}

fn inlayHintHandler(server: *Server, arena: std.mem.Allocator, request: types.InlayHintParams) Error!?[]types.InlayHint {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    if (handle.tree.mode == .zon) return null;

    // The Language Server Specification does not provide a client capabilities that allows the client to specify the MarkupKind of inlay hints.
    const hover_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const loc = offsets.rangeToLoc(handle.tree.source, request.range, server.offset_encoding);

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    return try inlay_hints.writeRangeInlayHint(
        arena,
        server.config,
        &analyser,
        handle,
        loc,
        hover_kind,
        server.offset_encoding,
    );
}

fn codeActionHandler(server: *Server, arena: std.mem.Allocator, request: types.CodeActionParams) Error!lsp.ResultType("textDocument/codeAction") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    // as of right now, only ast-check errors may get a code action
    if (handle.tree.errors.len != 0) return null;
    if (handle.tree.mode == .zon) return null;

    var error_bundle = try diagnostics_gen.getAstCheckDiagnostics(server, handle);
    defer error_bundle.deinit(server.allocator);

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();

    const only_kinds = if (request.context.only) |kinds| blk: {
        var set: std.EnumSet(std.meta.Tag(types.CodeActionKind)) = .initEmpty();
        for (kinds) |kind| {
            set.setPresent(kind, true);
        }
        break :blk set;
    } else null;

    var builder: code_actions.Builder = .{
        .arena = arena,
        .analyser = &analyser,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
        .only_kinds = only_kinds,
    };

    try builder.generateCodeAction(error_bundle);
    try builder.generateCodeActionsInRange(request.range);

    const Result = lsp.ResultType("textDocument/codeAction");
    const result = try arena.alloc(std.meta.Child(std.meta.Child(Result)), builder.actions.items.len);
    for (builder.actions.items, result) |action, *out| {
        out.* = .{ .CodeAction = action };
    }

    return result;
}

fn foldingRangeHandler(server: *Server, arena: std.mem.Allocator, request: types.FoldingRangeParams) Error!?[]types.FoldingRange {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    return try folding_range.generateFoldingRanges(arena, handle.tree, server.offset_encoding);
}

fn selectionRangeHandler(server: *Server, arena: std.mem.Allocator, request: types.SelectionRangeParams) Error!?[]types.SelectionRange {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    return try selection_range.generateSelectionRanges(arena, handle, request.positions, server.offset_encoding);
}

const HandledRequestParams = union(enum) {
    initialize: types.InitializeParams,
    shutdown,
    @"textDocument/willSaveWaitUntil": types.WillSaveTextDocumentParams,
    @"textDocument/semanticTokens/full": types.SemanticTokensParams,
    @"textDocument/semanticTokens/range": types.SemanticTokensRangeParams,
    @"textDocument/inlayHint": types.InlayHintParams,
    @"textDocument/completion": types.CompletionParams,
    @"textDocument/signatureHelp": types.SignatureHelpParams,
    @"textDocument/definition": types.DefinitionParams,
    @"textDocument/typeDefinition": types.TypeDefinitionParams,
    @"textDocument/implementation": types.ImplementationParams,
    @"textDocument/declaration": types.DeclarationParams,
    @"textDocument/hover": types.HoverParams,
    @"textDocument/documentSymbol": types.DocumentSymbolParams,
    @"textDocument/formatting": types.DocumentFormattingParams,
    @"textDocument/rename": types.RenameParams,
    @"textDocument/prepareRename": types.PrepareRenameParams,
    @"textDocument/references": types.ReferenceParams,
    @"textDocument/documentHighlight": types.DocumentHighlightParams,
    @"textDocument/codeAction": types.CodeActionParams,
    @"textDocument/foldingRange": types.FoldingRangeParams,
    @"textDocument/selectionRange": types.SelectionRangeParams,
    other: lsp.MethodWithParams,
};

const HandledNotificationParams = union(enum) {
    initialized: types.InitializedParams,
    exit,
    @"textDocument/didOpen": types.DidOpenTextDocumentParams,
    @"textDocument/didChange": types.DidChangeTextDocumentParams,
    @"textDocument/didSave": types.DidSaveTextDocumentParams,
    @"textDocument/didClose": types.DidCloseTextDocumentParams,
    @"workspace/didChangeWatchedFiles": types.DidChangeWatchedFilesParams,
    @"workspace/didChangeWorkspaceFolders": types.DidChangeWorkspaceFoldersParams,
    @"workspace/didChangeConfiguration": types.DidChangeConfigurationParams,
    other: lsp.MethodWithParams,
};

const Message = lsp.Message(HandledRequestParams, HandledNotificationParams, .{});

fn isBlockingMessage(msg: Message) bool {
    switch (msg) {
        .request => |request| switch (request.params) {
            .initialize,
            .shutdown,
            => return true,
            .@"textDocument/willSaveWaitUntil",
            .@"textDocument/semanticTokens/full",
            .@"textDocument/semanticTokens/range",
            .@"textDocument/inlayHint",
            .@"textDocument/completion",
            .@"textDocument/signatureHelp",
            .@"textDocument/definition",
            .@"textDocument/typeDefinition",
            .@"textDocument/implementation",
            .@"textDocument/declaration",
            .@"textDocument/hover",
            .@"textDocument/documentSymbol",
            .@"textDocument/formatting",
            .@"textDocument/rename",
            .@"textDocument/prepareRename",
            .@"textDocument/references",
            .@"textDocument/documentHighlight",
            .@"textDocument/codeAction",
            .@"textDocument/foldingRange",
            .@"textDocument/selectionRange",
            => return false,
            .other => return false,
        },
        .notification => |notification| switch (notification.params) {
            .initialized,
            .exit,
            .@"textDocument/didOpen",
            .@"textDocument/didChange",
            .@"textDocument/didSave",
            .@"textDocument/didClose",
            .@"workspace/didChangeWatchedFiles",
            .@"workspace/didChangeWorkspaceFolders",
            .@"workspace/didChangeConfiguration",
            => return true,
            .other => return false,
        },
        .response => return true,
    }
}

/// make sure to also set the `transport` field
pub fn create(allocator: std.mem.Allocator) !*Server {
    const server = try allocator.create(Server);
    errdefer server.destroy();
    server.* = .{
        .allocator = allocator,
        .config = .{},
        .document_store = .{
            .allocator = allocator,
            .config = .init,
            .thread_pool = if (zig_builtin.single_threaded) {} else undefined, // set below
            .diagnostics_collection = &server.diagnostics_collection,
        },
        .job_queue = .init(allocator),
        .thread_pool = undefined, // set below
        .wait_group = if (zig_builtin.single_threaded) {} else .{},
        .diagnostics_collection = .{ .allocator = allocator },
    };

    if (zig_builtin.single_threaded) {
        server.thread_pool = {};
    } else {
        try server.thread_pool.init(.{
            .allocator = allocator,
            .n_jobs = @min(4, std.Thread.getCpuCount() catch 1), // what is a good value here?
        });
        server.document_store.thread_pool = &server.thread_pool;
    }

    server.ip = try InternPool.init(allocator);

    return server;
}

pub fn destroy(server: *Server) void {
    if (!zig_builtin.single_threaded) {
        server.wait_group.wait();
        server.thread_pool.deinit();
    }

    while (server.job_queue.readItem()) |job| job.deinit(server.allocator);
    server.job_queue.deinit();
    server.document_store.deinit();
    server.ip.deinit(server.allocator);
    for (server.workspaces.items) |*workspace| workspace.deinit(server.allocator);
    server.workspaces.deinit(server.allocator);
    server.diagnostics_collection.deinit();
    server.client_capabilities.deinit(server.allocator);
    server.resolved_config.deinit(server.allocator);
    server.config_arena.promote(server.allocator).deinit();
    server.allocator.destroy(server);
}

pub fn setTransport(server: *Server, transport: lsp.AnyTransport) void {
    server.transport = transport;
    server.diagnostics_collection.transport = transport;
    server.document_store.transport = transport;
}

pub fn keepRunning(server: Server) bool {
    switch (server.status) {
        .exiting_success, .exiting_failure => return false,
        else => return true,
    }
}

pub fn waitAndWork(server: *Server) void {
    if (zig_builtin.single_threaded) return;
    server.thread_pool.waitAndWork(&server.wait_group);
    server.wait_group.reset();
}

/// The main loop of ZLS
pub fn loop(server: *Server) !void {
    std.debug.assert(server.transport != null);
    while (server.keepRunning()) {
        const json_message = try server.transport.?.readJsonMessage(server.allocator);
        defer server.allocator.free(json_message);

        try server.sendJsonMessage(json_message);

        while (server.job_queue.readItem()) |job| {
            if (zig_builtin.single_threaded) {
                server.processJob(job);
                continue;
            }

            switch (job.syncMode()) {
                .exclusive => {
                    server.waitAndWork();
                    server.processJob(job);
                },
                .shared => {
                    server.thread_pool.spawnWg(&server.wait_group, processJob, .{ server, job });
                },
            }
        }
    }
}

pub fn sendJsonMessage(server: *Server, json_message: []const u8) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const parsed_message = Message.parseFromSlice(
        server.allocator,
        json_message,
        .{ .ignore_unknown_fields = true, .max_value_len = null, .allocate = .alloc_always },
    ) catch return error.ParseError;
    try server.pushJob(.{ .incoming_message = parsed_message });
}

pub fn sendJsonMessageSync(server: *Server, json_message: []const u8) Error!?[]u8 {
    const parsed_message = Message.parseFromSlice(
        server.allocator,
        json_message,
        .{ .ignore_unknown_fields = true, .max_value_len = null, .allocate = .alloc_always },
    ) catch return error.ParseError;
    defer parsed_message.deinit();
    return try server.processMessage(parsed_message.value);
}

pub fn sendRequestSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: lsp.ParamsType(method)) Error!lsp.ResultType(method) {
    comptime std.debug.assert(lsp.isRequestMethod(method));
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    tracy_zone.setName(method);

    const Params = std.meta.Tag(HandledRequestParams);
    if (!@hasField(Params, method)) return null;

    return switch (@field(Params, method)) {
        .initialize => try server.initializeHandler(arena, params),
        .shutdown => try server.shutdownHandler(arena, params),
        .@"textDocument/willSaveWaitUntil" => try server.willSaveWaitUntilHandler(arena, params),
        .@"textDocument/semanticTokens/full" => try server.semanticTokensFullHandler(arena, params),
        .@"textDocument/semanticTokens/range" => try server.semanticTokensRangeHandler(arena, params),
        .@"textDocument/inlayHint" => try server.inlayHintHandler(arena, params),
        .@"textDocument/completion" => try server.completionHandler(arena, params),
        .@"textDocument/signatureHelp" => try server.signatureHelpHandler(arena, params),
        .@"textDocument/definition" => try server.gotoDefinitionHandler(arena, params),
        .@"textDocument/typeDefinition" => try server.gotoTypeDefinitionHandler(arena, params),
        .@"textDocument/implementation" => try server.gotoImplementationHandler(arena, params),
        .@"textDocument/declaration" => try server.gotoDeclarationHandler(arena, params),
        .@"textDocument/hover" => try server.hoverHandler(arena, params),
        .@"textDocument/documentSymbol" => try server.documentSymbolsHandler(arena, params),
        .@"textDocument/formatting" => try server.formattingHandler(arena, params),
        .@"textDocument/rename" => try server.renameHandler(arena, params),
        .@"textDocument/prepareRename" => server.prepareRenameHandler(params),
        .@"textDocument/references" => try server.referencesHandler(arena, params),
        .@"textDocument/documentHighlight" => try server.documentHighlightHandler(arena, params),
        .@"textDocument/codeAction" => try server.codeActionHandler(arena, params),
        .@"textDocument/foldingRange" => try server.foldingRangeHandler(arena, params),
        .@"textDocument/selectionRange" => try server.selectionRangeHandler(arena, params),
        .other => return null,
    };
}

pub fn sendNotificationSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: lsp.ParamsType(method)) Error!void {
    comptime std.debug.assert(lsp.isNotificationMethod(method));
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    tracy_zone.setName(method);

    const Params = std.meta.Tag(HandledNotificationParams);
    if (!@hasField(Params, method)) return null;

    return switch (@field(Params, method)) {
        .initialized => try server.initializedHandler(arena, params),
        .exit => try server.exitHandler(arena, params),
        .@"textDocument/didOpen" => try server.openDocumentHandler(arena, params),
        .@"textDocument/didChange" => try server.changeDocumentHandler(arena, params),
        .@"textDocument/didSave" => try server.saveDocumentHandler(arena, params),
        .@"textDocument/didClose" => try server.closeDocumentHandler(arena, params),
        .@"workspace/didChangeWatchedFiles" => try server.didChangeWatchedFilesHandler(arena, params),
        .@"workspace/didChangeWorkspaceFolders" => try server.didChangeWorkspaceFoldersHandler(arena, params),
        .@"workspace/didChangeConfiguration" => try server.didChangeConfigurationHandler(arena, params),
        .other => {},
    };
}

pub fn sendMessageSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: lsp.ParamsType(method)) Error!lsp.ResultType(method) {
    comptime std.debug.assert(lsp.isRequestMethod(method) or lsp.isNotificationMethod(method));

    if (comptime lsp.isRequestMethod(method)) {
        return try server.sendRequestSync(arena, method, params);
    } else if (comptime lsp.isNotificationMethod(method)) {
        return try server.sendNotificationSync(arena, method, params);
    } else unreachable;
}

fn processMessage(server: *Server, message: Message) Error!?[]u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var timer = std.time.Timer.start() catch null;
    defer if (timer) |*t| {
        const total_time = @divFloor(t.read(), std.time.ns_per_ms);
        if (zig_builtin.single_threaded) {
            log.debug("Took {d}ms to process {}", .{ total_time, fmtMessage(message) });
        } else {
            const thread_id = std.Thread.getCurrentId();
            log.debug("Took {d}ms to process {} on Thread {d}", .{ total_time, fmtMessage(message), thread_id });
        }
    };

    try server.validateMessage(message);

    var arena_allocator: std.heap.ArenaAllocator = .init(server.allocator);
    defer arena_allocator.deinit();

    switch (message) {
        .request => |request| switch (request.params) {
            .other => return try server.sendToClientResponse(request.id, @as(?void, null)),
            inline else => |params, method| {
                const result = try server.sendRequestSync(arena_allocator.allocator(), @tagName(method), params);
                return try server.sendToClientResponse(request.id, result);
            },
        },
        .notification => |notification| switch (notification.params) {
            .other => {},
            inline else => |params, method| try server.sendNotificationSync(arena_allocator.allocator(), @tagName(method), params),
        },
        .response => |response| try server.handleResponse(response),
    }
    return null;
}

fn processMessageReportError(server: *Server, message: Message) ?[]const u8 {
    return server.processMessage(message) catch |err| {
        log.err("failed to process {}: {}", .{ fmtMessage(message), err });
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }

        switch (message) {
            .request => |request| return server.sendToClientResponseError(request.id, .{
                .code = @enumFromInt(switch (err) {
                    error.OutOfMemory => @intFromEnum(types.ErrorCodes.InternalError),
                    error.ParseError => @intFromEnum(types.ErrorCodes.ParseError),
                    error.InvalidRequest => @intFromEnum(types.ErrorCodes.InvalidRequest),
                    error.MethodNotFound => @intFromEnum(types.ErrorCodes.MethodNotFound),
                    error.InvalidParams => @intFromEnum(types.ErrorCodes.InvalidParams),
                    error.InternalError => @intFromEnum(types.ErrorCodes.InternalError),
                    error.ServerNotInitialized => @intFromEnum(types.ErrorCodes.ServerNotInitialized),
                    error.RequestFailed => @intFromEnum(types.LSPErrorCodes.RequestFailed),
                    error.ServerCancelled => @intFromEnum(types.LSPErrorCodes.ServerCancelled),
                    error.ContentModified => @intFromEnum(types.LSPErrorCodes.ContentModified),
                    error.RequestCancelled => @intFromEnum(types.LSPErrorCodes.RequestCancelled),
                }),
                .message = @errorName(err),
            }) catch null,
            .notification, .response => return null,
        }
    };
}

fn processJob(server: *Server, job: Job) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    tracy_zone.setName(@tagName(job));
    defer job.deinit(server.allocator);

    switch (job) {
        .incoming_message => |parsed_message| {
            const response = server.processMessageReportError(parsed_message.value) orelse return;
            server.allocator.free(response);
        },
        .generate_diagnostics => |uri| {
            const handle = server.document_store.getHandle(uri) orelse return;
            diagnostics_gen.generateDiagnostics(server, handle) catch return;
        },
    }
}

fn validateMessage(server: *const Server, message: Message) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const method = switch (message) {
        .request => |request| switch (request.params) {
            .other => |info| info.method,
            else => @tagName(request.params),
        },
        .notification => |notification| switch (notification.params) {
            .other => |info| info.method,
            else => @tagName(notification.params),
        },
        .response => return, // validation happens in `handleResponse`
    };

    // https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#dollarRequests
    if (message == .request and std.mem.startsWith(u8, method, "$/")) return error.MethodNotFound;
    if (message == .notification and std.mem.startsWith(u8, method, "$/")) return;

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
}

fn handleResponse(server: *Server, response: lsp.JsonRPCMessage.Response) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (response.id == null) {
        log.warn("received response from client without id!", .{});
        return;
    }

    const id: []const u8 = switch (response.id.?) {
        .string => |id| id,
        .number => |id| {
            log.warn("received response from client with id '{d}' that has no handler!", .{id});
            return;
        },
    };

    const result = switch (response.result_or_error) {
        .result => |result| result,
        .@"error" => |err| {
            log.err("Error response for '{s}': {}, {s}", .{ id, err.code, err.message });
            return;
        },
    };

    if (std.mem.eql(u8, id, "semantic_tokens_refresh")) {
        //
    } else if (std.mem.eql(u8, id, "inlay_hints_refresh")) {
        //
    } else if (std.mem.eql(u8, id, "progress")) {
        //
    } else if (std.mem.startsWith(u8, id, "register")) {
        //
    } else if (std.mem.eql(u8, id, "apply_edit")) {
        //
    } else if (std.mem.eql(u8, id, "i_haz_configuration")) {
        try server.handleConfiguration(result orelse .null);
    } else {
        log.warn("received response from client with id '{s}' that has no handler!", .{id});
    }
}

/// takes ownership of `job`
fn pushJob(server: *Server, job: Job) error{OutOfMemory}!void {
    server.job_queue_lock.lock();
    defer server.job_queue_lock.unlock();
    server.job_queue.writeItem(job) catch |err| {
        job.deinit(server.allocator);
        return err;
    };
}

pub fn formatMessage(
    message: Message,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, message);
    switch (message) {
        .request => |request| try writer.print("request-{}-{s}", .{ std.json.fmt(request.id, .{}), @tagName(request.params) }),
        .notification => |notification| try writer.print("notification-{s}", .{@tagName(notification.params)}),
        .response => |response| try writer.print("response-{?}", .{std.json.fmt(response.id, .{})}),
    }
}

fn fmtMessage(message: Message) std.fmt.Formatter(formatMessage) {
    return .{ .data = message };
}
