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
const Ast = std.zig.Ast;
const tracy = @import("tracy.zig");
const diff = @import("diff.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
const InternPool = @import("analyser/analyser.zig").InternPool;
const ZigVersionWrapper = @import("ZigVersionWrapper.zig");
const Transport = @import("Transport.zig");
const known_folders = @import("known-folders");

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

const log = std.log.scoped(.zls_server);

// public fields
allocator: std.mem.Allocator,
// use updateConfiguration or updateConfiguration2 for setting config options
config: Config = .{},
document_store: DocumentStore,
transport: ?*Transport = null,
offset_encoding: offsets.Encoding = .@"utf-16",
status: Status = .uninitialized,

// private fields
thread_pool: if (zig_builtin.single_threaded) void else std.Thread.Pool,
wait_group: if (zig_builtin.single_threaded) void else std.Thread.WaitGroup,
job_queue: std.fifo.LinearFifo(Job, .Dynamic),
job_queue_lock: std.Thread.Mutex = .{},
ip: InternPool = .{},
zig_exe_lock: std.Thread.Mutex = .{},
config_arena: std.heap.ArenaAllocator.State = .{},
client_capabilities: ClientCapabilities = .{},
runtime_zig_version: ?ZigVersionWrapper = null,
recording_enabled: bool = false,
replay_enabled: bool = false,

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
    supports_textDocument_definition_linkSupport: bool = false,
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
    load_build_configuration: DocumentStore.Uri,

    fn deinit(self: Job, allocator: std.mem.Allocator) void {
        switch (self) {
            .incoming_message => |parsed_message| parsed_message.deinit(),
            .generate_diagnostics => |uri| allocator.free(uri),
            .load_build_configuration => |uri| allocator.free(uri),
        }
    }

    const SynchronizationMode = enum {
        /// this `Job` requires exclusive access to `Server` and `DocumentStore`
        /// all previous jobs will be awaited
        exclusive,
        /// this `Job` requires shared access to `Server` and `DocumentStore`
        /// other non exclusive jobs can be processed in parallel
        shared,
        /// this `Job` operates atomically and does not require any synchronisation
        atomic,
    };

    fn syncMode(self: Job) SynchronizationMode {
        return switch (self) {
            .incoming_message => |parsed_message| if (parsed_message.value.isBlocking()) .exclusive else .shared,
            .generate_diagnostics => .shared,
            .load_build_configuration => .atomic,
        };
    }
};

fn sendToClientResponse(server: *Server, id: types.RequestId, result: anytype) error{OutOfMemory}![]u8 {
    // TODO validate result type is a possible response
    // TODO validate response is from a client to server request
    // TODO validate result type

    return try server.sendToClientInternal(id, null, null, "result", result);
}

fn sendToClientRequest(server: *Server, id: types.RequestId, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    // TODO validate method is a request
    // TODO validate method is server to client
    // TODO validate params type

    return try server.sendToClientInternal(id, method, null, "params", params);
}

fn sendToClientNotification(server: *Server, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    // TODO validate method is a notification
    // TODO validate method is server to client
    // TODO validate params type

    return try server.sendToClientInternal(null, method, null, "params", params);
}

fn sendToClientResponseError(server: *Server, id: types.RequestId, err: ?types.ResponseError) error{OutOfMemory}![]u8 {
    return try server.sendToClientInternal(id, null, err, "", null);
}

fn sendToClientInternal(
    server: *Server,
    maybe_id: ?types.RequestId,
    maybe_method: ?[]const u8,
    maybe_err: ?types.ResponseError,
    extra_name: []const u8,
    extra: anytype,
) error{OutOfMemory}![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(server.allocator);
    var writer = buffer.writer(server.allocator);
    try writer.writeAll(
        \\{"jsonrpc":"2.0"
    );
    if (maybe_id) |id| {
        try writer.writeAll(
            \\,"id":
        );
        try std.json.stringify(id, .{}, writer);
    }
    if (maybe_method) |method| {
        try writer.writeAll(
            \\,"method":
        );
        try std.json.stringify(method, .{}, writer);
    }
    switch (@TypeOf(extra)) {
        void => {},
        ?void => {
            try writer.print(
                \\,"{s}":null
            , .{extra_name});
        },
        else => {
            try writer.print(
                \\,"{s}":
            , .{extra_name});
            try std.json.stringify(extra, .{ .emit_null_optional_fields = false }, writer);
        },
    }
    if (maybe_err) |err| {
        try writer.writeAll(
            \\,"error":
        );
        try std.json.stringify(err, .{}, writer);
    }
    try writer.writeByte('}');

    if (server.transport) |transport| {
        transport.writeJsonMessage(buffer.items) catch |err| {
            log.err("failed to write response: {}", .{err});
        };
    }
    return buffer.toOwnedSlice(server.allocator);
}

fn showMessage(
    server: *Server,
    message_type: types.MessageType,
    comptime fmt: []const u8,
    args: anytype,
) void {
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
    const message = std.fmt.allocPrint(server.allocator, fmt, args) catch return;
    defer server.allocator.free(message);
    switch (message_type) {
        .Error => log.err("{s}", .{message}),
        .Warning => log.warn("{s}", .{message}),
        .Info => log.info("{s}", .{message}),
        .Log => log.debug("{s}", .{message}),
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
pub fn autofix(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle) error{OutOfMemory}!std.ArrayListUnmanaged(types.TextEdit) {
    if (!server.config.enable_ast_check_diagnostics) return .{};
    if (handle.tree.errors.len != 0) return .{};

    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    try diagnostics_gen.getAstCheckDiagnostics(server, arena, handle.*, &diagnostics);
    if (diagnostics.items.len == 0) return .{};

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    var builder = code_actions.Builder{
        .arena = arena,
        .analyser = &analyser,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
    };

    var actions = std.ArrayListUnmanaged(types.CodeAction){};
    var remove_capture_actions = std.AutoHashMapUnmanaged(types.Range, void){};
    for (diagnostics.items) |diagnostic| {
        try builder.generateCodeAction(diagnostic, &actions, &remove_capture_actions);
    }

    var text_edits = std.ArrayListUnmanaged(types.TextEdit){};
    for (actions.items) |action| {
        std.debug.assert(action.kind != null);
        std.debug.assert(action.edit != null);
        std.debug.assert(action.edit.?.changes != null);

        if (action.kind.? != .@"source.fixAll") continue;

        const changes = action.edit.?.changes.?.map;
        if (changes.count() != 1) continue;

        const edits: []const types.TextEdit = changes.get(handle.uri) orelse continue;

        try text_edits.appendSlice(arena, edits);
    }

    return text_edits;
}

fn initializeHandler(server: *Server, _: std.mem.Allocator, request: types.InitializeParams) Error!types.InitializeResult {
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
                    .custom_value => {},
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
                    for (literalSupport.codeActionKind.valueSet) |code_action_kind| {
                        if (code_action_kind.eql(.@"source.fixAll")) {
                            server.client_capabilities.supports_code_action_fixall = true;
                            break;
                        }
                    }
                }
            }
        }
        if (textDocument.definition) |definition| {
            server.client_capabilities.supports_textDocument_definition_linkSupport = definition.linkSupport orelse false;
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
            if (server.transport) |transport| {
                transport.message_tracing = true;
            }
        }
    }

    log.info("{}", .{server.client_capabilities});
    log.info("offset encoding: {s}", .{@tagName(server.offset_encoding)});

    server.updateConfiguration(.{}, false) catch |err| {
        log.err("failed to load configuration: {}", .{err});
    };

    server.status = .initializing;

    if (server.recording_enabled) {
        server.showMessage(.Info,
            \\This zls session is being recorded to {s}.
        , .{server.config.record_session_path.?});
    }

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

    return .{
        .serverInfo = .{
            .name = "zls",
            .version = build_options.version,
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

fn initializedHandler(server: *Server, _: std.mem.Allocator, notification: types.InitializedParams) Error!void {
    _ = notification;

    if (server.status != .initializing) {
        log.warn("received a initialized notification but the server has not send a initialize request!", .{});
    }

    server.status = .initialized;

    if (!server.recording_enabled and server.client_capabilities.supports_workspace_did_change_configuration_dynamic_registration) {
        try server.registerCapability("workspace/didChangeConfiguration");
    }

    if (server.client_capabilities.supports_configuration)
        try server.requestConfiguration();
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

fn cancelRequestHandler(server: *Server, _: std.mem.Allocator, request: types.CancelParams) Error!void {
    _ = server;
    _ = request;
    // TODO implement $/cancelRequest
}

fn setTraceHandler(server: *Server, _: std.mem.Allocator, request: types.SetTraceParams) Error!void {
    if (server.transport) |transport| {
        transport.message_tracing = request.value != .off;
    }
}

fn registerCapability(server: *Server, method: []const u8) Error!void {
    const id = try std.fmt.allocPrint(server.allocator, "register-{s}", .{method});
    defer server.allocator.free(id);

    log.debug("Dynamically registering method '{s}'", .{method});

    const json_message = try server.sendToClientRequest(
        .{ .string = id },
        "client/registerCapability",
        types.RegistrationParams{ .registrations = &.{
            types.Registration{
                .id = id,
                .method = method,
            },
        } },
    );
    server.allocator.free(json_message);
}

fn invalidateAllBuildFiles(server: *Server) error{OutOfMemory}!void {
    if (!std.process.can_spawn) return;

    server.document_store.lock.lockShared();
    defer server.document_store.lock.unlockShared();

    server.job_queue_lock.lock();
    defer server.job_queue_lock.unlock();

    try server.job_queue.ensureUnusedCapacity(server.document_store.build_files.count());
    for (server.document_store.build_files.keys()) |build_file_uri| {
        server.job_queue.writeItemAssumeCapacity(.{
            .load_build_configuration = try server.allocator.dupe(u8, build_file_uri),
        });
    }
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

    if (server.replay_enabled) {
        log.info("workspace/configuration are disabled during a replay!", .{});
        return;
    }

    const fields = std.meta.fields(configuration.Configuration);
    const result = switch (json) {
        .array => |arr| if (arr.items.len == fields.len) arr.items else {
            log.err("workspace/configuration expectes an array of size {d} but received {d}", .{ fields.len, arr.items.len });
            return;
        },
        else => {
            log.err("workspace/configuration expectes an array but received {s}", .{@tagName(json)});
            return;
        },
    };

    var arena_allocator = std.heap.ArenaAllocator.init(server.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var new_config: configuration.Configuration = .{};

    inline for (fields, result) |field, json_value| {
        const maybe_new_value = std.json.parseFromValueLeaky(field.type, arena, json_value, .{}) catch |err| blk: {
            log.err("failed to parse configuration option '{s}': {}", .{ field.name, err });
            break :blk null;
        };
        if (maybe_new_value) |new_value| {
            @field(new_config, field.name) = new_value;
        }
    }

    server.updateConfiguration(new_config, false) catch |err| {
        log.err("failed to update configuration: {}", .{err});
    };
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

    server.updateConfiguration(new_config, false) catch |err| {
        log.err("failed to update configuration: {}", .{err});
    };
}

pub fn updateConfiguration2(server: *Server, new_config: Config, resolve: bool) !void {
    var cfg: configuration.Configuration = .{};
    inline for (std.meta.fields(Config)) |field| {
        @field(cfg, field.name) = @field(new_config, field.name);
    }
    try server.updateConfiguration(cfg, resolve);
}

pub fn updateConfiguration(server: *Server, new_config: configuration.Configuration, resolve: bool) !void {
    // NOTE every changed configuration will increase the amount of memory allocated by the arena
    // This is unlikely to cause any big issues since the user is probably not going set settings
    // often in one session
    var config_arena_allocator = server.config_arena.promote(server.allocator);
    defer server.config_arena = config_arena_allocator.state;
    const config_arena = config_arena_allocator.allocator();

    var new_cfg = new_config;

    try server.validateConfiguration(&new_cfg);
    if (resolve) {
        try server.resolveConfiguration(config_arena, &new_cfg);
        try server.validateConfiguration(&new_cfg);
    }
    // <---------------------------------------------------------->
    //                        apply changes
    // <---------------------------------------------------------->

    const new_zig_exe_path =
        new_config.zig_exe_path != null and
        (server.config.zig_exe_path == null or !std.mem.eql(u8, server.config.zig_exe_path.?, new_config.zig_exe_path.?));
    const new_zig_lib_path =
        new_config.zig_lib_path != null and
        (server.config.zig_lib_path == null or !std.mem.eql(u8, server.config.zig_lib_path.?, new_config.zig_lib_path.?));
    const new_build_runner_path =
        new_config.build_runner_path != null and
        (server.config.build_runner_path == null or !std.mem.eql(u8, server.config.build_runner_path.?, new_config.build_runner_path.?));

    inline for (std.meta.fields(Config)) |field| {
        if (@field(new_cfg, field.name)) |new_config_value| {
            if (@TypeOf(new_config_value) == []const u8) {
                if (@field(server.config, field.name) == null or
                    !std.mem.eql(u8, @field(server.config, field.name).?, new_config_value))
                {
                    log.info("set config option '{s}' to '{s}'", .{ field.name, new_config_value });
                    @field(server.config, field.name) = try config_arena.dupe(u8, new_config_value);
                }
            } else {
                if (@field(server.config, field.name) != new_config_value) {
                    log.info("set config option '{s}' to '{any}'", .{ field.name, new_config_value });
                    @field(server.config, field.name) = new_config_value;
                }
            }
        }
    }

    if (server.config.zig_exe_path == null and
        server.runtime_zig_version != null)
    {
        server.runtime_zig_version.?.free();
        server.runtime_zig_version = null;
    }

    if (new_zig_exe_path or new_build_runner_path) {
        try server.invalidateAllBuildFiles();
    }

    if (new_zig_exe_path or new_zig_lib_path) {
        server.document_store.cimports.clearAndFree(server.document_store.allocator);
    }

    // <---------------------------------------------------------->
    //  don't modify config options after here, only show messages
    // <---------------------------------------------------------->

    if (std.process.can_spawn and server.config.zig_exe_path == null) {
        // TODO there should a way to supress this message
        server.showMessage(.Warning, "zig executable could not be found", .{});
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

    if (server.status == .initialized) {
        const json_message = try server.sendToClientRequest(
            .{ .string = "semantic_tokens_refresh" },
            "workspace/semanticTokens/refresh",
            {},
        );
        server.allocator.free(json_message);
    }
}

fn validateConfiguration(server: *Server, config: *configuration.Configuration) !void {
    inline for (comptime std.meta.fieldNames(Config)) |field_name| {
        const FileCheckInfo = struct {
            kind: enum { file, directory },
            is_accessible: bool,
        };

        @setEvalBranchQuota(2_000);
        const file_info: FileCheckInfo = comptime if (std.mem.indexOf(u8, field_name, "path") != null) blk: {
            if (std.mem.eql(u8, field_name, "zig_exe_path") or
                std.mem.eql(u8, field_name, "replay_session_path") or
                std.mem.eql(u8, field_name, "builtin_path") or
                std.mem.eql(u8, field_name, "build_runner_path"))
            {
                break :blk .{ .kind = .file, .is_accessible = true };
            } else if (std.mem.eql(u8, field_name, "record_session_path")) {
                break :blk .{ .kind = .file, .is_accessible = false };
            } else if (std.mem.eql(u8, field_name, "zig_lib_path")) {
                break :blk .{ .kind = .directory, .is_accessible = true };
            } else if (std.mem.eql(u8, field_name, "global_cache_path") or
                std.mem.eql(u8, field_name, "build_runner_global_cache_path"))
            {
                break :blk .{ .kind = .directory, .is_accessible = false };
            } else {
                @compileError(std.fmt.comptimePrint(
                    \\config option '{s}' contains the word 'path'.
                    \\Please add config option validation checks above if necessary.
                    \\If not necessary, just add a continue switch-case to ignore this error.
                    \\
                , .{field_name}));
            }
        } else continue;

        const is_ok = if (@field(config, field_name)) |path| ok: {
            if (path.len == 0) break :ok false;

            if (!std.fs.path.isAbsolute(path)) {
                server.showMessage(.Warning, "config option '{s}': expected absolute path but got '{s}'", .{ field_name, path });
                break :ok false;
            }

            switch (file_info.kind) {
                .file => {
                    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
                        if (file_info.is_accessible) {
                            server.showMessage(.Warning, "config option '{s}': invalid file path '{s}': {}", .{ field_name, path, err });
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
                            server.showMessage(.Warning, "config option '{s}': expected file path but '{s}' is a directory", .{ field_name, path });
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
                        if (file_info.is_accessible) {
                            server.showMessage(.Warning, "config option '{s}': invalid directory path '{s}': {}", .{ field_name, path, err });
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
                            server.showMessage(.Warning, "config option '{s}': expected directory path but '{s}' is a file", .{ field_name, path });
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
            @field(config, field_name) = null;
        }
    }

    // some config options can't be changed after initialization
    if (server.status != .uninitialized) {
        config.record_session = null;
        config.record_session_path = null;
        config.replay_session_path = null;
    }
}

fn resolveConfiguration(server: *Server, config_arena: std.mem.Allocator, config: *configuration.Configuration) !void {
    if (config.zig_exe_path == null) blk: {
        comptime if (!std.process.can_spawn) break :blk;
        config.zig_exe_path = try configuration.findZig(config_arena);
    }

    if (config.zig_exe_path) |exe_path| blk: {
        comptime if (!std.process.can_spawn) break :blk;
        const env = configuration.getZigEnv(server.allocator, exe_path) orelse break :blk;
        defer env.deinit();

        if (config.zig_lib_path == null) {
            config.zig_lib_path = try config_arena.dupe(u8, env.value.lib_dir.?);
        }

        if (config.build_runner_global_cache_path == null) {
            config.build_runner_global_cache_path = try config_arena.dupe(u8, env.value.global_cache_dir);
        }

        if (server.runtime_zig_version) |current_version| current_version.free();
        server.runtime_zig_version = null;

        const duped_zig_version_string = try server.allocator.dupe(u8, env.value.version);
        errdefer server.allocator.free(duped_zig_version_string);

        server.runtime_zig_version = .{
            .version = try std.SemanticVersion.parse(duped_zig_version_string),
            .allocator = server.allocator,
            .raw_string = duped_zig_version_string,
        };
    }

    if (config.global_cache_path == null) {
        const cache_dir_path = (try known_folders.getPath(server.allocator, .cache)) orelse {
            log.warn("Known-folders could not fetch the cache path", .{});
            return;
        };
        defer server.allocator.free(cache_dir_path);

        config.global_cache_path = try std.fs.path.resolve(config_arena, &[_][]const u8{ cache_dir_path, "zls" });

        try std.fs.cwd().makePath(config.global_cache_path.?);
    }

    if (config.build_runner_path == null) blk: {
        if (config.global_cache_path == null) break :blk;

        config.build_runner_path = try std.fs.path.resolve(config_arena, &[_][]const u8{ config.global_cache_path.?, "build_runner.zig" });

        const file = try std.fs.createFileAbsolute(config.build_runner_path.?, .{});
        defer file.close();

        try file.writeAll(@embedFile("special/build_runner.zig"));
    }

    if (config.builtin_path == null) blk: {
        comptime if (!std.process.can_spawn) break :blk;
        if (config.zig_exe_path == null) break :blk;
        if (config.global_cache_path == null) break :blk;

        const result = try std.ChildProcess.exec(.{
            .allocator = server.allocator,
            .argv = &.{
                config.zig_exe_path.?,
                "build-exe",
                "--show-builtin",
            },
            .max_output_bytes = 1024 * 1024 * 50,
        });
        defer server.allocator.free(result.stdout);
        defer server.allocator.free(result.stderr);

        var d = try std.fs.cwd().openDir(config.global_cache_path.?, .{});
        defer d.close();

        const f = d.createFile("builtin.zig", .{}) catch |err| switch (err) {
            error.AccessDenied => break :blk,
            else => |e| return e,
        };
        defer f.close();

        try f.writeAll(result.stdout);

        config.builtin_path = try std.fs.path.join(config_arena, &.{ config.global_cache_path.?, "builtin.zig" });
    }
}

fn openDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidOpenTextDocumentParams) Error!void {
    try server.document_store.openDocument(notification.textDocument.uri, notification.textDocument.text);

    if (server.client_capabilities.supports_publish_diagnostics) {
        try server.pushJob(.{
            .generate_diagnostics = try server.allocator.dupe(u8, notification.textDocument.uri),
        });
    }
}

fn changeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidChangeTextDocumentParams) Error!void {
    const handle = server.document_store.getHandle(notification.textDocument.uri) orelse return;

    const new_text = try diff.applyContentChanges(server.allocator, handle.text, notification.contentChanges, server.offset_encoding);

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
        try server.pushJob(.{
            .load_build_configuration = try server.allocator.dupe(u8, uri),
        });
    }

    if (server.getAutofixMode() == .on_save) {
        const handle = server.document_store.getHandle(uri) orelse return;
        var text_edits = try server.autofix(arena, handle);

        var workspace_edit = types.WorkspaceEdit{ .changes = .{} };
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
}

fn closeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidCloseTextDocumentParams) error{}!void {
    server.document_store.closeDocument(notification.textDocument.uri);
}

fn willSaveWaitUntilHandler(server: *Server, arena: std.mem.Allocator, request: types.WillSaveTextDocumentParams) Error!?[]types.TextEdit {
    if (server.getAutofixMode() != .will_save_wait_until) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var text_edits = try server.autofix(arena, handle);

    return try text_edits.toOwnedSlice(arena);
}

fn semanticTokensFullHandler(server: *Server, arena: std.mem.Allocator, request: types.SemanticTokensParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    return try semantic_tokens.writeSemanticTokens(
        arena,
        &analyser,
        handle,
        null,
        server.offset_encoding,
        server.config.semantic_tokens == .partial,
    );
}

fn semanticTokensRangeHandler(server: *Server, arena: std.mem.Allocator, request: types.SemanticTokensRangeParams) Error!?types.SemanticTokens {
    if (server.config.semantic_tokens == .none) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const loc = offsets.rangeToLoc(handle.tree.source, request.range, server.offset_encoding);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    return try semantic_tokens.writeSemanticTokens(
        arena,
        &analyser,
        handle,
        loc,
        server.offset_encoding,
        server.config.semantic_tokens == .partial,
    );
}

pub fn completionHandler(server: *Server, arena: std.mem.Allocator, request: types.CompletionParams) Error!ResultType("textDocument/completion") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    return .{
        .CompletionList = try completions.completionAtIndex(server, &analyser, arena, handle, source_index) orelse return null,
    };
}

pub fn signatureHelpHandler(server: *Server, arena: std.mem.Allocator, request: types.SignatureHelpParams) Error!?types.SignatureHelp {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (request.position.character == 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    const signature_info = (try signature_help.getSignatureInfo(
        &analyser,
        arena,
        handle,
        source_index,
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
) Error!ResultType("textDocument/definition") {
    return server.gotoHandler(arena, .definition, request);
}

fn gotoHandler(
    server: *Server,
    arena: std.mem.Allocator,
    comptime kind: goto.GotoKind,
    request: types.DefinitionParams,
) Error!ResultType("textDocument/definition") {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    const response = try goto.goto(&analyser, &server.document_store, arena, handle, source_index, kind, server.offset_encoding) orelse return null;
    if (server.client_capabilities.supports_textDocument_definition_linkSupport) {
        return .{
            .array_of_DefinitionLink = response,
        };
    }

    var aol = try arena.alloc(types.Location, response.len);
    for (0..response.len) |index| {
        aol[index].uri = response[index].targetUri;
        aol[index].range = response[index].targetSelectionRange;
    }
    return .{
        .Definition = .{ .array_of_Location = aol },
    };
}

fn gotoTypeDefinitionHandler(server: *Server, arena: std.mem.Allocator, request: types.TypeDefinitionParams) Error!ResultType("textDocument/typeDefinition") {
    const response = (try server.gotoHandler(arena, .type_definition, .{
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

fn gotoImplementationHandler(server: *Server, arena: std.mem.Allocator, request: types.ImplementationParams) Error!ResultType("textDocument/implementation") {
    const response = (try server.gotoHandler(arena, .definition, .{
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

fn gotoDeclarationHandler(server: *Server, arena: std.mem.Allocator, request: types.DeclarationParams) Error!ResultType("textDocument/declaration") {
    const response = (try server.gotoHandler(arena, .declaration, .{
        .textDocument = request.textDocument,
        .position = request.position,
        .workDoneToken = request.workDoneToken,
        .partialResultToken = request.partialResultToken,
    })) orelse return null;
    return switch (response) {
        .array_of_DefinitionLink => |adl| .{ .array_of_DeclarationLink = adl },
        .Definition => |def| .{ .Declaration = .{ .array_of_Location = def.array_of_Location } },
    };
}

pub fn hoverHandler(server: *Server, arena: std.mem.Allocator, request: types.HoverParams) Error!?types.Hover {
    if (request.position.character == 0) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    const source_index = offsets.positionToIndex(handle.text, request.position, server.offset_encoding);

    const markup_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    const response = hover_handler.hover(&analyser, arena, handle, source_index, markup_kind, server.offset_encoding);

    // TODO: Figure out a better solution for comptime interpreter diags
    if (server.client_capabilities.supports_publish_diagnostics) {
        try server.pushJob(.{
            .generate_diagnostics = try server.allocator.dupe(u8, handle.uri),
        });
    }

    return response;
}

pub fn documentSymbolsHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentSymbolParams) Error!ResultType("textDocument/documentSymbol") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;
    return .{
        .array_of_DocumentSymbol = try document_symbol.getDocumentSymbols(arena, handle.tree, server.offset_encoding),
    };
}

pub fn formattingHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentFormattingParams) Error!?[]types.TextEdit {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    if (handle.tree.errors.len != 0) return null;

    const formatted = try handle.tree.render(arena);

    if (std.mem.eql(u8, handle.text, formatted)) return null;

    return if (diff.edits(arena, handle.text, formatted, server.offset_encoding)) |text_edits| text_edits.items else |_| null;
}

pub fn renameHandler(server: *Server, arena: std.mem.Allocator, request: types.RenameParams) Error!?types.WorkspaceEdit {
    const response = try generalReferencesHandler(server, arena, .{ .rename = request });
    return if (response) |rep| rep.rename else null;
}

pub fn referencesHandler(server: *Server, arena: std.mem.Allocator, request: types.ReferenceParams) Error!?[]types.Location {
    const response = try generalReferencesHandler(server, arena, .{ .references = request });
    return if (response) |rep| rep.references else null;
}

pub fn documentHighlightHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentHighlightParams) Error!?[]types.DocumentHighlight {
    const response = try generalReferencesHandler(server, arena, .{ .highlight = request });
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

// TODO: Move to src/features/references.zig?
pub fn generalReferencesHandler(server: *Server, arena: std.mem.Allocator, request: GeneralReferencesRequest) Error!?GeneralReferencesResponse {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(request.uri()) orelse return null;

    if (request.position().character <= 0) return null;

    const source_index = offsets.positionToIndex(handle.text, request.position(), server.offset_encoding);
    const name_loc = Analyser.identifierLocFromPosition(source_index, handle) orelse return null;
    const name = offsets.locToSlice(handle.text, name_loc);
    const pos_context = try Analyser.getPositionContext(server.allocator, handle.text, source_index, true);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    // TODO: Make this work with branching types
    const decl = switch (pos_context) {
        .var_access => try analyser.getSymbolGlobal(source_index, handle, name),
        .field_access => |loc| z: {
            const held_loc = offsets.locMerge(loc, name_loc);
            const a = try analyser.getSymbolFieldAccesses(arena, handle, source_index, held_loc, name);
            if (a) |b| {
                if (b.len != 0) break :z b[0];
            }

            break :z null;
        },
        .label => try Analyser.getLabelGlobal(source_index, handle, name),
        else => null,
    } orelse return null;

    const include_decl = switch (request) {
        .references => |ref| ref.context.includeDeclaration,
        else => true,
    };

    const locations = if (decl.decl.* == .label_decl)
        try references.labelReferences(arena, decl, server.offset_encoding, include_decl)
    else
        try references.symbolReferences(
            arena,
            &analyser,
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
                const gop = try changes.getOrPutValue(arena, loc.uri, .{});
                try gop.value_ptr.append(arena, .{
                    .range = loc.range,
                    .newText = rename.newName,
                });
            }

            // TODO can we avoid having to move map from `changes` to `new_changes`?
            var new_changes: types.Map(types.DocumentUri, []const types.TextEdit) = .{};
            try new_changes.map.ensureTotalCapacity(arena, @intCast(changes.count()));

            var changes_it = changes.iterator();
            while (changes_it.next()) |entry| {
                new_changes.map.putAssumeCapacityNoClobber(entry.key_ptr.*, try entry.value_ptr.toOwnedSlice(arena));
            }

            return .{ .rename = .{ .changes = new_changes } };
        },
        .references => return .{ .references = locations.items },
        .highlight => {
            var highlights = try std.ArrayListUnmanaged(types.DocumentHighlight).initCapacity(arena, locations.items.len);
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

fn inlayHintHandler(server: *Server, arena: std.mem.Allocator, request: types.InlayHintParams) Error!?[]types.InlayHint {
    if (!server.config.enable_inlay_hints) return null;

    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    const hover_kind: types.MarkupKind = if (server.client_capabilities.hover_supports_md) .markdown else .plaintext;
    const loc = offsets.rangeToLoc(handle.text, request.range, server.offset_encoding);

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
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

fn codeActionHandler(server: *Server, arena: std.mem.Allocator, request: types.CodeActionParams) Error!ResultType("textDocument/codeAction") {
    const handle = server.document_store.getHandle(request.textDocument.uri) orelse return null;

    var analyser = Analyser.init(server.allocator, &server.document_store, &server.ip);
    defer analyser.deinit();

    var builder = code_actions.Builder{
        .arena = arena,
        .analyser = &analyser,
        .handle = handle,
        .offset_encoding = server.offset_encoding,
    };

    // as of right now, only ast-check errors may get a code action
    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};
    if (server.config.enable_ast_check_diagnostics and handle.tree.errors.len == 0) {
        try diagnostics_gen.getAstCheckDiagnostics(server, arena, handle.*, &diagnostics);
    }

    var actions = std.ArrayListUnmanaged(types.CodeAction){};
    var remove_capture_actions = std.AutoHashMapUnmanaged(types.Range, void){};
    for (diagnostics.items) |diagnostic| {
        try builder.generateCodeAction(diagnostic, &actions, &remove_capture_actions);
    }

    const Result = getRequestMetadata("textDocument/codeAction").?.Result;
    var result = try arena.alloc(std.meta.Child(std.meta.Child(Result)), actions.items.len);
    for (actions.items, result) |action, *out| {
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

pub const Message = union(enum) {
    request: Request,
    notification: Notification,
    response: Response,

    pub const Request = struct {
        id: types.RequestId,
        params: Params,

        pub const Params = union(enum) {
            initialize: types.InitializeParams,
            shutdown: void,
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
            @"textDocument/references": types.ReferenceParams,
            @"textDocument/documentHighlight": types.DocumentHighlightParams,
            @"textDocument/codeAction": types.CodeActionParams,
            @"textDocument/foldingRange": types.FoldingRangeParams,
            @"textDocument/selectionRange": types.SelectionRangeParams,
            unknown: []const u8,
        };
    };

    pub const Notification = union(enum) {
        initialized: types.InitializedParams,
        exit: void,
        @"$/cancelRequest": types.CancelParams,
        @"$/setTrace": types.SetTraceParams,
        @"textDocument/didOpen": types.DidOpenTextDocumentParams,
        @"textDocument/didChange": types.DidChangeTextDocumentParams,
        @"textDocument/didSave": types.DidSaveTextDocumentParams,
        @"textDocument/didClose": types.DidCloseTextDocumentParams,
        @"workspace/didChangeConfiguration": types.DidChangeConfigurationParams,
        unknown: []const u8,
    };

    pub const Response = struct {
        id: types.RequestId,
        data: Data,

        pub const Data = union(enum) {
            result: types.LSPAny,
            @"error": types.ResponseError,
        };
    };

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!Message {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();
        const json_value = try std.json.parseFromTokenSourceLeaky(std.json.Value, allocator, source, options);
        return try jsonParseFromValue(allocator, json_value, options);
    }

    pub fn jsonParseFromValue(
        allocator: std.mem.Allocator,
        source: std.json.Value,
        options: std.json.ParseOptions,
    ) !Message {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        if (source != .object) return error.UnexpectedToken;
        const object = source.object;

        @setEvalBranchQuota(10_000);
        if (object.get("id")) |id_obj| {
            const msg_id = try std.json.parseFromValueLeaky(types.RequestId, allocator, id_obj, options);

            if (object.get("method")) |method_obj| {
                const msg_method = try std.json.parseFromValueLeaky([]const u8, allocator, method_obj, options);

                const msg_params = object.get("params") orelse .null;

                const fields = @typeInfo(Request.Params).Union.fields;

                inline for (fields) |field| {
                    if (std.mem.eql(u8, msg_method, field.name)) {
                        const params = if (field.type == void)
                            void{}
                        else
                            try std.json.parseFromValueLeaky(field.type, allocator, msg_params, options);

                        return .{ .request = .{
                            .id = msg_id,
                            .params = @unionInit(Request.Params, field.name, params),
                        } };
                    }
                }
                return .{ .request = .{
                    .id = msg_id,
                    .params = .{ .unknown = msg_method },
                } };
            } else {
                const result = object.get("result") orelse .null;
                const error_obj = object.get("error") orelse .null;

                const err = try std.json.parseFromValueLeaky(?types.ResponseError, allocator, error_obj, options);

                if (result != .null and err != null) return error.UnexpectedToken;

                if (err) |e| {
                    return .{ .response = .{
                        .id = msg_id,
                        .data = .{ .@"error" = e },
                    } };
                } else {
                    return .{ .response = .{
                        .id = msg_id,
                        .data = .{ .result = result },
                    } };
                }
            }
        } else {
            const method_obj = object.get("method") orelse return error.UnexpectedToken;
            const msg_method = try std.json.parseFromValueLeaky([]const u8, allocator, method_obj, options);

            const msg_params = object.get("params") orelse .null;

            const fields = @typeInfo(Notification).Union.fields;

            inline for (fields) |field| {
                if (std.mem.eql(u8, msg_method, field.name)) {
                    const params = if (field.type == void)
                        void{}
                    else
                        try std.json.parseFromValueLeaky(field.type, allocator, msg_params, options);

                    return .{
                        .notification = @unionInit(Notification, field.name, params),
                    };
                }
            }
            return .{ .notification = .{ .unknown = msg_method } };
        }
    }

    pub fn isBlocking(self: Message) bool {
        switch (self) {
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
                .@"textDocument/references",
                .@"textDocument/documentHighlight",
                .@"textDocument/codeAction",
                .@"textDocument/foldingRange",
                .@"textDocument/selectionRange",
                => return false,
                .unknown => return false,
            },
            .notification => |notification| switch (notification) {
                .@"$/cancelRequest" => return false,
                .initialized,
                .exit,
                .@"$/setTrace",
                .@"textDocument/didOpen",
                .@"textDocument/didChange",
                .@"textDocument/didSave",
                .@"textDocument/didClose",
                .@"workspace/didChangeConfiguration",
                => return true,
                .unknown => return false,
            },
            .response => return true,
        }
    }

    pub fn format(message: Message, comptime fmt_str: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, message);
        switch (message) {
            .request => |request| try writer.print("request-{}-{s}", .{ request.id, switch (request.params) {
                .unknown => |method| method,
                else => @tagName(request.params),
            } }),
            .notification => |notification| try writer.print("notification-{s}", .{switch (notification) {
                .unknown => |method| method,
                else => @tagName(notification),
            }}),
            .response => |response| try writer.print("response-{}", .{response.id}),
        }
    }
};

/// make sure to also set the `transport` field
pub fn create(allocator: std.mem.Allocator) !*Server {
    const server = try allocator.create(Server);
    errdefer server.destroy();
    server.* = Server{
        .allocator = allocator,
        .document_store = .{
            .allocator = allocator,
            .config = &server.config,
            .runtime_zig_version = &server.runtime_zig_version,
        },
        .job_queue = std.fifo.LinearFifo(Job, .Dynamic).init(allocator),
        .thread_pool = undefined, // set below
        .wait_group = if (zig_builtin.single_threaded) {} else .{},
    };

    if (zig_builtin.single_threaded) {
        server.thread_pool = {};
    } else {
        try server.thread_pool.init(.{
            .allocator = allocator,
            .n_jobs = 4, // what is a good value here?
        });
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
    if (server.runtime_zig_version) |zig_version| zig_version.free();
    server.config_arena.promote(server.allocator).deinit();
    server.allocator.destroy(server);
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

comptime {
    if (build_options.coverage) {
        std.testing.refAllDecls(@This());
    }
}

pub fn loop(server: *Server) !void {
    std.debug.assert(server.transport != null);
    while (server.keepRunning()) {
        const json_message = try server.transport.?.readJsonMessage(server.allocator);
        defer server.allocator.free(json_message);
        try server.sendJsonMessage(json_message);

        while (server.job_queue.readItem()) |job| {
            if (zig_builtin.single_threaded) {
                server.processJob(job, null);
                continue;
            }

            switch (job.syncMode()) {
                .exclusive => {
                    server.waitAndWork();
                    server.processJob(job, null);
                },
                .shared => {
                    server.wait_group.start();
                    errdefer job.deinit(server.allocator);
                    try server.thread_pool.spawn(processJob, .{ server, job, &server.wait_group });
                },
                .atomic => {
                    errdefer job.deinit(server.allocator);
                    try server.thread_pool.spawn(processJob, .{ server, job, null });
                },
            }
        }
    }
}

pub fn sendJsonMessage(server: *Server, json_message: []const u8) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try server.job_queue.ensureUnusedCapacity(1);
    const parsed_message = std.json.parseFromSlice(
        Message,
        server.allocator,
        json_message,
        .{ .ignore_unknown_fields = true },
    ) catch return error.ParseError;
    server.job_queue.writeItemAssumeCapacity(.{ .incoming_message = parsed_message });
}

pub fn sendJsonMessageSync(server: *Server, json_message: []const u8) Error!?[]u8 {
    const parsed_message = std.json.parseFromSlice(
        Message,
        server.allocator,
        json_message,
        .{ .ignore_unknown_fields = true },
    ) catch return error.ParseError;
    defer parsed_message.deinit();
    return try server.processMessage(parsed_message.value);
}

pub fn sendRequestSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!ResultType(method) {
    comptime std.debug.assert(isRequestMethod(method));
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    tracy_zone.setName(method);

    const RequestMethods = std.meta.Tag(Message.Request.Params);

    return switch (comptime std.meta.stringToEnum(RequestMethods, method).?) {
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
        .@"textDocument/references" => try server.referencesHandler(arena, params),
        .@"textDocument/documentHighlight" => try server.documentHighlightHandler(arena, params),
        .@"textDocument/codeAction" => try server.codeActionHandler(arena, params),
        .@"textDocument/foldingRange" => try server.foldingRangeHandler(arena, params),
        .@"textDocument/selectionRange" => try server.selectionRangeHandler(arena, params),
        .unknown => return null,
    };
}

pub fn sendNotificationSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!void {
    comptime std.debug.assert(isNotificationMethod(method));
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    tracy_zone.setName(method);

    const NotificationMethods = std.meta.Tag(Message.Notification);

    return switch (comptime std.meta.stringToEnum(NotificationMethods, method).?) {
        .initialized => try server.initializedHandler(arena, params),
        .exit => try server.exitHandler(arena, params),
        .@"$/cancelRequest" => try server.cancelRequestHandler(arena, params),
        .@"$/setTrace" => try server.setTraceHandler(arena, params),
        .@"textDocument/didOpen" => try server.openDocumentHandler(arena, params),
        .@"textDocument/didChange" => try server.changeDocumentHandler(arena, params),
        .@"textDocument/didSave" => try server.saveDocumentHandler(arena, params),
        .@"textDocument/didClose" => try server.closeDocumentHandler(arena, params),
        .@"workspace/didChangeConfiguration" => try server.didChangeConfigurationHandler(arena, params),
        .unknown => return,
    };
}

pub fn sendMessageSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!ResultType(method) {
    comptime std.debug.assert(isRequestMethod(method) or isNotificationMethod(method));

    if (comptime isRequestMethod(method)) {
        return try server.sendRequestSync(arena, method, params);
    } else if (comptime isNotificationMethod(method)) {
        return try server.sendNotificationSync(arena, method, params);
    } else unreachable;
}

fn processMessage(server: *Server, message: Message) Error!?[]u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const start_time = std.time.milliTimestamp();
    defer {
        const end_time = std.time.milliTimestamp();
        const total_time = end_time - start_time;
        if (zig_builtin.single_threaded) {
            log.debug("Took {d}ms to process {}", .{ total_time, message });
        } else {
            const thread_id = std.Thread.getCurrentId();
            log.debug("Took {d}ms to process {} on Thread {d}", .{ total_time, message, thread_id });
        }
    }

    try server.validateMessage(message);

    var arena_allocator = std.heap.ArenaAllocator.init(server.allocator);
    defer arena_allocator.deinit();

    @setEvalBranchQuota(5_000);
    switch (message) {
        .request => |request| switch (std.meta.activeTag(request.params)) {
            inline else => |method_name| {
                const method = @tagName(method_name);
                const params = @field(request.params, method);
                const result = try server.sendRequestSync(arena_allocator.allocator(), method, params);
                return try server.sendToClientResponse(request.id, result);
            },
            .unknown => return try server.sendToClientResponse(request.id, null),
        },
        .notification => |notification| switch (std.meta.activeTag(notification)) {
            inline else => |method_name| {
                const method = @tagName(method_name);
                const params = @field(notification, method);
                try server.sendNotificationSync(arena_allocator.allocator(), method, params);
            },
            .unknown => {},
        },
        .response => |response| try server.handleResponse(response),
    }
    return null;
}

fn processMessageReportError(server: *Server, message: Message) ?[]const u8 {
    return server.processMessage(message) catch |err| {
        log.err("failed to process {}: {}", .{ message, err });
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }

        switch (message) {
            .request => |request| return server.sendToClientResponseError(request.id, types.ResponseError{
                .code = switch (err) {
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
                },
                .message = @errorName(err),
            }) catch null,
            .notification, .response => return null,
        }
    };
}

fn processJob(server: *Server, job: Job, wait_group: ?*std.Thread.WaitGroup) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    defer if (!zig_builtin.single_threaded and wait_group != null) wait_group.?.finish();

    defer job.deinit(server.allocator);

    switch (job) {
        .incoming_message => |parsed_message| {
            const response = server.processMessageReportError(parsed_message.value) orelse return;
            server.allocator.free(response);
        },
        .generate_diagnostics => |uri| {
            const handle = server.document_store.getHandle(uri) orelse return;
            var arena_allocator = std.heap.ArenaAllocator.init(server.allocator);
            defer arena_allocator.deinit();
            const diagnostics = diagnostics_gen.generateDiagnostics(server, arena_allocator.allocator(), handle.*) catch return;
            const json_message = server.sendToClientNotification("textDocument/publishDiagnostics", diagnostics) catch return;
            server.allocator.free(json_message);
        },
        .load_build_configuration => |build_file_uri| {
            std.debug.assert(std.process.can_spawn);
            if (!std.process.can_spawn) return;
            server.document_store.invalidateBuildFile(build_file_uri) catch return;
        },
    }
}

fn validateMessage(server: *const Server, message: Message) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const method = switch (message) {
        .request => |request| switch (request.params) {
            .unknown => |method| blk: {
                if (!isRequestMethod(method)) return error.MethodNotFound;
                break :blk method;
            },
            else => @tagName(request.params),
        },
        .notification => |notification| switch (notification) {
            .unknown => |method| blk: {
                if (!isNotificationMethod(method)) return error.MethodNotFound;
                break :blk method;
            },
            else => @tagName(notification),
        },
        .response => return, // validation happens in `handleResponse`
    };

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

fn handleResponse(server: *Server, response: Message.Response) Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const id: []const u8 = switch (response.id) {
        .string => |id| id,
        .integer => |id| {
            log.warn("received response from client with id '{d}' that has no handler!", .{id});
            return;
        },
    };

    if (response.data == .@"error") {
        const err = response.data.@"error";
        log.err("Error response for '{s}': {}, {s}", .{ id, err.code, err.message });
        return;
    }

    if (std.mem.eql(u8, id, "semantic_tokens_refresh")) {
        //
    } else if (std.mem.startsWith(u8, id, "register")) {
        //
    } else if (std.mem.eql(u8, id, "apply_edit")) {
        //
    } else if (std.mem.eql(u8, id, "i_haz_configuration")) {
        try server.handleConfiguration(response.data.result);
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

//
// LSP helper functions
//

pub fn ResultType(comptime method: []const u8) type {
    if (getRequestMetadata(method)) |meta| return meta.Result;
    if (isNotificationMethod(method)) return void;
    @compileError("unknown method '" ++ method ++ "'");
}

pub fn ParamsType(comptime method: []const u8) type {
    if (getRequestMetadata(method)) |meta| return meta.Params orelse void;
    if (getNotificationMetadata(method)) |meta| return meta.Params orelse void;
    @compileError("unknown method '" ++ method ++ "'");
}

fn getRequestMetadata(comptime method: []const u8) ?types.RequestMetadata {
    for (types.request_metadata) |meta| {
        if (std.mem.eql(u8, method, meta.method)) {
            return meta;
        }
    }
    return null;
}

fn getNotificationMetadata(comptime method: []const u8) ?types.NotificationMetadata {
    for (types.notification_metadata) |meta| {
        if (std.mem.eql(u8, method, meta.method)) {
            return meta;
        }
    }
    return null;
}

const RequestMethodSet = blk: {
    @setEvalBranchQuota(5000);
    var kvs_list: [types.request_metadata.len]struct { []const u8 } = undefined;
    inline for (types.request_metadata, &kvs_list) |meta, *kv| {
        kv.* = .{meta.method};
    }
    break :blk std.ComptimeStringMap(void, &kvs_list);
};

const NotificationMethodSet = blk: {
    @setEvalBranchQuota(5000);
    var kvs_list: [types.notification_metadata.len]struct { []const u8 } = undefined;
    inline for (types.notification_metadata, &kvs_list) |meta, *kv| {
        kv.* = .{meta.method};
    }
    break :blk std.ComptimeStringMap(void, &kvs_list);
};

/// return true if there is a request with the given method name
fn isRequestMethod(method: []const u8) bool {
    return RequestMethodSet.has(method);
}

/// return true if there is a notification with the given method name
fn isNotificationMethod(method: []const u8) bool {
    return NotificationMethodSet.has(method);
}
