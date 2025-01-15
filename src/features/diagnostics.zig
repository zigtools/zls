//! Implementation of [`textDocument/publishDiagnostics`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_publishDiagnostics)

const std = @import("std");
const builtin = @import("builtin");
const Ast = std.zig.Ast;
const log = std.log.scoped(.diag);

const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const lsp = @import("lsp");
const types = lsp.types;
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const code_actions = @import("code_actions.zig");
const tracy = @import("tracy");
const DiagnosticsCollection = @import("../DiagnosticsCollection.zig");

const Zir = std.zig.Zir;

pub fn generateDiagnostics(
    server: *Server,
    handle: *DocumentStore.Handle,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (handle.tree.errors.len == 0) {
        const tracy_zone2 = tracy.traceNamed(@src(), "ast-check");
        defer tracy_zone2.end();

        var error_bundle = try getAstCheckDiagnostics(server, handle);
        errdefer error_bundle.deinit(server.allocator);

        try server.diagnostics_collection.pushSingleDocumentDiagnostics(
            .parse,
            handle.uri,
            .{ .error_bundle = error_bundle },
        );
    } else {
        var wip: std.zig.ErrorBundle.Wip = undefined;
        try wip.init(server.allocator);
        defer wip.deinit();

        try collectParseDiagnostics(handle.tree, &wip);

        var error_bundle = try wip.toOwnedBundle("");
        errdefer error_bundle.deinit(server.allocator);

        try server.diagnostics_collection.pushSingleDocumentDiagnostics(
            .parse,
            handle.uri,
            .{ .error_bundle = error_bundle },
        );
    }

    {
        var arena_allocator: std.heap.ArenaAllocator = .init(server.diagnostics_collection.allocator);
        errdefer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        var diagnostics: std.ArrayListUnmanaged(types.Diagnostic) = .empty;

        if (server.getAutofixMode() != .none and handle.tree.mode == .zig) {
            try code_actions.collectAutoDiscardDiagnostics(handle.tree, arena, &diagnostics, server.offset_encoding);
        }

        if (server.config.warn_style and handle.tree.mode == .zig) {
            try collectWarnStyleDiagnostics(handle.tree, arena, &diagnostics, server.offset_encoding);
        }

        if (server.config.highlight_global_var_declarations and handle.tree.mode == .zig) {
            try collectGlobalVarDiagnostics(handle.tree, arena, &diagnostics, server.offset_encoding);
        }

        try server.diagnostics_collection.pushSingleDocumentDiagnostics(
            .parse,
            handle.uri,
            .{ .lsp = .{ .arena = arena_allocator.state, .diagnostics = diagnostics.items } },
        );
    }

    std.debug.assert(server.client_capabilities.supports_publish_diagnostics);
    server.diagnostics_collection.publishDiagnostics() catch |err| {
        log.err("failed to publish diagnostics: {}", .{err});
    };
}

fn collectParseDiagnostics(tree: Ast, eb: *std.zig.ErrorBundle.Wip) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (tree.errors.len == 0) return;

    const allocator = eb.gpa;

    var msg_buffer: std.ArrayListUnmanaged(u8) = .empty;
    defer msg_buffer.deinit(allocator);

    var notes: std.ArrayListUnmanaged(std.zig.ErrorBundle.MessageIndex) = .empty;
    defer notes.deinit(allocator);

    const current_error = tree.errors[0];
    for (tree.errors[1..]) |err| {
        if (!err.is_note) break;

        msg_buffer.clearRetainingCapacity();
        try tree.renderError(err, msg_buffer.writer(allocator));
        try notes.append(allocator, try eb.addErrorMessage(.{
            .msg = try eb.addString(msg_buffer.items),
            .src_loc = try errorBundleSourceLocationFromToken(tree, eb, err.token),
        }));
    }

    msg_buffer.clearRetainingCapacity();
    try tree.renderError(current_error, msg_buffer.writer(allocator));
    try eb.addRootErrorMessage(.{
        .msg = try eb.addString(msg_buffer.items),
        .src_loc = try errorBundleSourceLocationFromToken(tree, eb, current_error.token),
        .notes_len = @intCast(notes.items.len),
    });

    const notes_start = try eb.reserveNotes(@intCast(notes.items.len));
    @memcpy(eb.extra.items[notes_start..][0..notes.items.len], @as([]const u32, @ptrCast(notes.items)));
}

fn errorBundleSourceLocationFromToken(
    tree: Ast,
    eb: *std.zig.ErrorBundle.Wip,
    token: Ast.TokenIndex,
) error{OutOfMemory}!std.zig.ErrorBundle.SourceLocationIndex {
    const loc = offsets.tokenToLoc(tree, token);
    const pos = offsets.indexToPosition(tree.source, loc.start, .@"utf-8");
    const line = offsets.lineSliceAtIndex(tree.source, loc.start);

    return try eb.addSourceLocation(.{
        .src_path = try eb.addString(""),
        .line = pos.line,
        .column = pos.character,
        .span_start = @intCast(loc.start),
        .span_main = @intCast(loc.start),
        .span_end = @intCast(loc.end),
        .source_line = try eb.addString(line),
    });
}

fn collectWarnStyleDiagnostics(
    tree: Ast,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
                try diagnostics.append(arena, .{
                    .range = offsets.tokenToRange(tree, import_str_token, offset_encoding),
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
                    const func = tree.fullFnProto(&buf, decl_idx).?;
                    if (func.extern_export_inline_token != null) break :blk;

                    if (func.name_token) |name_token| {
                        const is_type_function = Analyser.isTypeFunction(tree, func);

                        const func_name = tree.tokenSlice(name_token);
                        if (!is_type_function and !Analyser.isCamelCase(func_name)) {
                            try diagnostics.append(arena, .{
                                .range = offsets.tokenToRange(tree, name_token, offset_encoding),
                                .severity = .Hint,
                                .code = .{ .string = "bad_style" },
                                .source = "zls",
                                .message = "Functions should be camelCase",
                            });
                        } else if (is_type_function and !Analyser.isPascalCase(func_name)) {
                            try diagnostics.append(arena, .{
                                .range = offsets.tokenToRange(tree, name_token, offset_encoding),
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

fn collectGlobalVarDiagnostics(
    tree: Ast,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
                try diagnostics.append(arena, .{
                    .range = offsets.tokenToRange(tree, decl_main_token, offset_encoding),
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

/// caller owns the returned ErrorBundle
pub fn getAstCheckDiagnostics(server: *Server, handle: *DocumentStore.Handle) error{OutOfMemory}!std.zig.ErrorBundle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(handle.tree.errors.len == 0);

    if (std.process.can_spawn and
        server.config.prefer_ast_check_as_child_process and
        handle.tree.mode == .zig and // TODO pass `--zon` if available
        server.config.zig_exe_path != null)
    {
        return getErrorBundleFromAstCheck(
            server.allocator,
            server.config.zig_exe_path.?,
            &server.zig_ast_check_lock,
            handle.tree.source,
        ) catch |err| {
            log.err("failed to run ast-check: {}", .{err});
            return .empty;
        };
    } else switch (handle.tree.mode) {
        .zig => {
            const zir = try handle.getZir();
            if (!zir.hasCompileErrors()) return .empty;

            var eb: std.zig.ErrorBundle.Wip = undefined;
            try eb.init(server.allocator);
            defer eb.deinit();
            try eb.addZirErrorMessages(zir, handle.tree, handle.tree.source, "");
            return try eb.toOwnedBundle("");
        },
        .zon => {
            const zoir = try handle.getZoir();
            if (!zoir.hasCompileErrors()) return .empty;

            var eb: std.zig.ErrorBundle.Wip = undefined;
            try eb.init(server.allocator);
            defer eb.deinit();
            try eb.addZoirErrorMessages(zoir, handle.tree, handle.tree.source, "");
            return try eb.toOwnedBundle("");
        },
    }
}

fn getErrorBundleFromAstCheck(
    allocator: std.mem.Allocator,
    zig_exe_path: []const u8,
    zig_ast_check_lock: *std.Thread.Mutex,
    source: [:0]const u8,
) !std.zig.ErrorBundle {
    comptime std.debug.assert(std.process.can_spawn);

    var stderr_bytes: []u8 = "";
    defer allocator.free(stderr_bytes);

    {
        zig_ast_check_lock.lock();
        defer zig_ast_check_lock.unlock();

        var process: std.process.Child = .init(&.{ zig_exe_path, "ast-check", "--color", "off" }, allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Ignore;
        process.stderr_behavior = .Pipe;

        process.spawn() catch |err| {
            log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
            return .empty;
        };
        try process.stdin.?.writeAll(source);
        process.stdin.?.close();

        process.stdin = null;

        stderr_bytes = try process.stderr.?.readToEndAlloc(allocator, 16 * 1024 * 1024);

        const term = process.wait() catch |err| {
            log.warn("Failed to await zig ast-check process, error: {}", .{err});
            return .empty;
        };

        if (term != .Exited) return .empty;
    }

    if (stderr_bytes.len == 0) return .empty;

    var last_error_message: ?std.zig.ErrorBundle.ErrorMessage = null;
    var notes: std.ArrayListUnmanaged(std.zig.ErrorBundle.MessageIndex) = .empty;
    defer notes.deinit(allocator);

    var error_bundle: std.zig.ErrorBundle.Wip = undefined;
    try error_bundle.init(allocator);
    defer error_bundle.deinit();

    const eb_file_path = try error_bundle.addString("");

    var line_iterator = std.mem.splitScalar(u8, stderr_bytes, '\n');
    while (line_iterator.next()) |line| {
        var pos_and_diag_iterator = std.mem.splitScalar(u8, line, ':');

        const src_path = pos_and_diag_iterator.next() orelse continue;
        const line_string = pos_and_diag_iterator.next() orelse continue;
        const column_string = pos_and_diag_iterator.next() orelse continue;
        const msg = pos_and_diag_iterator.rest();

        if (!std.mem.eql(u8, src_path, "<stdin>")) continue;

        // zig uses utf-8 encoding for character offsets
        const utf8_position: types.Position = .{
            .line = (std.fmt.parseInt(u32, line_string, 10) catch continue) -| 1,
            .character = (std.fmt.parseInt(u32, column_string, 10) catch continue) -| 1,
        };
        const source_index = offsets.positionToIndex(source, utf8_position, .@"utf-8");
        const source_line = offsets.lineSliceAtIndex(source, source_index);

        var loc: offsets.Loc = .{ .start = source_index, .end = source_index };

        while (loc.end < source.len and Analyser.isSymbolChar(source[loc.end])) {
            loc.end += 1;
        }

        const src_loc = try error_bundle.addSourceLocation(.{
            .src_path = eb_file_path,
            .line = utf8_position.line,
            .column = utf8_position.character,
            .span_start = @intCast(loc.start),
            .span_main = @intCast(source_index),
            .span_end = @intCast(loc.end),
            .source_line = try error_bundle.addString(source_line),
        });

        if (std.mem.startsWith(u8, msg, " note: ")) {
            try notes.append(allocator, try error_bundle.addErrorMessage(.{
                .msg = try error_bundle.addString(msg[" note: ".len..]),
                .src_loc = src_loc,
            }));
            continue;
        }

        const message = if (std.mem.startsWith(u8, msg, " error: ")) msg[" error: ".len..] else msg;

        if (last_error_message) |*em| {
            em.notes_len = @intCast(notes.items.len);
            try error_bundle.addRootErrorMessage(em.*);
            const notes_start = try error_bundle.reserveNotes(em.notes_len);
            @memcpy(error_bundle.extra.items[notes_start..][0..em.notes_len], @as([]const u32, @ptrCast(notes.items)));

            notes.clearRetainingCapacity();
            last_error_message = null;
        }

        last_error_message = .{
            .msg = try error_bundle.addString(message),
            .src_loc = src_loc,
            .notes_len = undefined, // set later
        };
    }

    if (last_error_message) |*em| {
        em.notes_len = @intCast(notes.items.len);
        try error_bundle.addRootErrorMessage(em.*);
        const notes_start = try error_bundle.reserveNotes(em.notes_len);
        @memcpy(error_bundle.extra.items[notes_start..][0..em.notes_len], @as([]const u32, @ptrCast(notes.items)));
    }

    return try error_bundle.toOwnedBundle("");
}

/// This struct is not relocatable after initilization.
pub const BuildOnSave = struct {
    allocator: std.mem.Allocator,
    child_process: std.process.Child,
    thread: std.Thread,

    const shared = @import("../build_runner/shared.zig");
    const Transport = shared.Transport;
    const ServerToClient = shared.ServerToClient;

    pub const InitOptions = struct {
        allocator: std.mem.Allocator,
        workspace_path: []const u8,
        build_on_save_args: []const []const u8,
        check_step_only: bool,
        zig_exe_path: []const u8,
        zig_lib_path: []const u8,
        build_runner_path: []const u8,

        collection: *DiagnosticsCollection,
    };

    pub fn init(self: *BuildOnSave, options: InitOptions) !void {
        self.* = undefined;

        const base_args: []const []const u8 = &.{
            options.zig_exe_path,
            "build",
            "--build-runner",
            options.build_runner_path,
            "--zig-lib-dir",
            options.zig_lib_path,
            "--watch",
        };
        var argv: std.ArrayListUnmanaged([]const u8) = try .initCapacity(
            options.allocator,
            base_args.len + options.build_on_save_args.len + @intFromBool(options.check_step_only),
        );
        defer argv.deinit(options.allocator);

        argv.appendSliceAssumeCapacity(base_args);
        if (options.check_step_only) argv.appendAssumeCapacity("--check-only");
        argv.appendSliceAssumeCapacity(options.build_on_save_args);

        var child_process: std.process.Child = .init(argv.items, options.allocator);
        child_process.stdin_behavior = .Pipe;
        child_process.stdout_behavior = .Pipe;
        child_process.stderr_behavior = .Pipe;
        child_process.cwd = options.workspace_path;

        child_process.spawn() catch |err| {
            log.err("failed to spawn zig build process: {}", .{err});
            return;
        };

        errdefer {
            _ = terminateChildProcessReportError(
                &child_process,
                options.allocator,
                "zig build runner",
                .kill,
            );
        }

        self.* = .{
            .allocator = options.allocator,
            .child_process = child_process,
            .thread = undefined, // set below
        };

        const duped_workspace_path = try options.allocator.dupe(u8, options.workspace_path);
        errdefer options.allocator.free(duped_workspace_path);

        self.thread = try std.Thread.spawn(.{ .allocator = options.allocator }, loop, .{
            self,
            options.collection,
            duped_workspace_path,
        });
    }

    pub fn deinit(self: *BuildOnSave) void {
        // this write tells the child process to exit
        self.child_process.stdin.?.writeAll("\xaa") catch |err| {
            if (err != error.BrokenPipe) {
                log.warn("failed to send message to zig build runner: {}", .{err});
            }
            _ = terminateChildProcessReportError(
                &self.child_process,
                self.allocator,
                "zig build runner",
                .kill,
            );
            return;
        };

        const success = terminateChildProcessReportError(
            &self.child_process,
            self.allocator,
            "zig build runner",
            .wait,
        );
        if (!success) return;

        self.thread.join();
        self.* = undefined;
    }

    const windows_support_version = std.SemanticVersion.parse("0.14.0-dev.625+2de0e2eca") catch unreachable;
    const kqueue_support_version = std.SemanticVersion.parse("0.14.0-dev.2046+b8795b4d0") catch unreachable;

    /// Returns true if is comptime known that build on save is supported.
    pub inline fn isSupportedComptime() bool {
        if (!std.process.can_spawn) return false;
        if (builtin.single_threaded) return false;
        return true;
    }

    pub fn isSupportedRuntime(runtime_zig_version: std.SemanticVersion, log_message: bool) bool {
        comptime std.debug.assert(isSupportedComptime());

        if (builtin.os.tag == .linux) blk: {
            // std.build.Watch requires `AT_HANDLE_FID` which is Linux 6.5+
            // https://github.com/ziglang/zig/issues/20720
            const minimum_linux_version: std.SemanticVersion = .{ .major = 6, .minor = 5, .patch = 0 };

            const utsname = std.posix.uname();
            const version = parseUnameKernelVersion(&utsname.release) catch |err| {
                if (log_message) log.warn("failed to parse kernel version '{s}': {}", .{ utsname.release, err });
                break :blk;
            };
            if (version.order(minimum_linux_version) != .lt) break :blk;
            if (log_message) log.err("Build-On-Save is not supported by Linux '{s}' (requires at least {})", .{ utsname.release, minimum_linux_version });
            return false;
        }

        // We can't rely on `std.Build.Watch.have_impl` because we need to
        // check the runtime Zig version instead of Zig version that ZLS
        // has been built with.
        const zig_version_supported = switch (builtin.os.tag) {
            .linux => true,
            .windows => runtime_zig_version.order(windows_support_version) != .lt,
            .dragonfly,
            .freebsd,
            .netbsd,
            .openbsd,
            .ios,
            .macos,
            .tvos,
            .visionos,
            .watchos,
            .haiku,
            => runtime_zig_version.order(kqueue_support_version) != .lt,
            else => false,
        };

        if (!zig_version_supported) {
            log.warn("Build-On-Save is not supported on {s} by Zig {}", .{ @tagName(builtin.os.tag), runtime_zig_version });
        }

        return zig_version_supported;
    }

    fn parseUnameKernelVersion(kernel_version: []const u8) !std.SemanticVersion {
        const extra_index = std.mem.indexOfAny(u8, kernel_version, "-+");
        const required = kernel_version[0..(extra_index orelse kernel_version.len)];
        var it = std.mem.splitScalar(u8, required, '.');
        return .{
            .major = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
            .minor = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
            .patch = try std.fmt.parseUnsigned(usize, it.next() orelse return error.InvalidVersion, 10),
        };
    }

    test parseUnameKernelVersion {
        try std.testing.expectFmt("5.17.0", "{}", .{try parseUnameKernelVersion("5.17.0")});
        try std.testing.expectFmt("6.12.9", "{}", .{try parseUnameKernelVersion("6.12.9-rc7")});
        try std.testing.expectFmt("6.6.71", "{}", .{try parseUnameKernelVersion("6.6.71-42-generic")});
        try std.testing.expectFmt("5.15.167", "{}", .{try parseUnameKernelVersion("5.15.167.4-microsoft-standard-WSL2")}); // WSL2
        try std.testing.expectFmt("4.4.0", "{}", .{try parseUnameKernelVersion("4.4.0-20241-Microsoft")}); // WSL1

        try std.testing.expectError(error.InvalidCharacter, parseUnameKernelVersion(""));
        try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5"));
        try std.testing.expectError(error.InvalidVersion, parseUnameKernelVersion("5.5"));
    }

    fn loop(
        self: *BuildOnSave,
        collection: *DiagnosticsCollection,
        workspace_path: []const u8,
    ) void {
        defer self.allocator.free(workspace_path);

        var transport: Transport = .init(.{
            .gpa = self.allocator,
            .in = self.child_process.stdout.?,
            .out = self.child_process.stdin.?,
        });
        defer transport.deinit();

        var diagnostic_tags: std.AutoArrayHashMapUnmanaged(DiagnosticsCollection.Tag, void) = .empty;
        defer diagnostic_tags.deinit(self.allocator);

        defer {
            for (diagnostic_tags.keys()) |tag| collection.clearErrorBundle(tag);
            collection.publishDiagnostics() catch {};
        }

        while (true) {
            const header = transport.receiveMessage(null) catch |err| switch (err) {
                error.EndOfStream => {
                    log.debug("zig build runner process has exited", .{});
                    return;
                },
                else => {
                    log.err("failed to receive message from zig build runner: {}", .{err});
                    return;
                },
            };

            switch (@as(ServerToClient.Tag, @enumFromInt(header.tag))) {
                .watch_error_bundle => {
                    handleWatchErrorBundle(
                        self,
                        &transport,
                        collection,
                        workspace_path,
                        &diagnostic_tags,
                    ) catch |err| {
                        log.err("failed to handle error bundle message from zig build runner: {}", .{err});
                        return;
                    };
                },
                else => |tag| {
                    log.warn("received unexpected message from zig build runner: {}", .{tag});
                },
            }
        }
    }

    fn handleWatchErrorBundle(
        self: *BuildOnSave,
        transport: *Transport,
        collection: *DiagnosticsCollection,
        workspace_path: []const u8,
        diagnostic_tags: *std.AutoArrayHashMapUnmanaged(DiagnosticsCollection.Tag, void),
    ) !void {
        const header = try transport.reader().readStructEndian(ServerToClient.ErrorBundle, .little);

        const extra = try transport.receiveSlice(self.allocator, u32, header.extra_len);
        defer self.allocator.free(extra);

        const string_bytes = try transport.receiveBytes(self.allocator, header.string_bytes_len);
        defer self.allocator.free(string_bytes);

        const error_bundle: std.zig.ErrorBundle = .{ .string_bytes = string_bytes, .extra = extra };

        var hasher: std.hash.Wyhash = .init(0);
        hasher.update(workspace_path);
        std.hash.autoHash(&hasher, header.step_id);

        const diagnostic_tag: DiagnosticsCollection.Tag = @enumFromInt(@as(u32, @truncate(hasher.final())));

        try diagnostic_tags.put(self.allocator, diagnostic_tag, {});

        try collection.pushErrorBundle(diagnostic_tag, header.cycle, workspace_path, error_bundle);
        try collection.publishDiagnostics();
    }
};

fn terminateChildProcessReportError(
    child_process: *std.process.Child,
    allocator: std.mem.Allocator,
    name: []const u8,
    kind: enum { wait, kill },
) bool {
    const stderr = if (child_process.stderr) |stderr|
        stderr.readToEndAlloc(allocator, 16 * 1024 * 1024) catch ""
    else
        "";
    defer allocator.free(stderr);

    const term = (switch (kind) {
        .wait => child_process.wait(),
        .kill => child_process.kill(),
    }) catch |err| {
        log.warn("Failed to await {s}: {}", .{ name, err });
        return false;
    };

    switch (term) {
        .Exited => |code| if (code != 0) {
            if (stderr.len != 0) {
                log.warn("{s} exited with non-zero status: {}\nstderr:\n{s}", .{ name, code, stderr });
            } else {
                log.warn("{s} exited with non-zero status: {}", .{ name, code });
            }
        },
        else => {
            if (stderr.len != 0) {
                log.warn("{s} exitied abnormally: {s}\nstderr:\n{s}", .{ name, @tagName(term), stderr });
            } else {
                log.warn("{s} exitied abnormally: {s}", .{ name, @tagName(term) });
            }
        },
    }

    return true;
}
