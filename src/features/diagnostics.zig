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
const Uri = @import("../Uri.zig");
const code_actions = @import("code_actions.zig");
const tracy = @import("tracy");
const DiagnosticsCollection = @import("../DiagnosticsCollection.zig");

const Zir = std.zig.Zir;

pub fn generateDiagnostics(
    server: *Server,
    handle: *DocumentStore.Handle,
) Analyser.Error!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const config = &server.config_manager.config;

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

        try collectParseDiagnostics(&handle.tree, &wip);

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

        var diagnostics: std.ArrayList(types.Diagnostic) = .empty;

        if (handle.tree.mode == .zig) {
            var analyser = server.initAnalyser(arena, handle);
            defer analyser.deinit();
            try code_actions.collectAutoDiscardDiagnostics(&analyser, handle, arena, &diagnostics, server.offset_encoding);
        }

        if (config.warn_style and handle.tree.mode == .zig) {
            try collectWarnStyleDiagnostics(&handle.tree, arena, &diagnostics, server.offset_encoding);
        }

        if (config.highlight_global_var_declarations and handle.tree.mode == .zig) {
            try collectGlobalVarDiagnostics(&handle.tree, arena, &diagnostics, server.offset_encoding);
        }

        try server.diagnostics_collection.pushSingleDocumentDiagnostics(
            .parse,
            handle.uri,
            .{ .lsp = .{ .arena = arena_allocator.state, .diagnostics = diagnostics.items } },
        );
    }

    std.debug.assert(server.client_capabilities.supports_publish_diagnostics);
    server.diagnostics_collection.publishDiagnostics() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => log.err("failed to publish diagnostics: {}", .{err}),
    };
}

fn collectParseDiagnostics(tree: *const Ast, eb: *std.zig.ErrorBundle.Wip) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (tree.errors.len == 0) return;

    const allocator = eb.gpa;

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    var notes: std.ArrayList(std.zig.ErrorBundle.MessageIndex) = .empty;
    defer notes.deinit(allocator);

    const current_error = tree.errors[0];
    for (tree.errors[1..]) |err| {
        if (!err.is_note) break;

        aw.clearRetainingCapacity();
        tree.renderError(err, &aw.writer) catch return error.OutOfMemory;
        try notes.append(allocator, try eb.addErrorMessage(.{
            .msg = try eb.addString(aw.written()),
            .src_loc = try errorBundleSourceLocationFromToken(tree, eb, err.token),
        }));
    }

    aw.clearRetainingCapacity();
    tree.renderError(current_error, &aw.writer) catch return error.OutOfMemory;
    try eb.addRootErrorMessage(.{
        .msg = try eb.addString(aw.written()),
        .src_loc = try errorBundleSourceLocationFromToken(tree, eb, current_error.token),
        .notes_len = @intCast(notes.items.len),
    });

    const notes_start = try eb.reserveNotes(@intCast(notes.items.len));
    @memcpy(eb.extra.items[notes_start..][0..notes.items.len], @as([]const u32, @ptrCast(notes.items)));
}

fn errorBundleSourceLocationFromToken(
    tree: *const Ast,
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
    tree: *const Ast,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    for (0..tree.nodes.len) |i| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(i));
        if (ast.isBuiltinCall(tree, node)) {
            const builtin_token = tree.nodeMainToken(node);
            const call_name = tree.tokenSlice(builtin_token);

            if (!std.mem.eql(u8, call_name, "@import")) continue;

            var buffer: [2]Ast.Node.Index = undefined;
            const params = tree.builtinCallParams(&buffer, node).?;

            if (params.len != 1) continue;

            const import_str_token = tree.nodeMainToken(params[0]);
            const import_str = tree.tokenSlice(import_str_token);

            if (std.mem.startsWith(u8, import_str, "\"./")) {
                try diagnostics.append(arena, .{
                    .range = offsets.tokenToRange(tree, import_str_token, offset_encoding),
                    .severity = .Hint,
                    .code = .{ .string = "dot_slash_import" },
                    .source = "zls",
                    .message = .{ .string = "A ./ is not needed in imports" },
                });
            }
        }
    }

    // TODO: style warnings for types, values and declarations below root scope
    if (tree.errors.len == 0) {
        for (tree.rootDecls()) |decl_idx| {
            const decl = tree.nodeTag(decl_idx);
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
                        if (!is_type_function and !isCamelCase(func_name)) {
                            try diagnostics.append(arena, .{
                                .range = offsets.tokenToRange(tree, name_token, offset_encoding),
                                .severity = .Hint,
                                .code = .{ .string = "bad_style" },
                                .source = "zls",
                                .message = .{ .string = "Functions should be camelCase" },
                            });
                        } else if (is_type_function and !isPascalCase(func_name)) {
                            try diagnostics.append(arena, .{
                                .range = offsets.tokenToRange(tree, name_token, offset_encoding),
                                .severity = .Hint,
                                .code = .{ .string = "bad_style" },
                                .source = "zls",
                                .message = .{ .string = "Type functions should be PascalCase" },
                            });
                        }
                    }
                },
                else => {},
            }
        }
    }
}

fn isCamelCase(name: []const u8) bool {
    return !std.ascii.isUpper(name[0]) and !isSnakeCase(name);
}

fn isPascalCase(name: []const u8) bool {
    return std.ascii.isUpper(name[0]) and !isSnakeCase(name);
}

fn isSnakeCase(name: []const u8) bool {
    return std.mem.find(u8, name, "_") != null;
}

fn collectGlobalVarDiagnostics(
    tree: *const Ast,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    for (tree.rootDecls()) |decl| {
        const decl_tag = tree.nodeTag(decl);
        const decl_main_token = tree.nodeMainToken(decl);

        switch (decl_tag) {
            .simple_var_decl,
            .aligned_var_decl,
            .local_var_decl,
            .global_var_decl,
            => {
                if (tree.tokenTag(tree.nodeMainToken(decl)) != .keyword_var) continue; // skip anything immutable
                // uncomment this to get a list :)
                //log.debug("possible global variable \"{s}\"", .{tree.tokenSlice(decl_main_token + 1)});
                try diagnostics.append(arena, .{
                    .range = offsets.tokenToRange(tree, decl_main_token, offset_encoding),
                    .severity = .Hint,
                    .code = .{ .string = "highlight_global_var_declarations" },
                    .source = "zls",
                    .message = .{ .string = "Global var declaration" },
                });
            },
            else => {},
        }
    }
}

/// caller owns the returned ErrorBundle
pub fn getAstCheckDiagnostics(server: *Server, handle: *DocumentStore.Handle) error{ Canceled, OutOfMemory }!std.zig.ErrorBundle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(handle.tree.errors.len == 0);
    const config = &server.config_manager.config;

    if (std.process.can_spawn and
        config.prefer_ast_check_as_child_process and
        handle.tree.mode == .zig and // TODO pass `--zon` if available
        config.zig_exe_path != null)
    {
        return getErrorBundleFromAstCheck(
            server.io,
            server.allocator,
            config.zig_exe_path.?,
            handle.tree.source,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                log.err("failed to run ast-check: {}", .{err});
                return .empty;
            },
        };
    } else switch (handle.tree.mode) {
        .zig => {
            var zir = try std.zig.AstGen.generate(server.allocator, handle.tree);
            defer zir.deinit(server.allocator);

            if (!zir.hasCompileErrors()) return .empty;

            var eb: std.zig.ErrorBundle.Wip = undefined;
            try eb.init(server.allocator);
            defer eb.deinit();
            try eb.addZirErrorMessages(zir, handle.tree, handle.tree.source, "");
            return try eb.toOwnedBundle("");
        },
        .zon => {
            const zoir = try std.zig.ZonGen.generate(server.allocator, handle.tree, .{});
            defer zoir.deinit(server.allocator);

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
    io: std.Io,
    allocator: std.mem.Allocator,
    zig_exe_path: []const u8,
    source: [:0]const u8,
) !std.zig.ErrorBundle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    comptime std.debug.assert(std.process.can_spawn);

    var process = std.process.spawn(io, .{
        .argv = &.{ zig_exe_path, "ast-check", "--color", "off" },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
            return .empty;
        },
    };
    try process.stdin.?.writeStreamingAll(io, source);
    process.stdin.?.close(io);

    process.stdin = null;

    var buffer: [4096]u8 = undefined;
    var file_reader = process.stderr.?.readerStreaming(io, &buffer);
    const stderr = file_reader.interface.allocRemaining(allocator, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.OutOfMemory, error.StreamTooLong => |e| return e,
    };
    defer allocator.free(stderr);

    const term = try process.wait(io);
    switch (term) {
        .exited => return try getErrorBundleFromStderr(allocator, stderr, true, .{ .single_source_file = source }),
        .signal => |sig| std.log.err("zig ast-check failed with signal {t} and stderr:\n{s}", .{ sig, stderr }),
        .stopped => |sig| std.log.err("zig ast-check stopped with signal {d} and stderr:\n{s}", .{ sig, stderr }),
        .unknown => |code| std.log.err("zig ast-check failed for unknown reason with code {d} and stderr:\n{s}", .{ code, stderr }),
    }
    return .empty;
}

pub fn getErrorBundleFromStderr(
    allocator: std.mem.Allocator,
    stderr_bytes: []const u8,
    ignore_src_path: bool,
    path_resolution: union(enum) {
        single_source_file: [:0]const u8,
        dynamic: struct {
            document_store: *DocumentStore,
            /// file paths in stderr may be relative so we need to figure out the base path
            base_path: []const u8,
        },
    },
) !std.zig.ErrorBundle {
    if (stderr_bytes.len == 0) return .empty;

    var last_error_message: ?std.zig.ErrorBundle.ErrorMessage = null;
    var notes: std.ArrayList(std.zig.ErrorBundle.MessageIndex) = .empty;
    defer notes.deinit(allocator);

    var error_bundle: std.zig.ErrorBundle.Wip = undefined;
    try error_bundle.init(allocator);
    defer error_bundle.deinit();

    const eb_empty_string = try error_bundle.addString("");

    var line_iterator = std.mem.splitScalar(u8, stderr_bytes, '\n');
    while (line_iterator.next()) |line| {
        // `{optional indentation}{src_path}:{line}:{column}: {msg}`
        var pos_and_diag_iterator = std.mem.splitScalar(u8, std.mem.trimStart(u8, line, " "), ':');
        const src_path = pos_and_diag_iterator.next() orelse continue;
        const line_string = pos_and_diag_iterator.next() orelse continue;
        const column_string = pos_and_diag_iterator.next() orelse continue;
        const msg = pos_and_diag_iterator.rest();

        const eb_src_path = if (ignore_src_path) eb_empty_string else try error_bundle.addString(src_path);

        // zig uses utf-8 encoding for character offsets
        const utf8_position: types.Position = .{
            .line = (std.fmt.parseInt(u32, line_string, 10) catch continue) -| 1,
            .character = (std.fmt.parseInt(u32, column_string, 10) catch continue) -| 1,
        };

        const maybe_source: ?[:0]const u8 = switch (path_resolution) {
            .single_source_file => |source| source,
            .dynamic => |dynamic| source: {
                const file_path = try std.Io.Dir.path.resolve(allocator, &.{ dynamic.base_path, src_path });
                defer allocator.free(file_path);
                const file_uri: Uri = try .fromPath(allocator, file_path);
                defer file_uri.deinit(allocator);
                const handle = try dynamic.document_store.getOrLoadHandle(file_uri) orelse break :source null;
                break :source handle.tree.source;
            },
        };

        const src_loc = if (maybe_source) |source| src_loc: {
            const source_index = offsets.positionToIndex(source, utf8_position, .@"utf-8");
            const source_loc = offsets.lineLocAtIndex(source, source_index);

            const loc = offsets.tokenIndexToLoc(source, source_index);

            break :src_loc try error_bundle.addSourceLocation(.{
                .src_path = eb_src_path,
                .line = utf8_position.line,
                .column = utf8_position.character,
                // span_start <= span_main <= span_end <= source_loc.end
                .span_start = @intCast(@min(source_index, loc.start)),
                .span_main = @intCast(source_index),
                .span_end = @intCast(@min(@max(source_index, loc.end), source_loc.end)),
                .source_line = try error_bundle.addString(offsets.locToSlice(source, source_loc)),
            });
        } else src_loc: {
            break :src_loc try error_bundle.addSourceLocation(.{
                .src_path = eb_src_path,
                .line = utf8_position.line,
                .column = utf8_position.character,
                .span_start = 0,
                .span_main = 0,
                .span_end = 0,
                .source_line = 0,
            });
        };

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
