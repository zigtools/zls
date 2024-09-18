//! Implementation of [`textDocument/publishDiagnostics`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_publishDiagnostics)

const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_diag);

const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const types = @import("lsp").types;
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");
const URI = @import("../uri.zig");
const code_actions = @import("code_actions.zig");
const tracy = @import("tracy");

const Zir = std.zig.Zir;

pub fn generateDiagnostics(server: *Server, arena: std.mem.Allocator, handle: *DocumentStore.Handle) error{OutOfMemory}!types.PublishDiagnosticsParams {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(server.client_capabilities.supports_publish_diagnostics);

    const tree = handle.tree;

    var diagnostics: std.ArrayListUnmanaged(types.Diagnostic) = .{};

    try diagnostics.ensureUnusedCapacity(arena, tree.errors.len);
    for (tree.errors) |err| {
        var buffer: std.ArrayListUnmanaged(u8) = .{};
        try tree.renderError(err, buffer.writer(arena));

        diagnostics.appendAssumeCapacity(.{
            .range = offsets.tokenToRange(tree, err.token, server.offset_encoding),
            .severity = .Error,
            .code = .{ .string = @tagName(err.tag) },
            .source = "zls",
            .message = try buffer.toOwnedSlice(arena),
        });
    }

    if (tree.errors.len == 0 and tree.mode == .zig) {
        var error_bundle = try getAstCheckDiagnostics(server, handle);
        defer error_bundle.deinit(server.allocator);
        var diagnostics_set: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.Diagnostic)) = .{};
        try errorBundleToDiagnostics(error_bundle, arena, &diagnostics_set, "ast-check", server.offset_encoding);
        switch (diagnostics_set.count()) {
            0 => {},
            1 => try diagnostics.appendSlice(arena, diagnostics_set.values()[0].items),
            else => unreachable, // ast-check diagnostics only affect a single file
        }
    }

    if (server.config.enable_autofix and tree.mode == .zig) {
        try code_actions.collectAutoDiscardDiagnostics(tree, arena, &diagnostics, server.offset_encoding);
    }

    if (server.config.warn_style and tree.mode == .zig) {
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
            for (ast.rootDecls(tree)) |decl_idx| {
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
                                    .range = offsets.tokenToRange(tree, name_token, server.offset_encoding),
                                    .severity = .Hint,
                                    .code = .{ .string = "bad_style" },
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !Analyser.isPascalCase(func_name)) {
                                try diagnostics.append(arena, .{
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

    for (handle.cimports.items(.hash), handle.cimports.items(.node)) |hash, node| {
        const result = blk: {
            server.document_store.lock.lock();
            defer server.document_store.lock.unlock();
            break :blk server.document_store.cimports.get(hash) orelse continue;
        };
        const error_bundle: std.zig.ErrorBundle = switch (result) {
            .success => continue,
            .failure => |bundle| bundle,
        };

        if (error_bundle.errorMessageCount() == 0) continue; // `getMessages` can't be called on an empty ErrorBundle
        try diagnostics.ensureUnusedCapacity(arena, error_bundle.errorMessageCount());
        for (error_bundle.getMessages()) |err_msg_index| {
            const err_msg = error_bundle.getErrorMessage(err_msg_index);

            diagnostics.appendAssumeCapacity(.{
                .range = offsets.nodeToRange(tree, node, server.offset_encoding),
                .severity = .Error,
                .code = .{ .string = "cImport" },
                .source = "zls",
                .message = try arena.dupe(u8, error_bundle.nullTerminatedString(err_msg.msg)),
            });
        }
    }

    if (server.config.highlight_global_var_declarations and tree.mode == .zig) {
        const main_tokens = tree.nodes.items(.main_token);
        const tags = tree.tokens.items(.tag);
        for (ast.rootDecls(tree)) |decl| {
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

    return .{
        .uri = handle.uri,
        .diagnostics = diagnostics.items,
    };
}

pub fn generateBuildOnSaveDiagnostics(
    server: *Server,
    workspace_uri: types.URI,
    arena: std.mem.Allocator,
    diagnostics: *std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.Diagnostic)),
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    comptime std.debug.assert(std.process.can_spawn);

    const zig_exe_path = server.config.zig_exe_path orelse return;
    const zig_lib_path = server.config.zig_lib_path orelse return;

    const workspace_path = URI.parse(server.allocator, workspace_uri) catch |err| {
        log.err("failed to parse invalid uri '{s}': {}", .{ workspace_uri, err });
        return;
    };
    defer server.allocator.free(workspace_path);

    std.debug.assert(std.fs.path.isAbsolute(workspace_path));

    const build_zig_path = try std.fs.path.join(server.allocator, &.{ workspace_path, "build.zig" });
    defer server.allocator.free(build_zig_path);

    std.fs.accessAbsolute(build_zig_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| {
            log.err("failed to load build.zig at '{s}': {}", .{ build_zig_path, e });
            return e;
        },
    };

    const build_zig_uri = try URI.fromPath(server.allocator, build_zig_path);
    defer server.allocator.free(build_zig_uri);

    const base_args = &[_][]const u8{
        zig_exe_path,
        "build",
        "--zig-lib-dir",
        zig_lib_path,
        "-fno-reference-trace",
        "--summary",
        "none",
    };

    var argv = try std.ArrayListUnmanaged([]const u8).initCapacity(arena, base_args.len + server.config.build_on_save_args.len);
    defer argv.deinit(arena);
    argv.appendSliceAssumeCapacity(base_args);
    argv.appendSliceAssumeCapacity(server.config.build_on_save_args);

    const has_explicit_steps = for (server.config.build_on_save_args) |extra_arg| {
        if (!std.mem.startsWith(u8, extra_arg, "-")) break true;
    } else false;

    var has_check_step: bool = false;

    blk: {
        server.document_store.lock.lockShared();
        defer server.document_store.lock.unlockShared();
        const build_file = server.document_store.build_files.get(build_zig_uri) orelse break :blk;

        no_build_config: {
            const build_associated_config = build_file.build_associated_config orelse break :no_build_config;
            const build_options = build_associated_config.value.build_options orelse break :no_build_config;

            try argv.ensureUnusedCapacity(arena, build_options.len);
            for (build_options) |build_option| {
                argv.appendAssumeCapacity(try build_option.formatParam(arena));
            }
        }

        no_check: {
            if (has_explicit_steps) break :no_check;
            const config = build_file.tryLockConfig() orelse break :no_check;
            defer build_file.unlockConfig();
            for (config.top_level_steps) |tls| {
                if (std.mem.eql(u8, tls, "check")) {
                    has_check_step = true;
                    break;
                }
            }
        }
    }

    if (!(server.config.enable_build_on_save orelse has_check_step)) {
        return;
    }

    if (has_check_step) {
        std.debug.assert(!has_explicit_steps);
        try argv.append(arena, "check");
    }

    const extra_args_joined = try std.mem.join(server.allocator, " ", argv.items[base_args.len..]);
    defer server.allocator.free(extra_args_joined);

    log.info("Running build-on-save: {s} ({s})", .{ build_zig_uri, extra_args_joined });

    const result = std.process.Child.run(.{
        .allocator = server.allocator,
        .argv = argv.items,
        .cwd = workspace_path,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| {
        const joined = std.mem.join(server.allocator, " ", argv.items) catch return;
        defer server.allocator.free(joined);
        log.err("failed zig build command:\n{s}\nerror:{}\n", .{ joined, err });
        return err;
    };
    defer server.allocator.free(result.stdout);
    defer server.allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code == 0) return,
        else => {
            const joined = std.mem.join(server.allocator, " ", argv.items) catch return;
            defer server.allocator.free(joined);
            log.err("failed zig build command:\n{s}\nstderr:{s}\n\n", .{ joined, result.stderr });
        },
    }

    var last_diagnostic_uri: ?types.URI = null;
    var last_diagnostic: ?types.Diagnostic = null;
    // we don't store DiagnosticRelatedInformation in last_diagnostic instead
    // its stored in last_related_diagnostics because we need an ArrayList
    var last_related_diagnostics: std.ArrayListUnmanaged(types.DiagnosticRelatedInformation) = .{};

    // I believe that with color off it's one diag per line; is this correct?
    var line_iterator = std.mem.splitScalar(u8, result.stderr, '\n');

    while (line_iterator.next()) |line| {
        var pos_and_diag_iterator = std.mem.splitScalar(u8, line, ':');

        const src_path = pos_and_diag_iterator.next() orelse continue;
        const absolute_src_path = if (std.fs.path.isAbsolute(src_path)) src_path else blk: {
            const absolute_src_path = (if (src_path.len == 1)
                // it's a drive letter
                std.fs.path.join(arena, &.{ line[0..2], pos_and_diag_iterator.next() orelse continue })
            else
                std.fs.path.join(arena, &.{ workspace_path, src_path })) catch continue;
            if (!std.fs.path.isAbsolute(absolute_src_path)) continue;
            break :blk absolute_src_path;
        };

        const src_line = pos_and_diag_iterator.next() orelse continue;
        const src_character = pos_and_diag_iterator.next() orelse continue;

        // TODO zig uses utf-8 encoding for character offsets
        // convert them to the desired offset encoding would require loading every file that contains errors
        // is there some efficient way to do this?
        const utf8_position: types.Position = .{
            .line = (std.fmt.parseInt(u32, src_line, 10) catch continue) -| 1,
            .character = std.fmt.parseInt(u32, src_character, 10) catch continue,
        };
        const range: types.Range = .{ .start = utf8_position, .end = utf8_position };

        const rest = pos_and_diag_iterator.rest();
        if (rest.len <= 1) continue;
        const msg = rest[1..];

        if (std.mem.startsWith(u8, msg, "note: ")) {
            try last_related_diagnostics.append(arena, .{
                .location = .{
                    .uri = try URI.fromPath(arena, absolute_src_path),
                    .range = range,
                },
                .message = try arena.dupe(u8, msg["note: ".len..]),
            });
            continue;
        }

        if (last_diagnostic) |*diagnostic| {
            diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(arena);
            const entry = try diagnostics.getOrPutValue(arena, last_diagnostic_uri.?, .{});
            try entry.value_ptr.append(arena, diagnostic.*);
            last_diagnostic_uri = null;
            last_diagnostic = null;
        }

        if (std.mem.startsWith(u8, msg, "error: ")) {
            last_diagnostic_uri = try URI.fromPath(arena, absolute_src_path);
            last_diagnostic = .{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "zig_build" },
                .source = "zls",
                .message = try arena.dupe(u8, msg["error: ".len..]),
            };
        } else {
            last_diagnostic_uri = try URI.fromPath(arena, absolute_src_path);
            last_diagnostic = .{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "zig_build" },
                .source = "zls",
                .message = try arena.dupe(u8, msg),
            };
        }
    }

    if (last_diagnostic) |*diagnostic| {
        diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(arena);
        const entry = try diagnostics.getOrPutValue(arena, last_diagnostic_uri.?, .{});
        try entry.value_ptr.append(arena, diagnostic.*);
        last_diagnostic_uri = null;
        last_diagnostic = null;
    }
}

/// caller owns the returned ErrorBundle
pub fn getAstCheckDiagnostics(server: *Server, handle: *DocumentStore.Handle) error{OutOfMemory}!std.zig.ErrorBundle {
    std.debug.assert(handle.tree.errors.len == 0);
    std.debug.assert(handle.tree.mode == .zig);

    var eb: std.zig.ErrorBundle.Wip = undefined;
    try eb.init(server.allocator);
    defer eb.deinit();

    if (server.config.prefer_ast_check_as_child_process and
        std.process.can_spawn and
        server.config.zig_exe_path != null)
    {
        getErrorBundleFromAstCheck(
            server.allocator,
            server.config.zig_exe_path.?,
            &server.zig_ast_check_lock,
            handle.tree.source,
            &eb,
        ) catch |err| {
            log.err("failed to run ast-check: {}", .{err});
        };
    } else {
        const zir = try handle.getZir();
        std.debug.assert(handle.getZirStatus() == .done);

        if (zir.hasCompileErrors()) {
            try eb.addZirErrorMessages(zir, handle.tree, handle.tree.source, "");
        }
    }

    return try eb.toOwnedBundle("");
}

fn getErrorBundleFromAstCheck(
    allocator: std.mem.Allocator,
    zig_exe_path: []const u8,
    zig_ast_check_lock: *std.Thread.Mutex,
    source: [:0]const u8,
    error_bundle: *std.zig.ErrorBundle.Wip,
) !void {
    comptime std.debug.assert(std.process.can_spawn);
    const stderr_bytes = blk: {
        zig_ast_check_lock.lock();
        defer zig_ast_check_lock.unlock();

        var process = std.process.Child.init(&.{ zig_exe_path, "ast-check", "--color", "off" }, allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Ignore;
        process.stderr_behavior = .Pipe;

        process.spawn() catch |err| {
            log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
            return;
        };
        try process.stdin.?.writeAll(source);
        process.stdin.?.close();

        process.stdin = null;

        const stderr_bytes = try process.stderr.?.readToEndAlloc(allocator, std.math.maxInt(u32));
        errdefer allocator.free(stderr_bytes);

        const term = process.wait() catch |err| {
            log.warn("Failed to await zig ast-check process, error: {}", .{err});
            allocator.free(stderr_bytes);
            return;
        };

        if (term != .Exited) {
            allocator.free(stderr_bytes);
            return;
        }
        break :blk stderr_bytes;
    };
    defer allocator.free(stderr_bytes);

    var last_error_message: ?std.zig.ErrorBundle.ErrorMessage = null;
    var notes: std.ArrayListUnmanaged(std.zig.ErrorBundle.MessageIndex) = .{};
    defer notes.deinit(allocator);

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
            .src_path = 0,
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
}

pub fn errorBundleToDiagnostics(
    error_bundle: std.zig.ErrorBundle,
    arena: std.mem.Allocator,
    diagnostics: *std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.Diagnostic)),
    code: []const u8,
    /// The diagnostic's code, which usually appear in the user interface.
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    if (error_bundle.errorMessageCount() == 0) return; // `getMessages` can't be called on an empty ErrorBundle
    for (error_bundle.getMessages()) |msg_index| {
        const err = error_bundle.getErrorMessage(msg_index);
        if (err.src_loc == .none) continue;

        const src_loc = error_bundle.getSourceLocation(err.src_loc);
        const src_path = error_bundle.nullTerminatedString(src_loc.src_path);
        const src_range = errorBundleSourceLocationToRange(error_bundle, src_loc, offset_encoding);

        const eb_notes = error_bundle.getNotes(msg_index);
        const lsp_notes = try arena.alloc(types.DiagnosticRelatedInformation, eb_notes.len);
        for (lsp_notes, eb_notes) |*lsp_note, eb_note_index| {
            const eb_note = error_bundle.getErrorMessage(eb_note_index);
            if (eb_note.src_loc == .none) continue;

            const note_src_loc = error_bundle.getSourceLocation(eb_note.src_loc);
            const note_src_path = error_bundle.nullTerminatedString(src_loc.src_path);
            const note_src_range = errorBundleSourceLocationToRange(error_bundle, note_src_loc, offset_encoding);

            lsp_note.* = .{
                .location = .{
                    .uri = try URI.fromPath(arena, note_src_path),
                    .range = note_src_range,
                },
                .message = try arena.dupe(u8, error_bundle.nullTerminatedString(eb_note.msg)),
            };
        }

        const uri = try URI.fromPath(arena, src_path);

        const gop = try diagnostics.getOrPutValue(arena, uri, .{});
        try gop.value_ptr.append(arena, .{
            .range = src_range,
            .severity = .Error,
            .code = .{ .string = code },
            .source = "zls",
            .message = try arena.dupe(u8, error_bundle.nullTerminatedString(err.msg)),
            .relatedInformation = lsp_notes,
        });
    }
}

fn errorBundleSourceLocationToRange(
    error_bundle: std.zig.ErrorBundle,
    src_loc: std.zig.ErrorBundle.SourceLocation,
    offset_encoding: offsets.Encoding,
) types.Range {
    const source_line = error_bundle.nullTerminatedString(src_loc.source_line);

    const source_line_range_utf8: types.Range = .{
        .start = .{ .line = 0, .character = src_loc.column - (src_loc.span_main - src_loc.span_start) },
        .end = .{ .line = 0, .character = src_loc.column + (src_loc.span_end - src_loc.span_main) },
    };
    const source_line_range = offsets.convertRangeEncoding(source_line, source_line_range_utf8, .@"utf-8", offset_encoding);

    return .{
        .start = .{ .line = src_loc.line, .character = source_line_range.start.character },
        .end = .{ .line = src_loc.line, .character = source_line_range.end.character },
    };
}
