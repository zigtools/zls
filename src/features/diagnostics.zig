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

    var diagnostics = std.ArrayListUnmanaged(types.Diagnostic){};

    try diagnostics.ensureUnusedCapacity(arena, tree.errors.len);
    for (tree.errors) |err| {
        var buffer = std.ArrayListUnmanaged(u8){};
        try tree.renderError(err, buffer.writer(arena));

        diagnostics.appendAssumeCapacity(.{
            .range = offsets.tokenToRange(tree, err.token, server.offset_encoding),
            .severity = .Error,
            .code = .{ .string = @tagName(err.tag) },
            .source = "zls",
            .message = try buffer.toOwnedSlice(arena),
        });
    }

    if (tree.errors.len == 0) {
        try getAstCheckDiagnostics(server, arena, handle, &diagnostics);
    }

    if (server.config.enable_autofix) {
        try code_actions.collectAutoDiscardDiagnostics(tree, arena, &diagnostics, server.offset_encoding);
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

            // Organize imports
            const imports = try code_actions.getImportsDecls(tree, arena);
            const rootDecls = tree.rootDecls();
            std.log.debug("Imports: {any}", .{imports.items});
            std.log.debug("RootDecls: {any}", .{rootDecls});
            // If there are imports mixed in with other declarations, report them
            var first_bad_import: usize = 0;
            for (rootDecls) |decl_idx| {
                if (first_bad_import >= imports.items.len) break;
                if (decl_idx != imports.items[first_bad_import].var_decl) break;
                first_bad_import += 1;
            }
            if (first_bad_import < imports.items.len) {
                for (imports.items[first_bad_import..]) |import_decl| {
                    try diagnostics.append(arena, .{
                        .range = offsets.nodeToRange(tree, import_decl.var_decl, server.offset_encoding),
                        .severity = .Hint,
                        .code = .{ .string = "unorganized_import" },
                        .source = "zls",
                        .message = "unorganized @import statement",
                    });
                }
            }
            // Now check the order of the imports at the correct position by sorting the indexes
            const sort_checked = imports.items[0..first_bad_import];
            var decl_indexes = try arena.alloc(usize, sort_checked.len);
            for (decl_indexes[0..decl_indexes.len], 0..) |*decl_index, i| {
                decl_index.* = i;
            }
            std.sort.block(usize, decl_indexes, .{ sort_checked, tree }, sortIdxLessThen);
            for (decl_indexes, 0..) |decl_index, i| {
                if (decl_index == i) continue;
                try diagnostics.append(arena, .{
                    .range = offsets.nodeToRange(tree, sort_checked[i].var_decl, server.offset_encoding),
                    .severity = .Hint,
                    .code = .{ .string = "unorganized_import" },
                    .source = "zls",
                    .message = "unorganized @import statement",
                });
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

fn sortIdxLessThen(ctx: struct { []code_actions.ImportDecl, Ast }, lhs: usize, rhs: usize) bool {
    const imports = ctx[0];
    const lhs_decl = imports[lhs];
    const rhs_decl = imports[rhs];
    return code_actions.ImportDecl.lessThan(ctx[1], lhs_decl, rhs_decl);
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
        const utf8_position = types.Position{
            .line = (std.fmt.parseInt(u32, src_line, 10) catch continue) -| 1,
            .character = std.fmt.parseInt(u32, src_character, 10) catch continue,
        };
        const range = types.Range{ .start = utf8_position, .end = utf8_position };

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
            last_diagnostic = types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "zig_build" },
                .source = "zls",
                .message = try arena.dupe(u8, msg["error: ".len..]),
            };
        } else {
            last_diagnostic_uri = try URI.fromPath(arena, absolute_src_path);
            last_diagnostic = types.Diagnostic{
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

pub fn getAstCheckDiagnostics(
    server: *Server,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
) error{OutOfMemory}!void {
    std.debug.assert(handle.tree.errors.len == 0);

    if (server.config.prefer_ast_check_as_child_process and
        std.process.can_spawn and
        server.config.zig_exe_path != null)
    {
        getDiagnosticsFromAstCheck(server, arena, handle, diagnostics) catch |err| {
            log.err("failed to run ast-check: {}", .{err});
        };
    } else {
        try getDiagnosticsFromZir(server, arena, handle, diagnostics);
    }
}

fn getDiagnosticsFromAstCheck(
    server: *Server,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
) !void {
    comptime std.debug.assert(std.process.can_spawn);
    std.debug.assert(server.config.zig_exe_path != null);

    const zig_exe_path = server.config.zig_exe_path.?;

    const stderr_bytes = blk: {
        server.zig_ast_check_lock.lock();
        defer server.zig_ast_check_lock.unlock();

        var process = std.process.Child.init(&[_][]const u8{ zig_exe_path, "ast-check", "--color", "off" }, server.allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Ignore;
        process.stderr_behavior = .Pipe;

        process.spawn() catch |err| {
            log.warn("Failed to spawn zig ast-check process, error: {}", .{err});
            return;
        };
        try process.stdin.?.writeAll(handle.tree.source);
        process.stdin.?.close();

        process.stdin = null;

        const stderr_bytes = try process.stderr.?.readToEndAlloc(server.allocator, std.math.maxInt(usize));
        errdefer server.allocator.free(stderr_bytes);

        const term = process.wait() catch |err| {
            log.warn("Failed to await zig ast-check process, error: {}", .{err});
            server.allocator.free(stderr_bytes);
            return;
        };

        if (term != .Exited) {
            server.allocator.free(stderr_bytes);
            return;
        }
        break :blk stderr_bytes;
    };
    defer server.allocator.free(stderr_bytes);

    var last_diagnostic: ?types.Diagnostic = null;
    // we don't store DiagnosticRelatedInformation in last_diagnostic instead
    // its stored in last_related_diagnostics because we need an ArrayList
    var last_related_diagnostics: std.ArrayListUnmanaged(types.DiagnosticRelatedInformation) = .{};

    // I believe that with color off it's one diag per line; is this correct?
    var line_iterator = std.mem.splitScalar(u8, stderr_bytes, '\n');

    while (line_iterator.next()) |line| {
        var pos_and_diag_iterator = std.mem.splitScalar(u8, line, ':');

        const first = pos_and_diag_iterator.next() orelse continue;
        if (!std.mem.eql(u8, first, "<stdin>")) continue;

        const utf8_position = types.Position{
            .line = (std.fmt.parseInt(u32, pos_and_diag_iterator.next() orelse continue, 10) catch continue) -| 1,
            .character = (std.fmt.parseInt(u32, pos_and_diag_iterator.next() orelse continue, 10) catch continue) -| 1,
        };

        // zig uses utf-8 encoding for character offsets
        const position = offsets.convertPositionEncoding(handle.tree.source, utf8_position, .@"utf-8", server.offset_encoding);
        const range = offsets.tokenPositionToRange(handle.tree.source, position, server.offset_encoding);

        const rest = pos_and_diag_iterator.rest();
        if (rest.len <= 1) continue;
        const msg = rest[1..];

        if (std.mem.startsWith(u8, msg, "note: ")) {
            try last_related_diagnostics.append(arena, .{
                .location = .{
                    .uri = handle.uri,
                    .range = range,
                },
                .message = try arena.dupe(u8, msg["note: ".len..]),
            });
            continue;
        }

        if (last_diagnostic) |*diagnostic| {
            diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(arena);
            try diagnostics.append(arena, diagnostic.*);
            last_diagnostic = null;
        }

        if (std.mem.startsWith(u8, msg, "error: ")) {
            last_diagnostic = types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "ast_check" },
                .source = "zls",
                .message = try arena.dupe(u8, msg["error: ".len..]),
            };
        } else {
            last_diagnostic = types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "ast_check" },
                .source = "zls",
                .message = try arena.dupe(u8, msg),
            };
        }
    }

    if (last_diagnostic) |*diagnostic| {
        diagnostic.relatedInformation = try last_related_diagnostics.toOwnedSlice(arena);
        try diagnostics.append(arena, diagnostic.*);
        last_diagnostic = null;
    }
}

fn getDiagnosticsFromZir(
    server: *const Server,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
) error{OutOfMemory}!void {
    const tree = handle.tree;
    std.debug.assert(tree.errors.len == 0);
    const zir = try handle.getZir();
    std.debug.assert(handle.getZirStatus() == .done);

    const payload_index = zir.extra[@intFromEnum(Zir.ExtraIndex.compile_errors)];
    if (payload_index == 0) return;

    const header = zir.extraData(Zir.Inst.CompileErrors, payload_index);
    const items_len = header.data.items_len;

    try diagnostics.ensureUnusedCapacity(arena, items_len);

    var extra_index = header.end;
    for (0..items_len) |_| {
        const item = zir.extraData(Zir.Inst.CompileErrors.Item, extra_index);
        extra_index = item.end;
        const err_loc = blk: {
            if (item.data.node != 0) {
                break :blk offsets.nodeToLoc(tree, item.data.node);
            }
            const loc = offsets.tokenToLoc(tree, item.data.token);
            break :blk offsets.Loc{
                .start = loc.start + item.data.byte_offset,
                .end = loc.end,
            };
        };

        var notes: []types.DiagnosticRelatedInformation = &.{};
        if (item.data.notes != 0) {
            const block = zir.extraData(Zir.Inst.Block, item.data.notes);
            const body = zir.extra[block.end..][0..block.data.body_len];
            notes = try arena.alloc(types.DiagnosticRelatedInformation, body.len);
            for (notes, body) |*note, note_index| {
                const note_item = zir.extraData(Zir.Inst.CompileErrors.Item, note_index);
                const msg = zir.nullTerminatedString(note_item.data.msg);

                const loc = blk: {
                    if (note_item.data.node != 0) {
                        break :blk offsets.nodeToLoc(tree, note_item.data.node);
                    }
                    const loc = offsets.tokenToLoc(tree, note_item.data.token);
                    break :blk offsets.Loc{
                        .start = loc.start + note_item.data.byte_offset,
                        .end = loc.end,
                    };
                };

                note.* = .{
                    .location = .{
                        .uri = handle.uri,
                        .range = offsets.locToRange(handle.tree.source, loc, server.offset_encoding),
                    },
                    .message = msg,
                };
            }
        }

        const msg = zir.nullTerminatedString(item.data.msg);
        diagnostics.appendAssumeCapacity(.{
            .range = offsets.locToRange(handle.tree.source, err_loc, server.offset_encoding),
            .severity = .Error,
            .code = .{ .string = "ast_check" },
            .source = "zls",
            .message = msg,
            .relatedInformation = if (notes.len != 0) notes else null,
        });
    }
}
