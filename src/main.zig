const std = @import("std");
const build_options = @import("build_options");

const Config = @import("config.zig");
const DocumentStore = @import("document_store.zig");
const DebugAllocator = @import("debug_allocator.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;
const data = @import("data/" ++ build_options.data_version ++ ".zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const URI = @import("uri.zig");

// Code is largely based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

var stdout: std.io.BufferedOutStream(4096, std.fs.File.OutStream) = undefined;
var allocator: *std.mem.Allocator = undefined;

var document_store: DocumentStore = undefined;
var workspace_folder_configs: std.StringHashMap(?Config) = undefined;

const ClientCapabilities = struct {
    supports_snippets: bool = false,
};

var client_capabilities = ClientCapabilities{};

const initialize_response =
    \\,"result":{"capabilities":{"signatureHelpProvider":{"triggerCharacters":["(",","]},"textDocumentSync":1,"completionProvider":{"resolveProvider":false,"triggerCharacters":[".",":","@"]},"documentHighlightProvider":false,"hoverProvider":true,"codeActionProvider":false,"declarationProvider":true,"definitionProvider":true,"typeDefinitionProvider":true,"implementationProvider":false,"referencesProvider":false,"documentSymbolProvider":true,"colorProvider":false,"documentFormattingProvider":false,"documentRangeFormattingProvider":false,"foldingRangeProvider":false,"selectionRangeProvider":false,"workspaceSymbolProvider":false,"semanticTokensProvider":{"legend":{"tokenTypes":["type","struct","enum","parameter","variable","enumMember","function","member","keyword","modifier","comment","string","number","operator"],"tokenModifiers":["definition","async","documentation"]},"rangeProvider":false,"documentProvider":true},"workspace":{"workspaceFolders":{"supported":true,"changeNotifications":true}}}}}
;

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

/// Sends a request or response
fn send(reqOrRes: var) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var arr = std.ArrayList(u8).init(&arena.allocator);
    try std.json.stringify(reqOrRes, std.json.StringifyOptions{}, arr.outStream());

    const stdout_stream = stdout.outStream();
    try stdout_stream.print("Content-Length: {}\r\n\r\n", .{arr.items.len});
    try stdout_stream.writeAll(arr.items);
    try stdout.flush();
}

fn respondGeneric(id: types.RequestId, response: []const u8) !void {
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

    const stdout_stream = stdout.outStream();
    try stdout_stream.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{ response.len + id_len + json_fmt.len - 1 });
    switch (id) {
        .Integer => |int| try stdout_stream.print("{}", .{int}),
        .String => |str| try stdout_stream.print("\"{}\"", .{str}),
        else => unreachable,
    }

    try stdout_stream.writeAll(response);
    try stdout.flush();
}

// TODO: Is this correct or can we get a better end?
fn astLocationToRange(loc: std.zig.ast.Tree.Location) types.Range {
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

fn publishDiagnostics(handle: DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

    // Use an arena for our local memory allocations.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostics = std.ArrayList(types.Diagnostic).init(&arena.allocator);

    for (tree.errors) |*err| {
        const loc = tree.tokenLocation(0, err.loc());

        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        try tree.renderError(err, fbs.outStream());

        try diagnostics.append(.{
            .range = astLocationToRange(loc),
            .severity = .Error,
            .code = @tagName(err.*),
            .source = "zls",
            .message = try std.mem.dupe(&arena.allocator, u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (tree.errors.len == 0) {
        for (tree.root_node.decls()) |decl| {
            switch (decl.id) {
                .FnProto => blk: {
                    const func = decl.cast(std.zig.ast.Node.FnProto).?;
                    const is_extern = func.extern_export_inline_token != null;
                    if (is_extern)
                        break :blk;

                    if (config.warn_style) {
                        if (func.name_token) |name_token| {
                            const loc = tree.tokenLocation(0, name_token);

                            const is_type_function = analysis.isTypeFunction(tree, func);

                            const func_name = tree.tokenSlice(name_token);
                            if (!is_type_function and !analysis.isCamelCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Information,
                                    .code = "BadStyle",
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Information,
                                    .code = "BadStyle",
                                    .source = "zls",
                                    .message = "Type functions should be PascalCase",
                                });
                            }
                        }
                    }
                },
                else => {},
            }
        }
    }

    try send(types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnosticsParams = .{
                .uri = handle.uri(),
                .diagnostics = diagnostics.items,
            },
        },
    });
}

fn containerToCompletion(
    list: *std.ArrayList(types.CompletionItem),
    analysis_ctx: *DocumentStore.AnalysisContext,
    orig_handle: *DocumentStore.Handle,
    container: *std.zig.ast.Node,
    config: Config,
) !void {
    var child_idx: usize = 0;
    while (container.iterate(child_idx)) |child_node| : (child_idx += 1) {
        // Declarations in the same file do not need to be public.
        if (orig_handle == analysis_ctx.handle or analysis.isNodePublic(analysis_ctx.tree(), child_node)) {
            try nodeToCompletion(list, analysis_ctx, orig_handle, child_node, config);
        }
    }
}

const ResolveVarDeclFnAliasRewsult = struct {
    decl: *std.zig.ast.Node,
    analysis_ctx: DocumentStore.AnalysisContext,
};

fn resolveVarDeclFnAlias(analysis_ctx: *DocumentStore.AnalysisContext, decl: *std.zig.ast.Node) !ResolveVarDeclFnAliasRewsult {
    var child_analysis_context = try analysis_ctx.clone();
    if (decl.cast(std.zig.ast.Node.VarDecl)) |var_decl| {
        const child_node = block: {
            if (var_decl.type_node) |type_node| {
                if (std.mem.eql(u8, "type", analysis_ctx.tree().tokenSlice(type_node.firstToken()))) {
                    break :block var_decl.init_node orelse type_node;
                }
                break :block type_node;
            }
            break :block var_decl.init_node.?;
        };

        if (analysis.resolveTypeOfNode(&child_analysis_context, child_node)) |resolved_node| {
            if (resolved_node.id == .FnProto) {
                return ResolveVarDeclFnAliasRewsult{
                    .decl = resolved_node,
                    .analysis_ctx = child_analysis_context,
                };
            }
        }
    }
    return ResolveVarDeclFnAliasRewsult{
        .decl = decl,
        .analysis_ctx = analysis_ctx.*,
    };
}

fn nodeToCompletion(
    list: *std.ArrayList(types.CompletionItem),
    analysis_ctx: *DocumentStore.AnalysisContext,
    orig_handle: *DocumentStore.Handle,
    node: *std.zig.ast.Node,
    config: Config,
) error{OutOfMemory}!void {
    const doc = if (try analysis.getDocComments(list.allocator, analysis_ctx.tree(), node)) |doc_comments|
        types.MarkupContent{
            .kind = .Markdown,
            .value = doc_comments,
        }
    else
        null;

    switch (node.id) {
        .ErrorSetDecl, .Root, .ContainerDecl => {
            try containerToCompletion(list, analysis_ctx, orig_handle, node, config);
        },
        .FnProto => {
            const func = node.cast(std.zig.ast.Node.FnProto).?;
            if (func.name_token) |name_token| {
                const use_snippets = config.enable_snippets and client_capabilities.supports_snippets;

                const insert_text = if (use_snippets) blk: {
                    const skip_self_param = if (func.params_len > 0) param_check: {
                        var child_analysis_ctx = try analysis_ctx.clone();
                        break :param_check switch (func.paramsConst()[0].param_type) {
                            .type_expr => |type_node| if (analysis_ctx.in_container == analysis.resolveTypeOfNode(&child_analysis_ctx, type_node))
                                true
                            else if (type_node.cast(std.zig.ast.Node.PrefixOp)) |prefix_op|
                                prefix_op.op == .PtrType and analysis_ctx.in_container == analysis.resolveTypeOfNode(&child_analysis_ctx, prefix_op.rhs)
                            else
                                false,
                            else => false,
                        };
                    } else
                        false;

                    break :blk try analysis.getFunctionSnippet(list.allocator, analysis_ctx.tree(), func, skip_self_param);
                } else
                    null;

                const is_type_function = analysis.isTypeFunction(analysis_ctx.tree(), func);

                try list.append(.{
                    .label = analysis_ctx.tree().tokenSlice(name_token),
                    .kind = if (is_type_function) .Struct else .Function,
                    .documentation = doc,
                    .detail = analysis.getFunctionSignature(analysis_ctx.tree(), func),
                    .insertText = insert_text,
                    .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
                });
            }
        },
        .VarDecl => {
            const var_decl = node.cast(std.zig.ast.Node.VarDecl).?;
            const is_const = analysis_ctx.tree().token_ids[var_decl.mut_token] == .Keyword_const;

            var result = try resolveVarDeclFnAlias(analysis_ctx, node);
            if (result.decl != node) {
                return try nodeToCompletion(list, &result.analysis_ctx, orig_handle, result.decl, config);
            }

            try list.append(.{
                .label = analysis_ctx.tree().tokenSlice(var_decl.name_token),
                .kind = if (is_const) .Constant else .Variable,
                .documentation = doc,
                .detail = analysis.getVariableSignature(analysis_ctx.tree(), var_decl),
            });
        },
        .PrefixOp => {
            const prefix_op = node.cast(std.zig.ast.Node.PrefixOp).?;
            switch (prefix_op.op) {
                .ArrayType, .SliceType => {},
                .PtrType => {
                    if (prefix_op.rhs.cast(std.zig.ast.Node.PrefixOp)) |child_pop| {
                        switch (child_pop.op) {
                            .ArrayType => {},
                            else => return,
                        }
                    } else return;
                },
                else => return,
            }

            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
            try list.append(.{
                .label = "ptr",
                .kind = .Field,
            });
        },
        .StringLiteral => {
            try list.append(.{
                .label = "len",
                .kind = .Field,
            });
        },
        else => if (analysis.nodeToString(analysis_ctx.tree(), node)) |string| {
            try list.append(.{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = analysis_ctx.tree().getNodeSource(node)
            });
        },
    }
}

fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
    const text = handle.document.text;

    if (pos_index + 1 >= text.len) return &[0]u8{};
    var start_idx = pos_index;

    while (start_idx > 0 and
        (std.ascii.isAlNum(text[start_idx]) or text[start_idx] == '_')) : (start_idx -= 1)
    {}

    var end_idx = pos_index;
    while (end_idx < handle.document.text.len and
        (std.ascii.isAlNum(text[end_idx]) or text[end_idx] == '_')) : (end_idx += 1)
    {}

    if (end_idx <= start_idx) return &[0]u8{};
    return text[start_idx + 1 .. end_idx];
}

fn gotoDefinitionSymbol(id: types.RequestId, analysis_ctx: *DocumentStore.AnalysisContext, decl: *std.zig.ast.Node) !void {
    const result = try resolveVarDeclFnAlias(analysis_ctx, decl);

    const name_token = analysis.getDeclNameToken(result.analysis_ctx.tree(), result.decl) orelse
        return try respondGeneric(id, null_result_response);

    try send(types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = result.analysis_ctx.handle.document.uri,
                .range = astLocationToRange(result.analysis_ctx.tree().tokenLocation(0, name_token)),
            },
        },
    });
}

fn hoverSymbol(id: types.RequestId, analysis_ctx: *DocumentStore.AnalysisContext, decl: *std.zig.ast.Node) !void {
    const result = try resolveVarDeclFnAlias(analysis_ctx, decl);

    const doc_str = if (try analysis.getDocComments(&analysis_ctx.arena.allocator, result.analysis_ctx.tree(), result.decl)) |str|
        str
    else
        "";

    const signature_str = switch (result.decl.id) {
        .VarDecl => blk: {
            const var_decl = result.decl.cast(std.zig.ast.Node.VarDecl).?;
            break :blk analysis.getVariableSignature(result.analysis_ctx.tree(), var_decl);
        },
        .FnProto => blk: {
            const fn_decl = result.decl.cast(std.zig.ast.Node.FnProto).?;
            break :blk analysis.getFunctionSignature(result.analysis_ctx.tree(), fn_decl);
        },
        else => analysis.nodeToString(result.analysis_ctx.tree(), result.decl) orelse return try respondGeneric(id, null_result_response),
    };

    const md_string = try std.fmt.allocPrint(&analysis_ctx.arena.allocator, "```zig\n{}\n```\n{}", .{ signature_str, doc_str });
    try send(types.Response{
        .id = id,
        .result = .{
            .Hover = .{
                .contents = .{ .value = md_string },
            },
        },
    });
}

fn getSymbolGlobal(arena: *std.heap.ArenaAllocator, pos_index: usize, handle: DocumentStore.Handle) !?*std.zig.ast.Node {
    const name = identifierFromPosition(pos_index, handle);
    if (name.len == 0) return null;

    var decl_nodes = std.ArrayList(*std.zig.ast.Node).init(&arena.allocator);
    _ = try analysis.declsFromIndex(arena, &decl_nodes, handle.tree, pos_index);

    return analysis.getChildOfSlice(handle.tree, decl_nodes.items, name);
}

fn gotoDefinitionGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolGlobal(&arena, pos_index, handle.*)) orelse return try respondGeneric(id, null_result_response);
    var analysis_ctx = try document_store.analysisContext(handle, &arena, pos_index, config.zig_lib_path);
    return try gotoDefinitionSymbol(id, &analysis_ctx, decl);
}

fn hoverDefinitionGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const decl = (try getSymbolGlobal(&arena, pos_index, handle.*)) orelse return try respondGeneric(id, null_result_response);
    var analysis_ctx = try document_store.analysisContext(handle, &arena, pos_index, config.zig_lib_path);
    return try hoverSymbol(id, &analysis_ctx, decl);
}

fn getSymbolFieldAccess(
    analysis_ctx: *DocumentStore.AnalysisContext,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
) !?*std.zig.ast.Node {
    const pos_index = try analysis_ctx.handle.document.positionToIndex(position);
    var name = identifierFromPosition(pos_index, analysis_ctx.handle.*);
    if (name.len == 0) return null;

    const line = try analysis_ctx.handle.document.getLine(@intCast(usize, position.line));
    var tokenizer = std.zig.Tokenizer.init(line[range.start..range.end]);

    name = try std.mem.dupe(&analysis_ctx.arena.allocator, u8, name);
    if (analysis.getFieldAccessTypeNode(analysis_ctx, &tokenizer)) |container| {
        return analysis.getChild(analysis_ctx.tree(), container, name);
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var analysis_ctx = try document_store.analysisContext(handle, &arena, try handle.document.positionToIndex(position), config.zig_lib_path);
    const decl = (try getSymbolFieldAccess(&analysis_ctx, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try gotoDefinitionSymbol(id, &analysis_ctx, decl);
}

fn hoverDefinitionFieldAccess(
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: types.Position,
    range: analysis.SourceRange,
    config: Config,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var analysis_ctx = try document_store.analysisContext(handle, &arena, try handle.document.positionToIndex(position), config.zig_lib_path);
    const decl = (try getSymbolFieldAccess(&analysis_ctx, position, range, config)) orelse return try respondGeneric(id, null_result_response);
    return try hoverSymbol(id, &analysis_ctx, decl);
}

fn gotoDefinitionString(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    const tree = handle.tree;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const import_str = analysis.getImportStr(tree, pos_index) orelse return try respondGeneric(id, null_result_response);
    const uri = (try document_store.uriFromImportStr(
        &arena.allocator,
        handle.*,
        import_str,
        try DocumentStore.stdUriFromLibPath(&arena.allocator, config.zig_lib_path),
    )) orelse return try respondGeneric(id, null_result_response);

    try send(types.Response{
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

fn completeGlobal(id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle, config: Config) !void {
    // We use a local arena allocator to deallocate all temporary data without iterating
    var arena = std.heap.ArenaAllocator.init(allocator);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    // Deallocate all temporary data.
    defer arena.deinit();

    var analysis_ctx = try document_store.analysisContext(handle, &arena, pos_index, config.zig_lib_path);
    for (analysis_ctx.scope_nodes) |decl_ptr| {
        var decl = decl_ptr.*;
        try nodeToCompletion(&completions, &analysis_ctx, handle, decl_ptr, config);
    }

    try send(types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(id: types.RequestId, handle: *DocumentStore.Handle, position: types.Position, range: analysis.SourceRange, config: Config) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var analysis_ctx = try document_store.analysisContext(handle, &arena, try handle.document.positionToIndex(position), config.zig_lib_path);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);

    const line = try handle.document.getLine(@intCast(usize, position.line));
    var tokenizer = std.zig.Tokenizer.init(line[range.start..range.end]);

    if (analysis.getFieldAccessTypeNode(&analysis_ctx, &tokenizer)) |node| {
        try nodeToCompletion(&completions, &analysis_ctx, handle, node, config);
    }
    try send(types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn documentSymbol(id: types.RequestId, handle: *DocumentStore.Handle) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try send(types.Response{
        .id = id,
        .result = .{ .DocumentSymbols = try analysis.getDocumentSymbols(&arena.allocator, handle.tree) },
    });
}

// Compute builtin completions at comptime.
const builtin_completions = block: {
    @setEvalBranchQuota(3_500);
    const CompletionList = [data.builtins.len]types.CompletionItem;
    var with_snippets: CompletionList = undefined;
    var without_snippets: CompletionList = undefined;

    for (data.builtins) |builtin, i| {
        const cutoff = std.mem.indexOf(u8, builtin, "(") orelse builtin.len;

        const base_completion = types.CompletionItem{
            .label = builtin[0..cutoff],
            .kind = .Function,

            .filterText = builtin[1..cutoff],
            .detail = data.builtin_details[i],
            .documentation = .{
                .kind = .Markdown,
                .value = data.builtin_docs[i],
            },
        };

        with_snippets[i] = base_completion;
        with_snippets[i].insertText = builtin[1..];
        with_snippets[i].insertTextFormat = .Snippet;

        without_snippets[i] = base_completion;
        without_snippets[i].insertText = builtin[1..cutoff];
    }

    break :block [2]CompletionList{
        without_snippets, with_snippets,
    };
};

fn loadConfig(folder_path: []const u8) ?Config {
    var folder = std.fs.cwd().openDir(folder_path, .{}) catch return null;
    defer folder.close();

    const conf_file = folder.openFile("zls.json", .{}) catch return null;
    defer conf_file.close();

    // Max 1MB
    const file_buf = conf_file.inStream().readAllAlloc(allocator, 0x1000000) catch return null;
    defer allocator.free(file_buf);

    // TODO: Better errors? Doesn't seem like std.json can provide us positions or context.
    var config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{ .allocator = allocator }) catch |err| {
        std.debug.warn("Error while parsing configuration file: {}\nUsing default config.\n", .{err});
        return null;
    };

    if (config.zig_lib_path) |zig_lib_path| {
        if (!std.fs.path.isAbsolute(zig_lib_path)) {
            std.debug.warn("zig library path is not absolute, defaulting to null.\n", .{});
            allocator.free(zig_lib_path);
            config.zig_lib_path = null;
        }
    }

    return config;
}

fn loadWorkspaceConfigs() !void {
    var folder_config_it = workspace_folder_configs.iterator();
    while (folder_config_it.next()) |entry| {
        if (entry.value) |_| continue;

        const folder_path = try URI.parse(allocator, entry.key);
        defer allocator.free(folder_path);

        entry.value = loadConfig(folder_path);
    }
}

fn configFromUriOr(uri: []const u8, default: Config) Config {
    var folder_config_it = workspace_folder_configs.iterator();
    while (folder_config_it.next()) |entry| {
        if (std.mem.startsWith(u8, uri, entry.key)) {
            return entry.value orelse default;
        }
    }

    return default;
}

fn processJsonRpc(parser: *std.json.Parser, json: []const u8, config: Config) !void {
    var tree = try parser.parse(json);
    defer tree.deinit();

    const root = tree.root;

    const id = if (root.Object.getValue("id")) |id| switch (id) {
        .Integer => |int| types.RequestId{ .Integer = int },
        .String => |str| types.RequestId{ .String = str },
        else => types.RequestId{ .Integer = 0 },
    } else types.RequestId{ .Integer = 0 };

    if (id == .Integer and id.Integer == 1337 and (root.Object.getValue("method") == null or std.mem.eql(u8, root.Object.getValue("method").?.String, ""))) {
        if (root.Object.getValue("result")) |result_obj| {
            if (result_obj == .Array) {
                const result = result_obj.Array;

                for (result.items) |workspace_folder| {
                    const duped_uri = try std.mem.dupe(allocator, u8, workspace_folder.Object.getValue("uri").?.String);
                    try workspace_folder_configs.putNoClobber(duped_uri, null);
                }
            }
        }

        try loadWorkspaceConfigs();
        return;
    }

    std.debug.assert(root.Object.getValue("method") != null);
    const method = root.Object.getValue("method").?.String;
    const params = root.Object.getValue("params").?.Object;

    const start_time = std.time.milliTimestamp();
    defer {
        const end_time = std.time.milliTimestamp();
        std.debug.warn("Took {}ms to process method {}\n", .{ end_time - start_time, method });
    }

    // Core
    if (std.mem.eql(u8, method, "initialize")) {
        const client_capabs = params.getValue("capabilities").?.Object;
        if (client_capabs.getValue("textDocument")) |text_doc_capabs| {
            if (text_doc_capabs.Object.getValue("completion")) |completion_capabs| {
                if (completion_capabs.Object.getValue("completionItem")) |item_capabs| {
                    const maybe_support_snippet = item_capabs.Object.getValue("snippetSupport");
                    client_capabilities.supports_snippets = maybe_support_snippet != null and maybe_support_snippet.?.Bool;
                }
            }
        }

        try respondGeneric(id, initialize_response);
    } else if (std.mem.eql(u8, method, "initialized")) {
        // Send the workspaceFolders request
        try send(types.Request{
            .id = .{ .Integer = 1337 },
            .method = "workspace/workspaceFolders",
            .params = {},
        });
    } else if (std.mem.eql(u8, method, "$/cancelRequest")) {
        // noop
    }
    // Workspace folder changes
    else if (std.mem.eql(u8, method, "workspace/didChangeWorkspaceFolders")) {
        const event = params.getValue("event").?.Object;
        const added = event.getValue("added").?.Array;
        const removed = event.getValue("removed").?.Array;

        for (removed.items) |rem| {
            const uri = rem.Object.getValue("uri").?.String;
            if (workspace_folder_configs.remove(uri)) |entry| {
                allocator.free(entry.key);
                if (entry.value) |c| {
                    std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
                }
            }
        }

        for (added.items) |add| {
            const duped_uri = try std.mem.dupe(allocator, u8, add.Object.getValue("uri").?.String);
            if (try workspace_folder_configs.put(duped_uri, null)) |old| {
                allocator.free(old.key);
                if (old.value) |c| {
                    std.json.parseFree(Config, c, std.json.ParseOptions{ .allocator = allocator });
                }
            }
        }

        try loadWorkspaceConfigs();
    }
    // File changes
    else if (std.mem.eql(u8, method, "textDocument/didOpen")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const text = document.getValue("text").?.String;

        const handle = try document_store.openDocument(uri, text);
        try publishDiagnostics(handle.*, configFromUriOr(uri, config));
    } else if (std.mem.eql(u8, method, "textDocument/didChange")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const content_changes = params.getValue("contentChanges").?.Array;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to change non existent document {}", .{uri});
            return;
        };

        const local_config = configFromUriOr(uri, config);
        try document_store.applyChanges(handle, content_changes, local_config.zig_lib_path);
        try publishDiagnostics(handle.*, local_config);
    } else if (std.mem.eql(u8, method, "textDocument/didSave")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to save non existent document {}", .{uri});
            return;
        };

        try document_store.applySave(handle);
    } else if (std.mem.eql(u8, method, "textDocument/willSave")) {
        // noop
    } else if (std.mem.eql(u8, method, "textDocument/didClose")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        document_store.closeDocument(uri);
    }
    // Semantic highlighting
    else if (std.mem.eql(u8, method, "textDocument/semanticTokens")) {
        // @TODO Implement this (we dont get here from vscode atm even when we get the client capab.)
        return try respondGeneric(id, empty_array_response);
    }
    // Autocomplete / Signatures
    else if (std.mem.eql(u8, method, "textDocument/completion")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to complete in non existent document {}", .{uri});
            return try respondGeneric(id, no_completions_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            const this_config = configFromUriOr(uri, config);
            const use_snippets = this_config.enable_snippets and client_capabilities.supports_snippets;
            switch (pos_context) {
                .builtin => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = builtin_completions[@boolToInt(use_snippets)][0..],
                        },
                    },
                }),
                .var_access, .empty => try completeGlobal(id, pos_index, handle, this_config),
                .field_access => |range| try completeFieldAccess(id, handle, pos, range, this_config),
                .global_error_set => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = document_store.error_completions.completions.items,
                        },
                    },
                }),
                .enum_literal => try send(types.Response{
                    .id = id,
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = document_store.enum_completions.completions.items,
                        },
                    },
                }),
                else => try respondGeneric(id, no_completions_response),
            }
        } else {
            try respondGeneric(id, no_completions_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/signatureHelp")) {
        // TODO: Implement this
        try respondGeneric(id,
            \\,"result":{"signatures":[]}}
        );
    } else if (std.mem.eql(u8, method, "textDocument/definition") or
        std.mem.eql(u8, method, "textDocument/declaration") or
        std.mem.eql(u8, method, "textDocument/typeDefinition") or
        std.mem.eql(u8, method, "textDocument/implementation"))
    {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            switch (pos_context) {
                .var_access => try gotoDefinitionGlobal(
                    id,
                    pos_index,
                    handle,
                    configFromUriOr(uri, config),
                ),
                .field_access => |range| try gotoDefinitionFieldAccess(
                    id,
                    handle,
                    pos,
                    range,
                    configFromUriOr(uri, config),
                ),
                .string_literal => try gotoDefinitionString(id, pos_index, handle, config),
                else => try respondGeneric(id, null_result_response),
            }
        } else {
            try respondGeneric(id, null_result_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/hover")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try handle.document.positionToIndex(pos);
            const pos_context = try analysis.documentPositionContext(allocator, handle.document, pos);

            switch (pos_context) {
                .var_access => try hoverDefinitionGlobal(
                    id,
                    pos_index,
                    handle,
                    configFromUriOr(uri, config),
                ),
                .field_access => |range| try hoverDefinitionFieldAccess(
                    id,
                    handle,
                    pos,
                    range,
                    configFromUriOr(uri, config),
                ),
                else => try respondGeneric(id, null_result_response),
            }
        } else {
            try respondGeneric(id, null_result_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/documentSymbol")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        const handle = document_store.getHandle(uri) orelse {
            std.debug.warn("Trying to got to definition in non existent document {}", .{uri});
            return try respondGeneric(id, null_result_response);
        };

        try documentSymbol(id, handle);
    } else if (std.mem.eql(u8, method, "textDocument/references") or
        std.mem.eql(u8, method, "textDocument/documentHighlight") or
        std.mem.eql(u8, method, "textDocument/codeAction") or
        std.mem.eql(u8, method, "textDocument/codeLens") or
        std.mem.eql(u8, method, "textDocument/documentLink") or
        std.mem.eql(u8, method, "textDocument/formatting") or
        std.mem.eql(u8, method, "textDocument/rangeFormatting") or
        std.mem.eql(u8, method, "textDocument/onTypeFormatting") or
        std.mem.eql(u8, method, "textDocument/rename") or
        std.mem.eql(u8, method, "textDocument/prepareRename") or
        std.mem.eql(u8, method, "textDocument/foldingRange") or
        std.mem.eql(u8, method, "textDocument/selectionRange"))
    {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        try respondGeneric(id, null_result_response);
    } else if (root.Object.getValue("id")) |_| {
        std.debug.warn("Method with return value not implemented: {}", .{method});
        try respondGeneric(id, not_implemented_response);
    } else {
        std.debug.warn("Method without return value not implemented: {}", .{method});
    }
}

var debug_alloc_state: DebugAllocator = undefined;
// We can now use if(leak_count_alloc) |alloc| { ... } as a comptime check.
const debug_alloc: ?*DebugAllocator = if (build_options.allocation_info) &debug_alloc_state else null;

pub fn main() anyerror!void {
    // TODO: Use a better purpose general allocator once std has one.
    // Probably after the generic composable allocators PR?
    // This is not too bad for now since most allocations happen in local arenas.
    allocator = std.heap.page_allocator;

    if (build_options.allocation_info) {
        // TODO: Use a better debugging allocator, track size in bytes, memory reserved etc..
        // Initialize the leak counting allocator.
        debug_alloc_state = DebugAllocator.init(allocator);
        allocator = &debug_alloc_state.allocator;
    }

    // Init global vars
    const in_stream = std.io.getStdIn().inStream();
    stdout = std.io.bufferedOutStream(std.io.getStdOut().outStream());

    // Read the configuration, if any.
    const config_parse_options = std.json.ParseOptions{ .allocator = allocator };
    var config = Config{};
    defer std.json.parseFree(Config, config, config_parse_options);

    config_read: {
        const known_folders = @import("known-folders");

        const res = try known_folders.getPath(allocator, .local_configuration);
        if (res) |local_config_path| {
            defer allocator.free(local_config_path);
            if (loadConfig(local_config_path)) |conf| {
                config = conf;
                break :config_read;
            }
        }

        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = std.fs.selfExeDirPath(&exe_dir_bytes) catch break :config_read;

        if (loadConfig(exe_dir_path)) |conf| {
            config = conf;
        }
    }

    // Find the zig executable in PATH
    var zig_exe_path: ?[]const u8 = null;
    defer if (zig_exe_path) |exe_path| allocator.free(exe_path);

    find_zig: {
        if (config.zig_exe_path) |exe_path| {
            if (std.fs.path.isAbsolute(exe_path)) {
                zig_exe_path = try std.mem.dupe(allocator, u8, exe_path);
                break :find_zig;
            }

            std.debug.warn("zig path `{}` is not absolute, will look in path\n", .{exe_path});
        }

        const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => {
                std.debug.warn("Could not get PATH.\n", .{});
                break :find_zig;
            },
            else => return err,
        };
        defer allocator.free(env_path);

        const exe_extension = @as(std.zig.CrossTarget, .{}).exeFileExt();
        const zig_exe = try std.fmt.allocPrint(allocator, "zig{}", .{exe_extension});
        defer allocator.free(zig_exe);

        var it = std.mem.tokenize(env_path, &[_]u8{std.fs.path.delimiter});
        while (it.next()) |path| {
            const full_path = try std.fs.path.join(allocator, &[_][]const u8{
                path,
                zig_exe,
            });
            defer allocator.free(full_path);

            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            zig_exe_path = std.os.realpath(full_path, &buf) catch continue;
            std.debug.warn("Found zig in PATH: {}\n", .{zig_exe_path});
            break :find_zig;
        }
    }

    if (zig_exe_path) |exe_path| {
        std.debug.warn("Using zig executable {}\n", .{exe_path});
        if (config.zig_lib_path == null) {
            // Set the lib path relative to the executable path.
            config.zig_lib_path = try std.fs.path.resolve(allocator, &[_][]const u8{
                std.fs.path.dirname(exe_path).?, "./lib/zig",
            });

            std.debug.warn("Resolved standard library from executable: {}\n", .{config.zig_lib_path});
        }
    }

    if (config.build_runner_path) |build_runner_path| {
        try document_store.init(allocator, zig_exe_path, try std.mem.dupe(allocator, u8, build_runner_path));
    } else {
        var exe_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exe_dir_path = try std.fs.selfExeDirPath(&exe_dir_bytes);

        const build_runner_path = try std.fs.path.resolve(allocator, &[_][]const u8{ exe_dir_path, "build_runner.zig" });
        try document_store.init(allocator, zig_exe_path, build_runner_path);
    }

    defer document_store.deinit();

    workspace_folder_configs = std.StringHashMap(?Config).init(allocator);
    defer workspace_folder_configs.deinit();

    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(allocator, false);
    defer json_parser.deinit();

    while (true) {
        const headers = readRequestHeader(allocator, in_stream) catch |err| {
            std.debug.warn("{}; exiting!", .{@errorName(err)});
            return;
        };
        defer headers.deinit(allocator);
        const buf = try allocator.alloc(u8, headers.content_length);
        defer allocator.free(buf);
        try in_stream.readNoEof(buf);
        try processJsonRpc(&json_parser, buf, config);
        json_parser.reset();

        if (debug_alloc) |dbg| {
            std.debug.warn("{}\n", .{dbg.info});
        }
    }
}
