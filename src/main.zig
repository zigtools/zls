const std = @import("std");
const build_options = @import("build_options");

const Config = @import("config.zig");
const Uri = @import("uri.zig");
const data = @import("data/" ++ build_options.data_version ++ ".zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");

// Code is largely based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

var stdout: std.fs.File.OutStream = undefined;
var allocator: *std.mem.Allocator = undefined;

/// Documents hashmap, types.DocumentUri:types.TextDocument
var documents: std.StringHashMap(types.TextDocument) = undefined;

const initialize_response = \\,"result":{"capabilities":{"signatureHelpProvider":{"triggerCharacters":["(",","]},"textDocumentSync":1,"completionProvider":{"resolveProvider":false,"triggerCharacters":[".",":","@"]},"documentHighlightProvider":false,"codeActionProvider":false,"workspace":{"workspaceFolders":{"supported":true}}}}}
;

const not_implemented_response = \\,"error":{"code":-32601,"message":"NotImplemented"}}
;

const null_result_response = \\,"result":null}
;
const empty_result_response = \\,"result":{}}
;
const empty_array_response = \\,"result":[]}
;
const edit_not_applied_response = \\,"result":{"applied":false,"failureReason":"feature not implemented"}}
;
const no_completions_response = \\,"result":{"isIncomplete":false,"items":[]}}
;

/// Sends a request or response
fn send(reqOrRes: var) !void {
    // The most memory we'll probably need
    var mem_buffer: [1024 * 128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&mem_buffer);
    try std.json.stringify(reqOrRes, std.json.StringifyOptions{}, fbs.outStream());
    try stdout.print("Content-Length: {}\r\n\r\n", .{fbs.pos});
    try stdout.writeAll(fbs.getWritten());
}

fn log(comptime fmt: []const u8, args: var) !void {
    // Disable logs on Release modes.
    if (std.builtin.mode != .Debug) return;

    var message = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(message);

    try send(types.Notification{
        .method = "window/logMessage",
        .params = .{
            .LogMessageParams = .{
                .@"type" = .Log,
                .message = message,
            }
        },
    });
}

fn respondGeneric(id: i64, response: []const u8) !void {
    const id_digits = blk: {
        if (id == 0) break :blk 1;
        var digits: usize = 1;
        var value = @divTrunc(id, 10);
        while (value != 0) : (value = @divTrunc(value, 10)) {
            digits += 1;
        }
        break :blk digits;
    };

    // Numbers of character that will be printed from this string: len - 3 brackets
    // 1 from the beginning (escaped) and the 2 from the arg {}
    const json_fmt = "{{\"jsonrpc\":\"2.0\",\"id\":{}";
    try stdout.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{ response.len + id_digits + json_fmt.len - 3, id });
    try stdout.writeAll(response);
}

fn freeDocument(document: types.TextDocument) void {
    allocator.free(document.uri);
    allocator.free(document.mem);
    if (document.sane_text) |str| {
        allocator.free(str);
    }
}

fn openDocument(uri: []const u8, text: []const u8) !void {
    const duped_uri = try std.mem.dupe(allocator, u8, uri);
    const duped_text = try std.mem.dupe(allocator, u8, text);

    const res = try documents.put(duped_uri, .{
        .uri = duped_uri,
        .text = duped_text,
        .mem = duped_text,
    });

    if (res) |entry| {
        try log("Document already open: {}, closing old.", .{uri});
        freeDocument(entry.value);
    } else {
        try log("Opened document: {}", .{uri});
    }
}

fn closeDocument(uri: []const u8) !void {
    if (documents.remove(uri)) |entry| {
        try log("Closing document: {}", .{uri});
        freeDocument(entry.value);
    }
}

fn cacheSane(document: *types.TextDocument) !void {
    try log("Caching sane text for document: {}", .{document.uri});

    if (document.sane_text) |old_sane| {
        allocator.free(old_sane);
    }
    document.sane_text = try std.mem.dupe(allocator, u8, document.text);
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

fn publishDiagnostics(document: *types.TextDocument, config: Config) !void {
    const tree = try std.zig.parse(allocator, document.text);
    defer tree.deinit();

    // Use an arena for our local memory allocations.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostics = std.ArrayList(types.Diagnostic).init(&arena.allocator);

    var error_it = tree.errors.iterator(0);
    while (error_it.next()) |err| {
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
        try cacheSane(document);
        var decls = tree.root_node.decls.iterator(0);
        while (decls.next()) |decl_ptr| {
            var decl = decl_ptr.*;
            switch (decl.id) {
                .FnProto => blk: {
                    const func = decl.cast(std.zig.ast.Node.FnProto).?;
                    const is_extern = func.extern_export_inline_token != null;
                    if (is_extern)
                        break :blk;

                    if (func.name_token) |name_token| {
                        const loc = tree.tokenLocation(0, name_token);

                        const is_type_function = switch (func.return_type) {
                            .Explicit => |node| if (node.cast(std.zig.ast.Node.Identifier)) |ident|
                                std.mem.eql(u8, tree.tokenSlice(ident.token), "type")
                            else
                                false,
                            .InferErrorSet => false,
                        };

                        const func_name = tree.tokenSlice(name_token);
                        if (!is_type_function and !analysis.isCamelCase(func_name)) {
                            try diagnostics.append(.{
                                .range = astLocationToRange(loc),
                                .severity = .Information,
                                .code = "BadStyle",
                                .source = "zls",
                                .message = "Functions should be camelCase"
                            });
                        } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                            try diagnostics.append(.{
                                .range = astLocationToRange(loc),
                                .severity = .Information,
                                .code = "BadStyle",
                                .source = "zls",
                                .message = "Type functions should be PascalCase"
                            });
                        }
                    }
                },
                else => {}
            }
        }
    }

    try send(types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnosticsParams = .{
                .uri = document.uri,
                .diagnostics = diagnostics.items,
            },
        },
    });
}

fn completeGlobal(id: i64, document: *types.TextDocument, config: Config) !void {
    // The tree uses its own arena, so we just pass our main allocator.
    var tree = try std.zig.parse(allocator, document.text);

    if (tree.errors.len > 0) {
        if (document.sane_text) |sane_text| {
            tree.deinit();
            tree = try std.zig.parse(allocator, sane_text);
        } else return try respondGeneric(id, no_completions_response);
    }
    else try cacheSane(document);

    defer tree.deinit();

    // We use a local arena allocator to deallocate all temporary data without iterating
    var arena = std.heap.ArenaAllocator.init(allocator);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    // Deallocate all temporary data.
    defer arena.deinit();

    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {
        var decl = decl_ptr.*;
        switch (decl.id) {
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                if (func.name_token) |name_token| {
                    const insert_text = if(config.enable_snippets)
                        try analysis.getFunctionSnippet(&arena.allocator, tree, func)
                    else
                        null;

                    var doc_comments = try analysis.getDocComments(&arena.allocator, tree, decl);
                    var doc = types.MarkupContent{
                        .kind = .Markdown,
                        .value = doc_comments orelse "",
                    };
                    try completions.append(.{
                        .label = tree.tokenSlice(name_token),
                        .kind = .Function,
                        .documentation = doc,
                        .detail = analysis.getFunctionSignature(tree, func),
                        .insertText = insert_text,
                        .insertTextFormat = if(config.enable_snippets) .Snippet else .PlainText,
                    });
                }
            },
            .VarDecl => {
                const var_decl = decl.cast(std.zig.ast.Node.VarDecl).?;
                var doc_comments = try analysis.getDocComments(&arena.allocator, tree, decl);
                var doc = types.MarkupContent{
                    .kind = .Markdown,
                    .value = doc_comments orelse "",
                };
                try completions.append(.{
                    .label = tree.tokenSlice(var_decl.name_token),
                    .kind = .Variable,
                    .documentation = doc,
                    .detail = analysis.getVariableSignature(tree, var_decl),
                });
            },
            else => {}
        }

    }

    try send(types.Response{
        .id = .{.Integer = id},
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(id: i64, document: *types.TextDocument, position: types.Position, config: Config) !void {
    if (document.sane_text) |sane_text| {
        var tree = try std.zig.parse(allocator, sane_text);
        defer tree.deinit();

        // We use a local arena allocator to deallocate all temporary data without iterating
        var arena = std.heap.ArenaAllocator.init(allocator);
        var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
        // Deallocate all temporary data.
        defer arena.deinit();

        var line = try document.getLine(@intCast(usize, position.line));
        var tokenizer = std.zig.Tokenizer.init(line);

        if (analysis.getNodeFromTokens(tree, &tree.root_node.base, &tokenizer)) |node| {
            var index: usize = 0;
            while (node.iterate(index)) |child_node| {
                try completions.append(.{
                    .label = analysis.nodeToString(tree, child_node),
                    .kind = .Variable, 
                });
    
                index += 1;
            }
        }

        try send(types.Response{
            .id = .{.Integer = id},
            .result = .{
                .CompletionList = .{
                    .isIncomplete = false,
                    .items = completions.items,
                },
            },
        });
    } else {
        return try send(types.Response{
            .id = .{.Integer = id},
            .result = .{
                .CompletionList = .{
                    .isIncomplete = false,
                    .items = &[_]types.CompletionItem{},
                },
            },
        });
    }
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

    break :block [2]CompletionList {
        without_snippets, with_snippets
    };
};

const PositionContext = enum {
    builtin,
    comment,
    string_literal,
    field_access,
    var_access,
    other,
    empty
};

fn documentPositionContext(doc: types.TextDocument, pos_index: usize) PositionContext {
    // First extract the whole current line up to the cursor.
    var curr_position = pos_index;
    while (curr_position > 0) : (curr_position -= 1) {
        if (doc.text[curr_position - 1] == '\n') break;
    }

    var line = doc.text[curr_position .. pos_index + 1];
    // Strip any leading whitespace.
    curr_position = 0;
    while (curr_position < line.len and (line[curr_position] == ' ' or line[curr_position] == '\t')) : (curr_position += 1) {}
    if (curr_position >= line.len) return .empty;
    line = line[curr_position .. ];

    // Quick exit for comment lines and multi line string literals.
    if (line.len >= 2 and line[0] == '/' and line[1] == '/')
        return .comment;
    if (line.len >= 2 and line[0] == '\\' and line[1] == '\\')
        return .string_literal;

    // TODO: This does not detect if we are in a string literal over multiple lines.
    // Find out what context we are in.
    // Go over the current line character by character
    // and determine the context.
    curr_position = 0;
    var new_token = true;
    var context: PositionContext = .other;
    var string_pop_ctx: PositionContext = .other;
    while (curr_position < line.len) : (curr_position += 1) {
        const c = line[curr_position];
        const next_char = if (curr_position < line.len - 1) line[curr_position + 1] else null;

        if (context != .string_literal and c == '"') {
            context = .string_literal;
            continue;
        }

        if (context == .string_literal) {
            // Skip over escaped quotes
            if (c == '\\' and next_char != null and next_char.? == '"') {
                curr_position += 1;
            } else if (c == '"') {
                context = string_pop_ctx;
                string_pop_ctx = .other;
                new_token = true;
            }

            continue;
        }

        if (c == '/' and next_char != null and next_char.? == '/') {
            context = .comment;
            break;
        }

        if (c == ' ' or c == '\t') {
            new_token = true;
            context = .other;
            continue;
        }

        if (c == '.' and (!new_token or context == .string_literal)) {
            new_token = true;
            context = .field_access;
            continue;
        }

        if (new_token) {
            const access_ctx: PositionContext = if (context == .field_access) .field_access else .var_access;
            new_token = false;

            if (c == '_' or std.ascii.isAlpha(c)) {
                context = access_ctx;
            } else if (c == '@') {
                // This checks for @"..." identifiers by controlling
                // the context the string will set after it is over.
                if (next_char != null and next_char.? == '"') {
                    string_pop_ctx = access_ctx;
                }
                context = .builtin;
            } else {
                context = .other;
            }
            continue;
        }

        if (context == .field_access or context == .var_access or context == .builtin) {
            if (c != '_' and !std.ascii.isAlNum(c)) {
                context = .other;
            }
            continue;
        }

        context = .other;
    }

    return context;
}

fn processJsonRpc(parser: *std.json.Parser, json: []const u8, config: Config) !void {
    var tree = try parser.parse(json);
    defer tree.deinit();

    const root = tree.root;

    std.debug.assert(root.Object.getValue("method") != null);

    const method = root.Object.getValue("method").?.String;
    const id = if (root.Object.getValue("id")) |id| id.Integer else 0;
    
    const params = root.Object.getValue("params").?.Object;
    
    // Core
    if (std.mem.eql(u8, method, "initialize")) {
        try respondGeneric(id, initialize_response);
    } else if (std.mem.eql(u8, method, "initialized")) {
        // noop
    } else if (std.mem.eql(u8, method, "$/cancelRequest")) {
        // noop
    }
    // File changes
    else if (std.mem.eql(u8, method, "textDocument/didOpen")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const text = document.getValue("text").?.String;

        try openDocument(uri, text);
        try publishDiagnostics(&(documents.get(uri).?.value), config);
    } else if (std.mem.eql(u8, method, "textDocument/didChange")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;

        var document = &(documents.get(uri).?.value);
        const content_changes = params.getValue("contentChanges").?.Array;

        for (content_changes.items) |change| {
            if (change.Object.getValue("range")) |range| {
                const start_pos = types.Position{
                    .line = range.Object.getValue("start").?.Object.getValue("line").?.Integer,
                    .character = range.Object.getValue("start").?.Object.getValue("character").?.Integer
                };
                const end_pos = types.Position{
                    .line = range.Object.getValue("end").?.Object.getValue("line").?.Integer,
                    .character = range.Object.getValue("end").?.Object.getValue("character").?.Integer
                };

                const change_text = change.Object.getValue("text").?.String;
                const start_index = try document.positionToIndex(start_pos);
                const end_index = try document.positionToIndex(end_pos);

                const old_len = document.text.len;
                const new_len = old_len + change_text.len;
                if (new_len > document.mem.len) {
                    // We need to reallocate memory.
                    // We reallocate twice the current filesize or the new length, if it's more than that
                    // so that we can reduce the amount of realloc calls.
                    // We can tune this to find a better size if needed.
                    const realloc_len = std.math.max(2 * old_len, new_len);
                    document.mem = try allocator.realloc(document.mem, realloc_len);
                }

                // The first part of the string, [0 .. start_index] need not be changed.
                // We then copy the last part of the string, [end_index ..] to its
                //    new position, [start_index + change_len .. ]
                std.mem.copy(u8, document.mem[start_index + change_text.len..][0 .. old_len - end_index], document.mem[end_index .. old_len]);
                // Finally, we copy the changes over.
                std.mem.copy(u8, document.mem[start_index..][0 .. change_text.len], change_text);

                // Reset the text substring.
                document.text = document.mem[0 .. new_len];
            } else {
                const change_text = change.Object.getValue("text").?.String;
                const old_len = document.text.len;

                if (change_text.len > document.mem.len) {
                    // Like above.
                    const realloc_len = std.math.max(2 * old_len, change_text.len);
                    document.mem = try allocator.realloc(document.mem, realloc_len);
                }

                std.mem.copy(u8, document.mem[0 .. change_text.len], change_text);
                document.text = document.mem[0 .. change_text.len];
            }
        }

        try publishDiagnostics(document, config);
    } else if (std.mem.eql(u8, method, "textDocument/didSave")) {
        // noop
    } else if (std.mem.eql(u8, method, "textDocument/didClose")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        try closeDocument(uri);
    }
    // Autocomplete / Signatures
    else if (std.mem.eql(u8, method, "textDocument/completion")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;
        const position = params.getValue("position").?.Object;

        var document = &(documents.get(uri).?.value);
        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try document.positionToIndex(pos);
            const pos_context = documentPositionContext(document.*, pos_index);

            if (pos_context == .builtin) {
                try send(types.Response{
                    .id = .{.Integer = id},
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = builtin_completions[@boolToInt(config.enable_snippets)][0..],
                        },
                    },
                });
            } else if (pos_context == .var_access or pos_context == .empty) {
                try completeGlobal(id, document, config);
            } else if (pos_context == .field_access) {
                try completeFieldAccess(id, document, pos, config);
            } else {
                try respondGeneric(id, no_completions_response);
            }
        } else {
            try respondGeneric(id, no_completions_response);
        }
    } else if (std.mem.eql(u8, method, "textDocument/signatureHelp")) {
        try respondGeneric(id, 
        \\,"result":{"signatures":[{
        \\"label": "nameOfFunction(aNumber: u8)",
        \\"documentation": {"kind": "markdown", "value": "Description of the function in **Markdown**!"},
        \\"parameters": [
        \\{"label": [15, 27], "documentation": {"kind": "markdown", "value": "An argument"}}
        \\]
        \\}]}}
        );
        // try respondGeneric(id, 
        // \\,"result":{"signatures":[]}}
        // );
    } else if (root.Object.getValue("id")) |_| {
        try log("Method with return value not implemented: {}", .{method});
        try respondGeneric(id, not_implemented_response);
    } else {
        try log("Method without return value not implemented: {}", .{method});
    }
}

var debug_alloc_state: std.testing.LeakCountAllocator = undefined;
// We can now use if(leak_count_alloc) |alloc| { ... } as a comptime check.
const debug_alloc: ?*std.testing.LeakCountAllocator = if (build_options.allocation_info) &debug_alloc_state else null;

pub fn main() anyerror!void {
    // TODO: Use a better purpose general allocator once std has one.
    // Probably after the generic composable allocators PR?
    // This is not too bad for now since most allocations happen in local areans.
    allocator = std.heap.page_allocator;

    if (build_options.allocation_info) {
        // TODO: Use a better debugging allocator, track size in bytes, memory reserved etc..
        // Initialize the leak counting allocator.
        debug_alloc_state = std.testing.LeakCountAllocator.init(allocator);
        allocator = &debug_alloc_state.allocator;
    }

    // Init buffer for stdin read

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.resize(4096);

    // Init global vars

    const stdin = std.io.getStdIn().inStream();
    stdout = std.io.getStdOut().outStream();


    documents = std.StringHashMap(types.TextDocument).init(allocator);

    // Read he configuration, if any.
    var config = Config{};

    // TODO: Investigate using std.fs.Watch to detect writes to the config and reload it.
    config_read: {
        var exec_dir_bytes: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const exec_dir_path = std.fs.selfExeDirPath(&exec_dir_bytes) catch break :config_read;
    
        var exec_dir = std.fs.cwd().openDir(exec_dir_path, .{}) catch break :config_read;
        defer exec_dir.close();

        var conf_file = exec_dir.openFile("zls.json", .{}) catch break :config_read;
        defer conf_file.close();

        const conf_file_stat = conf_file.stat() catch break :config_read;

        // Allocate enough memory for the whole file.
        var file_buf = try allocator.alloc(u8, conf_file_stat.size);
        defer allocator.free(file_buf);

        const bytes_read = conf_file.readAll(file_buf) catch break :config_read;
        if (bytes_read != conf_file_stat.size) break :config_read;

        // TODO: Better errors? Doesnt seem like std.json can provide us positions or context.
        // Note that we don't need to pass an allocator to parse since we are not using pointer or slice fields.
        // Thus, we don't need to even call parseFree.
        config = std.json.parse(Config, &std.json.TokenStream.init(file_buf), std.json.ParseOptions{}) catch |err| {
            std.debug.warn("Error while parsing configuration file: {}\nUsing default config.\n", .{err});
            break :config_read;
        };
    }

    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(allocator, false);
    defer json_parser.deinit();

    var offset: usize = 0;
    var bytes_read: usize = 0;

    var index: usize = 0;
    var content_len: usize = 0;

    stdin_poll: while (true) {
        if (offset >= 16 and std.mem.startsWith(u8, buffer.items, "Content-Length: ")) {

            index = 16;
            while (index <= offset + 10) : (index += 1) {
                const c = buffer.items[index];
                if (c >= '0' and c <= '9') {
                    content_len = content_len * 10 + (c - '0');
                } if (c == '\r' and buffer.items[index + 1] == '\n') {
                    index += 2;
                    break;
                }
            }

            if (buffer.items[index] == '\r') {
                index += 2;
                if (buffer.items.len < index + content_len) {
                    try buffer.resize(index + content_len);
                }

                body_poll: while (offset < content_len + index) {
                    bytes_read = try stdin.readAll(buffer.items[offset .. index + content_len]);
                    if (bytes_read == 0) {
                        try log("0 bytes read; exiting!", .{});
                        return;
                    }

                    offset += bytes_read;
                }

                try processJsonRpc(&json_parser, buffer.items[index .. index + content_len], config);
                json_parser.reset();

                offset = 0;
                content_len = 0;
            } else {
                try log("\\r not found", .{});
            }

        } else if (offset >= 16) {
            try log("Offset is greater than 16!", .{});
            return;
        }

        if (offset < 16) {
            bytes_read = try stdin.readAll(buffer.items[offset..25]);
        } else {
            if (offset == buffer.items.len) {
                try buffer.resize(buffer.items.len * 2);
            }
            if (index + content_len > buffer.items.len) {
                bytes_read = try stdin.readAll(buffer.items[offset..buffer.items.len]);
            } else {
                bytes_read = try stdin.readAll(buffer.items[offset .. index + content_len]);
            }
        }

        if (bytes_read == 0) {
            try log("0 bytes read; exiting!", .{});
            return;
        }

        offset += bytes_read;

        if (debug_alloc) |dbg| {
            try log("Allocations alive: {}", .{dbg.count});
        }
    }
}
