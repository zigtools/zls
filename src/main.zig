const std = @import("std");
const build_options = @import("build_options");

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
pub fn send(reqOrRes: var) !void {
    // The most memory we'll probably need
    var mem_buffer: [1024 * 128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&mem_buffer);
    try std.json.stringify(reqOrRes, std.json.StringifyOptions{}, fbs.outStream());
    _ = try stdout.print("Content-Length: {}\r\n\r\n", .{fbs.pos});
    _ = try stdout.write(fbs.getWritten());
}

pub fn log(comptime fmt: []const u8, args: var) !void {
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

pub fn respondGeneric(id: i64, response: []const u8) !void {
    const id_digits = blk: {
        if (id == 0) break :blk 1;
        var digits: usize = 1;
        var value = @divTrunc(id, 10);
        while (value != 0) : (value = @divTrunc(value, 10)) {
            digits += 1;
        }
        break :blk digits;
    };

    _ = try stdout.print("Content-Length: {}\r\n\r\n{}\"jsonrpc\":\"2.0\",\"id\":{}", .{response.len + id_digits + 22, "{", id});
    _ = try stdout.write(response);
}

pub fn openDocument(uri: []const u8, text: []const u8) !void {
    const du = try std.mem.dupe(allocator, u8, uri);
    _ = try documents.put(du, .{
        .uri = du,
        .text = try std.mem.dupe(allocator, u8, text),
    });
}

pub fn cacheSane(document: *types.TextDocument) !void {
    if (document.sane_text) |old_sane| {
        allocator.free(old_sane);
    }
    document.sane_text = try std.mem.dupe(allocator, u8, document.text);
}

pub fn publishDiagnostics(document: *types.TextDocument) !void {
    const tree = try std.zig.parse(allocator, document.text);
    defer tree.deinit();

    // Use an arena for our local memory allocations.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostics = std.ArrayList(types.Diagnostic).init(&arena.allocator);

    if (tree.errors.len > 0) {
        var index: usize = 0;
        while (index < tree.errors.len) : (index += 1) {
            const err = tree.errors.at(index);
            const loc = tree.tokenLocation(0, err.loc());

            var mem_buffer: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&mem_buffer);
            _ = try tree.renderError(err, fbs.outStream());

            try diagnostics.append(.{
                .range = .{
                    .start = .{
                        .line = @intCast(i64, loc.line),
                        .character = @intCast(i64, loc.column),
                    },
                    .end = .{
                        .line = @intCast(i64, loc.line),
                        .character = @intCast(i64, loc.column),
                    },
                },
                .severity = .Error,
                .code = @tagName(err.*),
                .source = "zls",
                // We dupe the string from the stack to our arena
                .message = try std.mem.dupe(&arena.allocator, u8, fbs.getWritten()),
                // .relatedInformation = undefined
            });
        }
    } else {
        try cacheSane(document);
        var decls = tree.root_node.decls.iterator(0);
        while (decls.next()) |decl_ptr| {
            var decl = decl_ptr.*;
            switch (decl.id) {
                .FnProto => {
                    const func = decl.cast(std.zig.ast.Node.FnProto).?;
                    if (func.name_token) |name_token| {
                        const loc = tree.tokenLocation(0, name_token);
                        if (func.extern_export_inline_token == null and !analysis.isCamelCase(tree.tokenSlice(name_token))) {
                            try diagnostics.append(.{
                                .range = .{
                                    .start = .{
                                        .line = @intCast(i64, loc.line),
                                        .character = @intCast(i64, loc.column),
                                    },
                                    .end = .{
                                        .line = @intCast(i64, loc.line),
                                        .character = @intCast(i64, loc.column),
                                    },
                                },
                                .severity = .Information,
                                .code = "BadStyle",
                                .source = "zls",
                                .message = "Callables should be camelCase"
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

pub fn completeGlobal(id: i64, document: *types.TextDocument) !void {
    // The tree uses its own arena, so we just pass our main allocator.
    var tree = try std.zig.parse(allocator, document.text);

    if (tree.errors.len > 0) {
        if (document.sane_text) |sane_text| {
            tree.deinit();
            tree = try std.zig.parse(allocator, sane_text);
        } else return try respondGeneric(id, no_completions_response);
    }
    else {try cacheSane(document);}

    defer tree.deinit();

    // We use a local arena allocator to deallocate all temporary data without iterating
    var arena = std.heap.ArenaAllocator.init(allocator);
    var completions = std.ArrayList(types.CompletionItem).init(&arena.allocator);
    // Deallocate all temporary data.
    defer arena.deinit();

    // try log("{}", .{&tree.root_node.decls});
    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {

        var decl = decl_ptr.*;
        switch (decl.id) {
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                var doc_comments = try analysis.getDocComments(&arena.allocator, tree, decl);
                var doc = types.MarkupContent{
                    .kind = .Markdown,
                    .value = doc_comments orelse "",
                };
                try completions.append(.{
                    .label = tree.tokenSlice(func.name_token.?),
                    .kind = .Function,
                    .documentation = doc,
                    .detail = analysis.getFunctionSignature(tree, func),
                });
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


// Compute builtin completions at comptime.
const builtin_completions = block: {
    @setEvalBranchQuota(3_500);
    var temp: [data.builtins.len]types.CompletionItem = undefined;

    for (data.builtins) |builtin, i| {
        var cutoff = std.mem.indexOf(u8, builtin, "(") orelse builtin.len;
        temp[i] = .{
            .label = builtin[0..cutoff],
            .kind = .Function,

            .filterText = builtin[1..cutoff],
            .insertText = builtin[1..],
            .insertTextFormat = .Snippet,
            .detail = data.builtin_details[i],
            .documentation = .{
                .kind = .Markdown,
                .value = data.builtin_docs[i],
            },
        };
    }

    break :block temp;
};

// pub fn signature

pub fn processJsonRpc(json: []const u8) !void {

    var parser = std.json.Parser.init(allocator, false);
    defer parser.deinit();

    var tree = try parser.parse(json);
    defer tree.deinit();

    const root = tree.root;

    // if (root.Object.getValue("method") == null) {return;}

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
        try publishDiagnostics(&(documents.get(uri).?.value));
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

                const old_text = document.text;
                const before = old_text[0..try document.positionToIndex(start_pos)];
                const after = old_text[try document.positionToIndex(end_pos)..document.text.len];
                document.text = try std.mem.concat(allocator, u8, &[3][]const u8{ before, change.Object.getValue("text").?.String, after });
                allocator.free(old_text);
            } else {
                const old_text = document.text;
                document.text = try std.mem.dupe(allocator, u8, change.Object.getValue("text").?.String);
                allocator.free(old_text);
            }
        }

        try publishDiagnostics(document);
    } else if (std.mem.eql(u8, method, "textDocument/didSave")) {
        // noop
    } else if (std.mem.eql(u8, method, "textDocument/didClose")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;

        _ = documents.remove(uri);
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
            const char = document.text[pos_index];
            
            if (char == '@') {
                try send(types.Response{
                    .id = .{.Integer = id},
                    .result = .{
                        .CompletionList = .{
                            .isIncomplete = false,
                            .items = builtin_completions[0..],
                        },
                    },
                });
            } else if (char != '.') {
                try completeGlobal(id, document);
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

const use_leak_count_alloc = build_options.leak_detection;

var leak_alloc_global: std.testing.LeakCountAllocator = undefined;
// We can now use if(leak_count_alloc) |alloc| { ... } as a comptime check.
const leak_count_alloc: ?*std.testing.LeakCountAllocator = if (use_leak_count_alloc) &leak_alloc_global else null;

pub fn main() anyerror!void {

    // TODO: Use a better purpose general allocator once std has one.
    // Probably after the generic composable allocators PR?
    // This is not too bad for now since most allocations happen in local areans.
    allocator = std.heap.page_allocator;

    if (use_leak_count_alloc) {
        // Initialize the leak counting allocator.
        std.debug.warn("Counting memory leaks...\n", .{});
        leak_alloc_global = std.testing.LeakCountAllocator.init(allocator);
        allocator = &leak_alloc_global.allocator;
    }

    // Init buffer for stdin read

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.resize(4096);

    // Init global vars

    const stdin = std.io.getStdIn().inStream();
    stdout = std.io.getStdOut().outStream();

    documents = std.StringHashMap(types.TextDocument).init(allocator);

    var offset: usize = 0;
    var bytes_read: usize = 0;

    var index: usize = 0;
    var content_len: usize = 0;

    stdin_poll: while (true) {

        // var bytes = stdin.read(buffer.items[0..6]) catch return;

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

            // buffer.items[offset] = try stdin.readByte();=
            if (buffer.items[index] == '\r') {
                index += 2;
                if (buffer.items.len < index + content_len) {
                    try buffer.resize(index + content_len);
                }

                body_poll: while (offset < content_len + index) {
                    bytes_read = stdin.read(buffer.items[offset .. index + content_len]) catch return;
                    if (bytes_read == 0) {
                        try log("0 bytes written; exiting!", .{});
                        return;
                    }

                    offset += bytes_read;
                }
                
                try processJsonRpc(buffer.items[index .. index + content_len]);

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
            bytes_read = stdin.read(buffer.items[offset..25]) catch return;
        } else {
            if (offset == buffer.items.len) {
                try buffer.resize(buffer.items.len * 2);
            }
            if (index + content_len > buffer.items.len) {
                bytes_read = stdin.read(buffer.items[offset..buffer.items.len]) catch {
                    try log("Error reading!", .{});
                    return;
                };
            } else {
                bytes_read = stdin.read(buffer.items[offset .. index + content_len]) catch {
                    try log("Error reading!", .{});
                    return;
                };
            }
        }

        if (bytes_read == 0) {
            try log("0 bytes written; exiting!", .{});
            return;
        }

        offset += bytes_read;

        if (leak_count_alloc) |leaks| {
            try log("Allocations alive after message: {}", .{leaks.count});
        }
    }
}
