const std = @import("std");
const Uri = @import("uri.zig");
const data = @import("data.zig");
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
        .params = types.NotificationParams{
            .LogMessageParams = types.LogMessageParams{
                .@"type" = types.MessageType.Log,
                .message = message
            }
        }
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
    _ = try documents.put(du, types.TextDocument{
        .uri = du,
        .text = try std.mem.dupe(allocator, u8, text)
    });
}

pub fn publishDiagnostics(document: types.TextDocument) !void {
    const tree = try std.zig.parse(allocator, document.text);
    defer tree.deinit();

    var diagnostics = std.ArrayList(types.Diagnostic).init(allocator);

    if (tree.errors.len > 0) {
        var index: usize = 0;
        while (index < tree.errors.len) : (index += 1) {
            const err = tree.errors.at(index);
            const loc = tree.tokenLocation(0, err.loc());

            var mem_buffer: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&mem_buffer);
            _ = try tree.renderError(err, fbs.outStream());

            try diagnostics.append(types.Diagnostic{
                .range = types.Range{
                    .start = types.Position{
                        .line = @intCast(i64, loc.line),
                        .character = @intCast(i64, loc.column)
                    },
                    .end = types.Position{
                        .line = @intCast(i64, loc.line),
                        .character = @intCast(i64, loc.column)
                    }
                },
                .severity = types.DiagnosticSeverity.Error,
                .code = @tagName(err.*),
                .source = "zls",
                .message = fbs.getWritten(),
                // .relatedInformation = undefined
            });
        }
    }

    try send(types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = types.NotificationParams{
            .PublishDiagnosticsParams = types.PublishDiagnosticsParams{
                .uri = document.uri,
                .diagnostics = diagnostics.toOwnedSlice()
            }
        }
    });
}

pub fn completeGlobal(id: i64, document: types.TextDocument) !void {
    const tree = try std.zig.parse(allocator, document.text);
    defer tree.deinit();

    if (tree.errors.len > 0) return try respondGeneric(id, no_completions_response);

    var completions = std.ArrayList(types.CompletionItem).init(allocator);

    // try log("{}", .{&tree.root_node.decls});
    var decls = tree.root_node.decls.iterator(0);
    while (decls.next()) |decl_ptr| {

        var decl = decl_ptr.*;
        switch (decl.id) {
            .FnProto => {
                const func = decl.cast(std.zig.ast.Node.FnProto).?;
                // if (std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return func;
                try completions.append(types.CompletionItem{
                    .label = tree.tokenSlice(func.name_token.?),
                    .kind = types.CompletionItemKind.Function,
                });
            },
            .VarDecl => {
                const vari = decl.cast(std.zig.ast.Node.VarDecl).?;
                // if (std.mem.eql(u8, tree.tokenSlice(func.name_token.?), name)) return func;
                try completions.append(types.CompletionItem{
                    .label = tree.tokenSlice(vari.name_token),
                    .kind = types.CompletionItemKind.Variable,
                });
            },
            else => {}
        }

    }

    try send(types.Response{
        .id = .{.Integer = id},
        .result = types.ResponseParams{
            .CompletionList = types.CompletionList{
                .isIncomplete = false,
                .items = completions.toOwnedSlice()
            }
        }
    });
}

// pub fn signature

pub fn processJsonRpc(json: []const u8) !void {

    var parser = std.json.Parser.init(allocator, false);
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
        try publishDiagnostics(documents.getValue(uri).?);
    } else if (std.mem.eql(u8, method, "textDocument/didChange")) {
        const text_document = params.getValue("textDocument").?.Object;
        const uri = text_document.getValue("uri").?.String;

        var document = &(documents.get(uri).?.value);
        const content_changes = params.getValue("contentChanges").?.Array;
        // const text = content_changes.items[0].Object.getValue("text").?.String

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

                const before = document.text[0..try document.positionToIndex(start_pos)];
                const after = document.text[try document.positionToIndex(end_pos)..document.text.len];
                allocator.free(document.text);
                document.text = try std.mem.concat(allocator, u8, &[3][]const u8{ before, change.Object.getValue("text").?.String, after });
            } else {
                allocator.free(document.text);
                document.text = try std.mem.dupe(allocator, u8, change.Object.getValue("text").?.String);
            }
        }

        try publishDiagnostics(document.*);
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

        const document = documents.getValue(uri).?;
        const pos = types.Position{
            .line = position.getValue("line").?.Integer,
            .character = position.getValue("character").?.Integer - 1,
        };
        if (pos.character >= 0) {
            const pos_index = try document.positionToIndex(pos);
            const char = document.text[pos_index];
            
            if (char == '@') {
                var builtin_completions: [data.builtins.len]types.CompletionItem = undefined;

                for (data.builtins) |builtin, i| {
                    var cutoff = std.mem.indexOf(u8, builtin, "(") orelse builtin.len;
                    builtin_completions[i] = types.CompletionItem{
                        .label = builtin[0..cutoff],
                        .kind = types.CompletionItemKind.Function,
                        // .textEdit = types.TextEdit{
                        //     .range = types.Range{
                        //         .start = pos,
                        //         .end = pos,
                        //     },
                        //     .newText = builtin,
                        // },
                        .filterText = builtin[1..cutoff],
                        .insertText = builtin[1..],
                        .insertTextFormat = types.InsertTextFormat.Snippet
                    };
                }

                try send(types.Response{
                    .id = .{.Integer = id},
                    .result = types.ResponseParams{
                        .CompletionList = types.CompletionList{
                            .isIncomplete = false,
                            .items = builtin_completions[0..]
                        }
                    }
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
        // try respondGeneric(id, 
        // \\,"result":{"signatures":[{
        // \\"label": "nameOfFunction(aNumber: u8)",
        // \\"documentation": {"kind": "markdown", "value": "Description of the function in **Markdown**!"},
        // \\"parameters": [
        // \\{"label": [15, 27], "documentation": {"kind": "markdown", "value": "An argument"}}
        // \\]
        // \\}]}}
        // );
        try respondGeneric(id, 
        \\,"result":{"signatures":[]}}
        );
    } else if (root.Object.getValue("id")) |_| {
        try log("Method with return value not implemented: {}", .{method});
        try respondGeneric(id, not_implemented_response);
    } else {
        try log("Method without return value not implemented: {}", .{method});
    }

}

pub fn main() anyerror!void {

    // Init memory

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    allocator = &arena.allocator;

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

        if (offset >= 16 and std.mem.eql(u8, "Content-Length: ", buffer.items[0..16])) {

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

    }
}
