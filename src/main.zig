const std = @import("std");
const Uri = @import("uri.zig");

// Code is largely based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

var stdout: std.fs.File.OutStream = undefined;
var allocator: *std.mem.Allocator = undefined;

const initialize_response = \\,"result":{"capabilities":{"signatureHelpProvider":{"triggerCharacters":["(",","]},"textDocumentSync":1,"completionProvider":{"resolveProvider":false,"triggerCharacters":[".",":"]},"documentHighlightProvider":false,"codeActionProvider":false,"workspace":{"workspaceFolders":{"supported":true}}}}}
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

pub fn log(comptime fmt: []const u8, args: var) !void {
    // Don't need much memory for log messages. This is a bad approach, but it's quick and easy and I wrote this code in ~1 minute.
    var buffer: []u8 = try allocator.alloc(u8, 100);
    defer allocator.free(buffer);
    var bstream = std.io.fixedBufferStream(buffer);
    var stream = bstream.outStream();

    _ = try stream.write(
        \\{"jsonrpc":"2.0","method":"window/logMessage","params":{"type": 4, "message": "
    );
    _ = try stream.print(fmt, args);
    _ = try stream.write(
        \\"}}
    );

    _ = try stdout.print("Content-Length: {}\r\n\r\n", .{bstream.pos});
    _ = try stdout.write(bstream.getWritten());
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

pub fn processSource(uri: []const u8, source: []const u8) !void {

    try log("An error, cool", .{});

    const tree = try std.zig.parse(allocator, source);
    defer tree.deinit();

    var buffer: []u8 = try allocator.alloc(u8, 4096);
    defer allocator.free(buffer);
    // var buffer = try std.ArrayListSentineled(u8, 0).initSize(allocator, 0);
    // defer buffer.deinit();
    var bstream = std.io.fixedBufferStream(buffer);
    var stream = bstream.outStream();

    _ = try stream.write(
        \\{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":
    );
    _ = try stream.print("\"{}\",\"diagnostics\":[", .{uri});

    if (tree.errors.len > 0) {
        var index: usize = 0;
        while (index < tree.errors.len) : (index += 1) {
            
            const err = tree.errors.at(index);
            const loc = tree.tokenLocation(0, err.loc());

            _ = try stream.write(
                \\{"range":{"start":{
            );
            _ = try stream.print("\"line\":{},\"character\":{}", .{loc.line, loc.column});
            _ = try stream.write(
                \\},"end":{
            );
            _ = try stream.print("\"line\":{},\"character\":{}", .{loc.line, loc.column});
            _ = try stream.write(
                \\}},"severity":1,"source":"zig-lsp","message":"
            );
            _ = try tree.renderError(err, stream);
            _ = try stream.print("\",\"code\":\"{}\"", .{@tagName(err.*)});
            _ = try stream.write(
                \\,"relatedInformation":[]}
            );
            if (index != tree.errors.len - 1) {
                _ = try stream.writeByte(',');
            }

        }
    }

    _ = try stream.write(
        \\]}}
    );

    _ = try stdout.print("Content-Length: {}\r\n\r\n", .{bstream.pos});
    _ = try stdout.write(bstream.getWritten());

}

// pub fn signature

pub fn processJsonRpc(json: []const u8) !void {

    var parser = std.json.Parser.init(allocator, false);
    var tree = try parser.parse(json);
    defer tree.deinit();

    const root = tree.root;

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

        try processSource(uri, text);
    } else if (std.mem.eql(u8, method, "textDocument/didChange")) {
        const document = params.getValue("textDocument").?.Object;
        const uri = document.getValue("uri").?.String;
        const text = params.getValue("contentChanges").?.Array.items[0].Object.getValue("text").?.String;

        try processSource(uri, text);
    } else if (std.mem.eql(u8, method, "textDocument/didSave")) {
        // noop
    } else if (std.mem.eql(u8, method, "textDocument/didClose")) {
        // noop
    }
    // Autocomplete / Signatures
    else if (std.mem.eql(u8, method, "textDocument/completion")) {
        try respondGeneric(id, no_completions_response);
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
    } else if (root.Object.getValue("id")) |_| {
        try log("Method with return value not implemented: {}", .{method});
        try respondGeneric(id, not_implemented_response);
    } else {
        try log("Method without return value not implemented: {}", .{method});
    }

}

pub fn main() anyerror!void {

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    allocator = &arena.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.resize(4096);

    const stdin = std.io.getStdIn().inStream();
    stdout = std.io.getStdOut().outStream();

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
