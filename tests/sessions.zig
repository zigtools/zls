const std = @import("std");
const headerPkg = @import("header");

const suffix = if (std.builtin.os.tag == .windows) ".exe" else "";
const allocator = std.heap.page_allocator;

const initialize_msg =
    \\{"processId":6896,"clientInfo":{"name":"vscode","version":"1.46.1"},"rootPath":null,"rootUri":null,"capabilities":{"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional"},"didChangeConfiguration":{"dynamicRegistration":true},"didChangeWatchedFiles":{"dynamicRegistration":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]}},"executeCommand":{"dynamicRegistration":true},"configuration":true,"workspaceFolders":true},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"complexDiagnosticCodeSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true},"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true}},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]}},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}}},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["comment","keyword","number","regexp","operator","namespace","type","struct","class","interface","enum","typeParameter","function","member","macro","variable","parameter","property","label"],"tokenModifiers":["declaration","documentation","static","abstract","deprecated","readonly"]}},"window":{"workDoneProgress":true}},"trace":"off","workspaceFolders":[{"uri":"file://./tests", "name":"root"}]}
;
const initialize_msg_offs =
    \\{"processId":6896,"clientInfo":{"name":"vscode","version":"1.46.1"},"rootPath":null,"rootUri":null,"capabilities":{"offsetEncoding":["utf-16", "utf-8"],"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional"},"didChangeConfiguration":{"dynamicRegistration":true},"didChangeWatchedFiles":{"dynamicRegistration":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]}},"executeCommand":{"dynamicRegistration":true},"configuration":true,"workspaceFolders":true},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"complexDiagnosticCodeSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true},"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true}},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]}},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}}},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["comment","keyword","number","regexp","operator","namespace","type","struct","class","interface","enum","typeParameter","function","member","macro","variable","parameter","property","label"],"tokenModifiers":["declaration","documentation","static","abstract","deprecated","readonly"]}},"window":{"workDoneProgress":true}},"trace":"off","workspaceFolders":null}
;

const Server = struct {
    process: *std.ChildProcess,
    request_id: u32 = 1,

    fn start(initialization: []const u8, expect: ?[]const u8) !Server {
        var server = Server{ .process = try startZls() };

        try server.request("initialize", initialization, expect);
        try server.request("initialized", "{}", null);
        return server;
    }

    fn request(
        self: *Server,
        method: []const u8,
        params: []const u8,
        expect: ?[]const u8,
    ) !void {
        self.request_id += 1;
        const req = try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","id":{},"method":"{s}","params":{s}}}
        , .{ self.request_id, method, params });

        const to_server = self.process.stdin.?.writer();
        try to_server.print("Content-Length: {}\r\n\r\n", .{req.len});
        try to_server.writeAll(req);

        const expected = expect orelse return;
        var from_server = self.process.stdout.?.reader();

        while (true) {
            const header = headerPkg.readRequestHeader(allocator, from_server) catch |err| {
                switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                }
            };
            defer header.deinit(allocator);
            var resonse_bytes = try allocator.alloc(u8, header.content_length);
            defer allocator.free(resonse_bytes);
            if ((try from_server.readAll(resonse_bytes)) != header.content_length) {
                return error.InvalidResponse;
            }
            // std.debug.print("{s}\n", .{resonse_bytes});

            const json_fmt = "{\"jsonrpc\":\"2.0\",\"id\":";
            if (!std.mem.startsWith(u8, resonse_bytes, json_fmt)) {
                try extractError(resonse_bytes);
                continue;
            }

            const rest = resonse_bytes[json_fmt.len..];
            const id_end = std.mem.indexOfScalar(u8, rest, ',') orelse return error.InvalidResponse;

            const id = try std.fmt.parseInt(u32, rest[0..id_end], 10);

            if (id != self.request_id) {
                continue;
            }

            const result = ",\"result\":";
            const msg = rest[id_end + result.len .. rest.len - 1];

            if (std.mem.eql(u8, msg, expected)) {
                return;
            } else {
                const mismatch = std.mem.indexOfDiff(u8, expected, msg) orelse 0;
                std.debug.print("==> Expected:\n{s}\n==> Got: (Mismatch in position {})\n{s}\n", .{ expected, mismatch, msg });
                return error.InvalidResponse;
            }
        }
    }
    fn extractError(msg: []const u8) !void {
        const log_request =
            \\"method":"window/logMessage","params":{"type":
        ;
        if (std.mem.indexOf(u8, msg, log_request)) |log_msg| {
            const rest = msg[log_msg + log_request.len ..];
            const level = rest[0];
            if (level <= '2') {
                std.debug.print("{s}\n", .{rest[13 .. rest.len - 3]});
                if (level <= '1') {
                    return error.ServerError;
                }
            }
        }
    }

    fn shutdown(self: *Server) void {
        self.request("shutdown", "{}", null) catch @panic("Could not send shutdown request");
        waitNoError(self.process) catch |err| @panic("Server error");
        self.process.deinit();
    }
};
fn startZls() !*std.ChildProcess {
    std.debug.print("\n", .{});

    var process = try std.ChildProcess.init(&[_][]const u8{"zig-cache/bin/zls" ++ suffix}, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe; //std.ChildProcess.StdIo.Inherit;

    process.spawn() catch |err| {
        std.debug.print("Failed to spawn zls process, error: {}\n", .{err});
        return err;
    };

    return process;
}
fn waitNoError(process: *std.ChildProcess) !void {
    const stderr = std.io.getStdErr().writer();
    const err_in = process.stderr.?.reader();
    var buf: [4096]u8 = undefined;
    while (true) {
        const line = err_in.readUntilDelimiterOrEof(&buf, '\n') catch |err| switch (err) {
            error.StreamTooLong => {
                std.debug.print("skipping very long line\n", .{});
                continue;
            },
            else => return err,
        } orelse break;

        if (std.mem.startsWith(u8, line, "[debug")) continue;

        try stderr.writeAll(line);
        try stderr.writeByte('\n');
    }
    const result = try process.wait();

    switch (result) {
        .Exited => |code| if (code == 0) {
            return;
        },
        else => {},
    }
    return error.ShutdownWithError;
}

test "Open file, ask for semantic tokens" {
    var server = try Server.start(initialize_msg, null);
    defer server.shutdown();

    try server.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file://./tests/test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");"}}
    , null);
    try server.request("textDocument/semanticTokens/full",
        \\{"textDocument":{"uri":"file://./tests/test.zig"}}
    ,
        \\{"data":[0,0,5,7,0,0,6,3,0,33,0,4,1,11,0,0,2,7,12,0,0,8,5,9,0]}
    );
}

test "Request completion in an empty file" {
    var server = try Server.start(initialize_msg, null);
    defer server.shutdown();

    try server.request("textDocument/didOpen",
        \\{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":""}}}
    , null);
    try server.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":0,"character":0}}
    , null);
}

test "Request completion with no trailing whitespace" {
    var server = try Server.start(initialize_msg, null);
    defer server.shutdown();

    try server.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");\nc"}}
    , null);
    try server.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}
    ,
        \\{"isIncomplete":false,"items":[{"label":"std","kind":21,"textEdit":null,"filterText":null,"insertText":"std","insertTextFormat":1,"detail":"const std = @import(\"std\")","documentation":null}]}
    );
}

test "Request utf-8 offset encoding" {
    var server = try Server.start(initialize_msg_offs,
        \\{"offsetEncoding":"utf-8","capabilities":{"signatureHelpProvider":{"triggerCharacters":["("],"retriggerCharacters":[","]},"textDocumentSync":1,"renameProvider":true,"completionProvider":{"resolveProvider":false,"triggerCharacters":[".",":","@"]},"documentHighlightProvider":false,"hoverProvider":true,"codeActionProvider":false,"declarationProvider":true,"definitionProvider":true,"typeDefinitionProvider":true,"implementationProvider":false,"referencesProvider":true,"documentSymbolProvider":true,"colorProvider":false,"documentFormattingProvider":true,"documentRangeFormattingProvider":false,"foldingRangeProvider":false,"selectionRangeProvider":false,"workspaceSymbolProvider":false,"rangeProvider":false,"documentProvider":true,"workspace":{"workspaceFolders":{"supported":false,"changeNotifications":false}},"semanticTokensProvider":{"full":true,"range":false,"legend":{"tokenTypes":["type","parameter","variable","enumMember","field","errorTag","function","keyword","comment","string","number","operator","builtin","label","keywordLiteral"],"tokenModifiers":["namespace","struct","enum","union","opaque","declaration","async","documentation","generic"]}}},"serverInfo":{"name":"zls","version":"0.1.0"}}
    );
    server.shutdown();
}
