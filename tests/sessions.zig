const std = @import("std");
const headerPkg = @import("header");

const suffix = if (std.builtin.os.tag == .windows) ".exe" else "";
const allocator = std.heap.page_allocator;

const initialize_message = \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"processId":6896,"clientInfo":{"name":"vscode","version":"1.46.1"},"rootPath":null,"rootUri":null,"capabilities":{"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional"},"didChangeConfiguration":{"dynamicRegistration":true},"didChangeWatchedFiles":{"dynamicRegistration":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]}},"executeCommand":{"dynamicRegistration":true},"configuration":true,"workspaceFolders":true},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"complexDiagnosticCodeSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true},"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true}},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]}},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}}},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["comment","keyword","number","regexp","operator","namespace","type","struct","class","interface","enum","typeParameter","function","member","macro","variable","parameter","property","label"],"tokenModifiers":["declaration","documentation","static","abstract","deprecated","readonly"]}},"window":{"workDoneProgress":true}},"trace":"off","workspaceFolders":[{"uri":"file://./tests", "name":"root"}]}}
;

const initialized_message = \\{"jsonrpc":"2.0","method":"initialized","params":{}}
;

const shutdown_message = \\{"jsonrpc":"2.0", "id":"STDWN", "method":"shutdown","params":{}}
;

fn sendRequest(req: []const u8, process: *std.ChildProcess) !void {
    try process.stdin.?.writer().print("Content-Length: {}\r\n\r\n", .{req.len});
    try process.stdin.?.writeAll(req);
}

fn readResponses(process: *std.ChildProcess, expected_responses: anytype) !void {
    var seen = std.mem.zeroes([expected_responses.len]bool);
    while (true) {
        const header = headerPkg.readRequestHeader(allocator, process.stdout.?.reader()) catch |err| {
            switch(err) {
                error.EndOfStream => break,
                else => return err,
            }
        };
        defer header.deinit(allocator);

        var stdout_mem = try allocator.alloc(u8, header.content_length);
        defer allocator.free(stdout_mem);

        const stdout_bytes = stdout_mem[0..try process.stdout.?.reader().readAll(stdout_mem)];
        inline for (expected_responses) |resp, idx| {
            if (std.mem.eql(u8, resp, stdout_bytes)) {
                if (seen[idx]) @panic("Expected response already received.");
                seen[idx] = true;
            }
        }
        std.debug.print("GOT MESSAGE: {}\n", .{stdout_bytes});
    }

    comptime var idx = 0;
    inline while (idx < expected_responses.len) : (idx += 1) {
        if (!seen[idx]) {
            std.debug.print("Response `{}` not received.", .{expected_responses[idx]});
            return error.ExpectedResponse;
        }
    }
}

fn startZls() !*std.ChildProcess {
    var process = try std.ChildProcess.init(&[_][]const u8{ "zig-cache/bin/zls" ++ suffix }, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = std.ChildProcess.StdIo.Inherit;

    process.spawn() catch |err| {
        std.log.debug(.main, "Failed to spawn zls process, error: {}\n", .{err});
        return err;
    };

    return process;
}

fn waitNoError(process: *std.ChildProcess) !void {
    const result = try process.wait();
    switch (result) {
        .Exited => |code| if (code == 0) {
            return;
        },
        else => {},
    }
    return error.ShutdownWithError;
}

fn consumeOutputAndWait(process: *std.ChildProcess, expected_responses: anytype) !void {
    process.stdin.?.close();
    process.stdin = null;
    try readResponses(process, expected_responses);
    try waitNoError(process);
    process.deinit();
}

test "Open file, ask for semantic tokens" {
    var process = try startZls();
    try sendRequest(initialize_message, process);
    try sendRequest(initialized_message, process);

    const new_file_req = \\{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file://./tests/test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");"}}}
    ;
    try sendRequest(new_file_req, process);
    const sem_toks_req = \\{"jsonrpc":"2.0","id":2,"method":"textDocument/semanticTokens","params":{"textDocument":{"uri":"file://./tests/test.zig"}}}
    ;
    try sendRequest(sem_toks_req, process);
    try sendRequest(shutdown_message, process);
    try consumeOutputAndWait(process, .{
        \\{"jsonrpc":"2.0","id":2,"result":{"data":[0,0,5,11,0,0,6,3,0,1,0,4,1,15,0,0,2,7,16,0,0,8,5,13,0]}}
    });
}

test "Requesting a completion in an empty file" {
    var process = try startZls();
    try sendRequest(initialize_message, process);
    try sendRequest(initialized_message, process);

    const new_file_req = \\{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":""}}}
    ;
    try sendRequest(new_file_req, process);
    const completion_req = \\{"jsonrpc":"2.0","id":2,"method":"textDocument/completion","params":{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":0,"character":0}}}
    ;
    try sendRequest(completion_req, process);
    try sendRequest(shutdown_message, process);
    try consumeOutputAndWait(process, .{});
}

test "Requesting a completion with no trailing whitespace" {
    var process = try startZls();
    try sendRequest(initialize_message, process);
    try sendRequest(initialized_message, process);

    const new_file_req = \\{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");\nc"}}}
    ;
    try sendRequest(new_file_req, process);
    const completion_req = \\{"jsonrpc":"2.0","id":2,"method":"textDocument/completion","params":{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}}
    ;
    try sendRequest(completion_req, process);
    try sendRequest(shutdown_message, process);
    try consumeOutputAndWait(process, .{
        \\{"jsonrpc":"2.0","id":2,"result":{"isIncomplete":false,"items":[]}}
    });
}

const initialize_message_offs = \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"processId":6896,"clientInfo":{"name":"vscode","version":"1.46.1"},"rootPath":null,"rootUri":null,"capabilities":{"offsetEncoding":["utf-16", "utf-8"],"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional"},"didChangeConfiguration":{"dynamicRegistration":true},"didChangeWatchedFiles":{"dynamicRegistration":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]}},"executeCommand":{"dynamicRegistration":true},"configuration":true,"workspaceFolders":true},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"complexDiagnosticCodeSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true},"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true}},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]}},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}}},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["comment","keyword","number","regexp","operator","namespace","type","struct","class","interface","enum","typeParameter","function","member","macro","variable","parameter","property","label"],"tokenModifiers":["declaration","documentation","static","abstract","deprecated","readonly"]}},"window":{"workDoneProgress":true}},"trace":"off","workspaceFolders":null}}
;

test "Requesting utf-8 offset encoding" {
    var process = try startZls();
    try sendRequest(initialize_message_offs, process);
    try sendRequest(initialized_message, process);

    try sendRequest(shutdown_message, process);
    try consumeOutputAndWait(process, .{
        \\{"jsonrpc":"2.0","id":0,"result": {"offsetEncoding":"utf-8","capabilities": {"signatureHelpProvider": {"triggerCharacters": ["(",","]},"textDocumentSync": 1,"renameProvider":true,"completionProvider": {"resolveProvider": false,"triggerCharacters": [".",":","@"]},"documentHighlightProvider": false,"hoverProvider": true,"codeActionProvider": false,"declarationProvider": true,"definitionProvider": true,"typeDefinitionProvider": true,"implementationProvider": false,"referencesProvider": true,"documentSymbolProvider": true,"colorProvider": false,"documentFormattingProvider": true,"documentRangeFormattingProvider": false,"foldingRangeProvider": false,"selectionRangeProvider": false,"workspaceSymbolProvider": false,"rangeProvider": false,"documentProvider": true,"workspace": {"workspaceFolders": {"supported": true,"changeNotifications": true}},"semanticTokensProvider": {"documentProvider": true,"legend": {"tokenTypes": ["namespace","type","struct","enum","union","parameter","variable","tagField","field","errorTag","function","keyword","comment","string","number","operator","builtin","label"],"tokenModifiers": ["definition","async","documentation", "generic"]}}}}}
    });
}
