const std = @import("std");
const zls = @import("zls");

const headerPkg = zls.header;
const Server = zls.Server;

const initialize_msg =
    \\{"processId":6896,"clientInfo":{"name":"vscode","version":"1.46.1"},"rootPath":null,"rootUri":null,"capabilities":{"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional"},"didChangeConfiguration":{"dynamicRegistration":true},"didChangeWatchedFiles":{"dynamicRegistration":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]}},"executeCommand":{"dynamicRegistration":true},"configuration":true,"workspaceFolders":true},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"complexDiagnosticCodeSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true},"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true}},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]}},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}}},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["comment","keyword","number","regexp","operator","namespace","type","struct","class","interface","enum","typeParameter","function","member","macro","variable","parameter","property","label"],"tokenModifiers":["declaration","documentation","static","abstract","deprecated","readonly"]}},"window":{"workDoneProgress":true}},"trace":"off","workspaceFolders":[{"uri":"file://./tests", "name":"root"}]}
;

const allocator = std.testing.allocator;

pub const Context = struct {
    server: Server,
    request_id: u32 = 1,

    pub fn init() !Context {
        var context = Context{
            .server = try Server.init(
                allocator,
                .{
                    .enable_ast_check_diagnostics = false,
                    .enable_semantic_tokens = true,
                    .enable_inlay_hints = true,
                    .inlay_hints_exclude_single_argument = false,
                    .inlay_hints_show_builtin = true,
                },
                null,
                .debug,
            ),
        };

        try context.request("initialize", initialize_msg, null);
        try context.request("initialized", "{}", null);
        return context;
    }

    pub fn deinit(self: *Context) void {
        self.request("shutdown", "{}", null) catch {};
        self.server.deinit();
    }

    pub fn requestAlloc(
        self: *Context,
        method: []const u8,
        params: []const u8,
    ) ![]const u8 {
        var output = std.ArrayListUnmanaged(u8){};
        defer output.deinit(allocator);

        // create the request
        self.request_id += 1;
        const req = try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","id":{},"method":"{s}","params":{s}}}
        , .{ self.request_id, method, params });
        defer allocator.free(req);

        //  send the request to the server
        try self.server.processJsonRpc(output.writer(allocator), req);

        // get the output from the server
        var buffer_stream = std.io.fixedBufferStream(output.items);
        const header = try headerPkg.readRequestHeader(allocator, buffer_stream.reader());
        defer header.deinit(allocator);

        var response_bytes = try allocator.alloc(u8, header.content_length);
        errdefer allocator.free(response_bytes);

        const content_length = try buffer_stream.reader().readAll(response_bytes);
        try std.testing.expectEqual(content_length, header.content_length);

        return response_bytes;
    }

    pub fn request(
        self: *Context,
        method: []const u8,
        params: []const u8,
        expect: ?[]const u8,
    ) !void {
        const response_bytes = try self.requestAlloc(method, params);
        defer allocator.free(response_bytes);

        const expected = expect orelse return;

        // parse the response
        var parser = std.json.Parser.init(allocator, false);
        defer parser.deinit();

        var tree = try parser.parse(response_bytes);
        defer tree.deinit();

        const response = tree.root.Object;

        // assertions
        try std.testing.expectEqualStrings("2.0", response.get("jsonrpc").?.String);
        try std.testing.expectEqual(self.request_id, @intCast(u32, response.get("id").?.Integer));
        try std.testing.expect(!response.contains("error"));

        const result_json = try std.json.stringifyAlloc(allocator, response.get("result").?, .{});
        defer allocator.free(result_json);

        try std.testing.expectEqualStrings(expected, result_json);
    }
};
