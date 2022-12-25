const std = @import("std");
const zls = @import("zls");

const Header = zls.Header;
const Config = zls.Config;
const Server = zls.Server;
const types = zls.types;

const initialize_msg =
    \\{"processId":0,"clientInfo":{"name":"Visual Studio Code","version":"1.73.1"},"capabilities":{"workspace":{"applyEdit":true,"workspaceEdit":{"documentChanges":true,"resourceOperations":["create","rename","delete"],"failureHandling":"textOnlyTransactional","normalizesLineEndings":true,"changeAnnotationSupport":{"groupsOnLabel":true}},"configuration":true,"didChangeWatchedFiles":{"dynamicRegistration":true,"relativePatternSupport":true},"symbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"tagSupport":{"valueSet":[1]},"resolveSupport":{"properties":["location.range"]}},"codeLens":{"refreshSupport":true},"executeCommand":{"dynamicRegistration":true},"didChangeConfiguration":{"dynamicRegistration":true},"workspaceFolders":true,"semanticTokens":{"refreshSupport":true},"fileOperations":{"dynamicRegistration":true,"didCreate":true,"didRename":true,"didDelete":true,"willCreate":true,"willRename":true,"willDelete":true},"inlineValue":{"refreshSupport":true},"inlayHint":{"refreshSupport":true},"diagnostics":{"refreshSupport":true}},"textDocument":{"publishDiagnostics":{"relatedInformation":true,"versionSupport":false,"tagSupport":{"valueSet":[1,2]},"codeDescriptionSupport":true,"dataSupport":true},"synchronization":{"dynamicRegistration":true,"willSave":true,"willSaveWaitUntil":true,"didSave":true},"completion":{"dynamicRegistration":true,"contextSupport":true,"completionItem":{"snippetSupport":true,"commitCharactersSupport":true,"documentationFormat":["markdown","plaintext"],"deprecatedSupport":true,"preselectSupport":true,"tagSupport":{"valueSet":[1]},"insertReplaceSupport":true,"resolveSupport":{"properties":["documentation","detail","additionalTextEdits"]},"insertTextModeSupport":{"valueSet":[1,2]},"labelDetailsSupport":true},"insertTextMode":2,"completionItemKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]},"completionList":{"itemDefaults":["commitCharacters","editRange","insertTextFormat","insertTextMode"]}},"hover":{"dynamicRegistration":true,"contentFormat":["markdown","plaintext"]},"signatureHelp":{"dynamicRegistration":true,"signatureInformation":{"documentationFormat":["markdown","plaintext"],"parameterInformation":{"labelOffsetSupport":true},"activeParameterSupport":true},"contextSupport":true},"definition":{"dynamicRegistration":true,"linkSupport":true},"references":{"dynamicRegistration":true},"documentHighlight":{"dynamicRegistration":true},"documentSymbol":{"dynamicRegistration":true,"symbolKind":{"valueSet":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},"hierarchicalDocumentSymbolSupport":true,"tagSupport":{"valueSet":[1]},"labelSupport":true},"codeAction":{"dynamicRegistration":true,"isPreferredSupport":true,"disabledSupport":true,"dataSupport":true,"resolveSupport":{"properties":["edit"]},"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["","quickfix","refactor","refactor.extract","refactor.inline","refactor.rewrite","source","source.organizeImports"]}},"honorsChangeAnnotations":false},"codeLens":{"dynamicRegistration":true},"formatting":{"dynamicRegistration":true},"rangeFormatting":{"dynamicRegistration":true},"onTypeFormatting":{"dynamicRegistration":true},"rename":{"dynamicRegistration":true,"prepareSupport":true,"prepareSupportDefaultBehavior":1,"honorsChangeAnnotations":true},"documentLink":{"dynamicRegistration":true,"tooltipSupport":true},"typeDefinition":{"dynamicRegistration":true,"linkSupport":true},"implementation":{"dynamicRegistration":true,"linkSupport":true},"colorProvider":{"dynamicRegistration":true},"foldingRange":{"dynamicRegistration":true,"rangeLimit":5000,"lineFoldingOnly":true,"foldingRangeKind":{"valueSet":["comment","imports","region"]},"foldingRange":{"collapsedText":false}},"declaration":{"dynamicRegistration":true,"linkSupport":true},"selectionRange":{"dynamicRegistration":true},"callHierarchy":{"dynamicRegistration":true},"semanticTokens":{"dynamicRegistration":true,"tokenTypes":["namespace","type","class","enum","interface","struct","typeParameter","parameter","variable","property","enumMember","event","function","method","macro","keyword","modifier","comment","string","number","regexp","operator","decorator"],"tokenModifiers":["declaration","definition","readonly","static","deprecated","abstract","async","modification","documentation","defaultLibrary"],"formats":["relative"],"requests":{"range":true,"full":{"delta":true}},"multilineTokenSupport":false,"overlappingTokenSupport":false,"serverCancelSupport":true,"augmentsSyntaxTokens":true},"linkedEditingRange":{"dynamicRegistration":true},"typeHierarchy":{"dynamicRegistration":true},"inlineValue":{"dynamicRegistration":true},"inlayHint":{"dynamicRegistration":true,"resolveSupport":{"properties":["tooltip","textEdits","label.tooltip","label.location","label.command"]}},"diagnostic":{"dynamicRegistration":true,"relatedDocumentSupport":false}},"window":{"showMessage":{"messageActionItem":{"additionalPropertiesSupport":true}},"showDocument":{"support":true},"workDoneProgress":true},"general":{"staleRequestSupport":{"cancel":true,"retryOnContentModified":["textDocument/semanticTokens/full","textDocument/semanticTokens/range","textDocument/semanticTokens/full/delta"]},"regularExpressions":{"engine":"ECMAScript","version":"ES2020"},"markdown":{"parser":"marked","version":"1.1.0"},"positionEncodings":["utf-16"]},"notebookDocument":{"synchronization":{"dynamicRegistration":true,"executionSummarySupport":true}}}}
;

const default_config: Config = .{
    .enable_ast_check_diagnostics = false,
    .enable_semantic_tokens = true,
    .enable_inlay_hints = true,
    .inlay_hints_exclude_single_argument = false,
    .inlay_hints_show_builtin = true,
};

const allocator = std.testing.allocator;

pub const Context = struct {
    server: Server,
    config: *Config,
    request_id: u32 = 1,

    pub fn init() !Context {
        var config = try allocator.create(Config);
        errdefer allocator.destroy(config);

        config.* = default_config;

        var server = try Server.init(allocator, config, null);
        errdefer server.deinit();

        var context: Context = .{
            .server = server,
            .config = config,
        };

        try context.request("initialize", initialize_msg, null);
        try context.notification("initialized", "{}");

        // std.debug.assert(server.status == .initialized);
        return context;
    }

    pub fn deinit(self: *Context) void {
        std.json.parseFree(Config, self.config.*, .{ .allocator = allocator });
        allocator.destroy(self.config);

        self.request("shutdown", "{}", null) catch {};
        self.server.deinit();
    }

    pub fn notification(
        self: *Context,
        method: []const u8,
        params: []const u8,
    ) !void {
        var output = std.ArrayListUnmanaged(u8){};
        defer output.deinit(allocator);

        // create the request
        const req = try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","method":"{s}","params":{s}}}
        , .{ method, params });
        defer allocator.free(req);

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        //  send the request to the server
        self.server.processJsonRpc(&arena, req);

        for (self.server.outgoing_messages.items) |outgoing_message| {
            self.server.allocator.free(outgoing_message);
        }
        self.server.outgoing_messages.clearRetainingCapacity();
    }

    pub fn requestAlloc(
        self: *Context,
        method: []const u8,
        params: []const u8,
    ) ![]const u8 {
        // create the request
        self.request_id += 1;
        const req = try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","id":{},"method":"{s}","params":{s}}}
        , .{ self.request_id, method, params });
        defer allocator.free(req);

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        //  send the request to the server
        self.server.processJsonRpc(&arena, req);
        
        const messages = self.server.outgoing_messages.items;

        try std.testing.expect(messages.len != 0);

        for(messages[0..(messages.len - 1)]) |message| {
            self.server.allocator.free(message);
        }
        defer self.server.outgoing_messages.clearRetainingCapacity();

        return messages[messages.len - 1];
    }

    pub fn request(
        self: *Context,
        method: []const u8,
        params: []const u8,
        expect: ?[]const u8,
    ) !void {
        const response_bytes = try self.requestAlloc(method, params);
        defer self.server.allocator.free(response_bytes);

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

    // helper
    pub fn requestDidOpen(self: *Context, uri: []const u8, source: []const u8) !void {
        const open_document = types.DidOpenTextDocumentParams{
            .textDocument = .{
                .uri = uri,
                .languageId = "zig",
                .version = 420,
                .text = source,
            },
        };
        const params = try std.json.stringifyAlloc(allocator, open_document, .{});
        defer allocator.free(params);
        try self.notification("textDocument/didOpen", params);
    }

    pub fn Response(comptime Result: type) type {
        return struct {
            jsonrpc: []const u8,
            id: types.RequestId,
            result: Result,

            pub fn deinit(self: @This()) void {
                const parse_options = std.json.ParseOptions{
                    .allocator = allocator,
                    .ignore_unknown_fields = true,
                };
                std.json.parseFree(@This(), self, parse_options);
            }
        };
    }

    pub fn requestGetResponse(self: *Context, comptime Result: type, method: []const u8, params: anytype) !Response(Result) {
        const json_params = try std.json.stringifyAlloc(allocator, params, .{});
        defer allocator.free(json_params);

        const response_bytes = try self.requestAlloc(method, json_params);
        defer self.server.allocator.free(response_bytes);

        const parse_options = std.json.ParseOptions{
            .allocator = allocator,
            .ignore_unknown_fields = true,
        };

        var token_stream = std.json.TokenStream.init(response_bytes);
        const response = try std.json.parse(Response(Result), &token_stream, parse_options);
        errdefer std.json.parseFree(Response(Result), response, parse_options);

        // TODO validate jsonrpc and id

        return response;
    }
};
