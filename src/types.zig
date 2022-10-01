const std = @import("std");
const string = []const u8;

// LSP types
// https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/

pub const Position = struct {
    line: u32,
    character: u32,
};

pub const Range = struct {
    start: Position,
    end: Position,
};

pub const Location = struct {
    uri: string,
    range: Range,
};

/// Id of a request
pub const RequestId = union(enum) {
    String: string,
    Integer: i32,
};

/// Params of a response (result)
pub const ResponseParams = union(enum) {
    SignatureHelp: SignatureHelp,
    CompletionList: CompletionList,
    Location: Location,
    Hover: Hover,
    DocumentSymbols: []DocumentSymbol,
    SemanticTokensFull: SemanticTokens,
    InlayHint: []InlayHint,
    TextEdits: []TextEdit,
    Locations: []Location,
    WorkspaceEdit: WorkspaceEdit,
    InitializeResult: InitializeResult,
    ConfigurationParams: ConfigurationParams,
    RegistrationParams: RegistrationParams,
    DocumentHighlight: []DocumentHighlight,
    CodeAction: []CodeAction,
    ApplyEdit: ApplyWorkspaceEditParams,
};

pub const Response = struct {
    jsonrpc: string = "2.0",
    id: RequestId,
    result: ResponseParams,
};

pub const Request = struct {
    jsonrpc: string = "2.0",
    id: RequestId,
    method: []const u8,
    params: ?ResponseParams,
};

pub const ResponseError = struct {
    code: i32,
    message: string,
    data: std.json.Value,
};

pub const ErrorCodes = enum(i32) {
    // Defined by JSON-RPC
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,

    // JSON-RPC reserved error codes
    ServerNotInitialized = -32002,
    UnknownErrorCode = -3200,

    // LSP reserved error codes
    RequestFailed = -32803,
    ServerCancelled = -32802,
    ContentModified = -32801,
    RequestCancelled = -32800,
};

pub const Notification = struct {
    jsonrpc: string = "2.0",
    method: string,
    params: NotificationParams,
};

pub const NotificationParams = union(enum) {
    LogMessage: struct {
        type: MessageType,
        message: string,
    },
    PublishDiagnostics: struct {
        uri: string,
        diagnostics: []Diagnostic,
    },
    ShowMessage: struct {
        type: MessageType,
        message: string,
    },
};

/// Type of a debug message
pub const MessageType = enum(i64) {
    Error = 1,
    Warning = 2,
    Info = 3,
    Log = 4,

    pub fn jsonStringify(value: MessageType, options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const DiagnosticSeverity = enum(i64) {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,

    pub fn jsonStringify(value: DiagnosticSeverity, options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const DiagnosticRelatedInformation = struct {
    location: Location,
    message: string,
};

pub const Diagnostic = struct {
    range: Range,
    severity: ?DiagnosticSeverity,
    code: ?string,
    source: ?string,
    message: string,
    relatedInformation: ?[]DiagnosticRelatedInformation = null,
};

pub const WorkspaceEdit = struct {
    changes: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(TextEdit)),

    pub fn jsonStringify(self: WorkspaceEdit, options: std.json.StringifyOptions, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll("{\"changes\": {");
        var it = self.changes.iterator();
        var idx: usize = 0;
        while (it.next()) |entry| : (idx += 1) {
            if (idx != 0) try writer.writeAll(", ");

            try writer.writeByte('"');
            try writer.writeAll(entry.key_ptr.*);
            try writer.writeAll("\":");
            try std.json.stringify(entry.value_ptr.items, options, writer);
        }
        try writer.writeAll("}}");
    }
};

pub const TextEdit = struct {
    range: Range,
    newText: string,
};

pub const MarkupContent = struct {
    pub const Kind = enum(u1) {
        PlainText = 0,
        Markdown = 1,

        pub fn jsonStringify(value: Kind, options: std.json.StringifyOptions, out_stream: anytype) !void {
            const str = switch (value) {
                .PlainText => "plaintext",
                .Markdown => "markdown",
            };
            try std.json.stringify(str, options, out_stream);
        }
    };

    kind: Kind = .Markdown,
    value: string,
};

pub const CompletionList = struct {
    isIncomplete: bool,
    items: []const CompletionItem,
};

pub const InsertTextFormat = enum(i64) {
    PlainText = 1,
    Snippet = 2,

    pub fn jsonStringify(value: InsertTextFormat, options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const Hover = struct {
    contents: MarkupContent,
};

pub const SemanticTokens = struct {
    data: []const u32,
};

pub const CompletionItem = struct {
    pub const Kind = enum(i64) {
        Text = 1,
        Method = 2,
        Function = 3,
        Constructor = 4,
        Field = 5,
        Variable = 6,
        Class = 7,
        Interface = 8,
        Module = 9,
        Property = 10,
        Unit = 11,
        Value = 12,
        Enum = 13,
        Keyword = 14,
        Snippet = 15,
        Color = 16,
        File = 17,
        Reference = 18,
        Folder = 19,
        EnumMember = 20,
        Constant = 21,
        Struct = 22,
        Event = 23,
        Operator = 24,
        TypeParameter = 25,

        pub fn jsonStringify(value: Kind, options: std.json.StringifyOptions, out_stream: anytype) !void {
            try std.json.stringify(@enumToInt(value), options, out_stream);
        }
    };

    label: string,
    labelDetails: ?CompletionItemLabelDetails = null,
    kind: Kind,
    detail: ?string = null,

    sortText: ?string = null,
    filterText: ?string = null,
    insertText: ?string = null,

    insertTextFormat: ?InsertTextFormat = .PlainText,
    documentation: ?MarkupContent = null,

    // FIXME: i commented this out, because otherwise the vscode client complains about *ranges*
    // and breaks code completion entirely
    // see: https://github.com/zigtools/zls-vscode/pull/33
    // textEdit: ?TextEdit = null,
};

pub const CompletionItemLabelDetails = struct {
    detail: ?string,
    description: ?string,
    sortText: ?string = null,
};

pub const DocumentSymbol = struct {
    const Kind = enum(u32) {
        File = 1,
        Module = 2,
        Namespace = 3,
        Package = 4,
        Class = 5,
        Method = 6,
        Property = 7,
        Field = 8,
        Constructor = 9,
        Enum = 10,
        Interface = 11,
        Function = 12,
        Variable = 13,
        Constant = 14,
        String = 15,
        Number = 16,
        Boolean = 17,
        Array = 18,
        Object = 19,
        Key = 20,
        Null = 21,
        EnumMember = 22,
        Struct = 23,
        Event = 24,
        Operator = 25,
        TypeParameter = 26,

        pub fn jsonStringify(value: Kind, options: std.json.StringifyOptions, out_stream: anytype) !void {
            try std.json.stringify(@enumToInt(value), options, out_stream);
        }
    };

    name: string,
    detail: ?string = null,
    kind: Kind,
    deprecated: bool = false,
    range: Range,
    selectionRange: Range,
    children: []const DocumentSymbol = &[_]DocumentSymbol{},
};

pub const WorkspaceFolder = struct {
    uri: string,
    name: string,
};

pub const SignatureInformation = struct {
    pub const ParameterInformation = struct {
        // TODO Can also send a pair of encoded offsets
        label: string,
        documentation: ?MarkupContent,
    };

    label: string,
    documentation: ?MarkupContent,
    parameters: ?[]const ParameterInformation,
    activeParameter: ?u32,
};

pub const SignatureHelp = struct {
    signatures: ?[]const SignatureInformation,
    activeSignature: ?u32,
    activeParameter: ?u32,
};

pub const InlayHint = struct {
    position: Position,
    label: string,
    kind: InlayHintKind,
    tooltip: MarkupContent,
    paddingLeft: bool,
    paddingRight: bool,

    // appends a colon to the label and reduces the output size
    pub fn jsonStringify(value: InlayHint, options: std.json.StringifyOptions, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll("{\"position\":");
        try std.json.stringify(value.position, options, writer);
        try writer.writeAll(",\"label\":\"");
        try writer.writeAll(value.label);
        try writer.writeAll(":\",\"kind\":");
        try std.json.stringify(value.kind, options, writer);
        if (value.tooltip.value.len != 0) {
            try writer.writeAll(",\"tooltip\":");
            try std.json.stringify(value.tooltip, options, writer);
        }
        if (value.paddingLeft) try writer.writeAll(",\"paddingLeft\":true");
        if (value.paddingRight) try writer.writeAll(",\"paddingRight\":true");
        try writer.writeByte('}');
    }
};

pub const InlayHintKind = enum(i64) {
    Type = 1,
    Parameter = 2,

    pub fn jsonStringify(value: InlayHintKind, options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const CodeActionKind = enum {
    Empty,
    QuickFix,
    Refactor,
    RefactorExtract,
    RefactorInline,
    RefactorRewrite,
    Source,
    SourceOrganizeImports,
    SourceFixAll,

    pub fn jsonStringify(value: CodeActionKind, options: std.json.StringifyOptions, out_stream: anytype) !void {
        const name = switch (value) {
            .Empty => "",
            .QuickFix => "quickfix",
            .Refactor => "refactor",
            .RefactorExtract => "refactor.extract",
            .RefactorInline => "refactor.inline",
            .RefactorRewrite => "refactor.rewrite",
            .Source => "source",
            .SourceOrganizeImports => "source.organizeImports",
            .SourceFixAll => "source.fixAll",
        };
        try std.json.stringify(name, options, out_stream);
    }
};

pub const CodeAction = struct {
    title: string,
    kind: CodeActionKind,
    // diagnostics: []Diagnostic,
    isPreferred: bool,
    edit: WorkspaceEdit,
};

pub const ApplyWorkspaceEditParams = struct {
    label: string,
    edit: WorkspaceEdit,
};

pub const PositionEncodingKind = enum {
    utf8,
    utf16,
    utf32,

    pub fn jsonStringify(value: PositionEncodingKind, options: std.json.StringifyOptions, out_stream: anytype) !void {
        const str = switch (value) {
            .utf8 => "utf-8",
            .utf16 => "utf-16",
            .utf32 => "utf-32",
        };
        try std.json.stringify(str, options, out_stream);
    }
};

const TextDocumentSyncKind = enum(u32) {
    None = 0,
    Full = 1,
    Incremental = 2,

    pub fn jsonStringify(value: @This(), options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

// Only includes options we set in our initialize result.
const InitializeResult = struct {
    capabilities: struct {
        positionEncoding: PositionEncodingKind,
        signatureHelpProvider: struct {
            triggerCharacters: []const string,
            retriggerCharacters: []const string,
        },
        textDocumentSync: struct {
            openClose: bool,
            change: TextDocumentSyncKind,
            save: bool,
        },
        renameProvider: bool,
        completionProvider: struct {
            resolveProvider: bool,
            triggerCharacters: []const string,
            completionItem: struct { labelDetailsSupport: bool },
        },
        documentHighlightProvider: bool,
        hoverProvider: bool,
        codeActionProvider: bool,
        declarationProvider: bool,
        definitionProvider: bool,
        typeDefinitionProvider: bool,
        implementationProvider: bool,
        referencesProvider: bool,
        documentSymbolProvider: bool,
        colorProvider: bool,
        documentFormattingProvider: bool,
        documentRangeFormattingProvider: bool,
        foldingRangeProvider: bool,
        selectionRangeProvider: bool,
        workspaceSymbolProvider: bool,
        rangeProvider: bool,
        documentProvider: bool,
        workspace: ?struct {
            workspaceFolders: ?struct {
                supported: bool,
                changeNotifications: bool,
            },
        },
        semanticTokensProvider: struct {
            full: bool,
            range: bool,
            legend: struct {
                tokenTypes: []const string,
                tokenModifiers: []const string,
            },
        },
        inlayHintProvider: bool,
    },
    serverInfo: struct {
        name: string,
        version: ?string = null,
    },
};

pub const ConfigurationParams = struct {
    items: []const ConfigurationItem,

    pub const ConfigurationItem = struct {
        section: ?[]const u8,
    };
};

pub const RegistrationParams = struct {
    registrations: []const Registration,

    pub const Registration = struct {
        id: string,
        method: string,

        // registerOptions?: LSPAny;
    };
};

pub const DocumentHighlightKind = enum(u8) {
    Text = 1,
    Read = 2,
    Write = 3,

    pub fn jsonStringify(value: DocumentHighlightKind, options: std.json.StringifyOptions, out_stream: anytype) !void {
        try std.json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const DocumentHighlight = struct {
    range: Range,
    kind: ?DocumentHighlightKind,
};
