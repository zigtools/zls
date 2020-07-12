// Collection of JSONRPC and LSP structs, enums, and unions

const std = @import("std");
const json = std.json;

// JSON Types

pub const String = []const u8;
pub const Integer = i64;
pub const Float = f64;
pub const Bool = bool;
pub const Array = json.Array;
pub const Object = json.ObjectMap;
// pub const Any = @TypeOf(var);

// Basic structures

pub const DocumentUri = String;

pub const Position = struct {
    line: Integer,
    character: Integer,
};

pub const Range = struct {
    start: Position,
    end: Position,
};

pub const Location = struct {
    uri: DocumentUri, range: Range
};

/// Id of a request
pub const RequestId = union(enum) {
    String: String,
    Integer: Integer,
    Float: Float,
};

/// Params of a request
pub const RequestParams = void;

pub const NotificationParams = union(enum) {
    LogMessageParams: LogMessageParams, PublishDiagnosticsParams: PublishDiagnosticsParams, ShowMessageParams: ShowMessageParams
};

/// Hover response
pub const Hover = struct {
    contents: MarkupContent,
};

/// Params of a response (result)
pub const ResponseParams = union(enum) {
    CompletionList: CompletionList,
    Location: Location,
    Hover: Hover,
    DocumentSymbols: []DocumentSymbol,
    SemanticTokens: struct { data: []const u32 },
    TextEdits: []TextEdit,
    Locations: []Location,
    WorkspaceEdit: WorkspaceEdit,
};

/// JSONRPC error
pub const Error = struct {
    code: Integer,
    message: String,
    data: String,
};

/// JSONRPC request
pub const Request = struct {
    jsonrpc: String = "2.0", method: String, id: ?RequestId = RequestId{ .Integer = 0 }, params: RequestParams
};

/// JSONRPC notifications
pub const Notification = struct {
    jsonrpc: String = "2.0", method: String, params: NotificationParams
};

/// JSONRPC response
pub const Response = struct {
    jsonrpc: String = "2.0",
    // @"error": ?Error = null,
    id: RequestId,
    result: ResponseParams,
};

/// Type of a debug message
pub const MessageType = enum(Integer) {
    Error = 1,
    Warning = 2,
    Info = 3,
    Log = 4,

    pub fn jsonStringify(
        value: MessageType,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

/// Params for a LogMessage Notification (window/logMessage)
pub const LogMessageParams = struct {
    type: MessageType, message: String
};

pub const DiagnosticSeverity = enum(Integer) {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,

    pub fn jsonStringify(
        value: DiagnosticSeverity,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const Diagnostic = struct {
    range: Range,
    severity: DiagnosticSeverity,
    code: String,
    source: String,
    message: String,
};

pub const PublishDiagnosticsParams = struct {
    uri: DocumentUri, diagnostics: []Diagnostic
};

pub const TextDocument = struct {
    uri: DocumentUri,
    // This is a substring of mem starting at 0
    text: String,
    // This holds the memory that we have actually allocated.
    mem: []u8,
};

pub const WorkspaceEdit = struct {
    changes: ?std.StringHashMap([]TextEdit),

    pub fn jsonStringify(
        self: WorkspaceEdit,
        options: std.json.StringifyOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.writeByte('{');
        if (self.changes) |changes| {
            try writer.writeAll("\"changes\": {");
            var it = changes.iterator();
            var idx: usize = 0;
            while (it.next()) |entry| : (idx += 1) {
                if (idx != 0) try writer.writeAll(", ");

                try writer.writeByte('"');
                try writer.writeAll(entry.key);
                try writer.writeAll("\":");
                try std.json.stringify(entry.value, options, writer);
            }
            try writer.writeByte('}');
        }
        try writer.writeByte('}');
    }
};

pub const TextEdit = struct {
    range: Range,
    newText: String,
};

pub const MarkupKind = enum(u1) {
    PlainText = 0, // plaintext
    Markdown = 1, // markdown

    pub fn jsonStringify(
        value: MarkupKind,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        const str = switch (value) {
            .PlainText => "plaintext",
            .Markdown => "markdown",
        };
        try json.stringify(str, options, out_stream);
    }
};

pub const MarkupContent = struct {
    kind: MarkupKind = MarkupKind.Markdown, value: String
};

// pub const TextDocumentIdentifier = struct {
//     uri: DocumentUri,
// };

// pub const CompletionTriggerKind = enum(Integer) {
//     Invoked = 1,
//     TriggerCharacter = 2,
//     TriggerForIncompleteCompletions = 3,

//     pub fn jsonStringify(
//         value: CompletionTriggerKind,
//         options: json.StringifyOptions,
//         out_stream: var,
//     ) !void {
//         try json.stringify(@enumToInt(value), options, out_stream);
//     }
// };

pub const CompletionList = struct {
    isIncomplete: Bool,
    items: []const CompletionItem,
};

pub const CompletionItemKind = enum(Integer) {
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

    pub fn jsonStringify(
        value: CompletionItemKind,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const InsertTextFormat = enum(Integer) {
    PlainText = 1,
    Snippet = 2,

    pub fn jsonStringify(
        value: InsertTextFormat,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const CompletionItem = struct {
    label: String,
    kind: CompletionItemKind,
    textEdit: ?TextEdit = null,
    filterText: ?String = null,
    insertText: ?String = null,
    insertTextFormat: ?InsertTextFormat = InsertTextFormat.PlainText,
    detail: ?String = null,
    documentation: ?MarkupContent = null,
    // filterText: String = .NotDefined,
};

const SymbolKind = enum {
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

    pub fn jsonStringify(
        value: SymbolKind,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

pub const DocumentSymbol = struct {
    name: String,
    detail: ?String = null,
    kind: SymbolKind,
    deprecated: bool = false,
    range: Range,
    selectionRange: Range,
    children: []const DocumentSymbol = &[_]DocumentSymbol{},
};

pub const ShowMessageParams = struct {
    type: MessageType,
    message: String,
};

pub const WorkspaceFolder = struct {
    uri: DocumentUri,
    name: String,
};
