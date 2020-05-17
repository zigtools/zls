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
    character: Integer
};

pub const Range = struct {
    start: Position,
    end: Position
};

pub const Location = struct {
    uri: DocumentUri,
    range: Range
};

/// Id of a request
pub const RequestId = union(enum) {
    String: String,
    Integer: Integer,
    Float: Float,
};

/// Params of a request
pub const RequestParams = union(enum) {

};

pub const NotificationParams = union(enum) {
    LogMessageParams: LogMessageParams,
    PublishDiagnosticsParams: PublishDiagnosticsParams
};

/// Params of a response (result)
pub const ResponseParams = union(enum) {
    CompletionList: CompletionList
};

/// JSONRPC error
pub const Error = struct {
    code: Integer,
    message: String,
    data: String,
};

/// JSONRPC request
pub const Request = struct {
    jsonrpc: String = "2.0",
    method: String,
    id: ?RequestId = RequestId{.Integer = 0},
    params: RequestParams
};

/// JSONRPC notifications
pub const Notification = struct {
    jsonrpc: String = "2.0",
    method: String,
    params: NotificationParams
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
        out_stream: var,
    ) !void {
        try json.stringify(@enumToInt(value), options, out_stream);
    }
};

/// Params for a LogMessage Notification (window/logMessage)
pub const LogMessageParams = struct {
    @"type": MessageType,
    message: String
};

pub const DiagnosticSeverity = enum(Integer) {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,

    pub fn jsonStringify(
        value: DiagnosticSeverity,
        options: json.StringifyOptions,
        out_stream: var,
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
    uri: DocumentUri,
    diagnostics: []Diagnostic
};

pub const TextDocument = struct {
    uri: DocumentUri,
    // This is a substring of mem starting at 0
    text: String,
    // This holds the memory that we have actually allocated.
    mem: []u8,

    pub fn positionToIndex(self: TextDocument, position: Position) !usize {
        var split_iterator = std.mem.split(self.text, "\n");

        var line: i64 = 0;
        while (line < position.line) : (line += 1) {
            _ = split_iterator.next() orelse return error.InvalidParams;
        }

        var index = @intCast(i64, split_iterator.index.?) + position.character;

        if (index < 0 or index >= @intCast(i64, self.text.len)) {
            return error.InvalidParams;
        }

        return @intCast(usize, index);
    }

    pub fn getLine(self: TextDocument, target_line: usize) ![]const u8 {
        var split_iterator = std.mem.split(self.text, "\n");

        var line: i64 = 0;
        while (line < target_line) : (line += 1) {
            _ = split_iterator.next() orelse return error.InvalidParams;
        }
        if (split_iterator.next()) |next| {
            return next;
        } else return error.InvalidParams;
    }
};

pub const TextEdit = struct {
    range: Range,
    newText: String,
};

pub const MarkupKind = enum(u1) {
    PlainText = 0, // plaintext
    Markdown = 1,  // markdown

    pub fn jsonStringify(
        value: MarkupKind,
        options: json.StringifyOptions,
        out_stream: var,
    ) !void {
        const str = switch (value) {
            .PlainText => "plaintext",
            .Markdown => "markdown",
        };
        try json.stringify(str, options, out_stream);
    }
};

pub const MarkupContent = struct {
    kind: MarkupKind = MarkupKind.Markdown,
    value: String
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
        out_stream: var,
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
        out_stream: var,
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
    documentation: ?MarkupContent = null
    // filterText: String = .NotDefined,
};

