const std = @import("std");
const types = @import("types.zig");

/// Only check for the field's existence.
const Exists = struct {
    exists: bool,
};

fn Default(comptime T: type, comptime default_value: T) type {
    return struct {
        pub const value_type = T;
        pub const default = default_value;
        value: T,
    };
}

fn Transform(comptime Original: type, comptime transform_fn: anytype) type {
    return struct {
        pub const original_type = Original;
        pub const transform = transform_fn;

        value: @TypeOf(transform(@as(Original, undefined))),
    };
}

inline fn fromDynamicTreeInternal(arena: *std.heap.ArenaAllocator, value: std.json.Value, out: anytype) error{ MalformedJson, OutOfMemory }!void {
    const T = comptime std.meta.Child(@TypeOf(out));

    if (comptime std.meta.trait.is(.Struct)(T)) {
        if (value != .Object) return error.MalformedJson;

        var err = false;
        inline for (std.meta.fields(T)) |field| {
            const is_exists = field.field_type == Exists;

            const is_optional = comptime std.meta.trait.is(.Optional)(field.field_type);
            const actual_type = if (is_optional) std.meta.Child(field.field_type) else field.field_type;

            const is_struct = comptime std.meta.trait.is(.Struct)(actual_type);
            const is_default = comptime if (is_struct) std.meta.trait.hasDecls(actual_type, .{ "default", "value_type" }) else false;
            const is_transform = comptime if (is_struct) std.meta.trait.hasDecls(actual_type, .{ "original_type", "transform" }) else false;

            if (value.Object.get(field.name)) |json_field| {
                if (is_exists) {
                    @field(out, field.name) = Exists{ .exists = true };
                } else if (is_transform) {
                    var original_value: actual_type.original_type = undefined;
                    try fromDynamicTreeInternal(arena, json_field, &original_value);
                    @field(out, field.name) = actual_type{ .value = actual_type.transform(original_value) catch return error.MalformedJson };
                } else if (is_default) {
                    try fromDynamicTreeInternal(arena, json_field, &@field(out, field.name).value);
                } else if (is_optional) {
                    if (json_field == .Null) {
                        @field(out, field.name) = null;
                    } else {
                        var actual_value: actual_type = undefined;
                        try fromDynamicTreeInternal(arena, json_field, &actual_value);
                        @field(out, field.name) = actual_value;
                    }
                } else {
                    try fromDynamicTreeInternal(arena, json_field, &@field(out, field.name));
                }
            } else {
                if (is_exists) {
                    @field(out, field.name) = Exists{ .exists = false };
                } else if (is_optional) {
                    @field(out, field.name) = null;
                } else if (is_default) {
                    @field(out, field.name) = actual_type{ .value = actual_type.default };
                } else {
                    err = true;
                }
            }
        }
        if (err) return error.MalformedJson;
    } else if (comptime (std.meta.trait.isSlice(T) and T != []const u8)) {
        if (value != .Array) return error.MalformedJson;
        const Child = std.meta.Child(T);

        if (value.Array.items.len == 0) {
            out.* = &[0]Child{};
        } else {
            var slice = try arena.allocator.alloc(Child, value.Array.items.len);
            for (value.Array.items) |arr_item, idx| {
                try fromDynamicTreeInternal(arena, arr_item, &slice[idx]);
            }
            out.* = slice;
        }
    } else if (T == std.json.Value) {
        out.* = value;
    } else {
        switch (T) {
            bool => {
                if (value != .Bool) return error.MalformedJson;
                out.* = value.Bool;
            },
            i64 => {
                if (value != .Integer) return error.MalformedJson;
                out.* = value.Integer;
            },
            f64 => {
                if (value != .Float) return error.MalformedJson;
                out.* = value.Float;
            },
            []const u8 => {
                if (value != .String) return error.MalformedJson;
                out.* = value.String;
            },
            else => @compileError("Invalid type " ++ @typeName(T)),
        }
    }
}

pub fn fromDynamicTree(arena: *std.heap.ArenaAllocator, comptime T: type, value: std.json.Value) error{ MalformedJson, OutOfMemory }!T {
    var out: T = undefined;
    try fromDynamicTreeInternal(arena, value, &out);
    return out;
}

//! This file contains request types zls handles.
//! Note that the parameter types may be incomplete.
//! We only define what we actually use.

const MaybeStringArray = Default([]const types.String, &[0]types.String{});

pub const Initialize = struct {
    pub const ClientCapabilities = struct {
        workspace: ?struct {
            workspaceFolders: Default(bool, false),
        },
        textDocument: ?struct {
            semanticTokens: Exists,
            hover: ?struct {
                contentFormat: MaybeStringArray,
            },
            completion: ?struct {
                completionItem: ?struct {
                    snippetSupport: Default(bool, false),
                    documentationFormat: MaybeStringArray,
                },
            },
        },
        offsetEncoding: MaybeStringArray,
    };

    params: struct {
        capabilities: ClientCapabilities,
        workspaceFolders: ?[]const types.WorkspaceFolder,
    },
};

pub const WorkspaceFoldersChange = struct {
    params: struct {
        event: struct {
            added: []const types.WorkspaceFolder,
            removed: []const types.WorkspaceFolder,
        },
    },
};

pub const OpenDocument = struct {
    params: struct {
        textDocument: struct {
            uri: types.String,
            text: types.String,
        },
    },
};

const TextDocumentIdentifier = struct {
    uri: types.String,
};

pub const ChangeDocument = struct {
    params: struct {
        textDocument: TextDocumentIdentifier,
        contentChanges: std.json.Value,
    },
};

const TextDocumentIdentifierRequest = struct {
    params: struct {
        textDocument: TextDocumentIdentifier,
    },
};

pub const SaveDocument = TextDocumentIdentifierRequest;
pub const CloseDocument = TextDocumentIdentifierRequest;
pub const SemanticTokens = TextDocumentIdentifierRequest;

const TextDocumentIdentifierPositionRequest = struct {
    params: struct {
        textDocument: TextDocumentIdentifier,
        position: types.Position,
    },
};

pub const Completion = TextDocumentIdentifierPositionRequest;
pub const GotoDefinition = TextDocumentIdentifierPositionRequest;
pub const GotoDeclaration = TextDocumentIdentifierPositionRequest;
pub const Hover = TextDocumentIdentifierPositionRequest;
pub const DocumentSymbols = TextDocumentIdentifierRequest;
pub const Formatting = TextDocumentIdentifierRequest;
pub const Rename = struct {
    params: struct {
        textDocument: TextDocumentIdentifier,
        position: types.Position,
        newName: types.String,
    },
};

pub const References = struct {
    params: struct {
        textDocument: TextDocumentIdentifier,
        position: types.Position,
        context: struct {
            includeDeclaration: bool,
        },
    },
};
