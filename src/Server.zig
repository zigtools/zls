const Server = @This();

const std = @import("std");
const zig_builtin = @import("builtin");
const build_options = @import("build_options");
const Config = @import("Config.zig");
const DocumentStore = @import("DocumentStore.zig");
const readRequestHeader = @import("header.zig").readRequestHeader;
const requests = @import("requests.zig");
const types = @import("types.zig");
const analysis = @import("analysis.zig");
const ast = @import("ast.zig");
const references = @import("references.zig");
const rename = @import("rename.zig");
const offsets = @import("offsets.zig");
const setup = @import("setup.zig");
const semantic_tokens = @import("semantic_tokens.zig");
const inlay_hints = @import("inlay_hints.zig");
const shared = @import("shared.zig");
const Ast = std.zig.Ast;
const known_folders = @import("known-folders");
const tracy = @import("tracy.zig");
const uri_utils = @import("uri.zig");
const data = @import("data/data.zig");

// Server fields

config: Config,
allocator: std.mem.Allocator = undefined,
document_store: DocumentStore = undefined,
client_capabilities: ClientCapabilities = .{},
offset_encoding: offsets.Encoding = .utf16,

const logger = std.log.scoped(.main);

// Always set this to debug to make std.log call into our handler, then control the runtime
// value in the definition below.
pub const log_level = .debug;

var actual_log_level: std.log.Level = switch (zig_builtin.mode) {
    .Debug => .debug,
    else => @intToEnum(std.log.Level, @enumToInt(build_options.log_level)), //temporary fix to build failing on release-safe due to a Zig bug
};

pub fn log(comptime message_level: std.log.Level, comptime scope: @Type(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (@enumToInt(message_level) > @enumToInt(actual_log_level)) {
        return;
    }
    // After shutdown, pipe output to stderr
    if (!keep_running) {
        std.debug.print("[{s}-{s}] " ++ format ++ "\n", .{ @tagName(message_level), @tagName(scope) } ++ args);
        return;
    }

    // TODO: Use GPA
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var message = std.fmt.allocPrint(arena.allocator(), "[{s}-{s}] " ++ format, .{ @tagName(message_level), @tagName(scope) } ++ args) catch {
        std.debug.print("Failed to allocPrint message.\n", .{});
        return;
    };

    const message_type: types.MessageType = switch (message_level) {
        .debug => .Log,
        .info => .Info,
        .warn => .Warning,
        .err => .Error,
    };

    send(&arena, types.Notification{
        .method = "window/logMessage",
        .params = types.Notification.Params{
            .LogMessage = .{
                .type = message_type,
                .message = message,
            },
        },
    }) catch {
        // TODO: Find a way to handle this error properly
    };
}

// Code was based off of https://github.com/andersfr/zig-lsp/blob/master/server.zig

const ClientCapabilities = struct {
    supports_snippets: bool = false,
    supports_semantic_tokens: bool = false,
    supports_inlay_hints: bool = false,
    hover_supports_md: bool = false,
    completion_doc_supports_md: bool = false,
    label_details_support: bool = false,
    supports_configuration: bool = false,
};

const not_implemented_response =
    \\,"error":{"code":-32601,"message":"NotImplemented"}}
;

const null_result_response =
    \\,"result":null}
;
const empty_result_response =
    \\,"result":{}}
;
const empty_array_response =
    \\,"result":[]}
;
const edit_not_applied_response =
    \\,"result":{"applied":false,"failureReason":"feature not implemented"}}
;
const no_completions_response =
    \\,"result":{"isIncomplete":false,"items":[]}}
;
const no_signatures_response =
    \\,"result":{"signatures":[]}}
;
const no_semantic_tokens_response =
    \\,"result":{"data":[]}}
;

/// Sends a request or response
fn send(arena: *std.heap.ArenaAllocator, reqOrRes: anytype) !void {
    // NOTE: BufferedWriter not needed here; we pretty much have a dynamic ArrayList-based buffer

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arr = std.ArrayList(u8).init(arena.allocator());
    try std.json.stringify(reqOrRes, .{}, arr.writer());

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Content-Length: {}\r\n\r\n", .{arr.items.len});
    try stdout.writeAll(arr.items);
}

fn truncateCompletions(list: []types.CompletionItem, max_detail_length: usize) void {
    for (list) |*item| {
        if (item.detail) |det| {
            if (det.len > max_detail_length) {
                item.detail = det[0..max_detail_length];
            }
        }
    }
}

fn respondGeneric(id: types.RequestId, response: []const u8) !void {
    var stdout_buffered_writer = std.io.bufferedWriter(std.io.getStdOut().writer());
    const stdout = stdout_buffered_writer.writer();

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const id_len = switch (id) {
        .Integer => |id_val| blk: {
            if (id_val == 0) break :blk 1;
            var digits: usize = 1;
            var value = @divTrunc(id_val, 10);
            while (value != 0) : (value = @divTrunc(value, 10)) {
                digits += 1;
            }
            break :blk digits;
        },
        .String => |str_val| str_val.len + 2,
        else => unreachable,
    };

    // Numbers of character that will be printed from this string: len - 1 brackets
    const json_fmt = "{{\"jsonrpc\":\"2.0\",\"id\":";

    try stdout.print("Content-Length: {}\r\n\r\n" ++ json_fmt, .{response.len + id_len + json_fmt.len - 1});
    switch (id) {
        .Integer => |int| try stdout.print("{}", .{int}),
        .String => |str| try stdout.print("\"{s}\"", .{str}),
        else => unreachable,
    }

    try stdout.writeAll(response);
    try stdout_buffered_writer.flush();
}

fn showMessage(message_type: types.MessageType, message: []const u8) !void {
    try send(types.Notification{
        .method = "window/showMessage",
        .params = .{
            .ShowMessageParams = .{
                .type = message_type,
                .message = message,
            },
        },
    });
}

// TODO: Is this correct or can we get a better end?
fn astLocationToRange(loc: Ast.Location) types.Range {
    return .{
        .start = .{
            .line = @intCast(i64, loc.line),
            .character = @intCast(i64, loc.column),
        },
        .end = .{
            .line = @intCast(i64, loc.line),
            .character = @intCast(i64, loc.column),
        },
    };
}

fn publishDiagnostics(server: *Server, arena: *std.heap.ArenaAllocator, handle: DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;

    var diagnostics = std.ArrayList(types.Diagnostic).init(arena.allocator());

    for (tree.errors) |err| {
        const loc = tree.tokenLocation(0, err.token);

        var mem_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&mem_buffer);
        try tree.renderError(err, fbs.writer());

        try diagnostics.append(.{
            .range = astLocationToRange(loc),
            .severity = .Error,
            .code = @tagName(err.tag),
            .source = "zls",
            .message = try arena.allocator().dupe(u8, fbs.getWritten()),
            // .relatedInformation = undefined
        });
    }

    if (server.config.enable_unused_variable_warnings) {
        scopes: for (handle.document_scope.scopes) |scope| {
            const scope_data = switch (scope.data) {
                .function => |f| b: {
                    var buf: [1]std.zig.Ast.Node.Index = undefined;
                    var proto = ast.fnProto(tree, f, &buf) orelse break :b f;
                    if (proto.extern_export_inline_token) |tok| {
                        if (std.mem.eql(u8, tree.tokenSlice(tok), "extern")) continue :scopes;
                    }
                    break :b f;
                },
                .block => |b| b,
                else => continue,
            };

            var decl_iterator = scope.decls.iterator();
            while (decl_iterator.next()) |decl| {
                var identifier_count: usize = 0;

                var name_token_index = switch (decl.value_ptr.*) {
                    .ast_node => |an| s: {
                        const an_tag = tree.nodes.items(.tag)[an];
                        switch (an_tag) {
                            .simple_var_decl => {
                                break :s tree.nodes.items(.main_token)[an] + 1;
                            },
                            else => continue,
                        }
                    },
                    .param_decl => |param| param.name_token orelse continue,
                    else => continue,
                };

                if (std.mem.eql(u8, tree.tokenSlice(name_token_index), "_"))
                    continue;

                const pit_start = tree.firstToken(scope_data);
                const pit_end = ast.lastToken(tree, scope_data);

                for (tree.tokens.items(.tag)[pit_start..pit_end]) |tag, index| {
                    if (tag == .identifier and std.mem.eql(u8, tree.tokenSlice(pit_start + @intCast(u32, index)), tree.tokenSlice(name_token_index))) identifier_count += 1;
                }

                if (identifier_count <= 1)
                    try diagnostics.append(.{
                        .range = astLocationToRange(tree.tokenLocation(0, name_token_index)),
                        .severity = .Error,
                        .code = "unused_variable",
                        .source = "zls",
                        .message = "Unused variable; either remove the variable or use '_ = ' on the variable to bypass this error",
                    });
            }
        }
    }

    if (server.config.warn_style) {
        var node: u32 = 0;
        while (node < tree.nodes.len) : (node += 1) {
            if (ast.isBuiltinCall(tree, node)) {
                const builtin_token = tree.nodes.items(.main_token)[node];
                const call_name = tree.tokenSlice(builtin_token);

                if (!std.mem.eql(u8, call_name, "@import")) continue;

                const node_data = tree.nodes.items(.data)[node];
                const params = switch (tree.nodes.items(.tag)[node]) {
                    .builtin_call, .builtin_call_comma => tree.extra_data[node_data.lhs..node_data.rhs],
                    .builtin_call_two, .builtin_call_two_comma => if (node_data.lhs == 0)
                        &[_]Ast.Node.Index{}
                    else if (node_data.rhs == 0)
                        &[_]Ast.Node.Index{node_data.lhs}
                    else
                        &[_]Ast.Node.Index{ node_data.lhs, node_data.rhs },
                    else => unreachable,
                };

                if (params.len != 1) continue;

                const import_str_token = tree.nodes.items(.main_token)[params[0]];
                const import_str = tree.tokenSlice(import_str_token);

                if (std.mem.startsWith(u8, import_str, "\".")) {
                    try diagnostics.append(.{
                        .range = astLocationToRange(tree.tokenLocation(0, import_str_token)),
                        .severity = .Hint,
                        .code = "useless_dot",
                        .source = "zls",
                        .message = "A . or ./ is not needed in imports",
                    });
                }
            }
        }

        // TODO: style warnings for types, values and declarations below root scope
        if (tree.errors.len == 0) {
            for (tree.rootDecls()) |decl_idx| {
                const decl = tree.nodes.items(.tag)[decl_idx];
                switch (decl) {
                    .fn_proto,
                    .fn_proto_multi,
                    .fn_proto_one,
                    .fn_proto_simple,
                    .fn_decl,
                    => blk: {
                        var buf: [1]Ast.Node.Index = undefined;
                        const func = ast.fnProto(tree, decl_idx, &buf).?;
                        if (func.extern_export_inline_token != null) break :blk;

                        if (func.name_token) |name_token| {
                            const loc = tree.tokenLocation(0, name_token);

                            const is_type_function = analysis.isTypeFunction(tree, func);

                            const func_name = tree.tokenSlice(name_token);
                            if (!is_type_function and !analysis.isCamelCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Hint,
                                    .code = "bad_style",
                                    .source = "zls",
                                    .message = "Functions should be camelCase",
                                });
                            } else if (is_type_function and !analysis.isPascalCase(func_name)) {
                                try diagnostics.append(.{
                                    .range = astLocationToRange(loc),
                                    .severity = .Hint,
                                    .code = "bad_style",
                                    .source = "zls",
                                    .message = "Type functions should be PascalCase",
                                });
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    try send(arena, types.Notification{
        .method = "textDocument/publishDiagnostics",
        .params = .{
            .PublishDiagnostics = .{
                .uri = handle.uri(),
                .diagnostics = diagnostics.items,
            },
        },
    });
}

fn typeToCompletion(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    list: *std.ArrayList(types.CompletionItem),
    field_access: analysis.FieldAccessReturn,
    orig_handle: *DocumentStore.Handle,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const type_handle = field_access.original;
    switch (type_handle.type.data) {
        .slice => {
            if (!type_handle.type.is_type_val) {
                try list.append(.{
                    .label = "len",
                    .detail = "const len: usize",
                    .kind = .Field,
                    .insertText = "len",
                    .insertTextFormat = .PlainText,
                });
                try list.append(.{
                    .label = "ptr",
                    .kind = .Field,
                    .insertText = "ptr",
                    .insertTextFormat = .PlainText,
                });
            }
        },
        .error_union => {},
        .pointer => |n| {
            if (server.config.operator_completions) {
                try list.append(.{
                    .label = "*",
                    .kind = .Operator,
                    .insertText = "*",
                    .insertTextFormat = .PlainText,
                });
            }
            try server.nodeToCompletion(
                arena,
                list,
                .{ .node = n, .handle = type_handle.handle },
                null,
                orig_handle,
                type_handle.type.is_type_val,
                null,
            );
        },
        .other => |n| try server.nodeToCompletion(
            arena,
            list,
            .{ .node = n, .handle = type_handle.handle },
            field_access.unwrapped,
            orig_handle,
            type_handle.type.is_type_val,
            null,
        ),
        .primitive, .array_index => {},
    }
}

fn nodeToCompletion(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    list: *std.ArrayList(types.CompletionItem),
    node_handle: analysis.NodeWithHandle,
    unwrapped: ?analysis.TypeWithHandle,
    orig_handle: *DocumentStore.Handle,
    is_type_val: bool,
    parent_is_type_val: ?bool,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    const doc_kind: types.MarkupContent.Kind = if (server.client_capabilities.completion_doc_supports_md)
        .Markdown
    else
        .PlainText;

    const doc = if (try analysis.getDocComments(
        list.allocator,
        handle.tree,
        node,
        doc_kind,
    )) |doc_comments|
        types.MarkupContent{
            .kind = doc_kind,
            .value = doc_comments,
        }
    else
        null;

    if (ast.isContainer(handle.tree, node)) {
        const context = DeclToCompletionContext{
            .server = server,
            .completions = list,
            .arena = arena,
            .orig_handle = orig_handle,
            .parent_is_type_val = is_type_val,
        };
        try analysis.iterateSymbolsContainer(
            &server.document_store,
            arena,
            node_handle,
            orig_handle,
            declToCompletion,
            context,
            !is_type_val,
        );
    }

    if (is_type_val) return;

    switch (node_tags[node]) {
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const func = ast.fnProto(tree, node, &buf).?;
            if (func.name_token) |name_token| {
                const use_snippets = server.config.enable_snippets and server.client_capabilities.supports_snippets;
                const insert_text = if (use_snippets) blk: {
                    const skip_self_param = !(parent_is_type_val orelse true) and
                        try analysis.hasSelfParam(arena, &server.document_store, handle, func);
                    break :blk try analysis.getFunctionSnippet(arena.allocator(), tree, func, skip_self_param);
                } else tree.tokenSlice(func.name_token.?);

                const is_type_function = analysis.isTypeFunction(handle.tree, func);

                try list.append(.{
                    .label = handle.tree.tokenSlice(name_token),
                    .kind = if (is_type_function) .Struct else .Function,
                    .documentation = doc,
                    .detail = analysis.getFunctionSignature(handle.tree, func),
                    .insertText = insert_text,
                    .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
                });
            }
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = ast.varDecl(tree, node).?;
            const is_const = token_tags[var_decl.ast.mut_token] == .keyword_const;

            if (try analysis.resolveVarDeclAlias(&server.document_store, arena, node_handle)) |result| {
                const context = DeclToCompletionContext{
                    .server = server,
                    .completions = list,
                    .arena = arena,
                    .orig_handle = orig_handle,
                };
                return try declToCompletion(context, result);
            }

            try list.append(.{
                .label = handle.tree.tokenSlice(var_decl.ast.mut_token + 1),
                .kind = if (is_const) .Constant else .Variable,
                .documentation = doc,
                .detail = analysis.getVariableSignature(tree, var_decl),
                .insertText = tree.tokenSlice(var_decl.ast.mut_token + 1),
                .insertTextFormat = .PlainText,
            });
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = ast.containerField(tree, node).?;
            try list.append(.{
                .label = handle.tree.tokenSlice(field.ast.name_token),
                .kind = .Field,
                .documentation = doc,
                .detail = analysis.getContainerFieldSignature(handle.tree, field),
                .insertText = tree.tokenSlice(field.ast.name_token),
                .insertTextFormat = .PlainText,
            });
        },
        .array_type,
        .array_type_sentinel,
        => {
            try list.append(.{
                .label = "len",
                .detail = "const len: usize",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => {
            const ptr_type = ast.ptrType(tree, node).?;

            switch (ptr_type.size) {
                .One, .C, .Many => if (server.config.operator_completions) {
                    try list.append(.{
                        .label = "*",
                        .kind = .Operator,
                        .insertText = "*",
                        .insertTextFormat = .PlainText,
                    });
                },
                .Slice => {
                    try list.append(.{
                        .label = "ptr",
                        .kind = .Field,
                        .insertText = "ptr",
                        .insertTextFormat = .PlainText,
                    });
                    try list.append(.{
                        .label = "len",
                        .detail = "const len: usize",
                        .kind = .Field,
                        .insertText = "len",
                        .insertTextFormat = .PlainText,
                    });
                    return;
                },
            }

            if (unwrapped) |actual_type| {
                try server.typeToCompletion(arena, list, .{ .original = actual_type }, orig_handle);
            }
            return;
        },
        .optional_type => {
            if (server.config.operator_completions) {
                try list.append(.{
                    .label = "?",
                    .kind = .Operator,
                    .insertText = "?",
                    .insertTextFormat = .PlainText,
                });
            }
            return;
        },
        .string_literal => {
            try list.append(.{
                .label = "len",
                .detail = "const len: usize",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        else => if (analysis.nodeToString(tree, node)) |string| {
            try list.append(.{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = tree.getNodeSource(node),
                .insertText = string,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

pub fn identifierFromPosition(pos_index: usize, handle: DocumentStore.Handle) []const u8 {
    const text = handle.document.text;

    if (pos_index + 1 >= text.len) return "";
    var start_idx = pos_index;

    while (start_idx > 0 and isSymbolChar(text[start_idx - 1])) {
        start_idx -= 1;
    }

    var end_idx = pos_index;
    while (end_idx < handle.document.text.len and isSymbolChar(text[end_idx])) {
        end_idx += 1;
    }

    if (end_idx <= start_idx) return "";
    return text[start_idx..end_idx];
}

fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlNum(char) or char == '_';
}

fn gotoDefinitionSymbol(
    server: *Server,
    id: types.RequestId,
    arena: *std.heap.ArenaAllocator,
    decl_handle: analysis.DeclWithHandle,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle = decl_handle.handle;

    const location = switch (decl_handle.decl.*) {
        .ast_node => |node| block: {
            if (resolve_alias) {
                if (try analysis.resolveVarDeclAlias(&server.document_store, arena, .{ .node = node, .handle = handle })) |result| {
                    handle = result.handle;
                    break :block result.location(server.offset_encoding) catch return;
                }
            }

            const name_token = analysis.getDeclNameToken(handle.tree, node) orelse
                return try respondGeneric(id, null_result_response);
            break :block offsets.tokenRelativeLocation(handle.tree, 0, handle.tree.tokens.items(.start)[name_token], server.offset_encoding) catch return;
        },
        else => decl_handle.location(server.offset_encoding) catch return,
    };

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = handle.document.uri,
                .range = .{
                    .start = .{
                        .line = @intCast(i64, location.line),
                        .character = @intCast(i64, location.column),
                    },
                    .end = .{
                        .line = @intCast(i64, location.line),
                        .character = @intCast(i64, location.column),
                    },
                },
            },
        },
    });
}

fn hoverSymbol(
    server: *Server,
    id: types.RequestId,
    arena: *std.heap.ArenaAllocator,
    decl_handle: analysis.DeclWithHandle,
) (std.os.WriteError || error{OutOfMemory})!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = decl_handle.handle;
    const tree = handle.tree;

    const hover_kind: types.MarkupContent.Kind = if (server.client_capabilities.hover_supports_md) .Markdown else .PlainText;
    var doc_str: ?[]const u8 = null;

    const def_str = switch (decl_handle.decl.*) {
        .ast_node => |node| def: {
            if (try analysis.resolveVarDeclAlias(&server.document_store, arena, .{ .node = node, .handle = handle })) |result| {
                return try server.hoverSymbol(id, arena, result);
            }
            doc_str = try analysis.getDocComments(arena.allocator(), tree, node, hover_kind);

            var buf: [1]Ast.Node.Index = undefined;

            if (ast.varDecl(tree, node)) |var_decl| {
                break :def analysis.getVariableSignature(tree, var_decl);
            } else if (ast.fnProto(tree, node, &buf)) |fn_proto| {
                break :def analysis.getFunctionSignature(tree, fn_proto);
            } else if (ast.containerField(tree, node)) |field| {
                break :def analysis.getContainerFieldSignature(tree, field);
            } else {
                break :def analysis.nodeToString(tree, node) orelse
                    return try respondGeneric(id, null_result_response);
            }
        },
        .param_decl => |param| def: {
            if (param.first_doc_comment) |doc_comments| {
                doc_str = try analysis.collectDocComments(arena.allocator(), handle.tree, doc_comments, hover_kind, false);
            }

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr); // extern fn
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            const start = offsets.tokenLocation(tree, first_token).start;
            const end = offsets.tokenLocation(tree, last_token).end;
            break :def tree.source[start..end];
        },
        .pointer_payload => |payload| tree.tokenSlice(payload.name),
        .array_payload => |payload| handle.tree.tokenSlice(payload.identifier),
        .array_index => |payload| handle.tree.tokenSlice(payload),
        .switch_payload => |payload| tree.tokenSlice(payload.node),
        .label_decl => |label_decl| tree.tokenSlice(label_decl),
    };

    var bound_type_params = analysis.BoundTypeParams.init(arena.allocator());
    const resolved_type = try decl_handle.resolveType(&server.document_store, arena, &bound_type_params);

    const resolved_type_str = if (resolved_type) |rt|
        if (rt.type.is_type_val) "type" else switch (rt.type.data) { // TODO: Investigate random weird numbers like 897 that cause index of bounds
            .pointer,
            .slice,
            .error_union,
            .primitive,
            => |p| if (p >= tree.nodes.len) "unknown" else tree.getNodeSource(p),
            .other => |p| if (p >= tree.nodes.len) "unknown" else switch (tree.nodes.items(.tag)[p]) {
                .container_decl,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                => tree.tokenSlice(tree.nodes.items(.main_token)[p] - 2), // NOTE: This is a hacky nightmare but it works :P
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                .fn_decl,
                => "fn", // TODO:(?) Add more info?
                .array_type,
                .array_type_sentinel,
                .ptr_type,
                .ptr_type_aligned,
                .ptr_type_bit_range,
                .ptr_type_sentinel,
                => tree.getNodeSource(p),
                else => "unknown", // TODO: Implement more "other" type expressions; better safe than sorry
            },
            else => "unknown",
        }
    else
        "unknown";

    var hover_text: []const u8 = undefined;
    if (hover_kind == .Markdown) {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(arena.allocator(), "```zig\n{s}\n```\n```zig\n({s})\n```", .{ def_str, resolved_type_str });
    } else {
        hover_text =
            if (doc_str) |doc|
            try std.fmt.allocPrint(arena.allocator(), "{s} ({s})\n{s}", .{ def_str, resolved_type_str, doc })
        else
            try std.fmt.allocPrint(arena.allocator(), "{s} ({s})", .{ def_str, resolved_type_str });
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .Hover = .{
                .contents = .{ .value = hover_text },
            },
        },
    });
}

fn getLabelGlobal(pos_index: usize, handle: *DocumentStore.Handle) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupLabel(handle, name, pos_index);
}

fn getSymbolGlobal(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return null;

    return try analysis.lookupSymbolGlobal(&server.document_store, arena, handle, name, pos_index);
}

fn gotoDefinitionLabel(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try server.gotoDefinitionSymbol(id, arena, decl, false);
}

fn gotoDefinitionGlobal(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try server.gotoDefinitionSymbol(id, arena, decl, resolve_alias);
}

fn hoverDefinitionLabel(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try server.hoverSymbol(id, arena, decl);
}

fn hoverDefinitionBuiltin(arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(pos_index, handle.*);
    if (name.len == 0) return try respondGeneric(id, null_result_response);

    inline for (data.builtins) |builtin| {
        if (std.mem.eql(u8, builtin.name[1..], name)) {
            try send(arena, types.Response{
                .id = id,
                .result = .{
                    .Hover = .{
                        .contents = .{
                            .value = try std.fmt.allocPrint(
                                arena.allocator(),
                                "```zig\n{s}\n```\n{s}",
                                .{ builtin.signature, builtin.documentation },
                            ),
                        },
                    },
                },
            });
        }
    }
}

fn hoverDefinitionGlobal(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = server;

    const decl = (try server.getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    return try server.hoverSymbol(id, arena, decl);
}

fn getSymbolFieldAccess(
    server: *Server,
    handle: *DocumentStore.Handle,
    arena: *std.heap.ArenaAllocator,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
) !?analysis.DeclWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const name = identifierFromPosition(position.absolute_index, handle.*);
    if (name.len == 0) return null;

    const line_mem_start = @ptrToInt(position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
    var held_range = handle.document.borrowNullTerminatedSlice(line_mem_start + range.start, line_mem_start + range.end);
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    errdefer held_range.release();
    if (try analysis.getFieldAccessType(&server.document_store, arena, handle, position.absolute_index, &tokenizer)) |result| {
        held_range.release();
        const container_handle = result.unwrapped orelse result.original;
        const container_handle_node = switch (container_handle.type.data) {
            .other => |n| n,
            else => return null,
        };
        return try analysis.lookupSymbolContainer(
            &server.document_store,
            arena,
            .{ .node = container_handle_node, .handle = container_handle.handle },
            name,
            true,
        );
    }
    return null;
}

fn gotoDefinitionFieldAccess(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    resolve_alias: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, arena, position, range)) orelse return try respondGeneric(id, null_result_response);
    return try server.gotoDefinitionSymbol(id, arena, decl, resolve_alias);
}

fn hoverDefinitionFieldAccess(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, arena, position, range)) orelse return try respondGeneric(id, null_result_response);
    return try server.hoverSymbol(id, arena, decl);
}

fn gotoDefinitionString(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;

    const import_str = analysis.getImportStr(tree, 0, pos_index) orelse return try respondGeneric(id, null_result_response);
    const uri = (try server.document_store.uriFromImportStr(
        arena.allocator(),
        handle.*,
        import_str,
    )) orelse return try respondGeneric(id, null_result_response);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .Location = .{
                .uri = uri,
                .range = .{
                    .start = .{ .line = 0, .character = 0 },
                    .end = .{ .line = 0, .character = 0 },
                },
            },
        },
    });
}

fn renameDefinitionGlobal(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(arena.allocator()),
    };
    try rename.renameSymbol(arena, &server.document_store, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionFieldAccess(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, arena, position, range)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(arena.allocator()),
    };
    try rename.renameSymbol(arena, &server.document_store, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn renameDefinitionLabel(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    new_name: []const u8,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);

    var workspace_edit = types.WorkspaceEdit{
        .changes = std.StringHashMap([]types.TextEdit).init(arena.allocator()),
    };
    try rename.renameLabel(arena, decl, new_name, &workspace_edit.changes.?, server.offset_encoding);
    try send(arena, types.Response{
        .id = id,
        .result = .{ .WorkspaceEdit = workspace_edit },
    });
}

fn referencesDefinitionGlobal(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolGlobal(arena, pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(arena.allocator());
    try references.symbolReferences(
        arena,
        &server.document_store,
        decl,
        server.offset_encoding,
        include_decl,
        &locs,
        std.ArrayList(types.Location).append,
        server.config.skip_std_references,
        !highlight,
    );

    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(arena.allocator(), locs.items.len);
        for (locs.items) |loc| {
            highlights.appendAssumeCapacity(.{
                .range = loc.range,
                .kind = .Text,
            });
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };

    try send(arena, types.Response{
        .id = id,
        .result = result,
    });
}

fn referencesDefinitionFieldAccess(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    position: offsets.DocumentPosition,
    range: analysis.SourceRange,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try server.getSymbolFieldAccess(handle, arena, position, range)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(arena.allocator());
    try references.symbolReferences(
        arena,
        &server.document_store,
        decl,
        server.offset_encoding,
        include_decl,
        &locs,
        std.ArrayList(types.Location).append,
        server.config.skip_std_references,
        !highlight,
    );
    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(arena.allocator(), locs.items.len);
        for (locs.items) |loc| {
            highlights.appendAssumeCapacity(.{
                .range = loc.range,
                .kind = .Text,
            });
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };
    try send(arena, types.Response{
        .id = id,
        .result = result,
    });
}

fn referencesDefinitionLabel(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    handle: *DocumentStore.Handle,
    pos_index: usize,
    include_decl: bool,
    comptime highlight: bool,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const decl = (try getLabelGlobal(pos_index, handle)) orelse return try respondGeneric(id, null_result_response);
    var locs = std.ArrayList(types.Location).init(arena.allocator());
    try references.labelReferences(arena, decl, server.offset_encoding, include_decl, &locs, std.ArrayList(types.Location).append);
    const result: types.ResponseParams = if (highlight) result: {
        var highlights = try std.ArrayList(types.DocumentHighlight).initCapacity(arena.allocator(), locs.items.len);
        for (locs.items) |loc| {
            highlights.appendAssumeCapacity(.{
                .range = loc.range,
                .kind = .Text,
            });
        }
        break :result .{ .DocumentHighlight = highlights.items };
    } else .{ .Locations = locs.items };
    try send(arena, types.Response{
        .id = id,
        .result = result,
    });
}

fn hasComment(tree: Ast.Tree, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const token_starts = tree.tokens.items(.start);

    const start = token_starts[start_token];
    const end = token_starts[end_token];

    return std.mem.indexOf(u8, tree.source[start..end], "//") != null;
}

const DeclToCompletionContext = struct {
    server: *Server,
    completions: *std.ArrayList(types.CompletionItem),
    arena: *std.heap.ArenaAllocator,
    orig_handle: *DocumentStore.Handle,
    parent_is_type_val: ?bool = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: analysis.DeclWithHandle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = decl_handle.handle.tree;
    switch (decl_handle.decl.*) {
        .ast_node => |node| try context.server.nodeToCompletion(
            context.arena,
            context.completions,
            .{ .node = node, .handle = decl_handle.handle },
            null,
            context.orig_handle,
            false,
            context.parent_is_type_val,
        ),
        .param_decl => |param| {
            const doc_kind: types.MarkupContent.Kind = if (context.server.client_capabilities.completion_doc_supports_md) .Markdown else .PlainText;
            const doc = if (param.first_doc_comment) |doc_comments|
                types.MarkupContent{
                    .kind = doc_kind,
                    .value = try analysis.collectDocComments(context.arena.allocator(), tree, doc_comments, doc_kind, false),
                }
            else
                null;

            const first_token = param.first_doc_comment orelse
                param.comptime_noalias orelse
                param.name_token orelse
                tree.firstToken(param.type_expr);
            const last_token = param.anytype_ellipsis3 orelse tree.lastToken(param.type_expr);

            try context.completions.append(.{
                .label = tree.tokenSlice(param.name_token.?),
                .kind = .Constant,
                .documentation = doc,
                .detail = tree.source[offsets.tokenLocation(tree, first_token).start..offsets.tokenLocation(tree, last_token).end],
                .insertText = tree.tokenSlice(param.name_token.?),
                .insertTextFormat = .PlainText,
            });
        },
        .pointer_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.name),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.name),
                .insertTextFormat = .PlainText,
            });
        },
        .array_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.identifier),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.identifier),
                .insertTextFormat = .PlainText,
            });
        },
        .array_index => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload),
                .insertTextFormat = .PlainText,
            });
        },
        .switch_payload => |payload| {
            try context.completions.append(.{
                .label = tree.tokenSlice(payload.node),
                .kind = .Variable,
                .insertText = tree.tokenSlice(payload.node),
                .insertTextFormat = .PlainText,
            });
        },
        .label_decl => |label_decl| {
            try context.completions.append(.{
                .label = tree.tokenSlice(label_decl),
                .kind = .Variable,
                .insertText = tree.tokenSlice(label_decl),
                .insertTextFormat = .PlainText,
            });
        },
    }
}

fn completeLabel(
    server: *Server,
    arena: *std.heap.ArenaAllocator,
    id: types.RequestId,
    pos_index: usize,
    handle: *DocumentStore.Handle,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(arena.allocator());

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .arena = arena,
        .orig_handle = handle,
    };
    try analysis.iterateLabels(handle, pos_index, declToCompletion, context);
    sortCompletionItems(completions.items, arena.allocator());
    truncateCompletions(completions.items, server.config.max_detail_length);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

var builtin_completions: ?[]types.CompletionItem = null;
fn completeBuiltin(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (builtin_completions == null) {
        builtin_completions = try server.allocator.alloc(types.CompletionItem, data.builtins.len);
        for (data.builtins) |builtin, idx| {
            builtin_completions.?[idx] = types.CompletionItem{
                .label = builtin.name,
                .kind = .Function,
                .filterText = builtin.name[1..],
                .detail = builtin.signature,
                .documentation = .{
                    .kind = .Markdown,
                    .value = builtin.documentation,
                },
            };

            var insert_text: []const u8 = undefined;
            if (server.config.enable_snippets) {
                insert_text = builtin.snippet;
                builtin_completions.?[idx].insertTextFormat = .Snippet;
            } else {
                insert_text = builtin.name;
            }
            builtin_completions.?[idx].insertText =
                if (server.config.include_at_in_builtins)
                insert_text
            else
                insert_text[1..];
        }
        truncateCompletions(builtin_completions.?, server.config.max_detail_length);
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = builtin_completions.?,
            },
        },
    });
}

fn completeGlobal(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, pos_index: usize, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(arena.allocator());

    const context = DeclToCompletionContext{
        .server = server,
        .completions = &completions,
        .arena = arena,
        .orig_handle = handle,
    };
    try analysis.iterateSymbolsGlobal(&server.document_store, arena, handle, pos_index, declToCompletion, context);
    sortCompletionItems(completions.items, arena.allocator());
    truncateCompletions(completions.items, server.config.max_detail_length);

    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailledLabel(item, arena.allocator());
        }
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn completeFieldAccess(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle, position: offsets.DocumentPosition, range: analysis.SourceRange) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayList(types.CompletionItem).init(arena.allocator());

    const line_mem_start = @ptrToInt(position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
    var held_range = handle.document.borrowNullTerminatedSlice(line_mem_start + range.start, line_mem_start + range.end);
    errdefer held_range.release();
    var tokenizer = std.zig.Tokenizer.init(held_range.data());

    if (try analysis.getFieldAccessType(&server.document_store, arena, handle, position.absolute_index, &tokenizer)) |result| {
        held_range.release();
        try server.typeToCompletion(arena, &completions, result, handle);
        sortCompletionItems(completions.items, arena.allocator());
        truncateCompletions(completions.items, server.config.max_detail_length);
        if (server.client_capabilities.label_details_support) {
            for (completions.items) |*item| {
                try formatDetailledLabel(item, arena.allocator());
            }
        }
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions.items,
            },
        },
    });
}

fn formatDetailledLabel(item: *types.CompletionItem, alloc: std.mem.Allocator) !void {
    // NOTE: this is not ideal, we should build a detailled label like we do for label/detail
    // because this implementation is very loose, nothing is formated properly so we need to clean
    // things a little bit, wich is quite messy
    // but it works, it provide decent results

    if (item.detail == null)
        return;

    var detailLen: usize = item.detail.?.len;
    var it: []u8 = try alloc.alloc(u8, detailLen);

    detailLen -= std.mem.replace(u8, item.detail.?, "    ", " ", it) * 3;
    it = it[0..detailLen];

    // HACK: for enums 'MyEnum.', item.detail shows everything, we don't want that
    const isValue = std.mem.startsWith(u8, item.label, it);

    const isVar = std.mem.startsWith(u8, it, "var ");
    const isConst = std.mem.startsWith(u8, it, "const ");

    // we don't want the entire content of things, see the NOTE above
    if (std.mem.indexOf(u8, it, "{")) |end| {
        it = it[0..end];
    }
    if (std.mem.indexOf(u8, it, "}")) |end| {
        it = it[0..end];
    }
    if (std.mem.indexOf(u8, it, ";")) |end| {
        it = it[0..end];
    }

    // logger.info("## label: {s} it: {s} kind: {} isValue: {}", .{item.label, it, item.kind, isValue});

    if (std.mem.startsWith(u8, it, "fn ")) {
        var s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        var e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
        if (e < s) {
            logger.warn("something wrong when trying to build label detail for {s} kind: {s}", .{ it, item.kind });
            return;
        }

        item.detail = item.label;
        item.labelDetails = .{ .detail = it[s .. e + 1], .description = it[e + 1 ..] };

        if (item.kind == .Constant) {
            if (std.mem.indexOf(u8, it, "= struct")) |_| {
                item.labelDetails.?.description = "struct";
            } else if (std.mem.indexOf(u8, it, "= union")) |_| {
                var us: usize = std.mem.indexOf(u8, it, "(") orelse return;
                var ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
                if (ue < us) {
                    logger.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                    return;
                }

                item.labelDetails.?.description = it[us - 5 .. ue + 1];
            }
        }
    } else if ((item.kind == .Variable or item.kind == .Constant) and (isVar or isConst)) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;

        const eqlPos = std.mem.indexOf(u8, it, "=");

        if (std.mem.indexOf(u8, it, ":")) |start| {
            if (eqlPos != null) {
                if (start > eqlPos.?) return;
            }
            var e: usize = eqlPos orelse it.len;
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 1 .. e], // right
            };
        } else if (std.mem.indexOf(u8, it, "= .")) |start| {
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 2 .. it.len], // right
            };
        } else if (eqlPos) |start| {
            item.labelDetails = .{
                .detail = "", // left
                .description = it[start + 2 .. it.len], // right
            };
        }
    } else if (item.kind == .Variable) {
        var s: usize = std.mem.indexOf(u8, it, ":") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse return;

        if (e < s) {
            logger.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // logger.info("s: {} -> {}", .{s, e});
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it[s + 1 .. e], // right
        };
    } else if (std.mem.indexOf(u8, it, "@import") != null) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it, // right
        };
    } else if (item.kind == .Constant or item.kind == .Field) {
        var s: usize = std.mem.indexOf(u8, it, " ") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse it.len;
        if (e < s) {
            logger.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // logger.info("s: {} -> {}", .{s, e});
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = it[s + 1 .. e], // right
        };

        if (std.mem.indexOf(u8, it, "= union(")) |_| {
            var us: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ue < us) {
                logger.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[us - 5 .. ue + 1];
        } else if (std.mem.indexOf(u8, it, "= enum(")) |_| {
            var es: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ee: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ee < es) {
                logger.warn("something wrong when trying to build label detail for a .Constant|enum {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[es - 4 .. ee + 1];
        } else if (std.mem.indexOf(u8, it, "= struct")) |_| {
            item.labelDetails.?.description = "struct";
        } else if (std.mem.indexOf(u8, it, "= union")) |_| {
            item.labelDetails.?.description = "union";
        } else if (std.mem.indexOf(u8, it, "= enum")) |_| {
            item.labelDetails.?.description = "enum";
        }
    } else if (item.kind == .Field and isValue) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = item.label, // right
        };
    } else {
        // TODO: if something is missing, it neecs to be implemented here
    }

    // if (item.labelDetails != null)
    //     logger.info("labelDetails: {s}  ::  {s}", .{item.labelDetails.?.detail, item.labelDetails.?.description});
}

fn completeError(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = try server.document_store.errorCompletionItems(arena, handle);

    truncateCompletions(completions, server.config.max_detail_length);
    logger.debug("Completing error:", .{});

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
            },
        },
    });
}

fn kindToSortScore(kind: types.CompletionItem.Kind) []const u8 {
    return switch (kind) {
        .Constant => "1_",

        .Variable => "2_",
        .Field => "3_",
        .Function => "4_",

        .Keyword, .EnumMember => "5_",

        .Class,
        .Interface,
        .Struct,
        // Union?
        .TypeParameter,
        => "6_",

        else => "9_",
    };
}

fn sortCompletionItems(completions: []types.CompletionItem, alloc: std.mem.Allocator) void {
    // TODO: config for sorting rule?
    for (completions) |*c| {
        c.sortText = kindToSortScore(c.kind);

        if (alloc.alloc(u8, 2 + c.label.len)) |it| {
            std.mem.copy(u8, it, c.sortText.?);
            std.mem.copy(u8, it[2..], c.label);
            c.sortText = it;
        } else |_| {}
    }
}

fn completeDot(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = try server.document_store.enumCompletionItems(arena, handle);
    sortCompletionItems(completions, arena.allocator());
    truncateCompletions(completions, server.config.max_detail_length);

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .CompletionList = .{
                .isIncomplete = false,
                .items = completions,
            },
        },
    });
}

fn documentSymbol(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, handle: *DocumentStore.Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try send(arena, types.Response{
        .id = id,
        .result = .{ .DocumentSymbols = try analysis.getDocumentSymbols(arena.allocator(), handle.tree, server.offset_encoding) },
    });
}

fn initializeHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Initialize) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    for (req.params.capabilities.offsetEncoding.value) |encoding| {
        if (std.mem.eql(u8, encoding, "utf-8")) {
            server.offset_encoding = .utf8;
        }
    }

    if (req.params.capabilities.textDocument) |textDocument| {
        server.client_capabilities.supports_semantic_tokens = textDocument.semanticTokens.exists;
        server.client_capabilities.supports_inlay_hints = textDocument.inlayHint.exists;
        if (textDocument.hover) |hover| {
            for (hover.contentFormat.value) |format| {
                if (std.mem.eql(u8, "markdown", format)) {
                    server.client_capabilities.hover_supports_md = true;
                }
            }
        }
        if (textDocument.completion) |completion| {
            if (completion.completionItem) |completionItem| {
                server.client_capabilities.label_details_support = completionItem.labelDetailsSupport.value;
                server.client_capabilities.supports_snippets = completionItem.snippetSupport.value;
                for (completionItem.documentationFormat.value) |documentationFormat| {
                    if (std.mem.eql(u8, "markdown", documentationFormat)) {
                        server.client_capabilities.completion_doc_supports_md = true;
                    }
                }
            }
        }
    }

    try send(arena, types.Response{
        .id = id,
        .result = .{
            .InitializeResult = .{
                .offsetEncoding = if (server.offset_encoding == .utf8)
                    @as([]const u8, "utf-8")
                else
                    "utf-16",
                .serverInfo = .{
                    .name = "zls",
                    .version = "0.1.0",
                },
                .capabilities = .{
                    .signatureHelpProvider = .{
                        .triggerCharacters = &.{"("},
                        .retriggerCharacters = &.{","},
                    },
                    .textDocumentSync = .Full,
                    .renameProvider = true,
                    .completionProvider = .{ .resolveProvider = false, .triggerCharacters = &[_][]const u8{ ".", ":", "@" }, .completionItem = .{ .labelDetailsSupport = true } },
                    .documentHighlightProvider = true,
                    .hoverProvider = true,
                    .codeActionProvider = false,
                    .declarationProvider = true,
                    .definitionProvider = true,
                    .typeDefinitionProvider = true,
                    .implementationProvider = false,
                    .referencesProvider = true,
                    .documentSymbolProvider = true,
                    .colorProvider = false,
                    .documentFormattingProvider = true,
                    .documentRangeFormattingProvider = false,
                    .foldingRangeProvider = false,
                    .selectionRangeProvider = false,
                    .workspaceSymbolProvider = false,
                    .rangeProvider = false,
                    .documentProvider = true,
                    .workspace = .{
                        .workspaceFolders = .{
                            .supported = false,
                            .changeNotifications = false,
                        },
                    },
                    .semanticTokensProvider = .{
                        .full = true,
                        .range = false,
                        .legend = .{
                            .tokenTypes = comptime block: {
                                const tokTypeFields = std.meta.fields(semantic_tokens.TokenType);
                                var names: [tokTypeFields.len][]const u8 = undefined;
                                for (tokTypeFields) |field, i| {
                                    names[i] = field.name;
                                }
                                break :block &names;
                            },
                            .tokenModifiers = comptime block: {
                                const tokModFields = std.meta.fields(semantic_tokens.TokenModifiers);
                                var names: [tokModFields.len][]const u8 = undefined;
                                for (tokModFields) |field, i| {
                                    names[i] = field.name;
                                }
                                break :block &names;
                            },
                        },
                    },
                    .inlayHintProvider = true,
                },
            },
        },
    });

    if (req.params.capabilities.workspace) |workspace| {
        server.client_capabilities.supports_configuration = workspace.configuration.value;
        if (workspace.didChangeConfiguration != null and workspace.didChangeConfiguration.?.dynamicRegistration.value) {
            try registerCapability(arena, "workspace/didChangeConfiguration");
        }
    }

    logger.info("zls initialized", .{});
    logger.info("{}", .{server.client_capabilities});
    logger.info("Using offset encoding: {s}", .{std.meta.tagName(server.offset_encoding)});
}

fn registerCapability(arena: *std.heap.ArenaAllocator, method: []const u8) !void {
    // NOTE: stage1 moment occurs if we dont do it like this :(
    // long live stage2's not broken anon structs

    logger.debug("Dynamically registering method '{s}'", .{method});

    const id = try std.fmt.allocPrint(arena.allocator(), "register-{s}", .{method});
    const reg = types.RegistrationParams.Registration{
        .id = id,
        .method = method,
    };
    const registrations = [1]types.RegistrationParams.Registration{reg};
    const params = types.RegistrationParams{
        .registrations = &registrations,
    };

    const respp = types.ResponseParams{
        .RegistrationParams = params,
    };

    const req = types.Request{
        .id = .{ .String = id },
        .method = "client/registerCapability",
        .params = respp,
    };

    try send(arena, req);
}

fn requestConfiguration(arena: *std.heap.ArenaAllocator) !void {
    const configuration_items = comptime confi: {
        var comp_confi: [std.meta.fields(Config).len]types.ConfigurationParams.ConfigurationItem = undefined;
        inline for (std.meta.fields(Config)) |field, index| {
            comp_confi[index] = .{
                .section = "zls." ++ field.name,
            };
        }

        break :confi comp_confi;
    };

    logger.info("Requesting configuration!", .{});
    try send(arena, types.Request{
        .id = .{ .String = "i_haz_configuration" },
        .method = "workspace/configuration",
        .params = .{
            .ConfigurationParams = .{
                .items = &configuration_items,
            },
        },
    });
}

fn initializedHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId) !void {
    _ = id;
    _ = server;

    if (server.client_capabilities.supports_configuration)
        try requestConfiguration(arena);
}

var keep_running = true;
fn shutdownHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId) !void {
    _ = server;
    _ = arena;

    logger.info("Server closing...", .{});

    keep_running = false;
    // Technically we should deinitialize first and send possible errors to the client
    try respondGeneric(id, null_result_response);
}

fn openDocumentHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.OpenDocument) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = try server.document_store.openDocument(req.params.textDocument.uri, req.params.textDocument.text);
    try server.publishDiagnostics(arena, handle.*);

    if (server.client_capabilities.supports_semantic_tokens)
        try server.semanticTokensFullHandler(arena, id, .{ .params = .{ .textDocument = .{ .uri = req.params.textDocument.uri } } });
}

fn changeDocumentHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.ChangeDocument) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = id;

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.debug("Trying to change non existent document {s}", .{req.params.textDocument.uri});
        return;
    };

    try server.document_store.applyChanges(handle, req.params.contentChanges.Array, server.offset_encoding);
    try server.publishDiagnostics(arena, handle.*);
}

fn saveDocumentHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SaveDocument) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = server;
    _ = id;
    _ = arena;
    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to save non existent document {s}", .{req.params.textDocument.uri});
        return;
    };
    try server.document_store.applySave(handle);
}

fn closeDocumentHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.CloseDocument) error{}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = server;
    _ = id;
    _ = arena;
    server.document_store.closeDocument(req.params.textDocument.uri);
}

fn semanticTokensFullHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SemanticTokensFull) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.enable_semantic_tokens) blk: {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to get semantic tokens of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const token_array = try semantic_tokens.writeAllSemanticTokens(arena, &server.document_store, handle, server.offset_encoding);
        defer server.allocator.free(token_array);

        return try send(arena, types.Response{
            .id = id,
            .result = .{ .SemanticTokensFull = .{ .data = token_array } },
        });
    }
    return try respondGeneric(id, no_semantic_tokens_response);
}

fn completionHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Completion) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to complete in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, no_completions_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(id, no_completions_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
    const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

    switch (pos_context) {
        .builtin => try server.completeBuiltin(arena, id),
        .var_access, .empty => try server.completeGlobal(arena, id, doc_position.absolute_index, handle),
        .field_access => |range| try server.completeFieldAccess(arena, id, handle, doc_position, range),
        .global_error_set => try server.completeError(arena, id, handle),
        .enum_literal => try server.completeDot(arena, id, handle),
        .label => try server.completeLabel(arena, id, doc_position.absolute_index, handle),
        .import_string_literal, .embedfile_string_literal => |loc| {
            if (!server.config.enable_import_embedfile_argument_completions)
                return try respondGeneric(id, no_completions_response);

            const line_mem_start = @ptrToInt(doc_position.line.ptr) - @ptrToInt(handle.document.mem.ptr);
            const completing = handle.tree.source[line_mem_start + loc.start + 1 .. line_mem_start + loc.end];

            var subpath_present = false;
            var fsl_completions = std.ArrayListUnmanaged(types.CompletionItem){};

            fsc: {
                var document_path = try uri_utils.parse(arena.allocator(), handle.uri());
                var document_dir_path = std.fs.openIterableDirAbsolute(std.fs.path.dirname(document_path) orelse break :fsc, .{}) catch break :fsc;
                defer document_dir_path.close();

                if (std.mem.lastIndexOfScalar(u8, completing, '/')) |subpath_index| {
                    var subpath = completing[0..subpath_index];

                    if (std.mem.startsWith(u8, subpath, "./") and subpath_index > 2) {
                        subpath = completing[2..subpath_index];
                    } else if (std.mem.startsWith(u8, subpath, ".") and subpath_index > 1) {
                        subpath = completing[1..subpath_index];
                    }

                    var old = document_dir_path;
                    document_dir_path = document_dir_path.dir.openIterableDir(subpath, .{}) catch break :fsc // NOTE: Is this even safe lol?
                    old.close();

                    subpath_present = true;
                }

                var dir_iterator = document_dir_path.iterate();
                while (try dir_iterator.next()) |entry| {
                    if (std.mem.startsWith(u8, entry.name, ".")) continue;
                    if (entry.kind == .File and pos_context == .import_string_literal and !std.mem.endsWith(u8, entry.name, ".zig")) continue;

                    const l = try arena.allocator().dupe(u8, entry.name);
                    try fsl_completions.append(arena.allocator(), types.CompletionItem{
                        .label = l,
                        .insertText = l,
                        .kind = if (entry.kind == .File) .File else .Folder,
                    });
                }
            }

            if (!subpath_present and pos_context == .import_string_literal) {
                if (handle.associated_build_file) |bf| {
                    try fsl_completions.ensureUnusedCapacity(arena.allocator(), bf.packages.items.len);

                    for (bf.packages.items) |pkg| {
                        try fsl_completions.append(arena.allocator(), .{
                            .label = pkg.name,
                            .kind = .Module,
                        });
                    }
                }
            }

            truncateCompletions(fsl_completions.items, server.config.max_detail_length);

            try send(arena, types.Response{
                .id = id,
                .result = .{
                    .CompletionList = .{
                        .isIncomplete = false,
                        .items = fsl_completions.items,
                    },
                },
            });
        },
        else => try respondGeneric(id, no_completions_response),
    }
}

fn signatureHelpHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.SignatureHelp) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = server;

    const getSignatureInfo = @import("signature_help.zig").getSignatureInfo;
    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get signature help in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, no_signatures_response);
    };

    if (req.params.position.character == 0)
        return try respondGeneric(id, no_signatures_response);

    const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
    if (try getSignatureInfo(
        &server.document_store,
        arena,
        handle,
        doc_position.absolute_index,
        data,
    )) |sig_info| {
        return try send(arena, types.Response{
            .id = id,
            .result = .{
                .SignatureHelp = .{
                    .signatures = &[1]types.SignatureInformation{sig_info},
                    .activeSignature = 0,
                    .activeParameter = sig_info.activeParameter,
                },
            },
        });
    }
    return try respondGeneric(id, no_signatures_response);
}

fn gotoHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDefinition, resolve_alias: bool) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to go to definition in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.gotoDefinitionGlobal(arena, id, doc_position.absolute_index, handle, resolve_alias),
            .field_access => |range| try server.gotoDefinitionFieldAccess(arena, id, handle, doc_position, range, resolve_alias),
            .import_string_literal => try server.gotoDefinitionString(arena, id, doc_position.absolute_index, handle),
            .label => try server.gotoDefinitionLabel(arena, id, doc_position.absolute_index, handle),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn gotoDefinitionHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDefinition) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try server.gotoHandler(arena, id, req, true);
}

fn gotoDeclarationHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.GotoDeclaration) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try server.gotoHandler(arena, id, req, false);
}

fn hoverHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Hover) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get hover in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);
        switch (pos_context) {
            .builtin => try hoverDefinitionBuiltin(arena, id, doc_position.absolute_index, handle),
            .var_access => try server.hoverDefinitionGlobal(arena, id, doc_position.absolute_index, handle),
            .field_access => |range| try server.hoverDefinitionFieldAccess(arena, id, handle, doc_position, range),
            .label => try server.hoverDefinitionLabel(arena, id, doc_position.absolute_index, handle),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn documentSymbolsHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.DocumentSymbols) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = server;

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get document symbols in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };
    try server.documentSymbol(arena, id, handle);
}

fn formattingHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Formatting) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.zig_exe_path) |zig_exe_path| {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to got to definition in non existent document {s}", .{req.params.textDocument.uri});
            return try respondGeneric(id, null_result_response);
        };

        var process = std.ChildProcess.init(&[_][]const u8{ zig_exe_path, "fmt", "--stdin" }, server.allocator);
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;

        process.spawn() catch |err| {
            logger.warn("Failed to spawn zig fmt process, error: {}", .{err});
            return try respondGeneric(id, null_result_response);
        };
        try process.stdin.?.writeAll(handle.document.text);
        process.stdin.?.close();
        process.stdin = null;

        const stdout_bytes = try process.stdout.?.reader().readAllAlloc(server.allocator, std.math.maxInt(usize));
        defer server.allocator.free(stdout_bytes);

        switch (try process.wait()) {
            .Exited => |code| if (code == 0) {
                if (std.mem.eql(u8, handle.document.text, stdout_bytes)) return try respondGeneric(id, null_result_response);

                return try send(arena, types.Response{
                    .id = id,
                    .result = .{
                        .TextEdits = &[1]types.TextEdit{
                            .{
                                .range = try offsets.documentRange(handle.document, server.offset_encoding),
                                .newText = stdout_bytes,
                            },
                        },
                    },
                });
            },
            else => {},
        }
    }
    return try respondGeneric(id, null_result_response);
}

fn renameHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.Rename) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to rename in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.renameDefinitionGlobal(arena, id, handle, doc_position.absolute_index, req.params.newName),
            .field_access => |range| try server.renameDefinitionFieldAccess(arena, id, handle, doc_position, range, req.params.newName),
            .label => try server.renameDefinitionLabel(arena, id, handle, doc_position.absolute_index, req.params.newName),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn didChangeConfigurationHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, maybe_req: std.json.Value) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = arena;
    _ = id;
    if (maybe_req.Object.get("params").?.Object.get("settings").? == .Object) {
        const req = try requests.fromDynamicTree(arena, requests.Configuration, maybe_req);
        inline for (std.meta.fields(Config)) |field| {
            if (@field(req.params.settings, field.name)) |value| {
                logger.debug("setting configuration option '{s}' to '{any}'", .{ field.name, value });
                @field(server.config, field.name) = if (@TypeOf(value) == []const u8) try server.allocator.dupe(u8, value) else value;
            }
        }

        try server.config.configChanged(server.allocator, null);
    } else if (server.client_capabilities.supports_configuration)
        try requestConfiguration(arena);
}

fn referencesHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.References) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to get references in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        const include_decl = req.params.context.includeDeclaration;
        switch (pos_context) {
            .var_access => try server.referencesDefinitionGlobal(arena, id, handle, doc_position.absolute_index, include_decl, false),
            .field_access => |range| try server.referencesDefinitionFieldAccess(arena, id, handle, doc_position, range, include_decl, false),
            .label => try server.referencesDefinitionLabel(arena, id, handle, doc_position.absolute_index, include_decl, false),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn documentHighlightHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.DocumentHighlight) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
        logger.warn("Trying to highlight references in non existent document {s}", .{req.params.textDocument.uri});
        return try respondGeneric(id, null_result_response);
    };

    if (req.params.position.character >= 0) {
        const doc_position = try offsets.documentPosition(handle.document, req.params.position, server.offset_encoding);
        const pos_context = try analysis.documentPositionContext(arena, handle.document, doc_position);

        switch (pos_context) {
            .var_access => try server.referencesDefinitionGlobal(arena, id, handle, doc_position.absolute_index, true, true),
            .field_access => |range| try server.referencesDefinitionFieldAccess(arena, id, handle, doc_position, range, true, true),
            .label => try server.referencesDefinitionLabel(arena, id, handle, doc_position.absolute_index, true, true),
            else => try respondGeneric(id, null_result_response),
        }
    } else {
        try respondGeneric(id, null_result_response);
    }
}

fn isPositionBefore(lhs: types.Position, rhs: types.Position) bool {
    if (lhs.line == rhs.line) {
        return lhs.character < rhs.character;
    } else {
        return lhs.line < rhs.line;
    }
}

fn inlayHintHandler(server: *Server, arena: *std.heap.ArenaAllocator, id: types.RequestId, req: requests.InlayHint) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (server.config.enable_inlay_hints) blk: {
        const handle = server.document_store.getHandle(req.params.textDocument.uri) orelse {
            logger.warn("Trying to get inlay hint of non existent document {s}", .{req.params.textDocument.uri});
            break :blk;
        };

        const hover_kind: types.MarkupContent.Kind = if (server.client_capabilities.hover_supports_md) .Markdown else .PlainText;

        // TODO cache hints per document
        // because the function could be stored in a different document
        // we need the regenerate hints when the document itself or its imported documents change
        // with caching it would also make sense to generate all hints instead of only the visible ones
        const hints = try inlay_hints.writeRangeInlayHint(arena, &server.config, &server.document_store, handle, req.params.range, hover_kind);
        defer {
            for (hints) |hint| {
                server.allocator.free(hint.tooltip.value);
            }
            server.allocator.free(hints);
        }

        // and only convert and return all hints in range for every request
        var visible_hints = hints;

        // small_hints should roughly be sorted by position
        for (hints) |hint, i| {
            if (isPositionBefore(hint.position, req.params.range.start)) continue;
            visible_hints = hints[i..];
            break;
        }
        for (visible_hints) |hint, i| {
            if (isPositionBefore(hint.position, req.params.range.end)) continue;
            visible_hints = visible_hints[0..i];
            break;
        }

        return try send(arena, types.Response{
            .id = id,
            .result = .{ .InlayHint = visible_hints },
        });
    }
    return try respondGeneric(id, null_result_response);
}

// Needed for the hack seen below.
fn extractErr(val: anytype) anyerror {
    val catch |e| return e;
    return error.HackDone;
}

fn processJsonRpc(server: *Server, arena: *std.heap.ArenaAllocator, parser: *std.json.Parser, json: []const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var tree = try parser.parse(json);
    defer tree.deinit();

    const id = if (tree.root.Object.get("id")) |id| switch (id) {
        .Integer => |int| types.RequestId{ .Integer = int },
        .String => |str| types.RequestId{ .String = str },
        else => types.RequestId{ .Integer = 0 },
    } else types.RequestId{ .Integer = 0 };

    if (id == .String and std.mem.startsWith(u8, id.String, "register"))
        return;
    if (id == .String and std.mem.eql(u8, id.String, "i_haz_configuration")) {
        logger.info("Setting configuration...", .{});

        // NOTE: Does this work with other editors?
        // Yes, String ids are officially supported by LSP
        // but not sure how standard this "standard" really is

        const result = tree.root.Object.get("result").?.Array;

        inline for (std.meta.fields(Config)) |field, index| {
            const value = result.items[index];
            const ft = if (@typeInfo(field.field_type) == .Optional)
                @typeInfo(field.field_type).Optional.child
            else
                field.field_type;
            const ti = @typeInfo(ft);

            if (value != .Null) {
                const new_value: field.field_type = switch (ft) {
                    []const u8 => switch (value) {
                        .String => |s| try server.allocator.dupe(u8, s), // TODO: Allocation model? (same with didChangeConfiguration); imo this isn't *that* bad but still
                        else => @panic("Invalid configuration value"), // TODO: Handle this
                    },
                    else => switch (ti) {
                        .Int => switch (value) {
                            .Integer => |s| std.math.cast(ft, s) orelse @panic("Invalid configuration value"),
                            else => @panic("Invalid configuration value"), // TODO: Handle this
                        },
                        .Bool => switch (value) {
                            .Bool => |b| b,
                            else => @panic("Invalid configuration value"), // TODO: Handle this
                        },
                        else => @compileError("Not implemented for " ++ @typeName(ft)),
                    },
                };
                logger.debug("setting configuration option '{s}' to '{any}'", .{ field.name, new_value });
                @field(server.config, field.name) = new_value;
            }
        }

        try server.config.configChanged(server.allocator, null);

        return;
    }

    std.debug.assert(tree.root.Object.get("method") != null);
    const method = tree.root.Object.get("method").?.String;

    const start_time = std.time.milliTimestamp();
    defer {
        const end_time = std.time.milliTimestamp();
        logger.debug("Took {}ms to process method {s}", .{ end_time - start_time, method });
    }

    const method_map = .{
        .{ "initialized", void, initializedHandler },
        .{"$/cancelRequest"},
        .{"textDocument/willSave"},
        .{ "initialize", requests.Initialize, initializeHandler },
        .{ "shutdown", void, shutdownHandler },
        .{ "textDocument/didOpen", requests.OpenDocument, openDocumentHandler },
        .{ "textDocument/didChange", requests.ChangeDocument, changeDocumentHandler },
        .{ "textDocument/didSave", requests.SaveDocument, saveDocumentHandler },
        .{ "textDocument/didClose", requests.CloseDocument, closeDocumentHandler },
        .{ "textDocument/semanticTokens/full", requests.SemanticTokensFull, semanticTokensFullHandler },
        .{ "textDocument/inlayHint", requests.InlayHint, inlayHintHandler },
        .{ "textDocument/completion", requests.Completion, completionHandler },
        .{ "textDocument/signatureHelp", requests.SignatureHelp, signatureHelpHandler },
        .{ "textDocument/definition", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/typeDefinition", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/implementation", requests.GotoDefinition, gotoDefinitionHandler },
        .{ "textDocument/declaration", requests.GotoDeclaration, gotoDeclarationHandler },
        .{ "textDocument/hover", requests.Hover, hoverHandler },
        .{ "textDocument/documentSymbol", requests.DocumentSymbols, documentSymbolsHandler },
        .{ "textDocument/formatting", requests.Formatting, formattingHandler },
        .{ "textDocument/rename", requests.Rename, renameHandler },
        .{ "textDocument/references", requests.References, referencesHandler },
        .{ "textDocument/documentHighlight", requests.DocumentHighlight, documentHighlightHandler },
        .{ "workspace/didChangeConfiguration", std.json.Value, didChangeConfigurationHandler },
    };

    // Hack to avoid `return`ing in the inline for, which causes bugs.
    var done: ?anyerror = null;
    inline for (method_map) |method_info| {
        if (done == null and std.mem.eql(u8, method, method_info[0])) {
            if (method_info.len == 1) {
                logger.warn("method not mapped: {s}", .{method});
                done = error.HackDone;
            } else if (method_info[1] != void) {
                const ReqT = method_info[1];
                if (requests.fromDynamicTree(arena, ReqT, tree.root)) |request_obj| {
                    done = error.HackDone;
                    done = extractErr(method_info[2](server, arena, id, request_obj));
                } else |err| {
                    if (err == error.MalformedJson) {
                        logger.warn("Could not create request type {s} from JSON {s}", .{ @typeName(ReqT), json });
                    }
                    done = err;
                }
            } else {
                done = error.HackDone;
                (method_info[2])(server, arena, id) catch |err| {
                    done = err;
                };
            }
        }
    }
    if (done) |err| switch (err) {
        error.MalformedJson => return try respondGeneric(id, null_result_response),
        error.HackDone => return,
        else => return err,
    };

    // Boolean value is true if the method is a request (and thus the client
    // needs a response) or false if the method is a notification (in which
    // case it should be silently ignored)
    const unimplemented_map = std.ComptimeStringMap(bool, .{
        .{ "textDocument/codeAction", true },
        .{ "textDocument/codeLens", true },
        .{ "textDocument/documentLink", true },
        .{ "textDocument/rangeFormatting", true },
        .{ "textDocument/onTypeFormatting", true },
        .{ "textDocument/prepareRename", true },
        .{ "textDocument/foldingRange", true },
        .{ "textDocument/selectionRange", true },
        .{ "textDocument/semanticTokens/range", true },
        .{ "workspace/didChangeWorkspaceFolders", false },
    });

    if (unimplemented_map.get(method)) |request| {
        // TODO: Unimplemented methods, implement them and add them to server capabilities.
        if (request) {
            return try respondGeneric(id, null_result_response);
        }

        logger.debug("Notification method {s} is not implemented", .{method});
        return;
    }
    if (tree.root.Object.get("id")) |_| {
        return try respondGeneric(id, not_implemented_response);
    }
    logger.debug("Method without return value not implemented: {s}", .{method});
}

pub fn loop(server: *Server) !void {
    // This JSON parser is passed to processJsonRpc and reset.
    var json_parser = std.json.Parser.init(server.allocator, false);
    defer json_parser.deinit();

    // Arena used for temporary allocations while handling a request
    var arena = std.heap.ArenaAllocator.init(server.allocator);
    defer arena.deinit();

    const reader = std.io.getStdIn().reader();

    while (keep_running) {
        const headers = readRequestHeader(arena.allocator(), reader) catch |err| {
            logger.err("{s}; exiting!", .{@errorName(err)});
            return;
        };
        const buf = try arena.allocator().alloc(u8, headers.content_length);
        try reader.readNoEof(buf);

        try server.processJsonRpc(&arena, &json_parser, buf);
        json_parser.reset();
        arena.deinit();
        arena.state = .{};
    }
}

const stack_frames = switch (zig_builtin.mode) {
    .Debug => 10,
    else => 0,
};

pub fn main() anyerror!void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = stack_frames }){ .backing_allocator = std.heap.page_allocator };
    defer _ = gpa_state.deinit();

    defer keep_running = false;

    var allocator = gpa_state.allocator();
    if (tracy.enable_allocation) {
        allocator = tracy.tracyAllocator(allocator).allocator();
    }

    analysis.init(allocator);
    defer analysis.deinit();

    // Check arguments.
    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    if (!args_it.skip()) @panic("Could not find self argument");

    var config_path: ?[]const u8 = null;
    defer if (config_path) |path| allocator.free(path);

    var next_arg_config_path = false;
    while (args_it.next()) |arg| {
        if (next_arg_config_path) {
            config_path = try allocator.dupe(u8, arg);
            next_arg_config_path = false;
            continue;
        }

        if (std.mem.eql(u8, arg, "--debug-log")) {
            actual_log_level = .debug;
            std.debug.print("Enabled debug logging\n", .{});
        } else if (std.mem.eql(u8, arg, "--config-path")) {
            next_arg_config_path = true;
            continue;
        } else if (std.mem.eql(u8, arg, "config") or std.mem.eql(u8, arg, "configure")) {
            try setup.wizard(allocator);
            return;
        } else {
            std.debug.print("Unrecognized argument {s}\n", .{arg});
            std.os.exit(1);
        }
    }

    if (next_arg_config_path) {
        std.debug.print("Expected configuration file path after --config-path argument\n", .{});
        return;
    }

    // Read the configuration, if any.
    const config_parse_options = std.json.ParseOptions{ .allocator = allocator };
    var config = Config{};
    defer std.json.parseFree(Config, config, config_parse_options);

    config_read: {
        if (config_path) |path| {
            if (Config.loadFromFile(allocator, path)) |conf| {
                config = conf;
                break :config_read;
            }
            std.debug.print("Could not open configuration file '{s}'\n", .{path});
            std.debug.print("Falling back to a lookup in the local and global configuration folders\n", .{});
            allocator.free(path);
            config_path = null;
        }
        if (try known_folders.getPath(allocator, .local_configuration)) |path| {
            config_path = path;
            if (Config.loadFromFolder(allocator, path)) |conf| {
                config = conf;
                break :config_read;
            }
        }
        if (try known_folders.getPath(allocator, .global_configuration)) |path| {
            if (config_path) |cp| allocator.free(cp);
            config_path = path;
            if (Config.loadFromFolder(allocator, path)) |conf| {
                config = conf;
                break :config_read;
            }
        }
        if (config_path) |cp| allocator.free(cp);
        logger.info("No config file zls.json found.", .{});
        config_path = null;
    }

    try config.configChanged(allocator, config_path);

    var document_store = try DocumentStore.init(
        allocator,
        &config,
    );
    defer document_store.deinit();

    var server = Server{
        .config = config,
        .allocator = allocator,
        .document_store = document_store,
    };

    try server.loop();

    if (builtin_completions) |compls| {
        allocator.free(compls);
    }
}
