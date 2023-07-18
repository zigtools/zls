const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.zls_completions);

const Server = @import("../Server.zig");
const Config = @import("../Config.zig");
const DocumentStore = @import("../DocumentStore.zig");
const types = @import("../lsp.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");
const tracy = @import("../tracy.zig");
const URI = @import("../uri.zig");
const analyser_completions = @import("../analyser/completions.zig");

const data = @import("../data/data.zig");
const snipped_data = @import("../data/snippets.zig");

fn typeToCompletion(
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    field_access: Analyser.FieldAccessReturn,
    orig_handle: *const DocumentStore.Handle,
    either_descriptor: ?[]const u8,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const type_handle = field_access.original;
    switch (type_handle.type.data) {
        .slice => {
            if (!type_handle.type.is_type_val) {
                try list.append(arena, .{
                    .label = "len",
                    .detail = "const len: usize",
                    .kind = .Field,
                    .insertText = "len",
                    .insertTextFormat = .PlainText,
                });
                try list.append(arena, .{
                    .label = "ptr",
                    .kind = .Field,
                    .insertText = "ptr",
                    .insertTextFormat = .PlainText,
                });
            }
        },
        .pointer => |t| {
            if (server.config.operator_completions) {
                try list.append(arena, .{
                    .label = "*",
                    .kind = .Operator,
                    .insertText = "*",
                    .insertTextFormat = .PlainText,
                });
            }
            try typeToCompletion(server, analyser, arena, list, .{ .original = t.* }, orig_handle, null);
        },
        .other => |n| try nodeToCompletion(
            server,
            analyser,
            arena,
            list,
            .{ .node = n, .handle = type_handle.handle },
            field_access.unwrapped,
            orig_handle,
            null,
            null,
            type_handle.type.is_type_val,
            null,
            either_descriptor,
        ),
        .@"comptime" => |co| try analyser_completions.dotCompletions(
            arena,
            list,
            co.interpreter.ip,
            co.value.index,
            type_handle.type.is_type_val,
            co.value.node_idx,
        ),
        .either => |bruh| {
            for (bruh) |a|
                try typeToCompletion(server, analyser, arena, list, .{ .original = a.type_with_handle }, orig_handle, a.descriptor);
        },
        else => {},
    }
}

fn completionDoc(
    server: *Server,
    arena: std.mem.Allocator,
    either_descriptor: ?[]const u8,
    doc_comments: ?[]const u8,
) error{OutOfMemory}!@TypeOf(@as(types.CompletionItem, undefined).documentation) {
    var list = std.ArrayList(u8).init(arena);
    const writer = list.writer();

    if (either_descriptor) |ed|
        try writer.print("`Conditionally available: {s}`", .{ed});

    if (doc_comments) |dc| {
        if (either_descriptor != null)
            try writer.writeAll("\n\n");
        try writer.writeAll(dc);
    }

    if (list.items.len == 0)
        return null;

    return .{ .MarkupContent = types.MarkupContent{
        .kind = if (server.client_capabilities.completion_doc_supports_md) .markdown else .plaintext,
        .value = list.items,
    } };
}

fn nodeToCompletion(
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    node_handle: Analyser.NodeWithHandle,
    unwrapped: ?Analyser.TypeWithHandle,
    orig_handle: *const DocumentStore.Handle,
    orig_name: ?[]const u8,
    orig_doc: ?[]const u8,
    is_type_val: bool,
    parent_is_type_val: ?bool,
    either_descriptor: ?[]const u8,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);

    var doc_comments = orig_doc orelse (try Analyser.getDocComments(arena, handle.tree, node));
    if (try analyser.resolveVarDeclAlias(node_handle)) |result| {
        const context = DeclToCompletionContext{
            .server = server,
            .analyser = analyser,
            .arena = arena,
            .completions = list,
            .orig_handle = orig_handle,
            .orig_name = Analyser.getDeclName(tree, node),
            .orig_doc = doc_comments,
            .either_descriptor = either_descriptor,
        };
        return try declToCompletion(context, result);
    }
    if (doc_comments == null) {
        if (try analyser.resolveTypeOfNode(node_handle)) |resolved_type| {
            doc_comments = try resolved_type.docComments(arena);
        }
    }

    const doc = try completionDoc(
        server,
        arena,
        either_descriptor,
        doc_comments,
    );

    if (ast.isContainer(handle.tree, node)) {
        const context = DeclToCompletionContext{
            .server = server,
            .analyser = analyser,
            .arena = arena,
            .completions = list,
            .orig_handle = orig_handle,
            .parent_is_type_val = is_type_val,
            .either_descriptor = either_descriptor,
        };
        try analyser.iterateSymbolsContainer(
            node_handle,
            orig_handle,
            declToCompletion,
            context,
            !is_type_val,
        );
    }

    switch (node_tags[node]) {
        .merge_error_sets => {
            if (try analyser.resolveTypeOfNode(.{ .node = datas[node].lhs, .handle = handle })) |ty| {
                try typeToCompletion(server, analyser, arena, list, .{ .original = ty }, orig_handle, either_descriptor);
            }
            if (try analyser.resolveTypeOfNode(.{ .node = datas[node].rhs, .handle = handle })) |ty| {
                try typeToCompletion(server, analyser, arena, list, .{ .original = ty }, orig_handle, either_descriptor);
            }
        },
        else => {},
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
            const func = tree.fullFnProto(&buf, node).?;
            if (func.name_token) |name_token| {
                const func_name = orig_name orelse tree.tokenSlice(name_token);
                const use_snippets = server.config.enable_snippets and server.client_capabilities.supports_snippets;

                const insert_text = blk: {
                    if (!use_snippets) break :blk func_name;

                    const skip_self_param = !(parent_is_type_val orelse true) and try analyser.hasSelfParam(handle, func);

                    const use_placeholders = server.config.enable_argument_placeholders;
                    if (use_placeholders) {
                        var it = func.iterate(&tree);
                        if (skip_self_param) _ = ast.nextFnParam(&it);
                        break :blk try Analyser.getFunctionSnippet(arena, func_name, &it);
                    }

                    switch (func.ast.params.len) {
                        // No arguments, leave cursor at the end
                        0 => break :blk try std.fmt.allocPrint(arena, "{s}()", .{func_name}),
                        1 => {
                            if (skip_self_param) {
                                // The one argument is a self parameter, leave cursor at the end
                                break :blk try std.fmt.allocPrint(arena, "{s}()", .{func_name});
                            }

                            // Non-self parameter, leave the cursor in the parentheses
                            break :blk try std.fmt.allocPrint(arena, "{s}(${{1:}})", .{func_name});
                        },
                        // Atleast one non-self parameter, leave the cursor in the parentheses
                        else => break :blk try std.fmt.allocPrint(arena, "{s}(${{1:}})", .{func_name}),
                    }
                };

                const is_type_function = Analyser.isTypeFunction(handle.tree, func);

                try list.append(arena, .{
                    .label = func_name,
                    .kind = if (is_type_function) .Struct else .Function,
                    .documentation = doc,
                    .detail = Analyser.getFunctionSignature(handle.tree, func),
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
            const var_decl = tree.fullVarDecl(node).?;
            const name = orig_name orelse tree.tokenSlice(var_decl.ast.mut_token + 1);
            const is_const = token_tags[var_decl.ast.mut_token] == .keyword_const;

            try list.append(arena, .{
                .label = name,
                .kind = if (is_const) .Constant else .Variable,
                .documentation = doc,
                .detail = try Analyser.getVariableSignature(arena, tree, var_decl),
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = tree.fullContainerField(node).?;
            const name = tree.tokenSlice(field.ast.main_token);
            try list.append(arena, .{
                .label = name,
                .kind = if (field.ast.tuple_like) .EnumMember else .Field,
                .documentation = doc,
                .detail = Analyser.getContainerFieldSignature(handle.tree, field),
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
        .array_type,
        .array_type_sentinel,
        => {
            try list.append(arena, .{
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
            const ptr_type = ast.fullPtrType(tree, node).?;

            switch (ptr_type.size) {
                .One, .C, .Many => if (server.config.operator_completions) {
                    try list.append(arena, .{
                        .label = "*",
                        .kind = .Operator,
                        .insertText = "*",
                        .insertTextFormat = .PlainText,
                    });
                },
                .Slice => {
                    try list.append(arena, .{
                        .label = "ptr",
                        .kind = .Field,
                        .insertText = "ptr",
                        .insertTextFormat = .PlainText,
                    });
                    try list.append(arena, .{
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
                try typeToCompletion(server, analyser, arena, list, .{ .original = actual_type }, orig_handle, either_descriptor);
            }
            return;
        },
        .optional_type => {
            if (server.config.operator_completions) {
                try list.append(arena, .{
                    .label = "?",
                    .kind = .Operator,
                    .insertText = "?",
                    .insertTextFormat = .PlainText,
                });
            }
            return;
        },
        .multiline_string_literal,
        .string_literal,
        => {
            try list.append(arena, .{
                .label = "len",
                .detail = "const len: usize",
                .kind = .Field,
                .insertText = "len",
                .insertTextFormat = .PlainText,
            });
        },
        else => if (Analyser.nodeToString(tree, node)) |string| {
            try list.append(arena, .{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = offsets.nodeToSlice(tree, node),
                .insertText = string,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

const DeclToCompletionContext = struct {
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    orig_handle: *const DocumentStore.Handle,
    orig_name: ?[]const u8 = null,
    orig_doc: ?[]const u8 = null,
    parent_is_type_val: ?bool = null,
    either_descriptor: ?[]const u8 = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: Analyser.DeclWithHandle) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = decl_handle.handle.tree;
    const decl = decl_handle.decl.*;

    const is_cimport = std.mem.eql(u8, std.fs.path.basename(decl_handle.handle.uri), "cimport.zig");
    if (is_cimport) {
        const name = tree.tokenSlice(decl_handle.nameToken());
        if (std.mem.startsWith(u8, name, "_")) return;
        // TODO figuring out which declarations should be excluded could be made more complete and accurate
        // by translating an empty file to acquire all exclusions
        const exclusions = std.ComptimeStringMap(void, .{
            .{ "linux", {} },
            .{ "unix", {} },
            .{ "WIN32", {} },
            .{ "WINNT", {} },
            .{ "WIN64", {} },
        });
        if (exclusions.has(name)) return;
    }

    switch (decl_handle.decl.*) {
        .ast_node => |node| try nodeToCompletion(
            context.server,
            context.analyser,
            context.arena,
            context.completions,
            .{ .node = node, .handle = decl_handle.handle },
            null,
            context.orig_handle,
            context.orig_name,
            context.orig_doc,
            false,
            context.parent_is_type_val,
            context.either_descriptor,
        ),
        .param_payload => |pay| {
            const param = pay.param;
            const name = tree.tokenSlice(param.name_token.?);
            const doc = try completionDoc(
                context.server,
                context.arena,
                context.either_descriptor,
                try decl_handle.docComments(context.arena),
            );

            try context.completions.append(context.arena, .{
                .label = name,
                .kind = .Constant,
                .documentation = doc,
                .detail = ast.paramSlice(tree, param),
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
        .pointer_payload,
        .error_union_payload,
        .array_payload,
        .array_index,
        .switch_payload,
        .label_decl,
        => {
            const name = tree.tokenSlice(decl_handle.nameToken());

            try context.completions.append(context.arena, .{
                .label = name,
                .kind = if (decl == .label_decl) .Text else .Variable,
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
        .error_token => |token| {
            const name = tree.tokenSlice(token);
            const doc = try completionDoc(
                context.server,
                context.arena,
                context.either_descriptor,
                try decl_handle.docComments(context.arena),
            );

            try context.completions.append(context.arena, .{
                .label = name,
                .kind = .Constant,
                .documentation = doc,
                .detail = try std.fmt.allocPrint(context.arena, "error.{s}", .{name}),
                .insertText = name,
                .insertTextFormat = .PlainText,
            });
        },
    }
}

fn completeLabel(
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    pos_index: usize,
) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .analyser = analyser,
        .arena = arena,
        .completions = &completions,
        .orig_handle = handle,
    };
    try Analyser.iterateLabels(handle, pos_index, declToCompletion, context);

    return completions.toOwnedSlice(arena);
}

fn populateSnippedCompletions(
    allocator: std.mem.Allocator,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    snippets: []const snipped_data.Snipped,
    config: Config,
) error{OutOfMemory}!void {
    try completions.ensureUnusedCapacity(allocator, snippets.len);

    for (snippets) |snipped| {
        if (!config.enable_snippets and snipped.kind == .Snippet) continue;

        completions.appendAssumeCapacity(.{
            .label = snipped.label,
            .kind = snipped.kind,
            .detail = if (config.enable_snippets) snipped.text else null,
            .insertText = if (config.enable_snippets) snipped.text else null,
            .insertTextFormat = if (config.enable_snippets and snipped.text != null) .Snippet else .PlainText,
        });
    }
}

fn completeBuiltin(server: *Server, arena: std.mem.Allocator) error{OutOfMemory}!?[]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const completions = try arena.alloc(types.CompletionItem, data.builtins.len);
    for (completions, data.builtins) |*out, builtin| {
        const use_snippets = server.config.enable_snippets and server.client_capabilities.supports_snippets;
        const insert_text = if (use_snippets) builtin.snippet else builtin.name;
        out.* = types.CompletionItem{
            .label = builtin.name,
            .kind = .Function,
            .filterText = builtin.name[1..],
            .detail = builtin.signature,
            .insertText = if (server.config.include_at_in_builtins) insert_text else insert_text[1..],
            .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
            .documentation = .{
                .MarkupContent = .{
                    .kind = .markdown,
                    .value = builtin.documentation,
                },
            },
        };
    }

    if (server.client_capabilities.label_details_support) {
        for (completions) |*item| {
            try formatDetailedLabel(item, arena);
        }
    }

    return completions;
}

fn completeGlobal(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, pos_index: usize) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const context = DeclToCompletionContext{
        .server = server,
        .analyser = analyser,
        .arena = arena,
        .completions = &completions,
        .orig_handle = handle,
    };
    try analyser.iterateSymbolsGlobal(handle, pos_index, declToCompletion, context);
    try populateSnippedCompletions(arena, &completions, &snipped_data.generic, server.config.*);

    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailedLabel(item, arena);
        }
    }

    return completions.toOwnedSlice(arena);
}

fn completeFieldAccess(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, source_index: usize, loc: offsets.Loc) error{OutOfMemory}!?[]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    var held_loc = try arena.dupeZ(u8, offsets.locToSlice(handle.text, loc));
    var tokenizer = std.zig.Tokenizer.init(held_loc);

    const result = (try analyser.getFieldAccessType(handle, source_index, &tokenizer)) orelse return null;
    try typeToCompletion(server, analyser, arena, &completions, result, handle, null);
    if (server.client_capabilities.label_details_support) {
        for (completions.items) |*item| {
            try formatDetailedLabel(item, arena);
        }
    }

    return try completions.toOwnedSlice(arena);
}

fn formatDetailedLabel(item: *types.CompletionItem, arena: std.mem.Allocator) error{OutOfMemory}!void {
    // NOTE: this is not ideal, we should build a detailed label like we do for label/detail
    // because this implementation is very loose, nothing is formatted properly so we need to clean
    // things a little bit, which is quite messy
    // but it works, it provide decent results

    std.debug.assert(item.kind != null);
    if (item.detail == null)
        return;

    const detail = item.detail.?[0..@min(1024, item.detail.?.len)];
    var detailLen: usize = detail.len;
    var it: []u8 = try arena.alloc(u8, detailLen);

    detailLen -= std.mem.replace(u8, detail, "    ", " ", it) * 3;
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

    // log.info("## label: {s} it: {s} kind: {} isValue: {}", .{item.label, it, item.kind, isValue});

    if (std.mem.startsWith(u8, it, "fn ") or std.mem.startsWith(u8, it, "@")) {
        var s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        var e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
        if (e < s) {
            log.warn("something wrong when trying to build label detail for {s} kind: {}", .{ it, item.kind.? });
            return;
        }

        item.detail = item.label;
        item.labelDetails = .{ .detail = it[s .. e + 1], .description = it[e + 1 ..] };

        if (item.kind.? == .Constant) {
            if (std.mem.indexOf(u8, it, "= struct")) |_| {
                item.labelDetails.?.description = "struct";
            } else if (std.mem.indexOf(u8, it, "= union")) |_| {
                var us: usize = std.mem.indexOf(u8, it, "(") orelse return;
                var ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
                if (ue < us) {
                    log.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                    return;
                }

                item.labelDetails.?.description = it[us - 5 .. ue + 1];
            }
        }
    } else if ((item.kind.? == .Variable or item.kind.? == .Constant) and (isVar or isConst)) {
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
    } else if (item.kind.? == .Variable) {
        var s: usize = std.mem.indexOf(u8, it, ":") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse return;

        if (e < s) {
            log.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // log.info("s: {} -> {}", .{s, e});
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
    } else if (item.kind.? == .Constant or item.kind.? == .Field) {
        var s: usize = std.mem.indexOf(u8, it, " ") orelse return;
        var e: usize = std.mem.indexOf(u8, it, "=") orelse it.len;
        if (e < s) {
            log.warn("something wrong when trying to build label detail for a .Variable {s}", .{it});
            return;
        }
        // log.info("s: {} -> {}", .{s, e});
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
                log.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[us - 5 .. ue + 1];
        } else if (std.mem.indexOf(u8, it, "= enum(")) |_| {
            var es: usize = std.mem.indexOf(u8, it, "(") orelse return;
            var ee: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ee < es) {
                log.warn("something wrong when trying to build label detail for a .Constant|enum {s}", .{it});
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
    } else if (item.kind.? == .Field and isValue) {
        item.insertText = item.label;
        item.insertTextFormat = .PlainText;
        item.detail = item.label;
        item.labelDetails = .{
            .detail = "", // left
            .description = item.label, // right
        };
    } else {
        // TODO: if something is missing, it needs to be implemented here
    }

    // if (item.labelDetails != null)
    //     logger.info("labelDetails: {s}  ::  {s}", .{item.labelDetails.?.detail, item.labelDetails.?.description});
}

fn completeError(server: *Server, arena: std.mem.Allocator, handle: *const DocumentStore.Handle) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    return try server.document_store.errorCompletionItems(arena, handle.*);
}

fn kindToSortScore(kind: types.CompletionItemKind) ?[]const u8 {
    return switch (kind) {
        .Module => "1_", // use for packages
        .Folder => "2_",
        .File => "3_",

        .Constant => "1_",

        .Variable => "2_",
        .Field => "3_",
        .Function => "4_",

        .Keyword, .Snippet, .EnumMember => "5_",

        .Class,
        .Interface,
        .Struct,
        .Enum,
        // Union?
        .TypeParameter,
        => "6_",

        else => {
            log.debug(@typeName(types.CompletionItemKind) ++ "{s} has no sort score specified!", .{@tagName(kind)});
            return null;
        },
    };
}

/// Given a TypeWithHandle that is a container, adds it's `.container_field*`s to completions
pub fn collectContainerFields(
    arena: std.mem.Allocator,
    container: Analyser.TypeWithHandle,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
) error{OutOfMemory}!void {
    const node = switch (container.type.data) {
        .other => |n| n,
        else => return,
    };
    var buffer: [2]Ast.Node.Index = undefined;
    const container_decl = Ast.fullContainerDecl(container.handle.tree, &buffer, node) orelse return;
    for (container_decl.ast.members) |member| {
        const field = container.handle.tree.fullContainerField(member) orelse continue;
        const name = container.handle.tree.tokenSlice(field.ast.main_token);
        try completions.append(arena, .{
            .label = name,
            .kind = if (field.ast.tuple_like) .EnumMember else .Field,
            .detail = Analyser.getContainerFieldSignature(container.handle.tree, field),
            .insertText = name,
            .insertTextFormat = .PlainText,
        });
    }
}

/// Resolves `identifier`/`path.to.identifier` at `text_index`
/// If the `identifier` is a container `fn_arg_index` is unused
/// If the `identifier` is a `fn_name`/`identifier.fn_name`, tries to resolve
///         `fn_name`'s `fn_arg_index`'s param type
fn resolveContainer(
    document_store: *DocumentStore,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *const DocumentStore.Handle,
    text_index: usize,
    fn_arg_index: usize,
) error{OutOfMemory}![]Analyser.TypeWithHandle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var types_with_handles = std.ArrayListUnmanaged(Analyser.TypeWithHandle){};

    const pos_context = try Analyser.getPositionContext(arena, handle.text, text_index, false);

    switch (pos_context) {
        .var_access => |loc| va: {
            const symbol_decl = try analyser.lookupSymbolGlobal(handle, handle.text[loc.start..loc.end], loc.end) orelse break :va;
            if (symbol_decl.decl.* != .ast_node) break :va;
            const nodes_tags = symbol_decl.handle.tree.nodes.items(.tag);
            if (nodes_tags[symbol_decl.decl.ast_node] == .fn_decl) {
                var buf: [1]Ast.Node.Index = undefined;
                const full_fn_proto = symbol_decl.handle.tree.fullFnProto(&buf, symbol_decl.decl.ast_node) orelse break :va;
                var maybe_fn_param: ?Ast.full.FnProto.Param = undefined;
                var fn_param_iter = full_fn_proto.iterate(&symbol_decl.handle.tree);
                for (fn_arg_index + 1) |_| maybe_fn_param = ast.nextFnParam(&fn_param_iter);
                const param = maybe_fn_param orelse break :va;
                if (param.type_expr == 0) break :va;
                const param_rcts = try resolveContainer(
                    document_store,
                    analyser,
                    arena,
                    symbol_decl.handle,
                    offsets.nodeToLoc(symbol_decl.handle.tree, param.type_expr).end,
                    fn_arg_index,
                );
                for (param_rcts) |prct| try types_with_handles.append(arena, prct);
                break :va;
            }
            const node_data = symbol_decl.handle.tree.nodes.items(.data)[symbol_decl.decl.ast_node];
            if (node_data.rhs == 0) break :va;
            switch (nodes_tags[node_data.rhs]) {
                // decl is `const Alias = @import("MyStruct.zig");`
                .builtin_call_two => {
                    var buffer: [2]Ast.Node.Index = undefined;
                    const params = ast.builtinCallParams(
                        symbol_decl.handle.tree,
                        node_data.rhs,
                        &buffer,
                    ) orelse break :va;

                    const main_tokens = symbol_decl.handle.tree.nodes.items(.main_token);
                    const call_name = symbol_decl.handle.tree.tokenSlice(main_tokens[node_data.rhs]);

                    if (std.mem.eql(u8, call_name, "@import")) {
                        if (params.len == 0) break :va;
                        const import_param = params[0];
                        if (nodes_tags[import_param] != .string_literal) break :va;

                        const import_str = symbol_decl.handle.tree.tokenSlice(main_tokens[import_param]);
                        const import_uri = try document_store.uriFromImportStr(
                            arena,
                            symbol_decl.handle.*,
                            import_str[1 .. import_str.len - 1],
                        ) orelse break :va;

                        const node_handle = document_store.getOrLoadHandle(import_uri) orelse break :va;
                        try types_with_handles.append(
                            arena,
                            Analyser.TypeWithHandle{
                                .handle = node_handle,
                                .type = .{
                                    .data = .{ .other = 0 },
                                    .is_type_val = true,
                                },
                            },
                        );
                    }
                },
                // decl is `const Alias = path.to.MyStruct` or `const Alias = @import("file.zig").MyStruct;`
                .field_access => {
                    const node_loc = offsets.nodeToLoc(symbol_decl.handle.tree, node_data.rhs);
                    const rcts = try resolveContainer(
                        document_store,
                        analyser,
                        arena,
                        handle,
                        node_loc.end,
                        fn_arg_index,
                    );
                    for (rcts) |rct| try types_with_handles.append(arena, rct);
                },
                // decl is `const AliasB = AliasA;` (alias of an alias)
                .identifier => {
                    const node_loc = offsets.nodeToLoc(symbol_decl.handle.tree, node_data.rhs);
                    const rcts = try resolveContainer(
                        document_store,
                        analyser,
                        arena,
                        handle,
                        node_loc.end,
                        fn_arg_index,
                    );
                    for (rcts) |rct| try types_with_handles.append(arena, rct);
                },
                // decl is `const MyStruct = struct {..};
                else => {
                    if (ast.isContainer(symbol_decl.handle.tree, node_data.rhs))
                        try types_with_handles.append(
                            arena,
                            Analyser.TypeWithHandle{
                                .handle = symbol_decl.handle,
                                .type = .{
                                    .data = .{ .other = node_data.rhs },
                                    .is_type_val = true,
                                },
                            },
                        )
                    else {
                        const node_type = try analyser.resolveTypeOfNode(.{ .node = symbol_decl.decl.ast_node, .handle = symbol_decl.handle }) orelse break :va;
                        for (try node_type.getAllTypesWithHandles(arena)) |either| {
                            const node = switch (either.type.data) {
                                .other => |n| n,
                                else => continue,
                            };
                            if (ast.isContainer(symbol_decl.handle.tree, node))
                                try types_with_handles.append(
                                    arena,
                                    Analyser.TypeWithHandle{
                                        .handle = symbol_decl.handle,
                                        .type = .{
                                            .data = .{ .other = node },
                                            .is_type_val = true,
                                        },
                                    },
                                );
                        }
                    }
                    //Analyser.DeclWithHandle{ .handle = symbol_decl.handle, .decl = .{.array_payload = .{}} };
                },
            }
        },
        .field_access => |loc| fa: {
            const name_loc = Analyser.identifierLocFromPosition(loc.end, handle) orelse break :fa;
            const name = offsets.locToSlice(handle.text, name_loc);
            const held_loc = offsets.locMerge(loc, name_loc);
            const decls = try analyser.getSymbolFieldAccesses(arena, handle, loc.end, held_loc, name) orelse break :fa;
            for (decls) |decl| {
                const decl_node = switch (decl.decl.*) {
                    .ast_node => |ast_node| ast_node,
                    else => continue,
                };
                const node_type = try analyser.resolveTypeOfNode(.{ .node = decl_node, .handle = decl.handle }) orelse continue;
                if (node_type.isFunc()) {
                    var buf: [1]Ast.Node.Index = undefined;
                    const full_fn_proto = node_type.handle.tree.fullFnProto(&buf, node_type.type.data.other) orelse continue;
                    var maybe_fn_param: ?Ast.full.FnProto.Param = undefined;
                    var fn_param_iter = full_fn_proto.iterate(&node_type.handle.tree);
                    // don't have the luxury of referencing an `Ast.full.Call`
                    // check if the first symbol is a `T` or an instance_of_T
                    const additional_index: usize = blk: {
                        // NOTE: `loc` points to offsets within `handle`, not `node_type.decl.handle`
                        const field_access_slice = handle.text[loc.start..loc.end];
                        var symbol_iter = std.mem.tokenizeScalar(u8, field_access_slice, '.');
                        const first_symbol = symbol_iter.next() orelse continue;
                        const symbol_decl = try analyser.lookupSymbolGlobal(handle, first_symbol, loc.start) orelse continue;
                        const symbol_type = try symbol_decl.resolveType(analyser) orelse continue;
                        if (!symbol_type.type.is_type_val) { // then => instance_of_T
                            if (try analyser.hasSelfParam(node_type.handle, full_fn_proto)) break :blk 2;
                        }
                        break :blk 1; // is `T`, no SelfParam
                    };
                    for (fn_arg_index + additional_index) |_| maybe_fn_param = ast.nextFnParam(&fn_param_iter);
                    const param = maybe_fn_param orelse continue;
                    if (param.type_expr == 0) continue;
                    const param_rcts = try resolveContainer(
                        document_store,
                        analyser,
                        arena,
                        node_type.handle,
                        offsets.nodeToLoc(node_type.handle.tree, param.type_expr).end,
                        fn_arg_index,
                    );
                    for (param_rcts) |prct| try types_with_handles.append(arena, prct);
                    continue;
                }
                switch (node_type.type.data) {
                    .other => |n| if (ast.isContainer(node_type.handle.tree, n)) {
                        try types_with_handles.append(arena, node_type);
                        continue;
                    },
                    else => {},
                }
                for (try node_type.getAllTypesWithHandles(arena)) |either| {
                    const enode = switch (either.type.data) {
                        .other => |n| n,
                        else => continue,
                    };
                    if (ast.isContainer(node_type.handle.tree, enode))
                        try types_with_handles.append(
                            arena,
                            Analyser.TypeWithHandle{
                                .handle = node_type.handle,
                                .type = .{
                                    .data = .{ .other = enode },
                                    .is_type_val = true,
                                },
                            },
                        );
                }
            }
        },
        .enum_literal => |loc| el: {
            const alleged_field_name = handle.text[loc.start + 1 .. loc.end];
            const dot_index = offsets.sourceIndexToTokenIndex(handle.tree, loc.start);
            var field_fn_arg_index: usize = 0;
            const id_token_index = getIdentifierTokenIndexAndFnArgIndex(handle.tree, dot_index, &field_fn_arg_index) orelse break :el;
            const containers = try resolveContainer(
                document_store,
                analyser,
                arena,
                handle,
                handle.tree.tokens.items(.start)[id_token_index],
                field_fn_arg_index,
            );
            for (containers) |container| {
                const node = switch (container.type.data) {
                    .other => |n| n,
                    else => continue,
                };
                var buffer: [2]Ast.Node.Index = undefined;
                const container_decl = Ast.fullContainerDecl(container.handle.tree, &buffer, node) orelse continue;
                for (container_decl.ast.members) |member| {
                    const field = container.handle.tree.fullContainerField(member) orelse continue;
                    if (std.mem.eql(u8, container.handle.tree.tokenSlice(field.ast.main_token), alleged_field_name)) {
                        if (ast.isContainer(container.handle.tree, field.ast.type_expr)) {
                            try types_with_handles.append(
                                arena,
                                Analyser.TypeWithHandle{
                                    .handle = container.handle,
                                    .type = .{
                                        .data = .{ .other = field.ast.type_expr },
                                        .is_type_val = true,
                                    },
                                },
                            );
                            continue;
                        }
                        const end = offsets.tokenToLoc(container.handle.tree, ast.lastToken(container.handle.tree, field.ast.type_expr)).end;
                        const param_rcts = try resolveContainer(
                            document_store,
                            analyser,
                            arena,
                            container.handle,
                            end,
                            fn_arg_index,
                        );
                        for (param_rcts) |prct| try types_with_handles.append(arena, prct);
                    }
                }
            }
        },
        else => {}, // <- `else =>` of `switch (pos_context)`
    }
    return types_with_handles.toOwnedSlice(arena);
}

/// Looks for an identifier that can be passed to `resolveContainer()`
/// Returns the token index of the identifer
/// If the identifier is a `fn_name`, `fn_arg_index` is the index of the fn's param
fn getIdentifierTokenIndexAndFnArgIndex(
    tree: Ast,
    dot_index: Ast.TokenIndex,
    fn_arg_index_out: *usize,
) ?Ast.TokenIndex {
    // at least 3 tokens should be present, `x{.`
    if (dot_index < 2) return null;
    const token_tags = tree.tokens.items(.tag);
    // pedantic check (can be removed if the "generic exit" conditions below are made to cover more/all cases)
    if (token_tags[dot_index] != .period) return null;
    var upper_index = dot_index - 1;
    // This prevents completions popping up for `x{.field.`
    if (token_tags[upper_index] == .identifier) return null;
    // This prevents completions popping up for `x{.field = .`, ie it would suggest `field` again
    // in this case `fn completeDot` would still provide enum completions
    if (token_tags[upper_index] == .equal) return null;

    var fn_arg_index: usize = 0;

    // look for .identifier followed by .l_brace, skipping matches at depth 0+
    var depth: i32 = 0; // Should end up being negative, ie even the first/single .l_brace would put it at -1; 0+ => nested
    find_identifier: while (upper_index > 0) {
        if (token_tags[upper_index] != .identifier) {
            switch (token_tags[upper_index]) {
                .r_brace => depth += 1,
                .l_brace => depth -= 1,
                .period => if (depth < 0 and token_tags[upper_index + 1] == .l_brace) { // anon struct init `.{.`
                    // if the preceding token is `=`, then this might be a `var foo: Foo = .{.`
                    if (token_tags[upper_index - 1] == .equal) {
                        upper_index -= 2; // eat `= .`
                        break :find_identifier;
                    }
                    var num_braces: i32 = 0;
                    var num_parens: i32 = 0;
                    while (upper_index > 0) : (upper_index -= 1) {
                        switch (token_tags[upper_index]) {
                            .r_brace => num_braces += 1,
                            .l_brace => num_braces -= 1,
                            .r_paren => num_parens += 1,
                            .l_paren => {
                                num_parens -= 1;
                                if (num_parens < 0) {
                                    upper_index -= 1;
                                    break :find_identifier;
                                }
                            },
                            .semicolon => return null, // generic exit; maybe also .keyword_(var/const)
                            .comma => if (num_braces == 0 and num_parens == 0) { // those only matter when outside of braces or parens
                                fn_arg_index += 1;
                            },
                            else => {},
                        }
                    }
                    break :find_identifier;
                },
                .semicolon => return null, // generic exit; maybe also .keyword_(var/const)
                else => {},
            }
        } else if (token_tags[upper_index + 1] == .l_brace and depth < 0) break :find_identifier;
        upper_index -= 1;
    }

    fn_arg_index_out.* = fn_arg_index;
    return upper_index;
}

fn completeDot(document_store: *DocumentStore, analyser: *Analyser, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, source_index: usize) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);

    // as invoked source_index points to the char/token after the `.`, do `- 1`
    var token_index = offsets.sourceIndexToTokenIndex(tree, source_index - 1);

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    struct_init: {
        // This prevents completions popping up for floating point numbers
        // but I discovered it is a very helpful parser workaround to enable providing completions
        // for struct that are declared after the current block !
        // The fact that the logic outside this block (struct_init) already pops up completions for
        // floating point numbers, ie `var a = `1.m` will pop up completions for `m*`, makes me think
        // this hasn't been an issue for many ..
        // if (token_tags[token_index - 1] == .number_literal) break :struct_init; // `var s = MyStruct{.float_field = 1.`

        var fn_arg_index: usize = 0;
        token_index = getIdentifierTokenIndexAndFnArgIndex(tree, token_index, &fn_arg_index) orelse break :struct_init;
        if (token_index == 0) break :struct_init;

        const containers = try resolveContainer(
            document_store,
            analyser,
            arena,
            handle,
            tree.tokens.items(.start)[token_index],
            fn_arg_index,
        );

        for (containers) |container| try collectContainerFields(arena, container, &completions);

        if (completions.items.len != 0) return completions.toOwnedSlice(arena);
    }

    // This prevents completions popping up for floats; token/source_index points to the token/char after the `.`, => `- 2`
    if ((token_index > 1) and (token_tags[token_index - 2] == .number_literal)) return completions.toOwnedSlice(arena);

    var enum_completions = try document_store.enumCompletionItems(arena, handle.*);
    return enum_completions;
}

fn completeFileSystemStringLiteral(
    arena: std.mem.Allocator,
    store: DocumentStore,
    handle: DocumentStore.Handle,
    pos_context: Analyser.PositionContext,
) ![]types.CompletionItem {
    var completions: Analyser.CompletionSet = .{};

    const loc = pos_context.loc().?;
    var completing = handle.tree.source[loc.start + 1 .. loc.end - 1];

    var separator_index = completing.len;
    while (separator_index > 0) : (separator_index -= 1) {
        if (std.fs.path.isSep(completing[separator_index - 1])) break;
    }
    completing = completing[0..separator_index];

    var search_paths: std.ArrayListUnmanaged([]const u8) = .{};
    if (std.fs.path.isAbsolute(completing) and pos_context != .import_string_literal) {
        try search_paths.append(arena, completing);
    } else if (pos_context == .cinclude_string_literal) {
        store.collectIncludeDirs(arena, handle, &search_paths) catch |err| {
            log.err("failed to resolve include paths: {}", .{err});
            return &.{};
        };
    } else {
        var document_path = try URI.parse(arena, handle.uri);
        try search_paths.append(arena, std.fs.path.dirname(document_path).?);
    }

    for (search_paths.items) |path| {
        if (!std.fs.path.isAbsolute(path)) continue;
        const dir_path = if (std.fs.path.isAbsolute(completing)) path else try std.fs.path.join(arena, &.{ path, completing });

        var iterable_dir = std.fs.openIterableDirAbsolute(dir_path, .{}) catch continue;
        defer iterable_dir.close();
        var it = iterable_dir.iterateAssumeFirstIteration();

        while (it.next() catch null) |entry| {
            const expected_extension = switch (pos_context) {
                .import_string_literal => ".zig",
                .cinclude_string_literal => ".h",
                .embedfile_string_literal => null,
                else => unreachable,
            };
            switch (entry.kind) {
                .file => if (expected_extension) |expected| {
                    const actual_extension = std.fs.path.extension(entry.name);
                    if (!std.mem.eql(u8, actual_extension, expected)) continue;
                },
                .directory => {},
                else => continue,
            }

            _ = try completions.getOrPut(arena, types.CompletionItem{
                .label = try arena.dupe(u8, entry.name),
                .detail = if (pos_context == .cinclude_string_literal) path else null,
                .insertText = if (entry.kind == .directory)
                    try std.fmt.allocPrint(arena, "{s}/", .{entry.name})
                else
                    null,
                .kind = if (entry.kind == .file) .File else .Folder,
            });
        }
    }

    if (completing.len == 0 and pos_context == .import_string_literal) {
        if (handle.associated_build_file) |uri| {
            const build_file = store.build_files.get(uri).?;
            try completions.ensureUnusedCapacity(arena, build_file.config.packages.len);

            for (build_file.config.packages) |pkg| {
                completions.putAssumeCapacity(.{
                    .label = pkg.name,
                    .kind = .Module,
                }, {});
            }
        }
    }

    return completions.keys();
}

pub fn completionAtIndex(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *const DocumentStore.Handle, source_index: usize) error{OutOfMemory}!?types.CompletionList {
    const at_line_start = offsets.lineSliceUntilIndex(handle.tree.source, source_index).len == 0;
    if (at_line_start) {
        var completions = std.ArrayListUnmanaged(types.CompletionItem){};
        try populateSnippedCompletions(arena, &completions, &snipped_data.top_level_decl_data, server.config.*);

        return .{ .isIncomplete = false, .items = completions.items };
    }

    const pos_context = try Analyser.getPositionContext(arena, handle.text, source_index, false);

    const maybe_completions = switch (pos_context) {
        .builtin => try completeBuiltin(server, arena),
        .var_access, .empty => try completeGlobal(server, analyser, arena, handle, source_index),
        .field_access => |loc| try completeFieldAccess(server, analyser, arena, handle, source_index, loc),
        .global_error_set => try completeError(server, arena, handle),
        .enum_literal => try completeDot(&server.document_store, analyser, arena, handle, source_index),
        .label => try completeLabel(server, analyser, arena, handle, source_index),
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        => blk: {
            if (!server.config.enable_import_embedfile_argument_completions) break :blk null;

            break :blk completeFileSystemStringLiteral(arena, server.document_store, handle.*, pos_context) catch |err| {
                log.err("failed to get file system completions: {}", .{err});
                return null;
            };
        },
        else => null,
    };

    const completions = maybe_completions orelse return null;

    // The cursor is in the middle of a word or before a @, so we can replace
    // the remaining identifier with the completion instead of just inserting.
    // TODO Identify function call/struct init and replace the whole thing.
    const lookahead_context = try Analyser.getPositionContext(arena, handle.text, source_index, true);
    if (server.client_capabilities.supports_apply_edits and
        pos_context != .import_string_literal and
        pos_context != .cinclude_string_literal and
        pos_context != .embedfile_string_literal and
        pos_context.loc() != null and
        lookahead_context.loc() != null and
        pos_context.loc().?.end != lookahead_context.loc().?.end)
    {
        var end = lookahead_context.loc().?.end;
        while (end < handle.text.len and (std.ascii.isAlphanumeric(handle.text[end]) or handle.text[end] == '"')) {
            end += 1;
        }

        const replaceLoc = offsets.Loc{ .start = lookahead_context.loc().?.start, .end = end };
        const replaceRange = offsets.locToRange(handle.text, replaceLoc, server.offset_encoding);

        for (completions) |*item| {
            item.textEdit = .{
                .TextEdit = .{
                    .newText = item.insertText orelse item.label,
                    .range = replaceRange,
                },
            };
        }
    }

    // truncate completions
    for (completions) |*item| {
        if (item.detail) |det| {
            if (det.len > server.config.max_detail_length) {
                item.detail = det[0..server.config.max_detail_length];
            }
        }
    }

    // TODO: config for sorting rule?
    for (completions) |*c| {
        const prefix = kindToSortScore(c.kind.?) orelse continue;

        c.sortText = try std.fmt.allocPrint(arena, "{s}{s}", .{ prefix, c.label });
    }

    return .{ .isIncomplete = false, .items = completions };
}
