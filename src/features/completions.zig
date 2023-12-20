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
const DocumentScope = @import("../DocumentScope.zig");
const analyser_completions = @import("../analyser/completions.zig");

const data = @import("version_data");
const snipped_data = @import("../snippets.zig");

fn typeToCompletion(
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(types.CompletionItem),
    ty: Analyser.Type,
    orig_handle: *DocumentStore.Handle,
    either_descriptor: ?[]const u8,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    switch (ty.data) {
        .pointer => |info| switch (info.size) {
            .One => {
                if (ty.is_type_val) return;

                try list.append(arena, .{
                    .label = "*",
                    .kind = .Operator,
                    .insertText = "*",
                    .insertTextFormat = .PlainText,
                });

                if (try analyser.resolveDerefType(ty)) |child_ty| {
                    try typeToCompletion(server, analyser, arena, list, child_ty, orig_handle, null);
                }
            },
            .Slice => {
                if (ty.is_type_val) return;

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
            },
            .Many, .C => {},
        },
        .optional => |_| {
            try list.append(arena, .{
                .label = "?",
                .kind = .Operator,
                .insertText = "?",
                .insertTextFormat = .PlainText,
            });
        },
        .other => |n| try nodeToCompletion(
            server,
            analyser,
            arena,
            list,
            n,
            orig_handle,
            null,
            ty.is_type_val,
            null,
            either_descriptor,
            null,
        ),
        .ip_index => |payload| try analyser_completions.dotCompletions(
            arena,
            list,
            analyser.ip,
            payload.index,
            ty.is_type_val,
        ),
        .either => |bruh| {
            for (bruh) |a|
                try typeToCompletion(server, analyser, arena, list, a.type_with_handle, orig_handle, a.descriptor);
        },
        else => {},
    }
}

fn completionDoc(
    server: *Server,
    arena: std.mem.Allocator,
    either_descriptor: ?[]const u8,
    doc_comments: []const []const u8,
) error{OutOfMemory}!std.meta.FieldType(types.CompletionItem, .documentation) {
    var list = std.ArrayList(u8).init(arena);
    const writer = list.writer();

    if (either_descriptor) |ed|
        try writer.print("`Conditionally available: {s}`", .{ed});

    for (doc_comments) |dc| {
        if (list.items.len != 0)
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
    orig_handle: *DocumentStore.Handle,
    orig_name: ?[]const u8,
    is_type_val: bool,
    parent_is_type_val: ?bool,
    either_descriptor: ?[]const u8,
    doc_strings_0: ?*std.ArrayListUnmanaged([]const u8),
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const node = node_handle.node;
    const handle = node_handle.handle;
    const tree = handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const token_tags = tree.tokens.items(.tag);

    var doc_strings_1 = std.ArrayListUnmanaged([]const u8){};
    const doc_strings = doc_strings_0 orelse &doc_strings_1;
    if (try Analyser.getDocComments(arena, handle.tree, node)) |doc|
        try doc_strings.append(arena, doc);

    if (try analyser.resolveVarDeclAlias(node_handle)) |result| {
        const context = DeclToCompletionContext{
            .server = server,
            .analyser = analyser,
            .arena = arena,
            .completions = list,
            .orig_handle = orig_handle,
            .orig_name = Analyser.getDeclName(tree, node),
            .either_descriptor = either_descriptor,
            .doc_strings = doc_strings,
        };
        return try declToCompletion(context, result);
    }

    if (try analyser.resolveTypeOfNode(node_handle)) |resolved_type| {
        if (try resolved_type.docComments(arena)) |doc|
            try doc_strings.append(arena, doc);
    }

    const doc = try completionDoc(
        server,
        arena,
        either_descriptor,
        doc_strings.items,
    );

    if (ast.isContainer(tree, node)) {
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
                try typeToCompletion(server, analyser, arena, list, ty, orig_handle, either_descriptor);
            }
            if (try analyser.resolveTypeOfNode(.{ .node = datas[node].rhs, .handle = handle })) |ty| {
                try typeToCompletion(server, analyser, arena, list, ty, orig_handle, either_descriptor);
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

                const is_type_function = Analyser.isTypeFunction(tree, func);

                try list.append(arena, .{
                    .label = func_name,
                    .kind = if (is_type_function) .Struct else .Function,
                    .documentation = doc,
                    .detail = Analyser.getFunctionSignature(tree, func),
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
                .detail = Analyser.getContainerFieldSignature(tree, field),
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
        => unreachable,
        .optional_type => unreachable,
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
    orig_handle: *DocumentStore.Handle,
    orig_name: ?[]const u8 = null,
    parent_is_type_val: ?bool = null,
    either_descriptor: ?[]const u8 = null,
    doc_strings: ?*std.ArrayListUnmanaged([]const u8) = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: Analyser.DeclWithHandle) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = decl_handle.handle.tree;
    const decl = decl_handle.decl;

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

    switch (decl_handle.decl) {
        .ast_node => |node| try nodeToCompletion(
            context.server,
            context.analyser,
            context.arena,
            context.completions,
            .{ .node = node, .handle = decl_handle.handle },
            context.orig_handle,
            context.orig_name,
            false,
            context.parent_is_type_val,
            context.either_descriptor,
            context.doc_strings,
        ),
        .param_payload => |pay| {
            const param = pay.get(tree).?;
            const name = tree.tokenSlice(param.name_token.?);
            const doc = try completionDoc(
                context.server,
                context.arena,
                context.either_descriptor,
                if (try decl_handle.docComments(context.arena)) |doc| &.{doc} else &.{},
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
        .error_union_error,
        .array_payload,
        .assign_destructure,
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
                if (try decl_handle.docComments(context.arena)) |doc| &.{doc} else &.{},
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
    handle: *DocumentStore.Handle,
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
    server: *Server,
    allocator: std.mem.Allocator,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    snippets: []const snipped_data.Snipped,
) error{OutOfMemory}!void {
    try completions.ensureUnusedCapacity(allocator, snippets.len);

    const use_snippets = server.config.enable_snippets and server.client_capabilities.supports_snippets;
    for (snippets) |snipped| {
        if (!use_snippets and snipped.kind == .Snippet) continue;

        completions.appendAssumeCapacity(.{
            .label = snipped.label,
            .kind = snipped.kind,
            .detail = if (use_snippets) snipped.text else null,
            .insertText = if (use_snippets) snipped.text else null,
            .insertTextFormat = if (use_snippets and snipped.text != null) .Snippet else .PlainText,
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
            .insertText = if (server.client_capabilities.include_at_in_builtins) insert_text else insert_text[1..],
            .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
            .documentation = .{
                .MarkupContent = .{
                    .kind = .markdown,
                    .value = builtin.documentation,
                },
            },
        };
    }

    try formatCompletionDetails(server, arena, completions);

    return completions;
}

fn completeGlobal(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *DocumentStore.Handle, pos_index: usize) error{OutOfMemory}![]types.CompletionItem {
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
    try populateSnippedCompletions(server, arena, &completions, &snipped_data.generic);
    try formatCompletionDetails(server, arena, completions.items);

    return completions.toOwnedSlice(arena);
}

fn completeFieldAccess(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *DocumentStore.Handle, source_index: usize, loc: offsets.Loc) error{OutOfMemory}!?[]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    const ty = (try analyser.getFieldAccessType(handle, source_index, loc)) orelse return null;
    try typeToCompletion(server, analyser, arena, &completions, ty, handle, null);
    try formatCompletionDetails(server, arena, completions.items);

    return try completions.toOwnedSlice(arena);
}

fn formatCompletionDetails(server: *const Server, arena: std.mem.Allocator, completions: []types.CompletionItem) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!server.client_capabilities.label_details_support) return;

    for (completions) |*item| {
        try formatDetailedLabel(item, arena);
    }
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
        const s: usize = std.mem.indexOf(u8, it, "(") orelse return;
        const e: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
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
                const us: usize = std.mem.indexOf(u8, it, "(") orelse return;
                const ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
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
            const e: usize = eqlPos orelse it.len;
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
        const s: usize = std.mem.indexOf(u8, it, ":") orelse return;
        const e: usize = std.mem.indexOf(u8, it, "=") orelse return;

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
        const s: usize = std.mem.indexOf(u8, it, " ") orelse return;
        const e: usize = std.mem.indexOf(u8, it, "=") orelse it.len;
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
            const us: usize = std.mem.indexOf(u8, it, "(") orelse return;
            const ue: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
            if (ue < us) {
                log.warn("something wrong when trying to build label detail for a .Constant|union {s}", .{it});
                return;
            }
            item.labelDetails.?.description = it[us - 5 .. ue + 1];
        } else if (std.mem.indexOf(u8, it, "= enum(")) |_| {
            const es: usize = std.mem.indexOf(u8, it, "(") orelse return;
            const ee: usize = std.mem.lastIndexOf(u8, it, ")") orelse return;
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

fn completeError(server: *Server, arena: std.mem.Allocator, handle: *DocumentStore.Handle) error{OutOfMemory}![]types.CompletionItem {
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

fn completeDot(document_store: *DocumentStore, analyser: *Analyser, arena: std.mem.Allocator, handle: *DocumentStore.Handle, source_index: usize) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = handle.tree;
    const token_tags = tree.tokens.items(.tag);

    // as invoked source_index points to the char/token after the `.`, do `- 1`
    const dot_token_index = offsets.sourceIndexToTokenIndex(tree, source_index - 1);
    if (dot_token_index < 2) return &.{};

    var completions = std.ArrayListUnmanaged(types.CompletionItem){};

    blk: {
        const dot_context = getEnumLiteralContext(tree, dot_token_index) orelse break :blk;
        const containers = try collectContainerNodes(
            analyser,
            arena,
            handle,
            offsets.tokenToLoc(tree, dot_context.identifier_token_index).end,
            &dot_context,
        );
        for (containers) |container| {
            if (dot_context.likely == .enum_arg and !container.isEnumType()) continue;
            if (dot_context.likely != .struct_field)
                if (!container.isEnumType() and !container.isUnionType()) continue;
            try collectContainerFields(arena, container, &completions);
        }
    }

    if (completions.items.len != 0) return completions.toOwnedSlice(arena);

    // Prevent compl for float numbers, eg `1.`
    //  Ideally this would also `or token_tags[dot_token_index - 1] != .equal`,
    //  which would mean the only possibility left would be `var enum_val = .`.
    if (token_tags[dot_token_index - 1] == .number_literal or token_tags[dot_token_index - 1] != .equal) return &.{};

    // `var enum_val = .` or the get*Context logic failed because of syntax errors (parser didn't create the necessary node(s))
    const enum_completions = try document_store.enumCompletionItems(arena, handle.*);
    return enum_completions;
}

/// asserts that `pos_context` is one of the following:
///  - `.import_string_literal`
///  - `.cinclude_string_literal`
///  - `.embedfile_string_literal`
///  - `.string_literal`
fn completeFileSystemStringLiteral(
    arena: std.mem.Allocator,
    store: *DocumentStore,
    handle: DocumentStore.Handle,
    pos_context: Analyser.PositionContext,
) ![]types.CompletionItem {
    var completions: DocumentScope.CompletionSet = .{};

    const loc = switch (pos_context) {
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        .string_literal,
        => |loc| loc,
        else => unreachable,
    };

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
        _ = store.collectIncludeDirs(arena, handle, &search_paths) catch |err| {
            log.err("failed to resolve include paths: {}", .{err});
            return &.{};
        };
    } else {
        const document_path = try URI.parse(arena, handle.uri);
        try search_paths.append(arena, std.fs.path.dirname(document_path).?);
    }

    for (search_paths.items) |path| {
        if (!std.fs.path.isAbsolute(path)) continue;
        const dir_path = if (std.fs.path.isAbsolute(completing)) path else try std.fs.path.join(arena, &.{ path, completing });

        var iterable_dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch continue;
        defer iterable_dir.close();
        var it = iterable_dir.iterateAssumeFirstIteration();

        while (it.next() catch null) |entry| {
            const expected_extension = switch (pos_context) {
                .import_string_literal => ".zig",
                .cinclude_string_literal => ".h",
                .embedfile_string_literal => null,
                .string_literal => null,
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
        if (handle.associated_build_file) |uri| blk: {
            const build_file = store.getBuildFile(uri).?;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            try completions.ensureUnusedCapacity(arena, build_config.packages.len);
            for (build_config.packages) |pkg| {
                completions.putAssumeCapacity(.{
                    .label = pkg.name,
                    .kind = .Module,
                    .detail = pkg.path,
                }, {});
            }
        } else if (DocumentStore.isBuildFile(handle.uri)) blk: {
            const build_file = store.getBuildFile(handle.uri) orelse break :blk;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            try completions.ensureUnusedCapacity(arena, build_config.deps_build_roots.len);
            for (build_config.deps_build_roots) |dbr| {
                completions.putAssumeCapacity(.{
                    .label = dbr.name,
                    .kind = .Module,
                    .detail = dbr.path,
                }, {});
            }
        }

        try completions.ensureUnusedCapacity(arena, 2);
        if (store.config.zig_lib_path) |zig_lib_path| {
            completions.putAssumeCapacity(.{
                .label = "std",
                .kind = .Module,
                .detail = zig_lib_path,
            }, {});
        }
        if (store.config.builtin_path) |builtin_path| {
            completions.putAssumeCapacity(.{
                .label = "builtin",
                .kind = .Module,
                .detail = builtin_path,
            }, {});
        }
    }

    return completions.keys();
}

pub fn completionAtIndex(server: *Server, analyser: *Analyser, arena: std.mem.Allocator, handle: *DocumentStore.Handle, source_index: usize) error{OutOfMemory}!?types.CompletionList {
    const source = handle.tree.source;

    // Provide `top_level_decl_data` only if `offsets.lineSliceUntilIndex(handle.tree.source, source_index).len` is
    // 0 => Empty new line, manually triggered
    // 1 => This is the very first char on a given line
    const at_line_start = offsets.lineSliceUntilIndex(source, source_index).len < 2;
    if (at_line_start) {
        var completions = std.ArrayListUnmanaged(types.CompletionItem){};
        try populateSnippedCompletions(server, arena, &completions, &snipped_data.top_level_decl_data);

        return .{ .isIncomplete = false, .items = completions.items };
    }

    const pos_context = try Analyser.getPositionContext(arena, source, source_index, false);

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
        .string_literal,
        => blk: {
            if (pos_context == .string_literal and !DocumentStore.isBuildFile(handle.uri)) break :blk null;
            break :blk completeFileSystemStringLiteral(arena, &server.document_store, handle.*, pos_context) catch |err| {
                log.err("failed to get file system completions: {}", .{err});
                return null;
            };
        },
        else => null,
    };

    const completions = maybe_completions orelse return null;

    if (server.config.completions_with_replace) {
        // The cursor is in the middle of a word or before a @, so we can replace
        // the remaining identifier with the completion instead of just inserting.
        // TODO Identify function call/struct init and replace the whole thing.
        const lookahead_context = try Analyser.getPositionContext(arena, source, source_index, true);
        if (server.client_capabilities.supports_apply_edits and
            pos_context != .import_string_literal and
            pos_context != .cinclude_string_literal and
            pos_context != .embedfile_string_literal and
            pos_context != .string_literal and
            pos_context.loc() != null and
            lookahead_context.loc() != null and
            pos_context.loc().?.end != lookahead_context.loc().?.end)
        {
            var end = lookahead_context.loc().?.end;
            while (end < source.len and (std.ascii.isAlphanumeric(source[end]) or source[end] == '"')) {
                end += 1;
            }

            const replaceLoc = offsets.Loc{ .start = lookahead_context.loc().?.start, .end = end };
            const replaceRange = offsets.locToRange(source, replaceLoc, server.offset_encoding);

            for (completions) |*item| {
                item.textEdit = .{
                    .TextEdit = .{
                        .newText = item.insertText orelse item.label,
                        .range = replaceRange,
                    },
                };
            }
        }
    }

    // truncate completions
    for (completions) |*item| {
        if (item.detail) |det| {
            if (det.len > server.client_capabilities.max_detail_length) {
                item.detail = det[0..server.client_capabilities.max_detail_length];
            }
        }
    }

    // TODO: config for sorting rule?
    for (completions) |*c| {
        const prefix = kindToSortScore(c.kind.?) orelse continue;

        c.sortText = try std.fmt.allocPrint(arena, "{s}{s}", .{ prefix, c.label });

        if (source_index < source.len and source[source_index] == '(') {
            c.insertText = c.label;
            c.insertTextFormat = .PlainText;
        }
    }

    return .{ .isIncomplete = false, .items = completions };
}

// <--------------------------------------------------------------------------->
//               completions/enum_literal.zig staging area
// <--------------------------------------------------------------------------->

const EnumLiteralContext = struct {
    const Likely = enum { // TODO: better name, tagged union?
        /// `mye: Enum = .`, `abc.field = .` or `f(.{.field = .` if typeof(field) is enumlike)
        /// `== .`, `!= .`, switch case
        enum_literal,
        /// Same as above, but`f() = .` or `identifier.f() = .` are ignored, ie lhs of `=` is a fn call
        enum_assignment,
        /// the enum is a fn arg, eg `f(.`
        enum_arg,
        /// `S{.`, `var s:S = .{.`, `f(.{.` or `a.f(.{.`
        struct_field,
        // TODO Abort, don't list any enums
        //  - lhs of `=` is a fn call
        //  - able to resolve the type of a switch condition, but it is a struct
        //  ? Would this lead to confusion/perceived as the server not responding? Push an error diag ?
        // / Abort, don't list any enums
        // invalid,
    };
    likely: Likely,
    identifier_token_index: Ast.TokenIndex = 0,
    fn_arg_index: usize = 0,
    need_ret_type: bool = false,
};

fn getEnumLiteralContext(
    tree: Ast,
    dot_token_index: Ast.TokenIndex,
) ?EnumLiteralContext {
    const token_tags = tree.tokens.items(.tag);

    // Allow using `1.` (parser workaround)
    var token_index = if (token_tags[dot_token_index - 1] == .number_literal)
        (dot_token_index - 2)
    else
        (dot_token_index - 1);

    var dot_context = EnumLiteralContext{ .likely = .enum_literal };

    switch (token_tags[token_index]) {
        .equal, .equal_equal, .bang_equal => |tok_tag| {
            token_index -= 1;
            if (tok_tag == .equal) {
                if ((token_tags[token_index] == .r_paren)) return null; // `..) = .`, ie lhs is a fn call
                dot_context.likely = .enum_assignment;
            }
            dot_context.identifier_token_index = token_index;
        },
        .l_brace, .comma, .l_paren => {
            dot_context = getSwitchOrStructInitContext(tree, dot_token_index) orelse return null;
        },
        else => return null,
    }
    return dot_context;
}

/// Looks for an identifier that can be passed to `collectContainerNodes()`
/// Returns the token index of the identifer
/// If the identifier is a `fn_name`, `fn_arg_index` is the index of the fn's param
fn getSwitchOrStructInitContext(
    tree: Ast,
    dot_index: Ast.TokenIndex,
) ?EnumLiteralContext {
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

    var likely: EnumLiteralContext.Likely = .struct_field;

    var fn_arg_index: usize = 0;
    var need_ret_type: bool = false;

    // The following logic is weird because we assume at least one .l_brace and/or .l_paren
    // => a couple of helpful constants:
    const even = 1; // we haven't found an opening brace or paren so the count is even
    const one_opening = 0; // an unmatched opening brace or paren makes the depth 0

    // look for .identifier followed by .l_brace, skipping matches at braces_depth 'even'+
    var braces_depth: i32 = even;
    var parens_depth: i32 = even;
    find_identifier: while (upper_index > 0) : (upper_index -= 1) {
        switch (token_tags[upper_index]) {
            .r_brace => braces_depth += 1,
            .l_brace => braces_depth -= 1,
            .period => if (braces_depth == one_opening and token_tags[upper_index + 1] == .l_brace) { // anon struct init `.{.`
                // if the preceding token is `=`, then this might be a `var foo: Foo = .{.`
                if (upper_index > 1 and token_tags[upper_index - 1] == .equal) {
                    upper_index -= 2; // eat `= .`
                    break :find_identifier;
                }
                // We never return from this branch/condition to the `find_identifier: while ..` loop, so reset and reuse these
                fn_arg_index = 0;
                braces_depth = even; // not actually looking for/expecting an uneven number of braces, just making use of the helpful const
                parens_depth = even;
                while (upper_index > 0) : (upper_index -= 1) {
                    switch (token_tags[upper_index]) {
                        .r_brace => braces_depth += 1,
                        .l_brace => braces_depth -= 1,
                        .r_paren => parens_depth += 1,
                        .l_paren => {
                            parens_depth -= 1;
                            if (parens_depth == one_opening and token_tags[upper_index - 1] == .identifier) {
                                upper_index -= 1;
                                break :find_identifier;
                            }
                        },
                        .comma => if (braces_depth == even and parens_depth == even) { // those only matter when outside of braces and before final '('
                            fn_arg_index += 1;
                        },
                        .semicolon => return null, // generic exit; maybe also .keyword_(var/const)
                        else => {},
                    }
                }
                break :find_identifier;
            },
            // We're fishing for a `f(some, other{}, .<cursor>enum)`
            .r_paren => {
                parens_depth += 1;
                if (braces_depth == one_opening) { // The opening brace is preceded by a r_paren => evaluate
                    need_ret_type = true;
                    var token_index = upper_index - 1; // if `switch` we need the last token of the condition
                    parens_depth = even;
                    // Walk backwards counting parens until one_opening then check the preceding token's tag
                    while (token_index > 0) : (token_index -= 1) {
                        switch (token_tags[token_index]) {
                            .r_paren => parens_depth += 1,
                            .l_paren => {
                                parens_depth -= 1;
                                if (parens_depth == one_opening)
                                    switch (token_tags[token_index - 1]) {
                                        .keyword_switch => {
                                            likely = .enum_literal;
                                            upper_index -= 1; // eat the switch's .r_paren
                                            break :find_identifier;
                                        },
                                        .identifier => {
                                            upper_index = token_index - 1; // the fn name
                                            break :find_identifier;
                                        },
                                        else => return null,
                                    };
                            },
                            .semicolon => return null,
                            else => {},
                        }
                    }
                }
            },
            .l_paren => parens_depth -= 1,
            .comma => if (braces_depth == even and parens_depth == even) { // those only matter when outside of braces and before final '('
                fn_arg_index += 1;
            },
            // Have we arrived at an .identifier matching the criteria?
            .identifier => switch (token_tags[upper_index + 1]) {
                .l_brace => if (braces_depth == one_opening) break :find_identifier, // `S{.`
                .l_paren => if (braces_depth == even and parens_depth == one_opening) { // `f(.`
                    likely = .enum_arg;
                    break :find_identifier;
                },
                else => {},
            },
            // Exit conditions
            .semicolon => return null, // generic exit; maybe also .keyword_(var/const)
            else => {},
        }
    }
    // Maybe we simply ran out of tokens?
    // FIXME: This creates a 'blind spot' if the first node in a file is a .container_field_init
    if (upper_index == 0) return null;

    return EnumLiteralContext{
        .likely = likely,
        .identifier_token_index = upper_index,
        .fn_arg_index = fn_arg_index,
        .need_ret_type = need_ret_type,
    };
}

/// Given a Type that is a container, adds it's `.container_field*`s to completions
pub fn collectContainerFields(
    arena: std.mem.Allocator,
    container: Analyser.Type,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
) error{OutOfMemory}!void {
    const node_handle = switch (container.data) {
        .other => |n| n,
        else => return,
    };
    const node = node_handle.node;
    const handle = node_handle.handle;
    var buffer: [2]Ast.Node.Index = undefined;
    const container_decl = Ast.fullContainerDecl(handle.tree, &buffer, node) orelse return;
    for (container_decl.ast.members) |member| {
        const field = handle.tree.fullContainerField(member) orelse continue;
        const name = handle.tree.tokenSlice(field.ast.main_token);
        try completions.append(arena, .{
            .label = name,
            .kind = if (field.ast.tuple_like) .EnumMember else .Field,
            .detail = Analyser.getContainerFieldSignature(handle.tree, field),
            .insertText = name,
            .insertTextFormat = .PlainText,
        });
    }
}

/// Resolves `identifier`/`path.to.identifier` at `source_index`
/// If the `identifier` is a container `fn_arg_index` is unused
/// If the `identifier` is a `fn_name`/`identifier.fn_name`, tries to resolve
///         `fn_name`'s `fn_arg_index`'s param type
fn collectContainerNodes(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
    dot_context: *const EnumLiteralContext,
) error{OutOfMemory}![]Analyser.Type {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var types_with_handles = std.ArrayListUnmanaged(Analyser.Type){};

    switch (try Analyser.getPositionContext(arena, handle.tree.source, source_index, false)) {
        .var_access => |loc| try collectVarAccessContainerNodes(analyser, arena, handle, loc, dot_context, &types_with_handles),
        .field_access => |loc| try collectFieldAccessContainerNodes(analyser, arena, handle, loc, dot_context, &types_with_handles),
        .enum_literal => |loc| try collectEnumLiteralContainerNodes(analyser, arena, handle, loc, &types_with_handles),
        else => {},
    }
    return types_with_handles.toOwnedSlice(arena);
}

fn collectVarAccessContainerNodes(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    dot_context: *const EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const symbol_decl = try analyser.lookupSymbolGlobal(handle, handle.tree.source[loc.start..loc.end], loc.end) orelse return;
    const result = try symbol_decl.resolveType(analyser) orelse return;
    const type_expr = try analyser.resolveDerefType(result) orelse result;
    if (type_expr.isFunc()) {
        const fn_proto_node_handle = type_expr.data.other; // this assumes that function types can only be Ast nodes
        const fn_proto_node = fn_proto_node_handle.node;
        const fn_proto_handle = fn_proto_node_handle.handle;
        if (dot_context.likely == .enum_literal or dot_context.need_ret_type) { // => we need f()'s return type
            var buf: [1]Ast.Node.Index = undefined;
            const full_fn_proto = fn_proto_handle.tree.fullFnProto(&buf, fn_proto_node).?;
            const has_body = fn_proto_handle.tree.nodes.items(.tag)[fn_proto_node] == .fn_decl;
            const body = fn_proto_handle.tree.nodes.items(.data)[fn_proto_node].rhs;
            var node_type = try analyser.resolveReturnType(full_fn_proto, fn_proto_handle, if (has_body) body else null) orelse return;
            if (try analyser.resolveUnwrapErrorUnionType(node_type, .right)) |unwrapped| node_type = unwrapped;
            try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
            return;
        }
        const fn_param_decl = Analyser.Declaration{ .param_payload = .{
            .func = fn_proto_node,
            .param_index = @intCast(dot_context.fn_arg_index),
        } };
        const fn_param_decl_with_handle = Analyser.DeclWithHandle{ .decl = fn_param_decl, .handle = fn_proto_handle };
        const param_type = try fn_param_decl_with_handle.resolveType(analyser) orelse return;
        try types_with_handles.append(arena, param_type);
        return;
    }
    try type_expr.getAllTypesWithHandlesArrayList(arena, types_with_handles);
}

fn collectFieldAccessContainerNodes(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    dot_context: *const EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    // XXX It could be any/all of the preceding logic, but this fn seems
    // inconsistent at returning name_loc for methods, ie
    // `abc.method() == .` => fails, `abc.method(.{}){.}` => ok
    // it also fails for `abc.xyz.*` ... currently we take advantage of this quirk
    const name_loc = Analyser.identifierLocFromPosition(loc.end, handle) orelse {
        const result = try analyser.getFieldAccessType(handle, loc.end, loc) orelse return;
        const container = try analyser.resolveDerefType(result) orelse result;
        if (try analyser.resolveUnwrapErrorUnionType(container, .right)) |unwrapped| {
            if (unwrapped.isEnumType() or unwrapped.isUnionType()) {
                try types_with_handles.append(arena, unwrapped);
                return;
            }
        }
        // if (dot_context.likely == .enum_literal and !(container.isEnumType() or container.isUnionType())) return;
        try container.getAllTypesWithHandlesArrayList(arena, types_with_handles);
        return;
    };
    const name = offsets.locToSlice(handle.tree.source, name_loc);
    const decls = try analyser.getSymbolFieldAccesses(arena, handle, loc.end, loc, name) orelse return;
    for (decls) |decl| {
        var node_type = try decl.resolveType(analyser) orelse continue;
        // Unwrap `identifier.opt_enum_field = .` or `identifier.opt_cont_field = .{.`
        if (dot_context.likely == .enum_assignment or dot_context.likely == .struct_field) {
            if (try analyser.resolveOptionalChildType(node_type)) |unwrapped| node_type = unwrapped;
        }
        if (node_type.isFunc()) {
            const fn_proto_node_handle = node_type.data.other; // this assumes that function types can only be Ast nodes
            const fn_proto_node = fn_proto_node_handle.node;
            const fn_proto_handle = fn_proto_node_handle.handle;
            var buf: [1]Ast.Node.Index = undefined;
            const full_fn_proto = fn_proto_handle.tree.fullFnProto(&buf, fn_proto_node).?;
            if (dot_context.need_ret_type) { // => we need f()'s return type
                const has_body = fn_proto_handle.tree.nodes.items(.tag)[fn_proto_node] == .fn_decl;
                const body = fn_proto_handle.tree.nodes.items(.data)[fn_proto_node].rhs;
                node_type = try analyser.resolveReturnType(full_fn_proto, fn_proto_handle, if (has_body) body else null) orelse continue;
                if (try analyser.resolveUnwrapErrorUnionType(node_type, .right)) |unwrapped| node_type = unwrapped;
                try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
                continue;
            }
            var maybe_fn_param: ?Ast.full.FnProto.Param = undefined;
            var fn_param_iter = full_fn_proto.iterate(&fn_proto_handle.tree);
            // don't have the luxury of referencing an `Ast.full.Call`
            // check if the first symbol is a `T` or an instance_of_T
            const additional_index: usize = blk: {
                // NOTE: `loc` points to offsets within `handle`, not `node_type.decl.handle`
                const field_access_slice = handle.tree.source[loc.start..loc.end];
                if (field_access_slice[0] == '@') break :blk 1; // assume `@import("..").some.Other{.}`
                var symbol_iter = std.mem.tokenizeScalar(u8, field_access_slice, '.');
                const first_symbol = symbol_iter.next() orelse continue;
                const symbol_decl = try analyser.lookupSymbolGlobal(handle, first_symbol, loc.start) orelse continue;
                const symbol_type = try symbol_decl.resolveType(analyser) orelse continue;
                if (!symbol_type.is_type_val) { // then => instance_of_T
                    if (try analyser.hasSelfParam(fn_proto_handle, full_fn_proto)) break :blk 2;
                }
                break :blk 1; // is `T`, no SelfParam
            };
            for (dot_context.fn_arg_index + additional_index) |_| maybe_fn_param = ast.nextFnParam(&fn_param_iter);
            const param = maybe_fn_param orelse continue;
            if (param.type_expr == 0) continue;
            const param_rcts = try collectContainerNodes(
                analyser,
                arena,
                fn_proto_handle,
                offsets.nodeToLoc(fn_proto_handle.tree, param.type_expr).end,
                dot_context,
            );
            for (param_rcts) |prct| try types_with_handles.append(arena, prct);
            continue;
        }
        try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
    }
}

fn collectEnumLiteralContainerNodes(
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const alleged_field_name = handle.tree.source[loc.start + 1 .. loc.end];
    const dot_index = offsets.sourceIndexToTokenIndex(handle.tree, loc.start);
    const el_dot_context = getSwitchOrStructInitContext(handle.tree, dot_index) orelse return;
    const containers = try collectContainerNodes(
        analyser,
        arena,
        handle,
        handle.tree.tokens.items(.start)[el_dot_context.identifier_token_index],
        &el_dot_context,
    );
    for (containers) |container| {
        const container_instance = container.instanceTypeVal() orelse container;
        const member_decl = try container_instance.lookupSymbol(analyser, alleged_field_name) orelse continue;
        var member_type = try member_decl.resolveType(analyser) orelse continue;
        // Unwrap `x{ .fld_w_opt_type =`
        if (try analyser.resolveOptionalUnwrap(member_type)) |unwrapped| member_type = unwrapped;
        try types_with_handles.append(arena, member_type);
    }
}
