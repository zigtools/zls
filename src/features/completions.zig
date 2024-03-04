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
const tracy = @import("tracy");
const URI = @import("../uri.zig");
const DocumentScope = @import("../DocumentScope.zig");
const analyser_completions = @import("../analyser/completions.zig");

const data = @import("version_data");
const snipped_data = @import("../snippets.zig");

const Builder = struct {
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    orig_handle: *DocumentStore.Handle,
    source_index: usize,
    completions: std.ArrayListUnmanaged(types.CompletionItem),
};

fn typeToCompletion(
    builder: *Builder,
    ty: Analyser.Type,
    either_descriptor: ?[]const u8,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    switch (ty.data) {
        .pointer => |info| switch (info.size) {
            .One, .C => {
                if (ty.is_type_val) return;

                try builder.completions.append(builder.arena, .{
                    .label = "*",
                    .kind = .Operator,
                    .detail = try std.fmt.allocPrint(
                        builder.arena,
                        "{}",
                        .{info.elem_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                    ),
                });

                if (info.size == .C) return;

                if (try builder.analyser.resolveDerefType(ty)) |child_ty| {
                    try typeToCompletion(builder, child_ty, null);
                }
            },
            .Slice => {
                if (ty.is_type_val) return;

                try builder.completions.append(builder.arena, .{
                    .label = "len",
                    .detail = "usize",
                    .kind = .Field,
                });

                var many_ptr_ty = ty;
                many_ptr_ty.is_type_val = true;
                many_ptr_ty.data.pointer.size = .Many;
                try builder.completions.append(builder.arena, .{
                    .label = "ptr",
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(
                        builder.arena,
                        "{}",
                        .{many_ptr_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                    ),
                });
            },
            .Many => {},
        },
        .array => |info| {
            if (ty.is_type_val) return;
            try builder.completions.append(builder.arena, .{
                .label = "len",
                .detail = if (info.elem_count) |count|
                    try std.fmt.allocPrint(builder.arena, "usize = {}", .{count})
                else
                    "usize",
                .kind = .Field,
            });
        },
        .optional => |child_ty| {
            if (ty.is_type_val) return;
            try builder.completions.append(builder.arena, .{
                .label = "?",
                .kind = .Operator,
                .detail = try std.fmt.allocPrint(
                    builder.arena,
                    "{}",
                    .{child_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                ),
            });
        },
        .other => |node_handle| try nodeToCompletion(
            builder,
            node_handle,
            null,
            ty.is_type_val,
            null,
            either_descriptor,
            null,
        ),
        .ip_index => |payload| try analyser_completions.dotCompletions(
            builder.arena,
            &builder.completions,
            builder.analyser.ip,
            payload.index,
        ),
        .either => |either_entries| {
            for (either_entries) |entry| {
                const entry_ty = Analyser.Type{ .data = entry.type_data, .is_type_val = ty.is_type_val };
                try typeToCompletion(builder, entry_ty, entry.descriptor);
            }
        },
        .error_union,
        .union_tag,
        .compile_error,
        => {},
    }
}

fn completionDoc(
    builder: *Builder,
    either_descriptor: ?[]const u8,
    doc_comments: []const []const u8,
) error{OutOfMemory}!std.meta.FieldType(types.CompletionItem, .documentation) {
    var list = std.ArrayList(u8).init(builder.arena);
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
        .kind = if (builder.server.client_capabilities.completion_doc_supports_md) .markdown else .plaintext,
        .value = list.items,
    } };
}

fn nodeToCompletion(
    builder: *Builder,
    node_handle: Analyser.NodeWithHandle,
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
    if (try Analyser.getDocComments(builder.arena, handle.tree, node)) |doc|
        try doc_strings.append(builder.arena, doc);

    if (try builder.analyser.resolveVarDeclAlias(node_handle)) |result| {
        const context = DeclToCompletionContext{
            .builder = builder,
            .orig_name = Analyser.getDeclName(tree, node),
            .either_descriptor = either_descriptor,
            .doc_strings = doc_strings,
        };
        try declToCompletion(context, result);
        return;
    }

    if (try builder.analyser.resolveTypeOfNode(node_handle)) |resolved_type| {
        if (try resolved_type.docComments(builder.arena)) |doc|
            try doc_strings.append(builder.arena, doc);
    }

    const doc = try completionDoc(
        builder,
        either_descriptor,
        doc_strings.items,
    );

    if (ast.isContainer(tree, node)) {
        const context = DeclToCompletionContext{
            .builder = builder,
            .parent_is_type_val = is_type_val,
            .either_descriptor = either_descriptor,
        };
        try builder.analyser.iterateSymbolsContainer(
            node_handle,
            builder.orig_handle,
            declToCompletion,
            context,
            !is_type_val,
        );
    }

    switch (node_tags[node]) {
        .merge_error_sets => {
            if (try builder.analyser.resolveTypeOfNode(.{ .node = datas[node].lhs, .handle = handle })) |ty| {
                try typeToCompletion(builder, ty, either_descriptor);
            }
            if (try builder.analyser.resolveTypeOfNode(.{ .node = datas[node].rhs, .handle = handle })) |ty| {
                try typeToCompletion(builder, ty, either_descriptor);
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
            const name_token = func.name_token orelse return;

            const func_name = orig_name orelse tree.tokenSlice(name_token);
            const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;

            const func_ty = Analyser.Type{
                .data = .{ .other = .{ .node = node, .handle = handle } }, // this assumes that function types can only be Ast nodes
                .is_type_val = true,
            };

            const skip_self_param = !(parent_is_type_val orelse true) and try builder.analyser.hasSelfParam(func_ty);

            const insert_range, const replace_range, const new_text_format = prepareFunctionCompletion(builder);

            const new_text = switch (new_text_format) {
                .only_name => func_name,
                .snippet => blk: {
                    if (use_snippets and builder.server.config.enable_argument_placeholders) {
                        break :blk try std.fmt.allocPrint(builder.arena, "{}", .{Analyser.fmtFunction(.{
                            .fn_proto = func,
                            .tree = &tree,

                            .include_fn_keyword = false,
                            .include_name = true,
                            .override_name = func_name,
                            .skip_first_param = skip_self_param,
                            .parameters = .{ .show = .{
                                .include_modifiers = true,
                                .include_names = true,
                                .include_types = true,
                            } },
                            .include_return_type = false,
                            .snippet_placeholders = true,
                        })});
                    }

                    switch (func.ast.params.len) {
                        // No arguments, leave cursor at the end
                        0 => break :blk try std.fmt.allocPrint(builder.arena, "{s}()", .{func_name}),
                        1 => {
                            if (skip_self_param) {
                                // The one argument is a self parameter, leave cursor at the end
                                break :blk try std.fmt.allocPrint(builder.arena, "{s}()", .{func_name});
                            }

                            // Non-self parameter, leave the cursor in the parentheses
                            if (!use_snippets) break :blk func_name;
                            break :blk try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{func_name});
                        },
                        else => {
                            // Atleast one non-self parameter, leave the cursor in the parentheses
                            if (!use_snippets) break :blk func_name;
                            break :blk try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{func_name});
                        },
                    }
                },
            };

            const kind: types.CompletionItemKind = if (Analyser.isTypeFunction(tree, func))
                .Struct
            else if (skip_self_param)
                .Method
            else
                .Function;

            const label_details: ?types.CompletionItemLabelDetails = blk: {
                if (!builder.server.client_capabilities.label_details_support) break :blk null;

                const detail = try std.fmt.allocPrint(builder.arena, "{}", .{Analyser.fmtFunction(.{
                    .fn_proto = func,
                    .tree = &tree,

                    .include_fn_keyword = false,
                    .include_name = false,
                    .skip_first_param = skip_self_param,
                    .parameters = if (builder.server.config.completion_label_details)
                        .{ .show = .{
                            .include_modifiers = true,
                            .include_names = true,
                            .include_types = true,
                        } }
                    else
                        .collapse,
                    .include_return_type = false,
                    .snippet_placeholders = false,
                })});

                const description = description: {
                    if (func.ast.return_type == 0) break :description null;
                    const return_type_str = offsets.nodeToSlice(tree, func.ast.return_type);

                    break :description if (ast.hasInferredError(tree, func))
                        try std.fmt.allocPrint(builder.arena, "!{s}", .{return_type_str})
                    else
                        return_type_str;
                };

                break :blk .{
                    .detail = detail,
                    .description = description,
                };
            };

            const details = try std.fmt.allocPrint(builder.arena, "{}", .{Analyser.fmtFunction(.{
                .fn_proto = func,
                .tree = &tree,

                .include_fn_keyword = true,
                .include_name = false,
                .parameters = .{ .show = .{
                    .include_modifiers = true,
                    .include_names = true,
                    .include_types = true,
                } },
                .include_return_type = true,
                .snippet_placeholders = false,
            })});

            try builder.completions.append(builder.arena, .{
                .label = func_name,
                .labelDetails = label_details,
                .kind = kind,
                .documentation = doc,
                .detail = details,
                .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
                .textEdit = if (builder.server.client_capabilities.supports_completion_insert_replace_support)
                    .{ .InsertReplaceEdit = .{ .newText = new_text, .insert = insert_range, .replace = replace_range } }
                else
                    .{ .TextEdit = .{ .newText = new_text, .range = insert_range } },
            });
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const var_decl = tree.fullVarDecl(node).?;
            const name = orig_name orelse tree.tokenSlice(var_decl.ast.mut_token + 1);
            const is_const = token_tags[var_decl.ast.mut_token] == .keyword_const;

            const compile_error_message = blk: {
                if (!builder.server.client_capabilities.supports_completion_deprecated_old and
                    !builder.server.client_capabilities.supports_completion_deprecated_tag) break :blk null;

                if (var_decl.ast.init_node == 0) break :blk null;
                var buffer: [2]Ast.Node.Index = undefined;
                const params = ast.builtinCallParams(tree, var_decl.ast.init_node, &buffer) orelse break :blk null;
                if (params.len != 1) break :blk null;

                const builtin_name = tree.tokenSlice(tree.nodes.items(.main_token)[var_decl.ast.init_node]);
                if (!std.mem.eql(u8, builtin_name, "@compileError")) break :blk null;

                if (tree.nodes.items(.tag)[params[0]] == .string_literal) {
                    const literal = tree.tokenSlice(tree.nodes.items(.main_token)[params[0]]);
                    break :blk literal[1 .. literal.len - 1];
                }
                break :blk "";
            };

            if (compile_error_message) |message| {
                try builder.completions.append(builder.arena, .{
                    .label = name,
                    .kind = if (is_const) .Constant else .Variable,
                    .documentation = .{ .MarkupContent = .{ .kind = .markdown, .value = message } },
                    .deprecated = if (builder.server.client_capabilities.supports_completion_deprecated_old) true else null,
                    .tags = if (builder.server.client_capabilities.supports_completion_deprecated_tag) &.{.Deprecated} else null,
                });
            } else {
                try builder.completions.append(builder.arena, .{
                    .label = name,
                    .kind = if (is_const) .Constant else .Variable,
                    .documentation = doc,
                    .detail = try Analyser.getVariableSignature(builder.arena, tree, var_decl, false),
                });
            }
        },
        .container_field,
        .container_field_align,
        .container_field_init,
        => {
            const field = tree.fullContainerField(node).?;
            const name = tree.tokenSlice(field.ast.main_token);
            try builder.completions.append(builder.arena, .{
                .label = name,
                .kind = if (field.ast.tuple_like) .EnumMember else .Field,
                .documentation = doc,
                .detail = Analyser.getContainerFieldSignature(tree, field),
            });
        },
        .array_type,
        .array_type_sentinel,
        => unreachable,
        .ptr_type,
        .ptr_type_aligned,
        .ptr_type_bit_range,
        .ptr_type_sentinel,
        => unreachable,
        .optional_type => unreachable,
        .multiline_string_literal,
        .string_literal,
        => unreachable,
        else => if (Analyser.nodeToString(tree, node)) |string| {
            try builder.completions.append(builder.arena, .{
                .label = string,
                .kind = .Field,
                .documentation = doc,
                .detail = offsets.nodeToSlice(tree, node),
            });
        },
    }
}

const DeclToCompletionContext = struct {
    builder: *Builder,
    orig_name: ?[]const u8 = null,
    parent_is_type_val: ?bool = null,
    either_descriptor: ?[]const u8 = null,
    doc_strings: ?*std.ArrayListUnmanaged([]const u8) = null,
};

fn declToCompletion(context: DeclToCompletionContext, decl_handle: Analyser.DeclWithHandle) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const builder = context.builder;

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
            builder,
            .{ .node = node, .handle = decl_handle.handle },
            context.orig_name,
            false,
            context.parent_is_type_val,
            context.either_descriptor,
            context.doc_strings,
        ),
        .function_parameter => |pay| {
            const param = pay.get(tree).?;
            const name = tree.tokenSlice(param.name_token.?);
            const doc = try completionDoc(
                builder,
                context.either_descriptor,
                if (try decl_handle.docComments(builder.arena)) |doc| &.{doc} else &.{},
            );

            try builder.completions.append(builder.arena, .{
                .label = name,
                .kind = .Constant,
                .documentation = doc,
                .detail = offsets.nodeToSlice(tree, param.type_expr),
            });
        },
        .optional_payload,
        .error_union_payload,
        .error_union_error,
        .for_loop_payload,
        .assign_destructure,
        .switch_payload,
        .label,
        => {
            const name = tree.tokenSlice(decl_handle.nameToken());

            try builder.completions.append(builder.arena, .{
                .label = name,
                .kind = if (decl == .label) .Text else .Variable,
            });
        },
        .error_token => |token| {
            const name = tree.tokenSlice(token);
            const doc = try completionDoc(
                builder,
                context.either_descriptor,
                if (try decl_handle.docComments(builder.arena)) |doc| &.{doc} else &.{},
            );

            try builder.completions.append(builder.arena, .{
                .label = name,
                .kind = .Constant,
                .documentation = doc,
                .detail = try std.fmt.allocPrint(builder.arena, "error.{s}", .{name}),
            });
        },
    }
}

fn completeLabel(builder: *Builder) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const context = DeclToCompletionContext{ .builder = builder };
    try Analyser.iterateLabels(builder.orig_handle, builder.source_index, declToCompletion, context);
}

fn populateSnippedCompletions(builder: *Builder, snippets: []const snipped_data.Snipped) error{OutOfMemory}!void {
    try builder.completions.ensureUnusedCapacity(builder.arena, snippets.len);

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
    for (snippets) |snipped| {
        if (!use_snippets and snipped.kind == .Snippet) continue;

        builder.completions.appendAssumeCapacity(.{
            .label = snipped.label,
            .kind = snipped.kind,
            .detail = if (use_snippets) snipped.text else null,
            .insertText = if (use_snippets) snipped.text else null,
            .insertTextFormat = if (use_snippets and snipped.text != null) .Snippet else .PlainText,
        });
    }
}

const FunctionCompletionFormat = enum { snippet, only_name };

fn prepareFunctionCompletion(builder: *Builder) struct { types.Range, types.Range, FunctionCompletionFormat } {
    const source = builder.orig_handle.tree.source;

    var start_index = builder.source_index;
    while (start_index > 0 and Analyser.isSymbolChar(source[start_index - 1])) {
        start_index -= 1;
    }

    var end_index = builder.source_index;
    while (end_index < source.len and Analyser.isSymbolChar(source[end_index])) {
        end_index += 1;
    }

    var insert_loc = offsets.Loc{ .start = start_index, .end = builder.source_index };
    var replace_loc = offsets.Loc{ .start = start_index, .end = end_index };

    var format: FunctionCompletionFormat = .only_name;

    const insert_can_be_snippet = std.mem.startsWith(u8, source[insert_loc.end..], "()");
    const replace_can_be_snippet = std.mem.startsWith(u8, source[replace_loc.end..], "()");

    if (insert_can_be_snippet and replace_can_be_snippet) {
        insert_loc.end += 2;
        replace_loc.end += 2;
        format = .snippet;
    } else if (insert_can_be_snippet or replace_can_be_snippet) {
        // snippet completions would be possible but insert and replace would need different `newText`
    } else if (!std.mem.startsWith(u8, source[builder.source_index..], "(")) {
        format = .snippet;
    }

    const insert_range = offsets.locToRange(source, insert_loc, builder.server.offset_encoding);
    const replace_range = offsets.locToRange(source, replace_loc, builder.server.offset_encoding);

    return .{ insert_range, replace_range, format };
}

fn completeBuiltin(builder: *Builder) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
    const use_placeholders = use_snippets and builder.server.config.enable_argument_placeholders;

    const insert_range, const replace_range, const new_text_format = prepareFunctionCompletion(builder);

    try builder.completions.ensureUnusedCapacity(builder.arena, data.builtins.len);
    for (data.builtins) |builtin| {
        const new_text = switch (new_text_format) {
            .only_name => builtin.name,
            .snippet => blk: {
                if (builtin.arguments.len == 0) break :blk try std.fmt.allocPrint(builder.arena, "{s}()", .{builtin.name});
                if (use_snippets and use_placeholders) break :blk builtin.snippet;
                if (use_snippets) break :blk try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{builtin.name});
                break :blk builtin.name;
            },
        };

        builder.completions.appendAssumeCapacity(.{
            .label = builtin.name,
            .kind = .Function,
            .filterText = builtin.name[1..],
            .detail = builtin.signature,
            .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
            .textEdit = if (builder.server.client_capabilities.supports_completion_insert_replace_support)
                .{ .InsertReplaceEdit = .{ .newText = new_text[1..], .insert = insert_range, .replace = replace_range } }
            else
                .{ .TextEdit = .{ .newText = new_text[1..], .range = insert_range } },
            .documentation = .{
                .MarkupContent = .{
                    .kind = .markdown,
                    .value = builtin.documentation,
                },
            },
        });
    }
}

fn completeGlobal(builder: *Builder) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const context = DeclToCompletionContext{ .builder = builder };
    try builder.analyser.iterateSymbolsGlobal(builder.orig_handle, builder.source_index, declToCompletion, context);
    try populateSnippedCompletions(builder, &snipped_data.generic);
}

fn completeFieldAccess(builder: *Builder, loc: offsets.Loc) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const ty = try builder.analyser.getFieldAccessType(builder.orig_handle, builder.source_index, loc) orelse return;
    try typeToCompletion(builder, ty, null);
}

fn kindToSortScore(kind: types.CompletionItemKind) ?[]const u8 {
    return switch (kind) {
        .Module => "1_", // use for packages
        .Folder => "2_",
        .File => "3_",

        .Constant => "1_",

        .Variable => "2_",
        .Field => "3_",
        .Function, .Method => "4_",

        .Keyword, .Snippet, .EnumMember => "5_",

        .Class,
        .Interface,
        .Struct,
        .Enum,
        // Union?
        .TypeParameter,
        => "6_",

        else => {
            log.debug(@typeName(types.CompletionItemKind) ++ ".{s} has no sort score specified!", .{@tagName(kind)});
            return null;
        },
    };
}

fn completeDot(builder: *Builder, loc: offsets.Loc) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = builder.orig_handle.tree;
    const token_tags = tree.tokens.items(.tag);

    const dot_token_index = offsets.sourceIndexToTokenIndex(tree, loc.start);
    if (dot_token_index < 2) return;

    blk: {
        const dot_context = getEnumLiteralContext(tree, dot_token_index) orelse break :blk;
        const containers = try collectContainerNodes(
            builder,
            builder.orig_handle,
            offsets.tokenToLoc(tree, dot_context.identifier_token_index).end,
            dot_context,
        );
        for (containers) |container| {
            try collectContainerFields(builder, dot_context.likely, container);
        }
    }

    if (builder.completions.items.len != 0) return;

    // Prevent compl for float numbers, eg `1.`
    //  Ideally this would also `or token_tags[dot_token_index - 1] != .equal`,
    //  which would mean the only possibility left would be `var enum_val = .`.
    if (token_tags[dot_token_index - 1] == .number_literal or token_tags[dot_token_index - 1] != .equal) return;

    // `var enum_val = .` or the get*Context logic failed because of syntax errors (parser didn't create the necessary node(s))
    try globalSetCompletions(builder, .enum_set);
}

/// asserts that `pos_context` is one of the following:
///  - `.import_string_literal`
///  - `.cinclude_string_literal`
///  - `.embedfile_string_literal`
///  - `.string_literal`
fn completeFileSystemStringLiteral(builder: *Builder, pos_context: Analyser.PositionContext) !void {
    var completions: CompletionSet = .{};
    const store = &builder.server.document_store;

    const loc = switch (pos_context) {
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        .string_literal,
        => |loc| loc,
        else => unreachable,
    };

    var completing = builder.orig_handle.tree.source[loc.start + 1 .. loc.end - 1];

    var separator_index = completing.len;
    while (separator_index > 0) : (separator_index -= 1) {
        if (std.fs.path.isSep(completing[separator_index - 1])) break;
    }
    completing = completing[0..separator_index];

    var search_paths: std.ArrayListUnmanaged([]const u8) = .{};
    if (std.fs.path.isAbsolute(completing) and pos_context != .import_string_literal) {
        try search_paths.append(builder.arena, completing);
    } else if (pos_context == .cinclude_string_literal) {
        _ = store.collectIncludeDirs(builder.arena, builder.orig_handle, &search_paths) catch |err| {
            log.err("failed to resolve include paths: {}", .{err});
            return;
        };
    } else {
        const document_path = try URI.parse(builder.arena, builder.orig_handle.uri);
        try search_paths.append(builder.arena, std.fs.path.dirname(document_path).?);
    }

    for (search_paths.items) |path| {
        if (!std.fs.path.isAbsolute(path)) continue;
        const dir_path = if (std.fs.path.isAbsolute(completing)) path else try std.fs.path.join(builder.arena, &.{ path, completing });

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

            _ = try completions.getOrPut(builder.arena, types.CompletionItem{
                .label = try builder.arena.dupe(u8, entry.name),
                .detail = if (pos_context == .cinclude_string_literal) path else null,
                .insertText = if (entry.kind == .directory)
                    try std.fmt.allocPrint(builder.arena, "{s}/", .{entry.name})
                else
                    null,
                .kind = if (entry.kind == .file) .File else .Folder,
            });
        }
    }

    if (completing.len == 0 and pos_context == .import_string_literal) {
        if (try builder.orig_handle.getAssociatedBuildFileUri(store)) |uri| blk: {
            const build_file = store.getBuildFile(uri).?;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            try completions.ensureUnusedCapacity(builder.arena, build_config.packages.len);
            for (build_config.packages) |pkg| {
                completions.putAssumeCapacity(.{
                    .label = pkg.name,
                    .kind = .Module,
                    .detail = pkg.path,
                }, {});
            }
        } else if (DocumentStore.isBuildFile(builder.orig_handle.uri)) blk: {
            const build_file = store.getBuildFile(builder.orig_handle.uri) orelse break :blk;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            try completions.ensureUnusedCapacity(builder.arena, build_config.deps_build_roots.len);
            for (build_config.deps_build_roots) |dbr| {
                completions.putAssumeCapacity(.{
                    .label = dbr.name,
                    .kind = .Module,
                    .detail = dbr.path,
                }, {});
            }
        }

        try completions.ensureUnusedCapacity(builder.arena, 2);
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

    try builder.completions.appendSlice(builder.arena, completions.keys());
}

pub fn completionAtIndex(
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    handle: *DocumentStore.Handle,
    source_index: usize,
) error{OutOfMemory}!?types.CompletionList {
    var builder: Builder = .{
        .server = server,
        .analyser = analyser,
        .arena = arena,
        .orig_handle = handle,
        .source_index = source_index,
        .completions = .{},
    };
    const source = handle.tree.source;

    // Provide `top_level_decl_data` only if `offsets.lineSliceUntilIndex(handle.tree.source, source_index).len` is
    // 0 => Empty new line, manually triggered
    // 1 => This is the very first char on a given line
    const at_line_start = offsets.lineSliceUntilIndex(source, source_index).len < 2;
    if (at_line_start) {
        try populateSnippedCompletions(&builder, &snipped_data.top_level_decl_data);
        return .{ .isIncomplete = false, .items = builder.completions.items };
    }

    const pos_context = try Analyser.getPositionContext(arena, source, source_index, false);

    switch (pos_context) {
        .builtin => try completeBuiltin(&builder),
        .var_access, .empty => try completeGlobal(&builder),
        .field_access => |loc| try completeFieldAccess(&builder, loc),
        .global_error_set => try globalSetCompletions(&builder, .error_set),
        .enum_literal => |loc| try completeDot(&builder, loc),
        .label => try completeLabel(&builder),
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        .string_literal,
        => {
            if (pos_context == .string_literal and !DocumentStore.isBuildFile(handle.uri)) return null;
            completeFileSystemStringLiteral(&builder, pos_context) catch |err| {
                log.err("failed to get file system completions: {}", .{err});
                return null;
            };
        },
        else => return null,
    }

    const completions = builder.completions.items;
    if (completions.len == 0) return null;

    {
        var start_index = source_index;
        while (start_index > 0 and Analyser.isSymbolChar(source[start_index - 1])) {
            start_index -= 1;
        }

        var end_index = source_index;
        while (end_index < source.len and Analyser.isSymbolChar(source[end_index])) {
            end_index += 1;
        }

        const insert_range = offsets.locToRange(source, .{ .start = start_index, .end = source_index }, server.offset_encoding);
        const replace_range = offsets.locToRange(source, .{ .start = start_index, .end = end_index }, server.offset_encoding);

        for (completions) |*item| {
            if (item.textEdit == null) {
                item.textEdit = if (server.client_capabilities.supports_completion_insert_replace_support)
                    .{ .InsertReplaceEdit = .{ .newText = item.insertText orelse item.label, .insert = insert_range, .replace = replace_range } }
                else
                    .{ .TextEdit = .{ .newText = item.insertText orelse item.label, .range = insert_range } };
            }
            item.insertText = null;
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
    }

    return .{ .isIncomplete = false, .items = completions };
}

// <--------------------------------------------------------------------------->
//                    global error set / enum field set
// <--------------------------------------------------------------------------->

pub const CompletionSet = std.ArrayHashMapUnmanaged(types.CompletionItem, void, CompletionContext, false);

const CompletionContext = struct {
    pub fn hash(self: @This(), item: types.CompletionItem) u32 {
        _ = self;
        return std.array_hash_map.hashString(item.label);
    }

    pub fn eql(self: @This(), a: types.CompletionItem, b: types.CompletionItem, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return std.mem.eql(u8, a.label, b.label);
    }
};

const CompletionNameAdapter = struct {
    pub fn hash(ctx: @This(), name: []const u8) u32 {
        _ = ctx;
        return std.array_hash_map.hashString(name);
    }

    pub fn eql(ctx: @This(), a: []const u8, b: types.CompletionItem, b_map_index: usize) bool {
        _ = ctx;
        _ = b_map_index;
        return std.mem.eql(u8, a, b.label);
    }
};

/// Every `DocumentScope` store a set of all error names and a set of all enum field names.
/// This function collects all of these sets from all dependencies and returns them as completions.
fn globalSetCompletions(builder: *Builder, kind: enum { error_set, enum_set }) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const store = &builder.server.document_store;

    var dependencies = std.ArrayListUnmanaged(DocumentStore.Uri){};
    try dependencies.append(builder.arena, builder.orig_handle.uri);
    try store.collectDependencies(builder.arena, builder.orig_handle, &dependencies);

    // TODO Better solution for deciding what tags to include
    var result_set = CompletionSet{};

    for (dependencies.items) |uri| {
        // not every dependency is loaded which results in incomplete completion
        const dependency_handle = store.getHandle(uri) orelse continue;
        const document_scope: DocumentScope = try dependency_handle.getDocumentScope();
        const curr_set: DocumentScope.IdentifierSet = switch (kind) {
            .error_set => @field(document_scope, "global_error_set"),
            .enum_set => @field(document_scope, "global_enum_set"),
        };
        try result_set.ensureUnusedCapacity(builder.arena, curr_set.count());
        for (curr_set.keys()) |identifier_token| {
            const name = offsets.identifierTokenToNameSlice(dependency_handle.tree, identifier_token);

            const gop = result_set.getOrPutAssumeCapacityAdapted(
                name,
                CompletionNameAdapter{},
            );

            if (!gop.found_existing) {
                gop.key_ptr.* = types.CompletionItem{
                    .label = name,
                    .detail = switch (kind) {
                        .error_set => try std.fmt.allocPrint(builder.arena, "error.{}", .{std.zig.fmtId(name)}),
                        .enum_set => null,
                    },
                    .kind = switch (kind) {
                        .error_set => .Constant,
                        .enum_set => .EnumMember,
                    },
                    .documentation = null, // will be set below
                };
            }

            if (gop.key_ptr.documentation == null) {
                if (try Analyser.getDocCommentsBeforeToken(builder.arena, dependency_handle.tree, identifier_token)) |documentation| {
                    gop.key_ptr.documentation = .{
                        .MarkupContent = types.MarkupContent{
                            // TODO check if client supports markdown
                            .kind = .markdown,
                            .value = documentation,
                        },
                    };
                }
            }
        }
    }

    try builder.completions.appendSlice(builder.arena, result_set.keys());
}

// <--------------------------------------------------------------------------->
//               completions/enum_literal.zig staging area
// <--------------------------------------------------------------------------->

const EnumLiteralContext = struct {
    const Likely = enum { // TODO: better name, tagged union?
        /// `mye: Enum = .`, `abc.field = .`, `f(.{.field = .`
        enum_literal,
        /// Same as above, but`f() = .` or `identifier.f() = .` are ignored, ie lhs of `=` is a fn call
        enum_assignment,
        // `==`, `!=`
        enum_comparison,
        /// the enum is a fn arg, eg `f(.`
        enum_arg,
        /// `S{.`, `var s:S = .{.`, `f(.{.` or `a.f(.{.`
        struct_field,
        switch_case,
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
        .equal => {
            token_index -= 1;
            if ((token_tags[token_index] == .r_paren)) return null; // `..) = .`, ie lhs is a fn call
            dot_context.likely = .enum_assignment;
            dot_context.identifier_token_index = token_index;
        },
        .equal_equal, .bang_equal => {
            token_index -= 1;
            dot_context.likely = .enum_comparison;
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
            .l_brace => {
                braces_depth -= 1;
                if (braces_depth != one_opening) continue;
                upper_index -= 1;
                switch (token_tags[upper_index]) {
                    // `S{.`
                    .identifier => break :find_identifier,
                    // anon struct init `.{.`
                    .period => {
                        if (upper_index < 3) return null;
                        upper_index -= 1;
                        if (token_tags[upper_index] == .ampersand) upper_index -= 1; // `&.{.`
                        if (token_tags[upper_index] == .equal) { // `= .{.`
                            upper_index -= 1; // eat the `=`
                            switch (token_tags[upper_index]) {
                                .identifier, // `const s: S = .{.`, `S{.name = .`
                                .period_asterisk, //  `s.* = .{.`
                                => break :find_identifier,
                                else => return null,
                            }
                        }
                        // We never return from this branch/condition to the `find_identifier: while ..` loop, so reset and reuse these
                        fn_arg_index = 0;
                        braces_depth = even; // not actually looking for/expecting an uneven number of braces, just making use of the helpful const
                        parens_depth = even;
                        while (upper_index > 0) : (upper_index -= 1) {
                            switch (token_tags[upper_index]) {
                                .r_brace => braces_depth += 1,
                                .l_brace => {
                                    braces_depth -= 1;
                                    if (braces_depth == one_opening) return null;
                                },
                                .r_paren => parens_depth += 1,
                                .l_paren => {
                                    parens_depth -= 1;
                                    if (parens_depth == one_opening and switch (token_tags[upper_index - 1]) {
                                        .identifier,
                                        .builtin,
                                        => true,
                                        else => false,
                                    }) {
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
                        return null;
                    },
                    // The opening brace is preceded by a r_paren => evaluate
                    .r_paren => {
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
                                                likely = .switch_case;
                                                upper_index -= 1; // eat the switch's .r_paren
                                                break :find_identifier;
                                            },
                                            .identifier,
                                            // .builtin, // `@f(){.`
                                            => {
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
                    },
                    else => return null,
                }
            },
            // We're fishing for a `f(some, other{}, .<cursor>enum)`
            .r_paren => parens_depth += 1,
            .l_paren => {
                parens_depth -= 1;
                if (parens_depth != one_opening) continue;
                if (braces_depth != even) return null;
                upper_index -= 1;
                switch (token_tags[upper_index]) {
                    // `f(.`
                    .identifier,
                    .builtin,
                    .keyword_addrspace,
                    .keyword_callconv,
                    => {
                        likely = .enum_arg;
                        break :find_identifier;
                    },
                    else => return null,
                }
            },
            .comma => if (braces_depth == even and parens_depth == even) { // those only matter when outside of braces and before final '('
                fn_arg_index += 1;
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
    builder: *Builder,
    likely: EnumLiteralContext.Likely,
    container: Analyser.Type,
) error{OutOfMemory}!void {
    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
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
        if (likely != .struct_field and likely != .enum_comparison and likely != .switch_case and !field.ast.tuple_like) {
            try builder.completions.append(builder.arena, .{
                .label = name,
                .kind = if (field.ast.tuple_like) .EnumMember else .Field,
                .detail = Analyser.getContainerFieldSignature(handle.tree, field),
                .insertText = if (use_snippets)
                    try std.fmt.allocPrint(builder.arena, "{{ .{s} = $1 }}$0", .{name})
                else
                    try std.fmt.allocPrint(builder.arena, "{{ .{s} = ", .{name}),
                .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
            });
        } else try builder.completions.append(builder.arena, .{
            .label = name,
            .kind = if (field.ast.tuple_like) .EnumMember else .Field,
            .detail = Analyser.getContainerFieldSignature(handle.tree, field),
            .insertText = if (field.ast.tuple_like or likely == .enum_comparison or likely == .switch_case)
                name
            else
                try std.fmt.allocPrint(builder.arena, "{s} = ", .{name}),
        });
    }
}

/// Resolves `identifier`/`path.to.identifier` at `source_index`
/// If the `identifier` is a container `fn_arg_index` is unused
/// If the `identifier` is a `fn_name`/`identifier.fn_name`, tries to resolve
///         `fn_name`'s `fn_arg_index`'s param type
fn collectContainerNodes(
    builder: *Builder,
    handle: *DocumentStore.Handle,
    source_index: usize,
    dot_context: EnumLiteralContext,
) error{OutOfMemory}![]Analyser.Type {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var types_with_handles = std.ArrayListUnmanaged(Analyser.Type){};
    const position_context = try Analyser.getPositionContext(builder.arena, handle.tree.source, source_index, false);
    switch (position_context) {
        .var_access => |loc| try collectVarAccessContainerNodes(builder, handle, loc, dot_context, &types_with_handles),
        .field_access => |loc| try collectFieldAccessContainerNodes(builder, handle, loc, dot_context, &types_with_handles),
        .enum_literal => |loc| try collectEnumLiteralContainerNodes(builder, handle, loc, &types_with_handles),
        .builtin => |loc| try collectBuiltinContainerNodes(builder, handle, loc, dot_context, &types_with_handles),
        .keyword => |tag| try collectKeywordFnContainerNodes(builder, tag, dot_context, &types_with_handles),
        else => {},
    }
    return types_with_handles.toOwnedSlice(builder.arena);
}

fn resolveBuiltinFnArg(
    analyser: *Analyser,
    arg_index: usize,
    /// Includes leading `@`
    name: []const u8,
) std.mem.Allocator.Error!?Analyser.Type {
    const builtin_name: []const u8 = name: {
        if (std.mem.eql(u8, name, "@Type")) {
            switch (arg_index) {
                0 => break :name "Type",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@setFloatMode")) {
            switch (arg_index) {
                0 => break :name "FloatMode",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@prefetch")) {
            switch (arg_index) {
                1 => break :name "PrefetchOptions",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@reduce")) {
            switch (arg_index) {
                0 => break :name "ReduceOp",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@export")) {
            switch (arg_index) {
                1 => break :name "ExportOptions",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@extern")) {
            switch (arg_index) {
                1 => break :name "ExternOptions",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@fence")) {
            switch (arg_index) {
                0 => break :name "AtomicOrder",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@cmpxchgWeak") or std.mem.eql(u8, name, "@cmpxchgStrong")) {
            switch (arg_index) {
                4, 5 => break :name "AtomicOrder",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@atomicLoad")) {
            switch (arg_index) {
                2 => break :name "AtomicOrder",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@atomicStore")) {
            switch (arg_index) {
                3 => break :name "AtomicOrder",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@atomicRmw")) {
            switch (arg_index) {
                2 => break :name "AtomicRmwOp",
                4 => break :name "AtomicOrder",
                else => return null,
            }
        }

        if (std.mem.eql(u8, name, "@call")) {
            switch (arg_index) {
                0 => break :name "CallModifier",
                else => return null,
            }
        }

        return null;
    };

    return analyser.instanceStdBuiltinType(builtin_name);
}

fn collectBuiltinContainerNodes(
    builder: *Builder,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    dot_context: EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    if (dot_context.need_ret_type) return;
    if (try resolveBuiltinFnArg(
        builder.analyser,
        dot_context.fn_arg_index,
        handle.tree.source[loc.start..loc.end],
    )) |ty| {
        try types_with_handles.append(builder.arena, ty);
    }
}

fn collectVarAccessContainerNodes(
    builder: *Builder,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    dot_context: EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const analyser = builder.analyser;
    const arena = builder.arena;

    const symbol_decl = try analyser.lookupSymbolGlobal(handle, handle.tree.source[loc.start..loc.end], loc.end) orelse return;
    const result = try symbol_decl.resolveType(analyser) orelse return;
    const type_expr = try analyser.resolveDerefType(result) orelse result;
    if (type_expr.isFunc()) {
        const fn_proto_node_handle = type_expr.data.other; // this assumes that function types can only be Ast nodes
        const fn_proto_node = fn_proto_node_handle.node;
        const fn_proto_handle = fn_proto_node_handle.handle;
        if (dot_context.likely == .enum_comparison or dot_context.need_ret_type) { // => we need f()'s return type
            var buf: [1]Ast.Node.Index = undefined;
            const full_fn_proto = fn_proto_handle.tree.fullFnProto(&buf, fn_proto_node).?;
            const has_body = fn_proto_handle.tree.nodes.items(.tag)[fn_proto_node] == .fn_decl;
            const body = fn_proto_handle.tree.nodes.items(.data)[fn_proto_node].rhs;
            var node_type = try analyser.resolveReturnType(full_fn_proto, fn_proto_handle, if (has_body) body else null) orelse return;
            if (try analyser.resolveUnwrapErrorUnionType(node_type, .payload)) |unwrapped| node_type = unwrapped;
            try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
            return;
        }
        const fn_param_decl = Analyser.Declaration{ .function_parameter = .{
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
    builder: *Builder,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    dot_context: EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const analyser = builder.analyser;
    const arena = builder.arena;

    // XXX It could be any/all of the preceding logic, but this fn seems
    // inconsistent at returning name_loc for methods, ie
    // `abc.method() == .` => fails, `abc.method(.{}){.}` => ok
    // it also fails for `abc.xyz.*` ... currently we take advantage of this quirk
    const name_loc = Analyser.identifierLocFromPosition(loc.end, handle) orelse {
        const result = try analyser.getFieldAccessType(handle, loc.end, loc) orelse return;
        const container = try analyser.resolveDerefType(result) orelse result;
        if (try analyser.resolveUnwrapErrorUnionType(container, .payload)) |unwrapped| {
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
            if (try analyser.resolveOptionalUnwrap(node_type)) |unwrapped| node_type = unwrapped;
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
                if (try analyser.resolveUnwrapErrorUnionType(node_type, .payload)) |unwrapped| node_type = unwrapped;
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
                    if (try analyser.hasSelfParam(node_type)) break :blk 2;
                }
                break :blk 1; // is `T`, no SelfParam
            };
            for (dot_context.fn_arg_index + additional_index) |_| maybe_fn_param = ast.nextFnParam(&fn_param_iter);
            const param = maybe_fn_param orelse continue;
            if (param.type_expr == 0) continue;
            const param_rcts = try collectContainerNodes(
                builder,
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
    builder: *Builder,
    handle: *DocumentStore.Handle,
    loc: offsets.Loc,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const analyser = builder.analyser;
    const arena = builder.arena;
    const alleged_field_name = handle.tree.source[loc.start + 1 .. loc.end];
    const dot_index = offsets.sourceIndexToTokenIndex(handle.tree, loc.start);
    const el_dot_context = getSwitchOrStructInitContext(handle.tree, dot_index) orelse return;
    const containers = try collectContainerNodes(
        builder,
        handle,
        offsets.tokenToLoc(handle.tree, el_dot_context.identifier_token_index).end,
        el_dot_context,
    );
    for (containers) |container| {
        const container_instance = try container.instanceTypeVal(analyser) orelse container;
        const member_decl = try container_instance.lookupSymbol(analyser, alleged_field_name) orelse continue;
        var member_type = try member_decl.resolveType(analyser) orelse continue;
        // Unwrap `x{ .fld_w_opt_type =`
        if (try analyser.resolveOptionalUnwrap(member_type)) |unwrapped| member_type = unwrapped;
        try types_with_handles.append(arena, member_type);
    }
}

fn collectKeywordFnContainerNodes(
    builder: *Builder,
    tag: std.zig.Token.Tag,
    dot_context: EnumLiteralContext,
    types_with_handles: *std.ArrayListUnmanaged(Analyser.Type),
) error{OutOfMemory}!void {
    const builtin_type_name: []const u8 = name: {
        switch (tag) {
            .keyword_addrspace => switch (dot_context.fn_arg_index) {
                0 => break :name "AddressSpace",
                else => return,
            },
            .keyword_callconv => switch (dot_context.fn_arg_index) {
                0 => break :name "CallingConvention",
                else => return,
            },
            else => return,
        }
    };
    const ty = try builder.analyser.instanceStdBuiltinType(builtin_type_name) orelse return;
    try types_with_handles.append(builder.arena, ty);
}
