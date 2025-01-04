//! Implementation of [`textDocument/completion`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_completion)

const std = @import("std");
const Ast = std.zig.Ast;
const log = std.log.scoped(.completions);

const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const types = @import("lsp").types;
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");
const URI = @import("../uri.zig");
const DocumentScope = @import("../DocumentScope.zig");
const analyser_completions = @import("../analyser/completions.zig");

const version_data = @import("version_data");
const snipped_data = @import("../snippets.zig");

const Builder = struct {
    server: *Server,
    analyser: *Analyser,
    arena: std.mem.Allocator,
    orig_handle: *DocumentStore.Handle,
    source_index: usize,
    completions: std.ArrayListUnmanaged(types.CompletionItem),
    cached_prepare_function_completion_result: ?PrepareFunctionCompletionResult = null,
};

fn typeToCompletion(builder: *Builder, ty: Analyser.Type) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try builder.completions.ensureUnusedCapacity(builder.arena, 2);

    switch (ty.data) {
        .pointer => |info| switch (info.size) {
            .one, .c => {
                if (ty.is_type_val) return;

                builder.completions.appendAssumeCapacity(.{
                    .label = "*",
                    .kind = .Operator,
                    .detail = try std.fmt.allocPrint(
                        builder.arena,
                        "{}",
                        .{info.elem_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                    ),
                });

                if (info.size == .c) {
                    builder.completions.appendAssumeCapacity(.{
                        .label = "?",
                        .kind = .Operator,
                        .detail = try std.fmt.allocPrint(
                            builder.arena,
                            "{}",
                            .{ty.fmt(builder.analyser, .{ .truncate_container_decls = false })},
                        ),
                    });
                    return;
                }

                if (try builder.analyser.resolveDerefType(ty)) |child_ty| {
                    try typeToCompletion(builder, child_ty);
                }
            },
            .slice => {
                if (ty.is_type_val) return;

                builder.completions.appendAssumeCapacity(.{
                    .label = "len",
                    .detail = "usize",
                    .kind = .Field,
                });

                var many_ptr_ty = ty;
                many_ptr_ty.is_type_val = true;
                many_ptr_ty.data.pointer.size = .many;
                builder.completions.appendAssumeCapacity(.{
                    .label = "ptr",
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(
                        builder.arena,
                        "{}",
                        .{many_ptr_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                    ),
                });
            },
            .many => {},
        },
        .array => |info| {
            if (ty.is_type_val) return;
            builder.completions.appendAssumeCapacity(.{
                .label = "len",
                .detail = if (info.elem_count) |count|
                    try std.fmt.allocPrint(builder.arena, "usize = {}", .{count})
                else
                    "usize",
                .kind = .Field,
            });
        },
        .tuple => |elem_ty_slice| {
            if (ty.is_type_val) return;
            try builder.completions.ensureUnusedCapacity(builder.arena, elem_ty_slice.len);
            for (elem_ty_slice, 0..) |elem_ty, i| {
                builder.completions.appendAssumeCapacity(.{
                    .label = try std.fmt.allocPrint(builder.arena, "@\"{}\"", .{i}),
                    .kind = .Field,
                    .detail = try std.fmt.allocPrint(
                        builder.arena,
                        "{}",
                        .{elem_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                    ),
                });
            }
        },
        .optional => |child_ty| {
            if (ty.is_type_val) return;
            builder.completions.appendAssumeCapacity(.{
                .label = "?",
                .kind = .Operator,
                .detail = try std.fmt.allocPrint(
                    builder.arena,
                    "{}",
                    .{child_ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })},
                ),
            });
        },
        .container => |scope_handle| {
            const starting_depth = builder.analyser.bound_type_params.depth();
            try builder.analyser.bound_type_params.push(builder.analyser.gpa, scope_handle.bound_params);
            defer builder.analyser.bound_type_params.pop(starting_depth);
            var decls: std.ArrayListUnmanaged(Analyser.DeclWithHandle) = .empty;
            try builder.analyser.collectDeclarationsOfContainer(scope_handle, builder.orig_handle, !ty.is_type_val, &decls);

            for (decls.items) |decl_with_handle| {
                try declToCompletion(builder, decl_with_handle, .{
                    .parent_container_ty = ty,
                });
            }
        },
        .ip_index => |payload| try analyser_completions.dotCompletions(
            builder.arena,
            &builder.completions,
            builder.analyser.ip,
            payload.index orelse try builder.analyser.ip.getUnknown(builder.analyser.gpa, payload.type),
        ),
        .either => |either_entries| {
            for (either_entries) |entry| {
                const entry_ty: Analyser.Type = .{ .data = entry.type_data, .is_type_val = ty.is_type_val };
                try typeToCompletion(builder, entry_ty);
            }
        },
        .error_union,
        .union_tag,
        .other,
        .compile_error,
        => {},
    }
}

const DeclToCompletionOptions = struct {
    parent_container_ty: ?Analyser.Type = null,
};

fn declToCompletion(builder: *Builder, decl_handle: Analyser.DeclWithHandle, options: DeclToCompletionOptions) error{OutOfMemory}!void {
    const name = decl_handle.handle.tree.tokenSlice(decl_handle.nameToken());

    const is_cimport = std.mem.eql(u8, std.fs.path.basename(decl_handle.handle.uri), "cimport.zig");
    if (is_cimport) {
        if (std.mem.startsWith(u8, name, "_")) return;
        // TODO figuring out which declarations should be excluded could be made more complete and accurate
        // by translating an empty file to acquire all exclusions
        const exclusions: std.StaticStringMap(void) = .initComptime(.{
            .{ "linux", {} },
            .{ "unix", {} },
            .{ "WIN32", {} },
            .{ "WINNT", {} },
            .{ "WIN64", {} },
        });
        if (exclusions.has(name)) return;
    }

    var doc_comments: std.BoundedArray([]const u8, 2) = .{};
    if (try decl_handle.docComments(builder.arena)) |docs| {
        doc_comments.appendAssumeCapacity(docs);
    }

    const starting_depth = builder.analyser.bound_type_params.depth();
    var pushed = false;
    if (decl_handle.from) |from| {
        if (from.bound_params.len > 0) {
            try builder.analyser.bound_type_params.push(builder.analyser.gpa, from.bound_params);
            pushed = true;
        }
    }
    defer if (pushed) builder.analyser.bound_type_params.pop(starting_depth);
    const maybe_resolved_ty = try decl_handle.resolveType(builder.analyser);

    if (maybe_resolved_ty) |resolve_ty| {
        if (try resolve_ty.docComments(builder.arena)) |docs| {
            doc_comments.appendAssumeCapacity(docs);
        }
    }

    const documentation: std.meta.FieldType(types.CompletionItem, .documentation) = .{
        .MarkupContent = .{
            .kind = if (builder.server.client_capabilities.completion_doc_supports_md) .markdown else .plaintext,
            .value = try std.mem.join(builder.arena, "\n\n", doc_comments.constSlice()),
        },
    };

    try builder.completions.ensureUnusedCapacity(builder.arena, 1);

    const compile_error_message = blk: {
        if (!builder.server.client_capabilities.supports_completion_deprecated_old and
            !builder.server.client_capabilities.supports_completion_deprecated_tag) break :blk null;

        const resolved_ty = maybe_resolved_ty orelse break :blk null;
        if (resolved_ty.data != .compile_error) break :blk null;

        const node_with_handle = resolved_ty.data.compile_error;
        const tree = node_with_handle.handle.tree;

        var buffer: [2]Ast.Node.Index = undefined;
        const params = tree.builtinCallParams(&buffer, node_with_handle.node) orelse break :blk null;
        if (params.len != 1) break :blk null;

        if (tree.nodeTag(params[0]) == .string_literal) {
            const literal = tree.tokenSlice(tree.nodeMainToken(params[0]));
            break :blk literal[1 .. literal.len - 1];
        }
        break :blk "";
    };

    switch (decl_handle.decl) {
        .ast_node,
        .function_parameter,
        .optional_payload,
        .error_union_payload,
        .error_union_error,
        .for_loop_payload,
        .assign_destructure,
        .switch_payload,
        => {
            var kind: types.CompletionItemKind = blk: {
                const parent_is_type_val = if (options.parent_container_ty) |container_ty| container_ty.is_type_val else null;
                if (decl_handle.decl == .ast_node)
                    switch (decl_handle.handle.tree.nodeTag(decl_handle.decl.ast_node)) {
                        .container_field_init,
                        .container_field_align,
                        .container_field,
                        => {
                            if (!(parent_is_type_val orelse true)) break :blk .Field;
                        },
                        else => {},
                    };
                break :blk if (decl_handle.isConst()) .Constant else .Variable;
            };

            var is_deprecated: bool = false;
            if (maybe_resolved_ty) |ty| {
                if (try builder.analyser.resolveFuncProtoOfCallable(ty)) |func_ty| blk: {
                    var item = try functionTypeCompletion(builder, name, options.parent_container_ty, func_ty) orelse break :blk;
                    item.documentation = documentation;
                    builder.completions.appendAssumeCapacity(item);
                    return;
                } else if (ty.isEnumType()) {
                    if (ty.is_type_val) {
                        kind = .Enum;
                    } else {
                        kind = .EnumMember;
                    }
                } else if (ty.is_type_val and ty.isStructType() or ty.isUnionType()) {
                    kind = .Struct;
                } else if (decl_handle.decl == .function_parameter and ty.isMetaType()) {
                    kind = .TypeParameter;
                } else if (ty.isEnumLiteral()) {
                    kind = .EnumMember;
                } else if (ty.data == .compile_error) {
                    is_deprecated = true;
                }
            }

            const detail = if (maybe_resolved_ty) |ty| blk: {
                if (ty.is_type_val and ty.data == .ip_index and ty.data.ip_index.index != null and !builder.analyser.ip.isUnknown(ty.data.ip_index.index.?)) {
                    break :blk try std.fmt.allocPrint(builder.arena, "{}", .{ty.fmtTypeVal(builder.analyser, .{ .truncate_container_decls = false })});
                } else {
                    break :blk try std.fmt.allocPrint(builder.arena, "{}", .{ty.fmt(builder.analyser, .{ .truncate_container_decls = false })});
                }
            } else null;

            const label_details: ?types.CompletionItemLabelDetails = blk: {
                if (!builder.server.client_capabilities.label_details_support) break :blk null;

                break :blk .{ .description = detail };
            };

            builder.completions.appendAssumeCapacity(.{
                .label = name,
                .kind = kind,
                .documentation = if (compile_error_message) |message| .{
                    .MarkupContent = .{
                        .kind = if (builder.server.client_capabilities.completion_doc_supports_md) .markdown else .plaintext,
                        .value = message,
                    },
                } else documentation,
                .detail = detail,
                .labelDetails = label_details,
                .deprecated = if (compile_error_message != null and builder.server.client_capabilities.supports_completion_deprecated_old) true else null,
                .tags = if (compile_error_message != null and builder.server.client_capabilities.supports_completion_deprecated_tag) &.{.Deprecated} else null,
            });
        },
        .label => {
            builder.completions.appendAssumeCapacity(.{
                .label = name,
                .kind = .Text,
            });
        },
        .error_token => {
            builder.completions.appendAssumeCapacity(.{
                .label = name,
                .kind = .Constant,
                .documentation = documentation,
                .detail = try std.fmt.allocPrint(builder.arena, "error.{s}", .{name}),
            });
        },
    }
}

fn functionTypeCompletion(
    builder: *Builder,
    func_name: []const u8,
    parent_container_ty: ?Analyser.Type,
    func_ty: Analyser.Type,
) error{OutOfMemory}!?types.CompletionItem {
    std.debug.assert(func_ty.isFunc());

    const node_handle = func_ty.data.other; // this assumes that function types can only be Ast nodes
    const tree = node_handle.handle.tree;

    var buf: [1]Ast.Node.Index = undefined;
    const func = tree.fullFnProto(&buf, node_handle.node).?;

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;

    const has_self_param = if (parent_container_ty) |container_ty| blk: {
        if (container_ty.is_type_val) break :blk false;
        if (container_ty.isNamespace()) break :blk false;
        break :blk try builder.analyser.firstParamIs(func_ty, container_ty.typeOf(builder.analyser));
    } else false;

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
                    .skip_first_param = has_self_param,
                    .parameters = .{ .show = .{
                        .include_modifiers = true,
                        .include_names = true,
                        .include_types = true,
                    } },
                    .include_return_type = false,
                    .snippet_placeholders = true,
                })});
            }

            if (!use_snippets) break :blk func_name;

            switch (func.ast.params.len) {
                // No arguments, leave cursor at the end
                0 => break :blk try std.fmt.allocPrint(builder.arena, "{s}()", .{func_name}),
                1 => {
                    if (has_self_param) {
                        // The one argument is a self parameter, leave cursor at the end
                        break :blk try std.fmt.allocPrint(builder.arena, "{s}()", .{func_name});
                    }

                    // Non-self parameter, leave the cursor in the parentheses
                    break :blk try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{func_name});
                },
                else => {
                    // At least one non-self parameter, leave the cursor in the parentheses
                    break :blk try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{func_name});
                },
            }
        },
    };

    const kind: types.CompletionItemKind = if (func_ty.isTypeFunc())
        .Struct
    else if (has_self_param)
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
            .skip_first_param = has_self_param,
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
            const return_type = func.ast.return_type.unwrap() orelse break :description null;
            const return_type_str = offsets.nodeToSlice(tree, return_type);

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

    return .{
        .label = func_name,
        .labelDetails = label_details,
        .kind = kind,
        .detail = details,
        .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
        .textEdit = if (builder.server.client_capabilities.supports_completion_insert_replace_support)
            .{ .InsertReplaceEdit = .{ .newText = new_text, .insert = insert_range, .replace = replace_range } }
        else
            .{ .TextEdit = .{ .newText = new_text, .range = insert_range } },
    };
}

fn labelDeclToCompletion(builder: *Builder, decl_handle: Analyser.DeclWithHandle) !void {
    std.debug.assert(decl_handle.decl == .label);

    try builder.completions.append(builder.arena, .{
        .label = decl_handle.handle.tree.tokenSlice(decl_handle.nameToken()),
        .kind = .Text,
    });
}

fn completeLabel(builder: *Builder) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try Analyser.iterateLabels(builder.orig_handle, builder.source_index, labelDeclToCompletion, builder);
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
const PrepareFunctionCompletionResult = struct { types.Range, types.Range, FunctionCompletionFormat };

fn prepareFunctionCompletion(builder: *Builder) PrepareFunctionCompletionResult {
    if (builder.cached_prepare_function_completion_result) |result| return result;

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
    const source = builder.orig_handle.tree.source;

    var start_index = builder.source_index;
    while (start_index > 0 and Analyser.isSymbolChar(source[start_index - 1])) {
        start_index -= 1;
    }

    var end_index = builder.source_index;
    while (end_index < source.len and Analyser.isSymbolChar(source[end_index])) {
        end_index += 1;
    }

    var insert_loc: offsets.Loc = .{ .start = start_index, .end = builder.source_index };
    var replace_loc: offsets.Loc = .{ .start = start_index, .end = end_index };

    var format: FunctionCompletionFormat = .only_name;

    const insert_can_be_snippet = use_snippets and std.mem.startsWith(u8, source[insert_loc.end..], "()");
    const replace_can_be_snippet = use_snippets and std.mem.startsWith(u8, source[replace_loc.end..], "()");

    if (insert_can_be_snippet and replace_can_be_snippet) {
        insert_loc.end += 2;
        replace_loc.end += 2;
        format = .snippet;
    } else if (insert_can_be_snippet or replace_can_be_snippet) {
        // snippet completions would be possible but insert and replace would need different `newText`
    } else if (use_snippets and !std.mem.startsWith(u8, source[end_index..], "(")) {
        format = .snippet;
    }

    const insert_range = offsets.locToRange(source, insert_loc, builder.server.offset_encoding);
    const replace_range = offsets.locToRange(source, replace_loc, builder.server.offset_encoding);

    builder.cached_prepare_function_completion_result = .{ insert_range, replace_range, format };
    return builder.cached_prepare_function_completion_result.?;
}

fn completeBuiltin(builder: *Builder) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
    const use_placeholders = use_snippets and builder.server.config.enable_argument_placeholders;

    const insert_range, const replace_range, const new_text_format = prepareFunctionCompletion(builder);

    try builder.completions.ensureUnusedCapacity(builder.arena, version_data.builtins.kvs.len);
    for (version_data.builtins.keys(), version_data.builtins.values()) |name, builtin| {
        const new_text, const insertTextFormat: types.InsertTextFormat = switch (new_text_format) {
            .only_name => .{ name, .PlainText },
            .snippet => blk: {
                std.debug.assert(use_snippets);
                if (builtin.arguments.len == 0) break :blk .{ try std.fmt.allocPrint(builder.arena, "{s}()", .{name}), .PlainText };
                if (use_placeholders) break :blk .{ builtin.snippet, .Snippet };
                break :blk .{ try std.fmt.allocPrint(builder.arena, "{s}(${{1:}})", .{name}), .Snippet };
            },
        };

        builder.completions.appendAssumeCapacity(.{
            .label = name,
            .kind = .Function,
            .filterText = name[1..],
            .detail = builtin.signature,
            .insertTextFormat = insertTextFormat,
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

    var decls: std.ArrayListUnmanaged(Analyser.DeclWithHandle) = .empty;
    try builder.analyser.collectAllSymbolsAtSourceIndex(builder.orig_handle, builder.source_index, &decls);
    for (decls.items) |decl_with_handle| {
        try declToCompletion(builder, decl_with_handle, .{});
    }
    try populateSnippedCompletions(builder, &snipped_data.generic);
}

fn completeFieldAccess(builder: *Builder, loc: offsets.Loc) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const ty = try builder.analyser.getFieldAccessType(builder.orig_handle, builder.source_index, loc) orelse return;
    try typeToCompletion(builder, ty);
}

fn kindToSortScore(kind: types.CompletionItemKind) []const u8 {
    return switch (kind) {
        .Module => "1", // used for packages
        .Folder => "2",
        .File => "3",

        .Operator => "1",
        .Field, .EnumMember => "2",
        .Method => "3",
        .Function => "4",
        .Text, // used for labels
        .Constant,
        .Variable,
        .Struct,
        .Enum,
        .TypeParameter,
        => "5",
        .Snippet => "6",
        .Keyword => "7",

        else => unreachable,
    };
}

fn collectUsedMembersSet(builder: *Builder, likely: EnumLiteralContext.Likely, dot_token_index: Ast.TokenIndex) !std.BufSet {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    switch (likely) {
        .struct_field, .switch_case => {},
        else => return .init(builder.arena),
    }
    const tree = builder.orig_handle.tree;

    var used_members_set: std.BufSet = .init(builder.arena);

    var depth: usize = 0;
    var i: Ast.TokenIndex = @max(dot_token_index, 2);
    while (i > 0) : (i -= 1) {
        switch (tree.tokenTag(i)) {
            .r_brace => {
                depth += 1;
            },
            .l_brace => {
                if (depth == 0) break;
                depth -= 1;
            },
            .equal, .equal_angle_bracket_right, .comma => {
                if (depth > 0) continue;
                if (tree.tokenTag(i - 1) == .identifier and tree.tokenTag(i - 2) == .period) {
                    try used_members_set.insert(tree.tokenSlice(i - 1));
                    i -= 1;
                }
            },
            else => {},
        }
    }
    depth = 0;
    i = @max(dot_token_index, 2);
    while (i < tree.tokens.len) : (i += 1) {
        switch (tree.tokenTag(i)) {
            .l_brace => {
                depth += 1;
            },
            .r_brace => {
                if (depth == 0) break;
                depth -= 1;
            },
            .equal, .equal_angle_bracket_right, .comma => {
                if (depth > 0) continue;
                if (tree.tokenTag(i - 1) == .identifier and tree.tokenTag(i - 2) == .period) {
                    try used_members_set.insert(tree.tokenSlice(i - 1));
                }
            },
            else => {},
        }
    }

    return used_members_set;
}

fn completeDot(builder: *Builder, loc: offsets.Loc) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = builder.orig_handle.tree;

    const dot_token_index = offsets.sourceIndexToTokenIndex(tree, loc.start).pickPreferred(&.{.period}, &tree) orelse return;
    if (dot_token_index < 2) return;

    blk: {
        const nodes = try ast.nodesOverlappingIndex(builder.arena, tree, loc.start);
        const dot_context = getEnumLiteralContext(tree, dot_token_index, nodes) orelse break :blk;
        const used_members_set = try collectUsedMembersSet(builder, dot_context.likely, dot_token_index);
        const containers = try collectContainerNodes(
            builder,
            builder.orig_handle,
            offsets.tokenToLoc(tree, dot_context.identifier_token_index).end,
            dot_context,
        );
        for (containers) |container| {
            try collectContainerFields(builder, dot_context.likely, container, used_members_set);
        }
    }

    if (builder.completions.items.len != 0) return;

    // Prevent compl for float numbers, eg `1.`
    //  Ideally this would also `or token_tags[dot_token_index - 1] != .equal`,
    //  which would mean the only possibility left would be `var enum_val = .`.
    if (tree.tokenTag(dot_token_index - 1) == .number_literal or tree.tokenTag(dot_token_index - 1) != .equal) return;

    // `var enum_val = .` or the get*Context logic failed because of syntax errors (parser didn't create the necessary node(s))
    try globalSetCompletions(builder, .enum_set);
}

/// Asserts that `pos_context` is one of the following:
///  - `.import_string_literal`
///  - `.cinclude_string_literal`
///  - `.embedfile_string_literal`
///  - `.string_literal`
fn completeFileSystemStringLiteral(builder: *Builder, pos_context: Analyser.PositionContext) !void {
    var completions: CompletionSet = .empty;
    const store = &builder.server.document_store;
    const source = builder.orig_handle.tree.source;

    if (pos_context == .string_literal and !DocumentStore.isBuildFile(builder.orig_handle.uri)) return;

    var string_content_loc = pos_context.stringLiteralContentLoc(source);

    // the position context is without lookahead so we have to do it ourself
    string_content_loc.end = std.mem.indexOfAnyPos(u8, source, string_content_loc.end, &.{ 0, '\n', '\r', '"' }) orelse source.len;

    if (builder.source_index < string_content_loc.start or string_content_loc.end < builder.source_index) return;

    const previous_separator_index: ?usize = blk: {
        var index: usize = builder.source_index;
        break :blk while (index > string_content_loc.start) : (index -= 1) {
            if (std.fs.path.isSep(source[index - 1])) break index - 1;
        } else null;
    };

    const next_separator_index: ?usize = for (builder.source_index..string_content_loc.end) |index| {
        if (std.fs.path.isSep(source[index])) break index;
    } else null;

    const completing = offsets.locToSlice(source, .{ .start = string_content_loc.start, .end = previous_separator_index orelse string_content_loc.start });

    var search_paths: std.ArrayListUnmanaged([]const u8) = .empty;
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

    const after_separator_index = if (previous_separator_index) |index| index + 1 else string_content_loc.start;
    const insert_loc: offsets.Loc = .{ .start = after_separator_index, .end = builder.source_index };
    const replace_loc: offsets.Loc = .{ .start = after_separator_index, .end = next_separator_index orelse string_content_loc.end };

    const insert_range = offsets.locToRange(source, insert_loc, builder.server.offset_encoding);
    const replace_range = offsets.locToRange(source, replace_loc, builder.server.offset_encoding);

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

            const label = try builder.arena.dupe(u8, entry.name);
            const insert_text = if (entry.kind == .directory)
                try std.fmt.allocPrint(builder.arena, "{s}/", .{entry.name})
            else
                label;

            _ = try completions.getOrPut(builder.arena, .{
                .label = label,
                .kind = if (entry.kind == .file) .File else .Folder,
                .detail = if (pos_context == .cinclude_string_literal) path else null,
                .textEdit = if (builder.server.client_capabilities.supports_completion_insert_replace_support)
                    .{ .InsertReplaceEdit = .{ .newText = insert_text, .insert = insert_range, .replace = replace_range } }
                else
                    .{ .TextEdit = .{ .newText = insert_text, .range = insert_range } },
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

        const string_content_range = offsets.locToRange(source, string_content_loc, builder.server.offset_encoding);

        // completions on module replace the entire string literal
        for (completions.keys()) |*item| {
            if (item.kind == .Module and item.textEdit == null) {
                item.textEdit = if (builder.server.client_capabilities.supports_completion_insert_replace_support)
                    .{ .InsertReplaceEdit = .{ .newText = item.label, .insert = insert_range, .replace = string_content_range } }
                else
                    .{ .TextEdit = .{ .newText = item.label, .range = insert_range } };
            }
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
    std.debug.assert(source_index <= handle.tree.source.len);

    var builder: Builder = .{
        .server = server,
        .analyser = analyser,
        .arena = arena,
        .orig_handle = handle,
        .source_index = source_index,
        .completions = .empty,
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

    const pos_context = try Analyser.getPositionContext(arena, handle.tree, source_index, false);

    switch (pos_context) {
        .builtin => try completeBuiltin(&builder),
        .var_access, .empty => try completeGlobal(&builder),
        .field_access => |loc| try completeFieldAccess(&builder, loc),
        .global_error_set => try globalSetCompletions(&builder, .error_set),
        .enum_literal => |loc| try completeDot(&builder, loc),
        .label_access, .label_decl => try completeLabel(&builder),
        .import_string_literal,
        .cinclude_string_literal,
        .embedfile_string_literal,
        .string_literal,
        => completeFileSystemStringLiteral(&builder, pos_context) catch |err| {
            log.err("failed to get file system completions: {}", .{err});
            return null;
        },
        else => return null,
    }

    const completions = builder.completions.items;
    if (completions.len == 0) return null;

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
        // https://github.com/microsoft/language-server-protocol/issues/898#issuecomment-593968008
        item.filterText = item.filterText orelse item.label;

        if (item.detail) |det| {
            if (det.len > server.client_capabilities.max_detail_length) {
                item.detail = det[0..server.client_capabilities.max_detail_length];
            }
        }

        const score = kindToSortScore(item.kind.?);
        item.sortText = try std.fmt.allocPrint(arena, "{s}_{s}", .{ score, item.label });
    }

    return .{ .isIncomplete = false, .items = completions };
}

// <--------------------------------------------------------------------------->
//                    global error set / enum field set
// <--------------------------------------------------------------------------->

const CompletionSet = std.ArrayHashMapUnmanaged(types.CompletionItem, void, CompletionContext, false);

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

    var dependencies: std.ArrayListUnmanaged(DocumentStore.Uri) = .empty;
    try dependencies.append(builder.arena, builder.orig_handle.uri);
    try store.collectDependencies(builder.arena, builder.orig_handle, &dependencies);

    // TODO Better solution for deciding what tags to include
    var result_set: CompletionSet = .empty;

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
                gop.key_ptr.* = .{
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
                        .MarkupContent = .{
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
        /// `return .`
        enum_return,
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

        fn allowsDeclLiterals(likely: Likely) bool {
            return switch (likely) {
                .enum_assignment,
                .enum_return,
                .enum_arg,
                => true,
                else => false,
            };
        }
    };
    likely: Likely,
    identifier_token_index: Ast.TokenIndex = 0,
    fn_arg_index: usize = 0,
    need_ret_type: bool = false,
};

fn getEnumLiteralContext(
    tree: Ast,
    dot_token_index: Ast.TokenIndex,
    nodes: []const Ast.Node.Index,
) ?EnumLiteralContext {
    // Allow using `1.` (parser workaround)
    var token_index = if (tree.tokenTag(dot_token_index - 1) == .number_literal)
        (dot_token_index - 2)
    else
        (dot_token_index - 1);
    if (token_index == 0) return null;

    var dot_context: EnumLiteralContext = .{ .likely = .enum_literal };

    switch (tree.tokenTag(token_index)) {
        .equal => {
            token_index -= 1;
            dot_context.need_ret_type = tree.tokenTag(token_index) == .r_paren;
            dot_context.likely = .enum_assignment;
            dot_context.identifier_token_index = token_index;
        },
        .keyword_return => {
            dot_context.identifier_token_index = getReturnTypeLastToken(tree, nodes) orelse return null;
            dot_context.likely = .enum_return;
        },
        .equal_equal, .bang_equal => {
            token_index -= 1;
            dot_context.likely = .enum_comparison;
            dot_context.identifier_token_index = token_index;
        },
        .l_brace, .comma, .l_paren => {
            dot_context = getSwitchOrStructInitContext(tree, dot_token_index, nodes) orelse return null;
        },
        else => return null,
    }
    return dot_context;
}

/// Looks for an identifier that can be passed to `collectContainerNodes()`
/// Returns the token index of the identifier
/// If the identifier is a `fn_name`, `fn_arg_index` is the index of the fn's param
fn getSwitchOrStructInitContext(
    tree: Ast,
    dot_index: Ast.TokenIndex,
    nodes: []const Ast.Node.Index,
) ?EnumLiteralContext {
    // at least 3 tokens should be present, `x{.`
    if (dot_index < 2) return null;
    // pedantic check (can be removed if the "generic exit" conditions below are made to cover more/all cases)
    if (tree.tokenTag(dot_index) != .period) return null;
    var upper_index = dot_index - 1;
    // This prevents completions popping up for `x{.field.`
    if (tree.tokenTag(upper_index) == .identifier) return null;
    // This prevents completions popping up for `x{.field = .`, ie it would suggest `field` again
    // in this case `fn completeDot` would still provide enum completions
    if (tree.tokenTag(upper_index) == .equal) return null;

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
        switch (tree.tokenTag(upper_index)) {
            .r_brace => braces_depth += 1,
            .l_brace => {
                braces_depth -= 1;
                if (braces_depth != one_opening) continue;
                upper_index -= 1;
                switch (tree.tokenTag(upper_index)) {
                    // `S{.`
                    .identifier => break :find_identifier,
                    // anon struct init `.{.`
                    .period => {
                        if (upper_index < 3) return null;
                        upper_index -= 1;
                        if (tree.tokenTag(upper_index) == .ampersand) upper_index -= 1; // `&.{.`
                        if (tree.tokenTag(upper_index) == .equal) { // `= .{.`
                            upper_index -= 1; // eat the `=`
                            switch (tree.tokenTag(upper_index)) {
                                .identifier, // `const s: S = .{.`, `S{.name = .`
                                .period_asterisk, //  `s.* = .{.`
                                => break :find_identifier,
                                else => return null,
                            }
                        }
                        if (tree.tokenTag(upper_index) == .keyword_return) { // `return .{.`
                            upper_index = getReturnTypeLastToken(tree, nodes) orelse return null;
                            break :find_identifier;
                        }
                        // We never return from this branch/condition to the `find_identifier: while ..` loop, so reset and reuse these
                        fn_arg_index = 0;
                        braces_depth = even; // not actually looking for/expecting an uneven number of braces, just making use of the helpful const
                        parens_depth = even;
                        while (upper_index > 0) : (upper_index -= 1) {
                            switch (tree.tokenTag(upper_index)) {
                                .r_brace => braces_depth += 1,
                                .l_brace => {
                                    braces_depth -= 1;
                                    if (braces_depth == one_opening) return null;
                                },
                                .r_paren => parens_depth += 1,
                                .l_paren => {
                                    parens_depth -= 1;
                                    if (parens_depth == one_opening and switch (tree.tokenTag(upper_index - 1)) {
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
                            switch (tree.tokenTag(token_index)) {
                                .r_paren => parens_depth += 1,
                                .l_paren => {
                                    parens_depth -= 1;
                                    if (parens_depth == one_opening)
                                        switch (tree.tokenTag(token_index - 1)) {
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
                switch (tree.tokenTag(upper_index)) {
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
            // Have we arrived at an .identifier matching the criteria?
            .identifier => switch (tree.tokenTag(upper_index + 1)) {
                .l_brace => if (braces_depth == one_opening) break :find_identifier, // `S{.`
                .l_paren => if (braces_depth == even and parens_depth == one_opening) { // `f(.`
                    likely = .enum_arg;
                    break :find_identifier;
                },
                else => {},
            },
            // Exit conditions; generic exit, maybe also .keyword_(var/const)
            .semicolon => if (braces_depth < even) return null, // the braces_depth check handles switch case blocks, ie `.a => {..;}, .`
            else => {},
        }
    }
    // Maybe we simply ran out of tokens?
    // FIXME: This creates a 'blind spot' if the first node in a file is a .container_field_init
    if (upper_index == 0) return null;

    return .{
        .likely = likely,
        .identifier_token_index = upper_index,
        .fn_arg_index = fn_arg_index,
        .need_ret_type = need_ret_type,
    };
}

fn getReturnTypeLastToken(tree: Ast, nodes: []const Ast.Node.Index) ?Ast.TokenIndex {
    const return_type = blk: {
        var func_buf: [1]Ast.Node.Index = undefined;
        for (nodes) |node| {
            const func = tree.fullFnProto(&func_buf, node) orelse continue;
            break :blk func.ast.return_type.unwrap() orelse return null;
        }
        return null;
    };
    return ast.lastToken(tree, return_type);
}

/// Given a Type that is a container, adds it's `.container_field*`s to completions
fn collectContainerFields(
    builder: *Builder,
    likely: EnumLiteralContext.Likely,
    container: Analyser.Type,
    omit_members: std.BufSet,
) error{OutOfMemory}!void {
    const scope_handle = switch (container.data) {
        .container => |s| s,
        else => return,
    };
    const starting_depth = builder.analyser.bound_type_params.depth();
    try builder.analyser.bound_type_params.push(builder.analyser.gpa, scope_handle.bound_params);
    defer builder.analyser.bound_type_params.pop(starting_depth);

    const document_scope = try scope_handle.handle.getDocumentScope();
    const scope_decls = document_scope.getScopeDeclarationsConst(scope_handle.scope);

    const use_snippets = builder.server.config.enable_snippets and builder.server.client_capabilities.supports_snippets;
    for (scope_decls) |decl_index| {
        const decl = document_scope.declarations.get(@intFromEnum(decl_index));
        if (decl != .ast_node) continue;
        const decl_handle: Analyser.DeclWithHandle = .{ .decl = decl, .handle = scope_handle.handle };
        const tree = scope_handle.handle.tree;

        const name = offsets.tokenToSlice(tree, decl.nameToken(tree));
        if (omit_members.contains(name)) continue;

        const completion_item: types.CompletionItem = switch (tree.nodeTag(decl.ast_node)) {
            .container_field_init,
            .container_field_align,
            .container_field,
            => blk: {
                const field = tree.fullContainerField(decl.ast_node).?;

                const insert_text = insert_text: {
                    if (likely != .struct_field and likely != .enum_comparison and likely != .switch_case and !field.ast.tuple_like) {
                        if (use_snippets)
                            break :insert_text try std.fmt.allocPrint(builder.arena, "{{ .{s} = $1 }}$0", .{name})
                        else
                            break :insert_text try std.fmt.allocPrint(builder.arena, "{{ .{s} = ", .{name});
                    }

                    if (!use_snippets)
                        break :insert_text name;

                    if (field.ast.tuple_like or likely == .enum_comparison or likely == .switch_case)
                        break :insert_text name;

                    const is_following_by_equal_token = switch (offsets.sourceIndexToTokenIndex(builder.orig_handle.tree, builder.source_index)) {
                        .none => |data| if (data.right) |right| builder.orig_handle.tree.tokenTag(right) == .equal else false,
                        .one => |token| token + 1 < builder.orig_handle.tree.tokens.len and builder.orig_handle.tree.tokenTag(token + 1) == .equal,
                        .between => |data| builder.orig_handle.tree.tokenTag(data.right) == .equal,
                    };
                    if (is_following_by_equal_token)
                        break :insert_text name;

                    break :insert_text try std.fmt.allocPrint(builder.arena, "{s} = ", .{name});
                };

                const detail = if (Analyser.getContainerFieldSignature(tree, field)) |signature| detail: {
                    if (std.mem.eql(u8, name, signature) and field.ast.tuple_like) break :detail null;
                    break :detail signature;
                } else null;
                break :blk .{
                    .label = name,
                    .kind = if (field.ast.tuple_like) .EnumMember else .Field,
                    .detail = detail,
                    .insertTextFormat = if (use_snippets) .Snippet else .PlainText,
                    .insertText = insert_text,
                };
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                if (!likely.allowsDeclLiterals()) continue;
                // decl literal
                var expected_ty = try decl_handle.resolveType(builder.analyser) orelse continue;
                expected_ty = expected_ty.typeOf(builder.analyser).resolveDeclLiteralResultType();
                if (!expected_ty.eql(container) and !expected_ty.eql(container.typeOf(builder.analyser))) continue;
                try declToCompletion(builder, decl_handle, .{ .parent_container_ty = container });
                continue;
            },
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => blk: {
                if (!likely.allowsDeclLiterals()) continue;
                // decl literal
                const resolved_ty = try decl_handle.resolveType(builder.analyser) orelse continue;
                var expected_ty = try builder.analyser.resolveReturnType(resolved_ty) orelse continue;
                expected_ty = expected_ty.resolveDeclLiteralResultType();
                if (!expected_ty.eql(container) and !expected_ty.typeOf(builder.analyser).eql(container)) continue;
                break :blk try functionTypeCompletion(builder, name, container, resolved_ty) orelse continue;
            },
            else => continue,
        };
        try builder.completions.append(builder.arena, completion_item);
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

    var types_with_handles: std.ArrayListUnmanaged(Analyser.Type) = .empty;
    const position_context = try Analyser.getPositionContext(builder.arena, handle.tree, source_index, false);
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

        if (std.mem.eql(u8, name, "@branchHint")) {
            switch (arg_index) {
                0 => break :name "BranchHint",
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
    if (!type_expr.isFunc()) {
        try type_expr.getAllTypesWithHandlesArrayList(arena, types_with_handles);
        return;
    }

    if (dot_context.likely == .enum_comparison or dot_context.need_ret_type) { // => we need f()'s return type
        var node_type = try analyser.resolveReturnType(type_expr) orelse return;
        if (try analyser.resolveUnwrapErrorUnionType(node_type, .payload)) |unwrapped| node_type = unwrapped;
        try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
        return;
    }
    const func_node_handle = type_expr.data.other; // this assumes that function types can only be Ast nodes
    const fn_param_decl: Analyser.Declaration = .{ .function_parameter = .{
        .func = func_node_handle.node,
        .param_index = @intCast(dot_context.fn_arg_index),
    } };
    const fn_param_decl_with_handle: Analyser.DeclWithHandle = .{ .decl = fn_param_decl, .handle = func_node_handle.handle };
    const param_type = try fn_param_decl_with_handle.resolveType(analyser) orelse return;
    try types_with_handles.append(arena, param_type);
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
    const name_loc = Analyser.identifierLocFromIndex(handle.tree, loc.end) orelse {
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
        if (!node_type.isFunc()) {
            try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
            continue;
        }

        if (dot_context.need_ret_type) { // => we need f()'s return type
            node_type = try analyser.resolveReturnType(node_type) orelse continue;
            if (try analyser.resolveUnwrapErrorUnionType(node_type, .payload)) |unwrapped| node_type = unwrapped;
            try node_type.getAllTypesWithHandlesArrayList(arena, types_with_handles);
            continue;
        }
        // don't have the luxury of referencing an `Ast.full.Call`
        // check if the first symbol is a `T` or an instance_of_T
        const additional_index: usize = blk: {
            // `loc` points to offsets within `handle`, not `node_type.decl.handle`
            const field_access_slice = handle.tree.source[loc.start..loc.end];
            if (field_access_slice[0] == '@') break :blk 0; // assume `@import("..").some.Other{.}`
            var symbol_iter = std.mem.tokenizeScalar(u8, field_access_slice, '.');
            const first_symbol = symbol_iter.next() orelse continue;
            const symbol_decl = try analyser.lookupSymbolGlobal(handle, first_symbol, loc.start) orelse continue;
            const symbol_type = try symbol_decl.resolveType(analyser) orelse continue;
            if (!symbol_type.is_type_val) { // then => instance_of_T
                if (try analyser.hasSelfParam(node_type)) break :blk 1;
            }
            break :blk 0; // is `T`, no SelfParam
        };
        const fn_node_handle = node_type.data.other; // this assumes that function types can only be Ast nodes
        const param_decl: Analyser.Declaration.Param = .{
            .param_index = @truncate(dot_context.fn_arg_index + additional_index),
            .func = fn_node_handle.node,
        };
        const param = param_decl.get(fn_node_handle.handle.tree) orelse continue;

        const type_expr = param.type_expr orelse continue;
        const param_rcts = try collectContainerNodes(
            builder,
            fn_node_handle.handle,
            offsets.nodeToLoc(fn_node_handle.handle.tree, type_expr).end,
            dot_context,
        );
        for (param_rcts) |prct| try types_with_handles.append(arena, prct);
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
    const dot_index = offsets.sourceIndexToTokenIndex(handle.tree, loc.start).pickPreferred(&.{.period}, &handle.tree) orelse return;
    const nodes = try ast.nodesOverlappingIndex(arena, handle.tree, loc.start);
    const el_dot_context = getSwitchOrStructInitContext(handle.tree, dot_index, nodes) orelse return;
    const containers = try collectContainerNodes(
        builder,
        handle,
        offsets.tokenToLoc(handle.tree, el_dot_context.identifier_token_index).end,
        el_dot_context,
    );
    for (containers) |container| {
        const container_instance = container.instanceTypeVal(analyser) orelse container;
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
