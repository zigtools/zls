//! Implementation of [`textDocument/codeAction`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_codeAction)

const std = @import("std");
const Ast = std.zig.Ast;
const Token = std.zig.Token;

const DocumentStore = @import("../DocumentStore.zig");
const DocumentScope = @import("../DocumentScope.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");

pub const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    offset_encoding: offsets.Encoding,
    only_kinds: ?std.EnumSet(std.meta.Tag(types.CodeActionKind)),

    actions: std.ArrayList(types.CodeAction) = .empty,
    fixall_text_edits: std.ArrayList(types.TextEdit) = .empty,

    pub fn generateCodeAction(
        builder: *Builder,
        error_bundle: std.zig.ErrorBundle,
    ) error{OutOfMemory}!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        var remove_capture_actions: std.AutoHashMapUnmanaged(types.Range, void) = .empty;

        try handleUnorganizedImport(builder);

        if (error_bundle.errorMessageCount() == 0) return; // `getMessages` can't be called on an empty ErrorBundle
        for (error_bundle.getMessages()) |msg_index| {
            const err = error_bundle.getErrorMessage(msg_index);
            const message = error_bundle.nullTerminatedString(err.msg);
            const kind = DiagnosticKind.parse(message) orelse continue;

            if (err.src_loc == .none) continue;
            const src_loc = error_bundle.getSourceLocation(err.src_loc);

            const loc: offsets.Loc = .{
                .start = src_loc.span_start,
                .end = src_loc.span_end,
            };

            switch (kind) {
                .unused => |id| switch (id) {
                    .@"function parameter" => try handleUnusedFunctionParameter(builder, loc),
                    .@"local constant" => try handleUnusedVariableOrConstant(builder, loc),
                    .@"local variable" => try handleUnusedVariableOrConstant(builder, loc),
                    .@"switch tag capture", .capture => try handleUnusedCapture(builder, loc, &remove_capture_actions),
                },
                .non_camelcase_fn => try handleNonCamelcaseFunction(builder, loc),
                .pointless_discard => try handlePointlessDiscard(builder, loc),
                .omit_discard => |id| switch (id) {
                    .@"error capture; omit it instead" => {},
                    .@"error capture" => try handleUnusedCapture(builder, loc, &remove_capture_actions),
                },
                // the undeclared identifier may be a discard
                .undeclared_identifier => try handlePointlessDiscard(builder, loc),
                .unreachable_code => {
                    // TODO
                    // autofix: comment out code
                    // fix: remove code
                },
                .var_never_mutated => try handleVariableNeverMutated(builder, loc),
            }
        }

        if (builder.fixall_text_edits.items.len != 0) {
            try builder.actions.append(builder.arena, .{
                .title = "apply fixall",
                .kind = .@"source.fixAll",
                .edit = try builder.createWorkspaceEdit(builder.fixall_text_edits.items),
            });
        }
    }

    /// Returns `false` if the client explicitly specified that they are not interested in this code action kind.
    fn wantKind(builder: *Builder, kind: std.meta.Tag(types.CodeActionKind)) bool {
        const only_kinds = builder.only_kinds orelse return true;
        return only_kinds.contains(kind);
    }

    pub fn generateCodeActionsInRange(
        builder: *Builder,
        range: types.Range,
    ) error{OutOfMemory}!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const tree = builder.handle.tree;

        const source_index = offsets.positionToIndex(tree.source, range.start, builder.offset_encoding);

        const ctx = try Analyser.getPositionContext(builder.arena, builder.handle.tree, source_index, true);
        if (ctx != .string_literal) return;

        var token_idx = offsets.sourceIndexToTokenIndex(tree, source_index).pickPreferred(&.{ .string_literal, .multiline_string_literal_line }, &tree) orelse return;

        // if `offsets.sourceIndexToTokenIndex` is called with a source index between two tokens, it will be the token to the right.
        switch (tree.tokenTag(token_idx)) {
            .string_literal, .multiline_string_literal_line => {},
            else => token_idx -|= 1,
        }

        switch (tree.tokenTag(token_idx)) {
            .multiline_string_literal_line => try generateMultilineStringCodeActions(builder, token_idx),
            .string_literal => try generateStringLiteralCodeActions(builder, token_idx),
            else => {},
        }
    }

    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit {
        const range = offsets.locToRange(self.handle.tree.source, loc, self.offset_encoding);
        return .{ .range = range, .newText = new_text };
    }

    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit {
        const position = offsets.indexToPosition(self.handle.tree.source, index, self.offset_encoding);
        return .{ .range = .{ .start = position, .end = position }, .newText = new_text };
    }

    pub fn createWorkspaceEdit(self: *Builder, edits: []const types.TextEdit) error{OutOfMemory}!types.WorkspaceEdit {
        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try workspace_edit.changes.?.map.putNoClobber(self.arena, self.handle.uri, try self.arena.dupe(types.TextEdit, edits));

        return workspace_edit;
    }
};

pub fn generateStringLiteralCodeActions(
    builder: *Builder,
    token: Ast.TokenIndex,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.refactor)) return;

    const tree = builder.handle.tree;
    switch (tree.tokenTag(token -| 1)) {
        // Not covered by position context
        .keyword_test, .keyword_extern => return,
        else => {},
    }

    const token_text = offsets.tokenToSlice(tree, token); // Includes quotes
    const parsed = std.zig.string_literal.parseAlloc(builder.arena, token_text) catch |err| switch (err) {
        error.InvalidLiteral => return,
        else => |other| return other,
    };
    // Check for disallowed characters and utf-8 validity
    for (parsed) |c| {
        if (c == '\n') continue;
        if (std.ascii.isControl(c)) return;
    }
    if (!std.unicode.utf8ValidateSlice(parsed)) return;
    const with_slashes = try std.mem.replaceOwned(u8, builder.arena, parsed, "\n", "\n    \\\\"); // Hardcoded 4 spaces

    var result: std.ArrayList(u8) = try .initCapacity(builder.arena, with_slashes.len + 3);
    result.appendSliceAssumeCapacity("\\\\");
    result.appendSliceAssumeCapacity(with_slashes);
    result.appendAssumeCapacity('\n');

    const loc = offsets.tokenToLoc(tree, token);
    try builder.actions.append(builder.arena, .{
        .title = "convert to a multiline string literal",
        .kind = .refactor,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, result.items)}),
    });
}

pub fn generateMultilineStringCodeActions(
    builder: *Builder,
    token: Ast.TokenIndex,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.refactor)) return;

    const tree = builder.handle.tree;
    std.debug.assert(.multiline_string_literal_line == tree.tokenTag(token));
    // Collect (exclusive) token range of the literal (one token per literal line)
    const start = if (std.mem.lastIndexOfNone(Token.Tag, tree.tokens.items(.tag)[0..(token + 1)], &.{.multiline_string_literal_line})) |i| i + 1 else 0;
    const end = std.mem.indexOfNonePos(Token.Tag, tree.tokens.items(.tag), token, &.{.multiline_string_literal_line}) orelse tree.tokens.len;

    // collect the text in the literal
    const loc = offsets.tokensToLoc(builder.handle.tree, @intCast(start), @intCast(end));
    var str_escaped: std.ArrayList(u8) = try .initCapacity(builder.arena, 2 * (loc.end - loc.start));
    str_escaped.appendAssumeCapacity('"');
    for (start..end) |i| {
        std.debug.assert(tree.tokenTag(@intCast(i)) == .multiline_string_literal_line);
        const string_part = offsets.tokenToSlice(builder.handle.tree, @intCast(i));
        // Iterate without the leading \\
        for (string_part[2..]) |c| {
            const chunk = switch (c) {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => unreachable,
                else => &.{c},
            };
            str_escaped.appendSliceAssumeCapacity(chunk);
        }
        if (i != end - 1) {
            str_escaped.appendSliceAssumeCapacity("\\n");
        }
    }
    str_escaped.appendAssumeCapacity('"');

    // Get Loc of the whole literal to delete it
    // Multiline string literal ends before the \n or \r, but it must be deleted too
    const first_token_start = builder.handle.tree.tokenStart(@intCast(start));
    const last_token_end = std.mem.indexOfNonePos(
        u8,
        builder.handle.tree.source,
        offsets.tokenToLoc(builder.handle.tree, @intCast(end - 1)).end + 1,
        "\n\r",
    ) orelse builder.handle.tree.source.len;
    const remove_loc: offsets.Loc = .{ .start = first_token_start, .end = last_token_end };

    try builder.actions.append(builder.arena, .{
        .title = "convert to a string literal",
        .kind = .refactor,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(remove_loc, str_escaped.items)}),
    });
}

/// To report server capabilities
pub const supported_code_actions: []const types.CodeActionKind = &.{
    .quickfix,
    .refactor,
    .source,
    .@"source.organizeImports",
    .@"source.fixAll",
};

pub fn collectAutoDiscardDiagnostics(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    const tree = handle.tree;

    // search for the following pattern:
    // _ = some_identifier; // autofix

    var i: usize = 0;
    while (i < tree.tokens.len) {
        const first_token: Ast.TokenIndex = @intCast(std.mem.indexOfPos(
            Token.Tag,
            tree.tokens.items(.tag),
            i,
            &.{ .identifier, .equal, .identifier, .semicolon },
        ) orelse break);
        defer i = first_token + 4;

        const underscore_token = first_token;
        const identifier_token = first_token + 2;
        const semicolon_token = first_token + 3;

        if (!std.mem.eql(u8, offsets.tokenToSlice(tree, underscore_token), "_")) continue;

        const autofix_comment_start = std.mem.indexOfNonePos(u8, tree.source, tree.tokenStart(semicolon_token) + 1, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_comment_start..], "//")) continue;
        const autofix_str_start = std.mem.indexOfNonePos(u8, tree.source, autofix_comment_start + "//".len, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_str_start..], "autofix")) continue;

        const related_info = blk: {
            const decl = (try analyser.lookupSymbolGlobal(
                handle,
                offsets.tokenToSlice(tree, identifier_token),
                tree.tokenStart(identifier_token),
            )) orelse break :blk &.{};
            const def = try decl.definitionToken(analyser, false);
            const range = offsets.tokenToRange(tree, def.token, offset_encoding);
            break :blk try arena.dupe(types.DiagnosticRelatedInformation, &.{.{
                .location = .{
                    .uri = handle.uri,
                    .range = range,
                },
                .message = "variable declared here",
            }});
        };

        try diagnostics.append(arena, .{
            .range = offsets.tokenToRange(tree, identifier_token, offset_encoding),
            .severity = .Information,
            .code = null,
            .source = "zls",
            .message = "auto discard for unused variable",
            .relatedInformation = related_info,
        });
    }
}

fn handleNonCamelcaseFunction(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    if (std.mem.allEqual(u8, identifier_name, '_')) return;

    const new_text = try createCamelcaseText(builder.arena, identifier_name);

    try builder.actions.append(builder.arena, .{
        .title = "make function name camelCase",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, new_text)}),
    });
}

fn handleUnusedFunctionParameter(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const payload = switch (decl.decl) {
        .function_parameter => |pay| pay,
        else => return,
    };

    std.debug.assert(tree.nodeTag(payload.func) == .fn_decl);

    const block = tree.nodeData(payload.func).node_and_node[1];

    // If we are on the "last parameter" that requires a discard, then we need to append a newline,
    // as well as any relevant indentations, such that the next line is indented to the same column.
    // To do this, you may have a function like:
    // fn(a: i32, b: i32, c: i32) void { _ = a; _ = b; _ = c; }
    // or
    // fn(
    //     a: i32,
    //     b: i32,
    //     c: i32,
    // ) void { ... }
    // We have to be able to detect both cases.
    const fn_proto_param = payload.get(tree).?;
    const last_param_token = ast.paramLastToken(tree, fn_proto_param);

    const potential_comma_token = last_param_token + 1;
    const found_comma = potential_comma_token < tree.tokens.len and tree.tokenTag(potential_comma_token) == .comma;

    const potential_r_paren_token = potential_comma_token + @intFromBool(found_comma);
    const is_last_param = potential_r_paren_token < tree.tokens.len and tree.tokenTag(potential_r_paren_token) == .r_paren;

    const insert_token = tree.nodeMainToken(block);
    const add_suffix_newline = is_last_param and tree.tokenTag(insert_token + 1) == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);
    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.insert(builder.arena, 0, builder.createTextEditPos(insert_index, new_text));
    }

    if (builder.wantKind(.quickfix)) {
        // TODO add no `// autofix` comment
        // TODO fix formatting
        try builder.actions.append(builder.arena, .{
            .title = "remove function parameter",
            .kind = .quickfix,
            .isPreferred = false,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(getParamRemovalRange(tree, fn_proto_param), "")}),
        });
    }
}

fn handleUnusedVariableOrConstant(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const node = switch (decl.decl) {
        .ast_node => |node| node,
        .assign_destructure => |payload| payload.node,
        else => return,
    };

    const insert_token = ast.lastToken(tree, node) + 1;

    if (insert_token >= tree.tokens.len) return;
    if (tree.tokenTag(insert_token) != .semicolon) return;

    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, false, false);

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.append(builder.arena, builder.createTextEditPos(insert_index, new_text));
    }

    if (builder.wantKind(.quickfix)) {
        // TODO add no `// autofix` comment
        try builder.actions.append(builder.arena, .{
            .title = "discard value",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(insert_index, new_text)}),
        });
    }
}

fn handleUnusedCapture(
    builder: *Builder,
    loc: offsets.Loc,
    remove_capture_actions: *std.AutoHashMapUnmanaged(types.Range, void),
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const tree = builder.handle.tree;

    const source = tree.source;

    const identifier_token = offsets.sourceIndexToTokenIndex(tree, loc.start).pickPreferred(&.{.identifier}, &tree) orelse return;
    if (tree.tokenTag(identifier_token) != .identifier) return;

    const identifier_name = offsets.locToSlice(source, loc);

    // Zig can report incorrect "unused capture" errors
    // https://github.com/ziglang/zig/pull/22209
    if (std.mem.eql(u8, identifier_name, "_")) return;

    if (builder.wantKind(.quickfix)) {
        const capture_loc = getCaptureLoc(source, loc) orelse return;

        const remove_cap_loc = builder.createTextEditLoc(capture_loc, "");

        try builder.actions.append(builder.arena, .{
            .title = "discard capture name",
            .kind = .quickfix,
            .isPreferred = false,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, "_")}),
        });

        // prevent adding duplicate 'remove capture' action.
        // search for a matching action by comparing ranges.
        const gop = try remove_capture_actions.getOrPut(builder.arena, remove_cap_loc.range);
        if (!gop.found_existing) {
            try builder.actions.append(builder.arena, .{
                .title = "remove capture",
                .kind = .quickfix,
                .isPreferred = false,
                .edit = try builder.createWorkspaceEdit(&.{remove_cap_loc}),
            });
        }
    }

    if (!builder.wantKind(.@"source.fixAll")) return;

    const capture_end: Ast.TokenIndex = @intCast(std.mem.indexOfScalarPos(
        Token.Tag,
        tree.tokens.items(.tag),
        identifier_token,
        .pipe,
    ) orelse return);

    var lbrace_token = capture_end + 1;

    // handle while loop continue statements such as `while(foo) |bar| : (x += 1) {}`
    if (tree.tokenTag(capture_end + 1) == .colon) {
        var token_index = capture_end + 2;
        if (token_index >= tree.tokens.len) return;
        if (tree.tokenTag(token_index) != .l_paren) return;
        token_index += 1;

        var depth: u32 = 1;
        while (true) : (token_index += 1) {
            const tag = tree.tokenTag(token_index);
            switch (tag) {
                .eof => return,
                .l_paren => {
                    depth += 1;
                },
                .r_paren => {
                    depth -= 1;
                    if (depth == 0) {
                        token_index += 1;
                        break;
                    }
                },
                else => {},
            }
        }
        lbrace_token = token_index;
    }

    if (lbrace_token + 1 >= tree.tokens.len) return;
    if (tree.tokenTag(lbrace_token) != .l_brace) return;

    const is_last_capture = tree.tokenTag(identifier_token + 1) == .pipe;

    const insert_token = lbrace_token;
    // if we are on the last capture of the block, we need to add an additional newline
    // i.e |a, b| { ... } -> |a, b| { ... \n_ = a; \n_ = b;\n }
    const add_suffix_newline = is_last_capture and tree.tokenTag(insert_token + 1) == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);
    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);

    try builder.fixall_text_edits.insert(builder.arena, 0, builder.createTextEditPos(insert_index, new_text));
}

fn handlePointlessDiscard(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const edit_loc = getDiscardLoc(builder.handle.tree.source, loc) orelse return;

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.append(builder.arena, builder.createTextEditLoc(edit_loc, ""));
    }

    if (builder.wantKind(.quickfix)) {
        try builder.actions.append(builder.arena, .{
            .title = "remove pointless discard",
            .kind = .@"source.fixAll",
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{
                builder.createTextEditLoc(edit_loc, ""),
            }),
        });
    }
}

fn handleVariableNeverMutated(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.quickfix)) return;

    const source = builder.handle.tree.source;

    const var_keyword_end = 1 + (std.mem.lastIndexOfNone(u8, source[0..loc.start], &std.ascii.whitespace) orelse return);

    const var_keyword_loc: offsets.Loc = .{
        .start = var_keyword_end -| "var".len,
        .end = var_keyword_end,
    };

    if (!std.mem.eql(u8, offsets.locToSlice(source, var_keyword_loc), "var")) return;

    try builder.actions.append(builder.arena, .{
        .title = "use 'const'",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(var_keyword_loc, "const"),
        }),
    });
}

const ImportPlacement = enum {
    top,
    bottom,
};

fn analyzeImportPlacement(tree: Ast, imports: []const ImportDecl) ImportPlacement {
    const root_decls = tree.rootDecls();

    if (root_decls.len == 0 or imports.len == 0) return .top;

    const first_import = imports[0].var_decl;
    const last_import = imports[imports.len - 1].var_decl;

    const first_decl = root_decls[0];
    const last_decl = root_decls[root_decls.len - 1];

    const starts_with_import = first_decl == first_import;
    const ends_with_import = last_decl == last_import;

    if (starts_with_import and ends_with_import) {
        // If there are only imports, choose "top" to avoid unnecessary newlines.
        // Otherwise, having an import at the bottom is a strong signal that that is the preferred style.
        const has_gaps = root_decls.len != imports.len;

        return if (has_gaps) .bottom else .top;
    }

    return if (!starts_with_import and ends_with_import) .bottom else .top;
}

fn handleUnorganizedImport(builder: *Builder) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.organizeImports")) return;

    const tree = builder.handle.tree;
    if (tree.errors.len != 0) return;

    const imports = try getImportsDecls(builder, builder.arena);

    if (imports.len == 0) return;

    // The optimization is disabled because it does not detect the case where imports and other decls are mixed
    // if (std.sort.isSorted(ImportDecl, imports.items, tree, ImportDecl.lessThan)) return;

    const placement = analyzeImportPlacement(tree, imports);

    const sorted_imports = try builder.arena.dupe(ImportDecl, imports);
    std.mem.sort(ImportDecl, sorted_imports, tree, ImportDecl.lessThan);

    var edits: std.ArrayList(types.TextEdit) = .empty;

    // add sorted imports
    {
        var new_text: std.ArrayList(u8) = .empty;

        if (placement == .bottom) {
            try new_text.append(builder.arena, '\n');
        }

        for (sorted_imports, 0..) |import_decl, i| {
            if (i != 0 and ImportDecl.addSeperator(sorted_imports[i - 1], import_decl)) {
                try new_text.append(builder.arena, '\n');
            }

            try new_text.print(builder.arena, "{s}\n", .{offsets.locToSlice(tree.source, import_decl.getLoc(tree, false))});
        }

        try new_text.append(builder.arena, '\n');

        const range: offsets.Range = switch (placement) {
            .top => blk: {
                // Current behavior: insert at top after doc comments
                const first_token = std.mem.indexOfNone(Token.Tag, tree.tokens.items(.tag), &.{.container_doc_comment}) orelse tree.tokens.len;
                const insert_pos = offsets.tokenToPosition(tree, @intCast(first_token), builder.offset_encoding);
                break :blk .{ .start = insert_pos, .end = insert_pos };
            },
            .bottom => blk: {
                // Current behavior: insert at eof
                break :blk offsets.tokenToRange(tree, @intCast(tree.tokens.len - 1), builder.offset_encoding);
            },
        };

        try edits.append(builder.arena, .{
            .range = range,
            .newText = new_text.items,
        });
    }

    {
        // remove previous imports
        const import_locs = try builder.arena.alloc(offsets.Loc, imports.len);
        for (imports, import_locs) |import_decl, *loc| {
            loc.* = import_decl.getLoc(tree, true);
        }

        const import_ranges = try builder.arena.alloc(types.Range, imports.len);
        try offsets.multiple.locToRange(builder.arena, tree.source, import_locs, import_ranges, builder.offset_encoding);

        for (import_ranges) |range| {
            try edits.append(builder.arena, .{
                .range = range,
                .newText = "",
            });
        }
    }

    const workspace_edit = try builder.createWorkspaceEdit(edits.items);

    try builder.actions.append(builder.arena, .{
        .title = "organize @import",
        .kind = .@"source.organizeImports",
        .isPreferred = true,
        .edit = workspace_edit,
    });
}

/// const name_slice = @import(value_slice);
pub const ImportDecl = struct {
    var_decl: Ast.Node.Index,
    first_comment_token: ?Ast.TokenIndex,
    name: []const u8,
    value: []const u8,

    /// Strings for sorting second order imports (e.g. `const ascii = std.ascii`)
    parent_name: ?[]const u8 = null,
    parent_value: ?[]const u8 = null,

    pub const AstNodeAdapter = struct {
        pub fn hash(ctx: @This(), ast_node: Ast.Node.Index) u32 {
            _ = ctx;
            const hash_fn = std.array_hash_map.getAutoHashFn(Ast.Node.Index, void);
            return hash_fn({}, ast_node);
        }

        pub fn eql(ctx: @This(), a: Ast.Node.Index, b: ImportDecl, b_index: usize) bool {
            _ = ctx;
            _ = b_index;
            return a == b.var_decl;
        }
    };

    /// declaration order controls sorting order
    pub const Kind = enum {
        std,
        builtin,
        build_options,
        package,
        file,
    };

    pub const sort_case_sensitive: bool = false;
    pub const sort_public_decls_first: bool = false;

    pub fn lessThan(context: Ast, lhs: ImportDecl, rhs: ImportDecl) bool {
        const lhs_kind = lhs.getKind();
        const rhs_kind = rhs.getKind();
        if (lhs_kind != rhs_kind) return @intFromEnum(lhs_kind) < @intFromEnum(rhs_kind);

        if (sort_public_decls_first) {
            const node_tokens = context.nodes.items(.main_token);
            const is_lhs_pub = node_tokens[lhs.var_decl] > 0 and context.tokenTag(node_tokens[lhs.var_decl] - 1) == .keyword_pub;
            const is_rhs_pub = node_tokens[rhs.var_decl] > 0 and context.tokenTag(node_tokens[rhs.var_decl] - 1) == .keyword_pub;
            if (is_lhs_pub != is_rhs_pub) return is_lhs_pub;
        }

        // First the parent @import, then the child using it
        if (lhs.isParent(rhs)) return true;

        // 'root' gets sorted after 'builtin'
        if (sort_case_sensitive) {
            return std.mem.lessThan(u8, lhs.getSortSlice(), rhs.getSortSlice());
        } else {
            return std.ascii.lessThanIgnoreCase(lhs.getSortSlice(), rhs.getSortSlice());
        }
    }

    pub fn isParent(self: ImportDecl, child: ImportDecl) bool {
        const parent_name = child.parent_name orelse return false;
        const parent_value = child.parent_value orelse return false;
        return std.mem.eql(u8, self.name, parent_name) and std.mem.eql(u8, self.value, parent_value);
    }

    pub fn getKind(self: ImportDecl) Kind {
        const name = self.getSortValue()[1 .. self.getSortValue().len - 1];

        if (std.mem.endsWith(u8, name, ".zig")) return .file;

        if (std.mem.eql(u8, name, "std")) return .std;
        if (std.mem.eql(u8, name, "builtin")) return .builtin;
        if (std.mem.eql(u8, name, "root")) return .builtin;
        if (std.mem.eql(u8, name, "build_options")) return .build_options;

        return .package;
    }

    /// returns the string by which this import should be sorted
    pub fn getSortSlice(self: ImportDecl) []const u8 {
        switch (self.getKind()) {
            .file => {
                if (std.mem.indexOfScalar(u8, self.getSortValue(), '/') != null) {
                    return self.getSortValue()[1 .. self.getSortValue().len - 1];
                }
                return self.getSortName();
            },
            // There used to be unreachable for other than file and package, but the user
            // can just write @import("std") twice.
            else => return self.getSortName(),
        }
    }

    pub fn getSortName(self: ImportDecl) []const u8 {
        return self.parent_name orelse self.name;
    }

    pub fn getSortValue(self: ImportDecl) []const u8 {
        return self.parent_value orelse self.value;
    }

    /// returns true if there should be an empty line between these two imports
    /// assumes `lessThan(void, lhs, rhs) == true`
    pub fn addSeperator(lhs: ImportDecl, rhs: ImportDecl) bool {
        const lhs_kind = @intFromEnum(lhs.getKind());
        const rhs_kind = @intFromEnum(rhs.getKind());
        if (rhs_kind <= @intFromEnum(Kind.build_options)) return false;
        return lhs_kind != rhs_kind;
    }

    pub fn getSourceStartIndex(self: ImportDecl, tree: Ast) usize {
        return tree.tokenStart(self.first_comment_token orelse tree.firstToken(self.var_decl));
    }

    pub fn getSourceEndIndex(self: ImportDecl, tree: Ast, include_line_break: bool) usize {
        var last_token = ast.lastToken(tree, self.var_decl);
        if (last_token + 1 < tree.tokens.len - 1 and tree.tokenTag(last_token + 1) == .semicolon) {
            last_token += 1;
        }

        const end = offsets.tokenToLoc(tree, last_token).end;
        if (!include_line_break) return end;
        return std.mem.indexOfNonePos(u8, tree.source, end, &.{ ' ', '\t', '\n' }) orelse tree.source.len;
    }

    /// similar to `offsets.nodeToLoc` but will also include preceding comments and postfix semicolon and line break
    pub fn getLoc(self: ImportDecl, tree: Ast, include_line_break: bool) offsets.Loc {
        return .{
            .start = self.getSourceStartIndex(tree),
            .end = self.getSourceEndIndex(tree, include_line_break),
        };
    }
};

pub fn getImportsDecls(builder: *Builder, allocator: std.mem.Allocator) error{OutOfMemory}![]ImportDecl {
    const tree = builder.handle.tree;

    const root_decls = tree.rootDecls();

    var skip_set: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, root_decls.len);
    defer skip_set.deinit(allocator);

    var imports: std.ArrayHashMapUnmanaged(ImportDecl, void, void, true) = .empty;
    defer imports.deinit(allocator);

    // iterate until no more imports are found
    var updated = true;
    while (updated) {
        updated = false;
        var it = skip_set.iterator(.{ .kind = .unset });
        next_decl: while (it.next()) |root_decl_index| {
            const node = root_decls[root_decl_index];

            var do_skip: bool = true;
            defer if (do_skip) skip_set.set(root_decl_index);

            if (skip_set.isSet(root_decl_index)) continue;

            if (tree.nodeTag(node) != .simple_var_decl) continue;
            const var_decl = tree.simpleVarDecl(node);

            var current_node = var_decl.ast.init_node.unwrap() orelse continue;
            const import: ImportDecl = found_decl: while (true) {
                const token = tree.nodeMainToken(current_node);
                switch (tree.nodeTag(current_node)) {
                    .builtin_call_two, .builtin_call_two_comma => {
                        // `>@import("string")<` case
                        const builtin_name = offsets.tokenToSlice(tree, token);
                        if (!std.mem.eql(u8, builtin_name, "@import")) continue :next_decl;
                        // TODO what about @embedFile ?

                        const first_param, const second_param = tree.nodeData(current_node).opt_node_and_opt_node;
                        const param_node = first_param.unwrap() orelse continue :next_decl;
                        if (second_param != .none) continue :next_decl;
                        if (tree.nodeTag(param_node) != .string_literal) continue :next_decl;

                        const name_token = var_decl.ast.mut_token + 1;
                        const value_token = tree.nodeMainToken(param_node);

                        break :found_decl .{
                            .var_decl = node,
                            .first_comment_token = Analyser.getDocCommentTokenIndex(&tree, tree.nodeMainToken(node)),
                            .name = offsets.tokenToSlice(tree, name_token),
                            .value = offsets.tokenToSlice(tree, value_token),
                        };
                    },
                    .field_access => {
                        // `@import("foo").>bar<` or `foo.>bar<` case
                        // drill down to the base import
                        current_node = tree.nodeData(current_node).node_and_token[0];
                        continue;
                    },
                    .identifier => {
                        // `>std<.ascii` case - Might be an alias
                        const name_token = ast.identifierTokenFromIdentifierNode(tree, current_node) orelse continue :next_decl;
                        const name = offsets.identifierTokenToNameSlice(tree, name_token);

                        // calling `lookupSymbolGlobal` is slower than just looking up a symbol at the root scope directly.
                        // const decl = try builder.analyser.lookupSymbolGlobal(builder.handle, name, source_index) orelse continue :next_decl;
                        const document_scope = try builder.handle.getDocumentScope();

                        const decl_index = document_scope.getScopeDeclaration(.{
                            .scope = .root,
                            .name = name,
                            .kind = .other,
                        }).unwrap() orelse continue :next_decl;

                        const decl = document_scope.declarations.get(@intFromEnum(decl_index));

                        if (decl != .ast_node) continue :next_decl;
                        const decl_found = decl.ast_node;

                        const import_decl = imports.getKeyAdapted(decl_found, ImportDecl.AstNodeAdapter{}) orelse {
                            // We may find the import in a future loop iteration
                            do_skip = false;
                            continue :next_decl;
                        };
                        const ident_name_token = var_decl.ast.mut_token + 1;
                        const var_name = offsets.tokenToSlice(tree, ident_name_token);
                        break :found_decl .{
                            .var_decl = node,
                            .first_comment_token = Analyser.getDocCommentTokenIndex(&tree, tree.nodeMainToken(node)),
                            .name = var_name,
                            .value = var_name,
                            .parent_name = import_decl.getSortName(),
                            .parent_value = import_decl.getSortValue(),
                        };
                    },
                    else => continue :next_decl,
                }
            };
            const gop = try imports.getOrPutContextAdapted(allocator, import.var_decl, ImportDecl.AstNodeAdapter{}, {});
            if (!gop.found_existing) gop.key_ptr.* = import;
            updated = true;
        }
    }

    return try allocator.dupe(ImportDecl, imports.keys());
}

fn detectIndentation(source: []const u8) []const u8 {
    // Essentially I'm looking for the first indentation in the file.
    var i: usize = 0;
    const len = source.len - 1; // I need 1 look-ahead
    while (i < len) : (i += 1) {
        if (source[i] != '\n') continue;
        i += 1;
        if (source[i] == '\t') return "\t";
        var space_count: usize = 0;
        while (i < source.len and source[i] == ' ') : (i += 1) {
            space_count += 1;
        }
        if (source[i] == '\n') { // Some editors mess up indentation of empty lines
            i -= 1;
            continue;
        }
        if (space_count == 0) continue;
        if (source[i] == '/') continue; // Comments sometimes have additional alignment.
        if (source[i] == '\\') continue; // multi-line strings might as well.
        return source[i - space_count .. i];
    }
    return "    "; // recommended style
}

// attempts to converts a slice of text into camelcase 'FUNCTION_NAME' -> 'functionName'
fn createCamelcaseText(allocator: std.mem.Allocator, identifier: []const u8) ![]const u8 {
    // skip initial & ending underscores
    const trimmed_identifier = std.mem.trim(u8, identifier, "_");

    const num_separators = std.mem.count(u8, trimmed_identifier, "_");

    const new_text_len = trimmed_identifier.len - num_separators;
    var new_text: std.ArrayList(u8) = try .initCapacity(allocator, new_text_len);
    errdefer new_text.deinit(allocator);

    var idx: usize = 0;
    while (idx < trimmed_identifier.len) {
        const ch = trimmed_identifier[idx];
        if (ch == '_') {
            // the trimmed identifier is guaranteed to not have underscores at the end,
            // so it can be assumed that ptr dereferences are safe until an alnum char is found
            while (trimmed_identifier[idx] == '_') : (idx += 1) {}
            const ch2 = trimmed_identifier[idx];
            new_text.appendAssumeCapacity(std.ascii.toUpper(ch2));
        } else {
            new_text.appendAssumeCapacity(std.ascii.toLower(ch));
        }

        idx += 1;
    }

    return new_text.toOwnedSlice(allocator);
}

/// returns a discard string `_ = identifier_name; // autofix` with appropriate newlines and
/// indentation so that a discard is on a new line after the `insert_token`.
///
/// `add_block_indentation` is used to add one level of indentation to the discard.
/// `add_suffix_newline` is used to add a trailing newline with indentation.
fn createDiscardText(
    builder: *Builder,
    identifier_name: []const u8,
    insert_token: Ast.TokenIndex,
    add_block_indentation: bool,
    add_suffix_newline: bool,
) !struct {
    /// insert index
    usize,
    /// new text
    []const u8,
} {
    const tree = builder.handle.tree;
    const insert_token_end = offsets.tokenToLoc(tree, insert_token).end;
    const source_until_next_token = tree.source[0..tree.tokenStart(insert_token + 1)];
    // skip comments between the insert tokena and the token after it
    const insert_index = std.mem.indexOfScalarPos(u8, source_until_next_token, insert_token_end, '\n') orelse source_until_next_token.len;

    const indent = find_indent: {
        const line = offsets.lineSliceUntilIndex(tree.source, insert_index);
        for (line, 0..) |char, i| {
            if (!std.ascii.isWhitespace(char)) {
                break :find_indent line[0..i];
            }
        }
        break :find_indent line;
    };
    const additional_indent = if (add_block_indentation) detectIndentation(tree.source) else "";

    const new_text_len =
        "\n".len +
        indent.len +
        additional_indent.len +
        "_ = ".len +
        identifier_name.len +
        "; // autofix".len +
        if (add_suffix_newline) 1 + indent.len else 0;
    var new_text: std.ArrayList(u8) = try .initCapacity(builder.arena, new_text_len);

    new_text.appendAssumeCapacity('\n');
    new_text.appendSliceAssumeCapacity(indent);
    new_text.appendSliceAssumeCapacity(additional_indent);
    new_text.appendSliceAssumeCapacity("_ = ");
    new_text.appendSliceAssumeCapacity(identifier_name);
    new_text.appendSliceAssumeCapacity("; // autofix");
    if (add_suffix_newline) {
        new_text.appendAssumeCapacity('\n');
        new_text.appendSliceAssumeCapacity(indent);
    }

    return .{ insert_index, try new_text.toOwnedSlice(builder.arena) };
}

fn getParamRemovalRange(tree: Ast, param: Ast.full.FnProto.Param) offsets.Loc {
    var loc = ast.paramLoc(tree, param, true);

    var trim_end = false;
    while (loc.start != 0) : (loc.start -= 1) {
        switch (tree.source[loc.start - 1]) {
            ' ', '\n' => continue,
            ',' => {
                loc.start -= 1;
                break;
            },
            '(' => {
                trim_end = true;
                break;
            },
            else => break,
        }
    }

    var found_comma = false;
    while (trim_end and loc.end < tree.source.len) : (loc.end += 1) {
        switch (tree.source[loc.end]) {
            ' ', '\n' => continue,
            ',' => if (!found_comma) {
                found_comma = true;
                continue;
            } else {
                loc.end += 1;
                break;
            },
            ')' => break,
            else => break,
        }
    }

    return loc;
}

const DiagnosticKind = union(enum) {
    unused: IdCat,
    pointless_discard: IdCat,
    omit_discard: DiscardCat,
    non_camelcase_fn,
    undeclared_identifier,
    unreachable_code,
    var_never_mutated,

    const IdCat = enum {
        @"function parameter",
        @"local constant",
        @"local variable",
        @"switch tag capture",
        capture,
    };

    const DiscardCat = enum {
        @"error capture; omit it instead",
        @"error capture",
    };

    fn parse(diagnostic_message: []const u8) ?DiagnosticKind {
        const msg = diagnostic_message;

        if (std.mem.startsWith(u8, msg, "unused ")) {
            return .{
                .unused = parseEnum(IdCat, msg["unused ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "pointless discard of ")) {
            return .{
                .pointless_discard = parseEnum(IdCat, msg["pointless discard of ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "discard of ")) {
            return .{
                .omit_discard = parseEnum(DiscardCat, msg["discard of ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "Functions should be camelCase")) {
            return .non_camelcase_fn;
        } else if (std.mem.startsWith(u8, msg, "use of undeclared identifier")) {
            return .undeclared_identifier;
        } else if (std.mem.eql(u8, msg, "local variable is never mutated")) {
            return .var_never_mutated;
        }
        return null;
    }

    fn parseEnum(comptime T: type, message: []const u8) ?T {
        inline for (std.meta.fields(T)) |field| {
            if (std.mem.startsWith(u8, message, field.name)) {
                // is there a better way to achieve this?
                return @as(T, @enumFromInt(field.value));
            }
        }

        return null;
    }
};

/// takes the location of an identifier which is part of a discard `_ = location_here;`
/// and returns the location from '_' until ';' or null on failure
fn getDiscardLoc(text: []const u8, loc: offsets.Loc) ?offsets.Loc {
    // check of the loc points to a valid identifier
    for (offsets.locToSlice(text, loc)) |c| {
        if (!Analyser.isSymbolChar(c)) return null;
    }

    // check if the identifier is followed by a colon
    const colon_position = found: {
        var i = loc.end;
        while (i < text.len) : (i += 1) {
            switch (text[i]) {
                ' ' => continue,
                ';' => break :found i,
                else => return null,
            }
        }
        return null;
    };

    // check if the colon is followed by the autofix comment
    const autofix_comment_start = std.mem.indexOfNonePos(u8, text, colon_position + ";".len, " ") orelse return null;
    if (!std.mem.startsWith(u8, text[autofix_comment_start..], "//")) return null;
    const autofix_str_start = std.mem.indexOfNonePos(u8, text, autofix_comment_start + "//".len, " ") orelse return null;
    if (!std.mem.startsWith(u8, text[autofix_str_start..], "autofix")) return null;
    const autofix_comment_end = std.mem.indexOfNonePos(u8, text, autofix_str_start + "autofix".len, " ") orelse autofix_str_start + "autofix".len;

    // check if the identifier is precede by a equal sign and then an underscore
    var i: usize = loc.start - 1;
    var found_equal_sign = false;
    const underscore_position = found: {
        while (true) : (i -= 1) {
            if (i == 0) return null;
            switch (text[i]) {
                ' ' => {},
                '=' => {
                    if (found_equal_sign) return null;
                    found_equal_sign = true;
                },
                '_' => if (found_equal_sign) break :found i else return null,
                else => return null,
            }
        }
    };

    // move backwards until we find a newline
    i = underscore_position - 1;
    const start_position = found: {
        while (true) : (i -= 1) {
            if (i == 0) break :found underscore_position;
            switch (text[i]) {
                ' ', '\t' => {},
                '\n' => break :found i,
                else => break :found underscore_position,
            }
        }
    };

    return .{
        .start = start_position,
        .end = autofix_comment_end,
    };
}

/// takes the location of a capture ie `value` from `...|value...|...`.
/// returns the location from '|' until '|'
fn getCaptureLoc(text: []const u8, loc: offsets.Loc) ?offsets.Loc {
    const start_pipe_position = blk: {
        var i = loc.start;
        while (true) : (i -= 1) {
            if (text[i] == '|') break;
            if (i == 0) return null;
        }
        break :blk i;
    };

    const end_pipe_position = (std.mem.indexOfScalarPos(u8, text, start_pipe_position + 1, '|') orelse
        return null) + 1;

    const trimmed = std.mem.trim(u8, text[start_pipe_position + 1 .. end_pipe_position - 1], &std.ascii.whitespace);
    if (trimmed.len == 0) return null;

    return .{ .start = start_pipe_position, .end = end_pipe_position };
}

test getCaptureLoc {
    {
        const text = "|i|";
        const caploc = getCaptureLoc(text, .{ .start = 1, .end = 2 }) orelse
            return std.testing.expect(false);
        const captext = text[caploc.start..caploc.end];
        try std.testing.expectEqualStrings(text, captext);
    }
    {
        const text = "|i, jjj, foobar|";
        const caploc = getCaptureLoc(text, .{ .start = 1, .end = 17 }) orelse
            return std.testing.expect(false);
        const captext = text[caploc.start..caploc.end];
        try std.testing.expectEqualStrings(text, captext);
    }

    try std.testing.expect(getCaptureLoc("||", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc(" |", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc("| ", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc("||", .{ .start = 1, .end = 1 }) == null);
    try std.testing.expect(getCaptureLoc("| |", .{ .start = 1, .end = 3 }) == null);
    try std.testing.expect(getCaptureLoc("|    |", .{ .start = 1, .end = 6 }) == null);
}
