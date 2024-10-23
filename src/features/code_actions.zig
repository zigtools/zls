//! Implementation of [`textDocument/codeAction`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_codeAction)

const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("../DocumentStore.zig");
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

    pub fn generateCodeAction(
        builder: *Builder,
        diagnostic: types.Diagnostic,
        actions: *std.ArrayListUnmanaged(types.CodeAction),
        remove_capture_actions: *std.AutoHashMapUnmanaged(types.Range, void),
    ) error{OutOfMemory}!void {
        const kind = DiagnosticKind.parse(diagnostic.message) orelse return;

        const loc = offsets.rangeToLoc(builder.handle.tree.source, diagnostic.range, builder.offset_encoding);

        switch (kind) {
            .unused => |id| switch (id) {
                .@"function parameter" => try handleUnusedFunctionParameter(builder, actions, loc),
                .@"local constant" => try handleUnusedVariableOrConstant(builder, actions, loc),
                .@"local variable" => try handleUnusedVariableOrConstant(builder, actions, loc),
                .@"switch tag capture", .capture => try handleUnusedCapture(builder, actions, loc, remove_capture_actions),
            },
            .non_camelcase_fn => try handleNonCamelcaseFunction(builder, actions, loc),
            .pointless_discard => try handlePointlessDiscard(builder, actions, loc),
            .omit_discard => |id| switch (id) {
                .@"error capture; omit it instead" => {},
                .@"error capture" => try handleUnusedCapture(builder, actions, loc, remove_capture_actions),
            },
            // the undeclared identifier may be a discard
            .undeclared_identifier => try handlePointlessDiscard(builder, actions, loc),
            .unreachable_code => {
                // TODO
                // autofix: comment out code
                // fix: remove code
            },
            .var_never_mutated => try handleVariableNeverMutated(builder, actions, loc),
        }
    }

    pub fn generateOrganizeImportsAction(
        builder: *Builder,
        actions: *std.ArrayListUnmanaged(types.CodeAction),
    ) error{OutOfMemory}!void {
        try handleUnorganizedImport(builder, actions);
    }

    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit {
        const range = offsets.locToRange(self.handle.tree.source, loc, self.offset_encoding);
        return types.TextEdit{ .range = range, .newText = new_text };
    }

    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit {
        const position = offsets.indexToPosition(self.handle.tree.source, index, self.offset_encoding);
        return types.TextEdit{ .range = .{ .start = position, .end = position }, .newText = new_text };
    }

    pub fn createWorkspaceEdit(self: *Builder, edits: []const types.TextEdit) error{OutOfMemory}!types.WorkspaceEdit {
        var workspace_edit = types.WorkspaceEdit{ .changes = .{} };
        try workspace_edit.changes.?.map.putNoClobber(self.arena, self.handle.uri, try self.arena.dupe(types.TextEdit, edits));

        return workspace_edit;
    }
};

/// To report server capabilities
pub const supported_code_actions: []const types.CodeActionKind = &.{
    .quickfix,
    .refactor,
    .source,
    .@"source.organizeImports",
    .@"source.fixAll",
};

pub fn collectAutoDiscardDiagnostics(
    tree: Ast,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const token_tags = tree.tokens.items(.tag);
    const token_starts = tree.tokens.items(.start);

    // search for the following pattern:
    // _ = some_identifier; // autofix

    var i: usize = 0;
    while (i < tree.tokens.len) {
        const first_token: Ast.TokenIndex = @intCast(std.mem.indexOfPos(
            std.zig.Token.Tag,
            token_tags,
            i,
            &.{ .identifier, .equal, .identifier, .semicolon },
        ) orelse break);
        defer i = first_token + 4;

        const underscore_token = first_token;
        const identifier_token = first_token + 2;
        const semicolon_token = first_token + 3;

        if (!std.mem.eql(u8, offsets.tokenToSlice(tree, underscore_token), "_")) continue;

        const autofix_comment_start = std.mem.indexOfNonePos(u8, tree.source, token_starts[semicolon_token] + 1, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_comment_start..], "//")) continue;
        const autofix_str_start = std.mem.indexOfNonePos(u8, tree.source, autofix_comment_start + "//".len, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_str_start..], "autofix")) continue;

        try diagnostics.append(arena, .{
            .range = offsets.tokenToRange(tree, identifier_token, offset_encoding),
            .severity = .Information,
            .code = null,
            .source = "zls",
            .message = "auto discard for unused variable",
            // TODO add a relatedInformation that shows where the discarded identifier comes from
        });
    }
}

fn handleNonCamelcaseFunction(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    if (std.mem.allEqual(u8, identifier_name, '_')) return;

    const new_text = try createCamelcaseText(builder.arena, identifier_name);

    const action1 = types.CodeAction{
        .title = "make function name camelCase",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, new_text)}),
    };

    try actions.append(builder.arena, action1);
}

fn handleUnusedFunctionParameter(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const node_tokens = tree.nodes.items(.main_token);

    const token_tags = tree.tokens.items(.tag);

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const payload = switch (decl.decl) {
        .function_parameter => |pay| pay,
        else => return,
    };

    std.debug.assert(node_tags[payload.func] == .fn_decl);

    const block = node_datas[payload.func].rhs;

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
    const found_comma = potential_comma_token < tree.tokens.len and token_tags[potential_comma_token] == .comma;

    const potential_r_paren_token = potential_comma_token + @intFromBool(found_comma);
    const is_last_param = potential_r_paren_token < tree.tokens.len and token_tags[potential_r_paren_token] == .r_paren;

    const insert_token = node_tokens[block];
    const add_suffix_newline = is_last_param and token_tags[insert_token + 1] == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);
    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);

    const action1 = types.CodeAction{
        .title = "discard function parameter",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(insert_index, new_text)}),
    };

    // TODO fix formatting
    const action2 = types.CodeAction{
        .title = "remove function parameter",
        .kind = .quickfix,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(getParamRemovalRange(tree, fn_proto_param), "")}),
    };

    try actions.insertSlice(builder.arena, 0, &.{ action1, action2 });
}

fn handleUnusedVariableOrConstant(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;
    const token_tags = tree.tokens.items(.tag);

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
    if (token_tags[insert_token] != .semicolon) return;

    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, false, false);

    try actions.append(builder.arena, .{
        .title = "discard value",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(insert_index, new_text)}),
    });
}

fn handleUnusedCapture(
    builder: *Builder,
    actions: *std.ArrayListUnmanaged(types.CodeAction),
    loc: offsets.Loc,
    remove_capture_actions: *std.AutoHashMapUnmanaged(types.Range, void),
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const tree = builder.handle.tree;
    const token_tags = tree.tokens.items(.tag);

    const source = tree.source;
    const capture_loc = getCaptureLoc(source, loc) orelse return;

    const identifier_token = offsets.sourceIndexToTokenIndex(tree, loc.start);
    if (token_tags[identifier_token] != .identifier) return;

    const identifier_name = offsets.locToSlice(source, loc);

    const capture_end: Ast.TokenIndex = @intCast(std.mem.indexOfScalarPos(std.zig.Token.Tag, token_tags, identifier_token, .pipe) orelse return);

    var lbrace_token = capture_end + 1;

    // handle while loop continue statements such as `while(foo) |bar| : (x += 1) {}`
    if (token_tags[capture_end + 1] == .colon) {
        var token_index = capture_end + 2;
        if (token_index >= token_tags.len) return;
        if (token_tags[token_index] != .l_paren) return;
        token_index += 1;

        var depth: u32 = 1;
        while (true) : (token_index += 1) {
            const tag = token_tags[token_index];
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
    if (token_tags[lbrace_token] != .l_brace) return;

    const is_last_capture = token_tags[identifier_token + 1] == .pipe;

    const insert_token = lbrace_token;
    // if we are on the last capture of the block, we need to add an additional newline
    // i.e |a, b| { ... } -> |a, b| { ... \n_ = a; \n_ = b;\n }
    const add_suffix_newline = is_last_capture and token_tags[insert_token + 1] == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);

    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);
    const action1 = .{
        .title = "discard capture",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(insert_index, new_text)}),
    };
    const action2 = .{
        .title = "discard capture name",
        .kind = .quickfix,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, "_")}),
    };

    // prevent adding duplicate 'remove capture' action.
    // search for a matching action by comparing ranges.
    const remove_cap_loc = builder.createTextEditLoc(capture_loc, "");
    const gop = try remove_capture_actions.getOrPut(builder.arena, remove_cap_loc.range);
    if (gop.found_existing)
        try actions.insertSlice(builder.arena, 0, &.{ action1, action2 })
    else {
        const action0 = types.CodeAction{
            .title = "remove capture",
            .kind = .quickfix,
            .isPreferred = false,
            .edit = try builder.createWorkspaceEdit(&.{remove_cap_loc}),
        };
        try actions.insertSlice(builder.arena, 0, &.{ action0, action1, action2 });
    }
}

fn handlePointlessDiscard(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const edit_loc = getDiscardLoc(builder.handle.tree.source, loc) orelse return;

    try actions.append(builder.arena, .{
        .title = "remove pointless discard",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(edit_loc, ""),
        }),
    });
}

fn handleVariableNeverMutated(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const source = builder.handle.tree.source;

    const var_keyword_end = 1 + (std.mem.lastIndexOfNone(u8, source[0..loc.start], &std.ascii.whitespace) orelse return);

    const var_keyword_loc: offsets.Loc = .{
        .start = var_keyword_end -| "var".len,
        .end = var_keyword_end,
    };

    if (!std.mem.eql(u8, offsets.locToSlice(source, var_keyword_loc), "var")) return;

    try actions.append(builder.arena, .{
        .title = "use 'const'",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(var_keyword_loc, "const"),
        }),
    });
}

fn handleUnorganizedImport(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction)) !void {
    const tree = builder.handle.tree;
    if (tree.errors.len != 0) return;

    const imports = try getImportsDecls(builder, builder.arena);

    // The optimization is disabled because it does not detect the case where imports and other decls are mixed
    // if (std.sort.isSorted(ImportDecl, imports.items, tree, ImportDecl.lessThan)) return;

    const sorted_imports = try builder.arena.dupe(ImportDecl, imports.items);
    std.mem.sort(ImportDecl, sorted_imports, tree, ImportDecl.lessThan);

    var edits = std.ArrayListUnmanaged(types.TextEdit){};

    // add sorted imports
    {
        var new_text = std.ArrayListUnmanaged(u8){};
        var writer = new_text.writer(builder.arena);

        for (sorted_imports, 0..) |import_decl, i| {
            if (i != 0 and ImportDecl.addSeperator(sorted_imports[i - 1], import_decl)) {
                try new_text.append(builder.arena, '\n');
            }

            try writer.print("{s}\n", .{offsets.locToSlice(tree.source, import_decl.getLoc(tree, false))});
        }
        try writer.writeByte('\n');

        const tokens = tree.tokens.items(.tag);
        const first_token = std.mem.indexOfNone(std.zig.Token.Tag, tokens, &.{.container_doc_comment}) orelse tokens.len;
        const insert_pos = offsets.tokenToPosition(tree, @intCast(first_token), builder.offset_encoding);

        try edits.append(builder.arena, .{
            .range = .{ .start = insert_pos, .end = insert_pos },
            .newText = new_text.items,
        });
    }

    // remove previous imports
    // The order is unintuitive, but citing spec:
    // "it is possible that multiple edits have the same start position: multiple inserts, or any number of inserts followed by a single remove or replace edit."
    for (imports.items) |import_decl| {
        // if two imports are next to each other we can extend the previous text edit
        try edits.append(builder.arena, .{
            .range = offsets.locToRange(tree.source, import_decl.getLoc(tree, true), builder.offset_encoding),
            .newText = "",
        });
    }

    const workspace_edit = try builder.createWorkspaceEdit(edits.items);

    try actions.append(builder.arena, .{
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
            const token_tags = context.tokens.items(.tag);

            const is_lhs_pub = node_tokens[lhs.var_decl] > 0 and token_tags[node_tokens[lhs.var_decl] - 1] == .keyword_pub;
            const is_rhs_pub = node_tokens[rhs.var_decl] > 0 and token_tags[node_tokens[rhs.var_decl] - 1] == .keyword_pub;
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
        if (self.parent_name == null or child.parent_name == null) return false;
        return std.mem.eql(u8, self.name, child.parent_name.?) and std.mem.eql(u8, self.value, child.parent_value.?);
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
                    return self.value[1 .. self.getSortValue().len - 1];
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
        return offsets.tokenToIndex(tree, self.first_comment_token orelse tree.firstToken(self.var_decl));
    }

    pub fn getSourceEndIndex(self: ImportDecl, tree: Ast, include_line_break: bool) usize {
        const token_tags = tree.tokens.items(.tag);

        var last_token = ast.lastToken(tree, self.var_decl);
        if (last_token + 1 < tree.tokens.len - 1 and token_tags[last_token + 1] == .semicolon) {
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

pub fn getImportsDecls(builder: *Builder, allocator: std.mem.Allocator) error{OutOfMemory}!std.ArrayListUnmanaged(ImportDecl) {
    const tree = builder.handle.tree;
    var imports = std.ArrayListUnmanaged(ImportDecl){};
    errdefer imports.deinit(allocator);

    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const node_tokens = tree.nodes.items(.main_token);

    // iterate until no more imports are found
    var updated = true;
    while (updated) {
        updated = false;
        next_decl: for (tree.rootDecls()) |node| {
            if (node_tags[node] != .simple_var_decl) continue;

            // check if we already have this import
            for (imports.items) |import_decl| {
                if (import_decl.var_decl == node) continue :next_decl;
            }
            const var_decl = tree.simpleVarDecl(node);
            const base_token = var_decl.ast.init_node;

            var inode = base_token;
            const import: ImportDecl = found_decl: while (true) {
                const token = node_tokens[inode];
                switch (node_tags[inode]) {
                    .builtin_call_two, .builtin_call_two_comma => {
                        // @import("string") case
                        const init_node = inode;
                        const call_name = offsets.tokenToSlice(tree, token);
                        if (!std.mem.eql(u8, call_name, "@import")) continue :next_decl;
                        // TODO what about @embedFile ?

                        if (node_data[init_node].lhs == 0 or node_data[init_node].rhs != 0) continue :next_decl;
                        const import_param_node = node_data[init_node].lhs;
                        if (node_tags[import_param_node] != .string_literal) continue :next_decl;

                        const name_token = var_decl.ast.mut_token + 1;
                        const value_token = node_tokens[import_param_node];

                        break :found_decl .{
                            .var_decl = node,
                            .first_comment_token = Analyser.getDocCommentTokenIndex(tree.tokens.items(.tag), node_tokens[node]),
                            .name = offsets.tokenToSlice(tree, name_token),
                            .value = offsets.tokenToSlice(tree, value_token),
                        };
                    },
                    .field_access => {
                        // `@import("foo").bar` or `foo.bar` case
                        // drill down to the base import
                        inode = node_data[inode].lhs;
                        continue;
                    },
                    .identifier => {
                        // `std.ascii` case - Might be an import
                        const slice = offsets.tokenToSlice(tree, token);
                        const idx = offsets.tokenToIndex(tree, token);
                        const symbolDecl = try builder.analyser.lookupSymbolGlobal(builder.handle, slice, idx) orelse continue :next_decl;
                        const declIdx = symbolDecl.decl.ast_node;
                        // if the decl is in known imports, add this one as well
                        for (imports.items) |import_decl| {
                            if (import_decl.var_decl == declIdx) {
                                break :found_decl .{
                                    .var_decl = node,
                                    .first_comment_token = Analyser.getDocCommentTokenIndex(tree.tokens.items(.tag), node_tokens[node]),
                                    .name = slice,
                                    .value = slice,
                                    .parent_name = import_decl.getSortName(),
                                    .parent_value = import_decl.getSortValue(),
                                };
                            }
                        }
                        continue :next_decl;
                    },
                    else => continue :next_decl,
                }
            };
            try imports.append(allocator, import);
            updated = true;
        }
    }

    return imports;
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
    return " " ** 4; // recommended style
}

// attempts to converts a slice of text into camelcase 'FUNCTION_NAME' -> 'functionName'
fn createCamelcaseText(allocator: std.mem.Allocator, identifier: []const u8) ![]const u8 {
    // skip initial & ending underscores
    const trimmed_identifier = std.mem.trim(u8, identifier, "_");

    const num_separators = std.mem.count(u8, trimmed_identifier, "_");

    const new_text_len = trimmed_identifier.len - num_separators;
    var new_text = try std.ArrayListUnmanaged(u8).initCapacity(allocator, new_text_len);
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
    const source_until_next_token = tree.source[0..tree.tokens.items(.start)[insert_token + 1]];
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
    var new_text = try std.ArrayListUnmanaged(u8).initCapacity(builder.arena, new_text_len);

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
            return DiagnosticKind{
                .unused = parseEnum(IdCat, msg["unused ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "pointless discard of ")) {
            return DiagnosticKind{
                .pointless_discard = parseEnum(IdCat, msg["pointless discard of ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "discard of ")) {
            return DiagnosticKind{
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

    return offsets.Loc{
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
