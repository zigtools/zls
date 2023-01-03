const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const tracy = @import("../tracy.zig");

pub const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *const DocumentStore.Handle,
    range: ?types.Range = null,
    actions: std.ArrayListUnmanaged(types.CodeAction) = .{},
    offset_encoding: offsets.Encoding,

    pub fn generateCodeActions(
        builder: *Builder,
        diagnostisc: []const types.Diagnostic,
    ) error{OutOfMemory}!void {
        for (diagnostisc) |diagnostis| {
            try handleDiagnostic(builder, diagnostis);
        }

        try handleSortingImports(builder);
    }

    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit {
        const range = offsets.locToRange(self.handle.text, loc, self.offset_encoding);
        return types.TextEdit{ .range = range, .newText = new_text };
    }

    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit {
        const position = offsets.indexToPosition(self.handle.text, index, self.offset_encoding);
        return types.TextEdit{ .range = .{ .start = position, .end = position }, .newText = new_text };
    }

    pub fn createWorkspaceEdit(self: *Builder, edits: []const types.TextEdit) error{OutOfMemory}!types.WorkspaceEdit {
        var workspace_edit = types.WorkspaceEdit{ .changes = .{} };
        try workspace_edit.changes.?.putNoClobber(self.arena, self.handle.uri, try self.arena.dupe(types.TextEdit, edits));

        return workspace_edit;
    }

    pub fn createCodeAction(self: *Builder, code_action: types.CodeAction) error{OutOfMemory}!void {
        try self.actions.append(self.arena, code_action);
    }
};

pub fn handleDiagnostic(
    builder: *Builder,
    diagnostic: types.Diagnostic,
) error{OutOfMemory}!void {
    const kind = DiagnosticKind.parse(diagnostic.message) orelse return;

    const loc = offsets.rangeToLoc(builder.handle.text, diagnostic.range, builder.offset_encoding);

    switch (kind) {
        .unused => |id| switch (id) {
            .@"function parameter" => try handleUnusedFunctionParameter(builder, loc),
            .@"local constant" => try handleUnusedVariableOrConstant(builder, loc),
            .@"local variable" => try handleUnusedVariableOrConstant(builder, loc),
            .@"loop index capture" => try handleUnusedIndexCapture(builder, loc),
            .capture => try handleUnusedCapture(builder, loc),
        },
        .non_camelcase_fn => try handleNonCamelcaseFunction(builder, loc),
        .pointless_discard => try handlePointlessDiscard(builder, loc),
        .omit_discard => |id| switch (id) {
            .@"index capture" => try handleUnusedIndexCapture(builder, loc),
            .@"error capture" => try handleUnusedCapture(builder, loc),
        },
        // the undeclared identifier may be a discard
        .undeclared_identifier => try handlePointlessDiscard(builder, loc),
        .unreachable_code => {
            // TODO
            // autofix: comment out code
            // fix: remove code
        },
    }
}

fn handleNonCamelcaseFunction(builder: *Builder, loc: offsets.Loc) !void {
    const identifier_name = offsets.locToSlice(builder.handle.text, loc);

    if (std.mem.allEqual(u8, identifier_name, '_')) return;

    const new_text = try createCamelcaseText(builder.arena, identifier_name);

    try builder.createCodeAction(.{
        .title = "make function name camelCase",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, new_text)}),
    });
}

fn handleUnusedFunctionParameter(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const identifier_name = offsets.locToSlice(builder.handle.text, loc);

    const tree = builder.handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const node_tokens = tree.nodes.items(.main_token);

    const token_starts = tree.tokens.items(.start);

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const payload = switch (decl.decl.*) {
        .param_payload => |pay| pay,
        else => return,
    };

    std.debug.assert(node_tags[payload.func] == .fn_decl);

    const block = node_datas[payload.func].rhs;

    const new_text = try createDiscardText(builder, identifier_name, token_starts[node_tokens[payload.func]], true);

    const index = token_starts[node_tokens[block]] + 1;

    try builder.createCodeAction(.{
        .title = "discard function parameter",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
    });

    // TODO fix formatting
    try builder.createCodeAction(.{
        .title = "remove function parameter",
        .kind = .quickfix,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(getParamRemovalRange(tree, payload.param), "")}),
    });
}

fn handleUnusedVariableOrConstant(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const identifier_name = offsets.locToSlice(builder.handle.text, loc);

    const tree = builder.handle.tree;
    const token_tags = tree.tokens.items(.tag);
    const token_starts = tree.tokens.items(.start);

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const node = switch (decl.decl.*) {
        .ast_node => |node| node,
        else => return,
    };

    const first_token = tree.firstToken(node);
    const last_token = ast.lastToken(tree, node) + 1;

    if (token_tags[last_token] != .semicolon) return;

    const new_text = try createDiscardText(builder, identifier_name, token_starts[first_token], false);

    const index = token_starts[last_token] + 1;

    try builder.createCodeAction(.{
        .title = "discard value",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
    });
}

fn handleUnusedIndexCapture(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const capture_locs = getCaptureLoc(builder.handle.text, loc, true) orelse return;

    // TODO support discarding without modifying the capture
    // by adding a discard in the block scope
    const is_value_discarded = std.mem.eql(u8, offsets.locToSlice(builder.handle.text, capture_locs.value), "_");
    if (is_value_discarded) {
        // |_, i| ->
        // TODO fix formatting
        try builder.createCodeAction(.{
            .title = "remove capture",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.loc, "")}),
        });
    } else {
        // |v, i| -> |v|
        // |v, _| -> |v|
        try builder.createCodeAction(.{
            .title = "remove index capture",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(
                .{ .start = capture_locs.value.end, .end = capture_locs.loc.end - 1 },
                "",
            )}),
        });
    }
}

fn handleUnusedCapture(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const capture_locs = getCaptureLoc(builder.handle.text, loc, false) orelse return;

    // TODO support discarding without modifying the capture
    // by adding a discard in the block scope
    if (capture_locs.index != null) {
        // |v, i| -> |_, i|
        try builder.createCodeAction(.{
            .title = "discard capture",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.value, "_")}),
        });
    } else {
        // |v|    ->
        // TODO fix formatting
        try builder.createCodeAction(.{
            .title = "remove capture",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.loc, "")}),
        });
    }
}

fn handlePointlessDiscard(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const edit_loc = getDiscardLoc(builder.handle.text, loc) orelse return;

    try builder.createCodeAction(.{
        .title = "remove pointless discard",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(edit_loc, ""),
        }),
    });
}

fn handleSortingImports(builder: *Builder) !void {
    const tree = builder.handle.tree;
    if (tree.errors.len != 0) return;

    var imports = try getImportsDecls(tree, builder.arena);

    if (std.sort.isSorted(ImportDecl, imports.items, tree, ImportDecl.lessThan)) return;

    const sorted_imports = try builder.arena.dupe(ImportDecl, imports.items);
    std.sort.sort(ImportDecl, sorted_imports, tree, ImportDecl.lessThan);

    var edits = std.ArrayListUnmanaged(types.TextEdit){};

    // remove previous imports
    for (imports.items, 0..) |import_decl, i| {
        // if two imports are next to each other we can extend the previous text edit
        if (i != 0 and import_decl.var_decl - 1 == imports.items[i - 1].var_decl) {
            const new_end = offsets.indexToPosition(tree.source, import_decl.getSourceEndIndex(tree, true), builder.offset_encoding);
            edits.items[edits.items.len - 1].range.end = new_end;
        } else {
            try edits.append(builder.arena, .{
                .range = offsets.locToRange(tree.source, import_decl.getLoc(tree, true), builder.offset_encoding),
                .newText = "",
            });
        }
    }

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

        try edits.append(builder.arena, .{
            .range = .{ .start = .{ .line = 0, .character = 0 }, .end = .{ .line = 0, .character = 0 } },
            .newText = new_text.items,
        });
    }

    var workspace_edit = try builder.createWorkspaceEdit(edits.items);

    try builder.createCodeAction(.{
        .title = "orgnaize @import",
        .kind = .@"source.organizeImports",
        .isPreferred = true,
        .edit = workspace_edit,
    });

    if (builder.range) |range| {
        const edit_range: types.Range = .{
            .start = edits.items[0].range.start,
            .end = edits.items[edits.items.len - 1].range.end,
        };

        const intersects = (edit_range.start.line <= range.start.line and range.start.line <= edit_range.end.line) or
            (edit_range.start.line <= range.end.line and range.end.line <= edit_range.end.line);

        if (intersects) {
            try builder.createCodeAction(.{
                .title = "orgnaize @import",
                .kind = .quickfix,
                .isPreferred = true,
                .edit = workspace_edit,
            });
        }
    }
}

/// const name_slice = @import(value_slice);
pub const ImportDecl = struct {
    var_decl: Ast.Node.Index,
    first_comment_token: ?Ast.TokenIndex,
    name: []const u8,
    value: []const u8,

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
        if (lhs_kind != rhs_kind) return @enumToInt(lhs_kind) < @enumToInt(rhs_kind);

        if (sort_public_decls_first) {
            const node_tokens = context.nodes.items(.main_token);
            const token_tags = context.tokens.items(.tag);

            const is_lhs_pub = node_tokens[lhs.var_decl] > 0 and token_tags[node_tokens[lhs.var_decl] - 1] == .keyword_pub;
            const is_rhs_pub = node_tokens[rhs.var_decl] > 0 and token_tags[node_tokens[rhs.var_decl] - 1] == .keyword_pub;
            if (is_lhs_pub != is_rhs_pub) return is_lhs_pub;
        }

        if (sort_case_sensitive) {
            return std.mem.lessThan(u8, lhs.getSortSlice(), rhs.getSortSlice());
        } else {
            return std.ascii.lessThanIgnoreCase(lhs.getSortSlice(), rhs.getSortSlice());
        }
    }

    pub fn getKind(self: ImportDecl) Kind {
        const name = self.value[1 .. self.value.len - 1];

        if (std.mem.endsWith(u8, name, ".zig")) return .file;

        if (std.mem.eql(u8, name, "std")) return .std;
        if (std.mem.eql(u8, name, "builtin")) return .builtin;
        if (std.mem.eql(u8, name, "build_options")) return .build_options;

        return .package;
    }

    /// returns the string by which this import should be sorted
    pub fn getSortSlice(self: ImportDecl) []const u8 {
        switch (self.getKind()) {
            .file => {
                if (std.mem.indexOfScalar(u8, self.value, '/') != null) {
                    return self.value[1 .. self.value.len - 1];
                }
                return self.name;
            },
            .package => return self.name,
            else => unreachable,
        }
    }

    /// returns true if there should be an empty line between these two imports
    /// assumes `lessThan(void, lhs, rhs) == true`
    pub fn addSeperator(lhs: ImportDecl, rhs: ImportDecl) bool {
        const lhs_kind = @enumToInt(lhs.getKind());
        const rhs_kind = @enumToInt(rhs.getKind());
        if (rhs_kind <= @enumToInt(Kind.build_options)) return false;
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

        var end = offsets.tokenToLoc(tree, last_token).end;
        if (!include_line_break) return end;
        while (end < tree.source.len) {
            switch (tree.source[end]) {
                ' ', '\t', '\n' => end += 1,
                else => break,
            }
        }
        return end;
    }

    /// similar to `offsets.nodeToLoc` but will also include preceding comments and postfix semicolon and line break
    pub fn getLoc(self: ImportDecl, tree: Ast, include_line_break: bool) offsets.Loc {
        return .{
            .start = self.getSourceStartIndex(tree),
            .end = self.getSourceEndIndex(tree, include_line_break),
        };
    }
};

pub fn getImportsDecls(tree: Ast, allocator: std.mem.Allocator) error{OutOfMemory}!std.ArrayListUnmanaged(ImportDecl) {
    var imports = std.ArrayListUnmanaged(ImportDecl){};
    errdefer imports.deinit(allocator);

    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const node_tokens = tree.nodes.items(.main_token);
    for (tree.rootDecls()) |node| {
        // TODO allow this pattern: const name = @import("file.zig").Decl;

        if (node_tags[node] != .simple_var_decl) continue;
        const var_decl = tree.simpleVarDecl(node);

        switch (node_tags[var_decl.ast.init_node]) {
            .builtin_call_two, .builtin_call_two_comma => {},
            else => continue,
        }
        const call_name = offsets.tokenToSlice(tree, node_tokens[var_decl.ast.init_node]);
        if (!std.mem.eql(u8, call_name, "@import")) continue;
        // TODO what about @embedFile ?

        if (node_data[var_decl.ast.init_node].lhs == 0 or node_data[var_decl.ast.init_node].rhs != 0) continue;
        const import_param_node = node_data[var_decl.ast.init_node].lhs;
        if (node_tags[import_param_node] != .string_literal) continue;

        const name_token = var_decl.ast.mut_token + 1;
        const value_token = node_tokens[import_param_node];

        try imports.append(allocator, .{
            .var_decl = node,
            .first_comment_token = Analyser.getDocCommentTokenIndex(tree.tokens.items(.tag), node_tokens[node]),
            .name = offsets.tokenToSlice(tree, name_token),
            .value = offsets.tokenToSlice(tree, value_token),
        });
    }

    return imports;
}

fn detectIndentation(source: []const u8) []const u8 {
    // Essentially I'm looking for the first indentation in the file.
    var i: usize = 0;
    var len = source.len - 1; // I need 1 look-ahead
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

// returns a discard string `\n{indent}_ = identifier_name;`
fn createDiscardText(builder: *Builder, identifier_name: []const u8, declaration_start: usize, add_block_indentation: bool) ![]const u8 {
    const indent = find_indent: {
        const line = offsets.lineSliceUntilIndex(builder.handle.text, declaration_start);
        for (line, 0..) |char, i| {
            if (!std.ascii.isWhitespace(char)) {
                break :find_indent line[0..i];
            }
        }
        break :find_indent line;
    };
    const additional_indent = if (add_block_indentation) detectIndentation(builder.handle.text) else "";

    const new_text_len = 1 + indent.len + additional_indent.len + "_ = ;".len + identifier_name.len;
    var new_text = try std.ArrayListUnmanaged(u8).initCapacity(builder.arena, new_text_len);

    new_text.appendAssumeCapacity('\n');
    new_text.appendSliceAssumeCapacity(indent);
    new_text.appendSliceAssumeCapacity(additional_indent);
    new_text.appendSliceAssumeCapacity("_ = ");
    new_text.appendSliceAssumeCapacity(identifier_name);
    new_text.appendAssumeCapacity(';');

    return new_text.toOwnedSlice(builder.arena);
}

fn getParamRemovalRange(tree: Ast, param: Ast.full.FnProto.Param) offsets.Loc {
    var param_start = offsets.tokenToIndex(tree, ast.paramFirstToken(tree, param));
    var param_end = offsets.tokenToLoc(tree, ast.paramLastToken(tree, param)).end;

    var trim_end = false;
    while (param_start != 0) : (param_start -= 1) {
        switch (tree.source[param_start - 1]) {
            ' ', '\n' => continue,
            ',' => {
                param_start -= 1;
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
    while (trim_end and param_end < tree.source.len) : (param_end += 1) {
        switch (tree.source[param_end]) {
            ' ', '\n' => continue,
            ',' => if (!found_comma) {
                found_comma = true;
                continue;
            } else {
                param_end += 1;
                break;
            },
            ')' => break,
            else => break,
        }
    }

    return .{ .start = param_start, .end = param_end };
}

const DiagnosticKind = union(enum) {
    unused: IdCat,
    pointless_discard: IdCat,
    omit_discard: DiscardCat,
    non_camelcase_fn,
    undeclared_identifier,
    unreachable_code,

    const IdCat = enum {
        @"function parameter",
        @"local constant",
        @"local variable",
        @"loop index capture",
        capture,
    };

    const DiscardCat = enum {
        // "discard of index capture; omit it instead"
        @"index capture",
        // "discard of error capture; omit it instead"
        @"error capture",
    };

    pub fn parse(diagnostic_message: []const u8) ?DiagnosticKind {
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
        }
        return null;
    }

    fn parseEnum(comptime T: type, message: []const u8) ?T {
        inline for (std.meta.fields(T)) |field| {
            if (std.mem.startsWith(u8, message, field.name)) {
                // is there a better way to achieve this?
                return @intToEnum(T, field.value);
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
        if (!isSymbolChar(c)) return null;
    }

    // check if the identifier is followed by a colon
    const colon_position = found: {
        var i = loc.end;
        while (i < text.len) : (i += 1) {
            switch (text[i]) {
                ' ' => continue,
                ';' => break :found i + 1,
                else => return null,
            }
        }
        return null;
    };

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
                ' ' => {},
                '\n' => break :found i,
                else => break :found underscore_position,
            }
        }
    };

    return offsets.Loc{
        .start = start_position,
        .end = colon_position,
    };
}

const CaptureLocs = struct {
    loc: offsets.Loc,
    value: offsets.Loc,
    index: ?offsets.Loc,
};

/// takes the location of an identifier which is part of a payload `|value, index|`
/// and returns the location from '|' until '|' or null on failure
/// use `is_index_payload` to indicate whether `loc` points to `value` or `index`
fn getCaptureLoc(text: []const u8, loc: offsets.Loc, is_index_payload: bool) ?CaptureLocs {
    const value_end = if (!is_index_payload) loc.end else found: {
        // move back until we find a comma
        const comma_position = found_comma: {
            var i = loc.start - 1;
            while (i != 0) : (i -= 1) {
                switch (text[i]) {
                    ' ' => continue,
                    ',' => break :found_comma i,
                    else => return null,
                }
            } else return null;
        };

        // trim space
        var i = comma_position - 1;
        while (i != 0) : (i -= 1) {
            switch (text[i]) {
                ' ' => continue,
                else => {
                    if (!isSymbolChar(text[i])) return null;
                    break :found i + 1;
                },
            }
        } else return null;
    };

    const value_start = if (!is_index_payload) loc.start else found: {
        // move back until we find a non identifier character
        var i = value_end - 1;
        while (i != 0) : (i -= 1) {
            if (isSymbolChar(text[i])) continue;
            switch (text[i]) {
                ' ', '|', '*' => break :found i + 1,
                else => return null,
            }
        } else return null;
    };

    var index: ?offsets.Loc = null;

    if (is_index_payload) {
        index = loc;
    } else blk: {
        // move forward until we find a comma
        const comma_position = found_comma: {
            var i = value_end;
            while (i < text.len) : (i += 1) {
                switch (text[i]) {
                    ' ' => continue,
                    ',' => break :found_comma i,
                    else => break :blk,
                }
            }
            break :blk;
        };

        // trim space
        const index_start = found_start: {
            var i = comma_position + 1;
            while (i < text.len) : (i += 1) {
                switch (text[i]) {
                    ' ' => continue,
                    else => {
                        if (!isSymbolChar(text[i])) break :blk;
                        break :found_start i;
                    },
                }
            }
            break :blk;
        };

        // move forward until we find a non identifier character
        var i = index_start + 1;
        while (i < text.len) : (i += 1) {
            if (isSymbolChar(text[i])) continue;
            index = offsets.Loc{
                .start = index_start,
                .end = i,
            };
            break;
        }
    }

    const start_pipe_position = found: {
        var i = value_start - 1;
        while (i != 0) : (i -= 1) {
            switch (text[i]) {
                ' ' => continue,
                '|' => break :found i,
                else => return null,
            }
        } else return null;
    };

    const end_pipe_position = found: {
        var i: usize = if (index) |index_loc| index_loc.end else value_end;
        while (i < text.len) : (i += 1) {
            switch (text[i]) {
                ' ' => continue,
                '|' => break :found i + 1,
                else => return null,
            }
        } else return null;
    };

    return CaptureLocs{
        .loc = .{ .start = start_pipe_position, .end = end_pipe_position },
        .value = .{ .start = value_start, .end = value_end },
        .index = index,
    };
}

fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_';
}
