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
    const action1: types.CodeAction = .{
        .title = "discard capture",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(insert_index, new_text)}),
    };
    const action2: types.CodeAction = .{
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
