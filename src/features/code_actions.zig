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

    const token_starts = tree.tokens.items(.start);

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const payload = switch (decl.decl) {
        .param_payload => |pay| pay,
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
    const param_end = offsets.tokenToLoc(tree, ast.paramLastToken(tree, fn_proto_param)).end;

    const found_comma = std.mem.startsWith(
        u8,
        std.mem.trimLeft(u8, tree.source[param_end..], " \n"),
        ",",
    );

    const new_text = try createDiscardText(builder, identifier_name, token_starts[node_tokens[payload.func]], true, !found_comma);

    const index = token_starts[node_tokens[block]] + 1;

    const action1 = types.CodeAction{
        .title = "discard function parameter",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
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
    const token_starts = tree.tokens.items(.start);

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

    const first_token = tree.firstToken(node);
    const last_token = ast.lastToken(tree, node) + 1;

    if (last_token >= tree.tokens.len) return;
    if (token_tags[last_token] != .semicolon) return;

    const new_text = try createDiscardText(builder, identifier_name, token_starts[first_token], false, false);
    const index = token_starts[last_token] + 1;

    try actions.append(builder.arena, .{
        .title = "discard value",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
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

    const source = builder.handle.tree.source;
    const capture_loc = getCaptureLoc(source, loc) orelse return;

    // look for next non-whitespace after last '|'. if its a '{' we can insert discards.
    // this means bare loop/switch captures (w/out curlies) aren't supported.
    var block_start = capture_loc.end + 1;
    var is_comment = false;
    while (block_start < source.len) : (block_start += 1) {
        switch (source[block_start]) {
            '/' => if (block_start + 1 < source.len and source[block_start + 1] == '/') {
                is_comment = true;
                // we already know the next character is a `/` so lets skip that iteration
                block_start += 1;
            },
            // if we go to a new line, drop the is_comment boolean
            '\n' => if (is_comment) {
                is_comment = false;
            },
            //If the character is not a whitespace, and we're not in a comment then break out of the loop
            else => |c| if (!std.ascii.isWhitespace(c) and !is_comment) break,
        }
    }
    if (source[block_start] != '{') {
        return;
    }

    const block_start_loc = offsets.Loc{ .start = block_start + 1, .end = block_start + 1 };
    const identifier_name = source[loc.start..loc.end];

    var capture_end = loc.end;
    var is_last: bool = false;
    while (capture_end < source.len) : (capture_end += 1) {
        switch (source[capture_end]) {
            ' ', '\n' => continue,
            '|' => {
                is_last = true;
                break;
            },
            else => break,
        }
    }
    // if we are on the last capture of the block, we need to add an additional newline
    // i.e |a, b| { ... } -> |a, b| { ... \n_ = a; \n_ = b;\n }
    const new_text = try createDiscardText(builder, identifier_name, block_start, true, is_last);
    const action1 = .{
        .title = "discard capture",
        .kind = .@"source.fixAll",
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(block_start_loc, new_text)}),
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
        .kind = .@"source.fixAll",
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

// returns a discard string `\n{indent}_ = identifier_name;`
fn createDiscardText(
    builder: *Builder,
    identifier_name: []const u8,
    declaration_start: usize,
    add_block_indentation: bool,
    add_suffix_newline: bool,
) ![]const u8 {
    const indent = find_indent: {
        const line = offsets.lineSliceUntilIndex(builder.handle.tree.source, declaration_start);
        for (line, 0..) |char, i| {
            if (!std.ascii.isWhitespace(char)) {
                break :find_indent line[0..i];
            }
        }
        break :find_indent line;
    };
    const additional_indent = if (add_block_indentation) detectIndentation(builder.handle.tree.source) else "";

    const new_text_len =
        1 +
        indent.len +
        additional_indent.len +
        "_ = ;".len +
        identifier_name.len +
        if (add_suffix_newline) 1 + indent.len else 0;
    var new_text = try std.ArrayListUnmanaged(u8).initCapacity(builder.arena, new_text_len);

    new_text.appendAssumeCapacity('\n');
    new_text.appendSliceAssumeCapacity(indent);
    new_text.appendSliceAssumeCapacity(additional_indent);
    new_text.appendSliceAssumeCapacity("_ = ");
    new_text.appendSliceAssumeCapacity(identifier_name);
    new_text.appendAssumeCapacity(';');
    if (add_suffix_newline) {
        new_text.appendAssumeCapacity('\n');
        new_text.appendSliceAssumeCapacity(indent);
    }

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
    var_never_mutated,

    const IdCat = enum {
        @"function parameter",
        @"local constant",
        @"local variable",
        @"switch tag capture",
        capture,
    };

    const DiscardCat = enum {
        // "discard of error capture; omit it instead"
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

test "getCaptureLoc" {
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

fn isSymbolChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_';
}
