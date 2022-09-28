const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("DocumentStore.zig");
const analysis = @import("analysis.zig");
const ast = @import("ast.zig");

const types = @import("types.zig");
const requests = @import("requests.zig");
const offsets = @import("offsets.zig");

pub const Builder = struct {
    arena: *std.heap.ArenaAllocator,
    document_store: *DocumentStore,
    handle: *DocumentStore.Handle,
    offset_encoding: offsets.Encoding,

    pub fn generateCodeAction(
        builder: *Builder,
        diagnostic: types.Diagnostic,
        actions: *std.ArrayListUnmanaged(types.CodeAction),
    ) error{OutOfMemory}!void {
        const kind = DiagnosticKind.parse(diagnostic.message) orelse return;

        const loc = offsets.rangeToLoc(builder.text(), diagnostic.range, builder.offset_encoding);

        switch (kind) {
            .unused => |id| switch (id) {
                .@"function parameter" => try handleUnusedFunctionParameter(builder, actions, loc),
                .@"local constant" => try handleUnusedVariableOrConstant(builder, actions, loc),
                .@"local variable" => try handleUnusedVariableOrConstant(builder, actions, loc),
                .@"loop index capture" => try handleUnusedIndexCapture(builder, actions, loc),
                .@"capture" => try handleUnusedCapture(builder, actions, loc),
            },
            .non_camelcase_fn => try handleNonCamelcaseFunction(builder, actions, loc),
            .pointless_discard => try handlePointlessDiscard(builder, actions, loc),
            .omit_discard => |id| switch (id) {
                .@"index capture" => try handleUnusedIndexCapture(builder, actions, loc),
                .@"error capture" => try handleUnusedCapture(builder, actions, loc),
            },
            // the undeclared identifier may be a discard
            .undeclared_identifier => try handlePointlessDiscard(builder, actions, loc),
            .unreachable_code => {
                // TODO
                // autofix: comment out code
                // fix: remove code
            },
        }
    }

    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit {
        const range = offsets.locToRange(self.text(), loc, self.offset_encoding);
        return types.TextEdit{ .range = range, .newText = new_text };
    }

    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit {
        const position = offsets.indexToPosition(self.text(), index, self.offset_encoding);
        return types.TextEdit{ .range = .{ .start = position, .end = position }, .newText = new_text };
    }

    pub fn createWorkspaceEdit(self: *Builder, edits: []const types.TextEdit) error{OutOfMemory}!types.WorkspaceEdit {
        var text_edits = std.ArrayListUnmanaged(types.TextEdit){};
        try text_edits.appendSlice(self.arena.allocator(), edits);

        var workspace_edit = types.WorkspaceEdit{ .changes = .{} };
        try workspace_edit.changes.putNoClobber(self.arena.allocator(), self.handle.uri(), text_edits);

        return workspace_edit;
    }

    fn text(self: *Builder) []const u8 {
        return self.handle.document.text;
    }
};

fn handleNonCamelcaseFunction(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const identifier_name = offsets.locToSlice(builder.text(), loc);

    if (std.mem.allEqual(u8, identifier_name, '_')) return;

    const new_text = try createCamelcaseText(builder.arena.allocator(), identifier_name);

    const action1 = types.CodeAction{
        .title = "make function name camelCase",
        .kind = .QuickFix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, new_text)}),
    };

    try actions.append(builder.arena.allocator(), action1);
}

fn handleUnusedFunctionParameter(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const identifier_name = offsets.locToSlice(builder.text(), loc);

    const tree = builder.handle.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const node_tokens = tree.nodes.items(.main_token);

    const token_starts = tree.tokens.items(.start);

    const decl = (try analysis.lookupSymbolGlobal(
        builder.document_store,
        builder.arena,
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

    const indent = offsets.lineSliceUntilIndex(builder.text(), token_starts[node_tokens[payload.func]]).len;
    const new_text = try createDiscardText(builder.arena.allocator(), identifier_name, indent + 4);

    const index = token_starts[node_tokens[block]] + 1;

    const action1 = types.CodeAction{
        .title = "discard function parameter",
        .kind = .SourceFixAll,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
    };

    // TODO fix formatting
    const action2 = types.CodeAction{
        .title = "remove function parameter",
        .kind = .QuickFix,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(getParamRemovalRange(tree, payload.param), "")}),
    };

    try actions.appendSlice(builder.arena.allocator(), &.{ action1, action2 });
}

fn handleUnusedVariableOrConstant(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const identifier_name = offsets.locToSlice(builder.text(), loc);

    const tree = builder.handle.tree;
    const token_tags = tree.tokens.items(.tag);
    const token_starts = tree.tokens.items(.start);

    const decl = (try analysis.lookupSymbolGlobal(
        builder.document_store,
        builder.arena,
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

    const indent = offsets.lineSliceUntilIndex(builder.text(), token_starts[first_token]).len;

    if (token_tags[last_token] != .semicolon) return;

    const new_text = try createDiscardText(builder.arena.allocator(), identifier_name, indent);

    const index = token_starts[last_token] + 1;

    try actions.append(builder.arena.allocator(), .{
        .title = "discard value",
        .kind = .QuickFix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditPos(index, new_text)}),
    });
}

fn handleUnusedIndexCapture(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const capture_locs = getCaptureLoc(builder.text(), loc, true) orelse return;

    // TODO support discarding without modifying the capture
    // by adding a discard in the block scope
    const is_value_discarded = std.mem.eql(u8, offsets.locToSlice(builder.text(), capture_locs.value), "_");
    if (is_value_discarded) {
        // |_, i| ->
        // TODO fix formatting
        try actions.append(builder.arena.allocator(), .{
            .title = "remove capture",
            .kind = .QuickFix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.loc, "")}),
        });
    } else {
        // |v, i| -> |v|
        // |v, _| -> |v|
        try actions.append(builder.arena.allocator(), .{
            .title = "remove index capture",
            .kind = .QuickFix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(
                .{ .start = capture_locs.value.end, .end = capture_locs.loc.end - 1 },
                "",
            )}),
        });
    }
}

fn handleUnusedCapture(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const capture_locs = getCaptureLoc(builder.text(), loc, false) orelse return;

    // TODO support discarding without modifying the capture
    // by adding a discard in the block scope
    if (capture_locs.index != null) {
        // |v, i| -> |_, i|
        try actions.append(builder.arena.allocator(), .{
            .title = "discard capture",
            .kind = .QuickFix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.value, "_")}),
        });
    } else {
        // |v|    ->
        // TODO fix formatting
        try actions.append(builder.arena.allocator(), .{
            .title = "remove capture",
            .kind = .QuickFix,
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(capture_locs.loc, "")}),
        });
    }
}

fn handlePointlessDiscard(builder: *Builder, actions: *std.ArrayListUnmanaged(types.CodeAction), loc: offsets.Loc) !void {
    const edit_loc = getDiscardLoc(builder.text(), loc) orelse return;

    try actions.append(builder.arena.allocator(), .{
        .title = "remove pointless discard",
        .kind = .SourceFixAll,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(edit_loc, ""),
        }),
    });
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
fn createDiscardText(allocator: std.mem.Allocator, identifier_name: []const u8, indent: usize) ![]const u8 {
    const new_text_len = 1 + indent + "_ = ;".len + identifier_name.len;
    var new_text = try std.ArrayListUnmanaged(u8).initCapacity(allocator, new_text_len);
    errdefer new_text.deinit(allocator);

    new_text.appendAssumeCapacity('\n');
    new_text.appendNTimesAssumeCapacity(' ', indent);
    new_text.appendSliceAssumeCapacity("_ = ");
    new_text.appendSliceAssumeCapacity(identifier_name);
    new_text.appendAssumeCapacity(';');

    return new_text.toOwnedSlice(allocator);
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
        @"capture",
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

    // check if the identifier is preceed by a equal sign and then an underscore
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
    return std.ascii.isAlNum(char) or char == '_';
}
