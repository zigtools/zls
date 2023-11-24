const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "definition - smoke" {
    try testDefinition(
        \\fn main() void { f<>oo(); }
        \\fn <def>foo</def>() void {}
    );
}

test "definition - cursor is at the end of an identifier" {
    try testDefinition(
        \\fn main() void { foo<>(); }
        \\fn <def>foo</def>() void {}
    );
}

test "definition - cursor is at the start of an identifier" {
    try testDefinition(
        \\fn main() void { <>foo(); }
        \\fn <def>foo</def>() void {}
    );
}

test "definition - multiline builder pattern" {
    try testDefinition(
        \\const Foo = struct {
        \\    fn add(foo: Foo) Foo {}
        \\    fn remove(foo: Foo) Foo {}
        \\    fn process(foo: Foo) Foo {}
        \\    fn <def>finalize</def>(_: Foo) void {}
        \\};
        \\test {
        \\    var builder = Foo{};
        \\    builder
        \\        .add()
        \\        .remove()
        \\        .process()
        \\        // Comments should
        \\        // get ignored
        \\        .finalize<>();
        \\}
    );
}

/// - use `<>` to indicate the cursor position
/// - use `<decl>content</decl>` to set the expected range of the declaration
/// - use `<def>content</def>` to set the expected range of the definition
/// - use `<tdef>content</tdef>` to set the expected range of the type definition
///
/// If a declaration, definition or type definition is not set, it default to checking for no response from the Server
fn testDefinition(source: []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    const test_uri = try ctx.addDocument(phr.new_source);

    var error_builder = ErrorBuilder.init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(test_uri, phr.new_source);
    try error_builder.addFile("old_source", source);
    try error_builder.addFile("new_source", phr.new_source);

    const cursor_index: usize = blk: {
        var cursor_index: ?usize = null;
        var cursor_old_loc: ?offsets.Loc = null;
        for (phr.locations.items(.old), phr.locations.items(.new)) |old_loc, new_loc| {
            const str = offsets.locToSlice(source, old_loc);
            if (!std.mem.eql(u8, str, "<>")) continue;
            if (cursor_old_loc) |previous_loc| {
                try error_builder.msgAtLoc("duplicate cursor position", "old_source", old_loc, .err, .{});
                try error_builder.msgAtLoc("previously declared here", "old_source", previous_loc, .err, .{});
                return error.DuplicateCursorPosition;
            } else {
                std.debug.assert(new_loc.start == new_loc.end);
                cursor_index = new_loc.start;
                cursor_old_loc = old_loc;
            }
        }
        break :blk cursor_index orelse {
            std.debug.print("must specify cursor position with `<>`\n", .{});
            return error.ExpectedCursorPosition;
        };
    };

    for (phr.locations.items(.old)) |loc| {
        const str = offsets.locToSlice(source, loc); // e.g. '</decl>'
        const tag_content = str[1 .. str.len - 1]; // e.g. '/decl'
        const is_end = std.mem.startsWith(u8, tag_content, "/");
        const tag_name = tag_content[@intFromBool(is_end)..]; // e.g. 'decl'

        if (std.mem.eql(u8, tag_name, "")) continue; // cursor index
        if (std.mem.eql(u8, tag_name, "decl")) continue;
        if (std.mem.eql(u8, tag_name, "def")) continue;
        if (std.mem.eql(u8, tag_name, "tdef")) continue;
        std.debug.print("unknown placeholder '{s}'\n", .{str});
        return error.UnknownPlaceholder;
    }

    const declaration_loc: ?offsets.Loc = try parseTaggedLoc(source, phr, "decl");
    const definition_loc: ?offsets.Loc = try parseTaggedLoc(source, phr, "def");
    const type_definition_loc: ?offsets.Loc = try parseTaggedLoc(source, phr, "tdef");

    if (declaration_loc == null and
        definition_loc == null and
        type_definition_loc == null)
    {
        std.debug.print("must specify at least one sub-test with <decl>, <def> or <tdef>\n", .{});
        return error.NoChecksSpecified;
    }

    const cursor_position = offsets.indexToPosition(phr.new_source, cursor_index, ctx.server.offset_encoding);

    const declaration_params = types.DeclarationParams{ .textDocument = .{ .uri = test_uri }, .position = cursor_position };
    const definition_params = types.DefinitionParams{ .textDocument = .{ .uri = test_uri }, .position = cursor_position };
    const type_definition_params = types.TypeDefinitionParams{ .textDocument = .{ .uri = test_uri }, .position = cursor_position };

    const maybe_declaration_response = if (declaration_loc != null)
        try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/declaration", declaration_params)
    else
        null;

    const maybe_definition_response = if (definition_loc != null)
        try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/definition", definition_params)
    else
        null;

    const maybe_type_definition_response = if (type_definition_loc != null)
        try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/typeDefinition", type_definition_params)
    else
        null;

    if (maybe_declaration_response) |response| {
        try std.testing.expect(response == .Declaration);
        try std.testing.expect(response.Declaration == .Location);
        try std.testing.expectEqualStrings(test_uri, response.Declaration.Location.uri);
        const actual_loc = offsets.rangeToLoc(phr.new_source, response.Declaration.Location.range, ctx.server.offset_encoding);
        if (declaration_loc) |expected_loc| {
            if (!std.meta.eql(expected_loc, actual_loc)) {
                try error_builder.msgAtLoc("expected declaration here!", test_uri, expected_loc, .err, .{});
                try error_builder.msgAtLoc("actual declaration here", test_uri, actual_loc, .err, .{});
            }
        }
    } else if (declaration_loc) |expected_loc| {
        try error_builder.msgAtLoc("expected declaration here but got no result instead!", test_uri, expected_loc, .err, .{});
    }

    if (maybe_definition_response) |response| {
        try std.testing.expect(response == .Definition);
        try std.testing.expect(response.Definition == .Location);
        try std.testing.expectEqualStrings(test_uri, response.Definition.Location.uri);
        const actual_loc = offsets.rangeToLoc(phr.new_source, response.Definition.Location.range, ctx.server.offset_encoding);
        if (definition_loc) |expected_loc| {
            if (!std.meta.eql(expected_loc, actual_loc)) {
                try error_builder.msgAtLoc("expected definition here!", test_uri, expected_loc, .err, .{});
                try error_builder.msgAtLoc("actual definition here", test_uri, actual_loc, .err, .{});
            }
        }
    } else if (definition_loc) |expected_loc| {
        try error_builder.msgAtLoc("expected definition here but got no result instead!", test_uri, expected_loc, .err, .{});
    }

    if (maybe_type_definition_response) |response| {
        try std.testing.expect(response == .Definition);
        try std.testing.expect(response.Definition == .Location);
        try std.testing.expectEqualStrings(test_uri, response.Definition.Location.uri);
        const actual_loc = offsets.rangeToLoc(phr.new_source, response.Definition.Location.range, ctx.server.offset_encoding);
        if (type_definition_loc) |expected_loc| {
            if (!std.meta.eql(expected_loc, actual_loc)) {
                try error_builder.msgAtLoc("expected type definition here!", test_uri, expected_loc, .err, .{});
                try error_builder.msgAtLoc("actual type definition here", test_uri, actual_loc, .err, .{});
            }
        }
    } else if (type_definition_loc) |expected_loc| {
        try error_builder.msgAtLoc("expected type definition here but got no result instead!", test_uri, expected_loc, .err, .{});
    }

    if (error_builder.hasMessages()) {
        try error_builder.msgAtIndex("cursor position here", test_uri, cursor_index, .info, .{});
        return error.InvalidResponse;
    }
}

/// finds the source location that is enclosed by `<tag_name>return_value</tag_name>`
fn parseTaggedLoc(old_source: []const u8, phr: helper.CollectPlaceholdersResult, tag_name: []const u8) !?offsets.Loc {
    var old_start_loc: ?offsets.Loc = null;
    var old_end_loc: ?offsets.Loc = null;
    var start: ?usize = null;
    var end: ?usize = null;

    for (phr.locations.items(.old), phr.locations.items(.new)) |old_loc, new_loc| {
        const str = offsets.locToSlice(old_source, old_loc); // e.g. '</decl>'
        const tag_content = str[1 .. str.len - 1]; // e.g. '/decl'
        const is_end = std.mem.startsWith(u8, tag_content, "/");
        const tag = tag_content[@intFromBool(is_end)..]; // e.g. 'decl'
        if (!std.mem.eql(u8, tag_name, tag)) continue;
        if (is_end) {
            end = new_loc.start;
            old_end_loc = old_loc;
        } else {
            start = new_loc.end;
            old_start_loc = old_loc;
        }
    }

    if (start == null and end == null) {
        return null;
    } else if (start != null and end == null) {
        std.debug.print("'{s}' is missing closing tag", .{offsets.locToSlice(old_source, old_start_loc.?)});
        return error.MissingClosingTag;
    } else if (start == null and end != null) {
        std.debug.print("unexpected closing tag '{s}'", .{offsets.locToSlice(old_source, old_end_loc.?)});
        return error.UnexpectedClosingTag;
    }

    if (start.? > end.?) {
        std.debug.print("opening tag of '{s}' is after the closing tag", .{offsets.locToSlice(old_source, old_start_loc.?)});
        return error.MissmatchedTags;
    }

    return .{ .start = start.?, .end = end.? };
}
