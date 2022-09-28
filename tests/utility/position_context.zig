const std = @import("std");
const zls = @import("zls");

const analysis = zls.analysis;
const types = zls.types;
const offsets = zls.offsets;

const allocator = std.testing.allocator;

test "position context - var access" {
    try testContext(
        \\const this_var = id<cursor>entifier;
    ,
        .var_access,
        "id",
    );
    try testContext(
        \\const this_var = identifier<cursor>;
    ,
        .var_access,
        "identifier",
    );
    try testContext(
        \\    fn foo() !Str<cursor> {
    ,
        .var_access,
        "Str",
    );
    // TODO fix failing test!
    // try testContext(
    //     \\    fn foo() Err<cursor>!void {
    // ,
    //     .var_access,
    //     "Err",
    // );
}

test "position context - field access" {
    try testContext(
        \\if (foo.<cursor>field == foo) {
    ,
        .field_access,
        "foo.",
    );
    try testContext(
        \\if (foo.member.<cursor>field == foo) {
    ,
        .field_access,
        "foo.member.",
    );
    try testContext(
        \\if (foo.*.?.<cursor>field == foo) {
    ,
        .field_access,
        "foo.*.?.",
    );
    try testContext(
        \\if (foo[0].<cursor>field == foo) {
    ,
        .field_access,
        "foo[0].",
    );
    try testContext(
        \\if (foo.<cursor>@"field" == foo) {
    ,
        .field_access,
        "foo.",
    );
    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).in<cursor>it(allocator);
    ,
        .field_access,
        "std.ArrayList(SomeStruct(a, b, c, d)).in",
    );
    try testContext(
        \\fn foo() !Foo.b<cursor> {
    ,
        .field_access,
        "Foo.b",
    );
    // TODO fix failing test!
    // try testContext(
    //     \\fn foo() Foo.b<cursor>!void {
    // ,
    //     .field_access,
    //     "Foo.b",
    // );
}

test "position context - builtin" {
    try testContext(
        \\var foo = @intC<cursor>(u32, 5);
    ,
        .builtin,
        "@intC",
    );
    try testContext(
        \\fn foo() void { @setRuntime<cursor>(false); };
    ,
        .builtin,
        "@setRuntime",
    );
}

test "position context - comment" {
    // TODO fix failing test!
    // try testContext(
    //     \\// i am<cursor> a test
    // ,
    //     .comment,
    //     "// i am",
    // );
    // try testContext(
    //     \\/// i am<cursor> a test
    // ,
    //     .comment,
    //     "/// i am",
    // );
}

test "position context - import/embedfile string literal" {
    try testContext(
        \\const std = @import("st<cursor>");
    ,
        .import_string_literal,
        "\"st", // maybe report just "st"
    );
    try testContext(
        \\const std = @embedFile("file.<cursor>");
    ,
        .embedfile_string_literal,
        "\"file.", // maybe report just "file."
    );
}

test "position context - string literal" {
    try testContext(
        \\var foo = "he<cursor>llo world!";
    ,
        .string_literal,
        "\"he", // maybe report just "he"
    );
    try testContext(
        \\var foo = \\hello<cursor>;
    ,
        .string_literal,
        "\\\\hello", // maybe report just "hello"
    );
}

test "position context - global error set" {
    try testContext(
        \\fn foo() error<cursor>!void {
    ,
        .global_error_set,
        null,
    );
    try testContext(
        \\fn foo() error.<cursor>!void {
    ,
        .global_error_set,
        null,
    );
    // TODO this should probably also be .global_error_set
    // try testContext(
    //     \\fn foo() error{<cursor>}!void {
    // ,
    //     .global_error_set,
    //     null,
    // );
    // try testContext(
    //     \\fn foo() error{OutOfMemory, <cursor>}!void {
    // ,
    //     .global_error_set,
    //     null,
    // );
}

test "position context - enum literal" {
    try testContext(
        \\var foo = .tag<cursor>;
    ,
        .enum_literal,
        null,
    );
    try testContext(
        \\var foo = .<cursor>;
    ,
        .enum_literal,
        null,
    );
}

test "position context - label" {
    try testContext(
        \\var foo = blk: { break :blk<cursor> null };
    ,
        .label,
        null,
    );
}

test "position context - empty" {
    try testContext(
        \\<cursor>
    ,
        .empty,
        null,
    );
    try testContext(
        \\<cursor>const foo = struct {};
    ,
        .empty,
        null,
    );
    try testContext(
        \\try foo(arg, slice[<cursor>]);
    ,
        .empty,
        null,
    );
    try testContext(
        \\try foo(arg, slice[<cursor>..3]);
    ,
        .empty,
        null,
    );
    try testContext(
        \\try foo(arg, slice[0..<cursor>]);
    ,
        .empty,
        null,
    );
}

fn makeDocument(uri: []const u8, text: []const u8) !types.TextDocument {
    const mem = try allocator.alloc(u8, text.len + 1);
    std.mem.copy(u8, mem, text);
    mem[text.len] = 0;

    return types.TextDocument{
        .uri = uri,
        .mem = mem,
        .text = mem[0..text.len :0],
    };
}

fn freeDocument(doc: types.TextDocument) void {
    allocator.free(doc.text);
}

fn testContext(comptime line: []const u8, comptime tag: std.meta.Tag(analysis.PositionContext), comptime maybe_range: ?[]const u8) !void {
    const cursor_idx = std.mem.indexOf(u8, line, "<cursor>").?;
    const final_line = try std.mem.concat(allocator, u8, &.{ line[0..cursor_idx], line[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(final_line);

    const doc = try makeDocument("", line);
    defer freeDocument(doc);

    const ctx = try analysis.getPositionContext(allocator, doc, cursor_idx);

    if (std.meta.activeTag(ctx) != tag) {
        std.debug.print("Expected tag `{s}`, got `{s}`\n", .{ @tagName(tag), @tagName(std.meta.activeTag(ctx)) });
        return error.DifferentTag;
    }

    const actual_loc = ctx.loc() orelse if (maybe_range) |expected_range| {
        std.debug.print("Expected `{s}`, got null range\n", .{
            expected_range,
        });
        return error.DifferentRange;
    } else return;

    const expected_range = maybe_range orelse {
        std.debug.print("Expected null range, got `{s}`\n", .{
            doc.text[actual_loc.start..actual_loc.end],
        });
        return error.DifferentRange;
    };

    const expected_range_start = std.mem.indexOf(u8, final_line, expected_range).?;
    const expected_range_end = expected_range_start + expected_range.len;

    if (expected_range_start != actual_loc.start or expected_range_end != actual_loc.end) {
        std.debug.print("Expected range `{s}` ({}..{}), got `{s}` ({}..{})\n", .{
            doc.text[expected_range_start..expected_range_end], expected_range_start, expected_range_end,
            doc.text[actual_loc.start..actual_loc.end],         actual_loc.start,     actual_loc.end,
        });
        return error.DifferentRange;
    }
}
