const std = @import("std");
const zls = @import("zls");

const Analyser = zls.Analyser;
const types = zls.types;
const offsets = zls.offsets;

const allocator = std.testing.allocator;

test "position context - var access" {
    try testContext(
        \\const a_var =<cursor> identifier;
    ,
        .empty,
        null,
    );
    try testContext(
        \\const a_var = <cursor>identifier;
    ,
        .var_access,
        "i",
    );
    try testContext(
        \\const a_var = iden<cursor>tifier;
    ,
        .var_access,
        "ident",
    );
    try testContext(
        \\const a_var = identifier<cursor>;
    ,
        .var_access,
        "identifier",
    );
    try testContext(
        \\const a_var = identifier;<cursor>
    ,
        .empty,
        null,
    );

    try testContext(
        \\    fn foo() !<cursor>Str {
    ,
        .var_access,
        "S",
    );
    try testContext(
        \\    fn foo() !St<cursor>r {
    ,
        .var_access,
        "Str",
    );
    try testContext(
        \\    fn foo() !Str<cursor> {
    ,
        .var_access,
        "Str",
    );
    try testContext(
        \\    fn foo() !Str <cursor>{
    ,
        .var_access,
        "Str",
    );

    // TODO fix failing tests
    // try testContext(
    //     \\    fn foo() <cursor>Err!void {
    // ,
    //     .var_access,
    //     "E",
    // );
    // try testContext(
    //     \\    fn foo() Er<cursor>r!void {
    // ,
    //     .var_access,
    //     "Err",
    // );
    // try testContext(
    //     \\    fn foo() Err<cursor>!void {
    // ,
    //     .var_access,
    //     "Err",
    // );
    // try testContext(
    //     \\    fn foo() Err!<cursor>void {
    // ,
    //     .var_access,
    //     "v",
    // );

    try testContext(
        \\if (<cursor>bar.field == foo) {
    ,
        .var_access,
        "b",
    );
    try testContext(
        \\if (ba<cursor>r.field == foo) {
    ,
        .var_access,
        "bar",
    );
    try testContext(
        \\if (bar<cursor>.field == foo) {
    ,
        .var_access,
        "bar",
    );

    try testContext(
        \\if (bar[0]<cursor>.field == foo) {
    ,
        .var_access,
        "bar",
    );
}

test "position context - field access" {
    try testContext(
        \\if (bar.<cursor>field == foo) {
    ,
        .field_access,
        "bar.f",
    );
    try testContext(
        \\if (bar.fie<cursor>ld == foo) {
    ,
        .field_access,
        "bar.fiel",
    );
    try testContext(
        \\if (bar.field<cursor> == foo) {
    ,
        .field_access,
        "bar.field",
    );

    try testContext(
        \\if (bar.member<cursor>.field == foo) {
    ,
        .field_access,
        "bar.member",
    );
    try testContext(
        \\if (bar.member.<cursor>field == foo) {
    ,
        .field_access,
        "bar.member.f",
    );
    try testContext(
        \\if (bar.member.fie<cursor>ld == foo) {
    ,
        .field_access,
        "bar.member.fiel",
    );
    try testContext(
        \\if (bar.member.field<cursor> == foo) {
    ,
        .field_access,
        "bar.member.field",
    );

    try testContext(
        \\if (bar.*.?<cursor>.field == foo) {
    ,
        .field_access,
        "bar.*.?",
    );
    try testContext(
        \\if (bar.*.?.<cursor>field == foo) {
    ,
        .field_access,
        "bar.*.?.f",
    );

    try testContext(
        \\if (bar[0].<cursor>field == foo) {
    ,
        .field_access,
        "bar[0].f",
    );

    try testContext(
        \\if (bar.<cursor>@"field" == foo) {
    ,
        .field_access,
        "bar.@\"",
    );
    try testContext(
        \\if (bar.@"fie<cursor>ld" == foo) {
    ,
        .field_access,
        "bar.@\"fiel",
    );
    try testContext(
        \\if (bar.@"field"<cursor> == foo) {
    ,
        .field_access,
        "bar.@\"field\"",
    );

    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).<cursor>init(allocator);
    ,
        .field_access,
        "std.ArrayList(SomeStruct(a, b, c, d)).i",
    );
    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).in<cursor>it(allocator);
    ,
        .field_access,
        "std.ArrayList(SomeStruct(a, b, c, d)).ini",
    );
    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).init<cursor>(allocator);
    ,
        .field_access,
        "std.ArrayList(SomeStruct(a, b, c, d)).init",
    );

    try testContext(
        \\fn foo() !Foo.<cursor>bar {
    ,
        .field_access,
        "Foo.b",
    );
    try testContext(
        \\fn foo() !Foo.ba<cursor>r {
    ,
        .field_access,
        "Foo.bar",
    );
    try testContext(
        \\fn foo() !Foo.bar<cursor> {
    ,
        .field_access,
        "Foo.bar",
    );

    // TODO fix failing tests
    // try testContext(
    //     \\fn foo() Foo.<cursor>bar!void {
    // ,
    //     .field_access,
    //     "Foo.b",
    // );
    // try testContext(
    //     \\fn foo() Foo.ba<cursor>r!void {
    // ,
    //     .field_access,
    //     "Foo.bar",
    // );
    // try testContext(
    //     \\fn foo() Foo.bar<cursor>!void {
    // ,
    //     .field_access,
    //     "Foo.bar",
    // );
}

test "position context - builtin" {
    try testContext(
        \\var foo = <cursor>@
    ,
        .empty,
        null,
    );
    try testContext(
        \\var foo = <cursor>@intC(u32, 5);
    ,
        .builtin,
        "@i",
    );
    try testContext(
        \\var foo = @<cursor>intC(u32, 5);
    ,
        .builtin,
        "@i",
    );
    try testContext(
        \\var foo = @int<cursor>C(u32, 5);
    ,
        .builtin,
        "@intC",
    );
    try testContext(
        \\var foo = @intC<cursor>(u32, 5);
    ,
        .builtin,
        "@intC",
    );

    try testContext(
        \\fn foo() void { <cursor>@setRuntime(false); };
    ,
        .builtin,
        "@s",
    );
    try testContext(
        \\fn foo() void { @<cursor>setRuntime(false); };
    ,
        .builtin,
        "@s",
    );
    try testContext(
        \\fn foo() void { @set<cursor>Runtime(false); };
    ,
        .builtin,
        "@setR",
    );
    try testContext(
        \\fn foo() void { @setRuntime<cursor>(false); };
    ,
        .builtin,
        "@setRuntime",
    );
}

test "position context - comment" {
    try testContext(
        \\// i am<cursor> a test
    ,
        .comment,
        null, // report "// i am a test"
    );
    try testContext(
        \\/// i am<cursor> a test
    ,
        .comment,
        null, // report /// i am a test
    );
}

test "position context - import/embedfile string literal" {
    try testContext(
        \\const std = @import("s<cursor>t");
    ,
        .import_string_literal,
        "\"st", // maybe report just "st"
    );
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
    try testContext(
        \\const std = @embedFile("file<cursor>.");
    ,
        .embedfile_string_literal,
        "\"file", // maybe report just "file."
    );
}

test "position context - string literal" {
    try testContext(
        \\var foo = "he<cursor>llo world!";
    ,
        .string_literal,
        "\"hel", // maybe report just "he"
    );
    try testContext(
        \\var foo = \\hell<cursor>o;
    ,
        .string_literal,
        "\\\\hello", // maybe report just "hello;"
    );
}

test "position context - global error set" {
    // TODO why is this a .var_access instead of a .global_error_set?
    // try testContext(
    //     \\fn foo() <cursor>error!void {
    // ,
    //     .global_error_set,
    //     null,
    // );
    try testContext(
        \\fn foo() erro<cursor>r!void {
    ,
        .global_error_set,
        null,
    );
    try testContext(
        \\fn foo() error<cursor>!void {
    ,
        .global_error_set,
        null,
    );
    try testContext(
        \\fn foo() error<cursor>.!void {
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
        \\var foo = .<cursor>tag;
    ,
        .enum_literal,
        ".t",
    );
    try testContext(
        \\var foo = .ta<cursor>g;
    ,
        .enum_literal,
        ".tag",
    );
    try testContext(
        \\var foo = .tag<cursor>;
    ,
        .enum_literal,
        ".tag",
    );
    try testContext(
        \\var foo = <cursor>.;
    ,
        .empty,
        null,
    );
    try testContext(
        \\var foo = .<cursor>;
    ,
        .enum_literal,
        ".",
    );
}

test "position context - label" {
    try testContext(
        \\var foo = blk: { break <cursor>:blk null };
    ,
        .pre_label,
        null,
    );
    try testContext(
        \\var foo = blk: { break :<cursor>blk null };
    ,
        .label,
        null,
    );
    try testContext(
        \\var foo = blk: { break :bl<cursor>k null };
    ,
        .label,
        null,
    );
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

fn testContext(line: []const u8, tag: std.meta.Tag(Analyser.PositionContext), maybe_range: ?[]const u8) !void {
    const cursor_idx = std.mem.indexOf(u8, line, "<cursor>").?;
    const final_line = try std.mem.concat(allocator, u8, &.{ line[0..cursor_idx], line[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(final_line);

    const ctx = try Analyser.getPositionContext(allocator, final_line, cursor_idx, true);

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
            final_line[actual_loc.start..actual_loc.end],
        });
        return error.DifferentRange;
    };

    const expected_range_start = std.mem.indexOf(u8, final_line, expected_range).?;
    const expected_range_end = expected_range_start + expected_range.len;

    if (expected_range_start != actual_loc.start or expected_range_end != actual_loc.end) {
        std.debug.print("Expected range `{s}` ({}..{}), got `{s}` ({}..{})\n", .{
            final_line[expected_range_start..expected_range_end], expected_range_start, expected_range_end,
            final_line[actual_loc.start..actual_loc.end],         actual_loc.start,     actual_loc.end,
        });
        return error.DifferentRange;
    }
}
