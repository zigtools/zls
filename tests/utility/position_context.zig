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
        .{ .tag = .empty },
    );
    try testContext(
        \\const a_var = <cursor>identifier;
    , .{
        .tag = .var_access,
        .slice = "i",
    });
    try testContext(
        \\const a_var = iden<cursor>tifier;
    , .{
        .tag = .var_access,
        .slice = "ident",
    });
    try testContext(
        \\const a_var = identifier<cursor>;
    , .{
        .tag = .var_access,
        .slice = "identifier",
    });
    try testContext(
        \\const a_var = identifier;<cursor>
    , .{
        .tag = .empty,
    });

    try testContext(
        \\    fn foo() !<cursor>Str {
    , .{
        .tag = .var_access,
        .slice = "S",
    });
    try testContext(
        \\    fn foo() !St<cursor>r {
    , .{
        .tag = .var_access,
        .slice = "Str",
    });
    try testContext(
        \\    fn foo() !Str<cursor> {
    , .{
        .tag = .var_access,
        .slice = "Str",
    });
    try testContext(
        \\    fn foo() !Str <cursor>{
    , .{
        .tag = .var_access,
        .slice = "Str",
    });

    try testContext(
        \\    fn foo() <cursor>Err!void {
    , .{
        .tag = .var_access,
        .slice = "E",
    });
    try testContext(
        \\    fn foo() Er<cursor>r!void {
    , .{
        .tag = .var_access,
        .slice = "Err",
    });
    try testContext(
        \\    fn foo() Err<cursor>!void {
    , .{
        .tag = .var_access,
        .slice = "Err",
    });
    try testContext(
        \\    fn foo() Err!<cursor>void {
    , .{
        .tag = .var_access,
        .slice = "v",
    });

    try testContext(
        \\if (<cursor>bar.field == foo) {
    , .{
        .tag = .var_access,
        .slice = "b",
    });
    try testContext(
        \\if (ba<cursor>r.field == foo) {
    , .{
        .tag = .var_access,
        .slice = "bar",
    });
    try testContext(
        \\if (bar<cursor>.field == foo) {
    , .{
        .tag = .var_access,
        .slice = "bar",
    });

    try testContext(
        \\if (bar[0]<cursor>.field == foo) {
    , .{
        .tag = .var_access,
        .slice = "bar",
    });
}

test "position context - field access" {
    try testContext(
        \\if (bar.<cursor>field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.f",
    });
    try testContext(
        \\if (bar.fie<cursor>ld == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.fiel",
    });
    try testContext(
        \\if (bar.field<cursor> == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.field",
    });

    try testContext(
        \\if (bar.member<cursor>.field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.member",
    });
    try testContext(
        \\if (bar.member.<cursor>field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.member.f",
    });
    try testContext(
        \\if (bar.member.fie<cursor>ld == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.member.fiel",
    });
    try testContext(
        \\if (bar.member.field<cursor> == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.member.field",
    });

    try testContext(
        \\if (bar.*.?<cursor>.field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.*.?",
    });
    try testContext(
        \\if (bar.*.?.<cursor>field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.*.?.f",
    });

    try testContext(
        \\if (bar[0].<cursor>field == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar[0].f",
    });

    try testContext(
        \\if (bar.<cursor>@"field" == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.@\"",
    });
    try testContext(
        \\if (bar.@"fie<cursor>ld" == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.@\"fiel",
    });
    try testContext(
        \\if (bar.@"field"<cursor> == foo) {
    , .{
        .tag = .field_access,
        .slice = "bar.@\"field\"",
    });

    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).<cursor>init(allocator);
    , .{
        .tag = .field_access,
        .slice = "std.ArrayList(SomeStruct(a, b, c, d)).i",
    });
    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).in<cursor>it(allocator);
    , .{
        .tag = .field_access,
        .slice = "std.ArrayList(SomeStruct(a, b, c, d)).ini",
    });
    try testContext(
        \\const arr = std.ArrayList(SomeStruct(a, b, c, d)).init<cursor>(allocator);
    , .{
        .tag = .field_access,
        .slice = "std.ArrayList(SomeStruct(a, b, c, d)).init",
    });

    try testContext(
        \\fn foo() !Foo.<cursor>bar {
    , .{
        .tag = .field_access,
        .slice = "Foo.b",
    });
    try testContext(
        \\fn foo() !Foo.ba<cursor>r {
    , .{
        .tag = .field_access,
        .slice = "Foo.bar",
    });
    try testContext(
        \\fn foo() !Foo.bar<cursor> {
    , .{
        .tag = .field_access,
        .slice = "Foo.bar",
    });

    try testContext(
        \\fn foo() Foo.<cursor>bar!void {
    , .{
        .tag = .field_access,
        .slice = "Foo.b",
    });
    try testContext(
        \\fn foo() Foo.ba<cursor>r!void {
    , .{
        .tag = .field_access,
        .slice = "Foo.bar",
    });
    try testContext(
        \\fn foo() Foo.bar<cursor>!void {
    , .{
        .tag = .field_access,
        .slice = "Foo.bar",
    });
}

test "position context - builtin" {
    try testContext(
        \\var foo = <cursor>@
    , .{
        .tag = .empty,
    });
    try testContext(
        \\var foo = @<cursor>
    , .{
        .tag = .builtin,
        .slice = "@",
    });
    try testContext(
        \\var foo = <cursor>@intC(u32, 5);
    , .{
        .tag = .builtin,
        .slice = "@i",
    });
    try testContext(
        \\var foo = @<cursor>intC(u32, 5);
    , .{
        .tag = .builtin,
        .slice = "@i",
    });
    try testContext(
        \\var foo = @int<cursor>C(u32, 5);
    , .{
        .tag = .builtin,
        .slice = "@intC",
    });
    try testContext(
        \\var foo = @intC<cursor>(u32, 5);
    , .{
        .tag = .builtin,
        .slice = "@intC",
    });

    try testContext(
        \\fn foo() void { <cursor>@setRuntime(false); };
    , .{
        .tag = .builtin,
        .slice = "@s",
    });
    try testContext(
        \\fn foo() void { @<cursor>setRuntime(false); };
    , .{
        .tag = .builtin,
        .slice = "@s",
    });
    try testContext(
        \\fn foo() void { @set<cursor>Runtime(false); };
    , .{
        .tag = .builtin,
        .slice = "@setR",
    });
    try testContext(
        \\fn foo() void { @setRuntime<cursor>(false); };
    , .{
        .tag = .builtin,
        .slice = "@setRuntime",
    });
}

test "position context - comment" {
    try testContext(
        \\// i am<cursor> a test
    , .{
        .tag = .comment,
        .slice = null, // report "// i am a test"
    });
    try testContext(
        \\/// i am<cursor> a test
    , .{
        .tag = .comment,
        .slice = null, // report /// i am a test
    });
}

test "position context - import/embedfile string literal" {
    try testContext(
        \\const std = @import("s<cursor>t");
    , .{
        .tag = .import_string_literal,
        .slice = "\"st", // maybe report just "st"
    });
    try testContext(
        \\const std = @import("st<cursor>");
    , .{
        .tag = .import_string_literal,
        .slice = "\"st", // maybe report just "st"
    });
    try testContext(
        \\const std = @embedFile("file.<cursor>");
    , .{
        .tag = .embedfile_string_literal,
        .slice = "\"file.", // maybe report just "file."
    });
    try testContext(
        \\const std = @embedFile("file<cursor>.");
    , .{
        .tag = .embedfile_string_literal,
        .slice = "\"file", // maybe report just "file."
    });
}

test "position context - string literal" {
    try testContext(
        \\var foo = "he<cursor>llo world!";
    , .{
        .tag = .string_literal,
        .slice = "\"hel", // maybe report just "he"
    });
    try testContext(
        \\var foo = \\hell<cursor>o;
    , .{
        .tag = .string_literal,
        .slice = "\\\\hello", // maybe report just "hello;"
    });
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
    , .{
        .tag = .global_error_set,
    });
    try testContext(
        \\fn foo() error<cursor>!void {
    , .{
        .tag = .global_error_set,
    });
    try testContext(
        \\fn foo() error<cursor>.!void {
    , .{
        .tag = .global_error_set,
    });
    try testContext(
        \\fn foo() error.<cursor>!void {
    , .{
        .tag = .global_error_set,
    });

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
    , .{
        .tag = .enum_literal,
        .slice = ".t",
    });
    try testContext(
        \\var foo = .ta<cursor>g;
    , .{
        .tag = .enum_literal,
        .slice = ".tag",
    });
    try testContext(
        \\var foo = .tag<cursor>;
    , .{
        .tag = .enum_literal,
        .slice = ".tag",
    });
    try testContext(
        \\var foo = <cursor>.;
    , .{
        .tag = .empty,
    });
    try testContext(
        \\var foo = .<cursor>;
    , .{
        .tag = .enum_literal,
        .slice = ".",
    });
}

test "position context - label" {
    try testContext(
        \\var foo = blk: { break <cursor>:blk null };
    , .{
        .tag = .pre_label,
    });
    try testContext(
        \\var foo = blk: { break :<cursor>blk null };
    , .{
        .tag = .label,
    });
    try testContext(
        \\var foo = blk: { break :bl<cursor>k null };
    , .{
        .tag = .label,
    });
    try testContext(
        \\var foo = blk: { break :blk<cursor> null };
    , .{
        .tag = .label,
    });
}

test "position context - empty" {
    try testContext(
        \\<cursor>
    , .{
        .tag = .empty,
    });
    try testContext(
        \\try foo(arg, slice[<cursor>]);
    , .{
        .tag = .empty,
    });
    try testContext(
        \\try foo(arg, slice[<cursor>..3]);
    , .{
        .tag = .empty,
    });
    try testContext(
        \\try foo(arg, slice[0..<cursor>]);
    , .{
        .tag = .empty,
    });
}

test "position context - last resort/fallback" {
    try testContext(
        \\    <cursor>@Type(.{.Struct = .{.}})
    , .{
        .look_ahead = false,
        .tag = .builtin,
        .slice = "@Type",
    });
}

const Expected = struct {
    look_ahead: bool = true,
    tag: std.meta.Tag(Analyser.PositionContext),
    slice: ?[]const u8 = null,
};

fn testContext(
    line: []const u8,
    expected: Expected,
) !void {
    const cursor_idx = std.mem.indexOf(u8, line, "<cursor>").?;
    const final_line = try std.mem.concat(allocator, u8, &.{ line[0..cursor_idx], line[cursor_idx + "<cursor>".len ..] });
    defer allocator.free(final_line);

    const ctx = try Analyser.getPositionContext(allocator, final_line, cursor_idx, expected.look_ahead);

    if (std.meta.activeTag(ctx) != expected.tag) {
        std.debug.print("Expected tag `{s}`, got `{s}`\n", .{ @tagName(expected.tag), @tagName(std.meta.activeTag(ctx)) });
        return error.DifferentTag;
    }

    const actual_loc = ctx.loc() orelse if (expected.slice) |expected_range| {
        std.debug.print("Expected `{s}`, got null range\n", .{
            expected_range,
        });
        return error.DifferentRange;
    } else return;

    const expected_range = expected.slice orelse {
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
