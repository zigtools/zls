const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const ErrorBuilder = @import("../ErrorBuilder.zig");

const Analyser = zls.Analyser;
const offsets = zls.offsets;

const allocator = std.testing.allocator;

test "keyword" {
    try testContext(
        \\const foo = <cursor><loc>while</loc> (true) {};
    , .keyword, .{ .lookahead = true });
}

test "var_access" {
    try testContext(
        \\const foo = <cursor><loc>identifier</loc>;
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\const foo = <loc>identifier</loc><cursor>;
    , .var_access, .{});
    try testContext(
        \\const foo = <loc>iden<cursor>tifier</loc>;
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\const foo = <loc>identifier</loc><cursor>;
    , .var_access, .{});
    try testContext(
        \\const foo =<cursor> identifier;
    , .empty, .{ .lookahead = false });
    try testContext(
        \\const foo = identifier;<cursor>
    , .empty, .{});
}

test "function.payload" {
    try testContext(
        \\    fn foo() !<cursor><loc>Str</loc> {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() !<cursor><loc>Str</loc> {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() !<loc>St<cursor>r</loc> {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() !<loc>Str</loc><cursor> {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() !<loc>Str</loc> <cursor>{
    , .var_access, .{ .lookahead = false });
}

test "function.error_set" {
    try testContext(
        \\    fn foo() <cursor><loc>Err</loc>!void {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() <loc>Er<cursor>r</loc>!void {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() <loc>Err</loc><cursor>!void {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\    fn foo() Err!<cursor><loc>void</loc> {
    , .var_access, .{ .lookahead = true });
}

test "function.parameter" {
    try testContext(
        \\fn foo(
        \\    /// hello world
        \\    <loc><cursor>a</loc>: u32,
        \\) void {}
    , .var_access, .{ .lookahead = true });
}

test "var_access.nested" {
    try testContext(
        \\if (<cursor><loc>bar</loc>.field == foo) {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>ba<cursor>r</loc>.field == foo) {
    , .var_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar</loc><cursor>.field == foo) {
    , .var_access, .{ .lookahead = true });
}

test "var_access no lookahead" {
    try testContext(
        \\const a_var =<cursor> identifier;
    , .empty, .{ .lookahead = false });
    try testContext(
        \\const a_var = <cursor>identifier;
    , .empty, .{ .lookahead = false });
    try testContext(
        \\const a_var = <loc>iden</loc><cursor>tifier;
    , .var_access, .{ .lookahead = false });
    try testContext(
        \\const a_var = <loc>identifier</loc><cursor>;
    , .var_access, .{ .lookahead = false });
    try testContext(
        \\const a_var = identifier;<cursor>
    , .empty, .{ .lookahead = false });
}

test "field access" {
    try testContext(
        \\if (<loc>bar.<cursor>field</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.fie<cursor>ld</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.field</loc><cursor> == foo) {
    , .field_access, .{});

    try testContext(
        \\if (<loc>bar.member</loc><cursor>.field == foo) {
    , .field_access, .{});
    try testContext(
        \\if (<loc>bar.member.<cursor>field</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.member.fie<cursor>ld</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.member.field</loc><cursor> == foo) {
    , .field_access, .{});

    try testContext(
        \\if (<loc>bar.*.?</loc><cursor>.field == foo) {
    , .field_access, .{});
    try testContext(
        \\if (<loc>bar.*.?.<cursor>field</loc> == foo) {
    , .field_access, .{ .lookahead = true });

    try testContext(
        \\if (<loc>bar[0].<cursor>field</loc> == foo) {
    , .field_access, .{ .lookahead = true });

    try testContext(
        \\if (<loc>bar.<cursor>@"field"</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.@"fie<cursor>ld"</loc> == foo) {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (<loc>bar.@"field"</loc><cursor> == foo) {
    , .field_access, .{ .lookahead = true });

    try testContext(
        \\const arr = <loc>std.ArrayList(SomeStruct(a, b, c, d)).<cursor>init</loc>(allocator);
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\const arr = <loc>std.ArrayList(SomeStruct(a, b, c, d)).in<cursor>it</loc>(allocator);
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\const arr = <loc>std.ArrayList(SomeStruct(a, b, c, d)).init</loc><cursor>(allocator);
    , .field_access, .{ .lookahead = true });

    try testContext(
        \\fn foo() !<loc>Foo.<cursor>bar</loc> {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\fn foo() !<loc>Foo.ba<cursor>r</loc> {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\fn foo() !<loc>Foo.bar</loc><cursor> {
    , .field_access, .{});

    try testContext(
        \\fn foo() <loc>Foo.<cursor>bar</loc>!void {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\fn foo() <loc>Foo.ba<cursor>r</loc>!void {
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\fn foo() <loc>Foo.bar</loc><cursor>!void {
    , .field_access, .{});

    try testContext(
        \\if (true) <loc>foo.<cursor>bar</loc> == 3
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (true) <loc>foo.ba<cursor>r</loc> == 3
    , .field_access, .{ .lookahead = true });
    try testContext(
        \\if (true) <loc>foo.bar<cursor></loc> == 3
    , .field_access, .{});
}

test "field access across multiple lines" {
    // ErrorBuilder doesn't support locs across multiple lines so don't let the test fail :)
    try testContext(
        \\test {
        \\    <loc>item
        \\        .foo()
        \\        .bar()
        \\        .baz<cursor></loc>();
        \\}
    , .field_access, .{});

    try testContext(
        \\/// some comment
        \\    .<loc>foo</loc><cursor>()
    , .var_access, .{});
}

test "builtin" {
    try testContext(
        \\var foo = <cursor>@
    , .empty, .{ .lookahead = false });
    try testContext(
        \\var foo = <loc><cursor>@</loc>
    , .builtin, .{ .lookahead = true });

    try testContext(
        \\var foo = <loc>@<cursor></loc>
    , .builtin, .{});
    try testContext(
        \\var foo = <loc>@tag<cursor>Name</loc>
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>@tagName<cursor></loc>
    , .builtin, .{});

    try testContext(
        \\var foo = <cursor><loc>@intC</loc>(u32, 5);
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>@<cursor>intC</loc>(u32, 5);
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>@int<cursor>C</loc>(u32, 5);
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>@intC</loc><cursor>(u32, 5);
    , .builtin, .{});

    try testContext(
        \\var foo: <cursor>@
    , .empty, .{ .lookahead = false });
    try testContext(
        \\var foo: <loc><cursor>@</loc>
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo: <loc><cursor>@</loc>();
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo: <loc><cursor>@Thi</loc>();
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo: <loc>@<cursor>Thi</loc>();
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo: <loc>@Th<cursor>i</loc>();
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\var foo: <loc>@Thi<cursor></loc>();
    , .builtin, .{});

    try testContext(
        \\fn foo() void { <cursor><loc>@setRuntime</loc>(false); };
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\fn foo() void { <loc>@<cursor>setRuntime</loc>(false); };
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\fn foo() void { <loc>@set<cursor>Runtime</loc>(false); };
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\fn foo() void { <loc>@setRuntime</loc><cursor>(false); };
    , .builtin, .{});

    try testContext(
        \\if (true) <cursor><loc>@setRuntime</loc>(false)
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\if (true) <loc>@<cursor>setRuntime</loc>(false)
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\if (true) <loc>@set<cursor>Runtime</loc>(false)
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\if (true) <loc>@setRuntime</loc><cursor>(false)
    , .builtin, .{});

    try testContext(
        \\const foo = (<loc><cursor>@</loc>())
    , .builtin, .{ .lookahead = true });
    try testContext(
        \\const foo = (<loc><cursor>@trap</loc>())
    , .builtin, .{ .lookahead = true });
}

test "comment" {
    try testContext(
        \\//! i am<cursor> a test
    , .comment, .{});
    try testContext(
        \\// i am<cursor> a test
    , .comment, .{});
    try testContext(
        \\/// i am<cursor> a test
    , .comment, .{});
    // TODO
    // try testContext(
    //     \\const foo = // i am<cursor> a test
    // , .comment, .{});
}

test "import/embedfile string literal" {
    try testContext(
        \\const std = @import(<loc>"s</loc><cursor>t");
    , .import_string_literal, .{ .lookahead = false });
    try testContext(
        \\const std = @import(<loc>"st</loc><cursor>");
    , .import_string_literal, .{ .lookahead = false });
    try testContext(
        \\const std = @import(<loc>"s<cursor>t"</loc>);
    , .import_string_literal, .{ .lookahead = true });
    try testContext(
        \\const std = @embedFile(<loc>"file</loc><cursor>.");
    , .embedfile_string_literal, .{ .lookahead = false });
    try testContext(
        \\const std = @embedFile(<loc>"file.</loc><cursor>");
    , .embedfile_string_literal, .{ .lookahead = false });
    try testContext(
        \\const std = @embedFile(<loc>"file.<cursor>"</loc>);
    , .embedfile_string_literal, .{ .lookahead = true });

    try testContext(
        \\const std = @import(<loc>"std"</loc><cursor>);
    , .string_literal, .{});
    try testContext(
        \\const std = @import(<cursor><loc>"std"</loc>);
    , .string_literal, .{ .lookahead = true });
}

test "string literal" {
    try testContext(
        \\var foo = <cursor>"hello world!";
    , .empty, .{ .lookahead = false });
    try testContext(
        \\var foo = <cursor><loc>"hello world!"</loc>;
    , .string_literal, .{ .lookahead = true });

    try testContext(
        \\var foo = <loc>"hello world!"</loc><cursor>;
    , .string_literal, .{});

    try testContext(
        \\var foo = <loc>"<cursor></loc>";
    , .string_literal, .{ .lookahead = false });
    try testContext(
        \\var foo = <loc>"<cursor>"</loc>;
    , .string_literal, .{ .lookahead = true });
    // TODO
    // try testContext(
    //     \\var foo = <loc>"\"<cursor>"</loc>;
    // , .string_literal, .{ .lookahead = true });

    try testContext(
        \\var foo = <loc>"hello</loc><cursor> world!";
    , .string_literal, .{ .lookahead = false });
    try testContext(
        \\var foo = <loc>"hello<cursor> world!"</loc>;
    , .string_literal, .{ .lookahead = true });
}

test "multi-line string literal" {
    try testContext(
        \\var foo = <cursor>\\hello
    , .empty, .{ .lookahead = false });
    try testContext(
        \\var foo = <cursor><loc>\\hello</loc>
    , .string_literal, .{ .lookahead = true });

    try testContext(
        \\var foo = <loc>\\</loc><cursor>
    , .string_literal, .{});
    try testContext(
        \\var foo = <loc>\\\"</loc><cursor>
    , .string_literal, .{});

    try testContext(
        \\var foo = <loc>\\hello</loc><cursor> world!
    , .string_literal, .{ .lookahead = false });
    try testContext(
        \\var foo = <loc>\\hello<cursor> world!</loc>
    , .string_literal, .{ .lookahead = true });

    try testContext(
        \\var foo = <loc>\\hello;</loc><cursor>
    , .string_literal, .{});
}

test "global error set" {
    // TODO why is this a .var_access instead of a .global_error_set?
    // try testContext(
    //     \\fn foo() <cursor>error!void {
    // , .global_error_set, .{});
    try testContext(
        \\fn foo() erro<cursor>r!void {
    , .global_error_set, .{ .lookahead = true });
    try testContext(
        \\fn foo() error<cursor>!void {
    , .global_error_set, .{});
    try testContext(
        \\fn foo() error<cursor>.!void {
    , .global_error_set, .{});
    try testContext(
        \\fn foo() error.<cursor>!void {
    , .global_error_set, .{});

    // TODO this should probably also be .global_error_set
    // try testContext(
    //     \\fn foo() error{<cursor>}!void {
    // , .global_error_set, .{});
    // try testContext(
    //     \\fn foo() error{OutOfMemory, <cursor>}!void {
    // , .global_error_set, .{});
}

test "number literal" {
    try testContext(
        \\var foo = <loc>5<cursor></loc>;
    , .number_literal, .{});
    try testContext(
        \\var foo = <loc><cursor>5</loc>;
    , .number_literal, .{ .lookahead = true });
}

test "char literal" {
    try testContext(
        \\var foo = <loc>'5<cursor>'</loc>;
    , .char_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>'<cursor>5'</loc>;
    , .char_literal, .{ .lookahead = true });
}

test "enum literal" {
    try testContext(
        \\var foo = <loc>.<cursor>tag</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>.ta<cursor>g</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>.tag</loc><cursor>;
    , .enum_literal, .{});
    try testContext(
        \\var foo = <cursor>.;
    , .empty, .{ .lookahead = false });
    try testContext(
        \\var foo = <loc><cursor>.</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>.</loc><cursor>;
    , .enum_literal, .{});
}

test "enum literal after break" {
    try testContext(
        \\break <loc>.<cursor>foo</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\break <loc>.foo<cursor></loc>;
    , .enum_literal, .{});
}

test "enum literal after break label" {
    try testContext(
        \\break :blk <loc>.<cursor>foo</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\break :blk <loc>.foo<cursor></loc>;
    , .enum_literal, .{});
}

test "enum literal in 'then' expression of 'if' statement" {
    try testContext(
        \\var foo = if (bar) <loc>.<cursor>foo</loc> else .bar;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = if (bar) <loc>.foo<cursor></loc> else .bar;
    , .enum_literal, .{});
}

test "enum literal in 'else' expression of 'if' statement" {
    try testContext(
        \\var foo = if (bar) .foo else <loc>.<cursor>bar</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = if (bar) .foo else <loc>.bar<cursor></loc>;
    , .enum_literal, .{});
}

test "enum literal in body of 'while' loop" {
    try testContext(
        \\var foo = while (bar) <loc>.<cursor>foo</loc> else .bar;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = while (bar) <loc>.foo<cursor></loc> else .bar;
    , .enum_literal, .{});
    try testContext(
        \\var foo = while (bar) |baz| <loc>.<cursor>foo</loc> else .bar;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = while (bar) |baz| <loc>.foo<cursor></loc> else .bar;
    , .enum_literal, .{});
}

test "enum literal in 'else' expression of 'while' loop" {
    try testContext(
        \\var foo = while (bar) .foo else <loc>.<cursor>bar</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = while (bar) .foo else <loc>.bar<cursor></loc>;
    , .enum_literal, .{});
    try testContext(
        \\var foo = while (bar) |baz| .foo else <loc>.<cursor>bar</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = while (bar) |baz| .foo else <loc>.bar<cursor></loc>;
    , .enum_literal, .{});
}

test "enum literal in body of 'for' loop" {
    try testContext(
        \\var foo = for (bar) <loc>.<cursor>foo</loc> else .bar;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = for (bar) <loc>.foo<cursor></loc> else .bar;
    , .enum_literal, .{});
    try testContext(
        \\var foo = for (bar) |baz| <loc>.<cursor>foo</loc> else .bar;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = for (bar) |baz| <loc>.foo<cursor></loc> else .bar;
    , .enum_literal, .{});
}

test "enum literal in 'else' expression of 'for' loop" {
    try testContext(
        \\var foo = for (bar) .foo else <loc>.<cursor>bar</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = for (bar) .foo else <loc>.bar<cursor></loc>;
    , .enum_literal, .{});
    try testContext(
        \\var foo = for (bar) |baz| .foo else <loc>.<cursor>bar</loc>;
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = for (bar) |baz| .foo else <loc>.bar<cursor></loc>;
    , .enum_literal, .{});
}

test "label access" {
    try testContext(
        \\var foo = blk: { break :<loc><cursor>blk</loc> null };
    , .label_access, .{ .lookahead = true });
    try testContext(
        \\var foo = blk: { break :<loc>blk<cursor></loc> null };
    , .label_access, .{});

    try testContext(
        \\break :blk <loc>foo<cursor></loc>;
    , .var_access, .{});
}

test "label decl" {
    try testContext(
        \\var foo = <loc><cursor>blk</loc>: { break :blk null };
    , .label_decl, .{ .lookahead = true });
    try testContext(
        \\var foo = <loc>blk<cursor></loc>: { break :blk null };
    , .label_decl, .{});
}

test "empty" {
    try testContext(
        \\<cursor>
    , .empty, .{});
    try testContext(
        \\try foo(arg, slice[<cursor>]);
    , .empty, .{});
    try testContext(
        \\try foo(arg, slice[<cursor>..3]);
    , .empty, .{});
    try testContext(
        \\try foo(arg, slice[0..<cursor>]);
    , .empty, .{});
}

test "inferred struct init as call argument" {
    try testContext(
        \\var foo = bar(<loc><cursor>.</loc>{});
    , .enum_literal, .{ .lookahead = true });
    try testContext(
        \\var foo = bar(<loc>.<cursor></loc>{});
    , .enum_literal, .{});
}

const Options = struct {
    /// `null` means both
    lookahead: ?bool = null,
};

fn testContext(source: []const u8, expected_tag: std.meta.Tag(Analyser.PositionContext), options: Options) !void {
    const lookahead = options.lookahead orelse {
        var options_copy = options;

        options_copy.lookahead = true;
        try testContext(source, expected_tag, options_copy);

        options_copy.lookahead = false;
        try testContext(source, expected_tag, options_copy);

        return;
    };

    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    const expected_loc: ?offsets.Loc, const cursor_index: usize = blk: {
        var expected_loc: struct { ?usize, ?usize } = .{ null, null };
        var cursor_index: ?usize = null;

        for (phr.locations.items(.old), phr.locations.items(.new)) |old_loc, new_loc| {
            std.debug.assert(new_loc.start == new_loc.end);
            const str = offsets.locToSlice(source, old_loc);
            if (std.mem.eql(u8, str, "<cursor>")) {
                if (cursor_index != null) @panic("duplicate placeholder '<cursor>'");
                cursor_index = new_loc.start;
            } else if (std.mem.eql(u8, str, "<loc>")) {
                if (expected_loc[0] != null) @panic("duplicate placeholder '<loc>'");
                expected_loc[0] = new_loc.start;
            } else if (std.mem.eql(u8, str, "</loc>")) {
                if (expected_loc[1] != null) @panic("duplicate placeholder '</loc>'");
                expected_loc[1] = new_loc.start;
            } else std.debug.panic("unknown placeholder '{s}'", .{str});
        }
        break :blk .{
            if (expected_loc[0] == null and expected_loc[1] == null)
                null
            else
                .{
                    .start = expected_loc[0] orelse @panic("missing placeholder '<loc>'"),
                    .end = expected_loc[1] orelse @panic("missing placeholder '</loc>'"),
                },
            cursor_index orelse @panic("missing placeholder '<cursor>'"),
        };
    };

    const new_source = try allocator.dupeZ(u8, phr.new_source);
    defer allocator.free(new_source);

    var tree: std.zig.Ast = try .parse(allocator, new_source, .zig);
    defer tree.deinit(allocator);

    const ctx = try Analyser.getPositionContext(allocator, tree, cursor_index, lookahead);

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile("file.zig", phr.new_source);

    try error_builder.msgAtIndex("requested position context ({s}) here", "file.zig", cursor_index, .info, .{
        if (lookahead) "with lookahead" else "without lookahead",
    });

    if (std.meta.activeTag(ctx) != expected_tag) {
        std.debug.print("Expected tag `{t}`, got `{t}`\n", .{ expected_tag, std.meta.activeTag(ctx) });
        return error.DifferentTag;
    }

    if (!std.meta.eql(expected_loc, ctx.loc(&tree))) {
        if (ctx.loc(&tree)) |actual_loc| {
            try error_builder.msgAtLoc("actual range here", "file.zig", actual_loc, .info, .{});
        }

        if (expected_loc) |expected| {
            try error_builder.msgAtLoc("expected range here", "file.zig", expected, .info, .{});
        }

        std.debug.print("expected_loc: {?}\n", .{expected_loc});
        std.debug.print("actual_loc  : {?}\n", .{ctx.loc(&tree)});
        return error.DifferentRange;
    }
}
