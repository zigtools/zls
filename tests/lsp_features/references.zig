const std = @import("std");
const zls = @import("zls");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.lsp.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "references" {
    try testSymbolReferences(
        \\const <0> = 0;
        \\const foo = <0>;
    );
    try testSymbolReferences(
        \\var <0> = 0;
        \\var foo = <0>;
    );
    try testSymbolReferences(
        \\const <0> = struct {};
        \\var foo: <0> = <0>{};
    );
    try testSymbolReferences(
        \\const <0> = enum {};
        \\var foo: <0> = undefined;
    );
    try testSymbolReferences(
        \\const <0> = union {};
        \\var foo: <0> = <0>{};
    );
    try testSymbolReferences(
        \\fn <0>() void {}
        \\var foo = <0>();
    );
    try testSymbolReferences(
        \\const <0> = error{};
        \\fn bar() <0>!void {}
    );
}

test "global scope" {
    try testSymbolReferences(
        \\const foo = <0>;
        \\const <0> = 0;
        \\const bar = <0>;
    );
}

test "local scope" {
    try testSymbolReferences(
        \\fn foo(<0>: u32, bar: u32) void {
        \\    return <0> + bar;
        \\}
    );
    try testSymbolReferences(
        \\const foo = outer: {
        \\    _ = inner: {
        \\        const <0> = 0;
        \\        break :inner <0>;
        \\    };
        \\    const <1> = 0;
        \\    break :outer <1>;
        \\};
        \\const bar = foo;
    );
}

test "destructuring" {
    try testSymbolReferences(
        \\const blk = {
        \\    const <0>, const foo = .{ 1, 2 };
        \\    const bar = <0>;
        \\};
    );
    try testSymbolReferences(
        \\const blk = {
        \\    const foo, const <0> = .{ 1, 2 };
        \\    const bar = <0>;
        \\};
    );
}

test "for/while capture" {
    try testSymbolReferences(
        \\const blk = {
        \\    for ("") |<0>| {
        \\        _ = <0>;
        \\    }
        \\    while (false) |<1>| {
        \\        _ = <1>;
        \\    }
        \\};
    );
}

test "break/continue operands" {
    try testSymbolReferences(
        \\comptime {
        \\    const <0> = 0;
        \\    sw: switch (0) {
        \\        0 => continue :sw <0>,
        \\        else => break :sw <0>,
        \\    }
        \\}
    );
}

test "enum field access" {
    try testSymbolReferences(
        \\const E = enum {
        \\  <0>,
        \\  bar
        \\};
        \\const e = E.<0>;
    );
}

test "switch case with enum literal" {
    try testSymbolReferences(
        \\const E = enum {
        \\    <0>,
        \\    bar,
        \\};
        \\
        \\test {
        \\    const e = E.<0>;
        \\    switch (e) {
        \\        .<0> => {},
        \\        .bar => {},
        \\    }
        \\}
    );
}

test "struct field access" {
    try testSymbolReferences(
        \\const S = struct {<0>: u32 = 3};
        \\pub fn foo() bool {
        \\    const s: S = .{};
        \\    return s.<0> == s.<0>;
        \\}
    );
}

test "struct init result location from function return type" {
    try testSymbolReferences(
        \\fn foo() struct { <0>: i32 } {
        \\    return .{ .<0> = 1 };
        \\}
        \\
        \\test {
        \\    var x = foo();
        \\    x.<0> = 2;
        \\}
    );
}

test "struct decl access" {
    try testSymbolReferences(
        \\const S = struct {
        \\    fn <0>(self: S) void {}
        \\};
        \\pub fn foo() bool {
        \\    const s: S = .{};
        \\    s.<0>();
        \\    s.<0>();
        \\    <1>();
        \\}
        \\fn <1>() void {}
    );
}

test "struct one field init" {
    try testSymbolReferences(
        \\const S = struct { <0>: u32 };
        \\const s = S{ .<0> = 0 };
        \\const s2: S = .{ .<0> = 0 };
    );
}

test "struct multi-field init" {
    try testSymbolReferences(
        \\const S = struct { <0>: u32, a: bool };
        \\const s = S{ .<0> = 0, .a = true };
        \\const s2: S = .{ .<0> = 0, .a = true };
    );
}

test "decl literal on generic type" {
    try testSymbolReferences(
        \\fn Box(comptime T: type) type {
        \\    return struct {
        \\        item: T,
        \\        const <0>: @This() = undefined;
        \\    };
        \\};
        \\test {
        \\    const box: Box(u8) = .<0>;
        \\}
    );
}

test "while continue expression" {
    try testSymbolReferences(
        \\ pub fn foo() void {
        \\     var <0>: u32 = 0;
        \\     while (true) : (<0> += 1) {}
        \\ }
    );
}

test "test with identifier" {
    try testSymbolReferences(
        \\pub fn <0>() bool {}
        \\test <0> {}
        \\test "placeholder" {}
        \\test {}
    );
}

test "label" {
    try testSymbolReferences(
        \\const foo = <0>: {
        \\    break :<0> 0;
        \\};
    );
    try testSymbolReferences(
        \\const foo = <0>: {
        \\    const <1> = 0;
        \\    _ = <1>;
        \\    break :<0> 0;
        \\};
    );
    try testSymbolReferences(
        \\comptime {
        \\    <0>: switch (0) {
        \\        else => break :<0>,
        \\    }
        \\}
    );
}

test "asm" {
    try testSymbolReferences(
        \\fn foo(<0>: u32) void {
        \\    asm ("bogus"
        \\        : [ret] "={rax}" (-> void),
        \\        : [bar] "{rax}" (<0>),
        \\    );
        \\}
    );
    try testSymbolReferences(
        \\fn foo(comptime <0>: type) void {
        \\    asm ("bogus"
        \\        : [ret] "={rax}" (-> <0>),
        \\    );
        \\}
    );
}

test "function header" {
    try testSymbolReferences(
        \\fn foo(<0>: anytype) @TypeOf(<0>) {}
    );
    try testSymbolReferences(
        \\fn foo(<0>: type, bar: <0>) <0> {}
    );
}

test "switch case capture - union field" {
    try testSymbolReferences(
        \\const foo = switch (undefined) {
        \\    .foo => |<0>| <0>,
        \\};
    );
    try testSymbolReferences(
        \\const foo = switch (undefined) {
        \\    .foo => |<0>, _| <0>,
        \\};
    );
    try testSymbolReferences(
        \\const foo = switch (undefined) {
        \\    inline .foo => |<0>, _| <0>,
        \\};
    );
}

test "switch case capture - union tag" {
    try testSymbolReferences(
        \\const foo = switch (undefined) {
        \\    .foo => |_, <0>| <0>,
        \\};
    );
    try testSymbolReferences(
        \\const foo = switch (undefined) {
        \\    inline .foo => |_, <0>| <0>,
        \\};
    );
}

test "cross-file reference" {
    try testReferences(&.{
        // Untitled-0.zig
        \\pub const <0> = struct {};
        ,
        // Untitled-1.zig
        \\const file = @import("Untitled-0.zig");
        \\const <0> = file.<0>;
        \\const renamed = file.<0>;
        \\comptime {
        \\    _ = <0>;
        \\    _ = renamed;
        \\}
        ,
    }, .{ .format = .symmetric });
}

test "cross-file - transitive import" {
    try testReferences(&.{
        // Untitled-0.zig
        \\pub const <0> = struct {};
        ,
        // Untitled-1.zig
        \\pub const file = @import("Untitled-0.zig");
        ,
        // Untitled-2.zig
        \\const file = @import("Untitled-1.zig").file;
        \\const foo: file.<0> = undefined;
        ,
    }, .{ .format = .symmetric });
}

test "cross-file - alias" {
    try testReferences(&.{
        // Untitled-0.zig
        \\pub const <0> = struct {
        \\    fn foo(_: <0>) void {}
        \\    var bar: <0> = undefined;
        \\};
        ,
        // Untitled-1.zig
        \\const <0> = @import("Untitled-0.zig").<0>;
        \\comptime {
        \\    _ = <0>;
        \\}
        ,
    }, .{ .format = .symmetric });
}

test "matching control flow - unlabeled loop" {
    try testSimpleReferences(
        \\const foo = <loc>for<cursor></loc> (0..1) |i| {
        \\    <loc>break</loc> i;
        \\};
    );
    try testSimpleReferences(
        \\const foo = <loc>for</loc> (0..1) |i| {
        \\    <loc>break<cursor></loc> i;
        \\};
    );

    try testSimpleReferences(
        \\const foo = <loc>while<cursor></loc> (true) {
        \\    <loc>continue</loc>;
        \\};
    );
    try testSimpleReferences(
        \\const foo = <loc>for</loc> (0..1) |i| {
        \\    <loc>continue<cursor></loc> i;
        \\};
    );
}

test "matching control flow - labeled loop" {
    try testSimpleReferences(
        \\const foo = blk: <loc>for<cursor></loc> (0..1) |i| {
        \\    if (i == 0) {
        \\        <loc>continue</loc>;
        \\    } else {
        \\        <loc>break</loc> :blk 5;
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>for</loc> (0..1) |i| {
        \\    if (i == 0) {
        \\        <loc>continue<cursor></loc>;
        \\    } else {
        \\        break :blk 5;
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>while</loc> (true) {
        \\    if (i == 0) {
        \\        continue;
        \\    } else {
        \\        <loc>break<cursor></loc> :blk 5;
        \\    }
        \\};
    );
}

test "matching control flow - nested loop with outer label" {
    try testSimpleReferences(
        \\const foo = outer: <loc>for<cursor></loc> (0..1) |i| {
        \\    for (0..1) |j| {
        \\        if (i == j) {
        \\            break;
        \\        } else {
        \\            <loc>break</loc> :outer 5;
        \\        }
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = outer: for (0..1) |i| {
        \\    <loc>for</loc> (0..1) |j| {
        \\        if (i == j) {
        \\            <loc>break<cursor></loc>;
        \\        } else {
        \\            break :outer 5;
        \\        }
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = outer: <loc>for</loc> (0..1) |i| {
        \\    for (0..1) |j| {
        \\        if (i == j) {
        \\            break;
        \\        } else {
        \\            <loc>break<cursor></loc> :outer 5;
        \\        }
        \\    }
        \\};
    );
}

test "matching control flow - nested loop with inner label" {
    try testSimpleReferences(
        \\const foo = for (0..1) |i| {
        \\    inner: <loc>for<cursor></loc> (0..1) |j| {
        \\        if (i == j) {
        \\            <loc>break</loc>;
        \\        } else {
        \\            <loc>break</loc> :inner 5;
        \\        }
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = for (0..1) |i| {
        \\    inner: <loc>for</loc> (0..1) |j| {
        \\        if (i == j) {
        \\            <loc>break<cursor></loc>;
        \\        } else {
        \\            break :outer 5;
        \\        }
        \\    }
        \\};
    );
    try testSimpleReferences(
        \\const foo = for (0..1) |i| {
        \\    inner: <loc>for</loc> (0..1) |j| {
        \\        if (i == j) {
        \\            break;
        \\        } else {
        \\            <loc>break<cursor></loc> :inner 5;
        \\        }
        \\    }
        \\};
    );
}

test "matching control flow - labeled switch" {
    try testSimpleReferences(
        \\const foo = blk: <loc>switch<cursor></loc> (undefined) {
        \\    .foo => <loc>break</loc> :blk 5,
        \\    .bar => <loc>continue</loc> :blk 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>switch</loc> (undefined) {
        \\    .foo => <loc>break<cursor></loc> :blk 5,
        \\    .bar => continue :blk 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>switch</loc> (undefined) {
        \\    .foo => break :blk 5,
        \\    .bar => <loc>continue<cursor></loc> :blk 5,
        \\};
    );
}

test "matching control flow - unlabeled switch" {
    try testSimpleReferences(
        \\const foo = switch<cursor> (undefined) {
        \\    .foo => break 5,
        \\    .foo => continue 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = switch (undefined) {
        \\    .foo => <loc>break<cursor></loc> 5,
        \\    .foo => continue 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = switch (undefined) {
        \\    .foo => break 5,
        \\    .foo => <loc>continue<cursor></loc> 5,
        \\};
    );
}

test "escaped identifier with same name as primitive" {
    try testSimpleReferences(
        \\const <loc>@"null"<cursor></loc> = undefined;
        \\const foo = null;
        \\const bar = <loc>@"null"</loc>;
    );
    try testSimpleReferences(
        \\const <loc>@"i32"<cursor></loc> = undefined;
        \\const foo = i32;
        \\const bar = <loc>@"i32"</loc>;
    );
}

const TestOptions = struct {
    request_kind: RequestKind = .references,
    format: TestFormat,
    /// Only applies to `TestFormat.symmetric` test cases.
    placeholder_name: []const u8 = "placeholder",
};

const TestFormat = enum {
    /// The cursor position of the request is marked with `<cursor>`.
    ///
    /// The expected references are marked with `<loc>here</loc>`.
    ///
    /// Example source:
    ///
    /// ```zig
    /// const <loc>foo</loc> = 0;
    /// comptime {
    ///     _ = foo<cursor>;
    /// }
    /// ```
    asymmetric,
    /// A `textDocument/references` test on symbols that all
    /// reference each other.
    ///
    /// Example source:
    ///
    /// ```zig
    /// const <0> = 0;
    /// const foo = <0>;
    /// ```
    ///
    /// The `<0>` markers will be internally replaced with an identifier name:
    ///
    /// ```zig
    /// const placeholder = 0;
    /// const foo = placeholder;
    /// ```
    ///
    /// This test function will then verify that a references request on any of
    /// the placeholder identifiers will respond with locations to all the
    /// other identifiers.
    ///
    /// Use `<1>`, `<2>`, etc. to mark multiple distinct symbols in the same test.
    symmetric,
};

const RequestKind = enum {
    // `textDocument/references`
    references,
    // `textDocument/rename`
    rename,
    // `textDocument/documentHighlight`
    highlight,
};

fn testSimpleReferences(source: []const u8) !void {
    try testReferences(&.{source}, .{ .format = .asymmetric });
}

fn testSymbolReferences(source: []const u8) !void {
    try testReferences(&.{source}, .{ .format = .symmetric });
}

fn testReferences(
    /// source files have the following name pattern: `untitled-{d}.zig`
    sources: []const []const u8,
    options: TestOptions,
) !void {
    var ctx: Context = try .init();
    defer ctx.deinit();

    const File = struct {
        source: []const u8,
        new_source: []const u8,
        placeholders: std.MultiArrayList(helper.CollectPlaceholdersResult.LocPair),
    };

    var files: zls.Uri.ArrayHashMap(File) = .empty;
    defer {
        for (files.values()) |*file| {
            allocator.free(file.new_source);
            file.placeholders.deinit(allocator);
        }
        files.deinit(allocator);
    }

    try files.ensureTotalCapacity(allocator, sources.len);
    for (sources) |source| {
        const placeholder_name = switch (options.format) {
            .asymmetric => "", // remove placeholders
            .symmetric => options.placeholder_name,
        };
        var phr = try helper.collectReplacePlaceholders(allocator, source, placeholder_name);
        errdefer phr.deinit(allocator);

        const uri = try ctx.addDocument(.{ .source = phr.new_source });
        files.putAssumeCapacityNoClobber(uri, .{
            .source = source,
            .new_source = phr.new_source,
            .placeholders = phr.locations,
        });
    }

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    for (files.keys(), files.values()) |file_uri, file| {
        try error_builder.addFile(file_uri.raw, file.new_source);
    }

    const Position = struct { file_index: usize, source_index: usize };
    const Location = struct { file_index: usize, loc: offsets.Loc };

    var test_cases: std.ArrayList(struct {
        cursor_position: Position,
        expected_locations: std.ArrayList(Location),
    }) = .empty;
    defer {
        for (test_cases.items) |*test_case| test_case.expected_locations.deinit(allocator);
        test_cases.deinit(allocator);
    }

    switch (options.format) {
        .asymmetric => {
            const cursor_position: Position = cursor_position: for (files.values(), 0..) |*file, file_index| {
                for (file.placeholders.items(.old), file.placeholders.items(.new), 0..) |old, new, i| {
                    const name = offsets.locToSlice(file.source, old);
                    if (!std.mem.eql(u8, name, "<cursor>")) continue;
                    std.debug.assert(new.start == new.end);
                    file.placeholders.orderedRemove(i);
                    break :cursor_position .{ .file_index = file_index, .source_index = new.start };
                }
            } else @panic("missing <cursor> placeholder");

            var expected_locations: std.ArrayList(Location) = .empty;
            errdefer expected_locations.deinit(allocator);

            for (files.values(), 0..) |file, file_index| {
                std.debug.assert(file.placeholders.len % 2 == 0);
                try expected_locations.ensureUnusedCapacity(allocator, file.placeholders.len / 2);

                var i: usize = 0;
                while (i != file.placeholders.len) : (i += 2) {
                    std.debug.assert(std.mem.eql(u8, "<loc>", offsets.locToSlice(file.source, file.placeholders.items(.old)[i])));
                    std.debug.assert(std.mem.eql(u8, "</loc>", offsets.locToSlice(file.source, file.placeholders.items(.old)[i + 1])));
                    const start_loc = file.placeholders.items(.new)[i];
                    const end_loc = file.placeholders.items(.new)[i + 1];
                    std.debug.assert(start_loc.start == start_loc.end);
                    std.debug.assert(end_loc.start == end_loc.end);
                    expected_locations.appendAssumeCapacity(.{
                        .file_index = file_index,
                        .loc = .{ .start = start_loc.start, .end = end_loc.start },
                    });
                }
            }

            try test_cases.append(allocator, .{
                .cursor_position = cursor_position,
                .expected_locations = expected_locations,
            });
        },
        .symmetric => {
            const Marker = struct { file_index: usize, old: offsets.Loc, new: offsets.Loc };
            var marker_sets: std.array_hash_map.Auto(usize, std.ArrayList(Marker)) = .empty;
            defer {
                for (marker_sets.values()) |*locs| locs.deinit(allocator);
                marker_sets.deinit(allocator);
            }

            for (files.values(), 0..) |file, file_index| {
                for (file.placeholders.items(.old), file.placeholders.items(.new)) |old, new| {
                    const name = offsets.locToSlice(file.source, .{ .start = old.start + 1, .end = old.end - 1 });
                    const key = std.fmt.parseInt(usize, name, 10) catch
                        std.debug.panic("symmetric placeholder '{s}' must be a number", .{name});
                    const gop = try marker_sets.getOrPutValue(allocator, key, .empty);
                    try gop.value_ptr.append(allocator, .{ .file_index = file_index, .old = old, .new = new });
                }
            }

            for (marker_sets.values()) |markers| {
                for (markers.items) |cursor_marker| {
                    var expected_locations: std.ArrayList(Location) = try .initCapacity(allocator, markers.items.len);
                    errdefer expected_locations.deinit(allocator);

                    for (markers.items) |marker| {
                        expected_locations.appendAssumeCapacity(.{
                            .file_index = marker.file_index,
                            .loc = marker.new,
                        });
                    }

                    const cursor_loc = cursor_marker.new;
                    const middle = cursor_loc.start + (cursor_loc.end - cursor_loc.start) / 2;

                    try test_cases.append(allocator, .{
                        .cursor_position = .{ .file_index = cursor_marker.file_index, .source_index = middle },
                        .expected_locations = expected_locations,
                    });
                }
            }
        },
    }

    for (test_cases.items) |test_case| {
        const expected_locations = test_case.expected_locations;
        const cursor_file_index = test_case.cursor_position.file_index;
        const cursor_file_uri = files.keys()[cursor_file_index];

        const position = offsets.indexToPosition(
            files.values()[cursor_file_index].new_source,
            test_case.cursor_position.source_index,
            ctx.server.offset_encoding,
        );

        error_builder.clearMessages();
        try error_builder.msgAtIndex("asked for {t} here!", cursor_file_uri.raw, test_case.cursor_position.source_index, .info, .{options.request_kind});

        const actual_locations: []const types.Location = try sendRequest(
            ctx.server,
            ctx.arena.allocator(),
            options.request_kind,
            cursor_file_uri,
            position,
        ) orelse {
            std.debug.print("Server returned `null` as the result\n", .{});
            return error.InvalidResponse;
        };

        // keeps track of expected locations that have been given by the server
        // used to detect double references and missing references
        var visited: std.bit_set.Dynamic = try .initEmpty(allocator, expected_locations.items.len);
        defer visited.deinit(allocator);

        for (actual_locations) |response_location| {
            const actual_uri: zls.Uri = try .parse(allocator, response_location.uri);
            defer actual_uri.deinit(allocator);

            const actual_file_index = files.getIndex(actual_uri) orelse {
                std.debug.print("received location to unknown file `{s}` as the result\n", .{actual_uri.raw});
                return error.InvalidLocation;
            };
            const actual_file_source = files.values()[actual_file_index].new_source;
            const actual_loc = offsets.rangeToLoc(actual_file_source, response_location.range, ctx.server.offset_encoding);

            const index = for (expected_locations.items, 0..) |expected_loc, idx| {
                if (expected_loc.file_index != actual_file_index) continue;
                if (expected_loc.loc.start != actual_loc.start) continue;
                if (expected_loc.loc.end != actual_loc.end) continue;
                break idx;
            } else {
                try error_builder.msgAtLoc("server returned unexpected location", response_location.uri, actual_loc, .err, .{});
                return error.UnexpectedLocation;
            };

            if (visited.isSet(index)) {
                try error_builder.msgAtLoc("server returned duplicate location", response_location.uri, actual_loc, .err, .{});
                return error.DuplicateReference;
            } else {
                visited.set(index);
            }
        }

        var has_unvisited = false;
        var unvisited_it = visited.iterator(.{ .kind = .unset });
        while (unvisited_it.next()) |index| {
            const unvisited_file_index = expected_locations.items[index].file_index;
            const unvisited_uri = files.keys()[unvisited_file_index];
            const unvisited_loc = expected_locations.items[index].loc;
            try error_builder.msgAtLoc("expected location here", unvisited_uri.raw, unvisited_loc, .err, .{});
            has_unvisited = true;
        }

        if (has_unvisited) return error.MissingLocation;
    }
}

fn sendRequest(
    server: *zls.Server,
    arena: std.mem.Allocator,
    kind: RequestKind,
    uri: zls.Uri,
    position: types.Position,
) !?[]const types.Location {
    switch (kind) {
        .references => {
            return try server.sendRequestSync(arena, "textDocument/references", .{
                .textDocument = .{ .uri = uri.raw },
                .position = position,
                .context = .{ .includeDeclaration = true },
            });
        },
        .highlight => {
            const result: []const types.DocumentHighlight = try server.sendRequestSync(arena, "textDocument/documentHighlight", .{
                .textDocument = .{ .uri = uri.raw },
                .position = position,
            }) orelse return null;
            const locations = try arena.alloc(types.Location, result.len);
            for (locations, result) |*location, highlighting| {
                location.* = .{ .uri = uri.raw, .range = highlighting.range };
            }
            return locations;
        },
        .rename => {
            const result: types.WorkspaceEdit = try server.sendRequestSync(arena, "textDocument/rename", .{
                .textDocument = .{ .uri = uri.raw },
                .position = position,
                .newName = "placeholder",
            }) orelse return null;
            std.debug.assert(result.documentChanges == null);
            std.debug.assert(result.changeAnnotations == null);
            const changes = result.changes orelse return null;
            const text_edits = changes.map.get(uri.raw) orelse return &.{};
            const locations = try arena.alloc(types.Location, text_edits.len);
            for (locations, text_edits) |*location, text_edit| {
                location.* = .{ .uri = uri.raw, .range = text_edit.range };
            }
            return locations;
        },
    }
}
