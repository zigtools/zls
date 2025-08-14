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
    try testMultiFileSymbolReferences(&.{
        // TODO not putting a reference here is a hack to workaround cross-file references being broken https://github.com/zigtools/zls/issues/1071
        // for now this only tests the ability to find references within a file to a decl from another file
        \\pub const placeholder = struct {};
        ,
        \\const file = @import("test-0.zig");
        \\const first = file.<0>;
        \\const second = file.<0>;
        ,
    }, false);
}

fn testSymbolReferences(source: []const u8) !void {
    return testMultiFileSymbolReferences(&.{source}, true);
}

/// source files have the following name pattern: `test-{d}.zig`
fn testMultiFileSymbolReferences(sources: []const []const u8, include_decl: bool) !void {
    const placeholder_name = "placeholder";

    var ctx: Context = try .init();
    defer ctx.deinit();

    const File = struct { source: []const u8, new_source: []const u8 };
    const LocPair = struct { file_index: usize, old: offsets.Loc, new: offsets.Loc };

    var files: std.StringArrayHashMapUnmanaged(File) = .empty;
    defer {
        for (files.values()) |file| allocator.free(file.new_source);
        files.deinit(allocator);
    }

    var loc_set: std.StringArrayHashMapUnmanaged(std.MultiArrayList(LocPair)) = .empty;
    defer {
        for (loc_set.values()) |*locs| locs.deinit(allocator);
        loc_set.deinit(allocator);
    }

    try files.ensureTotalCapacity(allocator, sources.len);
    for (sources, 0..) |source, file_index| {
        var phr = try helper.collectReplacePlaceholders(allocator, source, placeholder_name);
        defer phr.deinit(allocator);

        const uri = try ctx.addDocument(.{ .source = phr.new_source });
        files.putAssumeCapacityNoClobber(uri, .{ .source = source, .new_source = phr.new_source });
        phr.new_source = ""; // `files` takes ownership of `new_source` from `phr`

        for (phr.locations.items(.old), phr.locations.items(.new)) |old, new| {
            const name = offsets.locToSlice(source, old);
            const gop = try loc_set.getOrPutValue(allocator, name, .{});
            try gop.value_ptr.append(allocator, .{ .file_index = file_index, .old = old, .new = new });
        }
    }

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    for (files.keys(), files.values()) |file_uri, file| {
        try error_builder.addFile(file_uri, file.new_source);
    }

    for (loc_set.values()) |locs| {
        error_builder.clearMessages();

        for (locs.items(.file_index), locs.items(.new)) |file_index, new_loc| {
            const file = files.values()[file_index];
            const file_uri = files.keys()[file_index];

            const middle = new_loc.start + (new_loc.end - new_loc.start) / 2;
            const params: types.ReferenceParams = .{
                .textDocument = .{ .uri = file_uri },
                .position = offsets.indexToPosition(file.new_source, middle, ctx.server.offset_encoding),
                .context = .{ .includeDeclaration = include_decl },
            };
            const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/references", params);

            try error_builder.msgAtLoc("asked for references here", file_uri, new_loc, .info, .{});

            const actual_locations: []const types.Location = response orelse {
                std.debug.print("Server returned `null` as the result\n", .{});
                return error.InvalidResponse;
            };

            // keeps track of expected locations that have been given by the server
            // used to detect double references and missing references
            var visited: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, locs.len);
            defer visited.deinit(allocator);

            for (actual_locations) |response_location| {
                const actual_loc = offsets.rangeToLoc(file.new_source, response_location.range, ctx.server.offset_encoding);
                const actual_file_index = files.getIndex(response_location.uri) orelse {
                    std.debug.print("received location to unknown file `{s}` as the result\n", .{response_location.uri});
                    return error.InvalidReference;
                };

                const index = found_index: {
                    for (locs.items(.new), locs.items(.file_index), 0..) |expected_loc, expected_file_index, idx| {
                        if (expected_file_index != actual_file_index) continue;
                        if (expected_loc.start != actual_loc.start) continue;
                        if (expected_loc.end != actual_loc.end) continue;
                        break :found_index idx;
                    }
                    try error_builder.msgAtLoc("server returned unexpected reference!", file_uri, actual_loc, .err, .{});
                    return error.UnexpectedReference;
                };

                if (visited.isSet(index)) {
                    try error_builder.msgAtLoc("server returned duplicate reference!", file_uri, actual_loc, .err, .{});
                    return error.DuplicateReference;
                } else {
                    visited.set(index);
                }
            }

            var has_unvisited = false;
            var unvisited_it = visited.iterator(.{ .kind = .unset });
            while (unvisited_it.next()) |index| {
                const unvisited_file_index = locs.items(.file_index)[index];
                const unvisited_uri = files.keys()[unvisited_file_index];
                const unvisited_loc = locs.items(.new)[index];
                try error_builder.msgAtLoc("expected reference here!", unvisited_uri, unvisited_loc, .err, .{});
                has_unvisited = true;
            }

            if (has_unvisited) return error.ExpectedReference;
        }
    }
}

test "matching control flow - unlabeled loop" {
    try testSimpleReferences(
        \\const foo = for<cursor> (0..1) |i| {
        \\    <loc>break</loc> i;
        \\};
    );
    try testSimpleReferences(
        \\const foo = <loc>for</loc> (0..1) |i| {
        \\    break<cursor> i;
        \\};
    );

    try testSimpleReferences(
        \\const foo = while<cursor> (true) {
        \\    <loc>continue</loc>;
        \\};
    );
    try testSimpleReferences(
        \\const foo = <loc>for</loc> (0..1) |i| {
        \\    continue<cursor> i;
        \\};
    );
}

test "matching control flow - labeled loop" {
    try testSimpleReferences(
        \\const foo = blk: for<cursor> (0..1) |i| {
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
        \\        continue<cursor>;
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
        \\        break<cursor> :blk 5;
        \\    }
        \\};
    );
}

test "matching control flow - nested loop with outer label" {
    try testSimpleReferences(
        \\const foo = outer: for<cursor> (0..1) |i| {
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
        \\            break<cursor>;
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
        \\            break<cursor> :outer 5;
        \\        }
        \\    }
        \\};
    );
}

test "matching control flow - nested loop with inner label" {
    try testSimpleReferences(
        \\const foo = for (0..1) |i| {
        \\    inner: for<cursor> (0..1) |j| {
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
        \\            break<cursor>;
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
        \\            break<cursor> :inner 5;
        \\        }
        \\    }
        \\};
    );
}

test "matching control flow - labeled switch" {
    try testSimpleReferences(
        \\const foo = blk: switch<cursor> (undefined) {
        \\    .foo => <loc>break</loc> :blk 5,
        \\    .bar => <loc>continue</loc> :blk 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>switch</loc> (undefined) {
        \\    .foo => break<cursor> :blk 5,
        \\    .bar => continue :blk 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = blk: <loc>switch</loc> (undefined) {
        \\    .foo => break :blk 5,
        \\    .bar => continue<cursor> :blk 5,
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
        \\    .foo => break<cursor> 5,
        \\    .foo => continue 5,
        \\};
    );
    try testSimpleReferences(
        \\const foo = switch (undefined) {
        \\    .foo => break 5,
        \\    .foo => continue<cursor> 5,
        \\};
    );
}

fn testSimpleReferences(source: []const u8) !void {
    var phr = try helper.collectClearPlaceholders(allocator, source);
    defer phr.deinit(allocator);

    std.debug.assert(phr.locations.len % 2 == 1);
    var expected_locations: std.ArrayList(offsets.Loc) = try .initCapacity(allocator, phr.locations.len / 2);
    defer expected_locations.deinit(allocator);

    const cursor_index = for (phr.locations.items(.old), phr.locations.items(.new), 0..) |old, new, i| {
        const name = offsets.locToSlice(source, old);
        if (!std.mem.eql(u8, name, "<cursor>")) continue;
        phr.locations.orderedRemove(i);
        std.debug.assert(new.start == new.end);
        break new.start;
    } else @panic("missing <cursor> placeholder");

    {
        var i: usize = 0;
        while (i != phr.locations.len) : (i += 2) {
            std.debug.assert(std.mem.eql(u8, "<loc>", offsets.locToSlice(source, phr.locations.items(.old)[i])));
            std.debug.assert(std.mem.eql(u8, "</loc>", offsets.locToSlice(source, phr.locations.items(.old)[i + 1])));
            const start_loc = phr.locations.items(.new)[i];
            const end_loc = phr.locations.items(.new)[i + 1];
            std.debug.assert(start_loc.start == start_loc.end);
            std.debug.assert(end_loc.start == end_loc.end);
            expected_locations.appendAssumeCapacity(.{ .start = start_loc.start, .end = end_loc.start });
        }
    }

    var ctx: Context = try .init();
    defer ctx.deinit();

    const file_uri = try ctx.addDocument(.{ .source = phr.new_source });

    var error_builder: ErrorBuilder = .init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(file_uri, phr.new_source);
    try error_builder.msgAtIndex("requested references here", file_uri, cursor_index, .info, .{});

    const params: types.ReferenceParams = .{
        .textDocument = .{ .uri = file_uri },
        .position = offsets.indexToPosition(phr.new_source, cursor_index, ctx.server.offset_encoding),
        .context = .{ .includeDeclaration = false },
    };
    const actual_locations: []const types.Location = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/references", params) orelse {
        std.debug.print("Server returned `null` as the result\n", .{});
        return error.InvalidResponse;
    };

    // keeps track of expected locations that have been given by the server
    // used to detect double references and missing references
    var visited: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, expected_locations.items.len);
    defer visited.deinit(allocator);

    for (actual_locations) |response_location| {
        std.debug.assert(std.mem.eql(u8, response_location.uri, file_uri));
        const actual_loc = offsets.rangeToLoc(phr.new_source, response_location.range, ctx.server.offset_encoding);

        const index = found_index: {
            for (expected_locations.items, 0..) |expected_loc, idx| {
                if (expected_loc.start != actual_loc.start) continue;
                if (expected_loc.end != actual_loc.end) continue;
                break :found_index idx;
            }
            try error_builder.msgAtLoc("server returned unexpected reference!", file_uri, actual_loc, .err, .{});
            return error.UnexpectedReference;
        };

        if (visited.isSet(index)) {
            try error_builder.msgAtLoc("server returned duplicate reference!", file_uri, actual_loc, .err, .{});
            return error.DuplicateReference;
        } else {
            visited.set(index);
        }
    }

    var has_unvisited = false;
    var unvisited_it = visited.iterator(.{ .kind = .unset });
    while (unvisited_it.next()) |index| {
        const unvisited_loc = expected_locations.items[index];
        try error_builder.msgAtLoc("expected reference here!", file_uri, unvisited_loc, .err, .{});
        has_unvisited = true;
    }

    if (has_unvisited) return error.ExpectedReference;
}
