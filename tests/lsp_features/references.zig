const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("../helper.zig");
const Context = @import("../context.zig").Context;
const ErrorBuilder = @import("../ErrorBuilder.zig");

const types = zls.types;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

test "references" {
    try testReferences(
        \\const <0> = 0;
        \\const foo = <0>;
    );
    try testReferences(
        \\var <0> = 0;
        \\var foo = <0>;
    );
    try testReferences(
        \\const <0> = struct {};
        \\var foo: <0> = <0>{};
    );
    try testReferences(
        \\const <0> = enum {};
        \\var foo: <0> = undefined;
    );
    try testReferences(
        \\const <0> = union {};
        \\var foo: <0> = <0>{};
    );
    try testReferences(
        \\fn <0>() void {}
        \\var foo = <0>();
    );
    try testReferences(
        \\const <0> = error{};
        \\fn bar() <0>!void {}
    );
}

test "references - global scope" {
    try testReferences(
        \\const foo = <0>;
        \\const <0> = 0;
        \\const bar = <0>;
    );
}

test "references - local scope" {
    try testReferences(
        \\fn foo(<0>: u32, bar: u32) void {
        \\    return <0> + bar;
        \\}
    );
    if (true) return error.SkipZigTest; // TODO
    try testReferences(
        \\const foo = blk: {
        \\    _ = blk: {
        \\        const <0> = 0;
        \\        break :blk <0>;
        \\    };
        \\    const <1> = 0;
        \\    break :blk <1>;
        \\};
        \\const bar = foo;
    );
}

test "references - struct field access" {
    if (true) return error.SkipZigTest; // TODO
    try testReferences(
        \\const S = struct {placeholder: u32 = 3};
        \\pub fn foo() bool {
        \\    const s: S = .{};
        \\    return s.<0> == s.<0>;
        \\}
    );
}

test "references - struct decl access" {
    try testReferences(
        \\const S = struct {
        \\    fn <0>() void {}
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

test "references - while continue expression" {
    try testReferences(
        \\ pub fn foo() void {
        \\     var <0>: u32 = 0;
        \\     while (true) : (<0> += 1) {}
        \\ }
    );
}

test "references - label" {
    if (true) return error.SkipZigTest; // TODO
    try testReferences(
        \\const foo = <0>: {
        \\    break :<0> 0;
        \\};
    );
}

fn testReferences(source: []const u8) !void {
    const new_name = "placeholder";

    var phr = try helper.collectReplacePlaceholders(allocator, source, new_name);
    defer phr.deinit(allocator);

    var ctx = try Context.init();
    defer ctx.deinit();

    const file_uri = try ctx.addDocument(phr.new_source);

    try std.testing.expect(phr.locations.len != 0);

    var i: usize = 0;
    while (i < phr.locations.len) : (i += 1) {
        const var_loc = phr.locations.items(.old)[i];
        const var_name = offsets.locToSlice(source, var_loc);
        const var_loc_middle = var_loc.start + (var_loc.end - var_loc.start) / 2;

        const params = types.ReferenceParams{
            .textDocument = .{ .uri = file_uri },
            .position = offsets.indexToPosition(source, var_loc_middle, ctx.server.offset_encoding),
            .context = .{ .includeDeclaration = true },
        };

        const response = try ctx.requestGetResponse(?[]types.Location, "textDocument/references", params);

        var error_builder = ErrorBuilder.init(allocator, phr.new_source);
        defer error_builder.deinit();
        errdefer {
            const note_loc = phr.locations.items(.new)[i];
            error_builder.msgAtLoc("asked for references here", note_loc, .info, .{}) catch {};
            error_builder.writeDebug();
        }

        const locations: []types.Location = response.result orelse {
            std.debug.print("Server returned `null` as the result\n", .{});
            return error.InvalidResponse;
        };

        for (locations) |response_location| {
            const actual_name = offsets.rangeToSlice(phr.new_source, response_location.range, ctx.server.offset_encoding);
            try std.testing.expectEqualStrings(file_uri, response_location.uri);
            try std.testing.expectEqualStrings(new_name, actual_name);
        }

        // collect all new placeholder locations with the given name
        const expected_locs: []offsets.Loc = blk: {
            var locs = std.ArrayListUnmanaged(offsets.Loc){};
            errdefer locs.deinit(allocator);

            var j: usize = 0;
            while (j < phr.locations.len) : (j += 1) {
                const old_loc = phr.locations.items(.old)[j];
                const new_loc = phr.locations.items(.new)[j];

                const old_loc_name = offsets.locToSlice(source, old_loc);
                if (!std.mem.eql(u8, var_name, old_loc_name)) continue;
                try locs.append(allocator, new_loc);
            }

            break :blk try locs.toOwnedSlice(allocator);
        };
        defer allocator.free(expected_locs);

        // keeps track of expected locations that have been given by the server
        // used to detect double references and missing references
        var visited = try std.DynamicBitSetUnmanaged.initEmpty(allocator, expected_locs.len);
        defer visited.deinit(allocator);

        for (locations) |response_location| {
            const actual_loc = offsets.rangeToLoc(phr.new_source, response_location.range, ctx.server.offset_encoding);

            const index = found_index: {
                for (expected_locs) |expected_loc, idx| {
                    if (expected_loc.start != actual_loc.start) continue;
                    if (expected_loc.end != actual_loc.end) continue;
                    break :found_index idx;
                }
                try error_builder.msgAtLoc("server returned unexpected reference!", actual_loc, .err, .{});
                return error.UnexpectedReference;
            };

            if (visited.isSet(index)) {
                try error_builder.msgAtLoc("server returned duplicate reference!", actual_loc, .err, .{});
                return error.DuplicateReference;
            } else {
                visited.set(index);
            }
        }

        var has_unvisited = false;
        var unvisited_it = visited.iterator(.{ .kind = .unset });
        while (unvisited_it.next()) |index| {
            try error_builder.msgAtLoc("expected reference here!", expected_locs[index], .err, .{});
            has_unvisited = true;
        }

        if (has_unvisited) return error.ExpectedReference;
    }
}
