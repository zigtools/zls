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
    try testReferences(
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

test "references - destructuring" {
    try testReferences(
        \\const blk = {
        \\    const <0>, const foo = .{ 1, 2 };
        \\    const bar = <0>;
        \\};
    );
    try testReferences(
        \\const blk = {
        \\    const foo, const <0> = .{ 1, 2 };
        \\    const bar = <0>;
        \\};
    );
}

test "references - for/while capture" {
    try testReferences(
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

test "references - test with identifier" {
    try testReferences(
        \\pub fn <0>() bool {}
        \\test <0> {}
    );
}

test "references - label" {
    try testReferences(
        \\const foo = <0>: {
        \\    break :<0> 0;
        \\};
    );
}

test "references - asm" {
    try testReferences(
        \\fn foo(<0>: u32) void {
        \\    asm ("bogus"
        \\        : [ret] "={rax}" (-> void),
        \\        : [bar] "{rax}" (<0>),
        \\    );
        \\}
    );
    try testReferences(
        \\fn foo(comptime <0>: type) void {
        \\    asm ("bogus"
        \\        : [ret] "={rax}" (-> <0>),
        \\    );
        \\}
    );
}

test "references - function header" {
    try testReferences(
        \\fn foo(<0>: anytype) @TypeOf(<0>) {}
    );
    try testReferences(
        \\fn foo(<0>: type, bar: <0>) <0> {}
    );
}

test "references - cross-file reference" {
    if (true) return error.SkipZigTest; // TODO
    try testMFReferences(&.{
        \\pub const <0> = struct {};
        ,
        \\const file = @import("file_0.zig");
        \\const F = file.<0>;
    });
}

fn testReferences(source: []const u8) !void {
    return testMFReferences(&.{source});
}

/// source files have the following name pattern: `file_{d}.zig`
fn testMFReferences(sources: []const []const u8) !void {
    const placeholder_name = "placeholder";

    var ctx = try Context.init();
    defer ctx.deinit();

    const File = struct { source: []const u8, new_source: []const u8 };
    const LocPair = struct { file_index: usize, old: offsets.Loc, new: offsets.Loc };

    var files = std.StringArrayHashMapUnmanaged(File){};
    defer {
        for (files.values()) |file| allocator.free(file.new_source);
        files.deinit(allocator);
    }

    var loc_set: std.StringArrayHashMapUnmanaged(std.MultiArrayList(LocPair)) = .{};
    defer {
        for (loc_set.values()) |*locs| locs.deinit(allocator);
        loc_set.deinit(allocator);
    }

    try files.ensureTotalCapacity(allocator, sources.len);
    for (sources, 0..) |source, file_index| {
        var phr = try helper.collectReplacePlaceholders(allocator, source, placeholder_name);
        defer phr.deinit(allocator);

        const uri = try ctx.addDocument(phr.new_source);
        files.putAssumeCapacityNoClobber(uri, .{ .source = source, .new_source = phr.new_source });
        phr.new_source = ""; // `files` takes ownership of `new_source` from `phr`

        for (phr.locations.items(.old), phr.locations.items(.new)) |old, new| {
            const name = offsets.locToSlice(source, old);
            const gop = try loc_set.getOrPutValue(allocator, name, .{});
            try gop.value_ptr.append(allocator, .{ .file_index = file_index, .old = old, .new = new });
        }
    }

    var error_builder = ErrorBuilder.init(allocator);
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
            const params = types.ReferenceParams{
                .textDocument = .{ .uri = file_uri },
                .position = offsets.indexToPosition(file.new_source, middle, ctx.server.offset_encoding),
                .context = .{ .includeDeclaration = true },
            };
            const response = try ctx.server.sendRequestSync(ctx.arena.allocator(), "textDocument/references", params);

            try error_builder.msgAtLoc("asked for references here", file_uri, new_loc, .info, .{});

            const actual_locations: []const types.Location = response orelse {
                std.debug.print("Server returned `null` as the result\n", .{});
                return error.InvalidResponse;
            };

            // keeps track of expected locations that have been given by the server
            // used to detect double references and missing references
            var visited = try std.DynamicBitSetUnmanaged.initEmpty(allocator, locs.len);
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
