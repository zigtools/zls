const std = @import("std");
const assert = std.debug.assert;

pub fn main() !void {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_allocator.allocator();

    const args = try std.process.argsAlloc(arena);
    var arg_i: usize = 1;

    assert(std.mem.eql(u8, "--zls-version", nextArg(args, &arg_i).?));
    const zls_version = nextArg(args, &arg_i).?;
    assert(std.mem.eql(u8, "--zig-version", nextArg(args, &arg_i).?));
    const zig_version = nextArg(args, &arg_i).?;
    assert(std.mem.eql(u8, "--minimum-build-zig-version", nextArg(args, &arg_i).?));
    const minimum_build_zig_version = nextArg(args, &arg_i).?;
    assert(std.mem.eql(u8, "--minimum-runtime-zig-version", nextArg(args, &arg_i).?));
    const minimum_runtime_zig_version = nextArg(args, &arg_i).?;
    assert(std.mem.eql(u8, "--compatibility", nextArg(args, &arg_i).?));
    const compatibility = nextArg(args, &arg_i).?;

    var output_buffer: std.ArrayListUnmanaged(u8) = .empty;

    var write_stream = std.json.writeStream(output_buffer.writer(arena), .{ .whitespace = .indent_2 });

    try write_stream.beginObject();

    try write_stream.objectField("zlsVersion");
    try write_stream.write(zls_version);

    try write_stream.objectField("zigVersion");
    try write_stream.write(zig_version);

    try write_stream.objectField("minimumBuildZigVersion");
    try write_stream.write(minimum_build_zig_version);

    try write_stream.objectField("minimumRuntimeZigVersion");
    try write_stream.write(minimum_runtime_zig_version);

    try write_stream.objectField("compatibility");
    try write_stream.write(compatibility);

    try write_stream.objectField("artifacts");

    try write_stream.beginObject();

    while (nextArg(args, &arg_i)) |file_path| {
        const file_name = std.fs.path.basename(file_path);

        try write_stream.objectField(file_name);
        try write_stream.beginObject();

        var file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const stat = try file.stat();

        var sha256sum: std.crypto.hash.sha2.Sha256 = .init(.{});
        var read_buffer: [16 * 1024]u8 = undefined;
        while (true) {
            const amt = try file.read(&read_buffer);
            if (amt == 0) break;
            sha256sum.update(read_buffer[0..amt]);
        }
        assert(sha256sum.total_len == stat.size);

        const hash = sha256sum.finalResult();

        try write_stream.objectField("shasum");
        try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(&hash)});

        try write_stream.objectField("size");
        try write_stream.write(sha256sum.total_len);

        try write_stream.endObject();
        try std.fs.cwd().access(file_path, .{});
    }

    try write_stream.endObject();

    try write_stream.endObject();

    try std.io.getStdOut().writeAll(output_buffer.items);
}

fn nextArg(args: []const [:0]const u8, i: *usize) ?[:0]const u8 {
    if (i.* >= args.len) return null;
    defer i.* += 1;
    return args[i.*];
}
