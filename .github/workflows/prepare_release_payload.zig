const std = @import("std");

pub const Metadata = struct {
    zlsVersion: []const u8,
    zigVersion: []const u8,
    minimumBuildZigVersion: []const u8,
    minimumRuntimeZigVersion: []const u8,
    files: []const []const u8,
};

pub fn main() !void {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_allocator.allocator();

    const metadata_source = try std.fs.cwd().readFileAlloc(arena, "zig-out/release.json", std.math.maxInt(u32));
    const artifacts_dir = try std.fs.cwd().openDir("zig-out/artifacts", .{ .iterate = true });
    const metadata = try std.json.parseFromSliceLeaky(Metadata, arena, metadata_source, .{});

    var buffer: [4096]u8 = undefined;
    var file_writer = std.fs.File.stdout().writer(&buffer);
    try createRequestBody(&file_writer.interface, artifacts_dir, metadata, "full");
    try file_writer.interface.flush();
}

fn createRequestBody(
    writer: *std.Io.Writer,
    artifacts_dir: std.fs.Dir,
    metadata: Metadata,
    compatibility: []const u8,
) !void {
    var write_stream: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };

    try write_stream.beginObject();

    try write_stream.objectField("zlsVersion");
    try write_stream.write(metadata.zlsVersion);

    try write_stream.objectField("zigVersion");
    try write_stream.write(metadata.zigVersion);

    try write_stream.objectField("minimumBuildZigVersion");
    try write_stream.write(metadata.minimumBuildZigVersion);

    try write_stream.objectField("minimumRuntimeZigVersion");
    try write_stream.write(metadata.minimumRuntimeZigVersion);

    try write_stream.objectField("compatibility");
    try write_stream.write(compatibility);

    try write_stream.objectField("artifacts");

    try write_stream.beginObject();

    for (metadata.files) |file_name| {
        try write_stream.objectField(file_name);
        try write_stream.beginObject();

        var file = try artifacts_dir.openFile(file_name, .{});
        defer file.close();

        const stat = try file.stat();

        var sha256sum: std.crypto.hash.sha2.Sha256 = .init(.{});
        var read_buffer: [16 * 1024]u8 = undefined;
        while (true) {
            const amt = try file.read(&read_buffer);
            if (amt == 0) break;
            sha256sum.update(read_buffer[0..amt]);
        }
        std.debug.assert(sha256sum.total_len == stat.size);

        try write_stream.objectField("shasum");
        try write_stream.print("\"{x}\"", .{sha256sum.finalResult()});

        try write_stream.objectField("size");
        try write_stream.write(sha256sum.total_len);

        try write_stream.endObject();
    }

    try write_stream.endObject();
    try write_stream.endObject();
}
