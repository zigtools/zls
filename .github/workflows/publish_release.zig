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

    const env_map = try std.process.getEnvMap(arena);

    const uri: std.Uri = if (env_map.get("ZLS_WORKER_ENDPOINT")) |endpoint| blk: {
        var uri = std.Uri.parse(endpoint) catch std.debug.panic("invalid URI: '{s}'", .{endpoint});
        if (!uri.path.isEmpty()) std.debug.panic("ZLS_WORKER_ENDPOINT URI must have no path component: '{s}'", .{endpoint});
        uri.path = .{ .raw = "/v1/zls/publish" };
        break :blk uri;
    } else .{
        .scheme = "https",
        .host = .{ .raw = "releases.zigtools.org" },
        .path = .{ .raw = "/v1/zls/publish" },
    };

    const authorization: std.http.Client.Request.Headers.Value = authorization: {
        const zls_worker_api_token = env_map.get("ZLS_WORKER_API_TOKEN") orelse "amogus";
        const usename_password = try std.fmt.allocPrint(arena, "admin:{s}", .{zls_worker_api_token});
        break :authorization .{ .override = try std.fmt.allocPrint(arena, "Basic {b64}", .{usename_password}) };
    };

    const body = try createRequestBody(arena, artifacts_dir, metadata, "full");

    var client: std.http.Client = .{ .allocator = arena };
    defer client.deinit();
    try client.initDefaultProxies(arena);

    var aw: std.Io.Writer.Allocating = .init(arena);
    defer aw.deinit();

    const result = try client.fetch(.{
        .response_writer = &aw.writer,
        .location = .{ .uri = uri },
        .method = .POST,
        .payload = body,
        .keep_alive = false,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = authorization,
        },
    });

    if (result.status.class() != .success) {
        std.process.fatal("response {s} ({d}): {s}", .{
            result.status.phrase() orelse "",
            @intFromEnum(result.status),
            aw.written(),
        });
    }
}

fn createRequestBody(
    arena: std.mem.Allocator,
    artifacts_dir: std.fs.Dir,
    metadata: Metadata,
    compatibility: []const u8,
) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);

    var write_stream: std.json.Stringify = .{
        .writer = &aw.writer,
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

    return try aw.toOwnedSlice();
}

fn nextArg(args: []const [:0]const u8, i: *usize) ?[:0]const u8 {
    if (i.* >= args.len) return null;
    defer i.* += 1;
    return args[i.*];
}
