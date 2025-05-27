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
        const base64_encode_buffer = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(usename_password.len));
        const auth = std.base64.standard.Encoder.encode(base64_encode_buffer, usename_password);
        break :authorization .{ .override = try std.fmt.allocPrint(arena, "Basic {s}", .{auth}) };
    };

    const body = try createRequestBody(arena, artifacts_dir, metadata, "full");

    var client: std.http.Client = .{ .allocator = arena };
    defer client.deinit();
    try client.initDefaultProxies(arena);

    var server_header_buffer: [16 * 1024]u8 = undefined;
    var request = try client.open(.POST, uri, .{
        .keep_alive = false,
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = authorization,
        },
    });
    defer request.deinit();
    request.transfer_encoding = .{ .content_length = body.len };

    try request.send();
    try request.writeAll(body);
    try request.finish();
    try request.wait();

    if (request.response.status.class() == .success) return;

    std.log.err("response {s} ({d}): {s}", .{
        request.response.status.phrase() orelse "",
        @intFromEnum(request.response.status),
        try request.reader().readAllAlloc(arena, 1024 * 1024),
    });
    std.process.exit(1);
}

fn createRequestBody(
    arena: std.mem.Allocator,
    artifacts_dir: std.fs.Dir,
    metadata: Metadata,
    compatibility: []const u8,
) ![]const u8 {
    var output_buffer: std.ArrayListUnmanaged(u8) = .empty;

    var write_stream = std.json.writeStream(output_buffer.writer(arena), .{ .whitespace = .indent_2 });

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

        const hash = sha256sum.finalResult();

        try write_stream.objectField("shasum");
        try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(&hash)});

        try write_stream.objectField("size");
        try write_stream.write(sha256sum.total_len);

        try write_stream.endObject();
    }

    try write_stream.endObject();
    try write_stream.endObject();

    return output_buffer.items;
}

fn nextArg(args: []const [:0]const u8, i: *usize) ?[:0]const u8 {
    if (i.* >= args.len) return null;
    defer i.* += 1;
    return args[i.*];
}
