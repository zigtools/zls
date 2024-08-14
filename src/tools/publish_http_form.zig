//! Sends a `multipart/form-data` Http POST request
//!
//! The CLI imitates [cURL](https://curl.se/).

const std = @import("std");

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_allocator.allocator();

    var arg_it = try std.process.argsWithAllocator(arena);
    defer arg_it.deinit();
    _ = arg_it.skip();

    var uri: ?std.Uri = null;
    var authorization: std.http.Client.Request.Headers.Value = .default;
    var form_fields = std.ArrayList(FormField).init(arena);

    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--user")) {
            const usename_password = arg_it.next() orelse @panic("expected argument after --user");
            const base64_encode_buffer = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(usename_password.len));
            const auth = std.base64.standard.Encoder.encode(base64_encode_buffer, usename_password);
            authorization = .{ .override = try std.fmt.allocPrint(arena, "Basic {s}", .{auth}) };
        } else if (std.mem.eql(u8, arg, "-F") or std.mem.eql(u8, arg, "--form")) {
            const form = arg_it.next() orelse std.debug.panic("expected argument after {s}!", .{arg});
            var it = std.mem.splitScalar(u8, form, '=');
            const name = it.next() orelse std.debug.panic("invalid argument '{s}' after {s}!", .{ form, arg });
            const content = it.next() orelse std.debug.panic("invalid argument '{s}' after {s}!", .{ form, arg });
            if (it.next() != null) std.debug.panic("invalid argument '{s}' after {s}!", .{ form, arg });
            const form_field: FormField = blk: {
                if (std.mem.startsWith(u8, content, "@")) {
                    const file = try std.fs.cwd().openFile(content[1..], .{});
                    defer file.close();

                    break :blk .{
                        .name = try arena.dupe(u8, name),
                        .filename = std.fs.path.basename(content[1..]),
                        .value = try file.readToEndAlloc(arena, std.math.maxInt(usize)),
                    };
                }
                break :blk .{
                    .name = try arena.dupe(u8, name),
                    .value = try arena.dupe(u8, content),
                };
            };
            try form_fields.append(form_field);
        } else if (uri == null) {
            uri = try std.Uri.parse(arg);
        } else {
            std.debug.panic("unknown argument '{s}'!", .{arg});
        }
    }

    var boundary: [64 + 3]u8 = undefined;
    std.debug.assert((std.fmt.bufPrint(
        &boundary,
        "{x:0>16}-{x:0>16}-{x:0>16}-{x:0>16}",
        .{ std.crypto.random.int(u64), std.crypto.random.int(u64), std.crypto.random.int(u64), std.crypto.random.int(u64) },
    ) catch unreachable).len == boundary.len);

    const body = try createMultiPartFormDataBody(arena, &boundary, form_fields.items);

    const headers: std.http.Client.Request.Headers = .{
        .content_type = .{ .override = try std.fmt.allocPrint(arena, "multipart/form-data; boundary={s}", .{boundary}) },
        .authorization = authorization,
    };

    var client: std.http.Client = .{ .allocator = arena };
    defer client.deinit();
    try client.initDefaultProxies(arena);

    var server_header_buffer: [16 * 1024]u8 = undefined;
    var request = try client.open(.POST, uri orelse @panic("expected URI"), .{
        .keep_alive = false,
        .server_header_buffer = &server_header_buffer,
        .headers = headers,
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

pub const FormField = struct {
    name: []const u8,
    filename: ?[]const u8 = null,
    content_type: std.http.Client.Request.Headers.Value = .default,
    value: []const u8,
};

fn createMultiPartFormDataBody(
    allocator: std.mem.Allocator,
    boundary: []const u8,
    fields: []const FormField,
) error{OutOfMemory}![]const u8 {
    var body: std.ArrayListUnmanaged(u8) = .{};
    errdefer body.deinit(allocator);
    const writer = body.writer(allocator);

    for (fields) |field| {
        try writer.print("--{s}\r\n", .{boundary});

        if (field.filename) |filename| {
            try writer.print("Content-Disposition: form-data; name=\"{s}\"; filename=\"{s}\"\r\n", .{ field.name, filename });
        } else {
            try writer.print("Content-Disposition: form-data; name=\"{s}\"\r\n", .{field.name});
        }

        switch (field.content_type) {
            .default => {
                if (field.filename != null) {
                    try writer.writeAll("Content-Type: application/octet-stream\r\n");
                }
            },
            .omit => {},
            .override => |content_type| {
                try writer.print("Content-Type: {s}\r\n", .{content_type});
            },
        }

        try writer.writeAll("\r\n");
        try writer.writeAll(field.value);
        try writer.writeAll("\r\n");
    }
    try writer.print("--{s}--\r\n", .{boundary});

    return try body.toOwnedSlice(allocator);
}

test createMultiPartFormDataBody {
    const body = try createMultiPartFormDataBody(std.testing.allocator, "AAAA-BBBB-CCCC-DDDD", &.{
        .{
            .name = "zls-version",
            .value = "0.14.0",
        },
        .{
            .name = "compatibility",
            .content_type = .{ .override = "application/json" },
            .value = "full",
        },
        .{
            .name = "zig-version",
            .value = "0.15.0",
        },
        .{
            .name = "zls-linux-x86_64-0.14.0-dev.77+3ec8ad16.tar.xz",
            .filename = "publish.zig",
            .value = "const std = @import(\"std\");",
        },
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "--AAAA-BBBB-CCCC-DDDD\r\n" ++
            "Content-Disposition: form-data; name=\"zls-version\"\r\n" ++
            "\r\n" ++
            "0.14.0\r\n" ++
            "--AAAA-BBBB-CCCC-DDDD\r\n" ++
            "Content-Disposition: form-data; name=\"compatibility\"\r\n" ++
            "Content-Type: application/json\r\n" ++
            "\r\n" ++
            "full\r\n" ++
            "--AAAA-BBBB-CCCC-DDDD\r\n" ++
            "Content-Disposition: form-data; name=\"zig-version\"\r\n" ++
            "\r\n" ++
            "0.15.0\r\n" ++
            "--AAAA-BBBB-CCCC-DDDD\r\n" ++
            "Content-Disposition: form-data; name=\"zls-linux-x86_64-0.14.0-dev.77+3ec8ad16.tar.xz\"; filename=\"publish.zig\"\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "\r\n" ++
            "const std = @import(\"std\");\r\n" ++
            "--AAAA-BBBB-CCCC-DDDD--\r\n",
        body,
    );
}
