const std = @import("std");

const Header = @This();

content_length: usize,

/// null implies "application/vscode-jsonrpc; charset=utf-8"
content_type: ?[]const u8 = null,

pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
    if (self.content_type) |ct| allocator.free(ct);
}

// Caller owns returned memory.
pub fn parse(allocator: std.mem.Allocator, reader: anytype) !Header {
    var r = Header{
        .content_length = undefined,
        .content_type = null,
    };
    errdefer r.deinit(allocator);

    var has_content_length = false;
    while (true) {
        const header = try reader.readUntilDelimiterAlloc(allocator, '\n', 0x100);
        defer allocator.free(header);
        if (header.len == 0 or header[header.len - 1] != '\r') return error.MissingCarriageReturn;
        if (header.len == 1) break;

        const header_name = header[0 .. std.mem.indexOf(u8, header, ": ") orelse return error.MissingColon];
        const header_value = header[header_name.len + 2 .. header.len - 1];
        if (std.mem.eql(u8, header_name, "Content-Length")) {
            if (header_value.len == 0) return error.MissingHeaderValue;
            r.content_length = std.fmt.parseInt(usize, header_value, 10) catch return error.InvalidContentLength;
            has_content_length = true;
        } else if (std.mem.eql(u8, header_name, "Content-Type")) {
            r.content_type = try allocator.dupe(u8, header_value);
        } else {
            return error.UnknownHeader;
        }
    }
    if (!has_content_length) return error.MissingContentLength;

    return r;
}

pub fn write(header: Header, writer: anytype) @TypeOf(writer).Error!void {
    try writer.print("Content-Length: {}\r\n", .{header.content_length});
    if (header.content_type) |content_type| {
        try writer.print("Content-Type: {s}\r\n", .{content_type});
    }
    try writer.writeAll("\r\n");
}
