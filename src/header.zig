const std = @import("std");
const mem = std.mem;

const RequestHeader = struct {
    content_length: usize,

    /// null implies "application/vscode-jsonrpc; charset=utf-8"
    content_type: ?[]const u8,

    pub fn deinit(self: @This(), allocator: *mem.Allocator) void {
        if (self.content_type) |ct| allocator.free(ct);
    }
};

pub fn readRequestHeader(allocator: *mem.Allocator, instream: anytype) !RequestHeader {
    var r = RequestHeader{
        .content_length = undefined,
        .content_type = null,
    };
    errdefer r.deinit(allocator);

    var has_content_length = false;
    while (true) {
        const header = try instream.readUntilDelimiterAlloc(allocator, '\n', 0x100);
        defer allocator.free(header);
        if (header.len == 0 or header[header.len - 1] != '\r') return error.MissingCarriageReturn;
        if (header.len == 1) break;

        const header_name = header[0 .. mem.indexOf(u8, header, ": ") orelse return error.MissingColon];
        const header_value = header[header_name.len + 2 .. header.len - 1];
        if (mem.eql(u8, header_name, "Content-Length")) {
            if (header_value.len == 0) return error.MissingHeaderValue;
            r.content_length = std.fmt.parseInt(usize, header_value, 10) catch return error.InvalidContentLength;
            has_content_length = true;
        } else if (mem.eql(u8, header_name, "Content-Type")) {
            r.content_type = try mem.dupe(allocator, u8, header_value);
        } else {
            return error.UnknownHeader;
        }
    }
    if (!has_content_length) return error.MissingContentLength;

    return r;
}
