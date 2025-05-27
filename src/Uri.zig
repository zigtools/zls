const std = @import("std");
const builtin = @import("builtin");

const Uri = @This();

/// The raw Uri string is guaranteed to have been normalized with the following rules:
///   - consistent percent encoding (implementations may escape differently)
///   - consistent casing of the Windows drive letter
///   - consistent path seperator on Windows (convert '\\' to '/')
///   - always add an authority component even if unnecessary
///   - remove query and fragment component
raw: []const u8,

pub fn parse(allocator: std.mem.Allocator, text: []const u8) (std.Uri.ParseError || error{OutOfMemory})!Uri {
    return try parseWithOs(allocator, text, builtin.os.tag == .windows);
}

fn parseWithOs(
    allocator: std.mem.Allocator,
    text: []const u8,
    comptime is_windows: bool,
) (std.Uri.ParseError || error{OutOfMemory})!Uri {
    var uri: std.Uri = try .parse(text);

    const capacity = capacity: {
        var capacity: usize = 0;
        capacity += uri.scheme.len + ":".len + "//".len;
        if (uri.host) |host| {
            if (uri.user) |user| {
                capacity += user.percent_encoded.len;
                if (uri.password) |password| {
                    capacity += ":".len;
                    capacity += password.percent_encoded.len;
                }
                capacity += "@".len;
            }
            capacity += host.percent_encoded.len;
        }
        if (uri.port != null) capacity += comptime ":".len + std.math.log10_int(@as(usize, std.math.maxInt(u16)));
        if (!std.mem.startsWith(u8, uri.path.percent_encoded, "/")) {
            capacity += "/".len;
        }
        capacity += uri.path.percent_encoded.len;
        break :capacity capacity;
    };

    var result: std.ArrayList(u8) = try .initCapacity(allocator, capacity);
    errdefer result.deinit(allocator);

    result.appendSliceAssumeCapacity(uri.scheme);
    result.appendSliceAssumeCapacity("://");
    if (uri.host) |host| {
        if (uri.user) |user| {
            normalizePercentEncoded(&result, user.percent_encoded, &isUserChar);
            if (uri.password) |password| {
                result.appendAssumeCapacity(':');
                normalizePercentEncoded(&result, password.percent_encoded, &isPasswordChar);
            }
            result.appendAssumeCapacity('@');
        }
        normalizePercentEncoded(&result, host.percent_encoded, &isHostChar);
    }
    if (uri.port) |port| result.printAssumeCapacity(":{d}", .{port});

    if (!std.mem.startsWith(u8, uri.path.percent_encoded, "/")) {
        result.appendAssumeCapacity('/');
    }
    if (!is_windows) {
        normalizePercentEncoded(&result, uri.path.percent_encoded, &isPathChar);
    } else {
        const path_start = result.items.len;
        // do not percent encode '\\' so that we can then convert it to '/'
        normalizePercentEncoded(&result, uri.path.percent_encoded, &isPathCharWithBackslash);
        const path = result.items[path_start..];

        // normalize windows path seperator ('\\' -> '/')
        for (path) |*c| {
            if (c.* == '\\') c.* = '/';
        }

        // convert windows drive letter to lower case
        if (path.len >= 3 and
            path[0] == '/' and
            std.ascii.isUpper(path[1]) and
            path[2] == ':')
        {
            path[1] = std.ascii.toLower(path[1]);
        }
    }

    return .{ .raw = try result.toOwnedSlice(allocator) };
}

test "parse (posix)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///foo/main.zig", false);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///foo/main.zig", uri.raw);
}

test "parse (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///C:/foo\\main.zig", true);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///c:/foo/main.zig", uri.raw);
}

test "parse - UNC (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file://wsl.localhost/foo\\main.zig", true);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file://wsl.localhost/foo/main.zig", uri.raw);
}

test "parse - always add authority component (posix)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:/foo/main.zig", false);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///foo/main.zig", uri.raw);
}

test "parse - normalize percent encoding (posix)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///f%Aao%5cmain%2ezig", false);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///f%AAo%5Cmain.zig", uri.raw);
}

test "parse - convert percent encoded '\\' to '/' (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///C:%5Cmain.zig", true);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///c:/main.zig", uri.raw);
}

test "parse - preserve percent encoded '\\' (posix)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///foo%5Cmain.zig", false);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///foo%5Cmain.zig", uri.raw);
}

test "parse - percent encoded drive letter (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///%43%3a%5Cfoo\\main.zig", true);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///c:/foo/main.zig", uri.raw);
}

test "parse - windows like path on posix" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///C:%5Cmain.zig", false);
    defer uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("file:///C:%5Cmain.zig", uri.raw);
}

pub fn deinit(uri: Uri, allocator: std.mem.Allocator) void {
    allocator.free(uri.raw);
}

pub fn dupe(uri: Uri, allocator: std.mem.Allocator) error{OutOfMemory}!Uri {
    return .{ .raw = try allocator.dupe(u8, uri.raw) };
}

pub fn eql(a: Uri, b: Uri) bool {
    return std.mem.eql(u8, a.raw, b.raw);
}

pub fn toStdUri(uri: Uri) std.Uri {
    // The Uri is guranteed to be valid
    return std.Uri.parse(uri.raw) catch unreachable;
}

pub const format = @compileError("Cannot format @import(\"Uri.zig\") directly!. Access the underlying raw string field instead.");
pub const jsonStringify = @compileError("Cannot stringify @import(\"Uri.zig\") directly!. Access the underlying raw string field instead.");

pub fn ArrayHashMap(comptime V: type) type {
    return std.ArrayHashMapUnmanaged(Uri, V, Context, true);
}

const Context = struct {
    pub fn hash(self: @This(), s: Uri) u32 {
        _ = self;
        return std.array_hash_map.hashString(s.raw);
    }
    pub fn eql(self: @This(), a: Uri, b: Uri, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return std.array_hash_map.eqlString(a.raw, b.raw);
    }
};

/// Converts a file system path to a Uri.
/// Caller owns the returned memory
pub fn fromPath(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}!Uri {
    return try fromPathWithOs(allocator, path, builtin.os.tag == .windows);
}

fn fromPathWithOs(
    allocator: std.mem.Allocator,
    path: []const u8,
    comptime is_windows: bool,
) error{OutOfMemory}!Uri {
    var buf: std.ArrayList(u8) = try .initCapacity(allocator, path.len + "file:///".len);
    errdefer buf.deinit(allocator);

    buf.appendSliceAssumeCapacity("file:");
    if (is_windows and
        path.len >= 2 and
        std.fs.path.PathType.isSep(.windows, u8, path[0]) and
        std.fs.path.PathType.isSep(.windows, u8, path[1]))
    {
        // UNC path
    } else if (!std.mem.startsWith(u8, path, "/")) {
        buf.appendSliceAssumeCapacity("///");
    } else {
        buf.appendSliceAssumeCapacity("//");
    }

    var value = path;

    if (is_windows and
        path.len >= 2 and
        std.ascii.isAlphabetic(path[0]) and
        path[1] == ':')
    {
        // convert windows drive letter to lower case
        buf.appendAssumeCapacity(std.ascii.toLower(path[0]));
        value = value[1..];
    }

    for (value) |c| {
        if (is_windows and c == '\\') {
            try buf.append(allocator, '/');
            continue;
        }
        if (isPathChar(c)) {
            try buf.append(allocator, c);
        } else {
            try buf.print(allocator, "%{X:0>2}", .{c});
        }
    }

    return .{ .raw = try buf.toOwnedSlice(allocator) };
}

test "fromPath (posix)" {
    const uri = try fromPathWithOs(std.testing.allocator, "/home/main.zig", false);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///home/main.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, false);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "C:/main.zig", true);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///c:/main.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, true);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - UNC (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "\\/wsl.localhost\\foo\\main.zig", true);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file://wsl.localhost/foo/main.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, true);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - preserve '\\' (posix)" {
    const uri = try fromPathWithOs(std.testing.allocator, "/home\\main.zig", false);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///home%5Cmain.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, false);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - convert '\\' to '/' (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "C:\\main.zig", true);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///c:/main.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, true);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - root directory (posix)" {
    const uri = try fromPathWithOs(std.testing.allocator, "/", false);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, false);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - root directory (windows)" {
    const uri = try fromPathWithOs(std.testing.allocator, "C:/", true);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///c:/", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, true);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

test "fromPath - windows like path on posix" {
    const uri = try fromPathWithOs(std.testing.allocator, "/C:\\main.zig", false);
    defer uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///C:%5Cmain.zig", uri.raw);

    const reparsed_uri: Uri = try .parseWithOs(std.testing.allocator, uri.raw, false);
    defer reparsed_uri.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(reparsed_uri.raw, uri.raw);
}

pub fn isFileScheme(uri: Uri) bool {
    const scheme = for (uri.raw, 0..) |byte, i| {
        if (!isSchemeChar(byte)) break uri.raw[0..i];
    } else unreachable; // The Uri is guranteed to be valid
    return std.mem.eql(u8, scheme, "file");
}

/// Converts a Uri to a file system path.
/// Caller owns the returned memory
pub fn toFsPath(
    uri: Uri,
    allocator: std.mem.Allocator,
) error{ UnsupportedScheme, OutOfMemory }![]u8 {
    return try toFsPathWithOs(uri, allocator, builtin.os.tag == .windows);
}

fn toFsPathWithOs(
    uri: Uri,
    allocator: std.mem.Allocator,
    comptime is_windows: bool,
) error{ UnsupportedScheme, OutOfMemory }![]u8 {
    const parsed_uri = std.Uri.parse(uri.raw) catch unreachable; // The Uri is guranteed to be valid
    if (!std.mem.eql(u8, parsed_uri.scheme, "file")) return error.UnsupportedScheme;

    var aw: std.Io.Writer.Allocating = try .initCapacity(allocator, uri.raw.len);
    if (is_windows and parsed_uri.host != null) {
        const host = parsed_uri.host.?;
        aw.writer.writeAll("\\\\") catch unreachable;
        if (parsed_uri.user) |user| {
            user.formatRaw(&aw.writer) catch unreachable;
            if (parsed_uri.password) |password| {
                aw.writer.writeByte(':') catch unreachable;
                password.formatRaw(&aw.writer) catch unreachable;
            }
            aw.writer.writeByte('@') catch unreachable;
        }
        host.formatRaw(&aw.writer) catch unreachable;
        if (parsed_uri.port) |port| aw.writer.print(":{d}", .{port}) catch unreachable;
    }
    parsed_uri.path.formatRaw(&aw.writer) catch unreachable; // capacity has already been reserved
    var buf = aw.toArrayList();
    errdefer buf.deinit(allocator);

    if (is_windows and
        buf.items.len >= 3 and
        buf.items[0] == '/' and
        std.ascii.isAlphabetic(buf.items[1]) and
        buf.items[2] == ':')
    {
        // remove the extra slash
        @memmove(buf.items[0 .. buf.items.len - 1], buf.items[1..]);
        buf.items.len -= 1;
    }

    return try buf.toOwnedSlice(allocator);
}

test "toFsPath (posix)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:/foo/main.zig", false);
    defer uri.deinit(std.testing.allocator);

    const path = try uri.toFsPath(std.testing.allocator);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings("/foo/main.zig", path);

    var round_trip_uri: Uri = try .fromPathWithOs(std.testing.allocator, path, false);
    defer round_trip_uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(uri.raw, round_trip_uri.raw);
}

test "toFsPath (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:/c:/foo/main.zig", true);
    defer uri.deinit(std.testing.allocator);

    const path = try uri.toFsPathWithOs(std.testing.allocator, true);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings("c:/foo/main.zig", path);

    var round_trip_uri: Uri = try .fromPathWithOs(std.testing.allocator, path, true);
    defer round_trip_uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(uri.raw, round_trip_uri.raw);
}

test "toFsPath - UNC (windows)" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file://wsl.localhost/foo/main.zig", true);
    defer uri.deinit(std.testing.allocator);

    const path = try uri.toFsPathWithOs(std.testing.allocator, true);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings("\\\\wsl.localhost/foo/main.zig", path);

    var round_trip_uri: Uri = try .fromPathWithOs(std.testing.allocator, path, true);
    defer round_trip_uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(uri.raw, round_trip_uri.raw);
}

pub fn resolveImport(
    allocator: std.mem.Allocator,
    uri: Uri,
    parsed_uri: std.Uri,
    sub_path: []const u8,
) error{OutOfMemory}!Uri {
    var result: std.ArrayList(u8) = try .initCapacity(allocator, uri.raw.len + sub_path.len);
    {
        errdefer comptime unreachable;
        result.printAssumeCapacity("{s}:", .{parsed_uri.scheme});
        result.appendSliceAssumeCapacity("//");
        if (parsed_uri.host) |host| {
            if (parsed_uri.user) |user| {
                result.appendSliceAssumeCapacity(user.percent_encoded);
                if (parsed_uri.password) |password| {
                    result.appendAssumeCapacity(':');
                    result.appendSliceAssumeCapacity(password.percent_encoded);
                }
                result.appendAssumeCapacity('@');
            }
            result.appendSliceAssumeCapacity(host.percent_encoded);
            if (parsed_uri.port) |port| result.printAssumeCapacity(":{d}", .{port});
        }
    }
    var aw: std.Io.Writer.Allocating = .fromArrayList(allocator, &result);
    defer aw.deinit();

    const percent_encoded_path = parsed_uri.path.percent_encoded;

    const joined_path = try std.fs.path.resolvePosix(allocator, &.{ percent_encoded_path, "..", sub_path });
    defer allocator.free(joined_path);

    std.Uri.Component.percentEncode(&aw.writer, joined_path, isPathChar) catch unreachable;

    return .{ .raw = try aw.toOwnedSlice() };
}

test "resolve" {
    const uri: Uri = try .parseWithOs(std.testing.allocator, "file:///dir/main.zig", false);
    defer uri.deinit(std.testing.allocator);

    const parsed_uri = std.Uri.parse(uri.raw) catch unreachable;

    const resolved_uri = try resolveImport(std.testing.allocator, uri, parsed_uri, "foo bar.zig");
    defer resolved_uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("file:///dir/foo%20bar.zig", resolved_uri.raw);

    var round_trip_uri: Uri = try .parseWithOs(std.testing.allocator, resolved_uri.raw, false);
    defer round_trip_uri.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(round_trip_uri.raw, resolved_uri.raw);
}

fn normalizePercentEncoded(
    result: *std.ArrayList(u8),
    percent_encoded: []const u8,
    isValidChar: *const fn (u8) bool,
) void {
    var start: usize = 0;
    var index: usize = 0;
    while (std.mem.findScalarPos(u8, percent_encoded, index, '%')) |percent| {
        index = percent + 1;
        if (percent_encoded.len - index < 2) continue;

        const upper_hex, const lower_hex = percent_encoded[index..][0..2].*;
        const upper_value = std.fmt.charToDigit(upper_hex, 16) catch continue;
        const lower_value = std.fmt.charToDigit(lower_hex, 16) catch continue;
        const percent_encoded_char = upper_value * 16 + lower_value;

        if (isValidChar(percent_encoded_char)) {
            // a character has been unnecessarily escaped
            result.appendSliceAssumeCapacity(percent_encoded[start..percent]);
            result.appendAssumeCapacity(percent_encoded_char);
            start = percent + 3;
        } else if (std.ascii.isLower(upper_hex) or std.ascii.isLower(lower_hex)) {
            // convert percent encoded character to upper case
            result.appendSliceAssumeCapacity(percent_encoded[start..percent]);
            result.appendAssumeCapacity('%');
            result.appendAssumeCapacity(std.ascii.toUpper(upper_hex));
            result.appendAssumeCapacity(std.ascii.toUpper(lower_hex));
            start = percent + 3;
        } else {
            // skip properly percent encoded character
        }
        index = percent + 3;
    }
    result.appendSliceAssumeCapacity(percent_encoded[start..]);
}

/// Taken from `std.Uri`
fn isSchemeChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '+', '-', '.' => true,
        else => false,
    };
}

/// Taken from `std.Uri`
fn isSubLimit(c: u8) bool {
    return switch (c) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

/// Taken from `std.Uri`
fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// Taken from `std.Uri`
fn isUserChar(c: u8) bool {
    return isUnreserved(c) or isSubLimit(c);
}

/// Taken from `std.Uri`
fn isPasswordChar(c: u8) bool {
    return isUserChar(c) or c == ':';
}

/// Taken from `std.Uri`
fn isHostChar(c: u8) bool {
    return isPasswordChar(c) or c == '[' or c == ']';
}

/// Taken from `std.Uri`
fn isPathChar(c: u8) bool {
    return isUserChar(c) or c == '/' or c == ':' or c == '@';
}

fn isPathCharWithBackslash(c: u8) bool {
    return isUserChar(c) or c == '/' or c == ':' or c == '@' or c == '\\';
}
