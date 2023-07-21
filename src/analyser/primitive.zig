const std = @import("std");

pub const PrimitiveType = union(enum) {
    uint: u16,
    int: u16,
    null,
    undefined,
    isize,
    usize,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_ulonglong,
    c_longdouble,
    anyopaque,
    f16,
    f32,
    f64,
    f80,
    f128,
    bool,
    void,
    noreturn,
    type,
    anyerror,
    comptime_int,
    comptime_float,
    @"anyframe",
    @"anytype",
    c_char,

    pub fn fromValueIdent(text: []const u8) ?PrimitiveType {
        const map = std.ComptimeStringMap(PrimitiveType, .{
            .{ "true", .bool },
            .{ "false", .bool },
            .{ "null", .null },
            .{ "undefined", .undefined },
        });

        return map.get(text);
    }

    pub fn fromTypeIdent(text: []const u8) ?PrimitiveType {
        const map = std.ComptimeStringMap(PrimitiveType, .{
            .{ "isize", .isize },               .{ "usize", .usize },
            .{ "c_short", .c_short },           .{ "c_ushort", .c_ushort },
            .{ "c_int", .c_int },               .{ "c_uint", .c_uint },
            .{ "c_long", .c_long },             .{ "c_ulong", .c_ulong },
            .{ "c_longlong", .c_longlong },     .{ "c_ulonglong", .c_ulonglong },
            .{ "c_longdouble", .c_longdouble }, .{ "anyopaque", .anyopaque },
            .{ "f16", .f16 },                   .{ "f32", .f32 },
            .{ "f64", .f64 },                   .{ "f80", .f80 },
            .{ "f128", .f128 },                 .{ "bool", .bool },
            .{ "void", .void },                 .{ "noreturn", .noreturn },
            .{ "type", .type },                 .{ "anyerror", .anyerror },
            .{ "comptime_int", .comptime_int }, .{ "comptime_float", .comptime_float },
            .{ "anyframe", .@"anyframe" },      .{ "anytype", .@"anytype" },
            .{ "c_char", .c_char },
        });

        if (map.get(text)) |t| return t;
        if (text.len == 1) return null;
        for (text[1..]) |c|
            if (!std.ascii.isDigit(c)) return null;
        const size = std.fmt.parseUnsigned(u16, text[1..], 10) catch return null;
        return switch (text[0]) {
            'u' => .{ .uint = size },
            'i' => .{ .int = size },
            else => null,
        };
    }

    pub fn toString(self: PrimitiveType, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self) {
            .uint => |size| try std.fmt.allocPrint(allocator, "u{d}", .{size}),
            .int => |size| try std.fmt.allocPrint(allocator, "i{d}", .{size}),
            .null => "@TypeOf(null)",
            .undefined => "@TypeOf(undefined)",
            .isize,
            .usize,
            .c_short,
            .c_ushort,
            .c_int,
            .c_uint,
            .c_long,
            .c_ulong,
            .c_longlong,
            .c_ulonglong,
            .c_longdouble,
            .anyopaque,
            .f16,
            .f32,
            .f64,
            .f80,
            .f128,
            .bool,
            .void,
            .noreturn,
            .type,
            .anyerror,
            .comptime_int,
            .comptime_float,
            .@"anyframe",
            .@"anytype",
            .c_char,
            => @tagName(self),
        };
    }

    pub fn hash(self: PrimitiveType, hasher: *std.hash.Wyhash) void {
        hasher.update(&.{@intFromEnum(self)});

        switch (self) {
            .uint, .int => |size| hasher.update(&std.mem.toBytes(size)),
            .null,
            .undefined,
            .isize,
            .usize,
            .c_short,
            .c_ushort,
            .c_int,
            .c_uint,
            .c_long,
            .c_ulong,
            .c_longlong,
            .c_ulonglong,
            .c_longdouble,
            .anyopaque,
            .f16,
            .f32,
            .f64,
            .f80,
            .f128,
            .bool,
            .void,
            .noreturn,
            .type,
            .anyerror,
            .comptime_int,
            .comptime_float,
            .@"anyframe",
            .@"anytype",
            .c_char,
            => {},
        }
    }

    pub fn eql(a: PrimitiveType, b: PrimitiveType) bool {
        if (@intFromEnum(a) != @intFromEnum(b)) return false;

        switch (a) {
            inline .uint, .int => |size, tag| {
                if (size != @field(b, @tagName(tag))) return false;
            },
            .null,
            .undefined,
            .isize,
            .usize,
            .c_short,
            .c_ushort,
            .c_int,
            .c_uint,
            .c_long,
            .c_ulong,
            .c_longlong,
            .c_ulonglong,
            .c_longdouble,
            .anyopaque,
            .f16,
            .f32,
            .f64,
            .f80,
            .f128,
            .bool,
            .void,
            .noreturn,
            .type,
            .anyerror,
            .comptime_int,
            .comptime_float,
            .@"anyframe",
            .@"anytype",
            .c_char,
            => {},
        }

        return true;
    }
};
