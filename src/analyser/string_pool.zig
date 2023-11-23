const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Config = struct {
    /// Whether the StringPool may be used simultaneously from multiple threads.
    thread_safe: bool = !builtin.single_threaded,

    /// What type of mutex you'd like to use, for thread safety.
    /// when specified, the mutex type must have the same shape as `std.Thread.Mutex` and
    /// `DummyMutex`, and have no required fields. Specifying this field causes
    /// the `thread_safe` field to be ignored.
    ///
    /// when null (default):
    /// * the mutex type defaults to `std.Thread.Mutex` when thread_safe is enabled.
    /// * the mutex type defaults to `DummyMutex` otherwise.
    MutexType: ?type = null,
};

pub fn StringPool(comptime config: Config) type {
    return struct {
        const Pool = @This();

        pub const String = enum(u32) {
            empty = 0,
            _,

            pub fn toOptional(self: String) OptionalString {
                return @enumFromInt(@intFromEnum(self));
            }

            pub fn fmt(self: String, pool: *Pool) std.fmt.Formatter(print) {
                return .{ .data = .{ .string = self, .pool = pool } };
            }
        };

        pub const OptionalString = enum(u32) {
            empty = 0,
            none = std.math.maxInt(u32),
            _,

            pub fn unwrap(self: OptionalString) ?String {
                if (self == .none) return null;
                return @enumFromInt(@intFromEnum(self));
            }
        };

        /// asserts that `str` contains no null bytes
        pub fn getString(pool: *Pool, str: []const u8) ?String {
            assert(std.mem.indexOfScalar(u8, str, 0) == null);
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const index = pool.map.getKeyAdapted(str, std.hash_map.StringIndexAdapter{ .bytes = &pool.bytes }) orelse return null;
            return @enumFromInt(index);
        }

        /// asserts that `str` contains no null bytes
        /// returns `error.OutOfMemory` if adding this new string would increase the amount of allocated bytes above std.math.maxInt(u32)
        pub fn getOrPutString(pool: *Pool, allocator: Allocator, str: []const u8) error{OutOfMemory}!String {
            assert(std.mem.indexOfScalar(u8, str, 0) == null);

            const start_index = std.math.cast(u32, pool.bytes.items.len) orelse return error.OutOfMemory;

            pool.mutex.lock();
            defer pool.mutex.unlock();

            pool.bytes.ensureUnusedCapacity(allocator, str.len + 1) catch {
                // If allocation fails, try to do the lookup anyway.
                const index = pool.map.getKeyAdapted(str, std.hash_map.StringIndexAdapter{ .bytes = &pool.bytes }) orelse return error.OutOfMemory;
                return @enumFromInt(index);
            };

            const gop = try pool.map.getOrPutContextAdapted(
                allocator,
                str,
                std.hash_map.StringIndexAdapter{ .bytes = &pool.bytes },
                std.hash_map.StringIndexContext{ .bytes = &pool.bytes },
            );

            if (!gop.found_existing) {
                pool.bytes.appendSliceAssumeCapacity(str);
                pool.bytes.appendAssumeCapacity(0);
                gop.key_ptr.* = start_index;
            }
            return @enumFromInt(gop.key_ptr.*);
        }

        pub fn hashString(pool: *Pool, hasher: anytype, index: String) void {
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const str = pool.stringToSliceUnsafe(index);
            hasher.update(str);
        }

        pub fn stringToSliceAlloc(pool: *Pool, allocator: Allocator, index: String) Allocator.Error![]const u8 {
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return try allocator.dupe(u8, std.mem.sliceTo(string_bytes + start, 0));
        }

        pub fn stringToSliceAllocZ(pool: *Pool, allocator: Allocator, index: String) Allocator.Error![:0]const u8 {
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return try allocator.dupeZ(u8, std.mem.sliceTo(string_bytes + start, 0));
        }

        /// returns the underlying slice from an interned string
        /// equal strings are guaranteed to share the same storage
        pub fn stringToSliceUnsafe(pool: *Pool, index: String) [:0]const u8 {
            std.debug.assert(@intFromEnum(index) < pool.bytes.items.len);
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return std.mem.sliceTo(string_bytes + start, 0);
        }

        mutex: @TypeOf(mutex_init) = mutex_init,
        bytes: std.ArrayListUnmanaged(u8) = .{},
        map: std.HashMapUnmanaged(u32, void, std.hash_map.StringIndexContext, std.hash_map.default_max_load_percentage) = .{},

        pub fn deinit(pool: *Pool, allocator: Allocator) void {
            pool.bytes.deinit(allocator);
            pool.map.deinit(allocator);
            pool.* = undefined;
        }

        const mutex_init = if (config.MutexType) |T|
            T{}
        else if (config.thread_safe)
            std.Thread.Mutex{}
        else
            DummyMutex{};

        const DummyMutex = struct {
            pub fn lock(_: *@This()) void {}
            pub fn unlock(_: *@This()) void {}
        };

        const FormatContext = struct {
            string: String,
            pool: *Pool,
        };

        fn print(ctx: FormatContext, comptime fmt_str: []const u8, _: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, ctx.string);
            ctx.pool.mutex.lock();
            defer ctx.pool.mutex.unlock();
            try writer.writeAll(ctx.pool.stringToSliceUnsafe(ctx.string));
        }
    };
}

test StringPool {
    const gpa = std.testing.allocator;
    var pool = StringPool(.{}){};
    defer pool.deinit(gpa);

    const str = "All Your Codebase Are Belong To Us";
    const index = try pool.getOrPutString(gpa, str);
    try std.testing.expectEqualStrings(str, pool.stringToSliceUnsafe(index));
    try std.testing.expectFmt(str, "{}", .{index.fmt(&pool)});
}

test "StringPool - check interning" {
    const gpa = std.testing.allocator;
    var pool = StringPool(.{}){};
    defer pool.deinit(gpa);

    const str = "All Your Codebase Are Belong To Us";
    const index1 = try pool.getOrPutString(gpa, str);
    const index2 = try pool.getOrPutString(gpa, str);
    const index3 = pool.getString(str).?;
    const storage1 = pool.stringToSliceUnsafe(index1);
    const storage2 = pool.stringToSliceUnsafe(index2);

    try std.testing.expectEqual(index1, index2);
    try std.testing.expectEqual(index2, index3);
    try std.testing.expectEqualStrings(str, storage1);
    try std.testing.expectEqualStrings(str, storage2);
    try std.testing.expectEqual(storage1.ptr, storage2.ptr);
    try std.testing.expectEqual(storage1.len, storage2.len);
}

test "StringPool - empty string" {
    if (true) return error.SkipZigTest; // TODO
    const gpa = std.testing.allocator;
    var pool = StringPool(.{}){};
    defer pool.deinit(gpa);

    try std.testing.expectEqualStrings("", pool.stringToSliceUnsafe(.empty));
}

test "StringPool - getOrPut on existing string without allocation" {
    const gpa = std.testing.allocator;
    var failing_gpa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });

    var pool = StringPool(.{}){};
    defer pool.deinit(gpa);

    const hello_string = try pool.getOrPutString(gpa, "hello");

    try std.testing.expectError(error.OutOfMemory, pool.getOrPutString(failing_gpa.allocator(), "world"));
    try std.testing.expectEqual(hello_string, try pool.getOrPutString(failing_gpa.allocator(), "hello"));
}
