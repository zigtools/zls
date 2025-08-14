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

/// The StringPool is a Data structure that stores only one copy of distinct and immutable strings i.e. `[]const u8`.
///
/// The `getOrPutString` function will intern a given string and return a unique identifier
/// that can then be used to retrieve the original string with the `stringToSlice*` functions.
pub fn StringPool(comptime config: Config) type {
    return struct {
        const Pool = @This();

        /// A unique number that identifier a interned string.
        ///
        /// Two interned string can be checked for equality simply by checking
        /// if this identifier are equal if they both come from the same StringPool.
        pub const String = enum(u32) {
            _,

            pub fn toOptional(self: String) OptionalString {
                return @enumFromInt(@intFromEnum(self));
            }

            pub fn fmt(self: String, pool: *Pool) std.fmt.Alt(FormatContext, print) {
                return .{ .data = .{ .string = self, .pool = pool } };
            }
        };

        pub const OptionalString = enum(u32) {
            none = std.math.maxInt(u32),
            _,

            pub fn unwrap(self: OptionalString) ?String {
                if (self == .none) return null;
                return @enumFromInt(@intFromEnum(self));
            }
        };

        /// Asserts that `str` contains no null bytes.
        pub fn getString(pool: *Pool, str: []const u8) ?String {
            assert(std.mem.indexOfScalar(u8, str, 0) == null);

            // precompute the hash before acquiring the lock
            const precomputed_key_hash = std.hash_map.hashString(str);

            pool.mutex.lock();
            defer pool.mutex.unlock();

            const adapter: PrecomputedStringIndexAdapter = .{
                .bytes = &pool.bytes,
                .adapted_key = str,
                .precomputed_key_hash = precomputed_key_hash,
            };

            const index = pool.map.getKeyAdapted(str, adapter) orelse return null;
            return @enumFromInt(index);
        }

        /// Asserts that `str` contains no null bytes.
        /// Returns `error.OutOfMemory` if adding this new string would increase the amount of allocated bytes above std.math.maxInt(u32)
        pub fn getOrPutString(pool: *Pool, allocator: Allocator, str: []const u8) error{OutOfMemory}!String {
            assert(std.mem.indexOfScalar(u8, str, 0) == null);

            const start_index = std.math.cast(u32, pool.bytes.items.len) orelse return error.OutOfMemory;

            // precompute the hash before acquiring the lock
            const precomputed_key_hash = std.hash_map.hashString(str);

            pool.mutex.lock();
            defer pool.mutex.unlock();

            const adapter: PrecomputedStringIndexAdapter = .{
                .bytes = &pool.bytes,
                .adapted_key = str,
                .precomputed_key_hash = precomputed_key_hash,
            };

            pool.bytes.ensureUnusedCapacity(allocator, str.len + 1) catch {
                // If allocation fails, try to do the lookup anyway.
                const index = pool.map.getKeyAdapted(str, adapter) orelse return error.OutOfMemory;
                return @enumFromInt(index);
            };

            const gop = try pool.map.getOrPutContextAdapted(
                allocator,
                str,
                adapter,
                .{ .bytes = &pool.bytes },
            );

            if (!gop.found_existing) {
                pool.bytes.appendSliceAssumeCapacity(str);
                pool.bytes.appendAssumeCapacity(0);
                gop.key_ptr.* = start_index;
            }
            return @enumFromInt(gop.key_ptr.*);
        }

        /// Caller owns the memory.
        pub fn stringToSliceAlloc(pool: *Pool, allocator: Allocator, index: String) Allocator.Error![]const u8 {
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return try allocator.dupe(u8, std.mem.sliceTo(string_bytes + start, 0));
        }

        /// Caller owns the memory.
        pub fn stringToSliceAllocZ(pool: *Pool, allocator: Allocator, index: String) Allocator.Error![:0]const u8 {
            pool.mutex.lock();
            defer pool.mutex.unlock();
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return try allocator.dupeZ(u8, std.mem.sliceTo(string_bytes + start, 0));
        }

        /// storage a slice that points into the internal storage of the `StringPool`.
        /// always call `release` method to unlock the `StringPool`.
        ///
        /// see `stringToSliceLock`
        pub const LockedString = struct {
            slice: [:0]const u8,

            pub fn release(locked_string: LockedString, pool: *Pool) void {
                _ = locked_string;
                pool.mutex.unlock();
            }
        };

        /// returns the underlying slice from an interned string
        /// equal strings are guaranteed to share the same storage
        ///
        /// Will lock the `StringPool` until the `release` method is called on the returned locked string.
        pub fn stringToSliceLock(pool: *Pool, index: String) LockedString {
            pool.mutex.lock();
            return .{ .slice = pool.stringToSliceUnsafe(index) };
        }

        /// returns the underlying slice from an interned string
        /// equal strings are guaranteed to share the same storage
        ///
        /// only callable when thread safety is disabled.
        pub const stringToSlice = if (config.thread_safe) {} else stringToSliceUnsafe;

        /// returns the underlying slice from an interned string
        /// equal strings are guaranteed to share the same storage
        pub fn stringToSliceUnsafe(pool: *Pool, index: String) [:0]const u8 {
            assert(@intFromEnum(index) < pool.bytes.items.len);
            const string_bytes: [*:0]u8 = @ptrCast(pool.bytes.items.ptr);
            const start = @intFromEnum(index);
            return std.mem.sliceTo(string_bytes + start, 0);
        }

        mutex: MutexType,
        bytes: std.ArrayList(u8),
        map: std.HashMapUnmanaged(u32, void, std.hash_map.StringIndexContext, std.hash_map.default_max_load_percentage),

        pub const empty: Pool = .{
            .mutex = .{},
            .bytes = .empty,
            .map = .empty,
        };

        pub fn deinit(pool: *Pool, allocator: Allocator) void {
            pool.bytes.deinit(allocator);
            pool.map.deinit(allocator);
            if (builtin.mode == .Debug and !builtin.single_threaded and config.thread_safe) {
                // detect deadlock when calling deinit while holding the lock
                pool.mutex.lock();
                pool.mutex.unlock();
            }
            pool.* = undefined;
        }

        pub const MutexType = config.MutexType orelse if (config.thread_safe) std.Thread.Mutex else DummyMutex;

        const DummyMutex = struct {
            pub fn lock(_: *@This()) void {}
            pub fn unlock(_: *@This()) void {}
        };

        const FormatContext = struct {
            string: String,
            pool: *Pool,
        };

        fn print(ctx: FormatContext, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const locked_string = ctx.pool.stringToSliceLock(ctx.string);
            defer locked_string.release(ctx.pool);
            try writer.writeAll(locked_string.slice);
        }
    };
}

/// same as `std.hash_map.StringIndexAdapter` but the hash of the adapted key is precomputed
const PrecomputedStringIndexAdapter = struct {
    bytes: *const std.ArrayList(u8),
    adapted_key: []const u8,
    precomputed_key_hash: u64,

    pub fn eql(self: @This(), a_slice: []const u8, b: u32) bool {
        const b_slice = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(self.bytes.items.ptr)) + b, 0);
        return std.mem.eql(u8, a_slice, b_slice);
    }

    pub fn hash(self: @This(), adapted_key: []const u8) u64 {
        assert(std.mem.eql(u8, self.adapted_key, adapted_key));
        return self.precomputed_key_hash;
    }
};

test StringPool {
    const gpa = std.testing.allocator;
    var pool: StringPool(.{}) = .empty;
    defer pool.deinit(gpa);

    const str = "All Your Codebase Are Belong To Us";
    const index = try pool.getOrPutString(gpa, str);

    {
        const locked_string = pool.stringToSliceLock(index);
        defer locked_string.release(&pool);

        try std.testing.expectEqualStrings(str, locked_string.slice);
    }
    try std.testing.expectFmt(str, "{f}", .{index.fmt(&pool)});
}

test "StringPool - check interning" {
    const gpa = std.testing.allocator;
    var pool: StringPool(.{ .thread_safe = false }) = .empty;
    defer pool.deinit(gpa);

    const str = "All Your Codebase Are Belong To Us";
    const index1 = try pool.getOrPutString(gpa, str);
    const index2 = try pool.getOrPutString(gpa, str);
    const index3 = pool.getString(str).?;
    const storage1 = pool.stringToSlice(index1);
    const storage2 = pool.stringToSliceUnsafe(index2);

    try std.testing.expectEqual(index1, index2);
    try std.testing.expectEqual(index2, index3);
    try std.testing.expectEqualStrings(str, storage1);
    try std.testing.expectEqualStrings(str, storage2);
    try std.testing.expectEqual(storage1.ptr, storage2.ptr);
    try std.testing.expectEqual(storage1.len, storage2.len);
}

test "StringPool - getOrPut on existing string without allocation" {
    const gpa = std.testing.allocator;
    var failing_gpa: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = 0 });

    var pool: StringPool(.{}) = .empty;
    defer pool.deinit(gpa);

    try pool.bytes.ensureTotalCapacityPrecise(gpa, "hello".len + 1);
    const hello_string = try pool.getOrPutString(gpa, "hello");

    try std.testing.expectError(error.OutOfMemory, pool.getOrPutString(failing_gpa.allocator(), "world"));
    try std.testing.expectEqual(hello_string, try pool.getOrPutString(failing_gpa.allocator(), "hello"));
}
