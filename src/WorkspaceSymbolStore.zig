const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const offsets = @import("offsets.zig");

const WorkspaceSymbolStore = @This();

pub const empty: WorkspaceSymbolStore = .{
    .entries = .empty,
};

entries: std.ArrayListUnmanaged(Entry),

pub fn deinit(store: *WorkspaceSymbolStore, allocator: std.mem.Allocator) void {
    for (store.entries.items) |*entry| {
        entry.deinit(allocator);
    }
    store.entries.deinit(allocator);
}

pub const Entry = struct {
    pub const Trigram = [3]u8;

    pub const NameSlice = struct { start: u32, end: u32 };

    pub const Declaration = struct {
        pub const Slice = struct { start: u32, end: u32 };

        trigram: Trigram,
        name: NameSlice,
        range: offsets.Range,
    };

    pub const empty: Entry = .{
        .has_filter = false,
        .filter_buckets = .empty,
        .trigram_to_declarations = .empty,
        .declarations = .empty,
        .names = .empty,
    };

    has_filter: bool,
    filter_buckets: std.ArrayListUnmanaged(CuckooFilter.Bucket),
    trigram_to_declarations: std.AutoArrayHashMapUnmanaged(Trigram, Declaration.Slice),
    declarations: std.MultiArrayList(Declaration),
    names: std.ArrayListUnmanaged(u8),

    pub fn deinit(entry: *Entry, allocator: std.mem.Allocator) void {
        entry.filter_buckets.deinit(allocator);
        entry.trigram_to_declarations.clearRetainingCapacity();
        entry.declarations.clearRetainingCapacity();
        entry.names.clearRetainingCapacity();
        entry.* = undefined;
    }

    pub fn clearRetainingCapacity(entry: *Entry, allocator: std.mem.Allocator) void {
        entry.filter_buckets.clearAndFree(allocator);
        entry.has_filter = false;
        entry.trigram_to_declarations.clearRetainingCapacity();
        entry.declarations.clearRetainingCapacity();
        entry.names.clearRetainingCapacity();
    }

    /// Caller must not submit name.len < 3.
    pub fn appendDeclarations(
        entry: *Entry,
        allocator: std.mem.Allocator,
        name: []const u8,
        range: offsets.Range,
    ) error{ OutOfMemory, InvalidUtf8 }!void {
        assert(name.len >= 3);

        const name_slice: NameSlice = blk: {
            const start = entry.bytes.items.len;
            try entry.bytes.appendSlice(allocator, name);
            break :blk .{
                .start = @intCast(start),
                .end = @intCast(entry.bytes.items.len),
            };
        };
        try entry.declarations.ensureUnusedCapacity(allocator, name.len - 2);

        for (0..name.len - 2) |index| {
            const trigram = name[index..][0..3].*;
            entry.declarations.appendAssumeCapacity(.{
                .trigram = trigram,
                .name = name_slice,
                .range = range,
            });
        }
    }

    pub const SortDeclarations = struct {
        trigrams: []const Trigram,
        range: []const offsets.Range,

        pub fn lessThan(ctx: SortDeclarations, a_index: usize, b_index: usize) bool {
            const a_trigram_numeric: u24 = @bitCast(ctx.trigrams[a_index]);
            const b_trigram_numeric: u24 = @bitCast(ctx.trigrams[b_index]);

            return a_trigram_numeric < b_trigram_numeric or
                (a_trigram_numeric == b_trigram_numeric and
                    ctx.range[a_index].start < ctx.range[b_index].start);
        }
    };

    /// Must be called before any queries are executed.
    pub fn finalize(entry: *Entry, allocator: std.mem.Allocator) error{OutOfMemory}!void {
        entry.declarations.sortUnstable(SortDeclarations{
            .trigrams = entry.declarations.items(.trigram),
            .ranges = entry.declarations.items(.range),
        });

        var prng = std.Random.DefaultPrng.init(0);

        try entry.filter_buckets.ensureTotalCapacityPrecise(
            allocator,
            entry.trigram_to_declarations.count(),
        );
        entry.filter_buckets.items.len = entry.trigram_to_declarations.count();

        var filter = CuckooFilter{ .buckets = entry.filter_buckets.items };
        filter.reset();
        entry.has_filter = true;

        for (entry.trigram_to_declarations.keys()) |trigram| {
            filter.append(prng.random(), trigram) catch |err| switch (err) {
                error.EvictionFailed => {
                    // NOTE: This should generally be quite rare.
                    entry.has_filter = false;
                    break;
                },
            };
        }
    }
};

// TODO: The pow2 requirement is quite inefficient: explore ideas posted in
// https://databasearchitects.blogspot.com/2019/07/cuckoo-filters-with-arbitrarily-sized.html
// (rocksdb even-odd scheme from comments looks interesting).
// TODO: Look more into FPR scaling.
pub const CuckooFilter = struct {
    /// len must be a power of 2.
    ///
    /// ### Pathological case with buckets.len power of 2
    ///
    /// - `BucketIndex(alias_0)` -> `bucket_1`, `BucketIndex(alias_0).alternate()` -> `bucket_2`
    /// - `BucketIndex(alias_1)` -> `bucket_1`, `BucketIndex(alias_1).alternate()` -> `bucket_2`
    ///
    /// Our alternate mappings hold and `contains()` will not return false negatives.
    ///
    /// ### Pathological case with buckets.len NOT power of 2:
    ///
    /// - `BucketIndex(alias_0)` -> `bucket_1`, `BucketIndex(alias_0).alternate()` -> `bucket_3`
    /// - `BucketIndex(alias_1)` -> `bucket_2`, `BucketIndex(alias_1).alternate()` -> `bucket_4`
    ///
    /// Our alternate mappings do not hold and `contains()` can return false negatives. This is not
    /// acceptable as the entire point of an AMQ datastructure is the presence of false positives
    /// but not false negatives.
    buckets: []Bucket,

    pub const Fingerprint = enum(u8) {
        none = std.math.maxInt(u8),
        _,

        pub fn hash(fingerprint: Fingerprint) u32 {
            return @truncate(std.hash.Murmur2_64.hash(&.{@intFromEnum(fingerprint)}));
        }
    };
    pub const Bucket = [4]Fingerprint;
    pub const BucketIndex = enum(u32) {
        _,

        pub fn alternate(index: BucketIndex, fingerprint: Fingerprint) BucketIndex {
            assert(fingerprint != .none);
            return @enumFromInt(@intFromEnum(index) ^ fingerprint.hash());
        }
    };

    pub const Triplet = struct {
        fingerprint: Fingerprint,
        index_1: BucketIndex,
        index_2: BucketIndex,

        pub fn initFromTrigram(trigram: Entry.Trigram) Triplet {
            const split: packed struct {
                fingerprint: Fingerprint,
                padding: u24,
                index_1: BucketIndex,
            } = @bitCast(std.hash.Murmur2_64.hash(&trigram));

            const fingerprint: Fingerprint = if (split.fingerprint == .none)
                @enumFromInt(0)
            else
                split.fingerprint;

            const triplet: Triplet = .{
                .fingerprint = fingerprint,
                .index_1 = split.index_1,
                .index_2 = split.index_1.alternate(fingerprint),
            };
            assert(triplet.index_2.alternate(fingerprint) == triplet.index_1);

            return triplet;
        }
    };

    pub fn reset(filter: CuckooFilter) void {
        @memset(filter.buckets, [1]Fingerprint{.none} ** 4);
    }

    // TODO: Dubious
    pub fn capacityForCount(count: usize) error{Overflow}!usize {
        const fill_rate = 0.95;
        return try std.math.ceilPowerOfTwo(usize, @ceil(@as(f32, @floatFromInt(count)) / fill_rate));
    }

    pub fn append(filter: CuckooFilter, random: std.Random, trigram: Entry.Trigram) error{EvictionFailed}!void {
        const triplet: Triplet = .initFromTrigram(trigram);

        if (filter.appendToBucket(triplet.index_1, triplet.fingerprint) or
            filter.appendToBucket(triplet.index_2, triplet.fingerprint))
        {
            return;
        }

        var fingerprint = triplet.fingerprint;
        var index = if (random.boolean()) triplet.index_1 else triplet.index_2;
        for (0..500) |_| {
            fingerprint = filter.swapFromBucket(random, index, fingerprint);
            index = index.alternate(fingerprint);

            if (filter.appendToBucket(index, fingerprint)) {
                return;
            }
        }

        return error.EvictionFailed;
    }

    fn bucketAt(filter: CuckooFilter, index: BucketIndex) *Bucket {
        assert(std.math.isPowerOfTwo(filter.buckets.len));
        return &filter.buckets[@intFromEnum(index) & (filter.buckets.len - 1)];
    }

    fn appendToBucket(filter: CuckooFilter, index: BucketIndex, fingerprint: Fingerprint) bool {
        assert(fingerprint != .none);

        const bucket = filter.bucketAt(index);
        for (bucket) |*slot| {
            if (slot.* == .none) {
                slot.* = fingerprint;
                return true;
            }
        }

        return false;
    }

    fn swapFromBucket(
        filter: CuckooFilter,
        random: std.Random,
        index: BucketIndex,
        fingerprint: Fingerprint,
    ) Fingerprint {
        assert(fingerprint != .none);

        const target = &filter.bucketAt(index)[random.int(u2)];

        const old_fingerprint = target.*;
        assert(old_fingerprint != .none);

        target.* = fingerprint;

        return old_fingerprint;
    }

    pub fn contains(filter: CuckooFilter, trigram: Entry.Trigram) bool {
        const triplet: Triplet = .initFromTrigram(trigram);

        return filter.containsInBucket(triplet.index_1, triplet.fingerprint) or
            filter.containsInBucket(triplet.index_2, triplet.fingerprint);
    }

    fn containsInBucket(filter: CuckooFilter, index: BucketIndex, fingerprint: Fingerprint) bool {
        assert(fingerprint != .none);

        const bucket = filter.bucketAt(index);
        for (bucket) |*slot| {
            if (slot.* == fingerprint) {
                return true;
            }
        }

        return false;
    }
};

// TODO: More extensive (different capacities) testing.
test CuckooFilter {
    const allocator = std.testing.allocator;

    const element_count = 486;
    const filter_size = comptime CuckooFilter.capacityForCount(element_count) catch unreachable;
    try std.testing.expectEqual(512, filter_size);

    var entries: std.AutoArrayHashMapUnmanaged(Entry.Trigram, void) = .empty;
    defer entries.deinit(allocator);
    try entries.ensureTotalCapacity(allocator, element_count);

    var buckets: [filter_size]CuckooFilter.Bucket = undefined;
    var filter = CuckooFilter{ .buckets = &buckets };
    var filter_prng = std.Random.DefaultPrng.init(42);

    for (0..2_500) |gen_prng_seed| {
        entries.clearRetainingCapacity();
        filter.reset();

        var gen_prng = std.Random.DefaultPrng.init(gen_prng_seed);
        for (0..element_count) |_| {
            const trigram: Entry.Trigram = @bitCast(gen_prng.random().int(u24));
            try entries.put(allocator, trigram, {});
            try filter.append(filter_prng.random(), trigram);
        }

        // No false negatives
        for (entries.keys()) |trigram| {
            try std.testing.expect(filter.contains(trigram));
        }

        // Reasonable false positive rate
        const fpr_count = 2_500;
        var false_positives: usize = 0;
        var negative_prng = std.Random.DefaultPrng.init(~gen_prng_seed);
        for (0..fpr_count) |_| {
            var trigram: Entry.Trigram = @bitCast(negative_prng.random().int(u24));
            while (entries.contains(trigram)) {
                trigram = @bitCast(negative_prng.random().int(u24));
            }

            false_positives += @intFromBool(filter.contains(trigram));
        }

        const fpr = @as(f32, @floatFromInt(false_positives)) / fpr_count;
        std.testing.expect(fpr < 0.035) catch |err| {
            std.log.err("fpr: {d}%", .{fpr * 100});
            return err;
        };
    }
}
