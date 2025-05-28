//! Per-file trigram store.

const std = @import("std");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;
const builtin = @import("builtin");
const assert = std.debug.assert;
const offsets = @import("offsets.zig");
const URI = @import("uri.zig");
const log = std.log.scoped(.store);

pub const TrigramStore = @This();

pub const Trigram = [3]u8;

pub const NameSlice = struct { start: u32, end: u32 };

pub const Declaration = struct {
    pub const Index = enum(u32) { _ };

    name: NameSlice,
    range: offsets.Range,
};

pub const empty: TrigramStore = .{
    .has_filter = false,
    .filter_buckets = .empty,
    .trigram_to_declarations = .empty,
    .declarations = .empty,
    .names = .empty,
};

has_filter: bool,
filter_buckets: std.ArrayListUnmanaged(CuckooFilter.Bucket),
trigram_to_declarations: std.AutoArrayHashMapUnmanaged(Trigram, std.ArrayListUnmanaged(Declaration.Index)),
declarations: std.MultiArrayList(Declaration),
names: std.ArrayListUnmanaged(u8),

pub fn deinit(store: *TrigramStore, allocator: std.mem.Allocator) void {
    store.filter_buckets.deinit(allocator);
    for (store.trigram_to_declarations.values()) |*list| {
        list.deinit(allocator);
    }
    store.trigram_to_declarations.deinit(allocator);
    store.declarations.deinit(allocator);
    store.names.deinit(allocator);
    store.* = undefined;
}

fn clearRetainingCapacity(store: *TrigramStore) void {
    store.filter_buckets.clearRetainingCapacity();
    store.has_filter = false;
    for (store.trigram_to_declarations.values()) |*list| {
        list.clearRetainingCapacity();
    }
    store.declarations.clearRetainingCapacity();
    store.names.clearRetainingCapacity();
}

pub fn fill(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    source: [:0]const u8,
    encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    store.clearRetainingCapacity();

    var tree = try Ast.parse(allocator, source, .zig);
    defer tree.deinit(allocator);

    const Context = struct {
        allocator: std.mem.Allocator,
        store: *TrigramStore,
        in_function: bool,
        encoding: offsets.Encoding,

        const Error = error{OutOfMemory};
        fn callback(context: *@This(), cb_tree: Ast, node: Ast.Node.Index) Error!void {
            const old_in_function = context.in_function;
            defer context.in_function = old_in_function;

            switch (cb_tree.nodeTag(node)) {
                .fn_decl => {
                    if (!context.in_function) {}

                    context.in_function = true;
                },
                .root => unreachable,
                .container_decl,
                .container_decl_trailing,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                => context.in_function = false,

                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl,
                => {
                    if (!context.in_function) {
                        const token = cb_tree.fullVarDecl(node).?.ast.mut_token + 1;
                        const name = cb_tree.tokenSlice(token);

                        if (name.len >= 3) {
                            try context.store.appendDeclaration(
                                context.allocator,
                                name,
                                offsets.tokenToRange(cb_tree, token, context.encoding),
                            );
                        }
                    }
                },

                else => {},
            }

            try ast.iterateChildren(cb_tree, node, context, Error, callback);
        }
    };

    var context = Context{
        .allocator = allocator,
        .store = store,
        .in_function = false,
        .encoding = encoding,
    };
    try ast.iterateChildren(tree, .root, &context, Context.Error, Context.callback);

    try store.finalize(allocator);
}

/// Caller must not submit name.len < 3.
fn appendDeclaration(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    name: []const u8,
    range: offsets.Range,
) error{OutOfMemory}!void {
    assert(name.len >= 3);

    const name_slice: NameSlice = blk: {
        const start = store.names.items.len;
        try store.names.appendSlice(allocator, name);
        break :blk .{
            .start = @intCast(start),
            .end = @intCast(store.names.items.len),
        };
    };

    try store.declarations.append(allocator, .{
        .name = name_slice,
        .range = range,
    });

    for (0..name.len - 2) |index| {
        const trigram = name[index..][0..3].*;
        const gop = try store.trigram_to_declarations.getOrPutValue(allocator, trigram, .empty);
        try gop.value_ptr.append(allocator, @enumFromInt(store.declarations.len - 1));
    }
}

/// Must be called before any queries are executed.
fn finalize(store: *TrigramStore, allocator: std.mem.Allocator) error{OutOfMemory}!void {
    {
        const lists = store.trigram_to_declarations.values();
        var index: usize = 0;
        while (index < lists.len) {
            if (lists[index].items.len == 0) {
                lists[index].deinit(allocator);
                store.trigram_to_declarations.swapRemoveAt(index);
            } else {
                index += 1;
            }
        }
    }

    const trigrams = store.trigram_to_declarations.keys();

    if (trigrams.len > 0) {
        var prng = std.Random.DefaultPrng.init(0);

        const filter_capacity = CuckooFilter.capacityForCount(store.trigram_to_declarations.count()) catch unreachable;
        try store.filter_buckets.ensureTotalCapacityPrecise(allocator, filter_capacity);
        store.filter_buckets.items.len = filter_capacity;

        const filter: CuckooFilter = .{ .buckets = store.filter_buckets.items };
        filter.reset();
        store.has_filter = true;

        for (trigrams) |trigram| {
            filter.append(prng.random(), trigram) catch |err| switch (err) {
                error.EvictionFailed => {
                    // NOTE: This should generally be quite rare.
                    store.has_filter = false;
                    break;
                },
            };
        }
    }
}

pub fn declarationsForQuery(
    store: *const TrigramStore,
    allocator: std.mem.Allocator,
    query: []const u8,
    declaration_buffer: *std.ArrayListUnmanaged(Declaration.Index),
) error{OutOfMemory}!void {
    assert(query.len >= 3);

    const filter: CuckooFilter = .{ .buckets = store.filter_buckets.items };

    if (store.has_filter) {
        for (0..query.len - 2) |index| {
            const trigram = query[index..][0..3].*;
            if (!filter.contains(trigram)) {
                return;
            }
        }
    }

    const first = (store.trigram_to_declarations.get(query[0..3].*) orelse {
        declaration_buffer.clearRetainingCapacity();
        return;
    }).items;

    declaration_buffer.clearRetainingCapacity();
    try declaration_buffer.ensureTotalCapacity(allocator, first.len * 2);
    declaration_buffer.items.len = first.len * 2;

    var len = first.len;
    @memcpy(declaration_buffer.items[0..len], first);

    for (0..query.len - 2) |index| {
        const trigram = query[index..][0..3].*;
        const old_len = len;
        len = mergeIntersection(
            (store.trigram_to_declarations.get(trigram[0..3].*) orelse return {
                declaration_buffer.clearRetainingCapacity();
                return;
            }).items,
            declaration_buffer.items[0..len],
            declaration_buffer.items[len..],
        );
        @memcpy(declaration_buffer.items[0..len], declaration_buffer.items[old_len..][0..len]);
        declaration_buffer.items.len = len * 2;
    }

    declaration_buffer.items.len = declaration_buffer.items.len / 2;
}

/// Asserts `@min(a.len, b.len) <= out.len`.
fn mergeIntersection(
    a: []const Declaration.Index,
    b: []const Declaration.Index,
    out: []Declaration.Index,
) u32 {
    std.debug.assert(@min(a.len, b.len) <= out.len);

    var out_idx: u32 = 0;

    var a_idx: u32 = 0;
    var b_idx: u32 = 0;

    while (a_idx < a.len and b_idx < b.len) {
        const a_val = a[a_idx];
        const b_val = b[b_idx];

        if (a_val == b_val) {
            out[out_idx] = a_val;
            out_idx += 1;
            a_idx += 1;
            b_idx += 1;
        } else if (@intFromEnum(a_val) < @intFromEnum(b_val)) {
            a_idx += 1;
        } else {
            b_idx += 1;
        }
    }

    return out_idx;
}

// TODO: The pow2 requirement is quite inefficient: explore ideas posted in
// https://databasearchitects.blogspot.com/2019/07/cuckoo-filters-with-arbitrarily-sized.html
// (rocksdb even-odd scheme from comments looks interesting).
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

        pub fn initFromTrigram(trigram: Trigram) Triplet {
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

    pub fn capacityForCount(count: usize) error{Overflow}!usize {
        const fill_rate = 0.95;
        return try std.math.ceilPowerOfTwo(usize, @intFromFloat(@ceil(@as(f32, @floatFromInt(count)) / fill_rate)));
    }

    // Use a hash (fnv) for randomness.
    pub fn append(filter: CuckooFilter, random: std.Random, trigram: Trigram) error{EvictionFailed}!void {
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

    pub fn contains(filter: CuckooFilter, trigram: Trigram) bool {
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

    var entries: std.AutoArrayHashMapUnmanaged(Trigram, void) = .empty;
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
            const trigram: Trigram = @bitCast(gen_prng.random().int(u24));
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
            var trigram: Trigram = @bitCast(negative_prng.random().int(u24));
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
