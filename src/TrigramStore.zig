//! Per-file trigram store.

const std = @import("std");
const ast = @import("ast.zig");
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const offsets = @import("offsets.zig");

pub const TrigramStore = @This();

pub const Trigram = [3]u8;

pub const Declaration = struct {
    pub const Index = enum(u32) { _ };

    pub const Kind = enum {
        variable,
        constant,
        function,
        test_function,
    };

    /// Either `.identifier` or `.string_literal`.
    name: Ast.TokenIndex,
    kind: Kind,
};

has_filter: bool,
filter_buckets: std.ArrayListUnmanaged(CuckooFilter.Bucket),
trigram_to_declarations: std.AutoArrayHashMapUnmanaged(Trigram, std.ArrayListUnmanaged(Declaration.Index)),
declarations: std.MultiArrayList(Declaration),

pub const TrigramIterator = struct {
    buffer: []const u8,
    index: usize,
    boundary: Boundary,

    pub fn init(buffer: []const u8) TrigramIterator {
        assert(buffer.len != 0);
        return .{ .buffer = buffer, .index = 0, .boundary = .calculate(buffer, 0) };
    }

    pub const Boundary = struct {
        end: usize,
        next_start: ?usize,

        pub fn calculate(buffer: []const u8, index: usize) Boundary {
            assert(buffer[index..].len > 0);

            if (std.ascii.isLower(buffer[index])) {
                // First character lowercase
                for (buffer[index + 1 ..], index + 1..) |c, i| {
                    if (!std.ascii.isLower(c)) {
                        return .{
                            .end = i,
                            .next_start = i,
                        };
                    }
                }
            } else {
                if (index + 1 >= buffer.len) {
                    return .{
                        .end = buffer.len,
                        .next_start = null,
                    };
                }

                if (std.ascii.isLower(buffer[index + 1])) {
                    // First char is uppercase, second char is lowercase
                    for (buffer[index + 2 ..], index + 2..) |c, i| {
                        if (!std.ascii.isLower(c)) {
                            return .{
                                .end = i,
                                .next_start = i,
                            };
                        }
                    }
                } else {
                    // First and second chars are uppercase
                    for (buffer[index + 2 ..], index + 2..) |c, i| {
                        if (!std.ascii.isUpper(c)) {
                            return .{
                                .end = i,
                                .next_start = i,
                            };
                        }
                    }
                }
            }

            return .{
                .end = buffer.len,
                .next_start = null,
            };
        }
    };

    pub fn next(ti: *TrigramIterator) ?Trigram {
        if (ti.index == ti.buffer.len) return null;
        assert(ti.index < ti.boundary.end);

        var trigram: [3]u8 = @splat(0);
        const unpadded = ti.buffer[ti.index..@min(ti.index + 3, ti.boundary.end)];
        _ = std.ascii.lowerString(&trigram, unpadded);

        if (unpadded.len < 3 or ti.index + 3 >= ti.boundary.end) {
            ti.index = ti.boundary.next_start orelse {
                ti.index = ti.buffer.len;
                return trigram;
            };
            ti.boundary = .calculate(ti.buffer, ti.index);
        } else {
            ti.index += 1;
        }

        return trigram;
    }
};

test "TrigramIterator.Boundary.calculate" {
    var boundary: TrigramIterator.Boundary = .calculate("helloWORLD", 0);
    try std.testing.expectEqual(5, boundary.end);
    try std.testing.expectEqual(5, boundary.next_start.?);

    boundary = .calculate("helloWORLD", 5);
    try std.testing.expectEqual(10, boundary.end);
    try std.testing.expectEqual(null, boundary.next_start);
}

test TrigramIterator {
    const allocator = std.testing.allocator;

    const matrix: []const struct { []const u8, []const Trigram } = &.{
        .{ "a", &.{"a\x00\x00".*} },
        .{ "ab", &.{"ab\x00".*} },
        .{ "helloWORLD", &.{ "hel".*, "ell".*, "llo".*, "wor".*, "orl".*, "rld".* } },
        .{ "HelloWORLD", &.{ "hel".*, "ell".*, "llo".*, "wor".*, "orl".*, "rld".* } },
        .{ "HelloWorld", &.{ "hel".*, "ell".*, "llo".*, "wor".*, "orl".*, "rld".* } },
    };

    var actual: std.ArrayList(Trigram) = .empty;
    defer actual.deinit(allocator);

    for (matrix) |entry| {
        const input, const expected = entry;

        actual.clearRetainingCapacity();

        var it: TrigramIterator = .init(input);
        while (it.next()) |trigram| {
            try actual.append(allocator, trigram);
        }

        try @import("testing.zig").expectEqual(expected, actual.items);
    }
}

pub fn init(
    allocator: std.mem.Allocator,
    tree: Ast,
) error{OutOfMemory}!TrigramStore {
    var store: TrigramStore = .{
        .has_filter = false,
        .filter_buckets = .empty,
        .trigram_to_declarations = .empty,
        .declarations = .empty,
    };
    errdefer store.deinit(allocator);

    const Context = struct {
        allocator: std.mem.Allocator,
        store: *TrigramStore,
        in_function: bool,

        const Error = error{OutOfMemory};
        fn callback(context: *@This(), cb_tree: Ast, node: Ast.Node.Index) Error!void {
            const old_in_function = context.in_function;
            defer context.in_function = old_in_function;

            switch (cb_tree.nodeTag(node)) {
                .fn_proto,
                .fn_proto_multi,
                .fn_proto_one,
                .fn_proto_simple,
                => |tag| skip: {
                    context.in_function = tag == .fn_decl;

                    const fn_token = cb_tree.nodeMainToken(node);
                    if (cb_tree.tokenTag(fn_token + 1) != .identifier) break :skip;

                    try context.store.appendDeclaration(
                        context.allocator,
                        offsets.identifierTokenToNameSlice(cb_tree, fn_token + 1),
                        fn_token + 1,
                        .function,
                    );
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
                => skip: {
                    if (context.in_function) break :skip;

                    const main_token = cb_tree.nodeMainToken(node);

                    const kind: Declaration.Kind = switch (cb_tree.tokenTag(main_token)) {
                        .keyword_var => .variable,
                        .keyword_const => .constant,
                        else => unreachable,
                    };

                    try context.store.appendDeclaration(
                        context.allocator,
                        offsets.identifierTokenToNameSlice(cb_tree, main_token + 1),
                        main_token + 1,
                        kind,
                    );
                },

                .test_decl => skip: {
                    const test_name_token, const test_name = ast.testDeclNameAndToken(cb_tree, node) orelse break :skip;

                    try context.store.appendDeclaration(
                        context.allocator,
                        test_name,
                        test_name_token,
                        .test_function,
                    );
                },
                else => {},
            }

            try ast.iterateChildren(cb_tree, node, context, Error, callback);
        }
    };

    var context: Context = .{
        .allocator = allocator,
        .store = &store,
        .in_function = false,
    };
    try ast.iterateChildren(tree, .root, &context, Context.Error, Context.callback);

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

    const trigrams = store.trigram_to_declarations.keys();

    if (trigrams.len > 0) {
        var prng = std.Random.DefaultPrng.init(0);

        const filter_capacity = CuckooFilter.capacityForCount(@intCast(store.trigram_to_declarations.count())) catch unreachable;
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

    return store;
}

pub fn deinit(store: *TrigramStore, allocator: std.mem.Allocator) void {
    store.filter_buckets.deinit(allocator);
    for (store.trigram_to_declarations.values()) |*list| {
        list.deinit(allocator);
    }
    store.trigram_to_declarations.deinit(allocator);
    store.declarations.deinit(allocator);
    store.* = undefined;
}

fn appendDeclaration(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    name: []const u8,
    name_token: Ast.TokenIndex,
    kind: Declaration.Kind,
) error{OutOfMemory}!void {
    if (name.len < 3) return;

    try store.declarations.append(allocator, .{
        .name = name_token,
        .kind = kind,
    });

    for (0..name.len - 2) |index| {
        const trigram = name[index..][0..3].*;
        const gop = try store.trigram_to_declarations.getOrPutValue(allocator, trigram, .empty);
        try gop.value_ptr.append(allocator, @enumFromInt(store.declarations.len - 1));
    }
}

/// Asserts query.len >= 3. Asserts declaration_buffer.items.len == 0.
pub fn declarationsForQuery(
    store: *const TrigramStore,
    allocator: std.mem.Allocator,
    query: []const u8,
    declaration_buffer: *std.ArrayListUnmanaged(Declaration.Index),
) error{OutOfMemory}!void {
    assert(query.len >= 3);
    assert(declaration_buffer.items.len == 0);

    const filter: CuckooFilter = .{ .buckets = store.filter_buckets.items };

    if (store.has_filter) {
        for (0..query.len - 2) |index| {
            const trigram = query[index..][0..3].*;
            if (!filter.contains(trigram)) {
                return;
            }
        }
    }

    const first = (store.trigram_to_declarations.get(query[0..3].*) orelse return).items;

    try declaration_buffer.resize(allocator, first.len * 2);

    var len = first.len;
    @memcpy(declaration_buffer.items[0..len], first);

    for (0..query.len - 2) |index| {
        const trigram = query[index..][0..3].*;
        const old_len = len;
        len = mergeIntersection(
            (store.trigram_to_declarations.get(trigram[0..3].*) orelse {
                declaration_buffer.clearRetainingCapacity();
                return;
            }).items,
            declaration_buffer.items[0..len],
            declaration_buffer.items[len..],
        );
        @memcpy(declaration_buffer.items[0..len], declaration_buffer.items[old_len..][0..len]);
        declaration_buffer.shrinkRetainingCapacity(len * 2);
    }

    declaration_buffer.shrinkRetainingCapacity(declaration_buffer.items.len / 2);
}

/// Asserts `@min(a.len, b.len) <= out.len`.
fn mergeIntersection(
    a: []const Declaration.Index,
    b: []const Declaration.Index,
    out: []Declaration.Index,
) u32 {
    assert(@min(a.len, b.len) <= out.len);

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

fn parity(integer: anytype) enum(u1) { even, odd } {
    return @enumFromInt(integer & 1);
}

pub const CuckooFilter = struct {
    buckets: []Bucket,

    pub const Fingerprint = enum(u8) {
        none = std.math.maxInt(u8),
        _,

        const precomputed_odd_hashes = blk: {
            var table: [255]u32 = undefined;

            for (&table, 0..) |*h, index| {
                h.* = @truncate(std.hash.Murmur2_64.hash(&.{index}) | 1);
            }

            break :blk table;
        };

        pub fn oddHash(fingerprint: Fingerprint) u32 {
            assert(fingerprint != .none);
            return precomputed_odd_hashes[@intFromEnum(fingerprint)];
        }
    };

    pub const Bucket = [4]Fingerprint;
    pub const BucketIndex = enum(u32) {
        _,

        pub fn alternate(index: BucketIndex, fingerprint: Fingerprint, len: u32) BucketIndex {
            assert(@intFromEnum(index) < len);
            assert(fingerprint != .none);

            const signed_index: i64 = @intFromEnum(index);
            const odd_hash: i64 = fingerprint.oddHash();

            const unbounded = switch (parity(signed_index)) {
                .even => signed_index + odd_hash,
                .odd => signed_index - odd_hash,
            };
            const bounded: u32 = @intCast(@mod(unbounded, len));

            assert(parity(signed_index) != parity(bounded));

            return @enumFromInt(bounded);
        }
    };

    pub const Triplet = struct {
        fingerprint: Fingerprint,
        index_1: BucketIndex,
        index_2: BucketIndex,

        pub fn initFromTrigram(trigram: Trigram, len: u32) Triplet {
            const split: packed struct {
                fingerprint: Fingerprint,
                padding: u24,
                index_1: u32,
            } = @bitCast(std.hash.Murmur2_64.hash(&trigram));

            const index_1: BucketIndex = @enumFromInt(split.index_1 % len);

            const fingerprint: Fingerprint = if (split.fingerprint == .none)
                @enumFromInt(1)
            else
                split.fingerprint;

            const triplet: Triplet = .{
                .fingerprint = fingerprint,
                .index_1 = index_1,
                .index_2 = index_1.alternate(fingerprint, len),
            };
            assert(triplet.index_2.alternate(fingerprint, len) == index_1);

            return triplet;
        }
    };

    pub fn init(buckets: []Bucket) CuckooFilter {
        assert(parity(buckets.len) == .even);
        return .{ .buckets = buckets };
    }

    pub fn reset(filter: CuckooFilter) void {
        @memset(filter.buckets, [1]Fingerprint{.none} ** @typeInfo(Bucket).array.len);
    }

    pub fn capacityForCount(count: u32) error{Overflow}!u32 {
        return count + (count & 1);
    }

    pub fn append(filter: CuckooFilter, random: std.Random, trigram: Trigram) error{EvictionFailed}!void {
        const triplet: Triplet = .initFromTrigram(trigram, @intCast(filter.buckets.len));

        if (filter.appendToBucket(triplet.index_1, triplet.fingerprint) or
            filter.appendToBucket(triplet.index_2, triplet.fingerprint))
        {
            return;
        }

        var fingerprint = triplet.fingerprint;
        var index = if (random.boolean()) triplet.index_1 else triplet.index_2;
        for (0..500) |_| {
            fingerprint = filter.swapFromBucket(random, index, fingerprint);
            index = index.alternate(fingerprint, @intCast(filter.buckets.len));

            if (filter.appendToBucket(index, fingerprint)) {
                return;
            }
        }

        return error.EvictionFailed;
    }

    fn bucketAt(filter: CuckooFilter, index: BucketIndex) *Bucket {
        return &filter.buckets[@intFromEnum(index)];
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

        comptime assert(@typeInfo(Bucket).array.len == 4);
        const target = &filter.bucketAt(index)[random.int(u2)];

        const old_fingerprint = target.*;
        assert(old_fingerprint != .none);

        target.* = fingerprint;

        return old_fingerprint;
    }

    pub fn contains(filter: CuckooFilter, trigram: Trigram) bool {
        const triplet: Triplet = .initFromTrigram(trigram, @intCast(filter.buckets.len));

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

    const element_count = 499;
    const filter_size = comptime CuckooFilter.capacityForCount(element_count) catch unreachable;

    var entries: std.AutoArrayHashMapUnmanaged(Trigram, void) = .empty;
    defer entries.deinit(allocator);
    try entries.ensureTotalCapacity(allocator, element_count);

    var buckets: [filter_size]CuckooFilter.Bucket = undefined;
    var filter: CuckooFilter = .init(&buckets);
    var filter_prng: std.Random.DefaultPrng = .init(42);

    for (0..2_500) |gen_prng_seed| {
        entries.clearRetainingCapacity();
        filter.reset();

        var gen_prng: std.Random.DefaultPrng = .init(gen_prng_seed);
        for (0..element_count) |_| {
            const trigram: Trigram = @bitCast(gen_prng.random().int(u24));
            entries.putAssumeCapacity(trigram, {});
            try filter.append(filter_prng.random(), trigram);
        }

        // No false negatives
        for (entries.keys()) |trigram| {
            try std.testing.expect(filter.contains(trigram));
        }

        // Reasonable false positive rate
        const fpr_count = 2_500;
        var false_positives: usize = 0;
        var negative_prng: std.Random.DefaultPrng = .init(~gen_prng_seed);
        for (0..fpr_count) |_| {
            var trigram: Trigram = @bitCast(negative_prng.random().int(u24));
            while (entries.contains(trigram)) {
                trigram = @bitCast(negative_prng.random().int(u24));
            }

            false_positives += @intFromBool(filter.contains(trigram));
        }

        const fpr = @as(f32, @floatFromInt(false_positives)) / fpr_count;

        errdefer std.log.err("fpr: {d}%", .{fpr * 100});
        try std.testing.expect(fpr < 0.035);
    }
}
