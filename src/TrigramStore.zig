//! A queryable per-file set of workspace symbols.

const std = @import("std");
const ast = @import("ast.zig");
const Ast = @import("zirp").Ast;
const assert = std.debug.assert;
const offsets = @import("offsets.zig");

pub const TrigramStore = @This();

pub const Trigram = [3]u8;

pub const Declaration = struct {
    pub const Index = enum(u32) { _ };

    pub const Kind = enum {
        variable,
        constant,
        field,
        function,
        test_function,
    };

    /// Either `.identifier` or `.string_literal`.
    name: Ast.Token.Index,
    kind: Kind,
};

filter_buckets: ?[]CuckooFilter.Bucket,
trigram_to_declarations: std.array_hash_map.Auto(Trigram, std.ArrayList(Declaration.Index)),
declarations: std.MultiArrayList(Declaration),

pub fn init(
    allocator: std.mem.Allocator,
    tree: *const Ast,
) error{OutOfMemory}!TrigramStore {
    var store: TrigramStore = .{
        .filter_buckets = null,
        .trigram_to_declarations = .empty,
        .declarations = .empty,
    };
    errdefer store.deinit(allocator);

    var walker: ast.Walker = try .init(allocator, tree, .root);
    defer walker.deinit(allocator);

    var in_function_stack: std.ArrayList(bool) = try .initCapacity(allocator, 16);
    defer in_function_stack.deinit(allocator);

    while (try walker.next(allocator, tree)) |entry| {
        switch (entry) {
            .open => |node| switch (node.tag(tree)) {
                .decl_fn => try in_function_stack.append(allocator, true),
                .type_fn => {
                    const fn_token = node.mainToken(tree);
                    if (fn_token.add(1).tag(tree) != .name) continue;

                    try store.appendDeclaration(
                        allocator,
                        tree,
                        fn_token.add(1),
                        .function,
                    );
                },
                .decl_test => {
                    try in_function_stack.append(allocator, true);
                    const decl_test: Ast.Member.Test = node.cast(.decl_test, tree).?;
                    const name_token = decl_test.name(tree) orelse continue;

                    try store.appendDeclaration(
                        allocator,
                        tree,
                        name_token,
                        .test_function,
                    );
                },
                .type_container => try in_function_stack.append(allocator, false),

                // BRANCH_TODO is the `in_function` still necessary since we are excluding `.var_local`
                // .var_local,
                .var_global,
                => {
                    const in_function = in_function_stack.last() orelse false;
                    if (in_function) continue;

                    const var_decl: Ast.Member.GlobalVar = node.cast(.var_global, tree).?;

                    const kind: Declaration.Kind = switch (var_decl.mutability.get(tree)) {
                        .@"var" => .variable,
                        .@"const" => .constant,
                    };
                    const name_token = var_decl.name(tree) orelse continue;

                    if (isVarDeclAlias(tree, var_decl)) continue;

                    try store.appendDeclaration(
                        allocator,
                        tree,
                        name_token,
                        kind,
                    );
                },
                .member_field => {
                    const member_field: Ast.Member.Field = node.cast(.member_field, tree).?;
                    const name_leaf = member_field.name orelse continue;
                    const name_token = name_leaf.token(tree);
                    std.debug.assert(name_token.tag(tree) == .name);

                    try store.appendDeclaration(
                        allocator,
                        tree,
                        name_token,
                        .field,
                    );
                },
                else => {},
            },
            .close => |node| switch (node.tag(tree)) {
                .decl_fn, .decl_test => assert(in_function_stack.pop().?),
                .type_container => assert(!in_function_stack.pop().?),
                else => {},
            },
        }
    }

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

        const filter_capacity = CuckooFilter.capacityForCount(trigrams.len) catch unreachable;
        const buckets = try allocator.alloc(CuckooFilter.Bucket, filter_capacity);
        errdefer comptime unreachable;

        const filter: CuckooFilter = .{ .buckets = buckets };
        filter.reset();

        for (trigrams) |trigram| {
            filter.append(prng.random(), trigram) catch |err| switch (err) {
                error.EvictionFailed => {
                    // This should generally be quite rare.
                    allocator.free(buckets);
                    break;
                },
            };
        } else {
            store.filter_buckets = buckets;
        }
    }

    return store;
}

pub fn deinit(store: *TrigramStore, allocator: std.mem.Allocator) void {
    if (store.filter_buckets) |buckets| allocator.free(buckets);
    for (store.trigram_to_declarations.values()) |*list| {
        list.deinit(allocator);
    }
    store.trigram_to_declarations.deinit(allocator);
    store.declarations.deinit(allocator);
    store.* = undefined;
}

/// Asserts `query.len >= 1`. Asserts declaration_buffer.items.len == 0.
pub fn declarationsForQuery(
    store: *const TrigramStore,
    allocator: std.mem.Allocator,
    query: []const u8,
    declaration_buffer: *std.ArrayList(Declaration.Index),
) error{OutOfMemory}!void {
    assert(query.len >= 1);
    assert(declaration_buffer.items.len == 0);

    if (store.filter_buckets) |buckets| {
        const filter: CuckooFilter = .{ .buckets = buckets };
        var ti: TrigramIterator = .init(query);
        while (ti.next()) |trigram| {
            if (!filter.contains(trigram)) {
                return;
            }
        }
    }

    var ti: TrigramIterator = .init(query);

    const first = (store.trigram_to_declarations.get(ti.next() orelse return) orelse return).items;

    try declaration_buffer.resize(allocator, first.len * 2);

    var len = first.len;
    @memcpy(declaration_buffer.items[0..len], first);

    while (ti.next()) |trigram| {
        const old_len = len;
        len = mergeIntersection(
            (store.trigram_to_declarations.get(trigram) orelse {
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

fn appendDeclaration(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    tree: *const Ast,
    name_token: Ast.Token.Index,
    kind: Declaration.Kind,
) error{OutOfMemory}!void {
    const raw_name = name_token.slice(tree);

    const strategy: enum { raw, smart }, const name = switch (name_token.tag(tree)) {
        .string => .{ .raw, raw_name[1 .. raw_name.len - 1] },
        .name => if (std.mem.startsWith(u8, raw_name, "@"))
            .{ .raw, raw_name[2 .. raw_name.len - 1] }
        else
            .{ .smart, raw_name },
        else => unreachable,
    };

    switch (strategy) {
        .raw => {
            if (name.len < 3) return;
            for (0..name.len - 2) |index| {
                var trigram = name[index..][0..3].*;
                for (&trigram) |*char| char.* = std.ascii.toLower(char.*);
                try store.appendOneTrigram(allocator, trigram);
            }
        },
        .smart => {
            var it: TrigramIterator = .init(name);
            while (it.next()) |trigram| {
                try store.appendOneTrigram(allocator, trigram);
            }
        },
    }

    try store.declarations.append(allocator, .{
        .name = name_token,
        .kind = kind,
    });
}

fn appendOneTrigram(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    trigram: Trigram,
) error{OutOfMemory}!void {
    const declaration_index: Declaration.Index = @fromBackingInt(@intCast(store.declarations.len));

    const gop = try store.trigram_to_declarations.getOrPutValue(allocator, trigram, .empty);

    if (gop.value_ptr.last() != declaration_index) {
        try gop.value_ptr.append(allocator, declaration_index);
    }
}

/// Check if the init expression is a sequence of field accesses
/// where the last field name matches the var decl name:
///
/// ```zig
/// const Foo = a.Foo; // true
/// const Bar = a.b.Bar; // true
/// const Baz = a.Bar; // false
/// const Biz = 5; // false
/// ```
fn isVarDeclAlias(tree: *const Ast, var_decl: Ast.Member.GlobalVar) bool {
    switch (var_decl.mutability.get(tree)) {
        .@"const" => {},
        .@"var" => return false,
    }

    const init_node = var_decl.init orelse return false;
    const init_expr: Ast.Expr.DotAccess = (init_node.cast(.dot_access, tree) orelse return false).get(tree);

    const alias_name = offsets.identifierTokenToNameSlice(tree, var_decl.name(tree) orelse return false);
    const target_name = offsets.identifierTokenToNameSlice(tree, init_expr.rhs.token(tree));
    if (!std.mem.eql(u8, alias_name, target_name)) return false;

    var current_node = init_expr.lhs;
    while (true) {
        switch (current_node.idx.tag(tree)) {
            .leaf => return current_node.cast(.name, tree) != null,
            .expr_dot_access => current_node = current_node.cast(.dot_access, tree).?.get(tree).lhs,
            else => return false,
        }
    }
}

/// Splits a symbol into trigrams with the following rules:
/// - ignore `_` symbol characters
/// - convert symbol characters to lowercase
/// - append `\x00` (null bytes) to the symbol if symbol length is not divisible by the trigram length
const TrigramIterator = struct {
    symbol: []const u8,
    index: usize,

    trigram_buffer: Trigram,
    trigram_buffer_index: u2,

    pub fn init(symbol: []const u8) TrigramIterator {
        assert(symbol.len != 0);
        return .{
            .symbol = symbol,
            .index = 0,
            .trigram_buffer = @splat(0),
            .trigram_buffer_index = 0,
        };
    }

    pub fn next(ti: *TrigramIterator) ?Trigram {
        while (ti.index < ti.symbol.len) {
            defer ti.index += 1;
            const c = std.ascii.toLower(ti.symbol[ti.index]);
            if (c == '_') continue;

            if (ti.trigram_buffer_index < 3) {
                ti.trigram_buffer[ti.trigram_buffer_index] = c;
                ti.trigram_buffer_index += 1;
                continue;
            }

            defer {
                @memmove(ti.trigram_buffer[0..2], ti.trigram_buffer[1..3]);
                ti.trigram_buffer[2] = c;
            }
            return ti.trigram_buffer;
        } else if (ti.trigram_buffer_index > 0) {
            ti.trigram_buffer_index = 0;
            return ti.trigram_buffer;
        } else {
            return null;
        }
    }
};

test TrigramIterator {
    try testTrigramIterator("a", &.{"a\x00\x00".*});
    try testTrigramIterator("ab", &.{"ab\x00".*});
    try testTrigramIterator("abc", &.{"abc".*});

    try testTrigramIterator("hello", &.{ "hel".*, "ell".*, "llo".* });
    try testTrigramIterator("HELLO", &.{ "hel".*, "ell".*, "llo".* });
    try testTrigramIterator("HellO", &.{ "hel".*, "ell".*, "llo".* });

    try testTrigramIterator("a_", &.{"a\x00\x00".*});
    try testTrigramIterator("ab_", &.{"ab\x00".*});
    try testTrigramIterator("abc_", &.{"abc".*});

    try testTrigramIterator("_a", &.{"a\x00\x00".*});
    try testTrigramIterator("_a_", &.{"a\x00\x00".*});
    try testTrigramIterator("_a__", &.{"a\x00\x00".*});

    try testTrigramIterator("_", &.{});
    try testTrigramIterator("__", &.{});
    try testTrigramIterator("___", &.{});

    try testTrigramIterator("He_ll_O", &.{ "hel".*, "ell".*, "llo".* });
    try testTrigramIterator("He__ll___O", &.{ "hel".*, "ell".*, "llo".* });
    try testTrigramIterator("__He__ll__O_", &.{ "hel".*, "ell".*, "llo".* });

    try testTrigramIterator("HellO__World___HelloWorld", &.{
        "hel".*, "ell".*, "llo".*,
        "low".*, "owo".*, "wor".*,
        "orl".*, "rld".*, "ldh".*,
        "dhe".*, "hel".*, "ell".*,
        "llo".*, "low".*, "owo".*,
        "wor".*, "orl".*, "rld".*,
    });
}

fn testTrigramIterator(
    input: []const u8,
    expected: []const Trigram,
) !void {
    const allocator = std.testing.allocator;

    var actual_buffer: std.ArrayList(Trigram) = .empty;
    defer actual_buffer.deinit(allocator);

    var it: TrigramIterator = .init(input);
    while (it.next()) |trigram| {
        try actual_buffer.append(allocator, trigram);
    }

    try @import("testing.zig").expectEqual(expected, actual_buffer.items);
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
        } else if (@backingInt(a_val) < @backingInt(b_val)) {
            a_idx += 1;
        } else {
            b_idx += 1;
        }
    }

    return out_idx;
}

const CuckooFilter = struct {
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
            return precomputed_odd_hashes[@backingInt(fingerprint)];
        }
    };

    pub const Bucket = [4]Fingerprint;
    pub const BucketIndex = enum(u32) {
        _,

        pub fn alternate(index: BucketIndex, fingerprint: Fingerprint, len: u32) BucketIndex {
            assert(@backingInt(index) < len);
            assert(fingerprint != .none);

            const signed_index: i64 = @backingInt(index);
            const odd_hash: i64 = fingerprint.oddHash();

            const unbounded = switch (parity(signed_index)) {
                .even => signed_index + odd_hash,
                .odd => signed_index - odd_hash,
            };
            const bounded: u32 = @intCast(@mod(unbounded, len));

            assert(parity(signed_index) != parity(bounded));

            return @fromBackingInt(bounded);
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

            const index_1: BucketIndex = @fromBackingInt(split.index_1 % len);

            const fingerprint: Fingerprint = if (split.fingerprint == .none)
                @fromBackingInt(1)
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
        @memset(filter.buckets, @splat(.none));
    }

    pub fn capacityForCount(count: usize) error{Overflow}!usize {
        const overallocated_count = std.math.divCeil(usize, try std.math.mul(usize, count, 105), 100) catch |err| switch (err) {
            error.DivisionByZero => unreachable,
            else => |e| return e,
        };
        return overallocated_count + (overallocated_count & 1);
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
        return &filter.buckets[@backingInt(index)];
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

    fn parity(integer: anytype) enum(u1) { even, odd } {
        return @fromBackingInt(@intCast(integer & 1));
    }
};

test CuckooFilter {
    const allocator = std.testing.allocator;

    const element_count = 499;
    const filter_size = comptime CuckooFilter.capacityForCount(element_count) catch unreachable;

    var entries: std.array_hash_map.Auto(Trigram, void) = .empty;
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
