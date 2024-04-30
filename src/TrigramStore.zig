//! `Trigram -> Declaration` mapping.
//! `finalize` must be called before any queries are executed.

const std = @import("std");
const analysis = @import("analysis.zig");
const fastfilter = @import("fastfilter");
const Declaration = analysis.Declaration;
const DocumentStore = @import("DocumentStore.zig");

const TrigramStore = @This();

/// Fast lookup with false positives.
filter: ?fastfilter.BinaryFuse8 = null,
/// Index into `extra`.
/// Body:
///     prev: u32 or none = maxInt(u32)
///     decl: Declaration.Index
lookup: std.AutoArrayHashMapUnmanaged(Trigram, u32) = .{},
extra: std.ArrayListUnmanaged(u32) = .{},

pub const Trigram = packed struct(u64) {
    codepoint_0: u21,
    codepoint_1: u21,
    codepoint_2: u21,
    padding: u1 = 0,
};

pub fn init(allocator: std.mem.Allocator, handle: *DocumentStore.Handle) error{ InvalidUtf8, OutOfMemory }!TrigramStore {
    const doc_scope = try handle.getDocumentScope();
    var store = TrigramStore{};
    for (doc_scope.declarations_that_should_be_trigram_indexed.items) |decl_idx| {
        const decl = doc_scope.declarations.get(@intFromEnum(decl_idx));
        try store.append(allocator, handle.tree.tokenSlice(decl.nameToken(handle.tree)), decl_idx);
    }
    try store.finalize(allocator);
    return store;
}

/// Must be called before any queries are executed.
pub fn finalize(store: *TrigramStore, allocator: std.mem.Allocator) error{OutOfMemory}!void {
    store.filter = try fastfilter.BinaryFuse8.init(allocator, store.lookup.count());
    store.filter.?.populate(allocator, @ptrCast(store.lookup.keys())) catch |err| switch (err) {
        error.KeysLikelyNotUnique => {
            // NOTE(SuperAuguste): Ignore this? It shouldn't happen ever
            // and should, at worst, break lookups for one document, unless
            // the filter state is all messed up (might crash at lookup time?).
            // TODO: Look into this more.
        },
        else => |e| return e,
    };
}

pub fn reset(store: *TrigramStore, allocator: std.mem.Allocator) void {
    if (store.filter) |filter| {
        filter.deinit(allocator);
        store.filter = null;
    }
    store.lookup.clearRetainingCapacity();
    store.extra.items.len = 0;
}

pub fn deinit(store: *TrigramStore, allocator: std.mem.Allocator) void {
    if (store.filter) |filter| filter.deinit(allocator);
    store.lookup.deinit(allocator);
    store.extra.deinit(allocator);
    store.* = undefined;
}

/// Appends declaration with `name`'s trigrams to store.
pub fn append(
    store: *TrigramStore,
    allocator: std.mem.Allocator,
    name: []const u8,
    declaration: Declaration.Index,
) error{ OutOfMemory, InvalidUtf8 }!void {
    std.debug.assert(name.len >= 3);

    // These will either be exact, or in the case of non-ASCII text
    // be a slight overshoot.
    try store.lookup.ensureUnusedCapacity(allocator, name.len - 2);
    try store.extra.ensureUnusedCapacity(allocator, (name.len - 2) * 2);

    const view = try std.unicode.Utf8View.init(name);

    var iterator = view.iterator();
    while (iterator.nextCodepoint()) |codepoint_0| {
        const next_idx = iterator.i;
        const codepoint_1 = iterator.nextCodepoint() orelse break;
        const codepoint_2 = iterator.nextCodepoint() orelse break;

        const gop = store.lookup.getOrPutAssumeCapacity(.{
            .codepoint_0 = codepoint_0,
            .codepoint_1 = codepoint_1,
            .codepoint_2 = codepoint_2,
        });

        const prev_or_none = if (gop.found_existing) gop.value_ptr.* else std.math.maxInt(u32);
        const new_last = store.extra.items.len;
        store.extra.appendSliceAssumeCapacity(&.{ prev_or_none, @intFromEnum(declaration) });

        gop.value_ptr.* = @intCast(new_last);

        iterator.i = next_idx;
    }
}

pub const TrigramIterator = struct {
    extra: []const u32,
    extra_index: ?u32,

    pub fn next(iterator: *TrigramIterator) Declaration.OptionalIndex {
        if (iterator.extra_index == null) return .none;
        const prev, const decl = iterator.extra[iterator.extra_index.?..][0..2].*;
        iterator.extra_index = if (prev == std.math.maxInt(u32)) null else prev;
        return @as(Declaration.Index, @enumFromInt(decl)).toOptional();
    }
};

/// Iterates all declarations containing `trigram`.
pub fn iterate(store: TrigramStore, trigram: Trigram) TrigramIterator {
    return .{
        .extra = store.extra.items,
        .extra_index = store.lookup.get(trigram),
    };
}
