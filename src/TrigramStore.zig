//! `Trigram -> Declaration` mapping.
//! `finalize` must be called before any queries are executed.

const std = @import("std");
const analysis = @import("analysis.zig");
const fastfilter = @import("fastfilter");
const Declaration = analysis.Declaration;
const DocumentStore = @import("DocumentStore.zig");
const CompactingMultiList = @import("compacting_multi_list.zig").CompactingMultiList;

const TrigramStore = @This();

/// Fast lookup with false positives.
filter: fastfilter.BinaryFuse8,
/// Map index is a slice in decls.
lookup: std.AutoArrayHashMapUnmanaged(Trigram, void),
decls: CompactingMultiList(Declaration.Index).Compacted,

pub const Builder = struct {
    lookup: std.AutoArrayHashMapUnmanaged(Trigram, void),
    decls: CompactingMultiList(Declaration.Index),

    pub fn init(allocator: std.mem.Allocator, decls_capacity: u32) error{OutOfMemory}!Builder {
        var builder = Builder{ .lookup = .{}, .decls = .{} };
        try builder.decls.ensureTotalCapacity(allocator, decls_capacity);
        return builder;
    }

    /// Appends declaration with `name`'s trigrams to store.
    pub fn append(
        builder: *Builder,
        allocator: std.mem.Allocator,
        name: []const u8,
        declaration: Declaration.Index,
    ) error{ OutOfMemory, InvalidUtf8 }!void {
        std.debug.assert(name.len >= 3);

        // These will either be exact, or in the case of non-ASCII text
        // be a slight overshoot.
        try builder.lookup.ensureUnusedCapacity(allocator, name.len - 2);

        const view = try std.unicode.Utf8View.init(name);

        var iterator = view.iterator();
        while (iterator.nextCodepoint()) |codepoint_0| {
            const next_idx = iterator.i;
            const codepoint_1 = iterator.nextCodepoint() orelse break;
            const codepoint_2 = iterator.nextCodepoint() orelse break;

            const gop = builder.lookup.getOrPutAssumeCapacity(.{
                .codepoint_0 = codepoint_0,
                .codepoint_1 = codepoint_1,
                .codepoint_2 = codepoint_2,
            });

            if (!gop.found_existing) {
                _ = try builder.decls.appendToNewListAssumeCapacity(allocator, declaration);
            } else {
                builder.decls.appendAssumeCapacity(@intCast(gop.index), declaration);
            }

            iterator.i = next_idx;
        }
    }

    /// Must be called before any queries are executed.
    pub fn finalize(builder: *Builder, allocator: std.mem.Allocator) error{OutOfMemory}!TrigramStore {
        var filter = try fastfilter.BinaryFuse8.init(allocator, builder.lookup.count());
        filter.populate(allocator, @ptrCast(builder.lookup.keys())) catch |err| switch (err) {
            error.KeysLikelyNotUnique => {
                // NOTE(SuperAuguste): Ignore this? It shouldn't happen ever
                // and should, at worst, break lookups for one document, unless
                // the filter state is all messed up (might crash at lookup time?).
                // TODO: Look into this more.
            },
            else => |e| return e,
        };

        const store = TrigramStore{
            .filter = filter,
            .lookup = builder.lookup,
            .decls = try builder.decls.compact(allocator),
        };
        builder.decls.deinit(allocator);

        return store;
    }
};

pub const Trigram = packed struct(u64) {
    codepoint_0: u21,
    codepoint_1: u21,
    codepoint_2: u21,
    padding: u1 = 0,
};

pub fn init(allocator: std.mem.Allocator, handle: *DocumentStore.Handle) error{ InvalidUtf8, OutOfMemory }!TrigramStore {
    const doc_scope = try handle.getDocumentScope();
    var builder = try Builder.init(allocator, doc_scope.trigram_decls_mapping_capacity);
    for (doc_scope.declarations_that_should_be_trigram_indexed.items) |decl_idx| {
        const decl = doc_scope.declarations.get(@intFromEnum(decl_idx));
        try builder.append(allocator, handle.tree.tokenSlice(decl.nameToken(handle.tree)), decl_idx);
    }
    return try builder.finalize(allocator);
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
    store.filter.deinit(allocator);
    store.lookup.deinit(allocator);
    store.decls.deinit(allocator);
    store.* = undefined;
}

pub fn getDeclarationsForTrigram(store: TrigramStore, trigram: Trigram) ?[]const Declaration.Index {
    return store.decls.slice(@intCast(store.lookup.getIndex(trigram) orelse return null));
}
