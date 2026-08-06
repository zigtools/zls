const std = @import("std");
const lsp = @import("lsp");
const tracy = @import("tracy");
const offsets = @import("offsets.zig");
const Uri = @import("Uri.zig");

io: std.Io,
allocator: std.mem.Allocator,
mutex: std.Io.Mutex = .init,
tag_set: std.array_hash_map.Auto(Tag, struct {
    version: u32 = 0,
    error_bundle_src_base_path: ?[]const u8 = null,
    /// Used to store diagnostics from `pushErrorBundle`
    error_bundle: std.zig.ErrorBundle = .empty,
    /// Used to store diagnostics from `pushSingleDocumentDiagnostics`
    diagnostics_set: Uri.ArrayHashMap(struct {
        arena: std.heap.ArenaAllocator.State = .{},
        diagnostics: []lsp.types.Diagnostic = &.{},
        error_bundle: std.zig.ErrorBundle = .empty,
    }) = .empty,
}) = .empty,
outdated_files: Uri.ArrayHashMap(void) = .empty,
transport: ?*lsp.Transport = null,
offset_encoding: offsets.Encoding = .@"utf-16",
/// When a compile error is located outside of the workspace (e.g. the standard
/// library or a dependency), report it at the innermost reference trace
/// location that is inside the workspace instead.
promote_reference_traces: bool = true,

const DiagnosticsCollection = @This();

/// Diagnostics with different tags are treated independently.
/// This enables the DiagnosticsCollection to differentiate syntax level errors from build-on-save errors.
/// Build on Save diagnostics have an tag that is the hash of the build step and the path to the `build.zig`
pub const Tag = enum(u32) {
    /// - `std.zig.Ast.parse`
    /// - ast-check
    /// - warn_style
    parse,
    /// - Build On Save
    /// - Build Runner
    _,
};

pub fn deinit(collection: *DiagnosticsCollection) void {
    for (collection.tag_set.values()) |*entry| {
        entry.error_bundle.deinit(collection.allocator);
        if (entry.error_bundle_src_base_path) |src_path| collection.allocator.free(src_path);
        for (entry.diagnostics_set.keys(), entry.diagnostics_set.values()) |uri, *lsp_diagnostic| {
            uri.deinit(collection.allocator);
            lsp_diagnostic.arena.promote(collection.allocator).deinit();
            lsp_diagnostic.error_bundle.deinit(collection.allocator);
        }
        entry.diagnostics_set.deinit(collection.allocator);
    }
    collection.tag_set.deinit(collection.allocator);
    for (collection.outdated_files.keys()) |uri| uri.deinit(collection.allocator);
    collection.outdated_files.deinit(collection.allocator);
    collection.* = undefined;
}

/// Thread-safe setter for `promote_reference_traces`.
pub fn setPromoteReferenceTraces(collection: *DiagnosticsCollection, promote_reference_traces: bool) void {
    collection.mutex.lockUncancelable(collection.io);
    defer collection.mutex.unlock(collection.io);
    collection.promote_reference_traces = promote_reference_traces;
}

pub fn pushSingleDocumentDiagnostics(
    collection: *DiagnosticsCollection,
    tag: Tag,
    document_uri: Uri,
    /// LSP and ErrorBundle will not override each other.
    ///
    /// Takes ownership on success.
    diagnostics: union(enum) {
        lsp: struct {
            arena: std.heap.ArenaAllocator.State,
            diagnostics: []lsp.types.Diagnostic,
        },
        error_bundle: std.zig.ErrorBundle,
    },
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    collection.mutex.lockUncancelable(collection.io);
    defer collection.mutex.unlock(collection.io);

    const gop_tag = try collection.tag_set.getOrPutValue(collection.allocator, tag, .{});

    {
        try collection.outdated_files.ensureUnusedCapacity(collection.allocator, 1);
        const duped_uri = try document_uri.dupe(collection.allocator);
        if (collection.outdated_files.fetchPutAssumeCapacity(duped_uri, {})) |_| duped_uri.deinit(collection.allocator);
    }

    try gop_tag.value_ptr.diagnostics_set.ensureUnusedCapacity(collection.allocator, 1);
    const duped_uri = try document_uri.dupe(collection.allocator);
    const gop_file = gop_tag.value_ptr.diagnostics_set.getOrPutAssumeCapacity(duped_uri);
    if (gop_file.found_existing) {
        duped_uri.deinit(collection.allocator);
    } else {
        gop_file.value_ptr.* = .{};
    }

    errdefer comptime unreachable;

    switch (diagnostics) {
        .lsp => |data| {
            if (gop_file.found_existing) gop_file.value_ptr.arena.promote(collection.allocator).deinit();
            gop_file.value_ptr.arena = data.arena;
            gop_file.value_ptr.diagnostics = data.diagnostics;
        },
        .error_bundle => |error_bundle| {
            if (gop_file.found_existing) gop_file.value_ptr.error_bundle.deinit(collection.allocator);
            gop_file.value_ptr.error_bundle = error_bundle;
        },
    }
}

pub fn pushErrorBundle(
    collection: *DiagnosticsCollection,
    /// All changes will affect diagnostics with the same tag.
    tag: Tag,
    /// * If the `version` is greater than the old version, all diagnostics get removed and the errors from `error_bundle` get added and the `version` is updated.
    /// * If the `version` is equal   to   the old version, the errors from `error_bundle` get added.
    /// * If the `version` is less    than the old version, the errors from `error_bundle` are ignored.
    version: u32,
    /// Used to resolve relative `std.zig.ErrorBundle.SourceLocation.src_path`
    ///
    /// The current implementation assumes that the base path is always the same for the same tag.
    src_base_path: ?[]const u8,
    error_bundle: std.zig.ErrorBundle,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var new_error_bundle: std.zig.ErrorBundle.Wip = undefined;
    try new_error_bundle.init(collection.allocator);
    defer new_error_bundle.deinit();

    collection.mutex.lockUncancelable(collection.io);
    defer collection.mutex.unlock(collection.io);

    const gop = try collection.tag_set.getOrPutValue(collection.allocator, tag, .{});
    const version_order = std.math.order(version, gop.value_ptr.version);

    switch (version_order) {
        .lt => return, // Ignore outdated diagnostics
        .eq => {},
        .gt => gop.value_ptr.version = version,
    }

    if (error_bundle.errorMessageCount() == 0 and gop.value_ptr.error_bundle.errorMessageCount() == 0) return;

    if (error_bundle.errorMessageCount() != 0) {
        try collectUrisFromErrorBundle(collection.allocator, error_bundle, src_base_path, collection.promote_reference_traces, &collection.outdated_files);
        try new_error_bundle.addBundleAsRoots(error_bundle);
    }

    if (version_order == .gt) {
        try collectUrisFromErrorBundle(
            collection.allocator,
            gop.value_ptr.error_bundle,
            gop.value_ptr.error_bundle_src_base_path,
            collection.promote_reference_traces,
            &collection.outdated_files,
        );
    } else {
        if (gop.value_ptr.error_bundle.errorMessageCount() != 0) {
            try new_error_bundle.addBundleAsRoots(gop.value_ptr.error_bundle);
        }
    }

    const compile_log_text = if (error_bundle.errorMessageCount() == 0) "" else error_bundle.getCompileLogOutput();

    var owned_error_bundle = try new_error_bundle.toOwnedBundle(compile_log_text);
    errdefer owned_error_bundle.deinit(collection.allocator);

    const duped_error_bundle_src_base_path = if (src_base_path) |base_path| try collection.allocator.dupe(u8, base_path) else null;
    errdefer if (duped_error_bundle_src_base_path) |base_path| collection.allocator.free(base_path);

    errdefer comptime unreachable;

    gop.value_ptr.error_bundle.deinit(collection.allocator);
    gop.value_ptr.error_bundle = owned_error_bundle;

    if (duped_error_bundle_src_base_path) |base_path| {
        if (gop.value_ptr.error_bundle_src_base_path) |old_base_path| {
            collection.allocator.free(old_base_path);
            gop.value_ptr.error_bundle_src_base_path = null;
        }
        gop.value_ptr.error_bundle_src_base_path = base_path;
    }
}

pub fn clearErrorBundle(collection: *DiagnosticsCollection, tag: Tag) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    collection.mutex.lockUncancelable(collection.io);
    defer collection.mutex.unlock(collection.io);

    const item = collection.tag_set.getPtr(tag) orelse return;

    collectUrisFromErrorBundle(
        collection.allocator,
        item.error_bundle,
        item.error_bundle_src_base_path,
        collection.promote_reference_traces,
        &collection.outdated_files,
    ) catch |err| switch (err) {
        error.OutOfMemory => return,
    };

    if (item.error_bundle_src_base_path) |base_path| {
        collection.allocator.free(base_path);
        item.error_bundle_src_base_path = null;
    }
    item.error_bundle.deinit(collection.allocator);
    item.error_bundle = .empty;
}

pub fn clearSingleDocumentDiagnostics(collection: *DiagnosticsCollection, document_uri: Uri) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    collection.mutex.lockUncancelable(collection.io);
    defer collection.mutex.unlock(collection.io);

    for (collection.tag_set.values()) |*item| {
        var kv = item.diagnostics_set.fetchSwapRemove(document_uri) orelse continue;
        kv.value.arena.promote(collection.allocator).deinit();
        kv.value.error_bundle.deinit(collection.allocator);

        const gop = collection.outdated_files.getOrPut(collection.allocator, kv.key) catch {
            kv.key.deinit(collection.allocator);
            continue;
        };
        if (gop.found_existing) kv.key.deinit(collection.allocator);
    }
}

fn collectUrisFromErrorBundle(
    allocator: std.mem.Allocator,
    error_bundle: std.zig.ErrorBundle,
    src_base_path: ?[]const u8,
    promote_reference_traces: bool,
    uri_set: *Uri.ArrayHashMap(void),
) error{OutOfMemory}!void {
    if (error_bundle.errorMessageCount() == 0) return;
    for (error_bundle.getMessages()) |msg_index| {
        const err = error_bundle.getErrorMessage(msg_index);
        if (err.src_loc == .none) continue;

        const promoted_src_loc: std.zig.ErrorBundle.SourceLocationIndex = if (promote_reference_traces)
            promoteSourceLocation(error_bundle, err.src_loc, src_base_path) orelse .none
        else
            .none;

        for ([2]std.zig.ErrorBundle.SourceLocationIndex{ err.src_loc, promoted_src_loc }) |src_loc_index| {
            if (src_loc_index == .none) continue;
            const src_loc = error_bundle.getSourceLocation(src_loc_index);
            const src_path = error_bundle.nullTerminatedString(src_loc.src_path);

            try uri_set.ensureUnusedCapacity(allocator, 1);
            const uri = try pathToUri(allocator, src_base_path, src_path) orelse continue;
            if (uri_set.fetchPutAssumeCapacity(uri, {})) |_| {
                uri.deinit(allocator);
            }
        }
    }
}

/// Implements "trace promotion": If an error is located outside of the
/// workspace (e.g. the standard library or a dependency), returns the location
/// of the innermost reference trace entry that is inside the workspace.
///
/// Returns `null` if the error should be reported at its original location.
fn promoteSourceLocation(
    error_bundle: std.zig.ErrorBundle,
    src_loc_index: std.zig.ErrorBundle.SourceLocationIndex,
    src_base_path: ?[]const u8,
) ?std.zig.ErrorBundle.SourceLocationIndex {
    std.debug.assert(src_loc_index != .none);
    // Without a base path, a promoted location with a relative path could not be resolved to a URI.
    const base_path = src_base_path orelse return null;
    const src_loc = error_bundle.getSourceLocation(src_loc_index);
    if (src_loc.reference_trace_len == 0) return null;
    if (isWorkspacePath(error_bundle.nullTerminatedString(src_loc.src_path), base_path)) return null;

    var it: ReferenceTraceIterator = .init(error_bundle, src_loc_index, src_loc);
    while (it.next()) |ref_trace| {
        if (ref_trace.src_loc == .none) continue; // sentinel that indicates hidden references
        const ref_src_loc = error_bundle.getSourceLocation(ref_trace.src_loc);
        const ref_src_path = error_bundle.nullTerminatedString(ref_src_loc.src_path);
        if (isWorkspacePath(ref_src_path, base_path)) return ref_trace.src_loc;
    }
    return null;
}

/// Iterates over the `std.zig.ErrorBundle.ReferenceTrace` items that trail a
/// `std.zig.ErrorBundle.SourceLocation`.
const ReferenceTraceIterator = struct {
    error_bundle: std.zig.ErrorBundle,
    index: usize,
    remaining: u32,

    comptime {
        // `init` and `next` assume that every field is encoded as a single item in `extra`.
        for (@typeInfo(std.zig.ErrorBundle.SourceLocation).@"struct".fields ++
            @typeInfo(std.zig.ErrorBundle.ReferenceTrace).@"struct".fields) |field|
        {
            std.debug.assert(@bitSizeOf(field.type) == 32);
        }
    }

    fn init(
        error_bundle: std.zig.ErrorBundle,
        src_loc_index: std.zig.ErrorBundle.SourceLocationIndex,
        src_loc: std.zig.ErrorBundle.SourceLocation,
    ) ReferenceTraceIterator {
        return .{
            .error_bundle = error_bundle,
            .index = @intFromEnum(src_loc_index) + @typeInfo(std.zig.ErrorBundle.SourceLocation).@"struct".fields.len,
            .remaining = src_loc.reference_trace_len,
        };
    }

    fn next(it: *ReferenceTraceIterator) ?std.zig.ErrorBundle.ReferenceTrace {
        if (it.remaining == 0) return null;
        it.remaining -= 1;
        defer it.index += @typeInfo(std.zig.ErrorBundle.ReferenceTrace).@"struct".fields.len;
        return .{
            .decl_name = it.error_bundle.extra[it.index],
            .src_loc = @enumFromInt(it.error_bundle.extra[it.index + 1]),
        };
    }
};

/// Whether `src_path` refers to a file inside the workspace at `src_base_path`,
/// excluding generated files inside cache directories.
fn isWorkspacePath(src_path: []const u8, src_base_path: []const u8) bool {
    const workspace_relative_path = if (std.Io.Dir.path.isAbsolute(src_path)) blk: {
        var base_path = src_base_path;
        while (base_path.len != 0 and std.Io.Dir.path.isSep(base_path[base_path.len - 1])) {
            base_path.len -= 1;
        }
        if (base_path.len == 0) return false;
        if (!std.mem.startsWith(u8, src_path, base_path)) return false;
        if (src_path.len == base_path.len) return true;
        if (!std.Io.Dir.path.isSep(src_path[base_path.len])) return false;
        break :blk src_path[base_path.len + 1 ..];
    } else src_path;

    var component_it = std.Io.Dir.path.componentIterator(workspace_relative_path);
    while (component_it.next()) |component| {
        // Keep in sync with `DocumentStore.loadDirectoryRecursive`
        if (std.mem.startsWith(u8, component.name, ".")) return false;
        if (std.mem.eql(u8, component.name, "zig-cache")) return false;
        if (std.mem.eql(u8, component.name, "zig-pkg")) return false;
    }
    return true;
}

fn pathToUri(allocator: std.mem.Allocator, base_path: ?[]const u8, src_path: []const u8) error{OutOfMemory}!?Uri {
    if (std.Io.Dir.path.isAbsolute(src_path)) {
        return try .fromPath(allocator, src_path);
    }
    const base = base_path orelse return null;
    const absolute_src_path = try std.Io.Dir.path.join(allocator, &.{ base, src_path });
    defer allocator.free(absolute_src_path);

    return try .fromPath(allocator, absolute_src_path);
}

pub fn publishDiagnostics(collection: *DiagnosticsCollection) (std.mem.Allocator.Error || std.Io.File.Writer.Error)!void {
    const io = collection.io;
    const transport = collection.transport orelse return;

    var arena_allocator: std.heap.ArenaAllocator = .init(collection.allocator);
    defer arena_allocator.deinit();

    while (true) {
        const json_message = blk: {
            try collection.mutex.lock(io);
            defer collection.mutex.unlock(io);

            const entry = collection.outdated_files.pop() orelse break;
            defer entry.key.deinit(collection.allocator);
            const document_uri: Uri = entry.key;

            _ = arena_allocator.reset(.retain_capacity);

            var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
            try collection.collectLspDiagnosticsForDocument(document_uri, collection.offset_encoding, arena_allocator.allocator(), &diagnostics);

            const notification: lsp.TypedJsonRPCNotification(lsp.types.publish_diagnostics.Params) = .{
                .method = "textDocument/publishDiagnostics",
                .params = .{
                    .uri = document_uri.raw,
                    .diagnostics = diagnostics.items,
                },
            };

            // TODO make the diagnostics serializable without requiring the mutex to be locked
            break :blk try std.json.Stringify.valueAlloc(collection.allocator, notification, .{ .emit_null_optional_fields = false });
        };
        defer collection.allocator.free(json_message);

        const old_cancel_protect = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(old_cancel_protect);

        try transport.writeJsonMessageUncancelable(io, json_message);
    }
}

fn collectLspDiagnosticsForDocument(
    collection: *DiagnosticsCollection,
    document_uri: Uri,
    offset_encoding: offsets.Encoding,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(lsp.types.Diagnostic),
) error{OutOfMemory}!void {
    for (collection.tag_set.values()) |entry| {
        if (entry.diagnostics_set.get(document_uri)) |per_document| {
            try diagnostics.appendSlice(arena, per_document.diagnostics);

            try convertErrorBundleToLSPDiangostics(
                per_document.error_bundle,
                null,
                document_uri,
                offset_encoding,
                arena,
                diagnostics,
                true,
                collection.promote_reference_traces,
            );
        }

        try convertErrorBundleToLSPDiangostics(
            entry.error_bundle,
            entry.error_bundle_src_base_path,
            document_uri,
            offset_encoding,
            arena,
            diagnostics,
            false,
            collection.promote_reference_traces,
        );
    }
}

pub const collectLspDiagnosticsForDocumentTesting = if (@import("builtin").is_test) collectLspDiagnosticsForDocument else {};

fn convertErrorBundleToLSPDiangostics(
    eb: std.zig.ErrorBundle,
    error_bundle_src_base_path: ?[]const u8,
    document_uri: Uri,
    offset_encoding: offsets.Encoding,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(lsp.types.Diagnostic),
    is_single_document: bool,
    promote_reference_traces: bool,
) error{OutOfMemory}!void {
    if (eb.errorMessageCount() == 0) return; // `getMessages` can't be called on an empty ErrorBundle
    for (eb.getMessages()) |msg_index| {
        const err = eb.getErrorMessage(msg_index);
        if (err.src_loc == .none) continue;

        const promoted_src_loc_index: ?std.zig.ErrorBundle.SourceLocationIndex = if (promote_reference_traces and !is_single_document)
            promoteSourceLocation(eb, err.src_loc, error_bundle_src_base_path)
        else
            null;

        const src_loc = eb.getSourceLocation(promoted_src_loc_index orelse err.src_loc);
        const src_path = eb.nullTerminatedString(src_loc.src_path);

        if (!is_single_document) {
            const src_uri = try pathToUri(arena, error_bundle_src_base_path, src_path) orelse continue;
            if (!document_uri.eql(src_uri)) continue;
        }

        const src_range = errorBundleSourceLocationToRange(eb, src_loc, offset_encoding);

        var related_information: std.ArrayList(lsp.types.Diagnostic.RelatedInformation) = .empty;

        if (promoted_src_loc_index != null) {
            const original_src_loc = eb.getSourceLocation(err.src_loc);
            const original_src_path = eb.nullTerminatedString(original_src_loc.src_path);
            if (try pathToUri(arena, error_bundle_src_base_path, original_src_path)) |original_uri| {
                try related_information.append(arena, .{
                    .location = .{
                        .uri = original_uri.raw,
                        .range = errorBundleSourceLocationToRange(eb, original_src_loc, offset_encoding),
                    },
                    .message = "error occurred here",
                });
            }
        }

        for (eb.getNotes(msg_index)) |eb_note_index| {
            const eb_note = eb.getErrorMessage(eb_note_index);
            if (eb_note.src_loc == .none) continue;

            const note_src_loc = eb.getSourceLocation(eb_note.src_loc);
            const note_src_path = eb.nullTerminatedString(note_src_loc.src_path);
            const note_src_range = errorBundleSourceLocationToRange(eb, note_src_loc, offset_encoding);

            const note_uri: Uri = if (is_single_document)
                document_uri
            else
                try pathToUri(arena, error_bundle_src_base_path, note_src_path) orelse continue;

            try related_information.append(arena, .{
                .location = .{
                    .uri = note_uri.raw,
                    .range = note_src_range,
                },
                .message = eb.nullTerminatedString(eb_note.msg),
            });
        }

        if (promoted_src_loc_index) |promoted_index| {
            // Preserve the remaining reference trace entries.
            var it: ReferenceTraceIterator = .init(eb, err.src_loc, eb.getSourceLocation(err.src_loc));
            while (it.next()) |ref_trace| {
                if (ref_trace.src_loc == .none) continue; // sentinel that indicates hidden references
                if (ref_trace.src_loc == promoted_index) continue;

                const ref_src_loc = eb.getSourceLocation(ref_trace.src_loc);
                const ref_src_path = eb.nullTerminatedString(ref_src_loc.src_path);
                const ref_uri = try pathToUri(arena, error_bundle_src_base_path, ref_src_path) orelse continue;

                try related_information.append(arena, .{
                    .location = .{
                        .uri = ref_uri.raw,
                        .range = errorBundleSourceLocationToRange(eb, ref_src_loc, offset_encoding),
                    },
                    .message = try std.fmt.allocPrint(arena, "referenced by '{s}'", .{eb.nullTerminatedString(ref_trace.decl_name)}),
                });
            }
        }

        var tags: std.ArrayList(lsp.types.Diagnostic.Tag) = .empty;

        var message: []const u8 = eb.nullTerminatedString(err.msg);

        if (std.mem.startsWith(u8, message, "unused ")) {
            try tags.append(arena, .Unnecessary);
        }
        if (std.mem.eql(u8, message, "found compile log statement")) {
            message = try std.fmt.allocPrint(arena, "{s}\n\nCompile Log Output:\n{s}", .{ message, eb.getCompileLogOutput() });
        }

        try diagnostics.append(arena, .{
            .range = src_range,
            .severity = .Error,
            .source = "zls",
            .message = message,
            .tags = if (tags.items.len != 0) tags.items else null,
            .relatedInformation = if (related_information.items.len != 0) related_information.items else null,
        });
    }
}

fn errorBundleSourceLocationToRange(
    error_bundle: std.zig.ErrorBundle,
    src_loc: std.zig.ErrorBundle.SourceLocation,
    offset_encoding: offsets.Encoding,
) lsp.types.Range {
    // We assume that the span is inside of the source line
    const source_line_range_utf8: lsp.types.Range = .{
        .start = .{ .line = 0, .character = src_loc.column - (src_loc.span_main - src_loc.span_start) },
        .end = .{ .line = 0, .character = src_loc.column + (src_loc.span_end - src_loc.span_main) },
    };

    if (src_loc.source_line == 0) {
        // Without the source line it is not possible to figure out the precise character value
        // The result will be incorrect if the line contains non-ascii characters
        return .{
            .start = .{ .line = src_loc.line, .character = source_line_range_utf8.start.character },
            .end = .{ .line = src_loc.line, .character = source_line_range_utf8.end.character },
        };
    }

    const source_line = error_bundle.nullTerminatedString(src_loc.source_line);
    const source_line_range = offsets.convertRangeEncoding(source_line, source_line_range_utf8, .@"utf-8", offset_encoding);

    return .{
        .start = .{ .line = src_loc.line, .character = source_line_range.start.character },
        .end = .{ .line = src_loc.line, .character = source_line_range.end.character },
    };
}

test errorBundleSourceLocationToRange {
    var eb = try createTestingErrorBundle(&.{
        .{
            .message = "First Error",
            .source_location = .{
                .src_path = "",
                .line = 2,
                .column = 6,
                .span_start = 14,
                .span_main = 14,
                .span_end = 17,
                .source_line = "const foo = 5",
            },
        },
        .{
            .message = "Second Error",
            .source_location = .{
                .src_path = "",
                .line = 1,
                .column = 4,
                .span_start = 20,
                .span_main = 23,
                .span_end = 25,
                .source_line = null,
            },
        },
    }, "");
    defer eb.deinit(std.testing.allocator);

    const src_loc0 = eb.getSourceLocation(eb.getErrorMessage(eb.getMessages()[0]).src_loc);
    const src_loc1 = eb.getSourceLocation(eb.getErrorMessage(eb.getMessages()[1]).src_loc);

    try std.testing.expectEqual(lsp.types.Range{
        .start = .{ .line = 2, .character = 6 },
        .end = .{ .line = 2, .character = 9 },
    }, errorBundleSourceLocationToRange(eb, src_loc0, .@"utf-8"));

    try std.testing.expectEqual(lsp.types.Range{
        .start = .{ .line = 1, .character = 1 },
        .end = .{ .line = 1, .character = 6 },
    }, errorBundleSourceLocationToRange(eb, src_loc1, .@"utf-8"));
}

test DiagnosticsCollection {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    try std.testing.expectEqual(0, collection.outdated_files.count());

    var eb1 = try createTestingErrorBundle(&.{.{ .message = "Living For The City" }}, "");
    defer eb1.deinit(std.testing.allocator);
    var eb2 = try createTestingErrorBundle(&.{.{ .message = "You Haven't Done Nothin'" }}, "");
    defer eb2.deinit(std.testing.allocator);
    var eb3 = try createTestingErrorBundle(&.{.{ .message = "As" }}, "");
    defer eb3.deinit(std.testing.allocator);

    const uri: Uri = try .fromPath(std.testing.allocator, testing_src_path);
    defer uri.deinit(std.testing.allocator);

    {
        try collection.pushErrorBundle(.parse, 1, null, eb1);
        try std.testing.expectEqual(1, collection.outdated_files.count());
        try std.testing.expect(uri.eql(collection.outdated_files.keys()[0]));

        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqual(lsp.types.Diagnostic.Severity.Error, diagnostics.items[0].severity);
        try std.testing.expectEqualStrings("Living For The City", diagnostics.items[0].message);
        try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
    }

    {
        try collection.pushErrorBundle(.parse, 0, null, eb2);

        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqualStrings("Living For The City", diagnostics.items[0].message);
    }

    {
        try collection.pushErrorBundle(.parse, 2, null, eb2);

        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqualStrings("You Haven't Done Nothin'", diagnostics.items[0].message);
    }

    {
        try collection.pushErrorBundle(.parse, 3, null, .empty);

        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(0, diagnostics.items.len);
    }

    {
        try collection.pushErrorBundle(@enumFromInt(16), 4, null, eb2);
        try collection.pushErrorBundle(@enumFromInt(17), 4, null, eb3);

        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(2, diagnostics.items.len);
        try std.testing.expectEqualStrings("You Haven't Done Nothin'", diagnostics.items[0].message);
        try std.testing.expectEqualStrings("As", diagnostics.items[1].message);
    }
}

test "DiagnosticsCollection - compile_log_text" {
    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{ .message = "found compile log statement" }}, "@as(comptime_int, 7)\n@as(comptime_int, 13)");
    defer eb.deinit(std.testing.allocator);

    const src_uri: Uri = try .fromPath(std.testing.allocator, testing_src_path);
    defer src_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, null, eb);
    try std.testing.expectEqual(1, collection.outdated_files.count());
    try std.testing.expect(src_uri.eql(collection.outdated_files.keys()[0]));

    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
    try collection.collectLspDiagnosticsForDocument(src_uri, .@"utf-8", arena, &diagnostics);

    try std.testing.expectEqual(1, diagnostics.items.len);
    try std.testing.expectEqual(lsp.types.Diagnostic.Severity.Error, diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(
        \\found compile log statement
        \\
        \\Compile Log Output:
        \\@as(comptime_int, 7)
        \\@as(comptime_int, 13)
    , diagnostics.items[0].message);
    try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
}

test "DiagnosticsCollection - trace promotion" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'comptime_int'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "print", .src_path = testing_std_debug_path, .line = 3, .column = 4 },
                .{ .decl_name = "main", .src_path = "src/main.zig", .line = 8, .column = 4 },
            },
            .hidden_references = 2,
        },
        .notes = &.{"some note"},
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const main_uri: Uri = try .fromPath(std.testing.allocator, testing_main_path);
    defer main_uri.deinit(std.testing.allocator);
    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);
    const std_debug_uri: Uri = try .fromPath(std.testing.allocator, testing_std_debug_path);
    defer std_debug_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb);

    // Both the promoted and the original location must be republished.
    try std.testing.expect(collection.outdated_files.contains(main_uri));
    try std.testing.expect(collection.outdated_files.contains(std_fmt_uri));

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(main_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        const diagnostic = diagnostics.items[0];
        try std.testing.expectEqualStrings("invalid format string 's' for type 'comptime_int'", diagnostic.message);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 8, .character = 4 },
            .end = .{ .line = 8, .character = 4 },
        }, diagnostic.range);

        const related_information = diagnostic.relatedInformation.?;
        try std.testing.expectEqual(3, related_information.len);

        try std.testing.expectEqualStrings("error occurred here", related_information[0].message);
        try std.testing.expectEqualStrings(std_fmt_uri.raw, related_information[0].location.uri);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 5, .character = 8 },
            .end = .{ .line = 5, .character = 8 },
        }, related_information[0].location.range);

        try std.testing.expectEqualStrings("some note", related_information[1].message);
        try std.testing.expectEqualStrings(std_fmt_uri.raw, related_information[1].location.uri);

        try std.testing.expectEqualStrings("referenced by 'print'", related_information[2].message);
        try std.testing.expectEqualStrings(std_debug_uri.raw, related_information[2].location.uri);
        try std.testing.expectEqual(3, related_information[2].location.range.start.line);
    }

    {
        // The error is no longer reported at its original location.
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(std_fmt_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(0, diagnostics.items.len);
    }
}

test "DiagnosticsCollection - trace promotion disabled" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .promote_reference_traces = false,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'comptime_int'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "main", .src_path = "src/main.zig", .line = 8, .column = 4 },
            },
        },
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const main_uri: Uri = try .fromPath(std.testing.allocator, testing_main_path);
    defer main_uri.deinit(std.testing.allocator);
    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb);

    try std.testing.expect(!collection.outdated_files.contains(main_uri));

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(std_fmt_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 5, .character = 8 },
            .end = .{ .line = 5, .character = 8 },
        }, diagnostics.items[0].range);
        try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
    }

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(main_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(0, diagnostics.items.len);
    }
}

test "DiagnosticsCollection - trace promotion without workspace reference" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'comptime_int'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "print", .src_path = testing_std_debug_path, .line = 3, .column = 4 },
            },
            .hidden_references = 2,
        },
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb);

    // The diagnostic degrades gracefully to its original location.
    var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
    try collection.collectLspDiagnosticsForDocument(std_fmt_uri, .@"utf-8", arena, &diagnostics);

    try std.testing.expectEqual(1, diagnostics.items.len);
    try std.testing.expectEqual(lsp.types.Range{
        .start = .{ .line = 5, .character = 8 },
        .end = .{ .line = 5, .character = 8 },
    }, diagnostics.items[0].range);
    try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
}

test "DiagnosticsCollection - trace promotion keeps errors inside the workspace unchanged" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "expected type 'u32', found 'bool'",
        .source_location = .{
            .src_path = "src/main.zig",
            .line = 8,
            .column = 4,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "foo", .src_path = "src/other.zig", .line = 3, .column = 4 },
            },
        },
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const main_uri: Uri = try .fromPath(std.testing.allocator, testing_main_path);
    defer main_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb);

    var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
    try collection.collectLspDiagnosticsForDocument(main_uri, .@"utf-8", arena, &diagnostics);

    try std.testing.expectEqual(1, diagnostics.items.len);
    try std.testing.expectEqual(lsp.types.Range{
        .start = .{ .line = 8, .character = 4 },
        .end = .{ .line = 8, .character = 4 },
    }, diagnostics.items[0].range);
    try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
}

test "DiagnosticsCollection - trace promotion picks the innermost workspace reference" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'u32'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "logLine", .src_path = "src/log.zig", .line = 3, .column = 4 },
                .{ .decl_name = "main", .src_path = "src/main.zig", .line = 31, .column = 4 },
            },
        },
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const log_uri: Uri = try .fromPath(std.testing.allocator, testing_log_path);
    defer log_uri.deinit(std.testing.allocator);
    const main_uri: Uri = try .fromPath(std.testing.allocator, testing_main_path);
    defer main_uri.deinit(std.testing.allocator);
    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb);

    {
        // The innermost workspace reference is chosen even though 'main' also references the error.
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(log_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 3, .character = 4 },
            .end = .{ .line = 3, .character = 4 },
        }, diagnostics.items[0].range);

        const related_information = diagnostics.items[0].relatedInformation.?;
        try std.testing.expectEqual(2, related_information.len);

        try std.testing.expectEqualStrings("error occurred here", related_information[0].message);
        try std.testing.expectEqualStrings(std_fmt_uri.raw, related_information[0].location.uri);

        try std.testing.expectEqualStrings("referenced by 'main'", related_information[1].message);
        try std.testing.expectEqualStrings(main_uri.raw, related_information[1].location.uri);
        try std.testing.expectEqual(31, related_information[1].location.range.start.line);
    }

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(main_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(0, diagnostics.items.len);
    }
}

test "DiagnosticsCollection - trace promotion without src_base_path" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'comptime_int'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "main", .src_path = "src/main.zig", .line = 8, .column = 4 },
            },
        },
    }}, "");
    defer eb.deinit(std.testing.allocator);

    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, null, eb);

    // A relative promoted location could not be resolved to a URI, so the
    // diagnostic must remain at its original location instead of being dropped.
    var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
    try collection.collectLspDiagnosticsForDocument(std_fmt_uri, .@"utf-8", arena, &diagnostics);

    try std.testing.expectEqual(1, diagnostics.items.len);
    try std.testing.expectEqual(lsp.types.Range{
        .start = .{ .line = 5, .character = 8 },
        .end = .{ .line = 5, .character = 8 },
    }, diagnostics.items[0].range);
    try std.testing.expectEqual(null, diagnostics.items[0].relatedInformation);
}

test "DiagnosticsCollection - trace promotion after merging error bundles" {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var collection: DiagnosticsCollection = .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
    };
    defer collection.deinit();

    var eb1 = try createTestingErrorBundle(&.{.{
        .message = "invalid format string 's' for type 'comptime_int'",
        .source_location = .{
            .src_path = testing_std_fmt_path,
            .line = 5,
            .column = 8,
            .source_line = null,
            .reference_trace = &.{
                .{ .decl_name = "print", .src_path = testing_std_debug_path, .line = 3, .column = 4 },
                .{ .decl_name = "main", .src_path = "src/main.zig", .line = 8, .column = 4 },
            },
        },
    }}, "");
    defer eb1.deinit(std.testing.allocator);

    var eb2 = try createTestingErrorBundle(&.{.{
        .message = "expected type 'u32', found 'bool'",
        .source_location = .{
            .src_path = "src/other.zig",
            .line = 2,
            .column = 6,
            .source_line = null,
        },
    }}, "");
    defer eb2.deinit(std.testing.allocator);

    const main_uri: Uri = try .fromPath(std.testing.allocator, testing_main_path);
    defer main_uri.deinit(std.testing.allocator);
    const other_uri: Uri = try .fromPath(std.testing.allocator, testing_other_path);
    defer other_uri.deinit(std.testing.allocator);
    const std_fmt_uri: Uri = try .fromPath(std.testing.allocator, testing_std_fmt_path);
    defer std_fmt_uri.deinit(std.testing.allocator);

    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb1);
    // Pushing with the same version merges both bundles which copies the reference trace.
    try collection.pushErrorBundle(.parse, 1, testing_workspace_path, eb2);

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(main_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 8, .character = 4 },
            .end = .{ .line = 8, .character = 4 },
        }, diagnostics.items[0].range);

        const related_information = diagnostics.items[0].relatedInformation.?;
        try std.testing.expectEqual(2, related_information.len);
        try std.testing.expectEqualStrings("error occurred here", related_information[0].message);
        try std.testing.expectEqualStrings(std_fmt_uri.raw, related_information[0].location.uri);
        try std.testing.expectEqualStrings("referenced by 'print'", related_information[1].message);
    }

    {
        var diagnostics: std.ArrayList(lsp.types.Diagnostic) = .empty;
        try collection.collectLspDiagnosticsForDocument(other_uri, .@"utf-8", arena, &diagnostics);

        try std.testing.expectEqual(1, diagnostics.items.len);
        try std.testing.expectEqual(lsp.types.Range{
            .start = .{ .line = 2, .character = 6 },
            .end = .{ .line = 2, .character = 6 },
        }, diagnostics.items[0].range);
    }
}

test isWorkspacePath {
    try std.testing.expect(isWorkspacePath("src/main.zig", testing_workspace_path));
    try std.testing.expect(isWorkspacePath(testing_main_path, testing_workspace_path));

    try std.testing.expect(!isWorkspacePath(testing_std_fmt_path, testing_workspace_path));
    try std.testing.expect(!isWorkspacePath("../dependency/src/main.zig", testing_workspace_path));
    try std.testing.expect(!isWorkspacePath(".zig-cache/generated.zig", testing_workspace_path));
    try std.testing.expect(!isWorkspacePath("zig-cache/generated.zig", testing_workspace_path));
}

const testing_src_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\sample.zig",
    else => "/sample.zig",
};

const testing_workspace_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\workspace",
    else => "/workspace",
};

const testing_main_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\workspace\\src\\main.zig",
    else => "/workspace/src/main.zig",
};

const testing_log_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\workspace\\src\\log.zig",
    else => "/workspace/src/log.zig",
};

const testing_other_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\workspace\\src\\other.zig",
    else => "/workspace/src/other.zig",
};

const testing_std_fmt_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\zig\\lib\\std\\fmt.zig",
    else => "/zig/lib/std/fmt.zig",
};

const testing_std_debug_path = switch (@import("builtin").os.tag) {
    .windows => "C:\\zig\\lib\\std\\debug.zig",
    else => "/zig/lib/std/debug.zig",
};

const TestingSourceLocation = struct {
    src_path: []const u8,
    line: u32 = 0,
    column: u32 = 0,
    span_start: u32 = 0,
    span_main: u32 = 0,
    span_end: u32 = 0,
    source_line: ?[]const u8 = "",
    reference_trace: []const struct {
        decl_name: []const u8,
        src_path: []const u8,
        line: u32 = 0,
        column: u32 = 0,
    } = &.{},
    /// Appends a sentinel reference trace entry that indicates hidden references.
    hidden_references: ?u32 = null,
};

fn createTestingSourceLocation(
    eb: *std.zig.ErrorBundle.Wip,
    options: TestingSourceLocation,
) error{OutOfMemory}!std.zig.ErrorBundle.SourceLocationIndex {
    var trace_src_locs: std.ArrayList(std.zig.ErrorBundle.SourceLocationIndex) = .empty;
    defer trace_src_locs.deinit(std.testing.allocator);

    for (options.reference_trace) |ref_trace| {
        try trace_src_locs.append(std.testing.allocator, try eb.addSourceLocation(.{
            .src_path = try eb.addString(ref_trace.src_path),
            .line = ref_trace.line,
            .column = ref_trace.column,
            .span_start = 0,
            .span_main = 0,
            .span_end = 0,
        }));
    }

    const src_loc = try eb.addSourceLocation(.{
        .src_path = try eb.addString(options.src_path),
        .line = options.line,
        .column = options.column,
        .span_start = options.span_start,
        .span_main = options.span_main,
        .span_end = options.span_end,
        .source_line = if (options.source_line) |source_line| try eb.addString(source_line) else 0,
        .reference_trace_len = @intCast(options.reference_trace.len + @intFromBool(options.hidden_references != null)),
    });

    // The reference trace entries must be added directly after their source location.
    for (options.reference_trace, trace_src_locs.items) |ref_trace, trace_src_loc| {
        try eb.addReferenceTrace(.{
            .decl_name = try eb.addString(ref_trace.decl_name),
            .src_loc = trace_src_loc,
        });
    }
    if (options.hidden_references) |count| {
        try eb.addReferenceTrace(.{ .decl_name = count, .src_loc = .none });
    }

    return src_loc;
}

fn createTestingErrorBundle(
    messages: []const struct {
        message: []const u8,
        count: u32 = 1,
        source_location: TestingSourceLocation = .{ .src_path = testing_src_path },
        notes: []const []const u8 = &.{},
    },
    compile_log_text: []const u8,
) error{OutOfMemory}!std.zig.ErrorBundle {
    var eb: std.zig.ErrorBundle.Wip = undefined;
    try eb.init(std.testing.allocator);
    errdefer eb.deinit();

    for (messages) |msg| {
        const src_loc = try createTestingSourceLocation(&eb, msg.source_location);
        try eb.addRootErrorMessage(.{
            .msg = try eb.addString(msg.message),
            .count = msg.count,
            .src_loc = src_loc,
            .notes_len = @intCast(msg.notes.len),
        });
        const notes_start = try eb.reserveNotes(@intCast(msg.notes.len));
        for (notes_start.., msg.notes) |note_slot, note_message| {
            const note_index = @intFromEnum(try eb.addErrorMessage(.{
                .msg = try eb.addString(note_message),
                .src_loc = try createTestingSourceLocation(&eb, .{ .src_path = msg.source_location.src_path }),
            }));
            eb.extra.items[note_slot] = note_index;
        }
    }

    return eb.toOwnedBundle(compile_log_text);
}
