const std = @import("std");
const types = @import("types.zig");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");

const DocumentStore = @This();

pub const Handle = struct {
    document: types.TextDocument,
    count: usize,
    import_uris: std.ArrayList([]const u8),

    pub fn uri(handle: Handle) []const u8 {
        return handle.document.uri;
    }

    /// Returns a zig AST, with all its errors.
    pub fn tree(handle: Handle, allocator: *std.mem.Allocator) !*std.zig.ast.Tree {
        return try std.zig.parse(allocator, handle.document.text);
    }
};

allocator: *std.mem.Allocator,
handles: std.StringHashMap(Handle),
std_uri: ?[]const u8,

pub fn init(self: *DocumentStore, allocator: *std.mem.Allocator, zig_lib_path: ?[]const u8) !void {
    self.allocator = allocator;
    self.handles = std.StringHashMap(Handle).init(allocator);
    errdefer self.handles.deinit();

    if (zig_lib_path) |zpath| {
        const std_path = std.fs.path.resolve(allocator, &[_][]const u8 {
            zpath, "./std/std.zig"
        }) catch |err| block: {
            std.debug.warn("Failed to resolve zig std library path, error: {}\n", .{err});
            self.std_uri = null;
            return;
        };

        defer allocator.free(std_path);
        // Get the std_path as a URI, so we can just append to it!
        self.std_uri = try URI.fromPath(allocator, std_path);
        std.debug.warn("Standard library base uri: {}\n", .{self.std_uri});
    } else {
        self.std_uri = null;
    }
}

/// This function asserts the document is not open yet and takes ownership
/// of the uri and text passed in.
fn newDocument(self: *DocumentStore, uri: []const u8, text: []u8) !*Handle {
    std.debug.warn("Opened document: {}\n", .{uri});

    var handle = Handle{
        .count = 1,
        .import_uris = std.ArrayList([]const u8).init(self.allocator),
        .document = .{
            .uri = uri,
            .text = text,
            .mem = text,
        },
    };
    const kv = try self.handles.getOrPutValue(uri, handle);
    return &kv.value;
}

pub fn openDocument(self: *DocumentStore, uri: []const u8, text: []const u8) !*Handle {
    if (self.handles.get(uri)) |entry| {
        std.debug.warn("Document already open: {}, incrementing count\n", .{uri});
        entry.value.count += 1;
        std.debug.warn("New count: {}\n", .{entry.value.count});
        return &entry.value;
    }

    const duped_text = try std.mem.dupe(self.allocator, u8, text);
    errdefer self.allocator.free(duped_text);
    const duped_uri = try std.mem.dupe(self.allocator, u8, uri);
    errdefer self.allocator.free(duped_uri);

    return try self.newDocument(duped_uri, duped_text);
}

fn decrementCount(self: *DocumentStore, uri: []const u8) void {
    if (self.handles.get(uri)) |entry| {
        entry.value.count -= 1;
        if (entry.value.count > 0)
            return;

        std.debug.warn("Freeing document: {}\n", .{uri});
        self.allocator.free(entry.value.document.mem);

        for (entry.value.import_uris.items) |import_uri| {
            self.decrementCount(import_uri);
            self.allocator.free(import_uri);
        }

        entry.value.import_uris.deinit();

        const uri_key = entry.key;
        self.handles.removeAssertDiscard(uri);
        self.allocator.free(uri_key);
    }
}

pub fn closeDocument(self: *DocumentStore, uri: []const u8) void {
    self.decrementCount(uri);
}

pub fn getHandle(self: *DocumentStore, uri: []const u8) ?*Handle {
    if (self.handles.get(uri)) |entry| {
        return &entry.value;
    }

    return null;
}

// Check if the document text is now sane, move it to sane_text if so.
fn removeOldImports(self: *DocumentStore, handle: *Handle) !void {
    std.debug.warn("New text for document {}\n", .{handle.uri()});
    // TODO: Better algorithm or data structure?
    // Removing the imports is costly since they live in an array list
    // Perhaps we should use an AutoHashMap([]const u8, {}) ?

    // Try to detect removed imports and decrement their counts.
    if (handle.import_uris.items.len == 0) return;

    const tree = try handle.tree(self.allocator);
    defer tree.deinit();

    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();

    var import_strs = std.ArrayList([]const u8).init(&arena.allocator);
    try analysis.collectImports(&import_strs, tree);

    const still_exist = try arena.allocator.alloc(bool, handle.import_uris.items.len);
    for (still_exist) |*ex| {
        ex.* = false;
    }

    for (import_strs.items) |str| {
        const uri = (try uriFromImportStr(self, &arena.allocator, handle.*, str)) orelse continue;

        var idx: usize = 0;
        exists_loop: while (idx < still_exist.len) : (idx += 1) {
            if (still_exist[idx]) continue;

            if (std.mem.eql(u8, handle.import_uris.items[idx], uri)) {
                still_exist[idx] = true;
                break :exists_loop;
            }
        }
    }

    // Go through still_exist, remove the items that are false and decrement their handle counts.
    var offset: usize = 0;
    var idx: usize = 0;
    while (idx < still_exist.len) : (idx += 1) {
        if (still_exist[idx]) continue;

        std.debug.warn("Import removed: {}\n", .{handle.import_uris.items[idx - offset]});
        const uri = handle.import_uris.orderedRemove(idx - offset);
        offset += 1;

        self.closeDocument(uri);
        self.allocator.free(uri);
    }
}

pub fn applyChanges(self: *DocumentStore, handle: *Handle, content_changes: std.json.Array) !void {
    const document = &handle.document;

    for (content_changes.items) |change| {
        if (change.Object.getValue("range")) |range| {
            const start_pos = types.Position{
                .line = range.Object.getValue("start").?.Object.getValue("line").?.Integer,
                .character = range.Object.getValue("start").?.Object.getValue("character").?.Integer
            };
            const end_pos = types.Position{
                .line = range.Object.getValue("end").?.Object.getValue("line").?.Integer,
                .character = range.Object.getValue("end").?.Object.getValue("character").?.Integer
            };

            const change_text = change.Object.getValue("text").?.String;
            const start_index = try document.positionToIndex(start_pos);
            const end_index = try document.positionToIndex(end_pos);

            const old_len = document.text.len;
            const new_len = old_len + change_text.len;
            if (new_len > document.mem.len) {
                // We need to reallocate memory.
                // We reallocate twice the current filesize or the new length, if it's more than that
                // so that we can reduce the amount of realloc calls.
                // We can tune this to find a better size if needed.
                const realloc_len = std.math.max(2 * old_len, new_len);
                document.mem = try self.allocator.realloc(document.mem, realloc_len);
            }

            // The first part of the string, [0 .. start_index] need not be changed.
            // We then copy the last part of the string, [end_index ..] to its
            //    new position, [start_index + change_len .. ]
            std.mem.copy(u8, document.mem[start_index + change_text.len..][0 .. old_len - end_index], document.mem[end_index .. old_len]);
            // Finally, we copy the changes over.
            std.mem.copy(u8, document.mem[start_index..][0 .. change_text.len], change_text);

            // Reset the text substring.
            document.text = document.mem[0 .. new_len];
        } else {
            const change_text = change.Object.getValue("text").?.String;
            const old_len = document.text.len;

            if (change_text.len > document.mem.len) {
                // Like above.
                const realloc_len = std.math.max(2 * old_len, change_text.len);
                document.mem = try self.allocator.realloc(document.mem, realloc_len);
            }

            std.mem.copy(u8, document.mem[0 .. change_text.len], change_text);
            document.text = document.mem[0 .. change_text.len];
        }
    }

    try self.removeOldImports(handle);
}

fn uriFromImportStr(store: *DocumentStore, allocator: *std.mem.Allocator, handle: Handle, import_str: []const u8) !?[]const u8 {
    return if (std.mem.eql(u8, import_str, "std"))
        if (store.std_uri) |std_root_uri| try std.mem.dupe(allocator, u8, std_root_uri)
        else {
            std.debug.warn("Cannot resolve std library import, path is null.\n", .{});
            return null;
        }
    else b: {
        // Find relative uri
        const path = try URI.parse(allocator, handle.uri());
        defer allocator.free(path);

        const dir_path = std.fs.path.dirname(path) orelse "";
        const import_path = try std.fs.path.resolve(allocator, &[_][]const u8 {
            dir_path, import_str
        });

        defer allocator.free(import_path);

        break :b (try URI.fromPath(allocator, import_path));
    };
}

pub const AnalysisContext = struct {
    store: *DocumentStore,
    handle: *Handle,
    // This arena is used for temporary allocations while analyzing,
    // not for the tree allocations.
    arena: *std.heap.ArenaAllocator,
    tree: *std.zig.ast.Tree,
    scope_nodes: []*std.zig.ast.Node,

    fn refreshScopeNodes(self: *AnalysisContext) !void {
        var scope_nodes = std.ArrayList(*std.zig.ast.Node).init(&self.arena.allocator);
        try analysis.addChildrenNodes(&scope_nodes, self.tree, &self.tree.root_node.base);
        self.scope_nodes = scope_nodes.items;
    }

    pub fn onImport(self: *AnalysisContext, import_str: []const u8) !?*std.zig.ast.Node {
        const allocator = self.store.allocator;
        const final_uri = (try uriFromImportStr(self.store, self.store.allocator, self.handle.*, import_str)) orelse return null;

        std.debug.warn("Import final URI: {}\n", .{final_uri});
        var consumed_final_uri = false;
        defer if (!consumed_final_uri) allocator.free(final_uri);

        // Check if we already imported this.
        for (self.handle.import_uris.items) |uri| {
            // If we did, set our new handle and return the parsed tree root node.
            if (std.mem.eql(u8, uri, final_uri)) {
                self.handle = self.store.getHandle(final_uri) orelse return null;

                self.tree.deinit();
                self.tree = try self.handle.tree(allocator);
                try self.refreshScopeNodes();
                return &self.tree.root_node.base;
            }
        }

        // New import.
        // Check if the import is already opened by others.
        if (self.store.getHandle(final_uri)) |new_handle| {
            // If it is, increment the count, set our new handle and return the parsed tree root node.
            new_handle.count += 1;
            self.handle = new_handle;

            self.tree.deinit();
            self.tree = try self.handle.tree(allocator);
            try self.refreshScopeNodes();
            return &self.tree.root_node.base;
        }

        // New document, read the file then call into openDocument.
        const file_path = try URI.parse(allocator, final_uri);
        defer allocator.free(file_path);

        var file = std.fs.cwd().openFile(file_path, .{}) catch {
            std.debug.warn("Cannot open import file {}\n", .{file_path});
            return null;
        };

        defer file.close();
        const size = std.math.cast(usize, try file.getEndPos()) catch std.math.maxInt(usize);

        {
            const file_contents = try allocator.alloc(u8, size);
            errdefer allocator.free(file_contents);

            file.inStream().readNoEof(file_contents) catch {
                std.debug.warn("Could not read from file {}\n", .{file_path});
                return null;
            };

            // Add to import table of current handle.
            try self.handle.import_uris.append(final_uri);
            consumed_final_uri = true;

            // Swap handles and get new tree.
            // This takes ownership of the passed uri and text.
            const duped_final_uri = try std.mem.dupe(allocator, u8, final_uri);
            errdefer allocator.free(duped_final_uri);
            self.handle = try newDocument(self.store, duped_final_uri, file_contents);
        }

        // Free old tree, add new one if it exists.
        // If we return null, no one should access the tree.
        self.tree.deinit();
        self.tree = try self.handle.tree(allocator);
        try self.refreshScopeNodes();
        return &self.tree.root_node.base;
    }

    pub fn deinit(self: *AnalysisContext) void {
        self.tree.deinit();
    }
};

pub fn analysisContext(self: *DocumentStore, handle: *Handle, arena: *std.heap.ArenaAllocator, position: types.Position) !AnalysisContext {
    const tree = try handle.tree(self.allocator);

    var scope_nodes = std.ArrayList(*std.zig.ast.Node).init(&arena.allocator);
    try analysis.declsFromIndex(&scope_nodes, tree, try handle.document.positionToIndex(position));

    return AnalysisContext{
        .store = self,
        .handle = handle,
        .arena = arena,
        .tree = tree,
        .scope_nodes = scope_nodes.items,
    };
}

pub fn deinit(self: *DocumentStore) void {
    var entry_iterator = self.handles.iterator();
    while (entry_iterator.next()) |entry| {
        self.allocator.free(entry.value.document.mem);

        for (entry.value.import_uris.items) |uri| {
            self.allocator.free(uri);
        }

        entry.value.import_uris.deinit();
        self.allocator.free(entry.key);
    }

    self.handles.deinit();
    if (self.std_uri) |uri| {
        self.allocator.free(uri);
    }
}
