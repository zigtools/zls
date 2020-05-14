const std = @import("std");
const types = @import("types.zig");
const URI = @import("uri.zig");

const DocumentStore = @This();

pub const Handle = struct {
    document: types.TextDocument,
    count: usize,
    import_uris: std.ArrayList([]const u8),

    pub fn uri(handle: Handle) []const u8 {
        return handle.document.uri;
    }

    /// Returns the zig AST resulting from parsing the document's text, even
    /// if it contains errors.
    pub fn dirtyTree(handle: Handle, allocator: *std.mem.Allocator) !*std.zig.ast.Tree {
        return try std.zig.parse(allocator, handle.document.text);
    }

    /// Returns a zig AST with no errors, either from the current text or
    /// the stored sane text, null if no such ast exists.
    pub fn saneTree(handle: Handle, allocator: *std.mem.Allocator) !?*std.zig.ast.Tree {
        var tree = try std.zig.parse(allocator, handle.document.text);
        if (tree.errors.len == 0) return tree;

        tree.deinit();
        if (handle.document.sane_text) |sane| {
            return try std.zig.parse(allocator, sane);
        }
        return null;
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

// TODO: Normalize URIs somehow, probably just lowercase
pub fn openDocument(self: *DocumentStore, uri: []const u8, text: []const u8) !*Handle {
    if (self.handles.get(uri)) |entry| {
        std.debug.warn("Document already open: {}, incrementing count\n", .{uri});
        entry.value.count += 1;
        std.debug.warn("New count: {}\n", .{entry.value.count});
        return &entry.value;
    }

    std.debug.warn("Opened document: {}\n", .{uri});
    const duped_text = try std.mem.dupe(self.allocator, u8, text);
    errdefer self.allocator.free(duped_text);
    const duped_uri = try std.mem.dupe(self.allocator, u8, uri);
    errdefer self.allocator.free(duped_uri);

    var handle = Handle{
        .count = 1,
        .import_uris = std.ArrayList([]const u8).init(self.allocator),
        .document = .{
            .uri = duped_uri,
            .text = duped_text,
            .mem = duped_text,
            .sane_text = null,
        },
    };
    try self.checkSanity(&handle);
    try self.handles.putNoClobber(duped_uri, handle);
    return &(self.handles.get(duped_uri) orelse unreachable).value;
}

fn decrementCount(self: *DocumentStore, uri: []const u8) void {
    if (self.handles.get(uri)) |entry| {
        entry.value.count -= 1;
        if (entry.value.count == 0) {
            std.debug.warn("Freeing document: {}\n", .{uri});
        }

        self.allocator.free(entry.value.document.uri);
        self.allocator.free(entry.value.document.mem);
        if (entry.value.document.sane_text) |sane| {
            self.allocator.free(sane);
        }

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
fn checkSanity(self: *DocumentStore, handle: *Handle) !void {
    const dirty_tree = try handle.dirtyTree(self.allocator);
    defer dirty_tree.deinit();

    if (dirty_tree.errors.len > 0) return;

    std.debug.warn("New sane text for document {}\n", .{handle.uri()});
    if (handle.document.sane_text) |sane| {
        self.allocator.free(sane);
    }

    handle.document.sane_text = try std.mem.dupe(self.allocator, u8, handle.document.text);
}

pub fn applyChanges(self: *DocumentStore, handle: *Handle, content_changes: std.json.Array) !void {
    var document = &handle.document;

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

    try self.checkSanity(handle);
}

// @TODO: We only reduce the count upon closing,
// find a way to reduce it when removing imports.
// Perhaps on new sane text we can go through imports
// and remove those that are in the import_uris table
// but not in the file anymore.
pub const ImportContext = struct {
    store: *DocumentStore,
    handle: *Handle,
    trees: std.ArrayList(*std.zig.ast.Tree),

    pub fn lastTree(self: *ImportContext) *std.zig.ast.Tree {
        std.debug.assert(self.trees.items.len > 0);
        return self.trees.items[self.trees.items.len - 1];
    }

    pub fn onImport(self: *ImportContext, import_str: []const u8) !?*std.zig.ast.Node {
        const allocator = self.store.allocator;
        
        const final_uri = if (std.mem.eql(u8, import_str, "std"))
            if (self.store.std_uri) |std_root_uri| try std.mem.dupe(allocator, u8, std_root_uri)
            else {
                std.debug.warn("Cannot resolve std library import, path is null.\n", .{});
                return null;
            }
        else b: {
            // Find relative uri
            const path = try URI.parse(allocator, self.handle.uri());
            defer allocator.free(path);

            const dir_path = std.fs.path.dirname(path) orelse "";
            const import_path = try std.fs.path.resolve(allocator, &[_][]const u8 {
                dir_path, import_str
            });

            break :b import_path;
        };

        // @TODO Clean up code, lots of repetition
        {
            errdefer allocator.free(final_uri);

            // Check if we already imported this.
            for (self.handle.import_uris.items) |uri| {
                // If we did, set our new handle and return the parsed tree root node.
                if (std.mem.eql(u8, uri, final_uri)) {
                    self.handle = self.store.getHandle(final_uri) orelse return null;
                    if (try self.handle.saneTree(allocator)) |tree| {
                        try self.trees.append(tree);
                        return &tree.root_node.base;
                    }
                    return null;
                }
            }
        }

        // New import.
        // Add to import table of current handle.
        try self.handle.import_uris.append(final_uri);
    
        // Check if the import is already opened by others.
        if (self.store.getHandle(final_uri)) |new_handle| {
            // If it is, increment the count, set our new handle and return the parsed tree root node.
            new_handle.count += 1;
            self.handle = new_handle;
            if (try self.handle.saneTree(allocator)) |tree| {
                try self.trees.append(tree);
                return &tree.root_node.base;
            }
            return null;
        }

        // New document, read the file then call into openDocument.
        const file_path = try URI.parse(allocator, final_uri);
        defer allocator.free(file_path);

        var file = std.fs.cwd().openFile(file_path, .{}) catch {
            std.debug.warn("Cannot open import file {}", .{file_path});
            return null;
        };

        defer file.close();
        const size = std.math.cast(usize, try file.getEndPos()) catch std.math.maxInt(usize);

        // TODO: This is wasteful, we know we don't need to copy the text on this openDocument call
        const file_contents = try allocator.alloc(u8, size);
        defer allocator.free(file_contents);

        file.inStream().readNoEof(file_contents) catch {
            std.debug.warn("Could not read from file {}", .{file_path});
            return null;
        };

        self.handle = try openDocument(self.store, final_uri, file_contents);
        if (try self.handle.saneTree(allocator)) |tree| {
            try self.trees.append(tree);
            return &tree.root_node.base;
        }
        return null;
    }

    pub fn deinit(self: *ImportContext) void {
        for (self.trees.items) |tree| {
            tree.deinit();
        }

        self.trees.deinit();
    }
};

pub fn importContext(self: *DocumentStore, handle: *Handle) ImportContext {
    return .{
        .store = self,
        .handle = handle,
        .trees = std.ArrayList(*std.zig.ast.Tree).init(self.allocator),
    };
}

pub fn deinit(self: *DocumentStore) void {
    // @TODO: Deinit everything!

    self.handles.deinit();
}
