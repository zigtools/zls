const std = @import("std");
const types = @import("types.zig");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.doc_store);

const DocumentStore = @This();

const BuildFile = struct {
    const Pkg = struct {
        name: []const u8,
        uri: []const u8,
    };

    refs: usize,
    uri: []const u8,
    packages: std.ArrayListUnmanaged(Pkg),
};

pub const Handle = struct {
    document: types.TextDocument,
    count: usize,
    import_uris: std.ArrayList([]const u8),
    tree: *std.zig.ast.Tree,
    document_scope: analysis.DocumentScope,

    associated_build_file: ?*BuildFile,
    is_build_file: ?*BuildFile,

    pub fn uri(handle: Handle) []const u8 {
        return handle.document.uri;
    }
};

allocator: *std.mem.Allocator,
handles: std.StringHashMap(*Handle),
zig_exe_path: ?[]const u8,
build_files: std.ArrayListUnmanaged(*BuildFile),
build_runner_path: []const u8,
build_runner_cache_path: []const u8,
std_uri: ?[]const u8,

pub fn init(
    self: *DocumentStore,
    allocator: *std.mem.Allocator,
    zig_exe_path: ?[]const u8,
    build_runner_path: []const u8,
    build_runner_cache_path: []const u8,
    zig_lib_path: ?[]const u8,
) !void {
    self.allocator = allocator;
    self.handles = std.StringHashMap(*Handle).init(allocator);
    self.zig_exe_path = zig_exe_path;
    self.build_files = .{};
    self.build_runner_path = build_runner_path;
    self.build_runner_cache_path = build_runner_cache_path;
    self.std_uri = try stdUriFromLibPath(allocator, zig_lib_path);
}

const LoadPackagesContext = struct {
    build_file: *BuildFile,
    allocator: *std.mem.Allocator,
    build_runner_path: []const u8,
    build_runner_cache_path: []const u8,
    zig_exe_path: []const u8,
};

fn loadPackages(context: LoadPackagesContext) !void {
    const allocator = context.allocator;
    const build_file = context.build_file;
    const build_runner_path = context.build_runner_path;
    const build_runner_cache_path = context.build_runner_cache_path;
    const zig_exe_path = context.zig_exe_path;

    const build_file_path = try URI.parse(allocator, build_file.uri);
    defer allocator.free(build_file_path);
    const directory_path = build_file_path[0 .. build_file_path.len - "build.zig".len];

    const zig_run_result = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            zig_exe_path,
            "run",
            build_runner_path,
            "--cache-dir",
            build_runner_cache_path,
            "--pkg-begin",
            "@build@",
            build_file_path,
            "--pkg-end",
        },
    });

    defer {
        allocator.free(zig_run_result.stdout);
        allocator.free(zig_run_result.stderr);
    }

    switch (zig_run_result.term) {
        .Exited => |exit_code| {
            if (exit_code == 0) {
                log.debug("Finished zig run for build file {s}", .{build_file.uri});

                for (build_file.packages.items) |old_pkg| {
                    allocator.free(old_pkg.name);
                    allocator.free(old_pkg.uri);
                }

                build_file.packages.shrinkAndFree(allocator, 0);
                var line_it = std.mem.split(zig_run_result.stdout, "\n");
                while (line_it.next()) |line| {
                    if (std.mem.indexOfScalar(u8, line, '\x00')) |zero_byte_idx| {
                        const name = line[0..zero_byte_idx];
                        const rel_path = line[zero_byte_idx + 1 ..];

                        const pkg_abs_path = try std.fs.path.resolve(allocator, &[_][]const u8{ directory_path, rel_path });
                        defer allocator.free(pkg_abs_path);

                        const pkg_uri = try URI.fromPath(allocator, pkg_abs_path);
                        errdefer allocator.free(pkg_uri);

                        const duped_name = try std.mem.dupe(allocator, u8, name);
                        errdefer allocator.free(duped_name);

                        (try build_file.packages.addOne(allocator)).* = .{
                            .name = duped_name,
                            .uri = pkg_uri,
                        };
                    }
                }
            }
        },
        else => return error.RunFailed,
    }
}

/// This function asserts the document is not open yet and takes ownership
/// of the uri and text passed in.
fn newDocument(self: *DocumentStore, uri: []const u8, text: []u8) anyerror!*Handle {
    log.debug("Opened document: {s}", .{uri});

    var handle = try self.allocator.create(Handle);
    errdefer self.allocator.destroy(handle);

    const tree = try std.zig.parse(self.allocator, text);
    errdefer tree.deinit();

    const document_scope = try analysis.makeDocumentScope(self.allocator, tree);
    errdefer document_scope.deinit(self.allocator);

    handle.* = Handle{
        .count = 1,
        .import_uris = std.ArrayList([]const u8).init(self.allocator),
        .document = .{
            .uri = uri,
            .text = text,
            .mem = text,
        },
        .tree = tree,
        .document_scope = document_scope,
        .associated_build_file = null,
        .is_build_file = null,
    };

    // TODO: Better logic for detecting std or subdirectories?
    const in_std = std.mem.indexOf(u8, uri, "/std/") != null;
    if (self.zig_exe_path != null and std.mem.endsWith(u8, uri, "/build.zig") and !in_std) {
        log.debug("Document is a build file, extracting packages...", .{});
        // This is a build file.
        var build_file = try self.allocator.create(BuildFile);
        errdefer self.allocator.destroy(build_file);

        build_file.* = .{
            .refs = 1,
            .uri = try std.mem.dupe(self.allocator, u8, uri),
            .packages = .{},
        };

        try self.build_files.append(self.allocator, build_file);
        handle.is_build_file = build_file;

        // TODO: Do this in a separate thread?
        // It can take quite long.
        loadPackages(.{
            .build_file = build_file,
            .allocator = self.allocator,
            .build_runner_path = self.build_runner_path,
            .build_runner_cache_path = self.build_runner_cache_path,
            .zig_exe_path = self.zig_exe_path.?,
        }) catch |err| {
            log.debug("Failed to load packages of build file {s} (error: {})", .{ build_file.uri, err });
        };
    } else if (self.zig_exe_path != null and !in_std) {
        // Look into build files and keep the one that lives closest to the document in the directory structure
        var candidate: ?*BuildFile = null;
        {
            var uri_chars_matched: usize = 0;
            for (self.build_files.items) |build_file| {
                const build_file_base_uri = build_file.uri[0 .. std.mem.lastIndexOfScalar(u8, build_file.uri, '/').? + 1];

                if (build_file_base_uri.len > uri_chars_matched and std.mem.startsWith(u8, uri, build_file_base_uri)) {
                    uri_chars_matched = build_file_base_uri.len;
                    candidate = build_file;
                }
            }
            if (candidate) |build_file| {
                log.debug("Found a candidate associated build file: `{s}`", .{build_file.uri});
            }
        }

        // Then, try to find the closest build file.
        var curr_path = try URI.parse(self.allocator, uri);
        defer self.allocator.free(curr_path);
        while (true) {
            if (curr_path.len == 0) break;

            if (std.mem.lastIndexOfScalar(u8, curr_path[0 .. curr_path.len - 1], std.fs.path.sep)) |idx| {
                // This includes the last separator
                curr_path = curr_path[0 .. idx + 1];

                // Try to open the folder, then the file.
                var folder = std.fs.cwd().openDir(curr_path, .{}) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
                defer folder.close();

                var build_file = folder.openFile("build.zig", .{}) catch |err| switch (err) {
                    error.FileNotFound, error.AccessDenied => continue,
                    else => return err,
                };
                defer build_file.close();

                // Calculate build file's URI
                var candidate_path = try std.mem.concat(self.allocator, u8, &[_][]const u8{ curr_path, "build.zig" });
                defer self.allocator.free(candidate_path);
                const build_file_uri = try URI.fromPath(self.allocator, candidate_path);
                errdefer self.allocator.free(build_file_uri);

                if (candidate) |candidate_build_file| {
                    // Check if it is the same as the current candidate we got from the existing build files.
                    // If it isn't, we need to read the file and make a new build file.
                    if (std.mem.eql(u8, candidate_build_file.uri, build_file_uri)) {
                        self.allocator.free(build_file_uri);
                        break;
                    }
                }

                // Read the build file, create a new document, set the candidate to the new build file.
                const build_file_text = try build_file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
                errdefer self.allocator.free(build_file_text);

                const build_file_handle = try self.newDocument(build_file_uri, build_file_text);
                candidate = build_file_handle.is_build_file.?;
                break;
            } else break;
        }
        // Finally, associate the candidate build file, if any, to the new document.
        if (candidate) |build_file| {
            build_file.refs += 1;
            handle.associated_build_file = build_file;
            log.debug("Associated build file `{s}` to document `{s}`", .{ build_file.uri, handle.uri() });
        }
    }

    try self.handles.putNoClobber(uri, handle);
    return handle;
}

pub fn openDocument(self: *DocumentStore, uri: []const u8, text: []const u8) !*Handle {
    if (self.handles.getEntry(uri)) |entry| {
        log.debug("Document already open: {s}, incrementing count", .{uri});
        entry.value.count += 1;
        if (entry.value.is_build_file) |build_file| {
            build_file.refs += 1;
        }
        log.debug("New count: {}", .{entry.value.count});
        return entry.value;
    }

    const duped_text = try std.mem.dupe(self.allocator, u8, text);
    errdefer self.allocator.free(duped_text);
    const duped_uri = try std.mem.dupe(self.allocator, u8, uri);
    errdefer self.allocator.free(duped_uri);

    return try self.newDocument(duped_uri, duped_text);
}

fn decrementBuildFileRefs(self: *DocumentStore, build_file: *BuildFile) void {
    build_file.refs -= 1;
    if (build_file.refs == 0) {
        log.debug("Freeing build file {s}", .{build_file.uri});
        for (build_file.packages.items) |pkg| {
            self.allocator.free(pkg.name);
            self.allocator.free(pkg.uri);
        }
        build_file.packages.deinit(self.allocator);

        // Decrement count of the document since one count comes
        // from the build file existing.
        self.decrementCount(build_file.uri);
        self.allocator.free(build_file.uri);

        // Remove the build file from the array list
        _ = self.build_files.swapRemove(std.mem.indexOfScalar(*BuildFile, self.build_files.items, build_file).?);
        self.allocator.destroy(build_file);
    }
}

fn decrementCount(self: *DocumentStore, uri: []const u8) void {
    if (self.handles.getEntry(uri)) |entry| {
        if (entry.value.count == 0) return;
        entry.value.count -= 1;

        if (entry.value.count > 0)
            return;

        log.debug("Freeing document: {s}", .{uri});

        if (entry.value.associated_build_file) |build_file| {
            self.decrementBuildFileRefs(build_file);
        }

        if (entry.value.is_build_file) |build_file| {
            self.decrementBuildFileRefs(build_file);
        }

        entry.value.tree.deinit();
        self.allocator.free(entry.value.document.mem);

        for (entry.value.import_uris.items) |import_uri| {
            self.decrementCount(import_uri);
            self.allocator.free(import_uri);
        }

        entry.value.document_scope.deinit(self.allocator);
        entry.value.import_uris.deinit();
        self.allocator.destroy(entry.value);
        const uri_key = entry.key;
        self.handles.removeAssertDiscard(uri);
        self.allocator.free(uri_key);
    }
}

pub fn closeDocument(self: *DocumentStore, uri: []const u8) void {
    self.decrementCount(uri);
}

pub fn getHandle(self: *DocumentStore, uri: []const u8) ?*Handle {
    return self.handles.get(uri);
}

// Check if the document text is now sane, move it to sane_text if so.
fn refreshDocument(self: *DocumentStore, handle: *Handle, zig_lib_path: ?[]const u8) !void {
    log.debug("New text for document {s}", .{handle.uri()});
    handle.tree.deinit();
    handle.tree = try std.zig.parse(self.allocator, handle.document.text);

    handle.document_scope.deinit(self.allocator);
    handle.document_scope = try analysis.makeDocumentScope(self.allocator, handle.tree);

    // TODO: Better algorithm or data structure?
    // Removing the imports is costly since they live in an array list
    // Perhaps we should use an AutoHashMap([]const u8, {}) ?

    // Try to detect removed imports and decrement their counts.
    if (handle.import_uris.items.len == 0) return;

    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();

    var import_strs = std.ArrayList([]const u8).init(&arena.allocator);
    try analysis.collectImports(&import_strs, handle.tree);

    const still_exist = try arena.allocator.alloc(bool, handle.import_uris.items.len);
    for (still_exist) |*ex| {
        ex.* = false;
    }

    const std_uri = try stdUriFromLibPath(&arena.allocator, zig_lib_path);
    for (import_strs.items) |str| {
        const uri = (try self.uriFromImportStr(&arena.allocator, handle.*, str)) orelse continue;

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

        log.debug("Import removed: {s}", .{handle.import_uris.items[idx - offset]});
        const uri = handle.import_uris.orderedRemove(idx - offset);
        offset += 1;

        self.decrementCount(uri);
        self.allocator.free(uri);
    }
}

pub fn applySave(self: *DocumentStore, handle: *Handle) !void {
    if (handle.is_build_file) |build_file| {
        loadPackages(.{
            .build_file = build_file,
            .allocator = self.allocator,
            .build_runner_path = self.build_runner_path,
            .build_runner_cache_path = self.build_runner_cache_path,
            .zig_exe_path = self.zig_exe_path.?,
        }) catch |err| {
            log.debug("Failed to load packages of build file {s} (error: {})", .{ build_file.uri, err });
        };
    }
}

pub fn applyChanges(
    self: *DocumentStore,
    handle: *Handle,
    content_changes: std.json.Array,
    offset_encoding: offsets.Encoding,
    zig_lib_path: ?[]const u8,
) !void {
    const document = &handle.document;

    for (content_changes.items) |change| {
        if (change.Object.get("range")) |range| {
            std.debug.assert(document.text.ptr == document.mem.ptr);

            const start_pos = types.Position{
                .line = range.Object.get("start").?.Object.get("line").?.Integer,
                .character = range.Object.get("start").?.Object.get("character").?.Integer,
            };
            const end_pos = types.Position{
                .line = range.Object.get("end").?.Object.get("line").?.Integer,
                .character = range.Object.get("end").?.Object.get("character").?.Integer,
            };

            const change_text = change.Object.get("text").?.String;
            const start_index = (try offsets.documentPosition(document.*, start_pos, offset_encoding)).absolute_index;
            const end_index = (try offsets.documentPosition(document.*, end_pos, offset_encoding)).absolute_index;

            const old_len = document.text.len;
            const new_len = old_len - (end_index - start_index) + change_text.len;
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
            if (new_len < old_len) {
                std.mem.copy(u8, document.mem[start_index + change_text.len ..][0 .. old_len - end_index], document.mem[end_index..old_len]);
            } else {
                std.mem.copyBackwards(u8, document.mem[start_index + change_text.len ..][0 .. old_len - end_index], document.mem[end_index..old_len]);
            }
            // Finally, we copy the changes over.
            std.mem.copy(u8, document.mem[start_index..][0..change_text.len], change_text);

            // Reset the text substring.
            document.text = document.mem[0..new_len];
        } else {
            const change_text = change.Object.get("text").?.String;
            const old_len = document.text.len;

            if (change_text.len > document.mem.len) {
                // Like above.
                const realloc_len = std.math.max(2 * old_len, change_text.len);
                document.mem = try self.allocator.realloc(document.mem, realloc_len);
            }

            std.mem.copy(u8, document.mem[0..change_text.len], change_text);
            document.text = document.mem[0..change_text.len];
        }
    }

    try self.refreshDocument(handle, zig_lib_path);
}

pub fn uriFromImportStr(
    self: *DocumentStore,
    allocator: *std.mem.Allocator,
    handle: Handle,
    import_str: []const u8,
) !?[]const u8 {
    if (std.mem.eql(u8, import_str, "std")) {
        if (self.std_uri) |uri| return try std.mem.dupe(allocator, u8, uri) else {
            log.debug("Cannot resolve std library import, path is null.", .{});
            return null;
        }
    } else if (std.mem.eql(u8, import_str, "builtin")) {
        return null; // TODO find the correct zig-cache folder
    } else if (!std.mem.endsWith(u8, import_str, ".zig")) {
        if (handle.associated_build_file) |build_file| {
            for (build_file.packages.items) |pkg| {
                if (std.mem.eql(u8, import_str, pkg.name)) {
                    return try std.mem.dupe(allocator, u8, pkg.uri);
                }
            }
        }
        return null;
    } else {
        // Find relative uri
        const path = try URI.parse(allocator, handle.uri());
        defer allocator.free(path);

        const dir_path = std.fs.path.dirname(path) orelse "";
        const import_path = try std.fs.path.resolve(allocator, &[_][]const u8{
            dir_path, import_str,
        });

        defer allocator.free(import_path);

        return try URI.fromPath(allocator, import_path);
    }
}

pub fn resolveImport(self: *DocumentStore, handle: *Handle, import_str: []const u8) !?*Handle {
    const allocator = self.allocator;
    const final_uri = (try self.uriFromImportStr(
        self.allocator,
        handle.*,
        import_str,
    )) orelse return null;

    var consumed_final_uri = false;
    defer if (!consumed_final_uri) allocator.free(final_uri);

    // Check if we already imported this.
    for (handle.import_uris.items) |uri| {
        // If we did, set our new handle and return the parsed tree root node.
        if (std.mem.eql(u8, uri, final_uri)) {
            return self.getHandle(final_uri);
        }
    }

    // New import.
    // Check if the import is already opened by others.
    if (self.getHandle(final_uri)) |new_handle| {
        // If it is, append it to our imports, increment the count, set our new handle
        // and return the parsed tree root node.
        try handle.import_uris.append(final_uri);
        consumed_final_uri = true;

        new_handle.count += 1;
        return new_handle;
    }

    // New document, read the file then call into openDocument.
    const file_path = try URI.parse(allocator, final_uri);
    defer allocator.free(file_path);

    var file = std.fs.cwd().openFile(file_path, .{}) catch {
        log.debug("Cannot open import file {s}", .{file_path});
        return null;
    };

    defer file.close();
    const size = std.math.cast(usize, try file.getEndPos()) catch std.math.maxInt(usize);

    {
        const file_contents = try allocator.alloc(u8, size);
        errdefer allocator.free(file_contents);

        file.reader().readNoEof(file_contents) catch {
            log.debug("Could not read from file {s}", .{file_path});
            return null;
        };

        // Add to import table of current handle.
        try handle.import_uris.append(final_uri);
        consumed_final_uri = true;

        // Swap handles.
        // This takes ownership of the passed uri and text.
        const duped_final_uri = try std.mem.dupe(allocator, u8, final_uri);
        errdefer allocator.free(duped_final_uri);
        return try self.newDocument(duped_final_uri, file_contents);
    }
}

fn stdUriFromLibPath(allocator: *std.mem.Allocator, zig_lib_path: ?[]const u8) !?[]const u8 {
    if (zig_lib_path) |zpath| {
        const std_path = std.fs.path.resolve(allocator, &[_][]const u8{
            zpath, "./std/std.zig",
        }) catch |err| {
            log.debug("Failed to resolve zig std library path, error: {}", .{err});
            return null;
        };

        defer allocator.free(std_path);
        // Get the std_path as a URI, so we can just append to it!
        return try URI.fromPath(allocator, std_path);
    }

    return null;
}

pub fn deinit(self: *DocumentStore) void {
    var entry_iterator = self.handles.iterator();
    while (entry_iterator.next()) |entry| {
        entry.value.document_scope.deinit(self.allocator);
        entry.value.tree.deinit();
        self.allocator.free(entry.value.document.mem);

        for (entry.value.import_uris.items) |uri| {
            self.allocator.free(uri);
        }

        entry.value.import_uris.deinit();
        self.allocator.free(entry.key);
        self.allocator.destroy(entry.value);
    }

    self.handles.deinit();
    for (self.build_files.items) |build_file| {
        for (build_file.packages.items) |pkg| {
            self.allocator.free(pkg.name);
            self.allocator.free(pkg.uri);
        }
        build_file.packages.deinit(self.allocator);
        self.allocator.free(build_file.uri);
        self.allocator.destroy(build_file);
    }
    if (self.std_uri) |std_uri| {
        self.allocator.free(std_uri);
    }
    self.allocator.free(self.build_runner_path);
    self.allocator.free(self.build_runner_cache_path);
    self.build_files.deinit(self.allocator);
}

fn tagStoreCompletionItems(self: DocumentStore, arena: *std.heap.ArenaAllocator, base: *DocumentStore.Handle, comptime name: []const u8) ![]types.CompletionItem {
    // TODO Better solution for deciding what tags to include
    var handle_arr = try arena.allocator.alloc(*DocumentStore.Handle, base.import_uris.items.len + 1);
    handle_arr[0] = base;
    var len: usize = @field(base.document_scope, name).len;
    for (base.import_uris.items) |uri, idx| {
        handle_arr[idx + 1] = self.handles.get(uri).?;
        len += @field(handle_arr[idx + 1].document_scope, name).len;
    }

    var result = try arena.allocator.alloc(types.CompletionItem, len);
    var res_idx: usize = 0;
    for (handle_arr) |handle| {
        for (@field(handle.document_scope, name)) |item| {
            result[res_idx] = item;
            res_idx += 1;
        }
    }
    return result;
}

pub fn errorCompletionItems(self: DocumentStore, arena: *std.heap.ArenaAllocator, base: *DocumentStore.Handle) ![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, base, "error_completions");
}

pub fn enumCompletionItems(self: DocumentStore, arena: *std.heap.ArenaAllocator, base: *DocumentStore.Handle) ![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, base, "enum_completions");
}
