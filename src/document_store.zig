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
    /// Contains one entry for every import in the document
    import_uris: []const []const u8,
    /// Items in this array list come from `import_uris`
    imports_used: std.ArrayListUnmanaged([]const u8),
    tree: std.zig.ast.Tree,
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

    var tree = try std.zig.parse(self.allocator, text);
    errdefer tree.deinit(self.allocator);

    var document_scope = try analysis.makeDocumentScope(self.allocator, tree);
    errdefer document_scope.deinit(self.allocator);

    handle.* = Handle{
        .count = 1,
        .import_uris = &.{},
        .imports_used = .{},
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
                var candidate_path = try std.mem.concat(self.allocator, u8, &.{ curr_path, "build.zig" });
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

    handle.import_uris = try self.collectImportUris(handle);
    errdefer {
        for (handle.import_uris) |imp_uri| {
            self.allocator.free(imp_uri);
        }
        self.allocator.free(handle.import_uris);
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

        entry.value.tree.deinit(self.allocator);
        self.allocator.free(entry.value.document.mem);

        for (entry.value.imports_used.items) |import_uri| {
            self.decrementCount(import_uri);
        }

        for (entry.value.import_uris) |import_uri| {
            self.allocator.free(import_uri);
        }

        entry.value.document_scope.deinit(self.allocator);
        entry.value.imports_used.deinit(self.allocator);
        self.allocator.free(entry.value.import_uris);
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

fn collectImportUris(self: *DocumentStore, handle: *Handle) ![]const []const u8 {
    var new_imports = std.ArrayList([]const u8).init(self.allocator);
    errdefer {
        for (new_imports.items) |imp| {
            self.allocator.free(imp);
        }
        new_imports.deinit();
    }
    try analysis.collectImports(&new_imports, handle.tree);

    // Convert to URIs
    var i: usize = 0;
    while (i < new_imports.items.len) {
        if (try self.uriFromImportStr(self.allocator, handle.*, new_imports.items[i])) |uri| {
            // The raw import strings are owned by the document and do not need to be freed here.
            new_imports.items[i] = uri;
            i += 1;
        } else {
            _ = new_imports.swapRemove(i);
        }
    }
    return new_imports.toOwnedSlice();
}

fn refreshDocument(self: *DocumentStore, handle: *Handle) !void {
    log.debug("New text for document {s}", .{handle.uri()});
    handle.tree.deinit(self.allocator);
    handle.tree = try std.zig.parse(self.allocator, handle.document.text);

    handle.document_scope.deinit(self.allocator);
    handle.document_scope = try analysis.makeDocumentScope(self.allocator, handle.tree);

    const new_imports = try self.collectImportUris(handle);
    errdefer {
        for (new_imports) |imp| {
            self.allocator.free(imp);
        }
        self.allocator.free(new_imports);
    }

    const old_imports = handle.import_uris;
    handle.import_uris = new_imports;
    defer {
        for (old_imports) |uri| {
            self.allocator.free(uri);
        }
        self.allocator.free(old_imports);
    }

    var i: usize = 0;
    while (i < handle.imports_used.items.len) {
        const old = handle.imports_used.items[i];
        still_exists: {
            for (new_imports) |new| {
                if (std.mem.eql(u8, new, old)) {
                    handle.imports_used.items[i] = new;
                    break :still_exists;
                }
            }
            log.debug("Import removed: {s}", .{old});
            self.decrementCount(old);
            _ = handle.imports_used.swapRemove(i);
            continue;
        }
        i += 1;
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
) !void {
    const document = &handle.document;

    for (content_changes.items) |change| {
        if (change.Object.get("range")) |range| {
            std.debug.assert(document.text.ptr == document.mem.ptr);

            // TODO: add tests and validate the JSON
            const start_obj = range.Object.get("start").?.Object;
            const start_pos = types.Position{
                .line = start_obj.get("line").?.Integer,
                .character = start_obj.get("character").?.Integer,
            };
            const end_obj = range.Object.get("end").?.Object;
            const end_pos = types.Position{
                .line = end_obj.get("line").?.Integer,
                .character = end_obj.get("character").?.Integer,
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

    try self.refreshDocument(handle);
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
        const base = handle.uri();
        var base_len = base.len;
        while (base[base_len - 1] != '/' and base_len > 0) {
            base_len -= 1;
        }
        base_len -= 1;
        if (base_len <= 0) {
            return error.UriBadScheme;
        }
        return try URI.pathRelative(allocator, base[0..base_len], import_str);
    }
}

pub fn resolveImport(self: *DocumentStore, handle: *Handle, import_str: []const u8) !?*Handle {
    const allocator = self.allocator;
    const final_uri = (try self.uriFromImportStr(
        self.allocator,
        handle.*,
        import_str,
    )) orelse return null;
    defer allocator.free(final_uri);

    for (handle.imports_used.items) |uri| {
        if (std.mem.eql(u8, uri, final_uri)) {
            return self.getHandle(final_uri).?;
        }
    }
    // The URI must be somewhere in the import_uris or the package uris
    const handle_uri = find_uri: {
        for (handle.import_uris) |uri| {
            if (std.mem.eql(u8, uri, final_uri)) {
                break :find_uri uri;
            }
        }
        if (handle.associated_build_file) |bf| {
            for (bf.packages.items) |pkg| {
                if (std.mem.eql(u8, pkg.uri, final_uri)) {
                    break :find_uri pkg.uri;
                }
            }
        }
        return null;
    };

    // New import.
    // Check if the import is already opened by others.
    if (self.getHandle(final_uri)) |new_handle| {
        // If it is, append it to our imports, increment the count, set our new handle
        // and return the parsed tree root node.
        try handle.imports_used.append(self.allocator, handle_uri);
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
    {
        const file_contents = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.debug("Could not read from file {s}", .{file_path});
                return null;
            },
        };
        errdefer allocator.free(file_contents);

        // Add to import table of current handle.
        try handle.imports_used.append(self.allocator, handle_uri);
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
        entry.value.tree.deinit(self.allocator);
        self.allocator.free(entry.value.document.mem);
        for (entry.value.import_uris) |uri| {
            self.allocator.free(uri);
        }
        self.allocator.free(entry.value.import_uris);
        entry.value.imports_used.deinit(self.allocator);
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

fn tagStoreCompletionItems(
    self: DocumentStore,
    arena: *std.heap.ArenaAllocator,
    base: *DocumentStore.Handle,
    comptime name: []const u8,
) ![]types.CompletionItem {
    // TODO Better solution for deciding what tags to include
    var max_len: usize = @field(base.document_scope, name).count();
    for (base.imports_used.items) |uri| {
        max_len += @field(self.handles.get(uri).?.document_scope, name).count();
    }

    var result_set = analysis.CompletionSet{};
    try result_set.ensureCapacity(&arena.allocator, max_len);
    result_set.entries.appendSliceAssumeCapacity(@field(base.document_scope, name).entries.items);
    try result_set.reIndex(&arena.allocator);

    for (base.imports_used.items) |uri| {
        const curr_set = &@field(self.handles.get(uri).?.document_scope, name);
        for (curr_set.entries.items) |entry| {
            result_set.putAssumeCapacity(entry.key, {});
        }
    }
    // This is safe to do because CompletionSet.Entry == struct { value: types.CompletionItem }
    return std.mem.bytesAsSlice(types.CompletionItem, std.mem.sliceAsBytes(result_set.entries.items));
}

pub fn errorCompletionItems(
    self: DocumentStore,
    arena: *std.heap.ArenaAllocator,
    base: *DocumentStore.Handle,
) ![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, base, "error_completions");
}

pub fn enumCompletionItems(
    self: DocumentStore,
    arena: *std.heap.ArenaAllocator,
    base: *DocumentStore.Handle,
) ![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, base, "enum_completions");
}
