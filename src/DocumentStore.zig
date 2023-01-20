const std = @import("std");
const builtin = @import("builtin");
const types = @import("lsp.zig");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.store);
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
const BuildConfig = @import("special/build_runner.zig").BuildConfig;
const tracy = @import("tracy.zig");
const Config = @import("Config.zig");
const translate_c = @import("translate_c.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");

const DocumentStore = @This();

pub const Uri = []const u8;

pub const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);
pub const Hash = [Hasher.mac_length]u8;

pub fn computeHash(bytes: []const u8) Hash {
    var hasher: Hasher = Hasher.init(&[_]u8{0} ** Hasher.key_length);
    hasher.update(bytes);
    var hash: Hash = undefined;
    hasher.final(&hash);
    return hash;
}

const BuildFile = struct {
    uri: Uri,
    /// contains information extracted from running build.zig with a custom build runner
    /// e.g. include paths & packages
    config: BuildConfig,
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    build_associated_config: ?BuildAssociatedConfig = null,

    pub fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        std.json.parseFree(BuildConfig, self.config, .{ .allocator = allocator });
        if (self.builtin_uri) |builtin_uri| allocator.free(builtin_uri);
        if (self.build_associated_config) |cfg| {
            std.json.parseFree(BuildAssociatedConfig, cfg, .{ .allocator = allocator });
        }
    }
};

pub const Handle = struct {
    /// `true` if the document has been directly opened by the client i.e. with `textDocument/didOpen`
    /// `false` indicates the document only exists because it is a dependency of another document
    /// or has been closed with `textDocument/didClose` and is awaiting cleanup through `garbageCollection`
    open: bool,
    uri: Uri,
    text: [:0]const u8,
    tree: Ast,
    /// Not null if a ComptimeInterpreter is actually used
    interpreter: ?*ComptimeInterpreter = null,
    document_scope: analysis.DocumentScope,
    /// Contains one entry for every import in the document
    import_uris: std.ArrayListUnmanaged(Uri) = .{},
    /// Contains one entry for every cimport in the document
    cimports: std.MultiArrayList(CImportHandle) = .{},

    /// `DocumentStore.build_files` is guaranteed to contain this uri
    /// uri memory managed by its build_file
    associated_build_file: ?Uri = null,

    pub fn deinit(self: *Handle, allocator: std.mem.Allocator) void {
        self.document_scope.deinit(allocator);
        self.tree.deinit(allocator);
        allocator.free(self.text);
        allocator.free(self.uri);

        for (self.import_uris.items) |import_uri| {
            allocator.free(import_uri);
        }
        self.import_uris.deinit(allocator);

        self.cimports.deinit(allocator);
    }
};

allocator: std.mem.Allocator,
config: *const Config,
handles: std.StringArrayHashMapUnmanaged(*Handle) = .{},
build_files: std.StringArrayHashMapUnmanaged(BuildFile) = .{},
cimports: std.AutoArrayHashMapUnmanaged(Hash, translate_c.Result) = .{},

pub fn deinit(self: *DocumentStore) void {
    for (self.handles.values()) |handle| {
        handle.deinit(self.allocator);
        self.allocator.destroy(handle);
    }
    self.handles.deinit(self.allocator);

    for (self.build_files.values()) |*build_file| {
        build_file.deinit(self.allocator);
    }
    self.build_files.deinit(self.allocator);

    for (self.cimports.values()) |*result| {
        result.deinit(self.allocator);
    }
    self.cimports.deinit(self.allocator);
}

/// returns a handle to the given document
pub fn getHandle(self: *DocumentStore, uri: Uri) ?*const Handle {
    return self.handles.get(uri);
}

/// returns a handle to the given document
/// will load the document from disk if it hasn't been already
pub fn getOrLoadHandle(self: *DocumentStore, uri: Uri) ?*const Handle {
    return self.getOrLoadHandleInternal(uri) catch null;
}

fn getOrLoadHandleInternal(self: *DocumentStore, uri: Uri) !?*const Handle {
    if (self.handles.get(uri)) |handle| return handle;

    var handle = try self.allocator.create(Handle);
    errdefer self.allocator.destroy(handle);

    handle.* = (try self.createDocumentFromURI(uri, false)) orelse return error.Unknown; // error name doesn't matter
    errdefer handle.deinit(self.allocator);

    const gop = try self.handles.getOrPutValue(self.allocator, handle.uri, handle);
    if (gop.found_existing) return error.Unknown;

    return gop.value_ptr.*;
}

pub fn openDocument(self: *DocumentStore, uri: Uri, text: []const u8) error{OutOfMemory}!Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |handle| {
        if (handle.open) {
            log.warn("Document already open: {s}", .{uri});
        } else {
            handle.open = true;
        }
        return handle.*;
    }

    var handle = try self.allocator.create(Handle);
    errdefer self.allocator.destroy(handle);

    const duped_text = try self.allocator.dupeZ(u8, text);

    handle.* = try self.createDocument(uri, duped_text, true);
    errdefer handle.deinit(self.allocator);

    try self.handles.putNoClobber(self.allocator, handle.uri, handle);

    return handle.*;
}

pub fn closeDocument(self: *DocumentStore, uri: Uri) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = self.handles.get(uri) orelse {
        log.warn("Document not found: {s}", .{uri});
        return;
    };

    // instead of destroying the handle here we just mark it not open
    // and let it be destroy by the garbage collection code
    if (handle.open) {
        handle.open = false;
    } else {
        log.warn("Document already closed: {s}", .{uri});
    }

    self.garbageCollectionImports() catch {};
    self.garbageCollectionCImports() catch {};
    self.garbageCollectionBuildFiles() catch {};
}

/// takes ownership of `new_text` which has to be allocated with `self.allocator`
pub fn refreshDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = self.handles.get(uri) orelse unreachable;

    // TODO: Handle interpreter cross reference
    if (handle.interpreter) |int| {
        int.deinit();
        handle.interpreter = null;
    }

    self.allocator.free(handle.text);
    handle.text = new_text;

    var new_tree = try std.zig.parse(self.allocator, handle.text);
    handle.tree.deinit(self.allocator);
    handle.tree = new_tree;

    var new_document_scope = try analysis.makeDocumentScope(self.allocator, handle.tree);
    handle.document_scope.deinit(self.allocator);
    handle.document_scope = new_document_scope;

    var new_import_uris = try self.collectImportUris(handle.*);
    for (handle.import_uris.items) |import_uri| {
        self.allocator.free(import_uri);
    }
    handle.import_uris.deinit(self.allocator);
    handle.import_uris = new_import_uris;

    var new_cimports = try self.collectCIncludes(handle.*);
    handle.cimports.deinit(self.allocator);
    handle.cimports = new_cimports;

    // a include could have been removed but it would increase latency
    // try self.garbageCollectionImports();
    // try self.garbageCollectionCImports();
}

pub fn applySave(self: *DocumentStore, handle: *const Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (std.process.can_spawn and isBuildFile(handle.uri)) {
        const build_file = self.build_files.getPtr(handle.uri).?;

        const build_config = loadBuildConfiguration(self.allocator, build_file.*, self.config.*) catch |err| {
            log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri, err });
            return;
        };

        std.json.parseFree(BuildConfig, build_file.config, .{ .allocator = self.allocator });
        build_file.config = build_config;
    }
}

/// The `DocumentStore` represents a graph structure where every
/// handle/document is a node and every `@import` & `@cImport` represent
/// a directed edge.
/// We can remove every document which cannot be reached from
/// another document that is `open` (see `Handle.open`)
fn garbageCollectionImports(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();

    var reachable_handles = std.StringHashMapUnmanaged(void){};
    defer reachable_handles.deinit(arena.allocator());

    var queue = std.ArrayListUnmanaged(Uri){};

    for (self.handles.values()) |handle| {
        if (!handle.open) continue;

        try reachable_handles.put(arena.allocator(), handle.uri, {});

        try self.collectDependencies(arena.allocator(), handle.*, &queue);
    }

    while (queue.popOrNull()) |uri| {
        const gop = try reachable_handles.getOrPut(arena.allocator(), uri);
        if (gop.found_existing) continue;

        const handle = self.handles.get(uri) orelse continue;

        try self.collectDependencies(arena.allocator(), handle.*, &queue);
    }

    var i: usize = 0;
    while (i < self.handles.count()) {
        const handle = self.handles.values()[i];
        if (reachable_handles.contains(handle.uri)) {
            i += 1;
            continue;
        }
        log.debug("Closing document {s}", .{handle.uri});
        var kv = self.handles.fetchSwapRemove(handle.uri).?;
        kv.value.deinit(self.allocator);
        self.allocator.destroy(kv.value);
    }
}

fn garbageCollectionCImports(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.cimports.count() == 0) return;

    var reachable_hashes = std.AutoArrayHashMapUnmanaged(Hash, void){};
    defer reachable_hashes.deinit(self.allocator);

    for (self.handles.values()) |handle| {
        for (handle.cimports.items(.hash)) |hash| {
            try reachable_hashes.put(self.allocator, hash, {});
        }
    }

    var i: usize = 0;
    while (i < self.cimports.count()) {
        const hash = self.cimports.keys()[i];
        if (reachable_hashes.contains(hash)) {
            i += 1;
            continue;
        }
        var kv = self.cimports.fetchSwapRemove(hash).?;
        const message = switch (kv.value) {
            .failure => "",
            .success => |uri| uri,
        };
        log.debug("Destroying cimport {s}", .{message});
        kv.value.deinit(self.allocator);
    }
}

fn garbageCollectionBuildFiles(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var reachable_build_files = std.StringHashMapUnmanaged(void){};
    defer reachable_build_files.deinit(self.allocator);

    for (self.handles.values()) |handle| {
        const build_file_uri = handle.associated_build_file orelse continue;

        try reachable_build_files.put(self.allocator, build_file_uri, {});
    }

    var i: usize = 0;
    while (i < self.build_files.count()) {
        const hash = self.build_files.keys()[i];
        if (reachable_build_files.contains(hash)) {
            i += 1;
            continue;
        }
        var kv = self.build_files.fetchSwapRemove(hash).?;
        log.debug("Destroying build file {s}", .{kv.value.uri});
        kv.value.deinit(self.allocator);
    }
}

pub fn isBuildFile(uri: Uri) bool {
    return std.mem.endsWith(u8, uri, "/build.zig");
}

pub fn isBuiltinFile(uri: Uri) bool {
    return std.mem.endsWith(u8, uri, "/builtin.zig");
}

pub fn isInStd(uri: Uri) bool {
    // TODO: Better logic for detecting std or subdirectories?
    return std.mem.indexOf(u8, uri, "/std/") != null;
}

/// looks for a `zls.build.json` file in the build file directory
/// has to be freed with `std.json.parseFree`
fn loadBuildAssociatedConfiguration(allocator: std.mem.Allocator, build_file: BuildFile) !BuildAssociatedConfig {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const build_file_path = try URI.parse(allocator, build_file.uri);
    defer allocator.free(build_file_path);
    const config_file_path = try std.fs.path.resolve(allocator, &.{ build_file_path, "../zls.build.json" });
    defer allocator.free(config_file_path);

    var config_file = try std.fs.cwd().openFile(config_file_path, .{});
    defer config_file.close();

    const file_buf = try config_file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(file_buf);

    var token_stream = std.json.TokenStream.init(file_buf);
    return try std.json.parse(BuildAssociatedConfig, &token_stream, .{ .allocator = allocator });
}

/// runs the build.zig and extracts include directories and packages
/// has to be freed with `std.json.parseFree`
fn loadBuildConfiguration(
    allocator: std.mem.Allocator,
    build_file: BuildFile,
    config: Config,
) !BuildConfig {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const build_file_path = try URI.parse(arena_allocator, build_file.uri);
    const directory_path = try std.fs.path.resolve(arena_allocator, &.{ build_file_path, "../" });

    // TODO extract this option from `BuildAssociatedConfig.BuildOption`
    const zig_cache_root: []const u8 = try std.fs.path.join(arena_allocator, &.{ directory_path, "zig-cache" });
    // Since we don't compile anything and no packages should put their
    // files there this path can be ignored
    const zig_global_cache_root: []const u8 = "ZLS_DONT_CARE";

    const standard_args = [_][]const u8{
        config.zig_exe_path.?,
        "run",
        config.build_runner_path.?,
        "--cache-dir",
        config.global_cache_path.?,
        "--pkg-begin",
        "@build@",
        build_file_path,
        "--pkg-end",
        "--",
        config.zig_exe_path.?,
        directory_path,
        zig_cache_root,
        zig_global_cache_root,
    };

    const arg_length = standard_args.len + if (build_file.build_associated_config) |cfg| if (cfg.build_options) |options| options.len else 0 else 0;
    var args = try std.ArrayListUnmanaged([]const u8).initCapacity(arena_allocator, arg_length);
    args.appendSliceAssumeCapacity(standard_args[0..]);
    if (build_file.build_associated_config) |cfg| {
        if (cfg.build_options) |options| {
            for (options) |opt| {
                args.appendAssumeCapacity(try opt.formatParam(arena_allocator));
            }
        }
    }

    const zig_run_result = try std.ChildProcess.exec(.{
        .allocator = arena_allocator,
        .argv = args.items,
        .cwd = try std.fs.path.resolve(arena_allocator, &.{ config.zig_exe_path.?, "../" }),
    });

    defer {
        arena_allocator.free(zig_run_result.stdout);
        arena_allocator.free(zig_run_result.stderr);
    }

    errdefer blk: {
        const joined = std.mem.join(arena_allocator, " ", args.items) catch break :blk;

        log.err(
            "Failed to execute build runner to collect build configuration, command:\n{s}\nError: {s}",
            .{ joined, zig_run_result.stderr },
        );
    }

    switch (zig_run_result.term) {
        .Exited => |exit_code| if (exit_code != 0) return error.RunFailed,
        else => return error.RunFailed,
    }

    const parse_options = std.json.ParseOptions{ .allocator = allocator };
    var token_stream = std.json.TokenStream.init(zig_run_result.stdout);
    var build_config = std.json.parse(BuildConfig, &token_stream, parse_options) catch return error.RunFailed;
    errdefer std.json.parseFree(BuildConfig, build_config, parse_options);

    for (build_config.packages) |*pkg| {
        const pkg_abs_path = try std.fs.path.resolve(allocator, &[_][]const u8{ directory_path, pkg.path });
        allocator.free(pkg.path);
        pkg.path = pkg_abs_path;
    }

    return build_config;
}

// walks the build.zig files above "uri"
const BuildDotZigIterator = struct {
    allocator: std.mem.Allocator,
    uri_path: []const u8,
    dir_path: []const u8,
    i: usize,

    fn init(allocator: std.mem.Allocator, uri_path: []const u8) !BuildDotZigIterator {
        const dir_path = std.fs.path.dirname(uri_path) orelse uri_path;

        return BuildDotZigIterator{
            .allocator = allocator,
            .uri_path = uri_path,
            .dir_path = dir_path,
            .i = std.fs.path.diskDesignator(uri_path).len + 1,
        };
    }

    // the iterator allocates this memory so you gotta free it
    fn next(self: *BuildDotZigIterator) !?[]const u8 {
        while (true) {
            if (self.i > self.dir_path.len)
                return null;

            const potential_build_path = try std.fs.path.join(self.allocator, &.{
                self.dir_path[0..self.i], "build.zig",
            });

            self.i += 1;
            while (self.i < self.dir_path.len and self.dir_path[self.i] != std.fs.path.sep) : (self.i += 1) {}

            if (std.fs.accessAbsolute(potential_build_path, .{})) {
                // found a build.zig file
                return potential_build_path;
            } else |_| {
                // nope it failed for whatever reason, free it and move the
                // machinery forward
                self.allocator.free(potential_build_path);
            }
        }
    }
};

/// takes ownership of `uri`
fn createBuildFile(self: *const DocumentStore, uri: Uri) error{OutOfMemory}!BuildFile {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var build_file = BuildFile{
        .uri = uri,
        .config = .{
            .packages = &.{},
            .include_dirs = &.{},
        },
    };
    errdefer build_file.deinit(self.allocator);

    if (loadBuildAssociatedConfiguration(self.allocator, build_file)) |config| {
        build_file.build_associated_config = config;

        if (config.relative_builtin_path) |relative_builtin_path| blk: {
            const build_file_path = URI.parse(self.allocator, build_file.uri) catch break :blk;
            const absolute_builtin_path = std.fs.path.resolve(self.allocator, &.{ build_file_path, "../", relative_builtin_path }) catch break :blk;
            defer self.allocator.free(absolute_builtin_path);
            build_file.builtin_uri = try URI.fromPath(self.allocator, absolute_builtin_path);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            log.debug("Failed to load config associated with build file {s} (error: {})", .{ build_file.uri, err });
        }
    }

    // TODO: Do this in a separate thread?
    // It can take quite long.
    if (loadBuildConfiguration(self.allocator, build_file, self.config.*)) |build_config| {
        build_file.config = build_config;
    } else |err| {
        log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri, err });
    }

    return build_file;
}

fn uriAssociatedWithBuild(
    self: *DocumentStore,
    build_file: BuildFile,
    uri: Uri,
) error{OutOfMemory}!bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var checked_uris = std.StringHashMapUnmanaged(void){};
    defer checked_uris.deinit(self.allocator);

    for (build_file.config.packages) |package| {
        const package_uri = try URI.fromPath(self.allocator, package.path);
        defer self.allocator.free(package_uri);

        if (std.mem.eql(u8, uri, package_uri)) {
            return true;
        }

        if (try self.uriInImports(&checked_uris, build_file, package_uri, uri))
            return true;
    }

    return false;
}

fn uriInImports(
    self: *DocumentStore,
    checked_uris: *std.StringHashMapUnmanaged(void),
    build_file: BuildFile,
    source_uri: Uri,
    uri: Uri,
) error{OutOfMemory}!bool {
    if (checked_uris.contains(source_uri))
        return false;

    if (isInStd(source_uri)) return false;

    // consider it checked even if a failure happens
    try checked_uris.put(self.allocator, source_uri, {});

    const handle = self.getOrLoadHandle(source_uri) orelse return false;

    if (handle.associated_build_file) |associated_build_file_uri| {
        return std.mem.eql(u8, associated_build_file_uri, build_file.uri);
    }

    for (handle.import_uris.items) |import_uri| {
        if (std.mem.eql(u8, uri, import_uri))
            return true;

        if (try self.uriInImports(checked_uris, build_file, import_uri, uri))
            return true;
    }

    return false;
}

/// takes ownership of the text passed in.
fn createDocument(self: *DocumentStore, uri: Uri, text: [:0]u8, open: bool) error{OutOfMemory}!Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle: Handle = blk: {
        errdefer self.allocator.free(text);

        var duped_uri = try self.allocator.dupe(u8, uri);
        errdefer self.allocator.free(duped_uri);

        var tree = try std.zig.parse(self.allocator, text);
        errdefer tree.deinit(self.allocator);

        var document_scope = try analysis.makeDocumentScope(self.allocator, tree);
        errdefer document_scope.deinit(self.allocator);

        break :blk Handle{
            .open = open,
            .uri = duped_uri,
            .text = text,
            .tree = tree,
            .document_scope = document_scope,
        };
    };
    errdefer handle.deinit(self.allocator);

    defer {
        if (handle.associated_build_file) |build_file_uri| {
            log.debug("Opened document `{s}` with build file `{s}`", .{ handle.uri, build_file_uri });
        } else if (isBuildFile(handle.uri)) {
            log.debug("Opened document `{s}` (build file)", .{handle.uri});
        } else {
            log.debug("Opened document `{s}`", .{handle.uri});
        }
    }

    handle.import_uris = try self.collectImportUris(handle);
    handle.cimports = try self.collectCIncludes(handle);

    if (!std.process.can_spawn or self.config.zig_exe_path == null) return handle;

    if (isBuildFile(handle.uri) and !isInStd(handle.uri)) {
        const gop = try self.build_files.getOrPut(self.allocator, uri);
        errdefer |err| {
            self.build_files.swapRemoveAt(gop.index);
            log.debug("Failed to load build file {s}: (error: {})", .{ uri, err });
        }
        if (!gop.found_existing) {
            const duped_uri = try self.allocator.dupe(u8, uri);
            gop.value_ptr.* = try self.createBuildFile(duped_uri);
            gop.key_ptr.* = gop.value_ptr.uri;
        }
    } else if (!isBuiltinFile(handle.uri) and !isInStd(handle.uri)) blk: {
        // log.debug("Going to walk down the tree towards: {s}", .{uri});

        // walk down the tree towards the uri. When we hit build.zig files
        // determine if the uri we're interested in is involved with the build.
        // This ensures that _relevant_ build.zig files higher in the
        // filesystem have precedence.
        const path = URI.parse(self.allocator, uri) catch break :blk;
        defer self.allocator.free(path);

        var build_it = try BuildDotZigIterator.init(self.allocator, path);
        while (try build_it.next()) |build_path| {
            defer self.allocator.free(build_path);

            // log.debug("found build path: {s}", .{build_path});

            const build_file_uri = try URI.fromPath(self.allocator, build_path);
            const gop = self.build_files.getOrPut(self.allocator, build_file_uri) catch |err| {
                self.allocator.free(build_file_uri);
                return err;
            };

            if (!gop.found_existing) {
                errdefer self.build_files.swapRemoveAt(gop.index);
                gop.value_ptr.* = try self.createBuildFile(build_file_uri);
            } else {
                self.allocator.free(build_file_uri);
            }

            if (try self.uriAssociatedWithBuild(gop.value_ptr.*, uri)) {
                handle.associated_build_file = gop.key_ptr.*;
                break;
            } else if (handle.associated_build_file == null) {
                handle.associated_build_file = gop.key_ptr.*;
            }
        }
    }

    return handle;
}

fn createDocumentFromURI(self: *DocumentStore, uri: Uri, open: bool) error{OutOfMemory}!?Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_path = URI.parse(self.allocator, uri) catch return null;
    defer self.allocator.free(file_path);

    var file = std.fs.openFileAbsolute(file_path, .{}) catch return null;
    defer file.close();

    const file_contents = file.readToEndAllocOptions(self.allocator, std.math.maxInt(usize), null, @alignOf(u8), 0) catch return null;

    return try self.createDocument(uri, file_contents, open);
}

/// Caller owns returned memory.
fn collectImportUris(self: *const DocumentStore, handle: Handle) error{OutOfMemory}!std.ArrayListUnmanaged(Uri) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var imports = try analysis.collectImports(self.allocator, handle.tree);

    var i: usize = 0;
    errdefer {
        // only free the uris
        for (imports.items[0..i]) |uri| self.allocator.free(uri);
        imports.deinit(self.allocator);
    }

    // Convert to URIs
    while (i < imports.items.len) {
        const maybe_uri = try self.uriFromImportStr(self.allocator, handle, imports.items[i]);

        if (maybe_uri) |uri| {
            // The raw import strings are owned by the document and do not need to be freed here.
            imports.items[i] = uri;
            i += 1;
        } else {
            _ = imports.swapRemove(i);
        }
    }

    return imports;
}

pub const CImportHandle = struct {
    /// the `@cImport` node
    node: Ast.Node.Index,
    /// hash of c source file
    hash: Hash,
    /// c source file
    source: []const u8,
};

/// Collects all `@cImport` nodes and converts them into c source code
/// Caller owns returned memory.
fn collectCIncludes(self: *const DocumentStore, handle: Handle) error{OutOfMemory}!std.MultiArrayList(CImportHandle) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var cimport_nodes = try analysis.collectCImportNodes(self.allocator, handle.tree);
    defer self.allocator.free(cimport_nodes);

    var sources = std.MultiArrayList(CImportHandle){};
    try sources.ensureTotalCapacity(self.allocator, cimport_nodes.len);
    errdefer {
        for (sources.items(.source)) |source| {
            self.allocator.free(source);
        }
        sources.deinit(self.allocator);
    }

    for (cimport_nodes) |node| {
        const c_source = translate_c.convertCInclude(self.allocator, handle.tree, node) catch |err| switch (err) {
            error.Unsupported => continue,
            error.OutOfMemory => return error.OutOfMemory,
        };

        sources.appendAssumeCapacity(.{
            .node = node,
            .hash = computeHash(c_source),
            .source = c_source,
        });
    }

    return sources;
}

/// collects every file uri the given handle depends on
/// includes imports, cimports & packages
pub fn collectDependencies(
    store: *const DocumentStore,
    allocator: std.mem.Allocator,
    handle: Handle,
    dependencies: *std.ArrayListUnmanaged(Uri),
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    try dependencies.ensureUnusedCapacity(allocator, handle.import_uris.items.len);
    for (handle.import_uris.items) |uri| {
        dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri));
    }

    try dependencies.ensureUnusedCapacity(allocator, handle.cimports.len);
    for (handle.cimports.items(.hash)) |hash| {
        const result = store.cimports.get(hash) orelse continue;
        switch (result) {
            .success => |uri| dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri)),
            .failure => continue,
        }
    }

    if (handle.associated_build_file) |build_file_uri| {
        if (store.build_files.get(build_file_uri)) |build_file| {
            const packages = build_file.config.packages;
            try dependencies.ensureUnusedCapacity(allocator, packages.len);
            for (packages) |pkg| {
                dependencies.appendAssumeCapacity(try URI.fromPath(allocator, pkg.path));
            }
        }
    }
}

/// returns the document behind `@cImport()` where `node` is the `cImport` node
/// if a cImport can't be translated e.g. requires computing a
/// comptime value `resolveCImport` will return null
/// returned memory is owned by DocumentStore
pub fn resolveCImport(self: *DocumentStore, handle: Handle, node: Ast.Node.Index) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!std.process.can_spawn) return null;

    const index = std.mem.indexOfScalar(Ast.Node.Index, handle.cimports.items(.node), node).?;

    const hash: Hash = handle.cimports.items(.hash)[index];

    // TODO regenerate cimports if config changes or the header files gets modified
    const result = self.cimports.get(hash) orelse blk: {
        const source: []const u8 = handle.cimports.items(.source)[index];

        const include_dirs: []const []const u8 = if (handle.associated_build_file) |build_file_uri|
            self.build_files.get(build_file_uri).?.config.include_dirs
        else
            &.{};

        var result = (try translate_c.translate(
            self.allocator,
            self.config.*,
            include_dirs,
            source,
        )) orelse return null;

        self.cimports.putNoClobber(self.allocator, hash, result) catch result.deinit(self.allocator);

        switch (result) {
            .success => |uri| log.debug("Translated cImport into {s}", .{uri}),
            .failure => {},
        }

        break :blk result;
    };

    switch (result) {
        .success => |uri| return uri,
        .failure => return null,
    }
}

/// takes the string inside a @import() node (without the quotation marks)
/// and returns it's uri
/// caller owns the returned memory
pub fn uriFromImportStr(self: *const DocumentStore, allocator: std.mem.Allocator, handle: Handle, import_str: []const u8) error{OutOfMemory}!?Uri {
    if (std.mem.eql(u8, import_str, "std")) {
        const zig_lib_path = self.config.zig_lib_path orelse return null;

        const std_path = std.fs.path.resolve(allocator, &[_][]const u8{ zig_lib_path, "./std/std.zig" }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };

        defer allocator.free(std_path);
        return try URI.fromPath(allocator, std_path);
    } else if (std.mem.eql(u8, import_str, "builtin")) {
        if (handle.associated_build_file) |build_file_uri| {
            const build_file = self.build_files.get(build_file_uri).?;
            if (build_file.builtin_uri) |builtin_uri| {
                return try allocator.dupe(u8, builtin_uri);
            }
        }
        if (self.config.builtin_path) |_| {
            return try URI.fromPath(allocator, self.config.builtin_path.?);
        }
        return null;
    } else if (!std.mem.endsWith(u8, import_str, ".zig")) {
        if (handle.associated_build_file) |build_file_uri| {
            const build_file = self.build_files.get(build_file_uri).?;
            for (build_file.config.packages) |pkg| {
                if (std.mem.eql(u8, import_str, pkg.name)) {
                    return try URI.fromPath(allocator, pkg.path);
                }
            }
        }
        return null;
    } else {
        const base = handle.uri;
        var base_len = base.len;
        while (base[base_len - 1] != '/' and base_len > 0) {
            base_len -= 1;
        }
        base_len -= 1;
        if (base_len <= 0) {
            return null;
            // return error.UriBadScheme;
        }

        return URI.pathRelative(allocator, base[0..base_len], import_str) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UriBadScheme => return null,
        };
    }
}

fn tagStoreCompletionItems(self: DocumentStore, arena: std.mem.Allocator, handle: Handle, comptime name: []const u8) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var dependencies = std.ArrayListUnmanaged(Uri){};
    try dependencies.append(arena, handle.uri);
    try self.collectDependencies(arena, handle, &dependencies);

    // TODO Better solution for deciding what tags to include
    var result_set = analysis.CompletionSet{};

    for (dependencies.items) |uri| {
        // not every dependency is loaded which results in incomplete completion
        const hdl = self.handles.get(uri) orelse continue;
        const curr_set = @field(hdl.document_scope, name);
        for (curr_set.entries.items(.key)) |completion| {
            try result_set.put(arena, completion, {});
        }
    }

    return result_set.entries.items(.key);
}

pub fn errorCompletionItems(self: DocumentStore, arena: std.mem.Allocator, handle: Handle) error{OutOfMemory}![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, handle, "error_completions");
}

pub fn enumCompletionItems(self: DocumentStore, arena: std.mem.Allocator, handle: Handle) error{OutOfMemory}![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, handle, "enum_completions");
}

pub fn ensureInterpreterExists(self: *DocumentStore, uri: Uri) !void {
    var handle = self.handles.get(uri).?;
    if (handle.interpreter == null) {
        var int = try self.allocator.create(ComptimeInterpreter);
        int.* = ComptimeInterpreter{
            .allocator = self.allocator,
            .document_store = self,
            .uri = uri,
        };
        handle.interpreter = int;
        _ = try int.interpret(0, .none, .{});
    }
}
