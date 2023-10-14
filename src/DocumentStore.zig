const std = @import("std");
const builtin = @import("builtin");
const types = @import("lsp.zig");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.zls_store);
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
const BuildConfig = @import("build_runner/BuildConfig.zig");
const tracy = @import("tracy.zig");
const Config = @import("Config.zig");
const ZigVersionWrapper = @import("ZigVersionWrapper.zig");
const translate_c = @import("translate_c.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
const AstGen = @import("stage2/AstGen.zig");
const Zir = @import("stage2/Zir.zig");
const InternPool = @import("analyser/InternPool.zig");

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
    /// TODO this field should not be nullable, callsites should await the build config to be resolved
    /// and then continue instead of dealing with missing information.
    config: ?std.json.Parsed(BuildConfig),
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    build_associated_config: ?std.json.Parsed(BuildAssociatedConfig) = null,

    pub fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        if (self.config) |cfg| cfg.deinit();
        if (self.builtin_uri) |builtin_uri| allocator.free(builtin_uri);
        if (self.build_associated_config) |cfg| cfg.deinit();
    }
};

pub const Handle = struct {
    /// `true` if the document has been directly opened by the client i.e. with `textDocument/didOpen`
    /// `false` indicates the document only exists because it is a dependency of another document
    /// or has been closed with `textDocument/didClose` and is awaiting cleanup through `garbageCollection`
    open: std.atomic.Atomic(bool),
    uri: Uri,
    text: [:0]const u8,
    tree: Ast,
    /// do not access unless `zir_status != .none`
    zir: Zir = undefined,
    zir_status: enum {
        none,
        outdated,
        done,
    } = .none,
    /// Not null if a ComptimeInterpreter is actually used
    interpreter: ?*ComptimeInterpreter = null,
    document_scope: analysis.DocumentScope,
    /// Contains one entry for every import in the document
    import_uris: std.ArrayListUnmanaged(Uri) = .{},
    /// Contains one entry for every cimport in the document
    cimports: std.MultiArrayList(CImportHandle) = .{},

    /// error messages from comptime_interpreter or astgen_analyser
    analysis_errors: std.ArrayListUnmanaged(ErrorMessage) = .{},

    /// `DocumentStore.build_files` is guaranteed to contain this uri
    /// uri memory managed by its build_file
    associated_build_file: ?Uri = null,

    pub fn deinit(self: *Handle, allocator: std.mem.Allocator) void {
        if (self.interpreter) |interpreter| {
            interpreter.deinit();
            allocator.destroy(interpreter);
        }
        self.document_scope.deinit(allocator);
        if (self.zir_status != .none) self.zir.deinit(allocator);
        self.tree.deinit(allocator);
        allocator.free(self.text);
        allocator.free(self.uri);

        for (self.import_uris.items) |import_uri| {
            allocator.free(import_uri);
        }
        self.import_uris.deinit(allocator);

        for (self.cimports.items(.source)) |source| {
            allocator.free(source);
        }
        self.cimports.deinit(allocator);

        for (self.analysis_errors.items) |err| {
            allocator.free(err.message);
        }
        self.analysis_errors.deinit(allocator);
        self.* = undefined;
    }
};

pub const ErrorMessage = struct {
    loc: offsets.Loc,
    code: []const u8,
    message: []const u8,
};

allocator: std.mem.Allocator,
config: *const Config,
runtime_zig_version: *const ?ZigVersionWrapper,
lock: std.Thread.RwLock = .{},
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
    self.* = undefined;
}

/// Returns a handle to the given document
/// **Thread safe** takes a shared lock
pub fn getHandle(self: *DocumentStore, uri: Uri) ?*const Handle {
    self.lock.lockShared();
    defer self.lock.unlockShared();
    return self.handles.get(uri);
}

/// Returns a handle to the given document
/// Will load the document from disk if it hasn't been already
/// **Thread safe** takes an exclusive lock
pub fn getOrLoadHandle(self: *DocumentStore, uri: Uri) ?*const Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.getHandle(uri)) |handle| return handle;

    const file_path = URI.parse(self.allocator, uri) catch return null;
    defer self.allocator.free(file_path);

    var file = std.fs.openFileAbsolute(file_path, .{}) catch return null;
    defer file.close();

    const file_contents = file.readToEndAllocOptions(self.allocator, std.math.maxInt(usize), null, @alignOf(u8), 0) catch return null;

    const handle = self.createAndStoreDocument(uri, file_contents, false) catch return null;

    defer {
        if (handle.associated_build_file) |build_file_uri| {
            log.debug("Opened document `{s}` with build file `{s}`", .{ handle.uri, build_file_uri });
        } else if (isBuildFile(handle.uri)) {
            log.debug("Opened document `{s}` (build file)", .{handle.uri});
        } else {
            log.debug("Opened document `{s}`", .{handle.uri});
        }
    }

    return handle;
}

/// **Thread safe** takes a shared lock
pub fn getBuildFile(self: *DocumentStore, uri: Uri) ?BuildFile {
    self.lock.lockShared();
    defer self.lock.unlockShared();
    return self.build_files.get(uri);
}

/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
fn getOrLoadBuildFile(self: *DocumentStore, uri: Uri) ?std.StringArrayHashMapUnmanaged(BuildFile).Entry {
    {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.build_files.getEntry(uri)) |entry| return entry;
    }

    self.lock.lock();
    defer self.lock.unlock();

    const gop = self.build_files.getOrPut(self.allocator, uri) catch return null;
    if (!gop.found_existing) {
        gop.value_ptr.* = self.createBuildFile(uri) catch |err| {
            self.build_files.swapRemoveAt(gop.index);
            log.debug("Failed to load build file {s}: {}", .{ uri, err });
            return null;
        };
        gop.key_ptr.* = gop.value_ptr.uri;
    }
    return .{
        .key_ptr = gop.key_ptr,
        .value_ptr = gop.value_ptr,
    };
}

/// **Thread safe** takes an exclusive lock
pub fn openDocument(self: *DocumentStore, uri: Uri, text: []const u8) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.handles.get(uri)) |handle| {
            if (!handle.open.swap(true, .Acquire)) {
                log.warn("Document already open: {s}", .{uri});
            }
            return;
        }
    }

    const duped_text = try self.allocator.dupeZ(u8, text);
    _ = try self.createAndStoreDocument(uri, duped_text, true);
}

/// **Thread safe** takes an exclusive lock
pub fn closeDocument(self: *DocumentStore, uri: Uri) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const handle = self.handles.get(uri) orelse {
            log.warn("Document not found: {s}", .{uri});
            return;
        };
        // instead of destroying the handle here we just mark it not open
        // and let it be destroy by the garbage collection code
        if (!handle.open.swap(false, .Acquire)) {
            log.warn("Document already closed: {s}", .{uri});
        }
    }

    if (!self.lock.tryLock()) return;
    defer self.lock.unlock();

    self.garbageCollectionImports() catch {};
    self.garbageCollectionCImports() catch {};
    self.garbageCollectionBuildFiles() catch {};
}

/// Takes ownership of `new_text` which has to be allocated
/// with this DocumentStore's allocator
/// **Thread safe** takes an exclusive lock
pub fn refreshDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const old_handle = self.getHandle(uri).?;
    const old_import_count = old_handle.import_uris.items.len;
    const old_cimport_count = old_handle.cimports.len;

    var new_handle = try self.createDocument(uri, new_text, old_handle.open.load(.Acquire));

    self.lock.lock();
    defer self.lock.unlock();

    const handle: *Handle = self.handles.get(uri).?;

    // keep the old memory address of the handle uri
    self.allocator.free(new_handle.uri);
    new_handle.uri = handle.uri;
    handle.uri = "";

    // if the new document failed to generate ZIR, reuse
    // the outdated ZIR of the old document
    if (new_handle.zir_status == .none and handle.zir_status != .none) {
        new_handle.zir = handle.zir;
        new_handle.zir_status = .outdated;
        handle.zir_status = .none;
        handle.zir = undefined;
    }

    handle.deinit(self.allocator);
    handle.* = new_handle;

    const new_import_count = handle.import_uris.items.len;
    const new_cimport_count = handle.cimports.len;

    if (old_import_count != new_import_count or
        old_cimport_count != new_cimport_count)
    {
        self.garbageCollectionImports() catch {};
        self.garbageCollectionCImports() catch {};
    }
}

/// Invalidates a build files.
/// **Thread safe** takes an exclusive lock
pub fn invalidateBuildFile(self: *DocumentStore, build_file_uri: Uri) error{OutOfMemory}!void {
    std.debug.assert(std.process.can_spawn);
    if (!std.process.can_spawn) return;

    if (self.config.zig_exe_path == null) return;
    if (self.config.build_runner_path == null) return;
    if (self.config.global_cache_path == null) return;

    const build_config = loadBuildConfiguration(self, build_file_uri) catch |err| {
        log.err("Failed to load build configuration for {s} (error: {})", .{ build_file_uri, err });
        return;
    };
    errdefer build_config.deinit();

    self.lock.lock();
    defer self.lock.unlock();

    const build_file: *BuildFile = self.build_files.getPtr(build_file_uri) orelse {
        build_config.deinit();
        return;
    };
    if (build_file.config) |*old_config| {
        old_config.deinit();
    }
    build_file.config = build_config;
}

/// The `DocumentStore` represents a graph structure where every
/// handle/document is a node and every `@import` and `@cImport` represent
/// a directed edge.
/// We can remove every document which cannot be reached from
/// another document that is `open` (see `Handle.open`)
/// **Not thread safe** requires access to `DocumentStore.handles`, `DocumentStore.cimports` and `DocumentStore.build_files`
fn garbageCollectionImports(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();

    var reachable = try std.DynamicBitSetUnmanaged.initEmpty(arena.allocator(), self.handles.count());

    var queue = std.ArrayListUnmanaged(Uri){};

    for (self.handles.values(), 0..) |handle, handle_index| {
        if (!handle.open.load(.Acquire)) continue;

        reachable.set(handle_index);

        try self.collectDependenciesInternal(arena.allocator(), handle.*, &queue, false);
    }

    while (queue.popOrNull()) |uri| {
        const handle_index = self.handles.getIndex(uri) orelse continue;
        if (reachable.isSet(handle_index)) continue;
        reachable.set(handle_index);

        const handle = self.handles.values()[handle_index];

        try self.collectDependenciesInternal(arena.allocator(), handle.*, &queue, false);
    }

    var it = reachable.iterator(.{
        .kind = .unset,
        .direction = .reverse,
    });

    while (it.next()) |handle_index| {
        const handle = self.handles.values()[handle_index];
        log.debug("Closing document {s}", .{handle.uri});
        self.handles.swapRemoveAt(handle_index);
        handle.deinit(self.allocator);
        self.allocator.destroy(handle);
    }
}

/// see `garbageCollectionImports`
/// **Not thread safe** requires access to `DocumentStore.handles` and `DocumentStore.cimports`
fn garbageCollectionCImports(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.cimports.count() == 0) return;

    var reachable = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, self.cimports.count());
    defer reachable.deinit(self.allocator);

    for (self.handles.values()) |handle| {
        for (handle.cimports.items(.hash)) |hash| {
            const index = self.cimports.getIndex(hash) orelse continue;
            reachable.set(index);
        }
    }

    var it = reachable.iterator(.{
        .kind = .unset,
        .direction = .reverse,
    });

    while (it.next()) |cimport_index| {
        var result = self.cimports.values()[cimport_index];
        const message = switch (result) {
            .failure => "",
            .success => |uri| uri,
        };
        log.debug("Destroying cimport {s}", .{message});
        self.cimports.swapRemoveAt(cimport_index);
        result.deinit(self.allocator);
    }
}

/// see `garbageCollectionImports`
/// **Not thread safe** requires access to `DocumentStore.handles` and `DocumentStore.build_files`
fn garbageCollectionBuildFiles(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.build_files.count() == 0) return;

    var reachable = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, self.build_files.count());
    defer reachable.deinit(self.allocator);

    for (self.handles.values()) |handle| {
        const build_file_uri = handle.associated_build_file orelse continue;
        const build_file_index = self.build_files.getIndex(build_file_uri).?;

        reachable.set(build_file_index);
    }

    var it = reachable.iterator(.{
        .kind = .unset,
        .direction = .reverse,
    });

    while (it.next()) |build_file_index| {
        var build_file = self.build_files.values()[build_file_index];
        log.debug("Destroying build file {s}", .{build_file.uri});
        self.build_files.swapRemoveAt(build_file_index);
        build_file.deinit(self.allocator);
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
/// has to be freed with `json_compat.parseFree`
fn loadBuildAssociatedConfiguration(allocator: std.mem.Allocator, build_file: BuildFile) !std.json.Parsed(BuildAssociatedConfig) {
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

    return try std.json.parseFromSlice(
        BuildAssociatedConfig,
        allocator,
        file_buf,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    );
}

fn prepareBuildRunnerArgs(self: *DocumentStore, build_file_uri: []const u8) ![][]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const base_args = &[_][]const u8{
        self.config.zig_exe_path.?, "build", "--build-runner", self.config.build_runner_path.?,
    };

    var args = try std.ArrayListUnmanaged([]const u8).initCapacity(self.allocator, base_args.len);
    errdefer {
        for (args.items) |arg| self.allocator.free(arg);
        args.deinit(self.allocator);
    }

    for (base_args) |arg| {
        args.appendAssumeCapacity(try self.allocator.dupe(u8, arg));
    }

    self.lock.lockShared();
    defer self.lock.unlockShared();
    if (self.build_files.getPtr(build_file_uri)) |build_file| blk: {
        const build_config = build_file.build_associated_config orelse break :blk;
        const build_options = build_config.value.build_options orelse break :blk;

        try args.ensureUnusedCapacity(self.allocator, build_options.len);
        for (build_options) |option| {
            args.appendAssumeCapacity(try option.formatParam(self.allocator));
        }
    }

    return try args.toOwnedSlice(self.allocator);
}

/// Runs the build.zig and extracts include directories and packages
pub fn loadBuildConfiguration(self: *DocumentStore, build_file_uri: Uri) !std.json.Parsed(BuildConfig) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(self.config.zig_exe_path != null);
    std.debug.assert(self.config.build_runner_path != null);
    std.debug.assert(self.config.global_cache_path != null);

    const build_file_path = try URI.parse(self.allocator, build_file_uri);
    defer self.allocator.free(build_file_path);

    const args = try self.prepareBuildRunnerArgs(build_file_uri);
    defer {
        for (args) |arg| self.allocator.free(arg);
        self.allocator.free(args);
    }

    var zig_run_result = blk: {
        const tracy_zone2 = tracy.trace(@src());
        defer tracy_zone2.end();
        break :blk try std.process.Child.exec(.{
            .allocator = self.allocator,
            .argv = args,
            .cwd = std.fs.path.dirname(build_file_path).?,
            .max_output_bytes = 1024 * 100,
        });
    };
    defer self.allocator.free(zig_run_result.stdout);
    defer self.allocator.free(zig_run_result.stderr);

    errdefer blk: {
        const joined = std.mem.join(self.allocator, " ", args) catch break :blk;
        defer self.allocator.free(joined);

        log.err(
            "Failed to execute build runner to collect build configuration, command:\n{s}\nError: {s}",
            .{ joined, zig_run_result.stderr },
        );
    }

    switch (zig_run_result.term) {
        .Exited => |exit_code| if (exit_code != 0) return error.RunFailed,
        else => return error.RunFailed,
    }

    const parse_options = std.json.ParseOptions{
        // We ignore unknown fields so people can roll
        // their own build runners in libraries with
        // the only requirement being general adherance
        // to the BuildConfig type
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    const build_config = std.json.parseFromSlice(
        BuildConfig,
        self.allocator,
        zig_run_result.stdout,
        parse_options,
    ) catch return error.RunFailed;
    errdefer build_config.deinit();

    for (build_config.value.packages) |*pkg| {
        pkg.path = try std.fs.path.resolve(build_config.arena.allocator(), &[_][]const u8{ build_file_path, "..", pkg.path });
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

            if (std.fs.path.isAbsolute(potential_build_path)) {
                if (std.fs.accessAbsolute(potential_build_path, .{})) {
                    // found a build.zig file
                    return potential_build_path;
                } else |_| {}
            }
            // nope it failed for whatever reason, free it and move the
            // machinery forward
            self.allocator.free(potential_build_path);
        }
    }
};

fn createBuildFile(self: *DocumentStore, uri: Uri) error{OutOfMemory}!BuildFile {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var build_file = BuildFile{
        .uri = try self.allocator.dupe(u8, uri),
        .config = null,
    };

    errdefer build_file.deinit(self.allocator);

    if (loadBuildAssociatedConfiguration(self.allocator, build_file)) |cfg| {
        build_file.build_associated_config = cfg;

        if (cfg.value.relative_builtin_path) |relative_builtin_path| blk: {
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

    if (std.process.can_spawn) {
        const Server = @import("Server.zig");
        const server = @fieldParentPtr(Server, "document_store", self);

        server.job_queue_lock.lock();
        defer server.job_queue_lock.unlock();

        try server.job_queue.ensureUnusedCapacity(1);
        server.job_queue.writeItemAssumeCapacity(.{
            .load_build_configuration = try server.allocator.dupe(u8, build_file.uri),
        });
    }

    return build_file;
}

/// invalidates any pointers into `build_files`
/// **Thread safe** takes an exclusive lock
fn uriAssociatedWithBuild(
    self: *DocumentStore,
    build_file: BuildFile,
    uri: Uri,
) error{OutOfMemory}!bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var checked_uris = std.StringHashMapUnmanaged(void){};
    defer checked_uris.deinit(self.allocator);

    const build_config = build_file.config orelse return false;
    for (build_config.value.packages) |package| {
        const package_uri = try URI.fromPath(self.allocator, package.path);
        defer self.allocator.free(package_uri);

        if (try self.uriInImports(&checked_uris, build_file.uri, package_uri, uri))
            return true;
    }

    return false;
}

/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
fn uriInImports(
    self: *DocumentStore,
    checked_uris: *std.StringHashMapUnmanaged(void),
    build_file_uri: Uri,
    source_uri: Uri,
    uri: Uri,
) error{OutOfMemory}!bool {
    if (std.mem.eql(u8, uri, source_uri)) return true;
    if (isInStd(source_uri)) return false;

    const gop = try checked_uris.getOrPut(self.allocator, source_uri);
    if (gop.found_existing) return false;

    const handle = self.getOrLoadHandle(source_uri) orelse {
        errdefer std.debug.assert(checked_uris.remove(source_uri));
        gop.key_ptr.* = try self.allocator.dupe(u8, source_uri);
        return false;
    };
    gop.key_ptr.* = handle.uri;

    if (handle.associated_build_file) |associated_build_file_uri| {
        return std.mem.eql(u8, associated_build_file_uri, build_file_uri);
    }

    for (handle.import_uris.items) |import_uri| {
        if (try self.uriInImports(checked_uris, build_file_uri, import_uri, uri))
            return true;
    }

    return false;
}

/// invalidates any pointers into `DocumentStore.build_files`
/// takes ownership of the `text` passed in.
/// **Thread safe** takes an exclusive lock
fn createDocument(self: *DocumentStore, uri: Uri, text: [:0]const u8, open: bool) error{OutOfMemory}!Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var handle: Handle = blk: {
        errdefer self.allocator.free(text);

        var duped_uri = try self.allocator.dupe(u8, uri);
        errdefer self.allocator.free(duped_uri);

        var tree = try Ast.parse(self.allocator, text, .zig);
        errdefer tree.deinit(self.allocator);

        // remove unused capacity
        var nodes = tree.nodes.toMultiArrayList();
        try nodes.setCapacity(self.allocator, nodes.len);
        tree.nodes = nodes.slice();

        // remove unused capacity
        var tokens = tree.tokens.toMultiArrayList();
        try tokens.setCapacity(self.allocator, tokens.len);
        tree.tokens = tokens.slice();

        const generate_zir = self.wantZir() and open and tree.errors.len == 0;
        var zir: ?Zir = if (generate_zir) try AstGen.generate(self.allocator, tree) else null;
        errdefer if (zir) |*code| code.deinit(self.allocator);

        // remove unused capacity
        if (zir) |*code| {
            var instructions = code.instructions.toMultiArrayList();
            try instructions.setCapacity(self.allocator, instructions.len);
            code.instructions = instructions.slice();
        }

        var document_scope = try analysis.makeDocumentScope(self.allocator, tree);
        errdefer document_scope.deinit(self.allocator);

        // remove unused capacity
        try document_scope.scopes.setCapacity(self.allocator, document_scope.scopes.len);

        break :blk Handle{
            .open = std.atomic.Atomic(bool).init(open),
            .uri = duped_uri,
            .text = text,
            .tree = tree,
            .zir = if (zir) |code| code else undefined,
            .zir_status = if (zir != null) .done else .none,
            .document_scope = document_scope,
        };
    };
    errdefer handle.deinit(self.allocator);

    handle.import_uris = try self.collectImportUris(handle);
    handle.cimports = try collectCIncludes(self.allocator, handle.tree);

    if (isBuildFile(handle.uri) and !isInStd(handle.uri)) {
        _ = self.getOrLoadBuildFile(handle.uri);
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
            defer self.allocator.free(build_file_uri);
            const build_file = self.getOrLoadBuildFile(build_file_uri) orelse continue;

            if (handle.associated_build_file == null) {
                handle.associated_build_file = build_file.value_ptr.uri;
            } else if (try self.uriAssociatedWithBuild(build_file.value_ptr.*, uri)) { // build_file has been invalidated
                handle.associated_build_file = self.getBuildFile(build_file_uri).?.uri;
                break;
            }
        }
    }

    return handle;
}

/// takes ownership of the `text` passed in.
/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
fn createAndStoreDocument(self: *DocumentStore, uri: Uri, text: [:0]const u8, open: bool) error{OutOfMemory}!*Handle {
    var handle = try self.createDocument(uri, text, open);

    const handle_ptr = try self.allocator.create(Handle);
    errdefer self.allocator.destroy(handle_ptr);
    handle_ptr.* = handle;

    const gop = blk: {
        self.lock.lock();
        defer self.lock.unlock();
        break :blk try self.handles.getOrPutValue(self.allocator, handle.uri, handle_ptr);
    };

    if (gop.found_existing) {
        handle.deinit(self.allocator);
        self.allocator.destroy(handle_ptr);
    }

    return gop.value_ptr.*;
}

/// Caller owns returned memory.
/// **Thread safe** takes a shared lock
fn collectImportUris(self: *DocumentStore, handle: Handle) error{OutOfMemory}!std.ArrayListUnmanaged(Uri) {
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

/// Collects all `@cImport` nodes and converts them into c source code if possible
/// Caller owns returned memory.
fn collectCIncludes(allocator: std.mem.Allocator, tree: Ast) error{OutOfMemory}!std.MultiArrayList(CImportHandle) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var cimport_nodes = try analysis.collectCImportNodes(allocator, tree);
    defer allocator.free(cimport_nodes);

    var sources = std.MultiArrayList(CImportHandle){};
    try sources.ensureTotalCapacity(allocator, cimport_nodes.len);
    errdefer {
        for (sources.items(.source)) |source| {
            allocator.free(source);
        }
        sources.deinit(allocator);
    }

    for (cimport_nodes) |node| {
        const c_source = translate_c.convertCInclude(allocator, tree, node) catch |err| switch (err) {
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
/// **Thread safe** takes a shared lock
pub fn collectDependencies(
    store: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: Handle,
    dependencies: *std.ArrayListUnmanaged(Uri),
) error{OutOfMemory}!void {
    return store.collectDependenciesInternal(allocator, handle, dependencies, true);
}

fn collectDependenciesInternal(
    store: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: Handle,
    dependencies: *std.ArrayListUnmanaged(Uri),
    lock: bool,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (lock) store.lock.lockShared();
    defer if (lock) store.lock.unlockShared();

    try dependencies.ensureUnusedCapacity(allocator, handle.import_uris.items.len + handle.cimports.len);
    for (handle.import_uris.items) |uri| {
        dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri));
    }

    for (handle.cimports.items(.hash)) |hash| {
        const result = store.cimports.get(hash) orelse continue;
        switch (result) {
            .success => |uri| dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri)),
            .failure => continue,
        }
    }

    if (handle.associated_build_file) |build_file_uri| {
        if (store.build_files.get(build_file_uri)) |build_file| blk: {
            const build_config = build_file.config orelse break :blk;
            const packages = build_config.value.packages;
            try dependencies.ensureUnusedCapacity(allocator, packages.len);
            for (packages) |pkg| {
                dependencies.appendAssumeCapacity(try URI.fromPath(allocator, pkg.path));
            }
        }
    }
}

/// returns `true` if all include paths could be collected
/// may return `false` because include paths from a build.zig may not have been resolved already
pub fn collectIncludeDirs(
    store: *const DocumentStore,
    allocator: std.mem.Allocator,
    handle: Handle,
    include_dirs: *std.ArrayListUnmanaged([]const u8),
) !bool {
    var collected_all = true;

    const target_info = try std.zig.system.NativeTargetInfo.detect(.{});

    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();

    var native_paths = try std.zig.system.NativePaths.detect(arena_allocator.allocator(), target_info);

    const build_file_includes_paths: []const []const u8 = if (handle.associated_build_file) |build_file_uri| blk: {
        if (store.build_files.get(build_file_uri).?.config) |cfg| {
            break :blk cfg.value.include_dirs;
        } else {
            collected_all = false;
            break :blk &.{};
        }
    } else &.{};

    try include_dirs.ensureTotalCapacity(allocator, native_paths.include_dirs.items.len + build_file_includes_paths.len);

    for (native_paths.include_dirs.items) |native_include_dir| {
        include_dirs.appendAssumeCapacity(try allocator.dupe(u8, native_include_dir));
    }

    for (build_file_includes_paths) |include_path| {
        const absolute_path = if (std.fs.path.isAbsolute(include_path))
            try allocator.dupe(u8, include_path)
        else blk: {
            const build_file_uri = handle.associated_build_file.?;
            const build_file_dir = std.fs.path.dirname(build_file_uri).?;
            const build_file_path = try URI.parse(allocator, build_file_dir);
            defer allocator.free(build_file_path);

            break :blk try std.fs.path.join(allocator, &.{ build_file_path, include_path });
        };
        include_dirs.appendAssumeCapacity(absolute_path);
    }

    return collected_all;
}

/// returns the document behind `@cImport()` where `node` is the `cImport` node
/// if a cImport can't be translated e.g. requires computing a
/// comptime value `resolveCImport` will return null
/// returned memory is owned by DocumentStore
/// **Thread safe** takes an exclusive lock
pub fn resolveCImport(self: *DocumentStore, handle: Handle, node: Ast.Node.Index) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!std.process.can_spawn) return null;
    if (self.config.zig_exe_path == null) return null;
    if (self.config.zig_lib_path == null) return null;
    if (self.config.global_cache_path == null) return null;

    self.lock.lock();
    defer self.lock.unlock();

    const index = std.mem.indexOfScalar(Ast.Node.Index, handle.cimports.items(.node), node) orelse return null;

    const hash: Hash = handle.cimports.items(.hash)[index];

    // TODO regenerate cimports if the header files gets modified
    const result = self.cimports.get(hash) orelse blk: {
        const source: []const u8 = handle.cimports.items(.source)[index];

        var include_dirs: std.ArrayListUnmanaged([]const u8) = .{};
        defer {
            for (include_dirs.items) |path| {
                self.allocator.free(path);
            }
            include_dirs.deinit(self.allocator);
        }

        const collected_all_include_dirs = self.collectIncludeDirs(self.allocator, handle, &include_dirs) catch |err| {
            log.err("failed to resolve include paths: {}", .{err});
            return null;
        };

        const maybe_result = translate_c.translate(
            self.allocator,
            self.config.*,
            include_dirs.items,
            source,
        ) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => |e| {
                log.err("failed to translate cimport: {}", .{e});
                return null;
            },
        };
        var result = maybe_result orelse return null;

        if (result == .failure and !collected_all_include_dirs) {
            result.deinit(self.allocator);
            return null;
        }

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
/// **Thread safe** takes a shared lock
pub fn uriFromImportStr(self: *DocumentStore, allocator: std.mem.Allocator, handle: Handle, import_str: []const u8) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
            const build_file = self.getBuildFile(build_file_uri).?;
            if (build_file.builtin_uri) |builtin_uri| {
                return try allocator.dupe(u8, builtin_uri);
            }
        }
        if (self.config.builtin_path) |_| {
            return try URI.fromPath(allocator, self.config.builtin_path.?);
        }
        return null;
    } else if (!std.mem.endsWith(u8, import_str, ".zig")) {
        if (handle.associated_build_file) |build_file_uri| blk: {
            const build_file = self.getBuildFile(build_file_uri).?;
            const config = build_file.config orelse break :blk;
            for (config.value.packages) |pkg| {
                if (std.mem.eql(u8, import_str, pkg.name)) {
                    return try URI.fromPath(allocator, pkg.path);
                }
            }
        }
        return null;
    } else {
        var separator_index = handle.uri.len;
        while (separator_index > 0) : (separator_index -= 1) {
            if (std.fs.path.isSep(handle.uri[separator_index - 1])) break;
        }
        const base = handle.uri[0 .. separator_index - 1];

        return URI.pathRelative(allocator, base, import_str) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UriBadScheme => return null,
        };
    }
}

/// **Thread safe** takes a shared lock
fn tagStoreCompletionItems(self: *DocumentStore, arena: std.mem.Allocator, handle: Handle, comptime name: []const u8) error{OutOfMemory}![]types.CompletionItem {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var dependencies = std.ArrayListUnmanaged(Uri){};
    try dependencies.append(arena, handle.uri);
    try self.collectDependenciesInternal(arena, handle, &dependencies, true);

    // TODO Better solution for deciding what tags to include
    var result_set = analysis.CompletionSet{};

    for (dependencies.items) |uri| {
        // not every dependency is loaded which results in incomplete completion
        const hdl = self.getHandle(uri) orelse continue; // takes a shared lock
        const curr_set = @field(hdl.document_scope, name);
        try result_set.ensureUnusedCapacity(arena, curr_set.count());
        for (curr_set.keys()) |completion| {
            result_set.putAssumeCapacity(completion, {});
        }
    }

    return result_set.keys();
}

/// **Thread safe** takes a shared lock
pub fn errorCompletionItems(self: *DocumentStore, arena: std.mem.Allocator, handle: Handle) error{OutOfMemory}![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, handle, "error_completions");
}

/// **Thread safe** takes a shared lock
pub fn enumCompletionItems(self: *DocumentStore, arena: std.mem.Allocator, handle: Handle) error{OutOfMemory}![]types.CompletionItem {
    return try self.tagStoreCompletionItems(arena, handle, "enum_completions");
}

pub fn wantZir(self: DocumentStore) bool {
    if (!self.config.enable_ast_check_diagnostics) return false;
    const can_run_ast_check = std.process.can_spawn and self.config.zig_exe_path != null and self.config.prefer_ast_check_as_child_process;
    return !can_run_ast_check;
}

/// **Thread safe** takes an exclusive lock
pub fn ensureInterpreterExists(self: *DocumentStore, uri: Uri, ip: *InternPool) !*ComptimeInterpreter {
    if (self.getHandle(uri).?.interpreter) |interpreter| return interpreter;

    self.lock.lock();
    defer self.lock.unlock();

    const handle = self.handles.get(uri).?;
    {
        var interpreter = try self.allocator.create(ComptimeInterpreter);
        errdefer self.allocator.destroy(interpreter);

        interpreter.* = ComptimeInterpreter{
            .allocator = self.allocator,
            .ip = ip,
            .document_store = self,
            .uri = uri,
        };
        handle.interpreter = interpreter;
    }

    _ = try handle.interpreter.?.interpret(0, .none, .{});
    return handle.interpreter.?;
}
