const std = @import("std");
const builtin = @import("builtin");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.zls_store);
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
const BuildConfig = @import("build_runner/BuildConfig.zig");
const tracy = @import("tracy");
const translate_c = @import("translate_c.zig");
const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
const AstGen = std.zig.AstGen;
const Zir = std.zig.Zir;
const InternPool = @import("analyser/InternPool.zig");
const DocumentScope = @import("DocumentScope.zig");

const DocumentStore = @This();

allocator: std.mem.Allocator,
/// the DocumentStore assumes that `config` is not modified while calling one of its functions.
config: Config,
lock: std.Thread.RwLock = .{},
thread_pool: if (builtin.single_threaded) void else *std.Thread.Pool,
handles: std.StringArrayHashMapUnmanaged(*Handle) = .{},
handles_in_workspace_folders: std.StringArrayHashMapUnmanaged(*Handle) = .{},
build_files: std.StringArrayHashMapUnmanaged(*BuildFile) = .{},
cimports: std.AutoArrayHashMapUnmanaged(Hash, translate_c.Result) = .{},

pub const Uri = []const u8;

pub const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);
pub const Hash = [Hasher.mac_length]u8;

pub const max_document_size = std.math.maxInt(u32);

pub fn computeHash(bytes: []const u8) Hash {
    var hasher: Hasher = Hasher.init(&[_]u8{0} ** Hasher.key_length);
    hasher.update(bytes);
    var hash: Hash = undefined;
    hasher.final(&hash);
    return hash;
}

pub const Config = struct {
    zig_exe_path: ?[]const u8,
    zig_lib_path: ?[]const u8,
    build_runner_path: ?[]const u8,
    builtin_path: ?[]const u8,
    global_cache_path: ?[]const u8,
    workspace_folders: []const Uri = &.{},

    pub fn fromMainConfig(config: @import("Config.zig"), workspace_folders: []const Uri) Config {
        return .{
            .zig_exe_path = config.zig_exe_path,
            .zig_lib_path = config.zig_lib_path,
            .build_runner_path = config.build_runner_path,
            .builtin_path = config.builtin_path,
            .global_cache_path = config.global_cache_path,
            .workspace_folders = workspace_folders,
        };
    }
};

pub const BuildFile = struct {
    uri: Uri,
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    /// config options extracted from zls.build.json
    build_associated_config: ?std.json.Parsed(BuildAssociatedConfig) = null,
    impl: struct {
        mutex: std.Thread.Mutex = .{},
        /// contains information extracted from running build.zig with a custom build runner
        /// e.g. include paths & packages
        /// TODO this field should not be nullable, callsites should await the build config to be resolved
        /// and then continue instead of dealing with missing information.
        config: ?std.json.Parsed(BuildConfig) = null,
    } = .{},

    pub fn tryLockConfig(self: *BuildFile) ?BuildConfig {
        self.impl.mutex.lock();
        return if (self.impl.config) |cfg| cfg.value else {
            self.impl.mutex.unlock();
            return null;
        };
    }

    pub fn unlockConfig(self: *BuildFile) void {
        self.impl.mutex.unlock();
    }

    /// Usage example:
    /// ```zig
    /// const package_uris = std.ArrayListUnmanaged([]const u8){};
    /// defer {
    ///     for (package_uris) |uri| allocator.free(uri);
    ///     package_uris.deinit(allocator);
    /// }
    /// const success = try build_file.collectBuildConfigPackageUris(allocator, &package_uris);
    /// ```
    pub fn collectBuildConfigPackageUris(
        self: *BuildFile,
        allocator: std.mem.Allocator,
        package_uris: *std.ArrayListUnmanaged(Uri),
    ) error{OutOfMemory}!bool {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const build_config = self.tryLockConfig() orelse return false;
        defer self.unlockConfig();

        try package_uris.ensureUnusedCapacity(allocator, build_config.packages.len);
        for (build_config.packages) |package| {
            package_uris.appendAssumeCapacity(try URI.fromPath(allocator, package.path));
        }
        return true;
    }

    /// Usage example:
    /// ```zig
    /// const include_paths = std.ArrayListUnmanaged([]u8){};
    /// defer {
    ///     for (include_paths) |path| allocator.free(path);
    ///     include_paths.deinit(allocator);
    /// }
    /// const success = try build_file.collectBuildConfigIncludePaths(allocator, &include_paths);
    /// ```
    pub fn collectBuildConfigIncludePaths(
        self: *BuildFile,
        allocator: std.mem.Allocator,
        include_paths: *std.ArrayListUnmanaged([]const u8),
    ) !bool {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const build_config = self.tryLockConfig() orelse return false;
        defer self.unlockConfig();

        try include_paths.ensureUnusedCapacity(allocator, build_config.include_dirs.len);
        for (build_config.include_dirs) |include_path| {
            const absolute_path = if (std.fs.path.isAbsolute(include_path))
                try allocator.dupe(u8, include_path)
            else blk: {
                const build_file_dir = std.fs.path.dirname(self.uri).?;
                const build_file_path = try URI.parse(allocator, build_file_dir);
                defer allocator.free(build_file_path);
                break :blk try std.fs.path.join(allocator, &.{ build_file_path, include_path });
            };

            include_paths.appendAssumeCapacity(absolute_path);
        }
        return true;
    }

    fn setBuildConfig(self: *BuildFile, new_build_config: std.json.Parsed(BuildConfig)) void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        self.impl.mutex.lock();
        defer self.impl.mutex.unlock();

        if (self.impl.config) |*old_config| {
            old_config.deinit();
        }
        self.impl.config = new_build_config;
    }

    fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        if (self.impl.config) |cfg| cfg.deinit();
        if (self.builtin_uri) |builtin_uri| allocator.free(builtin_uri);
        if (self.build_associated_config) |cfg| cfg.deinit();
    }
};

pub const Handle = struct {
    uri: Uri,
    tree: Ast,
    /// Contains one entry for every import in the document
    import_uris: std.ArrayListUnmanaged(Uri) = .{},
    /// Contains one entry for every cimport in the document
    cimports: std.MultiArrayList(CImportHandle) = .{},

    /// error messages from comptime_interpreter or astgen_analyser
    analysis_errors: std.ArrayListUnmanaged(ErrorMessage) = .{},

    is_in_workspace_folders: bool = false,

    /// private field
    impl: struct {
        /// @bitCast from/to `Status`
        status: std.atomic.Value(u32) = std.atomic.Value(u32).init(@bitCast(Status{})),
        /// TODO can we avoid storing one allocator per Handle?
        allocator: std.mem.Allocator,

        lock: std.Thread.Mutex = .{},
        condition: std.Thread.Condition = .{},

        document_scope: DocumentScope = undefined,
        zir: Zir = undefined,
        comptime_interpreter: *ComptimeInterpreter = undefined,

        associated_build_file: union(enum) {
            /// The Handle has no associated build file (build.zig).
            none,
            /// The associated build file (build.zig) has not been resolved yet.
            /// Uris that come first have higher priority.
            unresolved: struct {
                potential_build_files: []const Uri,
                /// to avoid checking build files multiple times, a bitset stores whether or
                /// not the build file should be skipped because it has previously been
                /// found to be "unassociated" with the handle.
                has_been_checked: std.DynamicBitSetUnmanaged,

                fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                    for (self.potential_build_files) |uri| allocator.free(uri);
                    allocator.free(self.potential_build_files);
                    self.has_been_checked.deinit(allocator);
                    self.* = undefined;
                }
            },
            /// The associated build file (build.zig) has been successfully resolved.
            resolved: Uri,
        } = .none,
    },

    const Status = packed struct(u32) {
        /// `true` if the document has been directly opened by the client i.e. with `textDocument/didOpen`
        /// `false` indicates the document only exists because it is a dependency of another document
        /// or has been closed with `textDocument/didClose` and is awaiting cleanup through `garbageCollection`
        open: bool = false,
        /// true if a thread has acquired the permission to compute the `DocumentScope`
        /// all other threads will wait until the given thread has computed the `DocumentScope` before reading it.
        has_document_scope_lock: bool = false,
        /// true if `handle.impl.document_scope` has been set
        has_document_scope: bool = false,
        /// true if a thread has acquired the permission to compute the `ZIR`
        has_zir_lock: bool = false,
        /// all other threads will wait until the given thread has computed the `ZIR` before reading it.
        /// true if `handle.impl.zir` has been set
        has_zir: bool = false,
        zir_outdated: bool = undefined,
        /// true if `handle.impl.comptime_interpreter` has been set
        has_comptime_interpreter: bool = false,
        _: u25 = undefined,
    };

    pub const ZirStatus = enum {
        none,
        outdated,
        done,
    };

    /// takes ownership of `text`
    pub fn init(allocator: std.mem.Allocator, uri: Uri, text: [:0]const u8) error{OutOfMemory}!Handle {
        const duped_uri = try allocator.dupe(u8, uri);
        errdefer allocator.free(duped_uri);

        const tree = try parseTree(allocator, text);
        errdefer tree.deinit(allocator);

        return .{
            .uri = duped_uri,
            .tree = tree,
            .impl = .{
                .allocator = allocator,
            },
        };
    }

    pub fn getDocumentScope(self: *Handle) error{OutOfMemory}!DocumentScope {
        if (self.getStatus().has_document_scope) return self.impl.document_scope;
        return try self.getDocumentScopeCold();
    }

    pub fn getZir(self: *Handle) error{OutOfMemory}!Zir {
        if (self.getStatus().has_zir) return self.impl.zir;
        return try self.getZirCold();
    }

    pub fn getZirStatus(self: Handle) ZirStatus {
        const status = self.getStatus();
        if (!status.has_zir) return .none;
        return if (status.zir_outdated) .outdated else .done;
    }

    pub fn getComptimeInterpreter(self: *Handle, document_store: *DocumentStore, ip: *InternPool) error{OutOfMemory}!*ComptimeInterpreter {
        if (self.getStatus().has_comptime_interpreter) return self.impl.comptime_interpreter;
        return try self.getComptimeInterpreterCold(document_store, ip);
    }

    /// Returns the associated build file (build.zig) of the handle.
    ///
    /// `DocumentStore.build_files` is guaranteed to contain this Uri.
    /// Uri memory managed by its build_file
    pub fn getAssociatedBuildFileUri(self: *Handle, document_store: *DocumentStore) error{OutOfMemory}!?Uri {
        switch (try self.getAssociatedBuildFileUri2(document_store)) {
            .none,
            .unresolved,
            => return null,
            .resolved => |uri| return uri,
        }
    }

    /// Returns the associated build file (build.zig) of the handle.
    ///
    /// `DocumentStore.build_files` is guaranteed to contain this Uri.
    /// Uri memory managed by its build_file
    pub fn getAssociatedBuildFileUri2(self: *Handle, document_store: *DocumentStore) error{OutOfMemory}!union(enum) {
        /// The Handle has no associated build file (build.zig).
        none,
        /// The associated build file (build.zig) has not been resolved yet.
        unresolved,
        /// The associated build file (build.zig) has been successfully resolved.
        resolved: Uri,
    } {
        self.impl.lock.lock();
        defer self.impl.lock.unlock();

        const unresolved = switch (self.impl.associated_build_file) {
            .none => return .none,
            .unresolved => |*unresolved| unresolved,
            .resolved => |uri| return .{ .resolved = uri },
        };

        // special case when there is only one potential build file
        if (unresolved.potential_build_files.len == 1) blk: {
            const build_file = document_store.getOrLoadBuildFile(unresolved.potential_build_files[0]) orelse break :blk;
            log.debug("Resolved build file of `{s}` as `{s}`", .{ self.uri, build_file.uri });
            unresolved.deinit(document_store.allocator);
            self.impl.associated_build_file = .{ .resolved = build_file.uri };
            return .{ .resolved = build_file.uri };
        }

        var has_missing_build_config = false;

        var it = unresolved.has_been_checked.iterator(.{
            .kind = .unset,
            .direction = .reverse,
        });
        while (it.next()) |i| {
            const build_file_uri = unresolved.potential_build_files[i];
            const build_file = document_store.getOrLoadBuildFile(build_file_uri) orelse continue;
            const is_associated = try document_store.uriAssociatedWithBuild(build_file, self.uri) orelse {
                has_missing_build_config = true;
                continue;
            };

            if (!is_associated) {
                // the build file should be skipped in future calls.
                unresolved.has_been_checked.set(i);
                continue;
            }

            log.debug("Resolved build file of `{s}` as `{s}`", .{ self.uri, build_file.uri });
            unresolved.deinit(document_store.allocator);
            self.impl.associated_build_file = .{ .resolved = build_file.uri };
            return .{ .resolved = build_file.uri };
        }

        if (has_missing_build_config) {
            // when build configs are missing we keep the state at .unresolved so that
            // future calls will retry until all build config are resolved.
            // Then will have a conclusive result on whether or not there is a associated build file.
            return .unresolved;
        }

        unresolved.deinit(document_store.allocator);
        self.impl.associated_build_file = .none;
        return .none;
    }

    fn getAssociatedBuildFileUriDontResolve(self: *Handle) ?Uri {
        self.impl.lock.lock();
        defer self.impl.lock.unlock();

        switch (self.impl.associated_build_file) {
            .none, .unresolved => return null,
            .resolved => |uri| return uri,
        }
    }

    fn getDocumentScopeCold(self: *Handle) error{OutOfMemory}!DocumentScope {
        @setCold(true);
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        self.impl.lock.lock();
        defer self.impl.lock.unlock();
        while (true) {
            const status = self.getStatus();
            if (status.has_document_scope) break;
            if (status.has_document_scope_lock) {
                // another thread is currently computing the document scope
                self.impl.condition.wait(&self.impl.lock);
                continue;
            } else if (self.impl.status.bitSet(@bitOffsetOf(Status, "has_document_scope_lock"), .release) != 0) {
                // another thread is currently computing the document scope
                self.impl.condition.wait(&self.impl.lock);
                continue;
            }

            self.impl.document_scope = blk: {
                var document_scope = try DocumentScope.init(self.impl.allocator, self.tree);
                errdefer document_scope.deinit(self.impl.allocator);

                // remove unused capacity
                document_scope.extra.shrinkAndFree(self.impl.allocator, document_scope.extra.items.len);
                try document_scope.declarations.setCapacity(self.impl.allocator, document_scope.declarations.len);
                try document_scope.scopes.setCapacity(self.impl.allocator, document_scope.scopes.len);

                break :blk document_scope;
            };
            const old_has_document_scope = self.impl.status.bitSet(@bitOffsetOf(Status, "has_document_scope"), .release); // atomically set has_document_scope
            std.debug.assert(old_has_document_scope == 0); // race condition: another thread set `has_document_scope` even though we hold the lock

            self.impl.condition.broadcast();
        }
        return self.impl.document_scope;
    }

    fn getZirCold(self: *Handle) error{OutOfMemory}!Zir {
        @setCold(true);
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        self.impl.lock.lock();
        defer self.impl.lock.unlock();
        while (true) {
            const status = self.getStatus();
            if (status.has_zir) break;
            if (status.has_zir_lock) {
                // another thread is currently computing the ZIR
                self.impl.condition.wait(&self.impl.lock);
                continue;
            } else if (self.impl.status.bitSet(@bitOffsetOf(Status, "has_zir_lock"), .release) != 0) {
                // another thread is currently computing the ZIR
                self.impl.condition.wait(&self.impl.lock);
                continue;
            }

            self.impl.zir = blk: {
                const tracy_zone_inner = tracy.traceNamed(@src(), "AstGen.generate");
                defer tracy_zone_inner.end();

                var zir = try AstGen.generate(self.impl.allocator, self.tree);
                errdefer zir.deinit(self.impl.allocator);

                // remove unused capacity
                var instructions = zir.instructions.toMultiArrayList();
                try instructions.setCapacity(self.impl.allocator, instructions.len);
                zir.instructions = instructions.slice();

                break :blk zir;
            };
            _ = self.impl.status.bitReset(@bitOffsetOf(Status, "zir_outdated"), .release); // atomically set zir_outdated
            const old_has_zir = self.impl.status.bitSet(@bitOffsetOf(Status, "has_zir"), .release); // atomically set has_zir
            std.debug.assert(old_has_zir == 0); // race condition: another thread set `has_zir` even though we hold the lock

            self.impl.condition.broadcast();
        }
        return self.impl.zir;
    }

    fn getComptimeInterpreterCold(
        self: *Handle,
        document_store: *DocumentStore,
        ip: *InternPool,
    ) error{OutOfMemory}!*ComptimeInterpreter {
        @setCold(true);
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const comptime_interpreter = try self.impl.allocator.create(ComptimeInterpreter);
        errdefer self.impl.allocator.destroy(comptime_interpreter);

        comptime_interpreter.* = ComptimeInterpreter{
            .allocator = self.impl.allocator,
            .ip = ip,
            .document_store = document_store,
            .uri = self.uri,
        };

        {
            self.impl.lock.lock();
            errdefer @compileError("");

            if (self.getStatus().has_comptime_interpreter) { // another thread outpaced us
                self.impl.lock.unlock();
                self.impl.allocator.destroy(comptime_interpreter);
                return self.impl.comptime_interpreter;
            }
            self.impl.comptime_interpreter = comptime_interpreter;
            const old = self.impl.status.bitSet(@bitOffsetOf(Status, "has_comptime_interpreter"), .release); // atomically set has_imports
            std.debug.assert(old == 0); // race condition: another thread set the resource even though we hold the lock
            self.impl.lock.unlock();
        }

        return self.impl.comptime_interpreter;
    }

    fn getStatus(self: Handle) Status {
        return @bitCast(self.impl.status.load(.acquire));
    }

    pub fn isOpen(self: Handle) bool {
        return self.getStatus().open;
    }

    /// returns the previous value
    fn setOpen(self: *Handle, open: bool) bool {
        if (open) {
            return self.impl.status.bitSet(@offsetOf(Handle.Status, "open"), .release) == 1;
        } else {
            return self.impl.status.bitReset(@offsetOf(Handle.Status, "open"), .release) == 1;
        }
    }

    fn parseTree(allocator: std.mem.Allocator, new_text: [:0]const u8) error{OutOfMemory}!Ast {
        const tracy_zone_inner = tracy.traceNamed(@src(), "Ast.parse");
        defer tracy_zone_inner.end();

        var tree = try Ast.parse(allocator, new_text, .zig);
        errdefer tree.deinit(allocator);

        // remove unused capacity
        var nodes = tree.nodes.toMultiArrayList();
        try nodes.setCapacity(allocator, nodes.len);
        tree.nodes = nodes.slice();

        // remove unused capacity
        var tokens = tree.tokens.toMultiArrayList();
        try tokens.setCapacity(allocator, tokens.len);
        tree.tokens = tokens.slice();
        return tree;
    }

    fn setSource(self: *Handle, new_text: [:0]const u8) error{OutOfMemory}!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const new_status = Handle.Status{
            .open = self.getStatus().open,
        };

        const new_tree = try parseTree(self.impl.allocator, new_text);

        self.impl.lock.lock();
        errdefer @compileError("");

        const old_status: Handle.Status = @bitCast(self.impl.status.swap(@bitCast(new_status), .acq_rel));

        var old_tree = self.tree;
        var old_import_uris = self.import_uris;
        var old_cimports = self.cimports;
        var old_analysis_errors = self.analysis_errors;
        var old_document_scope = if (old_status.has_document_scope) self.impl.document_scope else null;
        var old_zir = if (old_status.has_zir) self.impl.zir else null;
        const old_comptime_interpreter = if (old_status.has_comptime_interpreter) self.impl.comptime_interpreter else null;

        self.tree = new_tree;
        self.import_uris = .{};
        self.cimports = .{};
        self.analysis_errors = .{};
        self.impl.document_scope = undefined;
        self.impl.zir = undefined;
        self.impl.comptime_interpreter = undefined;

        self.impl.lock.unlock();

        self.impl.allocator.free(old_tree.source);
        old_tree.deinit(self.impl.allocator);

        for (old_import_uris.items) |uri| self.impl.allocator.free(uri);
        old_import_uris.deinit(self.impl.allocator);

        for (old_analysis_errors.items) |err| self.impl.allocator.free(err.message);
        old_analysis_errors.deinit(self.impl.allocator);

        for (old_cimports.items(.source)) |source| self.impl.allocator.free(source);
        old_cimports.deinit(self.impl.allocator);

        if (old_document_scope) |*document_scope| document_scope.deinit(self.impl.allocator);
        if (old_zir) |*zir| zir.deinit(self.impl.allocator);
        if (old_comptime_interpreter) |comptime_interpreter| {
            comptime_interpreter.deinit();
            self.impl.allocator.destroy(comptime_interpreter);
        }
    }

    fn deinit(self: *Handle) void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const status = self.getStatus();

        const allocator = self.impl.allocator;

        if (status.has_comptime_interpreter) {
            self.impl.comptime_interpreter.deinit();
            allocator.destroy(self.impl.comptime_interpreter);
        }
        if (status.has_zir) self.impl.zir.deinit(allocator);
        if (status.has_document_scope) self.impl.document_scope.deinit(allocator);
        allocator.free(self.tree.source);
        self.tree.deinit(allocator);
        allocator.free(self.uri);

        for (self.import_uris.items) |uri| allocator.free(uri);
        self.import_uris.deinit(allocator);

        for (self.analysis_errors.items) |err| allocator.free(err.message);
        self.analysis_errors.deinit(allocator);

        for (self.cimports.items(.source)) |source| allocator.free(source);
        self.cimports.deinit(allocator);

        switch (self.impl.associated_build_file) {
            .none, .resolved => {},
            .unresolved => |*payload| payload.deinit(allocator),
        }

        self.* = undefined;
    }
};

pub const ErrorMessage = struct {
    loc: offsets.Loc,
    code: []const u8,
    message: []const u8,
};

pub fn deinit(self: *DocumentStore) void {
    for (self.handles.values()) |handle| {
        handle.deinit();
        self.allocator.destroy(handle);
    }
    self.handles.deinit(self.allocator);

    for (self.build_files.values()) |build_file| {
        build_file.deinit(self.allocator);
        self.allocator.destroy(build_file);
    }
    self.build_files.deinit(self.allocator);

    for (self.cimports.values()) |*result| {
        result.deinit(self.allocator);
    }
    self.cimports.deinit(self.allocator);
    self.handles_in_workspace_folders.deinit(self.allocator);
    self.* = undefined;
}

/// Returns a handle to the given document
/// **Thread safe** takes a shared lock
/// This function does not protect against data races from modifying the Handle
pub fn getHandle(self: *DocumentStore, uri: Uri) ?*Handle {
    self.lock.lockShared();
    defer self.lock.unlockShared();
    return self.handles.get(uri);
}

/// Returns a handle to the given document
/// Will load the document from disk if it hasn't been already
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the Handle
pub fn getOrLoadHandle(self: *DocumentStore, uri: Uri) ?*Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.getHandle(uri)) |handle| return handle;

    const file_path = URI.parse(self.allocator, uri) catch |err| {
        log.err("failed to parse URI `{s}`: {}", .{ uri, err });
        return null;
    };
    defer self.allocator.free(file_path);

    if (!std.fs.path.isAbsolute(file_path)) {
        log.err("file path is not absolute `{s}`", .{file_path});
        return null;
    }
    const file_contents = std.fs.cwd().readFileAllocOptions(
        self.allocator,
        file_path,
        max_document_size,
        null,
        @alignOf(u8),
        0,
    ) catch |err| {
        log.err("failed to load document `{s}`: {}", .{ file_path, err });
        return null;
    };

    return self.createAndStoreDocument(uri, file_contents, false) catch return null;
}

/// **Thread safe** takes a shared lock
/// This function does not protect against data races from modifying the BuildFile
pub fn getBuildFile(self: *DocumentStore, uri: Uri) ?*BuildFile {
    self.lock.lockShared();
    defer self.lock.unlockShared();
    return self.build_files.get(uri);
}

/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the BuildFile
fn getOrLoadBuildFile(self: *DocumentStore, uri: Uri) ?*BuildFile {
    if (self.getBuildFile(uri)) |build_file| return build_file;

    self.lock.lock();
    defer self.lock.unlock();

    const gop = self.build_files.getOrPut(self.allocator, uri) catch return null;
    if (!gop.found_existing) {
        gop.value_ptr.* = self.allocator.create(BuildFile) catch |err| {
            self.build_files.swapRemoveAt(gop.index);
            log.debug("Failed to load build file {s}: {}", .{ uri, err });
            return null;
        };

        gop.value_ptr.*.* = self.createBuildFile(uri) catch |err| {
            self.allocator.destroy(gop.value_ptr.*);
            self.build_files.swapRemoveAt(gop.index);
            log.debug("Failed to load build file {s}: {}", .{ uri, err });
            return null;
        };
        gop.key_ptr.* = gop.value_ptr.*.uri;
    }

    return gop.value_ptr.*;
}

/// **Thread safe** takes an exclusive lock
pub fn openDocument(self: *DocumentStore, uri: Uri, text: []const u8) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.handles.get(uri)) |handle| {
            if (!handle.setOpen(true)) {
                log.warn("Document already open: {s}", .{uri});
            }
            return;
        }
    }

    const duped_text = try self.allocator.dupeZ(u8, text);
    _ = try self.createAndStoreDocument(uri, duped_text, true);
}

/// **Thread safe** takes a shared lock, takes an exclusive lock (with `tryLock`)
/// Assumes that no other thread is currently accessing the given document
pub fn closeDocument(self: *DocumentStore, uri: Uri) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    _ = self.handles_in_workspace_folders.swapRemove(uri);

    {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const handle = self.handles.get(uri) orelse {
            log.warn("Document not found: {s}", .{uri});
            return;
        };
        // instead of destroying the handle here we just mark it not open
        // and let it be destroy by the garbage collection code
        if (!handle.setOpen(false)) {
            log.warn("Document already closed: {s}", .{uri});
        }
    }

    if (!self.lock.tryLock()) return;
    defer self.lock.unlock();

    self.garbageCollectionImports() catch {};
    self.garbageCollectionCImports() catch {};
    self.garbageCollectionBuildFiles() catch {};
}

/// Takes ownership of `new_text` which has to be allocated with this DocumentStore's allocator.
/// Assumes that a document with the given `uri` is in the DocumentStore.
///
/// **Thread safe** takes a shared lock when called on different documents
/// **Not thread safe** when called on the same document
pub fn refreshDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = self.getHandle(uri).?;
    if (!handle.getStatus().open) {
        log.warn("Document modified without being opened: {s}", .{uri});
    }
    try handle.setSource(new_text);
    handle.import_uris = try self.collectImportUris(handle);
    handle.cimports = try collectCIncludes(self.allocator, handle.tree);
}

/// Invalidates a build files.
/// **Thread safe** takes a shared lock
pub fn invalidateBuildFile(self: *DocumentStore, build_file_uri: Uri) error{OutOfMemory}!void {
    comptime std.debug.assert(std.process.can_spawn);

    if (self.config.zig_exe_path == null) return;
    if (self.config.build_runner_path == null) return;
    if (self.config.global_cache_path == null) return;

    const uri = try self.allocator.dupe(u8, build_file_uri);
    errdefer self.allocator.free(uri);

    if (builtin.single_threaded) {
        self.invalidateBuildFileWorker(uri);
    } else {
        try self.thread_pool.spawn(invalidateBuildFileWorker, .{ self, uri });
    }
}

fn invalidateBuildFileWorker(self: *DocumentStore, build_file_uri: Uri) void {
    defer self.allocator.free(build_file_uri);

    const build_config = loadBuildConfiguration(self, build_file_uri) catch |err| {
        log.err("Failed to load build configuration for {s} (error: {})", .{ build_file_uri, err });
        return;
    };

    const build_file = self.getBuildFile(build_file_uri) orelse {
        build_config.deinit();
        return;
    };
    build_file.setBuildConfig(build_config);
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
        if (!handle.getStatus().open) continue;
        reachable.set(handle_index);

        try self.collectDependenciesInternal(arena.allocator(), handle, &queue, false);
    }

    while (queue.popOrNull()) |uri| {
        const handle_index = self.handles.getIndex(uri) orelse continue;
        if (reachable.isSet(handle_index)) continue;
        reachable.set(handle_index);

        const handle = self.handles.values()[handle_index];

        try self.collectDependenciesInternal(arena.allocator(), handle, &queue, false);
    }

    var it = reachable.iterator(.{
        .kind = .unset,
        .direction = .reverse,
    });

    while (it.next()) |handle_index| {
        const handle = self.handles.values()[handle_index];
        log.debug("Closing document {s}", .{handle.uri});
        self.handles.swapRemoveAt(handle_index);
        handle.deinit();
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
        const build_file_uri = handle.getAssociatedBuildFileUriDontResolve() orelse continue;
        const build_file_index = self.build_files.getIndex(build_file_uri).?;

        reachable.set(build_file_index);
    }

    var it = reachable.iterator(.{
        .kind = .unset,
        .direction = .reverse,
    });

    while (it.next()) |build_file_index| {
        const build_file = self.build_files.values()[build_file_index];
        log.debug("Destroying build file {s}", .{build_file.uri});
        self.build_files.swapRemoveAt(build_file_index);
        build_file.deinit(self.allocator);
        self.allocator.destroy(build_file);
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

pub fn isInWorkspaceFolders(store: DocumentStore, uri: Uri) bool {
    // TODO: Better logic for detecting workspace folders?
    return for (store.config.workspace_folders) |wf| {
        // NOTE: terrible but it should work
        if (std.mem.startsWith(u8, uri, wf)) break true;
    } else false;
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

    if (self.getBuildFile(build_file_uri)) |build_file| blk: {
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
fn loadBuildConfiguration(self: *DocumentStore, build_file_uri: Uri) !std.json.Parsed(BuildConfig) {
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

    const zig_run_result = blk: {
        const tracy_zone2 = tracy.trace(@src());
        defer tracy_zone2.end();
        break :blk try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = args,
            .cwd = std.fs.path.dirname(build_file_path).?,
            .max_output_bytes = 1024 * 1024,
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

/// Walk down the tree towards the uri. When we hit `build.zig` files
/// add them to the list of potential build files.
/// `build.zig` files higher in the filesystem have precedence.
/// See `Handle.getAssociatedBuildFileUri`.
/// Caller owns returned memory.
fn collectPotentialBuildFiles(self: *DocumentStore, uri: Uri) ![]Uri {
    var potential_build_files = std.ArrayListUnmanaged(Uri){};
    errdefer {
        for (potential_build_files.items) |build_file_uri| self.allocator.free(build_file_uri);
        potential_build_files.deinit(self.allocator);
    }

    const path = try URI.parse(self.allocator, uri);
    defer self.allocator.free(path);

    var build_it = try BuildDotZigIterator.init(self.allocator, path);
    while (try build_it.next()) |build_path| {
        defer self.allocator.free(build_path);

        try potential_build_files.ensureUnusedCapacity(self.allocator, 1);

        const build_file_uri = try URI.fromPath(self.allocator, build_path);

        _ = self.getOrLoadBuildFile(build_file_uri) orelse {
            self.allocator.free(build_file_uri);
            continue;
        };
        potential_build_files.appendAssumeCapacity(build_file_uri);
    }

    return try potential_build_files.toOwnedSlice(self.allocator);
}

fn createBuildFile(self: *DocumentStore, uri: Uri) error{OutOfMemory}!BuildFile {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var build_file = BuildFile{
        .uri = try self.allocator.dupe(u8, uri),
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
        try self.invalidateBuildFile(build_file.uri);
    }

    return build_file;
}

/// Returns whether the `Uri` is a dependency of the given `BuildFile`.
/// May return `null` to indicate an inconclusive result because
/// the required build config has not been resolved yet.
///
/// invalidates any pointers into `build_files`
/// **Thread safe** takes an exclusive lock
fn uriAssociatedWithBuild(
    self: *DocumentStore,
    build_file: *BuildFile,
    uri: Uri,
) error{OutOfMemory}!?bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var checked_uris = std.StringHashMapUnmanaged(void){};
    defer checked_uris.deinit(self.allocator);

    var package_uris = std.ArrayListUnmanaged(Uri){};
    defer {
        for (package_uris.items) |package_uri| self.allocator.free(package_uri);
        package_uris.deinit(self.allocator);
    }
    const success = try build_file.collectBuildConfigPackageUris(self.allocator, &package_uris);
    if (!success) return null;

    for (package_uris.items) |package_uri| {
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

    if (try handle.getAssociatedBuildFileUri(self)) |associated_build_file_uri| {
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

    var handle = try Handle.init(self.allocator, uri, text);
    errdefer handle.deinit();

    _ = handle.setOpen(open);

    if (isBuildFile(handle.uri) and !isInStd(handle.uri)) {
        _ = self.getOrLoadBuildFile(handle.uri);
    } else if (!isBuiltinFile(handle.uri) and !isInStd(handle.uri)) blk: {
        const potential_build_files = self.collectPotentialBuildFiles(uri) catch {
            log.err("failed to collect potential build files of `{s}`", .{handle.uri});
            break :blk;
        };
        errdefer {
            for (potential_build_files) |build_file_uri| self.allocator.free(build_file_uri);
            self.allocator.free(potential_build_files);
        }

        var has_been_checked = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, potential_build_files.len);
        errdefer has_been_checked.deinit(self.allocator);

        handle.impl.associated_build_file = .{ .unresolved = .{
            .has_been_checked = has_been_checked,
            .potential_build_files = potential_build_files,
        } };
    }

    handle.import_uris = try self.collectImportUris(&handle);
    handle.cimports = try collectCIncludes(self.allocator, handle.tree);

    return handle;
}

/// takes ownership of the `text` passed in.
/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
fn createAndStoreDocument(self: *DocumentStore, uri: Uri, text: [:0]const u8, open: bool) error{OutOfMemory}!*Handle {
    const handle_ptr: *Handle = try self.allocator.create(Handle);
    errdefer self.allocator.destroy(handle_ptr);

    handle_ptr.* = try self.createDocument(uri, text, open);
    errdefer handle_ptr.deinit();

    const gop = blk: {
        self.lock.lock();
        defer self.lock.unlock();
        break :blk try self.handles.getOrPutValue(self.allocator, handle_ptr.uri, handle_ptr);
    };

    if (gop.found_existing) {
        handle_ptr.deinit();
        self.allocator.destroy(handle_ptr);
    }

    const is_build_file = isBuildFile(gop.value_ptr.*.uri);
    const is_in_workspace_folders = self.isInWorkspaceFolders(uri);

    if (is_in_workspace_folders) {
        handle_ptr.is_in_workspace_folders = true;
        if (is_in_workspace_folders) {
            try self.handles_in_workspace_folders.put(self.allocator, gop.value_ptr.*.uri, handle_ptr);
        }
    }

    if (is_build_file) {
        log.debug("Opened document `{s}` (build file)", .{gop.value_ptr.*.uri});
    } else {
        if (is_in_workspace_folders) {
            log.debug("Opened document `{s}` (in workspace folders)", .{gop.value_ptr.*.uri});
        } else {
            log.debug("Opened document `{s}`", .{gop.value_ptr.*.uri});
        }
    }

    return gop.value_ptr.*;
}

/// Caller owns returned memory.
/// **Thread safe** takes a shared lock
fn collectImportUris(self: *DocumentStore, handle: *Handle) error{OutOfMemory}!std.ArrayListUnmanaged(Uri) {
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

    const cimport_nodes = try analysis.collectCImportNodes(allocator, tree);
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
    handle: *Handle,
    dependencies: *std.ArrayListUnmanaged(Uri),
) error{OutOfMemory}!void {
    return store.collectDependenciesInternal(allocator, handle, dependencies, true);
}

fn collectDependenciesInternal(
    store: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: *Handle,
    dependencies: *std.ArrayListUnmanaged(Uri),
    lock: bool,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    {
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
    }

    no_build_file: {
        const build_file_uri = if (lock)
            try handle.getAssociatedBuildFileUri(store) orelse break :no_build_file
        else
            handle.getAssociatedBuildFileUriDontResolve() orelse break :no_build_file;

        const build_file = if (lock)
            store.getBuildFile(build_file_uri) orelse break :no_build_file
        else
            store.build_files.get(build_file_uri) orelse break :no_build_file;

        _ = try build_file.collectBuildConfigPackageUris(allocator, dependencies);
    }
}

/// returns `true` if all include paths could be collected
/// may return `false` because include paths from a build.zig may not have been resolved already
/// **Thread safe** takes a shared lock
pub fn collectIncludeDirs(
    store: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: *Handle,
    include_dirs: *std.ArrayListUnmanaged([]const u8),
) !bool {
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();

    const target_info = try std.zig.system.resolveTargetQuery(.{});
    const native_paths = try std.zig.system.NativePaths.detect(arena_allocator.allocator(), target_info);

    try include_dirs.ensureUnusedCapacity(allocator, native_paths.include_dirs.items.len);
    for (native_paths.include_dirs.items) |native_include_dir| {
        include_dirs.appendAssumeCapacity(try allocator.dupe(u8, native_include_dir));
    }

    const collected_all = switch (try handle.getAssociatedBuildFileUri2(store)) {
        .none => true,
        .unresolved => false,
        .resolved => |build_file_uri| blk: {
            const build_file = store.getBuildFile(build_file_uri).?;
            break :blk try build_file.collectBuildConfigIncludePaths(allocator, include_dirs);
        },
    };

    return collected_all;
}

/// returns the document behind `@cImport()` where `node` is the `cImport` node
/// if a cImport can't be translated e.g. requires computing a
/// comptime value `resolveCImport` will return null
/// returned memory is owned by DocumentStore
/// **Thread safe** takes an exclusive lock
pub fn resolveCImport(self: *DocumentStore, handle: *Handle, node: Ast.Node.Index) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!std.process.can_spawn) return null;
    if (self.config.zig_exe_path == null) return null;
    if (self.config.zig_lib_path == null) return null;
    if (self.config.global_cache_path == null) return null;

    // TODO regenerate cimports if the header files gets modified

    const index = std.mem.indexOfScalar(Ast.Node.Index, handle.cimports.items(.node), node) orelse return null;
    const hash: Hash = handle.cimports.items(.hash)[index];
    const source = handle.cimports.items(.source)[index];

    {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.cimports.get(hash)) |result| {
            switch (result) {
                .success => |uri| return uri,
                .failure => return null,
            }
        }
    }

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
        self.config,
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

    {
        self.lock.lock();
        defer self.lock.unlock();
        const gop = self.cimports.getOrPutValue(self.allocator, hash, result) catch |err| {
            result.deinit(self.allocator);
            return err;
        };
        if (gop.found_existing) {
            result.deinit(self.allocator);
            result = gop.value_ptr.*;
        }
    }

    switch (result) {
        .success => |uri| {
            log.debug("Translated cImport into {s}", .{uri});
            return uri;
        },
        .failure => return null,
    }
}

/// takes the string inside a @import() node (without the quotation marks)
/// and returns it's uri
/// caller owns the returned memory
/// **Thread safe** takes a shared lock
pub fn uriFromImportStr(self: *DocumentStore, allocator: std.mem.Allocator, handle: *Handle, import_str: []const u8) error{OutOfMemory}!?Uri {
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
        if (try handle.getAssociatedBuildFileUri(self)) |build_file_uri| {
            const build_file = self.getBuildFile(build_file_uri).?;
            if (build_file.builtin_uri) |builtin_uri| {
                return try allocator.dupe(u8, builtin_uri);
            }
        }
        if (self.config.builtin_path) |builtin_path| {
            return try URI.fromPath(allocator, builtin_path);
        }
        return null;
    } else if (!std.mem.endsWith(u8, import_str, ".zig")) {
        if (try handle.getAssociatedBuildFileUri(self)) |build_file_uri| blk: {
            const build_file = self.getBuildFile(build_file_uri).?;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            for (build_config.packages) |pkg| {
                if (std.mem.eql(u8, import_str, pkg.name)) {
                    return try URI.fromPath(allocator, pkg.path);
                }
            }
        } else if (isBuildFile(handle.uri)) blk: {
            const build_file = self.getBuildFile(handle.uri) orelse break :blk;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            for (build_config.deps_build_roots) |dep_build_root| {
                if (std.mem.eql(u8, import_str, dep_build_root.name)) {
                    return try URI.fromPath(allocator, dep_build_root.path);
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

pub fn updateHandlesInWorkspaceFolders(store: *DocumentStore) error{OutOfMemory}!void {
    store.handles_in_workspace_folders.clearRetainingCapacity();
    for (store.handles.values()) |handle| {
        const is_in_workspace_folders = store.isInWorkspaceFolders(handle.uri);
        handle.is_in_workspace_folders = is_in_workspace_folders;
        if (is_in_workspace_folders) {
            try store.handles_in_workspace_folders.put(store.allocator, handle.uri, handle);
        }
    }
}
