//! A thread-safe container for all document related state like zig source files including `build.zig`.

const std = @import("std");
const builtin = @import("builtin");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.store);
const lsp = @import("lsp");
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
const BuildConfig = @import("build_runner/shared.zig").BuildConfig;
const tracy = @import("tracy");
const translate_c = @import("translate_c.zig");
const DocumentScope = @import("DocumentScope.zig");
const DiagnosticsCollection = @import("DiagnosticsCollection.zig");

const DocumentStore = @This();

allocator: std.mem.Allocator,
/// the DocumentStore assumes that `config` is not modified while calling one of its functions.
config: Config,
lock: std.Thread.RwLock = .{},
thread_pool: *std.Thread.Pool,
handles: std.StringArrayHashMapUnmanaged(*Handle) = .empty,
build_files: if (supports_build_system) std.StringArrayHashMapUnmanaged(*BuildFile) else void = if (supports_build_system) .empty else {},
cimports: if (supports_build_system) std.AutoArrayHashMapUnmanaged(Hash, translate_c.Result) else void = if (supports_build_system) .empty else {},
diagnostics_collection: *DiagnosticsCollection,
builds_in_progress: std.atomic.Value(i32) = .init(0),
transport: ?*lsp.Transport = null,
lsp_capabilities: struct {
    supports_work_done_progress: bool = false,
    supports_semantic_tokens_refresh: bool = false,
    supports_inlay_hints_refresh: bool = false,
} = .{},

pub const Uri = []const u8;

pub const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);
pub const Hash = [Hasher.mac_length]u8;

pub const max_document_size = std.math.maxInt(u32);

pub const supports_build_system = std.process.can_spawn;

pub fn computeHash(bytes: []const u8) Hash {
    var hasher: Hasher = .init(&@splat(0));
    hasher.update(bytes);
    var hash: Hash = undefined;
    hasher.final(&hash);
    return hash;
}

pub const Config = struct {
    zig_exe_path: ?[]const u8,
    zig_lib_dir: ?std.Build.Cache.Directory,
    build_runner_path: ?[]const u8,
    builtin_path: ?[]const u8,
    global_cache_dir: ?std.Build.Cache.Directory,

    pub const init: Config = .{
        .zig_exe_path = null,
        .zig_lib_dir = null,
        .build_runner_path = null,
        .builtin_path = null,
        .global_cache_dir = null,
    };
};

/// Represents a `build.zig`
pub const BuildFile = struct {
    uri: Uri,
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    /// config options extracted from zls.build.json
    build_associated_config: ?std.json.Parsed(BuildAssociatedConfig) = null,
    impl: struct {
        mutex: std.Thread.Mutex = .{},
        build_runner_state: BuildRunnerState = .idle,
        version: u32 = 0,
        /// contains information extracted from running build.zig with a custom build runner
        /// e.g. include paths & packages
        /// TODO this field should not be nullable, callsites should await the build config to be resolved
        /// and then continue instead of dealing with missing information.
        config: ?std.json.Parsed(BuildConfig) = null,
    } = .{},

    const BuildRunnerState = enum {
        idle,
        running,
        running_but_already_invalidated,
    };

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
    /// const package_uris: std.ArrayList([]const u8) = .empty;
    /// defer {
    ///     for (package_uris) |uri| allocator.free(uri);
    ///     package_uris.deinit(allocator);
    /// }
    /// const success = try build_file.collectBuildConfigPackageUris(allocator, &package_uris);
    /// ```
    pub fn collectBuildConfigPackageUris(
        self: *BuildFile,
        allocator: std.mem.Allocator,
        package_uris: *std.ArrayList(Uri),
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
    /// const include_paths: std.ArrayList([]u8) = .empty;
    /// defer {
    ///     for (include_paths) |path| allocator.free(path);
    ///     include_paths.deinit(allocator);
    /// }
    /// const success = try build_file.collectBuildConfigIncludePaths(allocator, &include_paths);
    /// ```
    pub fn collectBuildConfigIncludePaths(
        self: *BuildFile,
        allocator: std.mem.Allocator,
        include_paths: *std.ArrayList([]const u8),
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
                const build_file_path = try URI.toFsPath(allocator, build_file_dir);
                defer allocator.free(build_file_path);
                break :blk try std.fs.path.join(allocator, &.{ build_file_path, include_path });
            };

            include_paths.appendAssumeCapacity(absolute_path);
        }
        return true;
    }

    fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        if (self.impl.config) |cfg| cfg.deinit();
        if (self.builtin_uri) |builtin_uri| allocator.free(builtin_uri);
        if (self.build_associated_config) |cfg| cfg.deinit();
    }
};

/// Represents a Zig source file.
pub const Handle = struct {
    uri: Uri,
    tree: Ast,
    /// Contains one entry for every cimport in the document
    cimports: std.MultiArrayList(CImportHandle),

    /// private field
    impl: struct {
        /// @bitCast from/to `Status`
        status: std.atomic.Value(u32),
        /// TODO can we avoid storing one allocator per Handle?
        allocator: std.mem.Allocator,

        lock: std.Thread.Mutex = .{},
        /// See `getLazy`
        lazy_condition: std.Thread.Condition = .{},

        import_uris: ?[]Uri = null,
        document_scope: DocumentScope = undefined,
        zzoiir: ZirOrZoir = undefined,

        associated_build_file: union(enum) {
            /// The initial state. The associated build file (build.zig) is resolved lazily.
            init,
            /// The associated build file (build.zig) has been requested but has not yet been resolved.
            unresolved: struct {
                /// The build files are ordered in decreasing priority.
                potential_build_files: []const *BuildFile,
                /// to avoid checking build files multiple times, a bitset stores whether or
                /// not the build file should be skipped because it has previously been
                /// found to be "unassociated" with the handle.
                has_been_checked: std.DynamicBitSetUnmanaged,

                fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                    allocator.free(self.potential_build_files);
                    self.has_been_checked.deinit(allocator);
                    self.* = undefined;
                }
            },
            /// The Handle has no associated build file (build.zig).
            none,
            /// The associated build file (build.zig) has been successfully resolved.
            resolved: *BuildFile,
        } = .init,
    },

    const ZirOrZoir = union(Ast.Mode) {
        zig: std.zig.Zir,
        zon: std.zig.Zoir,
    };

    const Status = packed struct(u32) {
        /// `true` if the document has been directly opened by the client i.e. with `textDocument/didOpen`
        /// `false` indicates the document only exists because it is a dependency of another document
        /// or has been closed with `textDocument/didClose`.
        lsp_synced: bool = false,
        /// true if a thread has acquired the permission to compute the `DocumentScope`
        /// all other threads will wait until the given thread has computed the `DocumentScope` before reading it.
        has_document_scope_lock: bool = false,
        /// true if `handle.impl.document_scope` has been set
        has_document_scope: bool = false,
        /// true if a thread has acquired the permission to compute the `std.zig.Zir` or `std.zig.Zoir`
        has_zzoiir_lock: bool = false,
        /// all other threads will wait until the given thread has computed the `std.zig.Zir` or `std.zig.Zoir` before reading it.
        /// true if `handle.impl.zir` has been set
        has_zzoiir: bool = false,
        _: u27 = 0,
    };

    /// Takes ownership of `text` on success.
    pub fn init(
        allocator: std.mem.Allocator,
        uri: Uri,
        text: [:0]const u8,
        lsp_synced: bool,
    ) error{OutOfMemory}!Handle {
        const mode: Ast.Mode = if (std.mem.eql(u8, std.fs.path.extension(uri), ".zon")) .zon else .zig;

        var tree = try parseTree(allocator, text, mode);
        errdefer tree.deinit(allocator);

        var cimports = try collectCIncludes(allocator, tree);
        errdefer cimports.deinit(allocator);

        return .{
            .uri = uri,
            .tree = tree,
            .cimports = cimports,
            .impl = .{
                .status = .init(@bitCast(Status{
                    .lsp_synced = lsp_synced,
                })),
                .allocator = allocator,
            },
        };
    }

    /// Caller must free `Handle.uri` if needed.
    fn deinit(self: *Handle) void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const status = self.getStatus();

        const allocator = self.impl.allocator;

        if (status.has_zzoiir) switch (self.tree.mode) {
            .zig => self.impl.zzoiir.zig.deinit(allocator),
            .zon => self.impl.zzoiir.zon.deinit(allocator),
        };
        if (status.has_document_scope) self.impl.document_scope.deinit(allocator);
        allocator.free(self.tree.source);
        self.tree.deinit(allocator);

        if (self.impl.import_uris) |import_uris| {
            for (import_uris) |uri| allocator.free(uri);
            allocator.free(import_uris);
        }

        for (self.cimports.items(.source)) |source| allocator.free(source);
        self.cimports.deinit(allocator);

        switch (self.impl.associated_build_file) {
            .init, .none, .resolved => {},
            .unresolved => |*payload| payload.deinit(allocator),
        }

        self.* = undefined;
    }

    pub fn getImportUris(self: *Handle) error{OutOfMemory}![]const Uri {
        self.impl.lock.lock();
        defer self.impl.lock.unlock();

        const allocator = self.impl.allocator;

        if (self.impl.import_uris) |import_uris| return import_uris;

        var imports = try analysis.collectImports(allocator, self.tree);

        var i: usize = 0;
        errdefer {
            // only free the uris
            for (imports.items[0..i]) |uri| allocator.free(uri);
            imports.deinit(allocator);
        }

        // Convert to URIs
        while (i < imports.items.len) {
            const import_str = imports.items[i];
            if (!std.mem.endsWith(u8, import_str, ".zig")) {
                _ = imports.swapRemove(i);
                continue;
            }
            // The raw import strings are owned by the document and do not need to be freed here.
            imports.items[i] = try uriFromFileImportStr(allocator, self, import_str) orelse {
                _ = imports.swapRemove(i);
                continue;
            };
            i += 1;
        }

        self.impl.import_uris = try imports.toOwnedSlice(allocator);
        return self.impl.import_uris.?;
    }

    pub fn getDocumentScope(self: *Handle) error{OutOfMemory}!DocumentScope {
        if (self.getStatus().has_document_scope) return self.impl.document_scope;
        return try self.getLazy(DocumentScope, "document_scope", struct {
            fn create(handle: *Handle, allocator: std.mem.Allocator) error{OutOfMemory}!DocumentScope {
                var document_scope: DocumentScope = try .init(allocator, handle.tree);
                errdefer document_scope.deinit(allocator);

                // remove unused capacity
                document_scope.extra.shrinkAndFree(allocator, document_scope.extra.items.len);
                try document_scope.declarations.setCapacity(allocator, document_scope.declarations.len);
                try document_scope.scopes.setCapacity(allocator, document_scope.scopes.len);

                return document_scope;
            }
        });
    }

    /// Asserts that `getDocumentScope` has been previously called on `handle`.
    pub fn getDocumentScopeCached(self: *Handle) DocumentScope {
        if (builtin.mode == .Debug) {
            std.debug.assert(self.getStatus().has_document_scope);
        }
        return self.impl.document_scope;
    }

    pub fn getZir(self: *Handle) error{OutOfMemory}!std.zig.Zir {
        std.debug.assert(self.tree.mode == .zig);
        const zir_or_zoir = try self.getZirOrZoir();
        return zir_or_zoir.zig;
    }

    pub fn getZoir(self: *Handle) error{OutOfMemory}!std.zig.Zoir {
        std.debug.assert(self.tree.mode == .zon);
        const zir_or_zoir = try self.getZirOrZoir();
        return zir_or_zoir.zon;
    }

    fn getZirOrZoir(self: *Handle) error{OutOfMemory}!ZirOrZoir {
        if (self.getStatus().has_zzoiir) return self.impl.zzoiir;
        return try self.getLazy(ZirOrZoir, "zzoiir", struct {
            fn create(handle: *Handle, allocator: std.mem.Allocator) error{OutOfMemory}!ZirOrZoir {
                switch (handle.tree.mode) {
                    .zig => {
                        const tracy_zone = tracy.traceNamed(@src(), "AstGen.generate");
                        defer tracy_zone.end();

                        var zir = try std.zig.AstGen.generate(allocator, handle.tree);
                        errdefer zir.deinit(allocator);

                        // remove unused capacity
                        var instructions = zir.instructions.toMultiArrayList();
                        try instructions.setCapacity(allocator, instructions.len);
                        zir.instructions = instructions.slice();

                        return .{ .zig = zir };
                    },
                    .zon => {
                        const tracy_zone = tracy.traceNamed(@src(), "ZonGen.generate");
                        defer tracy_zone.end();

                        const zoir = try std.zig.ZonGen.generate(allocator, handle.tree, .{});

                        return .{ .zon = zoir };
                    },
                }
            }
        });
    }

    /// Returns the associated build file (build.zig) of the handle.
    ///
    /// `DocumentStore.build_files` is guaranteed to contain this Uri.
    /// Uri memory managed by its build_file
    pub fn getAssociatedBuildFileUri(self: *Handle, document_store: *DocumentStore) error{OutOfMemory}!?Uri {
        comptime std.debug.assert(supports_build_system);
        switch (try self.getAssociatedBuildFileUri2(document_store)) {
            .none,
            .unresolved,
            => return null,
            .resolved => |build_file| return build_file.uri,
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
        resolved: *BuildFile,
    } {
        comptime std.debug.assert(supports_build_system);

        self.impl.lock.lock();
        defer self.impl.lock.unlock();

        const unresolved = switch (self.impl.associated_build_file) {
            .init => blk: {
                const potential_build_files = document_store.collectPotentialBuildFiles(self.uri) catch {
                    log.err("failed to collect potential build files of '{s}'", .{self.uri});
                    self.impl.associated_build_file = .none;
                    return .none;
                };
                errdefer document_store.allocator.free(potential_build_files);

                if (potential_build_files.len == 0) {
                    self.impl.associated_build_file = .none;
                    return .none;
                }

                var has_been_checked: std.DynamicBitSetUnmanaged = try .initEmpty(document_store.allocator, potential_build_files.len);
                errdefer has_been_checked.deinit(document_store.allocator);

                self.impl.associated_build_file = .{ .unresolved = .{
                    .has_been_checked = has_been_checked,
                    .potential_build_files = potential_build_files,
                } };

                break :blk &self.impl.associated_build_file.unresolved;
            },
            .unresolved => |*unresolved| unresolved,
            .none => return .none,
            .resolved => |build_file| return .{ .resolved = build_file },
        };

        // special case when there is only one potential build file
        if (unresolved.potential_build_files.len == 1) {
            const build_file = unresolved.potential_build_files[0];
            log.debug("Resolved build file of '{s}' as '{s}'", .{ self.uri, build_file.uri });
            unresolved.deinit(document_store.allocator);
            self.impl.associated_build_file = .{ .resolved = build_file };
            return .{ .resolved = build_file };
        }

        var has_missing_build_config = false;

        var it = unresolved.has_been_checked.iterator(.{
            .kind = .unset,
            .direction = .reverse,
        });
        while (it.next()) |i| {
            const build_file = unresolved.potential_build_files[i];
            const is_associated = try document_store.uriAssociatedWithBuild(build_file, self.uri) orelse {
                has_missing_build_config = true;
                continue;
            };

            if (!is_associated) {
                // the build file should be skipped in future calls.
                unresolved.has_been_checked.set(i);
                continue;
            }

            log.debug("Resolved build file of '{s}' as '{s}'", .{ self.uri, build_file.uri });
            unresolved.deinit(document_store.allocator);
            self.impl.associated_build_file = .{ .resolved = build_file };
            return .{ .resolved = build_file };
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

    fn getLazy(
        self: *Handle,
        comptime T: type,
        comptime name: []const u8,
        comptime Context: type,
    ) error{OutOfMemory}!T {
        @branchHint(.cold);
        const tracy_zone = tracy.traceNamed(@src(), "getLazy(" ++ name ++ ")");
        defer tracy_zone.end();

        const has_data_field_name = "has_" ++ name;
        const has_lock_field_name = "has_" ++ name ++ "_lock";

        self.impl.lock.lock();
        defer self.impl.lock.unlock();
        while (true) {
            const status = self.getStatus();
            if (@field(status, has_data_field_name)) break;
            if (@field(status, has_lock_field_name) or
                self.impl.status.bitSet(@bitOffsetOf(Status, has_lock_field_name), .release) != 0)
            {
                // another thread is currently computing the data
                self.impl.lazy_condition.wait(&self.impl.lock);
                continue;
            }
            defer self.impl.lazy_condition.broadcast();

            @field(self.impl, name) = try Context.create(self, self.impl.allocator);
            errdefer comptime unreachable;

            const old_has_data = self.impl.status.bitSet(@bitOffsetOf(Status, has_data_field_name), .release);
            std.debug.assert(old_has_data == 0); // race condition
        }
        return @field(self.impl, name);
    }

    fn getStatus(self: *const Handle) Status {
        return @bitCast(self.impl.status.load(.acquire));
    }

    pub fn isLspSynced(self: *const Handle) bool {
        return self.getStatus().lsp_synced;
    }

    /// returns the previous value
    fn setLspSynced(self: *Handle, lsp_synced: bool) bool {
        if (lsp_synced) {
            return self.impl.status.bitSet(@offsetOf(Handle.Status, "lsp_synced"), .release) == 1;
        } else {
            return self.impl.status.bitReset(@offsetOf(Handle.Status, "lsp_synced"), .release) == 1;
        }
    }

    fn parseTree(allocator: std.mem.Allocator, new_text: [:0]const u8, mode: Ast.Mode) error{OutOfMemory}!Ast {
        const tracy_zone_inner = tracy.traceNamed(@src(), "Ast.parse");
        defer tracy_zone_inner.end();

        var tree = try Ast.parse(allocator, new_text, mode);
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
};

pub const ErrorMessage = struct {
    loc: offsets.Loc,
    code: []const u8,
    message: []const u8,
};

pub fn deinit(self: *DocumentStore) void {
    for (self.handles.keys(), self.handles.values()) |uri, handle| {
        handle.deinit();
        self.allocator.destroy(handle);
        self.allocator.free(uri);
    }
    self.handles.deinit(self.allocator);

    if (supports_build_system) {
        for (self.build_files.values()) |build_file| {
            build_file.deinit(self.allocator);
            self.allocator.destroy(build_file);
        }
        self.build_files.deinit(self.allocator);

        for (self.cimports.values()) |*result| {
            result.deinit(self.allocator);
        }
        self.cimports.deinit(self.allocator);
    }

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

fn readFile(self: *DocumentStore, uri: Uri) ?[:0]u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_path = URI.toFsPath(self.allocator, uri) catch |err| {
        log.err("failed to parse URI '{s}': {}", .{ uri, err });
        return null;
    };
    defer self.allocator.free(file_path);

    if (!std.fs.path.isAbsolute(file_path)) {
        log.err("file path is not absolute '{s}'", .{file_path});
        return null;
    }

    const dir, const sub_path = blk: {
        if (builtin.target.cpu.arch.isWasm() and !builtin.link_libc) {
            // look up whether the file path refers to a preopen directory.
            for ([_]?std.Build.Cache.Directory{
                self.config.zig_lib_dir,
                self.config.global_cache_dir,
            }) |opt_preopen_dir| {
                const preopen_dir = opt_preopen_dir orelse continue;
                const preopen_path = preopen_dir.path.?;
                std.debug.assert(std.mem.eql(u8, preopen_path, "/lib") or std.mem.eql(u8, preopen_path, "/cache"));

                if (!std.mem.startsWith(u8, file_path, preopen_path)) continue;
                if (!std.mem.startsWith(u8, file_path[preopen_path.len..], "/")) continue;

                break :blk .{ preopen_dir.handle, file_path[preopen_path.len + 1 ..] };
            }
        }
        break :blk .{ std.fs.cwd(), file_path };
    };

    return dir.readFileAllocOptions(
        sub_path,
        self.allocator,
        .limited(max_document_size),
        .of(u8),
        0,
    ) catch |err| {
        log.err("failed to read document '{s}': {}", .{ file_path, err });
        return null;
    };
}

/// Returns a handle to the given document
/// Will load the document from disk if it hasn't been already
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the Handle
pub fn getOrLoadHandle(self: *DocumentStore, uri: Uri) ?*Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.getHandle(uri)) |handle| return handle;
    const file_contents = self.readFile(uri) orelse return null;
    return self.createAndStoreDocument(uri, file_contents, false) catch |err| {
        log.err("failed to store document '{s}': {}", .{ uri, err });
        return null;
    };
}

/// **Thread safe** takes a shared lock
/// This function does not protect against data races from modifying the BuildFile
pub fn getBuildFile(self: *DocumentStore, uri: Uri) ?*BuildFile {
    comptime std.debug.assert(supports_build_system);
    self.lock.lockShared();
    defer self.lock.unlockShared();
    return self.build_files.get(uri);
}

/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the BuildFile
fn getOrLoadBuildFile(self: *DocumentStore, uri: Uri) ?*BuildFile {
    comptime std.debug.assert(supports_build_system);

    if (self.getBuildFile(uri)) |build_file| return build_file;

    const new_build_file: *BuildFile = blk: {
        self.lock.lock();
        defer self.lock.unlock();

        const gop = self.build_files.getOrPut(self.allocator, uri) catch return null;
        if (gop.found_existing) return gop.value_ptr.*;

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
        break :blk gop.value_ptr.*;
    };

    // this code path is only reached when the build file is new

    self.invalidateBuildFile(new_build_file.uri);

    return new_build_file;
}

/// Opens a document that is synced over the LSP protocol (`textDocument/didOpen`).
/// **Not thread safe**
pub fn openLspSyncedDocument(self: *DocumentStore, uri: Uri, text: []const u8) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |handle| {
        if (handle.isLspSynced()) {
            log.warn("Document already open: {s}", .{uri});
        }
    }

    const duped_text = try self.allocator.dupeZ(u8, text);
    _ = try self.createAndStoreDocument(uri, duped_text, true);
}

/// Closes a document that has been synced over the LSP protocol (`textDocument/didClose`).
/// **Not thread safe**
pub fn closeLspSyncedDocument(self: *DocumentStore, uri: Uri) void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const kv = self.handles.fetchSwapRemove(uri) orelse {
        log.warn("Document not found: {s}", .{uri});
        return;
    };
    if (!kv.value.isLspSynced()) {
        log.warn("Document already closed: {s}", .{uri});
    }

    self.allocator.free(kv.key);
    kv.value.deinit();
    self.allocator.destroy(kv.value);
}

/// Updates a document that is synced over the LSP protocol (`textDocument/didChange`).
/// Takes ownership of `new_text` which has to be allocated with this DocumentStore's allocator.
/// **Not thread safe**
pub fn refreshLspSyncedDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |old_handle| {
        if (!old_handle.isLspSynced()) {
            log.warn("Document modified without being opened: {s}", .{uri});
        }
    } else {
        log.warn("Document modified without being opened: {s}", .{uri});
    }

    _ = try self.createAndStoreDocument(uri, new_text, true);
}

/// Refreshes a document from the file system, unless said document is synced over the LSP protocol.
/// **Not thread safe**
pub fn refreshDocumentFromFileSystem(self: *DocumentStore, uri: Uri, should_delete: bool) !bool {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (should_delete) {
        const index = self.handles.getIndex(uri) orelse return false;
        const handle = self.handles.values()[index];
        if (handle.isLspSynced()) return false;

        self.handles.swapRemoveAt(index);
        const handle_uri = handle.uri;
        handle.deinit();
        self.allocator.destroy(handle);
        self.allocator.free(handle_uri);
    } else {
        if (self.handles.get(uri)) |handle| {
            if (handle.isLspSynced()) return false;
        }
        const file_contents = self.readFile(uri) orelse return false;
        _ = try self.createAndStoreDocument(uri, file_contents, false);
    }

    return true;
}

/// Invalidates a build files.
/// **Thread safe** takes a shared lock
pub fn invalidateBuildFile(self: *DocumentStore, build_file_uri: Uri) void {
    comptime std.debug.assert(supports_build_system);

    if (self.config.zig_exe_path == null) return;
    if (self.config.build_runner_path == null) return;
    if (self.config.global_cache_dir == null) return;
    if (self.config.zig_lib_dir == null) return;

    const build_file = self.getBuildFile(build_file_uri) orelse return;

    self.thread_pool.spawn(invalidateBuildFileWorker, .{ self, build_file }) catch {
        self.invalidateBuildFileWorker(build_file);
        return;
    };
}

const progress_token = "buildProgressToken";

fn sendMessageToClient(allocator: std.mem.Allocator, transport: *lsp.Transport, message: anytype) !void {
    const serialized = try std.json.Stringify.valueAlloc(
        allocator,
        message,
        .{ .emit_null_optional_fields = false },
    );
    defer allocator.free(serialized);

    try transport.writeJsonMessage(serialized);
}

fn notifyBuildStart(self: *DocumentStore) void {
    if (!self.lsp_capabilities.supports_work_done_progress) return;

    const transport = self.transport orelse return;

    // Atomicity note: We do not actually care about memory surrounding the
    // counter, we only care about the counter itself. We only need to ensure
    // we aren't double entering/exiting
    const prev = self.builds_in_progress.fetchAdd(1, .monotonic);
    if (prev != 0) return;

    sendMessageToClient(
        self.allocator,
        transport,
        .{
            .jsonrpc = "2.0",
            .id = "progress",
            .method = "window/workDoneProgress/create",
            .params = lsp.types.WorkDoneProgressCreateParams{
                .token = .{ .string = progress_token },
            },
        },
    ) catch |err| {
        log.err("Failed to send create work message: {}", .{err});
        return;
    };

    sendMessageToClient(self.allocator, transport, .{
        .jsonrpc = "2.0",
        .method = "$/progress",
        .params = .{
            .token = progress_token,
            .value = lsp.types.WorkDoneProgressBegin{
                .title = "Loading build configuration",
            },
        },
    }) catch |err| {
        log.err("Failed to send progress start message: {}", .{err});
        return;
    };
}

const EndStatus = enum { success, failed };

fn notifyBuildEnd(self: *DocumentStore, status: EndStatus) void {
    if (!self.lsp_capabilities.supports_work_done_progress) return;

    const transport = self.transport orelse return;

    // Atomicity note: We do not actually care about memory surrounding the
    // counter, we only care about the counter itself. We only need to ensure
    // we aren't double entering/exiting
    const prev = self.builds_in_progress.fetchSub(1, .monotonic);
    if (prev != 1) return;

    const message = switch (status) {
        .failed => "Failed",
        .success => "Success",
    };

    sendMessageToClient(self.allocator, transport, .{
        .jsonrpc = "2.0",
        .method = "$/progress",
        .params = .{
            .token = progress_token,
            .value = lsp.types.WorkDoneProgressEnd{
                .message = message,
            },
        },
    }) catch |err| {
        log.err("Failed to send progress end message: {}", .{err});
        return;
    };
}

fn invalidateBuildFileWorker(self: *DocumentStore, build_file: *BuildFile) void {
    {
        build_file.impl.mutex.lock();
        defer build_file.impl.mutex.unlock();

        switch (build_file.impl.build_runner_state) {
            .idle => build_file.impl.build_runner_state = .running,
            .running => {
                build_file.impl.build_runner_state = .running_but_already_invalidated;
                return;
            },
            .running_but_already_invalidated => return,
        }
    }

    self.notifyBuildStart();

    while (true) {
        build_file.impl.version += 1;
        const new_version = build_file.impl.version;

        const build_config = loadBuildConfiguration(self, build_file.uri, new_version) catch |err| {
            if (err != error.RunFailed) { // already logged
                log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri, err });
            }
            self.notifyBuildEnd(.failed);
            build_file.impl.mutex.lock();
            defer build_file.impl.mutex.unlock();
            build_file.impl.build_runner_state = .idle;
            return;
        };

        build_file.impl.mutex.lock();
        switch (build_file.impl.build_runner_state) {
            .idle => unreachable,
            .running => {
                var old_config = build_file.impl.config;
                build_file.impl.config = build_config;
                build_file.impl.build_runner_state = .idle;
                build_file.impl.mutex.unlock();

                if (old_config) |*config| config.deinit();
                self.notifyBuildEnd(.success);
                break;
            },
            .running_but_already_invalidated => {
                build_file.impl.build_runner_state = .running;
                build_file.impl.mutex.unlock();

                build_config.deinit();
                continue;
            },
        }
    }

    if (self.transport) |transport| {
        if (self.lsp_capabilities.supports_semantic_tokens_refresh) {
            sendMessageToClient(
                self.allocator,
                transport,
                lsp.TypedJsonRPCRequest(?void){
                    .id = .{ .string = "semantic_tokens_refresh" },
                    .method = "workspace/semanticTokens/refresh",
                    .params = @as(?void, null),
                },
            ) catch {};
        }
        if (self.lsp_capabilities.supports_inlay_hints_refresh) {
            sendMessageToClient(
                self.allocator,
                transport,
                lsp.TypedJsonRPCRequest(?void){
                    .id = .{ .string = "inlay_hints_refresh" },
                    .method = "workspace/inlayHint/refresh",
                    .params = @as(?void, null),
                },
            ) catch {};
        }
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

    const build_file_path = try URI.toFsPath(allocator, build_file.uri);
    defer allocator.free(build_file_path);
    const config_file_path = try std.fs.path.resolve(allocator, &.{ build_file_path, "..", "zls.build.json" });
    defer allocator.free(config_file_path);

    const file_buf = try std.fs.cwd().readFileAlloc(
        config_file_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
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
        self.config.zig_exe_path.?,
        "build",
        "--build-runner",
        self.config.build_runner_path.?,
        "--zig-lib-dir",
        self.config.zig_lib_dir.?.path orelse ".",
    };

    var args: std.ArrayList([]const u8) = try .initCapacity(self.allocator, base_args.len);
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
fn loadBuildConfiguration(self: *DocumentStore, build_file_uri: Uri, build_file_version: u32) !std.json.Parsed(BuildConfig) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    std.debug.assert(self.config.zig_exe_path != null);
    std.debug.assert(self.config.build_runner_path != null);
    std.debug.assert(self.config.global_cache_dir != null);
    std.debug.assert(self.config.zig_lib_dir != null);

    const build_file_path = try URI.toFsPath(self.allocator, build_file_uri);
    defer self.allocator.free(build_file_path);

    const cwd = std.fs.path.dirname(build_file_path).?;

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
            .cwd = cwd,
            .max_output_bytes = 16 * 1024 * 1024,
        });
    };
    defer self.allocator.free(zig_run_result.stdout);
    defer self.allocator.free(zig_run_result.stderr);

    const is_ok = switch (zig_run_result.term) {
        .Exited => |exit_code| exit_code == 0,
        else => false,
    };

    const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
        var hasher: std.hash.Wyhash = .init(47); // Chosen by the following prompt: Pwease give a wandom nyumbew
        hasher.update(build_file_uri);
        break :tag @enumFromInt(@as(u32, @truncate(hasher.final())));
    };

    if (!is_ok) {
        const joined = try std.mem.join(self.allocator, " ", args);
        defer self.allocator.free(joined);

        log.err(
            "Failed to execute build runner to collect build configuration, command:\ncd {s};{s}\nError: {s}",
            .{ cwd, joined, zig_run_result.stderr },
        );

        var error_bundle = try @import("features/diagnostics.zig").getErrorBundleFromStderr(
            self.allocator,
            zig_run_result.stderr,
            false,
            .{ .dynamic = .{ .document_store = self, .base_path = cwd } },
        );
        defer error_bundle.deinit(self.allocator);

        try self.diagnostics_collection.pushErrorBundle(diagnostic_tag, build_file_version, cwd, error_bundle);
        try self.diagnostics_collection.publishDiagnostics();
        return error.RunFailed;
    } else {
        try self.diagnostics_collection.pushErrorBundle(diagnostic_tag, build_file_version, null, .empty);
        try self.diagnostics_collection.publishDiagnostics();
    }

    const parse_options: std.json.ParseOptions = .{
        // We ignore unknown fields so people can roll
        // their own build runners in libraries with
        // the only requirement being general adherence
        // to the BuildConfig type
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    const build_config = std.json.parseFromSlice(
        BuildConfig,
        self.allocator,
        zig_run_result.stdout,
        parse_options,
    ) catch return error.InvalidBuildConfig;
    errdefer build_config.deinit();

    for (build_config.value.packages) |*pkg| {
        pkg.path = try std.fs.path.resolve(build_config.arena.allocator(), &.{ build_file_path, "..", pkg.path });
    }

    return build_config;
}

/// Checks if the build.zig file is accessible in dir.
fn buildDotZigExists(dir_path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return false;
    defer dir.close();
    dir.access("build.zig", .{}) catch return false;
    return true;
}

/// Walk down the tree towards the uri. When we hit `build.zig` files
/// add them to the list of potential build files.
/// `build.zig` files higher in the filesystem have precedence.
/// See `Handle.getAssociatedBuildFileUri`.
/// Caller owns returned memory.
fn collectPotentialBuildFiles(self: *DocumentStore, uri: Uri) ![]*BuildFile {
    if (isInStd(uri)) return &.{};

    var potential_build_files: std.ArrayList(*BuildFile) = .empty;
    errdefer potential_build_files.deinit(self.allocator);

    const path = try URI.toFsPath(self.allocator, uri);
    defer self.allocator.free(path);

    var current_path: []const u8 = path;
    while (std.fs.path.dirname(current_path)) |potential_root_path| : (current_path = potential_root_path) {
        if (!buildDotZigExists(potential_root_path)) continue;

        const build_path = try std.fs.path.join(self.allocator, &.{ potential_root_path, "build.zig" });
        defer self.allocator.free(build_path);

        try potential_build_files.ensureUnusedCapacity(self.allocator, 1);

        const build_file_uri = try URI.fromPath(self.allocator, build_path);
        defer self.allocator.free(build_file_uri);

        const build_file = self.getOrLoadBuildFile(build_file_uri) orelse continue;
        potential_build_files.appendAssumeCapacity(build_file);
    }
    // The potential build files that come first should have higher priority.
    //
    // `build.zig` files that are higher up in the filesystem are more likely
    // to be the `build.zig` of the entire project/package instead of just a
    // sub-project/package.
    std.mem.reverse(*BuildFile, potential_build_files.items);

    return try potential_build_files.toOwnedSlice(self.allocator);
}

fn createBuildFile(self: *DocumentStore, uri: Uri) error{OutOfMemory}!BuildFile {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var build_file: BuildFile = .{
        .uri = try self.allocator.dupe(u8, uri),
    };

    errdefer build_file.deinit(self.allocator);

    if (loadBuildAssociatedConfiguration(self.allocator, build_file)) |cfg| {
        build_file.build_associated_config = cfg;

        if (cfg.value.relative_builtin_path) |relative_builtin_path| blk: {
            const build_file_path = URI.toFsPath(self.allocator, build_file.uri) catch break :blk;
            const absolute_builtin_path = std.fs.path.resolve(self.allocator, &.{ build_file_path, "..", relative_builtin_path }) catch break :blk;
            defer self.allocator.free(absolute_builtin_path);
            build_file.builtin_uri = try URI.fromPath(self.allocator, absolute_builtin_path);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            log.debug("Failed to load config associated with build file {s} (error: {})", .{ build_file.uri, err });
        }
    }

    log.info("Loaded build file '{s}'", .{build_file.uri});

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

    var checked_uris: std.StringHashMapUnmanaged(void) = .empty;
    defer checked_uris.deinit(self.allocator);

    var package_uris: std.ArrayList(Uri) = .empty;
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

    for (try handle.getImportUris()) |import_uri| {
        if (try self.uriInImports(checked_uris, build_file_uri, import_uri, uri))
            return true;
    }

    return false;
}

/// takes ownership of the `text` passed in.
/// **Thread safe** takes an exclusive lock
fn createAndStoreDocument(
    self: *DocumentStore,
    uri: Uri,
    text: [:0]const u8,
    lsp_synced: bool,
) error{OutOfMemory}!*Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var new_handle = Handle.init(self.allocator, uri, text, lsp_synced) catch |err| {
        self.allocator.free(text);
        return err;
    };
    errdefer new_handle.deinit();

    if (supports_build_system and isBuildFile(uri) and !isInStd(uri)) {
        _ = self.getOrLoadBuildFile(uri);
    }

    self.lock.lock();
    defer self.lock.unlock();

    const gop = try self.handles.getOrPut(self.allocator, uri);
    errdefer if (!gop.found_existing) std.debug.assert(self.handles.swapRemove(uri));

    if (gop.found_existing) {
        if (lsp_synced) {
            new_handle.impl.associated_build_file = gop.value_ptr.*.impl.associated_build_file;
            gop.value_ptr.*.impl.associated_build_file = .init;

            new_handle.uri = gop.key_ptr.*;
            gop.value_ptr.*.deinit();
            gop.value_ptr.*.* = new_handle;
        } else {
            // TODO prevent concurrent `createAndStoreDocument` invocations from racing each other
            new_handle.deinit();
        }
    } else {
        gop.key_ptr.* = try self.allocator.dupe(u8, uri);
        errdefer self.allocator.free(gop.key_ptr.*);

        gop.value_ptr.* = try self.allocator.create(Handle);
        errdefer self.allocator.destroy(gop.value_ptr.*);

        new_handle.uri = gop.key_ptr.*;
        gop.value_ptr.*.* = new_handle;
    }

    return gop.value_ptr.*;
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

    var sources: std.MultiArrayList(CImportHandle) = .empty;
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
    dependencies: *std.ArrayList(Uri),
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const import_uris = try handle.getImportUris();

    try dependencies.ensureUnusedCapacity(allocator, import_uris.len + handle.cimports.len);
    for (import_uris) |uri| {
        dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri));
    }

    if (supports_build_system) {
        store.lock.lockShared();
        defer store.lock.unlockShared();
        for (handle.cimports.items(.hash)) |hash| {
            const result = store.cimports.get(hash) orelse continue;
            switch (result) {
                .success => |uri| dependencies.appendAssumeCapacity(try allocator.dupe(u8, uri)),
                .failure => continue,
            }
        }
    }

    if (supports_build_system) no_build_file: {
        const build_file_uri = try handle.getAssociatedBuildFileUri(store) orelse break :no_build_file;
        const build_file = store.getBuildFile(build_file_uri) orelse break :no_build_file;
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
    include_dirs: *std.ArrayList([]const u8),
) !bool {
    comptime std.debug.assert(supports_build_system);

    var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
    defer arena_allocator.deinit();

    const target_info: std.Target = .{
        .cpu = .{
            .arch = builtin.cpu.arch,
            .model = undefined,
            .features = undefined,
        },
        .os = builtin.target.os,
        .abi = .none,
        .ofmt = comptime std.Target.ObjectFormat.default(builtin.os.tag, builtin.cpu.arch),
        .dynamic_linker = std.Target.DynamicLinker.none,
    };
    const native_paths: std.zig.system.NativePaths = try .detect(arena_allocator.allocator(), &target_info);

    try include_dirs.ensureUnusedCapacity(allocator, native_paths.include_dirs.items.len);
    for (native_paths.include_dirs.items) |native_include_dir| {
        include_dirs.appendAssumeCapacity(try allocator.dupe(u8, native_include_dir));
    }

    const collected_all = switch (try handle.getAssociatedBuildFileUri2(store)) {
        .none => true,
        .unresolved => false,
        .resolved => |build_file| try build_file.collectBuildConfigIncludePaths(allocator, include_dirs),
    };

    return collected_all;
}

/// returns `true` if all c macro definitions could be collected
/// may return `false` because macros from a build.zig may not have been resolved already
/// **Thread safe** takes a shared lock
pub fn collectCMacros(
    store: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: *Handle,
    c_macros: *std.ArrayList([]const u8),
) !bool {
    comptime std.debug.assert(supports_build_system);

    const collected_all = switch (try handle.getAssociatedBuildFileUri2(store)) {
        .none => true,
        .unresolved => false,
        .resolved => |build_file| blk: {
            const build_config = build_file.tryLockConfig() orelse break :blk false;
            defer build_file.unlockConfig();

            try c_macros.ensureUnusedCapacity(allocator, build_config.c_macros.len);
            for (build_config.c_macros) |c_macro| {
                c_macros.appendAssumeCapacity(try allocator.dupe(u8, c_macro));
            }
            break :blk true;
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
    comptime std.debug.assert(supports_build_system);

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.config.zig_exe_path == null) return null;
    if (self.config.zig_lib_dir == null) return null;
    if (self.config.global_cache_dir == null) return null;

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

    var include_dirs: std.ArrayList([]const u8) = .empty;
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

    var c_macros: std.ArrayList([]const u8) = .empty;
    defer {
        for (c_macros.items) |c_macro| {
            self.allocator.free(c_macro);
        }
        c_macros.deinit(self.allocator);
    }

    const collected_all_c_macros = self.collectCMacros(self.allocator, handle, &c_macros) catch |err| {
        log.err("failed to resolve include paths: {}", .{err});
        return null;
    };

    const maybe_result = translate_c.translate(
        self.allocator,
        self.config,
        include_dirs.items,
        c_macros.items,
        source,
    ) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => |e| {
            log.err("failed to translate cimport: {}", .{e});
            return null;
        },
    };
    var result = maybe_result orelse return null;

    if (result == .failure and (!collected_all_include_dirs or !collected_all_c_macros)) {
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

    self.publishCimportDiagnostics(handle) catch |err| {
        log.err("failed to publish cImport diagnostics: {}", .{err});
    };

    switch (result) {
        .success => |uri| {
            log.debug("Translated cImport into {s}", .{uri});
            return uri;
        },
        .failure => return null,
    }
}

fn publishCimportDiagnostics(self: *DocumentStore, handle: *Handle) !void {
    var wip: std.zig.ErrorBundle.Wip = undefined;
    try wip.init(self.allocator);
    defer wip.deinit();

    const src_path = try wip.addString("");

    for (handle.cimports.items(.hash), handle.cimports.items(.node)) |hash, node| {
        const result = blk: {
            self.lock.lock();
            defer self.lock.unlock();
            break :blk self.cimports.get(hash) orelse continue;
        };
        const error_bundle: std.zig.ErrorBundle = switch (result) {
            .success => continue,
            .failure => |bundle| bundle,
        };

        if (error_bundle.errorMessageCount() == 0) continue;

        const loc = offsets.nodeToLoc(handle.tree, node);
        const source_loc = std.zig.findLineColumn(handle.tree.source, loc.start);

        comptime std.debug.assert(max_document_size <= std.math.maxInt(u32));

        const src_loc = try wip.addSourceLocation(.{
            .src_path = src_path,
            .line = @intCast(source_loc.line),
            .column = @intCast(source_loc.column),
            .span_start = @intCast(loc.start),
            .span_main = @intCast(loc.start),
            .span_end = @intCast(loc.end),
            .source_line = try wip.addString(source_loc.source_line),
        });

        for (error_bundle.getMessages()) |err_msg_index| {
            const err_msg = error_bundle.getErrorMessage(err_msg_index);
            const msg = error_bundle.nullTerminatedString(err_msg.msg);

            try wip.addRootErrorMessage(.{
                .msg = try wip.addString(msg),
                .src_loc = src_loc,
            });
        }
    }

    {
        var error_bundle = try wip.toOwnedBundle("");
        errdefer error_bundle.deinit(self.allocator);

        try self.diagnostics_collection.pushSingleDocumentDiagnostics(
            .cimport,
            handle.uri,
            .{ .error_bundle = error_bundle },
        );
    }
    try self.diagnostics_collection.publishDiagnostics();
}

/// takes the string inside a @import() node (without the quotation marks)
/// and returns it's uri
/// caller owns the returned memory
/// **Thread safe** takes a shared lock
pub fn uriFromImportStr(self: *DocumentStore, allocator: std.mem.Allocator, handle: *Handle, import_str: []const u8) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (std.mem.eql(u8, import_str, "std")) {
        const zig_lib_dir = self.config.zig_lib_dir orelse return null;

        const std_path = try zig_lib_dir.join(allocator, &.{ "std", "std.zig" });
        defer allocator.free(std_path);

        return try URI.fromPath(allocator, std_path);
    } else if (std.mem.eql(u8, import_str, "builtin")) {
        if (supports_build_system) {
            if (try handle.getAssociatedBuildFileUri(self)) |build_file_uri| {
                const build_file = self.getBuildFile(build_file_uri).?;
                if (build_file.builtin_uri) |builtin_uri| {
                    return try allocator.dupe(u8, builtin_uri);
                }
            }
        }
        if (self.config.builtin_path) |builtin_path| {
            return try URI.fromPath(allocator, builtin_path);
        }
        return null;
    } else if (!std.mem.endsWith(u8, import_str, ".zig")) {
        if (!supports_build_system) return null;

        if (isBuildFile(handle.uri)) blk: {
            const build_file = self.getBuildFile(handle.uri) orelse break :blk;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            for (build_config.deps_build_roots) |dep_build_root| {
                if (std.mem.eql(u8, import_str, dep_build_root.name)) {
                    return try URI.fromPath(allocator, dep_build_root.path);
                }
            }
        } else if (try handle.getAssociatedBuildFileUri(self)) |build_file_uri| blk: {
            const build_file = self.getBuildFile(build_file_uri).?;
            const build_config = build_file.tryLockConfig() orelse break :blk;
            defer build_file.unlockConfig();

            for (build_config.packages) |pkg| {
                if (std.mem.eql(u8, import_str, pkg.name)) {
                    return try URI.fromPath(allocator, pkg.path);
                }
            }
        }
        return null;
    } else {
        return try uriFromFileImportStr(allocator, handle, import_str);
    }
}

fn uriFromFileImportStr(allocator: std.mem.Allocator, handle: *Handle, import_str: []const u8) error{OutOfMemory}!?Uri {
    const base_path = URI.toFsPath(allocator, handle.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer allocator.free(base_path);

    const joined_path = std.fs.path.resolve(allocator, &.{ base_path, "..", import_str }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer allocator.free(joined_path);

    return try URI.fromPath(allocator, joined_path);
}
