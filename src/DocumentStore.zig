//! A thread-safe container for all document related state like zig source files including `build.zig`.

const std = @import("std");
const builtin = @import("builtin");
const Uri = @import("Uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.store);
const lsp = @import("lsp");
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
pub const BuildConfig = @import("build_runner/shared.zig").BuildConfig;
const tracy = @import("tracy");
const translate_c = @import("translate_c.zig");
const DocumentScope = @import("DocumentScope.zig");
const DiagnosticsCollection = @import("DiagnosticsCollection.zig");

const DocumentStore = @This();

io: std.Io,
allocator: std.mem.Allocator,
/// the DocumentStore assumes that `config` is not modified while calling one of its functions.
config: Config,
mutex: std.Io.Mutex = .init,
wait_group: if (supports_build_system) std.Io.Group else void = if (supports_build_system) .init else {},
handles: Uri.ArrayHashMap(*Handle) = .empty,
build_files: if (supports_build_system) Uri.ArrayHashMap(*BuildFile) else void = if (supports_build_system) .empty else {},
cimports: if (supports_build_system) std.AutoArrayHashMapUnmanaged(Hash, translate_c.Result) else void = if (supports_build_system) .empty else {},
diagnostics_collection: *DiagnosticsCollection,
builds_in_progress: std.atomic.Value(i32) = .init(0),
transport: ?*lsp.Transport = null,
lsp_capabilities: struct {
    supports_work_done_progress: bool = false,
    supports_semantic_tokens_refresh: bool = false,
    supports_inlay_hints_refresh: bool = false,
} = .{},

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
    environ_map: *const std.process.Environ.Map,
    zig_exe_path: ?[]const u8,
    zig_lib_dir: ?std.Build.Cache.Directory,
    build_runner_path: ?[]const u8,
    builtin_path: ?[]const u8,
    global_cache_dir: ?std.Build.Cache.Directory,
    wasi_preopens: switch (builtin.os.tag) {
        .wasi => std.process.Preopens,
        else => void,
    },
};

/// Represents a `build.zig`
pub const BuildFile = struct {
    uri: Uri,
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    /// config options extracted from zls.build.json
    build_associated_config: ?std.json.Parsed(BuildAssociatedConfig) = null,
    impl: struct {
        mutex: std.Io.Mutex = .init,
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

    pub fn tryLockConfig(self: *BuildFile, io: std.Io) ?BuildConfig {
        self.impl.mutex.lockUncancelable(io);
        return if (self.impl.config) |cfg| cfg.value else {
            self.impl.mutex.unlock(io);
            return null;
        };
    }

    pub fn unlockConfig(self: *BuildFile, io: std.Io) void {
        self.impl.mutex.unlock(io);
    }

    /// Returns whether the `Uri` is a dependency of the given `BuildFile`.
    /// May return `null` to indicate an inconclusive result because
    /// the required build config has not been resolved yet.
    ///
    /// invalidates any pointers into `build_files`
    /// **Thread safe** takes an exclusive lock
    fn isAssociatedWith(
        build_file: *BuildFile,
        uri: Uri,
        store: *DocumentStore,
    ) error{ Canceled, OutOfMemory }!union(enum) {
        unknown,
        no,
        /// Stores the `root_source_file`. Caller owns returned memory.
        yes: []const u8,
    } {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const allocator = store.allocator;
        const io = store.io;

        var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
        defer arena_allocator.deinit();

        const arena = arena_allocator.allocator();

        var module_root_source_file_paths: std.ArrayList([]const u8) = .empty;

        {
            const build_config = build_file.tryLockConfig(io) orelse return .unknown;
            defer build_file.unlockConfig(io);

            const module_paths = build_config.modules.map.keys();

            try module_root_source_file_paths.ensureUnusedCapacity(arena, module_paths.len);
            for (module_paths) |module_path| {
                module_root_source_file_paths.appendAssumeCapacity(try arena.dupe(u8, module_path));
            }
        }

        var found_uris: Uri.ArrayHashMap(void) = .empty;

        var i: usize = 0;

        for (module_root_source_file_paths.items) |root_source_file| {
            try found_uris.put(arena, try .fromPath(arena, root_source_file), {});

            while (i < found_uris.count()) : (i += 1) {
                const source_uri = found_uris.keys()[i];
                if (uri.eql(source_uri)) {
                    return .{ .yes = try allocator.dupe(u8, root_source_file) };
                }
                if (isInStd(source_uri)) continue;

                const handle = try store.getOrLoadHandle(source_uri) orelse return .unknown;

                const import_uris = try handle.getImportUris();
                try found_uris.ensureUnusedCapacity(arena, import_uris.len);
                for (import_uris) |import_uri| found_uris.putAssumeCapacity(try import_uri.dupe(arena), {});
            }
        }

        return .no;
    }

    fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        self.uri.deinit(allocator);
        if (self.impl.config) |cfg| cfg.deinit();
        if (self.builtin_uri) |builtin_uri| builtin_uri.deinit(allocator);
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
        store: *DocumentStore,

        lock: std.Io.Mutex = .init,
        /// See `getLazy`
        lazy_condition: std.Io.Condition = .init,

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
            },
            /// The Handle has no associated build file (build.zig).
            none,
            /// The associated build file (build.zig) has been successfully resolved.
            resolved: GetAssociatedBuildFileResult.Resolved,

            fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .init, .none => {},
                    .unresolved => |*unresolved| {
                        allocator.free(unresolved.potential_build_files);
                        unresolved.has_been_checked.deinit(allocator);
                    },
                    .resolved => |resolved| {
                        allocator.free(resolved.root_source_file);
                    },
                }
                self.* = undefined;
            }
        } = .init,

        associated_compilation_units: GetAssociatedCompilationUnitsResult = .unresolved,
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
        store: *DocumentStore,
        uri: Uri,
        text: [:0]const u8,
        lsp_synced: bool,
    ) error{OutOfMemory}!Handle {
        const allocator = store.allocator;
        const mode: Ast.Mode = if (std.mem.eql(u8, std.fs.path.extension(uri.raw), ".zon")) .zon else .zig;

        var tree = try parseTree(allocator, text, mode);
        errdefer tree.deinit(allocator);

        var cimports = try collectCIncludes(allocator, &tree);
        errdefer cimports.deinit(allocator);

        return .{
            .uri = uri,
            .tree = tree,
            .cimports = cimports,
            .impl = .{
                .status = .init(@bitCast(Status{
                    .lsp_synced = lsp_synced,
                })),
                .store = store,
            },
        };
    }

    /// Caller must free `Handle.uri` if needed.
    fn deinit(self: *Handle) void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const status = self.getStatus();

        const allocator = self.impl.store.allocator;

        if (status.has_zzoiir) switch (self.tree.mode) {
            .zig => self.impl.zzoiir.zig.deinit(allocator),
            .zon => self.impl.zzoiir.zon.deinit(allocator),
        };
        if (status.has_document_scope) self.impl.document_scope.deinit(allocator);
        allocator.free(self.tree.source);
        self.tree.deinit(allocator);

        if (self.impl.import_uris) |import_uris| {
            for (import_uris) |uri| uri.deinit(allocator);
            allocator.free(import_uris);
        }

        for (self.cimports.items(.source)) |source| allocator.free(source);
        self.cimports.deinit(allocator);

        self.impl.associated_build_file.deinit(allocator);
        self.impl.associated_compilation_units.deinit(allocator);

        self.* = undefined;
    }

    pub fn getImportUris(self: *Handle) error{OutOfMemory}![]const Uri {
        const store = self.impl.store;
        const allocator = store.allocator;
        const io = store.io;

        self.impl.lock.lockUncancelable(io);
        defer self.impl.lock.unlock(io);

        if (self.impl.import_uris) |import_uris| return import_uris;

        var imports = try analysis.collectImports(allocator, &self.tree);
        defer imports.deinit(allocator);

        const base_path = self.uri.toFsPath(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedScheme => {
                self.impl.import_uris = &.{};
                return self.impl.import_uris.?;
            },
        };
        defer allocator.free(base_path);

        var uris: std.ArrayList(Uri) = try .initCapacity(allocator, imports.items.len);
        errdefer {
            for (uris.items) |uri| uri.deinit(allocator);
            uris.deinit(allocator);
        }

        for (imports.items) |import_str| {
            if (!std.mem.endsWith(u8, import_str, ".zig")) continue;
            uris.appendAssumeCapacity(try resolveFileImportString(allocator, base_path, import_str) orelse continue);
        }

        self.impl.import_uris = try uris.toOwnedSlice(allocator);
        return self.impl.import_uris.?;
    }

    pub fn getDocumentScope(self: *Handle) error{OutOfMemory}!DocumentScope {
        if (self.getStatus().has_document_scope) return self.impl.document_scope;
        return try self.getLazy(DocumentScope, "document_scope", struct {
            fn create(handle: *Handle, allocator: std.mem.Allocator) error{OutOfMemory}!DocumentScope {
                var document_scope: DocumentScope = try .init(allocator, &handle.tree);
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

    pub const GetAssociatedBuildFileResult = union(enum) {
        /// The Handle has no associated build file (build.zig).
        none,
        /// The associated build file (build.zig) has not been resolved yet.
        unresolved,
        /// The associated build file (build.zig) has been successfully resolved.
        resolved: Resolved,

        pub const Resolved = struct {
            build_file: *BuildFile,
            root_source_file: []const u8,
        };
    };

    /// Returns the associated build file (build.zig) of the handle.
    ///
    /// `DocumentStore.build_files` is guaranteed to contain this Uri.
    /// Uri memory managed by its build_file
    pub fn getAssociatedBuildFile(self: *Handle, document_store: *DocumentStore) error{ Canceled, OutOfMemory }!GetAssociatedBuildFileResult {
        comptime std.debug.assert(supports_build_system);

        try self.impl.lock.lock(document_store.io);
        defer self.impl.lock.unlock(document_store.io);

        const unresolved = switch (self.impl.associated_build_file) {
            .init => blk: {
                const potential_build_files = try document_store.collectPotentialBuildFiles(self.uri);
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
            .resolved => |resolved| return .{ .resolved = resolved },
        };

        var has_missing_build_config = false;

        var it = unresolved.has_been_checked.iterator(.{
            .kind = .unset,
            .direction = .reverse,
        });
        while (it.next()) |i| {
            const build_file = unresolved.potential_build_files[i];
            switch (try build_file.isAssociatedWith(self.uri, document_store)) {
                .unknown => {
                    has_missing_build_config = true;
                    continue;
                },
                .no => {
                    // the build file should be skipped in future calls.
                    unresolved.has_been_checked.set(i);
                    continue;
                },
                .yes => |root_source_file| {
                    // log.debug("Resolved build file of '{s}' as '{s}' root={s}", .{ self.uri.raw, build_file.uri, root_source_file.raw });
                    errdefer comptime unreachable;
                    self.impl.associated_build_file.deinit(document_store.allocator);
                    self.impl.associated_build_file = .{
                        .resolved = .{
                            .build_file = build_file,
                            .root_source_file = root_source_file,
                        },
                    };
                    return .{ .resolved = self.impl.associated_build_file.resolved };
                },
            }
        }

        if (has_missing_build_config) {
            // when build configs are missing we keep the state at .unresolved so that
            // future calls will retry until all build config are resolved.
            // Then will have a conclusive result on whether or not there is a associated build file.
            return .unresolved;
        }

        self.impl.associated_build_file.deinit(document_store.allocator);
        self.impl.associated_build_file = .none;
        return .none;
    }

    pub const GetAssociatedCompilationUnitsResult = union(enum) {
        /// The Handle has no associated compilation unit.
        none,
        /// The associated compilation unit has not been resolved yet.
        unresolved,
        /// The associated compilation unit has been successfully resolved to a list of root module.
        resolved: []const []const u8,

        fn deinit(result: *GetAssociatedCompilationUnitsResult, allocator: std.mem.Allocator) void {
            switch (result.*) {
                .none, .unresolved => {},
                .resolved => |root_source_files| {
                    allocator.free(root_source_files);
                },
            }
            result.* = undefined;
        }
    };

    /// Returns the root source file of the root module of the given handle. Same as `@import("root")`.
    pub fn getAssociatedCompilationUnits(self: *Handle, document_store: *DocumentStore) error{ Canceled, OutOfMemory }!GetAssociatedCompilationUnitsResult {
        const allocator = document_store.allocator;
        const io = document_store.io;

        const build_file, const target_root_source_file = switch (self.impl.associated_compilation_units) {
            else => return self.impl.associated_compilation_units,
            .unresolved => switch (try self.getAssociatedBuildFile(document_store)) {
                .none => return .none,
                .unresolved => return .unresolved,
                .resolved => |resolved| .{ resolved.build_file, resolved.root_source_file },
            },
        };

        const build_config = build_file.tryLockConfig(io) orelse return .none;
        defer build_file.unlockConfig(io);

        const modules = &build_config.modules.map;

        var visted: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, modules.count());
        defer visted.deinit(allocator);

        var queue: std.ArrayList(usize) = try .initCapacity(allocator, 1);
        defer queue.deinit(allocator);

        const target_index = modules.getIndex(target_root_source_file).?;

        // We only care about the root source file of each root module so we convert them to a set.
        var root_modules: std.StringArrayHashMapUnmanaged(void) = .empty;
        defer root_modules.deinit(allocator);

        try root_modules.ensureTotalCapacity(allocator, build_config.compilations.len);
        for (build_config.compilations) |compile| {
            root_modules.putAssumeCapacity(compile.root_module, {});
        }

        var results: std.ArrayList([]const u8) = .empty;
        defer results.deinit(allocator);

        // Do a graph search from root modules until we reach `root_source_file`
        for (root_modules.keys()) |root_module| {
            visted.unsetAll();
            queue.clearRetainingCapacity();
            queue.appendAssumeCapacity(modules.getIndex(root_module).?);

            while (queue.pop()) |index| {
                if (index == target_index) {
                    try results.append(allocator, root_module);
                    break;
                }

                if (visted.isSet(index)) continue;
                visted.set(index);

                const imported_modules = modules.values()[index].import_table.map.values();
                try queue.ensureUnusedCapacity(allocator, imported_modules.len);
                for (imported_modules) |root_source_file| {
                    queue.appendAssumeCapacity(modules.getIndex(root_source_file) orelse continue);
                }
            }
        }

        if (results.items.len == 0) {
            self.impl.associated_compilation_units = .none;
        } else {
            self.impl.associated_compilation_units = .{ .resolved = try results.toOwnedSlice(allocator) };
        }
        return self.impl.associated_compilation_units;
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

        const io = self.impl.store.io;

        self.impl.lock.lockUncancelable(io);
        defer self.impl.lock.unlock(io);

        while (true) {
            const status = self.getStatus();
            if (@field(status, has_data_field_name)) break;
            if (@field(status, has_lock_field_name) or
                self.impl.status.bitSet(@bitOffsetOf(Status, has_lock_field_name), .release) != 0)
            {
                // another thread is currently computing the data
                self.impl.lazy_condition.waitUncancelable(io, &self.impl.lock);
                continue;
            }
            defer self.impl.lazy_condition.broadcast(io);

            @field(self.impl, name) = try Context.create(self, self.impl.store.allocator);
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
    if (supports_build_system) {
        self.wait_group.cancel(self.io);
    }

    for (self.handles.keys(), self.handles.values()) |uri, handle| {
        handle.deinit();
        self.allocator.destroy(handle);
        uri.deinit(self.allocator);
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
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    return self.handles.get(uri);
}

fn readFile(self: *DocumentStore, uri: Uri) error{ Canceled, OutOfMemory }!?[:0]u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_path = uri.toFsPath(self.allocator) catch |err| switch (err) {
        error.UnsupportedScheme => return null, // https://github.com/microsoft/language-server-protocol/issues/1264
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer self.allocator.free(file_path);

    if (!std.fs.path.isAbsolute(file_path)) {
        log.err("file path is not absolute '{s}'", .{file_path});
        return null;
    }

    const dir, const sub_path = blk: {
        if (builtin.target.cpu.arch.isWasm() and !builtin.link_libc) {
            for (self.config.wasi_preopens.map.keys()[3..], 3..) |name, i| {
                const preopen_dir: std.Io.Dir = .{ .handle = @intCast(i) };
                const preopen_path = std.mem.trimEnd(u8, name, "/");

                if (!std.mem.startsWith(u8, file_path, preopen_path)) continue;
                if (!std.mem.startsWith(u8, file_path[preopen_path.len..], "/")) continue;

                break :blk .{ preopen_dir, std.mem.trimStart(u8, file_path[preopen_path.len..], "/") };
            }
        }
        break :blk .{ std.Io.Dir.cwd(), file_path };
    };

    return dir.readFileAllocOptions(
        self.io,
        sub_path,
        self.allocator,
        .limited(max_document_size),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.Canceled, error.OutOfMemory => |e| return e,
        else => {
            log.err("failed to read document '{s}': {}", .{ file_path, err });
            return null;
        },
    };
}

/// Returns a handle to the given document
/// Will load the document from disk if it hasn't been already
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the Handle
pub fn getOrLoadHandle(self: *DocumentStore, uri: Uri) error{ Canceled, OutOfMemory }!?*Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.getHandle(uri)) |handle| return handle;
    const file_contents = try self.readFile(uri) orelse return null;
    return try self.createAndStoreDocument(uri, file_contents, false);
}

/// **Thread safe** takes a shared lock
/// This function does not protect against data races from modifying the BuildFile
pub fn getBuildFile(self: *DocumentStore, uri: Uri) ?*BuildFile {
    comptime std.debug.assert(supports_build_system);
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    return self.build_files.get(uri);
}

/// invalidates any pointers into `DocumentStore.build_files`
/// **Thread safe** takes an exclusive lock
/// This function does not protect against data races from modifying the BuildFile
fn getOrLoadBuildFile(self: *DocumentStore, uri: Uri) error{ Canceled, OutOfMemory }!*BuildFile {
    comptime std.debug.assert(supports_build_system);

    if (self.getBuildFile(uri)) |build_file| return build_file;

    const new_build_file: *BuildFile = blk: {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        const gop = try self.build_files.getOrPut(self.allocator, uri);
        if (gop.found_existing) return gop.value_ptr.*;
        errdefer self.build_files.swapRemoveAt(gop.index);

        gop.value_ptr.* = try self.allocator.create(BuildFile);
        errdefer self.allocator.destroy(gop.value_ptr.*);

        gop.value_ptr.*.* = try self.createBuildFile(uri);
        gop.key_ptr.* = gop.value_ptr.*.uri;
        break :blk gop.value_ptr.*;
    };

    // this code path is only reached when the build file is new

    self.invalidateBuildFile(new_build_file.uri);

    return new_build_file;
}

/// Opens a document that is synced over the LSP protocol (`textDocument/didOpen`).
/// **Not thread safe**
pub fn openLspSyncedDocument(self: *DocumentStore, uri: Uri, text: []const u8) error{ Canceled, OutOfMemory }!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |handle| {
        if (handle.isLspSynced()) {
            log.warn("Document already open: {s}", .{uri.raw});
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
        log.warn("Document not found: {s}", .{uri.raw});
        return;
    };
    if (!kv.value.isLspSynced()) {
        log.warn("Document already closed: {s}", .{uri.raw});
    }

    kv.key.deinit(self.allocator);
    kv.value.deinit();
    self.allocator.destroy(kv.value);
}

/// Updates a document that is synced over the LSP protocol (`textDocument/didChange`).
/// Takes ownership of `new_text` which has to be allocated with this DocumentStore's allocator.
/// **Not thread safe**
pub fn refreshLspSyncedDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) error{ Canceled, OutOfMemory }!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |old_handle| {
        if (!old_handle.isLspSynced()) {
            log.warn("Document modified without being opened: {s}", .{uri.raw});
        }
    } else {
        log.warn("Document modified without being opened: {s}", .{uri.raw});
    }

    _ = try self.createAndStoreDocument(uri, new_text, true);
}

/// Refreshes a document from the file system, unless said document is synced over the LSP protocol.
/// **Not thread safe**
pub fn refreshDocumentFromFileSystem(self: *DocumentStore, uri: Uri, should_delete: bool) error{ Canceled, OutOfMemory }!bool {
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
        handle_uri.deinit(self.allocator);
    } else {
        if (self.handles.get(uri)) |handle| {
            if (handle.isLspSynced()) return false;
        } else return false;
        const file_contents = try self.readFile(uri) orelse return false;
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

    self.wait_group.async(self.io, invalidateBuildFileWorker, .{ self, build_file });
}

const progress_token = "buildProgressToken";

fn sendMessageToClient(
    io: std.Io,
    allocator: std.mem.Allocator,
    transport: *lsp.Transport,
    message: anytype,
) !void {
    const json_message = try std.json.Stringify.valueAlloc(
        allocator,
        message,
        .{ .emit_null_optional_fields = false },
    );
    defer allocator.free(json_message);

    try transport.writeJsonMessageUncancelable(io, json_message);
}

fn notifyBuildStart(self: *DocumentStore) void {
    if (!self.lsp_capabilities.supports_work_done_progress) return;

    const transport = self.transport orelse return;

    // Atomicity note: We do not actually care about memory surrounding the
    // counter, we only care about the counter itself. We only need to ensure
    // we aren't double entering/exiting
    const prev = self.builds_in_progress.fetchAdd(1, .monotonic);
    if (prev != 0) return;

    sendMessageToClient(self.io, self.allocator, transport, .{
        .jsonrpc = "2.0",
        .id = "progress",
        .method = "window/workDoneProgress/create",
        .params = lsp.types.window.work_done_progress.CreateParams{
            .token = .{ .string = progress_token },
        },
    }) catch |err| switch (err) {
        error.Canceled => comptime unreachable,
        else => |e| {
            log.err("Failed to send create work message: {}", .{e});
            return;
        },
    };

    sendMessageToClient(self.io, self.allocator, transport, .{
        .jsonrpc = "2.0",
        .method = "$/progress",
        .params = .{
            .token = progress_token,
            .value = lsp.types.window.work_done_progress.Begin{
                .title = "Loading build configuration",
            },
        },
    }) catch |err| switch (err) {
        error.Canceled => comptime unreachable,
        else => |e| {
            log.err("Failed to send progress start message: {}", .{e});
            return;
        },
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

    sendMessageToClient(self.io, self.allocator, transport, .{
        .jsonrpc = "2.0",
        .method = "$/progress",
        .params = .{
            .token = progress_token,
            .value = lsp.types.window.work_done_progress.End{
                .message = message,
            },
        },
    }) catch |err| switch (err) {
        error.Canceled => comptime unreachable,
        else => |e| {
            log.err("Failed to send progress end message: {}", .{e});
            return;
        },
    };
}

fn invalidateBuildFileWorker(self: *DocumentStore, build_file: *BuildFile) std.Io.Cancelable!void {
    {
        try build_file.impl.mutex.lock(self.io);
        defer build_file.impl.mutex.unlock(self.io);

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

        const build_config = loadBuildConfiguration(self, build_file.uri, new_version) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |e| {
                if (e != error.RunFailed) { // already logged
                    log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri.raw, e });
                }
                self.notifyBuildEnd(.failed);
                build_file.impl.mutex.lockUncancelable(self.io);
                defer build_file.impl.mutex.unlock(self.io);
                build_file.impl.build_runner_state = .idle;
                return;
            },
        };

        build_file.impl.mutex.lockUncancelable(self.io);
        switch (build_file.impl.build_runner_state) {
            .idle => unreachable,
            .running => {
                var old_config = build_file.impl.config;
                build_file.impl.config = build_config;
                build_file.impl.build_runner_state = .idle;
                build_file.impl.mutex.unlock(self.io);

                if (old_config) |*config| config.deinit();
                self.notifyBuildEnd(.success);
                break;
            },
            .running_but_already_invalidated => {
                build_file.impl.build_runner_state = .running;
                build_file.impl.mutex.unlock(self.io);

                build_config.deinit();
                continue;
            },
        }
    }

    if (self.transport) |transport| {
        if (self.lsp_capabilities.supports_semantic_tokens_refresh) {
            sendMessageToClient(
                self.io,
                self.allocator,
                transport,
                lsp.TypedJsonRPCRequest(?void){
                    .id = .{ .string = "semantic_tokens_refresh" },
                    .method = "workspace/semanticTokens/refresh",
                    .params = @as(?void, null),
                },
            ) catch |err| switch (err) {
                error.Canceled => comptime unreachable,
                else => {},
            };
        }
        if (self.lsp_capabilities.supports_inlay_hints_refresh) {
            sendMessageToClient(
                self.io,
                self.allocator,
                transport,
                lsp.TypedJsonRPCRequest(?void){
                    .id = .{ .string = "inlay_hints_refresh" },
                    .method = "workspace/inlayHint/refresh",
                    .params = @as(?void, null),
                },
            ) catch |err| switch (err) {
                error.Canceled => comptime unreachable,
                else => {},
            };
        }
    }
}

pub fn isBuildFile(uri: Uri) bool {
    return std.mem.endsWith(u8, uri.raw, "/build.zig");
}

pub fn isBuiltinFile(uri: Uri) bool {
    return std.mem.endsWith(u8, uri.raw, "/builtin.zig");
}

pub fn isInStd(uri: Uri) bool {
    // TODO: Better logic for detecting std or subdirectories?
    return std.mem.find(u8, uri.raw, "/std/") != null;
}

/// looks for a `zls.build.json` file in the build file directory
/// has to be freed with `json_compat.parseFree`
fn loadBuildAssociatedConfiguration(io: std.Io, allocator: std.mem.Allocator, build_file: BuildFile) !std.json.Parsed(BuildAssociatedConfig) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const build_file_path = try build_file.uri.toFsPath(allocator);
    defer allocator.free(build_file_path);
    const config_file_path = try std.fs.path.resolve(allocator, &.{ build_file_path, "..", "zls.build.json" });
    defer allocator.free(config_file_path);

    const file_buf = try std.Io.Dir.cwd().readFileAlloc(
        io,
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

fn prepareBuildRunnerArgs(self: *DocumentStore, build_file_uri: Uri) error{OutOfMemory}![][]const u8 {
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

    const build_file_path = try build_file_uri.toFsPath(self.allocator);
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
        break :blk try std.process.run(
            self.allocator,
            self.io,
            .{
                .argv = args,
                .cwd = cwd,
                .max_output_bytes = 16 * 1024 * 1024,
            },
        );
    };
    defer self.allocator.free(zig_run_result.stdout);
    defer self.allocator.free(zig_run_result.stderr);

    const is_ok = switch (zig_run_result.term) {
        .exited => |exit_code| exit_code == 0,
        else => false,
    };

    const diagnostic_tag: DiagnosticsCollection.Tag = tag: {
        var hasher: std.hash.Wyhash = .init(47); // Chosen by the following prompt: Pwease give a wandom nyumbew
        hasher.update(build_file_uri.raw);
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

    return std.json.parseFromSlice(
        BuildConfig,
        self.allocator,
        zig_run_result.stdout,
        parse_options,
    ) catch return error.InvalidBuildConfig;
}

/// Checks if the build.zig file is accessible in dir.
fn buildDotZigExists(io: std.Io, dir_path: []const u8) std.Io.Cancelable!bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    defer dir.close(io);
    dir.access(io, "build.zig", .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    return true;
}

/// Walk down the tree towards the uri. When we hit `build.zig` files
/// add them to the list of potential build files.
/// `build.zig` files higher in the filesystem have precedence.
/// See `Handle.getAssociatedBuildFile`.
/// Caller owns returned memory.
fn collectPotentialBuildFiles(self: *DocumentStore, uri: Uri) error{ Canceled, OutOfMemory }![]*BuildFile {
    if (isInStd(uri)) return &.{};

    var potential_build_files: std.ArrayList(*BuildFile) = .empty;
    errdefer potential_build_files.deinit(self.allocator);

    const path = uri.toFsPath(self.allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedScheme => return &.{},
    };
    defer self.allocator.free(path);

    // Zig's filesystem API does not handle `OBJECT_PATH_INVALID` being returned when dealing with invalid UNC paths on Windows.
    // https://github.com/ziglang/zig/issues/15607
    const root_end_index: usize = root_end_index: {
        if (builtin.target.os.tag != .windows) break :root_end_index 0;
        const component_iterator = std.fs.path.componentIterator(path);
        break :root_end_index component_iterator.root_end_index;
    };

    var current_path: []const u8 = path;
    while (std.fs.path.dirname(current_path)) |potential_root_path| : (current_path = potential_root_path) {
        if (potential_root_path.len < root_end_index) break;
        if (!try buildDotZigExists(self.io, potential_root_path)) continue;

        const build_path = try std.fs.path.join(self.allocator, &.{ potential_root_path, "build.zig" });
        defer self.allocator.free(build_path);

        try potential_build_files.ensureUnusedCapacity(self.allocator, 1);

        const build_file_uri: Uri = try .fromPath(self.allocator, build_path);
        defer build_file_uri.deinit(self.allocator);

        const build_file = try self.getOrLoadBuildFile(build_file_uri);
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

fn createBuildFile(self: *DocumentStore, uri: Uri) error{ Canceled, OutOfMemory }!BuildFile {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var build_file: BuildFile = .{
        .uri = try uri.dupe(self.allocator),
    };

    errdefer build_file.deinit(self.allocator);

    if (loadBuildAssociatedConfiguration(self.io, self.allocator, build_file)) |cfg| {
        build_file.build_associated_config = cfg;

        if (cfg.value.relative_builtin_path) |relative_builtin_path| blk: {
            const build_file_path = build_file.uri.toFsPath(self.allocator) catch break :blk;
            const absolute_builtin_path = try std.fs.path.resolve(self.allocator, &.{ build_file_path, "..", relative_builtin_path });
            defer self.allocator.free(absolute_builtin_path);
            build_file.builtin_uri = try .fromPath(self.allocator, absolute_builtin_path);
        }
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.FileNotFound => {},
        else => {
            log.debug("Failed to load config associated with build file {s} (error: {})", .{ build_file.uri.raw, err });
        },
    }

    log.info("Loaded build file '{s}'", .{build_file.uri.raw});

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
    const success = try build_file.collectBuildConfigPackageUris(self.io, self.allocator, &package_uris);
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
    checked_uris: *Uri.ArrayHashMap(void),
    build_file_uri: Uri,
    source_uri: Uri,
    uri: Uri,
) error{OutOfMemory}!bool {
    if (uri.eql(source_uri)) return true;
    if (isInStd(source_uri)) return false;

    const gop = try checked_uris.getOrPut(self.allocator, source_uri);
    if (gop.found_existing) return false;

    const handle = self.getOrLoadHandle(source_uri) orelse {
        errdefer std.debug.assert(checked_uris.swapRemove(source_uri));
        gop.key_ptr.* = try source_uri.dupe(self.allocator);
        return false;
    };
    gop.key_ptr.* = handle.uri;

    if (try handle.getAssociatedBuildFileUri(self)) |associated_build_file_uri| {
        return associated_build_file_uri.eql(build_file_uri);
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
) error{ Canceled, OutOfMemory }!*Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var new_handle = Handle.init(self, uri, text, lsp_synced) catch |err| switch (err) {
        error.OutOfMemory => {
            self.allocator.free(text);
            return err;
        },
    };
    errdefer new_handle.deinit();

    if (supports_build_system and lsp_synced and isBuildFile(uri) and !isInStd(uri)) {
        if (self.getBuildFile(uri)) |build_file| {
            self.invalidateBuildFile(build_file.uri);
        } else {
            _ = try self.getOrLoadBuildFile(uri);
        }
    }

    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);

    const gop = try self.handles.getOrPut(self.allocator, uri);
    errdefer if (!gop.found_existing) std.debug.assert(self.handles.swapRemove(uri));

    if (gop.found_existing) {
        std.debug.assert(new_handle.impl.associated_build_file == .init);
        std.debug.assert(new_handle.impl.associated_compilation_units == .unresolved);
        if (lsp_synced) {
            new_handle.impl.associated_build_file = gop.value_ptr.*.impl.associated_build_file;
            gop.value_ptr.*.impl.associated_build_file = .init;

            new_handle.impl.associated_compilation_units = gop.value_ptr.*.impl.associated_compilation_units;
            gop.value_ptr.*.impl.associated_compilation_units = .unresolved;

            new_handle.uri = gop.key_ptr.*;
            gop.value_ptr.*.deinit();
            gop.value_ptr.*.* = new_handle;
        } else {
            // TODO prevent concurrent `createAndStoreDocument` invocations from racing each other
            new_handle.deinit();
        }
    } else {
        gop.key_ptr.* = try uri.dupe(self.allocator);
        errdefer gop.key_ptr.*.deinit(self.allocator);

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
fn collectCIncludes(allocator: std.mem.Allocator, tree: *const Ast) error{OutOfMemory}!std.MultiArrayList(CImportHandle) {
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
) error{ Canceled, OutOfMemory }!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const import_uris = try handle.getImportUris();

    try dependencies.ensureUnusedCapacity(allocator, import_uris.len + handle.cimports.len);
    for (import_uris) |uri| {
        dependencies.appendAssumeCapacity(try uri.dupe(allocator));
    }

    if (supports_build_system) {
        try store.mutex.lock(store.io);
        defer store.mutex.unlock(store.io);
        for (handle.cimports.items(.hash)) |hash| {
            const result = store.cimports.get(hash) orelse continue;
            switch (result) {
                .success => |uri| dependencies.appendAssumeCapacity(try uri.dupe(allocator)),
                .failure => continue,
            }
        }
    }

    if (supports_build_system) no_build_file: {
        const build_file = switch (try handle.getAssociatedBuildFile(store)) {
            .none, .unresolved => break :no_build_file,
            .resolved => |resolved| resolved.build_file,
        };

        const build_config = build_file.tryLockConfig(store.io) orelse break :no_build_file;
        defer build_file.unlockConfig(store.io);

        const module_paths = build_config.modules.map.keys();

        try dependencies.ensureUnusedCapacity(allocator, module_paths.len);
        for (module_paths) |module_path| {
            dependencies.appendAssumeCapacity(try .fromPath(allocator, module_path));
        }
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
) error{ Canceled, OutOfMemory }!bool {
    comptime std.debug.assert(supports_build_system);

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

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
    const arena_allocator_allocator = arena_allocator.allocator();
    const native_paths: std.zig.system.NativePaths = try .detect(arena_allocator_allocator, store.io, &target_info, @constCast(store.config.environ_map));

    try include_dirs.ensureUnusedCapacity(allocator, native_paths.include_dirs.items.len);
    for (native_paths.include_dirs.items) |native_include_dir| {
        include_dirs.appendAssumeCapacity(try allocator.dupe(u8, native_include_dir));
    }

    const collected_all = switch (try handle.getAssociatedBuildFile(store)) {
        .none => true,
        .unresolved => false,
        .resolved => |resolved| collected_all: {
            const build_config = resolved.build_file.tryLockConfig(store.io) orelse break :collected_all false;
            defer resolved.build_file.unlockConfig(store.io);

            const module = build_config.modules.map.get(resolved.root_source_file) orelse break :collected_all true;

            try include_dirs.ensureUnusedCapacity(allocator, module.include_dirs.len);
            for (module.include_dirs) |include_path| {
                const absolute_path = if (std.fs.path.isAbsolute(include_path))
                    try allocator.dupe(u8, include_path)
                else blk: {
                    const build_file_path = resolved.build_file.uri.toFsPath(allocator) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.UnsupportedScheme => continue,
                    };
                    const build_file_dirname = std.fs.path.dirname(build_file_path) orelse continue;
                    break :blk try std.fs.path.join(allocator, &.{ build_file_dirname, include_path });
                };

                include_dirs.appendAssumeCapacity(absolute_path);
            }
            break :collected_all true;
        },
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
) error{ Canceled, OutOfMemory }!bool {
    comptime std.debug.assert(supports_build_system);

    const collected_all = switch (try handle.getAssociatedBuildFile(store)) {
        .none => true,
        .unresolved => false,
        .resolved => |resolved| collected_all: {
            const build_config = resolved.build_file.tryLockConfig(store.io) orelse break :collected_all false;
            defer resolved.build_file.unlockConfig(store.io);

            const module = build_config.modules.map.get(resolved.root_source_file) orelse break :collected_all true;

            try c_macros.ensureUnusedCapacity(allocator, module.c_macros.len);
            for (module.c_macros) |c_macro| {
                c_macros.appendAssumeCapacity(try allocator.dupe(u8, c_macro));
            }
            break :collected_all true;
        },
    };

    return collected_all;
}

/// returns the document behind `@cImport()` where `node` is the `cImport` node
/// if a cImport can't be translated e.g. requires computing a
/// comptime value `resolveCImport` will return null
/// returned memory is owned by DocumentStore
/// **Thread safe** takes an exclusive lock
pub fn resolveCImport(self: *DocumentStore, handle: *Handle, node: Ast.Node.Index) error{ Canceled, OutOfMemory }!?Uri {
    comptime std.debug.assert(supports_build_system);

    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.config.zig_exe_path == null) return null;
    if (self.config.zig_lib_dir == null) return null;
    if (self.config.global_cache_dir == null) return null;

    // TODO regenerate cimports if the header files gets modified

    const index = std.mem.findScalar(Ast.Node.Index, handle.cimports.items(.node), node) orelse return null;
    const hash: Hash = handle.cimports.items(.hash)[index];
    const source = handle.cimports.items(.source)[index];

    {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
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

    const collected_all_include_dirs = self.collectIncludeDirs(self.allocator, handle, &include_dirs) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.err("failed to resolve include paths: {}", .{err});
            return null;
        },
    };

    var c_macros: std.ArrayList([]const u8) = .empty;
    defer {
        for (c_macros.items) |c_macro| {
            self.allocator.free(c_macro);
        }
        c_macros.deinit(self.allocator);
    }

    const collected_all_c_macros = self.collectCMacros(self.allocator, handle, &c_macros) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.err("failed to resolve include paths: {}", .{err});
            return null;
        },
    };

    const maybe_result = translate_c.translate(
        self.io,
        self.allocator,
        self.config,
        include_dirs.items,
        c_macros.items,
        source,
    ) catch |err| switch (err) {
        error.Canceled, error.OutOfMemory => |e| return e,
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
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        const gop = self.cimports.getOrPutValue(self.allocator, hash, result) catch |err| {
            result.deinit(self.allocator);
            return err;
        };
        if (gop.found_existing) {
            result.deinit(self.allocator);
            result = gop.value_ptr.*;
        }
    }

    self.publishCimportDiagnostics(handle) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.err("failed to publish cImport diagnostics: {}", .{err});
        },
    };

    switch (result) {
        .success => |uri| {
            log.debug("Translated cImport into {s}", .{uri.raw});
            return uri;
        },
        .failure => return null,
    }
}

fn publishCimportDiagnostics(self: *DocumentStore, handle: *Handle) (std.mem.Allocator.Error || std.Io.File.Writer.Error)!void {
    var wip: std.zig.ErrorBundle.Wip = undefined;
    try wip.init(self.allocator);
    defer wip.deinit();

    const src_path = try wip.addString("");

    for (handle.cimports.items(.hash), handle.cimports.items(.node)) |hash, node| {
        const result = blk: {
            try self.mutex.lock(self.io);
            defer self.mutex.unlock(self.io);
            break :blk self.cimports.get(hash) orelse continue;
        };
        const error_bundle: std.zig.ErrorBundle = switch (result) {
            .success => continue,
            .failure => |bundle| bundle,
        };

        if (error_bundle.errorMessageCount() == 0) continue;

        const loc = offsets.nodeToLoc(&handle.tree, node);
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

pub const UriFromImportStringResult = union(enum) {
    none,
    one: Uri,
    many: []const Uri,

    pub fn deinit(result: *UriFromImportStringResult, allocator: std.mem.Allocator) void {
        switch (result.*) {
            .none => {},
            .one => |uri| uri.deinit(allocator),
            .many => |uris| {
                for (uris) |uri| uri.deinit(allocator);
                allocator.free(uris);
            },
        }
    }
};

/// takes the string inside a @import() node (without the quotation marks)
/// and returns it's uri
/// caller owns the returned memory
/// **Thread safe** takes a shared lock
pub fn uriFromImportStr(
    self: *DocumentStore,
    allocator: std.mem.Allocator,
    handle: *Handle,
    import_str: []const u8,
) error{ Canceled, OutOfMemory }!UriFromImportStringResult {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (std.mem.endsWith(u8, import_str, ".zig") or std.mem.endsWith(u8, import_str, ".zon")) {
        const base_path = handle.uri.toFsPath(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedScheme => return .none,
        };
        defer allocator.free(base_path);
        const uri = try resolveFileImportString(allocator, base_path, import_str) orelse return .none;
        return .{ .one = uri };
    }

    if (std.mem.eql(u8, import_str, "std")) {
        const zig_lib_dir = self.config.zig_lib_dir orelse return .none;

        const std_path = try zig_lib_dir.join(allocator, &.{ "std", "std.zig" });
        defer allocator.free(std_path);

        return .{ .one = try .fromPath(allocator, std_path) };
    }

    if (std.mem.eql(u8, import_str, "builtin")) {
        if (supports_build_system) {
            switch (try handle.getAssociatedBuildFile(self)) {
                .none, .unresolved => {},
                .resolved => |resolved| {
                    if (resolved.build_file.builtin_uri) |builtin_uri| {
                        return .{ .one = try builtin_uri.dupe(allocator) };
                    }
                },
            }
        }
        if (self.config.builtin_path) |builtin_path| {
            return .{ .one = try .fromPath(allocator, builtin_path) };
        }
        return .none;
    }

    if (!supports_build_system) return .none;

    if (std.mem.eql(u8, import_str, "root")) {
        const root_source_files = switch (try handle.getAssociatedCompilationUnits(self)) {
            .none, .unresolved => return .none,
            .resolved => |root_source_files| root_source_files,
        };
        var uris: std.ArrayList(Uri) = try .initCapacity(allocator, root_source_files.len);
        defer {
            for (uris.items) |uri| uri.deinit(allocator);
            uris.deinit(allocator);
        }
        for (root_source_files) |root_source_file| {
            uris.appendAssumeCapacity(try .fromPath(allocator, root_source_file));
        }
        return .{ .many = try uris.toOwnedSlice(allocator) };
    }

    if (isBuildFile(handle.uri)) blk: {
        const build_file = self.getBuildFile(handle.uri) orelse break :blk;
        const build_config = build_file.tryLockConfig(self.io) orelse break :blk;
        defer build_file.unlockConfig(self.io);

        if (build_config.dependencies.map.get(import_str)) |path| {
            return .{ .one = try .fromPath(allocator, path) };
        }
        return .none;
    }

    switch (try handle.getAssociatedBuildFile(self)) {
        .none, .unresolved => return .none,
        .resolved => |resolved| {
            const build_config = resolved.build_file.tryLockConfig(self.io) orelse return .none;
            defer resolved.build_file.unlockConfig(self.io);

            const module = build_config.modules.map.get(resolved.root_source_file) orelse return .none;
            const imported_root_source_file = module.import_table.map.get(import_str) orelse return .none;
            return .{ .one = try .fromPath(allocator, imported_root_source_file) };
        },
    }
}

fn resolveFileImportString(allocator: std.mem.Allocator, base_path: []const u8, import_str: []const u8) error{OutOfMemory}!?Uri {
    const joined_path = try std.fs.path.resolve(allocator, &.{ base_path, "..", import_str });
    defer allocator.free(joined_path);

    return try .fromPath(allocator, joined_path);
}
