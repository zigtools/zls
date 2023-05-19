const std = @import("std");
const builtin = @import("builtin");
const types = @import("lsp.zig");
const URI = @import("uri.zig");
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const log = std.log.scoped(.zls_store);
const Ast = std.zig.Ast;
const BuildAssociatedConfig = @import("BuildAssociatedConfig.zig");
const BuildConfig = @import("special/build_runner.zig").BuildConfig;
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
    config: BuildConfig,
    /// this build file may have an explicitly specified path to builtin.zig
    builtin_uri: ?Uri = null,
    build_associated_config: ?BuildAssociatedConfig = null,

    pub fn deinit(self: *BuildFile, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        std.json.parseFree(BuildConfig, allocator, self.config);
        if (self.builtin_uri) |builtin_uri| allocator.free(builtin_uri);
        if (self.build_associated_config) |cfg| {
            std.json.parseFree(BuildAssociatedConfig, allocator, cfg);
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

/// Returns a handle to the given document
pub fn getHandle(self: *DocumentStore, uri: Uri) ?*const Handle {
    return self.handles.get(uri);
}

/// Returns a handle to the given document
/// Will load the document from disk if it hasn't been already
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

/// Takes ownership of `text` which has to be allocated
/// with this DocumentStore's allocator
pub fn openDocument(self: *DocumentStore, uri: Uri, text: [:0]const u8) error{OutOfMemory}!Handle {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (self.handles.get(uri)) |handle| {
        if (handle.open) {
            log.warn("Document already open: {s}", .{uri});
        } else {
            handle.open = true;
        }
        self.allocator.free(text);
        return handle.*;
    }

    var handle = self.allocator.create(Handle) catch |err| {
        self.allocator.free(text);
        return err;
    };
    errdefer self.allocator.destroy(handle);

    handle.* = try self.createDocument(uri, text, true);
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

/// Takes ownership of `new_text` which has to be allocated
/// with this DocumentStore's allocator
pub fn refreshDocument(self: *DocumentStore, uri: Uri, new_text: [:0]const u8) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const handle = self.handles.get(uri).?;

    // TODO: Handle interpreter cross reference
    if (handle.interpreter) |int| {
        int.deinit();
        handle.interpreter = null;
    }

    self.allocator.free(handle.text);
    handle.text = new_text;

    var new_tree = try Ast.parse(self.allocator, handle.text, .zig);
    handle.tree.deinit(self.allocator);
    handle.tree = new_tree;

    if (self.wantZir() and handle.open and new_tree.errors.len == 0) {
        const new_zir = try AstGen.generate(self.allocator, new_tree);
        if (handle.zir_status != .none) handle.zir.deinit(self.allocator);
        handle.zir = new_zir;
        handle.zir_status = .done;
    } else if (handle.zir_status == .done) {
        handle.zir_status = .outdated;
    }

    var new_document_scope = try analysis.makeDocumentScope(self.allocator, handle.tree);
    handle.document_scope.deinit(self.allocator);
    handle.document_scope = new_document_scope;

    var new_import_uris = try self.collectImportUris(handle.*);
    for (handle.import_uris.items) |import_uri| {
        self.allocator.free(import_uri);
    }
    const old_import_count = handle.import_uris.items.len;
    const new_import_count = new_import_uris.items.len;
    handle.import_uris.deinit(self.allocator);
    handle.import_uris = new_import_uris;

    var new_cimports = try self.collectCIncludes(handle.*);
    const old_cimport_count = handle.cimports.len;
    const new_cimport_count = new_cimports.len;
    for (handle.cimports.items(.source)) |source| {
        self.allocator.free(source);
    }
    handle.cimports.deinit(self.allocator);
    handle.cimports = new_cimports;

    for (handle.analysis_errors.items) |err| {
        self.allocator.free(err.message);
    }
    handle.analysis_errors.deinit(self.allocator);
    handle.analysis_errors = .{};

    if (old_import_count != new_import_count or
        old_cimport_count != new_cimport_count)
    {
        self.garbageCollectionImports() catch {};
        self.garbageCollectionCImports() catch {};
    }
}

pub fn applySave(self: *DocumentStore, handle: *const Handle) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (std.process.can_spawn and isBuildFile(handle.uri)) {
        const build_file = self.build_files.getPtr(handle.uri).?;

        const build_config = loadBuildConfiguration(
            self.allocator,
            build_file.*,
            self.config.*,
            self.runtime_zig_version.*.?, // if we have the path to zig we should have the zig version
        ) catch |err| {
            log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri, err });
            return;
        };

        std.json.parseFree(BuildConfig, self.allocator, build_file.config);
        build_file.config = build_config;
    }
}

/// Invalidates all build files. Used to rerun
/// upon changing the zig exe path via a configuration request.
pub fn invalidateBuildFiles(self: *DocumentStore) void {
    if (!std.process.can_spawn) return;

    var it = self.build_files.iterator();

    while (it.next()) |entry| {
        const build_file = entry.value_ptr;

        const build_config = loadBuildConfiguration(
            self.allocator,
            build_file.*,
            self.config.*,
            self.runtime_zig_version.*.?, // if we have the path to zig we should have the zig version
        ) catch |err| {
            log.err("Failed to load build configuration for {s} (error: {})", .{ build_file.uri, err });
            return;
        };

        std.json.parseFree(BuildConfig, self.allocator, build_file.config);
        build_file.config = build_config;
    }
}

/// The `DocumentStore` represents a graph structure where every
/// handle/document is a node and every `@import` and `@cImport` represent
/// a directed edge.
/// We can remove every document which cannot be reached from
/// another document that is `open` (see `Handle.open`)
fn garbageCollectionImports(self: *DocumentStore) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();

    var reachable = try std.DynamicBitSetUnmanaged.initEmpty(arena.allocator(), self.handles.count());

    var queue = std.ArrayListUnmanaged(Uri){};

    for (self.handles.values(), 0..) |handle, handle_index| {
        if (!handle.open) continue;

        reachable.set(handle_index);

        try self.collectDependencies(arena.allocator(), handle.*, &queue);
    }

    while (queue.popOrNull()) |uri| {
        const handle_index = self.handles.getIndex(uri) orelse continue;
        if (reachable.isSet(handle_index)) continue;
        reachable.set(handle_index);

        const handle = self.handles.values()[handle_index];

        try self.collectDependencies(arena.allocator(), handle.*, &queue);
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

    return try std.json.parseFromSlice(BuildAssociatedConfig, allocator, file_buf, .{});
}

/// Caller owns returned memory!
pub fn populateBuildConfigurationArgs(
    allocator: std.mem.Allocator,
    args: *std.ArrayListUnmanaged([]const u8),
    zig_exe_path: []const u8,
    build_runner_path: []const u8,
) error{OutOfMemory}!void {
    try args.appendSlice(allocator, &.{ zig_exe_path, "build", "--build-runner", build_runner_path });
}

/// Runs the build.zig and returns the run result
/// Args should be the output of `createBuildConfigurationArgs`
/// plus any additional custom arguments
/// Arena recommended
pub fn executeBuildRunner(
    allocator: std.mem.Allocator,
    build_file_path: []const u8,
    args: []const []const u8,
) !std.ChildProcess.ExecResult {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const build_file_directory_path = try std.fs.path.resolve(allocator, &.{ build_file_path, "../" });
    defer allocator.free(build_file_directory_path);

    return try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = args,
        .cwd = build_file_directory_path,
    });
}

/// Runs the build.zig and extracts include directories and packages
/// Has to be freed with `std.json.parseFree`
pub fn loadBuildConfiguration(
    allocator: std.mem.Allocator,
    build_file: BuildFile,
    config: Config,
    _: ZigVersionWrapper,
) !BuildConfig {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const build_file_path = try URI.parse(arena_allocator, build_file.uri);

    // NOTE: This used to be backwards compatible
    // but then I came in like a wrecking ball

    const arg_length = 4 + if (build_file.build_associated_config) |cfg| if (cfg.build_options) |options| options.len else 0 else 0;
    var args = try std.ArrayListUnmanaged([]const u8).initCapacity(arena_allocator, arg_length);
    try populateBuildConfigurationArgs(arena_allocator, &args, config.zig_exe_path.?, config.build_runner_path.?);

    if (build_file.build_associated_config) |cfg| {
        if (cfg.build_options) |options| {
            for (options) |opt| {
                args.appendAssumeCapacity(try opt.formatParam(arena_allocator));
            }
        }
    }

    var zig_run_result = try executeBuildRunner(arena_allocator, build_file_path, args.items);

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

    const parse_options = std.json.ParseOptions{
        // We ignore unknown fields so people can roll
        // their own build runners in libraries with
        // the only requirement being general adherance
        // to the BuildConfig type
        .ignore_unknown_fields = true,
    };
    const build_config = std.json.parseFromSlice(
        BuildConfig,
        allocator,
        zig_run_result.stdout,
        parse_options,
    ) catch return error.RunFailed;
    errdefer std.json.parseFree(BuildConfig, allocator, build_config);

    for (build_config.packages) |*pkg| {
        const pkg_abs_path = try std.fs.path.resolve(allocator, &[_][]const u8{ build_file_path, "..", pkg.path });
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
    if (loadBuildConfiguration(
        self.allocator,
        build_file,
        self.config.*,
        self.runtime_zig_version.*.?, // if we have the path to zig we should have the zig version
    )) |build_config| {
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
            .open = open,
            .uri = duped_uri,
            .text = text,
            .tree = tree,
            .zir = if (zir) |code| code else undefined,
            .zir_status = if (zir != null) .done else .none,
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
        if (store.build_files.get(build_file_uri)) |build_file| {
            const packages = build_file.config.packages;
            try dependencies.ensureUnusedCapacity(allocator, packages.len);
            for (packages) |pkg| {
                dependencies.appendAssumeCapacity(try URI.fromPath(allocator, pkg.path));
            }
        }
    }
}

pub fn collectIncludeDirs(
    store: *const DocumentStore,
    allocator: std.mem.Allocator,
    handle: Handle,
    include_dirs: *std.ArrayListUnmanaged([]const u8),
) !void {
    const target_info = try std.zig.system.NativeTargetInfo.detect(.{});
    var native_paths = try std.zig.system.NativePaths.detect(allocator, target_info);
    defer native_paths.deinit();

    const build_file_includes_paths: []const []const u8 = if (handle.associated_build_file) |build_file_uri|
        store.build_files.get(build_file_uri).?.config.include_dirs
    else
        &.{};

    try include_dirs.ensureTotalCapacity(allocator, native_paths.include_dirs.items.len + build_file_includes_paths.len);

    const native_include_dirs = try native_paths.include_dirs.toOwnedSlice();
    defer allocator.free(native_include_dirs);
    include_dirs.appendSliceAssumeCapacity(native_include_dirs);

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
}

/// returns the document behind `@cImport()` where `node` is the `cImport` node
/// if a cImport can't be translated e.g. requires computing a
/// comptime value `resolveCImport` will return null
/// returned memory is owned by DocumentStore
pub fn resolveCImport(self: *DocumentStore, handle: Handle, node: Ast.Node.Index) error{OutOfMemory}!?Uri {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!std.process.can_spawn) return null;

    // FIXME: Re-enable cimport resolution once https://github.com/ziglang/zig/issues/15025 is resolved
    // Tracking issue: https://github.com/zigtools/zls/issues/1080
    if (true) return null;

    const index = std.mem.indexOfScalar(Ast.Node.Index, handle.cimports.items(.node), node) orelse return null;

    const hash: Hash = handle.cimports.items(.hash)[index];

    // TODO regenerate cimports if config changes or the header files gets modified
    const result = self.cimports.get(hash) orelse blk: {
        const source: []const u8 = handle.cimports.items(.source)[index];

        var include_dirs: std.ArrayListUnmanaged([]const u8) = .{};
        defer {
            for (include_dirs.items) |path| {
                self.allocator.free(path);
            }
            include_dirs.deinit(self.allocator);
        }
        self.collectIncludeDirs(self.allocator, handle, &include_dirs) catch |err| {
            log.err("failed to resolve include paths: {}", .{err});
            return null;
        };

        var result = (try translate_c.translate(
            self.allocator,
            self.config.*,
            include_dirs.items,
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

pub fn wantZir(self: DocumentStore) bool {
    if (!self.config.enable_ast_check_diagnostics) return false;
    const can_run_ast_check = std.process.can_spawn and self.config.zig_exe_path != null and self.config.prefer_ast_check_as_child_process;
    return !can_run_ast_check;
}

pub fn ensureInterpreterExists(self: *DocumentStore, uri: Uri, ip: *InternPool) !*ComptimeInterpreter {
    var handle = self.handles.get(uri).?;
    if (handle.interpreter != null) return handle.interpreter.?;

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
