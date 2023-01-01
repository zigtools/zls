const std = @import("std");
const types = @import("lsp.zig");
const Server = @import("Server.zig");
const offsets = @import("offsets.zig");
const uri_utils = @import("uri.zig");
const DocumentStore = @import("DocumentStore.zig");

const log = std.log.scoped(.compilation_diagnostics);

const CompilationDiagnostics = @This();

allocator: std.mem.Allocator,

arena: std.heap.ArenaAllocator = undefined,
build_file_path: []const u8 = undefined,
process: ?std.ChildProcess = null,

buffer: std.ArrayListUnmanaged(u8) = .{},

diagnostics_arena: ?std.heap.ArenaAllocator = null,
diagnostics: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(types.Diagnostic)) = .{},

pub fn init(allocator: std.mem.Allocator) CompilationDiagnostics {
    return .{ .allocator = allocator };
}

pub fn restart(
    cd: *CompilationDiagnostics,
    server: *Server,
    handle: DocumentStore.Handle,
) !void {
    if (cd.process) |*proc| {
        // windows.kernel32.GetExitCodeProcess(self.handle, &exit_code) == 259
        _ = proc.kill() catch {};
        cd.arena.deinit();
        cd.process = null;
    }

    cd.buffer.items.len = 0;

    const config = server.config;

    const build_file_uri = handle.associated_build_file orelse return;
    const build_file = server.document_store.build_files.get(build_file_uri).?;

    var arena = std.heap.ArenaAllocator.init(cd.allocator);
    const arena_allocator = arena.allocator();

    const build_file_path = try uri_utils.parse(arena_allocator, build_file.uri);
    cd.build_file_path = try arena_allocator.dupe(u8, build_file_path);
    const directory_path = try std.fs.path.resolve(arena_allocator, &.{ build_file_path, "../" });

    // TODO extract this option from `BuildAssociatedConfig.BuildOption`
    const zig_cache_root: []const u8 = try std.fs.path.join(arena_allocator, &.{ directory_path, "zig-cache" });
    // Since we don't compile anything and no packages should put their
    // files there this path can be ignored
    const zig_global_cache_root: []const u8 = server.config.global_cache_path.?;

    const standard_args = [_][]const u8{
        config.zig_exe_path.?,
        "run",
        config.diagnostics_build_runner_path.?,
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

    cd.arena = arena;
    cd.process = std.ChildProcess.init(args.items, arena_allocator);
    cd.process.?.stdout_behavior = .Ignore;
    cd.process.?.stderr_behavior = .Pipe;
    try cd.process.?.spawn();
}

extern fn PeekNamedPipe(
    hNamedPipe: std.os.windows.HANDLE,
    lpBuffer: ?std.os.windows.LPVOID,
    nBufferSize: std.os.windows.DWORD,
    lpBytesRead: ?*std.os.windows.DWORD,
    lpTotalBytesAvail: *std.os.windows.DWORD,
    lpBytesLeftThisMessage: ?*std.os.windows.DWORD,
) std.os.windows.BOOL;

pub fn advance(
    cd: *CompilationDiagnostics,
    server: *Server,
) !void {
    if (cd.process == null) return;

    var total_available_bytes: u32 = 0;
    const pnp = PeekNamedPipe(cd.process.?.stderr.?.handle, null, 0, null, &total_available_bytes, null);
    if (pnp == 0) {
        log.err("PeekNamedPipe failure: {d}", .{pnp});
    }

    if (total_available_bytes > 0) {
        try cd.buffer.ensureTotalCapacity(cd.allocator, 512);

        const p = try cd.process.?.stderr.?.read(cd.buffer.unusedCapacitySlice());
        cd.buffer.items.len += p;

        log.info("STDERR {s}", .{cd.buffer.items});
        if (p == 0) {
            _ = try cd.process.?.wait();
            cd.process = null;
            try cd.distill(server);
            cd.arena.deinit();
        }
    }
}

pub fn distill(
    cd: *CompilationDiagnostics,
    server: *Server,
) !void {
    if (cd.diagnostics_arena) |da| da.deinit();

    var new_arena = std.heap.ArenaAllocator.init(cd.allocator);
    var allocator = new_arena.allocator();

    cd.diagnostics = .{};

    log.info("DISTILLING from {s}", .{cd.build_file_path});
    var line_iterator = std.mem.split(u8, cd.buffer.items, "\n");

    while (line_iterator.next()) |line| lin: {
        if (std.mem.startsWith(u8, line, " ")) continue;

        var pos_and_diag_iterator = std.mem.split(u8, line, ":");
        const maybe_first = pos_and_diag_iterator.next();
        if (maybe_first) |first| {
            if (first.len <= 1) break :lin;
        } else break;

        const utf8_position = types.Position{
            .line = (std.fmt.parseInt(u32, pos_and_diag_iterator.next() orelse continue, 10) catch continue) - 1,
            .character = (std.fmt.parseInt(u32, pos_and_diag_iterator.next() orelse continue, 10) catch continue) - 1,
        };

        // TODO: Use a map to map "basic" paths to URIs so we don't keep allocating a million times
        const file_path = try std.fs.path.resolve(cd.arena.allocator(), &.{ cd.build_file_path, "../", maybe_first.? });
        const uri = try uri_utils.fromPath(cd.arena.allocator(), file_path);
        const handle = server.document_store.getHandle(uri);

        if (handle == null) continue;

        // // zig uses utf-8 encoding for character offsets
        const position = offsets.convertPositionEncoding(handle.?.text, utf8_position, .@"utf-8", server.offset_encoding);
        const range = offsets.tokenPositionToRange(handle.?.text, position, server.offset_encoding);

        const msg = pos_and_diag_iterator.rest()[1..];

        if (std.mem.startsWith(u8, msg, "error: ")) {
            const gop = try cd.diagnostics.getOrPut(cd.allocator, try allocator.dupe(u8, uri));
            if (!gop.found_existing) {
                gop.value_ptr.* = .{};
            }
            var diags = gop.value_ptr;

            try diags.append(allocator, types.Diagnostic{
                .range = range,
                .severity = .Error,
                .code = .{ .string = "compile_error" },
                .source = "zls",
                .message = try allocator.dupe(u8, msg["error: ".len..]),
            });
        }
    }

    cd.diagnostics_arena = new_arena;
}
