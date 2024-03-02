const std = @import("std");
const zig_builtin = @import("builtin");
const builtin = @import("builtin");
const Config = @import("DocumentStore.zig").Config;
const ast = @import("ast.zig");
const tracy = @import("tracy");
const Ast = std.zig.Ast;
const URI = @import("uri.zig");
const ZCS = @import("ZigCompileServer.zig");
const log = std.log.scoped(.zls_translate_c);

/// converts a `@cInclude` node into an equivalent c header file
/// which can then be handed over to `zig translate-c`
/// Caller owns returned memory.
///
/// **Example**
/// ```zig
/// const glfw = @cImport({
///     @cDefine("GLFW_INCLUDE_VULKAN", {});
///     @cInclude("GLFW/glfw3.h");
/// });
/// ```
/// gets converted into:
/// ```c
/// #define GLFW_INCLUDE_VULKAN
/// #include "GLFW/glfw3.h"
/// ```
pub fn convertCInclude(allocator: std.mem.Allocator, tree: Ast, node: Ast.Node.Index) error{ OutOfMemory, Unsupported }![]const u8 {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const main_tokens = tree.nodes.items(.main_token);

    std.debug.assert(ast.isBuiltinCall(tree, node));
    std.debug.assert(std.mem.eql(u8, Ast.tokenSlice(tree, main_tokens[node]), "@cImport"));

    var output = std.ArrayListUnmanaged(u8){};
    errdefer output.deinit(allocator);

    var buffer: [2]Ast.Node.Index = undefined;
    for (ast.builtinCallParams(tree, node, &buffer).?) |child| {
        var stack_allocator = std.heap.stackFallback(512, allocator);
        try convertCIncludeInternal(allocator, stack_allocator.get(), tree, child, &output);
    }

    return output.toOwnedSlice(allocator);
}

/// HACK self-hosted has not implemented async yet
fn callConvertCIncludeInternal(allocator: std.mem.Allocator, args: anytype) error{ OutOfMemory, Unsupported }!void {
    if (zig_builtin.zig_backend == .other or zig_builtin.zig_backend == .stage1) {
        const FrameSize = @sizeOf(@Frame(convertCIncludeInternal));
        const child_frame = try allocator.alignedAlloc(u8, std.Target.stack_align, FrameSize);
        defer allocator.free(child_frame);

        return await @asyncCall(child_frame, {}, convertCIncludeInternal, args);
    } else {
        // TODO find a non recursive solution
        return @call(.auto, convertCIncludeInternal, args);
    }
}

fn convertCIncludeInternal(
    allocator: std.mem.Allocator,
    stack_allocator: std.mem.Allocator,
    tree: Ast,
    node: Ast.Node.Index,
    output: *std.ArrayListUnmanaged(u8),
) error{ OutOfMemory, Unsupported }!void {
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    var writer = output.writer(allocator);

    var buffer: [2]Ast.Node.Index = undefined;
    if (ast.blockStatements(tree, node, &buffer)) |statements| {
        for (statements) |statement| {
            try callConvertCIncludeInternal(stack_allocator, .{ allocator, stack_allocator, tree, statement, output });
        }
    } else if (ast.builtinCallParams(tree, node, &buffer)) |params| {
        if (params.len < 1) return;

        const call_name = Ast.tokenSlice(tree, main_tokens[node]);

        if (node_tags[params[0]] != .string_literal) return error.Unsupported;
        const first = extractString(Ast.tokenSlice(tree, main_tokens[params[0]]));

        if (std.mem.eql(u8, call_name, "@cInclude")) {
            try writer.print("#include <{s}>\n", .{first});
        } else if (std.mem.eql(u8, call_name, "@cDefine")) {
            if (params.len < 2) return;

            var buffer2: [2]Ast.Node.Index = undefined;
            const is_void = if (ast.blockStatements(tree, params[1], &buffer2)) |block| block.len == 0 else false;

            if (is_void) {
                try writer.print("#define {s}\n", .{first});
            } else {
                if (node_tags[params[1]] != .string_literal) return error.Unsupported;
                const second = extractString(Ast.tokenSlice(tree, main_tokens[params[1]]));
                try writer.print("#define {s} {s}\n", .{ first, second });
            }
        } else if (std.mem.eql(u8, call_name, "@cUndef")) {
            try writer.print("#undef {s}\n", .{first});
        } else {
            return error.Unsupported;
        }
    }
}

pub const Result = union(enum) {
    // uri to the generated zig file
    success: []const u8,
    // zig translate-c failed with the given error messages
    failure: std.zig.ErrorBundle,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |path| allocator.free(path),
            .failure => |*bundle| bundle.deinit(allocator),
        }
    }
};

/// takes a c header file and returns the result from calling `zig translate-c`
/// returns a URI to the generated zig file on success or the content of stderr on failure
/// null indicates a failure which is automatically logged
/// Caller owns returned memory.
pub fn translate(
    allocator: std.mem.Allocator,
    config: Config,
    include_dirs: []const []const u8,
    source: []const u8,
) !?Result {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const file_path = try std.fs.path.join(allocator, &[_][]const u8{ config.global_cache_path.?, "cimport.h" });
    defer allocator.free(file_path);

    var file = std.fs.createFileAbsolute(file_path, .{}) catch |err| {
        log.warn("failed to create file '{s}': {}", .{ file_path, err });
        return null;
    };
    defer file.close();
    defer std.fs.deleteFileAbsolute(file_path) catch |err| {
        log.warn("failed to delete file '{s}': {}", .{ file_path, err });
    };

    file.writeAll(source) catch |err| {
        log.warn("failed to write to '{s}': {}", .{ file_path, err });
        return null;
    };

    const base_args = &[_][]const u8{
        config.zig_exe_path.?,
        "translate-c",
        "--zig-lib-dir",
        config.zig_lib_path.?,
        "--global-cache-dir",
        config.global_cache_path.?,
        "-lc",
        "--listen=-",
    };

    const argc = base_args.len + 2 * include_dirs.len + 1;
    var argv = try std.ArrayListUnmanaged([]const u8).initCapacity(allocator, argc);
    defer argv.deinit(allocator);

    argv.appendSliceAssumeCapacity(base_args);

    for (include_dirs) |include_dir| {
        argv.appendAssumeCapacity("-I");
        argv.appendAssumeCapacity(include_dir);
    }

    argv.appendAssumeCapacity(file_path);

    var process = std.process.Child.init(argv.items, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;

    errdefer |err| if (!zig_builtin.is_test) blk: {
        const joined = std.mem.join(allocator, " ", argv.items) catch break :blk;
        defer allocator.free(joined);
        if (process.stderr) |stderr| {
            const stderr_output = stderr.readToEndAlloc(allocator, std.math.maxInt(usize)) catch break :blk;
            defer allocator.free(stderr_output);
            log.err("failed zig translate-c command:\n{s}\nstderr:{s}\nerror:{}\n", .{ joined, stderr_output, err });
        } else {
            log.err("failed zig translate-c command:\n{s}\nerror:{}\n", .{ joined, err });
        }
    };

    process.spawn() catch |err| {
        log.err("failed to spawn zig translate-c process, error: {}", .{err});
        return null;
    };

    defer _ = process.wait() catch |wait_err| blk: {
        log.err("zig translate-c process did not terminate, error: {}", .{wait_err});
        break :blk process.kill() catch |kill_err| {
            std.debug.panic("failed to terminate zig translate-c process, error: {}", .{kill_err});
        };
    };

    var zcs = ZCS.init(.{
        .gpa = allocator,
        .in = process.stdout.?,
        .out = process.stdin.?,
    });
    defer zcs.deinit();

    try zcs.serveMessage(.{ .tag = .update, .bytes_len = 0 }, &.{});
    try zcs.serveMessage(.{ .tag = .exit, .bytes_len = 0 }, &.{});

    while (true) {
        const header = try zcs.receiveMessage();
        // log.debug("received header: {}", .{header});

        switch (header.tag) {
            .zig_version => {
                // log.debug("zig-version: {s}", .{zcs.receive_fifo.readableSliceOfLen(header.bytes_len)});
                zcs.pooler.fifo(.in).discard(header.bytes_len);
            },
            .emit_bin_path => {
                const body_size = @sizeOf(std.zig.Server.Message.EmitBinPath);
                if (header.bytes_len <= body_size) return error.InvalidResponse;

                _ = try zcs.receiveEmitBinPath();

                const trailing_size = header.bytes_len - body_size;
                const result_path = zcs.pooler.fifo(.in).readableSliceOfLen(trailing_size);

                return Result{ .success = try URI.fromPath(allocator, std.mem.sliceTo(result_path, '\n')) };
            },
            .error_bundle => {
                const error_bundle_header = try zcs.receiveErrorBundle();

                const extra = try zcs.receiveIntArray(allocator, error_bundle_header.extra_len);
                errdefer allocator.free(extra);

                const string_bytes = try zcs.receiveBytes(allocator, error_bundle_header.string_bytes_len);
                errdefer allocator.free(string_bytes);

                const error_bundle = std.zig.ErrorBundle{ .string_bytes = string_bytes, .extra = extra };

                return Result{ .failure = error_bundle };
            },
            else => {
                log.warn("received unexpected message {} from zig compile server", .{header.tag});
                return null;
            },
        }
    }
}

fn extractString(str: []const u8) []const u8 {
    if (std.mem.startsWith(u8, str, "\"") and std.mem.endsWith(u8, str, "\"")) {
        return str[1 .. str.len - 1];
    } else {
        return str;
    }
}
