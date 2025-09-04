//! Implementation of the `translate-c` i.e `@cImport`.

const std = @import("std");
const zig_builtin = @import("builtin");
const DocumentStore = @import("DocumentStore.zig");
const ast = @import("ast.zig");
const tracy = @import("tracy");
const Ast = std.zig.Ast;
const URI = @import("uri.zig");
const log = std.log.scoped(.translate_c);

const OutMessage = std.zig.Client.Message;
const InMessage = std.zig.Server.Message;

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

    std.debug.assert(ast.isBuiltinCall(tree, node));
    std.debug.assert(std.mem.eql(u8, Ast.tokenSlice(tree, tree.nodeMainToken(node)), "@cImport"));

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var buffer: [2]Ast.Node.Index = undefined;
    for (tree.builtinCallParams(&buffer, node).?) |child| {
        try convertCIncludeInternal(allocator, tree, child, &output);
    }

    return output.toOwnedSlice(allocator);
}

fn convertCIncludeInternal(
    allocator: std.mem.Allocator,
    tree: Ast,
    node: Ast.Node.Index,
    output: *std.ArrayList(u8),
) error{ OutOfMemory, Unsupported }!void {
    var buffer: [2]Ast.Node.Index = undefined;
    if (tree.blockStatements(&buffer, node)) |statements| {
        for (statements) |statement| {
            try convertCIncludeInternal(allocator, tree, statement, output);
        }
    } else if (tree.builtinCallParams(&buffer, node)) |params| {
        if (params.len < 1) return;

        const call_name = Ast.tokenSlice(tree, tree.nodeMainToken(node));

        if (tree.nodeTag(params[0]) != .string_literal) return error.Unsupported;
        const first = extractString(Ast.tokenSlice(tree, tree.nodeMainToken(params[0])));

        if (std.mem.eql(u8, call_name, "@cInclude")) {
            try output.print(allocator, "#include <{s}>\n", .{first});
        } else if (std.mem.eql(u8, call_name, "@cDefine")) {
            if (params.len < 2) return;

            var buffer2: [2]Ast.Node.Index = undefined;
            const is_void = if (tree.blockStatements(&buffer2, params[1])) |block| block.len == 0 else false;

            if (is_void) {
                try output.print(allocator, "#define {s}\n", .{first});
            } else {
                if (tree.nodeTag(params[1]) != .string_literal) return error.Unsupported;
                const second = extractString(Ast.tokenSlice(tree, tree.nodeMainToken(params[1])));
                try output.print(allocator, "#define {s} {s}\n", .{ first, second });
            }
        } else if (std.mem.eql(u8, call_name, "@cUndef")) {
            try output.print(allocator, "#undef {s}\n", .{first});
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
    config: DocumentStore.Config,
    include_dirs: []const []const u8,
    c_macros: []const []const u8,
    source: []const u8,
) !?Result {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    const zig_exe_path = config.zig_exe_path.?;
    const zig_lib_dir = config.zig_lib_dir.?;
    const global_cache_dir = config.global_cache_dir.?;

    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [std.fs.base64_encoder.calcSize(16)]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);

    var sub_dir = try global_cache_dir.handle.makeOpenPath(&sub_path, .{});
    defer sub_dir.close();

    sub_dir.writeFile(.{
        .sub_path = "cimport.h",
        .data = source,
    }) catch |err| {
        log.warn("failed to write to '{s}/{s}/cimport.h': {}", .{ global_cache_dir.path orelse ".", sub_path, err });
        return null;
    };

    defer global_cache_dir.handle.deleteTree(&sub_path) catch |err| {
        log.warn("failed to delete '{s}/{s}': {}", .{ global_cache_dir.path orelse ".", sub_path, err });
    };

    const file_path = try std.fs.path.join(allocator, &.{ global_cache_dir.path orelse ".", &sub_path, "cimport.h" });
    defer allocator.free(file_path);

    const base_args = &[_][]const u8{
        zig_exe_path,
        "translate-c",
        "--zig-lib-dir",
        zig_lib_dir.path orelse ".",
        "--cache-dir",
        global_cache_dir.path orelse ".",
        "--global-cache-dir",
        global_cache_dir.path orelse ".",
        "-lc",
        "--listen=-",
    };

    const argc = base_args.len + 2 * include_dirs.len + c_macros.len + 1;
    var argv: std.ArrayList([]const u8) = try .initCapacity(allocator, argc);
    defer argv.deinit(allocator);

    argv.appendSliceAssumeCapacity(base_args);

    for (include_dirs) |include_dir| {
        argv.appendAssumeCapacity("-I");
        argv.appendAssumeCapacity(include_dir);
    }

    argv.appendSliceAssumeCapacity(c_macros);

    argv.appendAssumeCapacity(file_path);

    var process: std.process.Child = .init(argv.items, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Ignore;

    errdefer |err| if (!zig_builtin.is_test) reportTranslateError(allocator, process.stderr, argv.items, @errorName(err));

    process.spawn() catch |err| {
        log.err("failed to spawn zig translate-c process, error: {}", .{err});
        return null;
    };

    defer _ = process.wait() catch |wait_err| {
        log.err("zig translate-c process did not terminate, error: {}", .{wait_err});
    };

    {
        var stdin_writer = process.stdin.?.writer(&.{});
        const writer = &stdin_writer.interface;

        writer.writeStruct(OutMessage.Header{
            .tag = .update,
            .bytes_len = 0,
        }, .little) catch return @as(std.fs.File.WriteError!?Result, stdin_writer.err.?);

        writer.writeStruct(OutMessage.Header{
            .tag = .exit,
            .bytes_len = 0,
        }, .little) catch return @as(std.fs.File.WriteError!?Result, stdin_writer.err.?);
    }

    var poller = std.Io.poll(allocator, enum { stdout }, .{ .stdout = process.stdout.? });
    defer poller.deinit();
    const stdout = poller.reader(.stdout);

    while (true) {
        const timeout: u64 = 20 * std.time.ns_per_s;

        while (stdout.buffered().len < @sizeOf(InMessage.Header)) {
            if (!try poller.pollTimeout(timeout)) return error.EndOfStream;
        }
        const header = stdout.takeStruct(InMessage.Header, .little) catch unreachable;
        while (stdout.buffered().len < header.bytes_len) {
            if (!try poller.pollTimeout(timeout)) return error.EndOfStream;
        }
        const body = stdout.take(header.bytes_len) catch unreachable;
        var reader: std.Io.Reader = .fixed(body);

        // log.debug("received header: {}", .{header});

        switch (header.tag) {
            .zig_version => {
                // log.debug("zig-version: {s}", .{body});
            },
            .emit_digest => {
                _ = reader.takeStruct(std.zig.Server.Message.EmitDigest, .little) catch return error.InvalidMessage;
                const bin_result_path = reader.takeArray(16) catch return error.InvalidMessage;
                if (reader.bufferedLen() != 0) return error.InvalidMessage; // ensure that we read the entire body

                const hex_result_path = std.Build.Cache.binToHex(bin_result_path.*);
                const result_path = try global_cache_dir.join(allocator, &.{ "o", &hex_result_path, "cimport.zig" });
                defer allocator.free(result_path);

                return .{ .success = try URI.fromPath(allocator, std.mem.sliceTo(result_path, '\n')) };
            },
            .error_bundle => {
                const error_bundle_header = reader.takeStruct(InMessage.ErrorBundle, .little) catch return error.InvalidMessage;

                const extra = reader.readSliceEndianAlloc(allocator, u32, error_bundle_header.extra_len, .little) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.EndOfStream => return error.InvalidMessage,
                    error.ReadFailed => unreachable,
                };
                errdefer allocator.free(extra);

                const string_bytes = reader.readAlloc(allocator, error_bundle_header.string_bytes_len) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.EndOfStream => return error.InvalidMessage,
                    error.ReadFailed => unreachable,
                };
                errdefer allocator.free(string_bytes);

                if (reader.bufferedLen() != 0) return error.InvalidMessage; // ensure that we read the entire body

                const error_bundle: std.zig.ErrorBundle = .{ .string_bytes = string_bytes, .extra = extra };

                return .{ .failure = error_bundle };
            },
            else => {},
        }
    }
}

fn reportTranslateError(allocator: std.mem.Allocator, stderr: ?std.fs.File, argv: []const []const u8, err_name: []const u8) void {
    const joined = std.mem.join(allocator, " ", argv) catch return;
    defer allocator.free(joined);
    if (stderr) |file| {
        var buffer: [1024]u8 = undefined;
        var file_reader = file.readerStreaming(&buffer);
        const stderr_output = file_reader.interface.allocRemaining(allocator, .limited(16 * 1024 * 1024)) catch return;
        defer allocator.free(stderr_output);
        log.err("failed zig translate-c command:\n{s}\nstderr:{s}\nerror:{s}\n", .{ joined, stderr_output, err_name });
    } else {
        log.err("failed zig translate-c command:\n{s}\nerror:{s}\n", .{ joined, err_name });
    }
}

fn extractString(str: []const u8) []const u8 {
    if (std.mem.startsWith(u8, str, "\"") and std.mem.endsWith(u8, str, "\"")) {
        return str[1 .. str.len - 1];
    } else {
        return str;
    }
}
