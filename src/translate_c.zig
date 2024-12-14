//! Implementation of the `translate-c` i.e `@cImport`.

const std = @import("std");
const zig_builtin = @import("builtin");
const Config = @import("DocumentStore.zig").Config;
const ast = @import("ast.zig");
const tracy = @import("tracy");
const Ast = std.zig.Ast;
const URI = @import("uri.zig");
const log = std.log.scoped(.translate_c);

const ZCSTransport = @import("build_runner/shared.zig").Transport;
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

    const main_tokens = tree.nodes.items(.main_token);

    std.debug.assert(ast.isBuiltinCall(tree, node));
    std.debug.assert(std.mem.eql(u8, Ast.tokenSlice(tree, main_tokens[node]), "@cImport"));

    var output = std.ArrayListUnmanaged(u8){};
    errdefer output.deinit(allocator);

    var buffer: [2]Ast.Node.Index = undefined;
    for (ast.builtinCallParams(tree, node, &buffer).?) |child| {
        try convertCIncludeInternal(allocator, tree, child, &output);
    }

    return output.toOwnedSlice(allocator);
}

fn convertCIncludeInternal(
    allocator: std.mem.Allocator,
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
            try convertCIncludeInternal(allocator, tree, statement, output);
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

    const zig_exe_path = config.zig_exe_path.?;
    const zig_lib_path = config.zig_lib_path.?;
    const global_cache_path = config.global_cache_path.?;

    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [std.fs.base64_encoder.calcSize(16)]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);

    var global_cache_dir = try std.fs.openDirAbsolute(global_cache_path, .{});
    defer global_cache_dir.close();

    var sub_dir = try global_cache_dir.makeOpenPath(&sub_path, .{});
    defer sub_dir.close();

    sub_dir.writeFile(.{
        .sub_path = "cimport.h",
        .data = source,
    }) catch |err| {
        log.warn("failed to write to '{s}/{s}/cimport.h': {}", .{ global_cache_path, sub_path, err });
        return null;
    };

    defer global_cache_dir.deleteTree(&sub_path) catch |err| {
        log.warn("failed to delete '{s}/{s}': {}", .{ global_cache_path, sub_path, err });
    };

    const file_path = try std.fs.path.join(allocator, &.{ global_cache_path, &sub_path, "cimport.h" });
    defer allocator.free(file_path);

    const base_args = &[_][]const u8{
        zig_exe_path,
        "translate-c",
        "--zig-lib-dir",
        zig_lib_path,
        "--cache-dir",
        global_cache_path,
        "--global-cache-dir",
        global_cache_path,
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
    process.stderr_behavior = .Ignore;

    errdefer |err| if (!zig_builtin.is_test) reportTranslateError(allocator, process.stderr, argv.items, @errorName(err));

    process.spawn() catch |err| {
        log.err("failed to spawn zig translate-c process, error: {}", .{err});
        return null;
    };

    defer _ = process.wait() catch |wait_err| {
        log.err("zig translate-c process did not terminate, error: {}", .{wait_err});
    };

    var zcs = ZCSTransport.init(.{
        .gpa = allocator,
        .in = process.stdout.?,
        .out = process.stdin.?,
    });
    defer zcs.deinit();

    try zcs.serveMessage(.{ .tag = @intFromEnum(OutMessage.Tag.update), .bytes_len = 0 }, &.{});
    try zcs.serveMessage(.{ .tag = @intFromEnum(OutMessage.Tag.exit), .bytes_len = 0 }, &.{});

    while (true) {
        const header = try zcs.receiveMessage(20 * std.time.ns_per_s);
        // log.debug("received header: {}", .{header});

        switch (@as(InMessage.Tag, @enumFromInt(header.tag))) {
            .zig_version => {
                // log.debug("zig-version: {s}", .{zcs.receive_fifo.readableSliceOfLen(header.bytes_len)});
                zcs.discard(header.bytes_len);
            },
            .emit_digest => {
                const expected_size: usize = @sizeOf(std.zig.Server.Message.EmitDigest) + 16;
                if (header.bytes_len != expected_size) return error.InvalidResponse;

                zcs.discard(@sizeOf(InMessage.EmitDigest));

                const bin_result_path = try zcs.reader().readBytesNoEof(16);
                const hex_result_path = std.Build.Cache.binToHex(bin_result_path);
                const result_path = try std.fs.path.join(allocator, &.{ global_cache_path, "o", &hex_result_path, "cimport.zig" });
                defer allocator.free(result_path);

                return .{ .success = try URI.fromPath(allocator, std.mem.sliceTo(result_path, '\n')) };
            },
            .error_bundle => {
                if (header.bytes_len < @sizeOf(InMessage.ErrorBundle)) return error.InvalidResponse;

                const error_bundle_header: InMessage.ErrorBundle = .{
                    .extra_len = try zcs.reader().readInt(u32, .little),
                    .string_bytes_len = try zcs.reader().readInt(u32, .little),
                };

                const expected_size = @sizeOf(InMessage.ErrorBundle) + error_bundle_header.extra_len * @sizeOf(u32) + error_bundle_header.string_bytes_len;
                if (header.bytes_len != expected_size) return error.InvalidResponse;

                const extra = try zcs.receiveSlice(allocator, u32, error_bundle_header.extra_len);
                errdefer allocator.free(extra);

                const string_bytes = try zcs.receiveBytes(allocator, error_bundle_header.string_bytes_len);
                errdefer allocator.free(string_bytes);

                const error_bundle: std.zig.ErrorBundle = .{ .string_bytes = string_bytes, .extra = extra };

                return .{ .failure = error_bundle };
            },
            else => {
                zcs.discard(header.bytes_len);
            },
        }
    }
}

fn reportTranslateError(allocator: std.mem.Allocator, stderr: ?std.fs.File, argv: []const []const u8, err_name: []const u8) void {
    const joined = std.mem.join(allocator, " ", argv) catch return;
    defer allocator.free(joined);
    if (stderr) |file| {
        const stderr_output = file.readToEndAlloc(allocator, 16 * 1024 * 1024) catch return;
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
