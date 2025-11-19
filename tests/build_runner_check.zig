//! This file implements a standalone executable that is used by
//! `add_build_runner_cases.zig` to run build runner tests.
//! See the `./build_runner_cases` subdirectory.

const std = @import("std");
const zls = @import("zls");

pub fn main() !u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    const cwd = try std.process.getCwdAlloc(gpa);
    defer gpa.free(cwd);

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 7) @panic("invalid arguments");

    const expected = std.fs.cwd().readFileAlloc(args[1], gpa, .limited(16 * 1024 * 1024)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[1], err });
    defer gpa.free(expected);

    const actual = std.fs.cwd().readFileAlloc(args[2], gpa, .limited(16 * 1024 * 1024)) catch |err|
        std.debug.panic("could no open/read file '{s}': {}", .{ args[2], err });
    defer gpa.free(actual);

    std.debug.assert(std.mem.eql(u8, args[3], "--cache-dir"));
    const local_cache_dir = try std.fs.path.resolve(gpa, &.{ cwd, args[4] });
    defer gpa.free(local_cache_dir);

    std.debug.assert(std.mem.eql(u8, args[5], "--global-cache-dir"));
    const global_cache_dir = try std.fs.path.resolve(gpa, &.{ cwd, args[6] });
    defer gpa.free(global_cache_dir);

    const actual_sanitized = sanitized: {
        const parsed = try std.json.parseFromSlice(zls.DocumentStore.BuildConfig, gpa, actual, .{});
        defer parsed.deinit();

        var new: zls.DocumentStore.BuildConfig = parsed.value;
        const arena = parsed.arena.allocator();

        for (new.dependencies.map.keys()) |*str| str.* = try sanitizePath(arena, str.*, cwd, local_cache_dir, global_cache_dir);
        try new.dependencies.map.reIndex(arena);

        for (new.modules.map.keys()) |*str| str.* = try sanitizePath(arena, str.*, cwd, local_cache_dir, global_cache_dir);
        try new.modules.map.reIndex(arena);

        for (new.modules.map.values()) |*mod| {
            for (mod.import_table.map.values()) |*str| str.* = try sanitizePath(arena, str.*, cwd, local_cache_dir, global_cache_dir);
            try mod.import_table.map.reIndex(arena);
        }

        break :sanitized try std.json.Stringify.valueAlloc(
            gpa,
            new,
            .{ .whitespace = .indent_2 },
        );
    };
    defer gpa.free(actual_sanitized);

    if (std.mem.eql(u8, expected, actual_sanitized)) return 0;

    zls.testing.renderLineDiff(gpa, expected, actual_sanitized);

    return 1;
}

fn stripBasePath(base_dir: []const u8, path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, base_dir)) return null;
    if (!std.mem.startsWith(u8, path[base_dir.len..], std.fs.path.sep_str)) return null;
    return path[base_dir.len + std.fs.path.sep_str.len ..];
}

fn sanitizePath(
    arena: std.mem.Allocator,
    path: []const u8,
    cwd: []const u8,
    local_cache_dir: []const u8,
    global_cache_dir: []const u8,
) ![]const u8 {
    const new = try arena.dupe(u8, new: {
        if (stripBasePath(cwd, path)) |foo| {
            break :new foo;
        }
        if (stripBasePath(local_cache_dir, path)) |to| {
            var it = try std.fs.path.componentIterator(to);
            std.debug.assert(std.mem.eql(u8, it.next().?.name, "o"));
            std.debug.assert(it.next().?.name.len == std.Build.Cache.hex_digest_len);
            break :new try std.fmt.allocPrint(arena, ".zig-local-cache/{s}", .{to[it.end_index + 1 ..]});
        }
        if (stripBasePath(global_cache_dir, path)) |to| {
            var it = try std.fs.path.componentIterator(to);
            std.debug.assert(std.mem.eql(u8, it.next().?.name, "o"));
            std.debug.assert(it.next().?.name.len == std.Build.Cache.hex_digest_len);
            break :new try std.fmt.allocPrint(arena, ".zig-global-cache/{s}", .{to[it.end_index + 1 ..]});
        }
        std.debug.assert(!std.fs.path.isAbsolute(path)); // got an absolute path that is not in cwd or any cache dir
        break :new path;
    });

    // Convert windows style '\\' path separators to posix style '/'.
    if (std.fs.path.sep == '\\') {
        for (new) |*c| {
            if (c.* == std.fs.path.sep) c.* = '/';
        }
    }

    return new;
}
