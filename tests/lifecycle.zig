const std = @import("std");
const builtin = @import("builtin");
const zls = @import("zls");
const test_options = @import("test_options");

const allocator = std.testing.allocator;

test "LSP lifecycle" {
    var server = try zls.Server.create(allocator);
    defer server.destroy();

    var zig_exe_path: ?[]const u8 = null;
    var global_cache_path: ?[]const u8 = null;

    defer if (builtin.target.os.tag != .wasi) {
        if (zig_exe_path) |path| allocator.free(path);
        if (global_cache_path) |path| allocator.free(path);
    };
    if (builtin.target.os.tag != .wasi) {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        zig_exe_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.zig_exe_path });
        global_cache_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.global_cache_path });
    }

    try server.updateConfiguration2(.{
        .zig_exe_path = zig_exe_path,
        .zig_lib_path = null,
        .global_cache_path = global_cache_path,
    }, .{});

    var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    try std.testing.expectEqual(zls.Server.Status.uninitialized, server.status);
    _ = try server.sendRequestSync(arena, "initialize", .{ .capabilities = .{} });
    try std.testing.expectEqual(zls.Server.Status.initializing, server.status);
    try server.sendNotificationSync(arena, "initialized", .{});
    try std.testing.expectEqual(zls.Server.Status.initialized, server.status);
    _ = try server.sendRequestSync(arena, "shutdown", {});
    try std.testing.expectEqual(zls.Server.Status.shutdown, server.status);
    try server.sendNotificationSync(arena, "exit", {});
    try std.testing.expectEqual(zls.Server.Status.exiting_success, server.status);
}
