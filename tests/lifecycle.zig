const std = @import("std");
const builtin = @import("builtin");
const zls = @import("zls");
const test_options = @import("test_options");

const io = std.testing.io;
const allocator = std.testing.allocator;

test "LSP lifecycle" {
    var environ_map: std.process.Environ.Map = .init(std.testing.failing_allocator);
    var config_manager: zls.configuration.Manager = try .init(io, allocator, &environ_map);
    defer config_manager.deinit();

    var arena_allocator: std.heap.ArenaAllocator = .init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    if (builtin.target.os.tag != .wasi) {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);

        try config_manager.setConfiguration(.frontend, &.{
            .zig_exe_path = try std.fs.path.resolve(arena, &.{ cwd, test_options.zig_exe_path }),
            .zig_lib_path = try std.fs.path.resolve(arena, &.{ cwd, test_options.zig_lib_path }),
            .global_cache_path = try std.fs.path.resolve(arena, &.{ cwd, test_options.global_cache_path }),
        });
    }

    var server: *zls.Server = try .create(.{
        .io = io,
        .allocator = allocator,
        .transport = null,
        .config_manager = &config_manager,
    });
    defer server.destroy();

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
