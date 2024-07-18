const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");
const test_options = @import("test_options");

const Config = zls.Config;
const Server = zls.Server;
const types = zls.types;

const default_config: Config = .{
    .semantic_tokens = .full,
    .enable_inlay_hints = true,
    .inlay_hints_exclude_single_argument = false,
    .inlay_hints_show_builtin = true,

    .zig_exe_path = test_options.zig_exe_path,
    .zig_lib_path = test_options.zig_lib_path,
    .global_cache_path = test_options.global_cache_path,
};

const allocator = std.testing.allocator;

pub const Context = struct {
    server: *Server,
    arena: std.heap.ArenaAllocator,
    file_id: u32 = 0,

    var resolved_config_arena: std.heap.ArenaAllocator.State = undefined;
    var resolved_config: ?Config = null;

    pub fn init() !Context {
        const server = try Server.create(allocator);
        errdefer server.destroy();

        if (resolved_config) |config| {
            // The configuration has previously been resolved an stored in `resolved_config`
            try server.updateConfiguration2(config, .{ .resolve = false });
        } else {
            try server.updateConfiguration2(default_config, .{});

            const config_string = try std.json.stringifyAlloc(allocator, server.config, .{ .whitespace = .indent_2 });
            defer allocator.free(config_string);

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            errdefer arena.deinit();

            const duped_config = try std.json.parseFromSliceLeaky(Config, arena.allocator(), config_string, .{ .allocate = .alloc_always });

            resolved_config_arena = arena.state;
            resolved_config = duped_config;
        }

        var context: Context = .{
            .server = server,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };

        _ = try context.server.sendRequestSync(context.arena.allocator(), "initialize", .{ .capabilities = .{} });
        _ = try context.server.sendNotificationSync(context.arena.allocator(), "initialized", .{});

        return context;
    }

    pub fn deinit(self: *Context) void {
        _ = self.server.sendRequestSync(self.arena.allocator(), "shutdown", {}) catch unreachable;
        self.server.sendNotificationSync(self.arena.allocator(), "exit", {}) catch unreachable;
        std.debug.assert(self.server.status == .exiting_success);
        self.server.destroy();
        self.arena.deinit();
    }

    // helper
    pub fn addDocument(self: *Context, source: []const u8) ![]const u8 {
        const fmt = switch (builtin.os.tag) {
            .windows => "file:///C:\\nonexistent\\test-{d}.zig",
            else => "file:///nonexistent/test-{d}.zig",
        };
        const uri = try std.fmt.allocPrint(
            self.arena.allocator(),
            fmt,
            .{self.file_id},
        );

        const params = types.DidOpenTextDocumentParams{
            .textDocument = .{
                .uri = uri,
                .languageId = "zig",
                .version = 420,
                .text = source,
            },
        };

        _ = try self.server.sendNotificationSync(self.arena.allocator(), "textDocument/didOpen", params);

        self.file_id += 1;
        return uri;
    }
};
