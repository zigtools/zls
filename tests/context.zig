const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");
const test_options = @import("test_options");

const Config = zls.Config;
const Server = zls.Server;
const types = zls.lsp.types;

const allocator = std.testing.allocator;

const default_config: Config = .{
    .semantic_tokens = .full,
    .inlay_hints_exclude_single_argument = false,
    .inlay_hints_show_builtin = true,
};

pub const Context = struct {
    server: *Server,
    arena: std.heap.ArenaAllocator,
    file_id: u32 = 0,

    var config_arena: std.heap.ArenaAllocator.State = .{};
    var cached_config: ?Config = null;
    var cached_resolved_config: ?@FieldType(Server, "resolved_config") = null;

    pub fn init() !Context {
        const server = try Server.create(allocator);
        errdefer server.destroy();

        if (cached_config == null and cached_resolved_config == null) {
            var config = default_config;
            defer if (builtin.target.os.tag != .wasi) {
                if (config.zig_exe_path) |zig_exe_path| allocator.free(zig_exe_path);
                if (config.zig_lib_path) |zig_lib_path| allocator.free(zig_lib_path);
                if (config.global_cache_path) |global_cache_path| allocator.free(global_cache_path);
            };
            if (builtin.target.os.tag != .wasi) {
                const cwd = try std.process.getCwdAlloc(allocator);
                defer allocator.free(cwd);
                config.zig_exe_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.zig_exe_path });
                config.zig_lib_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.zig_lib_path });
                config.global_cache_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.global_cache_path });
            }

            try server.updateConfiguration2(config, .{ .leaky_config_arena = true });
        } else {
            // the configuration has previously been resolved and cached.
            server.config_arena = config_arena;
            server.config = cached_config.?;
            server.resolved_config = cached_resolved_config.?;

            try server.updateConfiguration2(server.config, .{ .leaky_config_arena = true, .resolve = false });
        }

        std.debug.assert(server.resolved_config.zig_lib_dir != null);
        std.debug.assert(server.document_store.config.zig_lib_dir != null);
        std.debug.assert(server.resolved_config.global_cache_dir != null);
        std.debug.assert(server.document_store.config.global_cache_dir != null);

        var context: Context = .{
            .server = server,
            .arena = .init(allocator),
        };

        _ = try context.server.sendRequestSync(context.arena.allocator(), "initialize", .{ .capabilities = .{} });
        _ = try context.server.sendNotificationSync(context.arena.allocator(), "initialized", .{});

        return context;
    }

    pub fn deinit(self: *Context) void {
        config_arena = self.server.config_arena;
        cached_config = self.server.config;
        cached_resolved_config = self.server.resolved_config;

        self.server.config_arena = .{};
        self.server.config = .{};
        self.server.resolved_config = .unresolved;

        _ = self.server.sendRequestSync(self.arena.allocator(), "shutdown", {}) catch unreachable;
        self.server.sendNotificationSync(self.arena.allocator(), "exit", {}) catch unreachable;
        std.debug.assert(self.server.status == .exiting_success);
        self.server.destroy();
        self.arena.deinit();
    }

    // helper
    pub fn addDocument(self: *Context, options: struct {
        uri: ?[]const u8 = null,
        source: []const u8,
        mode: std.zig.Ast.Mode = .zig,
    }) ![]const u8 {
        const fmt = switch (builtin.os.tag) {
            .windows => "file:///C:\\nonexistent\\test-{d}.{s}",
            else => "file:///nonexistent/test-{d}.{s}",
        };
        const uri = options.uri orelse try std.fmt.allocPrint(
            self.arena.allocator(),
            fmt,
            .{ self.file_id, @tagName(options.mode) },
        );

        const params: types.DidOpenTextDocumentParams = .{
            .textDocument = .{
                .uri = uri,
                .languageId = "zig",
                .version = 420,
                .text = options.source,
            },
        };

        _ = try self.server.sendNotificationSync(self.arena.allocator(), "textDocument/didOpen", params);

        self.file_id += 1;
        return uri;
    }
};
