const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");
const test_options = @import("test_options");

const types = zls.lsp.types;

const allocator = std.testing.allocator;

const default_config: zls.configuration.UnresolvedConfig = .{
    .semantic_tokens = .full,
    .prefer_ast_check_as_child_process = false,
    .inlay_hints_exclude_single_argument = false,
    .inlay_hints_show_builtin = true,
};

pub const Context = struct {
    server: *zls.Server,
    arena: std.heap.ArenaAllocator,
    file_id: u32 = 0,

    var cached_config_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    var cached_config_manager: ?zls.configuration.Manager = null;

    pub fn init() !Context {
        const config_manager = cached_config_manager orelse config_manager: {
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

            var config_manager: zls.configuration.Manager = .init(cached_config_arena.allocator());
            try config_manager.setConfiguration(.frontend, &config);
            _ = try config_manager.resolveConfiguration(cached_config_arena.allocator());
            cached_config_manager = config_manager;
            break :config_manager config_manager;
        };

        const server: *zls.Server = try .create(.{
            .allocator = allocator,
            .transport = null,
            .config = null,
            .config_manager = config_manager,
        });
        errdefer server.destroy();

        std.debug.assert(server.config_manager.zig_lib_dir != null);
        std.debug.assert(server.document_store.config.zig_lib_dir != null);

        std.debug.assert(server.config_manager.global_cache_dir != null);
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
        self.server.config_manager = .init(undefined);

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
            .windows => "c:/nonexistent/test-{d}.{t}",
            else => "/nonexistent/test-{d}.{t}",
        };

        const uri = options.uri orelse uri: {
            const path = try std.fmt.allocPrint(
                self.arena.allocator(),
                fmt,
                .{ self.file_id, options.mode },
            );
            break :uri try zls.URI.fromPath(self.arena.allocator(), path);
        };

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
