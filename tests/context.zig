const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");
const test_options = @import("test_options");

const types = zls.lsp.types;

const io = std.testing.io;
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
        if (cached_config_manager == null) {
            var config = default_config;
            defer if (builtin.target.os.tag != .wasi) {
                if (config.zig_exe_path) |zig_exe_path| allocator.free(zig_exe_path);
                if (config.zig_lib_path) |zig_lib_path| allocator.free(zig_lib_path);
                if (config.global_cache_path) |global_cache_path| allocator.free(global_cache_path);
            };
            if (builtin.target.os.tag != .wasi) {
                const cwd = try std.process.currentPathAlloc(io, allocator);
                defer allocator.free(cwd);
                config.zig_exe_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.zig_exe_path });
                config.zig_lib_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.zig_lib_path });
                config.global_cache_path = try std.fs.path.resolve(allocator, &.{ cwd, test_options.global_cache_path });
            }

            const environ_map = try cached_config_arena.allocator().create(std.process.Environ.Map);
            environ_map.* = .init(std.testing.failing_allocator);
            var config_manager: zls.configuration.Manager = try .init(io, cached_config_arena.allocator(), environ_map);
            try config_manager.setConfiguration(.frontend, &config);
            _ = try config_manager.resolveConfiguration(cached_config_arena.allocator());
            cached_config_manager = config_manager;
        }

        const server: *zls.Server = try .create(.{
            .io = io,
            .allocator = allocator,
            .transport = null,
            .config_manager = &cached_config_manager.?,
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
        _ = self.server.sendRequestSync(self.arena.allocator(), "shutdown", {}) catch unreachable;
        self.server.sendNotificationSync(self.arena.allocator(), "exit", {}) catch unreachable;
        std.debug.assert(self.server.status == .exiting_success);
        self.server.destroy();
        self.arena.deinit();
    }

    // helper
    pub fn addDocument(self: *Context, options: struct {
        use_file_scheme: bool = false,
        source: []const u8,
        mode: std.zig.Ast.Mode = .zig,
    }) !zls.Uri {
        const fmt = switch (builtin.os.tag) {
            .windows => "file:///c:/Untitled-{d}.{t}",
            else => "file:///Untitled-{d}.{t}",
        };

        const arena = self.arena.allocator();
        const path = if (options.use_file_scheme)
            try std.fmt.allocPrint(arena, fmt, .{ self.file_id, options.mode })
        else
            try std.fmt.allocPrint(arena, "untitled:///Untitled-{d}.{t}", .{ self.file_id, options.mode });
        const uri: zls.Uri = try .parse(arena, path);

        const params: types.TextDocument.DidOpenParams = .{
            .textDocument = .{
                .uri = uri.raw,
                .languageId = .{ .custom_value = "zig" },
                .version = 420,
                .text = options.source,
            },
        };

        _ = try self.server.sendNotificationSync(arena, "textDocument/didOpen", params);

        self.file_id += 1;
        return uri;
    }
};
