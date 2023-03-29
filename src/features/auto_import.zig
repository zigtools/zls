// TODO:
// - third party library support (progressive - only crawl
//   them when they're found in an open file, then cache)
// - add ability to decide between full "path" (std.mem.) and
//   import+shortened (const mem = ...; ... mem.)

const std = @import("std");
const log = std.log.scoped(.zls_auto_import);

const Ast = std.zig.Ast;
const ast = @import("../ast.zig");
const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const completions = @import("completions.zig");
const types = @import("../lsp.zig");
const URI = @import("../uri.zig");
const offsets = @import("../offsets.zig");

pub fn init(server: *Server) !Generator {
    const allocator = server.allocator;

    const std_path = try std.fs.path.join(allocator, &.{ server.config.zig_lib_path orelse return .{ .server = server, .arena = std.heap.ArenaAllocator.init(allocator) }, "std", "std.zig" });
    defer allocator.free(std_path);

    const std_uri = try URI.fromPath(allocator, std_path);
    defer allocator.free(std_uri);

    var gen = Generator{ .server = server, .arena = std.heap.ArenaAllocator.init(allocator) };
    try gen.handleScope(try ImportStack.fromSlice(&.{.{ .text = "std", .kind = .import }}), server.document_store.getOrLoadHandle(std_uri).?, 0);
    return gen;
}

pub const ImportSection = struct {
    text: []const u8,
    kind: enum {
        /// [std].[mem].Allocator
        import,
        /// std.mem.[Allocator]
        other,
    },
};
pub const ImportStack = std.BoundedArray(ImportSection, 32);

pub const Generator = struct {
    server: *Server,
    arena: std.heap.ArenaAllocator,
    auto_imports: std.ArrayListUnmanaged(ImportStack) = .{},

    /// The procedure is quite simple;
    /// Find all decls
    /// Find those with @import values
    /// Recurse with the modified stack!
    fn handleScope(gen: *Generator, stack: ImportStack, handle: *const DocumentStore.Handle, scope_idx: usize) !void {
        const allocator = gen.arena.allocator();

        const tree = handle.tree;
        var token_tags = tree.tokens.items(.tag);
        var node_tags = tree.nodes.items(.tag);
        var main_tokens = tree.nodes.items(.main_token);

        var scope_data_list = handle.document_scope.scopes.items(.data);
        var scope_range_list = handle.document_scope.scopes.items(.loc);
        var decls_map_list = handle.document_scope.scopes.items(.decls);
        var child_scopes_list = handle.document_scope.scopes.items(.child_scopes);

        var it = decls_map_list[scope_idx].iterator();
        var init_map = std.AutoHashMapUnmanaged(std.zig.Ast.Node.Index, []const u8){};
        defer init_map.deinit(allocator);

        while (it.next()) |decl_entry| {
            const decl_name = decl_entry.key_ptr.*;
            const decl_data = decl_entry.value_ptr.*;

            switch (decl_data) {
                .ast_node => |node| {
                    var kind: types.CompletionItemKind = switch (node_tags[node]) {
                        .global_var_decl,
                        .local_var_decl,
                        .simple_var_decl,
                        .aligned_var_decl,
                        => if (token_tags[tree.fullVarDecl(node).?.ast.mut_token] == .keyword_const) .Constant else .Variable,
                        .fn_proto,
                        .fn_proto_multi,
                        .fn_proto_one,
                        .fn_proto_simple,
                        .fn_decl,
                        => .Function,
                        else => continue,
                    };
                    _ = kind;

                    // TODO: Do this correctly using Analyser typeval resolution
                    // how does this impact perf?

                    if (!Analyser.isNodePublic(tree, node)) continue;

                    if (tree.fullVarDecl(node)) |full_var| b: {
                        if (full_var.ast.init_node != 0) c: {
                            try init_map.put(allocator, full_var.ast.init_node, decl_name);

                            switch (node_tags[full_var.ast.init_node]) {
                                .builtin_call,
                                .builtin_call_comma,
                                .builtin_call_two,
                                .builtin_call_two_comma,
                                => {},
                                else => break :c,
                            }

                            var buffer: [2]std.zig.Ast.Node.Index = undefined;
                            const params = ast.builtinCallParams(tree, full_var.ast.init_node, &buffer).?;

                            const call_name = tree.tokenSlice(main_tokens[full_var.ast.init_node]);

                            if (!std.mem.eql(u8, call_name, "@import")) break :c;

                            if (params.len == 0) break :c;
                            const import_param = params[0];
                            if (node_tags[import_param] != .string_literal) break :c;

                            const import_str = tree.tokenSlice(main_tokens[import_param]);
                            const import_uri = (try gen.server.document_store.uriFromImportStr(allocator, handle.*, import_str[1 .. import_str.len - 1])) orelse break :c;
                            defer allocator.free(import_uri);

                            const new_handle = gen.server.document_store.getOrLoadHandle(import_uri) orelse break :c;

                            var new_stack = try ImportStack.fromSlice(stack.constSlice());
                            try new_stack.append(.{
                                .text = try allocator.dupe(u8, decl_name),
                                .kind = .import,
                            });

                            try gen.auto_imports.append(allocator, new_stack);
                            try gen.handleScope(new_stack, new_handle, 0);

                            break :b;
                        }

                        if (Analyser.isPascalCase(decl_name)) {
                            var new_stack = try ImportStack.fromSlice(stack.constSlice());
                            try new_stack.append(.{
                                .text = try allocator.dupe(u8, decl_name),
                                .kind = .other,
                            });
                            try gen.auto_imports.append(allocator, new_stack);
                        }
                    }
                },
                else => {},
            }
        }

        for (child_scopes_list[scope_idx].items) |idx| {
            if (scope_data_list[@enumToInt(idx)] != .container) continue;

            if (init_map.get(scope_data_list[@enumToInt(idx)].toNodeIndex().?)) |name| {
                var new_stack = try ImportStack.fromSlice(stack.constSlice());
                try new_stack.append(.{
                    .text = try allocator.dupe(u8, name),
                    .kind = .other,
                });
                try gen.handleScope(new_stack, handle, @enumToInt(idx));
            } else {
                log.warn("Anon fell through @ {s} byte index {d}", .{ handle.uri, scope_range_list[@enumToInt(idx)].start });
            }
        }
    }

    pub fn populate(
        gen: *Generator,
        arena: std.mem.Allocator,
        handle: *const DocumentStore.Handle,
        comps: *std.ArrayListUnmanaged(types.CompletionItem),
    ) !void {
        var name_buf = std.ArrayList(u8).init(arena);

        for (gen.auto_imports.items) |im| {
            const segments = im.constSlice();

            var import_boundary = segments.len;

            while (true) {
                import_boundary -|= 1;
                if (import_boundary == 0 or segments[import_boundary].kind == .import) break;
            }

            name_buf.items.len = 0;

            for (segments[0 .. import_boundary + 1]) |e| {
                try name_buf.appendSlice(e.text);
                try name_buf.append('.');
            }
            name_buf.items.len -|= 1;
            const pre = try arena.dupe(u8, name_buf.items);

            name_buf.items.len = 0;

            for (segments[import_boundary..]) |e| {
                try name_buf.appendSlice(e.text);
                try name_buf.append('.');
            }
            name_buf.items.len -|= 1;
            const post = try arena.dupe(u8, name_buf.items);

            name_buf.items.len = 0;

            for (segments) |e| {
                try name_buf.appendSlice(e.text);
                try name_buf.append('.');
            }
            name_buf.items.len -|= 1;
            const whole = try arena.dupe(u8, name_buf.items);

            var ate = std.ArrayListUnmanaged(types.TextEdit){};
            // TODO: Check if same, rename if already exists
            // e.g. if `Allocator` is already taken, call it `Allocator_0`

            const root_decls = handle.document_scope.scopes.items(.decls)[0];

            if (!root_decls.contains(segments[import_boundary].text)) {
                var lil = getLastImportLineAtTopOfFile(handle);

                try ate.append(arena, .{
                    .range = if (lil) |l| .{
                        .start = .{ .line = l + 1, .character = 0 },
                        .end = .{ .line = l + 1, .character = 0 },
                    } else .{
                        .start = .{ .line = 0, .character = 0 },
                        .end = .{ .line = 0, .character = 0 },
                    },
                    .newText = if (root_decls.contains("std"))
                        try std.fmt.allocPrint(arena, "const {s} = {s};\n{s}", .{ segments[import_boundary].text, pre, if (lil == null) "\n" else "" })
                    else
                        try std.fmt.allocPrint(arena, "const std = @import(\"std\");\nconst {s} = {s};\n{s}", .{ segments[import_boundary].text, pre, if (lil == null) "\n" else "" }),
                });
            }

            try comps.append(arena, .{
                .label = segments[segments.len - 1].text,
                .kind = .Event,
                .insertText = try std.fmt.allocPrint(arena, "{s}", .{post}),
                .sortText = try arena.dupe(u8, &.{ 'z', 'z', 'z', @intCast(u8, segments.len) + 97 }), // zzz puts it after all other (probably more relevant) completions
                .filterText = whole,
                .labelDetails = .{
                    .description = whole,
                },
                .additionalTextEdits = ate.items,
            });
        }
    }
};

/// Just get the last `const abc = ...;` from a file's import block
pub fn getLastImportLineAtTopOfFile(handle: *const DocumentStore.Handle) ?u32 {
    const tree = handle.tree;

    var last_decl: Ast.Node.Index = 0;

    for (tree.rootDecls()) |decl| {
        var full = tree.fullVarDecl(decl) orelse break;
        if (tree.tokenSlice(full.ast.mut_token).len == 3) break;

        last_decl = decl;
    }

    if (last_decl == 0) return null;

    return offsets.nodeToRange(tree, last_decl, .@"utf-8").end.line;
}

// TODO: This can definitely be improved by https://github.com/zigtools/zls/pull/881's
// awesome import management code once that's merged
