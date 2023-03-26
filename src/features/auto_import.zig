// TODO:
// - third party library support (progressive - only crawl
//   them when they're found in an open file, then cache)
// - UX improvements?
// - add ability to decide between full "path" (std.mem.) and
//   import+shortened (const mem = ...; ... mem.)

const std = @import("std");
const log = std.log.scoped(.zls_auto_import);

const ast = @import("../ast.zig");
const Server = @import("../Server.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const completions = @import("completions.zig");
const types = @import("../lsp.zig");
const URI = @import("../uri.zig");

pub fn populate(server: *Server, comps: *std.ArrayListUnmanaged(types.CompletionItem)) !void {
    const allocator = server.allocator;

    const std_path = try std.fs.path.join(allocator, &.{ server.config.zig_lib_path orelse return, "std", "std.zig" });
    defer allocator.free(std_path);

    const std_uri = try URI.fromPath(allocator, std_path);
    defer allocator.free(std_uri);

    var gen = Generator{ .server = server, .completions = comps };
    try gen.handleScope(try Generator.ImportStack.fromSlice(&.{"std"}), server.document_store.getOrLoadHandle(std_uri).?, 0);

    gen.name_buf.deinit(allocator);
}

pub const Generator = struct {
    pub const ImportStack = std.BoundedArray([]const u8, 32);

    server: *Server,
    completions: *std.ArrayListUnmanaged(types.CompletionItem),
    name_buf: std.ArrayListUnmanaged(u8) = .{},

    /// The procedure is quite simple;
    /// Find all decls
    /// Find those with @import values
    /// Recurse with the modified stack!
    fn handleScope(gen: *Generator, stack: ImportStack, handle: *const DocumentStore.Handle, scope_idx: usize) !void {
        const allocator = gen.server.allocator;

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

                    // TODO: Do this correctly using Analyser typeval resolution
                    // how does this impact perf?

                    if (!Analyser.isNodePublic(tree, node)) continue;

                    var should_add = Analyser.isPascalCase(decl_name);

                    if (tree.fullVarDecl(node)) |full_var| b: {
                        if (full_var.ast.init_node != 0) {
                            try init_map.put(allocator, full_var.ast.init_node, decl_name);

                            switch (node_tags[full_var.ast.init_node]) {
                                .builtin_call,
                                .builtin_call_comma,
                                .builtin_call_two,
                                .builtin_call_two_comma,
                                => {},
                                else => break :b,
                            }

                            var buffer: [2]std.zig.Ast.Node.Index = undefined;
                            const params = ast.builtinCallParams(tree, full_var.ast.init_node, &buffer).?;

                            const call_name = tree.tokenSlice(main_tokens[full_var.ast.init_node]);

                            if (!std.mem.eql(u8, call_name, "@import")) break :b;

                            if (params.len == 0) break :b;
                            const import_param = params[0];
                            if (node_tags[import_param] != .string_literal) break :b;

                            const import_str = tree.tokenSlice(main_tokens[import_param]);
                            const import_uri = (try gen.server.document_store.uriFromImportStr(allocator, handle.*, import_str[1 .. import_str.len - 1])) orelse break :b;
                            defer allocator.free(import_uri);

                            const new_handle = gen.server.document_store.getOrLoadHandle(import_uri) orelse break :b;

                            var new_stack = try ImportStack.fromSlice(stack.constSlice());
                            try new_stack.append(decl_name);
                            try gen.handleScope(new_stack, new_handle, 0);

                            should_add = true;
                        }
                    }

                    if (should_add) {
                        gen.name_buf.items.len = 0;

                        for (stack.constSlice()) |part|
                            try gen.name_buf.writer(allocator).print("{s}.", .{part});
                        gen.name_buf.items.len -|= 1;

                        const desc = try allocator.dupe(u8, gen.name_buf.items);
                        const insert = try std.mem.join(allocator, ".", &.{ desc, decl_name });

                        try gen.completions.append(allocator, .{
                            .label = try allocator.dupe(u8, decl_name),
                            .kind = kind,
                            .labelDetails = .{
                                .description = desc,
                            },
                            .insertText = insert,
                            .filterText = insert,
                            .sortText = desc,
                            .commitCharacters = &.{"."},
                        });
                    }
                },
                else => {},
            }
        }

        for (child_scopes_list[scope_idx].items) |idx| {
            if (scope_data_list[@enumToInt(idx)] != .container) continue;

            if (init_map.get(scope_data_list[@enumToInt(idx)].toNodeIndex().?)) |name| {
                var new_stack = try ImportStack.fromSlice(stack.constSlice());
                try new_stack.append(name);
                try gen.handleScope(new_stack, handle, @enumToInt(idx));
            } else {
                log.warn("Anon fell through @ {s} byte index {d}", .{ handle.uri, scope_range_list[@enumToInt(idx)].start });
            }
        }
    }
};
