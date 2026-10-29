//! Implementation of [`textDocument/foldingRange`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_foldingRange)

const std = @import("std");
const Ast = @import("zirp").Ast;

const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");
const tracy = @import("tracy");

pub const Error = error{ OutOfMemory, Canceled, InvalidParams };

pub fn @"textDocument/foldingRange"(
    server: *Server,
    arena: std.mem.Allocator,
    request: types.FoldingRange.Params,
) Error!?[]types.FoldingRange {
    const document_uri = Uri.parse(arena, request.textDocument.uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;
    return try generateFoldingRanges(arena, &handle.tree, server.offset_encoding);
}

const FoldingRange = struct {
    loc: offsets.Loc,
    kind: ?types.FoldingRange.Kind = null,
};

const Inclusivity = enum {
    /// Include the token itself as part of the folding range.
    inclusive,
    /// Do not include the token itself as part of the folding range.
    exclusive,
    /// Same as `exclusive` but will also not include any adjacent whitespace.
    exclusive_ignore_space,
};

/// Check if a node is an @import() call or an alias/field access based on an import.
/// This drills down field accesses to find the base, assuming identifiers are aliases.
fn isImportOrAlias(tree: *const Ast, init_node: Ast.Node.Index) bool {
    var node = init_node;
    while (true) {
        switch (node.tag(tree)) {
            .expr_builtin_call => { // Check if this is @import("...")
                const expr: Ast.Expr.Builtin = node.cast(.expr_builtin_call, tree).?;
                const token = expr.callee.token(tree);
                const builtin_name = offsets.tokenToSlice(tree, token);
                if (!std.mem.eql(u8, builtin_name, "@import")) return false;

                var it = expr.args.iter(tree);
                const first_param = it.next(tree) orelse return false;
                if (it.next(tree) != null) return false;

                return first_param.cast(.string, tree) != null;
            },
            .expr_dot_access => {
                // Field access like @import("foo").bar or std.ascii
                // Continue drilling down to check the left side
                const expr: Ast.Expr.DotAccess = node.cast(.expr_dot_access, tree).?;
                node = expr.lhs.idx;
            },
            .leaf => {
                // Assume identifiers are aliases like `const ascii = std.ascii`
                return ast.identifierTokenFromIdentifierNode(tree, node) != null;
            },
            else => return false,
        }
    }
}

const Builder = struct {
    allocator: std.mem.Allocator,
    locations: std.ArrayList(FoldingRange),
    tree: *const Ast,
    encoding: offsets.Encoding,

    fn deinit(builder: *Builder) void {
        builder.locations.deinit(builder.allocator);
    }

    fn add(
        builder: *Builder,
        kind: ?types.FoldingRange.Kind,
        start: Ast.Token.Index,
        end: Ast.Token.Index,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        if (@backingInt(start) >= @backingInt(end)) return;
        if (ast.tokensOnSameLine(builder.tree, start, end)) return;

        const start_index = switch (start_reach) {
            .inclusive => start.byteOffset(builder.tree),
            .exclusive => offsets.tokenToLoc(builder.tree, start).end,
            .exclusive_ignore_space => blk: {
                const start_index = offsets.tokenToLoc(builder.tree, start).end;
                const end_index = end.byteOffset(builder.tree);
                break :blk std.mem.findNonePos(u8, builder.tree.source[0..end_index], start_index, " \t") orelse end_index;
            },
        };

        const end_index = switch (end_reach) {
            .inclusive => offsets.tokenToLoc(builder.tree, end).end,
            .exclusive => end.byteOffset(builder.tree),
            .exclusive_ignore_space => std.mem.findLastNone(u8, builder.tree.source[0..end.byteOffset(builder.tree)], " \t") orelse 0,
        };

        std.debug.assert(start_index <= end_index);
        if (start_index == end_index) return;

        try builder.locations.append(builder.allocator, .{
            .loc = .{ .start = start_index, .end = end_index },
            .kind = kind,
        });
    }

    fn addNode(
        builder: *Builder,
        kind: ?types.FoldingRange.Kind,
        node: Ast.Node.Index,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        try builder.add(kind, node.firstToken(builder.tree), ast.lastToken(builder.tree, node), start_reach, end_reach);
    }

    fn getRanges(builder: Builder) error{OutOfMemory}![]types.FoldingRange {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const result_ranges = try builder.allocator.alloc(types.Range, builder.locations.items.len);
        errdefer builder.allocator.free(result_ranges);

        // one mapping for every start and end position
        var mappings = try builder.allocator.alloc(offsets.multiple.IndexToPositionMapping, builder.locations.items.len * 2);
        defer builder.allocator.free(mappings);

        for (builder.locations.items, result_ranges, 0..) |folding_range, *result, i| {
            mappings[2 * i + 0] = .{ .output = &result.start, .source_index = folding_range.loc.start };
            mappings[2 * i + 1] = .{ .output = &result.end, .source_index = folding_range.loc.end };
        }

        offsets.multiple.indexToPositionWithMappings(builder.tree.source, mappings, builder.encoding);

        var result_locations: std.ArrayList(types.FoldingRange) = try .initCapacity(builder.allocator, builder.locations.items.len);
        errdefer result_locations.deinit(builder.allocator);

        for (builder.locations.items, result_ranges) |folding_range, range| {
            if (range.start.line == range.end.line) continue;
            result_locations.appendAssumeCapacity(.{
                .startLine = range.start.line,
                .startCharacter = range.start.character,
                .endLine = range.end.line,
                .endCharacter = range.end.character,
                .kind = folding_range.kind,
                // TODO this should be simplified https://codeberg.org/ziglang/zig/issues/30627
                .collapsedText = if (folding_range.kind != null and folding_range.kind.? == .imports) "@import(...)" else null,
            });
        }

        return try result_locations.toOwnedSlice(builder.allocator);
    }
};

fn generateFoldingRanges(allocator: std.mem.Allocator, tree: *const Ast, encoding: offsets.Encoding) error{OutOfMemory}![]types.FoldingRange {
    var builder: Builder = .{
        .allocator = allocator,
        .locations = .empty,
        .tree = tree,
        .encoding = encoding,
    };
    defer builder.deinit();

    var start_doc_comment: ?Ast.Token.Index = null;
    var end_doc_comment: ?Ast.Token.Index = null;
    for (0..tree.tokens.len()) |i| {
        const token: Ast.Token.Index = @fromBackingInt(@intCast(i));
        switch (token.tag(tree)) {
            .doc_comment,
            .container_doc_comment,
            => {
                if (start_doc_comment == null) {
                    start_doc_comment = token;
                    end_doc_comment = token;
                } else {
                    end_doc_comment = token;
                }
            },
            else => {
                if (start_doc_comment != null and end_doc_comment != null) {
                    try builder.add(.comment, start_doc_comment.?, end_doc_comment.?, .inclusive, .inclusive);
                    start_doc_comment = null;
                    end_doc_comment = null;
                }
            },
        }
    }

    // TODO add folding range normal comments

    // Folding range for top level imports
    if (tree.mode == .zig) blk: {
        var start_import: ?Ast.Member.GlobalVar.Index = null;
        var end_import: ?Ast.Member.GlobalVar.Index = null;
        var import_count: usize = 0;

        const root_members = tree.root().members;
        var it = root_members.iter(tree);
        while (it.next(tree)) |member| {
            const import_member = import_member: {
                const var_decl_index = member.cast(.@"var", tree) orelse break :import_member null;
                const var_decl = var_decl_index.get(tree);
                const init_expr = var_decl.init orelse break :import_member null;
                if (!isImportOrAlias(tree, init_expr.idx)) break :import_member null;
                break :import_member var_decl_index;
            };

            if (import_member) |var_decl| {
                if (start_import == null) {
                    start_import = var_decl;
                }
                end_import = var_decl;
                import_count += 1;
                continue;
            }
            defer {
                start_import = null;
                end_import = null;
                import_count = 0;
            }

            const start = start_import orelse continue;
            const end = end_import orelse continue;
            if (import_count < 3) continue;
            try builder.add(.imports, start.idx.firstToken(tree), ast.lastToken(tree, end.idx).add(1), .inclusive, .inclusive);
        }

        // Handle the case where imports continue to the end of the file
        const start = start_import orelse break :blk;
        const end = end_import orelse break :blk;
        if (import_count < 3) break :blk;
        try builder.add(.imports, start.idx.firstToken(tree), ast.lastToken(tree, end.idx).add(1), .inclusive, .inclusive);
    }

    for (0..tree.nodes.len()) |i| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(i));

        switch (node.tag(tree)) {
            .root => continue,
            // TODO: Should folding multiline condition expressions also be supported? Ditto for the other control flow structures.

            .type_fn => {
                const fn_proto: Ast.Expr.Fn = node.cast(.type_fn, tree).?;
                const params = fn_proto.params.get(tree).items;

                var last_param: ?Ast.Expr.Fn.Param.Index = null;
                var it = params.iter(tree);
                while (it.next(tree)) |param| last_param = param;

                const list_start_tok = fn_proto.@"fn".token(tree).add(1);
                const last_param_tok = (last_param orelse continue).idx.lastToken(tree);
                const param_has_comma = @backingInt(last_param_tok.add(1)) < tree.tokens.len() and last_param_tok.add(1).tag(tree) == .@",";
                const list_end_tok = last_param_tok.add(@intFromBool(param_has_comma));

                try builder.add(null, list_start_tok, list_end_tok, .exclusive, .inclusive);
            },

            .block => {
                try builder.addNode(null, node, .exclusive, .exclusive_ignore_space);
            },

            .expr_switch => {
                const expr: Ast.Expr.Switch = node.cast(.expr_switch, tree).?;
                const start_tok = ast.lastToken(tree, expr.condition.idx).add(2); // lparen + rbrace
                const end_tok = ast.lastToken(tree, node);
                try builder.add(null, start_tok, end_tok, .exclusive, .exclusive_ignore_space);
            },

            .switch_prong => {
                const switch_prong: Ast.Expr.Switch.Prong = node.cast(.switch_prong, tree).?;
                if (true) @panic("BRANCH_TODO");
                if (switch_prong.cases.len >= 4) {
                    const first_value = switch_prong.cases[0];
                    const last_value = switch_prong.cases[switch_prong.cases.len - 1];

                    const last_token = ast.lastToken(tree, last_value);
                    const last_value_has_comma = last_token + 1 < tree.tokens.len() and last_token.add(1).tag(tree) == .@",";

                    const start_tok = first_value.firstToken(tree);
                    const end_tok = last_token + @intFromBool(last_value_has_comma);
                    try builder.add(null, start_tok, end_tok, .inclusive, .inclusive);
                }
            },

            .type_container => {
                const expr: Ast.Expr.Container = node.cast(.type_container, tree).?;
                var it = expr.members.iter(tree);
                if (it.next(tree)) |first_member| {
                    var start_tok = first_member.idx.firstToken(tree).addClamp(-1);
                    while (@backingInt(start_tok) != 0 and
                        (start_tok.tag(tree) == .doc_comment or start_tok.tag(tree) == .container_doc_comment))
                    {
                        start_tok = start_tok.add(-1);
                    }
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive_ignore_space);
                } else { // no members (yet), ie `const T = type {};`
                    var start_tok = node.firstToken(tree);
                    while (start_tok.tag(tree) != .@"{") start_tok = start_tok.add(1);
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive_ignore_space);
                }
            },

            .expr_call,
            .expr_init,
            => {
                const start = node.mainToken(tree);
                try builder.add(null, start, ast.lastToken(tree, node), .exclusive, .exclusive_ignore_space);
            },
            .expr_builtin_call,
            .type_error_set,
            => {
                const start = node.mainToken(tree).add(1);
                try builder.add(null, start, ast.lastToken(tree, node), .exclusive, .exclusive_ignore_space);
            },
            .leaf => {
                switch (node.mainToken(tree).tag(tree)) {
                    .multiline_string_line => {
                        try builder.addNode(null, node, .inclusive, .inclusive);
                    },
                    else => {},
                }
            },

            else => {},
        }
    }

    // We add opened folding regions to a stack as we go and pop one off when we find a closing brace.
    var stack: std.ArrayList(usize) = .empty;
    defer stack.deinit(allocator);

    var i: usize = 0;
    while (std.mem.findPos(u8, tree.source, i, "//#")) |possible_region| {
        i = possible_region + "//#".len;
        i = std.mem.findScalarPos(u8, tree.source, i, '\n') orelse tree.source.len;

        if (std.mem.startsWith(u8, tree.source[possible_region..], "//#region")) {
            try stack.append(allocator, possible_region);
        } else if (std.mem.startsWith(u8, tree.source[possible_region..], "//#endregion")) {
            const start_index = stack.pop() orelse break; // null means there are more endregions than regions
            try builder.locations.append(allocator, .{
                .loc = .{
                    .start = start_index,
                    .end = i,
                },
                .kind = .region,
            });
        }
    }

    return try builder.getRanges();
}
