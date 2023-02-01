const std = @import("std");
const ast = @import("ast.zig");
const types = @import("lsp.zig");
const offsets = @import("offsets.zig");
const Ast = std.zig.Ast;

const FoldingRange = struct {
    loc: offsets.Loc,
    kind: ?types.FoldingRangeKind = null,
};

const Inclusivity = enum { inclusive, exclusive };

const Builder = struct {
    allocator: std.mem.Allocator,
    locations: std.ArrayListUnmanaged(FoldingRange),
    tree: Ast,
    encoding: offsets.Encoding,

    pub fn deinit(builder: *Builder) void {
        builder.locations.deinit(builder.allocator);
    }

    pub fn add(
        builder: *Builder,
        kind: ?types.FoldingRangeKind,
        start: Ast.TokenIndex,
        end: Ast.TokenIndex,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        if (builder.tree.tokensOnSameLine(start, end)) return;
        std.debug.assert(start <= end);
        const start_loc = offsets.tokenToLoc(builder.tree, start);
        const end_loc = offsets.tokenToLoc(builder.tree, end);

        try builder.locations.append(builder.allocator, .{
            .loc = .{
                .start = if (start_reach == .exclusive) start_loc.end else start_loc.start,
                .end = if (end_reach == .exclusive) end_loc.start else end_loc.end,
            },
            .kind = kind,
        });
    }

    pub fn addNode(
        builder: *Builder,
        kind: ?types.FoldingRangeKind,
        node: Ast.Node.Index,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        try builder.add(kind, builder.tree.firstToken(node), ast.lastToken(builder.tree, node), start_reach, end_reach);
    }

    pub fn getRanges(builder: Builder) error{OutOfMemory}![]types.FoldingRange {
        var result = try builder.allocator.alloc(types.FoldingRange, builder.locations.items.len);
        errdefer builder.allocator.free(result);

        for (result) |*r, i| {
            r.* = .{
                .startLine = undefined,
                .endLine = undefined,
                .kind = builder.locations.items[i].kind,
            };
        }

        const Item = struct {
            output: *types.FoldingRange,
            input: *const FoldingRange,
            where: enum { start, end },

            const Self = @This();

            fn getInputIndex(self: Self) usize {
                return switch (self.where) {
                    .start => self.input.loc.start,
                    .end => self.input.loc.end,
                };
            }

            fn lessThan(_: void, lhs: Self, rhs: Self) bool {
                return lhs.getInputIndex() < rhs.getInputIndex();
            }
        };

        // one item for every start and end position
        var items = try builder.allocator.alloc(Item, builder.locations.items.len * 2);
        defer builder.allocator.free(items);

        for (builder.locations.items) |*folding_range, i| {
            items[2 * i + 0] = .{ .output = &result[i], .input = folding_range, .where = .start };
            items[2 * i + 1] = .{ .output = &result[i], .input = folding_range, .where = .end };
        }

        // sort items based on their source position
        std.sort.sort(Item, items, {}, Item.lessThan);

        var last_index: usize = 0;
        var last_position: types.Position = .{ .line = 0, .character = 0 };
        for (items) |item| {
            const index = item.getInputIndex();
            const position = offsets.advancePosition(builder.tree.source, last_position, last_index, index, builder.encoding);
            defer last_index = index;
            defer last_position = position;

            switch (item.where) {
                .start => {
                    item.output.startLine = position.line;
                    item.output.startCharacter = position.character;
                },
                .end => {
                    item.output.endLine = position.line;
                    item.output.endCharacter = position.character;
                },
            }
        }

        return result;
    }
};

pub fn generateFoldingRanges(allocator: std.mem.Allocator, tree: Ast, encoding: offsets.Encoding) error{OutOfMemory}![]types.FoldingRange {
    var builder = Builder{
        .allocator = allocator,
        .locations = .{},
        .tree = tree,
        .encoding = encoding,
    };
    defer builder.deinit();

    const token_tags = tree.tokens.items(.tag);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    var start_doc_comment: ?Ast.TokenIndex = null;
    var end_doc_comment: ?Ast.TokenIndex = null;
    for (token_tags) |tag, i| {
        const token = @intCast(Ast.TokenIndex, i);
        switch (tag) {
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

    // TODO add folding range for top level `@Import()`

    for (node_tags) |node_tag, i| {
        const node = @intCast(Ast.Node.Index, i);

        switch (node_tag) {
            .root => continue,
            // TODO: Should folding multiline condition expressions also be supported? Ditto for the other control flow structures.

            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            // .fn_decl
            => {
                var buffer: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buffer, node).?;

                const list_start_tok = fn_proto.lparen;
                const list_end_tok = ast.lastToken(tree, node) -| 1;

                try builder.add(null, list_start_tok, list_end_tok, .exclusive, .exclusive);
            },

            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            => {
                try builder.addNode(null, node, .exclusive, .exclusive);
            },
            .@"switch",
            .switch_comma,
            => {
                const lhs = tree.nodes.items(.data)[node].lhs;
                const start_tok = ast.lastToken(tree, lhs) + 2; // lparen + rbrace
                const end_tok = ast.lastToken(tree, node);
                try builder.add(null, start_tok, end_tok, .exclusive, .exclusive);
            },

            .switch_case_one,
            .switch_case_inline_one,
            .switch_case,
            .switch_case_inline,
            => {
                const switch_case = tree.fullSwitchCase(node).?.ast;
                if (switch_case.values.len >= 4) {
                    const first_value = tree.firstToken(switch_case.values[0]);
                    const last_value = ast.lastToken(tree, switch_case.values[switch_case.values.len - 1]);
                    try builder.add(null, first_value, last_value, .inclusive, .inclusive);
                }
            },

            .container_decl,
            .container_decl_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const container_decl = tree.fullContainerDecl(&buffer, node).?;
                if (container_decl.ast.members.len != 0) {
                    const first_member = container_decl.ast.members[0];
                    const start_tok = tree.firstToken(first_member) -| 1;
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive);
                }
            },

            .call,
            .call_comma,
            .call_one,
            .call_one_comma,
            .async_call,
            .async_call_comma,
            .async_call_one,
            .async_call_one_comma,
            => {
                const lparen = main_tokens[node];
                try builder.add(null, lparen, ast.lastToken(tree, node), .exclusive, .exclusive);
            },

            // everything after here is mostly untested
            .array_init,
            .array_init_one,
            .array_init_dot_two,
            .array_init_one_comma,
            .array_init_dot_two_comma,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init_comma,

            .struct_init,
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init_comma,

            .builtin_call,
            .builtin_call_comma,
            .builtin_call_two,
            .builtin_call_two_comma,

            .multiline_string_literal,
            .error_set_decl,
            .test_decl,
            => {
                try builder.addNode(null, node, .inclusive, .inclusive);
            },

            else => {},
        }
    }

    // We add opened folding regions to a stack as we go and pop one off when we find a closing brace.
    var stack = std.ArrayListUnmanaged(usize){};

    var i: usize = 0;
    while (std.mem.indexOfPos(u8, tree.source, i, "//#")) |possible_region| {
        defer i = possible_region + "//#".len;
        if (std.mem.startsWith(u8, tree.source[possible_region..], "//#region")) {
            try stack.append(allocator, possible_region);
        } else if (std.mem.startsWith(u8, tree.source[possible_region..], "//#endregion")) {
            const start_index = stack.popOrNull() orelse break; // null means there are more endregions than regions
            const end_index = offsets.lineLocAtIndex(tree.source, possible_region).end;
            const is_same_line = std.mem.indexOfScalar(u8, tree.source[start_index..end_index], '\n') == null;
            if (is_same_line) continue;
            try builder.locations.append(allocator, .{
                .loc = .{
                    .start = start_index,
                    .end = end_index,
                },
                .kind = .region,
            });
        }
    }

    return try builder.getRanges();
}
