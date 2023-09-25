const std = @import("std");
const Ast = std.zig.Ast;

const ast = @import("../ast.zig");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");
const tracy = @import("../tracy.zig");

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

    fn deinit(builder: *Builder) void {
        builder.locations.deinit(builder.allocator);
    }

    fn add(
        builder: *Builder,
        kind: ?types.FoldingRangeKind,
        start: Ast.TokenIndex,
        end: Ast.TokenIndex,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        if (start >= end) return;
        if (builder.tree.tokensOnSameLine(start, end)) return;
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

    fn addNode(
        builder: *Builder,
        kind: ?types.FoldingRangeKind,
        node: Ast.Node.Index,
        start_reach: Inclusivity,
        end_reach: Inclusivity,
    ) error{OutOfMemory}!void {
        try builder.add(kind, builder.tree.firstToken(node), ast.lastToken(builder.tree, node), start_reach, end_reach);
    }

    fn getRanges(builder: Builder) error{OutOfMemory}![]types.FoldingRange {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        var result_locations = try builder.allocator.alloc(types.FoldingRange, builder.locations.items.len);
        errdefer builder.allocator.free(result_locations);

        for (builder.locations.items, result_locations) |folding_range, *result| {
            result.* = .{
                .startLine = undefined,
                .endLine = undefined,
                .kind = folding_range.kind,
            };
        }

        // a mapping from a source index to a line character pair
        const IndexToPositionEntry = struct {
            output: *types.FoldingRange,
            source_index: usize,
            where: enum { start, end },

            const Self = @This();

            fn lessThan(_: void, lhs: Self, rhs: Self) bool {
                return lhs.source_index < rhs.source_index;
            }
        };

        // one mapping for every start and end position
        var mappings = try builder.allocator.alloc(IndexToPositionEntry, builder.locations.items.len * 2);
        defer builder.allocator.free(mappings);

        for (builder.locations.items, result_locations, 0..) |*folding_range, *result, i| {
            mappings[2 * i + 0] = .{ .output = result, .source_index = folding_range.loc.start, .where = .start };
            mappings[2 * i + 1] = .{ .output = result, .source_index = folding_range.loc.end, .where = .end };
        }

        // sort mappings based on their source index
        std.mem.sort(IndexToPositionEntry, mappings, {}, IndexToPositionEntry.lessThan);

        var last_index: usize = 0;
        var last_position: types.Position = .{ .line = 0, .character = 0 };
        for (mappings) |mapping| {
            const index = mapping.source_index;
            const position = offsets.advancePosition(builder.tree.source, last_position, last_index, index, builder.encoding);
            defer last_index = index;
            defer last_position = position;

            switch (mapping.where) {
                .start => {
                    mapping.output.startLine = position.line;
                    mapping.output.startCharacter = position.character;
                },
                .end => {
                    mapping.output.endLine = position.line;
                    mapping.output.endCharacter = position.character;
                },
            }
        }

        return result_locations;
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
    for (token_tags, 0..) |tag, i| {
        const token: Ast.TokenIndex = @intCast(i);
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

    for (node_tags, 0..) |node_tag, i| {
        const node: Ast.Node.Index = @intCast(i);

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

                if (fn_proto.ast.params.len != 0) {
                    const list_start_tok = fn_proto.lparen;
                    const last_param = fn_proto.ast.params[fn_proto.ast.params.len - 1];
                    const last_param_tok = ast.lastToken(tree, last_param);
                    const param_has_comma = last_param_tok + 1 < tree.tokens.len and token_tags[last_param_tok + 1] == .comma;
                    const list_end_tok = last_param_tok + @intFromBool(param_has_comma);

                    if (list_start_tok > list_end_tok) continue; // Incomplete, ie `fn a()`
                    try builder.add(null, list_start_tok, list_end_tok, .exclusive, .inclusive);
                }
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
                    var start_tok = tree.firstToken(first_member) -| 1;
                    while (start_tok != 0 and
                        (token_tags[start_tok] == .doc_comment or
                        token_tags[start_tok] == .container_doc_comment))
                    {
                        start_tok -= 1;
                    }
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive);
                } else { // no members (yet), ie `const T = type {};`
                    var start_tok = tree.firstToken(node);
                    while(token_tags[start_tok] != .l_brace) start_tok += 1;
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
    defer stack.deinit(allocator);

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
