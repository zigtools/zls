//! Implementation of [`textDocument/foldingRange`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_foldingRange)

const std = @import("std");
const Ast = std.zig.Ast;

const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");

const FoldingRange = struct {
    loc: offsets.Loc,
    kind: ?types.FoldingRangeKind = null,
};

const Inclusivity = enum {
    inclusive,
    inclusive_ignore_space,
    exclusive,
    exclusive_ignore_space,
};

const Builder = struct {
    allocator: std.mem.Allocator,
    locations: std.ArrayList(FoldingRange),
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
                .start = switch (start_reach) {
                    .inclusive, .inclusive_ignore_space => start_loc.start,
                    .exclusive => start_loc.end,
                    .exclusive_ignore_space => std.mem.indexOfNonePos(u8, builder.tree.source, start_loc.end, " \t") orelse builder.tree.source.len,
                },
                .end = switch (end_reach) {
                    .inclusive, .inclusive_ignore_space => end_loc.end,
                    .exclusive => end_loc.start,
                    .exclusive_ignore_space => std.mem.lastIndexOfNone(u8, builder.tree.source[0..end_loc.start], " \t") orelse 0,
                },
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

        const result_ranges = try builder.allocator.alloc(types.Range, builder.locations.items.len);
        errdefer builder.allocator.free(result_ranges);

        // one mapping for every start and end position
        var mappings = try builder.allocator.alloc(offsets.multiple.IndexToPositionMapping, builder.locations.items.len * 2);
        defer builder.allocator.free(mappings);

        for (builder.locations.items, result_ranges, 0..) |*folding_range, *result, i| {
            mappings[2 * i + 0] = .{ .output = &result.start, .source_index = folding_range.loc.start };
            mappings[2 * i + 1] = .{ .output = &result.end, .source_index = folding_range.loc.end };
        }

        offsets.multiple.indexToPositionWithMappings(builder.tree.source, mappings, builder.encoding);

        const result_locations = try builder.allocator.alloc(types.FoldingRange, builder.locations.items.len);
        errdefer builder.allocator.free(result_locations);

        for (builder.locations.items, result_ranges, result_locations) |folding_range, range, *result| {
            result.* = .{
                .startLine = range.start.line,
                .startCharacter = range.start.character,
                .endLine = range.end.line,
                .endCharacter = range.end.character,
                .kind = folding_range.kind,
            };
        }

        return result_locations;
    }
};

pub fn generateFoldingRanges(allocator: std.mem.Allocator, tree: Ast, encoding: offsets.Encoding) error{OutOfMemory}![]types.FoldingRange {
    var builder: Builder = .{
        .allocator = allocator,
        .locations = .empty,
        .tree = tree,
        .encoding = encoding,
    };
    defer builder.deinit();

    var start_doc_comment: ?Ast.TokenIndex = null;
    var end_doc_comment: ?Ast.TokenIndex = null;
    for (0..tree.tokens.len) |i| {
        const token: Ast.TokenIndex = @intCast(i);
        switch (tree.tokenTag(token)) {
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

    for (0..tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);

        switch (tree.nodeTag(node)) {
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
                var it = fn_proto.iterate(&tree);

                var last_param: ?Ast.full.FnProto.Param = null;
                while (ast.nextFnParam(&it)) |param| {
                    last_param = param;
                }

                const list_start_tok = fn_proto.lparen;
                const last_param_tok = ast.paramLastToken(tree, last_param orelse continue);
                const param_has_comma = last_param_tok + 1 < tree.tokens.len and tree.tokenTag(last_param_tok + 1) == .comma;
                const list_end_tok = last_param_tok + @intFromBool(param_has_comma);

                try builder.add(null, list_start_tok, list_end_tok, .exclusive, .inclusive);
            },

            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            => {
                try builder.addNode(null, node, .exclusive, .exclusive_ignore_space);
            },
            .@"switch",
            .switch_comma,
            => {
                const lhs = tree.nodeData(node).node_and_extra[0];
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
                    const first_value = switch_case.values[0];
                    const last_value = switch_case.values[switch_case.values.len - 1];

                    const last_token = ast.lastToken(tree, last_value);
                    const last_value_has_comma = last_token + 1 < tree.tokens.len and tree.tokenTag(last_token + 1) == .comma;

                    const start_tok = tree.firstToken(first_value);
                    const end_tok = last_token + @intFromBool(last_value_has_comma);
                    try builder.add(null, start_tok, end_tok, .inclusive, .inclusive);
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
                        (tree.tokenTag(start_tok) == .doc_comment or tree.tokenTag(start_tok) == .container_doc_comment))
                    {
                        start_tok -= 1;
                    }
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive);
                } else { // no members (yet), ie `const T = type {};`
                    var start_tok = tree.firstToken(node);
                    while (tree.tokenTag(start_tok) != .l_brace) start_tok += 1;
                    const end_tok = ast.lastToken(tree, node);
                    try builder.add(null, start_tok, end_tok, .exclusive, .exclusive);
                }
            },

            .call,
            .call_comma,
            .call_one,
            .call_one_comma,
            => {
                const lparen = tree.nodeMainToken(node);
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
    var stack: std.ArrayList(usize) = .empty;
    defer stack.deinit(allocator);

    var i: usize = 0;
    while (std.mem.indexOfPos(u8, tree.source, i, "//#")) |possible_region| {
        defer i = possible_region + "//#".len;
        if (std.mem.startsWith(u8, tree.source[possible_region..], "//#region")) {
            try stack.append(allocator, possible_region);
        } else if (std.mem.startsWith(u8, tree.source[possible_region..], "//#endregion")) {
            const start_index = stack.pop() orelse break; // null means there are more endregions than regions
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
