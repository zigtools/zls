const std = @import("std");
const DocumentStore = @import("document_store.zig");
const ast = std.zig.ast;

// ["type","struct","enum","union","parameter","variable","tagField","field","function","keyword","modifier","comment","string","number","operator"]
const TokenType = enum(u32) {
    type,
    @"struct",
    @"enum",
    @"union",
    parameter,
    variable,
    tagField,
    field,
    function,
    keyword,
    modifier,
    comment,
    string,
    number,
    operator,
};

const TokenModifiers = packed struct {
    definition: bool = false,
    @"async": bool = false,
    documentation: bool = false,

    pub fn toInt(value: u32) TokenModifiers {
        return @bitCast(TokenModifiers, value);
    }

    fn toInt(self: TokenModifiers) u32 {
        return @bitCast(u32, self);
    }

    fn with(lhs: TokenModifiers, rhs: TokenModifiers) TokenModifiers {
        return fromInt(toInt(lhs) | toInt(rhs));
    }

    fn intersect(lhs: TokenModifiers, rhs: TokenModifiers) TokenModifiers {
        return fromInt(toInt(lhs) & toInt(rhs));
    }
};

const Builder = struct {
    tree: *ast.Tree,
    current_token: ?ast.TokenIndex,
    arr: std.ArrayList(u32),

    fn printToken(start_idx: usize, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const delta_loc = self.tree.tokenLocationLoc(start_idx, token_loc);
        try out_stream.print(prefix ++ "{},{},{},{},{}", .{
            // TODO Is +1 on the column here correct? I think so.
            delta_loc.line,                  delta_loc.column + 1,
            token_loc.end - token_loc.start, @enumToInt(token_type),
            token_modifiers.toInt(),
        });
    }

    fn create(allocator: *std.mem.Allocator, tree: *ast.Tree) Builder {
        return Builder{
            .tree = tree,
            .current_token = null,
            .arr = std.ArrayList(u32).init(allocator),
        };
    }

    fn add(self: *Builder, out_stream: var, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        if (self.current_token) |current_token| {
            std.debug.assert(token > current_token);
            try out_stream.print(",");
            try printToken(self.tree.token_locs[current_token].end, token, token_type, token_modifiers);
        } else {
            try printToken(0, token, token_type, token_modifiers);
        }
        self.current_token = token;
    }

    pub fn toOwnedSlice(self: *Builder) []u32 {
        return self.arr.toOwnedSlice();
    }
};

pub fn writeAllSemanticTokens(allocator: *std.mem.Allocator, handle: DocumentStore.Handle) ![]u32 {
    // TODO Actual implementation
    var builder = Builder.create(allocator, handle.tree);

    return builder.toOwnedSlice();
}
