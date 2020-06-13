const std = @import("std");
const DocumentStore = @import("document_store.zig");
const ast = std.zig.ast;

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
    builtin,
};

const TokenModifiers = packed struct {
    definition: bool = false,
    @"async": bool = false,
    documentation: bool = false,

    fn toInt(self: TokenModifiers) u32 {
        return @as(u32, @bitCast(u3, self));
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

    fn init(allocator: *std.mem.Allocator, tree: *ast.Tree) Builder {
        return Builder{
            .tree = tree,
            .current_token = null,
            .arr = std.ArrayList(u32).init(allocator),
        };
    }

    fn add(self: *Builder, token: ast.TokenIndex, token_type: TokenType, token_modifiers: TokenModifiers) !void {
        const start_idx = if (self.current_token) |current_token|
            self.tree.token_locs[current_token].start + 1
        else
            0;

        const token_loc = self.tree.token_locs[token];
        const delta_loc = self.tree.tokenLocationLoc(start_idx, token_loc);
        try self.arr.appendSlice(&[_]u32{
            @truncate(u32, if (self.current_token == null) delta_loc.line + 1 else delta_loc.line),
            @truncate(u32, delta_loc.column + 1),
            @truncate(u32, token_loc.end - token_loc.start),
            @enumToInt(token_type),
            token_modifiers.toInt(),
        });
        self.current_token = token;
    }

    fn toOwnedSlice(self: *Builder) []u32 {
        return self.arr.toOwnedSlice();
    }
};

fn isAllDigit(str: []const u8) bool {
    for (str) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn isTypeIdent(tree: *ast.Tree, token_idx: ast.TokenIndex) bool {
    const PrimitiveTypes = std.ComptimeStringMap(void, .{
        .{ .@"0" = "isize" },          .{ .@"0" = "usize" },
        .{ .@"0" = "c_short" },        .{ .@"0" = "c_ushort" },
        .{ .@"0" = "c_int" },          .{ .@"0" = "c_uint" },
        .{ .@"0" = "c_long" },         .{ .@"0" = "c_ulong" },
        .{ .@"0" = "c_longlong" },     .{ .@"0" = "c_ulonglong" },
        .{ .@"0" = "c_longdouble" },   .{ .@"0" = "c_void" },
        .{ .@"0" = "f16" },            .{ .@"0" = "f32" },
        .{ .@"0" = "f64" },            .{ .@"0" = "f128" },
        .{ .@"0" = "bool" },           .{ .@"0" = "void" },
        .{ .@"0" = "noreturn" },       .{ .@"0" = "type" },
        .{ .@"0" = "anyerror" },       .{ .@"0" = "comptime_int" },
        .{ .@"0" = "comptime_float" }, .{ .@"0" = "anyframe" },
    });

    const text = tree.tokenSlice(token_idx);
    if (PrimitiveTypes.has(text)) return true;
    if (text.len > 1 and (text[0] == 'u' or text[0] == 'i') and isAllDigit(text[1..]))
        return true;

    return false;
}

pub fn writeAllSemanticTokens(allocator: *std.mem.Allocator, handle: DocumentStore.Handle) ![]u32 {
    var builder = Builder.init(allocator, handle.tree);

    // TODO We only scan tokens for now, we need to actually do semantic analysis
    for (handle.tree.token_ids) |token_id, token_idx| {
        const token_type: TokenType = switch (token_id) {
            .StringLiteral, .MultilineStringLiteralLine, .CharLiteral => .string,
            .Builtin => .builtin,
            .IntegerLiteral, .FloatLiteral => .number,
            .Bang,
            .Pipe,
            .PipePipe,
            .PipeEqual,
            .Equal,
            .EqualEqual,
            .EqualAngleBracketRight,
            .BangEqual,
            .Percent,
            .PercentEqual,
            .PeriodAsterisk,
            .Caret,
            .CaretEqual,
            .Plus,
            .PlusPlus,
            .PlusEqual,
            .PlusPercent,
            .PlusPercentEqual,
            .Minus,
            .MinusEqual,
            .MinusPercent,
            .MinusPercentEqual,
            .Asterisk,
            .AsteriskEqual,
            .AsteriskAsterisk,
            .AsteriskPercent,
            .AsteriskPercentEqual,
            .Arrow,
            .Slash,
            .SlashEqual,
            .Ampersand,
            .AmpersandEqual,
            .QuestionMark,
            .AngleBracketLeft,
            .AngleBracketLeftEqual,
            .AngleBracketAngleBracketLeft,
            .AngleBracketAngleBracketLeftEqual,
            .AngleBracketRight,
            .AngleBracketRightEqual,
            .AngleBracketAngleBracketRight,
            .AngleBracketAngleBracketRightEqual,
            .Tilde,
            => .operator,
            .LineComment, .DocComment, .ContainerDocComment => .comment,
            .Keyword_align,
            .Keyword_allowzero,
            .Keyword_and,
            .Keyword_asm,
            .Keyword_async,
            .Keyword_await,
            .Keyword_break,
            .Keyword_callconv,
            .Keyword_catch,
            .Keyword_comptime,
            .Keyword_const,
            .Keyword_continue,
            .Keyword_defer,
            .Keyword_else,
            .Keyword_enum,
            .Keyword_errdefer,
            .Keyword_error,
            .Keyword_export,
            .Keyword_extern,
            .Keyword_false,
            .Keyword_fn,
            .Keyword_for,
            .Keyword_if,
            .Keyword_inline,
            .Keyword_noalias,
            .Keyword_noinline,
            .Keyword_nosuspend,
            .Keyword_null,
            .Keyword_or,
            .Keyword_orelse,
            .Keyword_packed,
            .Keyword_anyframe,
            .Keyword_pub,
            .Keyword_resume,
            .Keyword_return,
            .Keyword_linksection,
            .Keyword_struct,
            .Keyword_suspend,
            .Keyword_switch,
            .Keyword_test,
            .Keyword_threadlocal,
            .Keyword_true,
            .Keyword_try,
            .Keyword_undefined,
            .Keyword_union,
            .Keyword_unreachable,
            .Keyword_usingnamespace,
            .Keyword_var,
            .Keyword_volatile,
            .Keyword_while,
            => .keyword,
            .Identifier => if (isTypeIdent(handle.tree, token_idx)) .type else continue,
            else => continue,
        };

        try builder.add(token_idx, token_type, TokenModifiers{});
    }

    return builder.toOwnedSlice();
}
