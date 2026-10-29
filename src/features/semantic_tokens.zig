//! Implementation of [`textDocument/semanticTokens/*`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_semanticTokens)

const std = @import("std");
const Ast = @import("zirp").Ast;

const offsets = @import("../offsets.zig");
const DocumentStore = @import("../DocumentStore.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const Server = @import("../Server.zig");
const Uri = @import("../Uri.zig");

pub const TokenType = enum(u32) {
    namespace,
    type,
    class,
    @"enum",
    interface,
    @"struct",
    typeParameter,
    parameter,
    variable,
    property,
    enumMember,
    event,
    function,
    method,
    macro,
    keyword,
    modifier,
    comment,
    string,
    escapeSequence,
    number,
    regexp,
    operator,
    decorator,
    /// non standard token type
    errorTag,
    /// non standard token type
    builtin,
    /// non standard token type
    label,
    /// non standard token type
    keywordLiteral,
};

pub const TokenModifiers = packed struct(u16) {
    declaration: bool = false,
    definition: bool = false,
    readonly: bool = false,
    static: bool = false,
    deprecated: bool = false,
    abstract: bool = false,
    async: bool = false,
    modification: bool = false,
    documentation: bool = false,
    defaultLibrary: bool = false,
    // non standard token modifiers
    generic: bool = false,
    mutable: bool = false,
    _: u4 = 0,

    pub fn format(modifiers: TokenModifiers, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(".{");
        var i: usize = 0;
        inline for (@typeInfo(TokenModifiers).@"struct".field_names) |field_name| {
            if ((comptime !std.mem.eql(u8, field_name, "_")) and @field(modifiers, field_name)) {
                if (i == 0) {
                    try writer.writeAll(" .");
                } else {
                    try writer.writeAll(", .");
                }
                try writer.writeAll(field_name);
                try writer.writeAll(" = true");
                i += 1;
            }
        }
        try writer.writeAll(" }");
    }
};

pub const Error = Analyser.Error || error{InvalidParams};

pub fn @"textDocument/semanticTokens/full"(server: *Server, arena: std.mem.Allocator, request: types.semantic_tokens.Params) Error!?types.semantic_tokens.Result {
    return try semanticTokens(
        server,
        arena,
        request.textDocument.uri,
        null,
    );
}

pub fn @"textDocument/semanticTokens/range"(server: *Server, arena: std.mem.Allocator, request: types.semantic_tokens.Params.Range) Error!?types.semantic_tokens.Result {
    return try semanticTokens(
        server,
        arena,
        request.textDocument.uri,
        request.range,
    );
}

const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    previous_source_index: usize = 0,
    source_index: usize = 0,
    token_buffer: std.ArrayList(u32) = .empty,
    encoding: offsets.Encoding,
    limited: bool,
    overlappingTokenSupport: bool,
    /// Only emit tokens for the given source range.
    loc: ?offsets.Loc,

    fn add(self: *Builder, token: Ast.Token.Index, token_type: TokenType, token_modifiers: TokenModifiers) error{OutOfMemory}!void {
        const tree = &self.handle.tree;

        try self.handleComments(self.previous_source_index, token.byteOffset(tree));
        try self.addDirect(token_type, token_modifiers, offsets.tokenToLoc(tree, token));
    }

    fn finish(self: *Builder) error{OutOfMemory}!types.semantic_tokens.Result {
        try self.handleComments(self.previous_source_index, self.handle.tree.source.len);
        return .{ .data = try self.token_buffer.toOwnedSlice(self.arena) };
    }

    /// Highlight normal comments and doc comments.
    fn handleComments(self: *Builder, from: usize, to: usize) error{OutOfMemory}!void {
        if (from >= to) return;

        const source = self.handle.tree.source;

        var i: usize = from;
        while (i < to) : (i += 1) {
            // Skip multi-line string literals
            if (source[i] == '\\' and source[i + 1] == '\\') {
                while (i < to and source[i] != '\n') : (i += 1) {}
                continue;
            }
            // Skip normal string literals
            if (source[i] == '"') {
                i += 1;
                while (i < to and
                    source[i] != '\n' and
                    !(source[i] == '"' and source[i - 1] != '\\')) : (i += 1)
                {}
                continue;
            }
            // Skip char literals
            if (source[i] == '\'') {
                i += 1;
                while (i < to and
                    source[i] != '\n' and
                    !(source[i] == '\'' and source[i - 1] != '\\')) : (i += 1)
                {}
                continue;
            }

            if (source[i] != '/' or source[i + 1] != '/')
                continue;

            const comment_start = i;
            var mods = TokenModifiers{};
            if (i + 2 < to and (source[i + 2] == '!' or source[i + 2] == '/'))
                mods.documentation = true;

            while (i < to and source[i] != '\n') : (i += 1) {}

            try self.addDirect(.comment, mods, .{ .start = comment_start, .end = i });
        }
    }

    fn addDirect(self: *Builder, token_type: TokenType, token_modifiers: TokenModifiers, loc: offsets.Loc) error{OutOfMemory}!void {
        std.debug.assert(loc.start <= loc.end);
        std.debug.assert(self.previous_source_index <= self.source_index);
        if (loc.start < self.previous_source_index) return;
        if (!self.overlappingTokenSupport and loc.start < self.source_index) return;
        switch (token_type) {
            .namespace,
            .type,
            .class,
            .@"enum",
            .interface,
            .@"struct",
            .typeParameter,
            .parameter,
            .variable,
            .property,
            .enumMember,
            .event,
            .function,
            .method,
            .macro,
            .modifier,
            .regexp,
            .decorator,
            .errorTag,
            => {},

            .builtin => if (self.limited and !token_modifiers.deprecated) return,

            .keyword,
            .comment,
            .string,
            .escapeSequence,
            .number,
            .operator,
            .label,
            .keywordLiteral,
            => if (self.limited) return,
        }

        const source = self.handle.tree.source;
        const delta_text = source[self.previous_source_index..loc.start];
        const delta = offsets.indexToPosition(delta_text, delta_text.len, self.encoding);
        const length = offsets.locLength(source, loc, self.encoding);

        // assert that the `@intCast(length)` below is safe
        comptime std.debug.assert(std.zig.max_src_size == std.math.maxInt(u32));

        try self.token_buffer.appendSlice(self.arena, &.{
            delta.line,
            delta.character,
            @intCast(length),
            @backingInt(token_type),
            @as(u16, @bitCast(token_modifiers)),
        });
        self.previous_source_index = loc.start;
        self.source_index = loc.end;
    }
};

fn writeToken(builder: *Builder, token_idx: ?Ast.Token.Index, tok_type: TokenType) error{OutOfMemory}!void {
    return try writeTokenMod(builder, token_idx, tok_type, .{});
}

fn writeTokenMod(builder: *Builder, token_idx: ?Ast.Token.Index, tok_type: TokenType, tok_mod: TokenModifiers) error{OutOfMemory}!void {
    if (token_idx) |ti| {
        try builder.add(ti, tok_type, tok_mod);
    }
}

fn colorIdentifierBasedOnType(
    builder: *Builder,
    type_node: Analyser.Type,
    target_tok: Ast.Token.Index,
    is_parameter: bool,
    tok_mod: TokenModifiers,
) error{OutOfMemory}!void {
    if (type_node.is_type_val) {
        const token_type: TokenType = if (type_node.isNamespace())
            .namespace
        else if (type_node.isStructType(builder.analyser))
            .@"struct"
        else if (type_node.isEnumType())
            .@"enum"
        else if (type_node.isUnionType())
            .type // There is no token type for a union type
        else if (type_node.isOpaqueType())
            .type // There is no token type for an opaque
        else if (is_parameter)
            .typeParameter
        else
            .type;

        try writeTokenMod(builder, target_tok, token_type, tok_mod);
    } else if (type_node.isTypeFunc()) {
        try writeTokenMod(builder, target_tok, .type, tok_mod);
    } else if (type_node.isFunc()) {
        var new_tok_mod = tok_mod;
        if (type_node.isGenericFunc()) {
            new_tok_mod.generic = true;
        }

        const has_self_param = try builder.analyser.hasSelfParam(type_node);

        try writeTokenMod(builder, target_tok, if (has_self_param) .method else .function, new_tok_mod);
    } else {
        var new_tok_mod = tok_mod;
        if (type_node.data == .compile_error) {
            new_tok_mod.deprecated = true;
        }
        try writeTokenMod(builder, target_tok, if (is_parameter) .parameter else .variable, new_tok_mod);
    }
}

fn writeNodeTokens(builder: *Builder, node: Ast.Node.Index) Analyser.Error!void {
    const handle = builder.handle;
    const tree = &handle.tree;

    if (builder.loc) |loc| {
        if (!offsets.locIntersect(loc, offsets.nodeToLoc(tree, node))) return;
    }

    const main_token = node.mainToken(tree);

    switch (node.tag(tree)) {
        else => |tag| std.debug.panic("BRANCH_TODO: writeNodeTokens(.{t})", .{tag}),
        .root => unreachable,
        .missing, .none => {},
        .leaf => {
            switch (main_token.tag(tree)) {
                else => |tag| std.debug.panic("BRANCH_TODO: writeNodeTokens(.{t})", .{tag}),
                .name => try writeIdentifier(builder, main_token),
                .string, .char => {
                    try writeToken(builder, main_token, .string);
                    if (!builder.limited and builder.overlappingTokenSupport) {
                        const string_start = main_token.byteOffset(tree);
                        const string = offsets.nodeToSlice(tree, node);
                        var offset: usize = 0;
                        while (offset < string.len) {
                            const slash_index = std.mem.findScalarPos(u8, string, offset, '\\') orelse break;
                            offset = slash_index;
                            _ = std.zig.string_literal.parseEscapeSequence(string, &offset);
                            try builder.addDirect(.escapeSequence, .{}, .{
                                .start = slash_index + string_start,
                                .end = offset + string_start,
                            });
                        }
                    }
                },
                .multiline_string_line => {
                    const multiline_string_line: Ast.Expr.MultilineString.Index = .{ .idx = node };
                    var it = multiline_string_line.get(tree).iter;
                    while (it.next(tree)) |_| {
                        try writeToken(builder, it.current, .string);
                    }
                },
                .@"unreachable" => try writeToken(builder, main_token, .keywordLiteral),
                .number => try writeToken(builder, main_token, .number),
            }
        },
        .leaf_enum_literal => {
            try writeToken(builder, main_token, .enumMember);
        },
        .member_field => {
            const member_field: Ast.Member.Field = node.cast(.member_field, tree).?;
            try writeContainerField(builder, member_field, null);
        },
        .block => {
            const block: Ast.Block = node.cast(.block, tree).?;
            if (block.label(tree)) |label_token| {
                try writeTokenMod(builder, label_token, .label, .{ .declaration = true });
            }

            var it = block.statements.iter(tree);
            while (it.next(tree)) |child| {
                try writeNodeTokens(builder, child.idx);
            }
        },
        .var_local => {
            const resolved_type = try builder.analyser.resolveTypeOfNode(.of(node, handle));
            try writeVarDecl(builder, ast.globalVarFromLocal(.{ .idx = node }, tree), true, resolved_type);
        },
        .var_global => {
            const resolved_type = try builder.analyser.resolveTypeOfNode(.of(node, handle));
            try writeVarDecl(builder, node.cast(.var_global, tree).?, false, resolved_type);
        },
        .type_container => {
            const decl: Ast.Expr.Container = node.cast(.type_container, tree).?;

            const attributes = decl.attributes(tree);
            if (attributes.@"extern") |token| try writeToken(builder, token, .keyword);
            if (attributes.@"packed") |token| try writeToken(builder, token, .keyword);

            const kind_token = switch (decl.kind.get(tree)) {
                .@"enum" => |enum_idx| switch (enum_idx.get(tree)) {
                    .@"enum" => |v| v.token(tree),
                    .with_backing => @panic("BRANCH_TODO"),
                },
                .@"union" => |union_idx| switch (union_idx.get(tree)) {
                    .@"union" => |v| v.token(tree),
                    .with_backing => @panic("BRANCH_TODO"),
                },
                .@"struct" => |struct_idx| switch (struct_idx.get(tree)) {
                    .@"struct" => |v| v.token(tree),
                    .with_backing => @panic("BRANCH_TODO"),
                },
                .@"opaque" => |opaque_idx| opaque_idx.token(tree),
            };

            try writeToken(builder, kind_token, .keyword);

            var it = decl.members.iter(tree);
            while (it.next(tree)) |member| {
                if (member.cast(.field, tree)) |member_field| {
                    try writeContainerField(builder, member_field.get(tree), decl);
                } else {
                    try writeNodeTokens(builder, member.idx);
                }
            }
        },
        .type_error_set => {
            const expr: Ast.Expr.ErrorSet = node.cast(.type_error_set, tree).?;

            try writeToken(builder, node.mainToken(tree), .keyword);

            var it = expr.errors.iter(tree);
            while (it.next(tree)) |err| {
                const error_token = err.get(tree).token;
                try writeTokenMod(builder, error_token, .errorTag, .{ .declaration = true });
            }
        },
        .expr_error => {
            const expr: Ast.Expr.Error = node.cast(.expr_error, tree).?;

            const error_token = node.mainToken(tree);
            try writeToken(builder, error_token, .keyword);

            const name_token = expr.rhs.token(tree);
            try writeToken(builder, name_token, .errorTag);
        },
        .type_fn,
        .decl_fn,
        => |tag| {
            const fn_proto: Ast.Expr.Fn, const attributes: Ast.Member.Fn.Attributes, const body: ?Ast.Block.Index = switch (tag) {
                .type_fn => blk: {
                    const fn_proto = node.cast(.type_fn, tree).?;
                    const attributes = fn_proto.attributes(tree);
                    break :blk .{ fn_proto, .{
                        .@"pub" = null,
                        .@"export" = null,
                        .@"inline" = null,
                        .@"noinline" = null,
                        .@"extern" = null,

                        .@"align" = attributes.@"align",
                        .@"callconv" = attributes.@"callconv",
                        .@"addrspace" = attributes.@"addrspace",
                        .@"linksection" = attributes.@"linksection",
                    }, null };
                },
                .decl_fn => blk: {
                    const decl_fn = node.cast(.decl_fn, tree).?;
                    break :blk .{
                        decl_fn.proto.get(tree),
                        decl_fn.attributes(tree),
                        decl_fn.body,
                    };
                },
                else => unreachable,
            };
            const fn_token = fn_proto.@"fn".token(tree);

            try writeToken(builder, attributes.@"pub", .keyword);
            try writeToken(builder, attributes.@"export" orelse attributes.@"inline" orelse attributes.@"noinline", .keyword);
            if (attributes.@"extern") |@"extern"| {
                try writeToken(builder, @"extern".@"extern", .keyword);
                try writeToken(builder, @"extern".string, .keyword);
            }
            try writeToken(builder, fn_token, .keyword);

            var is_generic = false;
            var func_name_tok_type: TokenType = .function;
            if (try builder.analyser.resolveTypeOfNode(.of(node, handle))) |func_ty| {
                is_generic = func_ty.isGenericFunc();
                if (func_ty.isTypeFunc()) {
                    func_name_tok_type = .type;
                } else {
                    const container_ty = try builder.analyser.innermostContainer(handle, fn_token.byteOffset(tree));
                    if (container_ty.data.container.scope_handle.scope != .root and
                        builder.analyser.firstParamIs(func_ty, container_ty))
                    {
                        func_name_tok_type = .method;
                    }
                }
            }

            const tok_mod: TokenModifiers = .{
                .declaration = true,
                .generic = is_generic,
            };

            try writeTokenMod(builder, fn_proto.name(tree), func_name_tok_type, tok_mod);

            var it = fn_proto.params.get(tree).items.iter(tree);
            while (it.next(tree)) |param_idx| {
                const param = param_idx.get(tree);
                const param_attributes = param.attributes(tree);
                const param_type = param.type.get(tree);

                try writeToken(builder, param_attributes.@"noalias" orelse param_attributes.@"comptime", .keyword);

                if (param.name) |name| {
                    const token_type: TokenType = switch (param_type) {
                        .expr => .parameter,
                        .@"anytype" => .typeParameter,
                        .varargs => .parameter,
                    };
                    try writeTokenMod(builder, name.token(tree), token_type, .{ .declaration = true });
                }

                switch (param_type) {
                    .expr => |expr_node| try writeNodeTokens(builder, expr_node.idx),
                    .@"anytype" => |leaf_node| try writeToken(builder, leaf_node.token(tree), .type),
                    .varargs => |leaf_node| try writeToken(builder, leaf_node.token(tree), .type),
                }
            }

            if (attributes.@"align") |align_expr| {
                try writeToken(builder, align_expr.idx.firstToken(tree).add(-2), .keyword);
                try writeNodeTokens(builder, align_expr.idx);
            }
            if (attributes.@"addrspace") |addrspace_expr| {
                try writeToken(builder, addrspace_expr.idx.firstToken(tree).add(-2), .keyword);
                try writeNodeTokens(builder, addrspace_expr.idx);
            }
            if (attributes.@"linksection") |section_expr| {
                try writeToken(builder, section_expr.idx.firstToken(tree).add(-2), .keyword);
                try writeNodeTokens(builder, section_expr.idx);
            }
            if (attributes.@"callconv") |callconv_expr| {
                try writeToken(builder, callconv_expr.idx.firstToken(tree).add(-2), .keyword);
                try writeNodeTokens(builder, callconv_expr.idx);
            }
            try writeNodeTokens(builder, fn_proto.return_type.idx);

            if (body) |body_idx| {
                try writeNodeTokens(builder, body_idx.idx);
            }
        },
        .stmt_defer => {
            const stmt: Ast.Statement.Defer = node.cast(.stmt_defer, tree).?;
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, stmt.body.idx);
        },
        .expr_switch => {
            const expr: Ast.Expr.Switch = node.cast(.expr_switch, tree).?;
            try writeTokenMod(builder, expr.label(tree), .label, .{ .declaration = true });
            try writeToken(builder, expr.@"switch".token(tree), .keyword);
            try writeNodeTokens(builder, expr.condition.idx);
            var it = expr.prongs.iter(tree);
            while (it.next(tree)) |prong| {
                try writeNodeTokens(builder, prong.idx);
            }
        },
        .switch_prong => {
            const prong: Ast.Expr.Switch.Prong = node.cast(.switch_prong, tree).?;
            const attributes = prong.attributes(tree);

            try writeToken(builder, attributes.@"inline", .keyword);
            var case_it = prong.cases.iter(tree);
            while (case_it.next(tree)) |case| {
                switch (case.get(tree)) {
                    .item => |case_expr| try writeNodeTokens(builder, case_expr.idx),
                    .range => |range_idx| {
                        const range = range_idx.get(tree);
                        try writeNodeTokens(builder, range.start.idx);
                        try writeNodeTokens(builder, range.end.idx);
                    },
                    .@"else" => |else_node| try writeToken(builder, else_node.token(tree), .keyword),
                }
            }
            if (prong.payload) |payload| try writePayload(builder, payload.get(tree));
            try writeNodeTokens(builder, prong.body.idx);
        },
        .expr_while => {
            const expr: Ast.Expr.While = node.cast(.expr_while, tree).?;
            const attributes = expr.attributes(tree);

            try writeTokenMod(builder, expr.label(tree), .label, .{ .declaration = true });

            try writeToken(builder, attributes.@"inline", .keyword);
            try writeToken(builder, expr.@"while".token(tree), .keyword);
            try writeNodeTokens(builder, expr.condition.idx);
            if (expr.payload) |payload| try writePayload(builder, payload.get(tree));
            if (expr.advance) |advance_expr| try writeNodeTokens(builder, advance_expr.idx);
            try writeNodeTokens(builder, expr.body.idx);
            if (expr.else_payload) |payload| try writePayload(builder, payload.get(tree));
        },
        .expr_for => {
            const expr: Ast.Expr.For = node.cast(.expr_for, tree).?;
            const attributes = expr.attributes(tree);

            try writeTokenMod(builder, expr.label(tree), .label, .{ .declaration = true });
            try writeToken(builder, attributes.@"inline", .keyword);
            try writeToken(builder, expr.@"for".token(tree), .keyword);

            var it = expr.inputs.get(tree).items.iter(tree);
            while (it.next(tree)) |input| {
                switch (input.get(tree)) {
                    .expr => |expr_node| try writeNodeTokens(builder, expr_node.idx),
                    .range => |range_node| {
                        const range = range_node.get(tree);
                        try writeNodeTokens(builder, range.start.idx);
                        if (range.end) |end| try writeNodeTokens(builder, end.idx);
                    },
                }
            }
            try writeNodeTokens(builder, expr.body.idx);

            if (expr.@"else") |else_expr| {
                // BRANCH_TODO try writeToken(builder, for_node.else_token, .keyword);
                try writeNodeTokens(builder, else_expr.idx);
            }
        },
        .expr_if,
        .expr_if_else,
        .expr_if_payload,
        .expr_if_full,
        => {
            const node_index: Ast.Expr.If.Index = .{ .idx = node };
            const expr = node_index.get(tree);

            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, expr.condition.idx);
            if (expr.then_payload) |payload| try writePayload(builder, payload.get(tree));
            try writeNodeTokens(builder, expr.then_branch.idx);
            if (expr.else_branch) |else_expr| {
                if (expr.else_payload) |payload| try writePayload(builder, payload.get(tree));
                try writeNodeTokens(builder, else_expr.idx);
            }
        },
        // .expr_init => {
        //     var buf: [2]Ast.Node.Index = undefined;
        //     const array_init: Ast.full.ArrayInit = tree.fullArrayInit(&buf, node).?;
        //     if (array_init.ast.type_expr.unwrap()) |type_expr| {
        //         try writeNodeTokens(builder, type_expr);
        //     }
        //     for (array_init.ast.elements) |elem| try writeNodeTokens(builder, elem);
        // },
        .expr_init => {
            const expr: Ast.Expr.Init = node.cast(.expr_init, tree).?;

            var field_token_type: ?TokenType = null;

            if (expr.type) |type_expr| {
                try writeNodeTokens(builder, type_expr.idx);

                blk: {
                    const struct_type = try builder.analyser.resolveTypeOfNode(.of(type_expr.idx, handle)) orelse
                        break :blk;

                    const scope_handle = switch (struct_type.data) {
                        .container => |info| info.scope_handle,
                        else => break :blk,
                    };
                    const container = scope_handle.toNode().cast(.type_container, &scope_handle.handle.tree).?;

                    field_token_type = switch (container.kind.get(tree)) {
                        .@"struct", .@"union" => .property,
                        .@"enum" => .enumMember,
                        .@"opaque" => .property, // opaque can't have fields but it's still syntactically valid
                    };
                }
            }

            var it = expr.fields.iter(tree);
            while (it.next(tree)) |field| {
                switch (field.get(tree)) {
                    .struct_field => |struct_field_idx| {
                        const struct_field = struct_field_idx.get(tree);
                        const name_token = struct_field.name.token(tree);
                        try writeToken(builder, name_token, field_token_type orelse .property);
                        try writeToken(builder, name_token.add(1), .operator); // '='
                        try writeNodeTokens(builder, struct_field.init.idx);
                    },
                    .tuple_field => |field_expr| try writeNodeTokens(builder, field_expr.idx),
                }
            }
        },
        .expr_call => {
            const expr: Ast.Expr.Call = node.cast(.expr_call, tree).?;

            if (expr.callee.idx.tag(tree) == .leaf_enum_literal) {
                // TODO actually try to resolve the decl literal
                try writeToken(builder, expr.callee.idx.mainToken(tree), .function);
            } else {
                try writeNodeTokens(builder, expr.callee.idx);
            }

            var it = expr.args.iter(tree);
            while (it.next(tree)) |arg| {
                try writeNodeTokens(builder, arg.idx);
            }
        },
        .expr_slice => {
            const expr: Ast.Expr.Slice = node.cast(.expr_slice, tree).?;

            try writeNodeTokens(builder, expr.lhs.idx);
            try writeNodeTokens(builder, expr.start.idx);
            if (expr.end) |end| try writeNodeTokens(builder, end.idx);
            if (expr.sentinel) |sentinel| try writeNodeTokens(builder, sentinel.idx);
        },
        .expr_deref => {
            const expr: Ast.Expr.Deref = node.cast(.expr_deref, tree).?;
            try writeNodeTokens(builder, expr.lhs.idx);
            try writeToken(builder, main_token, .operator);
        },
        .expr_unwrap => {
            const expr: Ast.Expr.Unwrap = node.cast(.expr_unwrap, tree).?;
            try writeNodeTokens(builder, expr.lhs.idx);
            try writeToken(builder, main_token, .operator);
        },
        .expr_group => {
            const expr: Ast.Expr.Grouping = node.cast(.expr_group, tree).?;
            try writeNodeTokens(builder, expr.inner.idx);
        },
        inline .expr_break, .expr_continue => |t| {
            const expr = node.cast(t, tree).?;
            try writeToken(builder, main_token, .keyword);
            if (expr.label(tree)) |target| try writeToken(builder, target, .label);
            if (expr.value) |value| try writeNodeTokens(builder, value.idx);
        },
        .expr_comptime => {
            const expr: Ast.Expr.Comptime = node.cast(.expr_comptime, tree).?;
            try writeToken(builder, main_token, .keyword);
            try writeNodeTokens(builder, expr.inner.idx);
        },
        .expr_return => {
            const expr: Ast.Expr.Return = node.cast(.expr_return, tree).?;
            try writeToken(builder, expr.@"return".token(tree), .keyword);
            if (expr.value) |value| try writeNodeTokens(builder, value.idx);
        },
        .expr_builtin_call => {
            const expr: Ast.Expr.Builtin = node.cast(.expr_builtin_call, tree).?;

            const builtin_token = expr.callee.token(tree);
            const name = offsets.identifierTokenToNameSlice(tree, builtin_token);
            const is_deprecated =
                std.mem.eql(u8, name, "enumFromInt") or
                std.mem.eql(u8, name, "intFromEnum") or
                std.mem.eql(u8, name, "intFromFloat");

            try writeTokenMod(builder, builtin_token, .builtin, .{ .deprecated = is_deprecated });
            var it = expr.args.iter(tree);
            while (it.next(tree)) |arg| {
                try writeNodeTokens(builder, arg.idx);
            }
        },
        .asm_output,
        .asm_input,
        => unreachable,
        .decl_test => {
            const decl_test: Ast.Member.Test = node.cast(.decl_test, tree).?;

            try writeToken(builder, main_token, .keyword);
            if (decl_test.name(tree)) |name_token| {
                switch (name_token.tag(tree)) {
                    .string => try writeToken(builder, name_token, .string),
                    .name => try writeIdentifier(builder, name_token),
                    else => {},
                }
            }

            try writeNodeTokens(builder, decl_test.block.idx);
        },
        .expr_catch => {
            const expr: Ast.Expr.Catch = node.cast(.expr_catch, tree).?;
            try writeNodeTokens(builder, expr.lhs.idx);
            try writeToken(builder, main_token, .keyword);
            if (expr.payload) |payload| try writePayload(builder, payload.get(tree));
            try writeNodeTokens(builder, expr.rhs.idx);
        },
        .expr_binary => {
            const expr: Ast.Expr.Binary = node.cast(.expr_binary, tree).?;

            try writeNodeTokens(builder, expr.lhs.idx);
            const token_type: TokenType = switch (expr.op.get(tree)) {
                .@"and", .@"or", .@"orelse" => .keyword,
                else => .operator,
            };

            try writeToken(builder, main_token, token_type);
            try writeNodeTokens(builder, expr.rhs.idx);
        },
        .expr_destructure => {
            const expr: Ast.Expr.Destructure = node.cast(.expr_destructure, tree).?;

            const resolved_type = try builder.analyser.resolveTypeOfNode(.of(expr.init.idx, handle));

            var index: u32 = 0;
            var it = expr.lvalues.iter(tree);
            while (it.next(tree)) |lvalue| : (index += 1) {
                switch (lvalue.get(tree)) {
                    .expr => |expr_node| try writeNodeTokens(builder, expr_node.idx),
                    .var_proto => |var_proto| {
                        const field_type = if (resolved_type) |ty|
                            try builder.analyser.resolveBracketAccessType(ty, .{ .single = index })
                        else
                            null;
                        try writeVarDecl(
                            builder,
                            ast.globalVarFromDestructureProto(var_proto, tree),
                            false,
                            field_type,
                        );
                    },
                }
            }

            try writeToken(builder, main_token, .operator);
            try writeNodeTokens(builder, expr.init.idx);
        },
        inline .expr_index, .type_error_union => |t| {
            const expr = node.cast(t, tree).?;
            try writeNodeTokens(builder, expr.lhs.idx);
            try writeNodeTokens(builder, expr.rhs.idx);
        },
        .expr_dot_access => {
            try writeDotAccess(builder, node.cast(.expr_dot_access, tree).?);
        },
        .type_pointer => {
            const expr: Ast.Expr.Pointer = node.cast(.type_pointer, tree).?;
            const attributes = expr.attributes(tree);

            if (expr.sentinel(tree)) |sentinel| {
                try writeNodeTokens(builder, sentinel.idx);
            }

            try writeToken(builder, attributes.@"allowzero", .keyword);

            if (attributes.@"align") |payload| {
                switch (payload.get(tree)) {
                    .expr => |align_expr| {
                        const align_token = align_expr.idx.firstToken(tree).add(-2);
                        try writeToken(builder, align_token, .keyword);
                        try writeNodeTokens(builder, align_expr.idx);
                    },
                    .bitalign => |bitalign_idx| {
                        const bitalign = bitalign_idx.get(tree);
                        try writeNodeTokens(builder, bitalign.byte.idx);
                        try writeNodeTokens(builder, bitalign.bit_start.idx);
                        try writeNodeTokens(builder, bitalign.bit_end.idx);
                    },
                }
            }

            try writeToken(builder, attributes.@"const", .keyword);
            try writeToken(builder, attributes.@"volatile", .keyword);

            try writeNodeTokens(builder, expr.child_type.idx);
        },
        .type_array => {
            const expr: Ast.Expr.Array = node.cast(.type_array, tree).?;
            try writeNodeTokens(builder, expr.size.idx);
            if (expr.sentinel) |sentinel| try writeNodeTokens(builder, sentinel.idx);
            try writeNodeTokens(builder, expr.child_type.idx);
        },
        .expr_prefix => {
            const expr: Ast.Expr.Prefix = node.cast(.expr_prefix, tree).?;
            const token_type: TokenType = switch (expr.op.get(tree)) {
                .@"!", .@"-", .@"-%", .@"~", .@"&" => .operator,
                .@"try" => .keyword,
            };
            try writeToken(builder, main_token, token_type);
            try writeNodeTokens(builder, expr.rhs.idx);
        },
    }
}

fn writePayload(builder: *Builder, payload: Ast.Payload) Analyser.Error!void {
    const tree = &builder.handle.tree;
    var it = payload.bindings.iter(tree);
    while (it.next(tree)) |binding| {
        const binding_token = binding.get(tree).name(tree) orelse continue;
        try writeTokenMod(builder, binding_token, .variable, .{ .declaration = true });
    }
}

fn writeContainerField(
    builder: *Builder,
    container_field: Ast.Member.Field,
    /// `null` means `.root`
    container_decl: ?Ast.Expr.Container,
) Analyser.Error!void {
    const tree = &builder.handle.tree;
    const attributes = container_field.attributes(tree);

    const field_token_type: TokenType = token_type: {
        const container = container_decl orelse
            break :token_type .property; // .root is a struct
        break :token_type switch (container.kind.get(tree)) {
            .@"struct", .@"union" => .property,
            .@"enum" => .enumMember,
            .@"opaque" => .property, // opaque can't have fields but it's still syntactically valid
        };
    };

    try writeToken(builder, attributes.@"comptime", .keyword);

    if (container_field.name) |leaf_node| {
        try writeTokenMod(builder, leaf_node.token(tree), field_token_type, .{ .declaration = true });
    }

    try writeNodeTokens(builder, container_field.type.idx);

    if (container_field.@"align") |align_expr| {
        try writeToken(builder, align_expr.idx.firstToken(tree).add(-2), .keyword);
        try writeNodeTokens(builder, align_expr.idx);
    }

    if (container_field.init) |value_expr| {
        const equal_token = value_expr.idx.firstToken(tree).add(-1);
        if (equal_token.tag(tree) == .@"=") {
            try writeToken(builder, equal_token, .operator);
        }
        try writeNodeTokens(builder, value_expr.idx);
    }
}

fn writeVarDecl(
    builder: *Builder,
    var_decl: Ast.Member.GlobalVar,
    is_global: bool,
    resolved_type: ?Analyser.Type,
) Analyser.Error!void {
    const tree = &builder.handle.tree;

    const attributes = var_decl.attributes(tree);

    try writeToken(builder, attributes.@"pub", .keyword);
    try writeToken(builder, attributes.@"export", .keyword);
    if (attributes.@"extern") |@"extern"| {
        try writeToken(builder, @"extern".@"extern", .keyword);
        try writeToken(builder, @"extern".string, .keyword);
    }
    try writeToken(builder, attributes.@"threadlocal", .keyword);

    // BRANCH_TODO
    // const decl: Analyser.DeclWithHandle = .{
    //     .decl = .{ .ast_node = var_decl },
    //     .handle = builder.handle,
    // };
    // const is_static = try decl.isStatic();
    const is_static = is_global;

    const is_mutable = switch (var_decl.mutability.get(tree)) {
        .@"const" => false,
        .@"var" => true,
    };

    if (var_decl.name(tree)) |name_token| {
        if (resolved_type) |decl_type| {
            try colorIdentifierBasedOnType(
                builder,
                decl_type,
                name_token,
                false,
                .{
                    .declaration = true,
                    .static = !(decl_type.is_type_val or decl_type.isFunc()) and is_static,
                    .mutable = is_mutable,
                },
            );
        } else {
            try writeTokenMod(
                builder,
                name_token,
                .variable,
                .{
                    .declaration = true,
                    .static = is_static,
                    .mutable = is_mutable,
                },
            );
        }
    }

    if (var_decl.type) |type_expr| try writeNodeTokens(builder, type_expr.idx);
    if (attributes.@"align") |align_expr| {
        try writeToken(builder, align_expr.idx.firstToken(tree).add(-2), .keyword);
        try writeNodeTokens(builder, align_expr.idx);
    }
    if (attributes.@"addrspace") |addrspace_expr| {
        try writeToken(builder, addrspace_expr.idx.firstToken(tree).add(-2), .keyword);
        try writeNodeTokens(builder, addrspace_expr.idx);
    }
    if (attributes.@"linksection") |linksection_expr| {
        try writeToken(builder, linksection_expr.idx.firstToken(tree).add(-2), .keyword);
        try writeNodeTokens(builder, linksection_expr.idx);
    }

    if (var_decl.init) |init_expr| {
        const equal_token = init_expr.idx.firstToken(tree).add(-1);
        if (equal_token.tag(tree) == .@"=") {
            try writeToken(builder, equal_token, .operator);
        }
        try writeNodeTokens(builder, init_expr.idx);
    }
}

fn writeIdentifier(builder: *Builder, name_token: Ast.Token.Index) Analyser.Error!void {
    const handle = builder.handle;
    const tree = &handle.tree;

    const name = offsets.identifierTokenToNameSlice(tree, name_token);
    const is_escaped_identifier = tree.source[name_token.byteOffset(tree)] == '@';

    if (!is_escaped_identifier) {
        if (std.mem.eql(u8, name, "_")) return;
        if (try builder.analyser.resolvePrimitive(name)) |primitive| {
            const is_type = builder.analyser.ip.typeOf(primitive) == .type_type;
            return try writeToken(builder, name_token, if (is_type) .type else .keywordLiteral);
        }
    }

    if (try builder.analyser.lookupSymbolGlobal(
        handle,
        name,
        name_token.byteOffset(tree),
    )) |child| {
        const is_param = child.decl == .function_parameter;
        const mutable = !child.isConst();
        if (try child.resolveType(builder.analyser)) |decl_type| {
            return try colorIdentifierBasedOnType(
                builder,
                decl_type,
                name_token,
                is_param,
                .{
                    .static = !(decl_type.is_type_val or decl_type.isFunc()) and try child.isStatic(),
                    .mutable = mutable,
                },
            );
        } else {
            try writeTokenMod(
                builder,
                name_token,
                if (is_param) .parameter else .variable,
                .{
                    .static = try child.isStatic(),
                    .mutable = mutable,
                },
            );
        }
    } else {
        try writeToken(builder, name_token, .variable);
    }
}

fn writeDotAccess(builder: *Builder, node: Ast.Expr.DotAccess) Analyser.Error!void {
    const handle = builder.handle;
    const tree = &builder.handle.tree;

    const field_name_token = node.rhs.token(tree);
    const symbol_name = offsets.identifierTokenToNameSlice(tree, field_name_token);

    try writeNodeTokens(builder, node.lhs.idx);

    const lhs = try builder.analyser.resolveTypeOfNode(.of(node.lhs.idx, handle)) orelse {
        try writeToken(builder, field_name_token, .variable);
        return;
    };

    const lhs_type = try builder.analyser.resolveDerefType(lhs) orelse lhs;
    if (lhs_type.isErrorSetType(builder.analyser)) {
        try writeToken(builder, field_name_token, .errorTag);
        return;
    }

    if (try lhs_type.lookupSymbol(builder.analyser, symbol_name)) |decl_type| decl_blk: {
        field_blk: {
            if (decl_type.decl != .ast_node) break :field_blk;
            const decl_node = decl_type.decl.ast_node;
            if (decl_node.cast(.field, tree) == null) break :field_blk;

            const scope_handle = switch (lhs_type.data) {
                .container => |info| info.scope_handle,
                else => break :field_blk,
            };
            const container = scope_handle.toNode().cast(.type_container, &scope_handle.handle.tree).?;

            const field_token_type: TokenType = if (lhs_type.is_type_val and ast.isTaggedUnion(tree, container))
                .enumMember
            else switch (container.kind.get(tree)) {
                .@"struct", .@"union" => .property,
                .@"enum" => .enumMember,
                .@"opaque" => .property, // opaque can't have fields but it's still syntactically valid
            };

            try writeTokenMod(builder, field_name_token, field_token_type, .{});
            return;
        }

        const resolved_type = try decl_type.resolveType(builder.analyser) orelse break :decl_blk;
        try colorIdentifierBasedOnType(
            builder,
            resolved_type,
            field_name_token,
            false,
            .{
                .mutable = !decl_type.isConst(),
                .static = !(resolved_type.is_type_val or resolved_type.isFunc()) and try decl_type.isStatic(),
            },
        );
        return;
    } else if (try builder.analyser.resolvePropertyType(lhs_type, symbol_name)) |_| {
        try writeTokenMod(builder, field_name_token, .property, .{});
        return;
    }

    try writeTokenMod(
        builder,
        field_name_token,
        .variable,
        .{},
    );
}

fn semanticTokens(
    server: *Server,
    arena: std.mem.Allocator,
    request_uri: types.DocumentUri,
    /// If `null`, semantic tokens will be computed for the entire source range.
    /// Otherwise only tokens in the give source range will be returned.
    range: ?types.Range,
) Error!?types.semantic_tokens.Result {
    const limited = switch (server.config_manager.config.semantic_tokens) {
        .full => false,
        .partial => true,
        .none => return null,
    };

    const document_uri = Uri.parse(arena, request_uri) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidParams,
    };
    const handle = server.document_store.getHandle(document_uri) orelse return null;

    // Workaround: The Ast on .zon files is unusable when an error occured on the root expr
    if (handle.tree.mode == .zon and handle.tree.errors.len > 0) return null;

    var analyser = server.initAnalyser(arena, handle);
    defer analyser.deinit();
    // semantic tokens can be quite expensive to compute on large files
    // and disabling callsite references can help with bringing the cost down.
    analyser.collect_callsite_references = false;

    var builder: Builder = .{
        .arena = arena,
        .analyser = &analyser,
        .handle = handle,
        .encoding = server.offset_encoding,
        .limited = limited,
        .overlappingTokenSupport = server.client_capabilities.supports_semantic_tokens_overlapping,
        .loc = if (range) |r| offsets.rangeToLoc(handle.tree.source, r, server.offset_encoding) else null,
    };

    // reverse the ast from the root declarations
    var root_it = handle.tree.root().members.iter(&handle.tree);
    while (root_it.next(&handle.tree)) |child| {
        try writeNodeTokens(&builder, child.idx);
    }

    return try builder.finish();
}
