//! Render a human-readable representation of the Zig abstract syntax tree (AST).

const std = @import("std");
const Ast = std.zig.Ast;
const expectEqualStrings = @import("testing.zig").expectEqualStrings;

pub const RenderOptions = struct {
    indent: usize = 4,
    trailing_comments: ?struct {
        filename: ?[]const u8 = null,
    } = .{},
};

pub fn renderToFile(
    tree: Ast,
    options: RenderOptions,
    file: std.fs.File,
) (std.fs.File.WriteError || std.fs.File.SetEndPosError || std.mem.Allocator.Error)!void {
    var buffer: [4096]u8 = undefined;
    var file_writer = file.writer(&buffer);
    renderToWriter(tree, options, &file_writer.interface) catch |err| switch (err) {
        error.WriteFailed => return file_writer.err.?,
    };
    file_writer.end() catch |err| switch (err) {
        error.WriteFailed => return file_writer.err.?,
        else => |e| return e,
    };
}

pub fn renderToWriter(
    tree: Ast,
    options: RenderOptions,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    var p: PrintAst = .{
        .w = writer,
        .tree = tree,
        .options = options,
    };
    return try p.renderRoot();
}

pub fn fmt(tree: Ast, options: RenderOptions) Formatter {
    return .{ .tree = tree, .options = options };
}

pub const Formatter = struct {
    tree: Ast,
    options: RenderOptions,

    pub fn format(
        ctx: Formatter,
        writer: *std.Io.Writer,
        comptime fmt_spec: []const u8,
    ) !void {
        comptime std.debug.assert(fmt_spec.len == 0);
        try renderToWriter(ctx.tree, ctx.options, writer);
    }
};

const PrintAst = struct {
    w: *std.Io.Writer,
    tree: Ast,
    options: RenderOptions,
    indent: u32 = 0,
    current_line: usize = 0,
    current_column: usize = 0,
    current_source_index: usize = 0,

    fn renderRoot(p: *PrintAst) std.Io.Writer.Error!void {
        try p.renderNode(.root);
        try p.w.writeByte('\n');
    }

    fn renderOptNode(p: *PrintAst, opt_node: Ast.Node.OptionalIndex) std.Io.Writer.Error!void {
        if (opt_node.unwrap()) |node| {
            try p.renderNode(node);
        } else {
            try p.w.writeAll(".none");
        }
    }

    fn renderNode(p: *PrintAst, node: Ast.Node.Index) std.Io.Writer.Error!void {
        const tree = p.tree;
        const tag = tree.nodeTag(node);

        // Compact style for some tags
        switch (tag) {
            .root => {
                try p.w.writeAll("pub const root = .{");
                p.indent += 1;
                for (tree.rootDecls()) |decl| {
                    try p.renderItem(decl);
                }
                p.indent -= 1;
                try p.newline();
                try p.w.writeAll("};");
                return;
            },
            .anyframe_literal => return try p.w.writeAll(".anyframe_literal"),
            .unreachable_literal => return try p.w.writeAll(".anyframe_literal"),
            .char_literal,
            .number_literal,
            .identifier,
            .enum_literal,
            .string_literal,
            => return try p.w.print(".{t}({s})", .{ tag, tree.tokenSlice(tree.nodeMainToken(node)) }),
            .error_value => return try p.w.print(".error_value({s})", .{tree.tokenSlice(tree.nodeMainToken(node) + 2)}),
            .multiline_string_literal => {
                try p.w.writeAll(".multiline_string_literal(");
                p.indent += 1;
                const start, const end = tree.nodeData(node).token_and_token;
                for (start..end + 1) |i| {
                    const token: Ast.TokenIndex = @intCast(i);
                    try p.newline();
                    try p.w.writeAll(tree.tokenSlice(token));
                }
                p.indent -= 1;
                try p.newline();
                try p.w.writeAll(")");
                return;
            },
            .@"return" => {
                const opt_expr = tree.nodeData(node).opt_node;
                if (opt_expr == .none) {
                    return try p.w.writeAll(".@\"return\"");
                }
            },
            .@"continue", .@"break" => {
                const opt_label, const opt_expr = tree.nodeData(node).opt_token_and_opt_node;
                if (opt_label == .none and opt_expr == .none) {
                    switch (tag) {
                        .@"continue" => return try p.w.writeAll(".@\"continue\""),
                        .@"break" => return try p.w.writeAll(".@\"break\""),
                        else => unreachable,
                    }
                }
            },
            else => {},
        }

        try p.w.print("{f}{{", .{std.zig.fmtId(nodeTagName(tag))});
        p.indent += 1;
        switch (tag) {
            .@"catch",
            .equal_equal,
            .bang_equal,
            .less_than,
            .greater_than,
            .less_or_equal,
            .greater_or_equal,
            .assign_mul,
            .assign_div,
            .assign_mod,
            .assign_add,
            .assign_sub,
            .assign_shl,
            .assign_shl_sat,
            .assign_shr,
            .assign_bit_and,
            .assign_bit_xor,
            .assign_bit_or,
            .assign_mul_wrap,
            .assign_add_wrap,
            .assign_sub_wrap,
            .assign_mul_sat,
            .assign_add_sat,
            .assign_sub_sat,
            .assign,
            .merge_error_sets,
            .mul,
            .div,
            .mod,
            .array_mult,
            .mul_wrap,
            .mul_sat,
            .add,
            .sub,
            .array_cat,
            .add_wrap,
            .sub_wrap,
            .add_sat,
            .sub_sat,
            .shl,
            .shl_sat,
            .shr,
            .bit_and,
            .bit_xor,
            .bit_or,
            .@"orelse",
            .bool_and,
            .bool_or,
            .array_access,
            .switch_range,
            .error_union,
            => {
                const lhs, const rhs = tree.nodeData(node).node_and_node;
                try p.renderField(lhs, "lhs");
                try p.renderField(rhs, "rhs");
            },

            .for_range => {
                const lhs, const opt_rhs = tree.nodeData(node).node_and_opt_node;
                try p.renderField(lhs, "lhs");
                try p.renderOptField(opt_rhs, "rhs", .always_render);
            },

            .@"defer",
            .optional_type,
            .bool_not,
            .negation,
            .bit_not,
            .negation_wrap,
            .address_of,
            .@"try",
            .deref,
            .@"suspend",
            .@"resume",
            .@"comptime",
            .@"nosuspend",
            => {
                const expr = tree.nodeData(node).node;
                try p.renderField(expr, "expr");
            },

            .@"errdefer" => {
                const payload_token, const expr = tree.nodeData(node).opt_token_and_node;
                try p.renderOptTokenField(payload_token.unwrap(), "payload_token", .hide_if_none);
                try p.renderField(expr, "expr");
            },
            .unwrap_optional => {
                const expr = tree.nodeData(node).node_and_token[0];
                try p.renderField(expr, "expr");
            },
            .grouped_expression => {
                const expr = tree.nodeData(node).node_and_token[0];
                try p.renderField(expr, "expr");
            },
            .anyframe_type => {
                const return_type = tree.nodeData(node).token_and_node[1];
                try p.renderField(return_type, "return_type");
            },
            .@"return" => {
                const opt_expr = tree.nodeData(node).opt_node;
                try p.renderField(opt_expr.unwrap().?, "expr");
            },
            .test_decl => {
                const opt_name_token, const body = tree.nodeData(node).opt_token_and_node;
                try p.renderOptTokenField(opt_name_token.unwrap(), "name_token", .hide_if_none);
                try p.renderField(body, "body");
            },
            .field_access => {
                const lhs, const field_name = tree.nodeData(node).node_and_token;
                try p.renderField(lhs, "lhs");
                try p.renderTokenField(field_name, "field_name");
            },
            .@"continue",
            .@"break",
            => {
                const opt_label, const opt_expr = tree.nodeData(node).opt_token_and_opt_node;
                try p.renderOptTokenField(opt_label.unwrap(), "name_token", .hide_if_none);
                try p.renderOptField(opt_expr, "expr", .hide_if_none);
            },

            .root,
            .anyframe_literal,
            .char_literal,
            .number_literal,
            .unreachable_literal,
            .identifier,
            .enum_literal,
            .string_literal,
            .multiline_string_literal,
            .error_value,
            => unreachable,

            .assign_destructure => {
                const assign_destructure = tree.assignDestructure(node);
                try p.renderNodeSliceField(assign_destructure.ast.variables, "variables");
                try p.renderField(assign_destructure.ast.value_expr, "init_node");
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const var_decl = tree.fullVarDecl(node).?;
                try p.renderTokenField(var_decl.ast.mut_token, "mut_token");
                try p.renderTokenField(var_decl.ast.mut_token + 1, "name_token");
                try p.renderOptField(var_decl.ast.type_node, "type_node", .always_render);
                try p.renderOptField(var_decl.ast.align_node, "align_node", .hide_if_none);
                try p.renderOptField(var_decl.ast.addrspace_node, "addrspace_node", .hide_if_none);
                try p.renderOptField(var_decl.ast.section_node, "section_node", .hide_if_none);
                try p.renderOptField(var_decl.ast.init_node, "init_node", .always_render);
            },
            .array_type,
            .array_type_sentinel,
            => {
                const array_type = tree.fullArrayType(node).?;
                try p.renderField(array_type.ast.elem_count, "elem_count");
                try p.renderOptField(array_type.ast.sentinel, "sentinel", .hide_if_none);
                try p.renderField(array_type.ast.elem_type, "elem_type");
            },
            .ptr_type_aligned,
            .ptr_type_sentinel,
            .ptr_type,
            .ptr_type_bit_range,
            => {
                const pointer_type = tree.fullPtrType(node).?;
                try p.renderCustomField("{t}", .{pointer_type.size}, "size");
                try p.renderOptTokenField(pointer_type.allowzero_token, "allowzero_token", .hide_if_none);
                try p.renderOptTokenField(pointer_type.const_token, "const_token", .hide_if_none);
                try p.renderOptTokenField(pointer_type.volatile_token, "volatile_token", .hide_if_none);
                try p.renderOptField(pointer_type.ast.align_node, "align_node", .hide_if_none);
                try p.renderOptField(pointer_type.ast.addrspace_node, "addrspace_node", .hide_if_none);
                try p.renderOptField(pointer_type.ast.sentinel, "sentinel", .hide_if_none);
                try p.renderOptField(pointer_type.ast.bit_range_start, "bit_range_start", .hide_if_none);
                try p.renderOptField(pointer_type.ast.bit_range_end, "bit_range_end", .hide_if_none);
                try p.renderField(pointer_type.ast.child_type, "child_type");
            },
            .slice_open,
            .slice,
            .slice_sentinel,
            => {
                const slice = tree.fullSlice(node).?;
                try p.renderField(slice.ast.sliced, "sliced");
                try p.renderField(slice.ast.start, "start");
                try p.renderOptField(slice.ast.end, "end", .hide_if_none);
                try p.renderOptField(slice.ast.sentinel, "sentinel", .hide_if_none);
            },
            .array_init_one,
            .array_init_one_comma,
            .array_init_dot_two,
            .array_init_dot_two_comma,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init,
            .array_init_comma,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const array_init = tree.fullArrayInit(&buffer, node).?;
                try p.renderOptField(array_init.ast.type_expr, "type_expr", .always_render);
                try p.renderNodeSliceField(array_init.ast.elements, "elements");
            },
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init,
            .struct_init_comma,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const struct_init = tree.fullStructInit(&buffer, node).?;
                try p.renderOptField(struct_init.ast.type_expr, "type_expr", .always_render);
                try p.renderNodeSliceField(struct_init.ast.fields, "fields");
                // This should also include field names
            },
            .call_one,
            .call_one_comma,
            .call,
            .call_comma,
            => {
                var buffer: [1]Ast.Node.Index = undefined;
                const call = tree.fullCall(&buffer, node).?;
                try p.renderField(call.ast.fn_expr, "fn_expr");
                try p.renderNodeSliceField(call.ast.params, "params");
            },
            .@"switch",
            .switch_comma,
            => {
                const switch_data = tree.fullSwitch(node).?;
                try p.renderField(switch_data.ast.condition, "condition");
                try p.renderNodeSliceField(switch_data.ast.cases, "cases");
            },
            .switch_case_one,
            .switch_case_inline_one,
            .switch_case,
            .switch_case_inline,
            => {
                const switch_case = tree.fullSwitchCase(node).?;
                try p.renderNodeSliceField(switch_case.ast.values, "values");
                try p.renderField(switch_case.ast.target_expr, "target_expr");
            },
            .while_simple,
            .while_cont,
            .@"while",
            => {
                const while_data = tree.fullWhile(node).?;
                try p.renderField(while_data.ast.cond_expr, "cond_expr");
                try p.renderOptField(while_data.ast.cont_expr, "cont_expr", .hide_if_none);
                try p.renderField(while_data.ast.then_expr, "then_expr");
                try p.renderOptField(while_data.ast.else_expr, "else_expr", .hide_if_none);
            },
            .for_simple,
            .@"for",
            => {
                const for_data = tree.fullFor(node).?;
                try p.renderNodeSliceField(for_data.ast.inputs, "inputs");
                try p.renderField(for_data.ast.then_expr, "then_expr");
                try p.renderOptField(for_data.ast.else_expr, "else_expr", .hide_if_none);
            },
            .if_simple,
            .@"if",
            => {
                const if_data = tree.fullIf(node).?;
                try p.renderField(if_data.ast.cond_expr, "cond_expr");
                try p.renderField(if_data.ast.then_expr, "then_expr");
                try p.renderOptField(if_data.ast.else_expr, "else_expr", .hide_if_none);
            },
            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            => {
                var buffer: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buffer, node).?;
                try p.renderOptTokenField(fn_proto.visib_token, "visib_token", .hide_if_none);
                try p.renderOptTokenField(fn_proto.extern_export_inline_token, "extern_export_inline_token", .hide_if_none);
                try p.renderOptTokenField(fn_proto.lib_name, "lib_name", .hide_if_none);
                try p.renderOptTokenField(fn_proto.name_token, "name_token", .hide_if_none);
                try p.renderOptField(fn_proto.ast.return_type, "return_type", .always_render);
                try p.renderOptField(fn_proto.ast.align_expr, "align_expr", .hide_if_none);
                try p.renderOptField(fn_proto.ast.addrspace_expr, "addrspace_expr", .hide_if_none);
                try p.renderOptField(fn_proto.ast.section_expr, "section_expr", .hide_if_none);
                try p.renderOptField(fn_proto.ast.callconv_expr, "callconv_expr", .hide_if_none);
                try p.renderNodeSliceField(fn_proto.ast.params, "params"); // This does not include all parameters.
            },
            .fn_decl => {
                const fn_proto, const body = tree.nodeData(node).node_and_node;
                try p.renderField(fn_proto, "fn_proto");
                try p.renderField(body, "body");
            },
            .builtin_call_two,
            .builtin_call_two_comma,
            .builtin_call,
            .builtin_call_comma,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const params = tree.builtinCallParams(&buffer, node).?;
                try p.renderNodeSliceField(params, "params");
            },
            .error_set_decl => {
                const lbrace, const rbrace = tree.nodeData(node).token_and_token;
                for (lbrace + 1..rbrace) |tok_i| {
                    const identifier_token: Ast.TokenIndex = @intCast(tok_i);
                    if (tree.tokenTag(identifier_token) != .identifier) continue;
                    try p.w.print(".{f},", .{std.zig.fmtId(tree.tokenSlice(identifier_token))});
                }
            },
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                const container_decl = tree.fullContainerDecl(&buffer, node).?;
                try p.renderOptTokenField(container_decl.layout_token, "layout_token", .hide_if_none);
                try p.renderOptField(container_decl.ast.arg, "arg", .hide_if_none);
                try p.renderNodeSliceField(container_decl.ast.members, "members");
            },
            .container_field_init,
            .container_field_align,
            .container_field,
            => {
                const container_field = tree.fullContainerField(node).?;
                try p.renderOptTokenField(container_field.comptime_token, "comptime_token", .hide_if_none);
                try p.renderOptField(container_field.ast.type_expr, "type_expr", .always_render);
                try p.renderOptField(container_field.ast.align_expr, "align_expr", .hide_if_none);
                try p.renderOptField(container_field.ast.value_expr, "value_expr", .hide_if_none);
                try p.renderCustomField("{}", .{container_field.ast.tuple_like}, "tuple_like");
            },
            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            => {
                var buffer: [2]Ast.Node.Index = undefined;
                for (tree.blockStatements(&buffer, node).?) |statement| {
                    try p.renderItem(statement);
                }
            },
            .asm_legacy => {
                const asm_data = tree.asmLegacy(node);
                try p.renderOptTokenField(asm_data.first_clobber, "first_clobber", .hide_if_none);
                try p.renderOptTokenField(asm_data.volatile_token, "volatile_token", .hide_if_none);
                try p.renderField(asm_data.ast.template, "template");
                try p.renderNodeSliceField(asm_data.inputs, "inputs");
                try p.renderNodeSliceField(asm_data.outputs, "outputs");
            },
            .asm_simple,
            .@"asm",
            => {
                const asm_data = tree.fullAsm(node).?;
                try p.renderOptTokenField(asm_data.volatile_token, "volatile_token", .hide_if_none);
                try p.renderField(asm_data.ast.template, "template");
                try p.renderNodeSliceField(asm_data.inputs, "inputs");
                try p.renderNodeSliceField(asm_data.outputs, "outputs");
                try p.renderOptField(asm_data.ast.clobbers, "clobbers", .hide_if_none);
            },
            .asm_output => {
                const name_token = tree.nodeMainToken(node);
                const constraint_token = name_token + 2;
                const has_arrow = tree.tokenTag(name_token + 4) == .arrow;
                try p.renderTokenField(name_token, "name_token");
                try p.renderTokenField(constraint_token, "constraint_token");
                if (has_arrow) {
                    try p.renderField(tree.nodeData(node).opt_node_and_token[0].unwrap().?, "operand");
                } else {
                    try p.renderTokenField(name_token + 4, "operand");
                }
            },
            .asm_input => {
                const name_token = tree.nodeMainToken(node);
                const constraint_token = name_token + 2;
                const operand = tree.nodeData(node).node_and_token[0];
                try p.renderTokenField(name_token, "name_token");
                try p.renderTokenField(constraint_token, "constraint_token");
                try p.renderField(operand, "operand");
            },
        }
        p.indent -= 1;
        try p.newline();
        try p.w.writeByte('}');
    }

    fn newline(p: *PrintAst) !void {
        try p.w.writeByte('\n');
        try p.w.splatByteAll(' ', p.indent * p.options.indent);
    }

    fn renderTrailing(p: *PrintAst, token: Ast.TokenIndex) !void {
        const tree = p.tree;
        const options = p.options.trailing_comments orelse return;

        try p.w.writeAll(" // ");
        if (options.filename) |filename| {
            try p.w.writeAll(filename);
        }
        p.moveSourceCursor(tree.tokenStart(token));
        try p.w.print(":{d}:{d}", .{ p.current_line + 1, p.current_column + 1 });
    }

    fn renderItem(p: *PrintAst, node: Ast.Node.Index) !void {
        try p.renderOptItem(node.toOptional());
    }

    fn renderOptItem(p: *PrintAst, opt_node: Ast.Node.OptionalIndex) !void {
        try p.newline();
        try p.renderOptNode(opt_node);
        try p.w.writeByte(',');
        if (opt_node.unwrap()) |node| try p.renderTrailing(p.tree.nodeMainToken(node));
    }

    fn renderCustomField(p: *PrintAst, comptime format: []const u8, value: anytype, field_name: []const u8) !void {
        try p.newline();
        try p.w.print(".{s} = " ++ format ++ ",", .{field_name} ++ value);
    }

    fn renderField(p: *PrintAst, node: Ast.Node.Index, field_name: []const u8) !void {
        try p.renderOptField(node.toOptional(), field_name, undefined);
    }

    fn renderOptField(
        p: *PrintAst,
        opt_node: Ast.Node.OptionalIndex,
        field_name: []const u8,
        style: enum { always_render, hide_if_none },
    ) !void {
        if (opt_node.unwrap()) |node| {
            try p.newline();
            try p.w.print(".{s} = ", .{field_name});
            try p.renderNode(node);
            try p.w.writeByte(',');
            try p.renderTrailing(p.tree.nodeMainToken(node));
        } else switch (style) {
            .always_render => {
                try p.newline();
                try p.w.print(".{s} = .none,", .{field_name});
            },
            .hide_if_none => return,
        }
    }

    fn renderTokenField(
        p: *PrintAst,
        token: Ast.TokenIndex,
        field_name: []const u8,
    ) !void {
        try p.renderOptTokenField(token, field_name, undefined);
    }

    fn renderOptTokenField(
        p: *PrintAst,
        opt_token: ?Ast.TokenIndex,
        field_name: []const u8,
        style: enum { always_render, hide_if_none },
    ) !void {
        if (opt_token) |token| {
            const tree = p.tree;
            try p.newline();
            try p.w.print(".{s} = {f},", .{ field_name, std.zig.fmtId(tree.tokenSlice(token)) });
            try p.renderTrailing(token);
        } else switch (style) {
            .always_render => {
                try p.newline();
                try p.w.print(".{s} = .none,", .{field_name});
            },
            .hide_if_none => return,
        }
    }

    fn renderNodeSliceField(
        p: *PrintAst,
        nodes: []const Ast.Node.Index,
        field_name: []const u8,
    ) !void {
        try p.newline();
        if (nodes.len == 0) {
            return try p.w.print(".{s} = .{{}},", .{field_name});
        }
        try p.w.print(".{s} = .{{", .{field_name});
        p.indent += 1;
        for (nodes) |node| {
            try p.renderItem(node);
        }
        p.indent -= 1;
        try p.newline();
        try p.w.writeAll("},");
    }

    fn moveSourceCursor(p: *PrintAst, source_index: usize) void {
        defer p.current_source_index = source_index;
        switch (std.math.order(source_index, p.current_source_index)) {
            .eq => return,
            .lt => { // move backwards
                const source = p.tree.source[source_index..p.current_source_index];
                for (source) |c| {
                    p.current_line -= @intFromBool(c == '\n');
                }
                const line_start_index = if (std.mem.lastIndexOfScalar(u8, p.tree.source[0..source_index], '\n')) |index| index + 1 else 0;
                p.current_column = source_index - line_start_index;
            },
            .gt => { // move forward
                const source = p.tree.source[p.current_source_index..source_index];
                for (source) |c| {
                    if (c == '\n') {
                        p.current_line += 1;
                        p.current_column = 0;
                    } else {
                        p.current_column += 1;
                    }
                }
            },
        }
    }
};

fn nodeTagName(tag: Ast.Node.Tag) []const u8 {
    return switch (tag) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => "VarDecl",
        .array_type,
        .array_type_sentinel,
        => "ArrayType",
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => "PtrType",
        .slice_open,
        .slice,
        .slice_sentinel,
        => "Slice",
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => "ArrayInit",
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => "StructInit",
        .call_one,
        .call_one_comma,
        .call,
        .call_comma,
        => "Call",
        .@"switch",
        .switch_comma,
        => "Switch",
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => "SwitchCase",
        .while_simple,
        .while_cont,
        .@"while",
        => "While",
        .for_simple,
        .@"for",
        => "For",
        .if_simple,
        .@"if",
        => "If",
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => "FnProto",
        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => "BuiltinCall",
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        => "ContainerDecl",
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => "TaggedUnion",
        .container_field_init,
        .container_field_align,
        .container_field,
        => "ContainerField",
        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => "Block",
        .asm_legacy,
        .asm_simple,
        .@"asm",
        => "Asm",

        .root => "Root",
        .test_decl => "TestDecl",
        .@"errdefer" => "Errdefer",
        .@"defer" => "Defer",
        .@"catch" => "Catch",
        .field_access => "FieldAccess",
        .unwrap_optional => "UnwrapOptional",
        .equal_equal => "EqualEqual",
        .bang_equal => "BangEqual",
        .less_than => "LessThan",
        .greater_than => "GreaterThan",
        .less_or_equal => "LessOrEqual",
        .greater_or_equal => "GreaterOrEqual",
        .assign_mul => "AssignMul",
        .assign_div => "AssignDiv",
        .assign_mod => "AssignMod",
        .assign_add => "AssignAdd",
        .assign_sub => "AssignSub",
        .assign_shl => "AssignShl",
        .assign_shl_sat => "AssignShlSat",
        .assign_shr => "AssignShr",
        .assign_bit_and => "AssignBitAnd",
        .assign_bit_xor => "AssignBitXor",
        .assign_bit_or => "AssignBitOr",
        .assign_mul_wrap => "AssignMulWrap",
        .assign_add_wrap => "AssignAddWrap",
        .assign_sub_wrap => "AssignSubWrap",
        .assign_mul_sat => "AssignMulSat",
        .assign_add_sat => "AssignAddSat",
        .assign_sub_sat => "AssignSubSat",
        .assign => "Assign",
        .assign_destructure => "AssignDestructure",
        .merge_error_sets => "MergeErrorSets",
        .mul => "Mul",
        .div => "Div",
        .mod => "Mod",
        .array_mult => "ArrayMult",
        .mul_wrap => "MulWrap",
        .mul_sat => "MulSat",
        .add => "Add",
        .sub => "Sub",
        .array_cat => "ArrayCat",
        .add_wrap => "AddWrap",
        .sub_wrap => "SubWrap",
        .add_sat => "AddSat",
        .sub_sat => "SubSat",
        .shl => "Shl",
        .shl_sat => "ShlSat",
        .shr => "Shr",
        .bit_and => "BitAnd",
        .bit_xor => "BitXor",
        .bit_or => "BitOr",
        .@"orelse" => "Orelse",
        .bool_and => "BoolAnd",
        .bool_or => "BoolOr",
        .bool_not => "BoolNot",
        .negation => "Negation",
        .bit_not => "BitNot",
        .negation_wrap => "NegationWrap",
        .address_of => "AddressOf",
        .@"try" => "Try",
        .optional_type => "OptionalType",
        .deref => "Deref",
        .array_access => "ArrayAccess",
        .switch_range => "SwitchRange",
        .for_range => "ForRange",
        .@"suspend" => "Suspend",
        .@"resume" => "Resume",
        .@"continue" => "Continue",
        .@"break" => "Break",
        .@"return" => "Return",
        .fn_decl => "FnDecl",
        .anyframe_type => "AnyframeType",
        .anyframe_literal => "AnyframeLiteral",
        .char_literal => "CharLiteral",
        .number_literal => "NumberLiteral",
        .unreachable_literal => "UnreachableLiteral",
        .identifier => "Identifier",
        .enum_literal => "EnumLiteral",
        .string_literal => "StringLiteral",
        .multiline_string_literal => "MultilineStringLiteral",
        .grouped_expression => "GroupedExpression",
        .error_set_decl => "ErrorSetDecl",
        .@"comptime" => "Comptime",
        .@"nosuspend" => "Nosuspend",
        .asm_output => "AsmOutput",
        .asm_input => "AsmInput",
        .error_value => "ErrorValue",
        .error_union => "ErrorUnion",
    };
}

test PrintAst {
    const source =
        \\const std = @import("std");
        \\pub fn main() !void {
        \\    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
        \\}
    ;

    var tree: Ast = try .parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    renderToWriter(tree, .{}, &aw.writer) catch return error.OutOfMemory;

    try expectEqualStrings(
        \\pub const root = .{
        \\    VarDecl{
        \\        .mut_token = @"const", // :1:1
        \\        .name_token = std, // :1:7
        \\        .type_node = .none,
        \\        .init_node = BuiltinCall{
        \\            .params = .{
        \\                .string_literal("std"), // :1:21
        \\            },
        \\        }, // :1:13
        \\    }, // :1:1
        \\    FnDecl{
        \\        .fn_proto = FnProto{
        \\            .visib_token = @"pub", // :2:1
        \\            .name_token = main, // :2:8
        \\            .return_type = .identifier(void), // :2:16
        \\            .params = .{},
        \\        }, // :2:5
        \\        .body = Block{
        \\            Call{
        \\                .fn_expr = FieldAccess{
        \\                    .lhs = FieldAccess{
        \\                        .lhs = .identifier(std), // :3:5
        \\                        .field_name = debug, // :3:9
        \\                    }, // :3:8
        \\                    .field_name = print, // :3:15
        \\                }, // :3:14
        \\                .params = .{
        \\                    .string_literal("All your {s} are belong to us.\n"), // :3:21
        \\                    ArrayInit{
        \\                        .type_expr = .none,
        \\                        .elements = .{
        \\                            .string_literal("codebase"), // :3:59
        \\                        },
        \\                    }, // :3:58
        \\                },
        \\            }, // :3:20
        \\        }, // :2:21
        \\    }, // :2:5
        \\};
        \\
    , aw.written());

    // The output itself is syntactically valid Zig code.

    const printed_source = try aw.toOwnedSliceSentinel(0);
    defer std.testing.allocator.free(printed_source);

    var printed_tree: Ast = try .parse(std.testing.allocator, printed_source, .zig);
    defer printed_tree.deinit(std.testing.allocator);

    try std.testing.expectEqual(0, printed_tree.errors.len);
}
