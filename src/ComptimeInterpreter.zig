//! Hacky comptime interpreter, courtesy of midnight code run fuelled by spite;
//! hope that one day this can use async... <33

// TODO: builtin work!!
// TODO: DODify
// TODO: Work with DocumentStore

const std = @import("std");
const ast = @import("ast.zig");
const zig = std.zig;
const Ast = zig.Ast;
const analysis = @import("analysis.zig");
const DocumentStore = @import("DocumentStore.zig");
const ComptimeInterpreter = @This();

tree: Ast,
root_scope: *InterpreterScope = undefined,
allocator: std.mem.Allocator,

type_info: std.ArrayListUnmanaged(TypeInfo) = .{},
type_info_map: std.HashMapUnmanaged(TypeInfo, usize, TypeInfo.Context, std.hash_map.default_max_load_percentage) = .{},

pub fn deinit(interpreter: *ComptimeInterpreter) void {
    for (interpreter.type_info.items) |*ti| ti.deinit(interpreter.allocator);
    interpreter.type_info.deinit(interpreter.allocator);
    interpreter.type_info_map.deinit(interpreter.allocator);
}

pub const TypeInfo = union(enum) {
    pub const Context = struct {
        interpreter: ComptimeInterpreter,
        hasher: *std.hash.Wyhash,

        pub fn hash(self: @This(), s: TypeInfo) u64 {
            TypeInfo.hash(self, s);
            return self.hasher.final();
        }
        pub fn eql(self: @This(), a: TypeInfo, b: TypeInfo) bool {
            return TypeInfo.eql(self.interpreter, a, b);
        }
    };

    pub const Signedness = enum { signed, unsigned };

    pub const Struct = struct {
        /// Declarations contained within
        scope: *InterpreterScope,
        fields: std.ArrayListUnmanaged(FieldDefinition) = .{},
    };

    pub const Int = struct {
        bits: u16,
        signedness: Signedness,
    };

    pub const Pointer = struct {
        size: Size,
        is_const: bool,
        is_volatile: bool,
        child: Type,
        is_allowzero: bool,

        sentinel: ?ValueData,

        pub const Size = enum {
            one,
            many,
            slice,
            c,
        };
    };

    pub const Fn = struct {
        return_type: ?Type,
        /// Index into interpreter.declarations
        params: std.ArrayListUnmanaged(usize) = .{},
    };

    /// Hack to get anytype working; only valid on fnparams
    @"anytype",
    @"type",
    @"bool",

    @"struct": Struct,
    pointer: Pointer,

    int: Int,
    @"comptime_int",
    float: u16,
    @"comptime_float",

    pub fn eql(interpreter: ComptimeInterpreter, a: TypeInfo, b: TypeInfo) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .@"struct" => false, // Struct declarations can never be equal
            .pointer => p: {
                const ap = a.pointer;
                const bp = b.pointer;
                break :p ap.size == bp.size and ap.is_const == bp.is_const and ap.is_volatile == bp.is_volatile and eql(
                    interpreter,
                    interpreter.typeToTypeInfo(ap.child),
                    interpreter.typeToTypeInfo(bp.child),
                ) and ap.is_allowzero == bp.is_allowzero and ((ap.sentinel == null and bp.sentinel == null) or ((ap.sentinel != null and bp.sentinel != null) and ap.sentinel.?.eql(bp.sentinel.?)));
            },
            .int => a.int.signedness == b.int.signedness and a.int.bits == b.int.bits,
            .float => a.float == b.float,
            else => return true,
        };
    }

    pub fn hash(context: TypeInfo.Context, ti: TypeInfo) void {
        context.hasher.update(&[_]u8{@enumToInt(ti)});
        return switch (ti) {
            .@"struct" => |s| {
                context.hasher.update(std.mem.sliceAsBytes(s.fields.items));
                // TODO: Fix
                // context.hasher.update(std.mem.sliceAsBytes(s.declarations.items));
            },
            .pointer => |p| {
                // const ap = a.pointer;
                // const bp = b.pointer;
                context.hasher.update(&[_]u8{ @enumToInt(p.size), @boolToInt(p.is_const), @boolToInt(p.is_volatile) });
                TypeInfo.hash(context, context.interpreter.typeToTypeInfo(p.child));
                context.hasher.update(&[_]u8{@boolToInt(p.is_allowzero)});
                // TODO: Hash Sentinel
                // break :p ap.size == bp.size and ap.is_const == bp.is_const and ap.is_volatile == bp.is_volatile and eql(
                //     source_unit,
                //     source_interpreter.type_info.items[ap.child.info_idx],
                //     source_interpreter.type_info.items[bp.child.info_idx],
                // ) and ap.is_allowzero == bp.is_allowzero and ((ap.sentinel == null and bp.sentinel == null) or ((ap.sentinel != null and bp.sentinel != null) and ap.sentinel.?.eql(bp.sentinel.?)));
            },
            .int => |i| {
                // a.int.signedness == b.int.signedness and a.int.bits == b.int.bits;
                context.hasher.update(&[_]u8{@enumToInt(i.signedness)});
                context.hasher.update(&std.mem.toBytes(i.bits));
            },
            .float => |f| context.hasher.update(&std.mem.toBytes(f)),
            else => {},
        };
    }

    pub fn deinit(ti: *TypeInfo, allocator: std.mem.Allocator) void {
        switch (ti.*) {
            .@"struct" => |*s| s.fields.deinit(allocator),
            else => {},
        }
    }
};

pub const Type = struct {
    node_idx: Ast.Node.Index,
    info_idx: usize,
};

pub const Value = struct {
    node_idx: Ast.Node.Index,
    @"type": Type,
    value_data: ValueData,

    pub fn eql(value: Value, other_value: Value) bool {
        return value.value_data.eql(other_value.value_data);
    }
};

pub const ValueData = union(enum) {
    // TODO: Support larger ints, floats; bigints?

    @"type": Type,
    @"bool": bool,

    // @"struct": struct {

    // },
    // one_ptr: *anyopaque,
    /// TODO: Optimize this with an ArrayList that uses anyopaque slice
    slice_ptr: std.ArrayListUnmanaged(ValueData),

    @"comptime_int": std.math.big.int.Managed,
    unsigned_int: u64,
    signed_int: i64,
    float: f64,

    pub fn eql(data: ValueData, other_data: ValueData) bool {
        if (std.meta.activeTag(data) != std.meta.activeTag(other_data)) return false;
        // std.enums.
        // std.meta.activeTag(u: anytype)
        switch (data) {
            .@"bool" => return data.@"bool" == other_data.@"bool",
            .@"comptime_int" => return data.@"comptime_int".eq(other_data.@"comptime_int"),
            .unsigned_int => return data.unsigned_int == other_data.unsigned_int,
            .signed_int => return data.signed_int == other_data.signed_int,
            .float => return data.float == other_data.float,
            else => @panic("Simple eql not implemented!"),
        }
    }
};

pub const FieldDefinition = struct {
    node_idx: Ast.Node.Index,
    /// Store name so tree doesn't need to be used to access field name
    name: []const u8,
    @"type": Type,
    default_value: ?Value,
};

pub const Declaration = struct {
    node_idx: Ast.Node.Index,
    /// Store name so tree doesn't need to be used to access declaration name
    name: []const u8,
    @"type": Type,
    value: Value,

    // TODO: figure this out
    // pub const DeclarationKind = enum{variable, function};
    // pub fn declarationKind(declaration: Declaration, tree: Ast) DeclarationKind {
    //     return switch(tree.nodes.items(.tag)[declaration.node_idx]) {
    //         .fn_proto,
    //     .fn_proto_one,
    //     .fn_proto_simple,
    //     .fn_proto_multi,
    //     .fn_decl
    //     }
    // }

    pub fn isConstant(declaration: Declaration, tree: Ast) bool {
        return switch (tree.nodes.items(.tag)[declaration.node_idx]) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => {
                return tree.tokenSlice(ast.varDecl(tree, declaration.node_idx).?.ast.mut_token).len == 3;
            },
            else => false,
        };
    }
};

pub fn createType(interpreter: *ComptimeInterpreter, node_idx: Ast.Node.Index, type_info: TypeInfo) std.mem.Allocator.Error!Type {
    // TODO: Figure out dedup
    var hasher = std.hash.Wyhash.init(0);
    var gpr = try interpreter.type_info_map.getOrPutContext(interpreter.allocator, type_info, .{ .interpreter = interpreter.*, .hasher = &hasher });

    if (gpr.found_existing) {
        // std.log.info("Deduplicating type {d}", .{interpreter.formatTypeInfo(unit.type_info.items[gpr.value_ptr.*])});
        return Type{ .node_idx = node_idx, .info_idx = gpr.value_ptr.* };
    } else {
        try interpreter.type_info.append(interpreter.allocator, type_info);
        const info_idx = interpreter.type_info.items.len - 1;
        gpr.value_ptr.* = info_idx;
        return Type{ .node_idx = node_idx, .info_idx = info_idx };
    }
}

pub fn typeToTypeInfo(interpreter: ComptimeInterpreter, @"type": Type) TypeInfo {
    return interpreter.type_info.items[@"type".info_idx];
}

pub const TypeInfoFormatter = struct {
    interpreter: *ComptimeInterpreter,
    ti: TypeInfo,

    pub fn format(value: TypeInfoFormatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return switch (value.ti) {
            .int => |ii| switch (ii.signedness) {
                .signed => try writer.print("i{d}", .{ii.bits}),
                .unsigned => try writer.print("u{d}", .{ii.bits}),
            }, // TODO
            .float => |f| try writer.print("f{d}", .{f}),
            .@"comptime_int" => try writer.writeAll("comptime_int"),
            .@"comptime_float" => try writer.writeAll("comptime_float"),
            .@"type" => try writer.writeAll("type"),
            .@"bool" => try writer.writeAll("bool"),
            .@"struct" => |s| {
                try writer.writeAll("struct {");
                for (s.fields.items) |field| {
                    try writer.print("{s}: {s}, ", .{ field.name, value.interpreter.formatTypeInfo(value.interpreter.typeToTypeInfo(field.@"type")) });
                }
                var iterator = s.scope.declarations.iterator();
                while (iterator.next()) |di| {
                    const decl = di.value_ptr.*;
                    if (decl.isConstant(value.interpreter.tree)) {
                        try writer.print("const {s}: {any} = TODO_PRINT_VALUES, ", .{ decl.name, value.interpreter.formatTypeInfo(value.interpreter.typeToTypeInfo(decl.@"type")) });
                    } else {
                        try writer.print("var {s}: {any}, ", .{ decl.name, value.interpreter.formatTypeInfo(value.interpreter.typeToTypeInfo(decl.@"type")) });
                    }
                }
                try writer.writeAll("}");
            },
            else => try writer.print("UnimplementedTypeInfoPrint", .{}),
        };
    }
};

pub fn formatTypeInfo(interpreter: *ComptimeInterpreter, ti: TypeInfo) TypeInfoFormatter {
    return TypeInfoFormatter{ .interpreter = interpreter, .ti = ti };
}

pub const InterpreterScope = struct {
    interpreter: *ComptimeInterpreter,

    parent: ?*InterpreterScope = null,
    node_idx: Ast.Node.Index,
    declarations: std.StringHashMapUnmanaged(Declaration) = .{},
    /// Resizes can modify element pointer locations, so we use a list of pointers
    child_scopes: std.ArrayListUnmanaged(*InterpreterScope) = .{},

    pub const ScopeKind = enum { container, block, function };
    pub fn scopeKind(scope: InterpreterScope, tree: Ast) ScopeKind {
        return switch (tree.nodes.items(.tag)[scope.node_idx]) {
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
            .root,
            .error_set_decl,
            => .container,
            else => .block,
        };
    }

    pub fn getLabel(scope: InterpreterScope, tree: Ast) ?Ast.TokenIndex {
        const token_tags = tree.tokens.items(.tag);

        return switch (scope.scopeKind(tree)) {
            .block => z: {
                const lbrace = tree.nodes.items(.main_token)[scope.node_idx];
                break :z if (token_tags[lbrace - 1] == .colon and token_tags[lbrace - 2] == .identifier)
                    lbrace - 2
                else
                    null;
            },
            else => null,
        };
    }

    pub const ParentScopeIterator = struct {
        maybe_scope: ?*InterpreterScope,

        pub fn next(psi: *ParentScopeIterator) ?*InterpreterScope {
            if (psi.maybe_scope) |scope| {
                const curr = scope;
                psi.maybe_scope = scope.parent;
                return curr;
            } else return null;
        }
    };

    pub fn parentScopeIterator(scope: *InterpreterScope) ParentScopeIterator {
        return ParentScopeIterator{ .maybe_scope = scope };
    }

    pub fn deinit(scope: *InterpreterScope) void {
        scope.declarations.deinit(scope.interpreter.allocator);
        for (scope.child_scopes.items) |child| child.deinit();
        scope.child_scopes.deinit(scope.interpreter.allocator);

        scope.interpreter.allocator.destroy(scope);
    }
};

pub fn newScope(interpreter: *ComptimeInterpreter, maybe_parent: ?*InterpreterScope, node_idx: Ast.Node.Index) std.mem.Allocator.Error!*InterpreterScope {
    var ls = try interpreter.allocator.create(InterpreterScope);
    if (maybe_parent) |parent| try parent.child_scopes.append(interpreter.allocator, ls);
    ls.* = .{
        .interpreter = interpreter,
        .parent = maybe_parent,
        .node_idx = node_idx,
    };
    return ls;
}

pub const InterpretResult = union(enum) {
    @"break": ?[]const u8,
    break_with_value: struct {
        label: ?[]const u8,
        value: Value,
    },
    value: Value,
    @"return",
    return_with_value: Value,
    nothing,

    pub fn maybeGetValue(result: InterpretResult) ?Value {
        return switch (result) {
            .break_with_value => |v| v.value,
            .value => |v| v,
            else => null,
        };
    }

    pub fn getValue(result: InterpretResult) error{ExpectedValue}!Value {
        return result.maybeGetValue() orelse error.ExpectedValue;
    }
};

// Might be useful in the future
pub const InterpretOptions = struct {};

pub const InterpretError = std.mem.Allocator.Error || std.fmt.ParseIntError || std.fmt.ParseFloatError || error{
    InvalidCharacter,
    InvalidBase,
    ExpectedValue,
    InvalidOperation,
    CriticalAstFailure,
    InvalidBuiltin,
};
pub fn interpret(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    scope: ?*InterpreterScope,
    options: InterpretOptions,
) InterpretError!InterpretResult {
    // _ = unit;
    // _ = node;
    // _ = observe_values;

    const tree = interpreter.tree;
    const tags = tree.nodes.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    std.log.info("{any}", .{tags[node_idx]});

    switch (tags[node_idx]) {
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
        .root,
        .error_set_decl,
        => {
            var container_scope = try interpreter.newScope(scope, node_idx);
            var type_info = TypeInfo{
                .@"struct" = .{
                    .scope = container_scope,
                },
            };

            if (node_idx == 0) interpreter.root_scope = container_scope;

            var buffer: [2]Ast.Node.Index = undefined;
            const members = ast.declMembers(tree, node_idx, &buffer);

            for (members) |member| {
                const maybe_container_field: ?zig.Ast.full.ContainerField = switch (tags[member]) {
                    .container_field => tree.containerField(member),
                    .container_field_align => tree.containerFieldAlign(member),
                    .container_field_init => tree.containerFieldInit(member),
                    else => null,
                };

                if (maybe_container_field) |field_info| {
                    var init_type = try interpreter.interpret(field_info.ast.type_expr, container_scope, .{});
                    var default_value = if (field_info.ast.value_expr == 0)
                        null
                    else
                        try (try interpreter.interpret(field_info.ast.value_expr, container_scope, .{})).getValue();

                    const name = tree.tokenSlice(field_info.ast.name_token);
                    const field = FieldDefinition{
                        .node_idx = member,
                        .name = name,
                        .@"type" = (try init_type.getValue()).value_data.@"type",
                        .default_value = default_value,
                        // TODO: Default values
                        // .@"type" = T: {
                        //     var value = (try interpreter.interpret(field_info.ast.type_expr, scope_idx, true)).?.value;
                        //     break :T @ptrCast(*Type, @alignCast(@alignOf(*Type), value)).*;
                        // },
                        // .value = null,
                    };

                    try type_info.@"struct".fields.append(interpreter.allocator, field);
                } else {
                    _ = try interpreter.interpret(member, container_scope, options);
                }
            }

            return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }),
                .value_data = .{ .@"type" = try interpreter.createType(node_idx, type_info) },
            } };
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            const decl = ast.varDecl(tree, node_idx).?;
            var value = try (try interpreter.interpret(decl.ast.init_node, scope, options)).getValue();
            var @"type" = if (decl.ast.type_node == 0) Value{
                .node_idx = std.math.maxInt(Ast.Node.Index),
                .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }),
                .value_data = .{ .@"type" = value.@"type" },
            } else try (try interpreter.interpret(decl.ast.type_node, scope, options)).getValue();

            const name = analysis.getDeclName(tree, node_idx).?;
            try scope.?.declarations.put(interpreter.allocator, name, .{
                .node_idx = node_idx,
                .name = name,
                .@"type" = @"type".value_data.@"type",
                .@"value" = value,
            });

            return InterpretResult{ .nothing = .{} };
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            // try interpreter.scopes.append(interpreter.allocator, .{
            //     .node_idx = node_idx,
            //     .parent_scope = parent_scope_idx orelse std.math.maxInt(usize),
            // });
            // const scope_idx = interpreter.scopes.items.len - 1;

            var block_scope = try interpreter.newScope(scope, node_idx);

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                const ret = try interpreter.interpret(idx, block_scope, options);
                switch (ret) {
                    .@"break" => |lllll| {
                        const maybe_block_label_string = if (scope.?.getLabel(tree)) |i| tree.tokenSlice(i) else null;
                        if (lllll) |l| {
                            if (maybe_block_label_string) |ls| {
                                if (std.mem.eql(u8, l, ls)) {
                                    return InterpretResult{ .nothing = .{} };
                                } else return ret;
                            } else return ret;
                        } else {
                            return InterpretResult{ .nothing = .{} };
                        }
                    },
                    .break_with_value => |bwv| {
                        const maybe_block_label_string = if (scope.?.getLabel(tree)) |i| tree.tokenSlice(i) else null;

                        if (bwv.label) |l| {
                            if (maybe_block_label_string) |ls| {
                                if (std.mem.eql(u8, l, ls)) {
                                    return InterpretResult{ .value = bwv.value };
                                } else return ret;
                            } else return ret;
                        } else {
                            return InterpretResult{ .value = bwv.value };
                        }
                    },
                    .@"return", .return_with_value => return ret,
                    else => {},
                }
            }

            return InterpretResult{ .nothing = .{} };
        },
        .identifier => {
            var value = tree.getNodeSource(node_idx);

            if (std.mem.eql(u8, "bool", value)) return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }),
                .value_data = .{ .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = .{} }) },
            } };
            if (std.mem.eql(u8, "true", value)) return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = .{} }),
                .value_data = .{ .@"bool" = true },
            } };
            if (std.mem.eql(u8, "false", value)) return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = .{} }),
                .value_data = .{ .@"bool" = false },
            } };

            if (std.mem.eql(u8, "type", value)) {
                return InterpretResult{ .value = Value{
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }),
                    .value_data = .{ .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }) },
                } };
            } else if (value.len >= 2 and (value[0] == 'u' or value[0] == 'i')) int: {
                return InterpretResult{ .value = Value{
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = .{} }),
                    .value_data = .{ .@"type" = try interpreter.createType(node_idx, .{
                        .int = .{
                            .signedness = if (value[0] == 'u') .unsigned else .signed,
                            .bits = std.fmt.parseInt(u16, value[1..], 10) catch break :int,
                        },
                    }) },
                } };
            }

            // TODO: Floats

            // Logic to find identifiers in accessible scopes

            var psi = scope.?.parentScopeIterator();
            while (psi.next()) |pscope| {
                return InterpretResult{ .value = (pscope.declarations.get(value) orelse continue).value };
            }

            std.log.err("Identifier not found: {s}", .{value});
            @panic("Could not find identifier");
        },
        .grouped_expression => {
            return try interpreter.interpret(data[node_idx].lhs, scope, options);
        },
        .@"break" => {
            const label = if (data[node_idx].lhs == 0) null else tree.tokenSlice(data[node_idx].lhs);
            return if (data[node_idx].rhs == 0)
                InterpretResult{ .@"break" = label }
            else
                InterpretResult{ .break_with_value = .{ .label = label, .value = try (try interpreter.interpret(data[node_idx].rhs, scope, options)).getValue() } };
        },
        .@"return" => {
            return if (data[node_idx].lhs == 0)
                InterpretResult{ .@"return" = {} }
            else
                InterpretResult{ .return_with_value = try (try interpreter.interpret(data[node_idx].lhs, scope, options)).getValue() };
        },
        .@"if", .if_simple => {
            const iff = ast.ifFull(tree, node_idx);
            // TODO: Don't evaluate runtime ifs
            // if (options.observe_values) {
            const ir = try interpreter.interpret(iff.ast.cond_expr, scope, options);
            if ((try ir.getValue()).value_data.@"bool") {
                return try interpreter.interpret(iff.ast.then_expr, scope, options);
            } else {
                if (iff.ast.else_expr != 0) {
                    return try interpreter.interpret(iff.ast.else_expr, scope, options);
                } else return InterpretResult{ .nothing = .{} };
            }
        },
        .equal_equal => {
            var a = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var b = try interpreter.interpret(data[node_idx].rhs, scope, options);
            return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = .{} }),
                .value_data = .{ .@"bool" = (try a.getValue()).eql(try b.getValue()) },
            } };
            // a.getValue().eql(b.getValue())
        },
        .number_literal => {
            const s = tree.getNodeSource(node_idx);
            const nl = std.zig.parseNumberLiteral(s);
            // if (nl == .failure) ;
            return InterpretResult{ .value = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"comptime_int" = .{} }),
                .value_data = switch (nl) {
                    .float => .{ .float = try std.fmt.parseFloat(f64, s) },
                    .int => if (s[0] == '-') ValueData{ .signed_int = try std.fmt.parseInt(i64, s, 0) } else ValueData{ .unsigned_int = try std.fmt.parseInt(u64, s, 0) },
                    .big_int => |bii| ppp: {
                        var bi = try std.math.big.int.Managed.init(interpreter.allocator);
                        try bi.setString(@enumToInt(bii), s[if (bii != .decimal) @as(usize, 2) else @as(usize, 0)..]);
                        break :ppp .{ .@"comptime_int" = bi };
                    },
                    .failure => return error.CriticalAstFailure,
                },
            } };
        },
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_mul,
        .assign_mul_wrap,
        => {
            // TODO: Make this work with non identifiers
            // TODO: Actually consider operators

            const value = tree.getNodeSource(data[node_idx].lhs);

            var psi = scope.?.parentScopeIterator();
            while (psi.next()) |pscope| {
                if (pscope.declarations.getEntry(value)) |decl|
                    decl.value_ptr.value = try (try interpreter.interpret(data[node_idx].rhs, scope.?, options)).getValue();
            }

            return InterpretResult{ .nothing = .{} };
        },
        // .@"switch",
        // .switch_comma,
        // => {
        //     const cond = data[node_idx].lhs;
        //     const extra = tree.extraData(data[node_idx].rhs, Ast.Node.SubRange);
        //     const cases = tree.extra_data[extra.start..extra.end];

        //     for (cases) |case| {
        //         const switch_case: Ast.full.SwitchCase = switch (tags[case]) {
        //             .switch_case => tree.switchCase(case),
        //             .switch_case_one => tree.switchCaseOne(case),
        //             else => continue,
        //         };
        //     }
        // },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const params = ast.builtinCallParams(tree, node_idx, &buffer).?;
            const call_name = tree.tokenSlice(main_tokens[node_idx]);

            if (std.mem.eql(u8, call_name, "@compileLog")) {
                pp: for (params) |param| {
                    const res = try (try interpreter.interpret(param, scope, .{})).getValue();
                    const ti = interpreter.type_info.items[res.@"type".info_idx];
                    switch (ti) {
                        .pointer => |ptr| {
                            const child = interpreter.type_info.items[ptr.child.info_idx];
                            if (ptr.size == .slice and child == .int and child.int.bits == 8 and child.int.signedness == .unsigned) {

                                // TODO: Fix once I optimize slices
                                std.debug.print("@compileLog output: ", .{});
                                for (res.value_data.slice_ptr.items) |i| std.debug.print("{c}", .{@truncate(u8, i.unsigned_int)});
                                std.debug.print("\n", .{});

                                break :pp;
                            }
                        },
                        else => {},
                    }

                    @panic("compileLog argument type not printable!");
                }

                return InterpretResult{ .nothing = .{} };
            }

            std.log.info("Builtin not implemented: {s}", .{call_name});
            @panic("Builtin not implemented");
            // return error.InvalidBuiltin;
        },
        .string_literal => {
            const value = tree.getNodeSource(node_idx)[1 .. tree.getNodeSource(node_idx).len - 1];
            var val = Value{
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{
                    .pointer = .{
                        .size = .slice,
                        .is_const = true,
                        .is_volatile = false,
                        .child = try interpreter.createType(0, .{ .int = .{
                            .bits = 8,
                            .signedness = .unsigned,
                        } }),
                        .is_allowzero = false,

                        .sentinel = .{ .unsigned_int = 0 },
                    },
                }),
                .value_data = .{ .slice_ptr = .{} },
            };

            for (value) |z| {
                try val.value_data.slice_ptr.append(interpreter.allocator, .{ .unsigned_int = z });
            }
            try val.value_data.slice_ptr.append(interpreter.allocator, .{ .unsigned_int = 0 });

            return InterpretResult{ .value = val };
        },
        // TODO: Add comptime autodetection; e.g. const MyArrayList = std.ArrayList(u8)
        .@"comptime" => {
            return try interpreter.interpret(data[node_idx].lhs, scope, .{});
        },
        // .fn_proto,
        // .fn_proto_multi,
        // .fn_proto_one,
        // .fn_proto_simple,
        .fn_decl => {
            // var buf: [1]Ast.Node.Index = undefined;
            // const func = ast.fnProto(tree, node_idx, &buf).?;

            // TODO: Add params

            // var type_info = TypeInfo{
            //     .@"fn" = .{
            //         .definition_scope = scope.?,
            //         .node_idx = node_idx,
            //     },
            // };

            // var it = func.iterate(&tree);
            // while (ast.nextFnParam(&it)) |param| {
            //     // Add parameter decls
            //     if (param.name_token) |name_token| {
            //         // TODO: Think of new method for functions
            //         if ((try interpreter.interpret(param.type_expr, func_scope_idx, .{ .observe_values = true, .is_comptime = true })).maybeGetValue()) |value| {
            //             try interpreter.addDeclaration(func_scope_idx, value.value_data.@"type");
            //             try fnd.params.append(interpreter.allocator, interpreter.declarations.items.len - 1);
            //         } else {
            //             try interpreter.addDeclaration(parent_scope_idx.?, .{
            //                 .node_idx = node_idx,
            //                 .name = tree.tokenSlice(name_token),
            //                 .scope_idx = func_scope_idx, // orelse std.math.maxInt(usize),
            //                 .@"value" = undefined,
            //                 .@"type" = interpreter.createType(0, .{ .@"anytype" = .{} }),
            //             });
            //             try fnd.params.append(interpreter.allocator, interpreter.declarations.items.len - 1);
            //         }
            //     }
            // }

            // if ((try interpreter.interpret(func.ast.return_type, func_scope_idx, .{ .observe_values = true, .is_comptime = true })).maybeGetValue()) |value|
            //     fnd.return_type = value.value_data.@"type";

            // var value = Value{
            //     .node_idx = node_idx,
            //     .@"type" = try interpreter.createType(node_idx, type_info),
            //     .value_data = .{ .@"fn" = .{} },
            // };

            // const name = ast.getDeclName(tree, node_idx).?;
            // try scope.?.declarations.put(interpreter.allocator, name, .{
            //     .node_idx = node_idx,
            //     .name = name,
            //     .@"type" = value.@"type",
            //     .@"value" = value,
            // });

            return InterpretResult{ .nothing = .{} };
        },
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        => {
            // var params: [1]Ast.Node.Index = undefined;
            // const call = ast.callFull(tree, node_idx, &params) orelse unreachable;

            // const callee = .{ .node = call.ast.fn_expr, .handle = handle };
            // const decl = (try resolveTypeOfNodeInternal(store, arena, callee, bound_type_params)) orelse
            //     return null;

            // if (decl.type.is_type_val) return null;
            // const decl_node = switch (decl.type.data) {
            //     .other => |n| n,
            //     else => return null,
            // };
            // var buf: [1]Ast.Node.Index = undefined;
            // const func_maybe = ast.fnProto(decl.handle.tree, decl_node, &buf);

            // if (func_maybe) |fn_decl| {
            //     var expected_params = fn_decl.ast.params.len;
            //     // If we call as method, the first parameter should be skipped
            //     // TODO: Back-parse to extract the self argument?
            //     var it = fn_decl.iterate(&decl.handle.tree);
            //     if (token_tags[call.ast.lparen - 2] == .period) {
            //         if (try hasSelfParam(arena, store, decl.handle, fn_decl)) {
            //             _ = ast.nextFnParam(&it);
            //             expected_params -= 1;
            //         }
            //     }

            //     // Bind type params to the arguments passed in the call.
            //     const param_len = std.math.min(call.ast.params.len, expected_params);
            //     var i: usize = 0;
            //     while (ast.nextFnParam(&it)) |decl_param| : (i += 1) {
            //         if (i >= param_len) break;
            //         if (!isMetaType(decl.handle.tree, decl_param.type_expr))
            //             continue;

            //         const argument = .{ .node = call.ast.params[i], .handle = handle };
            //         const argument_type = (try resolveTypeOfNodeInternal(
            //             store,
            //             arena,
            //             argument,
            //             bound_type_params,
            //         )) orelse
            //             continue;
            //         if (!argument_type.type.is_type_val) continue;

            //         try bound_type_params.put(arena.allocator(), decl_param, argument_type);
            //     }

            //     const has_body = decl.handle.tree.nodes.items(.tag)[decl_node] == .fn_decl;
            //     const body = decl.handle.tree.nodes.items(.data)[decl_node].rhs;
            //     return try resolveReturnType(store, arena, fn_decl, decl.handle, bound_type_params, if (has_body) body else null);
            // }
            // return null;
            return InterpretResult{ .nothing = .{} };
        },
        .bool_not => {
            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const value = (try result.getValue());
            if (value.value_data != .@"bool") return error.InvalidOperation;
            return InterpretResult{
                .value = .{
                    .node_idx = node_idx,
                    .@"type" = value.@"type",
                    .value_data = .{ .@"bool" = !value.value_data.@"bool" },
                },
            };
        },
        else => {
            std.log.err("Unhandled {any}", .{tags[node_idx]});
            return InterpretResult{ .nothing = .{} };
        },
    }
}

pub const CallResult = struct {
    scope: *InterpreterScope,
    result: union(enum) {
        value: Value,
        nothing,
    },
};

pub fn call(
    interpreter: *ComptimeInterpreter,
    func_node_idx: Ast.Node.Index,
    arguments: []const Value,
    options: InterpretOptions,
) InterpretError!CallResult {
    // TODO: Eval, check parameter types

    // TODO: Arguments
    _ = options;
    _ = arguments;

    const tree = interpreter.tree;
    const tags = tree.nodes.items(.tag);

    std.debug.assert(tags[func_node_idx] == .fn_decl);

    // TODO: Parent sc]ope exploration (consts, typefuncs, etc.)
    var fn_scope = try interpreter.newScope(null, func_node_idx);

    const body = tree.nodes.items(.data)[func_node_idx].rhs;
    const result = try interpreter.interpret(body, fn_scope, .{});

    // TODO: Defers
    return CallResult{
        .scope = fn_scope,
        .result = switch (result) {
            .@"return" => .{ .nothing = {} },
            .@"return_with_value" => |v| .{ .value = v },
            else => @panic("bruh"),
        },
    };
}
