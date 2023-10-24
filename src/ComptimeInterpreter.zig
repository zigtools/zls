//! Hacky comptime interpreter, courtesy of midnight code run fuelled by spite;
//! hope that one day this can use async... <33

// TODO: DODify

const std = @import("std");
const builtin = @import("builtin");
const ast = @import("ast.zig");
const zig = std.zig;
const Ast = zig.Ast;
const analysis = @import("analysis.zig");
const offsets = @import("offsets.zig");
const DocumentStore = @import("DocumentStore.zig");

pub const InternPool = @import("analyser/InternPool.zig");
pub const Index = InternPool.Index;
pub const Key = InternPool.Key;
pub const ComptimeInterpreter = @This();

const log = std.log.scoped(.zls_comptime_interpreter);

allocator: std.mem.Allocator,
ip: *InternPool,
document_store: *DocumentStore,
uri: DocumentStore.Uri,
namespaces: std.MultiArrayList(Namespace) = .{},

pub fn getHandle(interpreter: *ComptimeInterpreter) *DocumentStore.Handle {
    // This interpreter is loaded from a known-valid handle so a valid handle must exist
    return interpreter.document_store.getHandle(interpreter.uri).?;
}

pub fn recordError(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    code: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    const message = try std.fmt.allocPrint(interpreter.allocator, fmt, args);
    errdefer interpreter.allocator.free(message);
    const handle = interpreter.getHandle();
    try handle.analysis_errors.append(interpreter.document_store.allocator, .{
        .loc = offsets.nodeToLoc(handle.tree, node_idx),
        .code = code,
        .message = message,
    });
}

pub fn deinit(interpreter: *ComptimeInterpreter) void {
    for (
        interpreter.namespaces.items(.decls),
        interpreter.namespaces.items(.usingnamespaces),
    ) |*decls, *usingnamespaces| {
        decls.deinit(interpreter.allocator);
        usingnamespaces.deinit(interpreter.allocator);
    }
    interpreter.namespaces.deinit(interpreter.allocator);
}

pub const Value = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    /// this stores both the type and the value
    index: Index,
};
// pub const Comptimeness = enum { @"comptime", runtime };

pub const Namespace = struct {
    /// always points to Namespace or Index.none
    parent: Namespace.Index,
    node_idx: Ast.Node.Index,
    /// Will be a struct, enum, union, opaque or .none
    ty: InternPool.Index,
    decls: std.StringArrayHashMapUnmanaged(InternPool.DeclIndex) = .{},
    usingnamespaces: std.ArrayListUnmanaged(InternPool.DeclIndex) = .{},

    pub const Index = InternPool.NamespaceIndex;

    // TODO: Actually use this value
    // comptimeness: Comptimeness,

    pub fn getLabel(self: Namespace, tree: Ast) ?Ast.TokenIndex {
        const token_tags = tree.tokens.items(.tag);

        switch (tree.nodes.items(.tag)[self.node_idx]) {
            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            => {
                const lbrace = tree.nodes.items(.main_token)[self.node_idx];
                if (token_tags[lbrace - 1] == .colon and token_tags[lbrace - 2] == .identifier) {
                    return lbrace - 2;
                }

                return null;
            },
            else => return null,
        }
    }
};

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
            .return_with_value => |v| v,
            else => null,
        };
    }

    pub fn getValue(result: InterpretResult) error{ExpectedValue}!Value {
        return result.maybeGetValue() orelse error.ExpectedValue;
    }
};

pub fn huntItDown(
    interpreter: *ComptimeInterpreter,
    namespace: Namespace.Index,
    decl_name: []const u8,
    options: InterpretOptions,
) ?InternPool.DeclIndex {
    _ = options;

    var current_namespace = namespace;
    while (current_namespace != .none) {
        const decls = interpreter.namespaces.items(.decls)[@intFromEnum(current_namespace)];
        defer current_namespace = interpreter.namespaces.items(.parent)[@intFromEnum(current_namespace)];

        if (decls.get(decl_name)) |decl| {
            return decl;
        }
    }

    return null;
}

// Might be useful in the future
pub const InterpretOptions = struct {};

pub const InterpretError = std.mem.Allocator.Error || std.fmt.ParseIntError || std.fmt.ParseFloatError || error{
    InvalidCharacter,
    InvalidBase,
    ExpectedValue,
    InvalidOperation,
    CriticalAstFailure,
    InvalidBuiltin,
    IdentifierNotFound,
    MissingArguments,
    ImportFailure,
    InvalidCast,
};

pub fn interpret(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    namespace: Namespace.Index,
    options: InterpretOptions,
) InterpretError!InterpretResult {
    const tree = interpreter.getHandle().tree;
    const tags = tree.nodes.items(.tag);
    const data = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    switch (tags[node_idx]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        // .tagged_union, // TODO: Fix these
        // .tagged_union_trailing,
        // .tagged_union_two,
        // .tagged_union_two_trailing,
        // .tagged_union_enum_tag,
        // .tagged_union_enum_tag_trailing,
        .root,
        => {
            try interpreter.namespaces.append(interpreter.allocator, .{
                .parent = namespace,
                .node_idx = node_idx,
                .ty = .none,
            });
            const container_namespace = @as(Namespace.Index, @enumFromInt(interpreter.namespaces.len - 1));

            const struct_index = try interpreter.ip.createStruct(interpreter.allocator, .{
                .fields = .{},
                .namespace = container_namespace,
                .layout = .Auto, // TODO
                .backing_int_ty = .none, // TODO
                .status = .none, // TODO
            });
            var struct_info = interpreter.ip.getStruct(struct_index);

            var buffer: [2]Ast.Node.Index = undefined;

            const container_decl = tree.fullContainerDecl(&buffer, node_idx).?;
            for (container_decl.ast.members) |member| {
                const container_field = tree.fullContainerField(member) orelse {
                    _ = try interpreter.interpret(member, container_namespace, options);
                    continue;
                };

                var init_value = try (try interpreter.interpret(container_field.ast.type_expr, container_namespace, .{})).getValue();

                var default_value = if (container_field.ast.value_expr == 0)
                    Index.none
                else
                    (try (try interpreter.interpret(container_field.ast.value_expr, container_namespace, .{})).getValue()).index; // TODO check ty

                const init_value_ty = interpreter.ip.indexToKey(init_value.index).typeOf();
                if (init_value_ty != .type_type) {
                    try interpreter.recordError(
                        container_field.ast.type_expr,
                        "expected_type",
                        "expected type 'type', found '{}'",
                        .{init_value_ty.fmt(interpreter.ip.*)},
                    );
                    continue;
                }

                const field_name = tree.tokenSlice(container_field.ast.main_token);

                try struct_info.fields.put(interpreter.allocator, field_name, .{
                    .ty = init_value.index,
                    .default_value = default_value,
                    .alignment = 0, // TODO,
                    .is_comptime = false, // TODO
                });
            }

            const struct_type = try interpreter.ip.get(interpreter.allocator, Key{ .struct_type = struct_index });
            interpreter.namespaces.items(.ty)[@intFromEnum(container_namespace)] = struct_type;

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = struct_type,
            } };
        },
        .error_set_decl => {
            // TODO
            return InterpretResult{ .nothing = {} };
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            var decls: *std.StringArrayHashMapUnmanaged(InternPool.DeclIndex) = &interpreter.namespaces.items(.decls)[@intFromEnum(namespace)];

            const name = analysis.getDeclName(tree, node_idx).?;
            const decl_index = try interpreter.ip.createDecl(interpreter.allocator, .{
                .name = name,
                .node_idx = node_idx,
                .index = .none,
                .alignment = 0, // TODO
                .address_space = .generic, // TODO
                .is_pub = true, // TODO
                .is_exported = false, // TODO
            });

            const gop = try decls.getOrPutValue(interpreter.allocator, name, decl_index);
            if (gop.found_existing) {
                return InterpretResult{ .nothing = {} };
            }

            const var_decl = tree.fullVarDecl(node_idx).?;

            const type_value = blk: {
                if (var_decl.ast.type_node == 0) break :blk null;
                const result = interpreter.interpret(var_decl.ast.type_node, namespace, .{}) catch break :blk null;
                break :blk result.maybeGetValue();
            };
            const init_value = blk: {
                if (var_decl.ast.init_node == 0) break :blk null;
                const result = interpreter.interpret(var_decl.ast.init_node, namespace, .{}) catch break :blk null;
                break :blk result.maybeGetValue();
            };

            if (type_value == null and init_value == null) return InterpretResult{ .nothing = {} };

            if (type_value) |v| {
                if (interpreter.ip.indexToKey(v.index).typeOf() != .type_type) {
                    return InterpretResult{ .nothing = {} };
                }
            }
            // TODO coerce `init_value` into `type_value`

            const decl = interpreter.ip.getDecl(decl_index);
            decl.index = if (type_value) |v| try interpreter.ip.get(interpreter.allocator, .{
                .unknown_value = .{ .ty = v.index },
            }) else init_value.?.index;

            // TODO: Am I a dumbo shrimp? (e.g. is this tree shaking correct? works on my machine so like...)

            // if (scope.?.scopeKind() != .container) {
            // if (scope.?.node_idx != 0)
            //     _ = try decls.getPtr(name).?.getValue();

            return InterpretResult{ .nothing = {} };
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            try interpreter.namespaces.append(interpreter.allocator, .{
                .parent = namespace,
                .node_idx = node_idx,
                .ty = .none,
            });
            const block_namespace = @as(Namespace.Index, @enumFromInt(interpreter.namespaces.len - 1));

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                const ret = try interpreter.interpret(idx, block_namespace, options);
                switch (ret) {
                    .@"break" => |lllll| {
                        const maybe_block_label_string = if (interpreter.namespaces.get(@intFromEnum(namespace)).getLabel(tree)) |i| tree.tokenSlice(i) else null;
                        if (lllll) |l| {
                            if (maybe_block_label_string) |ls| {
                                if (std.mem.eql(u8, l, ls)) {
                                    return InterpretResult{ .nothing = {} };
                                } else return ret;
                            } else return ret;
                        } else {
                            return InterpretResult{ .nothing = {} };
                        }
                    },
                    .break_with_value => |bwv| {
                        const maybe_block_label_string = if (interpreter.namespaces.get(@intFromEnum(namespace)).getLabel(tree)) |i| tree.tokenSlice(i) else null;

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

            return InterpretResult{ .nothing = {} };
        },
        .identifier => {
            const identifier = offsets.nodeToSlice(tree, node_idx);

            const simples = std.ComptimeStringMap(Index, .{
                .{ "anyerror", Index.anyerror_type },
                .{ "anyframe", Index.anyframe_type },
                .{ "anyopaque", Index.anyopaque_type },
                .{ "bool", Index.bool_type },
                .{ "c_int", Index.c_int_type },
                .{ "c_long", Index.c_long_type },
                .{ "c_longdouble", Index.c_longdouble_type },
                .{ "c_longlong", Index.c_longlong_type },
                .{ "c_short", Index.c_short_type },
                .{ "c_uint", Index.c_uint_type },
                .{ "c_ulong", Index.c_ulong_type },
                .{ "c_ulonglong", Index.c_ulonglong_type },
                .{ "c_ushort", Index.c_ushort_type },
                .{ "comptime_float", Index.comptime_float_type },
                .{ "comptime_int", Index.comptime_int_type },
                .{ "f128", Index.f128_type },
                .{ "f16", Index.f16_type },
                .{ "f32", Index.f32_type },
                .{ "f64", Index.f64_type },
                .{ "f80", Index.f80_type },
                .{ "false", Index.bool_false },
                .{ "isize", Index.isize_type },
                .{ "noreturn", Index.noreturn_type },
                .{ "null", Index.null_value },
                .{ "true", Index.bool_true },
                .{ "type", Index.type_type },
                .{ "undefined", Index.undefined_value },
                .{ "usize", Index.usize_type },
                .{ "void", Index.void_type },
            });

            if (simples.get(identifier)) |index| {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = index,
                } };
            }

            if (identifier.len >= 2 and (identifier[0] == 'u' or identifier[0] == 'i')) blk: {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = try interpreter.ip.get(interpreter.allocator, Key{ .int_type = .{
                        .signedness = if (identifier[0] == 'u') .unsigned else .signed,
                        .bits = std.fmt.parseInt(u16, identifier[1..], 10) catch break :blk,
                    } }),
                } };
            }

            // Logic to find identifiers in accessible scopes
            if (interpreter.huntItDown(namespace, identifier, options)) |decl_index| {
                const decl = interpreter.ip.getDecl(decl_index);
                if (decl.index == .none) return InterpretResult{ .nothing = {} };
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = decl.node_idx,
                    .index = decl.index,
                } };
            }

            try interpreter.recordError(
                node_idx,
                "undeclared_identifier",
                "use of undeclared identifier '{s}'",
                .{identifier},
            );
            // return error.IdentifierNotFound;
            return InterpretResult{ .nothing = {} };
        },
        .field_access => {
            if (data[node_idx].rhs == 0) return error.CriticalAstFailure;
            const field_name = tree.tokenSlice(data[node_idx].rhs);

            var ir = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            var ir_value = try ir.getValue();

            const val_index = ir_value.index;
            const val = interpreter.ip.indexToKey(val_index);
            std.debug.assert(val.typeOf() != .none);
            const ty = interpreter.ip.indexToKey(val.typeOf());

            const inner_ty = switch (ty) {
                .pointer_type => |info| if (info.size == .One) interpreter.ip.indexToKey(info.elem_type) else ty,
                else => ty,
            };

            const can_have_fields: bool = switch (inner_ty) {
                .simple_type => |simple| switch (simple) {
                    .type => blk: {
                        if (interpreter.huntItDown(val.getNamespace(interpreter.ip.*), field_name, options)) |decl_index| {
                            const decl = interpreter.ip.getDecl(decl_index);
                            return InterpretResult{ .value = Value{
                                .interpreter = interpreter,
                                .node_idx = node_idx,
                                .index = decl.index,
                            } };
                        }

                        if (val == .unknown_value) {
                            return InterpretResult{ .value = Value{
                                .interpreter = interpreter,
                                .node_idx = data[node_idx].rhs,
                                .index = .unknown_unknown,
                            } };
                        }

                        switch (val) {
                            .error_set_type => |error_set_info| { // TODO
                                _ = error_set_info;
                            },
                            .union_type => {}, // TODO
                            .enum_type => |enum_index| { // TODO
                                const enum_info = interpreter.ip.getEnum(enum_index);
                                if (enum_info.fields.get(field_name)) |field| {
                                    _ = field;
                                    return InterpretResult{
                                        .value = Value{
                                            .interpreter = interpreter,
                                            .node_idx = data[node_idx].rhs,
                                            .index = .unknown_unknown, // TODO
                                        },
                                    };
                                }
                            },
                            else => break :blk false,
                        }
                        break :blk true;
                    },
                    else => false,
                },
                .pointer_type => |pointer_info| blk: {
                    if (pointer_info.size == .Slice) {
                        if (std.mem.eql(u8, field_name, "ptr")) {
                            var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                            many_ptr_info.pointer_type.size = .Many;
                            return InterpretResult{
                                .value = Value{
                                    .interpreter = interpreter,
                                    .node_idx = data[node_idx].rhs,
                                    // TODO resolve ptr of Slice
                                    .index = try interpreter.ip.get(interpreter.allocator, .{
                                        .unknown_value = .{ .ty = try interpreter.ip.get(interpreter.allocator, many_ptr_info) },
                                    }),
                                },
                            };
                        } else if (std.mem.eql(u8, field_name, "len")) {
                            return InterpretResult{
                                .value = Value{
                                    .interpreter = interpreter,
                                    .node_idx = data[node_idx].rhs,
                                    // TODO resolve length of Slice
                                    .index = try interpreter.ip.get(interpreter.allocator, .{
                                        .unknown_value = .{ .ty = Index.usize_type },
                                    }),
                                },
                            };
                        }
                    } else if (interpreter.ip.indexToKey(pointer_info.elem_type) == .array_type) {
                        if (std.mem.eql(u8, field_name, "len")) {
                            return InterpretResult{
                                .value = Value{
                                    .interpreter = interpreter,
                                    .node_idx = data[node_idx].rhs,
                                    // TODO resolve length of Slice
                                    .index = try interpreter.ip.get(interpreter.allocator, .{
                                        .unknown_value = .{ .ty = Index.usize_type },
                                    }),
                                },
                            };
                        }
                    }
                    break :blk true;
                },
                .array_type => |array_info| blk: {
                    if (std.mem.eql(u8, field_name, "len")) {
                        return InterpretResult{ .value = Value{
                            .interpreter = interpreter,
                            .node_idx = data[node_idx].rhs,
                            .index = try interpreter.ip.get(interpreter.allocator, .{ .int_u64_value = .{
                                .ty = .usize_type,
                                .int = array_info.len,
                            } }),
                        } };
                    }
                    break :blk true;
                },
                .optional_type => |optional_info| blk: {
                    if (!std.mem.eql(u8, field_name, "?")) break :blk false;

                    if (val_index == .type_type) {
                        try interpreter.recordError(
                            node_idx,
                            "null_unwrap",
                            "tried to unwrap optional of type `{}` which was null",
                            .{optional_info.payload_type.fmt(interpreter.ip.*)},
                        );
                        return error.InvalidOperation;
                    }
                    const result = switch (val) {
                        .optional_value => |optional_val| optional_val.val,
                        .unknown_value => val_index,
                        else => return error.InvalidOperation,
                    };
                    return InterpretResult{ .value = Value{
                        .interpreter = interpreter,
                        .node_idx = data[node_idx].rhs,
                        .index = result,
                    } };
                },
                .struct_type => |struct_index| blk: {
                    const struct_info = interpreter.ip.getStruct(struct_index);
                    if (struct_info.fields.getIndex(field_name)) |field_index| {
                        const field = struct_info.fields.values()[field_index];

                        const result = switch (val) {
                            .aggregate => |aggregate| aggregate.values[field_index],
                            .unknown_value => try interpreter.ip.get(interpreter.allocator, .{
                                .unknown_value = .{ .ty = field.ty },
                            }),
                            else => return error.InvalidOperation,
                        };

                        return InterpretResult{ .value = Value{
                            .interpreter = interpreter,
                            .node_idx = data[node_idx].rhs,
                            .index = result,
                        } };
                    }
                    break :blk true;
                },
                .enum_type => |enum_info| blk: { // TODO
                    _ = enum_info;
                    break :blk true;
                },
                .union_type => |union_info| blk: { // TODO
                    _ = union_info;
                    break :blk true;
                },
                .int_type,
                .error_union_type,
                .error_set_type,
                .function_type,
                .tuple_type,
                .vector_type,
                .anyframe_type,
                => false,

                .simple_value,
                .int_u64_value,
                .int_i64_value,
                .int_big_value,
                .float_16_value,
                .float_32_value,
                .float_64_value,
                .float_80_value,
                .float_128_value,
                .float_comptime_value,
                => unreachable,

                .bytes,
                .optional_value,
                .slice,
                .aggregate,
                .union_value,
                .null_value,
                .undefined_value,
                .unknown_value,
                => unreachable,
            };

            const accessed_ty = if (inner_ty == .simple_type and inner_ty.simple_type == .type) val else inner_ty;
            if (can_have_fields) {
                try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    "`{}` has no member '{s}'",
                    .{ accessed_ty.fmt(interpreter.ip.*), field_name },
                );
            } else {
                try interpreter.recordError(
                    node_idx,
                    "invalid_field_access",
                    "`{}` does not support field access",
                    .{accessed_ty.fmt(interpreter.ip.*)},
                );
            }
            return error.InvalidOperation;
        },
        .grouped_expression => {
            return try interpreter.interpret(data[node_idx].lhs, namespace, options);
        },
        .@"break" => {
            const label = if (data[node_idx].lhs == 0) null else tree.tokenSlice(data[node_idx].lhs);
            return if (data[node_idx].rhs == 0)
                InterpretResult{ .@"break" = label }
            else
                InterpretResult{ .break_with_value = .{ .label = label, .value = try (try interpreter.interpret(data[node_idx].rhs, namespace, options)).getValue() } };
        },
        .@"return" => {
            return if (data[node_idx].lhs == 0)
                InterpretResult{ .@"return" = {} }
            else
                InterpretResult{ .return_with_value = try (try interpreter.interpret(data[node_idx].lhs, namespace, options)).getValue() };
        },
        .@"if",
        .if_simple,
        => {
            const if_info = ast.fullIf(tree, node_idx).?;
            // if (options.observe_values) {
            const ir = try interpreter.interpret(if_info.ast.cond_expr, namespace, options);

            const condition = (try ir.getValue()).index;
            const condition_val = interpreter.ip.indexToKey(condition);
            const condition_ty = condition_val.typeOf();

            switch (condition_ty) {
                .bool_type => {},
                .unknown_type => return InterpretResult{ .nothing = {} },
                else => {
                    try interpreter.recordError(
                        if_info.ast.cond_expr,
                        "invalid_if_condition",
                        "expected `bool` but found `{}`",
                        .{condition_ty.fmt(interpreter.ip.*)},
                    );
                    return error.InvalidOperation;
                },
            }
            if (condition_val == .unknown_value) {
                return InterpretResult{ .nothing = {} };
            }

            std.debug.assert(condition == .bool_false or condition == .bool_true);
            if (condition == .bool_true) {
                return try interpreter.interpret(if_info.ast.then_expr, namespace, options);
            } else {
                if (if_info.ast.else_expr != 0) {
                    return try interpreter.interpret(if_info.ast.else_expr, namespace, options);
                }
            }
            return InterpretResult{ .nothing = {} };
        },
        .equal_equal => {
            var a = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            var b = try interpreter.interpret(data[node_idx].rhs, namespace, options);
            const a_value = a.maybeGetValue() orelse return InterpretResult{ .nothing = {} };
            const b_value = b.maybeGetValue() orelse return InterpretResult{ .nothing = {} };
            return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = if (a_value.index == b_value.index) .bool_true else .bool_false, // TODO eql function required?
                },
            };
        },
        .number_literal => {
            const s = tree.getNodeSource(node_idx);
            const nl = std.zig.parseNumberLiteral(s);

            if (nl == .failure) return error.CriticalAstFailure;

            const number_type = if (nl == .float) Index.comptime_float_type else Index.comptime_int_type;

            const value = try interpreter.ip.get(
                interpreter.allocator,
                switch (nl) {
                    .float => Key{
                        .float_comptime_value = try std.fmt.parseFloat(f128, s),
                    },
                    .int => if (s[0] == '-') Key{
                        .int_i64_value = .{
                            .ty = number_type,
                            .int = try std.fmt.parseInt(i64, s, 0),
                        },
                    } else Key{
                        .int_u64_value = .{
                            .ty = number_type,
                            .int = try std.fmt.parseInt(u64, s, 0),
                        },
                    },
                    .big_int => |base| blk: {
                        var big_int = try std.math.big.int.Managed.init(interpreter.allocator);
                        defer big_int.deinit();
                        const prefix_length: usize = if (base != .decimal) 2 else 0;
                        try big_int.setString(@intFromEnum(base), s[prefix_length..]);
                        std.debug.assert(number_type == .comptime_int_type);
                        break :blk Key{ .int_big_value = .{ .ty = number_type, .int = big_int.toConst() } };
                    },
                    .failure => return error.CriticalAstFailure,
                },
            );

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = value,
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
            // TODO: Actually consider operators

            if (std.mem.eql(u8, tree.getNodeSource(data[node_idx].lhs), "_")) {
                _ = try interpreter.interpret(data[node_idx].rhs, namespace, options);
                return InterpretResult{ .nothing = {} };
            }

            const lhs = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            const rhs = try interpreter.interpret(data[node_idx].rhs, namespace, options);

            const to_val = try lhs.getValue();
            const from_val = try rhs.getValue();

            const to_ty = interpreter.ip.indexToKey(to_val.index).typeOf();
            const from_ty = interpreter.ip.indexToKey(from_val.index).typeOf();

            // TODO report error
            _ = try interpreter.ip.cast(interpreter.allocator, to_ty, from_ty, builtin.target);

            return InterpretResult{ .nothing = {} };
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
                var final = std.ArrayList(u8).init(interpreter.allocator);
                var writer = final.writer();
                try writer.writeAll("log: ");

                for (params, 0..) |param, index| {
                    const ir_value = (try interpreter.interpret(param, namespace, options)).maybeGetValue() orelse {
                        try writer.writeAll("indeterminate");
                        continue;
                    };
                    const val = interpreter.ip.indexToKey(ir_value.index);
                    const ty = val.typeOf();

                    try writer.print("@as({}, {})", .{ ty.fmt(interpreter.ip.*), val.fmt(interpreter.ip.*) });
                    if (index != params.len - 1)
                        try writer.writeAll(", ");
                }
                try interpreter.recordError(node_idx, "compile_log", "{s}", .{try final.toOwnedSlice()});

                return InterpretResult{ .nothing = {} };
            }

            if (std.mem.eql(u8, call_name, "@compileError")) {
                if (params.len != 0) return error.InvalidBuiltin;
                const message = offsets.nodeToSlice(tree, params[0]);
                try interpreter.recordError(node_idx, "compile_error", "{s}", .{message});
                return InterpretResult{ .@"return" = {} };
            }

            if (std.mem.eql(u8, call_name, "@import")) {
                if (params.len == 0) return error.InvalidBuiltin;
                const import_param = params[0];
                if (tags[import_param] != .string_literal) return error.InvalidBuiltin;

                const import_str = tree.tokenSlice(main_tokens[import_param]);

                log.info("Resolving {s} from {s}", .{ import_str[1 .. import_str.len - 1], interpreter.uri });

                // TODO: Implement root support
                if (std.mem.eql(u8, import_str[1 .. import_str.len - 1], "root")) {
                    const struct_index = try interpreter.ip.createStruct(interpreter.allocator, .{
                        .fields = .{},
                        .namespace = .none,
                        .layout = .Auto,
                        .backing_int_ty = .none,
                        .status = .none,
                    });
                    return InterpretResult{ .value = Value{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        .index = try interpreter.ip.get(interpreter.allocator, .{ .unknown_value = .{
                            .ty = try interpreter.ip.get(interpreter.allocator, .{ .struct_type = struct_index }),
                        } }),
                    } };
                }

                var import_uri = (try interpreter.document_store.uriFromImportStr(interpreter.allocator, interpreter.getHandle().*, import_str[1 .. import_str.len - 1])) orelse return error.ImportFailure;
                defer interpreter.allocator.free(import_uri);

                const import_handle = interpreter.document_store.getOrLoadHandle(import_uri) orelse return error.ImportFailure;
                const import_interpreter = try import_handle.getComptimeInterpreter(interpreter.document_store, interpreter.ip);

                return import_interpreter.interpret(0, .none, options) catch |err| {
                    log.err("Failed to interpret node: {s}", .{@errorName(err)});
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                    return InterpretResult{
                        .value = Value{
                            .interpreter = import_interpreter,
                            .node_idx = 0,
                            .index = .unknown_type,
                        },
                    };
                };
            }

            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len == 0) return error.InvalidBuiltin;

                const types: []Index = try interpreter.allocator.alloc(Index, params.len);
                defer interpreter.allocator.free(types);

                for (params, types) |param, *out_type| {
                    const value = try (try interpreter.interpret(param, namespace, options)).getValue();
                    out_type.* = interpreter.ip.indexToKey(value.index).typeOf();
                }

                const peer_type = try interpreter.ip.resolvePeerTypes(interpreter.allocator, types, builtin.target);

                if (peer_type == .none) {
                    var output = std.ArrayListUnmanaged(u8){};
                    var writer = output.writer(interpreter.allocator);
                    try writer.writeAll("incompatible types: ");
                    for (types, 0..) |ty, i| {
                        if (i != 0) try writer.writeAll(", ");
                        try writer.print("`{}`", .{ty.fmt(interpreter.ip.*)});
                    }

                    try interpreter.recordError(node_idx, "invalid_typeof", "{s}", .{output.items});
                    return error.InvalidOperation;
                }

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = peer_type,
                } };
            }

            if (std.mem.eql(u8, call_name, "@hasDecl")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const ir_value = try (try interpreter.interpret(params[0], namespace, options)).getValue();
                const field_name = try (try interpreter.interpret(params[1], namespace, options)).getValue();

                const val = interpreter.ip.indexToKey(ir_value.index);
                const ty = val.typeOf();

                if (ty != .type_type) return error.InvalidBuiltin;

                const value_namespace = interpreter.ip.indexToKey(ty).getNamespace(interpreter.ip.*);
                if (value_namespace == .none) return error.InvalidBuiltin;

                const name = interpreter.ip.indexToKey(field_name.index).bytes; // TODO add checks

                const decls = interpreter.namespaces.items(.decls)[@intFromEnum(value_namespace)];
                const has_decl = decls.contains(name);

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = if (has_decl) .bool_true else .bool_false,
                } };
            }

            if (std.mem.eql(u8, call_name, "@as")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const as_type = try (try interpreter.interpret(params[0], namespace, options)).getValue();
                // const value = try (try interpreter.interpret(params[1], namespace, options)).getValue();

                if (interpreter.ip.indexToKey(as_type.index).typeOf() != .type_type) {
                    return error.InvalidBuiltin;
                }

                return InterpretResult{
                    .value = Value{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        // TODO port Sema.coerceExtra to InternPool
                        .index = try interpreter.ip.get(interpreter.allocator, .{
                            .unknown_value = .{ .ty = as_type.index },
                        }),
                    },
                };
            }

            log.err("Builtin not implemented: {s}", .{call_name});
            return error.InvalidBuiltin;
        },
        .string_literal => {
            const str = tree.getNodeSource(node_idx)[1 .. tree.getNodeSource(node_idx).len - 1];

            // const string_literal_type = try interpreter.ip.get(interpreter.allocator, Key{ .pointer_type = .{
            //     .elem_type = try interpreter.ip.get(interpreter.allocator, Key{ .array_type = .{
            //         .child = Index.u8_type,
            //         .len = @intCast(u64, str.len),
            //         .sentinel = try interpreter.ip.get(interpreter.allocator, Key{ .int_u64_value = .{ .ty = .u8_type, .int = 0 } }),
            //     } }),
            //     .sentinel = .none,
            //     .alignment = 0,
            //     .size = .One,
            //     .is_const = true,
            //     .is_volatile = false,
            //     .is_allowzero = false,
            //     .address_space = .generic,
            // } });

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = try interpreter.ip.get(interpreter.allocator, Key{ .bytes = str }),
            } };
        },
        // TODO: Add comptime autodetection; e.g. const MyArrayList = std.ArrayList(u8)
        .@"comptime" => {
            return try interpreter.interpret(data[node_idx].lhs, namespace, .{});
        },
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const func = tree.fullFnProto(&buf, node_idx).?;

            if (func.name_token == null) return InterpretResult{ .nothing = {} };
            const name = offsets.tokenToSlice(tree, func.name_token.?);

            // TODO: Resolve function type

            const function_type = try interpreter.ip.get(interpreter.allocator, Key{ .function_type = .{
                .calling_convention = .Unspecified,
                .alignment = 0,
                .is_generic = false,
                .is_var_args = false,
                .return_type = Index.none,
                .args = &.{},
            } });

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

            if (namespace != .none) {
                const decls = &interpreter.namespaces.items(.decls)[@intFromEnum(namespace)];

                const decl_index = try interpreter.ip.createDecl(interpreter.allocator, .{
                    .name = name,
                    .node_idx = node_idx,
                    .index = function_type,
                    .alignment = 0, // TODO
                    .address_space = .generic, // TODO
                    .is_pub = false, // TODO
                    .is_exported = false, // TODO
                });
                try decls.putNoClobber(interpreter.allocator, name, decl_index);
            }

            return InterpretResult{ .nothing = {} };
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
            var params: [1]Ast.Node.Index = undefined;
            const call_full = tree.fullCall(&params, node_idx) orelse unreachable;

            var args = try std.ArrayListUnmanaged(Value).initCapacity(interpreter.allocator, call_full.ast.params.len);
            defer args.deinit(interpreter.allocator);

            for (call_full.ast.params) |param| {
                args.appendAssumeCapacity(try (try interpreter.interpret(param, namespace, .{})).getValue());
            }

            const func_id_result = try interpreter.interpret(call_full.ast.fn_expr, namespace, .{});
            const func_id_val = try func_id_result.getValue();

            const call_res = try interpreter.call(namespace, func_id_val.node_idx, args.items, options);
            // TODO: Figure out call result memory model; this is actually fine because newScope
            // makes this a child of the decl scope which is freed on refresh... in theory

            return switch (call_res.result) {
                .value => |v| .{ .value = v },
                .nothing => .{ .nothing = {} },
            };
        },
        .bool_not => {
            const result = try interpreter.interpret(data[node_idx].lhs, namespace, .{});
            const ir_value = try result.getValue();

            const val = ir_value.index;
            const ty = interpreter.ip.indexToKey(ir_value.index).typeOf();

            if (ty == .unknown_type) {
                return InterpretResult{ .value = .{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = try interpreter.ip.get(interpreter.allocator, .{
                        .unknown_value = .{ .ty = .bool_type },
                    }),
                } };
            }

            if (ty != .bool_type) {
                try interpreter.recordError(
                    node_idx,
                    "invalid_deref",
                    "expected type `bool` but got `{}`",
                    .{ty.fmt(interpreter.ip.*)},
                );
                return error.InvalidOperation;
            }

            std.debug.assert(val == .bool_false or val == .bool_true);
            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = if (val == .bool_false) .bool_true else .bool_false,
            } };
        },
        .address_of => {
            // TODO: Make const pointers if we're drawing from a const;
            // variables are the only non-const(?)

            const result = try interpreter.interpret(data[node_idx].lhs, namespace, .{});
            const ir_value = try result.getValue();

            const ty = interpreter.ip.indexToKey(ir_value.index).typeOf();

            const pointer_type = try interpreter.ip.get(interpreter.allocator, Key{ .pointer_type = .{
                .elem_type = ty,
                .sentinel = .none,
                .alignment = 0,
                .size = .One,
                .is_const = false,
                .is_volatile = false,
                .is_allowzero = false,
                .address_space = .generic,
            } });

            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = try interpreter.ip.get(interpreter.allocator, .{
                    .unknown_value = .{ .ty = pointer_type },
                }),
            } };
        },
        .deref => {
            const result = try interpreter.interpret(data[node_idx].lhs, namespace, .{});
            const ir_value = (try result.getValue());

            const ty = interpreter.ip.indexToKey(ir_value.index).typeOf();

            if (ty == .unknown_type) {
                return InterpretResult{ .value = .{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .index = .unknown_unknown,
                } };
            }

            const type_key = interpreter.ip.indexToKey(ty);

            if (type_key != .pointer_type) {
                try interpreter.recordError(node_idx, "invalid_deref", "cannot deference non-pointer", .{});
                return error.InvalidOperation;
            }

            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .index = try interpreter.ip.get(interpreter.allocator, .{
                    .unknown_value = .{ .ty = type_key.pointer_type.elem_type },
                }),
            } };
        },
        else => {
            log.err("Unhandled {any}", .{tags[node_idx]});
            return InterpretResult{ .nothing = {} };
        },
    }
}

pub const CallResult = struct {
    namespace: Namespace.Index,
    result: union(enum) {
        value: Value,
        nothing,
    },
};

pub fn call(
    interpreter: *ComptimeInterpreter,
    namespace: Namespace.Index,
    func_node_idx: Ast.Node.Index,
    arguments: []const Value,
    options: InterpretOptions,
) InterpretError!CallResult {
    // _ = options;

    // TODO: type check args

    const tree = interpreter.getHandle().tree;
    const node_tags = tree.nodes.items(.tag);

    if (node_tags[func_node_idx] != .fn_decl) return error.CriticalAstFailure;

    var buf: [1]Ast.Node.Index = undefined;
    var proto = tree.fullFnProto(&buf, func_node_idx) orelse return error.CriticalAstFailure;

    // TODO: Make argument namespace to evaluate arguments in
    try interpreter.namespaces.append(interpreter.allocator, .{
        .parent = namespace,
        .node_idx = func_node_idx,
        .ty = .none,
    });
    const fn_namespace = @as(Namespace.Index, @enumFromInt(interpreter.namespaces.len - 1));

    var arg_it = proto.iterate(&tree);
    var arg_index: usize = 0;
    while (ast.nextFnParam(&arg_it)) |param| {
        if (arg_index >= arguments.len) return error.MissingArguments;
        var tex = try (try interpreter.interpret(param.type_expr, fn_namespace, options)).getValue();
        const tex_ty = interpreter.ip.indexToKey(tex.index).typeOf();
        if (tex_ty != .type_type) {
            try interpreter.recordError(
                param.type_expr,
                "expected_type",
                "expected type 'type', found '{}'",
                .{tex_ty.fmt(interpreter.ip.*)},
            );
            return error.InvalidCast;
        }
        // TODO validate that `arguments[arg_index].index`'s types matches tex.index
        if (param.name_token) |name_token| {
            const name = offsets.tokenToSlice(tree, name_token);

            const decls = &interpreter.namespaces.items(.decls)[@intFromEnum(fn_namespace)];
            const decl_index = try interpreter.ip.createDecl(interpreter.allocator, .{
                .name = name,
                .node_idx = name_token,
                .index = arguments[arg_index].index,
                .alignment = 0, // TODO
                .address_space = .generic, // TODO
                .is_pub = true, // TODO
                .is_exported = false, // TODO
            });
            try decls.putNoClobber(interpreter.allocator, name, decl_index);
            arg_index += 1;
        }
    }

    const body = tree.nodes.items(.data)[func_node_idx].rhs;
    const result = try interpreter.interpret(body, fn_namespace, .{});

    // TODO: Defers
    return CallResult{
        .namespace = fn_namespace,
        .result = switch (result) {
            .@"return", .nothing => .{ .nothing = {} }, // nothing could be due to an error
            .return_with_value => |v| .{ .value = v },
            else => @panic("bruh"),
        },
    };
}
