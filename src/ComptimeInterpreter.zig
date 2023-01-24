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

const log = std.log.scoped(.comptime_interpreter);

allocator: std.mem.Allocator,
ip: InternPool = .{},
document_store: *DocumentStore,
uri: DocumentStore.Uri,
decls: std.ArrayListUnmanaged(Decl) = .{},
namespaces: std.MultiArrayList(Namespace) = .{},

/// Interpreter diagnostic errors
errors: std.AutoArrayHashMapUnmanaged(Ast.Node.Index, InterpreterError) = .{},

pub fn getHandle(interpreter: *ComptimeInterpreter) *const DocumentStore.Handle {
    // This interpreter is loaded from a known-valid handle so a valid handle must exist
    return interpreter.document_store.getHandle(interpreter.uri).?;
}

pub const InterpreterError = struct {
    code: []const u8,
    message: []const u8,
};

pub fn recordError(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    code: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    const message = try std.fmt.allocPrint(interpreter.allocator, fmt, args);
    errdefer interpreter.allocator.free(message);
    const previous = try interpreter.errors.fetchPut(interpreter.allocator, node_idx, .{
        .code = code,
        .message = message,
    });
    if (previous != null) interpreter.allocator.free(message);
}

pub fn deinit(interpreter: *ComptimeInterpreter) void {
    for (interpreter.errors.values()) |err| {
        interpreter.allocator.free(err.message);
    }

    interpreter.errors.deinit(interpreter.allocator);
    interpreter.ip.deinit(interpreter.allocator);

    var i: usize = 0;
    while (i < interpreter.namespaces.len) : (i += 1) {
        interpreter.namespaces.items(.decls)[i].deinit(interpreter.allocator);
        interpreter.namespaces.items(.usingnamespaces)[i].deinit(interpreter.allocator);
    }
    interpreter.namespaces.deinit(interpreter.allocator);
    interpreter.decls.deinit(interpreter.allocator);
}

pub const Type = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    ty: Index,
};

pub const Value = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    ty: Index,
    val: Index,
};

pub const Decl = struct {
    name: []const u8,
    ty: Index,
    val: Index,
    alignment: u16,
    address_space: std.builtin.AddressSpace,
    is_pub: bool,
    is_exported: bool,
};

// pub const Comptimeness = enum { @"comptime", runtime };

pub const NamespaceIndex = InternPool.NamespaceIndex;

pub const Namespace = struct {
    /// always points to Namespace or Index.none
    parent: NamespaceIndex,
    node_idx: Ast.Node.Index,
    /// Will be a struct, enum, union, opaque or .none
    ty: Index,
    decls: std.StringArrayHashMapUnmanaged(Decl) = .{},
    usingnamespaces: std.ArrayListUnmanaged(NamespaceIndex) = .{},

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
    namespace: NamespaceIndex,
    decl_name: []const u8,
    options: InterpretOptions,
) ?Decl {
    _ = options;

    var current_namespace = namespace;
    while (current_namespace != .none) {
        const decls: std.StringArrayHashMapUnmanaged(Decl) = interpreter.namespaces.items(.decls)[@enumToInt(current_namespace)];
        defer current_namespace = interpreter.namespaces.items(.parent)[@enumToInt(current_namespace)];

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
    namespace: NamespaceIndex,
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
            const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });

            try interpreter.namespaces.append(interpreter.allocator, .{
                .parent = namespace,
                .node_idx = node_idx,
                .ty = undefined,
            });
            const container_namespace = @intToEnum(NamespaceIndex, interpreter.namespaces.len - 1);

            var fields = std.ArrayListUnmanaged(InternPool.Struct.Field){};
            defer fields.deinit(interpreter.allocator);

            var buffer: [2]Ast.Node.Index = undefined;
            const members = ast.declMembers(tree, node_idx, &buffer);
            for (members) |member| {
                const container_field = ast.containerField(tree, member) orelse {
                    _ = try interpreter.interpret(member, container_namespace, options);
                    continue;
                };

                var init_type_value = try (try interpreter.interpret(container_field.ast.type_expr, container_namespace, .{})).getValue();

                var default_value = if (container_field.ast.value_expr == 0)
                    Index.none
                else
                    (try (try interpreter.interpret(container_field.ast.value_expr, container_namespace, .{})).getValue()).val; // TODO check ty

                if (init_type_value.ty != type_type) {
                    try interpreter.recordError(
                        container_field.ast.type_expr,
                        "expected_type",
                        "expected type 'type', found '{}'",
                        .{init_type_value.ty.fmtType(interpreter.ip)},
                    );
                    continue;
                }
                const field_name = try interpreter.ip.get(interpreter.allocator, .{
                    .bytes = tree.tokenSlice(container_field.ast.main_token),
                });
                const field: InternPool.Struct.Field = .{
                    .name = field_name,
                    .ty = init_type_value.val,
                    .default_value = default_value,
                    .alignment = 0, // TODO,
                    .is_comptime = false, // TODO
                };

                try fields.append(interpreter.allocator, field);
            }

            const struct_type = try interpreter.ip.get(interpreter.allocator, Key{
                .struct_type = .{
                    .fields = fields.items,
                    .namespace = namespace,
                    .layout = .Auto, // TODO
                    .backing_int_ty = .none, // TODO
                },
            });
            interpreter.namespaces.items(.ty)[@enumToInt(container_namespace)] = struct_type;

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = type_type,
                .val = struct_type,
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
            var decls = &interpreter.namespaces.items(.decls)[@enumToInt(namespace)];

            const name = analysis.getDeclName(tree, node_idx).?;
            if (decls.contains(name))
                return InterpretResult{ .nothing = {} };

            const decl = ast.varDecl(tree, node_idx).?;

            const type_value = if (decl.ast.type_node != 0) (try interpreter.interpret(decl.ast.type_node, namespace, .{})).maybeGetValue() else null;
            const init_value = if (decl.ast.init_node != 0) (try interpreter.interpret(decl.ast.init_node, namespace, .{})).maybeGetValue() else null;

            if (type_value == null and init_value == null) return InterpretResult{ .nothing = {} };

            if (type_value) |v| {
                const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });
                if (v.ty != type_type) return InterpretResult{ .nothing = {} };
            }

            try decls.putNoClobber(interpreter.allocator, name, .{
                .name = name,
                .ty = if (type_value) |v| v.val else init_value.?.ty,
                .val = if (init_value) |init| init.val else .none,
                .alignment = 0, // TODO
                .address_space = .generic, // TODO
                .is_pub = true, // TODO
                .is_exported = false, // TODO
            });

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
            const block_namespace = @intToEnum(NamespaceIndex, interpreter.namespaces.len - 1);

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                const ret = try interpreter.interpret(idx, block_namespace, options);
                switch (ret) {
                    .@"break" => |lllll| {
                        const maybe_block_label_string = if (interpreter.namespaces.get(@enumToInt(namespace)).getLabel(tree)) |i| tree.tokenSlice(i) else null;
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
                        const maybe_block_label_string = if (interpreter.namespaces.get(@enumToInt(namespace)).getLabel(tree)) |i| tree.tokenSlice(i) else null;

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

            const simples = std.ComptimeStringMap(InternPool.Simple, .{
                .{ "anyerror", .anyerror },
                .{ "anyframe", .@"anyframe" },
                .{ "anyopaque", .anyopaque },
                .{ "bool", .bool },
                .{ "c_int", .c_int },
                .{ "c_long", .c_long },
                .{ "c_longdouble", .c_longdouble },
                .{ "c_longlong", .c_longlong },
                .{ "c_short", .c_short },
                .{ "c_uint", .c_uint },
                .{ "c_ulong", .c_ulong },
                .{ "c_ulonglong", .c_ulonglong },
                .{ "c_ushort", .c_ushort },
                .{ "comptime_float", .comptime_float },
                .{ "comptime_int", .comptime_int },
                .{ "f128", .f128 },
                .{ "f16", .f16 },
                .{ "f32", .f32 },
                .{ "f64", .f64 },
                .{ "f80", .f80 },
                .{ "false", .bool_false },
                .{ "isize", .isize },
                .{ "noreturn", .noreturn },
                .{ "null", .null_value },
                .{ "true", .bool_true },
                .{ "type", .type },
                .{ "undefined", .undefined_value },
                .{ "usize", .usize },
                .{ "void", .void },
            });

            if (simples.get(identifier)) |simple| {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = simple.toType() }),
                    .val = try interpreter.ip.get(interpreter.allocator, Key{ .simple = simple }),
                } };
            }

            if (identifier.len >= 2 and (identifier[0] == 'u' or identifier[0] == 'i')) blk: {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, Key{ .int_type = .{
                        .signedness = if (identifier[0] == 'u') .unsigned else .signed,
                        .bits = std.fmt.parseInt(u16, identifier[1..], 10) catch break :blk,
                    } }),
                } };
            }

            // Logic to find identifiers in accessible scopes
            if (interpreter.huntItDown(namespace, identifier, options)) |decl| {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = decl.ty,
                    .val = decl.val,
                } };
            }

            try interpreter.recordError(
                node_idx,
                "undeclared_identifier",
                "use of undeclared identifier '{s}'",
                .{identifier},
            );
            return error.IdentifierNotFound;
        },
        .field_access => {
            if (data[node_idx].rhs == 0) return error.CriticalAstFailure;
            const field_name = tree.tokenSlice(data[node_idx].rhs);

            var ir = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            var irv = try ir.getValue();

            const lhs = interpreter.ip.indexToKey(irv.ty);
            const inner_lhs = switch (lhs) {
                .pointer_type => |info| if (info.size == .One) interpreter.ip.indexToKey(info.elem_type) else lhs,
                else => lhs,
            };

            const can_have_fields: bool = switch (inner_lhs) {
                .simple => |simple| switch (simple) {
                    .type => blk: {
                        if (irv.val == .none) break :blk true;

                        const ty_key = interpreter.ip.indexToKey(irv.val);
                        if (interpreter.huntItDown(ty_key.getNamespace(), field_name, options)) |decl| {
                            return InterpretResult{ .value = Value{
                                .interpreter = interpreter,
                                .node_idx = node_idx,
                                .ty = decl.ty,
                                .val = decl.val,
                            } };
                        }

                        switch (ty_key) {
                            .error_set_type => |error_set_info| { // TODO
                                _ = error_set_info;
                            },
                            .union_type => {}, // TODO
                            .enum_type => |enum_info| { // TODO
                                if (interpreter.ip.contains(Key{ .bytes = field_name })) |field_name_index| {
                                    for (enum_info.fields) |field| {
                                        if (field.name != field_name_index) continue;
                                        return InterpretResult{
                                            .value = Value{
                                                .interpreter = interpreter,
                                                .node_idx = data[node_idx].rhs,
                                                .ty = irv.val,
                                                .val = .none, // TODO resolve enum value
                                            },
                                        };
                                    }
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
                                    .ty = try interpreter.ip.get(interpreter.allocator, many_ptr_info),
                                    .val = .none, // TODO resolve ptr of Slice
                                },
                            };
                        } else if (std.mem.eql(u8, field_name, "len")) {
                            return InterpretResult{
                                .value = Value{
                                    .interpreter = interpreter,
                                    .node_idx = data[node_idx].rhs,
                                    .ty = try interpreter.ip.get(interpreter.allocator, .{ .simple = .usize }),
                                    .val = .none, // TODO resolve length of Slice
                                },
                            };
                        }
                    } else if (interpreter.ip.indexToKey(pointer_info.elem_type) == .array_type) {
                        if (std.mem.eql(u8, field_name, "len")) {
                            return InterpretResult{
                                .value = Value{
                                    .interpreter = interpreter,
                                    .node_idx = data[node_idx].rhs,
                                    .ty = try interpreter.ip.get(interpreter.allocator, .{ .simple = .usize }),
                                    .val = .none, // TODO resolve length of Slice
                                },
                            };
                        }
                    }
                    break :blk true;
                },
                .array_type => |array_info| blk: {
                    const len_value = try interpreter.ip.get(interpreter.allocator, .{ .int_u64_value = array_info.len });

                    if (std.mem.eql(u8, field_name, "len")) {
                        return InterpretResult{ .value = Value{
                            .interpreter = interpreter,
                            .node_idx = data[node_idx].rhs,
                            .ty = try interpreter.ip.get(interpreter.allocator, .{ .simple = .comptime_int }),
                            .val = len_value,
                        } };
                    }
                    break :blk true;
                },
                .optional_type => |optional_info| blk: {
                    if (!std.mem.eql(u8, field_name, "?")) break :blk false;
                    const null_value = try interpreter.ip.get(interpreter.allocator, .{ .simple = .null_value });
                    if (irv.val == null_value) {
                        try interpreter.recordError(
                            node_idx,
                            "null_unwrap",
                            "tried to unwrap optional of type `{}` which was null",
                            .{irv.ty.fmtType(interpreter.ip)},
                        );
                        return error.InvalidOperation;
                    } else {
                        return InterpretResult{ .value = Value{
                            .interpreter = interpreter,
                            .node_idx = data[node_idx].rhs,
                            .ty = optional_info.payload_type,
                            .val = irv.val,
                        } };
                    }
                },
                .struct_type => |struct_info| blk: {
                    // if the intern pool does not contain the field name, it is impossible that there is a field with the given name
                    const field_name_index = interpreter.ip.contains(Key{ .bytes = field_name }) orelse break :blk true;

                    for (struct_info.fields) |field, i| {
                        if (field.name != field_name_index) continue;
                        const val = found_val: {
                            if (irv.val == .none) break :found_val .none;
                            const val_key = interpreter.ip.indexToKey(irv.val);
                            if (val_key != .aggregate) break :found_val .none;
                            break :found_val val_key.aggregate[i];
                        };

                        return InterpretResult{ .value = Value{
                            .interpreter = interpreter,
                            .node_idx = data[node_idx].rhs,
                            .ty = field.ty,
                            .val = val,
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
                else => false,
            };

            if (can_have_fields) {
                try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    "`{}` has no member '{s}'",
                    .{ irv.ty.fmtType(interpreter.ip), field_name },
                );
            } else {
                try interpreter.recordError(
                    node_idx,
                    "invalid_field_access",
                    "`{}` does not support field access",
                    .{irv.ty.fmtType(interpreter.ip)},
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
            const if_info = ast.ifFull(tree, node_idx);
            // TODO: Don't evaluate runtime ifs
            // if (options.observe_values) {
            const ir = try interpreter.interpret(if_info.ast.cond_expr, namespace, options);

            const false_value = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool_false });
            const true_value = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool_true });

            const condition = (try ir.getValue()).val;
            std.debug.assert(condition == false_value or condition == true_value);
            if (condition == true_value) {
                return try interpreter.interpret(if_info.ast.then_expr, namespace, options);
            } else {
                if (if_info.ast.else_expr != 0) {
                    return try interpreter.interpret(if_info.ast.else_expr, namespace, options);
                } else return InterpretResult{ .nothing = {} };
            }
        },
        .equal_equal => {
            var a = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            var b = try interpreter.interpret(data[node_idx].rhs, namespace, options);
            return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool }),
                    .val = try interpreter.ip.get(interpreter.allocator, Key{ .simple = if (a.value.val == b.value.val) .bool_true else .bool_false }), // TODO eql function required?
                },
            };
        },
        .number_literal => {
            const s = tree.getNodeSource(node_idx);
            const nl = std.zig.parseNumberLiteral(s);

            if (nl == .failure) return error.CriticalAstFailure;

            const number_type = try interpreter.ip.get(interpreter.allocator, Key{
                .simple = if (nl == .float) .comptime_float else .comptime_int,
            });

            const value = try interpreter.ip.get(
                interpreter.allocator,
                switch (nl) {
                    .float => Key{
                        .float_128_value = try std.fmt.parseFloat(f128, s),
                    },
                    .int => if (s[0] == '-') Key{
                        .int_i64_value = try std.fmt.parseInt(i64, s, 0),
                    } else Key{
                        .int_u64_value = try std.fmt.parseInt(u64, s, 0),
                    },
                    .big_int => |base| blk: {
                        var big_int = try std.math.big.int.Managed.init(interpreter.allocator);
                        defer big_int.deinit();
                        const prefix_length: usize = if (base != .decimal) 2 else 0;
                        try big_int.setString(@enumToInt(base), s[prefix_length..]);
                        break :blk Key{ .int_big_value = big_int.toConst() };
                    },
                    .failure => return error.CriticalAstFailure,
                },
            );

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = number_type,
                .val = value,
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

            var ir = try interpreter.interpret(data[node_idx].lhs, namespace, options);
            var to_value = try ir.getValue();
            var from_value = (try (try interpreter.interpret(data[node_idx].rhs, namespace, options)).getValue());

            // TODO report error
            _ = try interpreter.ip.cast(interpreter.allocator, to_value.ty, from_value.ty, builtin.target);

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

                for (params) |param, index| {
                    var value = (try interpreter.interpret(param, namespace, options)).maybeGetValue() orelse {
                        try writer.writeAll("indeterminate");
                        continue;
                    };
                    try writer.print("@as({}, {})", .{ value.ty.fmtType(interpreter.ip), value.val.fmtValue(value.ty, interpreter.ip) });
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
                    return InterpretResult{ .value = Value{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        .ty = try interpreter.ip.get(interpreter.allocator, Key{ .struct_type = .{
                            .fields = &.{},
                            .namespace = .none,
                            .layout = .Auto,
                            .backing_int_ty = .none,
                        } }),
                        .val = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .undefined_value }),
                    } };
                }

                var import_uri = (try interpreter.document_store.uriFromImportStr(interpreter.allocator, interpreter.getHandle().*, import_str[1 .. import_str.len - 1])) orelse return error.ImportFailure;
                defer interpreter.allocator.free(import_uri);

                var handle = interpreter.document_store.getOrLoadHandle(import_uri) orelse return error.ImportFailure;
                try interpreter.document_store.ensureInterpreterExists(handle.uri);

                return InterpretResult{
                    .value = Value{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type }),
                        .val = .none, // TODO
                    },
                };
            }

            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len != 1) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], namespace, options)).getValue();
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type }),
                    .val = value.ty,
                } };
            }

            if (std.mem.eql(u8, call_name, "@hasDecl")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], namespace, options)).getValue();
                const field_name = try (try interpreter.interpret(params[1], namespace, options)).getValue();

                const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });

                if (value.ty != type_type) return error.InvalidBuiltin;
                if (interpreter.ip.indexToKey(field_name.ty) != .pointer_type) return error.InvalidBuiltin; // Check if it's a []const u8

                const value_namespace = interpreter.ip.indexToKey(value.val).getNamespace();
                if (value_namespace == .none) return error.InvalidBuiltin;

                const name = interpreter.ip.indexToKey(field_name.val).bytes; // TODO add checks

                const decls = interpreter.namespaces.items(.decls)[@enumToInt(value_namespace)];
                const has_decl = decls.contains(name);

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool }),
                    .val = try interpreter.ip.get(interpreter.allocator, Key{ .simple = if (has_decl) .bool_true else .bool_false }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@as")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const as_type = try (try interpreter.interpret(params[0], namespace, options)).getValue();
                const value = try (try interpreter.interpret(params[1], namespace, options)).getValue();

                const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });

                if (as_type.ty != type_type) return error.InvalidBuiltin;

                return InterpretResult{
                    .value = Value{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        .ty = as_type.val,
                        .val = value.val, // TODO port Sema.coerceExtra to InternPool
                    },
                };
            }

            log.err("Builtin not implemented: {s}", .{call_name});
            return error.InvalidBuiltin;
        },
        .string_literal => {
            const str = tree.getNodeSource(node_idx)[1 .. tree.getNodeSource(node_idx).len - 1];

            const string_literal_type = try interpreter.ip.get(interpreter.allocator, Key{ .pointer_type = .{
                .elem_type = try interpreter.ip.get(interpreter.allocator, Key{ .array_type = .{
                    .child = try interpreter.ip.get(interpreter.allocator, Key{ .int_type = .{
                        .signedness = .unsigned,
                        .bits = 8,
                    } }),
                    .len = @intCast(u64, str.len),
                    .sentinel = try interpreter.ip.get(interpreter.allocator, Key{ .int_u64_value = 0 }),
                } }),
                .sentinel = .none,
                .alignment = 0,
                .size = .One,
                .is_const = true,
                .is_volatile = false,
                .is_allowzero = false,
                .address_space = .generic,
            } });

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = string_literal_type,
                .val = try interpreter.ip.get(interpreter.allocator, Key{ .bytes = str }),
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
            const func = ast.fnProto(tree, node_idx, &buf).?;

            // TODO: Resolve function type

            const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });

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

            const name = offsets.tokenToSlice(tree, func.name_token.?);

            if (namespace != .none) {
                const decls = &interpreter.namespaces.items(.decls)[@enumToInt(namespace)];
                try decls.put(interpreter.allocator, name, .{
                    .name = name,
                    .ty = type_type,
                    .val = function_type,
                    .alignment = 0, // TODO
                    .address_space = .generic, // TODO
                    .is_pub = false, // TODO
                    .is_exported = false, // TODO
                });
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
            const call_full = ast.callFull(tree, node_idx, &params).?;

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
            const bool_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool });
            const value = try result.getValue();

            if (value.ty != bool_type) {
                try interpreter.recordError(
                    node_idx,
                    "invalid_deref",
                    "expected type `bool` but got `{}`",
                    .{value.ty.fmtType(interpreter.ip)},
                );
                return error.InvalidOperation;
            }

            const false_value = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool_false });
            const true_value = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .bool_true });

            std.debug.assert(value.val == false_value or value.val == true_value);
            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = bool_type,
                .val = if (value.val == false_value) true_value else false_value,
            } };
        },
        .address_of => {
            // TODO: Make const pointers if we're drawing from a const;
            // variables are the only non-const(?)

            const result = try interpreter.interpret(data[node_idx].lhs, namespace, .{});
            const value = (try result.getValue());

            const pointer_type = try interpreter.ip.get(interpreter.allocator, Key{ .pointer_type = .{
                .elem_type = value.ty,
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
                .ty = pointer_type,
                .val = value.val,
            } };
        },
        .deref => {
            const result = try interpreter.interpret(data[node_idx].lhs, namespace, .{});
            const value = (try result.getValue());

            const type_key = interpreter.ip.indexToKey(value.ty);

            if (type_key != .pointer_type) {
                try interpreter.recordError(node_idx, "invalid_deref", "cannot deference non-pointer", .{});
                return error.InvalidOperation;
            }

            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = type_key.pointer_type.elem_type,
                .val = value.val,
            } };
        },
        else => {
            log.err("Unhandled {any}", .{tags[node_idx]});
            return InterpretResult{ .nothing = {} };
        },
    }
}

pub const CallResult = struct {
    namespace: NamespaceIndex,
    result: union(enum) {
        value: Value,
        nothing,
    },
};

pub fn call(
    interpreter: *ComptimeInterpreter,
    namespace: NamespaceIndex,
    func_node_idx: Ast.Node.Index,
    arguments: []const Value,
    options: InterpretOptions,
) InterpretError!CallResult {
    // _ = options;

    // TODO: type check args

    const tree = interpreter.getHandle().tree;

    var buf: [1]Ast.Node.Index = undefined;
    var proto = ast.fnProto(tree, func_node_idx, &buf) orelse return error.CriticalAstFailure;

    // TODO: Make argument namespace to evaluate arguments in
    try interpreter.namespaces.append(interpreter.allocator, .{
        .parent = namespace,
        .node_idx = func_node_idx,
        .ty = .none,
    });
    const fn_namespace = @intToEnum(NamespaceIndex, interpreter.namespaces.len - 1);

    const type_type = try interpreter.ip.get(interpreter.allocator, Key{ .simple = .type });

    var arg_it = proto.iterate(&tree);
    var arg_index: usize = 0;
    while (ast.nextFnParam(&arg_it)) |param| {
        if (arg_index >= arguments.len) return error.MissingArguments;
        var tex = try (try interpreter.interpret(param.type_expr, fn_namespace, options)).getValue();
        if (tex.ty != type_type) {
            try interpreter.recordError(
                param.type_expr,
                "expected_type",
                "expected type 'type', found '{}'",
                .{tex.ty.fmtType(interpreter.ip)},
            );
            return error.InvalidCast;
        }
        if (param.name_token) |name_token| {
            const name = offsets.tokenToSlice(tree, name_token);

            try interpreter.namespaces.items(.decls)[@enumToInt(fn_namespace)].put(interpreter.allocator, name, .{
                .name = name,
                .ty = tex.val,
                .val = arguments[arg_index].val,
                .alignment = 0, // TODO
                .address_space = .generic, // TODO
                .is_pub = true, // TODO
                .is_exported = false, // TODO
            });
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
