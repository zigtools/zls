//! Hacky comptime interpreter, courtesy of midnight code run fuelled by spite;
//! hope that one day this can use async... <33

// TODO: DODify

const std = @import("std");
const builtin = @import("builtin");
const ast = @import("ast.zig");
const zig = std.zig;
const Ast = zig.Ast;
const analysis = @import("analysis.zig");
const DocumentStore = @import("DocumentStore.zig");

pub const InternPool = @import("InternPool.zig");
pub const IPIndex = InternPool.Index;
pub const IPKey = InternPool.Key;
pub const ComptimeInterpreter = @This();

const log = std.log.scoped(.comptime_interpreter);

// TODO: Investigate arena

allocator: std.mem.Allocator,
arena: std.heap.ArenaAllocator,
ip: InternPool = .{},
document_store: *DocumentStore,
uri: DocumentStore.Uri,
scopes: std.MultiArrayList(Scope) = .{},

/// Interpreter diagnostic errors
errors: std.AutoArrayHashMapUnmanaged(Ast.Node.Index, InterpreterError) = .{},

pub fn getHandle(interpreter: *ComptimeInterpreter) *const DocumentStore.Handle {
    // This interpreter is loaded from a known-valid handle so a valid handle must exist
    return interpreter.document_store.getOrLoadHandle(interpreter.uri).?;
}

pub const InterpreterError = struct {
    code: []const u8,
    message: []const u8,
};

/// `message` must be allocated with interpreter allocator
pub fn recordError(interpreter: *ComptimeInterpreter, node_idx: Ast.Node.Index, code: []const u8, message: []const u8) error{OutOfMemory}!void {
    try interpreter.errors.put(interpreter.allocator, node_idx, .{
        .code = code,
        .message = message,
    });
}

pub fn deinit(interpreter: *ComptimeInterpreter) void {
    var err_it = interpreter.errors.iterator();
    while (err_it.next()) |entry| interpreter.allocator.free(entry.value_ptr.message);

    interpreter.errors.deinit(interpreter.allocator);
    interpreter.ip.deinit(interpreter.allocator);

    var i: usize = 0;
    while (i < interpreter.scopes.len) : (i += 1) {
        interpreter.scopes.items(.child_scopes)[i].deinit(interpreter.allocator);
    }
    interpreter.scopes.deinit(interpreter.allocator);
}

pub const Type = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    ty: IPIndex,
};

pub const Value = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    ty: IPIndex,
    val: IPIndex,
};

pub const FieldDefinition = struct {
    node_idx: Ast.Node.Index,
    /// Store name so tree doesn't need to be used to access field name
    /// When the field is a tuple field, `name` will be an empty slice
    name: []const u8,
    ty: Type,
    default_value: ?Value,
};

pub const Declaration = struct {
    scope: u32,

    node_idx: Ast.Node.Index,
    /// Store name so tree doesn't need to be used to access declaration name
    name: []const u8,

    /// If value is null, declaration has not been interpreted yet
    value: ?Value = null,

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

    pub fn getValue(decl: *Declaration) InterpretError!Value {
        var interpreter = decl.scope.interpreter;
        const tree = decl.scope.interpreter.getHandle().tree;
        const tags = tree.nodes.items(.tag);

        if (decl.value == null) {
            switch (tags[decl.node_idx]) {
                .global_var_decl,
                .local_var_decl,
                .aligned_var_decl,
                .simple_var_decl,
                => {
                    const var_decl = ast.varDecl(tree, decl.node_idx).?;
                    if (var_decl.ast.init_node == 0)
                        return error.CriticalAstFailure;

                    var value = try (try interpreter.interpret(var_decl.ast.init_node, decl.scope, .{})).getValue();

                    if (var_decl.ast.type_node != 0) {
                        var type_val = try (try interpreter.interpret(var_decl.ast.type_node, decl.scope, .{})).getValue();
                        const type_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type });
                        if (type_val.ty != type_type) {
                            try interpreter.recordError(
                                decl.node_idx,
                                "expected_type",
                                std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{}'", .{type_val.ty.fmtType(&interpreter.ip)}) catch return error.CriticalAstFailure,
                            );
                            return error.InvalidCast;
                        }
                        value = try interpreter.cast(var_decl.ast.type_node, type_val.value_data.type, value);
                    }

                    decl.value = value;
                },
                else => @panic("No other case supported for lazy declaration evaluation"),
            }
        }

        return decl.value.?;
    }

    pub fn isConstant(declaration: Declaration) bool {
        const tree = declaration.scope.interpreter.getHandle().tree;
        return switch (tree.nodes.items(.tag)[declaration.node_idx]) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => {
                return tree.tokenSlice(ast.varDecl(tree, declaration.node_idx).?.ast.mut_token).len != 3;
            },
            else => false,
        };
    }
};

// pub const Comptimeness = enum { @"comptime", runtime };

pub const Scope = struct {
    interpreter: *ComptimeInterpreter,

    // TODO: Actually use this value
    // comptimeness: Comptimeness,

    parent: u32, // zero indicates root scope
    node_idx: Ast.Node.Index,
    namespace: IPIndex,
    child_scopes: std.ArrayListUnmanaged(u32) = .{},

    pub const ScopeKind = enum { container, block, function };
    pub fn scopeKind(scope: Scope) ScopeKind {
        const tree = scope.interpreter.getHandle().tree;
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

    pub fn getLabel(scope: Scope) ?Ast.TokenIndex {
        const tree = scope.interpreter.getHandle().tree;
        const token_tags = tree.tokens.items(.tag);

        return switch (scope.scopeKind()) {
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
};

pub fn newScope(
    interpreter: *ComptimeInterpreter,
    maybe_parent: ?Scope,
    node_idx: Ast.Node.Index,
) std.mem.Allocator.Error!*Scope {
    var ls = try interpreter.allocator.create(Scope);
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
            .return_with_value => |v| v,
            else => null,
        };
    }

    pub fn getValue(result: InterpretResult) error{ExpectedValue}!Value {
        return result.maybeGetValue() orelse error.ExpectedValue;
    }
};

fn getDeclCount(tree: Ast, node_idx: Ast.Node.Index) usize {
    var buffer: [2]Ast.Node.Index = undefined;
    const members = ast.declMembers(tree, node_idx, &buffer);

    var count: usize = 0;

    for (members) |member| {
        switch (tree.nodes.items(.tag)[member]) {
            .global_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .simple_var_decl,
            => count += 1,
            else => {},
        }
    }

    return count;
}

pub fn huntItDown(
    interpreter: *ComptimeInterpreter,
    namespace: IPIndex,
    decl_name: []const u8,
    options: InterpretOptions,
) InterpretError!InternPool.Decl {
    _ = options;

    var current_namespace = namespace;
    while (current_namespace != IPIndex.none) {
        const namespace_info = interpreter.ip.indexToKey(current_namespace).namespace;
        defer current_namespace = namespace_info.parent;

        for (namespace_info.decls) |decl_index| {
            const decl_info = interpreter.ip.indexToKey(decl_index).declaration;
            if (std.mem.eql(u8, decl_info.name, decl_name)) {
                return decl_info;
            }
        }
    }

    log.err("Identifier not found: {s}", .{decl_name});
    return error.IdentifierNotFound;
}

pub fn cast(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    destination_ty: IPIndex,
    source_ty: IPIndex,
) error{ OutOfMemory, InvalidCast }!IPIndex {
    _ = node_idx;
    // TODO return errors
    return try interpreter.ip.cast(interpreter.allocator, destination_ty, source_ty, builtin.target);
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
    scope: ?Scope,
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
        // .error_set_decl, // TODO
        => {
            const type_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type });

            var container_scope = Scope{
                .interpreter = interpreter,
                .parent = if (scope) |sc| sc.parent else 0,
                .node_idx = node_idx,
                .namespace = IPIndex.none, // declarations have not been resolved yet
            };

            var fields = std.StringArrayHashMapUnmanaged(InternPool.Struct.Field){};
            defer fields.deinit(interpreter.allocator);

            var buffer: [2]Ast.Node.Index = undefined;
            const members = ast.declMembers(tree, node_idx, &buffer);
            for (members) |member| {
                const maybe_container_field: ?zig.Ast.full.ContainerField = switch (tags[member]) {
                    .container_field => tree.containerField(member),
                    .container_field_align => tree.containerFieldAlign(member),
                    .container_field_init => tree.containerFieldInit(member),
                    else => null,
                };

                const field_info = maybe_container_field orelse {
                    _ = try interpreter.interpret(member, container_scope, options);
                    continue;
                };

                var init_type_value = try (try interpreter.interpret(field_info.ast.type_expr, container_scope, .{})).getValue();

                var default_value = if (field_info.ast.value_expr == 0)
                    IPIndex.none
                else
                    (try (try interpreter.interpret(field_info.ast.value_expr, container_scope, .{})).getValue()).val; // TODO check ty

                if (init_type_value.ty != type_type) {
                    try interpreter.recordError(
                        field_info.ast.type_expr,
                        "expected_type",
                        try std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{}'", .{init_type_value.ty.fmtType(&interpreter.ip)}),
                    );
                    continue;
                }

                const name = tree.tokenSlice(field_info.ast.main_token);

                const field: InternPool.Struct.Field = .{
                    .ty = init_type_value.val,
                    .default_value = default_value,
                    .alignent = 0, // TODO,
                    .is_comptime = false, // TODO
                };

                try fields.put(interpreter.arena.allocator(), name, field);
            }

            const namespace = try interpreter.ip.get(interpreter.allocator, IPKey{
                .namespace = .{
                    .parent = IPIndex.none,
                    // .ty = struct_type,
                    .decls = undefined, // TODO,
                    .usingnamespaces = &.{},
                },
            });

            const struct_type = try interpreter.ip.get(interpreter.allocator, IPKey{
                .struct_type = .{
                    .fields = fields,
                    .namespace = namespace, // TODO
                    .layout = std.builtin.Type.ContainerLayout.Auto, // TODO
                    .backing_int_ty = IPIndex.none, // TODO
                },
            });

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = type_type,
                .val = struct_type,
            } };
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            // TODO: Add 0 check
            // const name = analysis.getDeclName(tree, node_idx).?;
            // if (scope.?.declarations.contains(name))
            //     return InterpretResult{ .nothing = {} };

            // const decl = ast.varDecl(tree, node_idx).?;
            // if (decl.ast.init_node == 0)
            //     return InterpretResult{ .nothing = {} };

            // try scope.?.declarations.put(interpreter.allocator, name, .{
            //     .scope = scope.?,
            //     .node_idx = node_idx,
            //     .name = name,
            // });

            // TODO: Am I a dumbo shrimp? (e.g. is this tree shaking correct? works on my machine so like...)

            // if (scope.?.scopeKind() != .container) {
            // if (scope.?.node_idx != 0)
            //     _ = try scope.?.declarations.getPtr(name).?.getValue();

            return InterpretResult{ .nothing = {} };
        },
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            var block_scope = Scope{
                .interpreter = interpreter,
                .parent = if (scope) |sc| sc.parent else 0,
                .node_idx = node_idx,
                .namespace = IPIndex.none,
            };

            var buffer: [2]Ast.Node.Index = undefined;
            const statements = ast.blockStatements(tree, node_idx, &buffer).?;

            for (statements) |idx| {
                const ret = try interpreter.interpret(idx, block_scope, options);
                switch (ret) {
                    .@"break" => |lllll| {
                        const maybe_block_label_string = if (scope.?.getLabel()) |i| tree.tokenSlice(i) else null;
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
                        const maybe_block_label_string = if (scope.?.getLabel()) |i| tree.tokenSlice(i) else null;

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
            var value = tree.getNodeSource(node_idx);

            if (std.mem.eql(u8, "bool", value)) return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool }),
            } };
            if (std.mem.eql(u8, "true", value)) return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool }),
                .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_true }),
            } };
            if (std.mem.eql(u8, "false", value)) return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool }),
                .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_false }),
            } };

            if (value.len == 5 and (value[0] == 'u' or value[0] == 'i') and std.mem.eql(u8, "size", value[1..])) return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{
                        .simple = if (value[0] == 'u') .usize else .isize,
                    }),
                },
            };

            if (std.mem.eql(u8, "type", value)) {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                } };
            } else if (value.len >= 2 and (value[0] == 'u' or value[0] == 'i')) int: {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .int_type = .{
                        .signedness = if (value[0] == 'u') .unsigned else .signed,
                        .bits = std.fmt.parseInt(u16, value[1..], 10) catch break :int,
                    } }),
                } };
            }

            // TODO: Floats

            // Logic to find identifiers in accessible scopes
            const decl = interpreter.huntItDown(scope.?.namespace, value, options) catch |err| {
                if (err == error.IdentifierNotFound) try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    try std.fmt.allocPrint(interpreter.allocator, "use of undeclared identifier '{s}'", .{value}),
                );
                return err;
            };

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = decl.ty,
                .val = decl.val,
            } };
        },
        .field_access => {
            if (data[node_idx].rhs == 0) return error.CriticalAstFailure;
            const rhs_str = ast.tokenSlice(tree, data[node_idx].rhs) catch return error.CriticalAstFailure;

            var ir = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var irv = try ir.getValue();

            const namespace = interpreter.ip.indexToKey(irv.val).getNamespace() orelse return error.IdentifierNotFound;

            var scope_sub_decl = irv.interpreter.huntItDown(namespace, rhs_str, options) catch |err| {
                if (err == error.IdentifierNotFound) try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    try std.fmt.allocPrint(interpreter.allocator, "use of undeclared identifier '{s}'", .{rhs_str}),
                );
                return err;
            };

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = data[node_idx].rhs,
                .ty = scope_sub_decl.ty,
                .val = scope_sub_decl.val,
            } };
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

            const false_value = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_false });
            const true_value = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_true });

            const condition = (try ir.getValue()).val;
            std.debug.assert(condition == false_value or condition == true_value);
            if (condition == true_value) {
                return try interpreter.interpret(iff.ast.then_expr, scope, options);
            } else {
                if (iff.ast.else_expr != 0) {
                    return try interpreter.interpret(iff.ast.else_expr, scope, options);
                } else return InterpretResult{ .nothing = {} };
            }
        },
        .equal_equal => {
            var a = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var b = try interpreter.interpret(data[node_idx].rhs, scope, options);
            return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = if (a.value.val == b.value.val) .bool_true else .bool_false }), // TODO eql function required?
                },
            };

            // a.getValue().eql(b.getValue())
        },
        .number_literal => {
            const s = tree.getNodeSource(node_idx);
            const nl = std.zig.parseNumberLiteral(s);

            if (nl == .failure) return error.CriticalAstFailure;

            const comptime_int_type = try interpreter.ip.get(interpreter.allocator, IPKey{
                .simple = if (nl == .float) .comptime_float else .comptime_int,
            });

            const value = try interpreter.ip.get(
                interpreter.allocator,
                switch (nl) {
                    .float => IPKey{
                        .float_64_value = try std.fmt.parseFloat(f64, s), // shouldn't this be f128?
                    },
                    .int => if (s[0] == '-') IPKey{
                        .int_i64_value = try std.fmt.parseInt(i64, s, 0),
                    } else IPKey{
                        .int_u64_value = try std.fmt.parseInt(u64, s, 0),
                    },
                    .big_int => @panic("TODO: implement big int"),
                    .failure => return error.CriticalAstFailure,
                },
            );

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = comptime_int_type,
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
                _ = try interpreter.interpret(data[node_idx].rhs, scope.?, options);
                return InterpretResult{ .nothing = {} };
            }

            var ir = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var to_value = try ir.getValue();
            var from_value = (try (try interpreter.interpret(data[node_idx].rhs, scope.?, options)).getValue());

            _ = try interpreter.cast(undefined, to_value.ty, from_value.ty);

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
                    var value = (try interpreter.interpret(param, scope, options)).maybeGetValue() orelse {
                        try writer.writeAll("indeterminate");
                        continue;
                    };
                    try writer.print("@as({s}, {s})", .{ value.ty.fmtType(&interpreter.ip), value.val.fmtValue(value.ty, &interpreter.ip) });
                    if (index != params.len - 1)
                        try writer.writeAll(", ");
                }
                try interpreter.recordError(node_idx, "compile_log", try final.toOwnedSlice());

                return InterpretResult{ .nothing = {} };
            }

            if (std.mem.eql(u8, call_name, "@compileError")) {
                // TODO: Add message
                try interpreter.recordError(node_idx, "compile_error", try std.fmt.allocPrint(interpreter.allocator, "compile error", .{}));
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
                        .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .struct_type = .{
                            .fields = .{},
                            .namespace = IPIndex.none,
                            .layout = .Auto,
                            .backing_int_ty = IPIndex.none,
                        } }),
                        .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .undefined_value }),
                    } };
                }

                var import_uri = (try interpreter.document_store.uriFromImportStr(interpreter.allocator, interpreter.getHandle().*, import_str[1 .. import_str.len - 1])) orelse return error.ImportFailure;
                defer interpreter.allocator.free(import_uri);

                var handle = interpreter.document_store.getOrLoadHandle(import_uri) orelse return error.ImportFailure;
                try interpreter.document_store.ensureInterpreterExists(handle.uri);

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .type_value = undefined }), // TODO
                } };
            }

            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len != 1) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], scope, options)).getValue();
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .type_value = value.ty }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@hasDecl")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], scope, options)).getValue();
                const field_name = try (try interpreter.interpret(params[1], scope, options)).getValue();

                const type_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type });

                if (value.ty != type_type) return error.InvalidBuiltin;
                if (interpreter.ip.indexToKey(field_name.ty) != .pointer_type) return error.InvalidBuiltin; // Check if it's a []const u8

                const namespace_index = interpreter.ip.indexToKey(value.val).getNamespace() orelse return error.InvalidBuiltin;
                const namespace = interpreter.ip.indexToKey(namespace_index).namespace;

                const name = interpreter.ip.indexToKey(field_name.val).bytes.data; // TODO add checks

                const has_decl = for (namespace.decls) |decl|{
                    const decl_name = interpreter.ip.indexToKey(decl).declaration.name;
                    if(std.mem.eql(u8, decl_name, name)) break true;
                } else false;

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool }),
                    .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = if (has_decl) .bool_true else .bool_false }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@as")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const as_type = try (try interpreter.interpret(params[0], scope, options)).getValue();
                const value = try (try interpreter.interpret(params[1], scope, options)).getValue();

                const type_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type });

                if (as_type.ty != type_type) return error.InvalidBuiltin;

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .ty = type_type,
                    .val = try interpreter.cast(node_idx, as_type.val, value.val),
                } };
            }

            log.err("Builtin not implemented: {s}", .{call_name});
            return error.InvalidBuiltin;
        },
        .string_literal => {
            const str = tree.getNodeSource(node_idx)[1 .. tree.getNodeSource(node_idx).len - 1];

            const string_literal_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .pointer_type = .{
                .elem_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .array_type = .{
                    .child = try interpreter.ip.get(interpreter.allocator, IPKey{ .int_type = .{
                        .signedness = .unsigned,
                        .bits = 8,
                    } }),
                    .len = @intCast(u32, str.len),
                    .sentinel = try interpreter.ip.get(interpreter.allocator, IPKey{ .int_u64_value = 0 }),
                } }),
                .sentinel = .none,
                .alignment = 0,
                .size = .One,
                .is_const = true,
                .is_volatile = false,
                .is_allowzero = false,
                .address_space = .generic,
            } });

            var val = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = string_literal_type,
                .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .bytes = .{ .data = str } }), // TODO
            };

            // TODO: Add type casting, sentinel
            // TODO: Should this be a `*const [len:0]u8`?
            // try val.value_data.slice_ptr.append(interpreter.allocator, .{ .unsigned_int = 0 });

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

            // TODO: Resolve function type

            // const function_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .function_type = .{
            //     .calling_convention = .Unspecified,
            //     .alignment = 0,
            //     .is_generic = false,
            //     .is_var_args = false,
            //     .return_type = IPIndex.none,
            //     .args = &.{},
            // } });

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
            //     .interpreter = interpreter,
            //     .node_idx = node_idx,
            //     .ty = function_type,
            //     .val = IPIndex.none, // TODO
            // };

            // const name = analysis.getDeclName(tree, node_idx).?;
            // var namespace = interpreter.ip.indexToKey(scope.?.namespace).namespace;
            // try namespace.decls.put(interpreter.allocator, name, .{
            //     .scope = scope.?,
            //     .node_idx = node_idx,
            //     .name = name,
            //     .value = value,
            // });

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
            const call_full = ast.callFull(tree, node_idx, &params) orelse unreachable;

            var args = try std.ArrayListUnmanaged(Value).initCapacity(interpreter.allocator, call_full.ast.params.len);
            defer args.deinit(interpreter.allocator);

            for (call_full.ast.params) |param| {
                try args.append(interpreter.allocator, try (try interpreter.interpret(param, scope, .{})).getValue());
            }

            const func_id_result = try interpreter.interpret(call_full.ast.fn_expr, interpreter.root_type.?.getTypeInfo().getScopeOfType().?, .{});
            const func_id_val = try func_id_result.getValue();

            const call_res = try interpreter.call(interpreter.root_type.?.getTypeInfo().getScopeOfType().?, func_id_val.node_idx, args.items, options);
            // defer call_res.scope.deinit();
            // TODO: Figure out call result memory model; this is actually fine because newScope
            // makes this a child of the decl scope which is freed on refresh... in theory

            return switch (call_res.result) {
                .value => |v| .{ .value = v },
                .nothing => .{ .nothing = {} },
            };
        },
        .bool_not => {
            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const bool_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool });
            const value = try result.getValue();
            if (value.ty == bool_type) {
                const false_value = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_false });
                const true_value = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .bool_true });

                const not_value = if (value.val == false_value) true_value else if (value.val == true_value) false_value else return error.InvalidOperation;
                return InterpretResult{
                    .value = .{
                        .interpreter = interpreter,
                        .node_idx = node_idx,
                        .ty = bool_type,
                        .val = not_value,
                    },
                };
            } else {
                // TODO
                return error.InvalidOperation;
            }
        },
        .address_of => {
            // TODO: Make const pointers if we're drawing from a const;
            // variables are the only non-const(?)

            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const value = (try result.getValue());

            const pointer_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .pointer_type = .{
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
                .val = try interpreter.ip.get(interpreter.allocator, IPKey{ .one_pointer = value.val }),
            } };
        },
        .deref => {
            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const value = (try result.getValue());

            const type_key = interpreter.ip.indexToKey(value.ty);

            if (type_key != .pointer_type) {
                try interpreter.recordError(node_idx, "invalid_deref", try std.fmt.allocPrint(interpreter.allocator, "cannot deference non-pointer", .{}));
                return error.InvalidOperation;
            }

            // TODO: Check if this is a one_ptr or not

            return InterpretResult{ .value = .{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .ty = type_key.pointer_type.elem_type,
                .val = interpreter.ip.indexToKey(value.val).one_pointer,
            } };
        },
        else => {
            log.err("Unhandled {any}", .{tags[node_idx]});
            return InterpretResult{ .nothing = {} };
        },
    }
}

pub const CallResult = struct {
    scope: *Scope,
    result: union(enum) {
        value: Value,
        nothing,
    },
};

pub fn call(
    interpreter: *ComptimeInterpreter,
    scope: ?Scope,
    func_node_idx: Ast.Node.Index,
    arguments: []const Value,
    options: InterpretOptions,
) InterpretError!CallResult {
    // _ = options;

    // TODO: type check args

    const tree = interpreter.getHandle().tree;
    const tags = tree.nodes.items(.tag);

    if (tags[func_node_idx] != .fn_decl) return error.CriticalAstFailure;

    // TODO: Make argument scope to evaluate arguments in
    var fn_scope = try interpreter.newScope(scope, func_node_idx);
    
    const type_type = try interpreter.ip.get(interpreter.allocator, IPKey{ .simple = .type });                    

    var buf: [1]Ast.Node.Index = undefined;
    var proto = ast.fnProto(tree, func_node_idx, &buf).?;

    var arg_it = proto.iterate(&tree);
    var arg_index: usize = 0;
    while (ast.nextFnParam(&arg_it)) |param| {
        if (arg_index >= arguments.len) return error.MissingArguments;
        var tex = try (try interpreter.interpret(param.type_expr, fn_scope, options)).getValue();
        if (tex.ty != type_type) {
            try interpreter.recordError(
                param.type_expr,
                "expected_type",
                std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{}'", .{tex.ty.fmtType(&interpreter.ip)}) catch return error.CriticalAstFailure,
            );
            return error.InvalidCast;
        }
        if (param.name_token) |nt| {
            const decl = Declaration{
                .scope = fn_scope,
                .node_idx = param.type_expr,
                .name = tree.tokenSlice(nt),
                .value = try interpreter.cast(arguments[arg_index].node_idx, tex.val, arguments[arg_index]),
            };
            try fn_scope.declarations.put(interpreter.allocator, tree.tokenSlice(nt), decl);
            arg_index += 1;
        }
    }

    const body = tree.nodes.items(.data)[func_node_idx].rhs;
    const result = try interpreter.interpret(body, fn_scope, .{});

    // TODO: Defers
    return CallResult{
        .scope = fn_scope,
        .result = switch (result) {
            .@"return", .nothing => .{ .nothing = {} }, // nothing could be due to an error
            .return_with_value => |v| .{ .value = v },
            else => @panic("bruh"),
        },
    };
}
