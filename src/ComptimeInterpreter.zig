//! Hacky comptime interpreter, courtesy of midnight code run fuelled by spite;
//! hope that one day this can use async... <33

// TODO: DODify

const std = @import("std");
const ast = @import("ast.zig");
const zig = std.zig;
const Ast = zig.Ast;
const analysis = @import("analysis.zig");
const DocumentStore = @import("DocumentStore.zig");
const ComptimeInterpreter = @This();

const log = std.log.scoped(.comptime_interpreter);

// TODO: Investigate arena

allocator: std.mem.Allocator,
document_store: *DocumentStore,
uri: DocumentStore.Uri,
root_type: ?Type = null,

/// Interpreter diagnostic errors
errors: std.AutoArrayHashMapUnmanaged(Ast.Node.Index, InterpreterError) = .{},

// TODO: Deduplicate typeinfo across different interpreters
type_info: std.ArrayListUnmanaged(TypeInfo) = .{},
type_info_map: std.HashMapUnmanaged(TypeInfo, usize, TypeInfo.Context, std.hash_map.default_max_load_percentage) = .{},

// TODO: Use DOD
value_data_list: std.ArrayListUnmanaged(*ValueData) = .{},

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

    if (interpreter.root_type) |rt| rt.getTypeInfo().getScopeOfType().?.deinit();
    for (interpreter.type_info.items) |*ti| ti.deinit(interpreter.allocator);
    for (interpreter.value_data_list.items) |ti| interpreter.allocator.destroy(ti);

    interpreter.errors.deinit(interpreter.allocator);
    interpreter.type_info.deinit(interpreter.allocator);
    interpreter.type_info_map.deinit(interpreter.allocator);
    interpreter.value_data_list.deinit(interpreter.allocator);
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
            _ = self;
            return TypeInfo.eql(a, b);
        }
    };

    pub const Signedness = enum { signed, unsigned };

    pub const Struct = struct {
        /// Declarations contained within
        scope: *InterpreterScope,
        fields: std.StringHashMapUnmanaged(FieldDefinition) = .{},
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

        sentinel: ?*ValueData,

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

    pub const Array = struct {
        len: usize,
        child: Type,

        sentinel: ?*ValueData,
    };

    /// Hack to get anytype working; only valid on fnparams
    @"anytype",
    @"type",
    @"bool",

    @"struct": Struct,
    pointer: Pointer,
    @"fn": Fn,

    int: Int,
    @"comptime_int",
    float: u16,
    @"comptime_float",

    array: Array,

    pub fn eql(a: TypeInfo, b: TypeInfo) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .@"struct" => false, // Struct declarations can never be equal (this is a lie, gotta fix this)
            .pointer => p: {
                const ap = a.pointer;
                const bp = b.pointer;
                break :p ap.size == bp.size and ap.is_const == bp.is_const and ap.is_volatile == bp.is_volatile and eql(
                    ap.child.getTypeInfo(),
                    bp.child.getTypeInfo(),
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
                _ = s;
                // TODO: Fix
                // context.hasher.update(std.mem.sliceAsBytes(s.fields.items));
                // TODO: Fix
                // context.hasher.update(std.mem.sliceAsBytes(s.declarations.items));
            },
            .pointer => |p| {
                // const ap = a.pointer;
                // const bp = b.pointer;
                context.hasher.update(&[_]u8{ @enumToInt(p.size), @boolToInt(p.is_const), @boolToInt(p.is_volatile) });
                TypeInfo.hash(context, p.child.getTypeInfo());
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

    pub fn getScopeOfType(ti: TypeInfo) ?*InterpreterScope {
        return switch (ti) {
            .@"struct" => |s| s.scope,
            else => null,
        };
    }
};

pub const Type = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    info_idx: usize,

    pub fn getTypeInfo(@"type": Type) TypeInfo {
        return @"type".interpreter.type_info.items[@"type".info_idx];
    }

    /// Be careful with this; typeinfo resizes reassign pointers!
    pub fn getTypeInfoMutable(@"type": Type) *TypeInfo {
        return &@"type".interpreter.type_info.items[@"type".info_idx];
    }
};

pub const Value = struct {
    interpreter: *ComptimeInterpreter,

    node_idx: Ast.Node.Index,
    @"type": Type,
    value_data: *ValueData,

    pub fn eql(value: Value, other_value: Value) bool {
        return value.value_data.eql(other_value.value_data);
    }
};

pub const ValueData = union(enum) {
    // TODO: Support larger ints, floats; bigints?

    @"type": Type,
    @"bool": bool,

    @"struct": struct {},
    /// This is what a pointer is; we don't need to map
    /// this to anything because @ptrToInt is comptime-illegal
    /// Pointer equality scares me though :( (but that's for later)
    one_ptr: *ValueData,
    /// Special case slice; this is extremely common at comptime so it makes sense
    slice_of_const_u8: []const u8,

    unsigned_int: u64,
    signed_int: i64,
    /// If the int does not fit into the previous respective slots,
    /// use a bit int to store it
    big_int: std.math.big.int.Managed,

    float: f64,

    @"fn",
    runtime,
    comptime_undetermined,

    pub fn eql(data: *ValueData, other_data: *ValueData) bool {
        if (std.meta.activeTag(data.*) != std.meta.activeTag(other_data.*)) return false;
        // std.enums.
        // std.meta.activeTag(u: anytype)
        switch (data.*) {
            .@"bool" => return data.@"bool" == other_data.@"bool",
            .big_int => return data.big_int.eq(other_data.big_int),
            .unsigned_int => return data.unsigned_int == other_data.unsigned_int,
            .signed_int => return data.signed_int == other_data.signed_int,
            .float => return data.float == other_data.float,

            else => return false,
        }
    }

    /// Get the bit count required to store a certain integer
    pub fn bitCount(data: ValueData) ?u16 {
        return switch (data) {
            // TODO: Implement for signed ints
            .unsigned_int => |i| if (i == 0) 0 else std.math.log2_int_ceil(@TypeOf(i), i + 1),
            .big_int => |bi| @intCast(u16, bi.bitCountAbs()),
            else => null,
        };
    }
};

pub const FieldDefinition = struct {
    node_idx: Ast.Node.Index,
    /// Store name so tree doesn't need to be used to access field name
    /// When the field is a tuple field, `name` will be an empty slice
    name: []const u8,
    @"type": Type,
    default_value: ?Value,
};

pub const Declaration = struct {
    scope: *InterpreterScope,

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
                        if (type_val.@"type".getTypeInfo() != .@"type") {
                            try interpreter.recordError(
                                decl.node_idx,
                                "expected_type",
                                std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{s}'", .{interpreter.formatTypeInfo(type_val.@"type".getTypeInfo())}) catch return error.CriticalAstFailure,
                            );
                            return error.InvalidCast;
                        }
                        value = try interpreter.cast(var_decl.ast.type_node, type_val.value_data.@"type", value);
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

pub fn createType(interpreter: *ComptimeInterpreter, node_idx: Ast.Node.Index, type_info: TypeInfo) std.mem.Allocator.Error!Type {
    // TODO: Figure out dedup
    var hasher = std.hash.Wyhash.init(0);
    var gpr = try interpreter.type_info_map.getOrPutContext(interpreter.allocator, type_info, .{ .interpreter = interpreter.*, .hasher = &hasher });

    if (gpr.found_existing) {
        return Type{ .interpreter = interpreter, .node_idx = node_idx, .info_idx = gpr.value_ptr.* };
    } else {
        try interpreter.type_info.append(interpreter.allocator, type_info);
        const info_idx = interpreter.type_info.items.len - 1;
        gpr.value_ptr.* = info_idx;
        return Type{ .interpreter = interpreter, .node_idx = node_idx, .info_idx = info_idx };
    }
}

pub fn createValueData(interpreter: *ComptimeInterpreter, data: ValueData) error{OutOfMemory}!*ValueData {
    var vd = try interpreter.allocator.create(ValueData);
    try interpreter.value_data_list.append(interpreter.allocator, vd);
    vd.* = data;
    return vd;
}

pub const TypeInfoFormatter = struct {
    interpreter: *const ComptimeInterpreter,
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
                var field_iterator = s.fields.iterator();
                while (field_iterator.next()) |di| {
                    try writer.print("{s}: {s}, ", .{ di.key_ptr.*, value.interpreter.formatTypeInfo(di.value_ptr.*.@"type".getTypeInfo()) });
                }

                var iterator = s.scope.declarations.iterator();
                while (iterator.next()) |di| {
                    const decl = di.value_ptr;
                    if (decl.isConstant()) {
                        if (decl.value) |sv| {
                            try writer.print("const {s}: {any} = { }, ", .{
                                decl.name,
                                value.interpreter.formatTypeInfo(sv.@"type".getTypeInfo()),
                                value.interpreter.formatValue(sv),
                            });
                        } else {
                            try writer.print("const {s} (not analyzed), ", .{decl.name});
                        }
                    } else {
                        if (decl.value) |sv| {
                            try writer.print("var {s}: {any} = { }, ", .{
                                decl.name,
                                value.interpreter.formatTypeInfo(sv.@"type".getTypeInfo()),
                                value.interpreter.formatValue(sv),
                            });
                        } else {
                            try writer.print("var {s} (not analyzed), ", .{decl.name});
                        }
                    }
                }
                try writer.writeAll("}");
            },
            else => try writer.print("UnimplementedTypeInfoPrint", .{}),
        };
    }
};

pub fn formatTypeInfo(interpreter: *const ComptimeInterpreter, ti: TypeInfo) TypeInfoFormatter {
    return TypeInfoFormatter{ .interpreter = interpreter, .ti = ti };
}

pub const ValueFormatter = struct {
    interpreter: *const ComptimeInterpreter,
    val: Value,

    pub fn format(form: ValueFormatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        var value = form.val;
        var ti = value.@"type".getTypeInfo();

        return switch (ti) {
            .int, .@"comptime_int" => switch (value.value_data.*) {
                .unsigned_int => |a| try writer.print("{d}", .{a}),
                .signed_int => |a| try writer.print("{d}", .{a}),
                .big_int => |a| try writer.print("{d}", .{a}),

                else => unreachable,
            },
            .@"type" => try writer.print("{ }", .{form.interpreter.formatTypeInfo(value.value_data.@"type".getTypeInfo())}),
            else => try writer.print("UnimplementedValuePrint", .{}),
        };
    }
};

pub fn formatValue(interpreter: *const ComptimeInterpreter, value: Value) ValueFormatter {
    return ValueFormatter{ .interpreter = interpreter, .val = value };
}

// pub const Comptimeness = enum { @"comptime", runtime };

pub const InterpreterScope = struct {
    interpreter: *ComptimeInterpreter,

    // TODO: Actually use this value
    // comptimeness: Comptimeness,

    parent: ?*InterpreterScope = null,
    node_idx: Ast.Node.Index,
    declarations: std.StringHashMapUnmanaged(Declaration) = .{},
    /// Resizes can modify element pointer locations, so we use a list of pointers
    child_scopes: std.ArrayListUnmanaged(*InterpreterScope) = .{},

    pub const ScopeKind = enum { container, block, function };
    pub fn scopeKind(scope: InterpreterScope) ScopeKind {
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

    pub fn getLabel(scope: InterpreterScope) ?Ast.TokenIndex {
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
        const allocator = scope.interpreter.allocator;

        scope.declarations.deinit(allocator);
        for (scope.child_scopes.items) |child| child.deinit();
        scope.child_scopes.deinit(allocator);

        allocator.destroy(scope);
    }
};

pub fn newScope(
    interpreter: *ComptimeInterpreter,
    maybe_parent: ?*InterpreterScope,
    node_idx: Ast.Node.Index,
) std.mem.Allocator.Error!*InterpreterScope {
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
    scope: *InterpreterScope,
    decl_name: []const u8,
    options: InterpretOptions,
) InterpretError!*Declaration {
    const tree = interpreter.getHandle().tree;
    const tags = tree.nodes.items(.tag);

    var psi = scope.parentScopeIterator();
    while (psi.next()) |pscope| {
        const known_decl = pscope.declarations.getEntry(decl_name);
        if (pscope.scopeKind() == .container and
            known_decl == null and
            pscope.declarations.count() != getDeclCount(tree, pscope.node_idx))
        {
            log.info("Order-independent evaluating {s}...", .{decl_name});

            var buffer: [2]Ast.Node.Index = undefined;
            const members = ast.declMembers(tree, pscope.node_idx, &buffer);

            for (members) |member| {
                switch (tags[member]) {
                    .global_var_decl,
                    .local_var_decl,
                    .aligned_var_decl,
                    .simple_var_decl,
                    => {
                        if (std.mem.eql(u8, analysis.getDeclName(tree, member).?, decl_name)) {
                            _ = try interpreter.interpret(member, pscope, options);
                            return pscope.declarations.getEntry(decl_name).?.value_ptr;
                        }
                    },
                    else => {},
                }
            }
        }
        return (known_decl orelse continue).value_ptr;
    }

    log.err("Identifier not found: {s}", .{decl_name});
    return error.IdentifierNotFound;
}

pub fn cast(
    interpreter: *ComptimeInterpreter,
    node_idx: Ast.Node.Index,
    dest_type: Type,
    value: Value,
) error{ OutOfMemory, InvalidCast }!Value {
    const value_data = value.value_data;

    const to_type_info = dest_type.getTypeInfo();
    const from_type_info = value.@"type".getTypeInfo();

    // TODO: Implement more implicit casts

    if (from_type_info.eql(to_type_info)) return value;

    const err = switch (from_type_info) {
        .@"comptime_int" => switch (to_type_info) {
            .int => {
                if (value_data.bitCount().? > to_type_info.int.bits) {
                    switch (value_data.*) {
                        .unsigned_int => |bi| try interpreter.recordError(node_idx, "invalid_cast", try std.fmt.allocPrint(interpreter.allocator, "integer value {d} cannot be coerced to type '{s}'", .{ bi, interpreter.formatTypeInfo(to_type_info) })),
                        .signed_int => |bi| try interpreter.recordError(node_idx, "invalid_cast", try std.fmt.allocPrint(interpreter.allocator, "integer value {d} cannot be coerced to type '{s}'", .{ bi, interpreter.formatTypeInfo(to_type_info) })),
                        .big_int => |bi| try interpreter.recordError(node_idx, "invalid_cast", try std.fmt.allocPrint(interpreter.allocator, "integer value {d} cannot be coerced to type '{s}'", .{ bi, interpreter.formatTypeInfo(to_type_info) })),

                        else => unreachable,
                    }
                    return error.InvalidCast;
                }
            },
            else => error.InvalidCast,
        },
        else => error.InvalidCast,
    };

    err catch |e| {
        try interpreter.recordError(node_idx, "invalid_cast", try std.fmt.allocPrint(interpreter.allocator, "invalid cast from '{s}' to '{s}'", .{ interpreter.formatTypeInfo(from_type_info), interpreter.formatTypeInfo(to_type_info) }));
        return e;
    };

    return Value{
        .interpreter = interpreter,

        .node_idx = node_idx,
        .@"type" = dest_type,
        .value_data = value.value_data,
    };
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
    scope: ?*InterpreterScope,
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
        .error_set_decl,
        => {
            var container_scope = try interpreter.newScope(scope, node_idx);
            var type_info = TypeInfo{
                .@"struct" = .{
                    .scope = container_scope,
                },
            };
            var cont_type = try interpreter.createType(node_idx, type_info);

            if (node_idx == 0) interpreter.root_type = cont_type;

            var buffer: [2]Ast.Node.Index = undefined;
            const members = ast.declMembers(tree, node_idx, &buffer);

            var field_idx: usize = 0;
            for (members) |member| {
                const maybe_container_field: ?zig.Ast.full.ContainerField = switch (tags[member]) {
                    .container_field => tree.containerField(member),
                    .container_field_align => tree.containerFieldAlign(member),
                    .container_field_init => tree.containerFieldInit(member),
                    else => null,
                };

                if (maybe_container_field) |field_info| {
                    var init_type_value = try (try interpreter.interpret(field_info.ast.type_expr, container_scope, .{})).getValue();
                    var default_value = if (field_info.ast.value_expr == 0)
                        null
                    else
                        try (try interpreter.interpret(field_info.ast.value_expr, container_scope, .{})).getValue();

                    if (init_type_value.@"type".getTypeInfo() != .@"type") {
                        try interpreter.recordError(
                            field_info.ast.type_expr,
                            "expected_type",
                            try std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{s}'", .{interpreter.formatTypeInfo(init_type_value.@"type".getTypeInfo())}),
                        );
                        continue;
                    }

                    const name = if (field_info.ast.tuple_like)
                        &[0]u8{}
                    else tree.tokenSlice(field_info.ast.main_token);
                    const field = FieldDefinition{
                        .node_idx = member,
                        .name = name,
                        .@"type" = init_type_value.value_data.@"type",
                        .default_value = default_value,
                        // TODO: Default values
                        // .@"type" = T: {
                        //     var value = (try interpreter.interpret(field_info.ast.type_expr, scope_idx, true)).?.value;
                        //     break :T @ptrCast(*Type, @alignCast(@alignOf(*Type), value)).*;
                        // },
                        // .value = null,
                    };

                    try cont_type.getTypeInfoMutable().@"struct".fields.put(interpreter.allocator, name, field);
                    field_idx += 1;
                } else {
                    _ = try interpreter.interpret(member, container_scope, options);
                }
            }

            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                .value_data = try interpreter.createValueData(.{ .@"type" = cont_type }),
            } };
        },
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            // TODO: Add 0 check
            const name = analysis.getDeclName(tree, node_idx).?;
            if (scope.?.declarations.contains(name))
                return InterpretResult{ .nothing = {} };

            const decl = ast.varDecl(tree, node_idx).?;
            if (decl.ast.init_node == 0)
                return InterpretResult{ .nothing = {} };

            try scope.?.declarations.put(interpreter.allocator, name, .{
                .scope = scope.?,
                .node_idx = node_idx,
                .name = name,
            });

            // TODO: Am I a dumbo shrimp? (e.g. is this tree shaking correct? works on my machine so like...)

            // if (scope.?.scopeKind() != .container) {
            if (scope.?.node_idx != 0)
                _ = try scope.?.declarations.getPtr(name).?.getValue();

            return InterpretResult{ .nothing = {} };
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
                .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                .value_data = try interpreter.createValueData(.{ .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = {} }) }),
            } };
            if (std.mem.eql(u8, "true", value)) return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = {} }),
                .value_data = try interpreter.createValueData(.{ .@"bool" = true }),
            } };
            if (std.mem.eql(u8, "false", value)) return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = {} }),
                .value_data = try interpreter.createValueData(.{ .@"bool" = false }),
            } };

            if (value.len == 5 and (value[0] == 'u' or value[0] == 'i') and std.mem.eql(u8, "size", value[1..])) return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                    .value_data = try interpreter.createValueData(.{
                        .@"type" = try interpreter.createType(node_idx, .{
                            .int = .{
                                .signedness = if (value[0] == 'u') .unsigned else .signed,
                                .bits = 64, // TODO: Platform specific
                            },
                        }),
                    }),
                },
            };

            if (std.mem.eql(u8, "type", value)) {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                    .value_data = try interpreter.createValueData(.{ .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }) }),
                } };
            } else if (value.len >= 2 and (value[0] == 'u' or value[0] == 'i')) int: {
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                    .value_data = try interpreter.createValueData(.{ .@"type" = try interpreter.createType(node_idx, .{
                        .int = .{
                            .signedness = if (value[0] == 'u') .unsigned else .signed,
                            .bits = std.fmt.parseInt(u16, value[1..], 10) catch break :int,
                        },
                    }) }),
                } };
            }

            // TODO: Floats

            // Logic to find identifiers in accessible scopes
            return InterpretResult{ .value = try (interpreter.huntItDown(scope.?, value, options) catch |err| {
                if (err == error.IdentifierNotFound) try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    try std.fmt.allocPrint(interpreter.allocator, "use of undeclared identifier '{s}'", .{value}),
                );
                return err;
            }).getValue() };
        },
        .field_access => {
            if (data[node_idx].rhs == 0) return error.CriticalAstFailure;
            const rhs_str = ast.tokenSlice(tree, data[node_idx].rhs) catch return error.CriticalAstFailure;

            var ir = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var irv = try ir.getValue();

            var sub_scope = irv.value_data.@"type".getTypeInfo().getScopeOfType() orelse return error.IdentifierNotFound;
            var scope_sub_decl = sub_scope.interpreter.huntItDown(sub_scope, rhs_str, options) catch |err| {
                if (err == error.IdentifierNotFound) try interpreter.recordError(
                    node_idx,
                    "undeclared_identifier",
                    try std.fmt.allocPrint(interpreter.allocator, "use of undeclared identifier '{s}'", .{rhs_str}),
                );
                return err;
            };

            return InterpretResult{
                .value = try scope_sub_decl.getValue(),
            };
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
                } else return InterpretResult{ .nothing = {} };
            }
        },
        .equal_equal => {
            var a = try interpreter.interpret(data[node_idx].lhs, scope, options);
            var b = try interpreter.interpret(data[node_idx].rhs, scope, options);
            return InterpretResult{ .value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = {} }),
                .value_data = try interpreter.createValueData(.{ .@"bool" = (try a.getValue()).eql(try b.getValue()) }),
            } };
            // a.getValue().eql(b.getValue())
        },
        .number_literal => {
            const s = tree.getNodeSource(node_idx);
            const nl = std.zig.parseNumberLiteral(s);

            return InterpretResult{
                .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"comptime_int" = {} }),
                    .value_data = try interpreter.createValueData(switch (nl) {
                        .float => .{ .float = try std.fmt.parseFloat(f64, s) },
                        .int => if (s[0] == '-') ValueData{ .signed_int = try std.fmt.parseInt(i64, s, 0) } else ValueData{ .unsigned_int = try std.fmt.parseInt(u64, s, 0) },
                        .big_int => |bii| ppp: {
                            var bi = try std.math.big.int.Managed.init(interpreter.allocator);
                            try bi.setString(@enumToInt(bii), s[if (bii != .decimal) @as(usize, 2) else @as(usize, 0)..]);
                            break :ppp .{ .big_int = bi };
                        },
                        .failure => return error.CriticalAstFailure,
                    }),
                },
            };
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

            to_value.value_data.* = (try interpreter.cast(node_idx, to_value.@"type", from_value)).value_data.*;

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
                    try writer.print("@as({s}, {s})", .{ interpreter.formatTypeInfo(value.@"type".getTypeInfo()), interpreter.formatValue(value) });
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
                        .@"type" = try interpreter.createType(node_idx, .{ .@"struct" = .{ .scope = try interpreter.newScope(null, 0) } }),
                        .value_data = try interpreter.createValueData(.{ .@"struct" = .{} }),
                    } };
                }

                var import_uri = (try interpreter.document_store.uriFromImportStr(interpreter.allocator, interpreter.getHandle().*, import_str[1 .. import_str.len - 1])) orelse return error.ImportFailure;
                defer interpreter.allocator.free(import_uri);

                var handle = interpreter.document_store.getOrLoadHandle(import_uri) orelse return error.ImportFailure;
                try interpreter.document_store.ensureInterpreterExists(handle.uri);

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                    .value_data = try interpreter.createValueData(.{ .@"type" = handle.interpreter.?.root_type.? }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@TypeOf")) {
                if (params.len != 1) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], scope, options)).getValue();
                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"type" = {} }),
                    .value_data = try interpreter.createValueData(.{ .@"type" = value.@"type" }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@hasDecl")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const value = try (try interpreter.interpret(params[0], scope, options)).getValue();
                const field_name = try (try interpreter.interpret(params[1], scope, options)).getValue();

                if (value.@"type".getTypeInfo() != .@"type") return error.InvalidBuiltin;
                if (field_name.@"type".getTypeInfo() != .@"pointer") return error.InvalidBuiltin; // Check if it's a []const u8

                const ti = value.value_data.@"type".getTypeInfo();
                if (ti.getScopeOfType() == null) return error.InvalidBuiltin;

                return InterpretResult{ .value = Value{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{ .@"bool" = {} }),
                    .value_data = try interpreter.createValueData(.{ .@"bool" = ti.getScopeOfType().?.declarations.contains(field_name.value_data.slice_of_const_u8) }),
                } };
            }

            if (std.mem.eql(u8, call_name, "@as")) {
                if (params.len != 2) return error.InvalidBuiltin;

                const as_type = try (try interpreter.interpret(params[0], scope, options)).getValue();
                const value = try (try interpreter.interpret(params[1], scope, options)).getValue();

                if (as_type.@"type".getTypeInfo() != .@"type") return error.InvalidBuiltin;

                return InterpretResult{ .value = try interpreter.cast(node_idx, as_type.value_data.@"type", value) };
            }

            log.err("Builtin not implemented: {s}", .{call_name});
            return error.InvalidBuiltin;
        },
        .string_literal => {
            const value = tree.getNodeSource(node_idx)[1 .. tree.getNodeSource(node_idx).len - 1];
            var val = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                // TODO: This is literally the wrong type lmao
                // the actual type is *[len:0]u8 because we're pointing
                // to a fixed size value in the data(?) section (when we're compilign zig code)
                .@"type" = try interpreter.createType(node_idx, .{
                    .pointer = .{
                        .size = .one,
                        .is_const = true,
                        .is_volatile = false,
                        .child = try interpreter.createType(0, .{ .int = .{
                            .bits = 8,
                            .signedness = .unsigned,
                        } }),
                        .is_allowzero = false,

                        .sentinel = null,
                    },
                }),
                .value_data = try interpreter.createValueData(.{ .slice_of_const_u8 = value }),
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

            // TODO: Add params

            var type_info = TypeInfo{
                .@"fn" = .{
                    .return_type = null,
                },
            };

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

            var value = Value{
                .interpreter = interpreter,
                .node_idx = node_idx,
                .@"type" = try interpreter.createType(node_idx, type_info),
                .value_data = try interpreter.createValueData(.{ .@"fn" = {} }),
            };

            const name = analysis.getDeclName(tree, node_idx).?;
            try scope.?.declarations.put(interpreter.allocator, name, .{
                .scope = scope.?,
                .node_idx = node_idx,
                .name = name,
                .@"value" = value,
            });

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
            const value = (try result.getValue());
            if (value.value_data.* != .@"bool") return error.InvalidOperation;
            return InterpretResult{
                .value = .{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = value.@"type",
                    .value_data = try interpreter.createValueData(.{ .@"bool" = !value.value_data.@"bool" }),
                },
            };
        },
        .address_of => {
            // TODO: Make const pointers if we're drawing from a const;
            // variables are the only non-const(?)

            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const value = (try result.getValue());

            return InterpretResult{
                .value = .{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = try interpreter.createType(node_idx, .{
                        .pointer = .{
                            .size = .one,
                            .is_const = false,
                            .is_volatile = false,
                            .child = value.@"type",
                            .is_allowzero = false,

                            .sentinel = null,
                        },
                    }),
                    .value_data = try interpreter.createValueData(.{ .@"one_ptr" = value.value_data }),
                },
            };
        },
        .deref => {
            const result = try interpreter.interpret(data[node_idx].lhs, scope, .{});
            const value = (try result.getValue());

            const ti = value.@"type".getTypeInfo();

            if (ti != .pointer) {
                try interpreter.recordError(node_idx, "invalid_deref", try std.fmt.allocPrint(interpreter.allocator, "cannot deference non-pointer", .{}));
                return error.InvalidOperation;
            }

            // TODO: Check if this is a one_ptr or not

            return InterpretResult{
                .value = .{
                    .interpreter = interpreter,
                    .node_idx = node_idx,
                    .@"type" = ti.pointer.child,
                    .value_data = value.value_data.one_ptr,
                },
            };
        },
        else => {
            log.err("Unhandled {any}", .{tags[node_idx]});
            return InterpretResult{ .nothing = {} };
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
    scope: ?*InterpreterScope,
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

    var buf: [1]Ast.Node.Index = undefined;
    var proto = ast.fnProto(tree, func_node_idx, &buf).?;

    var arg_it = proto.iterate(&tree);
    var arg_index: usize = 0;
    while (ast.nextFnParam(&arg_it)) |param| {
        if (arg_index >= arguments.len) return error.MissingArguments;
        var tex = try (try interpreter.interpret(param.type_expr, fn_scope, options)).getValue();
        if (tex.@"type".getTypeInfo() != .@"type") {
            try interpreter.recordError(
                param.type_expr,
                "expected_type",
                std.fmt.allocPrint(interpreter.allocator, "expected type 'type', found '{s}'", .{interpreter.formatTypeInfo(tex.@"type".getTypeInfo())}) catch return error.CriticalAstFailure,
            );
            return error.InvalidCast;
        }
        if (param.name_token) |nt| {
            const decl = Declaration{
                .scope = fn_scope,
                .node_idx = param.type_expr,
                .name = tree.tokenSlice(nt),
                .value = try interpreter.cast(arguments[arg_index].node_idx, tex.value_data.@"type", arguments[arg_index]),
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
            .@"return_with_value" => |v| .{ .value = v },
            else => @panic("bruh"),
        },
    };
}
