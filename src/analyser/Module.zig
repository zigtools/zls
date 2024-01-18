const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.zls_module);
const Ast = std.zig.Ast;

const Module = @This();
pub const DocumentStore = @import("../DocumentStore.zig");
pub const Handle = DocumentStore.Handle;
const Zir = @import("../stage2/Zir.zig");
const AstGen = @import("../stage2/AstGen.zig");

const InternPool = @import("InternPool.zig");
const Decl = InternPool.Decl;
const Sema = @import("Sema.zig");

gpa: Allocator,
ip: *InternPool,
allocated_namespaces: std.SegmentedList(Namespace, 0) = .{},
document_store: *DocumentStore,

pub fn init(allocator: Allocator, ip: *InternPool, document_store: *DocumentStore) Module {
    return .{
        .gpa = allocator,
        .ip = ip,
        .document_store = document_store,
    };
}

pub fn deinit(mod: *Module) void {
    mod.allocated_namespaces.deinit(mod.gpa);
    mod.* = undefined;
}

pub fn relativeToNodeIndex(decl: Decl, offset: i32) Ast.Node.Index {
    return @as(Ast.Node.Index, @bitCast(offset + @as(i32, @bitCast(decl.node_idx))));
}

pub fn zirBlockIndex(decl: *const Decl, mod: *Module) Zir.Inst.Index {
    assert(decl.zir_decl_index != 0);
    const zir = Module.getHandle(decl.*, mod).getCachedZir();
    return @enumFromInt(zir.extra[decl.zir_decl_index + 6]);
}

pub fn getHandle(decl: Decl, mod: *Module) *Handle {
    return mod.namespacePtr(decl.src_namespace).handle;
}

/// The container that structs, enums, unions, and opaques have.
pub const Namespace = struct {
    /// .none means root Namespace
    parent: InternPool.NamespaceIndex,
    handle: *Handle,
    /// Will be a struct, enum, union, or opaque.
    ty: InternPool.Index,
    decls: std.ArrayHashMapUnmanaged(Decl.Index, void, DeclContext, false) = .{},
    anon_decls: std.AutoArrayHashMapUnmanaged(Decl.Index, void) = .{},
    usingnamespace_set: std.AutoHashMapUnmanaged(Decl.Index, bool) = .{},

    pub const DeclStringAdapter = struct {
        ip: *InternPool,

        pub fn hash(self: @This(), s: InternPool.StringPool.String) u32 {
            const locked_string = self.ip.string_pool.stringToSliceLock(s);
            defer locked_string.release(&self.ip.string_pool);
            return std.array_hash_map.hashString(locked_string.slice);
        }

        pub fn eql(self: @This(), a: InternPool.StringPool.String, b_decl_index: Decl.Index, b_index: usize) bool {
            _ = b_index;
            const b_decl = self.ip.getDecl(b_decl_index);
            return a == b_decl.name;
        }
    };

    pub const DeclContext = struct {
        ip: *InternPool,

        pub fn hash(ctx: @This(), decl_index: Decl.Index) u32 {
            const name_index = ctx.ip.getDecl(decl_index).name;
            const locked_string = ctx.ip.string_pool.stringToSliceLock(name_index);
            defer locked_string.release(&ctx.ip.string_pool);
            return std.array_hash_map.hashString(locked_string.slice);
        }

        pub fn eql(ctx: @This(), a_decl_index: Decl.Index, b_decl_index: Decl.Index, b_index: usize) bool {
            _ = b_index;
            const a_decl_name_index = ctx.ip.getDecl(a_decl_index).name;
            const b_decl_name_index = ctx.ip.getDecl(b_decl_index).name;
            return a_decl_name_index == b_decl_name_index;
        }
    };

    // This renders e.g. "std.fs.Dir.OpenOptions"
    pub fn renderFullyQualifiedName(
        ns: Namespace,
        mod: *Module,
        name: []const u8,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (ns.parent) |parent| {
            const decl_index = ns.getDecl.Index();
            const decl = mod.declPtr(decl_index);
            try parent.renderFullyQualifiedName(mod, std.mem.sliceTo(decl.name, 0), writer);
        } else {
            try ns.handle.renderFullyQualifiedName(writer);
        }
        if (name.len != 0) {
            try writer.writeAll(".");
            try writer.writeAll(name);
        }
    }

    pub fn getDeclIndex(ns: Namespace, mod: *Module) Decl.Index {
        return mod.ip.getStruct(mod.ip.indexToKey(ns.ty).struct_type).owner_decl.unwrap().?;
    }
};

pub fn allocateNewDecl(
    mod: *Module,
    namespace: InternPool.NamespaceIndex,
    src_node: Ast.Node.Index,
) Allocator.Error!Decl.Index {
    const decl: *Decl = try mod.ip.decls.addOne(mod.gpa);
    const decl_index = @as(Decl.Index, @enumFromInt(mod.ip.decls.len - 1));

    decl.* = .{
        .name = undefined,
        .index = .none,
        .alignment = undefined,
        .address_space = .generic,
        .src_namespace = namespace,
        .node_idx = src_node,
        .src_line = undefined,
        .zir_decl_index = 0,
        .analysis = .unreferenced,
        .is_pub = false,
        .is_exported = false,
        .kind = .anon,
    };

    return decl_index;
}

pub fn createNamespace(mod: *Module, namespace: Namespace) Allocator.Error!InternPool.NamespaceIndex {
    try mod.allocated_namespaces.append(mod.gpa, namespace);
    const namespace_index = @as(InternPool.NamespaceIndex, @enumFromInt(mod.allocated_namespaces.len - 1));

    return namespace_index;
}

pub fn destroyNamespace(mod: *Module, namespace_index: InternPool.NamespaceIndex) void {
    const gpa = mod.gpa;

    const ns = mod.namespacePtr(namespace_index);

    var decls = ns.decls;
    ns.decls = .{};

    var anon_decls = ns.anon_decls;
    ns.anon_decls = .{};

    for (decls.keys()) |decl_index| {
        mod.destroyDecl(decl_index);
    }
    decls.deinit(gpa);

    for (anon_decls.keys()) |key| {
        mod.destroyDecl(key);
    }
    anon_decls.deinit(gpa);

    var usingnamespaces = ns.usingnamespace_set;
    ns.usingnamespace_set = .{};
    usingnamespaces.deinit(gpa);
}

pub fn destroyDecl(mod: *Module, decl_index: Decl.Index) void {
    const decl = mod.declPtr(decl_index);
    if (decl.index != .none) {
        const namespace = mod.ip.getNamespace(decl.index);
        if (namespace != .none) {
            mod.destroyNamespace(namespace);
        }
    }
    decl.* = undefined;
}

pub fn declPtr(mod: *Module, decl_index: Decl.Index) *Decl {
    return mod.ip.getDeclMut(decl_index);
}

pub fn declIsRoot(mod: *Module, decl_index: Decl.Index) bool {
    const decl = mod.declPtr(decl_index);
    if (decl.src_namespace != .none)
        return false;
    const namespace = mod.namespacePtr(decl.src_namespace);
    return decl_index == namespace.getDeclIndex(mod);
}

pub fn namespacePtr(mod: *Module, namespace_index: InternPool.NamespaceIndex) *Namespace {
    return mod.allocated_namespaces.at(@intFromEnum(namespace_index));
}

pub fn get(mod: *Module, key: InternPool.Key) Allocator.Error!InternPool.Index {
    return mod.ip.get(mod.gpa, key);
}

pub fn semaFile(mod: *Module, handle: *Handle) Allocator.Error!void {
    // TODO also support .outdated which may required require storing the old Ast as well
    assert(handle.getZirStatus() == .done);
    assert(handle.root_decl == .none);

    const struct_index = try mod.ip.createStruct(mod.gpa, .{
        .fields = .{},
        .owner_decl = undefined, // set below
        .zir_index = @intFromEnum(Zir.Inst.Index.main_struct_inst),
        .namespace = undefined, // set below
        .layout = .Auto,
        .backing_int_ty = .none,
        .status = .none,
    });
    const struct_ty = try mod.get(.{ .struct_type = struct_index });

    const namespace_index = try mod.createNamespace(.{
        .parent = .none,
        .handle = handle,
        .ty = struct_ty,
    });

    const decl_index = try mod.allocateNewDecl(namespace_index, 0);
    const decl = mod.declPtr(decl_index);

    const struct_obj = mod.ip.getStructMut(struct_index);
    struct_obj.owner_decl = decl_index.toOptional();
    struct_obj.namespace = namespace_index;

    handle.root_decl = decl_index.toOptional();
    decl.name = try mod.ip.string_pool.getOrPutString(mod.gpa, handle.uri); // TODO
    decl.index = struct_ty;
    decl.alignment = 0;
    decl.analysis = .in_progress;
    decl.is_pub = true;
    decl.is_exported = false;
    decl.src_line = 0;

    var arena = std.heap.ArenaAllocator.init(mod.gpa);
    defer arena.deinit();

    var sema = Sema{
        .mod = mod,
        .gpa = mod.gpa,
        .arena = arena.allocator(),
        .code = handle.getCachedZir(),
    };
    defer sema.deinit();

    try sema.analyzeStructDecl(decl, struct_obj);
    decl.analysis = .complete;
}

pub fn semaDecl(mod: *Module, decl_index: Decl.Index) Allocator.Error!void {
    const decl = mod.declPtr(decl_index);
    decl.analysis = .in_progress;

    const namespace = mod.namespacePtr(decl.src_namespace);
    const handle = namespace.handle;
    const zir = handle.getCachedZir();
    const zir_datas = zir.instructions.items(.data);
    assert(handle.getZirStatus() == .done);

    var arena = std.heap.ArenaAllocator.init(mod.gpa);
    defer arena.deinit();

    var sema = Sema{
        .mod = mod,
        .gpa = mod.gpa,
        .arena = arena.allocator(),
        .code = zir,
    };
    defer sema.deinit();

    const string_pool = &sema.mod.ip.string_pool;

    if (mod.declIsRoot(decl_index)) {
        log.debug("semaDecl root {d} ({})", .{ @intFromEnum(decl_index), decl.name.fmt(string_pool) });
        const struct_ty = mod.ip.indexToKey(decl.index).struct_type;
        const struct_obj = mod.ip.getStructMut(struct_ty);
        try sema.analyzeStructDecl(decl, struct_obj);
        decl.analysis = .complete;
        return;
    }
    log.debug("semaDecl {d} ({})", .{ @intFromEnum(decl_index), decl.name.fmt(string_pool) });

    var block_scope: Sema.Block = .{
        .parent = null,
        .src_decl = decl_index,
        .namespace = decl.src_namespace,
        .is_comptime = true,
    };
    defer block_scope.params.deinit(mod.gpa);
    defer if (block_scope.label) |l| l.merges.deinit(sema.gpa);

    const zir_block_index = Module.zirBlockIndex(decl, mod);
    const inst_data = zir_datas[@intFromEnum(zir_block_index)].pl_node;
    const extra = zir.extraData(Zir.Inst.Block, inst_data.payload_index);
    const body: []const Zir.Inst.Index = @ptrCast(zir.extra[extra.end..][0..extra.data.body_len]);
    decl.index = if (try sema.analyzeBodyBreak(&block_scope, body)) |break_data| sema.resolveIndex(break_data.operand) else .none;
    decl.analysis = .complete;

    const decl_name = try mod.ip.string_pool.stringToSliceAlloc(mod.gpa, decl.name);
    defer mod.gpa.free(decl_name);

    try sema.addDbgVar(&block_scope, decl.index, false, decl_name);
}
