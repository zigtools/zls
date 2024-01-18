const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.zls_sema);

const Sema = @This();
const Zir = @import("../stage2/Zir.zig");
const Module = @import("Module.zig");
const trace = @import("../tracy.zig").trace;
const Namespace = Module.Namespace;

const LazySrcLoc = @import("../stage2/Module.zig").LazySrcLoc;

const offsets = @import("../offsets.zig");
const types = @import("../lsp.zig");
const Analyser = @import("../analysis.zig");
const ErrorMsg = @import("error_msg.zig").ErrorMsg;
const InternPool = @import("InternPool.zig");
const Index = InternPool.Index;
const Decl = InternPool.Decl;
const StringPool = InternPool.StringPool;

mod: *Module,
gpa: Allocator,
arena: Allocator,
code: Zir,
index_map: IndexMap = .{},
src: LazySrcLoc = .{ .token_offset = 0 },
debug_src: Zir.Inst.LineColumn = .{ .line = 0, .column = 0 },

const IndexMap = struct {
    items: []Index = &[_]Index{},
    start: Zir.Inst.Index = @enumFromInt(0),

    fn deinit(map: IndexMap, allocator: Allocator) void {
        allocator.free(map.items);
    }

    fn get(map: IndexMap, key: Zir.Inst.Index) ?Index {
        if (!map.contains(key)) return null;
        return map.items[@intFromEnum(key) - @intFromEnum(map.start)];
    }

    fn putAssumeCapacity(
        map: *IndexMap,
        key: Zir.Inst.Index,
        index: Index,
    ) void {
        map.items[@intFromEnum(key) - @intFromEnum(map.start)] = index;
    }

    fn putAssumeCapacityNoClobber(
        map: *IndexMap,
        key: Zir.Inst.Index,
        index: Index,
    ) void {
        assert(!map.contains(key));
        map.putAssumeCapacity(key, index);
    }

    const GetOrPutResult = struct {
        value_ptr: *Index,
        found_existing: bool,
    };

    fn getOrPutAssumeCapacity(
        map: *IndexMap,
        key: Zir.Inst.Index,
    ) GetOrPutResult {
        const index = @intFromEnum(key) - @intFromEnum(map.start);
        return GetOrPutResult{
            .value_ptr = &map.items[index],
            .found_existing = map.items[index] != .none,
        };
    }

    fn remove(map: IndexMap, key: Zir.Inst.Index) bool {
        if (!map.contains(key)) return false;
        map.items[@intFromEnum(key) - @intFromEnum(map.start)] = .none;
        return true;
    }

    fn contains(map: IndexMap, key: Zir.Inst.Index) bool {
        return map.items[@intFromEnum(key) - @intFromEnum(map.start)] != .none;
    }

    fn ensureSpaceForInstructions(
        map: *IndexMap,
        allocator: Allocator,
        insts: []const Zir.Inst.Index,
    ) !void {
        const start, const end = std.mem.minMax(u32, @ptrCast(insts));
        if (@intFromEnum(map.start) <= start and end < map.items.len + @intFromEnum(map.start))
            return;

        const old_start = if (map.items.len == 0) start else @intFromEnum(map.start);
        var better_capacity = map.items.len;
        var better_start = old_start;
        while (true) {
            const extra_capacity = better_capacity / 2 + 16;
            better_capacity += extra_capacity;
            better_start -|= @as(u32, @intCast(extra_capacity / 2));
            if (better_start <= start and end < better_capacity + better_start)
                break;
        }

        const start_diff = old_start - better_start;
        const new_items = try allocator.alloc(Index, better_capacity);
        @memset(new_items[0..start_diff], .none);
        @memcpy(new_items[start_diff..][0..map.items.len], map.items);
        @memset(new_items[start_diff + map.items.len ..], .none);

        allocator.free(map.items);
        map.items = new_items;
        map.start = @enumFromInt(better_start);
    }
};

pub const Block = struct {
    parent: ?*Block,
    namespace: InternPool.NamespaceIndex,
    params: std.ArrayListUnmanaged(Param) = .{},
    label: ?*Label = null,
    src_decl: Decl.Index,
    is_comptime: bool,

    const Param = struct {
        ty: Index,
        is_comptime: bool,
        name: []const u8,
    };

    pub const Label = struct {
        zir_block: Zir.Inst.Index,
        merges: std.MultiArrayList(Merge),
    };

    pub const Merge = struct {
        result: Index,
        src_loc: ?LazySrcLoc,
    };

    pub fn getHandle(block: *Block, mod: *Module) *Module.Handle {
        return Module.getHandle(mod.declPtr(block.src_decl).*, mod);
    }
};

pub fn deinit(sema: *Sema) void {
    const gpa = sema.gpa;
    sema.index_map.deinit(gpa);
    sema.* = undefined;
}

const always_noreturn: Allocator.Error!Zir.Inst.Index = @as(Zir.Inst.Index, @enumFromInt(std.math.maxInt(u32)));

fn analyzeBodyInner(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!Zir.Inst.Index {
    const map = &sema.index_map;
    const tags = sema.code.instructions.items(.tag);
    const datas = sema.code.instructions.items(.data);

    try map.ensureSpaceForInstructions(sema.gpa, body);

    const result: Allocator.Error!Zir.Inst.Index = for (body) |inst| {
        const index: Index = switch (tags[@intFromEnum(inst)]) {
            // zig fmt: off
            .alloc                        => .none,
            .alloc_inferred               => .none,
            .alloc_inferred_mut           => .none,
            .alloc_inferred_comptime      => .none,
            .alloc_inferred_comptime_mut  => .none,
            .alloc_mut                    => .none,
            .alloc_comptime_mut           => .none,
            .make_ptr_const               => .none,
            .anyframe_type                => try sema.zirAnyframeType(block, inst),
            .array_cat                    => .none,
            .array_mul                    => .none,
            .array_type                   => try sema.zirArrayType(block, inst),
            .array_type_sentinel          => try sema.zirArrayTypeSentinel(block, inst),
            .vector_type                  => try sema.zirVectorType(block, inst),
            .as_node                      => try sema.zirAsNode(block, inst),
            .as_shift_operand             => .none,
            .bit_and                      => .none,
            .bit_not                      => .none,
            .bit_or                       => .none,
            .bitcast                      => .none,
            .suspend_block                => .none,
            .bool_not                     => try sema.zirBoolNot(block,inst),
            .bool_br_and                  => .none,
            .bool_br_or                   => .none,
            .c_import                     => .none,
            .call                         => .none,
            .field_call                   => .none,
            .closure_get                  => .none,
            .cmp_lt                       => try sema.getUnknownValue(Index.bool_type),
            .cmp_lte                      => try sema.getUnknownValue(Index.bool_type),
            .cmp_eq                       => try sema.zirCmpEq(block, inst, .eq),
            .cmp_gte                      => try sema.getUnknownValue(Index.bool_type),
            .cmp_gt                       => try sema.getUnknownValue(Index.bool_type),
            .cmp_neq                      => try sema.zirCmpEq(block, inst, .neq),
            .decl_ref                     => .none,
            .decl_val                     => try sema.zirDeclVal(block, inst),
            .load                         => try sema.zirLoad(block, inst),
            .elem_ptr                     => .none,
            .elem_ptr_node                => .none,
            .elem_val_node                => try sema.zirElemValNode(block, inst),
            .elem_val                     => try sema.zirElemVal(block, inst),
            .elem_val_imm                 => .none,
            .elem_type                    => .none,
            .indexable_ptr_elem_type      => .none,
            .vector_elem_type             => .none,
            .enum_literal                 => .none,
            .int_from_enum                => .none,
            .enum_from_int                => .none,
            .err_union_code               => .none,
            .err_union_code_ptr           => .none,
            .err_union_payload_unsafe     => .none,
            .err_union_payload_unsafe_ptr => .none,
            .error_union_type             => try sema.zirErrorUnionType(block, inst),
            .error_value                  => try sema.zirErrorValue(block, inst),
            .field_ptr                    => .none,
            .field_ptr_named              => .none,
            .field_val                    => try sema.zirFieldVal(block, inst),
            .field_val_named              => .none,
            .func                         => try sema.zirFunc(block, inst, false),
            .func_inferred                => try sema.zirFunc(block, inst, true),
            .func_fancy                   => .none,
            .import                       => .none,
            .indexable_ptr_len            => .none,
            .int                          => try sema.zirInt(block, inst),
            .int_big                      => .none,
            .float                        => try sema.zirFloat(block, inst),
            .float128                     => try sema.zirFloat128(block, inst),
            .int_type                     => try sema.zirIntType(block, inst),
            .is_non_err                   => try sema.getUnknownValue(Index.bool_type),
            .is_non_err_ptr               => try sema.getUnknownValue(Index.bool_type),
            .ret_is_non_err               => try sema.getUnknownValue(Index.bool_type),
            .is_non_null                  => try sema.getUnknownValue(Index.bool_type),
            .is_non_null_ptr              => try sema.getUnknownValue(Index.bool_type),
            .merge_error_sets             => try sema.zirMergeErrorSets(block, inst),
            .negate                       => .none,
            .negate_wrap                  => .none,
            .optional_payload_safe        => try sema.zirOptionalPayload(block,inst),
            .optional_payload_safe_ptr    => .none,
            .optional_payload_unsafe      => try sema.zirOptionalPayload(block,inst),
            .optional_payload_unsafe_ptr  => .none,
            .optional_type                => try sema.zirOptionalType(block, inst),
            .ref                          => try sema.zirRef(block, inst),
            .ptr_type                     => try sema.zirPtrType(block, inst),
            .ret_err_value_code           => .none,
            .shr                          => .none,
            .shr_exact                    => .none,
            .slice_end                    => .none,
            .slice_sentinel               => .none,
            .slice_start                  => .none,
            .slice_length                 => .none,
            .str                          => .none,
            .switch_block                 => try sema.zirSwitchBlock(block, inst, false),
            .switch_block_ref             => try sema.zirSwitchBlock(block, inst, true),
            .switch_block_err_union       => .none,
            .type_info                    => .none,
            .size_of                      => try sema.getUnknownValue(Index.comptime_int_type),
            .bit_size_of                  => try sema.getUnknownValue(Index.comptime_int_type),
            .typeof                       => try sema.zirTypeof(block, inst),
            .typeof_builtin               => try sema.zirTypeofBuiltin(block, inst),
            .typeof_log2_int_type         => .none,
            .xor                          => .none,
            .struct_init_empty            => try sema.zirStructInitEmpty(block, inst),
            .struct_init_empty_result     => .none,
            .struct_init_empty_ref_result => .none,
            .struct_init_anon             => .none,
            .struct_init                  => try sema.zirStructInit(block, inst, false),
            .struct_init_ref              => try sema.zirStructInit(block, inst, true),
            .struct_init_field_type       => .none,
            .struct_init_field_ptr        => .none,
            .array_init_anon              => .none,
            .array_init                   => .none,
            .array_init_ref               => .none,
            .array_init_elem_type         => .none,
            .array_init_elem_ptr          => .none,
            .union_init                   => .none,
            .field_type_ref               => Index.unknown_type,
            .int_from_ptr                 => try sema.getUnknownValue(Index.usize_type),
            .align_of                     => try sema.getUnknownValue(Index.comptime_int_type),
            .int_from_bool                => try sema.zirIntFromBool(block, inst),
            .embed_file                   => .none,
            .error_name                   => .none,
            .tag_name                     => .none,
            .type_name                    => .none,
            .frame_type                   => Index.unknown_type,
            .frame_size                   => try sema.getUnknownValue(Index.usize_type),
            .int_from_float               => .none,
            .float_from_int               => .none,
            .ptr_from_int                 => try sema.getUnknownValue(Index.usize_type),
            .float_cast                   => .none,
            .int_cast                     => .none,
            .ptr_cast                     => .none,
            .truncate                     => .none,
            .has_decl                     => try sema.getUnknownValue(Index.bool_type),
            .has_field                    => try sema.getUnknownValue(Index.bool_type),
            .byte_swap                    => .none,
            .bit_reverse                  => .none,
            .bit_offset_of                => try sema.getUnknownValue(Index.comptime_int_type),
            .offset_of                    => try sema.getUnknownValue(Index.comptime_int_type),
            .splat                        => .none,
            .reduce                       => .none,
            .shuffle                      => .none,
            .atomic_load                  => .none,
            .atomic_rmw                   => .none,
            .mul_add                      => .none,
            .builtin_call                 => .none,
            .field_parent_ptr             => .none,
            .@"resume"                    => .none,
            .@"await"                     => .none,
            .for_len                      => try sema.getUnknownValue(Index.usize_type),
            .validate_array_init_ref_ty   => .none,
            .opt_eu_base_ptr_init         => .none,
            .coerce_ptr_elem_ty           => .none,

            .clz       => .none,
            .ctz       => .none,
            .pop_count => .none,

            .sqrt  => .none,
            .sin   => .none,
            .cos   => .none,
            .tan   => .none,
            .exp   => .none,
            .exp2  => .none,
            .log   => .none,
            .log2  => .none,
            .log10 => .none,
            .abs   => .none,
            .floor => .none,
            .ceil  => .none,
            .round => .none,
            .trunc => .none,

            .error_set_decl      => try sema.zirErrorSetDecl(block, inst, .parent),
            .error_set_decl_anon => try sema.zirErrorSetDecl(block, inst, .anon),
            .error_set_decl_func => try sema.zirErrorSetDecl(block, inst, .func),

            .add       => .none,
            .addwrap   => .none,
            .add_sat   => .none,
            .add_unsafe=> .none,
            .mul       => .none,
            .mulwrap   => .none,
            .mul_sat   => .none,
            .sub       => .none,
            .subwrap   => .none,
            .sub_sat   => .none,

            .div       => .none,
            .div_exact => .none,
            .div_floor => .none,
            .div_trunc => .none,

            .mod_rem   => .none,
            .mod       => .none,
            .rem       => .none,

            .max => .none,
            .min => .none,

            .shl       => .none,
            .shl_exact => .none,
            .shl_sat   => .none,

            .ret_ptr  => .none,
            .ret_type => .none,

            // Instructions that we know to *always* be noreturn based solely on their tag.
            // These functions match the return type of analyzeBody so that we can
            // tail call them here.
            .compile_error  => break always_noreturn,
            .ret_implicit   => break always_noreturn,
            .ret_node       => break always_noreturn,
            .ret_load       => break always_noreturn,
            .ret_err_value  => break always_noreturn,
            .@"unreachable" => break always_noreturn,
            .panic          => break always_noreturn,
            .trap           => break always_noreturn,
            // zig fmt: on

            .extended => blk: {
                const extended = datas[@intFromEnum(inst)].extended;
                break :blk switch (extended.opcode) {
                    // zig fmt: off
                    .variable              => .none,
                    .struct_decl           => try sema.zirStructDecl(        block, extended, inst),
                    .enum_decl             => Index.unknown_type,
                    .union_decl            => Index.unknown_type,
                    .opaque_decl           => Index.unknown_type,
                    .this                  => Index.unknown_type,
                    .ret_addr              => try sema.getUnknownValue(Index.usize_type),
                    .builtin_src           => .none,
                    .error_return_trace    => .none,
                    .frame                 => .none,
                    .frame_address         => .none,
                    .alloc                 => .none,
                    .builtin_extern        => .none,
                    .@"asm"                => .none,
                    .asm_expr              => .none,
                    .typeof_peer           => try sema.zirTypeofPeer(        block, extended),
                    .compile_log           => .none,
                    .min_multi             => .none,
                    .max_multi             => .none,
                    .add_with_overflow     => .none,
                    .sub_with_overflow     => .none,
                    .mul_with_overflow     => .none,
                    .shl_with_overflow     => .none,
                    .c_undef               => .none,
                    .c_include             => .none,
                    .c_define              => .none,
                    .wasm_memory_size      => try sema.getUnknownValue(Index.u32_type),
                    .wasm_memory_grow      => try sema.getUnknownValue(Index.u32_type),
                    .prefetch              => Index.void_value,
                    .error_cast            => .none,
                    .await_nosuspend       => .none,
                    .select                => .none,
                    .int_from_error        => .none,
                    .error_from_int        => .none,
                    .reify                 => Index.unknown_type,
                    .builtin_async_call    => .none,
                    .cmpxchg               => .none,
                    .c_va_arg              => .none,
                    .c_va_copy             => .none,
                    .c_va_end              => .none,
                    .c_va_start            => .none,
                    .ptr_cast_full         => .none,
                    .ptr_cast_no_dest      => .none,
                    .work_item_id          => try sema.getUnknownValue(Index.u32_type),
                    .work_group_size       => try sema.getUnknownValue(Index.u32_type),
                    .work_group_id         => try sema.getUnknownValue(Index.u32_type),
                    .in_comptime           => try sema.zirInComptime(        block),
                    // zig fmt: on

                    .fence,
                    .set_float_mode,
                    .set_align_stack,
                    .set_cold,
                    .breakpoint,
                    => continue,
                    .value_placeholder => unreachable, // never appears in a body
                };
            },

            // Instructions that we know can *never* be noreturn based solely on
            // their tag. We avoid needlessly checking if they are noreturn and
            // continue the loop.
            // We also know that they cannot be referenced later, so we avoid
            // putting them into the map.
            .dbg_stmt => {
                try sema.zirDbgStmt(block, inst);
                continue;
            },
            .dbg_var_ptr => {
                try sema.zirDbgVar(block, inst, true);
                continue;
            },
            .dbg_var_val => {
                try sema.zirDbgVar(block, inst, false);
                continue;
            },
            .dbg_block_begin => {
                continue;
            },
            .dbg_block_end => {
                continue;
            },
            .ensure_err_union_payload_void => {
                continue;
            },
            .ensure_result_non_error => {
                continue;
            },
            .ensure_result_used => {
                continue;
            },
            .set_eval_branch_quota => {
                continue;
            },
            .atomic_store => {
                continue;
            },
            .store => {
                continue;
            },
            .store_node => {
                continue;
            },
            .store_to_inferred_ptr => {
                continue;
            },
            .resolve_inferred_alloc => {
                continue;
            },
            .validate_struct_init_ty => {
                continue;
            },
            .validate_struct_init_result_ty => {
                continue;
            },
            .validate_array_init_ty => {
                continue;
            },
            .validate_array_init_result_ty => {
                continue;
            },
            .validate_ptr_struct_init => {
                continue;
            },
            .validate_ptr_array_init => {
                continue;
            },
            .validate_deref => {
                continue;
            },
            .validate_destructure => {
                continue;
            },
            .validate_ref_ty => {
                continue;
            },
            .@"export" => {
                continue;
            },
            .export_value => {
                continue;
            },
            .set_runtime_safety => {
                continue;
            },
            .param => {
                try sema.zirParam(block, inst, false);
                continue;
            },
            .param_comptime => {
                try sema.zirParam(block, inst, true);
                continue;
            },
            .param_anytype => {
                continue;
            },
            .param_anytype_comptime => {
                continue;
            },
            .closure_capture => {
                continue;
            },
            .memcpy => {
                continue;
            },
            .memset => {
                continue;
            },
            .check_comptime_control_flow => {
                continue;
            },
            .save_err_ret_index => {
                continue;
            },
            .restore_err_ret_index => {
                continue;
            },

            // Special case instructions to handle comptime control flow.
            .@"break" => {
                if (block.is_comptime) {
                    break inst; // same as break_inline
                } else {
                    break try sema.zirBreak(block, inst);
                }
            },
            .break_inline => {
                if (block.is_comptime) {
                    break inst;
                } else {
                    break inst;
                    // sema.comptime_break_inst = inst;
                    // return error.ComptimeBreak;
                }
            },
            .repeat => continue,
            .repeat_inline => continue,
            .loop => continue,
            .block, .block_comptime, .block_inline => blk: {
                if (tags[@intFromEnum(inst)] != .block_inline) {
                    if (!block.is_comptime) {
                        break :blk try sema.zirBlock(block, inst, tags[@intFromEnum(inst)] == .block_comptime);
                    }
                }
                const inst_data = datas[@intFromEnum(inst)].pl_node;
                const extra = sema.code.extraData(Zir.Inst.Block, inst_data.payload_index);
                const inline_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.body_len]);

                const opt_break_data = try sema.analyzeBodyBreak(block, inline_body);

                const break_data = opt_break_data orelse break always_noreturn;
                if (inst == break_data.block_inst) {
                    break :blk sema.resolveIndex(break_data.operand);
                } else {
                    break break_data.inst;
                }
            },
            .condbr, .condbr_inline => blk: {
                if (tags[@intFromEnum(inst)] != .condbr_inline) {
                    if (!block.is_comptime) break sema.zirCondbr(block, inst);
                }

                const inst_data = datas[@intFromEnum(inst)].pl_node;
                //const cond_src: LazySrcLoc = .{ .node_offset_if_cond = inst_data.src_node };
                const extra = sema.code.extraData(Zir.Inst.CondBr, inst_data.payload_index);
                const then_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.then_body_len]);
                const else_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);

                const cond = sema.resolveIndex(extra.data.condition);
                assert(sema.typeOf(cond) == .bool_type);
                const inline_body = if (cond == .bool_true) then_body else if (cond == .bool_false) else_body else {
                    // std.debug.panic("TODO: comptime branch on unknown value", .{});
                    break always_noreturn;
                };

                const break_data = (try sema.analyzeBodyBreak(block, inline_body)) orelse break always_noreturn;
                if (inst == break_data.block_inst) {
                    break :blk sema.resolveIndex(break_data.operand);
                } else {
                    break break_data.inst;
                }
            },
            .@"try" => continue,
            .try_ptr => continue,
            .@"defer" => continue,
            .defer_err_code => continue,
        };

        const index_ty = if (index != .none) sema.typeOf(index) else .none;

        log.debug("ZIR %{d:<3} {s:<14} ({})", .{
            inst,
            @tagName(tags[@intFromEnum(inst)]),
            index.fmtDebug(sema.mod.ip),
        });
        if (index_ty == .noreturn_type) {
            break always_noreturn;
        }
        if (index != .none and index != .unknown_unknown) {
            map.putAssumeCapacity(inst, index);
        }
    } else always_noreturn;
    return result;
}

fn zirParam(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    comptime_syntax: bool,
) Allocator.Error!void {
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_tok;
    const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.Param, inst_data.payload_index);
    const param_name = sema.code.nullTerminatedString(extra.data.name);
    const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.body_len]);

    const param_ty_inst = try sema.resolveBody(block, body);
    const param_ty = try sema.coerce(block, .type_type, param_ty_inst, src);

    try block.params.append(sema.gpa, .{
        .ty = param_ty,
        .is_comptime = comptime_syntax,
        .name = param_name,
    });
}

fn zirBreak(sema: *Sema, start_block: *Block, inst: Zir.Inst.Index) !Zir.Inst.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].@"break";
    const extra = sema.code.extraData(Zir.Inst.Break, inst_data.payload_index).data;
    const operand = sema.resolveIndex(inst_data.operand);
    const zir_block = extra.block_inst;

    var block = start_block;
    while (true) : (block = block.parent.?) {
        const label = block.label orelse continue;
        if (label.zir_block != zir_block) continue;

        const src_loc = if (extra.operand_src_node != Zir.Inst.Break.no_src_node)
            LazySrcLoc.nodeOffset(extra.operand_src_node)
        else
            null;
        try label.merges.append(sema.gpa, .{
            .result = operand,
            .src_loc = src_loc,
        });
        return inst;
    }
}

fn zirBlock(sema: *Sema, parent_block: *Block, inst: Zir.Inst.Index, force_comptime: bool) Allocator.Error!Index {
    const pl_node = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = pl_node.src();
    const extra = sema.code.extraData(Zir.Inst.Block, pl_node.payload_index);
    const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.body_len]);

    var label: Block.Label = .{
        .zir_block = inst,
        .merges = .{},
    };

    var child_block: Block = .{
        .parent = parent_block,
        .namespace = parent_block.namespace,
        .src_decl = parent_block.src_decl,
        .label = &label,
        .is_comptime = parent_block.is_comptime or force_comptime,
    };
    defer child_block.params.deinit(sema.gpa);
    defer if (child_block.label) |l| l.merges.deinit(sema.gpa);

    if (child_block.is_comptime) {
        return try sema.resolveBody(&child_block, body);
    } else {
        _ = try sema.analyzeBodyInner(&child_block, body);
        return try sema.analyzeBlockBody(parent_block, src, &child_block, &label.merges);
    }
}

fn zirCondbr(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Zir.Inst.Index {
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.CondBr, inst_data.payload_index);

    const then_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);

    _ = try sema.analyzeBodyInner(block, then_body);
    _ = try sema.analyzeBodyInner(block, else_body);

    return always_noreturn;
}

//
//
//

pub fn resolveIndex(sema: *Sema, zir_ref: Zir.Inst.Ref) Index {
    var i: u32 = @intFromEnum(zir_ref);

    if (i < @intFromEnum(Zir.Inst.Ref.ref_start_index)) return @enumFromInt(i);
    i -= @intFromEnum(Zir.Inst.Ref.ref_start_index);

    return sema.index_map.get(@enumFromInt(i)) orelse .unknown_unknown;
}

pub fn resolveType(sema: *Sema, block: *Block, src: LazySrcLoc, zir_ref: Zir.Inst.Ref) Allocator.Error!Index {
    const index = sema.resolveIndex(zir_ref);
    switch (sema.typeOf(index)) {
        .type_type, .unknown_type => return index,
        else => {
            try sema.fail(block, src, .{ .expected_type = .{
                .expected = .type_type,
                .actual = index,
            } });
            return .unknown_type;
        },
    }
}

fn resolveInt(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    zir_ref: Zir.Inst.Ref,
    dest_ty: Index,
    reason: []const u8,
) !?u64 {
    std.debug.assert(sema.mod.ip.isType(dest_ty));
    const index = sema.resolveIndex(zir_ref);
    return try sema.analyzeAsInt(block, src, index, dest_ty, reason);
}

fn analyzeAsInt(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    inst: Index,
    dest_ty: Index,
    reason: []const u8,
) !?u64 {
    std.debug.assert(sema.mod.ip.isType(dest_ty));
    _ = reason;
    const coerced = try sema.coerce(block, dest_ty, inst, src);
    return try sema.mod.ip.toInt(coerced, u64);
}

fn resolveBody(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!Index {
    const break_data = try sema.analyzeBodyBreak(block, body) orelse return .unknown_unknown;
    return sema.resolveIndex(break_data.operand);
}

const BreakData = struct {
    block_inst: Zir.Inst.Index,
    operand: Zir.Inst.Ref,
    inst: Zir.Inst.Index,
};

pub fn analyzeBodyBreak(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!?BreakData {
    const break_inst = try sema.analyzeBodyInner(block, body);
    if (@intFromEnum(break_inst) == std.math.maxInt(u32)) return null;
    const break_data = sema.code.instructions.items(.data)[@intFromEnum(break_inst)].@"break";
    const extra = sema.code.extraData(Zir.Inst.Break, break_data.payload_index).data;
    return BreakData{
        .block_inst = extra.block_inst,
        .operand = break_data.operand,
        .inst = break_inst,
    };
}

fn analyzeBlockBody(
    sema: *Sema,
    parent_block: *Block,
    src: LazySrcLoc,
    child_block: *Block,
    merges: *const std.MultiArrayList(Block.Merge),
) Allocator.Error!Index {
    _ = parent_block;
    const result_types = try sema.arena.alloc(Index, merges.items(.result).len);
    defer sema.arena.free(result_types);
    for (merges.items(.result), result_types) |val, *ty| {
        ty.* = sema.typeOf(val);
    }
    const resolved_ty = try sema.mod.ip.resolvePeerTypes(sema.gpa, result_types, builtin.target);
    if (resolved_ty == .void_type) {
        // TODO implement switch_block and other control flow instructions to avoid false positives
        return .unknown_unknown;
    }
    if (resolved_ty == .none) {
        // TODO error message
        return .unknown_unknown;
    }
    for (merges.items(.result), merges.items(.src_loc)) |result, src_loc| {
        _ = try sema.coerce(child_block, resolved_ty, result, src_loc orelse src);
    }
    return try sema.getUnknownValue(resolved_ty);
}

//
//
//

fn fail(sema: *Sema, block: *Block, src: LazySrcLoc, error_msg: ErrorMsg) Allocator.Error!void {
    @setCold(true);
    const src_decl = sema.mod.declPtr(block.src_decl);
    const handle = Module.getHandle(src_decl.*, sema.mod);
    const src_loc = src.toSrcLoc(handle, src_decl, sema.mod);
    const src_span = src_loc.span();
    const loc = offsets.Loc{ .start = src_span.start, .end = src_span.end };

    const message = try std.fmt.allocPrint(sema.mod.document_store.allocator, "{}", .{error_msg.fmt(sema.mod.ip)});
    errdefer sema.mod.document_store.allocator.free(message);

    try handle.analysis_errors.append(sema.mod.document_store.allocator, .{
        .loc = loc,
        .message = message,
        .code = "TODO",
    });
}

//
//
//

fn zirAnyframeType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const operand_src: LazySrcLoc = .{ .node_offset_anyframe_type = inst_data.src_node };
    const return_type = try sema.resolveType(block, operand_src, inst_data.operand);

    return sema.get(.{ .anyframe_type = .{ .child = return_type } });
}

fn zirArrayType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const len_src: LazySrcLoc = .{ .node_offset_array_type_len = inst_data.src_node };
    const elem_src: LazySrcLoc = .{ .node_offset_array_type_elem = inst_data.src_node };
    const len = (try sema.resolveInt(block, len_src, extra.lhs, .usize_type, "array length must be comptime-known")) orelse return .none;
    const elem_type = try sema.resolveType(block, elem_src, extra.rhs);

    return try sema.get(.{ .array_type = .{
        .len = len,
        .child = elem_type,
        .sentinel = .none,
    } });
}

fn zirArrayTypeSentinel(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.ArrayTypeSentinel, inst_data.payload_index).data;
    const len_src: LazySrcLoc = .{ .node_offset_array_type_len = inst_data.src_node };
    const sentinel_src: LazySrcLoc = .{ .node_offset_array_type_sentinel = inst_data.src_node };
    const elem_src: LazySrcLoc = .{ .node_offset_array_type_elem = inst_data.src_node };
    const len = (try sema.resolveInt(block, len_src, extra.len, .usize_type, "array length must be comptime-known")) orelse return .none;
    const elem_type = try sema.resolveType(block, elem_src, extra.elem_type);

    const uncasted_sentinel = sema.resolveIndex(extra.sentinel);
    const sentinel = try sema.coerce(block, elem_type, uncasted_sentinel, sentinel_src);

    return try sema.get(.{ .array_type = .{
        .len = len,
        .child = elem_type,
        .sentinel = sentinel,
    } });
}

fn zirVectorType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const elem_type_src: LazySrcLoc = .{ .node_offset_builtin_call_arg0 = inst_data.src_node };
    const len_src: LazySrcLoc = .{ .node_offset_builtin_call_arg1 = inst_data.src_node };
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const len = (try sema.resolveInt(block, len_src, extra.lhs, .u32_type, "vector length must be comptime-known")) orelse return .none;
    const elem_type = try sema.resolveType(block, elem_type_src, extra.rhs);

    // TODO error invalid vector element type
    // try sema.checkVectorElemType(block, elem_type_src, elem_type);

    return try sema.get(.{ .vector_type = .{
        .len = @intCast(len),
        .child = elem_type,
    } });
}

fn zirAsNode(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.As, inst_data.payload_index).data;
    sema.src = src;
    const dest_ty = try sema.resolveType(block, src, extra.dest_type);
    const operand = sema.resolveIndex(extra.operand);

    return try sema.coerce(block, dest_ty, operand, src);
}

fn zirBoolNot(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    // const src = inst_data.src();
    const operand_src: LazySrcLoc = .{ .node_offset_un_op = inst_data.src_node };
    const uncasted_operand = sema.resolveIndex(inst_data.operand);

    const operand = try sema.coerce(block, .bool_type, uncasted_operand, operand_src);

    return switch (operand) {
        Index.bool_false => Index.bool_true,
        Index.bool_true => Index.bool_false,
        else => {
            if (std.debug.runtime_safety) {
                switch (sema.indexToKey(operand)) {
                    .undefined_value, .unknown_value => {},
                    else => unreachable,
                }
            }
            return operand;
        },
    };
}

/// Only called for equality operators. See also `zirCmp`.
fn zirCmpEq(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    op: std.math.CompareOperator,
) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const ip = sema.mod.ip;
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const src: LazySrcLoc = inst_data.src();
    const lhs = sema.resolveIndex(extra.lhs);
    const rhs = sema.resolveIndex(extra.rhs);

    const lhs_key = sema.indexToKey(lhs);
    const rhs_key = sema.indexToKey(rhs);

    if (lhs_key == .unknown_value or rhs_key == .unknown_value) {
        return try sema.getUnknownValue(.bool_type);
    } else if (lhs_key == .undefined_value or rhs_key == .undefined_value) {
        return try sema.getUndefinedValue(.bool_type);
    }

    const lhs_ty = ip.typeOf(lhs);
    const rhs_ty = ip.typeOf(rhs);

    const lhs_ty_tag = ip.zigTypeTag(lhs_ty);
    const rhs_ty_tag = ip.zigTypeTag(rhs_ty);

    if (lhs_ty == .bool_type and rhs_ty == .bool_type) {
        assert(lhs == .bool_false or lhs == .bool_true and
            rhs == .bool_false or rhs == .bool_true);
        return if ((lhs == rhs) == (op == .eq)) .bool_true else .bool_false;
    }

    if (lhs_ty == .null_type or rhs_ty == .null_type) {
        if (lhs_ty == .null_type and rhs_ty == .null_type) {
            return if (op == .eq) .bool_true else .bool_false;
        }
        const non_null_type_index = if (lhs_ty == .null_type) rhs_ty else lhs_ty;
        if (ip.zigTypeTag(non_null_type_index) == .Optional or ip.isCPointer(non_null_type_index)) {
            const non_null_val = if (lhs_ty == .null_type) rhs else lhs;
            const is_null = ip.isNull(non_null_val);
            return if (is_null == (op == .eq)) .bool_true else .bool_false;
        }
        try sema.fail(block, src, .{ .compare_eq_with_null = .{ .non_null_type = non_null_type_index } });
        return try sema.getUnknownValue(.bool_type);
    }

    if (lhs_ty == .null_type and rhs_ty == .null_type) {
        return if (op == .eq) .bool_true else .bool_false;
    } else if (lhs_ty == .null_type and (rhs_ty == .bool_type or ip.isCPointer(rhs_ty))) {
        // TODO return sema.analyzeIsNull(block, src, rhs, op == .neq);
    } else if (rhs_ty == .null_type and (lhs_ty == .bool_type or ip.isCPointer(lhs_ty))) {
        // TODO return sema.analyzeIsNull(block, src, lhs, op == .neq);
    } else if (lhs_ty == .null_type or rhs_ty == .null_type) {
        const non_null_type = if (lhs_ty == .null_type) rhs_ty else lhs_ty;
        try sema.fail(block, src, .{ .compare_eq_with_null = .{ .non_null_type = non_null_type } });
        return try sema.getUnknownValue(.bool_type);
    }

    // if (lhs_ty_key == .union_type and (rhs_ty_tag == .EnumLiteral or rhs_ty_key == .enum_type)) {
    //     // TODO return sema.analyzeCmpUnionTag(block, src, lhs, lhs_src, rhs, rhs_src, op);
    //     return try sema.getUnknown(.bool_type);
    // } else if (rhs_ty_key == .union_type and (lhs_ty_tag == .EnumLiteral or lhs_ty_key == .enum_type)) {
    //     // TODO return sema.analyzeCmpUnionTag(block, src, rhs, rhs_src, lhs, lhs_src, op);
    //     return try sema.getUnknown(.bool_type);
    // }

    if (lhs_ty_tag == .ErrorSet and rhs_ty_tag == .ErrorSet) {
        // TODO return block.addBinOp(air_tag, lhs, rhs);
    }

    if (lhs_ty == .type_type and rhs_ty == .type_type) {
        return if ((lhs == rhs) == (op == .eq)) .bool_true else .bool_false;
    }

    // TODO return sema.analyzeCmp(block, src, lhs, rhs, op, lhs_src, rhs_src, true);
    return try sema.getUnknownValue(.bool_type);
}

fn zirDeclVal(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].str_tok;
    const decl_name = inst_data.get(sema.code);
    const decl_index = (try sema.lookupIdentifier(block, decl_name)).unwrap() orelse return .none;
    try sema.ensureDeclAnalyzed(decl_index);
    const decl = sema.mod.declPtr(decl_index);
    return decl.index;
}

fn zirDbgStmt(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!void {
    _ = block;
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].dbg_stmt;
    sema.debug_src = inst_data;
}

fn zirDbgVar(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    is_ptr: bool,
) Allocator.Error!void {
    const str_op = sema.code.instructions.items(.data)[@intFromEnum(inst)].str_op;
    const operand = sema.resolveIndex(str_op.operand);
    const name = str_op.getStr(sema.code);
    try sema.addDbgVar(block, operand, is_ptr, name);
}

pub fn addDbgVar(
    sema: *Sema,
    block: *Block,
    operand: Index,
    is_ptr: bool,
    name: []const u8,
) Allocator.Error!void {
    _ = is_ptr;
    if (operand == .none) return;

    if (sema.mod.ip.isUnknown(operand)) return;

    const handle = block.getHandle(sema.mod);
    const document_scope = try handle.getDocumentScope();
    const source_index = offsets.positionToIndex(
        handle.tree.source,
        types.Position{ .line = sema.debug_src.line, .character = sema.debug_src.column },
        .@"utf-8", // AstGen's source_column counts bytes
    );

    const decl_index = Analyser.lookupDeclaration(document_scope, source_index, name, .other).unwrap() orelse return;
    const decl = document_scope.declarations.get(@intFromEnum(decl_index));

    // [TODO][WARN][ERR] STOP DOING THIS
    // YOUR NOT SUPPOSED TO DO THIS
    handle.impl.document_scope.declarations.set(@intFromEnum(decl_index), Analyser.Declaration{ .intern_pool_index = .{
        .name = decl.nameToken(handle.tree),
        .index = operand,
    } });
}

fn zirLoad(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const src = inst_data.src();
    const ptr = sema.resolveIndex(inst_data.operand);
    const ptr_ty = sema.typeOf(ptr);
    if (ptr_ty == .unknown_type) return .unknown_unknown;

    const elem_ty = switch (sema.indexToKey(ptr_ty)) {
        .pointer_type => |info| info.elem_type,
        else => {
            try sema.fail(block, src, .{ .expected_tag_type = .{ .expected_tag = .Pointer, .actual = ptr_ty } });
            return .unknown_unknown;
        },
    };

    return sema.getUnknownValue(elem_ty);
}

fn zirElemVal(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const array = sema.resolveIndex(extra.lhs);
    const elem_index = sema.resolveIndex(extra.rhs);
    return sema.elemVal(block, src, array, elem_index, src);
}

fn zirElemValNode(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = inst_data.src();
    const elem_index_src: LazySrcLoc = .{ .node_offset_array_access_index = inst_data.src_node };
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const array = sema.resolveIndex(extra.lhs);
    const elem_index = sema.resolveIndex(extra.rhs);
    return sema.elemVal(block, src, array, elem_index, elem_index_src);
}

fn elemVal(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    indexable: Index,
    elem_index_uncasted: Index,
    elem_index_src: LazySrcLoc,
) Allocator.Error!Index {
    const indexable_ty = sema.typeOf(indexable);

    if (indexable_ty == .unknown_type) return .unknown_unknown;
    if (!sema.mod.ip.isIndexable(indexable_ty)) {
        try sema.fail(block, src, .{ .expected_indexable_type = .{ .actual = indexable_ty } });
        return .unknown_unknown;
    }

    const elem_index = try sema.coerce(block, .usize_type, elem_index_uncasted, elem_index_src);
    _ = elem_index;

    return try sema.getUnknownValue(sema.mod.ip.elemType(indexable_ty));
}

fn zirErrorUnionType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const lhs_src: LazySrcLoc = .{ .node_offset_bin_lhs = inst_data.src_node };
    const rhs_src: LazySrcLoc = .{ .node_offset_bin_rhs = inst_data.src_node };
    var error_set = try sema.resolveType(block, lhs_src, extra.lhs);
    const payload = try sema.resolveType(block, rhs_src, extra.rhs);

    if (sema.mod.ip.isUnknown(error_set)) {
        error_set = Index.unknown_type;
    } else if (sema.mod.ip.zigTypeTag(error_set) != .ErrorSet) {
        try sema.fail(block, lhs_src, .{ .expected_tag_type = .{ .expected_tag = .ErrorSet, .actual = error_set } });
        return .unknown_type;
    }

    return try sema.get(.{ .error_union_type = .{
        .error_set_type = error_set,
        .payload_type = payload,
    } });
}

fn zirErrorValue(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].str_tok;
    const name = try sema.mod.ip.string_pool.getOrPutString(sema.gpa, inst_data.get(sema.code));
    _ = block;

    const error_set_type = try sema.get(.{ .error_set_type = .{
        .owner_decl = .none,
        .names = try sema.mod.ip.getStringSlice(sema.mod.gpa, &.{name}),
    } });

    return try sema.get(.{ .error_value = .{
        .ty = error_set_type,
        .error_tag_name = name,
    } });
}

fn lookupIdentifier(sema: *Sema, block: *Block, name: []const u8) Allocator.Error!Decl.OptionalIndex {
    var namespace_index = block.namespace;

    while (namespace_index != .none) {
        const namespace = sema.mod.namespacePtr(namespace_index);
        switch (try sema.lookupInNamespace(block, namespace, name)) {
            .found => |decl_index| return decl_index.toOptional(),
            .unknown => {}, // TODO does this produce false positives?
            .missing => {},
        }
        namespace_index = namespace.parent;
    }
    // TODO lazily analyse symbols in the root scope
    return .none;
    // unreachable; // AstGen detects use of undeclared identifier errors.
}

const LookupResult = union(enum) {
    found: Decl.Index,
    unknown,
    missing,
};

fn lookupInNamespace(
    sema: *Sema,
    block: *Block,
    namespace: *Namespace,
    ident_name: []const u8,
) Allocator.Error!LookupResult {
    const ip = sema.mod.ip;
    _ = block;

    const ident_name_index = ip.string_pool.getString(ident_name) orelse return .missing;
    if (namespace.decls.getKeyAdapted(ident_name_index, Namespace.DeclStringAdapter{ .ip = ip })) |decl_index| {
        return .{ .found = decl_index };
    }

    if (namespace.usingnamespace_set.count() != 0) {
        // TODO support usingnamespace
        return .unknown;
    }

    return .missing;
}

fn zirFieldVal(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = inst_data.src();
    // const field_name_src: LazySrcLoc = .{ .node_offset_field_name = inst_data.src_node };
    const extra = sema.code.extraData(Zir.Inst.Field, inst_data.payload_index).data;
    const field_name = sema.code.nullTerminatedString(extra.field_name_start);
    const object = sema.resolveIndex(extra.lhs);
    return sema.fieldVal(block, src, object, field_name);
}

fn fieldVal(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    object: Index,
    field_name: []const u8,
) Allocator.Error!Index {
    const val = object;
    const ty = sema.typeOf(object);

    const inner_ty = switch (sema.indexToKey(ty)) {
        .pointer_type => |info| if (info.flags.size == .One) info.elem_type else ty,
        else => ty,
    };

    switch (sema.indexToKey(inner_ty)) {
        .simple_type => |simple| switch (simple) {
            .type => {
                if (sema.mod.ip.isUnknown(val)) return .unknown_unknown;

                const namespace_index = sema.mod.ip.getNamespace(val);

                if (namespace_index != .none) {
                    switch (try sema.lookupInNamespace(block, sema.mod.namespacePtr(namespace_index), field_name)) {
                        .found => |decl_index| {
                            const decl = sema.mod.declPtr(decl_index);
                            return decl.index;
                        },
                        .unknown => return .unknown_unknown,
                        .missing => {},
                    }
                }

                switch (sema.indexToKey(val)) {
                    .error_set_type => |error_set_info| blk: {
                        const name_index = sema.mod.ip.string_pool.getString(field_name) orelse break :blk;
                        if (!error_set_info.names.contains(name_index, sema.mod.ip)) break :blk;
                        return try sema.get(.{ .error_value = .{
                            .ty = val,
                            .error_tag_name = name_index,
                        } });
                    },
                    .union_type => return .unknown_unknown, // TODO
                    .enum_type => |enum_index| blk: {
                        const enum_info = sema.mod.ip.getEnum(enum_index);
                        const field_name_index = sema.mod.ip.string_pool.getString(field_name) orelse break :blk;
                        const field = enum_info.fields.get(field_name_index) orelse break :blk;
                        _ = field;
                        return .unknown_unknown; // TODO
                    },
                    else => {},
                }
            },
            .unknown => return .unknown_unknown,
            else => {},
        },
        .pointer_type => |pointer_info| {
            if (pointer_info.flags.size == .Slice) {
                if (std.mem.eql(u8, field_name, "ptr")) {
                    var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                    many_ptr_info.pointer_type.flags.size = .Many;
                    // TODO resolve ptr of Slice
                    return try sema.getUnknownValue(try sema.get(many_ptr_info));
                } else if (std.mem.eql(u8, field_name, "len")) {
                    // TODO resolve length of Slice
                    return try sema.getUnknownValue(.usize_type);
                }
            } else if (sema.indexToKey(pointer_info.elem_type) == .array_type) {
                if (std.mem.eql(u8, field_name, "len")) {
                    // TODO resolve length of Slice
                    return try sema.getUnknownValue(.usize_type);
                }
            }
        },
        .array_type => |array_info| {
            if (std.mem.eql(u8, field_name, "len")) {
                return try sema.get(.{ .int_u64_value = .{
                    .ty = .usize_type,
                    .int = array_info.len,
                } });
            }
        },
        .optional_type => |optional_info| blk: {
            if (!std.mem.eql(u8, field_name, "?")) break :blk;

            if (sema.mod.ip.isNull(val)) {
                try sema.fail(block, src, .{ .invalid_optional_unwrap = .{ .operand = object } });
                return try sema.getUnknownValue(optional_info.payload_type);
            }

            return switch (sema.indexToKey(val)) {
                .optional_value => |optional_val| optional_val.val,
                else => try sema.getUnknownValue(optional_info.payload_type),
            };
        },
        .struct_type => |struct_index| blk: {
            const struct_info = sema.mod.ip.getStructMut(struct_index);
            try sema.resolveTypeFieldsStruct(struct_info);
            const field_name_index = sema.mod.ip.string_pool.getString(field_name) orelse break :blk;
            const field_index = struct_info.fields.getIndex(field_name_index) orelse break :blk;
            const field = struct_info.fields.values()[field_index];

            return switch (sema.indexToKey(val)) {
                .aggregate => |aggregate| aggregate.values.at(@intCast(field_index), sema.mod.ip),
                .undefined_value => try sema.getUndefinedValue(field.ty),
                .unknown_value => try sema.getUnknownValue(field.ty),
                else => unreachable,
            };
        },
        .enum_type => |enum_info| { // TODO
            _ = enum_info;
            return .unknown_unknown;
        },
        .union_type => |union_info| { // TODO
            _ = union_info;
            return .unknown_unknown;
        },
        .int_type,
        .error_union_type,
        .error_set_type,
        .function_type,
        .tuple_type,
        .vector_type,
        .anyframe_type,
        => {},

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

        .optional_value,
        .slice,
        .aggregate,
        .union_value,
        .null_value,
        .error_value,
        .undefined_value,
        => unreachable,

        .unknown_value => return .unknown_unknown,
    }

    try sema.fail(block, src, .{ .unknown_field = .{
        .accessed = val,
        .field_name = field_name,
    } });
    return .unknown_unknown;
}

fn zirFunc(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    inferred_error_set: bool,
) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Func, inst_data.payload_index);
    // const target = sema.mod.getTarget();
    const ret_ty_src: LazySrcLoc = .{ .node_offset_fn_type_ret_ty = inst_data.src_node };

    var extra_index = extra.end;

    const ret_ty: Index = switch (extra.data.ret_body_len) {
        0 => .void_type,
        1 => blk: {
            const ret_ty_ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_index]);
            extra_index += 1;
            break :blk try sema.resolveType(block, ret_ty_src, ret_ty_ref);
        },
        else => blk: {
            const ret_ty_body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra_index..][0..extra.data.ret_body_len]);
            extra_index += ret_ty_body.len;

            const index = try sema.resolveBody(block, ret_ty_body);
            break :blk try sema.coerce(block, .type_type, index, ret_ty_src);
        },
    };

    var src_locs: Zir.Inst.Func.SrcLocs = undefined;
    const has_body = extra.data.body_len != 0;
    if (has_body) {
        const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra_index..][0..extra.data.body_len]);

        var inner_block: Sema.Block = .{
            .parent = null,
            .src_decl = block.src_decl,
            .namespace = block.namespace,
            .is_comptime = false,
        };
        defer inner_block.params.deinit(sema.gpa);
        defer if (inner_block.label) |l| l.merges.deinit(sema.gpa);

        _ = try sema.analyzeBodyInner(&inner_block, body);
        extra_index += body.len;
        src_locs = sema.code.extraData(Zir.Inst.Func.SrcLocs, extra_index).data;
    }

    const args = try sema.arena.alloc(Index, block.params.items.len);
    defer sema.arena.free(args);

    for (block.params.items, args) |param, *out_arg| {
        out_arg.* = param.ty;
    }

    const inferred_return_ty = if (inferred_error_set) try sema.get(.{ .error_union_type = .{
        .error_set_type = .none,
        .payload_type = ret_ty,
    } }) else ret_ty;

    return try sema.get(.{
        .function_type = .{
            .args = try sema.mod.ip.getIndexSlice(sema.mod.gpa, args),
            .return_type = inferred_return_ty,
        },
    });
}

fn zirInt(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const int = sema.code.instructions.items(.data)[@intFromEnum(inst)].int;

    return try sema.get(.{ .int_u64_value = .{
        .ty = .comptime_int_type,
        .int = int,
    } });
}

fn zirFloat(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const number = sema.code.instructions.items(.data)[@intFromEnum(inst)].float;

    return try sema.get(.{ .float_comptime_value = number });
}

fn zirFloat128(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Float128, inst_data.payload_index).data;
    const number = extra.get();

    return try sema.get(.{ .float_comptime_value = number });
}

fn zirIntType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const int_type = sema.code.instructions.items(.data)[@intFromEnum(inst)].int_type;

    return try sema.get(.{ .int_type = .{
        .signedness = int_type.signedness,
        .bits = int_type.bit_count,
    } });
}

fn zirMergeErrorSets(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const src: LazySrcLoc = .{ .node_offset_bin_op = inst_data.src_node };
    _ = src;
    const lhs_src: LazySrcLoc = .{ .node_offset_bin_lhs = inst_data.src_node };
    const rhs_src: LazySrcLoc = .{ .node_offset_bin_rhs = inst_data.src_node };
    const lhs_ty = try sema.resolveType(block, lhs_src, extra.lhs);
    const rhs_ty = try sema.resolveType(block, rhs_src, extra.rhs);

    if (sema.mod.ip.isUnknown(lhs_ty) or sema.mod.ip.isUnknown(rhs_ty)) return Index.unknown_type;

    if (sema.mod.ip.zigTypeTag(lhs_ty) != .ErrorSet) {
        try sema.fail(block, lhs_src, .{ .expected_tag_type = .{ .expected_tag = .ErrorSet, .actual = lhs_ty } });
        return .unknown_unknown;
    } else if (sema.mod.ip.zigTypeTag(rhs_ty) != .ErrorSet) {
        try sema.fail(block, rhs_src, .{ .expected_tag_type = .{ .expected_tag = .ErrorSet, .actual = rhs_ty } });
        return .unknown_unknown;
    }

    return try sema.mod.ip.errorSetMerge(sema.gpa, lhs_ty, rhs_ty);
}

fn zirOptionalPayload(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const src = inst_data.src();
    const operand = sema.resolveIndex(inst_data.operand);
    const operand_ty = sema.typeOf(operand);

    if (operand_ty == .unknown_type) return .unknown_unknown;
    const result_ty = switch (sema.indexToKey(operand_ty)) {
        .optional_type => |optional_info| optional_info.payload_type,
        else => {
            try sema.fail(block, src, .{ .expected_tag_type = .{ .expected_tag = .Optional, .actual = operand_ty } });
            return try sema.getUnknownValue(.unknown_type);
        },
    };

    const operand_key = sema.indexToKey(operand);
    if (operand_key == .optional_value) {
        return operand_key.optional_value.val;
    } else if (sema.mod.ip.isNull(operand) or operand_key == .undefined_value) {
        try sema.fail(block, src, .{ .invalid_optional_unwrap = .{ .operand = operand } });
    } else {
        std.debug.assert(sema.mod.ip.isUnknown(operand));
    }

    return try sema.getUnknownValue(result_ty);
}

fn zirOptionalType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const operand_src: LazySrcLoc = .{ .node_offset_un_op = inst_data.src_node };
    const child_type = try sema.resolveType(block, operand_src, inst_data.operand);

    return try sema.get(.{
        .optional_type = .{ .payload_type = child_type },
    });
}

fn zirRef(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_tok;
    const operand = sema.resolveIndex(inst_data.operand);
    const operand_ty = sema.typeOf(operand);

    const ptr_type = try sema.get(.{
        .pointer_type = .{
            .elem_type = operand_ty,
            .flags = .{
                .size = .One,
                .is_const = false,
                .address_space = .generic, // TODO
            },
        },
    });

    return try sema.getUnknownValue(ptr_type);
}

fn zirPtrType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].ptr_type;
    const extra = sema.code.extraData(Zir.Inst.PtrType, inst_data.payload_index);
    const elem_ty_src: LazySrcLoc = .{ .node_offset_ptr_elem = extra.data.src_node };
    const sentinel_src: LazySrcLoc = .{ .node_offset_ptr_sentinel = extra.data.src_node };
    const align_src: LazySrcLoc = .{ .node_offset_ptr_align = extra.data.src_node };
    // const addrspace_src: LazySrcLoc = .{ .node_offset_ptr_addrspace = extra.data.src_node };
    const bitoffset_src: LazySrcLoc = .{ .node_offset_ptr_bitoffset = extra.data.src_node };
    const hostsize_src: LazySrcLoc = .{ .node_offset_ptr_hostsize = extra.data.src_node };

    const elem_ty = try sema.resolveType(block, elem_ty_src, extra.data.elem_type);

    var extra_i = extra.end;

    const sentinel = if (inst_data.flags.has_sentinel) blk: {
        const ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_i]);
        extra_i += 1;
        break :blk try sema.coerce(block, elem_ty, sema.resolveIndex(ref), sentinel_src);
    } else .none;

    const abi_align: u16 = if (inst_data.flags.has_align) blk: {
        const ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_i]);
        extra_i += 1;
        const coersed = try sema.coerce(block, .u16_type, sema.resolveIndex(ref), align_src);
        break :blk try sema.mod.ip.toInt(coersed, u16) orelse 0;
    } else 0;

    const address_space: std.builtin.AddressSpace = if (inst_data.flags.has_addrspace) blk: {
        const ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_i]);
        extra_i += 1;
        _ = ref;
        // TODO
        break :blk .generic;
    } else .generic;

    const bit_offset: u16 = if (inst_data.flags.has_bit_range) blk: {
        const ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_i]);
        extra_i += 1;
        const coersed = try sema.coerce(block, .u16_type, sema.resolveIndex(ref), bitoffset_src);
        break :blk try sema.mod.ip.toInt(coersed, u16) orelse 0;
    } else 0;

    const host_size: u16 = if (inst_data.flags.has_bit_range) blk: {
        const ref: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_i]);
        extra_i += 1;
        const coersed = try sema.coerce(block, .u16_type, sema.resolveIndex(ref), hostsize_src);
        break :blk try sema.mod.ip.toInt(coersed, u16) orelse 0;
    } else 0;

    return try sema.get(.{ .pointer_type = .{
        .elem_type = elem_ty,
        .sentinel = sentinel,
        .flags = .{
            .size = inst_data.size,
            .alignment = abi_align,
            .is_const = !inst_data.flags.is_mutable,
            .is_volatile = inst_data.flags.is_volatile,
            .is_allowzero = inst_data.flags.is_allowzero,
            .address_space = address_space,
        },
        .packed_offset = .{
            .bit_offset = bit_offset,
            .host_size = host_size,
        },
    } });
}

fn zirSwitchBlock(sema: *Sema, block: *Block, inst: Zir.Inst.Index, operand_is_ref: bool) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    if (operand_is_ref) return .none; // TODO

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const src = inst_data.src();
    // const src_node_offset = inst_data.src_node;
    // const operand_src: LazySrcLoc = .{ .node_offset_switch_operand = src_node_offset };
    // const special_prong_src: LazySrcLoc = .{ .node_offset_switch_special_prong = src_node_offset };
    const extra = sema.code.extraData(Zir.Inst.SwitchBlock, inst_data.payload_index);

    const operand = sema.resolveIndex(extra.data.operand);
    const operand_ty = sema.typeOf(operand);

    var extra_index: usize = extra.end;

    const scalar_cases_len = extra.data.bits.scalar_cases_len;
    const multi_cases_len = if (extra.data.bits.has_multi_cases) blk: {
        const multi_cases_len = sema.code.extra[extra_index];
        extra_index += 1;
        break :blk multi_cases_len;
    } else 0;

    const tag_capture_inst: ?Zir.Inst.Index = if (extra.data.bits.any_has_tag_capture) blk: {
        const tag_capture_inst: Zir.Inst.Index = @enumFromInt(sema.code.extra[extra_index]);
        extra_index += 1;
        break :blk tag_capture_inst;
    } else null;
    _ = tag_capture_inst;

    const Special = struct {
        body: []const Zir.Inst.Index,
        end: usize,
        capture: Zir.Inst.SwitchBlock.ProngInfo.Capture,
        is_inline: bool,
        has_tag_capture: bool,
    };

    const special_prong = extra.data.bits.specialProng();
    const special: Special = switch (special_prong) {
        .none => .{
            .body = &.{},
            .end = extra_index,
            .capture = .none,
            .is_inline = false,
            .has_tag_capture = false,
        },
        .under, .@"else" => blk: {
            const info: Zir.Inst.SwitchBlock.ProngInfo = @bitCast(sema.code.extra[extra_index]);
            const extra_body_start = extra_index + 1;
            break :blk .{
                .body = @ptrCast(sema.code.extra[extra_body_start..][0..info.body_len]),
                .end = extra_body_start + info.body_len,
                .capture = info.capture,
                .is_inline = info.is_inline,
                .has_tag_capture = info.has_tag_capture,
            };
        },
    };
    extra_index = special.end;

    var label: Block.Label = .{
        .zir_block = inst,
        .merges = .{},
    };

    var child_block: Block = .{
        .parent = block,
        .namespace = block.namespace,
        .src_decl = block.src_decl,
        .label = &label,
        .is_comptime = block.is_comptime,
    };
    defer child_block.params.deinit(sema.gpa);
    defer if (child_block.label) |l| l.merges.deinit(sema.gpa);

    var scalar_i: usize = 0;
    while (scalar_i != scalar_cases_len) : (scalar_i += 1) {
        const item: Zir.Inst.Ref = @enumFromInt(sema.code.extra[extra_index]);
        extra_index += 1;
        const info: Zir.Inst.SwitchBlock.ProngInfo = @bitCast(sema.code.extra[extra_index]);
        extra_index += 1;
        const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra_index..][0..info.body_len]);
        extra_index += info.body_len;

        if (child_block.is_comptime and !sema.mod.ip.isUnknown(operand) and !sema.mod.ip.isUnknown(operand_ty)) blk: {
            const item_index = sema.resolveIndex(item);
            const coerceed_item = try sema.coerce(&child_block, operand_ty, item_index, src); // TODO src loc

            if (sema.mod.ip.isUnknown(coerceed_item)) break :blk;
            if (operand != coerceed_item) break :blk;

            return try sema.resolveBody(&child_block, body);
        }

        _ = try sema.analyzeBodyInner(&child_block, body);
    }

    if (multi_cases_len != 0) {
        // TODO
        return .unknown_unknown;
    }

    if (special_prong != .none) {
        if (child_block.is_comptime) {
            return try sema.resolveBody(&child_block, special.body);
        } else {
            _ = try sema.analyzeBodyInner(&child_block, special.body);
        }
    }

    return sema.analyzeBlockBody(block, src, &child_block, &label.merges);
}

fn zirTypeof(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    _ = block;
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const operand = sema.resolveIndex(inst_data.operand);
    return sema.typeOf(operand);
}

fn zirTypeofBuiltin(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const pl_node = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Block, pl_node.payload_index);
    const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.end..][0..extra.data.body_len]);

    const operand = try sema.resolveBody(block, body);
    return sema.typeOf(operand);
}

fn zirStructInitEmpty(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const src = inst_data.src();
    const ty = try sema.resolveType(block, src, inst_data.operand);

    return try sema.getUnknownValue(ty);
}

fn zirStructInit(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    is_ref: bool,
) Allocator.Error!Index {
    _ = is_ref;
    const zir_datas = sema.code.instructions.items(.data);
    const inst_data = zir_datas[@intFromEnum(inst)].pl_node;
    const extra = sema.code.extraData(Zir.Inst.StructInit, inst_data.payload_index);
    const src = inst_data.src();

    const first_item = sema.code.extraData(Zir.Inst.StructInit.Item, extra.end).data;
    const first_field_type_data = zir_datas[@intFromEnum(first_item.field_type)].pl_node;
    const first_field_type_extra = sema.code.extraData(Zir.Inst.FieldType, first_field_type_data.payload_index).data;
    const ty = try sema.resolveType(block, src, first_field_type_extra.container_type);

    return sema.getUnknownValue(ty);
}

fn zirTypeofPeer(
    sema: *Sema,
    block: *Block,
    extended: Zir.Inst.Extended.InstData,
) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const extra = sema.code.extraData(Zir.Inst.TypeOfPeer, extended.operand);
    const body: []const Zir.Inst.Index = @ptrCast(sema.code.extra[extra.data.body_index..][0..extra.data.body_len]);

    _ = try sema.analyzeBodyBreak(block, body);

    const args = sema.code.refSlice(extra.end, extended.small);

    const arg_types = try sema.gpa.alloc(Index, args.len);
    defer sema.gpa.free(arg_types);

    for (args, arg_types) |arg_ref, *ty| {
        const arg = sema.resolveIndex(arg_ref);
        ty.* = sema.typeOf(arg);
    }

    return sema.mod.ip.resolvePeerTypes(sema.gpa, arg_types, builtin.target);
}

fn zirInComptime(
    sema: *Sema,
    block: *Block,
) Allocator.Error!Index {
    _ = sema;
    return if (block.is_comptime) .bool_true else .bool_false;
}

fn zirIntFromBool(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].un_node;
    const operand = sema.resolveIndex(inst_data.operand);

    switch (operand) {
        .bool_false => return .zero_u1,
        .bool_true => return .one_u1,
        else => {},
    }

    return switch (sema.indexToKey(operand)) {
        .undefined_value => try sema.getUndefinedValue(.u1_type),
        .unknown_value => try sema.getUnknownValue(.u1_type),
        else => unreachable,
    };
}

fn zirErrorSetDecl(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    name_strategy: Zir.Inst.NameStrategy,
) Allocator.Error!Index {
    _ = name_strategy;
    _ = block;
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = sema.gpa;
    const inst_data = sema.code.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    // const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.ErrorSetDecl, inst_data.payload_index);

    var names = try gpa.alloc(StringPool.String, extra.data.fields_len);
    defer gpa.free(names);

    var extra_index: u32 = @intCast(extra.end);
    var name_index: usize = 0;
    const extra_index_end = extra_index + (extra.data.fields_len * 2);
    while (extra_index < extra_index_end) : (extra_index += 2) { // +2 to skip over doc_string
        defer name_index += 1;
        const str_index: Zir.NullTerminatedString = @enumFromInt(sema.code.extra[extra_index]);
        const str = sema.code.nullTerminatedString(str_index);
        names[name_index] = try sema.mod.ip.string_pool.getOrPutString(sema.mod.gpa, str);
    }

    return try sema.get(.{
        .error_set_type = .{
            .owner_decl = .none, // TODO
            .names = try sema.mod.ip.getStringSlice(sema.mod.gpa, names),
        },
    });
}

fn zirStructDecl(
    sema: *Sema,
    block: *Block,
    extended: Zir.Inst.Extended.InstData,
    inst: Zir.Inst.Index,
) Allocator.Error!Index {
    const small: Zir.Inst.StructDecl.Small = @bitCast(extended.small);
    const src: LazySrcLoc = if (small.has_src_node) blk: {
        const node_offset: i32 = @bitCast(sema.code.extra[extended.operand]);
        break :blk LazySrcLoc.nodeOffset(node_offset);
    } else sema.src;

    const mod = sema.mod;
    const struct_index = try mod.ip.createStruct(mod.gpa, .{
        .fields = .{},
        .owner_decl = undefined, // set below
        .zir_index = @intFromEnum(inst),
        .namespace = undefined, // set below
        .layout = small.layout,
        .backing_int_ty = .none,
        .status = .none,
    });
    const struct_ty = try mod.get(.{ .struct_type = struct_index });

    const namespace_index = try mod.createNamespace(.{
        .parent = block.namespace,
        .handle = block.getHandle(mod),
        .ty = struct_ty,
    });

    const src_decl = mod.declPtr(block.src_decl);
    const src_node = Module.relativeToNodeIndex(src_decl.*, src.node_offset);
    const decl_index = try mod.allocateNewDecl(namespace_index, src_node);
    const decl = mod.declPtr(decl_index);

    const struct_obj = mod.ip.getStructMut(struct_index);
    struct_obj.owner_decl = decl_index.toOptional();
    struct_obj.namespace = namespace_index;
    // struct_obj.is_tuple = small.is_tuple;

    const ns = mod.namespacePtr(block.namespace);
    try ns.anon_decls.putNoClobber(mod.gpa, decl_index, {});

    decl.name = try sema.resolveAnonymousDeclTypeName(block, decl_index, small.name_strategy, "struct", inst);
    decl.index = struct_ty;
    decl.alignment = 0;
    decl.src_line = src_decl.src_line;

    try sema.analyzeStructDecl(decl, struct_obj);

    return struct_ty;
}

fn resolveAnonymousDeclTypeName(
    sema: *Sema,
    block: *Block,
    new_decl_index: Decl.Index,
    name_strategy: Zir.Inst.NameStrategy,
    anon_prefix: []const u8,
    inst: ?Zir.Inst.Index,
) Allocator.Error!InternPool.String {
    const mod = sema.mod;
    const src_decl = mod.declPtr(block.src_decl);

    switch (name_strategy) {
        .anon => {
            // It would be neat to have "struct:line:column" but this name has
            // to survive incremental updates, where it may have been shifted down
            // or up to a different line, but unchanged, and thus not unnecessarily
            // semantically analyzed.
            // This name is also used as the key in the parent namespace so it cannot be
            // renamed.
            const name = try std.fmt.allocPrint(sema.arena, "{}__{s}_{d}", .{
                src_decl.name.fmt(&sema.mod.ip.string_pool), anon_prefix, @intFromEnum(new_decl_index),
            });
            return try sema.mod.ip.string_pool.getOrPutString(sema.mod.gpa, name);
        },
        .parent => return mod.declPtr(block.src_decl).name,
        .func => {
            return sema.resolveAnonymousDeclTypeName(block, new_decl_index, .anon, anon_prefix, null);
            // TODO
            // const fn_info = sema.code.getFnInfo(sema.func.?.zir_body_inst);
            // const zir_tags = sema.code.instructions.items(.tag);

            // var buf = std.ArrayList(u8).init(sema.gpa);
            // defer buf.deinit();
            // try buf.appendSlice(std.mem.sliceTo(mod.declPtr(block.src_decl).name, 0));
            // try buf.appendSlice("(");

            // var arg_i: usize = 0;
            // for (fn_info.param_body) |zir_inst| {
            //     switch (zir_tags[zir_inst]) {
            //         .param, .param_comptime, .param_anytype, .param_anytype_comptime => {
            //             const arg = sema.inst_map.get(zir_inst).?;
            //             if (arg_i != 0) try buf.appendSlice(",");

            //             try buf.writer().print("{}", .{arg.fmt(mod)});

            //             arg_i += 1;
            //             continue;
            //         },
            //         else => continue,
            //     }
            // }

            // try buf.appendSlice(")");
            // return try buf.toOwnedSlice();
        },
        .dbg_var => {
            const ref = inst.?.toRef();
            const zir_tags = sema.code.instructions.items(.tag);
            const zir_data = sema.code.instructions.items(.data);
            var i = @intFromEnum(inst.?);
            while (i < zir_tags.len) : (i += 1) switch (zir_tags[i]) {
                .dbg_var_ptr, .dbg_var_val => {
                    if (zir_data[i].str_op.operand != ref) continue;

                    const name = try std.fmt.allocPrint(sema.arena, "{}.{s}", .{
                        src_decl.name.fmt(&sema.mod.ip.string_pool), zir_data[i].str_op.getStr(sema.code),
                    });
                    return try sema.mod.ip.string_pool.getOrPutString(sema.mod.gpa, name);
                },
                else => {},
            };
            return sema.resolveAnonymousDeclTypeName(block, new_decl_index, .anon, anon_prefix, null);
        },
    }
}

//
//
//

fn coerce(
    sema: *Sema,
    block: *Block,
    dest_ty: Index,
    inst: Index,
    inst_src: LazySrcLoc,
) Allocator.Error!Index {
    assert(sema.mod.ip.isType(dest_ty));

    var err_msg = ErrorMsg{ .expected_type = .{ .expected = dest_ty, .actual = inst } };
    const result = try sema.mod.ip.coerce(sema.gpa, sema.arena, dest_ty, inst, builtin.target, &err_msg);
    if (result == .none) {
        try sema.fail(block, inst_src, err_msg);
        return sema.getUnknownValue(dest_ty);
    }

    return result;
}

//
//
//

fn ensureDeclAnalyzed(sema: *Sema, decl_index: Decl.Index) Allocator.Error!void {
    const decl = sema.mod.declPtr(decl_index);
    switch (decl.analysis) {
        .unreferenced => {
            try sema.mod.semaDecl(decl_index);
        },
        .in_progress => return, // @panic("TODO: report error")
        .complete => return,
    }
}

pub fn analyzeStructDecl(
    sema: *Sema,
    new_decl: *Decl,
    struct_obj: *InternPool.Struct,
) Allocator.Error!void {
    const extended: Zir.Inst.Extended.InstData = sema.code.instructions.items(.data)[struct_obj.zir_index].extended;
    assert(extended.opcode == .struct_decl);
    const small: Zir.Inst.StructDecl.Small = @bitCast(extended.small);

    // struct_obj.known_non_opv = small.known_non_opv;

    var extra_index: u32 = extended.operand;
    extra_index += @intFromBool(small.has_src_node);
    extra_index += @intFromBool(small.has_fields_len);
    const decls_len = if (small.has_decls_len) blk: {
        const decls_len = sema.code.extra[extra_index];
        extra_index += 1;
        break :blk decls_len;
    } else 0;

    if (small.has_backing_int) {
        const backing_int_body_len = sema.code.extra[extra_index];
        extra_index += 1; // backing_int_body_len
        if (backing_int_body_len == 0) {
            extra_index += 1; // backing_int_ref
        } else {
            extra_index += backing_int_body_len; // backing_int_body_inst
        }
    }

    const namespace = sema.mod.namespacePtr(struct_obj.namespace);
    _ = try sema.scanNamespace(namespace, struct_obj.namespace, extra_index, decls_len, new_decl);
}

pub fn resolveTypeFieldsStruct(sema: *Sema, struct_obj: *InternPool.Struct) Allocator.Error!void {
    switch (struct_obj.status) {
        .none => {},
        .field_types_wip => return, // TODO error
        .have_field_types,
        .have_layout,
        .layout_wip,
        .fully_resolved_wip,
        .fully_resolved,
        => return,
    }

    struct_obj.status = .field_types_wip;
    errdefer struct_obj.status = .none;
    try semaStructFields(sema, struct_obj);
}

fn semaStructFields(sema: *Sema, struct_obj: *InternPool.Struct) Allocator.Error!void {
    const decl_index = struct_obj.owner_decl.unwrap().?;
    const namespace = sema.mod.namespacePtr(struct_obj.namespace);
    const zir = namespace.handle.getCachedZir();
    const extended = zir.instructions.items(.data)[struct_obj.zir_index].extended;
    assert(extended.opcode == .struct_decl);
    const small: Zir.Inst.StructDecl.Small = @bitCast(extended.small);
    var extra_index: usize = extended.operand;

    extra_index += @intFromBool(small.has_src_node);

    const fields_len = if (small.has_fields_len) blk: {
        const fields_len = zir.extra[extra_index];
        extra_index += 1;
        break :blk fields_len;
    } else 0;

    const decls_len = if (small.has_decls_len) decls_len: {
        const decls_len = zir.extra[extra_index];
        extra_index += 1;
        break :decls_len decls_len;
    } else 0;

    // The backing integer cannot be handled until `resolveStructLayout()`.
    if (small.has_backing_int) {
        const backing_int_body_len = zir.extra[extra_index];
        extra_index += 1; // backing_int_body_len
        if (backing_int_body_len == 0) {
            extra_index += 1; // backing_int_ref
        } else {
            extra_index += backing_int_body_len; // backing_int_body_inst
        }
    }

    // Skip over decls.
    var decls_it = zir.declIteratorInner(extra_index, decls_len);
    while (decls_it.next()) |_| {}
    extra_index = decls_it.extra_index;

    if (fields_len == 0) return;

    var block_scope: Block = .{
        .parent = null,
        .namespace = struct_obj.namespace,
        .src_decl = decl_index,
        .is_comptime = true,
    };
    defer block_scope.params.deinit(sema.gpa);
    defer if (block_scope.label) |l| l.merges.deinit(sema.gpa);

    try struct_obj.fields.ensureTotalCapacity(sema.gpa, fields_len);

    const Field = struct {
        type_body_len: u32 = 0,
        align_body_len: u32 = 0,
        init_body_len: u32 = 0,
        type_ref: Zir.Inst.Ref = .none,
    };
    const fields = try sema.arena.alloc(Field, fields_len);

    {
        const bits_per_field = 4;
        const fields_per_u32 = 32 / bits_per_field;
        const bit_bags_count = std.math.divCeil(usize, fields_len, fields_per_u32) catch unreachable;
        const flags_index = extra_index;
        var bit_bag_index: usize = flags_index;
        extra_index += bit_bags_count;
        var cur_bit_bag: u32 = undefined;
        for (fields, 0..) |*field, field_i| {
            if (field_i % fields_per_u32 == 0) {
                cur_bit_bag = zir.extra[bit_bag_index];
                bit_bag_index += 1;
            }
            const has_align = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const has_init = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const is_comptime = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const has_type_body = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;

            var field_name_zir: ?[:0]const u8 = null;
            if (!small.is_tuple) {
                field_name_zir = zir.nullTerminatedString(@enumFromInt(zir.extra[extra_index]));
                extra_index += 1;
            }
            extra_index += 1; // doc_comment

            field.* = .{};

            if (has_type_body) {
                field.type_body_len = zir.extra[extra_index];
            } else {
                field.type_ref = @enumFromInt(zir.extra[extra_index]);
            }
            extra_index += 1;

            const field_name_src = LazySrcLoc{ .container_field = .{ .decl = decl_index, .index = @intCast(field_i), .query = .name } };

            const field_name = try sema.mod.ip.string_pool.getOrPutString(sema.mod.gpa, if (field_name_zir) |s|
                s
            else
                try std.fmt.allocPrint(sema.arena, "{d}", .{field_i}));

            const gop = struct_obj.fields.getOrPutAssumeCapacity(field_name);
            if (gop.found_existing) {
                try sema.fail(&block_scope, field_name_src, .{ .duplicate_struct_field = .{
                    .name = field_name,
                } });
                continue;
            }

            gop.value_ptr.* = .{
                .ty = .noreturn_type,
                // .abi_align = 0,
                .default_value = .none,
                .is_comptime = is_comptime,
            };

            if (has_align) {
                field.align_body_len = zir.extra[extra_index];
                extra_index += 1;
            }
            if (has_init) {
                field.init_body_len = zir.extra[extra_index];
                extra_index += 1;
            }
        }
    }

    // may not match fields_len because of duplicate fields
    const field_count = struct_obj.fields.count();

    for (fields[0..field_count], struct_obj.fields.values(), 0..) |zir_field, *field, field_i| {
        const field_type_src = LazySrcLoc{ .container_field = .{ .decl = decl_index, .index = @intCast(field_i), .query = .type } };
        const field_align_src = LazySrcLoc{ .container_field = .{ .decl = decl_index, .index = @intCast(field_i), .query = .alignment } };

        field.ty = ty: {
            if (zir_field.type_ref != .none) {
                break :ty try sema.resolveType(&block_scope, field_type_src, zir_field.type_ref);
            }
            assert(zir_field.type_body_len != 0);
            const body: []const Zir.Inst.Index = @ptrCast(zir.extra[extra_index..][0..zir_field.type_body_len]);
            extra_index += body.len;
            const index = try sema.resolveBody(&block_scope, body);
            break :ty try sema.coerce(&block_scope, .type_type, index, field_type_src);
        };

        if (zir_field.align_body_len > 0) {
            const body: []const Zir.Inst.Index = @ptrCast(zir.extra[extra_index..][0..zir_field.align_body_len]);
            extra_index += body.len;
            const align_ref = try sema.resolveBody(&block_scope, body);
            const coersed = try sema.coerce(&block_scope, .u16_type, align_ref, field_align_src);
            field.alignment = try sema.mod.ip.toInt(coersed, u16) orelse 0;
        }
        extra_index += zir_field.init_body_len;
    }
    struct_obj.status = .have_field_types;
}

pub fn scanNamespace(
    sema: *Sema,
    namespace: *Namespace,
    namespace_index: InternPool.NamespaceIndex,
    extra_start: u32,
    decls_len: u32,
    parent_decl: *Decl,
) Allocator.Error!usize {
    const zir = namespace.handle.getCachedZir();

    try namespace.decls.ensureTotalCapacityContext(sema.gpa, decls_len, Namespace.DeclContext{
        .ip = sema.mod.ip,
    });

    const bit_bags_count = std.math.divCeil(u32, decls_len, 8) catch unreachable;
    var extra_index = extra_start + bit_bags_count;
    var bit_bag_index: u32 = extra_start;
    var cur_bit_bag: u32 = undefined;
    var decl_i: u32 = 0;
    var scan_decl_iter: ScanDeclIter = .{
        .module = sema.mod,
        .namespace = namespace,
        .namespace_index = namespace_index,
        .parent_decl = parent_decl,
    };
    while (decl_i < decls_len) : (decl_i += 1) {
        if (decl_i % 8 == 0) {
            cur_bit_bag = zir.extra[bit_bag_index];
            bit_bag_index += 1;
        }
        const flags = @as(u4, @truncate(cur_bit_bag));
        cur_bit_bag >>= 4;

        const decl_sub_index = extra_index;
        extra_index += 8; // src_hash(4) + line(1) + name(1) + value(1) + doc_comment(1)
        extra_index += @as(u1, @truncate(flags >> 2)); // Align
        extra_index += @as(u2, @as(u1, @truncate(flags >> 3))) * 2; // Link section or address space, consists of 2 Refs

        try sema.scanDecl(&scan_decl_iter, decl_sub_index, flags);
    }
    return extra_index;
}

const ScanDeclIter = struct {
    module: *Module,
    namespace: *Namespace,
    namespace_index: InternPool.NamespaceIndex,
    parent_decl: *Decl,
    usingnamespace_index: usize = 0,
    comptime_index: usize = 0,
    unnamed_test_index: usize = 0,
};

fn scanDecl(sema: *Sema, iter: *ScanDeclIter, decl_sub_index: u32, flags: u4) Allocator.Error!void {
    const mod = iter.module;
    const namespace = iter.namespace;
    const namespace_index = iter.namespace_index;
    const gpa = mod.gpa;
    const zir = namespace.handle.getCachedZir();

    // zig fmt: off
    const is_pub                       = (flags & 0b0001) != 0;
    const export_bit                   = (flags & 0b0010) != 0;
    const has_align                    = (flags & 0b0100) != 0;
    const has_linksection_or_addrspace = (flags & 0b1000) != 0;
    // zig fmt: on
    _ = has_align;
    _ = has_linksection_or_addrspace;

    const line_off = zir.extra[decl_sub_index + 4];
    const line = iter.parent_decl.src_line + line_off;
    const decl_name_index: Zir.NullTerminatedString = @enumFromInt(zir.extra[decl_sub_index + 5]);
    const decl_doccomment_index: Zir.NullTerminatedString = @enumFromInt(zir.extra[decl_sub_index + 7]);
    const decl_zir_index = zir.extra[decl_sub_index + 6];
    const decl_block_inst_data = zir.instructions.items(.data)[decl_zir_index].pl_node;
    const decl_node = Module.relativeToNodeIndex(iter.parent_decl.*, decl_block_inst_data.src_node);

    // Every Decl needs a name.
    var kind: Decl.Kind = .named;
    const decl_name: []const u8 = switch (decl_name_index) {
        .empty => name: {
            if (export_bit) {
                const i = iter.usingnamespace_index;
                iter.usingnamespace_index += 1;
                kind = .@"usingnamespace";
                break :name try std.fmt.allocPrint(gpa, "usingnamespace_{d}", .{i});
            } else {
                const i = iter.comptime_index;
                iter.comptime_index += 1;
                kind = .@"comptime";
                break :name try std.fmt.allocPrint(gpa, "comptime_{d}", .{i});
            }
        },
        .decltest => name: {
            const i = iter.unnamed_test_index;
            iter.unnamed_test_index += 1;
            kind = .@"test";
            break :name try std.fmt.allocPrint(gpa, "test_{d}", .{i});
        },
        .unnamed_test_decl => name: {
            const test_name = zir.nullTerminatedString(decl_doccomment_index);
            kind = .@"test";
            break :name try std.fmt.allocPrint(gpa, "decltest.{s}", .{test_name});
        },
        else => name: {
            const raw_name = zir.nullTerminatedString(decl_name_index);
            if (raw_name.len == 0) {
                const test_name = zir.nullTerminatedString(@enumFromInt(@intFromEnum(decl_name_index) + 1));
                kind = .@"test";
                break :name try std.fmt.allocPrint(gpa, "test.{s}", .{test_name});
            } else {
                break :name try gpa.dupe(u8, raw_name);
            }
        },
    };
    defer gpa.free(decl_name);

    const is_exported = export_bit and decl_name_index != .empty;
    if (kind == .@"usingnamespace") try namespace.usingnamespace_set.ensureUnusedCapacity(gpa, 1);

    const decl_name_string_index = try mod.ip.string_pool.getOrPutString(gpa, decl_name);

    // We create a Decl for it regardless of analysis status.
    const gop = try namespace.decls.getOrPutContextAdapted(
        gpa,
        decl_name_string_index,
        Namespace.DeclStringAdapter{ .ip = mod.ip },
        Namespace.DeclContext{ .ip = mod.ip },
    );

    if (!gop.found_existing) {
        const new_decl_index = try mod.allocateNewDecl(namespace_index, decl_node);
        const new_decl = mod.declPtr(new_decl_index);
        new_decl.kind = kind;
        new_decl.name = decl_name_string_index;
        if (kind == .@"usingnamespace") {
            namespace.usingnamespace_set.putAssumeCapacity(new_decl_index, is_pub);
        }
        gop.key_ptr.* = new_decl_index;

        new_decl.src_line = line;
        new_decl.is_pub = is_pub;
        new_decl.is_exported = is_exported;
        // new_decl.has_align = has_align;
        // new_decl.has_linksection_or_addrspace = has_linksection_or_addrspace;
        new_decl.zir_decl_index = decl_sub_index;

        try sema.ensureDeclAnalyzed(new_decl_index);
        return;
    }

    const decl_index = gop.key_ptr.*;
    const decl = mod.declPtr(decl_index);

    decl.node_idx = decl_node;
    decl.src_line = line;

    decl.is_pub = is_pub;
    decl.is_exported = is_exported;
    decl.kind = kind;
    // decl.has_align = has_align;
    // decl.has_linksection_or_addrspace = has_linksection_or_addrspace;
    decl.zir_decl_index = decl_sub_index;
}

//
//
//

fn getNullValue(sema: *Sema, ty: Index) Allocator.Error!Index {
    return try sema.mod.ip.getNull(sema.mod.gpa, ty);
}

fn getUndefinedValue(sema: *Sema, ty: Index) Allocator.Error!Index {
    return try sema.mod.ip.getUndefined(sema.mod.gpa, ty);
}

fn getUnknownValue(sema: *Sema, ty: Index) Allocator.Error!Index {
    return try sema.mod.ip.getUnknown(sema.mod.gpa, ty);
}

fn typeOf(sema: *Sema, index: Index) Index {
    return sema.mod.ip.typeOf(index);
}

fn get(sema: *Sema, key: InternPool.Key) Allocator.Error!Index {
    return sema.mod.ip.get(sema.mod.gpa, key);
}

fn indexToKey(sema: *Sema, index: Index) InternPool.Key {
    return sema.mod.ip.indexToKey(index);
}
