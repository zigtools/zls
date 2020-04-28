// SCRIPT
// [...document.querySelector("#toc-Builtin-Functions").parentElement.lastElementChild.children].map(_ => {

// const code = document.querySelector("#" + _.innerText.slice(1)).nextElementSibling.children[0].innerText;
// var l = (code.lastIndexOf(") ") == -1 ? code.length : code.lastIndexOf(") ")) + 1
// var p = code.slice(0, l);

// var name = p.slice(0, p.indexOf("("));
// var body = p.slice(p.indexOf("(") + 1, -1);
// if (body.len === 0) return `${name}()`;
// var nb = "";
// let depth = 0;
// let vi = 2;
// let i = 0;
// let skip = false;
// for (const c of body) {
// if (skip) {
// skip = false;
// if (c === " ") {i++; continue;}
// }
// if (c === "(") depth++;
// else if (c === ")") depth--;

// if (c === "," && depth == 0) {
// nb += `}, \${${vi}:`;
// vi++;
// skip = true;
// } else if (i === body.length - 1) {
// nb += c;
// nb += "}";
// } else nb += c;
// i++;
// }
// return `${name}(\${1:${nb})`;

// }).map(_ => JSON.stringify(_)).join(",\n");

/// Builtin functions
pub const builtins = [_][]const u8{
    "@addWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
    "@alignCast(${1:comptime alignment: u29}, ${2:ptr: var})",
    "@alignOf(${1:comptime T: type})",
    "@as(${1:comptime T: type}, ${2:expression})",
    "@asyncCall(${1:frame_buffer: []align(@alignOf(@Frame(anyAsyncFunction))) u8}, ${2:result_ptr}, ${3:function_ptr}, ${4:args: ...})",
    "@atomicLoad(${1:comptime T: type}, ${2:ptr: *const T}, ${3:comptime ordering: builtin.AtomicOrder})",
    "@atomicRmw(${1:comptime T: type}, ${2:ptr: *T}, ${3:comptime op: builtin.AtomicRmwOp}, ${4:operand: T}, ${5:comptime ordering: builtin.AtomicOrder})",
    "@atomicStore(${1:comptime T: type}, ${2:ptr: *T}, ${3:value: T}, ${4:comptime ordering: builtin.AtomicOrder})",
    "@bitCast(${1:comptime DestType: type}, ${2:value: var})",
    "@bitOffsetOf(${1:comptime T: type}, ${2:comptime field_name: []const u8})",
    "@boolToInt(${1:value: bool})",
    "@bitSizeOf(${1:comptime T: type})",
    "@breakpoint(${1:)",
    "@mulAdd(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:c: T})",
    "@byteSwap(${1:comptime T: type}, ${2:operand: T})",
    "@bitReverse(${1:comptime T: type}, ${2:integer: T})",
    "@byteOffsetOf(${1:comptime T: type}, ${2:comptime field_name: []const u8})",
    "@call(${1:options: std.builtin.CallOptions}, ${2:function: var}, ${3:args: var})",
    "@cDefine(${1:comptime name: []u8}, ${2:value})",
    "@cImport(${1:expression})",
    "@cInclude(${1:comptime path: []u8})",
    "@clz(${1:comptime T: type}, ${2:integer: T})",
    "@cmpxchgStrong(${1:comptime T: type}, ${2:ptr: *T}, ${3:expected_value: T}, ${4:new_value: T}, ${5:success_order: AtomicOrder}, ${6:fail_order: AtomicOrder})",
    "@cmpxchgWeak(${1:comptime T: type}, ${2:ptr: *T}, ${3:expected_value: T}, ${4:new_value: T}, ${5:success_order: AtomicOrder}, ${6:fail_order: AtomicOrder})",
    "@compileError(${1:comptime msg: []u8})",
    "@compileLog(${1:args: ...})",
    "@ctz(${1:comptime T: type}, ${2:integer: T})",
    "@cUndef(${1:comptime name: []u8})",
    "@divExact(${1:numerator: T}, ${2:denominator: T})",
    "@divFloor(${1:numerator: T}, ${2:denominator: T})",
    "@divTrunc(${1:numerator: T}, ${2:denominator: T})",
    "@embedFile(${1:comptime path: []const u8})",
    "@enumToInt(${1:enum_or_tagged_union: var})",
    "@errorName(${1:err: anyerror})",
    "@errorReturnTrace(${1:)",
    "@errorToInt(${1:err: var) std.meta.IntType(false}, ${2:@sizeOf(anyerror})",
    "@errSetCast(${1:comptime T: DestType}, ${2:value: var})",
    "@export(${1:target: var}, ${2:comptime options: std.builtin.ExportOptions})",
    "@fence(${1:order: AtomicOrder})",
    "@field(${1:lhs: var}, ${2:comptime field_name: []const u8})",
    "@fieldParentPtr(${1:comptime ParentType: type}, ${2:comptime field_name: []const u8}, ${3:\n    field_ptr: *T})",
    "@floatCast(${1:comptime DestType: type}, ${2:value: var})",
    "@floatToInt(${1:comptime DestType: type}, ${2:float: var})",
    "@frame(${1:)",
    "@Frame(${1:func: var})",
    "@frameAddress(${1:)",
    "@frameSize(${1:)",
    "@hasDecl(${1:comptime Container: type}, ${2:comptime name: []const u8})",
    "@hasField(${1:comptime Container: type}, ${2:comptime name: []const u8})",
    "@import(${1:comptime path: []u8})",
    "@intCast(${1:comptime DestType: type}, ${2:int: var})",
    "@intToEnum(${1:comptime DestType: type}, ${2:int_value: @TagType(DestType)})",
    "@intToError(${1:value: std.meta.IntType(false, @sizeOf(anyerror) * 8)})",
    "@intToFloat(${1:comptime DestType: type}, ${2:int: var})",
    "@intToPtr(${1:comptime DestType: type}, ${2:address: usize})",
    "@memcpy(${1:noalias dest: [*]u8}, ${2:noalias source: [*]const u8}, ${3:byte_count: usize})",
    "@memset(${1:dest: [*]u8}, ${2:c: u8}, ${3:byte_count: usize})",
    "@mod(${1:numerator: T}, ${2:denominator: T})",
    "@mulWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
    "@OpaqueType(${1:)",
    "@panic(${1:message: []const u8})",
    "@popCount(${1:comptime T: type}, ${2:integer: T})",
    "@ptrCast(${1:comptime DestType: type}, ${2:value: var})",
    "@ptrToInt(${1:value: var})",
    "@rem(${1:numerator: T}, ${2:denominator: T})",
    "@returnAddress(${1:)",
    "@setAlignStack(${1:comptime alignment: u29})",
    "@setCold(${1:is_cold: bool})",
    "@setEvalBranchQuota(${1:new_quota: usize})",
    "@setFloatMode(${1:mode: @import(\"builtin\").FloatMode})",
    "@setRuntimeSafety(${1:safety_on: bool})",
    "@shlExact(${1:value: T}, ${2:shift_amt: Log2T})",
    "@shlWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:shift_amt: Log2T}, ${4:result: *T})",
    "@shrExact(${1:value: T}, ${2:shift_amt: Log2T})",
    "@shuffle(${1:comptime E: type}, ${2:a: @Vector(a_len, E)}, ${3:b: @Vector(b_len, E)}, ${4:comptime mask: @Vector(mask_len, i32)})",
    "@sizeOf(${1:comptime T: type})",
    "@splat(${1:comptime len: u32}, ${2:scalar: var})",
    "@sqrt(${1:value: var})",
    "@sin(${1:value: var})",
    "@cos(${1:value: var})",
    "@exp(${1:value: var})",
    "@exp2(${1:value: var})",
    "@log(${1:value: var})",
    "@log2(${1:value: var})",
    "@log10(${1:value: var})",
    "@fabs(${1:value: var})",
    "@floor(${1:value: var})",
    "@ceil(${1:value: var})",
    "@trunc(${1:value: var})",
    "@round(${1:value: var})",
    "@subWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
    "@tagName(${1:value: var})",
    "@TagType(${1:T: type})",
    "@This(${1:)",
    "@truncate(${1:comptime T: type}, ${2:integer: var})",
    "@Type(${1:comptime info: @import(\"builtin\").TypeInfo})",
    "@typeInfo(${1:comptime T: type})",
    "@typeName(${1:T: type})",
    "@TypeOf(${1:...})",
    "@unionInit(${1:comptime Union: type}, ${2:comptime active_field_name: []const u8}, ${3:init_expr})",
    "@Vector(${1:comptime len: u32}, ${2:comptime ElemType: type})"
};
