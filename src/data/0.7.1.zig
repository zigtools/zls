const Builtin = struct {
    name: []const u8,
    signature: []const u8,
    snippet: []const u8,
    documentation: []const u8,
    arguments: []const []const u8,
};

pub const builtins = [_]Builtin{
    .{
        .name = "@addWithOverflow",
        .signature = "@addWithOverflow(comptime T: type, a: T, b: T, result: *T) bool",
        .snippet = "@addWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
        .documentation = 
        \\ Performs result.* = a + b. If overflow or underflow occurs, stores the overflowed bits in result and returns true. If no overflow or underflow occurs, returns false. 
        ,
        .arguments = &.{
            "comptime T: type",
            "a: T",
            "b: T",
            "result: *T",
        },
    },
    .{
        .name = "@alignCast",
        .signature = "@alignCast(comptime alignment: u29, ptr: anytype) anytype",
        .snippet = "@alignCast(${1:comptime alignment: u29}, ${2:ptr: anytype})",
        .documentation = 
        \\ ptr can be *T, fn(), ?*T, ?fn(), or []T. It returns the same type as ptr except with the alignment adjusted to the new value. 
        \\A pointer alignment safety check is added to the generated code to make sure the pointer is aligned as promised.
        ,
        .arguments = &.{
            "comptime alignment: u29",
            "ptr: anytype",
        },
    },
    .{
        .name = "@alignOf",
        .signature = "@alignOf(comptime T: type) comptime_int",
        .snippet = "@alignOf(${1:comptime T: type})",
        .documentation = 
        \\ This function returns the number of bytes that this type should be aligned to for the current target to match the C ABI. When the child type of a pointer has this alignment, the alignment can be omitted from the type. 
        \\```zig
        \\const expect = @import("std").testing.expect;
        \\comptime {
        \\    expect(*u32 == *align(@alignOf(u32)) u32);
        \\}
        \\```
        \\ The result is a target-specific compile time constant. It is guaranteed to be less than or equal to @sizeOf(T). 
        ,
        .arguments = &.{
            "comptime T: type",
        },
    },
    .{
        .name = "@as",
        .signature = "@as(comptime T: type, expression) T",
        .snippet = "@as(${1:comptime T: type}, ${2:expression})",
        .documentation = 
        \\ Performs Type Coercion. This cast is allowed when the conversion is unambiguous and safe, and is the preferred way to convert between types, whenever possible. 
        ,
        .arguments = &.{
            "comptime T: type",
            "expression",
        },
    },
    .{
        .name = "@asyncCall",
        .signature = "@asyncCall(frame_buffer: []align(@alignOf(@Frame(anyAsyncFunction))) u8, result_ptr, function_ptr, args: anytype) anyframe->T",
        .snippet = "@asyncCall(${1:frame_buffer: []align(@alignOf(@Frame(anyAsyncFunction))) u8}, ${2:result_ptr}, ${3:function_ptr}, ${4:args: anytype})",
        .documentation = 
        \\ @asyncCall performs an async call on a function pointer, which may or may not be an async function. 
        \\ The provided frame_buffer must be large enough to fit the entire function frame. This size can be determined with @frameSize. To provide a too-small buffer invokes safety-checked Undefined Behavior. 
        \\ result_ptr is optional (null may be provided). If provided, the function call will write its result directly to the result pointer, which will be available to read after await completes. Any result location provided to await will copy the result from result_ptr. 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "async fn pointer in a struct field" {
        \\    var data: i32 = 1;
        \\    const Foo = struct {
        \\        bar: fn (*i32) callconv(.Async) void,
        \\    };
        \\    var foo = Foo{ .bar = func };
        \\    var bytes: [64]u8 align(@alignOf(@Frame(func))) = undefined;
        \\    const f = @asyncCall(&bytes, {}, foo.bar, .{&data});
        \\    expect(data == 2);
        \\    resume f;
        \\    expect(data == 4);
        \\}
        \\
        \\fn func(y: *i32) void {
        \\    defer y.* += 2;
        \\    y.* += 1;
        \\    suspend;
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "async fn pointer in a struct field"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "frame_buffer: []align(@alignOf(@Frame(anyAsyncFunction))) u8",
            "result_ptr",
            "function_ptr",
            "args: anytype",
        },
    },
    .{
        .name = "@atomicLoad",
        .signature = "@atomicLoad(comptime T: type, ptr: *const T, comptime ordering: builtin.AtomicOrder) T",
        .snippet = "@atomicLoad(${1:comptime T: type}, ${2:ptr: *const T}, ${3:comptime ordering: builtin.AtomicOrder})",
        .documentation = 
        \\ This builtin function atomically dereferences a pointer and returns the value. 
        \\ T must be a pointer, a bool, a float, an integer or an enum. 
        ,
        .arguments = &.{
            "comptime T: type",
            "ptr: *const T",
            "comptime ordering: builtin.AtomicOrder",
        },
    },
    .{
        .name = "@atomicRmw",
        .signature = "@atomicRmw(comptime T: type, ptr: *T, comptime op: builtin.AtomicRmwOp, operand: T, comptime ordering: builtin.AtomicOrder) T",
        .snippet = "@atomicRmw(${1:comptime T: type}, ${2:ptr: *T}, ${3:comptime op: builtin.AtomicRmwOp}, ${4:operand: T}, ${5:comptime ordering: builtin.AtomicOrder})",
        .documentation = 
        \\ This builtin function atomically modifies memory and then returns the previous value. 
        \\ T must be a pointer, a bool, a float, an integer or an enum. 
        \\ Supported operations: 
        ,
        .arguments = &.{
            "comptime T: type",
            "ptr: *T",
            "comptime op: builtin.AtomicRmwOp",
            "operand: T",
            "comptime ordering: builtin.AtomicOrder",
        },
    },
    .{
        .name = "@atomicStore",
        .signature = "@atomicStore(comptime T: type, ptr: *T, value: T, comptime ordering: builtin.AtomicOrder) void",
        .snippet = "@atomicStore(${1:comptime T: type}, ${2:ptr: *T}, ${3:value: T}, ${4:comptime ordering: builtin.AtomicOrder})",
        .documentation = 
        \\ This builtin function atomically stores a value. 
        \\ T must be a pointer, a bool, a float, an integer or an enum. 
        ,
        .arguments = &.{
            "comptime T: type",
            "ptr: *T",
            "value: T",
            "comptime ordering: builtin.AtomicOrder",
        },
    },
    .{
        .name = "@bitCast",
        .signature = "@bitCast(comptime DestType: type, value: anytype) DestType",
        .snippet = "@bitCast(${1:comptime DestType: type}, ${2:value: anytype})",
        .documentation = 
        \\ Converts a value of one type to another type. 
        \\ Asserts that @sizeOf(@TypeOf(value)) == @sizeOf(DestType). 
        \\ Asserts that @typeInfo(DestType) != .Pointer. Use @ptrCast or @intToPtr if you need this. 
        \\ Can be used for these things for example: 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "value: anytype",
        },
    },
    .{
        .name = "@bitOffsetOf",
        .signature = "@bitOffsetOf(comptime T: type, comptime field_name: []const u8) comptime_int",
        .snippet = "@bitOffsetOf(${1:comptime T: type}, ${2:comptime field_name: []const u8})",
        .documentation = 
        \\ Returns the bit offset of a field relative to its containing struct. 
        \\ For non packed structs, this will always be divisible by 8. For packed structs, non-byte-aligned fields will share a byte offset, but they will have different bit offsets. 
        ,
        .arguments = &.{
            "comptime T: type",
            "comptime field_name: []const u8",
        },
    },
    .{
        .name = "@boolToInt",
        .signature = "@boolToInt(value: bool) u1",
        .snippet = "@boolToInt(${1:value: bool})",
        .documentation = 
        \\ Converts true to u1(1) and false to u1(0). 
        \\ If the value is known at compile-time, the return type is comptime_int instead of u1. 
        ,
        .arguments = &.{
            "value: bool",
        },
    },
    .{
        .name = "@bitSizeOf",
        .signature = "@bitSizeOf(comptime T: type) comptime_int",
        .snippet = "@bitSizeOf(${1:comptime T: type})",
        .documentation = 
        \\ This function returns the number of bits it takes to store T in memory. The result is a target-specific compile time constant. 
        \\ This function measures the size at runtime. For types that are disallowed at runtime, such as comptime_int and type, the result is 0. 
        ,
        .arguments = &.{
            "comptime T: type",
        },
    },
    .{
        .name = "@breakpoint",
        .signature = "@breakpoint()",
        .snippet = "@breakpoint()",
        .documentation = 
        \\ This function inserts a platform-specific debug trap instruction which causes debuggers to break there. 
        \\ This function is only valid within function scope. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@mulAdd",
        .signature = "@mulAdd(comptime T: type, a: T, b: T, c: T) T",
        .snippet = "@mulAdd(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:c: T})",
        .documentation = 
        \\ Fused multiply add, similar to (a * b) + c, except only rounds once, and is thus more accurate. 
        \\ Supports Floats and Vectors of floats. 
        ,
        .arguments = &.{
            "comptime T: type",
            "a: T",
            "b: T",
            "c: T",
        },
    },
    .{
        .name = "@byteSwap",
        .signature = "@byteSwap(comptime T: type, operand: T) T",
        .snippet = "@byteSwap(${1:comptime T: type}, ${2:operand: T})",
        .documentation = 
        \\T must be an integer type with bit count evenly divisible by 8.
        \\operand may be an integer or vector.
        \\ Swaps the byte order of the integer. This converts a big endian integer to a little endian integer, and converts a little endian integer to a big endian integer. 
        \\ Note that for the purposes of memory layout with respect to endianness, the integer type should be related to the number of bytes reported by @sizeOf bytes. This is demonstrated with u24. @sizeOf(u24) == 4, which means that a u24 stored in memory takes 4 bytes, and those 4 bytes are what are swapped on a little vs big endian system. On the other hand, if T is specified to be u24, then only 3 bytes are reversed. 
        ,
        .arguments = &.{
            "comptime T: type",
            "operand: T",
        },
    },
    .{
        .name = "@bitReverse",
        .signature = "@bitReverse(comptime T: type, integer: T) T",
        .snippet = "@bitReverse(${1:comptime T: type}, ${2:integer: T})",
        .documentation = 
        \\T accepts any integer type.
        \\ Reverses the bitpattern of an integer value, including the sign bit if applicable. 
        \\ For example 0b10110110 (u8 = 182, i8 = -74) becomes 0b01101101 (u8 = 109, i8 = 109). 
        ,
        .arguments = &.{
            "comptime T: type",
            "integer: T",
        },
    },
    .{
        .name = "@byteOffsetOf",
        .signature = "@byteOffsetOf(comptime T: type, comptime field_name: []const u8) comptime_int",
        .snippet = "@byteOffsetOf(${1:comptime T: type}, ${2:comptime field_name: []const u8})",
        .documentation = 
        \\ Returns the byte offset of a field relative to its containing struct. 
        ,
        .arguments = &.{
            "comptime T: type",
            "comptime field_name: []const u8",
        },
    },
    .{
        .name = "@call",
        .signature = "@call(options: std.builtin.CallOptions, function: anytype, args: anytype) anytype",
        .snippet = "@call(${1:options: std.builtin.CallOptions}, ${2:function: anytype}, ${3:args: anytype})",
        .documentation = 
        \\ Calls a function, in the same way that invoking an expression with parentheses does: 
        \\call.zig
        \\```zig
        \\const expect = @import("std").testing.expect;
        \\
        \\test "noinline function call" {
        \\    expect(@call(.{}, add, .{3, 9}) == 12);
        \\}
        \\
        \\fn add(a: i32, b: i32) i32 {
        \\    return a + b;
        \\}
        \\```
        \\```zig
        \\$ zig test call.zig
        \\1/1 test "noinline function call"... OK
        \\All 1 tests passed.
        \\
        \\```
        \\ @call allows more flexibility than normal function call syntax does. The CallOptions struct is reproduced here: 
        \\```zig
        \\pub const CallOptions = struct {
        \\    modifier: Modifier = .auto,
        \\    stack: ?[]align(std.Target.stack_align) u8 = null,
        \\
        \\    pub const Modifier = enum {
        \\        /// Equivalent to function call syntax.
        \\        auto,
        \\
        \\        /// Equivalent to async keyword used with function call syntax.
        \\        async_kw,
        \\
        \\        /// Prevents tail call optimization. This guarantees that the return
        \\        /// address will point to the callsite, as opposed to the callsite's
        \\        /// callsite. If the call is otherwise required to be tail-called
        \\        /// or inlined, a compile error is emitted instead.
        \\        never_tail,
        \\
        \\        /// Guarantees that the call will not be inlined. If the call is
        \\        /// otherwise required to be inlined, a compile error is emitted instead.
        \\        never_inline,
        \\
        \\        /// Asserts that the function call will not suspend. This allows a
        \\        /// non-async function to call an async function.
        \\        no_async,
        \\
        \\        /// Guarantees that the call will be generated with tail call optimization.
        \\        /// If this is not possible, a compile error is emitted instead.
        \\        always_tail,
        \\
        \\        /// Guarantees that the call will inlined at the callsite.
        \\        /// If this is not possible, a compile error is emitted instead.
        \\        always_inline,
        \\
        \\        /// Evaluates the call at compile-time. If the call cannot be completed at
        \\        /// compile-time, a compile error is emitted instead.
        \\        compile_time,
        \\    };
        \\};
        \\```
        ,
        .arguments = &.{
            "options: std.builtin.CallOptions",
            "function: anytype",
            "args: anytype",
        },
    },
    .{
        .name = "@cDefine",
        .signature = "@cDefine(comptime name: []u8, value)",
        .snippet = "@cDefine(${1:comptime name: []u8}, ${2:value})",
        .documentation = 
        \\ This function can only occur inside @cImport. 
        \\ This appends #define $name $value to the @cImport temporary buffer. 
        \\ To define without a value, like this: 
        \\```zig
        \\#define _GNU_SOURCE
        \\```
        \\ Use the void value, like this: 
        \\```zig
        \\@cDefine("_GNU_SOURCE", {})
        \\```
        ,
        .arguments = &.{
            "comptime name: []u8",
            "value",
        },
    },
    .{
        .name = "@cImport",
        .signature = "@cImport(expression) type",
        .snippet = "@cImport(${1:expression})",
        .documentation = 
        \\ This function parses C code and imports the functions, types, variables, and compatible macro definitions into a new empty struct type, and then returns that type. 
        \\ expression is interpreted at compile time. The builtin functions @cInclude, @cDefine, and @cUndef work within this expression, appending to a temporary buffer which is then parsed as C code. 
        \\ Usually you should only have one @cImport in your entire application, because it saves the compiler from invoking clang multiple times, and prevents inline functions from being duplicated. 
        \\ Reasons for having multiple @cImport expressions would be: 
        ,
        .arguments = &.{
            "expression",
        },
    },
    .{
        .name = "@cInclude",
        .signature = "@cInclude(comptime path: []u8)",
        .snippet = "@cInclude(${1:comptime path: []u8})",
        .documentation = 
        \\ This function can only occur inside @cImport. 
        \\ This appends #include <$path>\n to the c_import temporary buffer. 
        ,
        .arguments = &.{
            "comptime path: []u8",
        },
    },
    .{
        .name = "@clz",
        .signature = "@clz(comptime T: type, integer: T)",
        .snippet = "@clz(${1:comptime T: type}, ${2:integer: T})",
        .documentation = 
        \\ This function counts the number of most-significant (leading in a big-Endian sense) zeroes in integer. 
        \\ If integer is known at comptime, the return type is comptime_int. Otherwise, the return type is an unsigned integer with the minimum number of bits that can represent the bit count of the integer type. 
        \\ If integer is zero, @clz returns the bit width of integer type T. 
        ,
        .arguments = &.{
            "comptime T: type",
            "integer: T",
        },
    },
    .{
        .name = "@cmpxchgStrong",
        .signature = "@cmpxchgStrong(comptime T: type, ptr: *T, expected_value: T, new_value: T, success_order: AtomicOrder, fail_order: AtomicOrder) ?T",
        .snippet = "@cmpxchgStrong(${1:comptime T: type}, ${2:ptr: *T}, ${3:expected_value: T}, ${4:new_value: T}, ${5:success_order: AtomicOrder}, ${6:fail_order: AtomicOrder})",
        .documentation = 
        \\ This function performs a strong atomic compare exchange operation. It's the equivalent of this code, except atomic: 
        \\```zig
        \\fn cmpxchgStrongButNotAtomic(comptime T: type, ptr: *T, expected_value: T, new_value: T) ?T {
        \\    const old_value = ptr.*;
        \\    if (old_value == expected_value) {
        \\        ptr.* = new_value;
        \\        return null;
        \\    } else {
        \\        return old_value;
        \\    }
        \\}
        \\```
        \\ If you are using cmpxchg in a loop, @cmpxchgWeak is the better choice, because it can be implemented more efficiently in machine instructions. 
        \\ T must be a pointer, a bool, a float, an integer or an enum. 
        \\@typeInfo(@TypeOf(ptr)).Pointer.alignment must be >= @sizeOf(T).
        ,
        .arguments = &.{
            "comptime T: type",
            "ptr: *T",
            "expected_value: T",
            "new_value: T",
            "success_order: AtomicOrder",
            "fail_order: AtomicOrder",
        },
    },
    .{
        .name = "@cmpxchgWeak",
        .signature = "@cmpxchgWeak(comptime T: type, ptr: *T, expected_value: T, new_value: T, success_order: AtomicOrder, fail_order: AtomicOrder) ?T",
        .snippet = "@cmpxchgWeak(${1:comptime T: type}, ${2:ptr: *T}, ${3:expected_value: T}, ${4:new_value: T}, ${5:success_order: AtomicOrder}, ${6:fail_order: AtomicOrder})",
        .documentation = 
        \\ This function performs a weak atomic compare exchange operation. It's the equivalent of this code, except atomic: 
        \\```zig
        \\fn cmpxchgWeakButNotAtomic(comptime T: type, ptr: *T, expected_value: T, new_value: T) ?T {
        \\    const old_value = ptr.*;
        \\    if (old_value == expected_value and usuallyTrueButSometimesFalse()) {
        \\        ptr.* = new_value;
        \\        return null;
        \\    } else {
        \\        return old_value;
        \\    }
        \\}
        \\```
        \\ If you are using cmpxchg in a loop, the sporadic failure will be no problem, and cmpxchgWeak is the better choice, because it can be implemented more efficiently in machine instructions. However if you need a stronger guarantee, use @cmpxchgStrong. 
        \\ T must be a pointer, a bool, a float, an integer or an enum. 
        \\@typeInfo(@TypeOf(ptr)).Pointer.alignment must be >= @sizeOf(T).
        ,
        .arguments = &.{
            "comptime T: type",
            "ptr: *T",
            "expected_value: T",
            "new_value: T",
            "success_order: AtomicOrder",
            "fail_order: AtomicOrder",
        },
    },
    .{
        .name = "@compileError",
        .signature = "@compileError(comptime msg: []u8)",
        .snippet = "@compileError(${1:comptime msg: []u8})",
        .documentation = 
        \\ This function, when semantically analyzed, causes a compile error with the message msg. 
        \\ There are several ways that code avoids being semantically checked, such as using if or switch with compile time constants, and comptime functions. 
        ,
        .arguments = &.{
            "comptime msg: []u8",
        },
    },
    .{
        .name = "@compileLog",
        .signature = "@compileLog(args: ...)",
        .snippet = "@compileLog(${1:args: ...})",
        .documentation = 
        \\ This function prints the arguments passed to it at compile-time. 
        \\ To prevent accidentally leaving compile log statements in a codebase, a compilation error is added to the build, pointing to the compile log statement. This error prevents code from being generated, but does not otherwise interfere with analysis. 
        \\ This function can be used to do "printf debugging" on compile-time executing code. 
        \\test.zig
        \\```zig
        \\const print = @import("std").debug.print;
        \\
        \\const num1 = blk: {
        \\    var val1: i32 = 99;
        \\    @compileLog("comptime val1 = ", val1);
        \\    val1 = val1 + 1;
        \\    break :blk val1;
        \\};
        \\
        \\test "main" {
        \\    @compileLog("comptime in main");
        \\
        \\    print("Runtime in main, num1 = {}.\n", .{num1});
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\| *"comptime in main"
        \\| *"comptime val1 = ", 99
        \\./docgen_tmp/test.zig:11:5: error: found compile log statement
        \\    @compileLog("comptime in main");
        \\    ^
        \\./docgen_tmp/test.zig:1:35: note: referenced here
        \\const print = @import("std").debug.print;
        \\                                  ^
        \\./docgen_tmp/test.zig:13:5: note: referenced here
        \\    print("Runtime in main, num1 = {}.\n", .{num1});
        \\    ^
        \\./docgen_tmp/test.zig:5:5: error: found compile log statement
        \\    @compileLog("comptime val1 = ", val1);
        \\    ^
        \\./docgen_tmp/test.zig:13:46: note: referenced here
        \\    print("Runtime in main, num1 = {}.\n", .{num1});
        \\                                             ^
        \\
        \\```
        \\ will ouput: 
        \\ If all @compileLog calls are removed or not encountered by analysis, the program compiles successfully and the generated executable prints: 
        \\test.zig
        \\```zig
        \\const print = @import("std").debug.print;
        \\
        \\const num1 = blk: {
        \\    var val1: i32 = 99;
        \\    val1 = val1 + 1;
        \\    break :blk val1;
        \\};
        \\
        \\test "main" {
        \\    print("Runtime in main, num1 = {}.\n", .{num1});
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "main"... Runtime in main, num1 = 100.
        \\OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "args: ...",
        },
    },
    .{
        .name = "@ctz",
        .signature = "@ctz(comptime T: type, integer: T)",
        .snippet = "@ctz(${1:comptime T: type}, ${2:integer: T})",
        .documentation = 
        \\ This function counts the number of least-significant (trailing in a big-Endian sense) zeroes in integer. 
        \\ If integer is known at comptime, the return type is comptime_int. Otherwise, the return type is an unsigned integer with the minimum number of bits that can represent the bit count of the integer type. 
        \\ If integer is zero, @ctz returns the bit width of integer type T. 
        ,
        .arguments = &.{
            "comptime T: type",
            "integer: T",
        },
    },
    .{
        .name = "@cUndef",
        .signature = "@cUndef(comptime name: []u8)",
        .snippet = "@cUndef(${1:comptime name: []u8})",
        .documentation = 
        \\ This function can only occur inside @cImport. 
        \\ This appends #undef $name to the @cImport temporary buffer. 
        ,
        .arguments = &.{
            "comptime name: []u8",
        },
    },
    .{
        .name = "@divExact",
        .signature = "@divExact(numerator: T, denominator: T) T",
        .snippet = "@divExact(${1:numerator: T}, ${2:denominator: T})",
        .documentation = 
        \\ Exact division. Caller guarantees denominator != 0 and @divTrunc(numerator, denominator) * denominator == numerator. 
        ,
        .arguments = &.{
            "numerator: T",
            "denominator: T",
        },
    },
    .{
        .name = "@divFloor",
        .signature = "@divFloor(numerator: T, denominator: T) T",
        .snippet = "@divFloor(${1:numerator: T}, ${2:denominator: T})",
        .documentation = 
        \\ Floored division. Rounds toward negative infinity. For unsigned integers it is the same as numerator / denominator. Caller guarantees denominator != 0 and !(@typeInfo(T) == .Int and T.is_signed and numerator == std.math.minInt(T) and denominator == -1). 
        ,
        .arguments = &.{
            "numerator: T",
            "denominator: T",
        },
    },
    .{
        .name = "@divTrunc",
        .signature = "@divTrunc(numerator: T, denominator: T) T",
        .snippet = "@divTrunc(${1:numerator: T}, ${2:denominator: T})",
        .documentation = 
        \\ Truncated division. Rounds toward zero. For unsigned integers it is the same as numerator / denominator. Caller guarantees denominator != 0 and !(@typeInfo(T) == .Int and T.is_signed and numerator == std.math.minInt(T) and denominator == -1). 
        ,
        .arguments = &.{
            "numerator: T",
            "denominator: T",
        },
    },
    .{
        .name = "@embedFile",
        .signature = "@embedFile(comptime path: []const u8) *const [X:0]u8",
        .snippet = "@embedFile(${1:comptime path: []const u8})",
        .documentation = 
        \\ This function returns a compile time constant pointer to null-terminated, fixed-size array with length equal to the byte count of the file given by path. The contents of the array are the contents of the file. This is equivalent to a string literal with the file contents. 
        \\ path is absolute or relative to the current file, just like @import. 
        ,
        .arguments = &.{
            "comptime path: []const u8",
        },
    },
    .{
        .name = "@enumToInt",
        .signature = "@enumToInt(enum_or_tagged_union: anytype) anytype",
        .snippet = "@enumToInt(${1:enum_or_tagged_union: anytype})",
        .documentation = 
        \\ Converts an enumeration value into its integer tag type. When a tagged union is passed, the tag value is used as the enumeration value. 
        \\ If there is only one possible enum value, the resut is a comptime_int known at comptime. 
        ,
        .arguments = &.{
            "enum_or_tagged_union: anytype",
        },
    },
    .{
        .name = "@errorName",
        .signature = "@errorName(err: anyerror) []const u8",
        .snippet = "@errorName(${1:err: anyerror})",
        .documentation = 
        \\ This function returns the string representation of an error. The string representation of error.OutOfMem is "OutOfMem". 
        \\ If there are no calls to @errorName in an entire application, or all calls have a compile-time known value for err, then no error name table will be generated. 
        ,
        .arguments = &.{
            "err: anyerror",
        },
    },
    .{
        .name = "@errorReturnTrace",
        .signature = "@errorReturnTrace() ?*builtin.StackTrace",
        .snippet = "@errorReturnTrace()",
        .documentation = 
        \\ If the binary is built with error return tracing, and this function is invoked in a function that calls a function with an error or error union return type, returns a stack trace object. Otherwise returns null. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@errorToInt",
        .signature = "@errorToInt(err: anytype) std.meta.IntType(false, @sizeOf(anyerror) * 8)",
        .snippet = "@errorToInt(${1:err: anytype})",
        .documentation = 
        \\ Supports the following types: 
        ,
        .arguments = &.{
            "err: anytype",
        },
    },
    .{
        .name = "@errSetCast",
        .signature = "@errSetCast(comptime T: DestType, value: anytype) DestType",
        .snippet = "@errSetCast(${1:comptime T: DestType}, ${2:value: anytype})",
        .documentation = 
        \\ Converts an error value from one error set to another error set. Attempting to convert an error which is not in the destination error set results in safety-protected Undefined Behavior. 
        ,
        .arguments = &.{
            "comptime T: DestType",
            "value: anytype",
        },
    },
    .{
        .name = "@export",
        .signature = "@export(target: anytype, comptime options: std.builtin.ExportOptions) void",
        .snippet = "@export(${1:target: anytype}, ${2:comptime options: std.builtin.ExportOptions})",
        .documentation = 
        \\ Creates a symbol in the output object file. 
        \\ This function can be called from a comptime block to conditionally export symbols. When target is a function with the C calling convention and options.linkage is Strong, this is equivalent to the export keyword used on a function: 
        \\test.zig
        \\```zig
        \\comptime {
        \\    @export(internalName, .{ .name = "foo", .linkage = .Strong });
        \\}
        \\
        \\fn internalName() callconv(.C) void {}
        \\```
        \\```zig
        \\$ zig build-obj test.zig
        \\```
        \\This is equivalent to:
        \\test.zig
        \\```zig
        \\export fn foo() void {}
        \\```
        \\```zig
        \\$ zig build-obj test.zig
        \\```
        \\Note that even when using export, @"foo" syntax can be used to choose any string for the symbol name:
        \\test.zig
        \\```zig
        \\export fn @"A function name that is a complete sentence."() void {}
        \\```
        \\```zig
        \\$ zig build-obj test.zig
        \\```
        \\ When looking at the resulting object, you can see the symbol is used verbatim: 
        \\```zig
        \\00000000000001f0 T A function name that is a complete sentence.
        \\```
        ,
        .arguments = &.{
            "target: anytype",
            "comptime options: std.builtin.ExportOptions",
        },
    },
    .{
        .name = "@fence",
        .signature = "@fence(order: AtomicOrder)",
        .snippet = "@fence(${1:order: AtomicOrder})",
        .documentation = 
        \\ The fence function is used to introduce happens-before edges between operations. 
        \\ AtomicOrder can be found with @import("builtin").AtomicOrder. 
        ,
        .arguments = &.{
            "order: AtomicOrder",
        },
    },
    .{
        .name = "@field",
        .signature = "@field(lhs: anytype, comptime field_name: []const u8) (field)",
        .snippet = "@field(${1:lhs: anytype}, ${2:comptime field_name: []const u8})",
        .documentation = 
        \\Performs field access by a compile-time string. 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\
        \\const Point = struct {
        \\    x: u32,
        \\    y: u32
        \\};
        \\
        \\test "field access by string" {
        \\    const expect = std.testing.expect;
        \\    var p = Point {.x = 0, .y = 0};
        \\
        \\    @field(p, "x") = 4;
        \\    @field(p, "y") = @field(p, "x") + 1;
        \\
        \\    expect(@field(p, "x") == 4);
        \\    expect(@field(p, "y") == 5);
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "field access by string"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "lhs: anytype",
            "comptime field_name: []const u8",
        },
    },
    .{
        .name = "@fieldParentPtr",
        .signature = "@fieldParentPtr(comptime ParentType: type, comptime field_name: []const u8,    field_ptr: *T) *ParentType",
        .snippet = "@fieldParentPtr(${1:comptime ParentType: type}, ${2:comptime field_name: []const u8}, ${3:field_ptr: *T})",
        .documentation = 
        \\ Given a pointer to a field, returns the base pointer of a struct. 
        ,
        .arguments = &.{
            "comptime ParentType: type",
            "comptime field_name: []const u8",
            "field_ptr: *T",
        },
    },
    .{
        .name = "@floatCast",
        .signature = "@floatCast(comptime DestType: type, value: anytype) DestType",
        .snippet = "@floatCast(${1:comptime DestType: type}, ${2:value: anytype})",
        .documentation = 
        \\ Convert from one float type to another. This cast is safe, but may cause the numeric value to lose precision. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "value: anytype",
        },
    },
    .{
        .name = "@floatToInt",
        .signature = "@floatToInt(comptime DestType: type, float: anytype) DestType",
        .snippet = "@floatToInt(${1:comptime DestType: type}, ${2:float: anytype})",
        .documentation = 
        \\ Converts the integer part of a floating point number to the destination type. 
        \\ If the integer part of the floating point number cannot fit in the destination type, it invokes safety-checked Undefined Behavior. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "float: anytype",
        },
    },
    .{
        .name = "@frame",
        .signature = "@frame() *@Frame(func)",
        .snippet = "@frame()",
        .documentation = 
        \\ This function returns a pointer to the frame for a given function. This type can be coerced to anyframe->T and to anyframe, where T is the return type of the function in scope. 
        \\ This function does not mark a suspension point, but it does cause the function in scope to become an async function. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@Frame",
        .signature = "@Frame(func: anytype) type",
        .snippet = "@Frame(${1:func: anytype})",
        .documentation = 
        \\ This function returns the frame type of a function. This works for Async Functions as well as any function without a specific calling convention. 
        \\ This type is suitable to be used as the return type of async which allows one to, for example, heap-allocate an async function frame: 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\
        \\test "heap allocated frame" {
        \\    const frame = try std.heap.page_allocator.create(@Frame(func));
        \\    frame.* = async func();
        \\}
        \\
        \\fn func() void {
        \\    suspend;
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "heap allocated frame"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "func: anytype",
        },
    },
    .{
        .name = "@frameAddress",
        .signature = "@frameAddress() usize",
        .snippet = "@frameAddress()",
        .documentation = 
        \\ This function returns the base pointer of the current stack frame. 
        \\ The implications of this are target specific and not consistent across all platforms. The frame address may not be available in release mode due to aggressive optimizations. 
        \\ This function is only valid within function scope. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@frameSize",
        .signature = "@frameSize() usize",
        .snippet = "@frameSize()",
        .documentation = 
        \\ This is the same as @sizeOf(@Frame(func)), where func may be runtime-known. 
        \\ This function is typically used in conjunction with @asyncCall. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@hasDecl",
        .signature = "@hasDecl(comptime Container: type, comptime name: []const u8) bool",
        .snippet = "@hasDecl(${1:comptime Container: type}, ${2:comptime name: []const u8})",
        .documentation = 
        \\ Returns whether or not a struct, enum, or union has a declaration matching name. 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\const Foo = struct {
        \\    nope: i32,
        \\
        \\    pub var blah = "xxx";
        \\    const hi = 1;
        \\};
        \\
        \\test "@hasDecl" {
        \\    expect(@hasDecl(Foo, "blah"));
        \\
        \\    // Even though `hi` is private, @hasDecl returns true because this test is
        \\    // in the same file scope as Foo. It would return false if Foo was declared
        \\    // in a different file.
        \\    expect(@hasDecl(Foo, "hi"));
        \\
        \\    // @hasDecl is for declarations; not fields.
        \\    expect(!@hasDecl(Foo, "nope"));
        \\    expect(!@hasDecl(Foo, "nope1234"));
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "@hasDecl"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "comptime Container: type",
            "comptime name: []const u8",
        },
    },
    .{
        .name = "@hasField",
        .signature = "@hasField(comptime Container: type, comptime name: []const u8) bool",
        .snippet = "@hasField(${1:comptime Container: type}, ${2:comptime name: []const u8})",
        .documentation = 
        \\Returns whether the field name of a struct, union, or enum exists.
        \\ The result is a compile time constant. 
        \\ It does not include functions, variables, or constants. 
        ,
        .arguments = &.{
            "comptime Container: type",
            "comptime name: []const u8",
        },
    },
    .{
        .name = "@import",
        .signature = "@import(comptime path: []u8) type",
        .snippet = "@import(${1:comptime path: []u8})",
        .documentation = 
        \\ This function finds a zig file corresponding to path and adds it to the build, if it is not already added. 
        \\ Zig source files are implicitly structs, with a name equal to the file's basename with the extension truncated. @import returns the struct type corresponding to the file. 
        \\ Declarations which have the pub keyword may be referenced from a different source file than the one they are declared in. 
        \\ path can be a relative path or it can be the name of a package. If it is a relative path, it is relative to the file that contains the @import function call. 
        \\ The following packages are always available: 
        ,
        .arguments = &.{
            "comptime path: []u8",
        },
    },
    .{
        .name = "@intCast",
        .signature = "@intCast(comptime DestType: type, int: anytype) DestType",
        .snippet = "@intCast(${1:comptime DestType: type}, ${2:int: anytype})",
        .documentation = 
        \\ Converts an integer to another integer while keeping the same numerical value. Attempting to convert a number which is out of range of the destination type results in safety-protected Undefined Behavior. 
        \\ If T is comptime_int, then this is semantically equivalent to Type Coercion. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "int: anytype",
        },
    },
    .{
        .name = "@intToEnum",
        .signature = "@intToEnum(comptime DestType: type, int_value: @TagType(DestType)) DestType",
        .snippet = "@intToEnum(${1:comptime DestType: type}, ${2:int_value: @TagType(DestType)})",
        .documentation = 
        \\ Converts an integer into an enum value. 
        \\ Attempting to convert an integer which represents no value in the chosen enum type invokes safety-checked Undefined Behavior. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "int_value: @TagType(DestType)",
        },
    },
    .{
        .name = "@intToError",
        .signature = "@intToError(value: std.meta.IntType(false, @sizeOf(anyerror) * 8)) anyerror",
        .snippet = "@intToError(${1:value: std.meta.IntType(false, @sizeOf(anyerror) * 8)})",
        .documentation = 
        \\ Converts from the integer representation of an error into The Global Error Set type. 
        \\ It is generally recommended to avoid this cast, as the integer representation of an error is not stable across source code changes. 
        \\ Attempting to convert an integer that does not correspond to any error results in safety-protected Undefined Behavior. 
        ,
        .arguments = &.{
            "value: std.meta.IntType(false, @sizeOf(anyerror) * 8)",
        },
    },
    .{
        .name = "@intToFloat",
        .signature = "@intToFloat(comptime DestType: type, int: anytype) DestType",
        .snippet = "@intToFloat(${1:comptime DestType: type}, ${2:int: anytype})",
        .documentation = 
        \\ Converts an integer to the closest floating point representation. To convert the other way, use @floatToInt. This cast is always safe. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "int: anytype",
        },
    },
    .{
        .name = "@intToPtr",
        .signature = "@intToPtr(comptime DestType: type, address: usize) DestType",
        .snippet = "@intToPtr(${1:comptime DestType: type}, ${2:address: usize})",
        .documentation = 
        \\ Converts an integer to a pointer. To convert the other way, use @ptrToInt. 
        \\ If the destination pointer type does not allow address zero and address is zero, this invokes safety-checked Undefined Behavior. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "address: usize",
        },
    },
    .{
        .name = "@memcpy",
        .signature = "@memcpy(noalias dest: [*]u8, noalias source: [*]const u8, byte_count: usize)",
        .snippet = "@memcpy(${1:noalias dest: [*]u8}, ${2:noalias source: [*]const u8}, ${3:byte_count: usize})",
        .documentation = 
        \\ This function copies bytes from one region of memory to another. dest and source are both pointers and must not overlap. 
        \\ This function is a low level intrinsic with no safety mechanisms. Most code should not use this function, instead using something like this: 
        \\```zig
        \\for (source[0..byte_count]) |b, i| dest[i] = b;
        \\```
        \\ The optimizer is intelligent enough to turn the above snippet into a memcpy. 
        \\There is also a standard library function for this:
        \\```zig
        \\const mem = @import("std").mem;
        \\mem.copy(u8, dest[0..byte_count], source[0..byte_count]);
        \\```
        ,
        .arguments = &.{
            "noalias dest: [*]u8",
            "noalias source: [*]const u8",
            "byte_count: usize",
        },
    },
    .{
        .name = "@memset",
        .signature = "@memset(dest: [*]u8, c: u8, byte_count: usize)",
        .snippet = "@memset(${1:dest: [*]u8}, ${2:c: u8}, ${3:byte_count: usize})",
        .documentation = 
        \\ This function sets a region of memory to c. dest is a pointer. 
        \\ This function is a low level intrinsic with no safety mechanisms. Most code should not use this function, instead using something like this: 
        \\```zig
        \\for (dest[0..byte_count]) |*b| b.* = c;
        \\```
        \\ The optimizer is intelligent enough to turn the above snippet into a memset. 
        \\There is also a standard library function for this:
        \\```zig
        \\const mem = @import("std").mem;
        \\mem.set(u8, dest, c);
        \\```
        ,
        .arguments = &.{
            "dest: [*]u8",
            "c: u8",
            "byte_count: usize",
        },
    },
    .{
        .name = "@wasmMemorySize",
        .signature = "@wasmMemorySize(index: u32) u32",
        .snippet = "@wasmMemorySize(${1:index: u32})",
        .documentation = 
        \\ This function returns the size of the Wasm memory identified by index as an unsigned value in units of Wasm pages. Note that each Wasm page is 64KB in size. 
        \\ This function is a low level intrinsic with no safety mechanisms usually useful for allocator designers targeting Wasm. So unless you are writing a new allocator from scratch, you should use something like @import("std").heap.WasmPageAllocator. 
        ,
        .arguments = &.{
            "index: u32",
        },
    },
    .{
        .name = "@wasmMemoryGrow",
        .signature = "@wasmMemoryGrow(index: u32, delta: u32) i32",
        .snippet = "@wasmMemoryGrow(${1:index: u32}, ${2:delta: u32})",
        .documentation = 
        \\ This function increases the size of the Wasm memory identified by index by delta in units of unsigned number of Wasm pages. Note that each Wasm page is 64KB in size. On success, returns previous memory size; on failure, if the allocation fails, returns -1. 
        \\ This function is a low level intrinsic with no safety mechanisms usually useful for allocator designers targeting Wasm. So unless you are writing a new allocator from scratch, you should use something like @import("std").heap.WasmPageAllocator. 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\const expect = std.testing.expect;
        \\
        \\test "@wasmMemoryGrow" {
        \\    if (builtin.arch != .wasm32) return error.SkipZigTest;
        \\
        \\    var prev = @wasmMemorySize(0);
        \\    expect(prev == @wasmMemoryGrow(0, 1));
        \\    expect(prev + 1 == @wasmMemorySize(0));
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "@wasmMemoryGrow"... SKIP
        \\0 passed; 1 skipped.
        \\
        \\```
        ,
        .arguments = &.{
            "index: u32",
            "delta: u32",
        },
    },
    .{
        .name = "@mod",
        .signature = "@mod(numerator: T, denominator: T) T",
        .snippet = "@mod(${1:numerator: T}, ${2:denominator: T})",
        .documentation = 
        \\ Modulus division. For unsigned integers this is the same as numerator % denominator. Caller guarantees denominator > 0. 
        ,
        .arguments = &.{
            "numerator: T",
            "denominator: T",
        },
    },
    .{
        .name = "@mulWithOverflow",
        .signature = "@mulWithOverflow(comptime T: type, a: T, b: T, result: *T) bool",
        .snippet = "@mulWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
        .documentation = 
        \\ Performs result.* = a * b. If overflow or underflow occurs, stores the overflowed bits in result and returns true. If no overflow or underflow occurs, returns false. 
        ,
        .arguments = &.{
            "comptime T: type",
            "a: T",
            "b: T",
            "result: *T",
        },
    },
    .{
        .name = "@panic",
        .signature = "@panic(message: []const u8) noreturn",
        .snippet = "@panic(${1:message: []const u8})",
        .documentation = 
        \\ Invokes the panic handler function. By default the panic handler function calls the public panic function exposed in the root source file, or if there is not one specified, the std.builtin.default_panic function from std/builtin.zig. 
        \\Generally it is better to use @import("std").debug.panic. However, @panic can be useful for 2 scenarios: 
        ,
        .arguments = &.{
            "message: []const u8",
        },
    },
    .{
        .name = "@popCount",
        .signature = "@popCount(comptime T: type, integer: T)",
        .snippet = "@popCount(${1:comptime T: type}, ${2:integer: T})",
        .documentation = 
        \\Counts the number of bits set in an integer.
        \\ If integer is known at comptime, the return type is comptime_int. Otherwise, the return type is an unsigned integer with the minimum number of bits that can represent the bit count of the integer type. 
        ,
        .arguments = &.{
            "comptime T: type",
            "integer: T",
        },
    },
    .{
        .name = "@ptrCast",
        .signature = "@ptrCast(comptime DestType: type, value: anytype) DestType",
        .snippet = "@ptrCast(${1:comptime DestType: type}, ${2:value: anytype})",
        .documentation = 
        \\ Converts a pointer of one type to a pointer of another type. 
        \\ Optional Pointers are allowed. Casting an optional pointer which is null to a non-optional pointer invokes safety-checked Undefined Behavior. 
        ,
        .arguments = &.{
            "comptime DestType: type",
            "value: anytype",
        },
    },
    .{
        .name = "@ptrToInt",
        .signature = "@ptrToInt(value: anytype) usize",
        .snippet = "@ptrToInt(${1:value: anytype})",
        .documentation = 
        \\ Converts value to a usize which is the address of the pointer. value can be one of these types: 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@rem",
        .signature = "@rem(numerator: T, denominator: T) T",
        .snippet = "@rem(${1:numerator: T}, ${2:denominator: T})",
        .documentation = 
        \\ Remainder division. For unsigned integers this is the same as numerator % denominator. Caller guarantees denominator > 0. 
        ,
        .arguments = &.{
            "numerator: T",
            "denominator: T",
        },
    },
    .{
        .name = "@returnAddress",
        .signature = "@returnAddress() usize",
        .snippet = "@returnAddress()",
        .documentation = 
        \\ This function returns the address of the next machine code instruction that will be executed when the current function returns. 
        \\ The implications of this are target specific and not consistent across all platforms. 
        \\ This function is only valid within function scope. If the function gets inlined into a calling function, the returned address will apply to the calling function. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@setAlignStack",
        .signature = "@setAlignStack(comptime alignment: u29)",
        .snippet = "@setAlignStack(${1:comptime alignment: u29})",
        .documentation = 
        \\ Ensures that a function will have a stack alignment of at least alignment bytes. 
        ,
        .arguments = &.{
            "comptime alignment: u29",
        },
    },
    .{
        .name = "@setCold",
        .signature = "@setCold(is_cold: bool)",
        .snippet = "@setCold(${1:is_cold: bool})",
        .documentation = 
        \\ Tells the optimizer that a function is rarely called. 
        ,
        .arguments = &.{
            "is_cold: bool",
        },
    },
    .{
        .name = "@setEvalBranchQuota",
        .signature = "@setEvalBranchQuota(new_quota: u32)",
        .snippet = "@setEvalBranchQuota(${1:new_quota: u32})",
        .documentation = 
        \\ Changes the maximum number of backwards branches that compile-time code execution can use before giving up and making a compile error. 
        \\ If the new_quota is smaller than the default quota (1000) or a previously explicitly set quota, it is ignored. 
        \\ Example: 
        \\test.zig
        \\```zig
        \\test "foo" {
        \\    comptime {
        \\        var i = 0;
        \\        while (i < 1001) : (i += 1) {}
        \\    }
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\./docgen_tmp/test.zig:4:9: error: evaluation exceeded 1000 backwards branches
        \\        while (i < 1001) : (i += 1) {}
        \\        ^
        \\./docgen_tmp/test.zig:1:12: note: referenced here
        \\test "foo" {
        \\           ^
        \\
        \\```
        \\Now we use @setEvalBranchQuota:
        \\test.zig
        \\```zig
        \\test "foo" {
        \\    comptime {
        \\        @setEvalBranchQuota(1001);
        \\        var i = 0;
        \\        while (i < 1001) : (i += 1) {}
        \\    }
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "foo"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "new_quota: u32",
        },
    },
    .{
        .name = "@setFloatMode",
        .signature = "@setFloatMode(mode: @import(\"builtin\").FloatMode)",
        .snippet = "@setFloatMode(${1:mode: @import(\"builtin\").FloatMode})",
        .documentation = 
        \\ Sets the floating point mode of the current scope. Possible values are: 
        \\```zig
        \\pub const FloatMode = enum {
        \\    Strict,
        \\    Optimized,
        \\};
        \\```
        ,
        .arguments = &.{
            "mode: @import(\"builtin\").FloatMode",
        },
    },
    .{
        .name = "@setRuntimeSafety",
        .signature = "@setRuntimeSafety(safety_on: bool)",
        .snippet = "@setRuntimeSafety(${1:safety_on: bool})",
        .documentation = 
        \\ Sets whether runtime safety checks are enabled for the scope that contains the function call. 
        \\test.zig
        \\```zig
        \\test "@setRuntimeSafety" {
        \\    // The builtin applies to the scope that it is called in. So here, integer overflow
        \\    // will not be caught in ReleaseFast and ReleaseSmall modes:
        \\    // var x: u8 = 255;
        \\    // x += 1; // undefined behavior in ReleaseFast/ReleaseSmall modes.
        \\    {
        \\        // However this block has safety enabled, so safety checks happen here,
        \\        // even in ReleaseFast and ReleaseSmall modes.
        \\        @setRuntimeSafety(true);
        \\        var x: u8 = 255;
        \\        x += 1;
        \\
        \\        {
        \\            // The value can be overridden at any scope. So here integer overflow
        \\            // would not be caught in any build mode.
        \\            @setRuntimeSafety(false);
        \\            // var x: u8 = 255;
        \\            // x += 1; // undefined behavior in all build modes.
        \\        }
        \\    }
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig-OReleaseFast
        \\1/1 test "@setRuntimeSafety"... integer overflow
        \\error: the following test command crashed:
        \\docgen_tmp/zig-cache/o/d760ff9dc12761126824676bb5d40d62/test
        \\
        \\```
        \\Note: it is planned to replace @setRuntimeSafety with @optimizeFor
        ,
        .arguments = &.{
            "safety_on: bool",
        },
    },
    .{
        .name = "@shlExact",
        .signature = "@shlExact(value: T, shift_amt: Log2T) T",
        .snippet = "@shlExact(${1:value: T}, ${2:shift_amt: Log2T})",
        .documentation = 
        \\ Performs the left shift operation (<<). Caller guarantees that the shift will not shift any 1 bits out. 
        \\ The type of shift_amt is an unsigned integer with log2(T.bit_count) bits. This is because shift_amt >= T.bit_count is undefined behavior. 
        ,
        .arguments = &.{
            "value: T",
            "shift_amt: Log2T",
        },
    },
    .{
        .name = "@shlWithOverflow",
        .signature = "@shlWithOverflow(comptime T: type, a: T, shift_amt: Log2T, result: *T) bool",
        .snippet = "@shlWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:shift_amt: Log2T}, ${4:result: *T})",
        .documentation = 
        \\ Performs result.* = a << b. If overflow or underflow occurs, stores the overflowed bits in result and returns true. If no overflow or underflow occurs, returns false. 
        \\ The type of shift_amt is an unsigned integer with log2(T.bit_count) bits. This is because shift_amt >= T.bit_count is undefined behavior. 
        ,
        .arguments = &.{
            "comptime T: type",
            "a: T",
            "shift_amt: Log2T",
            "result: *T",
        },
    },
    .{
        .name = "@shrExact",
        .signature = "@shrExact(value: T, shift_amt: Log2T) T",
        .snippet = "@shrExact(${1:value: T}, ${2:shift_amt: Log2T})",
        .documentation = 
        \\ Performs the right shift operation (>>). Caller guarantees that the shift will not shift any 1 bits out. 
        \\ The type of shift_amt is an unsigned integer with log2(T.bit_count) bits. This is because shift_amt >= T.bit_count is undefined behavior. 
        ,
        .arguments = &.{
            "value: T",
            "shift_amt: Log2T",
        },
    },
    .{
        .name = "@shuffle",
        .signature = "@shuffle(comptime E: type, a: std.meta.Vector(a_len, E), b: std.meta.Vector(b_len, E), comptime mask: std.meta.Vector(mask_len, i32)) std.meta.Vector(mask_len, E)",
        .snippet = "@shuffle(${1:comptime E: type}, ${2:a: std.meta.Vector(a_len, E)}, ${3:b: std.meta.Vector(b_len, E)}, ${4:comptime mask: std.meta.Vector(mask_len, i32)})",
        .documentation = 
        \\ Constructs a new vector by selecting elements from a and b based on mask. 
        \\ Each element in mask selects an element from either a or b. Positive numbers select from a starting at 0. Negative values select from b, starting at -1 and going down. It is recommended to use the ~ operator from indexes from b so that both indexes can start from 0 (i.e. ~@as(i32, 0) is -1). 
        \\ For each element of mask, if it or the selected value from a or b is undefined, then the resulting element is undefined. 
        \\ a_len and b_len may differ in length. Out-of-bounds element indexes in mask result in compile errors. 
        \\ If a or b is undefined, it is equivalent to a vector of all undefined with the same length as the other vector. If both vectors are undefined, @shuffle returns a vector with all elements undefined. 
        \\ E must be an integer, float, pointer, or bool. The mask may be any vector length, and its length determines the result length. 
        ,
        .arguments = &.{
            "comptime E: type",
            "a: std.meta.Vector(a_len, E)",
            "b: std.meta.Vector(b_len, E)",
            "comptime mask: std.meta.Vector(mask_len, i32)",
        },
    },
    .{
        .name = "@sizeOf",
        .signature = "@sizeOf(comptime T: type) comptime_int",
        .snippet = "@sizeOf(${1:comptime T: type})",
        .documentation = 
        \\ This function returns the number of bytes it takes to store T in memory. The result is a target-specific compile time constant. 
        \\ This size may contain padding bytes. If there were two consecutive T in memory, this would be the offset in bytes between element at index 0 and the element at index 1. For integer, consider whether you want to use @sizeOf(T) or @typeInfo(T).Int.bits. 
        \\ This function measures the size at runtime. For types that are disallowed at runtime, such as comptime_int and type, the result is 0. 
        ,
        .arguments = &.{
            "comptime T: type",
        },
    },
    .{
        .name = "@splat",
        .signature = "@splat(comptime len: u32, scalar: anytype) std.meta.Vector(len, @TypeOf(scalar))",
        .snippet = "@splat(${1:comptime len: u32}, ${2:scalar: anytype})",
        .documentation = 
        \\ Produces a vector of length len where each element is the value scalar: 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "vector @splat" {
        \\    const scalar: u32 = 5;
        \\    const result = @splat(4, scalar);
        \\    comptime expect(@TypeOf(result) == std.meta.Vector(4, u32));
        \\    expect(std.mem.eql(u32, &@as([4]u32, result), &[_]u32{ 5, 5, 5, 5 }));
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "vector @splat"... OK
        \\All 1 tests passed.
        \\
        \\```
        \\ scalar must be an integer, bool, float, or pointer. 
        ,
        .arguments = &.{
            "comptime len: u32",
            "scalar: anytype",
        },
    },
    .{
        .name = "@reduce",
        .signature = "@reduce(comptime op: builtin.ReduceOp, value: anytype) std.meta.Child(value)",
        .snippet = "@reduce(${1:comptime op: builtin.ReduceOp}, ${2:value: anytype})",
        .documentation = 
        \\ Transforms a vector into a scalar value by performing a sequential horizontal reduction of its elements using the specified operator op. 
        \\ Not every operator is available for every vector element type: 
        ,
        .arguments = &.{
            "comptime op: builtin.ReduceOp",
            "value: anytype",
        },
    },
    .{
        .name = "@src",
        .signature = "@src() std.builtin.SourceLocation",
        .snippet = "@src()",
        .documentation = 
        \\ Returns a SourceLocation struct representing the function's name and location in the source code. This must be called in a function. 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "@src" {
        \\    doTheTest();
        \\}
        \\
        \\fn doTheTest() void {
        \\    const src = @src();
        \\
        \\    expect(src.line == 9);
        \\    expect(src.column == 17);
        \\    expect(std.mem.endsWith(u8, src.fn_name, "doTheTest"));
        \\    expect(std.mem.endsWith(u8, src.file, "test.zig"));
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "@src"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{},
    },
    .{
        .name = "@sqrt",
        .signature = "@sqrt(value: anytype) @TypeOf(value)",
        .snippet = "@sqrt(${1:value: anytype})",
        .documentation = 
        \\ Performs the square root of a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@sin",
        .signature = "@sin(value: anytype) @TypeOf(value)",
        .snippet = "@sin(${1:value: anytype})",
        .documentation = 
        \\ Sine trigometric function on a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@cos",
        .signature = "@cos(value: anytype) @TypeOf(value)",
        .snippet = "@cos(${1:value: anytype})",
        .documentation = 
        \\ Cosine trigometric function on a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@exp",
        .signature = "@exp(value: anytype) @TypeOf(value)",
        .snippet = "@exp(${1:value: anytype})",
        .documentation = 
        \\ Base-e exponential function on a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@exp2",
        .signature = "@exp2(value: anytype) @TypeOf(value)",
        .snippet = "@exp2(${1:value: anytype})",
        .documentation = 
        \\ Base-2 exponential function on a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@log",
        .signature = "@log(value: anytype) @TypeOf(value)",
        .snippet = "@log(${1:value: anytype})",
        .documentation = 
        \\ Returns the natural logarithm of a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@log2",
        .signature = "@log2(value: anytype) @TypeOf(value)",
        .snippet = "@log2(${1:value: anytype})",
        .documentation = 
        \\ Returns the logarithm to the base 2 of a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@log10",
        .signature = "@log10(value: anytype) @TypeOf(value)",
        .snippet = "@log10(${1:value: anytype})",
        .documentation = 
        \\ Returns the logarithm to the base 10 of a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@fabs",
        .signature = "@fabs(value: anytype) @TypeOf(value)",
        .snippet = "@fabs(${1:value: anytype})",
        .documentation = 
        \\ Returns the absolute value of a floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@floor",
        .signature = "@floor(value: anytype) @TypeOf(value)",
        .snippet = "@floor(${1:value: anytype})",
        .documentation = 
        \\ Returns the largest integral value not greater than the given floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@ceil",
        .signature = "@ceil(value: anytype) @TypeOf(value)",
        .snippet = "@ceil(${1:value: anytype})",
        .documentation = 
        \\ Returns the largest integral value not less than the given floating point number. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@trunc",
        .signature = "@trunc(value: anytype) @TypeOf(value)",
        .snippet = "@trunc(${1:value: anytype})",
        .documentation = 
        \\ Rounds the given floating point number to an integer, towards zero. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@round",
        .signature = "@round(value: anytype) @TypeOf(value)",
        .snippet = "@round(${1:value: anytype})",
        .documentation = 
        \\ Rounds the given floating point number to an integer, away from zero. Uses a dedicated hardware instruction when available. 
        \\ Supports Floats and Vectors of floats, with the caveat that some float operations are not yet implemented for all float types. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@subWithOverflow",
        .signature = "@subWithOverflow(comptime T: type, a: T, b: T, result: *T) bool",
        .snippet = "@subWithOverflow(${1:comptime T: type}, ${2:a: T}, ${3:b: T}, ${4:result: *T})",
        .documentation = 
        \\ Performs result.* = a - b. If overflow or underflow occurs, stores the overflowed bits in result and returns true. If no overflow or underflow occurs, returns false. 
        ,
        .arguments = &.{
            "comptime T: type",
            "a: T",
            "b: T",
            "result: *T",
        },
    },
    .{
        .name = "@tagName",
        .signature = "@tagName(value: anytype) []const u8",
        .snippet = "@tagName(${1:value: anytype})",
        .documentation = 
        \\ Converts an enum value or union value to a slice of bytes representing the name.
        \\If the enum is non-exhaustive and the tag value does not map to a name, it invokes safety-checked Undefined Behavior. 
        ,
        .arguments = &.{
            "value: anytype",
        },
    },
    .{
        .name = "@TagType",
        .signature = "@TagType(T: type) type",
        .snippet = "@TagType(${1:T: type})",
        .documentation = 
        \\ For an enum, returns the integer type that is used to store the enumeration value. 
        \\ For a union, returns the enum type that is used to store the tag value. 
        ,
        .arguments = &.{
            "T: type",
        },
    },
    .{
        .name = "@This",
        .signature = "@This() type",
        .snippet = "@This()",
        .documentation = 
        \\ Returns the innermost struct, enum, or union that this function call is inside. This can be useful for an anonymous struct that needs to refer to itself: 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "@This()" {
        \\    var items = [_]i32{ 1, 2, 3, 4 };
        \\    const list = List(i32){ .items = items[0..] };
        \\    expect(list.length() == 4);
        \\}
        \\
        \\fn List(comptime T: type) type {
        \\    return struct {
        \\        const Self = @This();
        \\
        \\        items: []T,
        \\
        \\        fn length(self: Self) usize {
        \\            return self.items.len;
        \\        }
        \\    };
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "@This()"... OK
        \\All 1 tests passed.
        \\
        \\```
        \\ When @This() is used at global scope, it returns a reference to the struct that corresponds to the current file. 
        ,
        .arguments = &.{},
    },
    .{
        .name = "@truncate",
        .signature = "@truncate(comptime T: type, integer: anytype) T",
        .snippet = "@truncate(${1:comptime T: type}, ${2:integer: anytype})",
        .documentation = 
        \\ This function truncates bits from an integer type, resulting in a smaller or same-sized integer type. 
        \\ The following produces safety-checked Undefined Behavior: 
        \\test.zig
        \\```zig
        \\test "integer cast panic" {
        \\    var a: u16 = 0xabcd;
        \\    var b: u8 = @intCast(u8, a);
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "integer cast panic"... integer cast truncated bits
        \\/home/andy/Downloads/zig/docgen_tmp/test.zig:3:17: 0x205995 in test "integer cast panic" (test)
        \\    var b: u8 = @intCast(u8, a);
        \\                ^
        \\/home/andy/Downloads/zig/lib/std/special/test_runner.zig:61:28: 0x22dab1 in std.special.main (test)
        \\        } else test_fn.func();
        \\                           ^
        \\/home/andy/Downloads/zig/lib/std/start.zig:334:37: 0x20729d in std.start.posixCallMainAndExit (test)
        \\            const result = root.main() catch |err| {
        \\                                    ^
        \\/home/andy/Downloads/zig/lib/std/start.zig:162:5: 0x206fd2 in std.start._start (test)
        \\    @call(.{ .modifier = .never_inline }, posixCallMainAndExit, .{});
        \\    ^
        \\error: the following test command crashed:
        \\docgen_tmp/zig-cache/o/8fe80128a94c1613e48317295fc76cfc/test
        \\
        \\```
        \\ However this is well defined and working code: 
        \\truncate.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "integer truncation" {
        \\    var a: u16 = 0xabcd;
        \\    var b: u8 = @truncate(u8, a);
        \\    expect(b == 0xcd);
        \\}
        \\```
        \\```zig
        \\$ zig test truncate.zig
        \\1/1 test "integer truncation"... OK
        \\All 1 tests passed.
        \\
        \\```
        \\ This function always truncates the significant bits of the integer, regardless of endianness on the target platform. 
        ,
        .arguments = &.{
            "comptime T: type",
            "integer: anytype",
        },
    },
    .{
        .name = "@Type",
        .signature = "@Type(comptime info: @import(\"builtin\").TypeInfo) type",
        .snippet = "@Type(${1:comptime info: @import(\"builtin\").TypeInfo})",
        .documentation = 
        \\ This function is the inverse of @typeInfo. It reifies type information into a type. 
        \\ It is available for the following types: 
        ,
        .arguments = &.{
            "comptime info: @import(\"builtin\").TypeInfo",
        },
    },
    .{
        .name = "@typeInfo",
        .signature = "@typeInfo(comptime T: type) @import(\"std\").builtin.TypeInfo",
        .snippet = "@typeInfo(${1:comptime T: type})",
        .documentation = 
        \\ Provides type reflection. 
        \\ For structs, unions, enums, and error sets, the fields are guaranteed to be in the same order as declared. For declarations, the order is unspecified. 
        ,
        .arguments = &.{
            "comptime T: type",
        },
    },
    .{
        .name = "@typeName",
        .signature = "@typeName(T: type) [N]u8",
        .snippet = "@typeName(${1:T: type})",
        .documentation = 
        \\ This function returns the string representation of a type, as an array. It is equivalent to a string literal of the type name. 
        ,
        .arguments = &.{
            "T: type",
        },
    },
    .{
        .name = "@TypeOf",
        .signature = "@TypeOf(...) type",
        .snippet = "@TypeOf(${1:...})",
        .documentation = 
        \\ @TypeOf is a special builtin function that takes any (nonzero) number of expressions as parameters and returns the type of the result, using Peer Type Resolution. 
        \\ The expressions are evaluated, however they are guaranteed to have no runtime side-effects: 
        \\test.zig
        \\```zig
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\
        \\test "no runtime side effects" {
        \\    var data: i32 = 0;
        \\    const T = @TypeOf(foo(i32, &data));
        \\    comptime expect(T == i32);
        \\    expect(data == 0);
        \\}
        \\
        \\fn foo(comptime T: type, ptr: *T) T {
        \\    ptr.* += 1;
        \\    return ptr.*;
        \\}
        \\```
        \\```zig
        \\$ zig test test.zig
        \\1/1 test "no runtime side effects"... OK
        \\All 1 tests passed.
        \\
        \\```
        ,
        .arguments = &.{
            "...",
        },
    },
    .{
        .name = "@unionInit",
        .signature = "@unionInit(comptime Union: type, comptime active_field_name: []const u8, init_expr) Union",
        .snippet = "@unionInit(${1:comptime Union: type}, ${2:comptime active_field_name: []const u8}, ${3:init_expr})",
        .documentation = 
        \\ This is the same thing as union initialization syntax, except that the field name is a comptime-known value rather than an identifier token. 
        \\ @unionInit forwards its result location to init_expr. 
        ,
        .arguments = &.{
            "comptime Union: type",
            "comptime active_field_name: []const u8",
            "init_expr",
        },
    },
};
