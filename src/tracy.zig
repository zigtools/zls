//! Tracy bindings from Zig compiler
//
// The MIT License (Expat)
//
// Copyright (c) Zig contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

const std = @import("std");
const assert = std.debug.assert;

const builtin = @import("builtin");
const options = @import("options");

pub const enable = if (builtin.is_test) false else options.enable;
pub const enable_allocation = enable and options.enable_allocation;
pub const enable_callstack = if (enable) options.callstack_depth > 0 else 0;
pub const callstack_depth = if (enable) options.callstack_depth else 0;

const ___tracy_c_zone_context = extern struct {
    id: u32,
    active: i32,

    pub inline fn end(self: @This()) void {
        ___tracy_emit_zone_end(self);
    }

    pub inline fn addText(self: @This(), text: []const u8) void {
        ___tracy_emit_zone_text(self, text.ptr, text.len);
    }

    pub inline fn addTextFmt(self: @This(), comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch &buf;
        self.addText(slice);
    }

    pub inline fn setName(self: @This(), name: []const u8) void {
        ___tracy_emit_zone_name(self, name.ptr, name.len);
    }

    pub inline fn setColor(self: @This(), color: u32) void {
        ___tracy_emit_zone_color(self, color);
    }

    pub inline fn setValue(self: @This(), value: u64) void {
        ___tracy_emit_zone_value(self, value);
    }
};

pub const Ctx = if (enable) ___tracy_c_zone_context else struct {
    pub inline fn end(self: @This()) void {
        _ = self;
    }

    pub inline fn addText(self: @This(), text: []const u8) void {
        _ = self;
        _ = text;
    }

    pub inline fn addTextFmt(self: @This(), comptime fmt: []const u8, args: anytype) void {
        _ = self;
        _ = fmt;
        _ = args;
    }

    pub inline fn setName(self: @This(), name: []const u8) void {
        _ = self;
        _ = name;
    }

    pub inline fn setColor(self: @This(), color: u32) void {
        _ = self;
        _ = color;
    }

    pub inline fn setValue(self: @This(), value: u64) void {
        _ = self;
        _ = value;
    }
};

pub inline fn trace(comptime src: std.lang.SourceLocation) Ctx {
    if (!enable) return .{};

    const global = struct {
        const loc: ___tracy_source_location_data = .{
            .name = null,
            .function = src.fn_name.ptr,
            .file = src.file.ptr,
            .line = src.line,
            .color = 0,
        };
    };

    return ___tracy_emit_zone_begin_callstack(&global.loc, callstack_depth, 1);
}

pub inline fn traceNamed(comptime src: std.lang.SourceLocation, comptime name: [:0]const u8) Ctx {
    if (!enable) return .{};

    const global = struct {
        const loc: ___tracy_source_location_data = .{
            .name = name.ptr,
            .function = src.fn_name.ptr,
            .file = src.file.ptr,
            .line = src.line,
            .color = 0,
        };
    };

    return ___tracy_emit_zone_begin_callstack(&global.loc, callstack_depth, 1);
}

pub inline fn fiberEnter(fiber: [*:0]const u8) void {
    if (!enable) return;
    ___tracy_fiber_enter(fiber);
}

pub inline fn fiberLeave() void {
    if (!enable) return;
    ___tracy_fiber_leave();
}

pub inline fn plotConfig(comptime name: [*:0]const u8, config: PlotConfig) void {
    if (!enable) return;
    ___tracy_emit_plot_config(
        name,
        config.format,
        config.mode,
        @intFromBool(config.fill),
        // https://github.com/wolfpld/tracy/issues/1232
        @byteSwap(config.color),
    );
}

pub inline fn plotInt(comptime name: [*:0]const u8, val: i64) void {
    if (!enable) return;
    ___tracy_emit_plot_int(name, val);
}

pub const Allocator = struct {
    parent_allocator: std.mem.Allocator,

    comptime {
        assert(enable); // used `tracy.Allocator` with Tracy disabled
    }

    pub fn interface(self: *Allocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(ptr));
        assert(len > 0);
        if (self.parent_allocator.rawAlloc(len, alignment, ret_addr)) |memory| {
            ___tracy_emit_memory_alloc_callstack(memory, len, callstack_depth, 0);
            return memory;
        } else {
            messageColor("allocation failed", 0xFF0000);
            return null;
        }
    }

    fn resizeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Allocator = @ptrCast(@alignCast(ptr));
        assert(memory.len > 0);
        assert(new_len > 0);
        // We need to mark the free before calling the implementation to avoid a race.
        ___tracy_emit_memory_free_callstack(memory.ptr, callstack_depth, 0);
        if (self.parent_allocator.rawResize(memory, alignment, new_len, ret_addr)) {
            ___tracy_emit_memory_alloc_callstack(memory.ptr, new_len, callstack_depth, 0);
            return true;
        } else {
            // No `messageColor` call here because this case is hit frequently in normal operation.
            ___tracy_emit_memory_alloc_callstack(memory.ptr, memory.len, callstack_depth, 0);
            return false;
        }
    }

    fn remapFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(ptr));
        assert(memory.len > 0);
        assert(new_len > 0);
        // We need to mark the free before calling the implementation to avoid a race.
        ___tracy_emit_memory_free_callstack(memory.ptr, callstack_depth, 0);
        if (self.parent_allocator.rawRemap(memory, alignment, new_len, ret_addr)) |new_memory| {
            ___tracy_emit_memory_alloc_callstack(new_memory, new_len, callstack_depth, 0);
            return new_memory;
        } else {
            // No `messageColor` call here because this case is hit frequently in normal operation.
            ___tracy_emit_memory_alloc_callstack(memory.ptr, memory.len, callstack_depth, 0);
            return null;
        }
    }

    fn freeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Allocator = @ptrCast(@alignCast(ptr));
        assert(memory.len > 0);
        ___tracy_emit_memory_free_callstack(memory.ptr, callstack_depth, 0);
        self.parent_allocator.rawFree(memory, alignment, ret_addr);
    }
};

// This function only accepts comptime-known strings, see `messageCopy` for runtime strings
pub inline fn message(comptime msg: [:0]const u8) void {
    messageColor(msg, 0);
}

// This function only accepts comptime-known strings, see `messageColorCopy` for runtime strings
pub inline fn messageColor(comptime msg: [:0]const u8, color: u24) void {
    if (!enable) return;
    ___tracy_emit_logStringL(.Info, color, callstack_depth, msg.ptr);
}

pub inline fn messageCopy(msg: []const u8) void {
    messageColorCopy(msg, 0);
}

pub inline fn messageColorCopy(msg: []const u8, color: u24) void {
    if (!enable) return;
    ___tracy_emit_logString(.Info, color, callstack_depth, msg.len, msg.ptr);
}

/// Used to store strings which Tracy requires to have stable pointers for the program's entire
/// lifetime. All such strings will be leaked.
///
/// The `enable` check ensures that this is not referenced if Tracy is disabled.
var tracy_arena: std.heap.ArenaAllocator = if (enable) .init(std.heap.page_allocator);

pub inline fn namedFrame(name: []const u8) Frame {
    if (!enable) return .{ .name = {} };
    const stable_name = tracy_arena.allocator().dupeSentinel(u8, name, 0) catch @panic("tracy arena OOM");
    ___tracy_emit_frame_mark_start(stable_name.ptr);
    return .{ .name = stable_name.ptr };
}

pub const Frame = struct {
    name: if (enable) [*:0]const u8 else void,
    pub inline fn end(frame: Frame) void {
        if (!enable) return;
        ___tracy_emit_frame_mark_end(frame.name);
    }
};

pub const MessageSeverity = enum(i8) {
    Trace, // Broadly track variable states and events in the software program.
    Debug, // Describes variable states and details about specific internal events in the software, that are useful for investigations.
    Info, // Describes normal events, which inform on the expected progress and state of your software.
    Warning, // Describes potentially dangerous situations caused by unexpected events and states.
    Error, // Describes the occurance of unexpected behavior. Does not interrupt the execution of the software.
    Fatal, // Describes a critical event that will lead to a software failure/crash.
};

pub const PlotConfig = struct {
    format: Format,
    mode: Mode,
    fill: bool = true,
    color: u24 = 0,

    pub const Format = enum(i32) {
        number = 0,
        memory = 1,
        percentage = 2,
        watt = 3,
    };

    pub const Mode = enum(i32) {
        line = 0,
        step = 1,
    };
};

extern fn ___tracy_emit_frame_mark_start(name: [*:0]const u8) void;
extern fn ___tracy_emit_frame_mark_end(name: [*:0]const u8) void;
extern fn ___tracy_emit_zone_begin_callstack(srcloc: *const ___tracy_source_location_data, depth: i32, active: i32) ___tracy_c_zone_context;
extern fn ___tracy_emit_zone_text(ctx: ___tracy_c_zone_context, txt: [*]const u8, size: usize) void;
extern fn ___tracy_emit_zone_name(ctx: ___tracy_c_zone_context, txt: [*]const u8, size: usize) void;
extern fn ___tracy_emit_zone_color(ctx: ___tracy_c_zone_context, color: u32) void;
extern fn ___tracy_emit_zone_value(ctx: ___tracy_c_zone_context, value: u64) void;
extern fn ___tracy_emit_zone_end(ctx: ___tracy_c_zone_context) void;
extern fn ___tracy_emit_memory_alloc_callstack(ptr: *const anyopaque, size: usize, depth: i32, secure: i32) void;
extern fn ___tracy_emit_memory_free_callstack(ptr: *const anyopaque, depth: i32, secure: i32) void;
extern fn ___tracy_emit_logString(severity: MessageSeverity, color: i32, callstack_depth: i32, size: usize, txt: [*]const u8) void;
extern fn ___tracy_emit_logStringL(severity: MessageSeverity, color: i32, callstack_depth: i32, txt: [*:0]const u8) void;
extern fn ___tracy_emit_plot_int(name: [*:0]const u8, val: i64) void;
extern fn ___tracy_emit_plot_config(name: [*:0]const u8, format: PlotConfig.Format, mode: PlotConfig.Mode, fill: i32, color: u32) void;
extern fn ___tracy_fiber_enter(fiber: [*:0]const u8) void;
extern fn ___tracy_fiber_leave() void;

const ___tracy_source_location_data = extern struct {
    name: ?[*:0]const u8,
    function: [*:0]const u8,
    file: [*:0]const u8,
    line: u32,
    color: u32,
};
