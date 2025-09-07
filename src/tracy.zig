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
const builtin = @import("builtin");
const options = @import("options");

pub const enable = if (builtin.is_test) false else options.enable;
pub const enable_allocation = enable and options.enable_allocation;
pub const enable_callstack = enable and options.enable_callstack;

// TODO: make this configurable
const callstack_depth = 10;

const ___tracy_c_zone_context = extern struct {
    id: u32,
    active: c_int,

    pub inline fn end(self: @This()) void {
        ___tracy_emit_zone_end(self);
    }

    pub inline fn addText(self: @This(), text: []const u8) void {
        ___tracy_emit_zone_text(self, text.ptr, text.len);
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

pub inline fn trace(comptime src: std.builtin.SourceLocation) Ctx {
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

    if (enable_callstack) {
        return ___tracy_emit_zone_begin_callstack(&global.loc, callstack_depth, 1);
    } else {
        return ___tracy_emit_zone_begin(&global.loc, 1);
    }
}

pub inline fn traceNamed(comptime src: std.builtin.SourceLocation, comptime name: [:0]const u8) Ctx {
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

    if (enable_callstack) {
        return ___tracy_emit_zone_begin_callstack(&global.loc, callstack_depth, 1);
    } else {
        return ___tracy_emit_zone_begin(&global.loc, 1);
    }
}

pub fn tracyAllocator(allocator: std.mem.Allocator) TracyAllocator(null) {
    return TracyAllocator(null).init(allocator);
}

pub fn TracyAllocator(comptime name: ?[:0]const u8) type {
    return struct {
        parent_allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(parent_allocator: std.mem.Allocator) Self {
            return .{
                .parent_allocator = parent_allocator,
            };
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
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
            std.debug.assert(len > 0);
            const self: *Self = @ptrCast(@alignCast(ptr));
            const new_memory = self.parent_allocator.rawAlloc(len, alignment, ret_addr) orelse {
                messageColor("allocation failed", 0xFF0000);
                return null;
            };
            if (name) |n| {
                allocNamed(new_memory, len, n);
            } else {
                alloc(new_memory, len);
            }
            return new_memory;
        }

        fn resizeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            std.debug.assert(memory.len > 0 and new_len.len > 0);
            const self: *Self = @ptrCast(@alignCast(ptr));
            if (!self.parent_allocator.rawResize(memory, alignment, new_len, ret_addr)) return false;
            if (name) |n| {
                freeNamed(memory.ptr, n);
                allocNamed(memory.ptr, new_len, n);
            } else {
                free(memory.ptr);
                alloc(memory.ptr, new_len);
            }
            return true;
        }

        fn remapFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            std.debug.assert(memory.len > 0 and new_len.len > 0);
            const self: *Self = @ptrCast(@alignCast(ptr));
            const new_memory = self.parent_allocator.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
            if (name) |n| {
                freeNamed(memory.ptr, n);
                allocNamed(new_memory, new_len, n);
            } else {
                free(memory.ptr);
                alloc(new_memory, new_len);
            }
            return new_memory;
        }

        fn freeFn(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            std.debug.assert(memory.len > 0);
            if (name) |n| {
                freeNamed(memory.ptr, n);
            } else {
                free(memory.ptr);
            }
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.parent_allocator.rawFree(memory, alignment, ret_addr);
        }
    };
}

// This function only accepts comptime known strings, see `messageCopy` for runtime strings
pub inline fn message(comptime msg: [:0]const u8) void {
    if (!enable) return;
    ___tracy_emit_messageL(msg.ptr, if (enable_callstack) callstack_depth else 0);
}

// This function only accepts comptime known strings, see `messageColorCopy` for runtime strings
pub inline fn messageColor(comptime msg: [:0]const u8, color: u32) void {
    if (!enable) return;
    ___tracy_emit_messageLC(msg.ptr, color, if (enable_callstack) callstack_depth else 0);
}

pub inline fn messageCopy(msg: []const u8) void {
    if (!enable) return;
    ___tracy_emit_message(msg.ptr, msg.len, if (enable_callstack) callstack_depth else 0);
}

pub inline fn messageColorCopy(msg: [:0]const u8, color: u32) void {
    if (!enable) return;
    ___tracy_emit_messageC(msg.ptr, msg.len, color, if (enable_callstack) callstack_depth else 0);
}

pub inline fn frameMark() void {
    if (!enable) return;
    ___tracy_emit_frame_mark(null);
}

pub inline fn frameMarkNamed(comptime name: [:0]const u8) void {
    if (!enable) return;
    ___tracy_emit_frame_mark(name.ptr);
}

pub inline fn namedFrame(comptime name: [:0]const u8) Frame(name) {
    frameMarkStart(name);
    return .{};
}

pub fn Frame(comptime name: [:0]const u8) type {
    return struct {
        pub fn end(_: @This()) void {
            frameMarkEnd(name);
        }
    };
}

inline fn frameMarkStart(comptime name: [:0]const u8) void {
    if (!enable) return;
    ___tracy_emit_frame_mark_start(name.ptr);
}

inline fn frameMarkEnd(comptime name: [:0]const u8) void {
    if (!enable) return;
    ___tracy_emit_frame_mark_end(name.ptr);
}

extern fn ___tracy_emit_frame_mark_start(name: [*:0]const u8) void;
extern fn ___tracy_emit_frame_mark_end(name: [*:0]const u8) void;

inline fn alloc(ptr: [*]u8, len: usize) void {
    if (!enable) return;

    if (enable_callstack) {
        ___tracy_emit_memory_alloc_callstack(ptr, len, callstack_depth, 0);
    } else {
        ___tracy_emit_memory_alloc(ptr, len, 0);
    }
}

inline fn allocNamed(ptr: [*]u8, len: usize, comptime name: [:0]const u8) void {
    if (!enable) return;

    if (enable_callstack) {
        ___tracy_emit_memory_alloc_callstack_named(ptr, len, callstack_depth, 0, name.ptr);
    } else {
        ___tracy_emit_memory_alloc_named(ptr, len, 0, name.ptr);
    }
}

inline fn free(ptr: [*]u8) void {
    if (!enable) return;

    if (enable_callstack) {
        ___tracy_emit_memory_free_callstack(ptr, callstack_depth, 0);
    } else {
        ___tracy_emit_memory_free(ptr, 0);
    }
}

inline fn freeNamed(ptr: [*]u8, comptime name: [:0]const u8) void {
    if (!enable) return;

    if (enable_callstack) {
        ___tracy_emit_memory_free_callstack_named(ptr, callstack_depth, 0, name.ptr);
    } else {
        ___tracy_emit_memory_free_named(ptr, 0, name.ptr);
    }
}

extern fn ___tracy_emit_zone_begin(
    srcloc: *const ___tracy_source_location_data,
    active: c_int,
) ___tracy_c_zone_context;
extern fn ___tracy_emit_zone_begin_callstack(
    srcloc: *const ___tracy_source_location_data,
    depth: c_int,
    active: c_int,
) ___tracy_c_zone_context;
extern fn ___tracy_emit_zone_text(ctx: ___tracy_c_zone_context, txt: [*]const u8, size: usize) void;
extern fn ___tracy_emit_zone_name(ctx: ___tracy_c_zone_context, txt: [*]const u8, size: usize) void;
extern fn ___tracy_emit_zone_color(ctx: ___tracy_c_zone_context, color: u32) void;
extern fn ___tracy_emit_zone_value(ctx: ___tracy_c_zone_context, value: u64) void;
extern fn ___tracy_emit_zone_end(ctx: ___tracy_c_zone_context) void;
extern fn ___tracy_emit_memory_alloc(ptr: *const anyopaque, size: usize, secure: c_int) void;
extern fn ___tracy_emit_memory_alloc_callstack(ptr: *const anyopaque, size: usize, depth: c_int, secure: c_int) void;
extern fn ___tracy_emit_memory_free(ptr: *const anyopaque, secure: c_int) void;
extern fn ___tracy_emit_memory_free_callstack(ptr: *const anyopaque, depth: c_int, secure: c_int) void;
extern fn ___tracy_emit_memory_alloc_named(ptr: *const anyopaque, size: usize, secure: c_int, name: [*:0]const u8) void;
extern fn ___tracy_emit_memory_alloc_callstack_named(ptr: *const anyopaque, size: usize, depth: c_int, secure: c_int, name: [*:0]const u8) void;
extern fn ___tracy_emit_memory_free_named(ptr: *const anyopaque, secure: c_int, name: [*:0]const u8) void;
extern fn ___tracy_emit_memory_free_callstack_named(ptr: *const anyopaque, depth: c_int, secure: c_int, name: [*:0]const u8) void;
extern fn ___tracy_emit_message(txt: [*]const u8, size: usize, callstack: c_int) void;
extern fn ___tracy_emit_messageL(txt: [*:0]const u8, callstack: c_int) void;
extern fn ___tracy_emit_messageC(txt: [*]const u8, size: usize, color: u32, callstack: c_int) void;
extern fn ___tracy_emit_messageLC(txt: [*:0]const u8, color: u32, callstack: c_int) void;
extern fn ___tracy_emit_frame_mark(name: ?[*:0]const u8) void;

const ___tracy_source_location_data = extern struct {
    name: ?[*:0]const u8,
    function: [*:0]const u8,
    file: [*:0]const u8,
    line: u32,
    color: u32,
};
