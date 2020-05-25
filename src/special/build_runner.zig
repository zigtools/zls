const root = @import("build.zig");
const std = @import("std");
const io = std.io;
const fmt = std.fmt;
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;
const LibExeObjStep = std.build.LibExeObjStep;
const ArrayList = std.ArrayList;
///! This is a modified build runner to extract information out of build.zig
///! Modified from std.special.build_runner

// We use a custom Allocator to intercept the creation of steps
const InterceptAllocator = struct {
    base_allocator: *std.mem.Allocator,
    allocator: std.mem.Allocator,
    steps: std.ArrayListUnmanaged(*LibExeObjStep),

    fn init(base_allocator: *std.mem.Allocator) InterceptAllocator {
        return .{
            .base_allocator = base_allocator,
            .allocator = .{
                .reallocFn = realloc,
                .shrinkFn = shrink,
            },
            .steps = .{},
        };
    }

    // TODO: Check LibExeObjStep has a unique size.
    fn realloc(allocator: *std.mem.Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) ![]u8 {
        const self = @fieldParentPtr(InterceptAllocator, "allocator", allocator);
        var data = try self.base_allocator.reallocFn(self.base_allocator, old_mem, old_align, new_size, new_align);
        if (old_mem.len == 0 and new_size == @sizeOf(LibExeObjStep)) {
            try self.steps.append(self.base_allocator, @ptrCast(*LibExeObjStep, @alignCast(@alignOf(LibExeObjStep), data.ptr)));
        }
        return data;
    }

    fn shrink(allocator: *std.mem.Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) []u8 {
        const self = @fieldParentPtr(InterceptAllocator, "allocator", allocator);
        return self.base_allocator.shrinkFn(self.base_allocator, old_mem, old_align, new_size, new_align);
    }

    fn deinit(self: *InterceptAllocator) void {
        self.steps.deinit(self.base_allocator);
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var intercept = InterceptAllocator.init(&arena.allocator);
    defer intercept.deinit();
    const allocator = &intercept.allocator;

    const builder = try Builder.create(allocator, "", "", "");
    defer builder.destroy();

    try runBuild(builder);

    const stdout_stream = io.getStdOut().outStream();

    // TODO: We currently add packages from every step.,
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (intercept.steps.items) |step| {
        for (step.packages.items) |pkg| {
            try processPackage(stdout_stream, pkg);
        }
    }
}

fn processPackage(out_stream: var, pkg: Pkg) anyerror!void {
    try out_stream.print("{}\x00{}\n", .{ pkg.name, pkg.path });
    if (pkg.dependencies) |dependencies| {
        for (dependencies) |dep| {
            try processPackage(out_stream, dep);
        }
    }
}

fn runBuild(builder: *Builder) anyerror!void {
    switch (@typeInfo(@TypeOf(root.build).ReturnType)) {
        .Void => root.build(builder),
        .ErrorUnion => try root.build(builder),
        else => @compileError("expected return type of build to be 'void' or '!void'"),
    }
}
