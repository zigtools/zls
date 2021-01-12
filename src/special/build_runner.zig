const root = @import("@build@");
const std = @import("std");
const io = std.io;
const fmt = std.fmt;
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;
const InstallArtifactStep = std.build.InstallArtifactStep;
const LibExeObjStep = std.build.LibExeObjStep;
const ArrayList = std.ArrayList;

///! This is a modified build runner to extract information out of build.zig
///! Modified from the std.special.build_runner

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;

    const builder = try Builder.create(allocator, "", "", "", "");
    defer builder.destroy();

    try runBuild(builder);

    const stdout_stream = io.getStdOut().writer();

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.top_level_steps.items) |tls| {
        for (tls.step.dependencies.items) |step| {
            try processStep(stdout_stream, step);
        }
    }
}

fn processStep(stdout_stream: anytype, step: *std.build.Step) anyerror!void {
    if (step.cast(InstallArtifactStep)) |install_exe| {
        for (install_exe.artifact.packages.items) |pkg| {
            try processPackage(stdout_stream, pkg);
        }
    } else if (step.cast(LibExeObjStep)) |exe| {
        for (exe.packages.items) |pkg| {
            try processPackage(stdout_stream, pkg);
        }
    } else {
        for (step.dependencies.items) |unknown_step| {
            try processStep(stdout_stream, unknown_step);
        }
    }
}

fn processPackage(out_stream: anytype, pkg: Pkg) anyerror!void {
    try out_stream.print("{s}\x00{s}\n", .{ pkg.name, pkg.path });
    if (pkg.dependencies) |dependencies| {
        for (dependencies) |dep| {
            try processPackage(out_stream, dep);
        }
    }
}

fn runBuild(builder: *Builder) anyerror!void {
    switch (@typeInfo(@typeInfo(@TypeOf(root.build)).Fn.return_type.?)) {
        .Void => root.build(builder),
        .ErrorUnion => try root.build(builder),
        else => @compileError("expected return type of build to be 'void' or '!void'"),
    }
}
