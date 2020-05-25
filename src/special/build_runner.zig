const root = @import("build.zig");
const std = @import("std");
const io = std.io;
const fmt = std.fmt;
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;
const InstallArtifactStep = std.build.InstallArtifactStep;
const ArrayList = std.ArrayList;

///! This is a modified build runner to extract information out of build.zig
///! Modified from the std.special.build_runner

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;

    const builder = try Builder.create(allocator, "", "", "");
    defer builder.destroy();

    try runBuild(builder);

    const stdout_stream = io.getStdOut().outStream();

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.getInstallStep().dependencies.items) |step| {
        if (step.cast(InstallArtifactStep)) |install_exe| {
            for (install_exe.artifact.packages.items) |pkg| {
                try processPackage(stdout_stream, pkg);
            }
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
