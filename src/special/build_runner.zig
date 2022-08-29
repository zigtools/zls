const root = @import("@build@");
const std = @import("std");
const log = std.log;
const process = std.process;
const Builder = std.build.Builder;
const InstallArtifactStep = std.build.InstallArtifactStep;
const LibExeObjStep = std.build.LibExeObjStep;

pub const BuildConfig = struct {
    packages: []Pkg,
    include_dirs: []IncludeDir,

    pub const Pkg = struct {
        name: []const u8,
        path: []const u8,
    };

    pub const IncludeDir = struct {
        path: []const u8,
        system: bool,
    };
};

///! This is a modified build runner to extract information out of build.zig
///! Modified version of lib/build_runner.zig
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);

    // skip my own exe name
    var arg_idx: usize = 1;

    const zig_exe = nextArg(args, &arg_idx) orelse {
        log.warn("Expected first argument to be path to zig compiler\n", .{});
        return error.InvalidArgs;
    };
    const build_root = nextArg(args, &arg_idx) orelse {
        log.warn("Expected second argument to be build root directory path\n", .{});
        return error.InvalidArgs;
    };
    const cache_root = nextArg(args, &arg_idx) orelse {
        log.warn("Expected third argument to be cache root directory path\n", .{});
        return error.InvalidArgs;
    };
    const global_cache_root = nextArg(args, &arg_idx) orelse {
        log.warn("Expected third argument to be global cache root directory path\n", .{});
        return error.InvalidArgs;
    };

    const builder = try Builder.create(
        allocator,
        zig_exe,
        build_root,
        cache_root,
        global_cache_root,
    );

    defer builder.destroy();

    builder.resolveInstallPrefix(null, Builder.DirList{});
    try runBuild(builder);

    var packages = std.ArrayListUnmanaged(BuildConfig.Pkg){};
    defer packages.deinit(allocator);

    var include_dirs = std.ArrayListUnmanaged(BuildConfig.IncludeDir){};
    defer include_dirs.deinit(allocator);

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.top_level_steps.items) |tls| {
        for (tls.step.dependencies.items) |step| {
            try processStep(allocator, &packages, &include_dirs, step);
        }
    }

    try std.json.stringify(
        BuildConfig{
            .packages = packages.items,
            .include_dirs = include_dirs.items,
        },
        .{ .whitespace = .{} },
        std.io.getStdOut().writer(),
    );
}

fn processStep(
    allocator: std.mem.Allocator,
    packages: *std.ArrayListUnmanaged(BuildConfig.Pkg),
    include_dirs: *std.ArrayListUnmanaged(BuildConfig.IncludeDir),
    step: *std.build.Step,
) anyerror!void {
    if (step.cast(InstallArtifactStep)) |install_exe| {
        try processIncludeDirs(allocator, include_dirs, install_exe.artifact.include_dirs.items);
        for (install_exe.artifact.packages.items) |pkg| {
            try processPackage(allocator, packages, pkg);
        }
    } else if (step.cast(LibExeObjStep)) |exe| {
        try processIncludeDirs(allocator, include_dirs, exe.include_dirs.items);
        for (exe.packages.items) |pkg| {
            try processPackage(allocator, packages, pkg);
        }
    } else {
        for (step.dependencies.items) |unknown_step| {
            try processStep(allocator, packages, include_dirs, unknown_step);
        }
    }
}

fn processPackage(
    allocator: std.mem.Allocator,
    packages: *std.ArrayListUnmanaged(BuildConfig.Pkg),
    pkg: std.build.Pkg,
) anyerror!void {
    for (packages.items) |package| {
        if (std.mem.eql(u8, package.name, pkg.name)) return;
    }

    const source = if (@hasField(std.build.Pkg, "source")) pkg.source else pkg.path;
    const maybe_path = switch (source) {
        .path => |path| path,
        .generated => |generated| generated.path,
    };

    if (maybe_path) |path| {
        try packages.append(allocator, .{ .name = pkg.name, .path = path });
    }

    if (pkg.dependencies) |dependencies| {
        for (dependencies) |dep| {
            try processPackage(allocator, packages, dep);
        }
    }
}

fn processIncludeDirs(
    allocator: std.mem.Allocator,
    include_dirs: *std.ArrayListUnmanaged(BuildConfig.IncludeDir),
    dirs: []std.build.LibExeObjStep.IncludeDir,
) !void {
    try include_dirs.ensureUnusedCapacity(allocator, dirs.len);

    outer: for (dirs) |dir| {
        const candidate: BuildConfig.IncludeDir = switch (dir) {
            .raw_path => |path| .{ .path = path, .system = false },
            .raw_path_system => |path| .{ .path = path, .system = true },
            else => continue,
        };

        for (include_dirs.items) |include_dir| {
            if (std.mem.eql(u8, candidate.path, include_dir.path)) continue :outer;
        }

        include_dirs.appendAssumeCapacity(candidate);
    }
}

fn runBuild(builder: *Builder) anyerror!void {
    switch (@typeInfo(@typeInfo(@TypeOf(root.build)).Fn.return_type.?)) {
        .Void => root.build(builder),
        .ErrorUnion => try root.build(builder),
        else => @compileError("expected return type of build to be 'void' or '!void'"),
    }
}

fn nextArg(args: [][]const u8, idx: *usize) ?[]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}
