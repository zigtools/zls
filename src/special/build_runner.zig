const root = @import("@build@");
const std = @import("std");
const log = std.log;
const process = std.process;
const Builder = std.build.Builder;
const InstallArtifactStep = std.build.InstallArtifactStep;
const LibExeObjStep = std.build.LibExeObjStep;
const OptionsStep = std.build.OptionsStep;

pub const BuildConfig = struct {
    packages: []Pkg,
    include_dirs: []const []const u8,

    pub const Pkg = struct {
        name: []const u8,
        path: []const u8,
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

    const build_root_directory: std.Build.Cache.Directory = .{
        .path = build_root,
        .handle = try std.fs.cwd().openDir(build_root, .{}),
    };

    const local_cache_directory: std.Build.Cache.Directory = .{
        .path = cache_root,
        .handle = try std.fs.cwd().makeOpenPath(cache_root, .{}),
    };

    const global_cache_directory: std.Build.Cache.Directory = .{
        .path = global_cache_root,
        .handle = try std.fs.cwd().makeOpenPath(global_cache_root, .{}),
    };

    var cache: std.Build.Cache = .{
        .gpa = allocator,
        .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
    };
    cache.addPrefix(.{ .path = null, .handle = std.fs.cwd() });
    cache.addPrefix(build_root_directory);
    cache.addPrefix(local_cache_directory);
    cache.addPrefix(global_cache_directory);

    const builder = blk: {
        // Zig 0.11.0-dev.1524+
        if (@hasDecl(std, "Build")) {
            const host = try std.zig.system.NativeTargetInfo.detect(.{});
            break :blk try Builder.create(
                allocator,
                zig_exe,
                build_root_directory,
                local_cache_directory,
                global_cache_directory,
                host,
                &cache,
            );
        } else break :blk try Builder.create(
            allocator,
            zig_exe,
            build_root,
            cache_root,
            global_cache_root,
        );
    };

    defer builder.destroy();

    while (nextArg(args, &arg_idx)) |arg| {
        if (std.mem.startsWith(u8, arg, "-D")) {
            const option_contents = arg[2..];
            if (option_contents.len == 0) {
                log.err("Expected option name after '-D'\n\n", .{});
                return error.InvalidArgs;
            }
            if (std.mem.indexOfScalar(u8, option_contents, '=')) |name_end| {
                const option_name = option_contents[0..name_end];
                const option_value = option_contents[name_end + 1 ..];
                if (try builder.addUserInputOption(option_name, option_value)) {
                    log.err("Option conflict '-D{s}'\n\n", .{option_name});
                    return error.InvalidArgs;
                }
            } else {
                const option_name = option_contents;
                if (try builder.addUserInputFlag(option_name)) {
                    log.err("Option conflict '-D{s}'\n\n", .{option_name});
                    return error.InvalidArgs;
                }
            }
        }
    }

    builder.resolveInstallPrefix(null, Builder.DirList{});
    try runBuild(builder);

    var packages = std.ArrayListUnmanaged(BuildConfig.Pkg){};
    defer packages.deinit(allocator);

    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};
    defer include_dirs.deinit(allocator);

    // This scans the graph of Steps to find all `OptionsStep`s then reifies them
    // Doing this before the loop to find packages ensures their `GeneratedFile`s have been given paths
    for (builder.top_level_steps.items) |tls| {
        for (tls.step.dependencies.items) |step| {
            try reifyOptions(step);
        }
    }

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
            .include_dirs = include_dirs.keys(),
        },
        .{ .whitespace = .{} },
        std.io.getStdOut().writer(),
    );
}

fn reifyOptions(step: *std.build.Step) anyerror!void {
    // Support Zig 0.9.1
    if (!@hasDecl(OptionsStep, "base_id")) return;

    if (step.cast(OptionsStep)) |option| {
        // We don't know how costly the dependency tree might be, so err on the side of caution
        if (step.dependencies.items.len == 0) {
            try option.step.make();
        }
    }

    for (step.dependencies.items) |unknown_step| {
        try reifyOptions(unknown_step);
    }
}

fn processStep(
    allocator: std.mem.Allocator,
    packages: *std.ArrayListUnmanaged(BuildConfig.Pkg),
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    step: *std.build.Step,
) anyerror!void {
    if (step.cast(InstallArtifactStep)) |install_exe| {
        if (install_exe.artifact.root_src) |src| {
            const maybe_path = switch (src) {
                .path => |path| path,
                .generated => |generated| generated.path,
            };
            if (maybe_path) |path| try packages.append(allocator, .{ .name = "root", .path = path });
        }

        try processIncludeDirs(allocator, include_dirs, install_exe.artifact.include_dirs.items);
        try processPkgConfig(allocator, include_dirs, install_exe.artifact);
        if (@hasField(LibExeObjStep, "modules")) {
            var modules_it = install_exe.artifact.modules.iterator();
            while (modules_it.next()) |module_entry| {
                try processModule(allocator, packages, module_entry);
            }
        } else { // assuming @hasField(LibExeObjStep, "packages")
            for (install_exe.artifact.packages.items) |pkg| {
                try processPackage(allocator, packages, pkg);
            }
        }
    } else if (step.cast(LibExeObjStep)) |exe| {
        if (exe.root_src) |src| {
            const maybe_path = switch (src) {
                .path => |path| path,
                .generated => |generated| generated.path,
            };
            if (maybe_path) |path| try packages.append(allocator, .{ .name = "root", .path = path });
        }
        try processIncludeDirs(allocator, include_dirs, exe.include_dirs.items);
        try processPkgConfig(allocator, include_dirs, exe);
        if (@hasField(LibExeObjStep, "modules")) {
            var modules_it = exe.modules.iterator();
            while (modules_it.next()) |module_entry| {
                try processModule(allocator, packages, module_entry);
            }
        } else { // assuming @hasField(LibExeObjStep, "packages")
            for (exe.packages.items) |pkg| {
                try processPackage(allocator, packages, pkg);
            }
        }
    } else {
        for (step.dependencies.items) |unknown_step| {
            try processStep(allocator, packages, include_dirs, unknown_step);
        }
    }
}

fn processModule(
    allocator: std.mem.Allocator,
    packages: *std.ArrayListUnmanaged(BuildConfig.Pkg),
    module: std.StringArrayHashMap(*std.Build.Module).Entry,
) !void {
    for (packages.items) |package| {
        if (std.mem.eql(u8, package.name, module.key_ptr.*)) return;
    }

    const maybe_path = switch (module.value_ptr.*.source_file) {
        .path => |path| path,
        .generated => |generated| generated.path,
    };

    if (maybe_path) |path| {
        try packages.append(allocator, .{ .name = module.key_ptr.*, .path = path });
    }

    var deps_it = module.value_ptr.*.dependencies.iterator();
    while (deps_it.next()) |module_dep| {
        try processModule(allocator, packages, module_dep);
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

    // Support Zig 0.9.1
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
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    dirs: []std.build.LibExeObjStep.IncludeDir,
) !void {
    try include_dirs.ensureUnusedCapacity(allocator, dirs.len);

    for (dirs) |dir| {
        const candidate: []const u8 = switch (dir) {
            .raw_path => |path| path,
            .raw_path_system => |path| path,
            else => continue,
        };

        include_dirs.putAssumeCapacity(candidate, {});
    }
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *std.build.LibExeObjStep,
) !void {
    for (exe.link_objects.items) |link_object| {
        if (link_object != .system_lib) continue;
        const system_lib = link_object.system_lib;

        // Support Zig 0.9.1
        if (@TypeOf(system_lib) == []const u8) return;

        if (system_lib.use_pkg_config == .no) continue;

        getPkgConfigIncludes(allocator, include_dirs, exe, system_lib.name) catch |err| switch (err) {
            error.PkgConfigInvalidOutput,
            error.PkgConfigCrashed,
            error.PkgConfigFailed,
            error.PkgConfigNotInstalled,
            error.PackageNotFound,
            => switch (system_lib.use_pkg_config) {
                .yes => {
                    // pkg-config failed, so zig will not add any include paths
                },
                .force => {
                    log.warn("pkg-config failed for library {s}", .{system_lib.name});
                },
                .no => unreachable,
            },
            else => |e| return e,
        };
    }
}

fn getPkgConfigIncludes(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *std.build.LibExeObjStep,
    name: []const u8,
) !void {
    if (exe.runPkgConfig(name)) |args| {
        for (args) |arg| {
            if (std.mem.startsWith(u8, arg, "-I")) {
                const candidate = arg[2..];
                try include_dirs.put(allocator, candidate, {});
            }
        }
    } else |err| return err;
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
