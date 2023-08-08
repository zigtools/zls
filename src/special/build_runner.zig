const root = @import("@build");
const std = @import("std");
const log = std.log;
const process = std.process;

pub const dependencies = @import("@dependencies");

const Build = std.Build;

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

    const build_root_directory = Build.Cache.Directory{
        .path = build_root,
        .handle = try std.fs.cwd().openDir(build_root, .{}),
    };

    const local_cache_directory = Build.Cache.Directory{
        .path = cache_root,
        .handle = try std.fs.cwd().makeOpenPath(cache_root, .{}),
    };

    const global_cache_directory = Build.Cache.Directory{
        .path = global_cache_root,
        .handle = try std.fs.cwd().makeOpenPath(global_cache_root, .{}),
    };

    var cache = Build.Cache{
        .gpa = allocator,
        .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
    };

    cache.addPrefix(.{ .path = null, .handle = std.fs.cwd() });
    cache.addPrefix(build_root_directory);
    cache.addPrefix(local_cache_directory);
    cache.addPrefix(global_cache_directory);

    const host = try std.zig.system.NativeTargetInfo.detect(.{});

    const builder = try Build.create(
        allocator,
        zig_exe,
        build_root_directory,
        local_cache_directory,
        global_cache_directory,
        host,
        &cache,
    );

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

    builder.resolveInstallPrefix(null, Build.DirList{});
    try runBuild(builder);

    var packages = Packages{ .allocator = allocator };
    defer packages.deinit();

    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};
    defer include_dirs.deinit(allocator);

    // This scans the graph of Steps to find all `OptionsStep`s then reifies them
    // Doing this before the loop to find packages ensures their `GeneratedFile`s have been given paths
    for (builder.top_level_steps.values()) |tls| {
        for (tls.step.dependencies.items) |step| {
            try reifyOptions(step);
        }
    }

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.top_level_steps.values()) |tls| {
        for (tls.step.dependencies.items) |step| {
            try processStep(builder, &packages, &include_dirs, step);
        }
    }

    const package_list = try packages.toPackageList();
    defer allocator.free(package_list);

    try std.json.stringify(
        BuildConfig{
            .packages = package_list,
            .include_dirs = include_dirs.keys(),
        },
        .{},
        std.io.getStdOut().writer(),
    );
}

fn reifyOptions(step: *Build.Step) anyerror!void {
    if (step.cast(Build.Step.Options)) |option| {
        // We don't know how costly the dependency tree might be, so err on the side of caution
        if (step.dependencies.items.len == 0) {
            var progress: std.Progress = .{};
            const main_progress_node = progress.start("", 0);
            defer main_progress_node.end();

            try option.step.make(main_progress_node);
        }
    }

    for (step.dependencies.items) |unknown_step| {
        try reifyOptions(unknown_step);
    }
}

const Packages = struct {
    allocator: std.mem.Allocator,

    /// Outer key is the package name, inner key is the file path.
    packages: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .{},

    /// Returns true if the package was already present.
    pub fn addPackage(self: *Packages, name: []const u8, path: []const u8) !bool {
        const name_gop_result = try self.packages.getOrPut(self.allocator, name);
        if (!name_gop_result.found_existing) {
            name_gop_result.value_ptr.* = .{};
        }

        const path_gop_result = try name_gop_result.value_ptr.getOrPut(self.allocator, path);
        return path_gop_result.found_existing;
    }

    pub fn toPackageList(self: *Packages) ![]BuildConfig.Pkg {
        var result: std.ArrayListUnmanaged(BuildConfig.Pkg) = .{};
        errdefer result.deinit(self.allocator);

        var name_iter = self.packages.iterator();
        while (name_iter.next()) |path_hashmap| {
            var path_iter = path_hashmap.value_ptr.iterator();
            while (path_iter.next()) |path| {
                try result.append(self.allocator, .{ .name = path_hashmap.key_ptr.*, .path = path.key_ptr.* });
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    pub fn deinit(self: *Packages) void {
        var outer_iter = self.packages.iterator();
        while (outer_iter.next()) |inner| {
            inner.value_ptr.deinit(self.allocator);
        }
        self.packages.deinit(self.allocator);
    }
};

fn processStep(
    builder: *std.Build,
    packages: *Packages,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    step: *Build.Step,
) anyerror!void {
    if (step.cast(Build.Step.InstallArtifact)) |install_exe| {
        if (install_exe.artifact.root_src) |src| {
            if (copied_from_zig.getPath(src, builder)) |path| {
                _ = try packages.addPackage("root", path);
            }
        }
        try processIncludeDirs(builder, include_dirs, install_exe.artifact.include_dirs.items);
        try processPkgConfig(builder.allocator, include_dirs, install_exe.artifact);
        try processModules(builder, packages, install_exe.artifact.modules);
    } else if (step.cast(Build.Step.Compile)) |exe| {
        if (exe.root_src) |src| {
            if (copied_from_zig.getPath(src, builder)) |path| {
                _ = try packages.addPackage("root", path);
            }
        }
        try processIncludeDirs(builder, include_dirs, exe.include_dirs.items);
        try processPkgConfig(builder.allocator, include_dirs, exe);
        try processModules(builder, packages, exe.modules);
    } else {
        for (step.dependencies.items) |unknown_step| {
            try processStep(builder, packages, include_dirs, unknown_step);
        }
    }
}

fn processModules(
    builder: *Build,
    packages: *Packages,
    modules: std.StringArrayHashMap(*Build.Module),
) !void {
    for (modules.keys(), modules.values()) |name, mod| {
        const path = copied_from_zig.getPath(mod.source_file, mod.builder) orelse continue;

        const already_added = try packages.addPackage(name, path);
        // if the package has already been added short circuit here or recursive modules will ruin us
        if (already_added) continue;

        try processModules(builder, packages, mod.dependencies);
    }
}

fn processIncludeDirs(
    builder: *Build,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    dirs: []Build.Step.Compile.IncludeDir,
) !void {
    try include_dirs.ensureUnusedCapacity(builder.allocator, dirs.len);

    for (dirs) |dir| {
        const candidate: []const u8 = switch (dir) {
            .path => |path| copied_from_zig.getPath(path, builder) orelse continue,
            .path_system => |path| copied_from_zig.getPath(path, builder) orelse continue,
            else => continue,
        };

        include_dirs.putAssumeCapacity(candidate, {});
    }
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *Build.Step.Compile,
) !void {
    for (exe.link_objects.items) |link_object| {
        if (link_object != .system_lib) continue;
        const system_lib = link_object.system_lib;

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
    exe: *Build.Step.Compile,
    name: []const u8,
) !void {
    if (copied_from_zig.runPkgConfig(exe, name)) |args| {
        for (args) |arg| {
            if (std.mem.startsWith(u8, arg, "-I")) {
                const candidate = arg[2..];
                try include_dirs.put(allocator, candidate, {});
            }
        }
    } else |err| return err;
}

// TODO: Having a copy of this is not very nice
const copied_from_zig = struct {
    /// Copied from `std.Build.LazyPath.getPath2` and massaged a bit.
    fn getPath(path: std.Build.LazyPath, builder: *Build) ?[]const u8 {
        switch (path) {
            .path => |p| return builder.pathFromRoot(p),
            .cwd_relative => |p| return pathFromCwd(builder, p),
            .generated => |gen| return builder.pathFromRoot(gen.path orelse return null),
        }
    }

    /// Copied from `std.Build.pathFromCwd` as it is non-pub.
    fn pathFromCwd(b: *Build, p: []const u8) []u8 {
        const cwd = process.getCwdAlloc(b.allocator) catch @panic("OOM");
        return std.fs.path.resolve(b.allocator, &.{ cwd, p }) catch @panic("OOM");
    }

    fn runPkgConfig(self: *Build.Step.Compile, lib_name: []const u8) ![]const []const u8 {
        const b = self.step.owner;
        const pkg_name = match: {
            // First we have to map the library name to pkg config name. Unfortunately,
            // there are several examples where this is not straightforward:
            // -lSDL2 -> pkg-config sdl2
            // -lgdk-3 -> pkg-config gdk-3.0
            // -latk-1.0 -> pkg-config atk
            const pkgs = try getPkgConfigList(b);

            // Exact match means instant winner.
            for (pkgs) |pkg| {
                if (std.mem.eql(u8, pkg.name, lib_name)) {
                    break :match pkg.name;
                }
            }

            // Next we'll try ignoring case.
            for (pkgs) |pkg| {
                if (std.ascii.eqlIgnoreCase(pkg.name, lib_name)) {
                    break :match pkg.name;
                }
            }

            // Now try appending ".0".
            for (pkgs) |pkg| {
                if (std.ascii.indexOfIgnoreCase(pkg.name, lib_name)) |pos| {
                    if (pos != 0) continue;
                    if (std.mem.eql(u8, pkg.name[lib_name.len..], ".0")) {
                        break :match pkg.name;
                    }
                }
            }

            // Trimming "-1.0".
            if (std.mem.endsWith(u8, lib_name, "-1.0")) {
                const trimmed_lib_name = lib_name[0 .. lib_name.len - "-1.0".len];
                for (pkgs) |pkg| {
                    if (std.ascii.eqlIgnoreCase(pkg.name, trimmed_lib_name)) {
                        break :match pkg.name;
                    }
                }
            }

            return error.PackageNotFound;
        };

        var code: u8 = undefined;
        const stdout = if (b.execAllowFail(&[_][]const u8{
            "pkg-config",
            pkg_name,
            "--cflags",
            "--libs",
        }, &code, .Ignore)) |stdout| stdout else |err| switch (err) {
            error.ProcessTerminated => return error.PkgConfigCrashed,
            error.ExecNotSupported => return error.PkgConfigFailed,
            error.ExitCodeFailure => return error.PkgConfigFailed,
            error.FileNotFound => return error.PkgConfigNotInstalled,
            else => return err,
        };

        var zig_args = std.ArrayList([]const u8).init(b.allocator);
        defer zig_args.deinit();

        var it = std.mem.tokenize(u8, stdout, " \r\n\t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "-I")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-I", dir });
            } else if (std.mem.startsWith(u8, tok, "-I")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-L")) {
                const dir = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-L", dir });
            } else if (std.mem.startsWith(u8, tok, "-L")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-l")) {
                const lib = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-l", lib });
            } else if (std.mem.startsWith(u8, tok, "-l")) {
                try zig_args.append(tok);
            } else if (std.mem.eql(u8, tok, "-D")) {
                const macro = it.next() orelse return error.PkgConfigInvalidOutput;
                try zig_args.appendSlice(&[_][]const u8{ "-D", macro });
            } else if (std.mem.startsWith(u8, tok, "-D")) {
                try zig_args.append(tok);
            } else if (b.debug_pkg_config) {
                return self.step.fail("unknown pkg-config flag '{s}'", .{tok});
            }
        }

        return zig_args.toOwnedSlice();
    }

    fn execPkgConfigList(self: *std.Build, out_code: *u8) (PkgConfigError || ExecError)![]const PkgConfigPkg {
        const stdout = try self.execAllowFail(&[_][]const u8{ "pkg-config", "--list-all" }, out_code, .Ignore);
        var list = std.ArrayList(PkgConfigPkg).init(self.allocator);
        errdefer list.deinit();
        var line_it = std.mem.tokenize(u8, stdout, "\r\n");
        while (line_it.next()) |line| {
            if (std.mem.trim(u8, line, " \t").len == 0) continue;
            var tok_it = std.mem.tokenize(u8, line, " \t");
            try list.append(PkgConfigPkg{
                .name = tok_it.next() orelse return error.PkgConfigInvalidOutput,
                .desc = tok_it.rest(),
            });
        }
        return list.toOwnedSlice();
    }

    fn getPkgConfigList(self: *std.Build) ![]const PkgConfigPkg {
        if (self.pkg_config_pkg_list) |res| {
            return res;
        }
        var code: u8 = undefined;
        if (execPkgConfigList(self, &code)) |list| {
            self.pkg_config_pkg_list = list;
            return list;
        } else |err| {
            const result = switch (err) {
                error.ProcessTerminated => error.PkgConfigCrashed,
                error.ExecNotSupported => error.PkgConfigFailed,
                error.ExitCodeFailure => error.PkgConfigFailed,
                error.FileNotFound => error.PkgConfigNotInstalled,
                error.InvalidName => error.PkgConfigNotInstalled,
                error.PkgConfigInvalidOutput => error.PkgConfigInvalidOutput,
                else => return err,
            };
            self.pkg_config_pkg_list = result;
            return result;
        }
    }

    pub const ExecError = std.Build.ExecError;
    pub const PkgConfigError = std.Build.PkgConfigError;
    pub const PkgConfigPkg = std.Build.PkgConfigPkg;
};

fn runBuild(builder: *Build) anyerror!void {
    switch (@typeInfo(@typeInfo(@TypeOf(root.build)).Fn.return_type.?)) {
        .Void => root.build(builder),
        .ErrorUnion => try root.build(builder),
        else => @compileError("expected return type of build to be 'void' or '!void'"),
    }
}

fn nextArg(args: [][:0]const u8, idx: *usize) ?[:0]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}
