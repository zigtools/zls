const root = @import("@build");
const std = @import("std");
const log = std.log;
const process = std.process;
const builtin = @import("builtin");

const BuildConfig = @import("BuildConfig.zig");

pub const dependencies = @import("@dependencies");

const Build = std.Build;

///! This is a modified build runner to extract information out of build.zig
///! Modified version of lib/build_runner.zig
pub fn main() !void {
    // Here we use an ArenaAllocator backed by a DirectAllocator because a build is a short-lived,
    // one shot program. We don't need to waste time freeing memory and finding places to squish
    // bytes into. So we free everything all at once at the very end.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try process.argsAlloc(allocator);

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

    var graph: std.Build.Graph = .{
        .arena = allocator,
        .cache = .{
            .gpa = allocator,
            .manifest_dir = try local_cache_directory.handle.makeOpenPath("h", .{}),
        },
        .zig_exe = zig_exe,
        .env_map = try process.getEnvMap(allocator),
        .global_cache_root = global_cache_directory,
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolveTargetQuery(.{}),
        },
    };

    graph.cache.addPrefix(.{ .path = null, .handle = std.fs.cwd() });
    graph.cache.addPrefix(build_root_directory);
    graph.cache.addPrefix(local_cache_directory);
    graph.cache.addPrefix(global_cache_directory);
    graph.cache.hash.addBytes(builtin.zig_version_string);

    const builder = try Build.create(
        &graph,
        build_root_directory,
        local_cache_directory,
        dependencies.root_deps,
    );

    var output_tmp_nonce: ?[16]u8 = null;

    while (nextArg(args, &arg_idx)) |arg| {
        if (std.mem.startsWith(u8, arg, "-Z")) {
            if (arg.len != 18) {
                log.err("bad argument: '{s}'", .{arg});
                return error.InvalidArgs;
            }
            output_tmp_nonce = arg[2..18].*;
        } else if (std.mem.startsWith(u8, arg, "-D")) {
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
        } else if (std.mem.eql(u8, arg, "--zig-lib-dir")) {
            const zig_lib_dir = nextArg(args, &arg_idx) orelse {
                log.err("Expected argument after '{s}'", .{arg});
                return error.InvalidArgs;
            };
            builder.zig_lib_dir = .{ .cwd_relative = zig_lib_dir };
        }
    }

    builder.resolveInstallPrefix(null, Build.DirList{});
    try runBuild(builder);

    if (graph.needed_lazy_dependencies.entries.len != 0) {
        var buffer: std.ArrayListUnmanaged(u8) = .{};
        for (graph.needed_lazy_dependencies.keys()) |k| {
            try buffer.appendSlice(allocator, k);
            try buffer.append(allocator, '\n');
        }
        const s = std.fs.path.sep_str;
        const tmp_sub_path = "tmp" ++ s ++ (output_tmp_nonce orelse std.debug.panic("missing -Z arg", .{}));
        local_cache_directory.handle.writeFile2(.{
            .sub_path = tmp_sub_path,
            .data = buffer.items,
            .flags = .{ .exclusive = true },
        }) catch |err| {
            std.debug.panic("unable to write configuration results to '{}{s}': {s}", .{
                local_cache_directory, tmp_sub_path, @errorName(err),
            });
        };
        process.exit(3); // Indicate configure phase failed with meaningful stdout.
    }

    var packages = Packages{ .allocator = allocator };
    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};

    // This scans the graph of Steps to find all `OptionsStep`s and installed headers then reifies them
    // Doing this before the loop to find packages ensures their `GeneratedFile`s have been given paths
    for (builder.top_level_steps.values()) |tls| {
        for (tls.step.dependencies.items) |step| {
            try reifySteps(step);
        }
    }

    // TODO: We currently add packages from every LibExeObj step that the install step depends on.
    //       Should we error out or keep one step or something similar?
    // We also flatten them, we should probably keep the nested structure.
    for (builder.top_level_steps.values()) |tls| {
        for (tls.step.dependencies.items) |step| {
            try processStep(step, &packages, &include_dirs);
        }
    }

    // Sample `@dependencies` structure:
    // pub const packages = struct {
    //     pub const @"1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5" = struct {
    //         pub const build_root = "/home/rad/.cache/zig/p/1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5";
    //         pub const build_zig = @import("1220363c7e27b2d3f39de6ff6e90f9537a0634199860fea237a55ddb1e1717f5d6a5");
    //         pub const deps: []const struct { []const u8, []const u8 } = &.{};
    //     };
    // ...
    // };
    // pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    //     .{ "known_folders", "1220bb12c9bfe291eed1afe6a2070c7c39918ab1979f24a281bba39dfb23f5bcd544" },
    //     .{ "diffz", "122089a8247a693cad53beb161bde6c30f71376cd4298798d45b32740c3581405864" },
    // };

    var deps_build_roots: std.ArrayListUnmanaged(BuildConfig.DepsBuildRoots) = .{};
    for (dependencies.root_deps) |root_dep| {
        inline for (@typeInfo(dependencies.packages).Struct.decls) |package| blk: {
            if (std.mem.eql(u8, package.name, root_dep[1])) {
                const package_info = @field(dependencies.packages, package.name);
                if (!@hasDecl(package_info, "build_root")) break :blk;
                if (!@hasDecl(package_info, "build_zig")) break :blk;
                try deps_build_roots.append(allocator, .{
                    .name = root_dep[0],
                    .path = try std.fs.path.resolve(allocator, &[_][]const u8{ package_info.build_root, "./build.zig" }),
                });
            }
        }
    }

    try std.json.stringify(
        BuildConfig{
            .deps_build_roots = try deps_build_roots.toOwnedSlice(allocator),
            .packages = try packages.toPackageList(),
            .include_dirs = include_dirs.keys(),
        },
        .{
            .whitespace = .indent_1,
        },
        std.io.getStdOut().writer(),
    );
}

fn makeStep(step: *Build.Step) anyerror!void {
    // dependency loop detection and make phase merged into one.
    switch (step.state) {
        .precheck_started => return, // dependency loop
        .precheck_unstarted => {
            step.state = .precheck_started;

            for (step.dependencies.items) |unknown_step| {
                try makeStep(unknown_step);
            }

            var progress: std.Progress = .{};
            const main_progress_node = progress.start("", 0);
            defer main_progress_node.end();

            try step.make(main_progress_node);

            step.state = .precheck_done;
        },
        .precheck_done => {},

        .dependency_failure,
        .running,
        .success,
        .failure,
        .skipped,
        .skipped_oom,
        => {},
    }
}

fn reifySteps(step: *Build.Step) anyerror!void {
    if (step.cast(Build.Step.Options)) |option| {
        // We don't know how costly the dependency tree might be, so err on the side of caution
        if (step.dependencies.items.len == 0) {
            var progress: std.Progress = .{};
            const main_progress_node = progress.start("", 0);
            defer main_progress_node.end();

            try option.step.make(main_progress_node);
        }
    }

    if (step.cast(Build.Step.Compile)) |compile| {
        if (compile.generated_h) |header| {
            try makeStep(header.step);
        }
        if (compile.installed_headers_include_tree) |include_tree| {
            try makeStep(include_tree.generated_directory.step);
        }
    }

    for (step.dependencies.items) |unknown_step| {
        try reifySteps(unknown_step);
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
    step: *Build.Step,
    packages: *Packages,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
) anyerror!void {
    for (step.dependencies.items) |dependant_step| {
        try processStep(dependant_step, packages, include_dirs);
    }

    const exe = blk: {
        if (step.cast(Build.Step.InstallArtifact)) |install_exe| break :blk install_exe.artifact;
        if (step.cast(Build.Step.Compile)) |exe| break :blk exe;
        return;
    };

    try processPkgConfig(step.owner.allocator, include_dirs, exe);

    if (exe.root_module.root_source_file) |src| {
        if (copied_from_zig.getPath(src, exe.root_module.owner)) |path| {
            _ = try packages.addPackage("root", path);
        }
    }
    try processModule(exe.root_module, packages, include_dirs);
}

fn processModule(
    module: Build.Module,
    packages: *Packages,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
) anyerror!void {
    try processModuleIncludeDirs(module, include_dirs);

    for (module.import_table.keys(), module.import_table.values()) |name, mod| {
        const path = copied_from_zig.getPath(
            mod.root_source_file orelse continue,
            mod.owner,
        ) orelse continue;

        const already_added = try packages.addPackage(name, path);
        // if the package has already been added short circuit here or recursive modules will ruin us
        if (already_added) continue;

        try processModule(mod.*, packages, include_dirs);
    }
}

fn processModuleIncludeDirs(
    module: Build.Module,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
) !void {
    for (module.include_dirs.items) |dir| {
        switch (dir) {
            .path, .path_system, .path_after => |path| {
                const resolved_path = copied_from_zig.getPath(path, module.owner) orelse continue;
                try include_dirs.put(module.owner.allocator, resolved_path, {});
            },
            .other_step => |other_step| {
                if (other_step.generated_h) |header| {
                    if (header.path) |path| {
                        try include_dirs.put(module.owner.allocator, std.fs.path.dirname(path).?, {});
                    }
                }
                if (other_step.installed_headers_include_tree) |include_tree| {
                    if (include_tree.generated_directory.path) |path| {
                        try include_dirs.put(module.owner.allocator, path, {});
                    }
                }
            },
            .config_header_step => |config_header| {
                const full_file_path = config_header.output_file.path orelse continue;
                const header_dir_path = full_file_path[0 .. full_file_path.len - config_header.include_path.len];
                try include_dirs.put(module.owner.allocator, header_dir_path, {});
            },
            .framework_path, .framework_path_system => {},
        }
    }
}

fn processPkgConfig(
    allocator: std.mem.Allocator,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    exe: *Build.Step.Compile,
) !void {
    for (exe.root_module.link_objects.items) |link_object| {
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

fn reify(step: *Build.Step) anyerror!void {
    var progress: std.Progress = .{};
    const main_progress_node = progress.start("", 0);
    defer main_progress_node.end();

    for (step.dependencies.items) |unknown_step| {
        try reify(unknown_step);
    }

    try step.make(main_progress_node);
}

// TODO: Having a copy of this is not very nice
const copied_from_zig = struct {
    /// Copied from `std.Build.LazyPath.getPath2` and massaged a bit.
    fn getPath(path: std.Build.LazyPath, builder: *Build) ?[]const u8 {
        switch (path) {
            .path => |p| return builder.pathFromRoot(p),
            .src_path => |sp| return sp.owner.pathFromRoot(sp.sub_path),
            .cwd_relative => |p| return pathFromCwd(builder, p),
            .generated => |gen| {
                if (gen.path) |gen_path|
                    return builder.pathFromRoot(gen_path)
                else {
                    reify(gen.step) catch return null;
                    if (gen.path) |gen_path|
                        return builder.pathFromRoot(gen_path)
                    else
                        return null;
                }
            },
            .generated_dirname => |gen| {
                var dirname = getPath(.{ .generated = gen.generated }, builder) orelse return null;
                var i: usize = 0;
                while (i <= gen.up) : (i += 1) {
                    dirname = std.fs.path.dirname(dirname) orelse return null;
                }
                return dirname;
            },
            .dependency => |dep| return dep.dependency.builder.pathJoin(&[_][]const u8{
                dep.dependency.builder.build_root.path.?,
                dep.sub_path,
            }),
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
        const stdout = if (b.runAllowFail(&[_][]const u8{
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

    fn execPkgConfigList(self: *std.Build, out_code: *u8) (PkgConfigError || RunError)![]const PkgConfigPkg {
        const stdout = try self.runAllowFail(&[_][]const u8{ "pkg-config", "--list-all" }, out_code, .Ignore);
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

    pub const RunError = std.Build.RunError;
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
