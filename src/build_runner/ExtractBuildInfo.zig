//! Build step to extract build info for ZLS
//!
//! Simply depend on the steps you want ZLS
//! to draw information from and then invoke
//! this step somewhere (we recommend adding it
//! your install step so ZLS is always synced
//! with the latest build)
//!
//! See https://github.com/zigtools/zls-as-step-demo

const ExtractBuildInfo = @This();
const std = @import("std");
const Build = std.Build;
const Step = Build.Step;
const fs = std.fs;
const mem = std.mem;
const BuildConfig = @import("BuildConfig.zig");
const Packages = @import("Packages.zig");

const build_runner = @import("root");
const dependencies = build_runner.dependencies;

step: Step,

pub const base_id = .custom;

pub fn create(owner: *Build) *ExtractBuildInfo {
    const self = owner.allocator.create(ExtractBuildInfo) catch @panic("OOM");
    self.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "ExtractBuildInfo",
            .owner = owner,
            .makeFn = make,
        }),
    };
    return self;
}

fn processStep(
    builder: *std.Build,
    packages: *Packages,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    step: *Build.Step,
) anyerror!void {
    for (step.dependencies.items) |dependant_step| {
        try processStep(builder, packages, include_dirs, dependant_step);
    }

    const exe = blk: {
        if (step.cast(Build.Step.InstallArtifact)) |install_exe| break :blk install_exe.artifact;
        if (step.cast(Build.Step.Compile)) |exe| break :blk exe;
        return;
    };

    if (exe.root_src) |src| {
        _ = try packages.addPackage("root", src.getPath(builder));
    }
    try processIncludeDirs(builder, include_dirs, exe.include_dirs.items);
    // TODO // try processPkgConfig(builder.allocator, include_dirs, exe);
    try processModules(builder, packages, exe.modules);
}

fn processIncludeDirs(
    builder: *Build,
    include_dirs: *std.StringArrayHashMapUnmanaged(void),
    dirs: []Build.Step.Compile.IncludeDir,
) !void {
    for (dirs) |dir| {
        switch (dir) {
            .path, .path_system, .path_after => |path| {
                try include_dirs.put(builder.allocator, path.getPath(builder), {});
            },
            .other_step => |other_step| {
                if (other_step.generated_h) |header| {
                    if (header.path) |path| {
                        try include_dirs.put(builder.allocator, std.fs.path.dirname(path).?, {});
                    }
                }
                if (other_step.installed_headers.items.len > 0) {
                    const path = builder.pathJoin(&.{
                        other_step.step.owner.install_prefix, "include",
                    });
                    try include_dirs.put(builder.allocator, path, {});
                }
            },
            .config_header_step => |config_header| {
                const full_file_path = config_header.output_file.path orelse continue;
                const header_dir_path = full_file_path[0 .. full_file_path.len - config_header.include_path.len];
                try include_dirs.put(builder.allocator, header_dir_path, {});
            },
            .framework_path, .framework_path_system => {},
        }
    }
}

fn processModules(
    builder: *Build,
    packages: *Packages,
    modules: std.StringArrayHashMap(*Build.Module),
) !void {
    for (modules.keys(), modules.values()) |name, mod| {
        const already_added = try packages.addPackage(name, mod.source_file.getPath(mod.builder));
        // if the package has already been added short circuit here or recursive modules will ruin us
        if (already_added) continue;

        try processModules(builder, packages, mod.dependencies);
    }
}

fn make(step: *Step, prog_node: *std.Progress.Node) !void {
    _ = prog_node;
    const b = step.owner;

    var packages = Packages{ .allocator = b.allocator };
    var include_dirs: std.StringArrayHashMapUnmanaged(void) = .{};

    var deps_build_roots: std.ArrayListUnmanaged(BuildConfig.DepsBuildRoots) = .{};
    for (dependencies.root_deps) |root_dep| {
        inline for (@typeInfo(dependencies.packages).Struct.decls) |package| {
            if (std.mem.eql(u8, package.name, root_dep[1])) {
                const package_info = @field(dependencies.packages, package.name);
                if (!@hasDecl(package_info, "build_root")) continue;
                try deps_build_roots.append(b.allocator, .{
                    .name = root_dep[0],
                    // XXX Check if it exists?
                    .path = try std.fs.path.resolve(b.allocator, &[_][]const u8{ package_info.build_root, "./build.zig" }),
                });
            }
        }
    }

    try processStep(step.owner, &packages, &include_dirs, step);

    var out = try std.fs.createFileAbsolute(try b.cache_root.join(b.allocator, &.{"zls-build-info.json"}), .{});
    defer out.close();

    var bufw = std.io.bufferedWriter(out.writer());

    try std.json.stringify(
        BuildConfig{
            .deps_build_roots = try deps_build_roots.toOwnedSlice(b.allocator),
            .packages = try packages.toPackageList(),
            .include_dirs = include_dirs.keys(),
        },
        .{
            .whitespace = .indent_1,
        },
        bufw.writer(),
    );
    try bufw.flush();
}
