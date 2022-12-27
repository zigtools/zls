const std = @import("std");
const builtin = @import("builtin");
const known_folders = @import("known-folders");

/// Caller must free memory.
pub fn askString(allocator: std.mem.Allocator, prompt: []const u8, max_size: usize) ![]u8 {
    const in = std.io.getStdIn().reader();
    const out = std.io.getStdOut().writer();

    try out.print("? {s}", .{prompt});

    const result = try in.readUntilDelimiterAlloc(allocator, '\n', max_size);
    return if (std.mem.endsWith(u8, result, "\r")) result[0..(result.len - 1)] else result;
}

/// Caller must free memory. Max size is recommended to be a high value, like 512.
pub fn askDirPath(allocator: std.mem.Allocator, prompt: []const u8, max_size: usize) ![]u8 {
    const out = std.io.getStdOut().writer();

    while (true) {
        const path = try askString(allocator, prompt, max_size);
        if (!std.fs.path.isAbsolute(path)) {
            try out.writeAll("Error: Invalid directory, please try again.\n\n");
            allocator.free(path);
            continue;
        }

        var dir = std.fs.cwd().openDir(path, std.fs.Dir.OpenDirOptions{}) catch {
            try out.writeAll("Error: Invalid directory, please try again.\n\n");
            allocator.free(path);
            continue;
        };

        dir.close();
        return path;
    }
}

pub fn askBool(prompt: []const u8) !bool {
    const in = std.io.getStdIn().reader();
    const out = std.io.getStdOut().writer();

    var buffer: [1]u8 = undefined;

    while (true) {
        try out.print("? {s} (y/n) > ", .{prompt});

        const read = in.read(&buffer) catch continue;
        try in.skipUntilDelimiterOrEof('\n');

        if (read == 0) return error.EndOfStream;

        switch (buffer[0]) {
            'y' => return true,
            'n' => return false,
            else => continue,
        }
    }
}

pub fn askSelectOne(prompt: []const u8, comptime Options: type) !Options {
    const in = std.io.getStdIn().reader();
    const out = std.io.getStdOut().writer();

    try out.print("? {s} (select one)\n\n", .{prompt});

    comptime var max_size: usize = 0;
    inline for (@typeInfo(Options).Enum.fields) |option| {
        try out.print("  - {s}\n", .{option.name});
        if (option.name.len > max_size) max_size = option.name.len;
    }

    while (true) {
        var buffer: [max_size + 1]u8 = undefined;

        try out.writeAll("\n> ");

        var result = (in.readUntilDelimiterOrEof(&buffer, '\n') catch {
            try in.skipUntilDelimiterOrEof('\n');
            try out.writeAll("Error: Invalid option, please try again.\n");
            continue;
        }) orelse return error.EndOfStream;
        result = if (std.mem.endsWith(u8, result, "\r")) result[0..(result.len - 1)] else result;

        inline for (@typeInfo(Options).Enum.fields) |option|
            if (std.ascii.eqlIgnoreCase(option.name, result))
                return @intToEnum(Options, option.value);

        try out.writeAll("Error: Invalid option, please try again.\n");
    }
}

pub fn wizard(allocator: std.mem.Allocator) !void {
    @setEvalBranchQuota(2500);
    const stdout = std.io.getStdOut().writer();

    try stdout.writeAll(
        \\Welcome to the ZLS configuration wizard!
        \\      *
        \\       |\
        \\      /* \
        \\      |  *\
        \\    _/_*___|_    x
        \\      | @ @     /
        \\     @     \   /
        \\      \__-/   /
        \\
        \\
    );

    var local_path = known_folders.getPath(allocator, .local_configuration) catch null;
    var global_path = known_folders.getPath(allocator, .global_configuration) catch null;
    defer if (local_path) |d| allocator.free(d);
    defer if (global_path) |d| allocator.free(d);

    const can_access_global = blk: {
        std.fs.accessAbsolute(global_path orelse break :blk false, .{}) catch break :blk false;
        break :blk true;
    };

    if (global_path == null and local_path == null) {
        try stdout.writeAll("Could not open a global or local config directory.\n");
        return;
    }
    var config_path: []const u8 = undefined;
    if (can_access_global and try askBool("Should this configuration be system-wide?")) {
        config_path = global_path.?;
    } else {
        if (local_path) |p| {
            config_path = p;
        } else {
            try stdout.writeAll("Could not find a local config directory.\n");
            return;
        }
    }
    var dir = std.fs.cwd().openDir(config_path, .{}) catch |err| {
        try stdout.print("Could not open {s}: {}.\n", .{ config_path, err });
        return;
    };
    defer dir.close();
    var file = dir.createFile("zls.json", .{}) catch |err| {
        try stdout.print("Could not create {s}/zls.json: {}.\n", .{ config_path, err });
        return;
    };
    defer file.close();
    const out = file.writer();

    var zig_exe_path = try findZig(allocator);
    defer if (zig_exe_path) |p| allocator.free(p);

    if (zig_exe_path) |path| {
        try stdout.print("Found zig executable '{s}' in PATH.\n", .{path});
    } else {
        try stdout.writeAll("Could not find 'zig' in PATH\n");
        zig_exe_path = try askString(allocator, if (builtin.os.tag == .windows)
            \\What is the path to the 'zig' executable you would like to use?
            \\Note that due to a bug in zig (https://github.com/ziglang/zig/issues/6044),
            \\your zig directory cannot contain the '/' character.
        else
            "What is the path to the 'zig' executable you would like to use?", std.fs.MAX_PATH_BYTES);
    }

    const snippets = try askBool("Do you want to enable snippets?");
    const ast_check = try askBool("Do you want to enable ast-check diagnostics?");
    const autofix = try askBool("Do you want to zls to automatically try to fix errors on save? (supports adding & removing discards)");
    const ief_apc = try askBool("Do you want to enable @import/@embedFile argument path completion?");
    const style = try askBool("Do you want to enable style warnings?");
    const semantic_tokens = try askBool("Do you want to enable semantic highlighting?");
    const inlay_hints = try askBool("Do you want to enable inlay hints?");
    const operator_completions = try askBool("Do you want to enable .* and .? completions?");

    std.debug.print("Writing config to {s}/zls.json ... ", .{config_path});

    try std.json.stringify(.{
        .@"$schema" = "https://raw.githubusercontent.com/zigtools/zls/master/schema.json",
        .zig_exe_path = zig_exe_path,
        .enable_snippets = snippets,
        .enable_ast_check_diagnostics = ast_check,
        .enable_autofix = autofix,
        .enable_import_embedfile_argument_completions = ief_apc,
        .warn_style = style,
        .enable_semantic_tokens = semantic_tokens,
        .enable_inlay_hints = inlay_hints,
        .operator_completions = operator_completions,
    }, .{
        .whitespace = .{},
    }, out);

    try stdout.writeAll(
        \\successful.
        \\
        \\You can find information on how to setup zls for your editor on zigtools.github.io/install-zls/
        \\
        \\Thank you for choosing ZLS!
        \\
    );
}

pub fn findZig(allocator: std.mem.Allocator) !?[]const u8 {
    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            return null;
        },
        else => return err,
    };
    defer allocator.free(env_path);

    const exe_extension = builtin.target.exeFileExt();
    const zig_exe = try std.fmt.allocPrint(allocator, "zig{s}", .{exe_extension});
    defer allocator.free(zig_exe);

    var it = std.mem.tokenize(u8, env_path, &[_]u8{std.fs.path.delimiter});
    while (it.next()) |path| {
        if (builtin.os.tag == .windows) {
            if (std.mem.indexOfScalar(u8, path, '/') != null) continue;
        }
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, zig_exe });
        defer allocator.free(full_path);

        if (!std.fs.path.isAbsolute(full_path)) continue;

        const file = std.fs.openFileAbsolute(full_path, .{}) catch continue;
        defer file.close();
        const stat = file.stat() catch continue;
        if (stat.kind == .Directory) continue;

        return try allocator.dupe(u8, full_path);
    }
    return null;
}
