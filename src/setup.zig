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

fn print(comptime fmt: []const u8, args: anytype) void {
    const stdout = std.io.getStdOut().writer();
    stdout.print(fmt, args) catch @panic("Could not write to stdout");
}

fn write(text: []const u8) void {
    const stdout = std.io.getStdOut().writer();
    stdout.writeAll(text) catch @panic("Could not write to stdout");
}

pub fn wizard(allocator: std.mem.Allocator) !void {
    @setEvalBranchQuota(2500);
    write(
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

    if (global_path == null and local_path == null) {
        write("Could not open a global or local config directory.\n");
        return;
    }
    var config_path: []const u8 = undefined;
    if (try askBool("Should this configuration be system-wide?")) {
        if (global_path) |p| {
            config_path = p;
        } else {
            write("Could not find a global config directory.\n");
            return;
        }
    } else {
        if (local_path) |p| {
            config_path = p;
        } else {
            write("Could not find a local config directory.\n");
            return;
        }
    }
    var dir = std.fs.cwd().openDir(config_path, .{}) catch |err| {
        print("Could not open {s}: {}.\n", .{ config_path, err });
        return;
    };
    defer dir.close();
    var file = dir.createFile("zls.json", .{}) catch |err| {
        print("Could not create {s}/zls.json: {}.\n", .{ config_path, err });
        return;
    };
    defer file.close();
    const out = file.writer();

    var zig_exe_path = try findZig(allocator);
    defer if (zig_exe_path) |p| allocator.free(p);

    if (zig_exe_path) |path| {
        print("Found zig executable '{s}' in PATH.\n", .{path});
    } else {
        write("Could not find 'zig' in PATH\n");
        zig_exe_path = try askString(allocator, if (builtin.os.tag == .windows)
            \\What is the path to the 'zig' executable you would like to use?
            \\Note that due to a bug in zig (https://github.com/ziglang/zig/issues/6044),
            \\your zig directory cannot contain the '/' character.
        else
            "What is the path to the 'zig' executable you would like to use?", std.fs.MAX_PATH_BYTES);
    }

    const editor = try askSelectOne("Which code editor do you use?", enum { VSCode, Sublime, Kate, Neovim, Vim8, Emacs, Doom, Spacemacs, Other });
    const snippets = try askBool("Do you want to enable snippets?");
    const unused_variables = try askBool("Do you want to enable unused variable warnings?");
    const ief_apc = try askBool("Do you want to enable @import/@embedFile argument path completion?");
    const style = try askBool("Do you want to enable style warnings?");
    const semantic_tokens = try askBool("Do you want to enable semantic highlighting?");
    const inlay_hints = try askBool("Do you want to enable inlay hints?");
    const operator_completions = try askBool("Do you want to enable .* and .? completions?");
    const include_at_in_builtins = switch (editor) {
        .Sublime => true,
        .VSCode, .Kate, .Neovim, .Vim8, .Emacs, .Doom, .Spacemacs => false,
        else => try askBool("Should the @ sign be included in completions of builtin functions?\nChange this later if `@inc` completes to `include` or `@@include`"),
    };
    const max_detail_length: usize = switch (editor) {
        .Sublime => 256,
        else => 1024 * 1024,
    };

    std.debug.print("Writing config to {s}/zls.json ... ", .{config_path});

    try std.json.stringify(.{
        .zig_exe_path = zig_exe_path,
        .enable_snippets = snippets,
        .enable_unused_variable_warnings = unused_variables,
        .enable_import_embedfile_argument_completions = ief_apc,
        .warn_style = style,
        .enable_semantic_tokens = semantic_tokens,
        .enable_inlay_hints = inlay_hints,
        .operator_completions = operator_completions,
        .include_at_in_builtins = include_at_in_builtins,
        .max_detail_length = max_detail_length,
    }, .{}, out);

    write("successful.\n\n\n\n");

    // Keep synced with README.md
    switch (editor) {
        .VSCode => {
            write(
                \\To use ZLS in Visual Studio Code, install the 'ZLS for VSCode' extension from 
                \\'https://github.com/zigtools/zls-vscode/releases' or via the extensions menu.
                \\Then, open VSCode's 'settings.json' file, and add:
                \\
                \\"zls.path": "[command_or_path_to_zls]"
            );
        },
        .Sublime => {
            write(
                \\To use ZLS in Sublime, install the `LSP` package from 
                \\https://github.com/sublimelsp/LSP/releases or via Package Control.
                \\Then, add the following snippet to LSP's user settings:
                \\
                \\For Sublime Text 3:
                \\
                \\{
                \\  "clients": {
                \\    "zig": {
                \\      "command": ["zls"],
                \\      "enabled": true,
                \\      "languageId": "zig",
                \\      "scopes": ["source.zig"],
                \\      "syntaxes": ["Packages/Zig Language/Syntaxes/Zig.tmLanguage"]
                \\    }
                \\  }
                \\}
                \\
                \\For Sublime Text 4:
                \\
                \\{
                \\  "clients": {
                \\    "zig": {
                \\      "command": ["zls"],
                \\      "enabled": true,
                \\      "selector": "source.zig"
                \\    }
                \\  }
                \\}
            );
        },
        .Kate => {
            write(
                \\To use ZLS in Kate, enable `LSP client` plugin in Kate settings.
                \\Then, add the following snippet to `LSP client's` user settings:
                \\(or paste it in `LSP client's` GUI settings)
                \\
                \\{
                \\    "servers": {
                \\        "zig": {
                \\            "command": ["zls"],
                \\            "url": "https://github.com/zigtools/zls",
                \\            "highlightingModeRegex": "^Zig$"
                \\        }
                \\    }
                \\}
            );
        },
        .Neovim, .Vim8 => {
            write(
                \\To use ZLS in Neovim/Vim8, we recommend using CoC engine.
                \\You can get it from https://github.com/neoclide/coc.nvim.
                \\Then, simply issue cmd from Neovim/Vim8 `:CocConfig`, and add this to your CoC config:
                \\
                \\{
                \\  "languageserver": {
                \\    "zls" : {
                \\      "command": "command_or_path_to_zls",
                \\      "filetypes": ["zig"]
                \\    }
                \\  }
                \\}
            );
        },
        .Emacs => {
            write(
                \\To use ZLS in Emacs, install lsp-mode (https://github.com/emacs-lsp/lsp-mode) from melpa.
                \\Zig mode (https://github.com/ziglang/zig-mode) is also useful!
                \\Then, add the following to your emacs config:
                \\
                \\(require 'lsp-mode)
                \\(setq lsp-zig-zls-executable "<path to zls>")
            );
        },
        .Doom => {
            write(
                \\To use ZLS in Doom Emacs, enable the lsp module
                \\And install the `zig-mode` (https://github.com/ziglang/zig-mode)
                \\package by adding `(package! zig-mode)` to your packages.el file.
                \\
                \\(use-package! zig-mode
                \\  :hook ((zig-mode . lsp-deferred))
                \\  :custom (zig-format-on-save nil)
                \\  :config
                \\  (after! lsp-mode
                \\    (add-to-list 'lsp-language-id-configuration '(zig-mode . "zig"))
                \\    (lsp-register-client
                \\      (make-lsp-client
                \\        :new-connection (lsp-stdio-connection "<path to zls>")
                \\        :major-modes '(zig-mode)
                \\        :server-id 'zls))))
            );
        },
        .Spacemacs => {
            write(
                \\To use ZLS in Spacemacs, add the `lsp` and `zig` layers
                \\to `dotspacemacs-configuration-layers` in your .spacemacs file.
                \\Then, if you don't have `zls` in your PATH, add the following to
                \\`dotspacemacs/user-config` in your .spacemacs file:
                \\
                \\(setq lsp-zig-zls-executable "<path to zls>")
            );
        },
        .Other => {
            write(
                \\We might not *officially* support your editor, but you can definitely still use ZLS!
                \\Simply configure your editor for use with language servers and point it to the ZLS executable!
            );
        },
    }

    write("\n\nThank you for choosing ZLS!\n");
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
