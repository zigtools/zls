const std = @import("std");
const zinput = @import("zinput/src/main.zig");
const known_folders = @import("known-folders");

fn print(comptime fmt: []const u8, args: anytype) void {
    const stdout = std.io.getStdOut().writer();
    stdout.print(fmt, args) catch @panic("Could not write to stdout");
}

fn write(text: []const u8) void {
    const stdout = std.io.getStdOut().writer();
    stdout.writeAll(text) catch @panic("Could not write to stdout");
}

pub fn wizard(allocator: *std.mem.Allocator) !void {
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
    if (try zinput.askBool("Should this configuration be system-wide?")) {
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
        print("Could not open {s}: {}.\n", .{config_path, err});
        return;
    };
    defer dir.close();
    var file = dir.createFile("zls.json", .{}) catch |err| {
        print("Could not create {s}/zls.json: {}.\n", .{config_path, err});
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
        zig_exe_path = try zinput.askString(allocator, 
            if (std.builtin.os.tag == .windows) 
                \\What is the path to the 'zig' executable you would like to use?
                \\Note that due to a bug in zig (https://github.com/ziglang/zig/issues/6044),
                \\your zig directory cannot contain the '/' character.
            else
                "What is the path to the 'zig' executable you would like to use?",
            std.fs.MAX_PATH_BYTES);
    }

    const editor = try zinput.askSelectOne("Which code editor do you use?", enum { VSCode, Sublime, Kate, Neovim, Vim8, Emacs, Doom, Other });
    const snippets = try zinput.askBool("Do you want to enable snippets?");
    const style = try zinput.askBool("Do you want to enable style warnings?");
    const semantic_tokens = try zinput.askBool("Do you want to enable semantic highlighting?");
    const operator_completions = try zinput.askBool("Do you want to enable .* and .? completions?");
    const include_at_in_builtins = switch (editor) {
        .Sublime => true,
        .VSCode, .Kate, .Neovim, .Vim8, .Emacs, .Doom => false,
        else => try zinput.askBool("Should the @ sign be included in completions of builtin functions?\nChange this later if `@inc` completes to `include` or `@@include`"),
    };
    const max_detail_length: usize = switch (editor) {
        .Sublime => 256,
        else => 1024 * 1024,
    };

    std.debug.warn("Writing config to {s}/zls.json ... ", .{config_path});

    const content = std.json.stringify(.{
        .zig_exe_path = zig_exe_path,
        .enable_snippets = snippets,
        .warn_style = style,
        .enable_semantic_tokens = semantic_tokens,
        .operator_completions = operator_completions,
        .include_at_in_builtins = include_at_in_builtins,
        .max_detail_length = max_detail_length,
    }, std.json.StringifyOptions{}, out);

    write("successful.\n\n\n\n");


    // Keep synced with README.md
    switch (editor) {
        .VSCode => {
            write(
                \\To use ZLS in Visual Studio Code, install the 'ZLS for VSCode' extension from 
                \\'https://github.com/zigtools/zls-vscode/releases' or via the extensions menu.
                \\Then, open VSCode's 'settings.json' file, and add:
                \\
                \\"zigLanguageClient.path": "[command_or_path_to_zls]"
            );
        },
        .Sublime => {
            write(
                \\To use ZLS in Sublime, install the `LSP` package from 
                \\https://github.com/sublimelsp/LSP/releases or via Package Control.
                \\Then, add the following snippet to LSP's user settings:
                \\
                \\{
                \\  "clients": {
                \\    "zig": {
                \\      "command": ["zls"],
                \\      "enabled": true,
                \\      "languageId": "zig",
                \\      "scopes": ["source.zig"],
                \\      "syntaxes": ["Packages/Zig/Syntaxes/Zig.tmLanguage"]
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
        .Other => {
            write(
                \\We might not *officially* support your editor, but you can definitely still use ZLS!
                \\Simply configure your editor for use with language servers and point it to the ZLS executable!
            );
        },
    }

    write("\n\nThank you for choosing ZLS!\n");
}

pub fn findZig(allocator: *std.mem.Allocator) !?[]const u8 {
    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            return null;
        },
        else => return err,
    };
    defer allocator.free(env_path);

    const exe_extension = std.Target.current.exeFileExt();
    const zig_exe = try std.fmt.allocPrint(allocator, "zig{s}", .{exe_extension});
    defer allocator.free(zig_exe);

    var it = std.mem.tokenize(env_path, &[_]u8{std.fs.path.delimiter});
    while (it.next()) |path| {
        if (std.builtin.os.tag == .windows) {
            if (std.mem.indexOfScalar(u8, path, '/')) |s| continue;
        }
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{
            path,
            zig_exe,
        });
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
