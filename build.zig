const std = @import("std");
const builtin = @import("builtin");
// const build_options = @import("build_options")

const zinput = @import("src/zinput/src/main.zig");

var builder: *std.build.Builder = undefined;

pub fn config(step: *std.build.Step) anyerror!void {
    @setEvalBranchQuota(2500);
    std.debug.warn("Welcome to the ZLS configuration wizard! (insert mage emoji here)\n", .{});

    var zig_exe_path: ?[]const u8 = null;
    std.debug.print("Looking for 'zig' in PATH...\n", .{});
    find_zig: {
        const allocator = builder.allocator;
        const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => {
                break :find_zig;
            },
            else => return err,
        };
        defer allocator.free(env_path);

        const exe_extension = @as(std.zig.CrossTarget, .{}).exeFileExt();
        const zig_exe = try std.fmt.allocPrint(allocator, "zig{s}", .{exe_extension});
        defer allocator.free(zig_exe);

        var it = std.mem.tokenize(env_path, &[_]u8{std.fs.path.delimiter});
        while (it.next()) |path| {
            const resolved_path = try std.fs.path.resolve(allocator, &[_][]const u8{path});
            defer allocator.free(resolved_path);
            const full_path = try std.fs.path.join(allocator, &[_][]const u8{
                resolved_path,
                zig_exe,
            });
            defer allocator.free(full_path);

            if (!std.fs.path.isAbsolute(full_path)) continue;
            // Skip folders named zig
            const file = std.fs.openFileAbsolute(full_path, .{}) catch continue;
            const stat = file.stat() catch continue;
            const is_dir = stat.kind == .Directory;
            if (is_dir) continue;

            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            zig_exe_path = try std.mem.dupe(allocator, u8, std.os.realpath(full_path, &buf) catch continue);
            break :find_zig;
        }
    }

    if (zig_exe_path == null) {
        std.debug.print("Could not find 'zig' in PATH\n", .{});
        zig_exe_path = try zinput.askString(builder.allocator, "What is the path to the 'zig' executable you would like to use?", 512);
    } else {
        std.debug.print("Found zig executable '{s}'\n", .{zig_exe_path.?});
    }

    const editor = try zinput.askSelectOne("Which code editor do you use?", enum { VSCode, Sublime, Kate, Neovim, Vim8, Emacs, Doom, Other });
    const snippets = try zinput.askBool("Do you want to enable snippets?");
    const style = try zinput.askBool("Do you want to enable style warnings?");
    const semantic_tokens = try zinput.askBool("Do you want to enable semantic highlighting?");
    const operator_completions = try zinput.askBool("Do you want to enable .* and .? completions?");
    const include_at_in_builtins = switch (editor) {
        .Sublime =>
            true,
        .VSCode,
        .Kate,
        .Neovim,
        .Vim8,
        .Emacs,
        .Doom =>
            false,
        else =>
            try zinput.askBool("Should the @ sign be included in completions of builtin functions?\nChange this later if `@inc` completes to `include` or `@@include`")
    };
    const max_detail_length: usize = switch (editor) {
        .Sublime =>
            256,
        else =>
            1024 * 1024
    };
    
    var dir = try std.fs.cwd().openDir(builder.exe_dir, .{});
    defer dir.close();

    var file = try dir.createFile("zls.json", .{});
    defer file.close();

    const out = file.writer();

    std.debug.warn("Writing to config...\n", .{});

    const content = std.json.stringify(.{
        .zig_exe_path = zig_exe_path,
        .enable_snippets = snippets,
        .warn_style = style,
        .enable_semantic_tokens = semantic_tokens,
        .operator_completions = operator_completions,
        .include_at_in_builtins = include_at_in_builtins,
        .max_detail_length = max_detail_length,
    }, std.json.StringifyOptions{}, out);

    std.debug.warn("Successfully saved configuration options!\n", .{});
    std.debug.warn("\n", .{});

    switch (editor) {
        .VSCode => {
            std.debug.warn(
                \\To use ZLS in Visual Studio Code, install the 'ZLS for VSCode' extension.
                \\Then, open VSCode's 'settings.json' file, and add `"zigLanguageClient.path": "[command_or_path_to_zls]"`.
            , .{});
        },
        .Sublime => {
            std.debug.warn(
                \\To use ZLS in Sublime, install the `LSP` package from `https://github.com/sublimelsp/LSP/releases` or via Package Control.
                \\Then, add the following snippet to `LSP`'s user settings:
                \\
                \\{{
                \\  "clients": {{
                \\    "zig": {{
                \\      "command": ["zls"],
                \\      "enabled": true,
                \\      "languageId": "zig",
                \\      "scopes": ["source.zig"],
                \\      "syntaxes": ["Packages/Zig/Syntaxes/Zig.tmLanguage"]
                \\    }}
                \\  }}
                \\}}
            , .{});
        },
        .Kate => {
            std.debug.warn(
                \\To use ZLS in Kate, enable `LSP client` plugin in Kate settings.
                \\Then, add the following snippet to `LSP client's` user settings:
                \\(or paste it in `LSP client's` GUI settings)
                \\
                \\{{
                \\    "servers": {{
                \\        "zig": {{
                \\            "command": ["zls"],
                \\            "url": "https://github.com/zigtools/zls",
                \\            "highlightingModeRegex": "^Zig$"
                \\        }}
                \\    }}
                \\}}
            , .{});
        },
        .Neovim, .Vim8 => {
            std.debug.warn(
                \\To use ZLS in Neovim/Vim8, we recommend using CoC engine. You can get it from 'https://github.com/neoclide/coc.nvim'.
                \\Then, simply issue cmd from Neovim/Vim8 `:CocConfig`, and add this to your CoC config:
                \\
                \\{{
                \\  "languageserver": {{
                \\    "zls" : {{
                \\      "command": "command_or_path_to_zls",
                \\      "filetypes": ["zig"]
                \\    }}
                \\  }}
                \\}}
            , .{});
        },
        .Emacs => {
            std.debug.warn(
                \\To use ZLS in Emacs, install lsp-mode (https://github.com/emacs-lsp/lsp-mode) from melpa.
                \\Zig mode (https://github.com/ziglang/zig-mode) is also useful!
                \\Then, add the following to your emacs config:
                \\
                \\(require 'lsp-mode)
                \\(setq lsp-zig-zls-executable "<path to zls>")
            , .{});
        },
        .Doom => {
            std.debug.warn(
                \\To use ZLS in Doom Emacs, enable the lsp module
                \\And install the `zig-mode` (https://github.com/ziglang/zig-mode) package by adding `(package! zig-mode)` to your packages.el file.
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
            , .{});
        },
        .Other => {
            std.debug.warn(
                \\We might not *officially* support your editor, but you can definitely still use ZLS!
                \\Simply configure your editor for use with language servers and point it to the ZLS executable!
            , .{});
        },
    }

    std.debug.warn("\nYou can find the ZLS executable in the \"zig-cache/bin\" by default.\nNOTE: Make sure that if you move the ZLS executable, you move the `zls.json` config file with it as well!\n\nAnd finally: Thanks for choosing ZLS!\n\n", .{});
}

pub fn build(b: *std.build.Builder) !void {
    builder = b;
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zls", "src/main.zig");

    exe.addBuildOption(
        []const u8,
        "data_version",
        b.option([]const u8, "data_version", "The data version - either 0.7.0 or master.") orelse "master",
    );

    exe.addPackage(.{ .name = "known-folders", .path = "src/known-folders/known-folders.zig" });

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    b.installFile("src/special/build_runner.zig", "bin/build_runner.zig");

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const configure_step = b.step("config", "Configure zls");
    configure_step.makeFn = config;

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(builder.getInstallStep());

    var unit_tests = b.addTest("src/unit_tests.zig");
    unit_tests.setBuildMode(.Debug);
    test_step.dependOn(&unit_tests.step);

    var session_tests = b.addTest("tests/sessions.zig");
    session_tests.addPackage(.{ .name = "header", .path = "src/header.zig" });
    session_tests.setBuildMode(.Debug);
    test_step.dependOn(&session_tests.step);
}
