const std = @import("std");
const builtin = @import("builtin");
// const build_options = @import("build_options")

const zinput = @import("src/zinput/src/main.zig");

var builder: *std.build.Builder = undefined;

pub fn config(step: *std.build.Step) anyerror!void {
    @setEvalBranchQuota(2500);
    std.debug.warn("Welcome to the ZLS configuration wizard! (insert mage emoji here)\n", .{});

    // std.debug.warn("{}", .{dir.});

    const lib_path = try zinput.askDirPath(builder.allocator, "What is your Zig lib path (path that contains the 'std' folder)?", 512);
    const snippets = try zinput.askBool("Do you want to enable snippets?");
    const style = try zinput.askBool("Do you want to enable style warnings?");
    const semantic_tokens = try zinput.askBool("Do you want to enable semantic highlighting?");

    var dir = try std.fs.cwd().openDir(builder.exe_dir, .{});
    defer dir.close();

    var file = try dir.createFile("zls.json", .{});
    defer file.close();

    const out = file.outStream();

    std.debug.warn("Writing to config...\n", .{});

    const content = std.json.stringify(.{
        .zig_lib_path = lib_path,
        .enable_snippets = snippets,
        .warn_style = style,
        .enable_semantic_tokens = semantic_tokens,
    }, std.json.StringifyOptions{}, out);

    std.debug.warn("Successfully saved configuration options!\n", .{});

    const editor = try zinput.askSelectOne("Which code editor do you use?", enum { VSCode, Sublime, Kate, Neovim, Vim8, Emacs, Other });
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
                \\(require 'lsp)
                \\(add-to-list 'lsp-language-id-configuration '(zig-mode . "zig"))
                \\(lsp-register-client
                \\  (make-lsp-client
                \\    :new-connection (lsp-stdio-connection "<path to zls>")
                \\    :major-modes '(zig-mode)
                \\    :server-id 'zls))
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

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zls", "src/main.zig");
    
    exe.addBuildOption(
        []const u8,
        "data_version",
        b.option([]const u8, "data_version", "The data version - either 0.6.0 or master.") orelse "0.6.0",
    );

    exe.addBuildOption(
        bool,
        "allocation_info",
        b.option(bool, "allocation_info", "Enable use of debugging allocator and info logging.") orelse false,
    );

    const max_bytes_str = b.option([]const u8, "max_bytes_allocated", "Maximum amount of bytes to allocate before we exit. Zero for unlimited allocations. Only takes effect when allocation_info=true") orelse "0";
    exe.addBuildOption(
        usize,
        "max_bytes_allocated",
        try std.fmt.parseInt(usize, max_bytes_str, 10),
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

    var unit_tests = b.addTest("tests/unit_tests.zig");
    unit_tests.addPackage(.{ .name = "analysis", .path = "src/analysis.zig" });
    unit_tests.addPackage(.{ .name = "types", .path = "src/types.zig" });
    unit_tests.setBuildMode(.Debug);

    var session_tests = b.addTest("tests/sessions.zig");
    session_tests.addPackage(.{ .name = "header", .path = "src/header.zig" });
    session_tests.setBuildMode(.Debug);

    test_step.dependOn(&session_tests.step);
}
