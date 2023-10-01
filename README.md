<img src="https://raw.githubusercontent.com/zigtools/install-zls/main/img/zls-opt.svg" alt="Zig Language Server" width=200>

[![CI](https://github.com/zigtools/zls/workflows/CI/badge.svg)](https://github.com/zigtools/zls/actions)

**Need support? Wanna help out? Join our [Discord server](https://discord.gg/5m5U3qpUhk)!**

The Zig Language Server (zls) is a tool that implements Microsoft's Language Server Protocol for Zig in Zig. In simpler terms: it'll provide you with completions, go-to definition, [etc.](#features) when you write Zig code!

<!-- omit in toc -->
## Table Of Contents

- [Installation](#installation)
  - [From Source](#from-source)
    - [Build Options](#build-options)
  - [Configuration Options](#configuration-options)
  - [Per-build Configuration Options](#per-build-configuration-options)
    - [`BuildOption`](#buildoption)
- [Features](#features)
- [Using as a library](#using-as-a-library)
- [Related Projects](#related-projects)
- [Quick Thanks :)](#quick-thanks-)
- [License](#license)

## Installation

<!-- omit in toc -->
### [See the `install zls` tool](https://zigtools.github.io/install-zls/) for editor and binary installation instructions.

### From Source

Building `zls` is very easy. You will need [a build of Zig master](https://ziglang.org/download/) to build zls.

```bash
git clone https://github.com/zigtools/zls
cd zls
zig build -Doptimize=ReleaseSafe
```

#### Build Options

| Option | Type | Default Value | What it Does |
| --- | --- | --- | --- |
| `-Ddata_version` | `string` (like 0.7.1 or 0.9.0) | master | The data file version. This selects the files in the `src/data` folder that correspond to the Zig version being served.|

### Configuration Options

You can configure zls by editing your `zls.json` configuration file.
Running `zls --show-config-path` will show a path to an already existing `zls.json` or a path to the local configuration folder instead.

zls will look for a `zls.json` configuration file in multiple locations with the following priority:
- In the local configuration folder of your OS (as provided by [known-folders](https://github.com/ziglibs/known-folders/blob/master/RESOURCES.md#folder-list))
- In the global configuration folder of your OS (as provided by [known-folders](https://github.com/ziglibs/known-folders/blob/master/RESOURCES.md#folder-list))

The following options are currently available.

<!-- DO NOT EDIT | THIS SECTION IS AUTO-GENERATED | DO NOT EDIT -->
| Option | Type | Default value | What it Does |
| --- | --- | --- | --- |
| `enable_snippets` | `bool` | `true` | Enables snippet completions when the client also supports them |
| `enable_argument_placeholders` | `bool` | `true` | Whether to enable function argument placeholder completions |
| `enable_ast_check_diagnostics` | `bool` | `true` | Whether to enable ast-check diagnostics |
| `enable_build_on_save` | `bool` | `false` | Whether to enable build-on-save diagnostics |
| `enable_autofix` | `bool` | `true` | Whether to automatically fix errors on save. Currently supports adding and removing discards. |
| `semantic_tokens` | `enum` | `.full` | Set level of semantic tokens. Partial only includes information that requires semantic analysis. |
| `enable_inlay_hints` | `bool` | `true` | Enables inlay hint support when the client also supports it |
| `inlay_hints_show_variable_declaration` | `bool` | `true` | Enable inlay hints for variable declarations |
| `inlay_hints_show_parameter_name` | `bool` | `true` | Enable inlay hints for parameter names |
| `inlay_hints_show_builtin` | `bool` | `true` | Enable inlay hints for builtin functions |
| `inlay_hints_exclude_single_argument` | `bool` | `true` | Don't show inlay hints for single argument calls |
| `inlay_hints_hide_redundant_param_names` | `bool` | `false` | Hides inlay hints when parameter name matches the identifier (e.g. foo: foo) |
| `inlay_hints_hide_redundant_param_names_last_token` | `bool` | `false` | Hides inlay hints when parameter name matches the last token of a parameter node (e.g. foo: bar.foo, foo: &foo) |
| `warn_style` | `bool` | `false` | Enables warnings for style guideline mismatches |
| `highlight_global_var_declarations` | `bool` | `false` | Whether to highlight global var declarations |
| `dangerous_comptime_experiments_do_not_enable` | `bool` | `false` | Whether to use the comptime interpreter |
| `skip_std_references` | `bool` | `false` | When true, skips searching for references in std. Improves lookup speed for functions in user's code. Renaming and go-to-definition will continue to work as is |
| `prefer_ast_check_as_child_process` | `bool` | `true` | Can be used in conjuction with `enable_ast_check_diagnostics` to favor using `zig ast-check` instead of ZLS's fork |
| `record_session` | `bool` | `false` | When true, zls will record all request is receives and write in into `record_session_path`, so that they can replayed with `zls replay` |
| `record_session_path` | `?[]const u8` | `null` | Output file path when `record_session` is set. The recommended file extension *.zlsreplay |
| `replay_session_path` | `?[]const u8` | `null` | Used when calling `zls replay` for specifying the replay file. If no extra argument is given `record_session_path` is used as the default path. |
| `builtin_path` | `?[]const u8` | `null` | Path to 'builtin;' useful for debugging, automatically set if let null |
| `zig_lib_path` | `?[]const u8` | `null` | Zig library path, e.g. `/path/to/zig/lib/zig`, used to analyze std library imports |
| `zig_exe_path` | `?[]const u8` | `null` | Zig executable path, e.g. `/path/to/zig/zig`, used to run the custom build runner. If `null`, zig is looked up in `PATH`. Will be used to infer the zig standard library path if none is provided |
| `build_runner_path` | `?[]const u8` | `null` | Path to the `build_runner.zig` file provided by zls. null is equivalent to `${executable_directory}/build_runner.zig` |
| `global_cache_path` | `?[]const u8` | `null` | Path to a directory that will be used as zig's cache. null is equivalent to `${KnownFolders.Cache}/zls` |
| `build_runner_global_cache_path` | `?[]const u8` | `null` | Path to a directory that will be used as the global cache path when executing a projects build.zig. null is equivalent to the path shown by `zig env` |
| `completions_with_replace` | `bool` | `true` | Completions confirm behavior. If 'true', replace the text after the cursor |
<!-- DO NOT EDIT -->

### Per-build Configuration Options

The following options can be set on a per-project basis by placing `zls.build.json` in the project root directory next to `build.zig`.

| Option | Type | Default value | What it Does |
| --- | --- | --- | --- |
| `relative_builtin_path` | `?[]const u8` | `null` | If present, this path is used to resolve `@import("builtin")` |
| `build_options` | `?[]BuildOption` | `null` | If present, this contains a list of user options to pass to the build. This is useful when options are used to conditionally add packages in `build.zig`. |

#### `BuildOption`

`BuildOption` is defined as follows:

```zig
const BuildOption = struct {
    name: []const u8,
    value: ?[]const u8 = null,
};
```

When `value` is present, the option will be passed the same as in `zig build -Dname=value`. When `value` is `null`, the option will be passed as a flag instead as in `zig build -Dflag`.

## Features

`zls` supports most language features, including simple type function support, using namespace, payload capture type resolution, custom packages, cImport and others. Support for comptime and semantic analysis is Work-in-Progress.

The following LSP features are supported:
- Completions
- Hover
- Goto definition/declaration
- Document symbols
- Find references
- Rename symbol
- Formatting using `zig fmt`
- Semantic token highlighting
- Inlay hints
- Code actions
- Selection ranges
- Folding regions

## Using as a library

You can use zls as a library! [Check out this demo repo](https://github.com/zigtools/zls-as-lib-demo) for a good reference.

## Related Projects

- [`sublime-zig-language` by @prime31](https://github.com/prime31/sublime-zig-language)
  - Supports basic language features
  - Uses data provided by `src/data` to perform builtin autocompletion
- [`zig-lsp` by @xackus](https://github.com/xackus/zig-lsp)
  - Inspiration for `zls`
- [`known-folders` by @ziglibs](https://github.com/ziglibs/known-folders)
  - Provides API to access known folders on Linux, Windows and Mac OS
- [`zls` by @zigtools](https://github.com/zigtools/zls)
  - Used by many zls developers to more efficiently work on zls

## Quick Thanks :)

We'd like to take a second to thank all our awesome [contributors](https://github.com/zigtools/zls/graphs/contributors) and donators/backers/sponsors; if you have time or money to spare, consider partaking in either of these options - they help keep zls awesome for everyone!

[![OpenCollective Backers](https://opencollective.com/zigtools/backers.svg?width=890&limit=1000)](https://opencollective.com/zigtools#category-CONTRIBUTE)

## License

MIT
