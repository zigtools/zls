<img src="https://raw.githubusercontent.com/zigtools/zls/master/.github/assets/zls-opt.svg" alt="Zig Language Server" width=200>

[![CI](https://github.com/zigtools/zls/workflows/CI/badge.svg)](https://github.com/zigtools/zls/actions)
[![codecov](https://codecov.io/github/zigtools/zls/graph/badge.svg?token=WE18MPF00W)](https://codecov.io/github/zigtools/zls)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Need support? Wanna help out? Join our [Discord server](https://discord.gg/5m5U3qpUhk)!**

The Zig Language Server (ZLS) is a tool that implements Microsoft's Language Server Protocol for Zig in Zig. In simpler terms: it'll provide you with completions, go-to definition, [etc.](#features) when you write Zig code!

## Installation

### See the [Installation Guide](https://github.com/zigtools/zls/wiki/Installation) for editor and binary installation instructions.

### From Source

Building ZLS is very easy. You will need [a build of Zig master](https://ziglang.org/download/) to build ZLS.

```bash
git clone https://github.com/zigtools/zls
cd zls
zig build -Doptimize=ReleaseSafe
```

## Features

ZLS supports most language features, including simple type function support, using namespace, payload capture type resolution, custom packages, cImport and others. Support for comptime and semantic analysis is Work-in-Progress.

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

## Related Projects

- [`sublime-zig-language` by @prime31](https://github.com/prime31/sublime-zig-language)
  - Supports basic language features
  - Uses data provided by `src/data` to perform builtin autocompletion
- [`zig-lsp` by @xackus](https://github.com/xackus/zig-lsp)
  - Inspiration for ZLS
- [`known-folders` by @ziglibs](https://github.com/ziglibs/known-folders)
  - Provides API to access known folders on Linux, Windows and Mac OS
- [`zls` by @zigtools](https://github.com/zigtools/zls)
  - Used by many ZLS developers to more efficiently work on ZLS

## Quick Thanks :)

We'd like to take a second to thank all our awesome [contributors](https://github.com/zigtools/zls/graphs/contributors) and donators/backers/sponsors; if you have time or money to spare, consider partaking in either of these options - they help keep ZLS awesome for everyone!

[![OpenCollective Backers](https://opencollective.com/zigtools/backers.svg?width=890&limit=1000)](https://opencollective.com/zigtools#category-CONTRIBUTE)
