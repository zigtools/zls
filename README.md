<img src="https://raw.githubusercontent.com/zigtools/zls/master/.github/assets/zls-opt.svg" alt="ZLS Logo" width=200>

[![CI](https://github.com/zigtools/zls/actions/workflows/main.yml/badge.svg)](https://github.com/zigtools/zls/actions/workflows/main.yml)
[![codecov](https://codecov.io/github/zigtools/zls/graph/badge.svg?token=WE18MPF00W)](https://codecov.io/github/zigtools/zls)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Discord](https://discord.com/api/guilds/997174129532866701/widget.png?style=shield)](https://discord.gg/5m5U3qpUhk)

ZLS is a non-official implementation of the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) for [Zig](https://ziglang.org/) in Zig. It provides developers with IDE [features](#features) in their editor.

## Installation

The complete installation guide is available on the [Zigtools website](https://zigtools.org/zls/install/). It covers editor setup, prebuilt binaries and additional documentation.

### Build From Source

The default branch of ZLS targets [Zig master](https://ziglang.org/download/).

```bash
git clone https://github.com/zigtools/zls
cd zls
zig build -Doptimize=ReleaseSafe
```

When upgrading Zig, make sure to update ZLS too keep them in sync.

## Features

ZLS supports most language features, including simple type function support, payload capture type resolution, custom packages, and others. Support for comptime and semantic analysis is Work-in-Progress.

The majority of LSP features are supported:

- Completions
- Hover
- Diagnostics and opt-in [build-on-save](https://zigtools.org/zls/guides/build-on-save/)
- Go to definition/declaration
- Workspace symbols and document symbols
- Find references and rename symbol
- Formatting based on `zig fmt`
- Semantic tokens highlighting
- Inlay hints
- Code actions

## Quick Thanks :)

We'd like to take a second to thank all our awesome [contributors](https://github.com/zigtools/zls/graphs/contributors) and donators/backers/sponsors; if you have time or money to spare, consider partaking in either of these options - they help keep ZLS awesome for everyone!

[![OpenCollective Backers](https://opencollective.com/zigtools/backers.svg?width=890&limit=1000)](https://opencollective.com/zigtools#category-CONTRIBUTE)
