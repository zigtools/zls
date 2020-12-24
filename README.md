![Zig Language Server](https://raw.githubusercontent.com/zigtools/zls/master/.assets/zls.svg)

![CI](https://github.com/zigtools/zls/workflows/CI/badge.svg)
![Zig Tools](https://img.shields.io/static/v1?label=zigtools&message=for%20all%20of%20ziguanity&color=F7A41D&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAIAAACRXR/mAAAEDklEQVR4nOzYbUwbZRwA8Oe53vXuSltaa2lxc+KKBGcyBhLDgH3SiSMZ++TQRT8uJH4x8S0myL6YmUjUbIkfZvZtX3TJlAwjiYImxuBwa1hEtxAcQ8GFQrtBWXvXu17vTH1ux1lv99IeLcn6//Rw9/D0l+ft/28xsC2jyrISVZaV2KYsfCsGxSDYs5OIhPCAB0tlpFt3hF//yqYyUsVYrQ3Eaz2ew0/Tta7/rENOlCZnuTMTqZHLrJlxoF2ggAf7+FVff2eNfrf+U/HRaMZwNHtmqzGMf/NucNfDxqNFQqY+0QZWYxifGKoL1TrQnzlRGrvKXphio/M8ANLEUKjeL7+aW86e+5EpB4vEwRevBxTTtSX++Gd3rv6ZBQCEfdi3g3VqU8/J1dspsRysd454n3rUidq//MH1Dcc3WEkxNdUTalNsXTYFPNgr3TULcWE0qn0CStryXhoufPqIi8wfusWE0DEYW0sbm9Rvj52Oj1zROAElXacvd7mQCQAwdH4dmdwUNGkCAAwc9GiOXBKrp4VGjcWEcGFKXo6B59wmTQCA7mbSTWmsWEmstsflXfXdTEa8d4e375YfMpx46AM9EwDAgcGWXYSdLAyCkE8+Zdf/5pXnqxs51HCR2Pv9PgxqmJbXckr/HQGHnSx1cNnN9tnvU5msPHXHumvODjy0w194AvqGV5X+bkrDUDxLlPI3J2rXujb3x+9LwoufxNWymY/qC3Ybw22m7cTdnJ0sAMD8ioAaHU+Q6ucTv3FqmXJalRPQHnEqnW/GBJtZk7Mcajy/l/bSUEdWcCqP7pczejItXr+lwSr+lg/7sK5meZIoJ2x5jPhpli+QHTixcvxZd73fcfkGd2Y8hUqu1gbihX0U6vP1NCNqlWFF3vL/v8c7BmMsb/yPXhr+cKJOyVed78VQAi2IYhZRM7eYMflr4MjbQcV0/ue0pqkYln6+o53wwJNkwT5Dl9zR/fTUyXBnk7zuiwnhzXPr9/sUa3vLZA7OZKXxGfbSHJ9kRIqAe3YSB/dS6iIxsZHrG47rFDkW9pb5ukA/ri3xL52+fUPrXlDC7GzZYmI48dTY3eGLG5weyTTLkmluOTs5y3U1k5EQ7vg3I64kc9F5fnwm8/lkGhWJhmHMsmpSvy06DE5iRUwGrEqZ9FgYBF++EayISY91pJ1qu1dnltmkx+ptlev0JCOW2aTH8rvlWvbKPFdmkx5rNSkXjZ1NZGMYL6dJL/kc2kd99VYQtRlOvDTHt0ecys9DW2rKfyO634ubK0J3M9kQzM8TgcPdIZwiYHlMeiwJgNEo+0yjE8mUmF7gD38Y31KTcQWBQdDbSvW20XVex1paHJtmL0ZZzTL3gYht+ktzlWUlqiwrUWVZiX8CAAD//7jyYLmjqPd4AAAAAElFTkSuQmCC)

Zig Language Server, or `zls`, is a language server for Zig. The Zig wiki states that "The Zig community is decentralized" and "There is no concept of 'official' or 'unofficial'", so instead of calling `zls` unofficial, and I'm going to call it a cool option, one of [many](https://github.com/search?q=zig+language+server).

<!-- omit in toc -->
## Table Of Contents
- [Installation](#installation)
  - [Build Options](#build-options)
  - [Configuration Options](#configuration-options)
- [Usage](#usage)
  - [VSCode](#vscode)
  - [Sublime Text 3](#sublime-text-3)
  - [Kate](#kate)
  - [Neovim/Vim8](#neovimvim8)
  - [Emacs](#emacs)
- [Related Projects](#related-projects)
- [License](#license)

## Installation

Installation starts with downloading an official release from the [Releases page](https://github.com/zigtools/zls/releases).

See [Downloading and Building ZLS](https://github.com/zigtools/zls/wiki/Downloading-and-Building-ZLS) on the Wiki, or the page about [using ZLS with Visual Studio Code](https://github.com/zigtools/zls/wiki/Installing-for-Visual-Studio-Code) for a guide to help get `zls` running in your editor.

### From Source

Building `zls` is very easy. You will need [a build of Zig master](https://ziglang.org/download/) to build zls.

```bash
git clone --recurse-submodules https://github.com/zigtools/zls
cd zls
zig build -Drelease-safe
zig build config # Configure ZLS
```

*For detailed building instructions, see the Wiki page about [Cloning With Git](https://github.com/zigtools/zls/wiki/Downloading-and-Building-ZLS#cloning-with-git).*

#### Build Options

<!-- When updating this table, be sure to copy changes to the Wiki page about building from source. -->
<!-- If this table grows too large, then delete this one and move it all over to the Wiki page about building from source. -->
| Option | Type | Default Value | What it Does |
| --- | --- | --- | --- |
| `-Ddata_version` | `string` (master or 0.7.0) | master | The data file version. This selects the files in the `src/data` folder that correspond to the Zig version being served.|

### Configuration Options

You can configure zls by providing a zls.json file.  
zls will look for a zls.json configuration file in multiple locations with the following priority:  
- In the local configuration folder of your OS (as provided by [known-folders](https://github.com/ziglibs/known-folders#folder-list))  
- In the same directory as the executable  

The following options are currently available.  

| Option | Type | Default value | What it Does |
| --- | --- | --- | --- |
| `enable_snippets` | `bool` | `false` | Enables snippet completions when the client also supports them. |
| `zig_lib_path` | `?[]const u8` | `null` | zig library path, e.g. `/path/to/zig/lib/zig`, used to analyze std library imports. |
| `zig_exe_path` | `?[]const u8` | `null` | zig executable path, e.g. `/path/to/zig/zig`, used to run the custom build runner. If `null`, zig is looked up in `PATH`. Will be used to infer the zig standard library path if none is provided. |
| `warn_style` | `bool` | `false` | Enables warnings for style *guideline* mismatches |
| `build_runner_path` | `?[]const u8` | `null` | Path to the build_runner.zig file provided by zls. This option must be present in one of the global configuration files to have any effect. `null` is equivalent to `${executable_directory}/build_runner.zig` |
| `enable_semantic_tokens` | `bool` | `true` | Enables semantic token support when the client also supports it. |
| `operator_completions` | `bool` | `true` | Enables `*` and `?` operators in completion lists. |

## Features

`zls` supports most language features, including simple type function support, usingnamespace, payload capture type resolution, custom packages and others. 
Notable language features that are not currently implemented include `@cImport` as well as most forms of compile time evaluation.  

The following LSP features are supported:  
- Completions
- Hover
- Goto definition/declaration
- Document symbols
- Find references
- Rename symbol
- Formatting using `zig fmt`
- Semantic token highlighting (LSP 3.16 proposed feature, implemented by a few clients including VSCode, kak and emacs lsp-mode)

You can install `zls` using the instuctions for your text editor below:  

### VSCode

Install the `zls-vscode` extension from [here](https://github.com/zigtools/zls-vscode/releases) and provide a path to the build `zls` executable.

### Sublime Text 3

- Install the `LSP` package from [here](https://github.com/sublimelsp/LSP/releases) or via Package Control.
- Add this snippet to `LSP's` user settings:

```json
{
    "clients": {
        "zig":{
            "command": ["zls"],
            "enabled": true,
            "languageId": "zig",
            "scopes": ["source.zig"],
            "syntaxes": ["Packages/Zig Language/Syntaxes/Zig.tmLanguage"]
        }
    }
}
```

### Kate

- Enable `LSP client` plugin in Kate settings.
- Add this snippet to `LSP client's` user settings (e.g. /$HOME/.config/kate/lspclient)
  (or paste it in `LSP client's` GUI settings)

```json
{
    "servers": {
        "zig": {
            "command": ["zls"],
            "url": "https://github.com/zigtools/zls",
            "highlightingModeRegex": "^Zig$"
        }
    }
}
```

### Neovim/Vim8
#### CoC

- Install the CoC engine from [here](https://github.com/neoclide/coc.nvim).
- Issue `:CocConfig` from within your Vim editor, and the following snippet:

```json
{
   "languageserver": {
       "zls" : {
           "command": "command_or_path_to_zls",
           "filetypes": ["zig"]
       }
   }
}
```

#### nvim-lspconfig
Requires Nvim 0.5 (HEAD)!

- Install nvim-lspconfig from [here](https://github.com/neovim/nvim-lspconfig).
- Install zig.vim from [here](https://github.com/ziglang/zig.vim).

nvim-lspconfig already ships a configuration for zls. A simple `init.vim` might look like this:
```vim
call plug#begin('~/.config/nvim/plugged')
Plug 'neovim/nvim-lspconfig'
Plug 'nvim-lua/completion-nvim'
Plug 'ziglang/zig.vim'
call plug#end()

:lua << EOF
    local lspconfig = require('lspconfig')

    local on_attach = function(_, bufnr)
        vim.api.nvim_buf_set_option(bufnr, 'omnifunc', 'v:lua.vim.lsp.omnifunc')
        require('completion').on_attach()
    end

    local servers = {'zls'}
    for _, lsp in ipairs(servers) do 
        lspconfig[lsp].setup {
            on_attach = on_attach,
        }
    end
EOF

" Set completeopt to have a better completion experience
set completeopt=menuone,noinsert,noselect

" Enable completions as you type
let g:completion_enable_auto_popup = 1
```


### Emacs

- Install [lsp-mode](https://github.com/emacs-lsp/lsp-mode) from melpa
- [zig mode](https://github.com/ziglang/zig-mode) is also useful

```elisp
(require 'lsp)
(add-to-list 'lsp-language-id-configuration '(zig-mode . "zig"))
(lsp-register-client
  (make-lsp-client
    :new-connection (lsp-stdio-connection "<path to zls>")
    :major-modes '(zig-mode)
    :server-id 'zls))
```

## Related Projects
- [`sublime-zig-language` by @prime31](https://github.com/prime31/sublime-zig-language)
  - Supports basic language features
  - Uses data provided by `src/data` to perform builtin autocompletion
- [`zig-lsp` by @xackus](https://github.com/xackus/zig-lsp)
  - Inspiration for `zls`
- [`known-folders` by @ziglibs](https://github.com/ziglibs/known-folders)
  - Provides API to access known folders on Linux, Windows and Mac OS

## License
MIT
