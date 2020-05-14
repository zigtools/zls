![Zig Language Server](https://raw.githubusercontent.com/SuperAuguste/zls/master/.assets/zls.svg)

Zig Language Server, or `zls`, is a language server for Zig. The Zig wiki states that "The Zig community is decentralized" and "There is no concept of 'official' or 'unofficial'", so instead of calling `zls` unofficial, and I'm going to call it a cool option, one of [many](https://github.com/search?q=zig+language+server).

## Installation

Installing `zls` is pretty simple;

```bash
git clone https://github.com/SuperAuguste/zls
cd zls
zig build
```

### Build Options

| Option | Type | What it Does |
| --- | --- | --- |
| `-Ddata_version` | `string` | The data file version. Any files in the `src/data` file that correspond with the Zig version you want the language server to build for (0.6.0, master).

Then, you can use the `zls` executable in an editor of your choice that has a Zig language server client!

### Configuration options

You can configure zls by providing a zls.json file in the same directory as the executable.  
The following options are currently available.  

| Option | Type | Default value | What it Does |
| --- | --- | --- | --- |
| `enable_snippets` | `bool` | `true` | Enables snippet completion, set to false for compatibility with language clients that do not support snippets (such as ale). |
| `zig_lib_path` | `?[]const u8` | `null` | zig library path, used to analyze std library imports. |

## Usage

`zls` is in its early stages, with a full analysis/completion engine coming soon, but it is still usable. 

### VSCode

Install the `zig-lsc` extension from [here](https://github.com/SuperAuguste/zig-lsc).


## Related Projects
- [`sublime-zig-language` by @prime31](https://github.com/prime31/sublime-zig-language)
  - Supports basic language features
  - Uses data provided by `src/data` to perform builtin autocompletion

## License
MIT
