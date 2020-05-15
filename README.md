![Zig Language Server](https://raw.githubusercontent.com/SuperAuguste/zls/master/.assets/zls.svg)

![CI](https://github.com/zigtools/zls/workflows/CI/badge.svg)
![Zig Tools](https://img.shields.io/static/v1?label=zigtools&message=for%20all%20of%20ziguanity&color=F7A41D&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAIAAACRXR/mAAAEDklEQVR4nOzYbUwbZRwA8Oe53vXuSltaa2lxc+KKBGcyBhLDgH3SiSMZ++TQRT8uJH4x8S0myL6YmUjUbIkfZvZtX3TJlAwjiYImxuBwa1hEtxAcQ8GFQrtBWXvXu17vTH1ux1lv99IeLcn6//Rw9/D0l+ft/28xsC2jyrISVZaV2KYsfCsGxSDYs5OIhPCAB0tlpFt3hF//yqYyUsVYrQ3Eaz2ew0/Tta7/rENOlCZnuTMTqZHLrJlxoF2ggAf7+FVff2eNfrf+U/HRaMZwNHtmqzGMf/NucNfDxqNFQqY+0QZWYxifGKoL1TrQnzlRGrvKXphio/M8ANLEUKjeL7+aW86e+5EpB4vEwRevBxTTtSX++Gd3rv6ZBQCEfdi3g3VqU8/J1dspsRysd454n3rUidq//MH1Dcc3WEkxNdUTalNsXTYFPNgr3TULcWE0qn0CStryXhoufPqIi8wfusWE0DEYW0sbm9Rvj52Oj1zROAElXacvd7mQCQAwdH4dmdwUNGkCAAwc9GiOXBKrp4VGjcWEcGFKXo6B59wmTQCA7mbSTWmsWEmstsflXfXdTEa8d4e375YfMpx46AM9EwDAgcGWXYSdLAyCkE8+Zdf/5pXnqxs51HCR2Pv9PgxqmJbXckr/HQGHnSx1cNnN9tnvU5msPHXHumvODjy0w194AvqGV5X+bkrDUDxLlPI3J2rXujb3x+9LwoufxNWymY/qC3Ybw22m7cTdnJ0sAMD8ioAaHU+Q6ucTv3FqmXJalRPQHnEqnW/GBJtZk7Mcajy/l/bSUEdWcCqP7pczejItXr+lwSr+lg/7sK5meZIoJ2x5jPhpli+QHTixcvxZd73fcfkGd2Y8hUqu1gbihX0U6vP1NCNqlWFF3vL/v8c7BmMsb/yPXhr+cKJOyVed78VQAi2IYhZRM7eYMflr4MjbQcV0/ue0pqkYln6+o53wwJNkwT5Dl9zR/fTUyXBnk7zuiwnhzXPr9/sUa3vLZA7OZKXxGfbSHJ9kRIqAe3YSB/dS6iIxsZHrG47rFDkW9pb5ukA/ri3xL52+fUPrXlDC7GzZYmI48dTY3eGLG5weyTTLkmluOTs5y3U1k5EQ7vg3I64kc9F5fnwm8/lkGhWJhmHMsmpSvy06DE5iRUwGrEqZ9FgYBF++EayISY91pJ1qu1dnltmkx+ptlev0JCOW2aTH8rvlWvbKPFdmkx5rNSkXjZ1NZGMYL6dJL/kc2kd99VYQtRlOvDTHt0ecys9DW2rKfyO634ubK0J3M9kQzM8TgcPdIZwiYHlMeiwJgNEo+0yjE8mUmF7gD38Y31KTcQWBQdDbSvW20XVex1paHJtmL0ZZzTL3gYht+ktzlWUlqiwrUWVZiX8CAAD//7jyYLmjqPd4AAAAAElFTkSuQmCC)

Zig Language Server, or `zls`, is a language server for Zig. The Zig wiki states that "The Zig community is decentralized" and "There is no concept of 'official' or 'unofficial'", so instead of calling `zls` unofficial, and I'm going to call it a cool option, one of [many](https://github.com/search?q=zig+language+server).

- [Installation](#installation)
  - [Build Options](#build-options)
  - [Configuration Options](#configuration-options)
- [Usage](#usage)
  - [VSCode](#vscode)
- [Related Projects](#related-projects)
- [License](#license)

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

### Configuration Options

You can configure zls by providing a zls.json file in the same directory as the executable.  
The following options are currently available.  

| Option | Type | Default value | What it Does |
| --- | --- | --- | --- |
| `enable_snippets` | `bool` | `true` | Enables snippet completion, set to false for compatibility with language clients that do not support snippets (such as ale). |
| `zig_lib_path` | `?[]const u8` | `null` | zig library path, used to analyze std library imports. |

## Usage

`zls` is in its early stages, with a full analysis/completion engine coming soon, but it is still usable. 

### VSCode

Install the `zls-vscode` extension from [here](https://github.com/zigtools/zls-vscode/releases).

## Related Projects
- [`sublime-zig-language` by @prime31](https://github.com/prime31/sublime-zig-language)
  - Supports basic language features
  - Uses data provided by `src/data` to perform builtin autocompletion
- [`zig-lsp` by @xackus](https://github.com/xackus/zig-lsp)
  - Inspiration for `zls`

## License
MIT
