# Code of Conduct

The ZLS follows the same policy as the [Zig project](https://ziglang.org/code-of-conduct/#strict-no-llm-no-ai-policy) including the **Strict No LLM / No AI Policy**. For enforcement and issues regarding the Code of Conduct please E-Mail `contact[at]zigtools.org`.

# Discord

Join the [ZLS discord server](https://discord.gg/5m5U3qpUhk) if you'd like to coordinate with other contributors.

# Compile From Source

As part of the code editing workflow, consider the following commands:

- `zig build`: compile and install zls executable to `zig-out/bin/zls`
- `zig build check`: report compilation errors only (faster)
- `zig build check --watch -fincremental`: run compiler continously with incremental compilation

The ZLS language server itself will automatically report compilation errors through to the editor. Incremental compilation is still disabled by default so consider instructing ZLS to enable `-fincremental`. See the [build-on-save guide](https://zigtools.org/zls/guides/build-on-save/) on how to do that.

# Testing

Use `zig build test` to run the ZLS test suite. This includes the following kinds of tests:

- Standalone unit tests in `./src`
- Code analysis tests in `./tests/analysis`
- LSP feature tests in `./tests/lsp_features`

Use `-Dtest-filter` to run a specific test or a subset of tests.

# Testing in Editor

To test the newly compiled ZLS built in your editor of choice, see the [editor configuration guide](https://zigtools.org/zls/install/) and manually set the ZLS to the binary in `./zig-out/bin/zls`.

# Logging

See the [ZLS guide](https://zigtools.org/zls/guides/view-logs/) on how log messages can be inspected. Editor logs are encouraged during development to inspect the output of `std.debug.print` calls.

# Resources

- [ZLS website](https://zigtools.org/zls/install/)
- [LSP Specification](https://microsoft.github.io/language-server-protocol/specifications/specification-current)
- [Tracy Profiler](https://github.com/wolfpld/tracy) (See `-Denable-tracy` build option, a [Zig port](https://github.com/allyourcodebase/tracy) is also available)
