// Configuration options for zls.

/// Whether to enable snippet completions
enable_snippets: bool = false,

/// zig library path
zig_lib_path: ?[]const u8 = null,

/// zig executable path used to run the custom build runner.
/// May be used to find a lib path if none is provided.
zig_exe_path: ?[]const u8 = null,

/// Whether to pay attention to style issues. This is opt-in since the style
/// guide explicitly states that the style info provided is a guideline only.
warn_style: bool = false,

/// Path to the build_runner.zig file.
build_runner_path: ?[]const u8 = null,

/// Path to a directory that will be used as cache when `zig run`ing the build runner
build_runner_cache_path: ?[]const u8 = null,

/// Semantic token support
enable_semantic_tokens: bool = true,

/// Whether to enable `*` and `?` operators in completion lists
operator_completions: bool = true,

/// Skips references to std. This will improve lookup speeds.
/// Going to definition however will continue to work
skip_std_references: bool = true,
