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

/// Path to the build_runner.zig file. This option must be present in one of
/// the global configuration directories to have any effect.
build_runner_path: ?[]const u8 = null,

/// Semantic token support
enable_semantic_tokens: bool = false,

/// Whether to enable `*` and `?` operators in completion lists
operator_completions: bool = true,
