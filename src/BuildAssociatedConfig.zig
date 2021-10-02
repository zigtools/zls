// Configuration options related to a specific `BuildFile`.

/// If provided this path is used when resolving `@import("builtin")`
/// It is relative to the directory containing the `build.zig`
///
/// This file should contain the output of:
/// `zig build-exe/build-lib/build-obj --show-builtin <options>`
relative_builtin_path: ?[]const u8 = null,
