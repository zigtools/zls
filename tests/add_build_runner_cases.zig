//! This file is imported by `../build.zig` to add build runner tests to the build system.
//! See the `./build_runner_cases` subdirectory.

const std = @import("std");

pub fn addCases(
    b: *std.Build,
    test_step: *std.Build.Step,
    test_filters: []const []const u8,
) void {
    _ = b;
    _ = test_step;
    _ = test_filters;
    // Build runner tests are disabled because the `--build-runner` flag was
    // removed in Zig 0.17.0-dev. The custom build runner approach needs to be
    // rearchitected for Zig 0.17+.
}
