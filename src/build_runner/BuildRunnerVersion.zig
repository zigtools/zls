const std = @import("std");
const build_options = @import("build_options");

// These versions must be ordered from newest to oldest.
// There should be no need to have a build runner for minor patches (e.g. 0.10.1)
pub const BuildRunnerVersion = enum {
    master,
    @"0.11.0",
    @"0.10.0",

    pub fn selectBuildRunnerVersion(runtime_zig_version: std.SemanticVersion) ?BuildRunnerVersion {
        const runtime_zig_version_simple = std.SemanticVersion{
            .major = runtime_zig_version.major,
            .minor = runtime_zig_version.minor,
            .patch = 0,
        };
        const zls_version_simple = std.SemanticVersion{
            .major = build_options.version.major,
            .minor = build_options.version.minor,
            .patch = 0,
        };

        return switch (runtime_zig_version_simple.order(zls_version_simple)) {
            .eq, .gt => .master,
            .lt => {
                const available_versions = comptime std.meta.tags(BuildRunnerVersion);
                inline for (available_versions[1..]) |build_runner_version| {
                    const version = comptime std.SemanticVersion.parse(@tagName(build_runner_version)) catch unreachable;
                    switch (runtime_zig_version.order(version)) {
                        .eq => return build_runner_version,
                        .lt, .gt => {},
                    }
                }
                return null;
            },
        };
    }
};
