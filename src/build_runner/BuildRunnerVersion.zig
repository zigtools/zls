const std = @import("std");
const build_options = @import("build_options");

// These versions must be ordered from newest to oldest.
// There should be no need to have a build runner for minor patches (e.g. 0.10.1)
pub const BuildRunnerVersion = enum {
    // master,
    @"0.12.0",

    pub fn isTaggedRelease(version: BuildRunnerVersion) bool {
        return !@hasField(BuildRunnerVersion, "master") or version != .master;
    }

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

        const minimum_runtime_zig_version = comptime std.SemanticVersion.parse(build_options.minimum_runtime_zig_version_string) catch unreachable;
        const minimum_runtime_zig_version_is_tagged = minimum_runtime_zig_version.build == null and minimum_runtime_zig_version.pre == null;
        const has_master = @hasField(BuildRunnerVersion, "master");
        const available_versions = std.meta.tags(BuildRunnerVersion);

        comptime std.debug.assert(available_versions.len != 0);
        comptime std.debug.assert(minimum_runtime_zig_version_is_tagged == !has_master);

        return switch (runtime_zig_version_simple.order(zls_version_simple)) {
            .eq, .gt => {
                if (has_master) return .master;
                return available_versions[0];
            },
            .lt => {
                inline for (available_versions[@intFromBool(has_master)..]) |build_runner_version| {
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
