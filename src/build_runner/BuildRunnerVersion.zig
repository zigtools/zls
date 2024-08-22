const std = @import("std");
const build_options = @import("build_options");

/// These versions must be ordered from newest to oldest.
/// There should be no need to have a build runner for minor patches (e.g. 0.10.1)
///
/// A "master" build runner should only be added if it is infeasible to make the latest build runner compatible with Zig master.
///
/// The GitHub matrix in `.github\workflows\build_runner.yml` should be updated to check Zig master with the latest build runner file.
pub const BuildRunnerVersion = enum {
    // master,
    @"0.13.0",
    @"0.12.0",

    pub fn isTaggedRelease(version: BuildRunnerVersion) bool {
        return !@hasField(BuildRunnerVersion, "master") or version != .master;
    }

    pub fn selectBuildRunnerVersion(runtime_zig_version: std.SemanticVersion) ?BuildRunnerVersion {
        const minimum_runtime_zig_version = comptime std.SemanticVersion.parse(build_options.minimum_runtime_zig_version_string) catch unreachable;
        return selectVersionInternal(BuildRunnerVersion, minimum_runtime_zig_version, runtime_zig_version);
    }

    pub fn getBuildRunnerFile(version: BuildRunnerVersion) [:0]const u8 {
        return switch (version) {
            // .master => @embedFile("master.zig"),
            .@"0.13.0" => @embedFile("0.12.0.zig"), // The Zig 0.12.0 build runner is also compatible with Zig 0.13.0
            .@"0.12.0" => @embedFile("0.12.0.zig"),
        };
    }

    pub const Hasher = std.crypto.auth.siphash.SipHash128(1, 3);
    pub const Hash = [Hasher.mac_length]u8;

    pub fn getBuildRunnerFileHash(version: BuildRunnerVersion) Hash {
        const source = version.getBuildRunnerFile();
        var hash: Hash = undefined;
        var hasher: Hasher = Hasher.init(&[_]u8{0} ** Hasher.key_length);
        hasher.update(source);
        hasher.final(&hash);
        return hash;
    }
};

fn selectVersionInternal(
    comptime AvailableVersion: type,
    /// Only relevant when the ZLS version is a development build
    comptime minimum_runtime_zig_version: std.SemanticVersion,
    runtime_zig_version: std.SemanticVersion,
) ?AvailableVersion {
    const runtime_zig_version_is_tagged = runtime_zig_version.build == null and runtime_zig_version.pre == null;
    const minimum_runtime_zig_version_is_tagged = minimum_runtime_zig_version.build == null and minimum_runtime_zig_version.pre == null;

    const available_version_tags = comptime std.meta.tags(AvailableVersion);
    // `null` means master
    const available_versions = comptime blk: {
        var versions: [available_version_tags.len]?std.SemanticVersion = undefined;
        for (available_version_tags, &versions) |tag, *version| {
            if (@hasField(AvailableVersion, "master") and tag == .master) {
                version.* = null;
            } else {
                version.* = std.SemanticVersion.parse(@tagName(tag)) catch unreachable;
                std.debug.assert(version.*.?.patch == 0 and version.*.?.build == null and version.*.?.pre == null);
            }
        }
        break :blk versions;
    };

    comptime {
        std.debug.assert(available_version_tags.len != 0);
        std.debug.assert(available_version_tags.len == available_versions.len);
        std.debug.assert(minimum_runtime_zig_version_is_tagged == !@hasField(AvailableVersion, "master"));
    }

    if (runtime_zig_version_is_tagged) {
        const runtime_zig_version_simple: std.SemanticVersion = .{ .major = runtime_zig_version.major, .minor = runtime_zig_version.minor, .patch = 0 };
        inline for (available_version_tags, available_versions) |tag, version| {
            switch (runtime_zig_version_simple.order(version orelse continue)) {
                .eq => return tag,
                .lt, .gt => {},
            }
        }
        return null;
    }

    switch (runtime_zig_version.order(available_versions[0] orelse minimum_runtime_zig_version)) {
        .eq, .gt => return available_version_tags[0],
        .lt => return null,
    }
}

test selectVersionInternal {
    @setEvalBranchQuota(6_000);
    const expect = std.testing.expect;
    const expectEqual = std.testing.expectEqual;
    const parse = std.SemanticVersion.parse;

    // 0.11.0-dev < 0.11.0 < 0.12.0-dev < 0.12.0 < 0.13.0-dev < 0.13.0

    {
        const current_zig_version = @import("builtin").zig_version;
        const build_runner = BuildRunnerVersion.selectBuildRunnerVersion(current_zig_version);
        if (build_runner == null) {
            std.debug.print(
                \\ZLS is being tested with Zig {}.
                \\No build runner could be resolved for this Zig version!
                \\
            , .{current_zig_version});
            return error.TestUnexpectedResult;
        }
    }

    {
        const is_zls_version_tagged_release = build_options.version.build == null and build_options.version.pre == null;
        if (is_zls_version_tagged_release) {
            // A tagged release of ZLS should support the same tagged release of Zig
            // Example: ZLS 0.12.0 should support Zig 0.12.0
            const build_runner = BuildRunnerVersion.selectBuildRunnerVersion(build_options.version);
            try expect(build_runner != null);
            try expect(build_runner.?.isTaggedRelease());
        } else {
            // A development build of ZLS should support the latest tagged release of Zig
            // Example: ZLS 0.13.0-dev.1+aaaaaaaaa should support Zig 0.12.0
            const build_runner = BuildRunnerVersion.selectBuildRunnerVersion(.{ .major = build_options.version.major, .minor = build_options.version.minor - 1, .patch = 0 });
            try expect(build_runner != null);
            try expect(build_runner.?.isTaggedRelease());
        }
    }

    {
        const AvailableVersion = enum { @"0.12.0" };

        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.11.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.1"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.13.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.13.0"), // Zig version
        ));
    }

    {
        const AvailableVersion = enum { @"0.12.0", @"0.11.0" };

        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.11.0"), // minimum Zig version on master
            try parse("0.11.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.11.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.11.0"), // minimum Zig version on master
            try parse("0.11.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.11.0"), // minimum Zig version on master
            try parse("0.12.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.11.0"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));

        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.10.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.11.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.11.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.11.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.12.1"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.13.0-dev.1+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.12.0"), // minimum Zig version on master
            try parse("0.13.0"), // Zig version
        ));
    }

    {
        const AvailableVersion = enum { master, @"0.12.0", @"0.11.0" };

        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.11.0-dev.5+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.11.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.11.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.12.0-dev.5+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.12.0"), // Zig version
        ));
        try expectEqual(.@"0.12.0", selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.12.1"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.13.0-dev.4+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.master, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.13.0-dev.5+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(.master, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.13.0-dev.10+aaaaaaaaa"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.13.0"), // Zig version
        ));
        try expectEqual(null, selectVersionInternal(
            AvailableVersion, // available build runners
            try parse("0.13.0-dev.5+aaaaaaaaa"), // minimum Zig version on master
            try parse("0.13.1"), // Zig version
        ));
    }
}
