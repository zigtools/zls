const std = @import("std");

pub fn isBuildRunnerSupported(runtime_zig_version: std.SemanticVersion) bool {
    _ = runtime_zig_version;
    // The `--build-runner` flag was removed in Zig 0.17.0-dev, and the custom
    // build runner was never properly wired up in the production code (the
    // `--build-runner` flag was never passed to `zig build`).
    //
    // TODO: Reimplement the build runner extraction for Zig 0.17+ using a
    // different approach (e.g., parsing build.zig AST directly, or using
    // `zig build --print-configuration` once it's complete).
    return false;
}

fn isBuildRunnerSupportedInternal(
    minimum_zig_version: std.SemanticVersion,
    param_zig_version: std.SemanticVersion,
    /// If set, a non-tagged zig version cannot be used when `minimum_runtime_zig_version` is a tagged version.
    /// Example: Zig `0.13.0-dev` cannot be used when the minimum Zig version is `0.12.0`.
    ///
    /// Will be set iff ZLS is a tagged release.
    strict: bool,
) bool {
    const minimum_version_is_tagged = minimum_zig_version.pre == null;

    var zig_version = param_zig_version;
    var version_is_tagged = zig_version.pre == null;

    if (!version_is_tagged and zig_version.patch != 0) {
        // A zig version like `0.12.2-dev` has the same compatibility as `0.12.1`
        zig_version.patch -= 1;
        zig_version.pre = null;
        version_is_tagged = true;
    }

    if (strict and !version_is_tagged) {
        std.debug.assert(minimum_version_is_tagged);
        // A tagged release of ZLS must be used with a tagged release of Zig.
        return false;
    }

    if (zig_version.major != minimum_zig_version.major) return false;

    if (minimum_version_is_tagged) {
        if (version_is_tagged) {
            if (zig_version.order(minimum_zig_version) == .lt) return false;
            const next_minor_release: std.SemanticVersion = .{
                .major = minimum_zig_version.major,
                .minor = minimum_zig_version.minor + 1,
                .patch = 0,
            };
            return zig_version.order(next_minor_release) == .lt;
        } else {
            std.debug.assert(zig_version.patch == 0);
            return zig_version.minor == 1 + minimum_zig_version.minor;
        }
    } else {
        if (version_is_tagged) return false;
        if (zig_version.minor != minimum_zig_version.minor) return false;
        return zig_version.order(minimum_zig_version) != .lt;
    }
}

// The build runner is currently disabled because the `--build-runner` flag was
// removed in Zig 0.17.0-dev. The `isBuildRunnerSupportedInternal` implementation
// below is kept for reference and its tests remain active.

// Version order for reference:
// 0.11.0-dev < 0.11.0 < 0.12.0-dev < 0.12.0 < 0.13.0-dev < 0.13.0

test isBuildRunnerSupportedInternal {
    var did_fail = false;
    for (test_cases) |test_case| {
        const minimum_runtime_zig_version: std.SemanticVersion = try .parse(test_case.minimum_runtime_zig_version);
        const runtime_zig_version: std.SemanticVersion = try .parse(test_case.runtime_zig_version);
        const minimum_runtime_version_is_tagged = minimum_runtime_zig_version.pre == null;
        const expected_if_strict, const expected_if_not_strict = switch (test_case.is_supported) {
            .yes => .{ true, true },
            .no => .{ false, false },
            .if_not_strict => .{ false, true },
        };

        const actual_if_not_strict = isBuildRunnerSupportedInternal(minimum_runtime_zig_version, runtime_zig_version, false);
        if (expected_if_not_strict != actual_if_not_strict) {
            std.debug.print("minimum={f}, actual={f}, strict={} -> expected {} but got {}\n", .{
                minimum_runtime_zig_version,
                runtime_zig_version,
                false,
                expected_if_not_strict,
                actual_if_not_strict,
            });
            did_fail = true;
        }

        if (minimum_runtime_version_is_tagged) {
            const actual_if_strict = isBuildRunnerSupportedInternal(minimum_runtime_zig_version, runtime_zig_version, true);
            if (expected_if_strict != actual_if_strict) {
                std.debug.print("minimum={f}, actual={f}, strict={} -> expected {} but got {}\n", .{
                    minimum_runtime_zig_version,
                    runtime_zig_version,
                    true,
                    expected_if_strict,
                    actual_if_strict,
                });
                did_fail = true;
            }
        }
    }
    if (did_fail) return error.Unexpected;
}

const test_cases: []const struct {
    minimum_runtime_zig_version: []const u8,
    runtime_zig_version: []const u8,
    is_supported: enum { yes, no, if_not_strict },
} = &.{
    // Minimum Zig Version: 0.12.0
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.11.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.0",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.1-dev",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.12.1",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.0-dev",
        .is_supported = .if_not_strict,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0",
        .runtime_zig_version = "0.13.1-dev",
        .is_supported = .no,
    },
    // Minimum Zig Version: 0.12.1
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.11.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.1-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.1",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.2-dev",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.12.2",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.0-dev",
        .is_supported = .if_not_strict,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.1-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.1",
        .runtime_zig_version = "0.13.1",
        .is_supported = .no,
    },
    // Minimum Zig Version: 0.12.0-dev.5
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.11.0-dev",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.11.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.4",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.5",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0-dev.10",
        .is_supported = .yes,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.0",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.12.1",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.13.0-dev.10",
        .is_supported = .no,
    },
    .{
        .minimum_runtime_zig_version = "0.12.0-dev.5",
        .runtime_zig_version = "0.13.0",
        .is_supported = .no,
    },
};
