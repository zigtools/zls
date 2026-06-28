//! Request handling structures and properties used for the custom `customZig/listBuildSteps`
//! server endpoint. The endpoint expects a `params` object of type `{ workspaceUri: string }`.
//! The handler method is `extractBuildStepsInfoHandler` and the method name is contained in
//! the `method_name` property.
//!
//! Upon successful extraction, the handler returns an array of type `BuildStepInfo`,
//! which is a simple structure containing the step's name and description, as defined
//! in the workspace's root `build.zig` file.

const std = @import("std");
const DocumentStore = @import("../DocumentStore.zig");
const Server = @import("../Server.zig");
const tracy = @import("tracy");
const Uri = @import("../Uri.zig");

const log = std.log.scoped(.list_build_steps);

/// The method name for the custom server endpoint.
pub const method_name = "customZig/listBuildSteps";

const Params = struct {
    const workspace_uri_key = "workspaceUri";

    workspace_uri: []const u8,

    pub fn fromJson(value: ?std.json.Value) ?@This() {
        const v = value orelse return null;
        if (v != .object) return null;
        const workspace_uri_value = v.object.get(workspace_uri_key) orelse return null;
        switch (workspace_uri_value) {
            .string => |s| return .{ .workspace_uri = s },
            else => return null,
        }
    }
};

pub const BuildStepInfo = struct {
    name: []const u8,
    description: []const u8,

    pub fn init(arena: std.mem.Allocator, name: []const u8, description: []const u8) std.mem.Allocator.Error!@This() {
        const allocated_name = try std.fmt.allocPrint(arena, "{s}", .{name});
        const allocated_description = try std.fmt.allocPrint(arena, "{s}", .{description});
        return .{ .name = allocated_name, .description = allocated_description };
    }
};

/// A request handler that extracts top-level build steps from the document
/// store using the workspace URI provided in the `params` object.
pub fn extractBuildStepsInfoHandler(server: *Server, arena: std.mem.Allocator, params: ?std.json.Value) error{ InvalidParams, OutOfMemory, Canceled }!std.ArrayList(BuildStepInfo) {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!DocumentStore.supports_build_system) {
        return .empty;
    }

    var workspace_uri: Uri = undefined;
    if (Params.fromJson(params)) |p| {
        _ = blk: {
            for (server.workspaces.items) |w| {
                if (std.mem.eql(u8, w.uri.raw, p.workspace_uri)) {
                    workspace_uri = w.uri;
                    break :blk;
                }
            }
            // log.debug("Could not find {s} in workspace list", .{p.workspace_uri});
            return error.InvalidParams;
        };
    } else {
        // log.debug("No information available regarding root 'build.zig' file, so returning empty array", .{});
        return error.InvalidParams;
    }

    const build_file_path = try std.fmt.allocPrint(arena, "{s}/build.zig", .{workspace_uri.raw});
    const build_file_uri = Uri.parse(arena, build_file_path) catch |err| {
        // log.err("Failed to parse build file path {s} as URI: {}", .{ build_file_path, err });
        switch (err) {
            error.OutOfMemory => |e| return e,
            else => return error.InvalidParams,
        }
    };

    server.document_store.primeBuildFile(build_file_uri) catch |err| {
        switch (err) {
            error.Canceled, error.OutOfMemory => |e| return e,
            else => { // `InvalidBuildFileUri` (should not be possible) or `DocumentStoreDoesNotSupportBuildSystem` (not possible at this point)
                log.err("Failed to prime build file {s}: {}", .{ build_file_uri.raw, err });
                return .empty;
            },
        }
    };

    try server.document_store.mutex.lock(server.io);
    defer server.document_store.mutex.unlock(server.io);

    const build_file = server.document_store.build_files.get(build_file_uri) orelse {
        return .empty;
    };

    var items: std.ArrayList(BuildStepInfo) = .empty;

    if (build_file.tryLockConfig(server.io)) |config| {
        defer build_file.unlockConfig(server.io);
        for (config.top_level_steps) |step_info| {
            log.debug("Build step found in {s}: name = {s}; description = {s}", .{ build_file.uri.raw, step_info.name, step_info.description });
            const item: BuildStepInfo = try .init(arena, step_info.name, step_info.description);
            try items.append(arena, item);
        }
    } else {
        log.debug("Failed to lock build file for {s}", .{build_file.uri.raw});
    }

    return items;
}
