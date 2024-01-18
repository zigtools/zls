const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("helper.zig");
const ErrorBuilder = @import("ErrorBuilder.zig");

const Module = zls.analyser.Module;
const InternPool = zls.analyser.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const Analyser = zls.Analyser;
const offsets = zls.offsets;

pub const std_options = struct {
    pub const log_level = .warn;
};

const Error = error{
    OutOfMemory,
    InvalidTestItem,

    ExpectedErrorMessage,
    UnexpectedErrorMessages,
    WrongErrorMessage,
    IdentifierNotFound,
    WrongType,
    WrongValue,
};

pub fn main() Error!void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const gpa = general_purpose_allocator.allocator();

    const stderr = std.io.getStdErr().writer();

    var arg_it = std.process.argsWithAllocator(gpa) catch |err| std.debug.panic("failed to collect args: {}", .{err});
    defer arg_it.deinit();

    _ = arg_it.skip();

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var files = std.ArrayListUnmanaged([]const u8){};
    var is_fuzz = false;

    var config = zls.Config{
        .analysis_backend = .astgen_analyser,
    };

    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--")) {
            while (arg_it.next()) |path| {
                // std.debug.print("file_path: {s}\n", .{path});
                try files.append(arena, try arena.dupe(u8, path));
            }
            break;
        } else if (std.mem.eql(u8, arg, "--zig-exe-path")) {
            const zig_exe_path = arg_it.next() orelse {
                stderr.print("expected argument after '--zig-exe-path'.\n", .{}) catch {};
                std.process.exit(1);
            };
            config.zig_exe_path = try arena.dupe(u8, zig_exe_path);
        } else if (std.mem.eql(u8, arg, "--zig-lib-path")) {
            const zig_lib_path = arg_it.next() orelse {
                stderr.print("expected argument after '--zig-lib-path'.\n", .{}) catch {};
                std.process.exit(1);
            };
            config.zig_lib_path = try arena.dupe(u8, zig_lib_path);
        } else if (std.mem.eql(u8, arg, "--fuzz")) {
            is_fuzz = true;
        } else {
            stderr.print("Unrecognized argument '{s}'.\n", .{arg}) catch {};
            std.process.exit(1);
        }
    }

    var ip = try InternPool.init(gpa);
    defer ip.deinit(gpa);

    var document_store = zls.DocumentStore{
        .allocator = gpa,
        .config = &config,
        .runtime_zig_version = &@as(?zls.ZigVersionWrapper, null),
    };
    var mod = Module.init(gpa, &ip, &document_store);
    document_store.mod = &mod;

    defer mod.deinit();
    defer document_store.deinit();

    var error_builder = ErrorBuilder.init(gpa);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();
    error_builder.file_name_visibility = .always;

    var previous_handle_uri: ?[]const u8 = null;
    var previous_eb_filename: ?[]const u8 = null;

    for (files.items, 0..) |file_path, increment| {
        const file = std.fs.openFileAbsolute(file_path, .{}) catch |err| std.debug.panic("failed to open {s}: {}", .{ file_path, err });
        defer file.close();

        const source = file.readToEndAllocOptions(gpa, std.math.maxInt(usize), null, @alignOf(u8), 0) catch |err|
            std.debug.panic("failed to read from {s}: {}", .{ file_path, err });

        const handle_uri = try zls.URI.fromPath(arena, file_path);

        if (increment == 0) {
            defer gpa.free(source);
            try document_store.openDocument(handle_uri, source);
            previous_handle_uri = handle_uri;
        } else {
            try document_store.refreshDocument(previous_handle_uri.?, source);
            // rename handle
            document_store.handles.getKeyPtr(previous_handle_uri.?).?.* = handle_uri;
            try document_store.handles.reIndex(document_store.allocator);
        }
        const handle: *zls.DocumentStore.Handle = document_store.handles.get(handle_uri).?;

        if (previous_eb_filename) |name| {
            error_builder.removeFile(name);
        }
        try error_builder.addFile(file_path, handle.tree.source);
        previous_eb_filename = file_path;

        std.debug.assert(handle.getZirStatus() == .done);
        std.debug.assert(handle.tree.errors.len == 0); // TODO show in error builder
        std.debug.assert(!handle.getCachedZir().hasCompileErrors()); // TODO show in error builder
        std.debug.assert(handle.root_decl != .none);

        if (is_fuzz) {
            if (handle.analysis_errors.items.len == 0) return;
            for (handle.analysis_errors.items) |err_msg| {
                try error_builder.msgAtLoc("unexpected error '{s}'", file_path, err_msg.loc, .err, .{err_msg.message});
            }
            return error.UnexpectedErrorMessages; // semantic analysis produced errors on its own codebase which are likely false positives
        }

        var visited = try std.DynamicBitSetUnmanaged.initEmpty(gpa, handle.analysis_errors.items.len);
        defer visited.deinit(gpa);

        const annotations = helper.collectAnnotatedSourceLocations(gpa, handle.tree.source) catch |err| switch (err) {
            error.InvalidSourceLoc => std.debug.panic("{s} contains invalid annotated source locations: {}", .{ file_path, err }),
            error.OutOfMemory => |e| return e,
        };
        defer gpa.free(annotations);

        for (annotations) |annotation| {
            const identifier_loc = annotation.loc;
            const identifier = offsets.locToSlice(handle.tree.source, identifier_loc);
            const test_item = parseAnnotatedSourceLoc(annotation) catch |err| {
                try error_builder.msgAtLoc("invalid annotated source location '{s}'", file_path, annotation.loc, .err, .{
                    annotation.content,
                });
                return err;
            };

            if (test_item.expected_error) |expected_error| {
                const actual_error: zls.DocumentStore.ErrorMessage = for (handle.analysis_errors.items, 0..) |actual_error, i| {
                    if (!std.meta.eql(actual_error.loc, annotation.loc)) continue;
                    std.debug.assert(!visited.isSet(i)); // duplicate error message
                    visited.set(i);
                    break actual_error;
                } else {
                    try error_builder.msgAtLoc("expected error message '{s}'", file_path, annotation.loc, .err, .{
                        expected_error,
                    });
                    return error.ExpectedErrorMessage;
                };

                if (!std.mem.eql(u8, expected_error, actual_error.message)) {
                    try error_builder.msgAtLoc("expected error message '{s}' but got '{s}'", file_path, annotation.loc, .err, .{
                        expected_error,
                        actual_error.message,
                    });
                    return error.WrongErrorMessage;
                }

                continue;
            }

            const found_decl_index = lookupDeclIndex(&mod, handle, identifier_loc) orelse {
                try error_builder.msgAtLoc("couldn't find identifier `{s}` here", file_path, identifier_loc, .err, .{identifier});
                return error.IdentifierNotFound;
            };

            if (test_item.expected_type) |expected_type| {
                const val: InternPool.Index = found_decl_index;
                const ty: InternPool.Index = if (val == .none) .none else mod.ip.typeOf(val);
                const actual_type = try std.fmt.allocPrint(gpa, "{}", .{ty.fmtDebug(mod.ip)});
                defer gpa.free(actual_type);
                if (!std.mem.eql(u8, expected_type, actual_type)) {
                    try error_builder.msgAtLoc("expected type `{s}` but got `{s}`", file_path, identifier_loc, .err, .{
                        expected_type,
                        actual_type,
                    });
                    return error.WrongType;
                }
            }

            if (test_item.expected_value) |expected_value| {
                const val: InternPool.Index = found_decl_index;
                const actual_value = try std.fmt.allocPrint(gpa, "{}", .{val.fmt(mod.ip)});
                defer gpa.free(actual_value);
                if (!std.mem.eql(u8, expected_value, actual_value)) {
                    try error_builder.msgAtLoc("expected value `{s}` but got `{s}`", file_path, identifier_loc, .err, .{
                        expected_value,
                        actual_value,
                    });
                    return error.WrongValue;
                }
            }
        }

        var has_unexpected_errors = false;
        var it = visited.iterator(.{ .kind = .unset });
        while (it.next()) |index| {
            const err_msg: zls.DocumentStore.ErrorMessage = handle.analysis_errors.items[index];
            try error_builder.msgAtLoc("unexpected error message '{s}'", file_path, err_msg.loc, .err, .{
                err_msg.message,
            });
            has_unexpected_errors = true;
        }
        if (has_unexpected_errors) return error.UnexpectedErrorMessages;
    }
}

fn lookupDeclIndex(mod: *Module, handle: *zls.DocumentStore.Handle, identifier_loc: offsets.Loc) ?InternPool.Index {
    const document_scope = handle.getDocumentScope() catch unreachable;
    const identifier = offsets.locToSlice(handle.tree.source, identifier_loc);
    if (Analyser.lookupDeclaration(document_scope, identifier_loc.start, identifier, .other).unwrap()) |decl_index| {
        switch (document_scope.declarations.get(@intFromEnum(decl_index))) {
            .intern_pool_index => |payload| {
                std.debug.assert(std.mem.eql(u8, identifier, offsets.tokenToSlice(handle.tree, payload.name)));
                return payload.index;
            },
            else => {},
        }
    }

    const identifier_index = mod.ip.string_pool.getString(identifier) orelse return null;

    // this is not how you are supposed to lookup identifiers but its good enough for now
    var decl_it = mod.ip.decls.constIterator(0);
    while (decl_it.next()) |decl| {
        if (decl.name != identifier_index) continue;
        return decl.index;
    }
    return null;
}

const TestItem = struct {
    loc: offsets.Loc,
    expected_type: ?[]const u8 = null,
    expected_value: ?[]const u8 = null,
    expected_error: ?[]const u8 = null,
};

fn parseAnnotatedSourceLoc(annotation: helper.AnnotatedSourceLoc) error{InvalidTestItem}!TestItem {
    const str = annotation.content;

    if (std.mem.startsWith(u8, str, "error:")) {
        return .{
            .loc = annotation.loc,
            .expected_error = std.mem.trim(u8, str["error:".len..], &std.ascii.whitespace),
        };
    }

    if (!std.mem.startsWith(u8, str, "(")) return error.InvalidTestItem;
    const expected_type_start = 1;
    const expected_type_end = expected_type_start + (findClosingBrace(str[expected_type_start..]) orelse return error.InvalidTestItem);

    if (!std.mem.startsWith(u8, str[expected_type_end + 1 ..], "(")) return error.InvalidTestItem;
    const expected_value_start = expected_type_end + 2;
    const expected_value_end = expected_value_start + (findClosingBrace(str[expected_value_start..]) orelse return error.InvalidTestItem);

    const expected_type = std.mem.trim(
        u8,
        offsets.locToSlice(str, .{ .start = expected_type_start, .end = expected_type_end }),
        &std.ascii.whitespace,
    );
    const expected_value = std.mem.trim(
        u8,
        offsets.locToSlice(str, .{ .start = expected_value_start, .end = expected_value_end }),
        &std.ascii.whitespace,
    );

    return .{
        .loc = annotation.loc,
        .expected_type = if (expected_type.len != 0) expected_type else null,
        .expected_value = if (expected_value.len != 0) expected_value else null,
    };
}

fn findClosingBrace(source: []const u8) ?usize {
    var depth: usize = 0;
    for (source, 0..) |c, i| {
        switch (c) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) return i;
                depth -= 1;
            },
            else => continue,
        }
    }
    return null;
}
