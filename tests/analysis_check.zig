//! This file implements a standalone executable that is used by
//! `add_analysis_cases.zig` to run code analysis tests.
//! See the `./analysis` subdirectory.

const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("helper.zig");
const ErrorBuilder = @import("ErrorBuilder.zig");

const InternPool = zls.analyser.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const Analyser = zls.Analyser;
const offsets = zls.offsets;

pub const std_options: std.Options = .{
    .log_level = .warn,
};

const Error = error{
    OutOfMemory,
    InvalidTestItem,

    IdentifierNotFound,
    ResolveTypeFailed,
    WrongType,
    WrongValue,
};

pub fn main() Error!void {
    var general_purpose_allocator: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = general_purpose_allocator.deinit();
    const gpa = general_purpose_allocator.allocator();

    var arg_it = std.process.argsWithAllocator(gpa) catch |err| std.debug.panic("failed to collect args: {}", .{err});
    defer arg_it.deinit();

    _ = arg_it.skip();

    var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
    defer arena_allocator.deinit();

    const arena = arena_allocator.allocator();

    var config: zls.Config = .{};

    var opt_file_path: ?[]const u8 = null;

    while (arg_it.next()) |arg| {
        if (!std.mem.startsWith(u8, arg, "--")) {
            if (opt_file_path != null) {
                std.log.err("duplicate source file argument", .{});
                std.process.exit(1);
            } else {
                opt_file_path = try arena.dupe(u8, arg);
            }
        } else if (std.mem.eql(u8, arg, "--zig-exe-path")) {
            const zig_exe_path = arg_it.next() orelse {
                std.log.err("expected argument after '--zig-exe-path'.", .{});
                std.process.exit(1);
            };
            config.zig_exe_path = try arena.dupe(u8, zig_exe_path);
        } else if (std.mem.eql(u8, arg, "--zig-lib-path")) {
            const zig_lib_path = arg_it.next() orelse {
                std.log.err("expected argument after '--zig-lib-path'.", .{});
                std.process.exit(1);
            };
            config.zig_lib_path = try arena.dupe(u8, zig_lib_path);
        } else {
            std.log.err("Unrecognized argument '{s}'.", .{arg});
            std.process.exit(1);
        }
    }

    var thread_pool: if (builtin.single_threaded) void else std.Thread.Pool = undefined;
    if (builtin.single_threaded) {
        thread_pool = {};
    } else {
        thread_pool.init(.{
            .allocator = gpa,
        }) catch std.debug.panic("failed to initalize thread pool", .{});
    }
    defer if (!builtin.single_threaded) thread_pool.deinit();

    var ip: InternPool = try .init(gpa);
    defer ip.deinit(gpa);

    var diagnostics_collection: zls.DiagnosticsCollection = .{ .allocator = gpa };
    defer diagnostics_collection.deinit();

    var document_store: zls.DocumentStore = .{
        .allocator = gpa,
        .config = .fromMainConfig(config),
        .thread_pool = &thread_pool,
        .diagnostics_collection = &diagnostics_collection,
    };
    defer document_store.deinit();

    const file_path = opt_file_path orelse {
        std.log.err("Missing source file path argument", .{});
        std.process.exit(1);
    };

    const file = std.fs.openFileAbsolute(file_path, .{}) catch |err| std.debug.panic("failed to open {s}: {}", .{ file_path, err });
    defer file.close();

    const source = file.readToEndAllocOptions(gpa, std.math.maxInt(usize), null, .of(u8), 0) catch |err|
        std.debug.panic("failed to read from {s}: {}", .{ file_path, err });
    defer gpa.free(source);

    const handle_uri = try zls.URI.fromPath(arena, file_path);
    try document_store.openDocument(handle_uri, source);
    const handle: *zls.DocumentStore.Handle = document_store.handles.get(handle_uri).?;

    var error_builder: ErrorBuilder = .init(gpa);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();
    error_builder.file_name_visibility = .always;

    try error_builder.addFile(file_path, handle.tree.source);

    const annotations = helper.collectAnnotatedSourceLocations(gpa, handle.tree.source) catch |err| switch (err) {
        error.InvalidSourceLoc => std.debug.panic("{s} contains invalid annotated source locations: {}", .{ file_path, err }),
        error.OutOfMemory => |e| return e,
    };
    defer gpa.free(annotations);

    var analyser = zls.Analyser.init(gpa, &document_store, &ip, handle);
    defer analyser.deinit();

    for (annotations) |annotation| {
        var identifier_loc = annotation.loc;
        var identifier = offsets.locToSlice(handle.tree.source, annotation.loc);

        const is_enum_literal = identifier[0] == '.';
        if (is_enum_literal) {
            identifier_loc.start += 1;
            identifier = identifier[1..];
        }

        const test_item = parseAnnotatedSourceLoc(annotation) catch |err| {
            try error_builder.msgAtLoc("invalid annotated source location '{s}'", file_path, annotation.loc, .err, .{
                annotation.content,
            });
            return err;
        };

        const decl_maybe = if (is_enum_literal)
            try analyser.getSymbolEnumLiteral(handle, identifier_loc.start, identifier)
        else
            try analyser.lookupSymbolGlobal(handle, identifier, identifier_loc.start);

        const decl = decl_maybe orelse {
            try error_builder.msgAtLoc("failed to find identifier '{s}' here", file_path, annotation.loc, .err, .{
                annotation.content,
            });
            return error.IdentifierNotFound;
        };

        const expect_unknown = (if (test_item.expected_type) |expected_type| std.mem.eql(u8, expected_type, "unknown") else false) and
            (if (test_item.expected_value) |expected_value| std.mem.eql(u8, expected_value, "unknown") else true) and
            test_item.expected_error == null;

        const ty = try decl.resolveType(&analyser) orelse {
            if (expect_unknown) continue;
            try error_builder.msgAtLoc("failed to resolve type of '{s}'", file_path, annotation.loc, .err, .{
                identifier,
            });
            return error.ResolveTypeFailed;
        };

        if (expect_unknown) {
            const actual_type = try std.fmt.allocPrint(gpa, "{}", .{ty.fmt(&analyser, .{
                .truncate_container_decls = false,
            })});
            defer gpa.free(actual_type);

            try error_builder.msgAtLoc("expected unknown but got `{s}`", file_path, identifier_loc, .err, .{
                actual_type,
            });
            return error.WrongType;
        }

        if (test_item.expected_error) |_| {
            @panic("unsupported");
        }

        if (test_item.expected_type) |expected_type| {
            const actual_type = try std.fmt.allocPrint(gpa, "{}", .{ty.fmt(&analyser, .{
                .truncate_container_decls = false,
            })});
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
            if (ty.data != .ip_index and !ty.is_type_val) {
                try error_builder.msgAtLoc("unsupported value check `{s}`", file_path, identifier_loc, .err, .{
                    expected_value,
                });
                return error.WrongValue;
            }

            const actual_value = try std.fmt.allocPrint(gpa, "{}", .{ty.fmtTypeVal(&analyser, .{
                .truncate_container_decls = false,
            })});
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
