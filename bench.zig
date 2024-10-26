const std = @import("std");
const zls = @import("zls");
const Context = @import("tests/context.zig").Context;

const iteration_count: usize = 100;
/// When comparing measurements, be sure to reuse the same seed.
const seed: ?u64 = 3829500786504880821;

/// Number of package imports. Does not include builtin imports or aliases.
const number_of_package_imports: usize = 1_000;
/// Number of root decls that are not imports
const number_of_non_import_decls: usize = 10_000;
/// percent of package imports that will have aliases
const percent_of_imports_with_aliases: f64 = 0.3;
/// imports with aliases will have evenely distributed number of aliases from `[1..max_number_of_aliases]`
const max_number_of_aliases: usize = 3;
/// imports with aliases will have evenely distributed number of field accesses from `[0..max_number_of_alias_fields]`
const max_number_of_alias_fields: usize = 5;

fn genRandomName(random: std.Random) [8]u8 {
    var result: [8]u8 = undefined;
    for (&result) |*c| {
        c.* = random.intRangeAtMost(u8, 97, 122);
    }
    return result;
}

pub fn main() !void {
    var allocator_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = allocator_state.deinit();

    const gpa = allocator_state.allocator();

    var context = try Context.initWithAllocator(gpa);
    defer context.deinit();

    const selected_seed = seed orelse std.crypto.random.int(u64);
    std.log.info("seed={d}", .{selected_seed});

    var random_gen = std.Random.DefaultPrng.init(selected_seed);
    const random = random_gen.random();

    var buffer: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (buffer.items) |line| gpa.free(line);
        buffer.deinit(gpa);
    }

    try buffer.ensureUnusedCapacity(gpa, 3);
    buffer.appendAssumeCapacity(try gpa.dupe(u8, "pub const std = @import(\"std\");"));
    buffer.appendAssumeCapacity(try gpa.dupe(u8, "pub const builtin = @import(\"builtin\");"));
    buffer.appendAssumeCapacity(try gpa.dupe(u8, "pub const root = @import(\"root\");"));

    try buffer.ensureUnusedCapacity(gpa, number_of_non_import_decls);
    for (0..number_of_non_import_decls) |_| {
        const name = genRandomName(random);

        buffer.appendAssumeCapacity(try std.fmt.allocPrint(gpa, "fn {}() void {{}}", .{
            std.zig.fmtId(&name),
        }));
    }

    for (0..number_of_package_imports) |_| {
        const name = genRandomName(random);

        try buffer.ensureUnusedCapacity(gpa, 1);
        buffer.appendAssumeCapacity(try std.fmt.allocPrint(gpa, "const {} = @import(\"{}\");", .{
            std.zig.fmtId(&name),
            std.zig.fmtEscapes(&name),
        }));

        if (random.float(f64) < percent_of_imports_with_aliases) {
            for (0..random.intRangeAtMost(usize, 1, max_number_of_aliases)) |_| {
                const alias_name = genRandomName(random);

                var line_buffer: std.ArrayListUnmanaged(u8) = .{};
                errdefer line_buffer.deinit(gpa);

                try line_buffer.writer(gpa).print("const {} = {}", .{
                    std.zig.fmtId(&alias_name),
                    std.zig.fmtId(&name),
                });

                for (0..random.intRangeAtMost(usize, 0, max_number_of_alias_fields)) |_| {
                    const field_name = genRandomName(random);
                    try line_buffer.writer(gpa).print(".{}", .{
                        std.zig.fmtId(&field_name),
                    });
                }

                try line_buffer.append(gpa, ';');

                try buffer.ensureUnusedCapacity(gpa, 1);
                buffer.appendAssumeCapacity(try line_buffer.toOwnedSlice(gpa));
            }
        }
    }

    random.shuffle([]const u8, buffer.items);

    const source = try std.mem.join(gpa, "\n", buffer.items);
    defer gpa.free(source);

    // uncomment this to show the document
    //
    // std.debug.print("{s}\n\n", .{source});

    const uri = try context.addDocument(source);
    const handle = context.server.document_store.getHandle(uri).?;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();

    var analyser = zls.Analyser.init(gpa, &context.server.document_store, &context.server.ip, null);
    defer analyser.deinit();

    var builder: zls.code_actions.Builder = .{
        .arena = arena_allocator.allocator(),
        .analyser = &analyser,
        .handle = handle,
        .offset_encoding = context.server.offset_encoding,
    };

    var timer = try std.time.Timer.start();

    var actions: std.ArrayListUnmanaged(zls.types.CodeAction) = .{};
    for (0..iteration_count) |_| {
        defer actions.clearRetainingCapacity();
        try builder.generateOrganizeImportsAction(&actions);
        std.debug.assert(actions.items.len == 1);
    }

    const total_time_ns = timer.read();
    const time_per_it_ns = total_time_ns / iteration_count;

    std.log.info("total_time={}, iteration_count={d}, time_per_iteration={}\n", .{
        std.fmt.fmtDuration(total_time_ns),
        iteration_count,
        std.fmt.fmtDuration(time_per_it_ns),
    });
}
