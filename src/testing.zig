//! Custom unit testing utilities similar to `std.testing`.

const std = @import("std");
const builtin = @import("builtin");
const DocumentScope = @import("DocumentScope.zig");

pub const print_ast = @import("print_ast.zig");

pub fn expectEqual(expected: anytype, actual: anytype) error{TestExpectedEqual}!void {
    const allocator = std.testing.allocator;

    const options: std.json.Stringify.Options = .{
        .whitespace = .indent_2,
        .emit_null_optional_fields = false,
    };

    const expected_stringified = std.json.Stringify.valueAlloc(allocator, expected, options) catch @panic("OOM");
    defer allocator.free(expected_stringified);

    const actual_stringified = std.json.Stringify.valueAlloc(allocator, actual, options) catch @panic("OOM");
    defer allocator.free(actual_stringified);

    if (std.mem.eql(u8, expected_stringified, actual_stringified)) return;
    renderLineDiff(allocator, expected_stringified, actual_stringified);
    return error.TestExpectedEqual;
}

pub fn expectEqualStrings(expected: []const u8, actual: []const u8) error{TestExpectedEqual}!void {
    if (std.mem.eql(u8, expected, actual)) return;
    renderLineDiff(std.testing.allocator, expected, actual);
    return error.TestExpectedEqual;
}

pub fn printDocumentScope(doc_scope: DocumentScope) void {
    if (builtin.mode != .Debug) @compileError("this function should only be used in debug mode!");

    for (0..doc_scope.scopes.len) |index| {
        const scope_index: DocumentScope.Scope.Index = @enumFromInt(index);
        const scope = doc_scope.scopes.get(index);
        if (index != 0) std.debug.print("\n\n", .{});
        std.debug.print(
            \\[{d}, {d}]
            \\  tag: {}
            \\  ast node: {?}
            \\  parent: {}
            \\  child scopes: {any}
            \\  decls:
            \\
        , .{
            scope.loc.start,
            scope.loc.end,
            scope.data.tag,
            doc_scope.getScopeAstNode(scope_index),
            doc_scope.getScopeParent(scope_index),
            doc_scope.getScopeChildScopesConst(scope_index),
        });

        for (doc_scope.getScopeDeclarationsConst(scope_index)) |decl| {
            std.debug.print("    - {s:<8} {}\n", .{
                doc_scope.declaration_lookup_map.keys()[@intFromEnum(decl)].name,
                doc_scope.declarations.get(@intFromEnum(decl)),
            });
        }
    }
}

pub const FailingAllocator = struct {
    internal_allocator: std.mem.Allocator,
    random: std.Random.DefaultPrng,
    likelihood: u32,

    /// the chance that an allocation will fail is `1/likelihood`
    /// `likelihood == 0` means that every allocation will fail
    /// `likelihood == std.math.intMax(u32)` means that no allocation will be forced to fail
    pub fn init(internal_allocator: std.mem.Allocator, likelihood: u32) FailingAllocator {
        return .{
            .internal_allocator = internal_allocator,
            .random = .init(std.crypto.random.int(u64)),
            .likelihood = likelihood,
        };
    }

    pub fn allocator(self: *FailingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (shouldFail(self)) return null;
        return self.internal_allocator.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        return self.internal_allocator.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        return self.internal_allocator.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        self.internal_allocator.rawFree(memory, alignment, ret_addr);
    }

    fn shouldFail(self: *FailingAllocator) bool {
        if (self.likelihood == std.math.maxInt(u32)) return false;
        return 0 == self.random.random().intRangeAtMostBiased(u32, 0, self.likelihood);
    }
};

pub const Diff = struct {
    pub const Operation = enum {
        insert,
        delete,
        equal,
    };

    operation: Operation,
    text: []const u8,
};

fn diff(
    allocator: std.mem.Allocator,
    before: []const u8,
    after: []const u8,
) error{OutOfMemory}!std.MultiArrayList(Diff) {
    const before_lines = try allocator.alloc([]const u8, std.mem.count(u8, before, "\n") + 1);
    defer allocator.free(before_lines);

    const after_lines = try allocator.alloc([]const u8, std.mem.count(u8, after, "\n") + 1);
    defer allocator.free(after_lines);

    {
        // Do not use typewriters and you will be fine.
        var before_line_it = std.mem.splitScalar(u8, before, '\n');
        for (before_lines) |*line| line.* = before_line_it.next().?;
        std.debug.assert(before_line_it.next() == null);

        var after_line_it = std.mem.splitScalar(u8, after, '\n');
        for (after_lines) |*line| line.* = after_line_it.next().?;
        std.debug.assert(after_line_it.next() == null);
    }

    const dp: []usize = try allocator.alloc(usize, (before_lines.len + 1) * (after_lines.len + 1));
    defer allocator.free(dp);
    @memset(dp, 0);

    const m = after_lines.len + 1;

    for (1..before_lines.len + 1) |i| {
        for (1..after_lines.len + 1) |j| {
            if (std.mem.eql(u8, before_lines[i - 1], after_lines[j - 1])) {
                dp[i * m + j] = dp[(i - 1) * m + (j - 1)] + 1;
            } else {
                dp[i * m + j] = @max(dp[(i - 1) * m + j], dp[i * m + (j - 1)]);
            }
        }
    }

    var diff_list: std.MultiArrayList(Diff) = .empty;
    errdefer diff_list.deinit(allocator);

    var i = before_lines.len;
    var j = after_lines.len;

    while (i > 0 or j > 0) {
        if (i == 0) {
            try diff_list.append(allocator, .{ .operation = .insert, .text = after_lines[j - 1] });
            j -= 1;
        } else if (j == 0) {
            try diff_list.append(allocator, .{ .operation = .delete, .text = before_lines[i - 1] });
            i -= 1;
        } else if (std.mem.eql(u8, before_lines[i - 1], after_lines[j - 1])) {
            try diff_list.append(allocator, .{ .operation = .equal, .text = before_lines[i - 1] });
            i -= 1;
            j -= 1;
        } else if (dp[(i - 1) * m + j] <= dp[i * m + (j - 1)]) {
            try diff_list.append(allocator, .{ .operation = .insert, .text = after_lines[j - 1] });
            j -= 1;
        } else {
            try diff_list.append(allocator, .{ .operation = .delete, .text = before_lines[i - 1] });
            i -= 1;
        }
    }

    std.mem.reverse(Diff.Operation, diff_list.items(.operation));
    std.mem.reverse([]const u8, diff_list.items(.text));
    return diff_list;
}

pub fn renderLineDiff(
    allocator: std.mem.Allocator,
    expected: []const u8,
    actual: []const u8,
) void {
    var diff_list = diff(allocator, expected, actual) catch @panic("OOM");
    defer diff_list.deinit(allocator);

    std.debug.print(" \n====== expected this output: =========\n", .{});
    printWithVisibleNewlines(expected);
    std.debug.print("\n======== instead found this: =========\n", .{});
    printWithVisibleNewlines(actual);
    std.debug.print("\n======================================\n", .{});
    std.debug.print("\n============ difference: =============\n", .{});

    const stderr = std.fs.File.stderr();
    const tty_config = std.Io.tty.detectConfig(stderr);
    var file_writer = stderr.writer(&.{});
    const writer = &file_writer.interface;

    for (diff_list.items(.operation), diff_list.items(.text)) |op, text| {
        tty_config.setColor(writer, switch (op) {
            .insert => .green,
            .delete => .red,
            .equal => .reset,
        }) catch {};
        writer.writeAll(switch (op) {
            .insert => "+ ",
            .delete => "- ",
            .equal => "  ",
        }) catch {};
        printLine(text);
    }
    tty_config.setColor(writer, .reset) catch {};
    writer.writeAll("␃") catch {}; // End of Text symbol (ETX)
    std.debug.print("\n======================================\n", .{});
}

fn printWithVisibleNewlines(source: []const u8) void {
    var i: usize = 0;
    while (std.mem.indexOfScalar(u8, source[i..], '\n')) |nl| : (i += nl + 1) {
        printLine(source[i..][0..nl]);
    }
    std.debug.print("{s}␃\n", .{source[i..]}); // End of Text symbol (ETX)
}

fn printLine(line: []const u8) void {
    if (line.len != 0) switch (line[line.len - 1]) {
        ' ', '\t' => return std.debug.print("{s}⏎\n", .{line}), // Return symbol
        else => {},
    };
    std.debug.print("{s}\n", .{line});
}

comptime {
    std.testing.refAllDecls(print_ast);
}
