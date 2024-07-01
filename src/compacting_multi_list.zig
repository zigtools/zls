const std = @import("std");
const Allocator = std.mem.Allocator;

fn growCapacity(current: u32, minimum: u32) u32 {
    var new = current;
    while (true) {
        new +|= new / 2 + 8;
        if (new >= minimum)
            return new;
    }
}

/// Represents multiple append-only lists efficiently.
/// Intended for use in MultiMap-like scenarios.
/// Requires a known capacity.
///
/// Used in two phases:
///     - Compacting: fast append-only
///     - Compacted: made contiguous, fast to access
pub fn CompactingMultiList(comptime T: type) type {
    return struct {
        const MultiList = @This();

        pub const Compacted = struct {
            data: []T,
            starts: []u32,

            pub fn len(compacted: Compacted, list: u32) u32 {
                return compacted.starts[list + 1] - compacted.starts[list];
            }

            pub fn slice(compacted: Compacted, list: u32) []T {
                return compacted.data[compacted.starts[list]..][0..compacted.len(list)];
            }

            pub fn deinit(compacted: *Compacted, allocator: std.mem.Allocator) void {
                allocator.free(compacted.data);
                allocator.free(compacted.starts);
                compacted.* = undefined;
            }
        };

        const ListAndIndex = struct { list: u32, index: u32 };
        comptime {
            std.debug.assert(@bitSizeOf(ListAndIndex) == 64);
        }

        // MultiArrayList causes a slowdown here.
        data: [*]T = undefined,
        lists_and_indices: [*]ListAndIndex = undefined,

        len: u32 = 0,
        capacity: u32 = 0,

        next_list_indices: std.ArrayListUnmanaged(u32) = .{},

        pub fn ensureTotalCapacity(multi: *MultiList, allocator: std.mem.Allocator, minimum_capacity: u32) Allocator.Error!void {
            if (multi.capacity >= minimum_capacity) return;

            const new_capacity = growCapacity(multi.capacity, minimum_capacity);

            inline for (.{ &multi.data, &multi.lists_and_indices }, .{ T, ListAndIndex }) |many, MT| {
                if (!allocator.resize(many.*[0..multi.capacity], new_capacity)) {
                    const new_memory = try allocator.alloc(MT, new_capacity);
                    @memcpy(new_memory[0..multi.len], many.*[0..multi.len]);
                    allocator.free(many.*[0..multi.capacity]);
                    many.* = new_memory.ptr;
                }
            }

            multi.capacity = new_capacity;
        }

        fn addOneAssumeCapacity(multi: *MultiList) u32 {
            multi.len += 1;
            return @intCast(multi.len - 1);
        }

        pub fn appendToNewListAssumeCapacity(multi: *MultiList, allocator: std.mem.Allocator, item: T) Allocator.Error!u32 {
            const new = multi.addOneAssumeCapacity();

            const new_list: u32 = @intCast(multi.next_list_indices.items.len);

            multi.data[new] = item;
            multi.lists_and_indices[new] = .{
                .list = new_list,
                .index = 0,
            };

            try multi.next_list_indices.append(allocator, 1);

            return new_list;
        }

        pub fn appendAssumeCapacity(multi: *MultiList, list: u32, item: T) void {
            const index = &multi.next_list_indices.items[list];

            const new = multi.addOneAssumeCapacity();

            multi.data[new] = item;
            multi.lists_and_indices[new] = .{
                .list = list,
                .index = index.*,
            };

            index.* += 1;
        }

        pub fn deinit(multi: *MultiList, allocator: std.mem.Allocator) void {
            if (multi.capacity != 0) {
                allocator.free(multi.data[0..multi.capacity]);
                allocator.free(multi.lists_and_indices[0..multi.capacity]);
            }

            multi.next_list_indices.deinit(allocator);

            multi.* = undefined;
        }

        /// `CompactingMultiList` may be `deinit`ed after this function.
        pub fn compact(multi: MultiList, allocator: std.mem.Allocator) Allocator.Error!Compacted {
            const lens = multi.next_list_indices.items;

            if (lens.len == 0) {
                return .{
                    .data = &.{},
                    .starts = &.{},
                };
            }

            const data = try allocator.alloc(T, multi.len);
            const starts = try allocator.alloc(u32, multi.next_list_indices.items.len + 1);

            starts[0] = 0;
            starts[starts.len - 1] = multi.len;

            var sum: u32 = 0;
            for (lens[0 .. lens.len - 1], starts[1 .. starts.len - 1]) |len, *start| {
                sum += len;
                start.* = sum;
            }

            for (multi.data[0..multi.len], multi.lists_and_indices[0..multi.len]) |datum, list_and_index| {
                data[starts[list_and_index.list] + list_and_index.index] = datum;
            }

            return .{
                .data = data,
                .starts = starts,
            };
        }
    };
}
