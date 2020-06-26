//! This allocator collects information about allocation sizes

const std = @import("std");

const DebugAllocator = @This();

const Stats = struct {
    mean: f64 = 0,
    mean_of_squares: f64 = 0,
    total: usize = 0,
    count: usize = 0,

    fn addSample(self: *Stats, value: usize) void {
        const count_f64 = @intToFloat(f64, self.count);
        self.mean = (self.mean * count_f64 + @intToFloat(f64, value)) / (count_f64 + 1);
        self.mean_of_squares = (self.mean_of_squares * count_f64 + @intToFloat(f64, value * value)) / (count_f64 + 1);
        self.total += value;
        self.count += 1;
    }

    fn stdDev(self: Stats) f64 {
        return std.math.sqrt(self.mean_of_squares - self.mean * self.mean);
    }
};

pub const AllocationInfo = struct {
    allocation_stats: Stats = Stats{},
    deallocation_count: usize = 0,
    deallocation_total: usize = 0,

    peak_allocated: usize = 0,

    reallocation_stats: Stats = Stats{},
    shrink_stats: Stats = Stats{},

    fn currentlyAllocated(self: AllocationInfo) usize {
        return self.allocation_stats.total + self.reallocation_stats.total - self.deallocation_total - self.shrink_stats.total;
    }

    pub fn format(
        self: AllocationInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: var,
    ) !void {
        @setEvalBranchQuota(2000);

        return std.fmt.format(
            out_stream,
            \\------------------------------------------ Allocation info ------------------------------------------
            \\{} total allocations (total: {Bi:.2}, mean: {Bi:.2}, std. dev: {Bi:.2} MB), {} deallocations
            \\{} current allocations ({Bi:.2}), peak mem usage: {Bi:.2}
            \\{} reallocations (total: {Bi:.2}, mean: {Bi:.2}, std. dev: {Bi:.2})
            \\{} shrinks (total: {Bi:.2}, mean: {Bi:.2}, std. dev: {Bi:.2})
            \\-----------------------------------------------------------------------------------------------------
        ,
            .{
                self.allocation_stats.count,
                self.allocation_stats.total,
                self.allocation_stats.mean,
                self.allocation_stats.stdDev(),
                self.deallocation_count,
                self.allocation_stats.count - self.deallocation_count,
                self.currentlyAllocated(),
                self.peak_allocated,
                self.reallocation_stats.count,
                self.reallocation_stats.total,
                self.reallocation_stats.mean,
                self.reallocation_stats.stdDev(),
                self.shrink_stats.count,
                self.shrink_stats.total,
                self.shrink_stats.mean,
                self.shrink_stats.stdDev(),
            },
        );
    }
};

base_allocator: *std.mem.Allocator,
info: AllocationInfo,
max_bytes: usize,

// Interface implementation
allocator: std.mem.Allocator,

pub fn init(base_allocator: *std.mem.Allocator, max_bytes: usize) DebugAllocator {
    return .{
        .base_allocator = base_allocator,
        .info = .{},
        .max_bytes = max_bytes,
        .allocator = .{
            .reallocFn = realloc,
            .shrinkFn = shrink,
        },
    };
}

fn realloc(allocator: *std.mem.Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) ![]u8 {
    const self = @fieldParentPtr(DebugAllocator, "allocator", allocator);
    var data = try self.base_allocator.reallocFn(self.base_allocator, old_mem, old_align, new_size, new_align);
    if (old_mem.len == 0) {
        self.info.allocation_stats.addSample(new_size);
    } else if (new_size > old_mem.len) {
        self.info.reallocation_stats.addSample(new_size - old_mem.len);
    } else if (new_size < old_mem.len) {
        self.info.shrink_stats.addSample(old_mem.len - new_size);
    }

    const curr_allocs = self.info.currentlyAllocated();
    if (self.max_bytes != 0 and curr_allocs >= self.max_bytes) {
        std.debug.print("Exceeded maximum bytes {}, exiting.\n", .{self.max_bytes});
        std.process.exit(1);
    }

    if (curr_allocs > self.info.peak_allocated) {
        self.info.peak_allocated = curr_allocs;
    }
    return data;
}

fn shrink(allocator: *std.mem.Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) []u8 {
    const self = @fieldParentPtr(DebugAllocator, "allocator", allocator);
    if (new_size == 0) {
        if (self.info.allocation_stats.count == self.info.deallocation_count) {
            @panic("error - too many calls to free, most likely double free");
        }
        self.info.deallocation_total += old_mem.len;
        self.info.deallocation_count += 1;
    } else if (new_size < old_mem.len) {
        self.info.shrink_stats.addSample(old_mem.len - new_size);
    } else if (new_size > old_mem.len) {
        @panic("error - trying to shrink to a bigger size");
    }
    return self.base_allocator.shrinkFn(self.base_allocator, old_mem, old_align, new_size, new_align);
}
