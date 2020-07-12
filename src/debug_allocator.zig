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
        out_stream: anytype,
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

const stack_addresses_size = 15;

base_allocator: *std.mem.Allocator,
info: AllocationInfo,
max_bytes: usize,
allocation_strack_addresses: std.AutoHashMap(usize, [stack_addresses_size]usize),

// Interface implementation
allocator: std.mem.Allocator,

pub fn init(base_allocator: *std.mem.Allocator, max_bytes: usize) DebugAllocator {
    return .{
        .base_allocator = base_allocator,
        .info = .{},
        .max_bytes = max_bytes,
        .allocation_strack_addresses = std.AutoHashMap(usize, [stack_addresses_size]usize).init(base_allocator),
        .allocator = .{
            .allocFn = alloc,
            .resizeFn = resize,
        },
    };
}

pub fn deinit(self: *DebugAllocator) void {
    self.allocation_strack_addresses.deinit();
}

fn alloc(allocator: *std.mem.Allocator, len: usize, ptr_align: u29, len_align: u29) error{OutOfMemory}![]u8 {
    const self = @fieldParentPtr(DebugAllocator, "allocator", allocator);

    const ptr = try self.base_allocator.callAllocFn(len, ptr_align, len_align);
    self.info.allocation_stats.addSample(ptr.len);

    var stack_addresses = std.mem.zeroes([stack_addresses_size + 2]usize);
    var stack_trace = std.builtin.StackTrace{
        .instruction_addresses = &stack_addresses,
        .index = 0,
    };
    std.debug.captureStackTrace(@returnAddress(), &stack_trace);
    try self.allocation_strack_addresses.putNoClobber(@ptrToInt(ptr.ptr), stack_addresses[2..].*);

    const curr_allocs = self.info.currentlyAllocated();
    if (self.max_bytes != 0 and curr_allocs >= self.max_bytes) {
        std.debug.print("Exceeded maximum bytes {}, exiting.\n", .{self.max_bytes});
        std.process.exit(1);
    }

    if (curr_allocs > self.info.peak_allocated) {
        self.info.peak_allocated = curr_allocs;
    }

    return ptr;
}

fn resize(allocator: *std.mem.Allocator, old_mem: []u8, new_size: usize, len_align: u29) error{OutOfMemory}!usize {
    const self = @fieldParentPtr(DebugAllocator, "allocator", allocator);

    if (old_mem.len == 0) {
        std.log.debug(.debug_alloc, "Trying to resize empty slice\n", .{});
        std.process.exit(1);
    }

    if (self.allocation_strack_addresses.get(@ptrToInt(old_mem.ptr)) == null) {
        @panic("error - resize call on block not allocated by debug allocator");
    }

    if (new_size == 0) {
        if (self.info.allocation_stats.count == self.info.deallocation_count) {
            @panic("error - too many calls to free, most likely double free");
        }
        self.info.deallocation_total += old_mem.len;
        self.info.deallocation_count += 1;
        self.allocation_strack_addresses.removeAssertDiscard(@ptrToInt(old_mem.ptr));
    } else if (new_size > old_mem.len) {
        self.info.reallocation_stats.addSample(new_size - old_mem.len);
    } else if (new_size < old_mem.len) {
        self.info.shrink_stats.addSample(old_mem.len - new_size);
    }

    const curr_allocs = self.info.currentlyAllocated();
    if (self.max_bytes != 0 and curr_allocs >= self.max_bytes) {
        std.log.debug(.debug_alloc, "Exceeded maximum bytes {}, exiting.\n", .{self.max_bytes});
        std.process.exit(1);
    }

    if (curr_allocs > self.info.peak_allocated) {
        self.info.peak_allocated = curr_allocs;
    }

    return self.base_allocator.callResizeFn(old_mem, new_size, len_align) catch |e| {
        return e;
    };
}

pub fn printRemainingStackTraces(self: DebugAllocator) void {
    std.debug.print(
        \\{} allocations - stack traces follow
        \\------------------------------------
    , .{self.allocation_strack_addresses.count()});
    var it = self.allocation_strack_addresses.iterator();
    var idx: usize = 1;
    while (it.next()) |entry| : (idx += 1) {
        std.debug.print("\nAllocation {}\n-------------\n", .{idx});
        var len: usize = 0;
        while (len < stack_addresses_size and entry.value[len] != 0) : (len += 1) {}
        const stack_trace = std.builtin.StackTrace{
            .instruction_addresses = &entry.value,
            .index = len,
        };
        std.debug.dumpStackTrace(stack_trace);
    }
}
