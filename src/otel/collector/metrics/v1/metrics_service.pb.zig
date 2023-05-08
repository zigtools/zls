// ---
// prelude
// ---

const std = @import("std");
const pb = @import("protobuf");
const types = pb.types;
const MessageDescriptor = types.MessageDescriptor;
const Message = types.Message;
const FieldDescriptor = types.FieldDescriptor;
const EnumMixins = types.EnumMixins;
const MessageMixins = types.MessageMixins;
const FieldFlag = FieldDescriptor.FieldFlag;
const String = pb.extern_types.String;
const ArrayListMut = pb.extern_types.ArrayListMut;
const ArrayList = pb.extern_types.ArrayList;
const metrics = @import("../../../metrics/v1/metrics.pb.zig");

// ---
// typedefs
// ---

// ---
// message types
// ---

pub const ExportMetricsServiceRequest = extern struct {
    base: Message,
    resource_metrics: ArrayListMut(*metrics.ResourceMetrics) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "resource_metrics",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ExportMetricsServiceRequest, "resource_metrics"),
            &metrics.ResourceMetrics.descriptor,
            null,
            0,
        ),
    };
};

pub const ExportMetricsServiceResponse = extern struct {
    base: Message,
    partial_success: *ExportMetricsPartialSuccess = undefined,

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{1};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "partial_success",
            1,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(ExportMetricsServiceResponse, "partial_success"),
            &ExportMetricsPartialSuccess.descriptor,
            null,
            0,
        ),
    };
};

pub const ExportMetricsPartialSuccess = extern struct {
    base: Message,
    rejected_data_points: i64 = 0,
    error_message: String = String.empty,

    pub const field_ids = [_]c_uint{ 1, 2 };
    pub const opt_field_ids = [_]c_uint{ 1, 2 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "rejected_data_points",
            1,
            .LABEL_OPTIONAL,
            .TYPE_INT64,
            @offsetOf(ExportMetricsPartialSuccess, "rejected_data_points"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "error_message",
            2,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ExportMetricsPartialSuccess, "error_message"),
            null,
            null,
            0,
        ),
    };
};

// ---
// tests
// ---

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = ExportMetricsServiceRequest;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const tarena = arena.allocator();
    const data = try pb.testing.testInit(T, null, tarena);
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try pb.protobuf.serialize(&data.base, buf.writer());
    var ctx = pb.protobuf.context(buf.items, std.testing.allocator);
    const m = try ctx.deserialize(&T.descriptor);
    defer m.deinit(std.testing.allocator);
    var buf2 = std.ArrayList(u8).init(std.testing.allocator);
    defer buf2.deinit();
    try pb.protobuf.serialize(m, buf2.writer());
    try std.testing.expectEqualStrings(buf.items, buf2.items);
}

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = ExportMetricsServiceResponse;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const tarena = arena.allocator();
    const data = try pb.testing.testInit(T, null, tarena);
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try pb.protobuf.serialize(&data.base, buf.writer());
    var ctx = pb.protobuf.context(buf.items, std.testing.allocator);
    const m = try ctx.deserialize(&T.descriptor);
    defer m.deinit(std.testing.allocator);
    var buf2 = std.ArrayList(u8).init(std.testing.allocator);
    defer buf2.deinit();
    try pb.protobuf.serialize(m, buf2.writer());
    try std.testing.expectEqualStrings(buf.items, buf2.items);
}

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = ExportMetricsPartialSuccess;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const tarena = arena.allocator();
    const data = try pb.testing.testInit(T, null, tarena);
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try pb.protobuf.serialize(&data.base, buf.writer());
    var ctx = pb.protobuf.context(buf.items, std.testing.allocator);
    const m = try ctx.deserialize(&T.descriptor);
    defer m.deinit(std.testing.allocator);
    var buf2 = std.ArrayList(u8).init(std.testing.allocator);
    defer buf2.deinit();
    try pb.protobuf.serialize(m, buf2.writer());
    try std.testing.expectEqualStrings(buf.items, buf2.items);
}
