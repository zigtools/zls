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
const trace = @import("../../../trace/v1/trace.pb.zig");

// ---
// typedefs
// ---

// ---
// message types
// ---

pub const ExportTraceServiceRequest = extern struct {
    base: Message,
    resource_spans: ArrayListMut(*trace.ResourceSpans) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "resource_spans",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ExportTraceServiceRequest, "resource_spans"),
            &trace.ResourceSpans.descriptor,
            null,
            0,
        ),
    };
};

pub const ExportTraceServiceResponse = extern struct {
    base: Message,
    partial_success: *ExportTracePartialSuccess = undefined,

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
            @offsetOf(ExportTraceServiceResponse, "partial_success"),
            &ExportTracePartialSuccess.descriptor,
            null,
            0,
        ),
    };
};

pub const ExportTracePartialSuccess = extern struct {
    base: Message,
    rejected_spans: i64 = 0,
    error_message: String = String.empty,

    pub const field_ids = [_]c_uint{ 1, 2 };
    pub const opt_field_ids = [_]c_uint{ 1, 2 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "rejected_spans",
            1,
            .LABEL_OPTIONAL,
            .TYPE_INT64,
            @offsetOf(ExportTracePartialSuccess, "rejected_spans"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "error_message",
            2,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ExportTracePartialSuccess, "error_message"),
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
    const T = ExportTraceServiceRequest;
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
    const T = ExportTraceServiceResponse;
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
    const T = ExportTracePartialSuccess;
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
