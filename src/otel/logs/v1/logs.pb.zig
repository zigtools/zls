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
const common = @import("../../common/v1/common.pb.zig");
const resource = @import("../../resource/v1/resource.pb.zig");

// ---
// typedefs
// ---

pub const SeverityNumber = enum(i32) {
    SEVERITY_NUMBER_UNSPECIFIED = 0,
    SEVERITY_NUMBER_TRACE = 1,
    SEVERITY_NUMBER_TRACE2 = 2,
    SEVERITY_NUMBER_TRACE3 = 3,
    SEVERITY_NUMBER_TRACE4 = 4,
    SEVERITY_NUMBER_DEBUG = 5,
    SEVERITY_NUMBER_DEBUG2 = 6,
    SEVERITY_NUMBER_DEBUG3 = 7,
    SEVERITY_NUMBER_DEBUG4 = 8,
    SEVERITY_NUMBER_INFO = 9,
    SEVERITY_NUMBER_INFO2 = 10,
    SEVERITY_NUMBER_INFO3 = 11,
    SEVERITY_NUMBER_INFO4 = 12,
    SEVERITY_NUMBER_WARN = 13,
    SEVERITY_NUMBER_WARN2 = 14,
    SEVERITY_NUMBER_WARN3 = 15,
    SEVERITY_NUMBER_WARN4 = 16,
    SEVERITY_NUMBER_ERROR = 17,
    SEVERITY_NUMBER_ERROR2 = 18,
    SEVERITY_NUMBER_ERROR3 = 19,
    SEVERITY_NUMBER_ERROR4 = 20,
    SEVERITY_NUMBER_FATAL = 21,
    SEVERITY_NUMBER_FATAL2 = 22,
    SEVERITY_NUMBER_FATAL3 = 23,
    SEVERITY_NUMBER_FATAL4 = 24,

    pub usingnamespace EnumMixins(@This());
};
pub const LogRecordFlags = enum(i32) {
    LOG_RECORD_FLAG_UNSPECIFIED = 0,
    LOG_RECORD_FLAG_TRACE_FLAGS_MASK = 255,

    pub usingnamespace EnumMixins(@This());
};
// ---
// message types
// ---

pub const LogsData = extern struct {
    base: Message,
    resource_logs: ArrayListMut(*ResourceLogs) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "resource_logs",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(LogsData, "resource_logs"),
            &ResourceLogs.descriptor,
            null,
            0,
        ),
    };
};

pub const ResourceLogs = extern struct {
    base: Message,
    resource: *resource.Resource = undefined,
    scope_logs: ArrayListMut(*ScopeLogs) = .{},
    schema_url: String = String.empty,

    pub const field_ids = [_]c_uint{ 1, 2, 3 };
    pub const opt_field_ids = [_]c_uint{ 1, 3 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "resource",
            1,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(ResourceLogs, "resource"),
            &resource.Resource.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "scope_logs",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ResourceLogs, "scope_logs"),
            &ScopeLogs.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ResourceLogs, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const ScopeLogs = extern struct {
    base: Message,
    scope: *common.InstrumentationScope = undefined,
    log_records: ArrayListMut(*LogRecord) = .{},
    schema_url: String = String.empty,

    pub const field_ids = [_]c_uint{ 1, 2, 3 };
    pub const opt_field_ids = [_]c_uint{ 1, 3 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "scope",
            1,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(ScopeLogs, "scope"),
            &common.InstrumentationScope.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "log_records",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ScopeLogs, "log_records"),
            &LogRecord.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ScopeLogs, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const LogRecord = extern struct {
    base: Message,
    time_unix_nano: u64 = 0,
    observed_time_unix_nano: u64 = 0,
    severity_number: SeverityNumber = @intToEnum(SeverityNumber, 0),
    severity_text: String = String.empty,
    body: *common.AnyValue = undefined,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    dropped_attributes_count: u32 = 0,
    flags: u32 = 0,
    trace_id: String = String.empty,
    span_id: String = String.empty,

    pub const field_ids = [_]c_uint{ 1, 11, 2, 3, 5, 6, 7, 8, 9, 10 };
    pub const opt_field_ids = [_]c_uint{ 1, 11, 2, 3, 5, 7, 8, 9, 10 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "time_unix_nano",
            1,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(LogRecord, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "observed_time_unix_nano",
            11,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(LogRecord, "observed_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "severity_number",
            2,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(LogRecord, "severity_number"),
            &SeverityNumber.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "severity_text",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(LogRecord, "severity_text"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "body",
            5,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(LogRecord, "body"),
            &common.AnyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "attributes",
            6,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(LogRecord, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "dropped_attributes_count",
            7,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(LogRecord, "dropped_attributes_count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "flags",
            8,
            .LABEL_OPTIONAL,
            .TYPE_FIXED32,
            @offsetOf(LogRecord, "flags"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "trace_id",
            9,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(LogRecord, "trace_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "span_id",
            10,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(LogRecord, "span_id"),
            null,
            null,
            0,
        ),
    };
};

// ---
// tests
// ---

test { // dummy test for typechecking
    std.testing.log_level = .err; // suppress 'required field' warnings
    _ = SeverityNumber;
}

test { // dummy test for typechecking
    std.testing.log_level = .err; // suppress 'required field' warnings
    _ = LogRecordFlags;
}

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = LogsData;
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
    const T = ResourceLogs;
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
    const T = ScopeLogs;
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
    const T = LogRecord;
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
