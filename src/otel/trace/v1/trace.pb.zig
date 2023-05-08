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

// ---
// message types
// ---

pub const TracesData = extern struct {
    base: Message,
    resource_spans: ArrayListMut(*ResourceSpans) = .{},

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
            @offsetOf(TracesData, "resource_spans"),
            &ResourceSpans.descriptor,
            null,
            0,
        ),
    };
};

pub const ResourceSpans = extern struct {
    base: Message,
    resource: *resource.Resource = undefined,
    scope_spans: ArrayListMut(*ScopeSpans) = .{},
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
            @offsetOf(ResourceSpans, "resource"),
            &resource.Resource.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "scope_spans",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ResourceSpans, "scope_spans"),
            &ScopeSpans.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ResourceSpans, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const ScopeSpans = extern struct {
    base: Message,
    scope: *common.InstrumentationScope = undefined,
    spans: ArrayListMut(*Span) = .{},
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
            @offsetOf(ScopeSpans, "scope"),
            &common.InstrumentationScope.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "spans",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ScopeSpans, "spans"),
            &Span.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ScopeSpans, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const Span = extern struct {
    base: Message,
    trace_id: String = String.empty,
    span_id: String = String.empty,
    trace_state: String = String.empty,
    parent_span_id: String = String.empty,
    name: String = String.empty,
    kind: Span.SpanKind = @intToEnum(Span.SpanKind, 0),
    start_time_unix_nano: u64 = 0,
    end_time_unix_nano: u64 = 0,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    dropped_attributes_count: u32 = 0,
    events: ArrayListMut(*Span.Event) = .{},
    dropped_events_count: u32 = 0,
    links: ArrayListMut(*Span.Link) = .{},
    dropped_links_count: u32 = 0,
    status: *Status = undefined,

    pub const field_ids = [_]c_uint{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    pub const opt_field_ids = [_]c_uint{ 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 15 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "trace_id",
            1,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(Span, "trace_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "span_id",
            2,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(Span, "span_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "trace_state",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Span, "trace_state"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "parent_span_id",
            4,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(Span, "parent_span_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "name",
            5,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Span, "name"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "kind",
            6,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(Span, "kind"),
            &Span.SpanKind.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "start_time_unix_nano",
            7,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(Span, "start_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "end_time_unix_nano",
            8,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(Span, "end_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "attributes",
            9,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Span, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "dropped_attributes_count",
            10,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(Span, "dropped_attributes_count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "events",
            11,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Span, "events"),
            &Span.Event.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "dropped_events_count",
            12,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(Span, "dropped_events_count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "links",
            13,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Span, "links"),
            &Span.Link.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "dropped_links_count",
            14,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(Span, "dropped_links_count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "status",
            15,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Span, "status"),
            &Status.descriptor,
            null,
            0,
        ),
    };

    pub const Event = extern struct {
        base: Message,
        time_unix_nano: u64 = 0,
        name: String = String.empty,
        attributes: ArrayListMut(*common.KeyValue) = .{},
        dropped_attributes_count: u32 = 0,

        pub const field_ids = [_]c_uint{ 1, 2, 3, 4 };
        pub const opt_field_ids = [_]c_uint{ 1, 2, 4 };
        pub const is_map_entry = false;

        pub usingnamespace MessageMixins(@This());
        pub const field_descriptors = [_]FieldDescriptor{
            FieldDescriptor.init(
                "time_unix_nano",
                1,
                .LABEL_OPTIONAL,
                .TYPE_FIXED64,
                @offsetOf(Span.Event, "time_unix_nano"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "name",
                2,
                .LABEL_OPTIONAL,
                .TYPE_STRING,
                @offsetOf(Span.Event, "name"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "attributes",
                3,
                .LABEL_REPEATED,
                .TYPE_MESSAGE,
                @offsetOf(Span.Event, "attributes"),
                &common.KeyValue.descriptor,
                null,
                0,
            ),
            FieldDescriptor.init(
                "dropped_attributes_count",
                4,
                .LABEL_OPTIONAL,
                .TYPE_UINT32,
                @offsetOf(Span.Event, "dropped_attributes_count"),
                null,
                null,
                0,
            ),
        };
    };

    pub const Link = extern struct {
        base: Message,
        trace_id: String = String.empty,
        span_id: String = String.empty,
        trace_state: String = String.empty,
        attributes: ArrayListMut(*common.KeyValue) = .{},
        dropped_attributes_count: u32 = 0,

        pub const field_ids = [_]c_uint{ 1, 2, 3, 4, 5 };
        pub const opt_field_ids = [_]c_uint{ 1, 2, 3, 5 };
        pub const is_map_entry = false;

        pub usingnamespace MessageMixins(@This());
        pub const field_descriptors = [_]FieldDescriptor{
            FieldDescriptor.init(
                "trace_id",
                1,
                .LABEL_OPTIONAL,
                .TYPE_BYTES,
                @offsetOf(Span.Link, "trace_id"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "span_id",
                2,
                .LABEL_OPTIONAL,
                .TYPE_BYTES,
                @offsetOf(Span.Link, "span_id"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "trace_state",
                3,
                .LABEL_OPTIONAL,
                .TYPE_STRING,
                @offsetOf(Span.Link, "trace_state"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "attributes",
                4,
                .LABEL_REPEATED,
                .TYPE_MESSAGE,
                @offsetOf(Span.Link, "attributes"),
                &common.KeyValue.descriptor,
                null,
                0,
            ),
            FieldDescriptor.init(
                "dropped_attributes_count",
                5,
                .LABEL_OPTIONAL,
                .TYPE_UINT32,
                @offsetOf(Span.Link, "dropped_attributes_count"),
                null,
                null,
                0,
            ),
        };
    };
    pub const SpanKind = enum(i32) {
        SPAN_KIND_UNSPECIFIED = 0,
        SPAN_KIND_INTERNAL = 1,
        SPAN_KIND_SERVER = 2,
        SPAN_KIND_CLIENT = 3,
        SPAN_KIND_PRODUCER = 4,
        SPAN_KIND_CONSUMER = 5,

        pub usingnamespace EnumMixins(@This());
    };
};

pub const Status = extern struct {
    base: Message,
    message: String = String.empty,
    code: Status.StatusCode = @intToEnum(Status.StatusCode, 0),

    pub const field_ids = [_]c_uint{ 2, 3 };
    pub const opt_field_ids = [_]c_uint{ 2, 3 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "message",
            2,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Status, "message"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "code",
            3,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(Status, "code"),
            &Status.StatusCode.descriptor,
            null,
            0,
        ),
    };
    pub const StatusCode = enum(i32) {
        STATUS_CODE_UNSET = 0,
        STATUS_CODE_OK = 1,
        STATUS_CODE_ERROR = 2,

        pub usingnamespace EnumMixins(@This());
    };
};

// ---
// tests
// ---

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = TracesData;
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
    const T = ResourceSpans;
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
    const T = ScopeSpans;
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
    const T = Span;
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
    const T = Status;
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
