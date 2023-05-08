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

// ---
// typedefs
// ---

// ---
// message types
// ---

pub const AnyValue = extern struct {
    base: Message,
    value: extern union {
        string_value: String,
        bool_value: bool,
        int_value: i64,
        double_value: f64,
        array_value: *ArrayValue,
        kvlist_value: *KeyValueList,
        bytes_value: String,
    } = undefined,

    pub const field_ids = [_]c_uint{ 1, 2, 3, 4, 5, 6, 7 };
    pub const opt_field_ids = [_]c_uint{ 1, 2, 3, 4, 5, 6, 7 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{ 1, 2, 3, 4, 5, 6, 7 }),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "string_value",
            1,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(AnyValue, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "bool_value",
            2,
            .LABEL_OPTIONAL,
            .TYPE_BOOL,
            @offsetOf(AnyValue, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "int_value",
            3,
            .LABEL_OPTIONAL,
            .TYPE_INT64,
            @offsetOf(AnyValue, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "double_value",
            4,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(AnyValue, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.initRecursive(
            "array_value",
            5,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(AnyValue, "value"),
            ArrayValue,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.initRecursive(
            "kvlist_value",
            6,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(AnyValue, "value"),
            KeyValueList,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "bytes_value",
            7,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(AnyValue, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };
};

pub const ArrayValue = extern struct {
    base: Message,
    values: ArrayListMut(*AnyValue) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "values",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ArrayValue, "values"),
            &AnyValue.descriptor,
            null,
            0,
        ),
    };
};

pub const KeyValueList = extern struct {
    base: Message,
    values: ArrayListMut(*KeyValue) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "values",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(KeyValueList, "values"),
            &KeyValue.descriptor,
            null,
            0,
        ),
    };
};

pub const KeyValue = extern struct {
    base: Message,
    key: String = String.empty,
    value: *AnyValue = undefined,

    pub const field_ids = [_]c_uint{ 1, 2 };
    pub const opt_field_ids = [_]c_uint{ 1, 2 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "key",
            1,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(KeyValue, "key"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "value",
            2,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(KeyValue, "value"),
            &AnyValue.descriptor,
            null,
            0,
        ),
    };
};

pub const InstrumentationScope = extern struct {
    base: Message,
    name: String = String.empty,
    version: String = String.empty,
    attributes: ArrayListMut(*KeyValue) = .{},
    dropped_attributes_count: u32 = 0,

    pub const field_ids = [_]c_uint{ 1, 2, 3, 4 };
    pub const opt_field_ids = [_]c_uint{ 1, 2, 4 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "name",
            1,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(InstrumentationScope, "name"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "version",
            2,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(InstrumentationScope, "version"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "attributes",
            3,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(InstrumentationScope, "attributes"),
            &KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "dropped_attributes_count",
            4,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(InstrumentationScope, "dropped_attributes_count"),
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
    const T = AnyValue;
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
    const T = ArrayValue;
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
    const T = KeyValueList;
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
    const T = KeyValue;
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
    const T = InstrumentationScope;
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
