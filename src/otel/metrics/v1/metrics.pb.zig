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

pub const AggregationTemporality = enum(i32) {
    AGGREGATION_TEMPORALITY_UNSPECIFIED = 0,
    AGGREGATION_TEMPORALITY_DELTA = 1,
    AGGREGATION_TEMPORALITY_CUMULATIVE = 2,

    pub usingnamespace EnumMixins(@This());
};
pub const DataPointFlags = enum(i32) {
    FLAG_NONE = 0,
    FLAG_NO_RECORDED_VALUE = 1,

    pub usingnamespace EnumMixins(@This());
};
// ---
// message types
// ---

pub const MetricsData = extern struct {
    base: Message,
    resource_metrics: ArrayListMut(*ResourceMetrics) = .{},

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
            @offsetOf(MetricsData, "resource_metrics"),
            &ResourceMetrics.descriptor,
            null,
            0,
        ),
    };
};

pub const ResourceMetrics = extern struct {
    base: Message,
    resource: *resource.Resource = undefined,
    scope_metrics: ArrayListMut(*ScopeMetrics) = .{},
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
            @offsetOf(ResourceMetrics, "resource"),
            &resource.Resource.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "scope_metrics",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ResourceMetrics, "scope_metrics"),
            &ScopeMetrics.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ResourceMetrics, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const ScopeMetrics = extern struct {
    base: Message,
    scope: *common.InstrumentationScope = undefined,
    metrics: ArrayListMut(*Metric) = .{},
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
            @offsetOf(ScopeMetrics, "scope"),
            &common.InstrumentationScope.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "metrics",
            2,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ScopeMetrics, "metrics"),
            &Metric.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "schema_url",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(ScopeMetrics, "schema_url"),
            null,
            null,
            0,
        ),
    };
};

pub const Metric = extern struct {
    base: Message,
    name: String = String.empty,
    description: String = String.empty,
    unit: String = String.empty,
    data: extern union {
        gauge: *Gauge,
        sum: *Sum,
        histogram: *Histogram,
        exponential_histogram: *ExponentialHistogram,
        summary: *Summary,
    } = undefined,

    pub const field_ids = [_]c_uint{ 1, 2, 3, 5, 7, 9, 10, 11 };
    pub const opt_field_ids = [_]c_uint{ 1, 2, 3, 5, 7, 9, 10, 11 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{ 5, 7, 9, 10, 11 }),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "name",
            1,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Metric, "name"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "description",
            2,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Metric, "description"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "unit",
            3,
            .LABEL_OPTIONAL,
            .TYPE_STRING,
            @offsetOf(Metric, "unit"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "gauge",
            5,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Metric, "data"),
            &Gauge.descriptor,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "sum",
            7,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Metric, "data"),
            &Sum.descriptor,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "histogram",
            9,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Metric, "data"),
            &Histogram.descriptor,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "exponential_histogram",
            10,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Metric, "data"),
            &ExponentialHistogram.descriptor,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "summary",
            11,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(Metric, "data"),
            &Summary.descriptor,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };
};

pub const Gauge = extern struct {
    base: Message,
    data_points: ArrayListMut(*NumberDataPoint) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "data_points",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Gauge, "data_points"),
            &NumberDataPoint.descriptor,
            null,
            0,
        ),
    };
};

pub const Sum = extern struct {
    base: Message,
    data_points: ArrayListMut(*NumberDataPoint) = .{},
    aggregation_temporality: AggregationTemporality = @intToEnum(AggregationTemporality, 0),
    is_monotonic: bool = false,

    pub const field_ids = [_]c_uint{ 1, 2, 3 };
    pub const opt_field_ids = [_]c_uint{ 2, 3 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "data_points",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Sum, "data_points"),
            &NumberDataPoint.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "aggregation_temporality",
            2,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(Sum, "aggregation_temporality"),
            &AggregationTemporality.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "is_monotonic",
            3,
            .LABEL_OPTIONAL,
            .TYPE_BOOL,
            @offsetOf(Sum, "is_monotonic"),
            null,
            null,
            0,
        ),
    };
};

pub const Histogram = extern struct {
    base: Message,
    data_points: ArrayListMut(*HistogramDataPoint) = .{},
    aggregation_temporality: AggregationTemporality = @intToEnum(AggregationTemporality, 0),

    pub const field_ids = [_]c_uint{ 1, 2 };
    pub const opt_field_ids = [_]c_uint{2};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "data_points",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Histogram, "data_points"),
            &HistogramDataPoint.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "aggregation_temporality",
            2,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(Histogram, "aggregation_temporality"),
            &AggregationTemporality.descriptor,
            null,
            0,
        ),
    };
};

pub const ExponentialHistogram = extern struct {
    base: Message,
    data_points: ArrayListMut(*ExponentialHistogramDataPoint) = .{},
    aggregation_temporality: AggregationTemporality = @intToEnum(AggregationTemporality, 0),

    pub const field_ids = [_]c_uint{ 1, 2 };
    pub const opt_field_ids = [_]c_uint{2};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "data_points",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ExponentialHistogram, "data_points"),
            &ExponentialHistogramDataPoint.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "aggregation_temporality",
            2,
            .LABEL_OPTIONAL,
            .TYPE_ENUM,
            @offsetOf(ExponentialHistogram, "aggregation_temporality"),
            &AggregationTemporality.descriptor,
            null,
            0,
        ),
    };
};

pub const Summary = extern struct {
    base: Message,
    data_points: ArrayListMut(*SummaryDataPoint) = .{},

    pub const field_ids = [_]c_uint{1};
    pub const opt_field_ids = [_]c_uint{};
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "data_points",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Summary, "data_points"),
            &SummaryDataPoint.descriptor,
            null,
            0,
        ),
    };
};

pub const NumberDataPoint = extern struct {
    base: Message,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    start_time_unix_nano: u64 = 0,
    time_unix_nano: u64 = 0,
    exemplars: ArrayListMut(*Exemplar) = .{},
    flags: u32 = 0,
    value: extern union {
        as_double: f64,
        as_int: i64,
    } = undefined,

    pub const field_ids = [_]c_uint{ 7, 2, 3, 5, 8, 4, 6 };
    pub const opt_field_ids = [_]c_uint{ 2, 3, 8, 4, 6 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{ 4, 6 }),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "attributes",
            7,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(NumberDataPoint, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "start_time_unix_nano",
            2,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(NumberDataPoint, "start_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "time_unix_nano",
            3,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(NumberDataPoint, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "exemplars",
            5,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(NumberDataPoint, "exemplars"),
            &Exemplar.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "flags",
            8,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(NumberDataPoint, "flags"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "as_double",
            4,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(NumberDataPoint, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "as_int",
            6,
            .LABEL_OPTIONAL,
            .TYPE_SFIXED64,
            @offsetOf(NumberDataPoint, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };
};

pub const HistogramDataPoint = extern struct {
    base: Message,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    start_time_unix_nano: u64 = 0,
    time_unix_nano: u64 = 0,
    count: u64 = 0,
    bucket_counts: ArrayListMut(u64) = .{},
    explicit_bounds: ArrayListMut(f64) = .{},
    exemplars: ArrayListMut(*Exemplar) = .{},
    flags: u32 = 0,
    _sum: extern union {
        sum: f64,
    } = undefined,
    _min: extern union {
        min: f64,
    } = undefined,
    _max: extern union {
        max: f64,
    } = undefined,

    pub const field_ids = [_]c_uint{ 9, 2, 3, 4, 6, 7, 8, 10, 5, 11, 12 };
    pub const opt_field_ids = [_]c_uint{ 2, 3, 4, 10, 5, 11, 12 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{5}),
        ArrayList(c_uint).init(&.{11}),
        ArrayList(c_uint).init(&.{12}),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "attributes",
            9,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(HistogramDataPoint, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "start_time_unix_nano",
            2,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(HistogramDataPoint, "start_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "time_unix_nano",
            3,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(HistogramDataPoint, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "count",
            4,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(HistogramDataPoint, "count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "bucket_counts",
            6,
            .LABEL_REPEATED,
            .TYPE_FIXED64,
            @offsetOf(HistogramDataPoint, "bucket_counts"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "explicit_bounds",
            7,
            .LABEL_REPEATED,
            .TYPE_DOUBLE,
            @offsetOf(HistogramDataPoint, "explicit_bounds"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "exemplars",
            8,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(HistogramDataPoint, "exemplars"),
            &Exemplar.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "flags",
            10,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(HistogramDataPoint, "flags"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "sum",
            5,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(HistogramDataPoint, "_sum"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "min",
            11,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(HistogramDataPoint, "_min"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "max",
            12,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(HistogramDataPoint, "_max"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };
};

pub const ExponentialHistogramDataPoint = extern struct {
    base: Message,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    start_time_unix_nano: u64 = 0,
    time_unix_nano: u64 = 0,
    count: u64 = 0,
    scale: i32 = 0,
    zero_count: u64 = 0,
    positive: *ExponentialHistogramDataPoint.Buckets = undefined,
    negative: *ExponentialHistogramDataPoint.Buckets = undefined,
    flags: u32 = 0,
    exemplars: ArrayListMut(*Exemplar) = .{},
    zero_threshold: f64 = 0,
    _sum: extern union {
        sum: f64,
    } = undefined,
    _min: extern union {
        min: f64,
    } = undefined,
    _max: extern union {
        max: f64,
    } = undefined,

    pub const field_ids = [_]c_uint{ 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 14, 5, 12, 13 };
    pub const opt_field_ids = [_]c_uint{ 2, 3, 4, 6, 7, 8, 9, 10, 14, 5, 12, 13 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{5}),
        ArrayList(c_uint).init(&.{12}),
        ArrayList(c_uint).init(&.{13}),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "attributes",
            1,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ExponentialHistogramDataPoint, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "start_time_unix_nano",
            2,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(ExponentialHistogramDataPoint, "start_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "time_unix_nano",
            3,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(ExponentialHistogramDataPoint, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "count",
            4,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(ExponentialHistogramDataPoint, "count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "scale",
            6,
            .LABEL_OPTIONAL,
            .TYPE_SINT32,
            @offsetOf(ExponentialHistogramDataPoint, "scale"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "zero_count",
            7,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(ExponentialHistogramDataPoint, "zero_count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "positive",
            8,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(ExponentialHistogramDataPoint, "positive"),
            &ExponentialHistogramDataPoint.Buckets.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "negative",
            9,
            .LABEL_OPTIONAL,
            .TYPE_MESSAGE,
            @offsetOf(ExponentialHistogramDataPoint, "negative"),
            &ExponentialHistogramDataPoint.Buckets.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "flags",
            10,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(ExponentialHistogramDataPoint, "flags"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "exemplars",
            11,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(ExponentialHistogramDataPoint, "exemplars"),
            &Exemplar.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "zero_threshold",
            14,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(ExponentialHistogramDataPoint, "zero_threshold"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "sum",
            5,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(ExponentialHistogramDataPoint, "_sum"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "min",
            12,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(ExponentialHistogramDataPoint, "_min"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "max",
            13,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(ExponentialHistogramDataPoint, "_max"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };

    pub const Buckets = extern struct {
        base: Message,
        offset: i32 = 0,
        bucket_counts: ArrayListMut(u64) = .{},

        pub const field_ids = [_]c_uint{ 1, 2 };
        pub const opt_field_ids = [_]c_uint{1};
        pub const is_map_entry = false;

        pub usingnamespace MessageMixins(@This());
        pub const field_descriptors = [_]FieldDescriptor{
            FieldDescriptor.init(
                "offset",
                1,
                .LABEL_OPTIONAL,
                .TYPE_SINT32,
                @offsetOf(ExponentialHistogramDataPoint.Buckets, "offset"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "bucket_counts",
                2,
                .LABEL_REPEATED,
                .TYPE_UINT64,
                @offsetOf(ExponentialHistogramDataPoint.Buckets, "bucket_counts"),
                null,
                null,
                0,
            ),
        };
    };
};

pub const SummaryDataPoint = extern struct {
    base: Message,
    attributes: ArrayListMut(*common.KeyValue) = .{},
    start_time_unix_nano: u64 = 0,
    time_unix_nano: u64 = 0,
    count: u64 = 0,
    sum: f64 = 0,
    quantile_values: ArrayListMut(*SummaryDataPoint.ValueAtQuantile) = .{},
    flags: u32 = 0,

    pub const field_ids = [_]c_uint{ 7, 2, 3, 4, 5, 6, 8 };
    pub const opt_field_ids = [_]c_uint{ 2, 3, 4, 5, 8 };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "attributes",
            7,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(SummaryDataPoint, "attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "start_time_unix_nano",
            2,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(SummaryDataPoint, "start_time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "time_unix_nano",
            3,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(SummaryDataPoint, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "count",
            4,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(SummaryDataPoint, "count"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "sum",
            5,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(SummaryDataPoint, "sum"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "quantile_values",
            6,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(SummaryDataPoint, "quantile_values"),
            &SummaryDataPoint.ValueAtQuantile.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "flags",
            8,
            .LABEL_OPTIONAL,
            .TYPE_UINT32,
            @offsetOf(SummaryDataPoint, "flags"),
            null,
            null,
            0,
        ),
    };

    pub const ValueAtQuantile = extern struct {
        base: Message,
        quantile: f64 = 0,
        value: f64 = 0,

        pub const field_ids = [_]c_uint{ 1, 2 };
        pub const opt_field_ids = [_]c_uint{ 1, 2 };
        pub const is_map_entry = false;

        pub usingnamespace MessageMixins(@This());
        pub const field_descriptors = [_]FieldDescriptor{
            FieldDescriptor.init(
                "quantile",
                1,
                .LABEL_OPTIONAL,
                .TYPE_DOUBLE,
                @offsetOf(SummaryDataPoint.ValueAtQuantile, "quantile"),
                null,
                null,
                0,
            ),
            FieldDescriptor.init(
                "value",
                2,
                .LABEL_OPTIONAL,
                .TYPE_DOUBLE,
                @offsetOf(SummaryDataPoint.ValueAtQuantile, "value"),
                null,
                null,
                0,
            ),
        };
    };
};

pub const Exemplar = extern struct {
    base: Message,
    filtered_attributes: ArrayListMut(*common.KeyValue) = .{},
    time_unix_nano: u64 = 0,
    span_id: String = String.empty,
    trace_id: String = String.empty,
    value: extern union {
        as_double: f64,
        as_int: i64,
    } = undefined,

    pub const field_ids = [_]c_uint{ 7, 2, 4, 5, 3, 6 };
    pub const opt_field_ids = [_]c_uint{ 2, 4, 5, 3, 6 };
    pub const oneof_field_ids = [_]ArrayList(c_uint){
        ArrayList(c_uint).init(&.{ 3, 6 }),
    };
    pub const is_map_entry = false;

    pub usingnamespace MessageMixins(@This());
    pub const field_descriptors = [_]FieldDescriptor{
        FieldDescriptor.init(
            "filtered_attributes",
            7,
            .LABEL_REPEATED,
            .TYPE_MESSAGE,
            @offsetOf(Exemplar, "filtered_attributes"),
            &common.KeyValue.descriptor,
            null,
            0,
        ),
        FieldDescriptor.init(
            "time_unix_nano",
            2,
            .LABEL_OPTIONAL,
            .TYPE_FIXED64,
            @offsetOf(Exemplar, "time_unix_nano"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "span_id",
            4,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(Exemplar, "span_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "trace_id",
            5,
            .LABEL_OPTIONAL,
            .TYPE_BYTES,
            @offsetOf(Exemplar, "trace_id"),
            null,
            null,
            0,
        ),
        FieldDescriptor.init(
            "as_double",
            3,
            .LABEL_OPTIONAL,
            .TYPE_DOUBLE,
            @offsetOf(Exemplar, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
        FieldDescriptor.init(
            "as_int",
            6,
            .LABEL_OPTIONAL,
            .TYPE_SFIXED64,
            @offsetOf(Exemplar, "value"),
            null,
            null,
            @enumToInt(FieldFlag.FLAG_ONEOF),
        ),
    };
};

// ---
// tests
// ---

test { // dummy test for typechecking
    std.testing.log_level = .err; // suppress 'required field' warnings
    _ = AggregationTemporality;
}

test { // dummy test for typechecking
    std.testing.log_level = .err; // suppress 'required field' warnings
    _ = DataPointFlags;
}

test {
    std.testing.log_level = .err; // suppress 'required field' warnings
    const T = MetricsData;
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
    const T = ResourceMetrics;
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
    const T = ScopeMetrics;
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
    const T = Metric;
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
    const T = Gauge;
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
    const T = Sum;
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
    const T = Histogram;
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
    const T = ExponentialHistogram;
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
    const T = Summary;
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
    const T = NumberDataPoint;
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
    const T = HistogramDataPoint;
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
    const T = ExponentialHistogramDataPoint;
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
    const T = SummaryDataPoint;
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
    const T = Exemplar;
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
