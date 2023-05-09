const std = @import("std");

const Server = @import("../Server.zig");
const builtin = @import("builtin");
const build_options = @import("build_options");

const protobuf = @import("protobuf");
const otel_common = @import("common/v1/common.pb.zig");
const otel_collector = @import("collector/trace/v1/trace_service.pb.zig");
const otel_resource = @import("resource/v1/resource.pb.zig");
const otel_trace = @import("trace/v1/trace.pb.zig");

const otel_schema_url = "https://opentelemetry.io/schemas/1.19.0";

const Telemetry = @This();

const SendStack = std.atomic.Stack([]const u8);

allocator: std.mem.Allocator,
arena: std.heap.ArenaAllocator,
server: *const Server,
random: std.rand.DefaultPrng,
stack: SendStack,

instrumentation_scope: otel_common.InstrumentationScope,
alive: bool = true,
thread: std.Thread,
thread_alive: bool = true,

pub fn init(
    allocator: std.mem.Allocator,
    server: *const Server,
) !*Telemetry {
    var instrumentation_scope = otel_common.InstrumentationScope.initFields(.{
        .name = protobuf.extern_types.String.init("zls-otel"),
        .version = protobuf.extern_types.String.init("0.0.1"),
        .attributes = .{},
        .dropped_attributes_count = 0,
    });

    var telemetry = try allocator.create(Telemetry);
    telemetry.* = Telemetry{
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .server = server,
        .random = std.rand.DefaultPrng.init(seed: {
            var seed: u64 = 0;
            std.os.getrandom(std.mem.asBytes(&seed)) catch @panic("Could not start zls.");
            break :seed seed;
        }),
        .stack = SendStack.init(),

        .instrumentation_scope = instrumentation_scope,
        .alive = true,
        .thread = undefined,
        .thread_alive = true,
    };

    telemetry.thread = try std.Thread.spawn(.{}, sendTelemetryThread, .{telemetry});

    return telemetry;
}

pub fn sendTelemetryThread(telemetry: *Telemetry) void {
    defer @atomicStore(bool, &telemetry.thread_alive, false, .Unordered);

    var http_arena = std.heap.ArenaAllocator.init(telemetry.allocator);
    defer http_arena.deinit();

    telemetry.maybeFreeArena();

    const telemetry_uri = std.Uri.parse("https://telemetry.zigtools.org:4318/v1/traces") catch @panic("Invalid telemetry URI");

    while (@atomicLoad(bool, &telemetry.alive, .Unordered)) {
        var payload = telemetry.stack.pop() orelse continue;

        var http_client: std.http.Client = .{ .allocator = http_arena.allocator() };
        // defer http_client.deinit();

        var h = std.http.Headers{ .allocator = http_arena.allocator() };
        h.append("Content-Type", "application/x-protobuf") catch @panic("OOM");

        var http_req = http_client.request(.POST, telemetry_uri, h, .{}) catch @panic("Failed to create http request");

        http_req.transfer_encoding = .chunked;

        http_req.start() catch @panic("OOM");
        http_req.writeAll(payload.data) catch @panic("HTTP Error");
        http_req.finish() catch @panic("HTTP Error");

        http_req.wait() catch @panic("HTTP Error");

        if (http_arena.queryCapacity() > 128 * 1024) {
            _ = http_arena.reset(.free_all);
        }
    }
}

pub fn maybeFreeArena(telemetry: *Telemetry) void {
    if (telemetry.stack.isEmpty() and telemetry.arena.queryCapacity() > 128 * 1024) {
        _ = telemetry.arena.reset(.free_all);
    }
}

pub const Span = struct {
    trace: *Trace,
    data: *otel_trace.Span,

    pub fn finish(span: Span) void {
        span.data.end_time_unix_nano = @intCast(u64, std.time.nanoTimestamp());
        span.trace.spans.append(span.trace.telemetry.arena.allocator(), span.data) catch @panic("failed to append span");
    }
};

const span_status_ok = otel_trace.Status.initFields(.{
    .message = protobuf.extern_types.String.init("Success."),
    .code = .STATUS_CODE_OK,
});

pub const Trace = struct {
    telemetry: *Telemetry,
    id: [16]u8,
    spans: protobuf.extern_types.ArrayListMut(*otel_trace.Span) = .{},

    pub fn span(t: *Trace, name: []const u8) Span {
        t.telemetry.maybeFreeArena();

        const allocator = t.telemetry.arena.allocator();

        var span_data = allocator.create(otel_trace.Span) catch @panic("failed to allocate span");

        span_data.* = otel_trace.Span.initFields(.{
            .trace_id = protobuf.extern_types.String.init(allocator.dupe(u8, &t.id) catch @panic("OOM")),
            .span_id = protobuf.extern_types.String.init(id: {
                var id = allocator.alloc(u8, 8) catch @panic("OOM");
                t.telemetry.random.random().bytes(id);
                break :id id;
            }),
            .trace_state = protobuf.extern_types.String.empty,
            .parent_span_id = protobuf.extern_types.String.empty,
            .name = protobuf.extern_types.String.init(allocator.dupe(u8, name) catch @panic("failed to allocate name")),
            .kind = .SPAN_KIND_SERVER,
            .start_time_unix_nano = @intCast(u64, std.time.nanoTimestamp()),
            .end_time_unix_nano = undefined,
            .attributes = .{},
            .dropped_attributes_count = 0,
            .events = .{},
            .dropped_events_count = 0,
            .links = .{},
            .dropped_links_count = 0,
            .status = @constCast(&span_status_ok),
        });

        return .{
            .trace = t,
            .data = span_data,
        };
    }

    pub fn send(t: *Trace) void {
        const allocator = t.telemetry.arena.allocator();

        var req = otel_collector.ExportTraceServiceRequest.initFields(.{
            .resource_spans = .{},
        });

        var resource = otel_resource.Resource.initFields(.{
            .attributes = .{},
            .dropped_attributes_count = 0,
        });

        var val1 = otel_common.AnyValue.initFields(.{
            .value__string_value = protobuf.extern_types.String.init("zls"),
        });
        var kv1 = otel_common.KeyValue.initFields(.{
            .key = protobuf.extern_types.String.init("service.name"),
            .value = &val1,
        });

        resource.attributes.append(allocator, &kv1) catch @panic("OOM");

        var val_zls = otel_common.AnyValue.initFields(.{
            .value__string_value = protobuf.extern_types.String.init(build_options.version),
        });
        var kv_zls = otel_common.KeyValue.initFields(.{
            .key = protobuf.extern_types.String.init("zls.version"),
            .value = &val_zls,
        });

        resource.attributes.append(allocator, &kv_zls) catch @panic("OOM");

        var val_optimize = otel_common.AnyValue.initFields(.{
            .value__string_value = protobuf.extern_types.String.init(@tagName(builtin.mode)),
        });
        var kv_optimize = otel_common.KeyValue.initFields(.{
            .key = protobuf.extern_types.String.init("zls.optimize_mode"),
            .value = &val_optimize,
        });

        resource.attributes.append(allocator, &kv_optimize) catch @panic("OOM");

        if (t.telemetry.server.runtime_zig_version) |v| {
            var val_zig = otel_common.AnyValue.initFields(.{
                .value__string_value = protobuf.extern_types.String.init(v.raw_string),
            });
            var kv_zig = otel_common.KeyValue.initFields(.{
                .key = protobuf.extern_types.String.init("zig.version"),
                .value = &val_zig,
            });

            resource.attributes.append(allocator, &kv_zig) catch @panic("OOM");
        }

        if (t.telemetry.server.editor) |editor| {
            var val2 = otel_common.AnyValue.initFields(.{
                .value__string_value = protobuf.extern_types.String.init(editor.name),
            });
            var kv2 = otel_common.KeyValue.initFields(.{
                .key = protobuf.extern_types.String.init("editor.name"),
                .value = &val2,
            });
            resource.attributes.append(allocator, &kv2) catch @panic("OOM");

            if (editor.version) |version| {
                var val3 = otel_common.AnyValue.initFields(.{
                    .value__string_value = protobuf.extern_types.String.init(version),
                });
                var kv3 = otel_common.KeyValue.initFields(.{
                    .key = protobuf.extern_types.String.init("editor.version"),
                    .value = &val3,
                });
                resource.attributes.append(allocator, &kv3) catch @panic("OOM");
            }
        }

        var scope_spans = protobuf.extern_types.ArrayListMut(*otel_trace.ScopeSpans){};

        var scope_span = otel_trace.ScopeSpans.initFields(.{
            .scope = &t.telemetry.instrumentation_scope,
            .spans = t.spans,
            .schema_url = protobuf.extern_types.String.init(otel_schema_url),
        });

        scope_spans.append(allocator, &scope_span) catch @panic("OOM");

        var resource_spans = otel_trace.ResourceSpans.initFields(.{
            .resource = &resource,
            .scope_spans = scope_spans,
            .schema_url = protobuf.extern_types.String.init(otel_schema_url),
        });

        req.resource_spans.append(allocator, &resource_spans) catch @panic("OOM");

        var buffer = std.ArrayList(u8).init(allocator);

        protobuf.protobuf.serialize(&req.base, buffer.writer()) catch @panic("bruh");

        var node = allocator.create(SendStack.Node) catch @panic("OOM");
        node.* = .{ .next = null, .data = buffer.items };
        t.telemetry.stack.push(node);
    }
};

pub fn trace(telemetry: *Telemetry) Trace {
    return .{
        .telemetry = telemetry,
        .id = id: {
            var id: [16]u8 = undefined;
            telemetry.random.random().bytes(&id);
            break :id id;
        },
    };
}
