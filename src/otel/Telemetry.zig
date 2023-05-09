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

current_trace: Trace,

pub fn create(
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

        .current_trace = .{ .telemetry = telemetry, .id = undefined },
    };

    telemetry.thread = try std.Thread.spawn(.{}, sendTelemetryThread, .{telemetry});

    return telemetry;
}

pub fn sendTelemetryThread(telemetry: *Telemetry) void {
    defer @atomicStore(bool, &telemetry.thread_alive, false, .Unordered);

    var http_arena = std.heap.ArenaAllocator.init(telemetry.allocator);
    defer http_arena.deinit();

    const telemetry_uri = std.Uri.parse("https://telemetry.zigtools.org:4318/v1/traces") catch @panic("Invalid telemetry URI");

    // Highlight memory bugs in comments
    while (@atomicLoad(bool, &telemetry.alive, .Unordered)) {
        var node = telemetry.stack.pop() orelse continue;

        defer telemetry.allocator.destroy(node);
        defer telemetry.allocator.free(node.data);

        var http_client: std.http.Client = .{ .allocator = http_arena.allocator() };

        var h = std.http.Headers{ .allocator = http_arena.allocator() };
        h.append("Content-Type", "application/x-protobuf") catch @panic("OOM");

        var http_req = http_client.request(.POST, telemetry_uri, h, .{}) catch @panic("Failed to create http request");

        http_req.transfer_encoding = .chunked;

        http_req.start() catch @panic("OOM");
        http_req.writeAll(node.data) catch |err| {
            std.log.info("err {s}", .{@errorName(err)});
            @panic("HTTP Error");
        };
        http_req.finish() catch |err| {
            std.log.info("err {s}", .{@errorName(err)});
            @panic("HTTP Error");
        };

        http_req.wait() catch |err| {
            std.log.info("err {s}", .{@errorName(err)});
            @panic("HTTP Error");
        };

        if (http_arena.queryCapacity() > 128 * 1024) {
            _ = http_arena.reset(.free_all);
        }
    }
}

pub fn maybeFreeArena(telemetry: *Telemetry) void {
    if (telemetry.current_trace.spans.len == 0 and telemetry.current_trace.span_parents.items.len == 0 and telemetry.arena.queryCapacity() > 128 * 1024) {
        _ = telemetry.arena.reset(.free_all);
    }
}

pub const Span = struct {
    trace: *Trace,
    data: *otel_trace.Span,

    pub fn finish(s: Span) void {
        s.data.end_time_unix_nano = @intCast(u64, std.time.nanoTimestamp());
        s.trace.span_parents.items.len -= 1;
        s.trace.spans.append(s.trace.telemetry.allocator, s.data) catch @panic("failed to append span");

        if (s.trace.span_parents.items.len == 0) s.trace.send();
    }
};

const Trace = struct {
    telemetry: *Telemetry,
    id: [16]u8,

    span_parents: std.ArrayListUnmanaged([]const u8) = .{},
    spans: protobuf.extern_types.ArrayListMut(*otel_trace.Span) = .{},

    pub fn span(t: *Trace, name: []const u8) Span {
        t.telemetry.maybeFreeArena();

        // const allocator = t.telemetry.arena.allocator();
        const allocator = t.telemetry.allocator;

        var span_data = allocator.create(otel_trace.Span) catch @panic("failed to allocate span");

        const span_id = id: {
            var id = allocator.alloc(u8, 8) catch @panic("OOM");
            t.telemetry.random.random().bytes(id);
            break :id id;
        };

        var status = t.telemetry.allocator.create(otel_trace.Status) catch @panic("OOM");
        status.* = otel_trace.Status.initFields(.{
            .message = protobuf.extern_types.String.init("Success."),
            .code = .STATUS_CODE_OK,
        });

        span_data.* = otel_trace.Span.initFields(.{
            .trace_id = protobuf.extern_types.String.init(allocator.dupe(u8, &t.id) catch @panic("OOM")),
            .span_id = protobuf.extern_types.String.init(span_id),
            .trace_state = protobuf.extern_types.String.empty,
            .parent_span_id = if (t.span_parents.items.len == 0)
                protobuf.extern_types.String.empty
            else
                protobuf.extern_types.String.init(t.span_parents.items[t.span_parents.items.len - 1]),
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
            .status = status,
        });

        t.span_parents.append(t.telemetry.allocator, span_id) catch @panic("OOM");

        return .{
            .trace = t,
            .data = span_data,
        };
    }

    pub fn send(t: *Trace) void {
        // const allocator = t.telemetry.arena.allocator();
        const allocator = t.telemetry.allocator;

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

        var buffer = std.ArrayList(u8).init(t.telemetry.allocator);

        protobuf.protobuf.serialize(&req.base, buffer.writer()) catch @panic("bruh");

        var node = t.telemetry.allocator.create(SendStack.Node) catch @panic("OOM");
        node.* = .{ .next = null, .data = buffer.toOwnedSlice() catch @panic("OOM") };
        t.telemetry.stack.push(node);

        t.spans.len = 0;

        t.telemetry.maybeFreeArena();
    }
};

fn startTrace(telemetry: *Telemetry) void {
    if (telemetry.current_trace.spans.len == 0 and telemetry.current_trace.span_parents.items.len == 0)
        telemetry.current_trace = .{
            .telemetry = telemetry,
            .id = id: {
                var id: [16]u8 = undefined;
                telemetry.random.random().bytes(&id);
                break :id id;
            },
        };
}

// -> a
pub fn span(telemetry: *Telemetry, name: []const u8) Span {
    telemetry.startTrace();
    return telemetry.current_trace.span(name);
}
