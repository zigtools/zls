const std = @import("std");
const Zir = @import("stage2/Zir.zig");
const AstGen = @import("stage2/AstGen.zig");
const ast = @import("../ast.zig");
const types = @import("../types.zig");
const offsets = @import("../offsets.zig");

const logger = std.log.scoped(.anal2);

pub const DiagnosticsContext = struct {
    /// Uses the request Arena
    allocator: std.mem.Allocator,
    tree: std.zig.Ast,
    diagnostics: *std.ArrayListUnmanaged(types.Diagnostic),
    uri: []const u8,
};

const DiagnosticRelatedInformationContext = struct {
    allocator: std.mem.Allocator,
    tree: std.zig.Ast,
    uri: []const u8,
    zir: Zir,
    related_info: *std.ArrayListUnmanaged(types.DiagnosticRelatedInformation),
    notes: u32,
};

fn getDiagnosticRelatedInformation(context: DiagnosticRelatedInformationContext) anyerror!void {
    std.debug.assert(context.notes != 0);

    var block = context.zir.extraData(Zir.Inst.Block, context.notes);
    var offset: usize = 0;

    while (offset < block.data.body_len) : (offset += 1) {
        const compile_error = context.zir.extraData(Zir.Inst.CompileErrors.Item, context.zir.extra[block.end + offset]);
        try context.related_info.append(context.allocator, .{
            .location = .{
                .uri = context.uri,
                .range = ast.astLocationToRange(context.tree.tokenLocation(0, if (compile_error.data.node != 0) context.tree.nodes.items(.main_token)[compile_error.data.node] else compile_error.data.token)),
            },
            .message = try context.allocator.dupe(u8, context.zir.nullTerminatedString(compile_error.data.msg)),
        });

        if (compile_error.data.notes != 0)
            try getDiagnosticRelatedInformation(.{
                .allocator = context.allocator,
                .tree = context.tree,
                .zir = context.zir,
                .uri = context.uri,
                .related_info = context.related_info,
                .notes = compile_error.data.notes,
            });
    }
}

pub fn getDiagnostics(context: DiagnosticsContext) !void {
    var zir = try AstGen.generate(context.allocator, context.tree);
    defer zir.deinit(context.allocator);

    if (zir.instructions.len == 0) return;

    if (zir.hasCompileErrors()) {
        const base = zir.extra[@enumToInt(Zir.ExtraIndex.compile_errors)];
        var ce_extra = zir.extraData(Zir.Inst.CompileErrors, base);

        var index: usize = 0;
        var offset: usize = base + 1;
        while (index < ce_extra.data.items_len) : (index += 1) {
            const item_extra = zir.extraData(Zir.Inst.CompileErrors.Item, offset);

            var related_info = std.ArrayListUnmanaged(types.DiagnosticRelatedInformation){};

            if (item_extra.data.notes != 0)
                try getDiagnosticRelatedInformation(.{
                    .allocator = context.allocator,
                    .tree = context.tree,
                    .zir = zir,
                    .uri = context.uri,
                    .related_info = &related_info,
                    .notes = item_extra.data.notes,
                });

            try context.diagnostics.append(context.allocator, .{
                // TODO: Improve location of diagnostic to reflect acutal feedback
                .range = ast.astLocationToRange(context.tree.tokenLocation(0, if (item_extra.data.node != 0) context.tree.nodes.items(.main_token)[item_extra.data.node] else item_extra.data.token)),
                .severity = .Error,
                .code = "astgen_error", // TODO: Codes
                .source = "zls",
                .message = try context.allocator.dupe(u8, zir.nullTerminatedString(item_extra.data.msg)),
                .relatedInformation = related_info.items,
            });

            offset = item_extra.end;
        }
    }
}
