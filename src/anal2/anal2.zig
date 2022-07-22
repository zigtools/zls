const std = @import("std");
const Zir = @import("stage2/Zir.zig");
const AstGen = @import("stage2/AstGen.zig");
const ast = @import("../ast.zig");
const types = @import("../types.zig");
const offsets = @import("../offsets.zig");
const DocumentStore = @import("../DocumentStore.zig");

const logger = std.log.scoped(.anal2);

const DiagnosticRelatedInformationContext = struct {
    allocator: std.mem.Allocator,
    handle: DocumentStore.Handle,
    related_info: *std.ArrayListUnmanaged(types.DiagnosticRelatedInformation),
    notes: u32,
};

fn getDiagnosticRelatedInformation(context: DiagnosticRelatedInformationContext) anyerror!void {
    std.debug.assert(context.notes != 0);

    var block = context.handle.zir.extraData(Zir.Inst.Block, context.notes);
    var offset: usize = 0;

    while (offset < block.data.body_len) : (offset += 1) {
        const compile_error = context.handle.zir.extraData(Zir.Inst.CompileErrors.Item, context.handle.zir.extra[block.end + offset]);
        try context.related_info.append(context.allocator, .{
            .location = .{
                .uri = context.handle.uri(),
                .range = ast.astLocationToRange(context.handle.tree.tokenLocation(0, if (compile_error.data.node != 0) context.handle.tree.nodes.items(.main_token)[compile_error.data.node] else compile_error.data.token)),
            },
            .message = try context.allocator.dupe(u8, context.handle.zir.nullTerminatedString(compile_error.data.msg)),
        });

        if (compile_error.data.notes != 0)
            try getDiagnosticRelatedInformation(.{
                .allocator = context.allocator,
                .handle = context.handle,
                .related_info = context.related_info,
                .notes = compile_error.data.notes,
            });
    }
}

/// Allocator should be request Arena
pub fn getDiagnostics(allocator: std.mem.Allocator, handle: DocumentStore.Handle, diagnostics: *std.ArrayListUnmanaged(types.Diagnostic)) !void {
    if (handle.zir.instructions.len == 0) return;

    if (handle.zir.hasCompileErrors()) {
        const base = handle.zir.extra[@enumToInt(Zir.ExtraIndex.compile_errors)];
        var ce_extra = handle.zir.extraData(Zir.Inst.CompileErrors, base);

        var index: usize = 0;
        var offset: usize = base + 1;
        while (index < ce_extra.data.items_len) : (index += 1) {
            const item_extra = handle.zir.extraData(Zir.Inst.CompileErrors.Item, offset);

            var related_info = std.ArrayListUnmanaged(types.DiagnosticRelatedInformation){};

            if (item_extra.data.notes != 0)
                try getDiagnosticRelatedInformation(.{
                    .allocator = allocator,
                    .handle = handle,
                    .related_info = &related_info,
                    .notes = item_extra.data.notes,
                });

            try diagnostics.append(allocator, .{
                // TODO: Improve location of diagnostic to reflect acutal feedback
                .range = ast.astLocationToRange(handle.tree.tokenLocation(0, if (item_extra.data.node != 0) handle.tree.nodes.items(.main_token)[item_extra.data.node] else item_extra.data.token)),
                .severity = .Error,
                .code = "astgen_error", // TODO: Codes
                .source = "zls",
                .message = try allocator.dupe(u8, handle.zir.nullTerminatedString(item_extra.data.msg)),
                .relatedInformation = related_info.items,
            });

            offset = item_extra.end;
        }
    }
}
