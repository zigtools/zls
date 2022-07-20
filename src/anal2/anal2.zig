const std = @import("std");
const Zir = @import("stage2/Zir.zig");
const AstGen = @import("stage2/AstGen.zig");
const ast = @import("../ast.zig");
const types = @import("../types.zig");
const offsets = @import("../offsets.zig");

pub fn getDiagnostics(allocator: std.mem.Allocator, tree: std.zig.Ast, diagnostics: *std.ArrayList(types.Diagnostic)) !void {
    var zir = try AstGen.generate(allocator, tree);
    defer zir.deinit(allocator);

    if (zir.instructions.len == 0) return;

    if (zir.hasCompileErrors()) {
        const base = zir.extra[@enumToInt(Zir.ExtraIndex.compile_errors)];
        var ce_extra = zir.extraData(Zir.Inst.CompileErrors, base);

        var index: usize = 0;
        var offset: usize = base + 1;
        while (index < ce_extra.data.items_len) : (index += 1) {
            const item_extra = zir.extraData(Zir.Inst.CompileErrors.Item, offset);
            // TODO: Use note data
            try diagnostics.append(.{
                .range = ast.astLocationToRange(tree.tokenLocation(0, if (item_extra.data.node != 0) tree.nodes.items(.main_token)[item_extra.data.node] else item_extra.data.token)),
                .severity = .Error,
                .code = "astgen_error", // TODO: Codes
                .source = "zls", // NOTE: zls-astgen? idk
                .message = try allocator.dupe(u8, zir.nullTerminatedString(item_extra.data.msg)),
            });
        }
    }
}
