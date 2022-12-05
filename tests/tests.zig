comptime {
    _ = @import("helper.zig");

    _ = @import("utility/offsets.zig");
    _ = @import("utility/position_context.zig");
    _ = @import("utility/uri.zig");

    // TODO Lifecycle Messages

    // TODO Document Synchronization

    // LSP features
    _ = @import("lsp_features/completion.zig");
    _ = @import("lsp_features/folding_range.zig");
    _ = @import("lsp_features/inlay_hints.zig");
    _ = @import("lsp_features/references.zig");
    _ = @import("lsp_features/selection_range.zig");
    _ = @import("lsp_features/semantic_tokens.zig");

    // Language features
    _ = @import("language_features/cimport.zig");
    _ = @import("language_features/comptime_interpreter.zig");
}
