comptime {
    _ = @import("sessions.zig");

    // TODO Lifecycle Messages

    // TODO Document Synchronization

    // LSP features
    _ = @import("lsp_features/semantic_tokens.zig");
    _ = @import("lsp_features/inlay_hints.zig");

    // Language features
    _ = @import("language_features/cimport.zig");
}
