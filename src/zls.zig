//! Used by tests as a package, can be used by tools such as
//! zigbot9001 to take advantage of zls' tools

pub const ast = @import("ast.zig");
pub const Analyser = @import("analysis.zig");
pub const Header = @import("Header.zig");
pub const debug = @import("debug.zig");
pub const offsets = @import("offsets.zig");
pub const Config = @import("Config.zig");
pub const Server = @import("Server.zig");
pub const translate_c = @import("translate_c.zig");
pub const types = @import("lsp.zig");
pub const URI = @import("uri.zig");
pub const DocumentStore = @import("DocumentStore.zig");
pub const ComptimeInterpreter = @import("ComptimeInterpreter.zig");
pub const diff = @import("diff.zig");
pub const analyser = @import("analyser/analyser.zig");
pub const configuration = @import("configuration.zig");
pub const ZigVersionWrapper = @import("ZigVersionWrapper.zig");

pub const signature_help = @import("features/signature_help.zig");
pub const references = @import("features/references.zig");
pub const semantic_tokens = @import("features/semantic_tokens.zig");
pub const inlay_hints = @import("features/inlay_hints.zig");
pub const code_actions = @import("features/code_actions.zig");
pub const folding_range = @import("features/folding_range.zig");
pub const document_symbol = @import("features/document_symbol.zig");
pub const completions = @import("features/completions.zig");
pub const goto = @import("features/goto.zig");
pub const hover_handler = @import("features/hover.zig");
pub const selection_range = @import("features/selection_range.zig");
pub const diagnostics = @import("features/diagnostics.zig");
pub const legacy_json = @import("legacy_json.zig");

comptime {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
