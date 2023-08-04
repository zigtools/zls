const build_options = @import("build_options");

pub usingnamespace switch (build_options.data_version) {
    .master => @import("master.zig"),
    .@"0.7.0" => @import("0.7.0.zig"),
    .@"0.7.1" => @import("0.7.1.zig"),
    .@"0.8.0" => @import("0.8.0.zig"),
    .@"0.8.1" => @import("0.8.1.zig"),
    .@"0.9.0" => @import("0.9.0.zig"),
    .@"0.9.1" => @import("0.9.1.zig"),
    .@"0.10.0" => @import("0.10.0.zig"),
    .@"0.10.1" => @import("0.10.1.zig"),
    .@"0.11.0" => @import("0.11.0.zig"),
};
