const std = @import("std");
const Context = @import("context.zig").Context;

const allocator = std.testing.allocator;

test "Open file, ask for semantic tokens" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");"}}
    , null);

    try ctx.request("textDocument/semanticTokens/full",
        \\{"textDocument":{"uri":"file:///test.zig"}}
    ,
        \\{"data":[0,0,5,7,0,0,6,3,0,33,0,4,1,11,0,0,2,7,12,0,0,8,5,9,0]}
    );
}

test "Request completion in an empty file" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":""}}}
    , null);
    try ctx.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":0,"character":0}}
    , null);
}

test "Request completion with no trailing whitespace" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const std = @import(\"std\");\nc"}}
    , null);

    try ctx.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}
    ,
        \\{"isIncomplete":false,"items":[{"label":"std","labelDetails":{"detail":"","description":"@import(\"std\")","sortText":null},"kind":21,"detail":"std","sortText":"1_std","filterText":null,"insertText":"std","insertTextFormat":1,"documentation":null}]}
    );
}

test "Encoded space in file name and usingnamespace on non-existing symbol" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///%20test.zig","languageId":"zig","version":420,"text":"usingnamespace a.b;\nb."}}
    , null);
    try ctx.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///%20test.zig"}, "position":{"line":1,"character":2}}
    ,
        \\{"isIncomplete":false,"items":[]}
    );
}

test "Self-referential definition" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const h = h(0);\nc"}}
    , null);
    try ctx.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}
    ,
        \\{"isIncomplete":false,"items":[{"label":"h","labelDetails":{"detail":"","description":"h(0)","sortText":null},"kind":21,"detail":"h","sortText":"1_h","filterText":null,"insertText":"h","insertTextFormat":1,"documentation":null}]}
    );
}

// This test as written depends on the configuration in the *host* machines zls.json, if `enable_snippets` is true then
// the insert text is "w()" if it is false it is "w"
//
// test "Missing return type" {
//     var server = try Server.start(initialize_msg, null);
//     defer server.shutdown();

//     try server.request("textDocument/didOpen",
//         \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"fn w() {}\nc"}}
//     , null);
//     try server.request("textDocument/completion",
//         \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}
//     ,
//         \\{"isIncomplete":false,"items":[{"label":"w","kind":3,"textEdit":null,"filterText":null,"insertText":"w","insertTextFormat":1,"detail":"fn","documentation":null}]}
//     );
// }

test "Pointer and optional deref" {
    var ctx = try Context.init();
    defer ctx.deinit();

    try ctx.request("textDocument/didOpen",
        \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"var value: ?struct { data: i32 = 5 } = null;const ptr = &value;\nconst a = ptr.*.?."}}
    , null);
    try ctx.request("textDocument/completion",
        \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":18}}
    ,
        \\{"isIncomplete":false,"items":[{"label":"data","labelDetails":{"detail":"","description":"i32 ","sortText":null},"kind":5,"detail":"data","sortText":"3_data","filterText":null,"insertText":"data","insertTextFormat":1,"documentation":null}]}
    );
}

// not fixed yet!
// test "Self-referential import" {
//     var ctx = try Context.init();
//     defer ctx.deinit();
//
//     try ctx.request("textDocument/didOpen",
//         \\{"textDocument":{"uri":"file:///test.zig","languageId":"zig","version":420,"text":"const a = @import(\"test.zig\").a;\nc"}}
//     , null);
//     try ctx.request("textDocument/completion",
//         \\{"textDocument":{"uri":"file:///test.zig"}, "position":{"line":1,"character":1}}
//     ,
//         \\{"isIncomplete":false,"items":[]}
//     );
// }
