// Run this in a Chrome developer console.
const builtins = $$("a#toc-Builtin-Functions+ul > li").map(element => {
    const anchor = element.querySelector("a").getAttribute("href");
    const code = $(`${anchor}+pre > code`).textContent.replace(/(\r\n|\n|\r)/gm, "");

    var curr_paragraph = $(`${anchor}+pre+p`);
    var doc = "";
    var first = true;

    while (curr_paragraph.nodeName == "P" || curr_paragraph.nodeName == "PRE") {
        if (curr_paragraph.innerHTML == "See also:")
            break;

        if (!first) {
            doc += "\n";
        } else {
            first = false;
        }

        if (curr_paragraph.nodeName == "PRE") {
            doc += "```zig\n";
            curr_paragraph.childNodes[0].childNodes.forEach(elem => {
                doc += elem.textContent;
            });
            doc += "\n```";
        } else {
            curr_paragraph.childNodes.forEach(elem => {
                doc += elem.textContent.replace(/(\s\s+)/gm, " ");
            });
        }

        curr_paragraph = curr_paragraph.nextElementSibling;
    }
    return { "name": anchor.substring(1), "code": code, "documentation": doc };
});

// Take output and paste into a .zig file
console.log(
    `const Builtin = struct {
    name: []const u8,
    signature: []const u8,
    snippet: []const u8,
    documentation: []const u8,
    arguments: []const []const u8,
};

pub const builtins = [_]Builtin{` +
    '\n' + builtins.map(builtin => {
        // Make a snippet
        const first_paren_idx = builtin.code.indexOf('(');
        var snippet = builtin.code.substr(0, first_paren_idx + 1);
        var rest = builtin.code.substr(first_paren_idx + 1);
        var args = [];

        if (rest[0] == ')') {
            snippet += ')';
        } else {
            snippet += "${1:"
            args.push("");

            var arg_idx = 2;
            var paren_depth = 1;
            var skip_space = false;
            for (const char of rest) {
                if (char == '(') {
                    paren_depth += 1;
                } else if (char == ')') {
                    paren_depth -= 1;
                    if (paren_depth == 0) {
                        snippet += "})";
                        break;
                    }
                } else if (char == '"') {
                    snippet += "\\\"";
                    args[args.length - 1] += "\\\"";
                    continue;
                } else if (char == ',' && paren_depth == 1) {
                    snippet += "}, ${" + arg_idx + ':';
                    arg_idx += 1;
                    args.push("");
                    skip_space = true;
                    continue;
                } else if (char == ' ' && skip_space) {
                    continue;
                }

                snippet += char;
                args[args.length - 1] += char;
                skip_space = false;
            }
        }

        return `    .{
        .name = "@${builtin.name}",
        .signature = "${builtin.code.replaceAll('"', "\\\"")}",
        .snippet = "${snippet}",
        .documentation =
        \\\\${builtin.documentation.split('\n').join("\n        \\\\")}
        ,
        .arguments = &.{${args.map(x => "\n            \"" + x + "\"").join(",") + ((args.length > 0) ? ",\n        " : "")}},
    },`;
    }).join('\n') + "\n};\n"
);
