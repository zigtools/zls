#!/usr/bin/env python3
import urllib.request
import re
import minify_html

zig_version = 'master'


def fix_ul(s):
    l = s.split('<li>')
    l.insert(0, '')
    return '\n  - '.join(l)


url = f'https://raw.githubusercontent.com/ziglang/zig/{zig_version}/doc/langref.html.in'
res = urllib.request.urlopen(url)
page = res.read().decode('utf-8')
print('''const Builtin = struct {
    name: []const u8,
    signature: []const u8,
    snippet: []const u8,
    documentation: []const u8,
    arguments: []const []const u8,
};

pub const builtins = [_]Builtin{''')
pattern = r'{#header_open\|(@\S+?)#}(.+?){#header_close#}'
for match in re.finditer(pattern, page, re.M | re.S):
    blk = match[2].strip(' \n')
    name = match[1]
    signature = re.search(r'<pre>{#syntax#}(.+?){#endsyntax#}</pre>', blk,
                          re.M | re.S)[1].replace('\n   ', '').replace('"', '\\"')
    snippet = name
    if f'{name}()' in signature:
        params = None
        snippet += '()'
    else:
        params = []
        i = signature.index('(') + 1
        level = 1
        j = i
        while i < len(signature):
            if signature[i] == '(':
                level += 1
            elif signature[i] == ')':
                level -= 1
            if signature[i] == ',' and level == 1:
                params.append(signature[j:i])
                j = i + 2
            if level == 0:
                break
            i += 1
        params.append(signature[j:i])
        snippet += '(${'
        i = 1
        for param in params:
            snippet += f'{i}:{param}}}, ${{'
            i += 1
        snippet = snippet[:-4] + ')'
    docs = re.sub(r'{#see_also\|[^#]+#}', '', blk)
    docs = re.sub(
        r'      {#code_begin\|(obj|syntax|(test(\|(call|truncate))?))#}\n', '      <pre>{#syntax#}', docs)
    docs = re.sub(
        r'      {#code_begin\|test_(err|safety)\|[^#]+#}\n', '      <pre>{#syntax#}', docs)
    docs = docs.replace('      {#code_release_fast#}\n', '')
    docs = docs.replace('      {#code_end#}', '{#endsyntax#}</pre>')
    docs = docs.replace('\n{#endsyntax#}</pre>', '{#endsyntax#}</pre>')
    docs = minify_html.minify(docs)
    prefix = '</pre><p>'
    docs = docs[docs.index(prefix)+len(prefix):]
    docs = docs.replace('<p>', '\n\n')
    docs = re.sub(r'{#(end)?syntax#}', '`', docs)
    # @cDefine
    docs = re.sub(r'<pre><code[^>]+>([^<]+)</code></pre>', '`\\1`', docs)
    docs = re.sub(r'</?code>', '`', docs)
    docs = docs.replace('<pre>`', '\n\n```zig\n')
    docs = docs.replace('`</pre>', '\n```')
    # @setFloatMode
    docs = docs.replace('```<', '```\n<')
    # @TypeOf
    docs = re.sub(r'</?em>', '*', docs)
    docs = re.sub(r'<a href=([^>]+)>([^<]+)</a>', '[\\2](\\1)', docs)
    docs = re.sub(r'{#link\|([^|#]+)\|([^|#]+)#}',
                  lambda m: f'[{m[1]}](https://ziglang.org/documentation/{zig_version}/#{m[2].replace(" ","-")})', docs)
    docs = re.sub(
        r'{#link\|([^|#]+)#}', lambda m: f'[{m[1]}](https://ziglang.org/documentation/{zig_version}/#{m[1].replace(" ","-").replace("@","")})', docs)
    docs = re.sub(r'<ul><li>(.+?)</ul>', lambda m: fix_ul(m[1]), docs)

    print('    .{')
    print(f'        .name = "{name}",')
    print(f'        .signature = "{signature}",')
    print(f'        .snippet = "{snippet}",')
    print('        .documentation =')
    for line in docs.splitlines():
        print(r'        \\' + line)
    print('        ,')
    if params is None:
        print('        .arguments = &.{},')
    else:
        print('        .arguments = &.{')
        for param in params:
            print(f'            "{param}",')
        print('        },')
    print('    },')
print('};')
