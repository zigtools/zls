#!/usr/bin/env python3
import urllib.request
import re

zig_version = 'master'


def make_link(name, anchor):
    anchor = anchor.replace(" ", "-").replace("@", "")
    return f'[{name}](https://ziglang.org/documentation/{zig_version}/#{anchor})'


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
    prefix = '</pre>'
    blk = blk[blk.index(prefix) + len(prefix):].replace('    ', '\t')
    l = []
    for line in blk.splitlines():
        if line.startswith('\t  '):
            line = line[3:]
        l.append(line)
    docs = []
    in_code = False
    for line in l[2:]:
        if line == '{#code_release_fast#}':
            continue
        elif line == '<p>':
            docs.append('')
        elif line == '{#code_end#}':
            docs.append('```')
            in_code = False
        elif line.startswith('{#code_begin'):
            docs.append('```zig')
            in_code = True
        elif not line.startswith('{#see_also|'):
            if line.startswith('<pre>{#syntax#}'):
                docs.append('```zig')
                line = line[len('<pre>{#syntax#}'):]
                in_code = True
            if line.endswith('{#endsyntax#}</pre>'):
                line = line[:-len('{#endsyntax#}</pre>')]
                docs.append(line)
                docs.append('```')
                in_code = False
                continue
            line = line.replace('\t', '    ')
            if in_code:
                docs.append(line)
            else:
                # li
                line = line.replace('  </li>', '').replace('</li>', '')
                line = line.replace('  <li>', '- ').replace('      - ', '- ')
                # entity
                line = line.replace('&lt;', '<').replace('&gt;', '>')
                # em
                line = re.sub(r'</?em>', '*', line)
                # code blocks
                line = re.sub(r'<pre><code>(.+?)</code></pre>',
                              '```\n\\1\n```', line)
                line = re.sub(r'<code>(.+?)</code>', '`\\1`', line)
                line = re.sub(r'{#(end)?syntax#}', '`', line)
                # link
                line = re.sub(r'<a href="(.+?)">(.+?)</a>', '[\\2](\\1)', line)
                line = re.sub(r'{#link\|([^|#]+)\|([^|#]+)#}',
                              lambda m: make_link(m[1], m[2]), line)
                line = re.sub(r'{#link\|([^|#]+)#}',
                              lambda m: make_link(m[1], m[1]), line)
                line = line.rstrip()
                if line != '' and (not '</p>' in line) and (not '<ul>' in line) and (not '</ul>' in line):
                    if '\n' in line:
                        docs += line.splitlines()
                    else:
                        docs.append(line)

    print('    .{')
    print(f'        .name = "{name}",')
    print(f'        .signature = "{signature}",')
    print(f'        .snippet = "{snippet}",')
    print('        .documentation =')
    for line in docs:
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
