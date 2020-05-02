# Data Scripts

## Snippet Generation
```js
[...document.querySelector("#toc-Builtin-Functions").parentElement.lastElementChild.children].map(_ => {

const code = document.querySelector("#" + _.innerText.slice(1)).nextElementSibling.children[0].innerText;
var l = (code.lastIndexOf(") ") == -1 ? code.length : code.lastIndexOf(") ")) + 1
var p = code.slice(0, l);

var name = p.slice(0, p.indexOf("("));
var body = p.slice(p.indexOf("(") + 1, -1);
if (body.trim().length === 0) return `${name}()`;
var nb = "";
let depth = 0;
let vi = 2;
let i = 0;
let skip = false;
for (const c of body) {
if (skip) {
skip = false;
if (c === " ") {i++; continue;}
}
if (c === "(") depth++;
else if (c === ")") depth--;

if (c === "," && depth == 0) {
nb += `}, \${${vi}:`;
vi++;
skip = true;
} else if (i === body.length - 1) {
nb += c;
nb += "}";
} else nb += c;
i++;
}
return `${name}(\${1:${nb})`;

}).map(_ => JSON.stringify(_)).join(",\n");
```

## Function Signature / Details
```js
[...document.querySelector("#toc-Builtin-Functions").parentElement.lastElementChild.children].map(_ => {
return document.querySelector("#" + _.innerText.slice(1)).nextElementSibling.innerText;
}).map(_ => JSON.stringify(_)).join(",\n");
```

## Docs
```js
[...document.querySelector("#toc-Builtin-Functions").parentElement.lastElementChild.children].map(_ => {
return document.querySelector("#" + _.innerText.slice(1)).nextElementSibling.nextElementSibling.innerText;
}).map(_ => JSON.stringify(_)).join(",\n");
```
