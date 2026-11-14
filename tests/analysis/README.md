# Analysis Test Suite

This directory contains the analysis test suite.

## Test Syntax

An individual test case is specified through zig code comments with special syntax.

Here is an example from `./array.zig`:

```zig
const ArrayType = [3]u8;
//    ^^^^^^^^^ (type)([3]u8)
```

The analyser will lookup and resolve `ArrayType`. It then tests that `@TypeOf(ArrayType) == type` and `ArrayType == [3]u8`.

### Skip expected value

A check for the expected value can be skipped using empty parenthesis:

```zig
fn foo() u32 {
    return 5;
}
const foo_result = foo();
//    ^^^^^^^^^^ (u32)()
```

This will only test the type of `foo_result` but not it's value because it runtime known.

### Expected unknown type or value

Use `unknown` to expect an unknown type or value:

```zig
fn Foo() type {
    // missing return
}
const SomeType = Foo();
//    ^^^^^^^^ (type)(unknown)
```

## Exclude files

Use the `-Dtest-filter` build option to specify a subset of test files to be run. Example:

```shell
zig build -Dtest-filter=array.zig
```
