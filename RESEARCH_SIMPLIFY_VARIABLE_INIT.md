# Research: Simplify Variable Initialization Code Action

## Overview
This document captures research findings for implementing a ZLS code action that simplifies verbose variable initialization patterns. The code action should transform:
- `const foo = @as(T, value)` → `const foo: T = value`
- `const bar = T{}` → `const bar: T = .{}`

## Key Findings

### 1. Code Action Architecture (Builder Pattern)

**Location:** `src/features/code_actions.zig`

#### Builder Structure
The `Builder` struct is the central coordinator for code actions:

```zig
pub const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    offset_encoding: offsets.Encoding,
    only_kinds: ?std.EnumSet(std.meta.Tag(types.CodeAction.Kind)),

    actions: std.ArrayList(types.CodeAction) = .empty,
    fixall_text_edits: std.ArrayList(types.TextEdit) = .empty,

    // Key methods:
    pub fn generateCodeAction(builder: *Builder, error_bundle: ...) !void
    pub fn generateCodeActionsInRange(builder: *Builder, range: types.Range) !void
    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit
    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit
    pub fn createWorkspaceEdit(self: *Builder, edits: []const types.TextEdit) !types.WorkspaceEdit
}
```

#### Two Execution Paths
1. **Error-based actions** (via `generateCodeAction`):
   - Triggered on Zig compiler diagnostics/errors
   - Handler functions called for specific error types (unused, never_mutated, etc.)
   - Example handlers: `handleVariableNeverMutated`, `handleUnusedVariableOrConstant`

2. **Range/Refactor actions** (via `generateCodeActionsInRange`):
   - Triggered by user cursor position in specific tokens
   - Currently only handles string literal refactors (convert to/from multiline)
   - Examples: `generateStringLiteralCodeActions`, `generateMultilineStringCodeActions`

### 2. AST Node Types for Target Patterns

#### For `@as()` Pattern: `const foo = @as(T, value)`

**Node Tag:** `.builtin_call_two` or `.builtin_call_two_comma`

Key characteristics:
- Main token is the `@as` builtin name
- Has two operands: type node and value node
- Located in `src/features/code_actions.zig:867-876` (import handler):
  ```zig
  .builtin_call_two, .builtin_call_two_comma => {
      const builtin_name = offsets.tokenToSlice(tree, token);
      if (!std.mem.eql(u8, builtin_name, "@import")) continue;

      const first_param, const second_param = tree.nodeData(current_node).opt_node_and_opt_node;
      const param_node = first_param.unwrap() orelse continue;
      // ... process params
  }
  ```

**To detect `@as`:**
- Check if main token text equals "@as"
- Extract first param (type expression) and second param (value expression)
- First param should be a type expression (identifier, builtin_call, ptr_type, etc.)
- Second param is the value to cast

#### For Struct Init Pattern: `const bar = T{}`

**Node Tags:** `.struct_init_*` variants
- `.struct_init`
- `.struct_init_comma`
- `.struct_init_one`
- `.struct_init_one_comma`
- `.struct_init_dot` (shorthand init)
- `.struct_init_dot_comma`
- `.struct_init_dot_two`
- `.struct_init_dot_two_comma`

**Key usage in analysis.zig (lines 2047-2060):**
```zig
.struct_init, .struct_init_comma, .struct_init_one, .struct_init_one_comma => {
    const struct_init = tree.fullStructInit(&buffer, node).?;
    const type_expr = struct_init.ast.type_expr.unwrap().?;
    // ... analyze type expression
}
```

**To transform to shorthand:**
- Check if all fields use default values (no explicit field assignments)
- Transform `T{}` → `T.{}` (shorthand initialization)
- For nested types, may need parentheses: `(T.U){}` → `(T.U).{}`

### 3. Variable Declaration Detection

**Key Pattern:** All handlers work with variable declarations through the analyser

**Method 1: Direct AST node lookup**
- Located via `offsets.sourceIndexToTokenIndex(tree, loc.start)`
- Pick token tag `.identifier` to find the variable name
- Lookup symbol with `analyser.lookupSymbolGlobal(handle, name, loc.start)`

**Method 2: From variable declaration node**
- Use `tree.simpleVarDecl(node)` to get var_decl structure
- Extract init node: `var_decl.ast.init_node.unwrap()`
- Check node tag to determine if it's `@as()` or struct init

**Example from handleUnusedVariableOrConstant (lines 395-438):**
```zig
fn handleUnusedVariableOrConstant(builder: *Builder, loc: offsets.Loc) !void {
    const tree = &builder.handle.tree;
    const identifier_token = offsets.sourceIndexToTokenIndex(tree, loc.start)
        .pickTokenTag(.identifier, tree) orelse return;
    const identifier_name = offsets.identifierTokenToNameSlice(tree, identifier_token);

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle, identifier_name, loc.start,
    )) orelse return;

    const node = switch (decl.decl) {
        .ast_node => |node| node,
        .assign_destructure => |payload| payload.node,
        else => return,
    };
    // ... process node
}
```

### 4. Implementation Strategy

#### Option A: Refactor Action (Cursor-Position Based)
- Trigger when cursor is on the assignment (=) token or variable name
- Detect pattern and propose transformation
- Advantage: Non-diagnostic based, always available
- Disadvantage: Requires user to position cursor precisely

#### Option B: Diagnostic-Based Action
- Create a custom diagnostic in the analyser for verbose patterns
- Handler extracts type and value, generates simplified form
- Advantage: Can be included in fixAll, always detected
- Disadvantage: Requires analyser changes (outside current scope)

#### Recommended Approach: Refactor Action
- Implement in `generateCodeActionsInRange()` or new handler
- Key steps:
  1. Check if cursor is on a variable declaration
  2. Extract the initialization expression (init node)
  3. Check if it's `@as(...)` or verbose struct init
  4. Generate simplified form
  5. Create TextEdit and CodeAction

### 5. Test Pattern Structure

**Location:** `tests/lsp_features/code_actions.zig`

**Test Helper Functions:**
```zig
fn testAutofix(before: []const u8, after: []const u8) !void
fn testDiagnostic(before: []const u8, after: []const u8, options: {...}) !void
fn testOrganizeImports(before: []const u8, after: []const u8) !void
fn testConvertString(before: []const u8, after: []const u8) !void
```

**Test Structure Example:**
```zig
test "variable never mutated" {
    try testDiagnostic(
        \\test {
        \\    var foo = 5;
        \\    _ = foo;
        \\}
    ,
        \\test {
        \\    const foo = 5;
        \\    _ = foo;
        \\}
    , .{ .filter_title = "use 'const'" });
}
```

**Key Test Mechanics:**
- `testDiagnostic()` calls helpers that:
  1. Parse before/after source code
  2. Handle placeholders (e.g., `<cursor>`)
  3. Create LSP CodeAction.Params with range
  4. Filter by kind or title
  5. Apply TextEdits and verify result matches after

**For refactor actions:**
- Use `.{ .filter_kind = .refactor }` to filter by kind
- Position range should be on the token of interest
- Placeholder support via `helper.collectClearPlaceholders()`

### 6. Key Files to Modify

For implementation:
1. **`src/features/code_actions.zig`**
   - Add handler function for simplify patterns
   - Integrate into `generateCodeActionsInRange()` or `generateCodeAction()`
   - Add pattern detection logic

2. **`src/ast.zig`** (if needed)
   - May need helper functions to extract type from `@as()` calls
   - May need to check struct init field completeness

3. **`tests/lsp_features/code_actions.zig`**
   - Add test cases for both `@as()` and struct init patterns
   - Test edge cases: complex types, nested structures, multiple fields

### 7. Edge Cases and Considerations

#### Type Expression Extraction
- Simple types: `i32`, `u64`, `bool`
- Complex types: `*const T`, `[]const u8`, `?T`
- User-defined types: `MyStruct`, `std.ArrayList(u32)`
- Builtin calls: `@TypeOf(...)`, `@TypeInfo(...)`

#### Field Analysis for Struct Init
- Check all fields have default values (no explicit assignments)
- Handle named fields vs positional fields
- Handle nested struct initialization

#### Whitespace and Formatting
- Preserve indentation
- Handle comments near the declaration
- Consider multi-line declarations

#### Valid Targets
- Only `const` and `var` declarations
- Skip extern declarations
- Skip declarations with complex initializers

### 8. AST Helper Functions to Use

From `src/ast.zig`:
- `lastToken(tree: *const Ast, node: Node.Index) Ast.TokenIndex` - get last token of node
- `nodeToLoc(tree: *const Ast, node: Node.Index) offsets.Loc` - convert node to location

From `std.zig.Ast`:
- `tree.fullStructInit(&buffer, node)` - get full struct init data
- `tree.nodeTag(node)` - get node type tag
- `tree.nodeData(node)` - get node data (union/struct fields)
- `tree.tokenTag(token_idx)` - get token type

## Summary

The ZLS codebase uses a builder pattern for code actions with two main paths:
1. Error-diagnostic based (handled in `generateCodeAction`)
2. Range/refactor based (handled in `generateCodeActionsInRange`)

For the simplify variable initialization action, a **refactor-based approach** is recommended because:
- No compiler diagnostic needed
- Can work on any valid variable declaration
- Follows existing string literal refactor pattern
- Can be tested with existing test infrastructure

The implementation requires:
1. Pattern detection for `@as(T, v)` and struct inits
2. Type and value extraction from AST nodes
3. TextEdit generation for the transformation
4. Integration into `generateCodeActionsInRange()` or new handler
5. Comprehensive test coverage

Key AST node types to work with:
- `.builtin_call_two`/`.builtin_call_two_comma` for `@as()`
- `.struct_init*` variants for struct initialization
- `.simple_var_decl` for variable declarations
