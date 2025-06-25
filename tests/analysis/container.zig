const Foo = struct {
    foo: i32 = 0,
    const bar: i64 = 0;
    fn fizz() void {}
    fn buzz(_: Foo) void {}
};

const foo: Foo = .{};
//               ^ (Foo)()

const static_access_field = Foo.foo;
//    ^^^^^^^^^^^^^^^^^^^ (unknown)()

const static_access_decl = Foo.bar;
//    ^^^^^^^^^^^^^^^^^^ (i64)()

const static_access_func = Foo.fizz;
//    ^^^^^^^^^^^^^^^^^^ (fn () void)()

const static_access_method = Foo.buzz;
//    ^^^^^^^^^^^^^^^^^^^^ (fn (Foo) void)()

const instance_access_field = foo.foo;
//    ^^^^^^^^^^^^^^^^^^^^^ (i32)()

const instance_access_decl = foo.bar;
//    ^^^^^^^^^^^^^^^^^^^^ (unknown)()

const instance_access_func = foo.fizz;
//    ^^^^^^^^^^^^^^^^^^^^ (unknown)()

const instance_access_method = foo.buzz;
//    ^^^^^^^^^^^^^^^^^^^^^^ (fn (Foo) void)()
