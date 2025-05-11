const Unknown: type = undefined;

fn unknown_parameter_type(_: Unknown) void {}
// ^^^^^^^^^^^^^^^^^^^^^^ (fn ((unknown type)) void)()

fn unknown_return_type() Unknown {}
// ^^^^^^^^^^^^^^^^^^^ (fn () (unknown type))()
