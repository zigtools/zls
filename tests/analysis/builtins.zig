const some_float: f32 = undefined;
const some_vector: @Vector(4, f32) = undefined;

const float_builtin_00 = @sqrt(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_01 = @sin(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_02 = @cos(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_03 = @tan(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_04 = @exp(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_05 = @exp2(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_06 = @log(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_07 = @log2(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_08 = @log10(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_09 = @abs(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_10 = @floor(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_11 = @ceil(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_12 = @trunc(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()
const float_builtin_13 = @round(some_float);
//    ^^^^^^^^^^^^^^^^ (f32)()

const vector_builtin_00 = @sqrt(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_01 = @sin(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_02 = @cos(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_03 = @tan(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_04 = @exp(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_05 = @exp2(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_06 = @log(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_07 = @log2(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_08 = @log10(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_09 = @abs(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_10 = @floor(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_11 = @ceil(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_12 = @trunc(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()
const vector_builtin_13 = @round(some_vector);
//    ^^^^^^^^^^^^^^^^^ (@Vector(4,f32))()

comptime {
    // Use @compileLog to verify the expected type with the compiler
    // @compileLog(vector_builtin_13);
}
