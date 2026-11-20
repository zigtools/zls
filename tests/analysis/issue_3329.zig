fn ElementType(comptime T: type) type {
    return @typeInfo(T).pointer.child;
}

fn first(slice: anytype) ElementType(@TypeOf(slice)) {
    return slice[0];
}

const arr: []u8 = "hello";
const result = first(arr);
//    ^^^^^^ should be (u8)(), currently (unknown type)()

fn SecondExample(comptime T: type) type {
    return @typeInfo(T).array.child;
}

fn getFirst(arr: anytype) SecondExample(@TypeOf(arr)) {
    return arr[0];
}

const array: [5]u8 = "hello".*;
const result2 = getFirst(array);
//    ^^^^^^^ should be (u8)(), currently (unknown type)()

fn PointerElementType(comptime T: type) type {
    const info = @typeInfo(T);
    return if (info == .pointer) info.pointer.child else T;
}

fn getPtrElement(ptr: anytype) PointerElementType(@TypeOf(ptr)) {
    return ptr.*;
}

const ptr: *u8 = undefined;
const result3 = getPtrElement(ptr);
//    ^^^^^^^ should be (u8)(), currently (unknown type)()
