#include "beacon.h"

volatile int g_test_id = 0;

// Test 1: zero variadic arguments
void test_zero_args(void) {
    BeaconPrintf(0, "hello");
}

// Test 2: one variadic argument (int)
void test_one_int(void) {
    BeaconPrintf(0, "val=%d", 42);
}

// Test 3: two variadic arguments (int, int)
void test_two_ints(void) {
    BeaconPrintf(0, "a=%d b=%d", 42, 84);
}

// Test 4: three variadic arguments (int, int, int)
void test_three_ints(void) {
    BeaconPrintf(0, "a=%d b=%d c=%d", 10, 20, 30);
}

// Test 5: int + string (tests pointer arg)
void test_int_string(void) {
    char *msg = "hello";
    BeaconPrintf(0, "n=%d s=%s", 42, msg);
}

// Test 6: many args - enough to push onto the MSVC x64 stack
// MSVC x64: first 4 args in RCX, RDX, R8, R9; rest on stack.
// For variadic calls, args are always passed in registers for _format_ 
// but for __cdecl with format string the format string is in RDX (arg2),
// and the variadic args start from R8.
// 5+ int variadic args → 2 in registers (R8, R9) + 3 on stack
void test_many_ints(void) {
    BeaconPrintf(0, "%d %d %d %d %d %d", 1, 2, 3, 4, 5, 6);
}

// Test 7: mixed types to exercise different register widths
void test_mixed_types(void) {
    BeaconPrintf(0, "i=%d p=%s d=%d", 99, "world", 77);
}

// Entry point: run all tests
void go(char *args, int length) {
    g_test_id = 1; test_zero_args();
    g_test_id = 2; test_one_int();
    g_test_id = 3; test_two_ints();
    g_test_id = 4; test_three_ints();
    g_test_id = 5; test_int_string();
    g_test_id = 6; test_many_ints();
    g_test_id = 7; test_mixed_types();
}
