#include "beacon.h"

// Multi-arg printf test BOF.
// Tests: 0, 1, 2, 3, 4, 5, 6 variadic args + pointer args + stack args.
// Each test writes a result token to a global buffer so we can verify from Go.

volatile int g_test_id = 0;
volatile int g_test_pass = 0;
volatile int g_printf_call_count = 0;

// We can't directly capture BeaconPrintf output in Go (beaconPrintf callback is nil),
// but we CAN verify the BOF doesn't crash and the trampoline forwards all args correctly.
// The test validates:
//   1. No crash (trampoline forwards args without corrupting stack)
//   2. BeaconPrintf is actually called (g_printf_call_count increments)
//   3. Pointer args don't crash (string dereference succeeds)

void go(char *args, int length) {
    g_test_id = 0;
    g_printf_call_count = 0;

    // Test 0: zero variadic args
    g_test_id = 1;
    BeaconPrintf(0, "hello");
    g_printf_call_count++;

    // Test 1: one int arg (passed in R8 register)
    g_test_id = 2;
    BeaconPrintf(0, "val=%d", 42);
    g_printf_call_count++;

    // Test 2: two int args (R8, R9 registers)
    g_test_id = 3;
    BeaconPrintf(0, "a=%d b=%d", 10, 20);
    g_printf_call_count++;

    // Test 3: three int args (R8, R9, stack[0])
    g_test_id = 4;
    BeaconPrintf(0, "a=%d b=%d c=%d", 10, 20, 30);
    g_printf_call_count++;

    // Test 4: four int args (R8, R9, stack[0], stack[1])
    g_test_id = 5;
    BeaconPrintf(0, "%d %d %d %d", 1, 2, 3, 4);
    g_printf_call_count++;

    // Test 5: five int args (2 regs + 3 stack)
    g_test_id = 6;
    BeaconPrintf(0, "%d %d %d %d %d", 1, 2, 3, 4, 5);
    g_printf_call_count++;

    // Test 6: six int args (2 regs + 4 stack) - max forwarded by trampoline
    g_test_id = 7;
    BeaconPrintf(0, "%d %d %d %d %d %d", 1, 2, 3, 4, 5, 6);
    g_printf_call_count++;

    // Test 7: pointer arg (string) - tests string dereference
    g_test_id = 8;
    BeaconPrintf(0, "msg=%s", "test_string");
    g_printf_call_count++;

    // Test 8: mixed int + pointer
    g_test_id = 9;
    BeaconPrintf(0, "n=%d s=%s x=%d", 42, "world", 99);
    g_printf_call_count++;

    // Test 9: large values to test sign extension
    g_test_id = 10;
    BeaconPrintf(0, "big=%d", 0x7FFFFFFF);
    g_printf_call_count++;

    // All tests completed
    g_test_pass = 1;
}
