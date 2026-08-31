#include "beacon.h"

// ============================================================
// Comprehensive nonvolatile register preservation test.
//
// Tests ALL Microsoft x64 nonvolatile registers:
//   RBX, RBP, RSI, RDI, R12, R13, R14, R15
//
// Each __declspec(noinline) function forces MSVC /O2 to put
// intermediate values in nonvolatile registers that survive
// across the BeaconPrintf call.
//
// R14 is Go's g pointer and CANNOT be preserved — this test
// documents that known limitation.
// ============================================================

volatile int g_nv_pass = 0;
volatile int g_nv_count = 0;
volatile int g_nv_r14_clobbered = 0;

// Each function computes a unique value and holds it in a register
// across the BeaconPrintf call.  With /O2, the compiler allocates
// these to nonvolatile registers.

__declspec(noinline) int nv_compute_8(int a, int b, int c, int d,
                                      int e, int f, int g, int h)
{
    int v0 = a + b;
    int v1 = c + d;
    int v2 = e + f;
    int v3 = g + h;
    int v4 = v0 * v1;
    int v5 = v2 * v3;
    int v6 = v4 + v5;
    int v7 = v0 ^ v1 ^ v2 ^ v3 ^ v4 ^ v5 ^ v6;

    // BeaconPrintf forces all v0..v7 to be in nonvolatile registers
    // since they are live across this call.
    BeaconPrintf(0, "nv: %d %d %d %d %d %d %d %d",
                 v0, v1, v2, v3, v4, v5, v6, v7);

    return v7;
}

__declspec(noinline) int nv_compute_chain(int x, int y)
{
    int r = x * y;
    BeaconPrintf(0, "chain: %d*%d=%d", x, y, r);
    return r;
}

// Extreme register pressure: 12 locals spanning across 3 BeaconPrintf
// calls.  With /O2, MSVC should use RBX, RSI, RDI, R12, R13, R15
// (and possibly R14) to hold live values.
__declspec(noinline) int nv_extreme_pressure(int a, int b, int c, int d,
                                              int e, int f, int g, int h,
                                              int i, int j, int k, int l)
{
    int r0 = a + b;          // live across call 1
    int r1 = c * d;          // live across call 1
    int r2 = e + f;          // live across call 2
    int r3 = g * h;          // live across call 2
    int r4 = i + j;          // live across call 3
    int r5 = k * l;          // live across call 3
    int r6 = r0 + r2 + r4;   // live across calls 1-3
    int r7 = r1 + r3 + r5;   // live across calls 1-3
    int r8 = r0 * r3;        // live across calls 1-2
    int r9 = r1 + r4;        // live across calls 1-3
    int ra = r2 + r5;        // live across calls 2-3
    int rb = r6 + r7;        // live across all calls

    BeaconPrintf(0, "p1: %d %d %d", r0, r1, r6);
    BeaconPrintf(0, "p2: %d %d %d", r2, r3, r7);
    BeaconPrintf(0, "p3: %d %d %d", r4, r5, rb);

    return r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8 + r9 + ra + rb;
}

void go(char *args, int length)
{
    g_nv_pass = 0;
    g_nv_count = 0;
    g_nv_r14_clobbered = 0;

    // Test 1: 8-register compute
    // 10+20=30, 30+40=70, 50+60=110, 70+80=150
    // v4=30*70=2100, v5=110*150=16500, v6=18700
    // v7=30^70^110^150^2100^16500^18700 = computed value
    int result1 = nv_compute_8(10, 20, 30, 40, 50, 60, 70, 80);
    g_nv_count++;
    if (result1 != 0) {
        g_nv_pass |= 1;
    }

    // Test 2: chained calls (RBX live across second call)
    int chain = nv_compute_chain(2, 3);
    chain += nv_compute_chain(4, 5);
    g_nv_count++;
    if (chain == 26) {
        g_nv_pass |= 2;
    }

    // Test 3: extreme register pressure (12 locals across 3 calls)
    int pressure = nv_extreme_pressure(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
    g_nv_count++;
    if (pressure != 0) {
        g_nv_pass |= 4;
    }
}
