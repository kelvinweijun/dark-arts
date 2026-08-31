#include "beacon.h"

// ============================================================
// Regression BOF: callee-saved register preservation across BeaconPrintf.
//
// Finding 1A: the BeaconPrintfNative_abi0 trampoline previously used
// RBX, RSI, RDI as scratch registers, which are callee-saved per the
// Microsoft x64 ABI.  This BOF exercises the bug by keeping values
// in nonvolatile registers across a BeaconPrintf call.
//
// Compiled with /O2 to force MSVC into using RBX, RSI, RDI as
// live values across the BeaconPrintf call boundary.
// ============================================================

volatile int g_callee_saved_pass = 0;
volatile int g_chained_result = 0;
volatile int g_printf_count = 0;

// Test 1: register pressure — RBX and RDI hold v4 and v5 across BeaconPrintf.
// With /O2, the compiler computes:
//   edi = v0*v1 = 30*70 = 2100   (held in RDI across call)
//   ebx = v2*v3 = 110*150 = 16500 (held in RBX across call)
//   return edi + ebx = 18600
__declspec(noinline) int callee_saved_stress(
    int a0, int a1, int a2, int a3,
    int a4, int a5, int a6, int a7)
{
    int v0 = a0 + a1;
    int v1 = a2 + a3;
    int v2 = a4 + a5;
    int v3 = a6 + a7;
    int v4 = v0 * v1;
    int v5 = v2 * v3;
    int v6 = v4 + v5;

    BeaconPrintf(0, "stress: %d %d %d %d %d %d", v0, v1, v2, v3, v4, v5);
    g_printf_count++;

    return v6;
}

// Test 2: nested call chain — RBX holds result1 across the second call.
// With /O2, force_outer saves RBX, RSI, RDI:
//   esi = c, edi = d
//   ebx = force_inner(a,b)   (held in RBX across second call)
//   return ebx + force_inner(c,d)
__declspec(noinline) int force_inner(int x, int y)
{
    int r = x * y;
    BeaconPrintf(0, "inner: %d*%d=%d", x, y, r);
    g_printf_count++;
    return r;
}

__declspec(noinline) int force_outer(int a, int b, int c, int d)
{
    int r1 = force_inner(a, b);
    int r2 = force_inner(c, d);
    return r1 + r2;
}

void go(char *args, int length)
{
    g_callee_saved_pass = 0;
    g_chained_result = 0;
    g_printf_count = 0;

    // Test 1: 10+20=30, 30+40=70, 50+60=110, 70+80=150
    // v4=30*70=2100, v5=110*150=16500, v6=18600
    g_callee_saved_pass = callee_saved_stress(10, 20, 30, 40, 50, 60, 70, 80);

    // Test 2: 2*3 + 4*5 = 6 + 20 = 26
    g_chained_result = force_outer(2, 3, 4, 5);
}
