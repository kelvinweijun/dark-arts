//go:build windows && amd64

package bof

import (
	"testing"
	"unsafe"
)

// testSetR14AndCall sets R14 to setVal, calls fn(0, 0, 0),
// then reads the resulting R14 into outR14.
// Implemented in bridge_abi_test.s — bypasses Go's ABI wrapper so R14 is
// set directly without Go's callee-saved preservation.
func testSetR14AndCall(fn, setVal uintptr, outR14 *uintptr)

// testSetXMM14AndCall sets XMM14 to (lo|hi), calls fn(0, 0, 0),
// then reads the resulting XMM14 into out.
func testSetXMM14AndCall(fn uintptr, lo, hi uint64, out *byte)

func saveR14(ptr *uintptr)   // call_amd64.s
func saveXMM14(ptr *byte)    // call_amd64.s

// TestR14Preservation sets R14 to a non-g value, calls the trampoline,
// and checks whether R14 is restored.
//
// The Go ABI0→ABIInternal wrapper loads R14 from TLS (g pointer).
// After the Go function returns, R14 still holds the g pointer.
// The question is: can our outer trampoline save the MSVC caller's R14
// before the Go call and restore it afterward?
func TestR14Preservation(t *testing.T) {
	addrs := trampolineAddrs()
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		t.Fatal("BeaconPrintfNative not found")
	}

	testMsg := cstr("r14_test")

	// Step 1: observe the normal g pointer value
	var r14Normal uintptr
	saveR14(&r14Normal)
	t.Logf("R14 normal (g pointer): 0x%x", r14Normal)
	if r14Normal == 0 {
		t.Fatal("R14 is 0")
	}

	// Step 2: call the trampoline normally and verify R14 returns to g pointer
	CallFunc(fmtAddr, 0, testMsg, 0)
	var r14AfterCall uintptr
	saveR14(&r14AfterCall)
	t.Logf("R14 after normal call:  0x%x", r14AfterCall)
	if r14AfterCall != r14Normal {
		t.Errorf("R14 changed after normal call: 0x%x -> 0x%x", r14Normal, r14AfterCall)
	}

	// Step 3: set R14 to a non-g value via raw assembly, then call trampoline.
	// This bypasses Go's ABI wrapper which would preserve R14.
	magic := uintptr(0xDEADBEEF12345678)
	var r14After uintptr
	testSetR14AndCall(fmtAddr, magic, &r14After)
	t.Logf("R14 set to 0x%x, after trampoline: 0x%x", magic, r14After)

	if r14After == magic {
		t.Log("RESULT: R14 is RESTORED to the caller's value after the trampoline call.")
		t.Log("The trampoline saves R14 before CALL and restores it after RET.")
		t.Log("The ABI0→ABIInternal wrapper overwrites R14 with g, but the trampoline")
		t.Log("restores the MSVC caller's original R14 before returning.")
	} else if r14After == r14Normal {
		t.Log("RESULT: R14 returned to the g pointer value.")
		t.Log("The ABI0 wrapper overwrote R14 with the g pointer.")
		t.Logf("The caller's arbitrary R14 value (0x%x) was lost.", magic)
	} else {
		t.Logf("RESULT: R14 = 0x%x (neither magic nor g pointer)", r14After)
	}

	// Step 4: Now test if we CAN save/restore R14 by adding it to the trampoline.
	// We need to modify the trampoline to save R14 before the Go call and
	// restore it after. For now, this test documents the current behavior.
	t.Log("")
	t.Log("=== R14 preservation analysis ===")
	t.Log("The ABI0→ABIInternal wrapper at the Go linker-resolved address")
	t.Log("loads R14 from TLS (g pointer) before calling the Go function.")
	t.Log("After the Go function returns, R14 still holds the g pointer.")
	t.Log("The wrapper does NOT restore the original R14 value.")
	t.Log("To preserve R14, the OUTER trampoline (our assembly) must save")
	t.Log("R14 before calling ·BeaconPrintfNative(SB) and restore it after.")
	t.Log("This is safe because the wrapper is NOSPLIT assembly (no preemption).")
}

// TestXMM14Preservation tests whether XMM14 can be preserved across the
// BeaconPrintfNative_abi0 trampoline.
func TestXMM14Preservation(t *testing.T) {
	addrs := trampolineAddrs()
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		t.Fatal("BeaconPrintfNative not found")
	}

	testMsg := cstr("xmm14_test")

	// Step 1: observe normal XMM14
	var xmm14Before [2]uint64
	saveXMM14((*byte)(unsafe.Pointer(&xmm14Before[0])))
	t.Logf("XMM14 normal: [%x %x]", xmm14Before[0], xmm14Before[1])

	// Step 2: call trampoline, check XMM14 after
	CallFunc(fmtAddr, 0, testMsg, 0)
	var xmm14After [2]uint64
	saveXMM14((*byte)(unsafe.Pointer(&xmm14After[0])))
	t.Logf("XMM14 after call: [%x %x]", xmm14After[0], xmm14After[1])

	if xmm14Before == xmm14After {
		t.Log("XMM14 unchanged after normal call (may not have been used)")
	} else {
		t.Logf("XMM14 changed: [%x %x] -> [%x %x]",
			xmm14Before[0], xmm14Before[1], xmm14After[0], xmm14After[1])
	}

	// Step 3: set XMM14 to a known value via raw assembly, then call trampoline
	magic_lo := uint64(0xDEADBEEF12345678)
	magic_hi := uint64(0xCAFEBABE98765432)
	var xmm14Result [2]uint64
	testSetXMM14AndCall(fmtAddr, magic_lo, magic_hi, (*byte)(unsafe.Pointer(&xmm14Result[0])))
	t.Logf("XMM14 set to [%x %x], after trampoline: [%x %x]",
		magic_lo, magic_hi, xmm14Result[0], xmm14Result[1])

	if xmm14Result[0] == magic_lo && xmm14Result[1] == magic_hi {
		t.Log("RESULT: XMM14 is preserved!")
	} else if xmm14Result[0] == 0 && xmm14Result[1] == 0 {
		t.Log("RESULT: XMM14 zeroed — the ABIInternal function used it for memcpy")
	} else {
		t.Logf("RESULT: XMM14 = [%x %x] (different from both input and zero)", xmm14Result[0], xmm14Result[1])
	}

	t.Log("")
	t.Log("=== XMM14 preservation analysis ===")
	t.Log("XMM14 is used by the ABIInternal function body (varargs memcpy).")
	t.Log("Unlike R14 (which is set in the WRAPPER), XMM14 is modified")
	t.Log("INSIDE the Go function. The outer trampoline CAN save/restore it")
	t.Log("if it saves before the CALL and restores after. This is safe")
	t.Log("because XMM14 is not used by Go's runtime outside the function body.")
}
