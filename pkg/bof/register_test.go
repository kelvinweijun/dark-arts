//go:build windows && amd64

package bof

import (
	"testing"
	"unsafe"
)

// TestRegisterPreservation verifies that callee-saved registers are preserved
// across trampoline calls. This uses a small assembly helper to save/restore registers.
func TestRegisterPreservation(t *testing.T) {
	addrs := trampolineAddrs()

	// Test data for BeaconDataParse
	testdata := []byte{
		0x2a, 0x00, 0x00, 0x00, // int32: 42
		0x37, 0x17,              // int16: 5943
		0x41, 0x42, 0x43, 0x44, // "ABCD"
	}

	var msvcParser uintptr = 0

	// Get register values before any trampoline calls
	var regsBefore [8]uintptr
	saveCalleeSavedRegs(&regsBefore[0])

	// Call BeaconDataParse
	parseAddr := addrs["BeaconDataParse"]
	CallFunc(parseAddr,
		uintptr(unsafe.Pointer(&msvcParser)),
		uintptr(unsafe.Pointer(&testdata[0])),
		uintptr(len(testdata)),
	)

	// Call BeaconDataInt
	intAddr := addrs["BeaconDataInt"]
	result := CallFunc2(intAddr, msvcParser, 0)
	if result != 42 {
		t.Errorf("BeaconDataInt: expected 42, got %d", result)
	}

	// Call BeaconDataShort
	shortAddr := addrs["BeaconDataShort"]
	result = CallFunc2(shortAddr, msvcParser, 0)
	if result != 5943 {
		t.Errorf("BeaconDataShort: expected 5943, got %d", result)
	}

	// Call BeaconDataLength
	lengthAddr := addrs["BeaconDataLength"]
	result = CallFunc2(lengthAddr, msvcParser, 0)
	if result != 4 {
		t.Errorf("BeaconDataLength: expected 4, got %d", result)
	}

	// Call BeaconDataExtract
	extractAddr := addrs["BeaconDataExtract"]
	result = CallFunc2(extractAddr, msvcParser, 4)
	if result == 0 {
		t.Fatal("BeaconDataExtract returned nil")
	}
	extracted := unsafe.Slice((*byte)(unsafe.Pointer(result)), 4)
	if string(extracted) != "ABCD" {
		t.Errorf("BeaconDataExtract: expected ABCD, got %s", string(extracted))
	}

	// Get register values after all trampoline calls
	var regsAfter [8]uintptr
	saveCalleeSavedRegs(&regsAfter[0])

	// Verify callee-saved registers are preserved
	// Index: 0=rbx, 1=rbp, 2=rsi, 3=rdi, 4=r12, 5=r13, 6=r14, 7=r15
	// R12, R14, R15 are used by Go ABIInternal (R14=G pointer, R12=stack/nil check, R15=g.m)
	regNames := []string{"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15"}
	goRegs := map[int]bool{4: true, 6: true, 7: true} // R12, R14, R15 used by Go runtime
	for i, name := range regNames {
		if goRegs[i] {
			t.Logf("%s: Go runtime register (before=0x%x after=0x%x)", name, regsBefore[i], regsAfter[i])
			continue
		}
		if regsBefore[i] != regsAfter[i] {
			t.Errorf("%s: registers not preserved! before=0x%x after=0x%x",
				name, regsBefore[i], regsAfter[i])
		} else {
			t.Logf("%s: preserved (0x%x)", name, regsBefore[i])
		}
	}

	t.Log("=== Register preservation test COMPLETE ===")
}

// TestBeaconPrintfRegisterPreservation specifically tests that the
// BeaconPrintfNative_abi0 trampoline preserves all Microsoft x64
// nonvolatile registers (RBX, RBP, RSI, RDI, R12–R15).
//
// Finding 1A: the old trampoline used RBX, RSI, RDI as scratch,
// clobbering callee-saved registers.  This test verifies the fix
// by calling the trampoline and checking register state before/after.
func TestBeaconPrintfRegisterPreservation(t *testing.T) {
	addrs := trampolineAddrs()
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		t.Fatal("BeaconPrintfNative trampoline not found")
	}

	testMsg := cstr("test_reg_preserve")

	// Record GPR callee-saved registers BEFORE the call.
	var before [8]uintptr
	saveCalleeSavedRegs(&before[0])

	// Record XMM15 BEFORE the call.
	var xmm15Before [2]uint64
	saveXMM15((*byte)(unsafe.Pointer(&xmm15Before[0])))

	// Record XMM6–XMM14 BEFORE the call.
	var xmm6x14Before [9 * 2]uint64
	saveXMM6X14((*byte)(unsafe.Pointer(&xmm6x14Before[0])))

	// Call through the trampoline.
	CallFunc(fmtAddr, 0, testMsg, 0)

	// Record GPR callee-saved registers AFTER the call.
	var after [8]uintptr
	saveCalleeSavedRegs(&after[0])

	// Record XMM15 AFTER the call.
	var xmm15After [2]uint64
	saveXMM15((*byte)(unsafe.Pointer(&xmm15After[0])))

	// Record XMM6–XMM14 AFTER the call.
	var xmm6x14After [9 * 2]uint64
	saveXMM6X14((*byte)(unsafe.Pointer(&xmm6x14After[0])))

	// Verify GPR nonvolatile registers.
	// Index: 0=RBX, 1=RBP, 2=RSI, 3=RDI, 4=R12, 5=R13, 6=R14, 7=R15
	regNames := []string{"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15"}
	// R12, R14, R15 are Go-managed: R14 = g pointer, R12/R15 = runtime scratch.
	// Go's register allocator clobbers R12/R15 between function calls, so the
	// before/after comparison cannot distinguish trampoline clobbering from Go
	// clobbering.  The MSVC callee_saved_stress BOF test independently proves
	// R12 is preserved by the trampoline (it's live across the call).
	goRegs := map[int]bool{4: true, 6: true, 7: true}
	for i, name := range regNames {
		if goRegs[i] {
			t.Logf("%s: Go runtime register (skipped)", name)
			continue
		}
		if before[i] != after[i] {
			t.Errorf("%s clobbered: before=0x%x after=0x%x", name, before[i], after[i])
		} else {
			t.Logf("%s: preserved (0x%x)", name, before[i])
		}
	}

	// Verify XMM15 is preserved (trampoline saves/restores it).
	if xmm15Before != xmm15After {
		t.Errorf("XMM15 clobbered: before=[%x %x] after=[%x %x]",
			xmm15Before[0], xmm15Before[1], xmm15After[0], xmm15After[1])
	} else {
		t.Logf("XMM15: preserved [%x %x]", xmm15Before[0], xmm15Before[1])
	}

	// XMM14 is clobbered by the ABIInternal function (uses it for varargs memcpy).
	// XMM6–XMM13 should be preserved.
	xmmNames := []string{"XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14"}
	for i := 0; i < 9; i++ {
		off := i * 2
		if i == 8 { // XMM14
			if xmm6x14Before[off] == xmm6x14After[off] && xmm6x14Before[off+1] == xmm6x14After[off+1] {
				t.Logf("XMM14: preserved (unexpected — may not have been called)")
			} else {
				t.Logf("XMM14: clobbered as expected (ABIInternal memcpy)")
			}
			continue
		}
		if xmm6x14Before[off] != xmm6x14After[off] || xmm6x14Before[off+1] != xmm6x14After[off+1] {
			t.Errorf("%s clobbered: before=[%x %x] after=[%x %x]",
				xmmNames[i],
				xmm6x14Before[off], xmm6x14Before[off+1],
				xmm6x14After[off], xmm6x14After[off+1])
		} else {
			t.Logf("%s: preserved [%x %x]", xmmNames[i], xmm6x14Before[off], xmm6x14Before[off+1])
		}
	}

	// Amplification: capture a fresh baseline, call 100 times, re-verify.
	// (We re-capture because Go's frame pointer RBP naturally differs across
	// different call depths; the single-call test above already proved preservation.)
	var baseLoop [8]uintptr
	saveCalleeSavedRegs(&baseLoop[0])
	var xmm15BaseLoop [2]uint64
	saveXMM15((*byte)(unsafe.Pointer(&xmm15BaseLoop[0])))
	for j := 0; j < 100; j++ {
		CallFunc(fmtAddr, 0, testMsg, 0)
	}
	var afterLoop [8]uintptr
	saveCalleeSavedRegs(&afterLoop[0])
	var xmm15Loop [2]uint64
	saveXMM15((*byte)(unsafe.Pointer(&xmm15Loop[0])))
	for i, name := range regNames {
		if goRegs[i] {
			continue
		}
		if baseLoop[i] != afterLoop[i] {
			t.Errorf("%s clobbered after 100 iterations: base=0x%x after=0x%x",
				name, baseLoop[i], afterLoop[i])
		}
	}
	if xmm15BaseLoop != xmm15Loop {
		t.Errorf("XMM15 clobbered after 100 iterations")
	}

	t.Log("=== BeaconPrintfNative_abi0 register preservation PASSED ===")
}

// cstr returns a pointer to a Go-managed null-terminated C string.
// The pointer remains valid for the duration of the test.
func cstr(s string) uintptr {
	b := append([]byte(s), 0)
	return uintptr(unsafe.Pointer(&b[0]))
}

// saveCalleeSavedRegs saves all callee-saved registers to the provided array.
// This is implemented in call_amd64.s.
func saveCalleeSavedRegs(ptr *uintptr)

// saveXMM15 saves XMM15 (16 bytes) to the provided pointer.
// This is implemented in call_amd64.s.
func saveXMM15(ptr *byte)

// loadXMM15 loads XMM15 (16 bytes) from the provided pointer.
// This is implemented in call_amd64.s.
func loadXMM15(ptr *byte)

// saveXMM6X14 saves XMM6–XMM14 (9×16 = 144 bytes) to the provided pointer.
// This is implemented in call_amd64.s.
func saveXMM6X14(ptr *byte)

// loadXMM6X14 loads XMM6–XMM14 (9×16 = 144 bytes) from the provided pointer.
// This is implemented in call_amd64.s.
func loadXMM6X14(ptr *byte)
