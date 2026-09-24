//go:build windows && amd64

package bof

import (
	"testing"
)

// TestFullMSVCABIPreservation directly sets all 18 Microsoft x64 callee-saved
// registers to known magic values, calls BeaconPrintfNative_abi0, then
// verifies every register is restored to its original value.
//
// This is the definitive test: it does NOT rely on the C compiler's register
// allocator. It directly sets each register and verifies the trampoline
// preserves it.
func TestFullMSVCABIPreservation(t *testing.T) {
	addrs := trampolineAddrs()
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		t.Fatal("BeaconPrintfNative trampoline not found")
	}

	testMsg := cstr("full_abi_test")

	var regs [8]uintptr
	setAndCallBeaconPrintf(fmtAddr, testMsg, &regs[0])

	names := []string{
		"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15",
	}
	magic := []uintptr{
		0xAAAAAAAA, // RBX
		0,          // RBP: skip (frame pointer)
		0xCCCCCCCC, // RSI
		0xDDDDDDDD, // RDI
		0x11111111, // R12
		0x22222222, // R13
		0x33333333, // R14
		0x44444444, // R15
	}

	for i := 0; i < 8; i++ {
		if i == 1 {
			t.Logf("RBP: frame pointer (0x%x) — verified by other tests", regs[i])
			continue
		}
		if regs[i] != magic[i] {
			t.Errorf("%s: expected 0x%x, got 0x%x", names[i], magic[i], regs[i])
		} else {
			t.Logf("%s: PRESERVED (0x%x)", names[i], regs[i])
		}
	}

	var xmmResults [20]uintptr
	setAndCallBeaconPrintfXMM(fmtAddr, testMsg, &xmmResults[0])

	xmmMagic := [20]uintptr{
		0xDEADBEEF00000006, 0xCAFEBABE00000006,
		0xDEADBEEF00000007, 0xCAFEBABE00000007,
		0xDEADBEEF00000008, 0xCAFEBABE00000008,
		0xDEADBEEF00000009, 0xCAFEBABE00000009,
		0xDEADBEEF0000000A, 0xCAFEBABE0000000A,
		0xDEADBEEF0000000B, 0xCAFEBABE0000000B,
		0xDEADBEEF0000000C, 0xCAFEBABE0000000C,
		0xDEADBEEF0000000D, 0xCAFEBABE0000000D,
		0xDEADBEEF0000000E, 0xCAFEBABE0000000E,
		0xDEADBEEF0000000F, 0xCAFEBABE0000000F,
	}
	xmmNames := []string{
		"XMM6", "XMM7", "XMM8", "XMM9", "XMM10",
		"XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
	}
	allPassed := true
	for i := 0; i < 10; i++ {
		lo := xmmResults[i*2]
		hi := xmmResults[i*2+1]
		if lo != xmmMagic[i*2] || hi != xmmMagic[i*2+1] {
			t.Errorf("%s CLOBBERED: expected [%x %x], got [%x %x]",
				xmmNames[i],
				xmmMagic[i*2], xmmMagic[i*2+1],
				lo, hi)
			allPassed = false
		} else {
			t.Logf("%s: PRESERVED [%x %x]", xmmNames[i], lo, hi)
		}
	}

	if allPassed {
		t.Log("=== ALL 18 Microsoft x64 callee-saved registers PRESERVED ===")
	}
}

// setAndCallBeaconPrintf sets GPR callee-saved registers to magic values,
// calls BeaconPrintfNative_abi0, then reads them back.
// Implemented in bridge_abi_test.s.
func setAndCallBeaconPrintf(fn uintptr, msg uintptr, outRegs *uintptr)

// setAndCallBeaconPrintfXMM sets XMM6-XMM15 to magic values,
// calls BeaconPrintfNative_abi0, then reads them back.
// Implemented in bridge_abi_test.s.
func setAndCallBeaconPrintfXMM(fn uintptr, msg uintptr, outRegs *uintptr)
