package bof

import (
	"reflect"
	"testing"
	"unsafe"
)

// saveAllXMM saves XMM6-XMM15 (10 * 16 = 160 bytes) to the provided pointer.
// Implemented in call_amd64.s.
func saveAllXMM(ptr *byte)

// TestTraceXMMClobbering identifies exactly where XMM6 and XMM7 get clobbered.
func TestTraceXMMClobbering(t *testing.T) {
	addrs := trampolineAddrs()
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		t.Fatal("BeaconPrintfNative trampoline not found")
	}

	testMsg := cstr("trace_xmm")
	xmmNames := []string{"XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15"}

	var xmmBefore [10 * 2]uint64
	saveAllXMM((*byte)(unsafe.Pointer(&xmmBefore[0])))

	CallFunc(fmtAddr, 0, testMsg, 0)

	var xmmAfter [10 * 2]uint64
	saveAllXMM((*byte)(unsafe.Pointer(&xmmAfter[0])))

	trampolineClobbered := false
	for i := 0; i < 10; i++ {
		off := i * 2
		if xmmBefore[off] != xmmAfter[off] || xmmBefore[off+1] != xmmAfter[off+1] {
			t.Errorf("Trampoline path: %s CLOBBERED: before=[%x %x] after=[%x %x]",
				xmmNames[i],
				xmmBefore[off], xmmBefore[off+1],
				xmmAfter[off], xmmAfter[off+1])
			trampolineClobbered = true
		}
	}
	if !trampolineClobbered {
		t.Log("Trampoline path: ALL XMM6-XMM15 preserved")
	}

	goFuncAddr := reflect.ValueOf(_asm_BeaconPrintfNative_abi0).Pointer()

	var xmmGoBefore [10 * 2]uint64
	saveAllXMM((*byte)(unsafe.Pointer(&xmmGoBefore[0])))

	_asm_BeaconPrintfNative_abi0(0, testMsg, 0)

	var xmmGoAfter [10 * 2]uint64
	saveAllXMM((*byte)(unsafe.Pointer(&xmmGoAfter[0])))

	goClobbered := false
	for i := 0; i < 10; i++ {
		off := i * 2
		if xmmGoBefore[off] != xmmGoAfter[off] || xmmGoBefore[off+1] != xmmGoAfter[off+1] {
			t.Errorf("Go-only path: %s CLOBBERED: before=[%x %x] after=[%x %x]",
				xmmNames[i],
				xmmGoBefore[off], xmmGoBefore[off+1],
				xmmGoAfter[off], xmmGoAfter[off+1])
			goClobbered = true
		}
	}
	if !goClobbered {
		t.Log("Go-only path: ALL XMM6-XMM15 preserved")
	}

	_ = goFuncAddr
}
