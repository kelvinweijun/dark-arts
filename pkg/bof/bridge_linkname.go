package bof

import (
	"encoding/binary"
	"reflect"
	"unsafe"
)

// Assembly trampoline declarations.
// The global symbols are defined in bridge_abi0.s (no · prefix).
// The go:linkname directives bind these Go declarations to the assembly implementations.
//
// IMPORTANT: Go auto-generates an ABIInternal wrapper for each assembly function.
// reflect.ValueOf().Pointer() returns the wrapper address, not the raw .abi0 assembly.
// The COFF BOF needs the raw .abi0 address (which reads RCX/RDX/R8 per MSVC convention).
// We decode the ABIInternal wrapper's CALL instruction to find the .abi0 entry point.

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconDataInt_abi0 BeaconDataInt_abi0
func _asm_BeaconDataInt_abi0(parser uintptr) int32

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconDataShort_abi0 BeaconDataShort_abi0
func _asm_BeaconDataShort_abi0(parser uintptr) int16

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconDataLength_abi0 BeaconDataLength_abi0
func _asm_BeaconDataLength_abi0(parser uintptr) int32

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconDataParse_abi0 BeaconDataParse_abi0
func _asm_BeaconDataParse_abi0(parser uintptr, buffer uintptr, size int32)

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconDataExtract_abi0 BeaconDataExtract_abi0
func _asm_BeaconDataExtract_abi0(parser uintptr, size int32) uintptr

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconOutput_abi0 BeaconOutput_abi0
func _asm_BeaconOutput_abi0(outputType uintptr, data uintptr, length int32)

//go:nosplit
//go:noescape
//go:linkname _asm_BeaconPrintfNative_abi0 BeaconPrintfNative_abi0
func _asm_BeaconPrintfNative_abi0(outputType uintptr, format uintptr, vararg uintptr)

// decodeABI0Addr takes the address of an ABIInternal wrapper (as returned by
// reflect.ValueOf().Pointer()) and scans for the CALL instruction to find the
// actual .abi0 entry point address.
//
// Go's ABIInternal wrapper layout varies by arg count:
//   PUSHQ BP              (1 byte)
//   MOVQ SP, BP           (3 bytes)
//   SUBQ $imm, SP         (4 bytes)
//   [save AX/BX/CX...]    (variable)
//   CALL .abi0             (5 bytes, opcode 0xe8)
//   ... (epilogue)
//
// We scan for the first 0xe8 byte (CALL opcode) in the first 32 bytes.
func decodeABI0Addr(wrapperAddr uintptr) uintptr {
	code := (*[32]byte)(unsafe.Pointer(wrapperAddr))
	// Scan for CALL instruction (0xe8) in the first 32 bytes
	for i := 0; i < 28; i++ {
		if code[i] == 0xe8 {
			rel32 := int32(binary.LittleEndian.Uint32(code[i+1:]))
			callAddr := wrapperAddr + uintptr(i)
			return uintptr(int64(callAddr) + 5 + int64(rel32))
		}
	}
	return 0 // CALL not found
}

// trampolineAddrs returns the addresses of the raw .abi0 assembly trampolines.
// These are what COFF BOFs need to call (they read RCX/RDX/R8 per MSVC convention).
func trampolineAddrs() map[string]uintptr {
	return map[string]uintptr{
		"BeaconDataInt":      decodeABI0Addr(reflect.ValueOf(_asm_BeaconDataInt_abi0).Pointer()),
		"BeaconDataShort":    decodeABI0Addr(reflect.ValueOf(_asm_BeaconDataShort_abi0).Pointer()),
		"BeaconDataLength":   decodeABI0Addr(reflect.ValueOf(_asm_BeaconDataLength_abi0).Pointer()),
		"BeaconDataParse":    decodeABI0Addr(reflect.ValueOf(_asm_BeaconDataParse_abi0).Pointer()),
		"BeaconDataExtract":  decodeABI0Addr(reflect.ValueOf(_asm_BeaconDataExtract_abi0).Pointer()),
		"BeaconOutput":       decodeABI0Addr(reflect.ValueOf(_asm_BeaconOutput_abi0).Pointer()),
		"BeaconPrintf":       decodeABI0Addr(reflect.ValueOf(_asm_BeaconPrintfNative_abi0).Pointer()),
		"BeaconPrintfNative": decodeABI0Addr(reflect.ValueOf(_asm_BeaconPrintfNative_abi0).Pointer()),
	}
}
