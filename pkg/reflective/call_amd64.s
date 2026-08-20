//go:build windows && amd64

#include "textflag.h"

// callFn invokes an arbitrary Windows x64 function pointer with up to three
// arguments and returns rax. Used to call DllMain(PROCESS_ATTACH) and DLL
// exports that follow the Microsoft x64 calling convention. The trampoline
// reserves the caller-owned 32-byte shadow space (and pads to 16-byte
// alignment at the call site) so the callee's prologue cannot clobber the
// Go frame below it.
//
//	func callFn(fn uintptr, a, b, c uintptr) uintptr
TEXT ·callFn(SB), NOSPLIT, $0-40
	MOVQ fn+0(FP), AX
	MOVQ a+8(FP), CX
	MOVQ b+16(FP), DX
	MOVQ c+24(FP), R8
	SUBQ $0x30, SP
	CALL AX
	ADDQ $0x30, SP
	MOVQ AX, ret+32(FP)
	RET
