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

// CallFunc calls a function pointer with up to 3 arguments using the Windows x64 calling convention.
//	func CallFunc(fn uintptr, a1, a2, a3 uintptr) uintptr
TEXT ·CallFunc(SB), NOSPLIT, $0-40
	MOVQ fn+0(FP), AX
	MOVQ a1+8(FP), CX
	MOVQ a2+16(FP), DX
	MOVQ a3+24(FP), R8
	SUBQ $0x30, SP
	CALL AX
	ADDQ $0x30, SP
	MOVQ AX, ret+32(FP)
	RET

// CallFunc2 calls a function pointer with 2 arguments.
//	func CallFunc2(fn, a1, a2 uintptr) uintptr
TEXT ·CallFunc2(SB), NOSPLIT, $0-24
	MOVQ fn+0(FP), AX
	MOVQ a1+8(FP), CX
	MOVQ a2+16(FP), DX
	SUBQ $0x30, SP
	CALL AX
	ADDQ $0x30, SP
	MOVQ AX, ret+24(FP)
	RET

// CallFunc0 calls a function pointer with no arguments.
//	func CallFunc0(fn uintptr) uintptr
TEXT ·CallFunc0(SB), NOSPLIT, $0-8
	MOVQ fn+0(FP), AX
	SUBQ $0x30, SP
	CALL AX
	ADDQ $0x30, SP
	MOVQ AX, ret+8(FP)
	RET 
