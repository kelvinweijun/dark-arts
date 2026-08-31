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

// saveCalleeSavedRegs saves all GPR callee-saved registers to the provided array.
//	func saveCalleeSavedRegs(ptr *uintptr)
// On Windows x64, callee-saved: RBX, RBP, RSI, RDI, R12-R15
TEXT ·saveCalleeSavedRegs(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVQ BX,  0(AX)
	MOVQ BP,  8(AX)
	MOVQ SI, 16(AX)
	MOVQ DI, 24(AX)
	MOVQ R12, 32(AX)
	MOVQ R13, 40(AX)
	MOVQ R14, 48(AX)
	MOVQ R15, 56(AX)
	RET

// saveXMM15 saves XMM15 (16 bytes) to the provided pointer.
//	func saveXMM15(ptr *byte)
TEXT ·saveXMM15(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS X15, 0(AX)
	RET

// loadXMM15 loads XMM15 (16 bytes) from the provided pointer.
//	func loadXMM15(ptr *byte)
TEXT ·loadXMM15(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS 0(AX), X15
	RET

// saveXMM6X14 saves XMM6–XMM14 (9×16 = 144 bytes) to the provided pointer.
//	func saveXMM6X14(ptr *byte)
TEXT ·saveXMM6X14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS X6,  0x00(AX)
	MOVUPS X7,  0x10(AX)
	MOVUPS X8,  0x20(AX)
	MOVUPS X9,  0x30(AX)
	MOVUPS X10, 0x40(AX)
	MOVUPS X11, 0x50(AX)
	MOVUPS X12, 0x60(AX)
	MOVUPS X13, 0x70(AX)
	MOVUPS X14, 0x80(AX)
	RET

// loadXMM6X14 loads XMM6–XMM14 (9×16 = 144 bytes) from the provided pointer.
//	func loadXMM6X14(ptr *byte)
TEXT ·loadXMM6X14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS 0x00(AX), X6
	MOVUPS 0x10(AX), X7
	MOVUPS 0x20(AX), X8
	MOVUPS 0x30(AX), X9
	MOVUPS 0x40(AX), X10
	MOVUPS 0x50(AX), X11
	MOVUPS 0x60(AX), X12
	MOVUPS 0x70(AX), X13
	MOVUPS 0x80(AX), X14
	RET

// saveXMM14 saves XMM14 (16 bytes) to the provided pointer.
//	func saveXMM14(ptr *byte)
TEXT ·saveXMM14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS X14, 0(AX)
	RET

// loadXMM14 loads XMM14 (16 bytes) from the provided pointer.
//	func loadXMM14(ptr *byte)
TEXT ·loadXMM14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS 0(AX), X14
	RET

// saveR14 saves R14 to the provided pointer.
//	func saveR14(ptr *uintptr)
TEXT ·saveR14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVQ R14, 0(AX)
	RET

// loadR14 loads R14 from the provided pointer.
//	func loadR14(ptr *uintptr)
TEXT ·loadR14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVQ 0(AX), R14
	RET

// setR14 sets R14 to the value at the provided pointer.
//	func setR14(val *uintptr)
TEXT ·setR14(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVQ 0(AX), R14
	RET

// saveAllXMM saves XMM6-XMM15 (10 * 16 = 160 bytes) to the provided pointer.
//	func saveAllXMM(ptr *byte)
TEXT ·saveAllXMM(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ ptr+0(FP), AX
	MOVUPS X6,  0x00(AX)
	MOVUPS X7,  0x10(AX)
	MOVUPS X8,  0x20(AX)
	MOVUPS X9,  0x30(AX)
	MOVUPS X10, 0x40(AX)
	MOVUPS X11, 0x50(AX)
	MOVUPS X12, 0x60(AX)
	MOVUPS X13, 0x70(AX)
	MOVUPS X14, 0x80(AX)
	MOVUPS X15, 0x90(AX)
	RET
