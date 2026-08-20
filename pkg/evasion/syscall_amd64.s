//go:build windows && amd64

#include "textflag.h"

// invokeSyscall executes a direct syscall with the Windows x64 ABI:
//   arg1 -> R10, arg2 -> RDX, arg3 -> R8, arg4 -> R9,
//   args 5..11 -> [RSP+0x28..] (stack), SSN -> EAX.
// ABI0: ret at 0(SP), args at 8(SP).., result at 104(SP).
TEXT ·invokeSyscall(SB), NOSPLIT, $0-104
	MOVQ ssn+0(FP), AX
	MOVQ a1+8(FP), R10
	MOVQ a2+16(FP), DX
	MOVQ a3+24(FP), R8
	MOVQ a4+32(FP), R9
	MOVQ a5+40(FP), R11
	MOVQ R11, a4+32(FP)
	MOVQ a6+48(FP), R11
	MOVQ R11, a5+40(FP)
	MOVQ a7+56(FP), R11
	MOVQ R11, a6+48(FP)
	MOVQ a8+64(FP), R11
	MOVQ R11, a7+56(FP)
	MOVQ a9+72(FP), R11
	MOVQ R11, a8+64(FP)
	MOVQ a10+80(FP), R11
	MOVQ R11, a9+72(FP)
	MOVQ a11+88(FP), R11
	MOVQ R11, a10+80(FP)
	SYSCALL
	MOVQ AX, ret+96(FP)
	RET
