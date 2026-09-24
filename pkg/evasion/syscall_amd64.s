//go:build windows && amd64

#include "textflag.h"

// invokeSyscall issues an indirect syscall: it CALLs a `syscall; ret`
// gadget inside ntdll so RIP is inside ntdll when SYSCALL executes.
// CALL (not JMP) is required so the gadget's RET returns here and the
// NTSTATUS in AX can be written to ret(FP) — a JMP would RET straight
// to the Go caller and drop the result (the failure mode of the prior
// reverted attempt).
//
// NOFRAME: a PUSHQ BP prologue would shift SP by 8 and break the
// kernel's [RSP+0x28] arg5 offset (observed as NtProtectVirtualMemory
// STATUS_ACCESS_VIOLATION). Without BP, SP at CALL equals FP-8.
//
// Windows x64 kernel ABI at SYSCALL time:
//   SSN -> EAX, arg1 -> R10, arg2 -> RDX, arg3 -> R8, arg4 -> R9,
//   args 5..11 -> [RSP+0x28], [RSP+0x30], ... (RSP as seen inside
//   the gadget, i.e. after this function's CALL has pushed 8 bytes).
//
// ABI0 layout (FP = first arg, SP at entry = FP-8):
//   ssn+0, syscallAddr+8, a1+16 .. a11+96, ret+104; frame $0-112.
//
// Stack shuffle: kernel reads arg5 from [RSP_SYSCALL+0x28]. With CALL
// pushing 8 bytes, that slot is FP+24 (a2's slot) — so a5..a11 are
// shifted one slot earlier than the direct-SYSCALL layout. Register
// args are loaded before their slots are clobbered; syscallAddr is
// loaded into R11 after the shuffle (R11 is the shuffle temp).
TEXT ·invokeSyscall(SB), NOSPLIT|NOFRAME, $0-112
	MOVQ a1+16(FP), R10
	MOVQ a2+24(FP), DX
	MOVQ a3+32(FP), R8
	MOVQ a4+40(FP), R9
	MOVQ a5+48(FP), R11
	MOVQ R11, a2+24(FP)
	MOVQ a6+56(FP), R11
	MOVQ R11, a3+32(FP)
	MOVQ a7+64(FP), R11
	MOVQ R11, a4+40(FP)
	MOVQ a8+72(FP), R11
	MOVQ R11, a5+48(FP)
	MOVQ a9+80(FP), R11
	MOVQ R11, a6+56(FP)
	MOVQ a10+88(FP), R11
	MOVQ R11, a7+64(FP)
	MOVQ a11+96(FP), R11
	MOVQ R11, a8+72(FP)
	MOVQ ssn+0(FP), AX
	MOVQ syscallAddr+8(FP), R11
	CALL R11
	MOVQ AX, ret+104(FP)
	RET
