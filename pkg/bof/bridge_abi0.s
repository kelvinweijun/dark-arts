//go:build windows && amd64

#include "textflag.h"

// Microsoft x64 -> Go ABI0 trampolines for Beacon APIs
//
// These are defined as global symbols (no · prefix) so they can be
// resolved by go:linkname and used as COFF relocation targets.
//
// Microsoft x64 calling convention:
//   RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
//   Caller allocates 32-byte shadow space before CALL
//   Stack must be 16-byte aligned before CALL
//   Nonvolatile (callee-saved): RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15
//
// Go ABI0 calling convention:
//   After CALL pushes return address, callee reads args from
//   [callee_SP+8]=arg1, [callee_SP+16]=arg2, ...
//   Relative to our SP before CALL: arg1 at 0(SP), arg2 at 8(SP), ...
//
// Every trampoline saves/restores all MSVC nonvolatile GPRs and XMM6-XMM15
// around the Go call so BOFs observe full Microsoft x64 ABI preservation.
//
// Stack layout (args at bottom for ABI0, save area above):
//   0x00 .. args region (arg slots)
//   SAVE_BASE .. GPR save (8*8) then XMM save (10*16)
//   Frame size chosen so SUB ≡ 8 (mod 16) → SP ≡ 0 before CALL.
//   Entry SP ≡ 8 (mod 16).

#define SAVE_BASE 0x40

#define SAVE_NONVOLATILE \
	MOVQ	BX, SAVE_BASE+0x00(SP); \
	MOVQ	BP, SAVE_BASE+0x08(SP); \
	MOVQ	DI, SAVE_BASE+0x10(SP); \
	MOVQ	SI, SAVE_BASE+0x18(SP); \
	MOVQ	R12, SAVE_BASE+0x20(SP); \
	MOVQ	R13, SAVE_BASE+0x28(SP); \
	MOVQ	R14, SAVE_BASE+0x30(SP); \
	MOVQ	R15, SAVE_BASE+0x38(SP); \
	MOVUPS	X6,  SAVE_BASE+0x40(SP); \
	MOVUPS	X7,  SAVE_BASE+0x50(SP); \
	MOVUPS	X8,  SAVE_BASE+0x60(SP); \
	MOVUPS	X9,  SAVE_BASE+0x70(SP); \
	MOVUPS	X10, SAVE_BASE+0x80(SP); \
	MOVUPS	X11, SAVE_BASE+0x90(SP); \
	MOVUPS	X12, SAVE_BASE+0xA0(SP); \
	MOVUPS	X13, SAVE_BASE+0xB0(SP); \
	MOVUPS	X14, SAVE_BASE+0xC0(SP); \
	MOVUPS	X15, SAVE_BASE+0xD0(SP)

#define RESTORE_NONVOLATILE \
	MOVQ	SAVE_BASE+0x00(SP), BX; \
	MOVQ	SAVE_BASE+0x08(SP), BP; \
	MOVQ	SAVE_BASE+0x10(SP), DI; \
	MOVQ	SAVE_BASE+0x18(SP), SI; \
	MOVQ	SAVE_BASE+0x20(SP), R12; \
	MOVQ	SAVE_BASE+0x28(SP), R13; \
	MOVQ	SAVE_BASE+0x30(SP), R14; \
	MOVQ	SAVE_BASE+0x38(SP), R15; \
	MOVUPS	SAVE_BASE+0x40(SP), X6; \
	MOVUPS	SAVE_BASE+0x50(SP), X7; \
	MOVUPS	SAVE_BASE+0x60(SP), X8; \
	MOVUPS	SAVE_BASE+0x70(SP), X9; \
	MOVUPS	SAVE_BASE+0x80(SP), X10; \
	MOVUPS	SAVE_BASE+0x90(SP), X11; \
	MOVUPS	SAVE_BASE+0xA0(SP), X12; \
	MOVUPS	SAVE_BASE+0xB0(SP), X13; \
	MOVUPS	SAVE_BASE+0xC0(SP), X14; \
	MOVUPS	SAVE_BASE+0xD0(SP), X15

// SAVE_BASE 0x40 + GPR 0x40 + XMM 0xE0 = 0x160 save region end.
// 3-arg trampolines: need args 0x00-0x1F + save to 0x160 → use 0x168
//   (0x168 ≡ 8 mod 16). Covers up to 8 arg slots below SAVE_BASE.
// Printf: 10 args = 0x50 > 0x40, so SAVE_BASE must be higher OR use larger frame.
// For printf use SAVE_BASE effectively at 0x60 with frame 0x188.

// ============================================================
// BeaconDataInt(*DataParser) int32
// MSVC: RCX=parser
// Args at 0x00. Frame 0x168 (≡8 mod 16).
// ============================================================
TEXT BeaconDataInt_abi0(SB), NOSPLIT|NOFRAME, $0-16
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	CALL	·BeaconDataInt(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// BeaconDataShort(*DataParser) int16
// MSVC: RCX=parser
// ============================================================
TEXT BeaconDataShort_abi0(SB), NOSPLIT|NOFRAME, $0-16
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	CALL	·BeaconDataShort(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// BeaconDataLength(*DataParser) int32
// MSVC: RCX=parser
// ============================================================
TEXT BeaconDataLength_abi0(SB), NOSPLIT|NOFRAME, $0-16
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	CALL	·BeaconDataLength(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// BeaconDataParse(**DataParser, uintptr, int32) void
// MSVC: RCX=parser, RDX=buffer, R8=size
// Args at 0x00/0x08/0x10. Frame 0x168.
// ============================================================
TEXT BeaconDataParse_abi0(SB), NOSPLIT|NOFRAME, $0-24
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	MOVQ	DX, 0x08(SP)
	MOVQ	R8, 0x10(SP)
	CALL	·BeaconDataParse(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// beaconDataExtractNative(*DataParser, int32) uintptr
// Returns data pointer in RAX. RESTORE does not touch AX.
// MSVC: RCX=parser, RDX=size
// ============================================================
TEXT BeaconDataExtract_abi0(SB), NOSPLIT|NOFRAME, $0-16
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	MOVQ	DX, 0x08(SP)
	CALL	·beaconDataExtractNative(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// beaconOutputNative(int, *byte, int32) void
// MSVC: RCX=type, RDX=data, R8=length
// ============================================================
TEXT BeaconOutput_abi0(SB), NOSPLIT|NOFRAME, $0-24
	SUBQ	$0x168, SP
	SAVE_NONVOLATILE
	MOVQ	CX, 0x00(SP)
	MOVQ	DX, 0x08(SP)
	MOVQ	R8, 0x10(SP)
	CALL	·beaconOutputNative(SB)
	RESTORE_NONVOLATILE
	ADDQ	$0x168, SP
	RET

// ============================================================
// beaconPrintfNative(int, *byte, v0..v7) void
// MSVC: RCX=type, RDX=format, R8=first vararg, R9=second vararg
// Go: outputType, format, v0..v7 (10 slots = 0x50 bytes)
// Args need 0x50, so SAVE_BASE 0x40 overlaps — use dedicated layout:
//   args 0x00-0x4F, save at 0x50, frame 0x178 (0x50+0x110=0x160, +0x18 pad ≡8)
// Simpler: frame 0x188 with save at 0x60.
// ============================================================
TEXT BeaconPrintfNative_abi0(SB), NOSPLIT|NOFRAME, $0-24
	SUBQ	$0x188, SP
	// Inline save at 0x60 (args occupy 0x00-0x4F)
	MOVQ	BX, 0x60(SP)
	MOVQ	BP, 0x68(SP)
	MOVQ	DI, 0x70(SP)
	MOVQ	SI, 0x78(SP)
	MOVQ	R12, 0x80(SP)
	MOVQ	R13, 0x88(SP)
	MOVQ	R14, 0x90(SP)
	MOVQ	R15, 0x98(SP)
	MOVUPS	X6,  0xA0(SP)
	MOVUPS	X7,  0xB0(SP)
	MOVUPS	X8,  0xC0(SP)
	MOVUPS	X9,  0xD0(SP)
	MOVUPS	X10, 0xE0(SP)
	MOVUPS	X11, 0xF0(SP)
	MOVUPS	X12, 0x100(SP)
	MOVUPS	X13, 0x110(SP)
	MOVUPS	X14, 0x120(SP)
	MOVUPS	X15, 0x130(SP)

	MOVQ	CX, 0x00(SP)
	MOVQ	DX, 0x08(SP)
	MOVQ	R8, 0x10(SP)
	MOVQ	R9, 0x18(SP)
	MOVQ	$0, 0x20(SP)
	MOVQ	$0, 0x28(SP)
	MOVQ	$0, 0x30(SP)
	MOVQ	$0, 0x38(SP)
	MOVQ	$0, 0x40(SP)
	MOVQ	$0, 0x48(SP)
	CALL	·BeaconPrintfNative(SB)

	MOVQ	0x60(SP), BX
	MOVQ	0x68(SP), BP
	MOVQ	0x70(SP), DI
	MOVQ	0x78(SP), SI
	MOVQ	0x80(SP), R12
	MOVQ	0x88(SP), R13
	MOVQ	0x90(SP), R14
	MOVQ	0x98(SP), R15
	MOVUPS	0xA0(SP), X6
	MOVUPS	0xB0(SP), X7
	MOVUPS	0xC0(SP), X8
	MOVUPS	0xD0(SP), X9
	MOVUPS	0xE0(SP), X10
	MOVUPS	0xF0(SP), X11
	MOVUPS	0x100(SP), X12
	MOVUPS	0x110(SP), X13
	MOVUPS	0x120(SP), X14
	MOVUPS	0x130(SP), X15
	ADDQ	$0x188, SP
	RET

// ============================================================
// Test trampolines (for internal testing, package-private)
// ============================================================

TEXT ·TestNativeBridge_abi0(SB), NOSPLIT|NOFRAME, $0-16
	SUBQ	$0x28, SP
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	CALL	·TestNativeBridge(SB)
	ADDQ	$0x28, SP
	RET

TEXT ·TestCallTrampoline(SB), NOSPLIT, $0-32
	SUBQ	$0x20, SP
	MOVQ	AX, 0x0(SP)
	MOVQ	CX, 0x8(SP)
	MOVQ	DX, 0x10(SP)
	MOVQ	0x0(SP), CX
	MOVQ	0x8(SP), DX
	MOVQ	0x10(SP), R8
	CALL	·TestNativeBridge_abi0(SB)
	ADDQ	$0x20, SP
	MOVQ	AX, ret+24(FP)
	RET
