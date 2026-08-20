//go:build windows && amd64

#include "textflag.h"

// currentTeb returns the current thread's TEB (GS:[0x30] on x64).
TEXT ·currentTeb(SB),NOSPLIT,$0-8
	MOVQ 0x30(GS), AX
	MOVQ AX, ret+0(FP)
	RET
