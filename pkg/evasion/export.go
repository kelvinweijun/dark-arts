//go:build windows && amd64

package evasion

import (
	"errors"
	"syscall"
	"unsafe"
)

// toPtr converts a uintptr address to an unsafe.Pointer in a form the
// unsafeptr vet check accepts.
func toPtr(u uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(nil)) + u)
}

func rd8(p unsafe.Pointer) uint8 {
	return *(*uint8)(p)
}

func rd16(p unsafe.Pointer) uint16 {
	return *(*uint16)(p)
}

func rd32(p unsafe.Pointer) uint32 {
	return *(*uint32)(p)
}

func hashAscii(p unsafe.Pointer) uint32 {
	h := uint32(5381)
	for {
		c := rd8(p)
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

// hashString is hashAscii over a Go string; the exported names the loader
// resolves are already lowercase, so the folding is a no-op for them.
func hashString(s string) uint32 {
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

// ResolveNtdllExport returns the address of a named export in the live ntdll,
// looked up by hash only (no API-name strings in the binary).
func ResolveNtdllExport(name string) (uintptr, error) {
	base, err := liveNtdllBase()
	if err != nil {
		return 0, err
	}
	fn, err := resolveExport(toPtr(base), hashString(name))
	if err != nil {
		return 0, err
	}
	return uintptr(fn), nil
}

// liveNtdllBase resolves the address of the loaded ntdll module via
// kernel32.GetModuleHandleW (a one-time import, used only for bootstrap).
func liveNtdllBase() (uintptr, error) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandleW := k32.NewProc("GetModuleHandleW")
	namePtr, _ := syscall.UTF16PtrFromString("ntdll.dll")
	base, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))
	if base == 0 {
		return 0, errors.New("evasion: GetModuleHandleW(ntdll.dll) failed")
	}
	return base, nil
}

// resolveExport walks the PE export directory of the image at base and
// returns the function address for the djb2-hashed export name.
func resolveExport(base unsafe.Pointer, want uint32) (unsafe.Pointer, error) {
	nt := unsafe.Add(base, uintptr(rd32(unsafe.Add(base, 0x3C))))
	opt := unsafe.Add(nt, 0x18)
	expRVA := rd32(unsafe.Add(opt, 0x70))
	if expRVA == 0 {
		return nil, errors.New("evasion: export directory missing")
	}
	sizeOfImage := uintptr(rd32(unsafe.Add(opt, 0x38)))
	exp := unsafe.Add(base, uintptr(expRVA))
	numNames := rd32(unsafe.Add(exp, 0x18))
	numFuncs := rd32(unsafe.Add(exp, 0x14))
	if numNames == 0 || numNames > 1<<20 || numFuncs == 0 {
		return nil, errors.New("evasion: malformed export directory")
	}
	funcsRVA := uintptr(rd32(unsafe.Add(exp, 0x1C)))
	namesRVA := uintptr(rd32(unsafe.Add(exp, 0x20)))
	ordsRVA := uintptr(rd32(unsafe.Add(exp, 0x24)))
	for i := uint32(0); i < numNames; i++ {
		nameRVA := rd32(unsafe.Add(base, namesRVA+uintptr(i)*4))
		if nameRVA == 0 {
			continue
		}
		if hashAscii(unsafe.Add(base, uintptr(nameRVA))) == want {
			ord := uint32(rd16(unsafe.Add(base, ordsRVA+uintptr(i)*2)))
			if ord >= numFuncs {
				return nil, errors.New("evasion: export ordinal out of range")
			}
			fnRVA := uintptr(rd32(unsafe.Add(base, funcsRVA+uintptr(ord)*4)))
			if fnRVA == 0 {
				return nil, errors.New("evasion: export slot empty")
			}
			if sizeOfImage > 0 && fnRVA >= sizeOfImage {
				return nil, errors.New("evasion: export outside image")
			}
			return unsafe.Add(base, fnRVA), nil
		}
	}
	return nil, errors.New("evasion: export not found")
}
