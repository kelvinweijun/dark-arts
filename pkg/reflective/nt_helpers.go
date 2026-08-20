//go:build windows && amd64

package reflective

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

func rd8(p uintptr) uint8   { return *(*uint8)(toPtr(p)) }
func rd16(p uintptr) uint16 { return *(*uint16)(toPtr(p)) }
func rd32(p uintptr) uint32 { return *(*uint32)(toPtr(p)) }
func rd64(p uintptr) uint64 { return *(*uint64)(toPtr(p)) }

func toPtr(u uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(nil)) + u)
}

// applyRelocs processes the base relocation directory in the mapped image,
// adjusting all absolute addresses by delta.
func applyRelocs(base uintptr, relocDir uint32, delta uint64) error {
	reloc := base + uintptr(relocDir)
	for {
		pageRVA := rd32(reloc)
		blockSize := rd32(reloc + 4)
		if pageRVA == 0 && blockSize == 0 {
			return nil
		}
		if blockSize < 8 || blockSize > 0x100000 {
			return errors.New("reflective: malformed relocation block")
		}
		n := int(blockSize-8) / 2
		for i := 0; i < n; i++ {
			entry := rd16(reloc + 8 + uintptr(i)*2)
			typ := entry >> 12
			off := uintptr(entry & 0xFFF)
			switch typ {
			case 0: // ABSOLUTE
			case 10: // DIR64
				slot := base + uintptr(pageRVA) + off
				v := rd64(slot)
				wr64(slot, v+delta)
			case 3: // HIGHLOW (32-bit, tolerated on x64)
				slot := base + uintptr(pageRVA) + off
				v := rd32(slot)
				wr32(slot, v+uint32(delta))
			default:
				return fmt.Errorf("reflective: unsupported relocation type %d", typ)
			}
		}
		reloc += uintptr(blockSize)
	}
}

// resolveImports walks the import directory, resolving each module and
// patching the IAT. Module bases come from the standard loader bootstrap
// (LoadLibraryW on an already-loaded module returns its base without doing
// work); exports are resolved directly from the module's in-memory export
// directory.
func resolveImports(base uintptr, importDir uint32) error {
	imp := base + uintptr(importDir)
	for {
		oft := rd32(imp)
		nameRVA := rd32(imp + 0x0C)
		ft := rd32(imp + 0x10)
		if oft == 0 && nameRVA == 0 && ft == 0 {
			return nil
		}
		name := cstr(base + uintptr(nameRVA))
		if name == "" {
			return errors.New("reflective: import descriptor with empty name")
		}
		mod, err := getDllHandle(name)
		thunkSrc := oft
		if thunkSrc == 0 {
			thunkSrc = ft
		}
		for {
			raw := rd64(base + uintptr(thunkSrc))
			if raw == 0 {
				break
			}
			slot := base + uintptr(ft)
			var fnAddr uintptr
			if raw&0x8000000000000000 != 0 {
				fnAddr, err = getProcedureAddress(mod, "", uint16(raw&0xFFFF))
			} else {
				fnAddr, err = getProcedureAddress(mod, cstr(base+uintptr(raw)+2), 0)
			}
			if err != nil {
				return fmt.Errorf("reflective: resolve import thunk: %w", err)
			}
			wr64(slot, uint64(fnAddr))
			thunkSrc += 8
			ft += 8
		}
		imp += 20
	}
}

func wr8(p uintptr, v byte)    { *(*byte)(toPtr(p)) = v }
func wr16(p uintptr, v uint16) { *(*uint16)(toPtr(p)) = v }
func wr32(p uintptr, v uint32) { *(*uint32)(toPtr(p)) = v }
func wr64(p uintptr, v uint64) { *(*uint64)(toPtr(p)) = v }

func cstr(p uintptr) string {
	var b []byte
	for {
		c := rd8(p)
		if c == 0 {
			return string(b)
		}
		b = append(b, c)
		p++
	}
}

func nameEquals(base uintptr, nameRVA uintptr, want string) bool {
	p := base + nameRVA
	for i := 0; i < len(want); i++ {
		if rd8(p+uintptr(i)) != want[i] {
			return false
		}
	}
	return rd8(p+uintptr(len(want))) == 0
}

// protectionOf maps IMAGE_SCN_* characteristics to PAGE_* constants.
func protectionOf(chars uint32) uint32 {
	write := chars&0x80000000 != 0
	exec := chars&0x20000000 != 0
	read := chars&0x40000000 != 0
	switch {
	case exec && write:
		return pageRWX
	case exec:
		return pageRX
	case write:
		return pageRW
	case read:
		return pageR
	default:
		return pageNo
	}
}

// getDllHandle returns the base address of a loaded module. LoadLibraryW on
// an already-loaded module returns its existing base without loading a new
// copy.
func getDllHandle(name string) (uintptr, error) {
	dll, err := syscall.LoadDLL(name)
	if err != nil {
		return 0, fmt.Errorf("reflective: module %s: %w", name, err)
	}
	return uintptr(dll.Handle), nil
}

// getProcedureAddress resolves an export by name or ordinal directly from the
// module's in-memory export directory. No loader API calls are made.
func getProcedureAddress(mod uintptr, name string, ordinal uint16) (uintptr, error) {
	pe := mod + uintptr(rd32(mod+0x3C))
	opt := pe + 0x18
	expRVA := uintptr(rd32(opt + 0x70))
	if expRVA == 0 {
		return 0, fmt.Errorf("reflective: %s: no export directory", name)
	}
	exp := mod + expRVA
	numFuncs := rd32(exp + 0x14)
	numNames := rd32(exp + 0x18)
	funcsRVA := uintptr(rd32(exp + 0x1C))
	namesRVA := uintptr(rd32(exp + 0x20))
	ordsRVA := uintptr(rd32(exp + 0x24))
	if name != "" {
		if numNames == 0 || namesRVA == 0 || ordsRVA == 0 {
			return 0, fmt.Errorf("reflective: %s: empty export table", name)
		}
		for i := uint32(0); i < numNames; i++ {
			nr := uintptr(rd32(mod + namesRVA + uintptr(i)*4))
			if nameEquals(mod, nr, name) {
				ord := rd16(mod + ordsRVA + uintptr(i)*2)
				if uint32(ord) >= numFuncs {
					return 0, fmt.Errorf("reflective: %s: bad ordinal %d", name, ord)
				}
				return mod + uintptr(rd32(mod+funcsRVA+uintptr(ord)*4)), nil
			}
		}
		return 0, fmt.Errorf("reflective: export %s not found", name)
	}
	if uint32(ordinal) >= numFuncs {
		return 0, fmt.Errorf("reflective: ordinal %d out of range", ordinal)
	}
	return mod + uintptr(rd32(mod+funcsRVA+uintptr(ordinal)*4)), nil
}
