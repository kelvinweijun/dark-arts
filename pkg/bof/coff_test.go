//go:build windows && amd64

package bof

import (
	"encoding/binary"
	"testing"
)

func buildTestCOFF(relocType uint16, relocOffset uint32) []byte {
	// Symbol table
	var symTable []byte

	// Symbol 0: .text (section definition)
	sym0 := make([]byte, 18)
	copy(sym0[0:8], []byte{'.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00}) // Name (inline)
	binary.LittleEndian.PutUint32(sym0[4:8], 0)   // Value
	binary.LittleEndian.PutUint16(sym0[8:10], 1)  // SectionNumber = 1
	binary.LittleEndian.PutUint16(sym0[10:12], 0) // Type
	sym0[12] = 3  // StorageClass: IMAGE_SYM_CLASS_STATIC
	sym0[13] = 1  // NumberOfAuxSymbols = 1
	symTable = append(symTable, sym0...)

	// Aux record for .text
	aux0 := make([]byte, 18)
	binary.LittleEndian.PutUint32(aux0[0:4], 4096) // Length
	binary.LittleEndian.PutUint16(aux0[4:6], 0)    // Number of relocations
	binary.LittleEndian.PutUint16(aux0[6:8], 0)    // Number of line numbers
	binary.LittleEndian.PutUint32(aux0[8:12], 0x60000020) // Characteristics
	symTable = append(symTable, aux0...)

	// Symbol 1: external symbol (e.g., "test")
	sym1 := make([]byte, 18)
	binary.LittleEndian.PutUint32(sym1[0:4], 0)          // Short name = 0 (use string table)
	binary.LittleEndian.PutUint32(sym1[4:8], 4)          // String table offset = 4 (after length prefix)
	binary.LittleEndian.PutUint32(sym1[8:12], 0)         // Value = 0
	binary.LittleEndian.PutUint16(sym1[12:14], 0)        // SectionNumber = 0 (undefined)
	binary.LittleEndian.PutUint16(sym1[14:16], 0)        // Type = 0
	sym1[16] = 2  // StorageClass = IMAGE_SYM_CLASS_EXTERNAL
	sym1[17] = 0  // NumberOfAuxSymbols = 0
	symTable = append(symTable, sym1...)

	// String table: length (4 bytes) + "test\0" (5 bytes) = 9 bytes, padded to 16 (4-byte alignment)
	strTable := make([]byte, 4+5) // 4 bytes length + "test\0" (5 bytes) = 9 bytes
	binary.LittleEndian.PutUint32(strTable[0:4], 9) // string table length = 9 bytes
	copy(strTable[4:], "test\x00")
	// Pad to 16 bytes (already 13 bytes, need 16)
	strTable = append(strTable, 0x00, 0x00, 0x00) // pad to 16 bytes

	// Relocation entry
	reloc := make([]byte, 10)
	binary.LittleEndian.PutUint32(reloc[0:4], relocOffset)
	binary.LittleEndian.PutUint32(reloc[4:8], 2)    // SymbolTableIndex: 2 (external symbol)
	binary.LittleEndian.PutUint16(reloc[8:10], uint16(relocType))

	// Build COFF manually
	coff := make([]byte, 0)

	// COFF Header (20 bytes)
	coff = append([]byte{}, 0x64, 0x86) // Machine: AMD64
	coff = append(coff, 0x01, 0x00) // Number of sections: 1
	coff = append(coff, 0x00, 0x00, 0x00, 0x00) // TimeDateStamp
	coff = append(coff, 0x34, 0x10, 0x00, 0x00) // SymbolTableOffset: 4156
	coff = append(coff, 0x03, 0x00, 0x00, 0x00) // NumberOfSymbols: 3
	coff = append(coff, 0x00, 0x00) // SizeOfOptionalHeader
	coff = append(coff, 0x00, 0x00) // Characteristics

	// Section Header (.text)
	coff = append(coff, '.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00)
	coff = append(coff, 0x00, 0x10, 0x00, 0x00) // VirtualSize: 4096
	coff = append(coff, 0x00, 0x00, 0x00, 0x00) // VirtualAddress: 0
	coff = append(coff, 0x00, 0x10, 0x00, 0x00) // SizeOfRawData: 4096
	coff = append(coff, 0x3C, 0x00, 0x00, 0x00) // Offset: 60
	coff = append(coff, 0x7E, 0x10, 0x00, 0x00) // PointerToRelocations: 4226
	coff = append(coff, 0x00, 0x00, 0x00, 0x00) // PointerToLineNumbers
	coff = append(coff, 0x01, 0x00) // NumberOfRelocations: 1
	coff = append(coff, 0x00, 0x00) // NumberOfLineNumbers
	coff = append(coff, 0x20, 0x00, 0x00, 0x60) // Characteristics

	// .text section data (RET + padding)
	textData := make([]byte, 4096)
	textData[0] = 0xC3 // RET
	for i := 1; i < 4096; i++ {
		textData[i] = 0x90 // NOP
	}
	coff = append(coff, textData...)

	// Symbol table
	coff = append(coff, symTable...)

	// String table
	coff = append(coff, strTable...)

	// Relocation entry
	reloc = make([]byte, 10)
	binary.LittleEndian.PutUint32(reloc[0:4], 4096) // Offset: 4096
	binary.LittleEndian.PutUint32(reloc[4:8], 2)    // SymbolTableIndex: 2 (external symbol)
	binary.LittleEndian.PutUint16(reloc[8:10], uint16(5)) // Type: REL32 (0x0004)

	coff = append(coff, reloc...)

	return coff
}

func TestExecuteCOFF(t *testing.T) {
	// BOF with a full-page section to ensure proper memory protection
	coff := []byte{
		// COFF Header (20 bytes)
		0x64, 0x86, // Machine: AMD64
		0x01, 0x00, // Number of sections: 1
		0x00, 0x00, 0x00, 0x00, // TimeDateStamp
		0x00, 0x00, 0x00, 0x00, // SymbolTableOffset
		0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
		0x00, 0x00, // SizeOfOptionalHeader
		0x00, 0x00, // Characteristics

		// Section Header (40 bytes)
		'.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x00, // VirtualSize: 4096 (one page)
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0
		0x00, 0x10, 0x00, 0x00, // SizeOfRawData: 4096
		0x3C, 0x00, 0x00, 0x00, // Offset: 60 (after headers)
		0x00, 0x10, 0x00, 0x00, // PointerToRelocations: 4156 (symbol table offset)
		0x00, 0x00, 0x00, 0x00, // PointerToLineNumbers
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLineNumbers
		0x20, 0x00, 0x00, 0x60, // Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ

		// Section data (4096 bytes) at offset 60 - RET + padding
		0xC3, // RET
	}
	// Pad section data to 4096 bytes
	padding := make([]byte, 4096-1)
	for i := range padding {
		padding[i] = 0x90 // NOP
	}
	coff = append(coff, padding...)

	result, err := ExecuteCOFF(coff, "go", nil)
	if err != nil {
		t.Fatalf("ExecuteCOFF failed: %v", err)
	}
	t.Logf("ExecuteCOFF result: %s", result)
}

func TestParseCOFFValid(t *testing.T) {
	// Minimal valid COFF with one section at VirtualAddress 0
	coff := []byte{
		// COFF Header (20 bytes)
		0x64, 0x86, // Machine: AMD64
		0x01, 0x00, // Number of sections: 1
		0x00, 0x00, 0x00, 0x00, // TimeDateStamp
		0x00, 0x00, 0x00, 0x00, // SymbolTableOffset
		0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
		0x00, 0x00, // SizeOfOptionalHeader
		0x00, 0x00, // Characteristics

		// Section Header (40 bytes)
		'.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00,
		0x0C, 0x00, 0x00, 0x00, // VirtualSize: 12
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0
		0x0C, 0x00, 0x00, 0x00, // SizeOfRawData
		0x3C, 0x00, 0x00, 0x00, // Offset: 60 (after headers)
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLineNumbers
		0x20, 0x00, 0x00, 0x60, // Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ

		// Section data (12 bytes) at offset 60
		0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	}

	coffParsed, err := ParseCOFF(coff)
	if err != nil {
		t.Fatalf("ParseCOFF failed: %v", err)
	}

	if coffParsed.Machine != 0x8664 {
		t.Errorf("expected machine 0x8664, got 0x%X", coffParsed.Machine)
	}

	if len(coffParsed.Sections) != 1 {
		t.Errorf("expected 1 section, got %d", len(coffParsed.Sections))
	}

	sec := coffParsed.Sections[0]
	if sec.Name != ".text" {
		t.Errorf("expected section name .text, got %s", sec.Name)
	}

	if sec.Virtual != 0 {
		t.Errorf("expected virtual address 0, got 0x%X", sec.Virtual)
	}

	if len(sec.Physical) != 12 {
		t.Errorf("expected 12 bytes physical, got %d", len(sec.Physical))
	}
}

// TestCOFFAdversarialMalformed tests that ParseCOFF handles malformed inputs
// without crashing.
func TestCOFFAdversarialMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"truncated_header", []byte{0x64, 0x86}},
		{"zero_sections", func() []byte {
			coff := make([]byte, 60)
			coff[0] = 0x64
			coff[1] = 0x86
			return coff
		}()},
		{"huge_section_count", func() []byte {
			coff := make([]byte, 60)
			coff[0] = 0x64
			coff[1] = 0x86
			coff[2] = 0xFF // 65535 sections
			coff[3] = 0xFF
			return coff
		}()},
		{"section_name_overflow", func() []byte {
			coff := make([]byte, 100)
			coff[0] = 0x64
			coff[1] = 0x86
			coff[2] = 0x01
			// Section name starts at offset 20, fills with non-null bytes
			for i := 20; i < 28; i++ {
				coff[i] = 'A'
			}
			return coff
		}()},
		{"bss_zero_size", func() []byte {
			// Section with MEM_BSS flag but zero VirtualSize
			coff := make([]byte, 60)
			coff[0] = 0x64
			coff[1] = 0x86
			coff[2] = 0x01
			copy(coff[20:28], ".bss\x00\x00\x00\x00")
			// Characteristics at offset 56: MEM_BSS = 0x80, MEM_READ = 0x40
			coff[56] = 0x80
			coff[57] = 0x00
			coff[58] = 0x00
			coff[59] = 0x40
			return coff
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseCOFF panicked on %s: %v", tt.name, r)
				}
			}()
			_, err := ParseCOFF(tt.data)
			if err == nil && len(tt.data) < 60 {
				t.Errorf("ParseCOFF should return error for %s", tt.name)
			}
		})
	}
}

// TestCOFFAdversarialOverlappingSections tests that the loader handles
// overlapping sections without crashing.
func TestCOFFAdversarialOverlappingSections(t *testing.T) {
	// Two sections with the same VirtualAddress — overlap
	// Loader should still allocate them (Go maps handle collisions gracefully)
	coff := []byte{
		0x64, 0x86, // Machine: AMD64
		0x02, 0x00, // Number of sections: 2
		0x00, 0x00, 0x00, 0x00, // TimeDateStamp
		0x00, 0x00, 0x00, 0x00, // SymbolTableOffset
		0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
		0x00, 0x00, // SizeOfOptionalHeader
		0x00, 0x00, // Characteristics

		// Section 1: .text
		'.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, // VirtualSize: 16
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0
		0x10, 0x00, 0x00, 0x00, // SizeOfRawData: 16
		0x3C, 0x00, 0x00, 0x00, // Offset: 60+40 = 100
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLineNumbers
		0x20, 0x00, 0x00, 0x60, // Characteristics

		// Section 2: .data (same VirtualAddress = overlap)
		'.', 'd', 'a', 't', 'a', 0x00, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, // VirtualSize: 16
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0 (overlaps!)
		0x10, 0x00, 0x00, 0x00, // SizeOfRawData: 16
		0x4C, 0x00, 0x00, 0x00, // Offset: 60+40+16 = 116
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLineNumbers
		0x40, 0x00, 0x00, 0xC0, // Characteristics: MEM_READ | MEM_WRITE
	}

	// Pad section data
	textData := make([]byte, 32)
	textData[0] = 0xC3
	coff = append(coff, textData...)

	parsed, err := ParseCOFF(coff)
	if err != nil {
		t.Fatalf("ParseCOFF failed on overlapping sections: %v", err)
	}
	t.Logf("parsed %d sections with overlapping virtual addresses", len(parsed.Sections))
}

// TestCOFFAdversarialHugeBSS tests that a very large BSS section doesn't
// cause OOM.
func TestCOFFAdversarialHugeBSS(t *testing.T) {
	coff := []byte{
		0x64, 0x86, // Machine: AMD64
		0x01, 0x00, // Number of sections: 1
		0x00, 0x00, 0x00, 0x00, // TimeDateStamp
		0x00, 0x00, 0x00, 0x00, // SymbolTableOffset
		0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
		0x00, 0x00, // SizeOfOptionalHeader
		0x00, 0x00, // Characteristics

		// Section: .bss with huge VirtualSize
		'.', 'b', 's', 's', 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, // VirtualSize: 16MB (0x100000)
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0
		0x00, 0x00, 0x00, 0x00, // SizeOfRawData: 0 (BSS)
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLineNumbers
		0x80, 0x00, 0x00, 0xC0, // Characteristics: MEM_BSS | MEM_READ | MEM_WRITE
	}

	_, err := ParseCOFF(coff)
	// Should either succeed or fail with a clear error — no panic
	if err != nil {
		t.Logf("ParseCOFF rejected huge BSS: %v", err)
	} else {
		t.Log("ParseCOFF accepted huge BSS (loader handles allocation)")
	}
}