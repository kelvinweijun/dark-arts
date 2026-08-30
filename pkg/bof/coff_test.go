//go:build windows && amd64

package bof

import (
	"testing"
)

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
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x60,

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
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
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