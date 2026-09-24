//go:build windows && amd64

package bof

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestDumpCOFF(t *testing.T) {
	coff := buildTestCOFF(5, 4096)
	fmt.Printf("COFF length: %d\n", len(coff))
	
	// Print first 100 bytes
	for i := 0; i < min(200, len(coff)); i += 16 {
		end := i + 16
		if end > len(coff) {
			end = len(coff)
		}
		fmt.Printf("%04x: ", i)
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", coff[j])
		}
		fmt.Println()
	}
	
	// Check section header
	fmt.Println("\nSection header (offset 20):")
	for i := 20; i < 60; i += 4 {
		val := binary.LittleEndian.Uint32(coff[i:i+4])
		fmt.Printf("  %02d: 0x%08x\n", i, val)
	}
	
	// Check relocation data
	fmt.Println("\nRelocation data (offset 4226):")
	relocOffset := 4226
	if len(coff) > relocOffset+10 {
		for i := 0; i < 10; i++ {
			fmt.Printf("  %02d: 0x%02x\n", i, coff[relocOffset+i])
		}
		// Parse manually
		offset := binary.LittleEndian.Uint32(coff[4226:4230])
		symIdx := binary.LittleEndian.Uint32(coff[4230:4234])
		relType := binary.LittleEndian.Uint16(coff[4234:4236])
		fmt.Printf("  Parsed: offset=%d, symIdx=%d, type=%d\n", offset, symIdx, relType)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}