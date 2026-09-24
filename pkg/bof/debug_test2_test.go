package bof

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestDumpCOFF2(t *testing.T) {
	coff := buildTestCOFF(5, 4096)
	fmt.Printf("COFF length: %d\n", len(coff))
	
	// Check section header PointerToRelocations
	ptrToReloc := binary.LittleEndian.Uint32(coff[44:48])
	fmt.Printf("PointerToRelocations: 0x%x (%d)\n", coff[44:48], coff[44:48])
	fmt.Printf("  As uint32: %d\n", ptrToReloc)
	
	// Check relocation data
	if len(coff) > 4226+10 {
		fmt.Printf("\nRelocation data at 4226:\n")
		for i := 0; i < 10; i++ {
			fmt.Printf("  %02d: 0x%02x\n", i, coff[4226+i])
		}
		offset := binary.LittleEndian.Uint32(coff[4226:4230])
		symIdx := binary.LittleEndian.Uint32(coff[4230:4234])
		relType := binary.LittleEndian.Uint16(coff[4234:4236])
		fmt.Printf("  Parsed: offset=%d, symIdx=%d, type=%d\n", offset, symIdx, relType)
	}
}