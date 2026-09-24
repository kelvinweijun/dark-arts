package bof

import (
	"os"
	"testing"
	"unsafe"
)

func TestRelocationAddendPreservation(t *testing.T) {
	// This test verifies that IMAGE_REL_AMD64_REL32 relocations preserve
	// the existing displacement/addend from the original COFF bytes.
	//
	// MSVC encodes array element offsets as REL32 addends:
	//   g_beacon_extract_result[0] -> addend 0
	//   g_beacon_extract_result[1] -> addend 1
	//   g_beacon_extract_result[2] -> addend 2
	//   g_beacon_extract_result[3] -> addend 3
	//
	// If addends are dropped, all four writes target offset 0,
	// and only the last write (0x44='D') survives -> [D 0 0 0].

	coffPath := "../../bof_test/bof_test.obj"
	coffBytes, err := os.ReadFile(coffPath)
	if err != nil {
		t.Skipf("BOF not found: %v", err)
	}

	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF: %v", err)
	}

	SetBeaconCallbacks(
		func(format string, args ...interface{}) {},
		func(data []byte) {},
	)

	if err := coff.ResolveBeaconAPIs(); err != nil {
		t.Fatalf("ResolveBeaconAPIs: %v", err)
	}

	_, err = coff.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Find the go() function
	goAddr, ok := coff.GetSymbol("go")
	if !ok {
		t.Fatal("go symbol not found")
	}

	// Dump the go() function bytes to inspect relocated instructions.
	// The g_beacon_extract_result[0..3] writes are at offsets 0x90-0xB3
	// in the .text$mn section, at VA = goAddr + (offset_in_section - section_VA).
	// We read the actual bytes after relocation to verify addend preservation.
	goBytes := make([]byte, 320)
	for i := range goBytes {
		goBytes[i] = *(*byte)(unsafe.Pointer(goAddr + uintptr(i)))
	}

	// The four MOV byte ptr [g_beacon_extract_result+N], reg instructions
	// are at offsets 0x90, 0x9A, 0xA4, 0xAE in the go() function's section.
	// Each instruction is: 88 0D/05 XX XX XX XX (mov byte ptr [rip+disp32], reg)
	// The displacement field is at instruction offset +3, occupying 4 bytes.
	//
	// After relocation, the displacement should satisfy:
	//   disp = symAddr - (instruction_addr + 4) + addend
	// where instruction_addr is the address of the displacement field (offset+4 from instruction start).
	//
	// For element [0]: addend=0
	// For element [1]: addend=1
	// For element [2]: addend=2
	// For element [3]: addend=3

	extractAddr, _ := coff.GetSymbol("g_beacon_extract_result")

	type instrCheck struct {
		offset     int    // offset within go() function bytes
		addend     int32  // expected addend
		regByte    byte   // opcode byte after disp32 (0x0D for CL, 0x05 for AL)
		elementNum int    // for error messages
	}

	checks := []instrCheck{
		{0x90, 0, 0x0D, 0}, // mov byte ptr [g_beacon_extract_result+0], cl
		{0x9A, 1, 0x0D, 1}, // mov byte ptr [g_beacon_extract_result+1], cl
		{0xA4, 2, 0x0D, 2}, // mov byte ptr [g_beacon_extract_result+2], cl
		{0xAE, 3, 0x05, 3}, // mov byte ptr [g_beacon_extract_result+3], al
	}

	for _, chk := range checks {
		// Verify instruction opcode
		if goBytes[chk.offset] != 0x88 {
			t.Errorf("element[%d]: expected MOV r/m8,r8 opcode 0x88 at offset 0x%x, got 0x%02x",
				chk.elementNum, chk.offset, goBytes[chk.offset])
			continue
		}

		// MOV r/m8, r8 with RIP-relative addressing: 88 0D disp32
		// Displacement field is at offset+2 (after opcode 0x88 and ModR/M 0x0D/0x05)
		dispOffset := chk.offset + 2
		disp := int32(goBytes[dispOffset]) | int32(goBytes[dispOffset+1])<<8 |
			int32(goBytes[dispOffset+2])<<16 | int32(goBytes[dispOffset+3])<<24

		// RIP at execution = dispFieldAddr + 4 (displacement is 4 bytes, RIP advances past it)
		dispFieldAddr := goAddr + uintptr(dispOffset)
		target := uint64(dispFieldAddr) + 4 + uint64(int64(disp))
		expectedTarget := uint64(extractAddr) + uint64(chk.addend)

		if target != expectedTarget {
			t.Errorf("element[%d]: displacement points to wrong target: "+
				"got 0x%x, want 0x%x (extract_result + %d). "+
				"displacement=0x%x, instr_addr=0x%x",
				chk.elementNum, target, expectedTarget, chk.addend,
				uint32(disp), goAddr+uintptr(chk.offset))
		} else {
			t.Logf("element[%d]: PASS - target=0x%x, addend=%d preserved correctly",
				chk.elementNum, target, chk.addend)
		}
	}
}

func TestRelocationZeroAddend(t *testing.T) {
	// Verify that relocations with addend=0 still work correctly.
	// This covers all the Beacon API call relocations (CALL rel32)
	// which always have addend 0.
	coffPath := "../../bof_test/bof_test.obj"
	coffBytes, err := os.ReadFile(coffPath)
	if err != nil {
		t.Skipf("BOF not found: %v", err)
	}

	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF: %v", err)
	}

	SetBeaconCallbacks(
		func(format string, args ...interface{}) {},
		func(data []byte) {},
	)

	if err := coff.ResolveBeaconAPIs(); err != nil {
		t.Fatalf("ResolveBeaconAPIs: %v", err)
	}

	_, err = coff.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify all Beacon API CALL relocations resolved correctly
	apiSymbols := []string{
		"BeaconDataParse", "BeaconDataInt", "BeaconDataShort",
		"BeaconDataLength", "BeaconDataExtract",
		"BeaconOutput", "BeaconPrintf",
	}

	addrs := trampolineAddrs()
	goAddr, _ := coff.GetSymbol("go")
	goBytes := make([]byte, 320)
	for i := range goBytes {
		goBytes[i] = *(*byte)(unsafe.Pointer(goAddr + uintptr(i)))
	}

	for _, api := range apiSymbols {
		trampolineAddr := addrs[api]
		if trampolineAddr == 0 {
			t.Errorf("no trampoline for %s", api)
			continue
		}

		// Find the CALL instruction for this API in the go() function bytes.
		// CALL rel32 is opcode E8 followed by 4-byte displacement.
		// After relocation, the target should be the trampoline address.
		found := false
		for i := 0; i < len(goBytes)-4; i++ {
			if goBytes[i] != 0xE8 {
				continue
			}
			disp := int32(goBytes[i+1]) | int32(goBytes[i+2])<<8 |
				int32(goBytes[i+3])<<16 | int32(goBytes[i+4])<<24
			callTarget := uint64(goAddr+uintptr(i)) + 5 + uint64(int64(disp))
			if callTarget == uint64(trampolineAddr) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no CALL instruction found targeting %s trampoline at 0x%x", api, trampolineAddr)
		}
	}
}
