//go:build windows && amd64

package bof

import (
	"fmt"
	"os"
	"testing"
	"unsafe"
)

// TestTrampolineAddresses verifies that the trampoline addresses are real
// function entry points (not null or garbage).
func TestTrampolineAddresses(t *testing.T) {
	addrs := trampolineAddrs()

	requiredAPIs := []string{
		"BeaconDataInt",
		"BeaconDataShort",
		"BeaconDataLength",
		"BeaconDataParse",
		"BeaconDataExtract",
		"BeaconOutput",
		"BeaconPrintf",
		"BeaconPrintfNative",
	}

	for _, api := range requiredAPIs {
		addr, ok := addrs[api]
		if !ok {
			t.Errorf("missing trampoline for %s", api)
			continue
		}
		if addr == 0 {
			t.Errorf("trampoline %s has null address", api)
			continue
		}
		code := (*[16]byte)(unsafe.Pointer(addr))
		if code[0] == 0 && code[1] == 0 && code[2] == 0 && code[3] == 0 {
			t.Errorf("trampoline %s at 0x%x appears to be all zeros", api, addr)
		}
		fmt.Printf("  %s -> 0x%x (first bytes: %x)\n", api, addr, code[:4])
	}
}

// TestResolveBeaconAPIs verifies that ResolveBeaconAPIs correctly resolves
// Beacon API symbols to real trampoline addresses.
func TestResolveBeaconAPIs(t *testing.T) {
	// Minimal COFF: 1 section (.text with RET), 1 undefined external symbol (BeaconDataInt)
	// Symbol table starts at offset 0x40 (20-byte header + 40-byte section + 1-byte data + padding)
	coffBytes := []byte{
		// COFF header (20 bytes)
		0x64, 0x86, // Machine: AMD64
		0x01, 0x00, // NumberOfSections: 1
		0x00, 0x00, 0x00, 0x00, // TimeDateStamp
		0x40, 0x00, 0x00, 0x00, // PointerToSymbolTable: 0x40
		0x01, 0x00, 0x00, 0x00, // NumberOfSymbols: 1
		0x00, 0x00, // OptionalHeaderSize: 0
		0x00, 0x00, // Characteristics: 0
		// Section header (.text) (40 bytes)
		0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, // Name: .text
		0x04, 0x00, 0x00, 0x00, // VirtualSize: 4
		0x00, 0x00, 0x00, 0x00, // VirtualAddress: 0
		0x01, 0x00, 0x00, 0x00, // SizeOfRawData: 1
		0x3c, 0x00, 0x00, 0x00, // PointerToRawData: 0x3c (after headers)
		0x00, 0x00, 0x00, 0x00, // PointerToRelocations
		0x00, 0x00, 0x00, 0x00, // PointerToLinenumbers
		0x00, 0x00, // NumberOfRelocations
		0x00, 0x00, // NumberOfLinenumbers
		0x60, 0x00, 0x00, 0x20, // Characteristics: CODE|EXECUTE|READ
		// Section data at 0x3c: RET instruction
		0xc3,
	}
	// Pad to PointerToSymbolTable (0x40)
	for len(coffBytes) < 0x40 {
		coffBytes = append(coffBytes, 0x00)
	}
	// Symbol table entry for BeaconDataInt (undefined external, sectionNumber=0)
	symEntry := []byte{
		0x00, 0x00, 0x00, 0x00, // Name[0:4] = 0 (indicates string table reference)
		0x04, 0x00, 0x00, 0x00, // Name[4:8] = offset 4 into string table
		0x00, 0x00, 0x00, 0x00, // Value
		0x00, 0x00, // SectionNumber: 0 (undefined)
		0x00, 0x00, // Type
		0x02,       // StorageClass: IMAGE_SYM_CLASS_EXTERNAL
		0x00,       // NumberOfAuxSymbols
	}
	coffBytes = append(coffBytes, symEntry...)
	// String table: starts with 4-byte total size, then null-terminated strings
	strTabSize := uint32(4 + 14) // 4 bytes header + "BeaconDataInt\0"
	coffBytes = append(coffBytes, byte(strTabSize), byte(strTabSize>>8), byte(strTabSize>>16), byte(strTabSize>>24))
	coffBytes = append(coffBytes, []byte("BeaconDataInt\x00")...)

	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF failed: %v", err)
	}

	if _, ok := coff.UndefinedSymbols["BeaconDataInt"]; !ok {
		t.Fatal("expected BeaconDataInt to be undefined")
	}

	err = coff.ResolveBeaconAPIs()
	if err != nil {
		t.Fatalf("ResolveBeaconAPIs failed: %v", err)
	}

	addr, ok := coff.Symbols["BeaconDataInt"]
	if !ok {
		t.Fatal("BeaconDataInt not resolved")
	}
	if addr == 0 {
		t.Fatal("BeaconDataInt resolved to null")
	}

	fmt.Printf("BeaconDataInt resolved to 0x%x\n", addr)
}

// TestGoBeaconAPIsDirect tests the Go Beacon API functions directly
// (without going through the trampoline). This validates the Go-side logic.
func TestGoBeaconAPIsDirect(t *testing.T) {
	// Test BeaconDataInt
	data := []byte{0x2a, 0x00, 0x00, 0x00} // 42 in LE
	parser := NewDataParser(data)
	result := BeaconDataInt(parser)
	if result != 42 {
		t.Errorf("BeaconDataInt: expected 42, got %d", result)
	}

	// Test BeaconDataShort
	data2 := []byte{0x37, 0x17} // 5943 in LE
	parser2 := NewDataParser(data2)
	result2 := BeaconDataShort(parser2)
	if result2 != 5943 {
		t.Errorf("BeaconDataShort: expected 5943, got %d", result2)
	}

	// Test BeaconDataLength returns remaining bytes (CS standard)
	data3 := []byte{0x10, 0x00, 0x00, 0x00} // 4-byte buffer
	parser3 := NewDataParser(data3)
	result3 := BeaconDataLength(parser3)
	if result3 != 4 {
		t.Errorf("BeaconDataLength: expected 4 (remaining), got %d", result3)
	}

	// Test BeaconDataExtract
	data4 := []byte{0x41, 0x42, 0x43, 0x44} // "ABCD"
	parser4 := NewDataParser(data4)
	result4 := BeaconDataExtract(parser4, 3)
	if string(result4) != "ABC" {
		t.Errorf("BeaconDataExtract: expected 'ABC', got '%s'", string(result4))
	}

	// Test BeaconDataParse + chained calls — layout matches bof_test.c:
	// [int32:42][int16:5943]["ABCD"] (10 bytes, no embedded length field)
	rawData := []byte{
		0x2a, 0x00, 0x00, 0x00, // int32: 42
		0x37, 0x17, // int16: 5943
		0x41, 0x42, 0x43, 0x44, // "ABCD"
	}
	var p *DataParser
	BeaconDataParse(&p, uintptr(unsafe.Pointer(&rawData[0])), int32(len(rawData)))
	if p == nil {
		t.Fatal("BeaconDataParse: parser is nil")
	}
	v1 := BeaconDataInt(p)
	if v1 != 42 {
		t.Errorf("chained BeaconDataInt: expected 42, got %d", v1)
	}
	v2 := BeaconDataShort(p)
	if v2 != 5943 {
		t.Errorf("chained BeaconDataShort: expected 5943, got %d", v2)
	}
	v3 := BeaconDataLength(p)
	if v3 != 4 {
		t.Errorf("chained BeaconDataLength: expected 4 (remaining), got %d", v3)
	}
	v4 := BeaconDataExtract(p, 4)
	if string(v4) != "ABCD" {
		t.Errorf("chained BeaconDataExtract: expected ABCD, got %q", string(v4))
	}

	fmt.Println("All Go Beacon API direct tests PASS")
}

// TestBeaconDataExtractIsolation isolates beaconDataExtractNative from the
// COFF loader and trampoline, testing the Go function directly with exact
// hex address logging. Layout matches bof_test.c (no embedded length field).
func TestBeaconDataExtractIsolation(t *testing.T) {
	// Exact byte stream the BOF constructs
	testdata := []byte{
		0x2a, 0x00, 0x00, 0x00, // int32: 42
		0x37, 0x17, // int16: 5943
		0x41, 0x42, 0x43, 0x44, // "ABCD"
	}

	// Allocate data on the heap to get a stable address
	heapData := make([]byte, len(testdata))
	copy(heapData, testdata)
	dataBase := uintptr(unsafe.Pointer(&heapData[0]))

	t.Logf("input buffer base:  0x%x", dataBase)
	t.Logf("testdata layout:    [0]=0x2a(42) [4]=0x37(short) [6]=ABCD")

	// Step 1: Pure Go method calls (no unsafe, no trampoline)
	parser := NewDataParser(heapData)
	t.Logf("parser ptr:         0x%x", uintptr(unsafe.Pointer(parser)))
	t.Logf("parser.buffer.ptr:  0x%x", uintptr(unsafe.Pointer(&parser.buffer[0])))
	t.Logf("parser.buffer.len:  %d", len(parser.buffer))
	t.Logf("parser.offset:      %d (before any calls)", parser.offset)

	v1 := parser.Int()
	t.Logf("after Int():        val=%d offset=%d", v1, parser.offset)

	v2 := parser.Short()
	t.Logf("after Short():      val=%d offset=%d", v2, parser.offset)

	v3 := parser.Length()
	t.Logf("after Length():     val=%d offset=%d (NOTE: CS spec says Length should NOT advance offset)", v3, parser.offset)

	expectedOffsetAfterLength := parser.offset

	extractSlice := parser.Extract(4)
	t.Logf("after Extract(4):   offset=%d", parser.offset)
	t.Logf("extract slice ptr:  0x%x", uintptr(unsafe.Pointer(&extractSlice[0])))
	t.Logf("extract slice len:  %d", len(extractSlice))
	t.Logf("extract[0..3]:      %02x %02x %02x %02x ('%c%c%c%c')",
		extractSlice[0], extractSlice[1], extractSlice[2], extractSlice[3],
		extractSlice[0], extractSlice[1], extractSlice[2], extractSlice[3])

	// Verify pure Go implementation
	if v1 != 42 {
		t.Errorf("Int: expected 42, got %d", v1)
	}
	if v2 != 5943 {
		t.Errorf("Short: expected 5943, got %d", v2)
	}
	if v3 != 4 {
		t.Errorf("Length: expected 4 (remaining), got %d", v3)
	}
	if len(extractSlice) != 4 || extractSlice[0] != 'A' || extractSlice[1] != 'B' || extractSlice[2] != 'C' || extractSlice[3] != 'D' {
		t.Errorf("Extract: expected ABCD, got %q", string(extractSlice))
	}

	// Step 2: Test beaconDataExtractNative through uintptr (simulates trampoline path)
	parser2 := NewDataParser(heapData)
	parser2.Int()
	parser2.Short()
	parser2.Length()
	parser2Ptr := uintptr(unsafe.Pointer(parser2))

	t.Logf("")
	t.Logf("=== beaconDataExtractNative test ===")
	t.Logf("parser ptr:         0x%x", parser2Ptr)
	t.Logf("parser offset:      %d (before Extract)", parser2.offset)

	resultPtr := beaconDataExtractNative(parser2Ptr, 4)
	expectedPtr := dataBase + uintptr(expectedOffsetAfterLength)

	t.Logf("expected ptr:       0x%x (base+=%d)", expectedPtr, expectedOffsetAfterLength)
	t.Logf("actual ptr:         0x%x", resultPtr)
	t.Logf("ptr delta:          %d bytes", int64(resultPtr)-int64(expectedPtr))

	if resultPtr == 0 {
		t.Fatal("beaconDataExtractNative returned nil")
	}

	resultByte := (*byte)(unsafe.Pointer(resultPtr))
	t.Logf("byte at result[0]:  0x%02x ('%c')", *resultByte, *resultByte)

	// Read 4 bytes from the returned pointer
	resultSlice := unsafe.Slice(resultByte, 4)
	t.Logf("bytes at result:    %02x %02x %02x %02x ('%c%c%c%c')",
		resultSlice[0], resultSlice[1], resultSlice[2], resultSlice[3],
		resultSlice[0], resultSlice[1], resultSlice[2], resultSlice[3])

	if resultSlice[0] != 'A' || resultSlice[1] != 'B' || resultSlice[2] != 'C' || resultSlice[3] != 'D' {
		t.Errorf("beaconDataExtractNative: expected ptr to ABCD, got %c%c%c%c (hex: %02x %02x %02x %02x) at 0x%x",
			resultSlice[0], resultSlice[1], resultSlice[2], resultSlice[3],
			resultSlice[0], resultSlice[1], resultSlice[2], resultSlice[3],
			resultPtr)
	}

	t.Logf("parser offset after: %d (expected 10)", parser2.offset)
	if parser2.offset != 10 {
		t.Errorf("parser offset: expected 10, got %d", parser2.offset)
	}

	// Step 3: Verify BeaconDataParse + beaconDataExtractNative path
	// This simulates what the MSVC BOF does: allocate parser via BeaconDataParse
	// then call through uintptr
	t.Logf("")
	t.Logf("=== Full BeaconDataParse -> beaconDataExtractNative path ===")
	var parsedParser *DataParser
	BeaconDataParse(&parsedParser, uintptr(unsafe.Pointer(&heapData[0])), int32(len(heapData)))
	if parsedParser == nil {
		t.Fatal("BeaconDataParse returned nil parser")
	}
	t.Logf("parsed parser ptr:  0x%x", uintptr(unsafe.Pointer(parsedParser)))

	BeaconDataInt(parsedParser)
	t.Logf("after Int:          offset=%d", parsedParser.offset)

	BeaconDataShort(parsedParser)
	t.Logf("after Short:        offset=%d", parsedParser.offset)

	BeaconDataLength(parsedParser)
	t.Logf("after Length:       offset=%d", parsedParser.offset)

	lengthVal := parsedParser.offset

	extracted2 := BeaconDataExtract(parsedParser, 4)
	t.Logf("after Extract:      offset=%d", parsedParser.offset)
	t.Logf("extracted bytes:    %02x %02x %02x %02x",
		extracted2[0], extracted2[1], extracted2[2], extracted2[3])

	// Also test via native function
	var parsedParser2 *DataParser
	BeaconDataParse(&parsedParser2, uintptr(unsafe.Pointer(&heapData[0])), int32(len(heapData)))
	BeaconDataInt(parsedParser2)
	BeaconDataShort(parsedParser2)
	BeaconDataLength(parsedParser2)
	nativePtr := beaconDataExtractNative(uintptr(unsafe.Pointer(parsedParser2)), 4)
	nativeBytes := unsafe.Slice((*byte)(unsafe.Pointer(nativePtr)), 4)
	t.Logf("native extract:     %02x %02x %02x %02x at 0x%x",
		nativeBytes[0], nativeBytes[1], nativeBytes[2], nativeBytes[3], nativePtr)

	_ = lengthVal
	_ = dataBase

	fmt.Println("TestBeaconDataExtractIsolation COMPLETE")
}

// TestBeaconDataLengthSemantics verifies whether Length advances the offset.
// The standard CS BeaconDataLength does NOT advance the offset.
func TestBeaconDataLengthSemantics(t *testing.T) {
	data := []byte{
		0x2a, 0x00, 0x00, 0x00, // int32: 42
		0x37, 0x17,              // int16: 5943
		0x10, 0x00, 0x00, 0x00, // int32: 16
		0x41, 0x42, 0x43, 0x44, // "ABCD"
	}

	parser := NewDataParser(data)
	parser.Int()  // offset: 0 -> 4
	parser.Short() // offset: 4 -> 6

	offsetBefore := parser.offset
	t.Logf("offset before Length: %d", offsetBefore)

	result := parser.Length()

	offsetAfter := parser.offset
	t.Logf("Length returned: %d", result)
	t.Logf("offset after Length: %d", offsetAfter)

	if offsetBefore != offsetAfter {
		t.Logf("WARNING: Length advanced offset by %d bytes (offset %d -> %d)", offsetAfter-offsetBefore, offsetBefore, offsetAfter)
		t.Logf("Standard CS BeaconDataLength does NOT advance the offset.")
		t.Logf("Current implementation reads a 4-byte int32 from the buffer and advances by 4.")
		t.Logf("This is a deviation from the CS API contract.")
	}

	// The standard CS API says:
	// BeaconDataLength returns the number of REMAINING bytes (total - consumed)
	// It does NOT modify the parser state.
	remaining := len(data) - offsetBefore
	t.Logf("Standard CS result would be: %d (remaining bytes)", remaining)
	t.Logf("Our implementation returned: %d (int32 read from buffer at offset %d)", result, offsetBefore)

	_ = remaining
}

// TestTrampolineDirectCall tests the trampolines directly using Microsoft x64 calling
// convention via CallFunc2, bypassing the COFF loader entirely.
// Layout matches bof_test.c: [int32:42][int16:5943]["ABCD"].
func TestTrampolineDirectCall(t *testing.T) {
	addrs := trampolineAddrs()

	// Build the exact same test data the MSVC BOF uses
	testdata := []byte{
		0x2a, 0x00, 0x00, 0x00, // int32: 42
		0x37, 0x17, // int16: 5943
		0x41, 0x42, 0x43, 0x44, // "ABCD"
	}

	// Simulate what MSVC does: allocate a parser pointer on the stack (initially 0)
	var msvcParser uintptr = 0

	t.Logf("testdata base: 0x%x", uintptr(unsafe.Pointer(&testdata[0])))
	t.Logf("msvcParser (before parse): 0x%x", msvcParser)

	// Step 1: Call BeaconDataParse through trampoline
	// BeaconDataParse(**DataParser, uintptr, int32)
	// MSVC: RCX=&parser, RDX=buffer, R8=size
	parseAddr := addrs["BeaconDataParse"]
	t.Logf("BeaconDataParse trampoline: 0x%x", parseAddr)

	parseResult := CallFunc(parseAddr,
		uintptr(unsafe.Pointer(&msvcParser)),
		uintptr(unsafe.Pointer(&testdata[0])),
		uintptr(len(testdata)),
	)
	t.Logf("BeaconDataParse returned: %d", parseResult)
	t.Logf("msvcParser (after parse): 0x%x", msvcParser)

	if msvcParser == 0 {
		t.Fatal("BeaconDataParse: parser is still 0 after call")
	}

	// Step 2: Call BeaconDataInt through trampoline
	// BeaconDataInt(*DataParser) int32
	// MSVC: RCX=parser
	intAddr := addrs["BeaconDataInt"]
	intResult := CallFunc2(intAddr, msvcParser, 0)
	t.Logf("BeaconDataInt returned: %d (0x%x)", intResult, intResult)

	// Step 3: Call BeaconDataShort through trampoline
	shortAddr := addrs["BeaconDataShort"]
	shortResult := CallFunc2(shortAddr, msvcParser, 0)
	t.Logf("BeaconDataShort returned: %d (0x%x)", shortResult, shortResult)

	// Step 4: Call BeaconDataLength through trampoline
	lengthAddr := addrs["BeaconDataLength"]
	lengthResult := CallFunc2(lengthAddr, msvcParser, 0)
	t.Logf("BeaconDataLength returned: %d (0x%x)", lengthResult, lengthResult)

	// Step 5: Call BeaconDataExtract through trampoline
	// BeaconDataExtract(*DataParser, int32) uintptr
	// MSVC: RCX=parser, RDX=size
	extractAddr := addrs["BeaconDataExtract"]
	t.Logf("BeaconDataExtract trampoline: 0x%x", extractAddr)
	t.Logf("Calling BeaconDataExtract(parser=0x%x, size=4)", msvcParser)

	extractResult := CallFunc2(extractAddr, msvcParser, 4)
	t.Logf("BeaconDataExtract returned: 0x%x", extractResult)

	if extractResult == 0 {
		t.Fatal("BeaconDataExtract returned nil")
	}

	// Read bytes at the returned pointer
	extractedBytes := (*[4]byte)(unsafe.Pointer(extractResult))
	t.Logf("bytes at returned ptr: %02x %02x %02x %02x ('%c%c%c%c')",
		extractedBytes[0], extractedBytes[1], extractedBytes[2], extractedBytes[3],
		extractedBytes[0], extractedBytes[1], extractedBytes[2], extractedBytes[3])

	// Log exact addresses for diagnosis
	t.Logf("test data base: 0x%x", uintptr(unsafe.Pointer(&testdata[0])))
	t.Logf("expected ptr:   0x%x (base+6)", uintptr(unsafe.Pointer(&testdata[0]))+6)
	t.Logf("actual ptr:     0x%x", extractResult)
	t.Logf("ptr delta:      %d bytes", int64(extractResult)-int64(uintptr(unsafe.Pointer(&testdata[0]))+6))

	if extractedBytes[0] != 'A' || extractedBytes[1] != 'B' || extractedBytes[2] != 'C' || extractedBytes[3] != 'D' {
		t.Errorf("BeaconDataExtract: expected ABCD, got %c%c%c%c (hex: %02x %02x %02x %02x)",
			extractedBytes[0], extractedBytes[1], extractedBytes[2], extractedBytes[3],
			extractedBytes[0], extractedBytes[1], extractedBytes[2], extractedBytes[3])
	}

	t.Logf("=== Trampoline direct call test COMPLETE ===")
}

// TestCOFFRelocationDiag dumps the relocation info and loaded bytes for BeaconDataExtract
// to diagnose the COFF loading path issue.
func TestCOFFRelocationDiag(t *testing.T) {
	coffPath := "../../bof_test/bof_test.obj"
	coffBytes, err := os.ReadFile(coffPath)
	if err != nil {
		t.Fatalf("failed to read BOF: %v", err)
	}

	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF failed: %v", err)
	}

	// Find all relocations for BeaconDataExtract
	for _, sec := range coff.Sections {
		for _, r := range sec.Relocs {
			if r.Symbol == "BeaconDataExtract" {
				t.Logf("RELOC: section=%s offset=0x%x type=0x%x symbol=%s",
					sec.Name, r.Offset, r.Type, r.Symbol)
			}
		}
	}

	// Print raw section data for .text
	for _, sec := range coff.Sections {
		if sec.Name == ".text$mn" || sec.Name == ".text" {
			t.Logf("Section %s: VA=0x%x size=%d raw=%d bytes",
				sec.Name, sec.Virtual, sec.VirtualSize, len(sec.Physical))
			// Dump first 32 bytes
			dumpLen := len(sec.Physical)
			if dumpLen > 128 {
				dumpLen = 128
			}
			t.Logf("  raw bytes (first %d): %x", dumpLen, sec.Physical[:dumpLen])
		}
	}

	// Now load and examine the relocated code
	err = coff.ResolveBeaconAPIs()
	if err != nil {
		t.Fatalf("ResolveBeaconAPIs failed: %v", err)
	}

	entry, err := coff.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	t.Logf("Loaded at entry 0x%x, base 0x%x", entry, coff.Base)

	// Find the BeaconDataExtract relocation and dump the relocated bytes
	for _, sec := range coff.Sections {
		for _, r := range sec.Relocs {
			if r.Symbol == "BeaconDataExtract" {
				addr := coff.Base + uintptr(sec.Virtual) + uintptr(r.Offset)
				// Dump 16 bytes before and after
				start := addr - 16
				if start < coff.Base {
					start = coff.Base
				}
				end := addr + 16
				code := make([]byte, end-start)
				for i := range code {
					code[i] = *(*byte)(unsafe.Pointer(start + uintptr(i)))
				}
				t.Logf("Code around reloc target (0x%x): %x", addr, code)

				// Check the CALL instruction
				// The CALL is at addr-1 (displacement starts at reloc offset, CALL opcode is 1 byte before)
				callAddr := addr - 1
				callByte := *(*byte)(unsafe.Pointer(callAddr))
				t.Logf("CALL instruction at 0x%x: opcode=0x%02x", callAddr, callByte)

				if callByte == 0xe8 {
					disp := *(*int32)(unsafe.Pointer(addr))
					target := int64(callAddr) + 5 + int64(disp)
					t.Logf("CALL rel32: displacement=0x%08x target=0x%x", uint32(disp), target)
					t.Logf("Expected target: 0x%x (BeaconDataExtract trampoline)", coff.Symbols["BeaconDataExtract"])
					if uintptr(target) != coff.Base+uintptr(coff.Symbols["BeaconDataExtract"]) {
						// The symbol is already absolute (from trampolineAddrs)
						if uintptr(target) != uintptr(coff.Symbols["BeaconDataExtract"]) {
							t.Errorf("CALL target mismatch! actual=0x%x expected=0x%x",
								target, coff.Symbols["BeaconDataExtract"])
						}
					}
				} else {
					t.Logf("Not a CALL rel32 at expected offset (opcode=0x%02x)", callByte)
					// Scan nearby for CALL
					for i := -8; i < 8; i++ {
						b := *(*byte)(unsafe.Pointer(addr + uintptr(i)))
						if b == 0xe8 {
							d := *(*int32)(unsafe.Pointer(addr + uintptr(i) + 1))
							t.Logf("  Found CALL at offset %d: displacement=0x%08x", i, uint32(d))
						}
					}
				}
			}
		}
	}
}

// TestRealBOFEndToEnd loads and executes the MSVC-compiled BOF through the
// full COFF loader path: parse -> resolve beacons -> load -> relocate -> call
func TestRealBOFEndToEnd(t *testing.T) {
	coffPath := "../../bof_test/bof_test.obj"

	if _, err := os.Stat(coffPath); os.IsNotExist(err) {
		t.Skipf("BOF test object not found at %s", coffPath)
	}

	coffBytes, err := os.ReadFile(coffPath)
	if err != nil {
		t.Fatalf("failed to read BOF: %v", err)
	}

	t.Logf("Loaded BOF: %d bytes", len(coffBytes))

	// Parse
	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF failed: %v", err)
	}

	t.Logf("Parsed: %d sections, %d symbols, %d undefined",
		len(coff.Sections), len(coff.Symbols), len(coff.UndefinedSymbols))

	for name := range coff.UndefinedSymbols {
		t.Logf("  undefined symbol: %s", name)
	}

	// Set up Beacon API callbacks to capture output
	var capturedOutput []byte
	var capturedPrintf []string
	SetBeaconCallbacks(
		func(format string, args ...interface{}) {
			capturedPrintf = append(capturedPrintf, fmt.Sprintf(format, args...))
		},
		func(data []byte) {
			capturedOutput = append(capturedOutput, data...)
		},
	)

	// Resolve Beacon API symbols to trampolines
	err = coff.ResolveBeaconAPIs()
	if err != nil {
		t.Fatalf("ResolveBeaconAPIs failed: %v", err)
	}

	for name, addr := range coff.Symbols {
		t.Logf("  resolved symbol: %s -> 0x%x", name, addr)
	}

	// Load into memory
	entry, err := coff.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	t.Logf("Loaded at entry point 0x%x", entry)

	// Find the go() function symbol
	goAddr, ok := coff.GetSymbol("go")
	if !ok {
		t.Fatal("go symbol not found")
	}
	t.Logf("go() at 0x%x", goAddr)

	// Call go() with no arguments (the BOF constructs its own test data)
	result := CallFunc2(goAddr, 0, 0)
	t.Logf("go() returned: %d (0x%x)", result, result)

	// Read the global variables from the .bss section
	// .bss is SECT3 at VirtualAddress 0x00
	// Global variable offsets from symbol table:
	//   g_beacon_data_int_result:   offset 0x00 (int32)
	//   g_beacon_data_short_result: offset 0x04 (int16)
	//   g_beacon_data_length_result:offset 0x08 (int32)
	//   g_beacon_extract_result:    offset 0x0C (char[4])
	//   g_beacon_output_called:     offset 0x10 (int32)
	//   g_beacon_printf_called:     offset 0x14 (int32)
	//   g_beacon_parse_called:      offset 0x18 (int32)

	// The .bss section is at VirtualAddress 0, so globals are at base + offset
	// But we need to find the actual base address. We can use the symbol addresses.
	// g_beacon_data_int_result is in SECT3 at offset 0x00
	// After relocation, it's at base + 0

	// Since the COFF was loaded, the memory is at some base address.
	// We can use the symbol table to find the addresses.
	intResultAddr, ok := coff.GetSymbol("g_beacon_data_int_result")
	if !ok {
		t.Fatal("g_beacon_data_int_result not found in symbols")
	}

	// Read values at those addresses
	intResult := *(*int32)(unsafe.Pointer(intResultAddr))
	shortResult := *(*int16)(unsafe.Pointer(intResultAddr + 4))
	lengthResult := *(*int32)(unsafe.Pointer(intResultAddr + 8))
	extract0 := *(*byte)(unsafe.Pointer(intResultAddr + 12))
	extract1 := *(*byte)(unsafe.Pointer(intResultAddr + 13))
	extract2 := *(*byte)(unsafe.Pointer(intResultAddr + 14))
	extract3 := *(*byte)(unsafe.Pointer(intResultAddr + 15))
	outputCalled := *(*int32)(unsafe.Pointer(intResultAddr + 16))
	printfCalled := *(*int32)(unsafe.Pointer(intResultAddr + 20))
	parseCalled := *(*int32)(unsafe.Pointer(intResultAddr + 24))

	t.Logf("g_beacon_data_int_result = %d", intResult)
	t.Logf("g_beacon_data_short_result = %d", shortResult)
	t.Logf("g_beacon_data_length_result = %d", lengthResult)
	t.Logf("g_beacon_extract_result = [%c%c%c%c] hex=[%02x %02x %02x %02x]", extract0, extract1, extract2, extract3, extract0, extract1, extract2, extract3)
	t.Logf("g_beacon_output_called = %d", outputCalled)
	t.Logf("g_beacon_printf_called = %d", printfCalled)
	t.Logf("g_beacon_parse_called = %d", parseCalled)

	// Verify expected values
	if intResult != 42 {
		t.Errorf("BeaconDataInt: expected 42, got %d", intResult)
	}
	if shortResult != 5943 {
		t.Errorf("BeaconDataShort: expected 5943, got %d", shortResult)
	}
	if lengthResult != 4 {
		t.Errorf("BeaconDataLength: expected 4 (remaining after Int+Short), got %d", lengthResult)
	}
	if extract0 != 'A' || extract1 != 'B' || extract2 != 'C' || extract3 != 'D' {
		t.Errorf("BeaconDataExtract: expected ABCD, got %c%c%c%c", extract0, extract1, extract2, extract3)
	}
	if outputCalled != 1 {
		t.Errorf("BeaconOutput: expected called=1, got %d", outputCalled)
	}
	if printfCalled != 1 {
		t.Errorf("BeaconPrintf: expected called=1, got %d", printfCalled)
	}
	if parseCalled != 1 {
		t.Errorf("BeaconDataParse: expected called=1, got %d", parseCalled)
	}

	// Verify captured output
	if len(capturedOutput) > 0 {
		t.Logf("BeaconOutput captured: %q", string(capturedOutput))
	}
	if len(capturedPrintf) > 0 {
		t.Logf("BeaconPrintf captured: %q", capturedPrintf)
	}

	t.Log("=== End-to-end BOF execution COMPLETE ===")
}
