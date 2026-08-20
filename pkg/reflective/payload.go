//go:build windows && amd64

package reflective

import "encoding/binary"

// TestPayload builds a minimal x64 DLL with no imports (kind "noimports")
// or with a kernel32.Sleep import (kind "imports"). The DLL's single export
// "run" returns a value that proves relocation and import resolution worked:
//
//   - "noimports": run returns loadedBase + 0x87 (the embedded absolute
//     pointer must be relocated from the preferred base to the real base).
//   - "imports":   run calls kernel32.Sleep(1) through the resolved IAT and
//     then returns 1 (DllMain and run both succeed only if the IAT slot was
//     patched to the real Sleep address).
//
// The entry point is the same code, so DllMain(PROCESS_ATTACH) returns TRUE.
func TestPayload(kind string) ([]byte, error) {
	switch kind {
	case "noimports":
		return testPayloadNoImports(), nil
	case "imports":
		return testPayloadImports(), nil
	}
	return nil, &kindError{kind}
}

const (
	prefBase = 0x140000000 // preferred image base
	secRVA   = 0x1000      // single section .text
	codeRVA  = 0x1200      // code (and the export)
	iatRVA   = 0x1100      // IAT slot (imports variant)
	rawPtr   = 0x200       // PointerToRawData of the section (== SizeOfHeaders)
)

// fileOff maps an image RVA to the file offset inside the single section.
func fileOff(rva uint32) int {
	return rawPtr + int(rva-secRVA)
}

// expDirOff is the file offset of the export directory for a given RVA.
func expDirFile(rva uint32) int { return fileOff(rva) }

func testPayloadBase(code []byte, expDirRVA uint32, impDirRVA uint32, iat bool, relocs []uint16) []byte {
	const sizeOfHeaders = 0x200
	const sizeOfImage = 0x2000
	const secRawSize = 0x400

	img := make([]byte, sizeOfHeaders+secRawSize)

	// DOS header.
	binary.LittleEndian.PutUint16(img[0:], 0x5A4D)  // MZ
	binary.LittleEndian.PutUint32(img[0x3C:], 0x40) // e_lfanew

	// PE signature + COFF header.
	copy(img[0x40:], "PE\x00\x00")
	coff := 0x44
	binary.LittleEndian.PutUint16(img[coff:], 0x8664)    // machine x64
	binary.LittleEndian.PutUint16(img[coff+2:], 1)       // one section
	binary.LittleEndian.PutUint16(img[coff+16:], 0xF0)   // optional header size
	binary.LittleEndian.PutUint16(img[coff+18:], 0x2022) // EXECUTABLE_IMAGE | DLL | LARGE_ADDRESS_AWARE

	// Optional header (PE32+).
	opt := coff + 20
	binary.LittleEndian.PutUint16(img[opt:], 0x20B)              // magic
	img[opt+2] = 14                                              // linker major
	img[opt+3] = 0                                               // linker minor
	binary.LittleEndian.PutUint32(img[opt+0x08:], secRawSize)    // SizeOfCode
	binary.LittleEndian.PutUint32(img[opt+0x10:], codeRVA)       // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(img[opt+0x14:], secRVA)        // BaseOfCode
	binary.LittleEndian.PutUint64(img[opt+0x18:], prefBase)      // ImageBase
	binary.LittleEndian.PutUint32(img[opt+0x20:], 0x1000)        // SectionAlignment
	binary.LittleEndian.PutUint32(img[opt+0x24:], 0x200)         // FileAlignment
	binary.LittleEndian.PutUint16(img[opt+0x28:], 6)             // OS major
	binary.LittleEndian.PutUint16(img[opt+0x2C:], 0)             // image major
	binary.LittleEndian.PutUint16(img[opt+0x30:], 6)             // subsystem major
	binary.LittleEndian.PutUint32(img[opt+0x34:], 0)             // Win32VersionValue
	binary.LittleEndian.PutUint32(img[opt+0x38:], sizeOfImage)   // SizeOfImage
	binary.LittleEndian.PutUint32(img[opt+0x3C:], sizeOfHeaders) // SizeOfHeaders
	binary.LittleEndian.PutUint16(img[opt+0x44:], 2)             // subsystem GUI
	binary.LittleEndian.PutUint16(img[opt+0x46:], 0)             // DllCharacteristics
	binary.LittleEndian.PutUint32(img[opt+0x48:], 0x100000)      // stack reserve
	binary.LittleEndian.PutUint32(img[opt+0x50:], 0x1000)        // stack commit
	binary.LittleEndian.PutUint32(img[opt+0x58:], 0x100000)      // heap reserve
	binary.LittleEndian.PutUint32(img[opt+0x60:], 0x1000)        // heap commit
	binary.LittleEndian.PutUint32(img[opt+0x6C:], 16)            // NumberOfRvaAndSizes
	// Data directories (PE32+ canonical layout).
	binary.LittleEndian.PutUint32(img[opt+0x70:], expDirRVA) // [0] export
	binary.LittleEndian.PutUint32(img[opt+0x74:], 0x28)
	if impDirRVA != 0 {
		binary.LittleEndian.PutUint32(img[opt+0x78:], impDirRVA) // [1] import
		binary.LittleEndian.PutUint32(img[opt+0x7C:], 0x28)
	}
	// No TLS ([9]). Relocations ([5]) at secRVA + 0x3C0.
	binary.LittleEndian.PutUint32(img[opt+0x98:], secRVA+0x3D0)
	binary.LittleEndian.PutUint32(img[opt+0x9C:], 12)

	// Section table (one .text).
	sh := opt + 0xF0
	copy(img[sh:], ".text")
	binary.LittleEndian.PutUint32(img[sh+8:], secRawSize)  // VirtualSize
	binary.LittleEndian.PutUint32(img[sh+12:], secRVA)     // VirtualAddress
	binary.LittleEndian.PutUint32(img[sh+16:], secRawSize) // SizeOfRawData
	binary.LittleEndian.PutUint32(img[sh+20:], rawPtr)     // PointerToRawData
	binary.LittleEndian.PutUint32(img[sh+36:], 0x60000020) // CODE | EXECUTE | READ

	copy(img[fileOff(codeRVA):], code)
	copy(img[expDirFile(expDirRVA):], exportDirectory(expDirRVA))
	if impDirRVA != 0 {
		copy(img[fileOff(impDirRVA):], importDirectory(impDirRVA, iatRVA))
		// IAT placeholder: overwritten by the loader with the real Sleep
		// address, but relocated from the preferred base for determinism.
		binary.LittleEndian.PutUint64(img[fileOff(iatRVA):], prefBase+uint64(iatRVA))
	}
	// Relocation block: one DIR64 entry per embedded absolute pointer slot,
	// page RVA = section RVA.
	rel := img[fileOff(secRVA+0x3D0):]
	binary.LittleEndian.PutUint32(rel, secRVA)
	binary.LittleEndian.PutUint32(rel[4:], uint32(8+2*len(relocs)))
	for i, off := range relocs {
		binary.LittleEndian.PutUint16(rel[8+i*2:], 0xA000|off)
	}
	return img
}

// exportDirectory builds an export directory (with the "run" export) that
// lives at dirRVA. Layout: directory (0x00-0x27), then the address-of-
// functions / names / ordinals tables and the name strings after it.
func exportDirectory(dirRVA uint32) []byte {
	b := make([]byte, 0x50)
	binary.LittleEndian.PutUint32(b[0x00:], dirRVA+0x48) // Name "run.dll"
	binary.LittleEndian.PutUint32(b[0x10:], 1)           // Base
	binary.LittleEndian.PutUint32(b[0x14:], 1)           // NumberOfFunctions
	binary.LittleEndian.PutUint32(b[0x18:], 1)           // NumberOfNames
	binary.LittleEndian.PutUint32(b[0x1C:], dirRVA+0x28) // AddressOfFunctions
	binary.LittleEndian.PutUint32(b[0x20:], dirRVA+0x30) // AddressOfNames
	binary.LittleEndian.PutUint32(b[0x24:], dirRVA+0x38) // AddressOfNameOrdinals
	binary.LittleEndian.PutUint32(b[0x28:], codeRVA)     // funcs[0] = run
	binary.LittleEndian.PutUint32(b[0x30:], dirRVA+0x40) // names[0]
	binary.LittleEndian.PutUint16(b[0x38:], 0)           // ordinals[0]
	copy(b[0x40:], "run\x00")
	copy(b[0x48:], "run.dll\x00")
	return b
}

// importDirectory builds an import descriptor for kernel32.Sleep that lives
// at impDirRVA, with the IAT at iatRVA; internal RVAs are relative to
// impDirRVA. The blob must not reach file 0x570 (the export directory of the
// imports variant starts there).
func importDirectory(impDirRVA, iatRVA uint32) []byte {
	b := make([]byte, 0x68)
	binary.LittleEndian.PutUint32(b[0x00:], impDirRVA+0x40)         // OriginalFirstThunk (INT)
	binary.LittleEndian.PutUint32(b[0x0C:], impDirRVA+0x50)         // Name "kernel32.dll"
	binary.LittleEndian.PutUint32(b[0x10:], iatRVA)                 // FirstThunk
	binary.LittleEndian.PutUint64(b[0x40:], uint64(impDirRVA+0x60)) // INT[0] -> hint/name
	binary.LittleEndian.PutUint16(b[0x60:], 0)                      // hint
	copy(b[0x62:], "Sleep\x00")
	copy(b[0x50:], "kernel32.dll\x00")
	return b
}

func testPayloadNoImports() []byte {
	// mov rax, imm64(prefBase+0x80); add rax, 7; ret (15 bytes)
	code := make([]byte, 15)
	code[0] = 0x48
	code[1] = 0xB8
	binary.LittleEndian.PutUint64(code[2:], prefBase+0x80)
	copy(code[10:], []byte{0x48, 0x83, 0xC0, 0x07, 0xC3})
	return testPayloadBase(code, 0x1300, 0, false, []uint16{0x202})
}

func testPayloadImports() []byte {
	// mov rax, imm64(prefBase+iatRVA); mov rax, qword [rax]; add rax, 7;
	// ret — returns IAT slot value + 7 without calling through it.
	code := make([]byte, 31)
	code[0] = 0x48
	code[1] = 0xB8
	binary.LittleEndian.PutUint64(code[2:], prefBase+uint64(iatRVA))
	copy(code[10:], []byte{0x48, 0x8B, 0x00, 0x48, 0x83, 0xC0, 0x07, 0xC3})
	return testPayloadBase(code, 0x1370, 0x1300, true, []uint16{0x202})
}

type kindError struct{ k string }

func (e *kindError) Error() string { return "reflective: unknown test payload kind " + e.k }
