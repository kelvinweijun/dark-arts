//go:build windows && amd64

package bof

import (
	"os"
	"testing"
	"unsafe"
)

func TestDisassembleBOF(t *testing.T) {
	coffPath := "../../bof_test/bof_test.obj"
	coffBytes, err := os.ReadFile(coffPath)
	if err != nil {
		t.Fatalf("failed to read BOF: %v", err)
	}

	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		t.Fatalf("ParseCOFF failed: %v", err)
	}

	err = coff.ResolveBeaconAPIs()
	if err != nil {
		t.Fatalf("ResolveBeaconAPIs failed: %v", err)
	}

	entry, err := coff.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	_ = entry

	for _, sec := range coff.Sections {
		if sec.Virtual == 0x140 {
			t.Logf("Section %s at VA 0x%x, %d raw bytes", sec.Name, sec.Virtual, len(sec.Physical))
			t.Logf("Loaded at base 0x%x", coff.Base)

			codeBase := coff.Base + uintptr(sec.Virtual)
			codeLen := len(sec.Physical)
			codeBytes := make([]byte, codeLen)
			for i := range codeBytes {
				codeBytes[i] = *(*byte)(unsafe.Pointer(codeBase + uintptr(i)))
			}
			t.Logf("Loaded code at 0x%x (%d bytes):", codeBase, codeLen)
			for i := 0; i < len(codeBytes); i += 16 {
				end := i + 16
				if end > len(codeBytes) {
					end = len(codeBytes)
				}
				t.Logf("  [%03x] %x", i, codeBytes[i:end])
			}

			for _, r := range sec.Relocs {
				t.Logf("RELOC offset=0x%x type=0x%x symbol=%s", r.Offset, r.Type, r.Symbol)
			}
			break
		}
	}
}
