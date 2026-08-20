//go:build windows && amd64

package evasion

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestDiagSSN(t *testing.T) {
	table, err := DiagSSN()
	if err != nil {
		t.Fatal(err)
	}
	for name, ssn := range table {
		t.Logf("%-24s 0x%08X", name, ssn)
		if ssn == 0 {
			t.Errorf("%s: zero SSN", name)
		}
	}
}

func TestSyscallABI(t *testing.T) {
	// NtClose(0) must fail with STATUS_INVALID_HANDLE (0xC0000008).
	// This validates the gadget arg shuffle and SSN resolution end-to-end.
	err := Close(0)
	if err == nil || !strings.Contains(err.Error(), "0xC0000008") {
		t.Fatalf("NtClose(0) expected 0xC0000008, got %v", err)
	}
}

func TestOpenProcessSelf(t *testing.T) {
	h, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenProcess(self): %v", err)
	}
	if h == 0 {
		t.Fatal("OpenProcess returned null handle")
	}
	if err := Close(h); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestUnhookStubsMatchClean(t *testing.T) {
	n, err := DiagUnhook()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stubs restored from clean copy: %d", n)
	clean, err := DiagCleanBase()
	if err != nil {
		t.Fatal(err)
	}
	if clean == 0 {
		t.Skip("clean-copy path unavailable on this system")
	}

	k32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandleW := k32.NewProc("GetModuleHandleW")
	name, _ := syscall.UTF16PtrFromString("ntdll.dll")
	base, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(name)))
	if base == 0 {
		t.Fatal("GetModuleHandleW(ntdll.dll) failed")
	}

	for _, h := range tableHashes() {
		liveFn, err := resolveExport(toPtr(base), h)
		if err != nil {
			t.Fatalf("resolve live export: %v", err)
		}
		cleanFn, err := resolveExport(toPtr(clean), h)
		if err != nil {
			t.Fatalf("resolve clean export: %v", err)
		}
		if !bytesEqual(liveFn, cleanFn, stubPatchLen) {
			t.Fatalf("live stub %08X still differs from clean copy after UDRL", h)
		}
	}
}
