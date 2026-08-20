//go:build windows && amd64

package reflective

import (
	"testing"

	"darkarts/pkg/sleepmask"
)

func TestLoadNoImportsReloc(t *testing.T) {
	payload, err := TestPayload("noimports")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := Load(payload, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ret, err := Call(mod, "run")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	// run = loadedBase + 0x87: proves the DIR64 relocation was applied
	// (the embedded pointer moved from the preferred base to the real one).
	want := mod.Base + 0x87
	if ret != want {
		t.Fatalf("run returned 0x%X, want 0x%X (relocation not applied)", ret, want)
	}
}

func TestLoadImportsIAT(t *testing.T) {
	payload, err := TestPayload("imports")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := Load(payload, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ret, err := Call(mod, "run")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	// run returns IAT slot + 7 without calling through it: proves the slot
	// was patched to the real Sleep address (in the system DLL range).
	if ret < 0x7FF000000000 || ret >= 0x800000000000 {
		t.Fatalf("run returned 0x%X, want Sleep address + 7 (IAT resolution failed)", ret)
	}
}

func TestLoadNotPE(t *testing.T) {
	if _, err := Load([]byte("not a dll"), Options{}); err != ErrNotPE {
		t.Fatalf("want ErrNotPE, got %v", err)
	}
}

func TestCallMissingExport(t *testing.T) {
	payload, _ := TestPayload("noimports")
	mod, err := Load(payload, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Call(mod, "nope"); err == nil {
		t.Fatal("want error for missing export")
	}
}

func TestMaskedModuleRoundTrip(t *testing.T) {
	payload, err := TestPayload("noimports")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := Load(payload, Options{Mask: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	m, err := sleepmask.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Mask(); err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if err := m.Unmask(); err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	ret, err := Call(mod, "run")
	if err != nil {
		t.Fatalf("Call after mask round-trip: %v", err)
	}
	if want := mod.Base + 0x87; ret != want {
		t.Fatalf("run returned 0x%X after mask round-trip, want 0x%X", ret, want)
	}
}
