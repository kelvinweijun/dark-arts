//go:build windows && amd64

package securityctl

import (
	"testing"

	"dark-arts/pkg/evasion"
)

func TestAMSIControl_FullLifecycle(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := a.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := a.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}
	a.Restore()
}

func TestETWControl_FullLifecycle(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := e.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := e.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}
	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := e.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}
	e.Restore()
}

func TestAMSIControl_PatchIntegrity(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if a.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	orig := make([]byte, len(a.fp.orig))
	copy(orig, a.fp.orig)
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	for i, b := range a.fp.orig {
		if b != orig[i] {
			t.Fatalf("byte %d: got %02x, want %02x after restore", i, b, orig[i])
		}
	}
}

func TestETWControl_PatchIntegrity(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if e.fp == nil {
		t.Fatal("fp is nil after Initialize")
	}
	orig := make([]byte, len(e.fp.orig))
	copy(orig, e.fp.orig)
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	for i, b := range e.fp.orig {
		if b != orig[i] {
			t.Fatalf("byte %d: got %02x, want %02x after restore", i, b, orig[i])
		}
	}
}

func TestAMSIControl_RestoreIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	a := NewAMSIControl()
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	a.Restore()
	a.Restore()
}

func TestETWControl_RestoreIsIdempotent(t *testing.T) {
	if err := evasion.Init(); err != nil {
		t.Skipf("evasion init failed: %v", err)
	}
	e := NewETWControl()
	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	e.Restore()
	e.Restore()
}
