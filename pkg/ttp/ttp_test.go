package ttp

import (
	"encoding/json"
	"testing"
)

func TestRegistryLookupAndList(t *testing.T) {
	for _, name := range []string{"shell", "exec", "sleep", "download", "upload", "kill", "inject"} {
		if _, ok := Lookup(name); !ok {
			t.Fatalf("expected ttp %q registered", name)
		}
	}
	if _, ok := Lookup("nonexistent"); ok {
		t.Fatal("nonexistent ttp must not resolve")
	}
	if len(List()) < 7 {
		t.Fatalf("expected at least 7 ttps, got %d", len(List()))
	}
}

func TestShellGenerate(t *testing.T) {
	b, err := Generate("shell", map[string]string{"cmd": "whoami"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["cmd"] != "whoami" {
		t.Fatalf("payload mismatch: %v", out)
	}
}

func TestRequiredArgsEnforced(t *testing.T) {
	if _, err := Generate("shell", map[string]string{}); err == nil {
		t.Fatal("shell without cmd must fail")
	}
	if _, err := Generate("inject", map[string]string{}); err == nil {
		t.Fatal("inject without data must fail")
	}
}

func TestSleepValidatesNumber(t *testing.T) {
	for _, bad := range []string{"0", "-1", "100000", "abc"} {
		if _, err := Generate("sleep", map[string]string{"seconds": bad}); err == nil {
			t.Fatalf("sleep %q must fail", bad)
		}
	}
	b, err := Generate("sleep", map[string]string{"seconds": "15"})
	if err != nil {
		t.Fatalf("sleep 15: %v", err)
	}
	var out map[string]int
	if err := json.Unmarshal(b, &out); err != nil || out["seconds"] != 15 {
		t.Fatalf("sleep payload mismatch: %v %v", out, err)
	}
}

func TestInjectValidation(t *testing.T) {
	if _, err := Generate("inject", map[string]string{"data": "zzz", "pid": "x"}); err == nil {
		t.Fatal("inject with non-numeric pid must fail")
	}
	if _, err := Generate("inject", map[string]string{"data": "not-base64!", "pid": "1234"}); err == nil {
		t.Fatal("inject with invalid base64 must fail")
	}
	b, err := Generate("inject", map[string]string{"data": "YWE=", "pid": "1234"})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["data"] != "YWE=" {
		t.Fatalf("inject payload mismatch: %v", out)
	}
}

func TestUnknownGenerate(t *testing.T) {
	if _, err := Generate("nope", nil); err == nil {
		t.Fatal("unknown ttp must fail")
	}
}
