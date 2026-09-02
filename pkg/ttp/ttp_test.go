package ttp

import (
	"encoding/json"
	"testing"
)

func TestRegistryLookupAndList(t *testing.T) {
	for _, name := range []string{"shell", "exec", "sleep", "download", "upload", "kill", "inject", "dll", "persist", "unpersist", "uac", "bof", "amsi", "etw"} {
		if _, ok := Lookup(name); !ok {
			t.Fatalf("expected ttp %q registered", name)
		}
	}
	if _, ok := Lookup("nonexistent"); ok {
		t.Fatal("nonexistent ttp must not resolve")
	}
	if len(List()) < 14 {
		t.Fatalf("expected at least 14 ttps, got %d", len(List()))
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

func TestPersistValidation(t *testing.T) {
	for _, bad := range []string{"", "bogus", "run", "SERVICE"} {
		if _, err := Generate("persist", map[string]string{"method": bad, "name": "x"}); err == nil {
			t.Fatalf("persist method %q must fail", bad)
		}
		if _, err := Generate("unpersist", map[string]string{"method": bad, "name": "x"}); err == nil {
			t.Fatalf("unpersist method %q must fail", bad)
		}
	}
	if _, err := Generate("persist", map[string]string{"method": "reg"}); err == nil {
		t.Fatal("persist without name must fail")
	}
	for _, method := range []string{"reg", "schtasks", "startup"} {
		b, err := Generate("persist", map[string]string{"method": method, "name": "sys", "cmd": "C:\\x.exe"})
		if err != nil {
			t.Fatalf("persist %s: %v", method, err)
		}
		var out map[string]string
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out["method"] != method || out["name"] != "sys" || out["cmd"] != `C:\x.exe` {
			t.Fatalf("persist payload mismatch: %v", out)
		}
	}
}

func TestUacValidation(t *testing.T) {
	for _, bad := range []string{"runas", "eventvwr"} {
		if _, err := Generate("uac", map[string]string{"method": bad, "cmd": "whoami"}); err == nil {
			t.Fatalf("uac method %q must fail", bad)
		}
	}
	if _, err := Generate("uac", map[string]string{}); err == nil {
		t.Fatal("uac without cmd or name must fail")
	}
	for _, method := range []string{"", "daily", "schtasks", "cmluautil", "fodhelper", "computerdefaults"} {
		b, err := Generate("uac", map[string]string{"method": method, "name": "sysaux"})
		if err != nil {
			t.Fatalf("uac %q: %v", method, err)
		}
		var out map[string]string
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out["method"] != method || out["name"] != "sysaux" {
			t.Fatalf("uac payload mismatch: %v", out)
		}
	}
}

func TestUnknownGenerate(t *testing.T) {
	if _, err := Generate("nope", nil); err == nil {
		t.Fatal("unknown ttp must fail")
	}
}

func TestBOFRegistryLookup(t *testing.T) {
	s, ok := Lookup("bof")
	if !ok {
		t.Fatal("bof ttp must be registered")
	}
	if s.Name != "bof" {
		t.Fatalf("expected name bof, got %s", s.Name)
	}
}

func TestBOFGenerateRequiresData(t *testing.T) {
	if _, err := Generate("bof", map[string]string{}); err == nil {
		t.Fatal("bof without data must fail")
	}
	if _, err := Generate("bof", map[string]string{"data": ""}); err == nil {
		t.Fatal("bof with empty data must fail")
	}
}

func TestBOFGenerateInvalidBase64(t *testing.T) {
	if _, err := Generate("bof", map[string]string{"data": "not-base64!"}); err == nil {
		t.Fatal("bof with invalid base64 must fail")
	}
}

func TestBOFGenerateValid(t *testing.T) {
	b, err := Generate("bof", map[string]string{"data": "AA=="})
	if err != nil {
		t.Fatalf("bof generate: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["data"] != "AA==" {
		t.Fatalf("bof data mismatch: %v", out)
	}
	if out["fn"] != "go" {
		t.Fatalf("expected fn=go, got %v", out["fn"])
	}
}

func TestBOFGenerateWithFn(t *testing.T) {
	b, err := Generate("bof", map[string]string{"data": "AA==", "fn": "main"})
	if err != nil {
		t.Fatalf("bof generate: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["fn"] != "main" {
		t.Fatalf("expected fn=main, got %v", out["fn"])
	}
}

func TestBOFGenerateWithArgs(t *testing.T) {
	b, err := Generate("bof", map[string]string{"data": "AA==", "args": "hello world"})
	if err != nil {
		t.Fatalf("bof generate: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["args"] != "hello world" {
		t.Fatalf("expected args='hello world', got %v", out["args"])
	}
}

func TestAMSIRegistryLookup(t *testing.T) {
	s, ok := Lookup("amsi")
	if !ok {
		t.Fatal("amsi ttp must be registered")
	}
	if s.Name != "amsi" {
		t.Fatalf("expected name amsi, got %s", s.Name)
	}
}

func TestAMSIGenerateRequiresAction(t *testing.T) {
	if _, err := Generate("amsi", map[string]string{}); err == nil {
		t.Fatal("amsi without action must fail")
	}
	if _, err := Generate("amsi", map[string]string{"action": ""}); err == nil {
		t.Fatal("amsi with empty action must fail")
	}
}

func TestAMSIGenerateInvalidAction(t *testing.T) {
	if _, err := Generate("amsi", map[string]string{"action": "bogus"}); err == nil {
		t.Fatal("amsi with invalid action must fail")
	}
}

func TestAMSIGenerateValid(t *testing.T) {
	for _, action := range []string{"activate", "deactivate", "status"} {
		b, err := Generate("amsi", map[string]string{"action": action})
		if err != nil {
			t.Fatalf("amsi %s: %v", action, err)
		}
		var out map[string]string
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out["action"] != action {
			t.Fatalf("amsi payload mismatch: %v", out)
		}
	}
}

func TestETWRegistryLookup(t *testing.T) {
	s, ok := Lookup("etw")
	if !ok {
		t.Fatal("etw ttp must be registered")
	}
	if s.Name != "etw" {
		t.Fatalf("expected name etw, got %s", s.Name)
	}
}

func TestETWGenerateRequiresAction(t *testing.T) {
	if _, err := Generate("etw", map[string]string{}); err == nil {
		t.Fatal("etw without action must fail")
	}
	if _, err := Generate("etw", map[string]string{"action": ""}); err == nil {
		t.Fatal("etw with empty action must fail")
	}
}

func TestETWGenerateInvalidAction(t *testing.T) {
	if _, err := Generate("etw", map[string]string{"action": "bogus"}); err == nil {
		t.Fatal("etw with invalid action must fail")
	}
}

func TestETWGenerateValid(t *testing.T) {
	for _, action := range []string{"activate", "deactivate", "status"} {
		b, err := Generate("etw", map[string]string{"action": action})
		if err != nil {
			t.Fatalf("etw %s: %v", action, err)
		}
		var out map[string]string
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out["action"] != action {
			t.Fatalf("etw payload mismatch: %v", out)
		}
	}
}
