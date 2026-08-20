package beacon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"darkarts/pkg/tasking"
)

// TestUacTaskEndToEnd exercises the full one-time-prompt trade: build a real
// beacon binary, run the uac task once (the UAC prompt appears once — click
// it when asked), which installs the reusable HIGHEST task, then verify a
// second invocation runs fully silent and returns the elevated output.
func TestUacTaskEndToEnd(t *testing.T) {
	dir, err := os.MkdirTemp("", "uac-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	beaconExe := filepath.Join(dir, "beacon-test.exe")
	if out, err := exec.Command("go", "build", "-o", beaconExe, "darkarts/cmd/beacon").CombinedOutput(); err != nil {
		t.Fatalf("build beacon: %v: %s", err, out)
	}

	prev := uacExeOverride
	uacExeOverride = beaconExe
	defer func() { uacExeOverride = prev }()

	// Isolate the reusable task name so the test is repeatable without
	// elevated cleanup of a stale task.
	prevTask := uacTaskName
	uacTaskName = `\DarkArts-uac-` + fmt.Sprintf("%d", time.Now().UnixNano())
	defer func() { uacTaskName = prevTask }()

	// Clean slate for the reusable task so the first run reinstalls it.
	os.Remove(uacTaskCfgPath())

	e := &Executor{}
	runOnce := func(label, cmd string) (string, error) {
		start := time.Now()
		payload, _ := json.Marshal(map[string]string{"method": "schtasks", "cmd": cmd})
		res := &tasking.Result{}
		e.runUac(payload, res)
		elapsed := time.Since(start)
		t.Logf("[%s] error=%q elapsed=%v output_len=%d", label, res.Error, elapsed, len(res.Output))
		if res.Error != "" {
			return "", fmt.Errorf("%s: %s", label, res.Error)
		}
		return string(res.Output), nil
	}

	// First run: one prompt appears, click it when asked.
	t.Log(">>>> FIRST RUN — APPROVE THE UAC PROMPT WHEN IT APPEARS <<<<")
	out, err := runOnce("first", "whoami /groups")
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if !strings.Contains(out, "High Mandatory Level") {
		t.Fatalf("first run did not return an elevated token; output: %s", out)
	}
	t.Log("first run elevated OK; task installed, subsequent runs should be silent")

	// Second run: must be silent and still elevated.
	out, err = runOnce("second", "whoami /groups")
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !strings.Contains(out, "High Mandatory Level") {
		t.Fatalf("second run did not return an elevated token; output: %s", out)
	}
	t.Log("second run silent + elevated OK")

	// Verify the task is registered with the right settings.
	if !uacTaskExists() {
		t.Fatal("reusable task missing after install")
	}
	xml, _ := exec.Command("schtasks", "/Query", "/TN", uacTaskName, "/XML").Output()
	xmlS := string(xml)
	if !strings.Contains(xmlS, "HighestAvailable") || !strings.Contains(xmlS, "InteractiveToken") {
		t.Fatalf("task principal wrong:\n%s", xmlS)
	}
	if !strings.Contains(xmlS, "-uacrun") {
		t.Fatalf("task action wrong:\n%s", xmlS)
	}

	// Cleanup: the reusable task deletes itself via one more elevated run
	// (delete from a medium process is denied by the task's SDL). This must
	// happen before the temp dir holding the beacon exe is removed.
	if out, err := runOnce("cleanup", "schtasks /delete /tn "+uacTaskName+" /f"); err == nil {
		t.Logf("cleanup output: %q", out)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && uacTaskExists() {
			time.Sleep(200 * time.Millisecond)
		}
	} else {
		t.Logf("cleanup error: %v", err)
	}
	if uacTaskExists() {
		t.Log("note: reusable task still present (remove manually)")
	} else {
		t.Log("reusable task removed")
	}
	os.Remove(uacTaskCfgPath())
}