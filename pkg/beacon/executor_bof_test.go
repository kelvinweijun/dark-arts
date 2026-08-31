//go:build windows && amd64

package beacon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"dark-arts/pkg/tasking"
)

func readTestBOF(t *testing.T) []byte {
	t.Helper()
	path := "../../bof_test/bof_test.obj"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("MSVC BOF not found at %s: %v", path, err)
	}
	return b
}

func runBOFTask(t *testing.T, payload []byte) *tasking.Result {
	t.Helper()
	ex := &Executor{Timeout: 30 * time.Second}
	return ex.Run(context.Background(), &tasking.Task{ID: "bof-test", SessionID: "s1", Type: "bof", Payload: payload})
}

func TestExecutorBOFDispatch(t *testing.T) {
	coff := readTestBOF(t)
	payload, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString(coff),
		"fn":   "go",
	})
	res := runBOFTask(t, payload)
	if res.Error != "" {
		t.Fatalf("runBOF failed: %s", res.Error)
	}
	if len(res.Output) == 0 {
		t.Fatal("runBOF produced no output")
	}
	t.Logf("output: %s", res.Output)
}

func TestExecutorBOFBeaconPrintfCapture(t *testing.T) {
	coff := readTestBOF(t)
	payload, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString(coff),
		"fn":   "go",
	})
	res := runBOFTask(t, payload)
	if res.Error != "" {
		t.Fatalf("runBOF failed: %s", res.Error)
	}
	if !strings.Contains(string(res.Output), "Test 42") {
		t.Fatalf("expected BeaconPrintf output 'Test 42', got: %s", res.Output)
	}
}

func TestExecutorBOFBeaconOutputCapture(t *testing.T) {
	coff := readTestBOF(t)
	payload, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString(coff),
		"fn":   "go",
	})
	res := runBOFTask(t, payload)
	if res.Error != "" {
		t.Fatalf("runBOF failed: %s", res.Error)
	}
	if !strings.Contains(string(res.Output), "Hi") {
		t.Fatalf("expected BeaconOutput containing 'Hi', got: %s", res.Output)
	}
}

func TestExecutorBOFEmptyData(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"data": ""})
	res := runBOFTask(t, payload)
	if res.Error == "" {
		t.Fatal("bof with empty data must error")
	}
}

func TestExecutorBOFInvalidBase64(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"data": "not-base64!"})
	res := runBOFTask(t, payload)
	if res.Error == "" {
		t.Fatal("bof with invalid base64 must error")
	}
}

func TestExecutorBOFInvalidCOFF(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString([]byte{0x64, 0x86, 0x00}),
		"fn":   "go",
	})
	res := runBOFTask(t, payload)
	if res.Error == "" {
		t.Fatal("bof with invalid COFF must error")
	}
}

func TestExecutorBOFBadPayload(t *testing.T) {
	res := runBOFTask(t, []byte("not json"))
	if res.Error == "" {
		t.Fatal("bof with invalid JSON payload must error")
	}
}

func TestExecutorBOFFnDefault(t *testing.T) {
	coff := readTestBOF(t)
	payload, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString(coff),
	})
	res := runBOFTask(t, payload)
	if res.Error != "" {
		t.Fatalf("runBOF with default fn failed: %s", res.Error)
	}
	if len(res.Output) == 0 {
		t.Fatal("runBOF with default fn produced no output")
	}
}


