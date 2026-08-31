//go:build windows && amd64

package beacon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/edge"
	"dark-arts/pkg/server"
	"dark-arts/pkg/store"
	"dark-arts/pkg/tasking"
)

func TestBOFLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	coff := readTestBOF(t)
	if len(coff) == 0 {
		t.Fatal("bof_test.obj is empty")
	}

	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server ident: %v", err)
	}
	agentIdent, err := crypto.IdentityFromSeed(bytes.Repeat([]byte{0xbb}, 32))
	if err != nil {
		t.Fatalf("agent ident: %v", err)
	}
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())

	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	pump := server.NewPump(engine, edgeSrv.URL, nil)

	b, err := New(beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid))
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	params := map[string]string{
		"data": base64.StdEncoding.EncodeToString(coff),
		"fn":   "go",
	}

	task, err := engine.IssueTask("op-e2e-bof", sid, "bof", params, "op-e2e-bof")
	if err != nil {
		t.Fatalf("issue bof task: %v", err)
	}

	if task.Type != "bof" {
		t.Fatalf("expected task type bof, got %s", task.Type)
	}
	if task.SessionID != sid {
		t.Fatalf("expected session %s, got %s", sid, task.SessionID)
	}

	var payload map[string]string
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		t.Fatalf("task payload unmarshal: %v", err)
	}
	if payload["data"] == "" {
		t.Fatal("task payload missing data field")
	}
	decoded, err := base64.StdEncoding.DecodeString(payload["data"])
	if err != nil {
		t.Fatalf("task payload data is not valid base64: %v", err)
	}
	if len(decoded) != len(coff) {
		t.Fatalf("task payload data length mismatch: got %d, want %d", len(decoded), len(coff))
	}
	if payload["fn"] != "go" {
		t.Fatalf("task payload fn: got %q, want %q", payload["fn"], "go")
	}

	if err := pump.Pass(ctx); err != nil {
		t.Fatalf("pump push: %v", err)
	}

	if err := b.CheckIn(ctx); err != nil {
		t.Fatalf("beacon check-in: %v", err)
	}

	if err := pump.Pass(ctx); err != nil {
		t.Fatalf("pump pull: %v", err)
	}

	results := engine.Queue().Results()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Error != "" {
		t.Fatalf("result error: %s", res.Error)
	}
	if len(res.Output) == 0 {
		t.Fatal("result output is empty")
	}
	if res.TaskID != task.ID {
		t.Fatalf("task ID mismatch: result has %q, issued %q", res.TaskID, task.ID)
	}
	if !strings.Contains(string(res.Output), "Test 42") {
		t.Fatalf("result output missing 'Test 42': %q", res.Output)
	}
	if !strings.Contains(string(res.Output), "Hi") {
		t.Fatalf("result output missing 'Hi': %q", res.Output)
	}

	t2, ok := engine.Queue().Task(task.ID)
	if !ok {
		t.Fatalf("task %q not found in queue", task.ID)
	}
	if t2.Status != tasking.StatusComplete {
		t.Fatalf("expected task status %s, got %s", tasking.StatusComplete, t2.Status)
	}

	t.Logf("lifecycle complete: task=%s output=%q status=%s", task.ID, string(res.Output), t2.Status)
}
