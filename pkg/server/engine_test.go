package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/tasking"
)

func testPair(t *testing.T) (*Engine, *crypto.Identity, *crypto.Session) {
	t.Helper()
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	agentIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	e := NewEngine(serverIdent)
	sess, err := crypto.NewSession(agentIdent, serverIdent.Public(), "sid-1", crypto.RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	e.Touch("sid-1", agentIdent.Public())
	return e, agentIdent, sess
}

func TestTouchCreatesSession(t *testing.T) {
	e, agentIdent, _ := testPair(t)
	m, ok := e.Session("sid-1")
	if !ok {
		t.Fatal("session not created")
	}
	if m.ID != "sid-1" || m.Beacons != 1 || m.AgentPub != hex.EncodeToString(agentIdent.Public()) {
		t.Fatalf("session mismatch: %+v", m)
	}
	if len(e.Sessions()) != 1 {
		t.Fatalf("expected 1 session, got %d", len(e.Sessions()))
	}
	e.Touch("sid-1", agentIdent.Public())
	if m := e.Sessions()[0]; m.Beacons != 2 {
		t.Fatalf("expected 2 beacons, got %d", m.Beacons)
	}
}

func TestTouchRotatedKeyRecreatesSession(t *testing.T) {
	e, _, _ := testPair(t)
	other, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	e.Touch("sid-1", other.Public())
	if m := e.Sessions()[0]; m.AgentPub != hex.EncodeToString(other.Public()) {
		t.Fatalf("agent pub not rotated: %s", m.AgentPub)
	}
}

func TestIssueTaskRoundTrip(t *testing.T) {
	e, _, agentSess := testPair(t)
	task, err := e.IssueTask("op-1", "sid-1", "shell", map[string]string{"cmd": "whoami"}, "op-a")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if task.ID == "" || task.Status != tasking.StatusQueued {
		t.Fatalf("task not queued: %+v", task)
	}

	envBytes, err := e.Encrypt("sid-1", task)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env, err := crypto.UnmarshalEnvelope(envBytes)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	plain, err := agentSess.Decrypt(env)
	if err != nil {
		t.Fatalf("agent decrypt: %v", err)
	}
	var got tasking.Task
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal task: %v", err)
	}
	if got.ID != task.ID || got.Type != "shell" || string(got.Payload) != `{"cmd":"whoami"}` {
		t.Fatalf("task mismatch: %+v", got)
	}

	resEnv, err := agentSess.Encrypt([]byte(`{"task_id":"` + task.ID + `","session_id":"sid-1","output":"YWRtaW4="}`))
	if err != nil {
		t.Fatalf("agent result encrypt: %v", err)
	}
	resBytes, err := resEnv.Marshal()
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := e.IngestEnvelope("sid-1", resBytes); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	rs := e.Queue().Results()
	if len(rs) != 1 || string(rs[0].Output) != "admin" || rs[0].TaskID != task.ID {
		t.Fatalf("result mismatch: %+v", rs)
	}
	task2, _ := e.Queue().Task(task.ID)
	if task2.Status != tasking.StatusComplete {
		t.Fatalf("expected complete, got %s", task2.Status)
	}
}

func TestEngineStateSurvivesRestart(t *testing.T) {
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	agentIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")

	e1 := NewEngineWithState(serverIdent, statePath)
	e1.Touch("restart-sid", agentIdent.Public())
	task1, err := e1.IssueTask("op-1", "restart-sid", "shell", map[string]string{"cmd": "one"}, "op-a")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	env1, err := e1.Encrypt("restart-sid", task1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env1Parsed, _ := crypto.UnmarshalEnvelope(env1)
	if counter := binary.BigEndian.Uint64(env1Parsed.Nonce[:8]); counter != 0 {
		t.Fatalf("first task counter %d", counter)
	}

	e2 := NewEngineWithState(serverIdent, statePath)
	e2.Touch("restart-sid", agentIdent.Public())
	task2, err := e2.IssueTask("op-2", "restart-sid", "shell", map[string]string{"cmd": "two"}, "op-a")
	if err != nil {
		t.Fatalf("issue after restart: %v", err)
	}
	env2, err := e2.Encrypt("restart-sid", task2)
	if err != nil {
		t.Fatalf("encrypt after restart: %v", err)
	}
	env2Parsed, _ := crypto.UnmarshalEnvelope(env2)
	if counter := binary.BigEndian.Uint64(env2Parsed.Nonce[:8]); counter != 1 {
		t.Fatalf("task counter after restart = %d, want 1 (no reuse)", counter)
	}

	agentSess, err := crypto.NewSession(agentIdent, serverIdent.Public(), "restart-sid", crypto.RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	plain, err := agentSess.Decrypt(env2Parsed)
	if err != nil {
		t.Fatalf("agent cannot decrypt post-restart task: %v", err)
	}
	var got tasking.Task
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != task2.ID {
		t.Fatalf("post-restart task mismatch: %+v", got)
	}
}

func TestEngineStateReplaysSessions(t *testing.T) {
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	agentIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")

	e1 := NewEngineWithState(serverIdent, statePath)
	e1.Touch("replay-sid", agentIdent.Public())
	task1, err := e1.IssueTask("op-1", "replay-sid", "shell", map[string]string{"cmd": "one"}, "op-a")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	env1, err := e1.Encrypt("replay-sid", task1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env1Parsed, _ := crypto.UnmarshalEnvelope(env1)
	if counter := binary.BigEndian.Uint64(env1Parsed.Nonce[:8]); counter != 0 {
		t.Fatalf("first task counter %d", counter)
	}

	e2 := NewEngineWithState(serverIdent, statePath)
	if got := len(e2.Sessions()); got != 1 {
		t.Fatalf("expected 1 replayed session, got %d", got)
	}
	if _, ok := e2.Session("replay-sid"); !ok {
		t.Fatal("replayed session missing")
	}
	task2, err := e2.IssueTask("op-2", "replay-sid", "shell", map[string]string{"cmd": "two"}, "op-a")
	if err != nil {
		t.Fatalf("issue after replay: %v", err)
	}
	env2, err := e2.Encrypt("replay-sid", task2)
	if err != nil {
		t.Fatalf("encrypt after replay: %v", err)
	}
	env2Parsed, _ := crypto.UnmarshalEnvelope(env2)
	if counter := binary.BigEndian.Uint64(env2Parsed.Nonce[:8]); counter != 1 {
		t.Fatalf("task counter after replay = %d, want 1 (no reuse)", counter)
	}

	agentSess, err := crypto.NewSession(agentIdent, serverIdent.Public(), "replay-sid", crypto.RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	plain, err := agentSess.Decrypt(env2Parsed)
	if err != nil {
		t.Fatalf("agent cannot decrypt post-replay task: %v", err)
	}
	var got tasking.Task
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != task2.ID {
		t.Fatalf("post-replay task mismatch: %+v", got)
	}
}

func TestIssueTaskUnknownTTP(t *testing.T) {
	e, _, _ := testPair(t)
	if _, err := e.IssueTask("op-1", "sid-1", "does-not-exist", nil, "op-a"); err == nil {
		t.Fatal("unknown ttp must fail")
	}
}

func TestIssueTaskUnknownSession(t *testing.T) {
	e, _, _ := testPair(t)
	if _, err := e.IssueTask("op-1", "ghost", "shell", map[string]string{"cmd": "whoami"}, "op-a"); err == nil {
		t.Fatal("task for unknown session must fail")
	}
}

func TestEncryptUnknownSession(t *testing.T) {
	e, _, _ := testPair(t)
	if _, err := e.Encrypt("ghost", &tasking.Task{Type: "shell"}); err == nil {
		t.Fatal("encrypt for unknown session must fail")
	}
	if err := e.IngestEnvelope("ghost", []byte("{}")); err == nil {
		t.Fatal("ingest for unknown session must fail")
	}
}

func TestIngestEnvelopeTamperedRejected(t *testing.T) {
	e, _, agentSess := testPair(t)
	env, _ := agentSess.Encrypt([]byte(`{"task_id":"t","session_id":"sid-1","output":"x"}`))
	b, _ := env.Marshal()
	b[len(b)-1] ^= 0xff
	if err := e.IngestEnvelope("sid-1", b); err == nil {
		t.Fatal("tampered envelope must be rejected")
	}
}

func TestHubPublishSubscribe(t *testing.T) {
	e, _, _ := testPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, unsub := e.Hub().Subscribe(ctx)
	defer unsub()
	other, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	e.Touch("sid-2", other.Public())
	select {
	case ev := <-ch:
		if ev.Kind != "session" {
			t.Fatalf("expected session event, got %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}
