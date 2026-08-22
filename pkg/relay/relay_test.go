package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dark-arts/pkg/beacon"
	"dark-arts/pkg/crypto"
	"dark-arts/pkg/edge"
	"dark-arts/pkg/server"
	"dark-arts/pkg/store"
	"dark-arts/pkg/tasking"
)

func envelopeBytes(t *testing.T, sid string, counter uint64, payload []byte) []byte {
	t.Helper()
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], counter)
	env := &crypto.MessageEnvelope{Version: 1, SessionID: sid, Nonce: nonce[:], Ciphertext: payload}
	b, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func postIngest(t *testing.T, ts *httptest.Server, body []byte, flow string) int {
	t.Helper()
	u := ts.URL + "/ingest"
	if flow != "" {
		u += "?f=" + flow
	}
	resp, err := http.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func getTasks(t *testing.T, ts *httptest.Server, sid string, since uint64, flow string) []json.RawMessage {
	t.Helper()
	u := fmt.Sprintf("%s/tasks/%s?since=%d&f=%s", ts.URL, sid, since, flow)
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("tasks: %v", err)
	}
	defer resp.Body.Close()
	var out []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestRelayForwardsIngestAndTasks(t *testing.T) {
	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	relayStore := store.NewFile(t.TempDir())
	relaySrv := httptest.NewServer(New(relayStore, []string{edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	body := envelopeBytes(t, "relay-1", 0, []byte("payload"))
	if code := postIngest(t, relaySrv, body, ""); code != http.StatusAccepted {
		t.Fatalf("ingest via relay: %d", code)
	}

	keys, err := edgeStore.List(context.Background(), "relay-1/beacon/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("blob must land in edge store: %v %v", keys, err)
	}
	tasks := getTasks(t, relaySrv, "relay-1", 0, "")
	if len(tasks) != 1 || !bytes.Equal(tasks[0], body) {
		t.Fatal("task fetch via relay mismatch")
	}
}

func TestRelayBuffersWhenUpstreamDown(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	edgeStore := store.NewFile(t.TempDir())
	edgeHandler := edge.New(edgeStore, edge.Options{}).Handler()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		edgeHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(fake.Close)

	relayStore := store.NewFile(t.TempDir())
	r := New(relayStore, []string{fake.URL}, Options{})
	relaySrv := httptest.NewServer(r.Handler())
	t.Cleanup(relaySrv.Close)

	body := envelopeBytes(t, "relay-buf", 0, []byte("buffered"))
	up.Store(false)
	if code := postIngest(t, relaySrv, body, "beacon"); code != http.StatusAccepted {
		t.Fatalf("ingest while upstream down: %d", code)
	}
	keys, _ := relayStore.List(context.Background(), "relay-buf/beacon/")
	if len(keys) != 1 {
		t.Fatalf("must buffer locally, keys: %v", keys)
	}
	markers, _ := relayStore.List(context.Background(), "pending/")
	if len(markers) != 1 {
		t.Fatalf("pending marker missing: %v", markers)
	}

	up.Store(true)
	if err := r.ForwardPending(context.Background()); err != nil {
		t.Fatalf("forward pending: %v", err)
	}
	edgeKeys, _ := edgeStore.List(context.Background(), "relay-buf/beacon/")
	if len(edgeKeys) != 1 {
		t.Fatalf("buffered item must reach edge after recovery, keys: %v", edgeKeys)
	}
	markers, _ = relayStore.List(context.Background(), "pending/")
	if len(markers) != 0 {
		t.Fatalf("pending markers must be cleared, got %v", markers)
	}
}

func TestRelayForwardsDelete(t *testing.T) {
	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	relayStore := store.NewFile(t.TempDir())
	relaySrv := httptest.NewServer(New(relayStore, []string{edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	body := envelopeBytes(t, "relay-del", 2, []byte("payload"))
	if code := postIngest(t, relaySrv, body, "server"); code != http.StatusAccepted {
		t.Fatalf("ingest via relay: %d", code)
	}
	if keys, _ := edgeStore.List(context.Background(), "relay-del/server/"); len(keys) != 1 {
		t.Fatalf("blob must land in edge store: %v", keys)
	}

	req, err := http.NewRequest(http.MethodDelete, relaySrv.URL+"/tasks/relay-del/00000000000000000002?f=server", nil)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	if keys, _ := edgeStore.List(context.Background(), "relay-del/server/"); len(keys) != 0 {
		t.Fatalf("blob must be deleted from edge store: %v", keys)
	}
}

func TestRelayDeleteClearsLocalBuffer(t *testing.T) {
	var up atomic.Bool
	up.Store(false)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(fake.Close)

	relayStore := store.NewFile(t.TempDir())
	r := New(relayStore, []string{fake.URL}, Options{})
	relaySrv := httptest.NewServer(r.Handler())
	t.Cleanup(relaySrv.Close)

	body := envelopeBytes(t, "relay-buf-del", 1, []byte("buffered"))
	if code := postIngest(t, relaySrv, body, "server"); code != http.StatusAccepted {
		t.Fatalf("ingest while upstream down: %d", code)
	}
	if keys, _ := relayStore.List(context.Background(), "relay-buf-del/server/"); len(keys) != 1 {
		t.Fatalf("must buffer locally: %v", keys)
	}

	req, err := http.NewRequest(http.MethodDelete, relaySrv.URL+"/tasks/relay-buf-del/00000000000000000001?f=server", nil)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	if keys, _ := relayStore.List(context.Background(), "relay-buf-del/server/"); len(keys) != 0 {
		t.Fatalf("buffered blob must be purged: %v", keys)
	}
	markers, _ := relayStore.List(context.Background(), "pending/")
	if len(markers) != 0 {
		t.Fatalf("pending marker must be purged: %v", markers)
	}
}

func TestRelayTasksMergeLocalAndUpstream(t *testing.T) {
	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	relayStore := store.NewFile(t.TempDir())
	relaySrv := httptest.NewServer(New(relayStore, []string{edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	upstreamBody := envelopeBytes(t, "relay-merge", 1, []byte("from-upstream"))
	if code := postIngest(t, edgeSrv, upstreamBody, "beacon"); code != http.StatusAccepted {
		t.Fatalf("seed edge: %d", code)
	}
	localBody := envelopeBytes(t, "relay-merge", 0, []byte("buffered-local"))
	relayStore.Put(context.Background(), "relay-merge/beacon/0000000000000000", localBody)

	tasks := getTasks(t, relaySrv, "relay-merge", 0, "beacon")
	if len(tasks) != 2 {
		t.Fatalf("expected merged 2 tasks, got %d", len(tasks))
	}
	if !bytes.Equal(tasks[0], localBody) || !bytes.Equal(tasks[1], upstreamBody) {
		t.Fatal("merge order/content mismatch")
	}
}

func TestRelayTasksUpstreamDownServesLocal(t *testing.T) {
	relayStore := store.NewFile(t.TempDir())
	relaySrv := httptest.NewServer(New(relayStore, []string{"http://127.0.0.1:1"}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	localBody := envelopeBytes(t, "relay-down", 0, []byte("served-locally"))
	relayStore.Put(context.Background(), "relay-down/beacon/0000000000000000", localBody)

	tasks := getTasks(t, relaySrv, "relay-down", 0, "beacon")
	if len(tasks) != 1 || !bytes.Equal(tasks[0], localBody) {
		t.Fatal("must serve local buffer when upstream unreachable")
	}
}

func TestRelayRejectsMalformed(t *testing.T) {
	edgeSrv := httptest.NewServer(edge.New(store.NewFile(t.TempDir()), edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	relaySrv := httptest.NewServer(New(store.NewFile(t.TempDir()), []string{edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	for _, body := range []string{"garbage", `{"v":1,"sid":"s","nonce":"c2hvcnQ=","data":"eA=="}`} {
		if code := postIngest(t, relaySrv, []byte(body), ""); code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d", body, code)
		}
	}
	if code := postIngest(t, relaySrv, envelopeBytes(t, "s", 0, []byte("x")), "bogus"); code != http.StatusBadRequest {
		t.Fatalf("bad flow must be rejected, got %d", code)
	}
}

func TestRelayE2EAsyncLoop(t *testing.T) {
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server ident: %v", err)
	}
	agentIdent, err := crypto.IdentityFromSeed(bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatalf("agent ident: %v", err)
	}
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())

	edgeSrv := httptest.NewServer(edge.New(store.NewFile(t.TempDir()), edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	relaySrv := httptest.NewServer(New(store.NewFile(t.TempDir()), []string{edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	pump := server.NewPump(engine, edgeSrv.URL, nil)
	b, err := beaconNew(t, serverIdent, agentIdent, relaySrv.URL, sid)
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	task, err := engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "echo relay-e2e-ok"}, "op-a")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pump.Pass(context.Background())
	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("beacon check-in: %v", err)
	}
	pump.Pass(context.Background())

	results := engine.Queue().Results()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !strings.Contains(string(results[0].Output), "relay-e2e-ok") {
		t.Fatalf("result mismatch: %q", results[0].Output)
	}
	if results[0].TaskID != task.ID {
		t.Fatalf("task id mismatch: %s", results[0].TaskID)
	}
	if t2, _ := engine.Queue().Task(task.ID); t2.Status != tasking.StatusComplete {
		t.Fatalf("task status: %s", t2.Status)
	}
}

func TestRelayFailoverBetweenUpstreams(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(dead.Close)

	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	relaySrv := httptest.NewServer(New(store.NewFile(t.TempDir()), []string{dead.URL, edgeSrv.URL}, Options{}).Handler())
	t.Cleanup(relaySrv.Close)

	body := envelopeBytes(t, "relay-failover", 0, []byte("x"))
	if code := postIngest(t, relaySrv, body, ""); code != http.StatusAccepted {
		t.Fatalf("ingest: %d", code)
	}
	keys, _ := edgeStore.List(context.Background(), "relay-failover/beacon/")
	if len(keys) != 1 {
		t.Fatal("must fail over to the healthy upstream")
	}
}

func beaconNew(t *testing.T, serverIdent, agentIdent *crypto.Identity, edgeURL, sid string) (*beacon.Beacon, error) {
	t.Helper()
	return beacon.New(beacon.Config{
		SeedHex:   hex.EncodeToString(agentIdent.PrivateSeed()),
		ServerPub: serverIdent.Public(),
		EdgeURL:   edgeURL,
		SID:       sid,
		Sleep:     1 * time.Second,
		Jitter:    0,
	})
}
