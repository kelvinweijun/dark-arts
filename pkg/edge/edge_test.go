package edge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"darkarts/pkg/crypto"
	"darkarts/pkg/store"
)

func newTestServer(t *testing.T, st store.Store) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(New(st, Options{}).Handler())
	t.Cleanup(ts.Close)
	return ts
}

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

func ingest(t *testing.T, ts *httptest.Server, body []byte) int {
	return ingestFlow(t, ts, body, "")
}

func ingestFlow(t *testing.T, ts *httptest.Server, body []byte, flow string) int {
	t.Helper()
	url := ts.URL + "/ingest"
	if flow != "" {
		url += "?f=" + flow
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func fetchTasks(t *testing.T, ts *httptest.Server, sid string, since uint64) []json.RawMessage {
	return fetchFlow(t, ts, sid, since, "")
}

func fetchFlow(t *testing.T, ts *httptest.Server, sid string, since uint64, flow string) []json.RawMessage {
	t.Helper()
	url := fmt.Sprintf("%s/tasks/%s?since=%d", ts.URL, sid, since)
	if flow != "" {
		url += "&f=" + flow
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()
	var out []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestIngestAndFetch(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	envelopes := [][]byte{
		envelopeBytes(t, "s1", 0, []byte("a")),
		envelopeBytes(t, "s1", 1, []byte("b")),
		envelopeBytes(t, "s1", 2, []byte("c")),
	}
	for _, e := range envelopes {
		if code := ingest(t, ts, e); code != http.StatusAccepted {
			t.Fatalf("ingest status %d", code)
		}
	}

	all := fetchTasks(t, ts, "s1", 0)
	if len(all) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(all))
	}
	if !bytesEqual(all[0], envelopes[0]) || !bytesEqual(all[2], envelopes[2]) {
		t.Fatal("envelope mismatch")
	}

	since := fetchTasks(t, ts, "s1", 1)
	if len(since) != 2 {
		t.Fatalf("expected 2 tasks since=1, got %d", len(since))
	}
	if !bytesEqual(since[0], envelopes[1]) {
		t.Fatal("since filter wrong")
	}
}

func TestDeleteTaskBlob(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	if code := ingestFlow(t, ts, envelopeBytes(t, "s1", 3, []byte("beacon-result")), "beacon"); code != http.StatusAccepted {
		t.Fatalf("ingest status %d", code)
	}
	if code := ingestFlow(t, ts, envelopeBytes(t, "s1", 3, []byte("server-task")), "server"); code != http.StatusAccepted {
		t.Fatalf("ingest status %d", code)
	}

	del := func(url string) int {
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			t.Fatalf("delete request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := del(ts.URL + "/tasks/s1/00000000000000000003?f=beacon"); code != http.StatusNoContent {
		t.Fatalf("beacon flow delete status %d", code)
	}
	if got := fetchFlow(t, ts, "s1", 0, "beacon"); len(got) != 0 {
		t.Fatalf("beacon flow must be empty after delete, got %d", len(got))
	}
	if got := fetchFlow(t, ts, "s1", 0, "server"); len(got) != 1 {
		t.Fatalf("server flow must be untouched, got %d", len(got))
	}
	if code := del(ts.URL + "/tasks/s1/00000000000000000003?f=beacon"); code != http.StatusNoContent {
		t.Fatalf("repeated delete must be idempotent, got %d", code)
	}
	if code := del(ts.URL + "/tasks/s1/xyz?f=beacon"); code != http.StatusBadRequest {
		t.Fatalf("bad counter must be rejected, got %d", code)
	}
	if code := del(ts.URL + "/tasks/s1/00000000000000000003?f=bogus"); code != http.StatusBadRequest {
		t.Fatalf("bad flow must be rejected, got %d", code)
	}
	if code := del(ts.URL + "/tasks/s1/00000000000000000003"); code != http.StatusNoContent {
		t.Fatalf("default flow delete status %d", code)
	}
}

func TestFlowNamespaceIsolation(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	beacon := envelopeBytes(t, "s1", 0, []byte("beacon-result"))
	server := envelopeBytes(t, "s1", 0, []byte("server-task"))
	if code := ingestFlow(t, ts, beacon, ""); code != http.StatusAccepted {
		t.Fatalf("beacon ingest status %d", code)
	}
	if code := ingestFlow(t, ts, server, "server"); code != http.StatusAccepted {
		t.Fatalf("server ingest status %d", code)
	}

	beaconSide := fetchFlow(t, ts, "s1", 0, "beacon")
	serverSide := fetchFlow(t, ts, "s1", 0, "server")
	if len(beaconSide) != 1 || !bytesEqual(beaconSide[0], beacon) {
		t.Fatal("beacon flow must see only beacon envelopes")
	}
	if len(serverSide) != 1 || !bytesEqual(serverSide[0], server) {
		t.Fatal("server flow must see only server envelopes")
	}
	if code := ingestFlow(t, ts, beacon, "bogus"); code != http.StatusBadRequest {
		t.Fatalf("bad flow must be rejected, got %d", code)
	}
}

func bytesEqual(a, b []byte) bool {
	return string(a) == string(b)
}

func TestIngestLandsInStore(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	body := envelopeBytes(t, "s2", 3, []byte("x"))
	if code := ingest(t, ts, body); code != http.StatusAccepted {
		t.Fatalf("ingest status %d", code)
	}
	got, err := st.Get(t.Context(), fmt.Sprintf("s2/%s/%020d", "beacon", 3))
	if err != nil {
		t.Fatalf("blob not in store: %v", err)
	}
	if !bytesEqual(got, body) {
		t.Fatal("stored blob mismatch")
	}
}

func TestStatelessAcrossInstances(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts1 := newTestServer(t, st)
	ts2 := newTestServer(t, st)

	body := envelopeBytes(t, "s3", 0, []byte("y"))
	if code := ingest(t, ts1, body); code != http.StatusAccepted {
		t.Fatalf("ingest via ts1: %d", code)
	}
	tasks := fetchTasks(t, ts2, "s3", 0)
	if len(tasks) != 1 || !bytesEqual(tasks[0], body) {
		t.Fatal("second instance must observe the same data (no local state)")
	}
}

func TestIngestRejectsMalformed(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	cases := map[string]string{
		"garbage":   "not json",
		"null":      "null",
		"bad nonce": string(envelopeBytes(t, "s4", 0, []byte("x"))[:10]) + strings.Repeat("0", 40),
		"empty ciphertext": func() string {
			env := crypto.MessageEnvelope{Version: 1, SessionID: "s4", Nonce: make([]byte, 12)}
			b, _ := env.Marshal()
			return string(b)
		}(),
		"bad sid": string(envelopeBytes(t, "../evil", 0, []byte("x"))),
	}
	for name, body := range cases {
		if code := ingest(t, ts, []byte(body)); code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", name, code)
		}
	}
}

func TestIngestRejectsOversize(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := httptest.NewServer(New(st, Options{MaxBody: 1024}).Handler())
	t.Cleanup(ts.Close)

	body := envelopeBytes(t, "big", 0, make([]byte, 4096))
	if code := ingest(t, ts, body); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", code)
	}
}

func TestTasksUnknownSession(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)
	tasks := fetchTasks(t, ts, "does-not-exist", 0)
	if len(tasks) != 0 {
		t.Fatalf("expected empty task list, got %d", len(tasks))
	}
}

func TestHealthz(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("healthz: status %d body %q", resp.StatusCode, b)
	}
	if got := resp.Header.Get("Server"); got != "nginx" {
		t.Fatalf("server header %q, want nginx", got)
	}
}

func TestCoverServesPage(t *testing.T) {
	ts := newTestServer(t, store.NewFile(t.TempDir()))
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cover status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Kraus &amp; Brandt") {
		t.Fatal("cover page missing expected content")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("cover content type %q", ct)
	}
}

func TestCoverCustomHTML(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := httptest.NewServer(New(st, Options{CoverHTML: "<html><title>café</title></html>"}).Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "café") {
		t.Fatal("custom cover not served")
	}
}

func TestCoverUnknownPathIsNginx404(t *testing.T) {
	ts := newTestServer(t, store.NewFile(t.TempDir()))
	for _, path := range []string{"/assets/style.css", "/admin/", "/wp-login.php"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status %d", path, resp.StatusCode)
		}
		if !strings.Contains(string(body), "nginx/1.27.4") {
			t.Fatalf("%s 404 body not nginx-style", path)
		}
	}
}

func TestCoverDoesNotBreakAPI(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)
	body := envelopeBytes(t, "cover-api", 0, []byte("hello"))
	if code := ingest(t, ts, body); code != http.StatusAccepted {
		t.Fatalf("ingest with cover: %d", code)
	}
	if got := fetchTasks(t, ts, "cover-api", 0); len(got) != 1 || !bytesEqual(got[0], body) {
		t.Fatal("task fetch with cover broken")
	}
}

func TestNoPlaintextInStore(t *testing.T) {
	st := store.NewFile(t.TempDir())
	ts := newTestServer(t, st)

	agent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	server, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	agentSess, err := crypto.NewSession(agent, server.Public(), "marker-test", crypto.RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	serverSess, err := crypto.NewSession(server, agent.Public(), "marker-test", crypto.RoleServer)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}

	marker := "SUPER_SECRET_BEACON_PAYLOAD_9f7a"
	env, err := agentSess.Encrypt([]byte(marker))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := serverSess.Decrypt(env)
	if err != nil || string(plain) != marker {
		t.Fatalf("session pair invalid: %q %v", plain, err)
	}
	body, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if code := ingest(t, ts, body); code != http.StatusAccepted {
		t.Fatalf("ingest status %d", code)
	}

	blob, err := st.Get(t.Context(), fmt.Sprintf("marker-test/%s/%020d", "beacon", 0))
	if err != nil {
		t.Fatalf("blob missing: %v", err)
	}
	if bytes.Contains(blob, []byte(marker)) {
		t.Fatal("plaintext marker leaked into stored blob")
	}

	keys, err := st.List(t.Context(), "marker-test/beacon/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected exactly 1 blob, got %v err %v", keys, err)
	}
}
