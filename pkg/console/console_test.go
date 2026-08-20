package console

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"darkarts/pkg/beacon"
	"darkarts/pkg/crypto"
	"darkarts/pkg/edge"
	"darkarts/pkg/server"
	"darkarts/pkg/store"
)

func testConsole(t *testing.T) (*Client, *server.Engine) {
	t.Helper()
	ident, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("ident: %v", err)
	}
	engine := server.NewEngine(ident)
	ts := httptest.NewServer(server.NewHandler(engine, "test-key", nil))
	t.Cleanup(ts.Close)
	return New(ts.URL, "test-key"), engine
}

func TestClientHealth(t *testing.T) {
	c, _ := testConsole(t)
	if ok, err := c.Health(context.Background()); err != nil || !ok {
		t.Fatalf("health: %v %v", ok, err)
	}
}

func TestClientUnauthorized(t *testing.T) {
	ident, _ := crypto.NewIdentity()
	ts := httptest.NewServer(server.NewHandler(server.NewEngine(ident), "secret-key", nil))
	t.Cleanup(ts.Close)
	wrong := New(ts.URL, "wrong-key")
	if _, err := wrong.Sessions(context.Background()); err == nil {
		t.Fatal("wrong key must be rejected")
	}
	none := New(ts.URL, "")
	if _, err := none.Sessions(context.Background()); err == nil {
		t.Fatal("missing key must be rejected")
	}
}

func TestClientTouchAndList(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	if err := c.Touch(context.Background(), "console-sid", hexOf(agent.Public())); err != nil {
		t.Fatalf("touch: %v", err)
	}
	sessions, err := c.Sessions(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "console-sid" {
		t.Fatalf("sessions: %+v", sessions)
	}
	got, err := c.Session(context.Background(), "console-sid")
	if err != nil || got.ID != "console-sid" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if len(engine.Sessions()) != 1 {
		t.Fatal("engine must hold the session")
	}
}

func TestClientIssueTaskAndResults(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	sid := "console-task-sid"
	engine.Touch(sid, agent.Public())
	task, err := c.IssueTask(context.Background(), sid, "op-t", "shell", map[string]string{"cmd": "echo hi"}, "op-t")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if task.Type != "shell" || task.SessionID != sid {
		t.Fatalf("task: %+v", task)
	}
	tasks, err := c.Tasks(context.Background())
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks: %v %v", tasks, err)
	}
	specs, err := c.TTPs(context.Background())
	if err != nil || len(specs) == 0 {
		t.Fatalf("ttps: %v %v", specs, err)
	}
	results, err := c.Results(context.Background())
	if err != nil || len(results) != 0 {
		t.Fatalf("results: %v %v", results, err)
	}
}

func TestClientWatch(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	engine.Touch("watch-sid", agent.Public())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan server.Event, 4)
	go func() {
		c.Watch(ctx, func(ev server.Event) error {
			events <- ev
			return nil
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		engine.IssueTask("op-w", "watch-sid", "shell", map[string]string{"cmd": "echo x"}, "op-w")
		select {
		case ev := <-events:
			if ev.Kind != "task" {
				t.Fatalf("expected task event, got %+v", ev)
			}
			return
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("no task event received")
			}
		}
	}
}

func TestREPLScript(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	engine.Touch("repl-sid", agent.Public())

	script := strings.Join([]string{
		"help",
		"sessions",
		"session repl-sid",
		"ttps",
		"task repl-sid shell cmd=echo hello",
		"tasks",
		"kill repl-sid",
		"results",
		"badcmd",
		"quit",
	}, "\n") + "\n"

	var out bytes.Buffer
	repl := NewREPL(c, "op-repl", &out)
	if err := repl.Run(context.Background(), strings.NewReader(script)); err != nil {
		t.Fatalf("repl run: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"repl-sid",
		"queued ",
		"kill queued for repl-sid",
		"no results",
		`unknown command "badcmd"`,
		"sleep <sid>",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("repl output missing %q:\n%s", want, text)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestREPLWatchReceivesEvents(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	engine.Touch("repl-ev-sid", agent.Public())

	pr, pw := io.Pipe()
	var out syncBuffer
	repl := NewREPL(c, "op-repl", &out)
	done := make(chan error, 1)
	go func() { done <- repl.Run(context.Background(), pr) }()

	pw.Write([]byte("watch\n"))
	start := time.Now()
	deadline := time.Now().Add(5 * time.Second)
	issued := false
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("repl exited before event, output:\n%s", out.String())
		default:
		}
		if !issued && time.Since(start) > 750*time.Millisecond {
			engine.IssueTask("op-ev", "repl-ev-sid", "shell", map[string]string{"cmd": "echo ev"}, "op-ev")
			issued = true
		}
		if strings.Contains(out.String(), `"kind":"task"`) || strings.Contains(out.String(), "op-ev") {
			pw.Write([]byte("stop\nquit\n"))
			pw.Close()
			select {
			case <-done:
				return
			case <-time.After(2 * time.Second):
				t.Fatalf("repl did not exit after stop/quit, output:\n%s", out.String())
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("repl never printed event, output:\n%s", out.String())
}

func TestREPLWatchStop(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	engine.Touch("repl-watch-sid", agent.Public())

	script := "watch\nstop\nquit\n"
	var out bytes.Buffer
	repl := NewREPL(c, "op-repl", &out)
	if err := repl.Run(context.Background(), strings.NewReader(script)); err != nil {
		t.Fatalf("repl run: %v", err)
	}
	if !strings.Contains(out.String(), "watch stopped") {
		t.Fatalf("watch did not stop:\n%s", out.String())
	}
}

func TestREPLTaskMultiWordValue(t *testing.T) {
	c, engine := testConsole(t)
	agent, _ := crypto.NewIdentity()
	engine.Touch("repl-mw-sid", agent.Public())

	script := strings.Join([]string{
		"task repl-mw-sid shell cmd=echo hello world",
		"quit",
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := NewREPL(c, "op-repl", &out).Run(context.Background(), strings.NewReader(script)); err != nil {
		t.Fatalf("repl run: %v", err)
	}
	tasks := engine.Queue().Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	var params map[string]string
	if err := json.Unmarshal(tasks[0].Payload, &params); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if params["cmd"] != "echo hello world" {
		t.Fatalf("multi-word param lost: %+v", params)
	}
}

func TestWatchE2EWithPumpAndBeacon(t *testing.T) {
	serverIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("ident: %v", err)
	}
	agentIdent, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	engine := server.NewEngine(serverIdent)
	engine.Touch("e2e-ws-sid", agentIdent.Public())
	ts := httptest.NewServer(server.NewHandler(engine, "test-key", nil))
	t.Cleanup(ts.Close)

	edgeStore := store.NewFile(t.TempDir())
	edgeSrv := httptest.NewServer(edge.New(edgeStore, edge.Options{}).Handler())
	t.Cleanup(edgeSrv.Close)
	pump := server.NewPump(engine, edgeSrv.URL, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan server.Event, 16)
	c := New(ts.URL, "test-key")
	go func() { c.Watch(ctx, func(ev server.Event) error { events <- ev; return nil }) }()

	cfg := beaconConfigFor(t, serverIdent, agentIdent, "e2e-ws-sid", edgeSrv.URL)
	beaconInst, err := NewBeaconFor(t, cfg)
	if err != nil {
		t.Fatalf("beacon: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	var kinds []string
	for time.Now().Before(deadline) {
		engine.IssueTask("op-e2e", "e2e-ws-sid", "shell", map[string]string{"cmd": "echo ws-e2e"}, "op-e2e")
		pump.Pass(context.Background())
		beaconInst.CheckIn(ctx)
		pump.Pass(context.Background())
	drain:
		for {
			select {
			case ev := <-events:
				kinds = append(kinds, ev.Kind)
			default:
				break drain
			}
		}
		if containsString(kinds, "task") && containsString(kinds, "result") {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("ws events incomplete, saw %v", kinds)
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestPrettyOutput(t *testing.T) {
	if got := prettyOutput([]byte("hello\nworld")); got != "hello\nworld" {
		t.Fatalf("text output: %q", got)
	}
	b := []byte{0x00, 0xff, 0x01}
	if !strings.HasPrefix(prettyOutput(b), "(base64) ") {
		t.Fatalf("binary output: %q", prettyOutput(b))
	}
	if prettyOutput(nil) != "(empty)" {
		t.Fatalf("empty output: %q", prettyOutput(nil))
	}
}

func hexOf(b []byte) string {
	return hex.EncodeToString(b)
}

func beaconConfigFor(t *testing.T, serverIdent, agentIdent *crypto.Identity, sid, edgeURL string) beacon.Config {
	t.Helper()
	return beacon.Config{
		SeedHex:     hex.EncodeToString(agentIdent.PrivateSeed()),
		ServerPub:   serverIdent.Public(),
		EdgeURL:     edgeURL,
		SID:         sid,
		Sleep:       time.Second,
		TaskTimeout: 10 * time.Second,
	}
}

func NewBeaconFor(t *testing.T, cfg beacon.Config) (*beacon.Beacon, error) {
	t.Helper()
	return beacon.New(cfg)
}
