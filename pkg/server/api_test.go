package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dark-arts/pkg/crypto"
	"golang.org/x/net/websocket"
)

func newAPI(t *testing.T, apiKey string) (*httptest.Server, *Engine) {
	t.Helper()
	ident, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	e := NewEngine(ident)
	ts := httptest.NewServer(NewHandler(e, apiKey, nil))
	t.Cleanup(ts.Close)
	return ts, e
}

func touchViaAPI(t *testing.T, ts *httptest.Server, key string, sid string) {
	t.Helper()
	id, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	body := `{"id":"` + sid + `","agent_pub":"` + hex.EncodeToString(id.Public()) + `"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("touch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("touch status %d", resp.StatusCode)
	}
}

func TestAPISessions(t *testing.T) {
	ts, e := newAPI(t, "")
	touchViaAPI(t, ts, "", "s1")
	got := getJSON(t, ts, "/api/v1/sessions")
	var sessions []Session
	if err := json.Unmarshal(got, &sessions); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("sessions mismatch: %+v", sessions)
	}
	_ = e
}

func TestAPIIssueTaskAndResults(t *testing.T) {
	ts, _ := newAPI(t, "")
	touchViaAPI(t, ts, "", "s1")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/tasks", strings.NewReader(`{"session_id":"s1","op_id":"op-1","type":"shell","params":{"cmd":"hostname"},"signed_by":"op-a"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue status %d", resp.StatusCode)
	}
	var task taskingTask
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if task.ID == "" || task.Type != "shell" {
		t.Fatalf("task mismatch: %+v", task)
	}

	got := getJSON(t, ts, "/api/v1/tasks")
	if !bytes.Contains(got, []byte(task.ID)) {
		t.Fatalf("task list missing task: %s", got)
	}
}

type taskingTask struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	Payload []byte `json:"payload,omitempty"`
}

func TestAPITTPS(t *testing.T) {
	ts, _ := newAPI(t, "")
	got := getJSON(t, ts, "/api/v1/ttps")
	var specs []map[string]any
	if err := json.Unmarshal(got, &specs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(specs) < 7 {
		t.Fatalf("expected >=7 ttps, got %d", len(specs))
	}
}

func TestAPIRequiresKey(t *testing.T) {
	ts, _ := newAPI(t, "sekret")
	touchViaAPI(t, ts, "sekret", "s1")

	for _, path := range []string{"/api/v1/sessions", "/api/v1/tasks", "/api/v1/results", "/api/v1/ttps"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without key: expected 401, got %d", path, resp.StatusCode)
		}
	}

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz must be public, got %d", resp.StatusCode)
	}
}

func TestWSStreamsEvents(t *testing.T) {
	ts, _ := newAPI(t, "")
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	ws, err := websocket.Dial(wsURL, "", ts.URL)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer ws.Close()

	touchViaAPI(t, ts, "", "ws-sess")

	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ev Event
	if err := websocket.JSON.Receive(ws, &ev); err != nil {
		t.Fatalf("ws receive: %v", err)
	}
	if ev.Kind != "session" {
		t.Fatalf("expected session event, got %+v", ev)
	}
}

func TestAPITouchBadInput(t *testing.T) {
	ts, _ := newAPI(t, "")
	for _, body := range []string{"not-json", `{"id":"s1","agent_pub":"zzzz-not-hex"}`} {
		resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d", body, resp.StatusCode)
		}
	}
}

func getJSON(t *testing.T, ts *httptest.Server, path string) []byte {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %s: status %d", path, resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return b
}
