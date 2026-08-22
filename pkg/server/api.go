package server

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"dark-arts/pkg/ttp"
	"golang.org/x/net/websocket"
)

type api struct {
	e      *Engine
	apiKey string
	log    *slog.Logger
}

func NewHandler(e *Engine, apiKey string, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	a := &api{e: e, apiKey: apiKey, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /api/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		a.authorize(func() { websocket.Server{Handler: a.handleWS}.ServeHTTP(w, r) }, w, r)
	})
	mux.HandleFunc("POST /api/v1/sessions", a.requireAuth(a.handleTouchSession))
	mux.HandleFunc("GET /api/v1/sessions", a.requireAuth(a.handleListSessions))
	mux.HandleFunc("GET /api/v1/sessions/{id}", a.requireAuth(a.handleGetSession))
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", a.requireAuth(a.handleDeleteSession))
	mux.HandleFunc("POST /api/v1/tasks", a.requireAuth(a.handleIssueTask))
	mux.HandleFunc("GET /api/v1/tasks", a.requireAuth(a.handleListTasks))
	mux.HandleFunc("GET /api/v1/results", a.requireAuth(a.handleListResults))
	mux.HandleFunc("GET /api/v1/ttps", a.requireAuth(a.handleListTTPs))
	return mux
}

func (a *api) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *api) authorize(fn func(), w http.ResponseWriter, r *http.Request) {
	if a.apiKey == "" {
		fn()
		return
	}
	got := r.Header.Get("Authorization")
	got = strings.TrimPrefix(got, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.apiKey)) == 1 {
		fn()
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (a *api) requireAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.authorize(func() { fn(w, r) }, w, r)
	}
}

func (a *api) handleTouchSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"id"`
		AgentPub string `json:"agent_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pub, err := hex.DecodeString(in.AgentPub)
	if err != nil || in.ID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m := a.e.Touch(in.ID, pub)
	writeJSON(w, http.StatusOK, m)
}

func (a *api) handleListSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.e.Sessions())
}

func (a *api) handleGetSession(w http.ResponseWriter, r *http.Request) {
	m, ok := a.e.Session(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (a *api) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	if !a.e.RemoveSession(r.PathValue("id")) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleIssueTask(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionID string            `json:"session_id"`
		OpID      string            `json:"op_id"`
		Type      string            `json:"type"`
		Params    map[string]string `json:"params"`
		SignedBy  string            `json:"signed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	t, err := a.e.IssueTask(in.OpID, in.SessionID, in.Type, in.Params, in.SignedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (a *api) handleListTasks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.e.Queue().Tasks())
}

func (a *api) handleListResults(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.e.Queue().Results())
}

func (a *api) handleListTTPs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ttpSpecs())
}

func (a *api) handleWS(ws *websocket.Conn) {
	ctx := ws.Request().Context()
	ch, unsub := a.e.Hub().Subscribe(ctx)
	defer unsub()
	enc := json.NewEncoder(ws)
	for {
		select {
		case ev := <-ch:
			if err := enc.Encode(ev); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON failed", "err", err)
	}
}

type ttpSpec struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Args        []ttp.Arg `json:"args,omitempty"`
}

func ttpSpecs() []ttpSpec {
	specs := ttp.List()
	out := make([]ttpSpec, 0, len(specs))
	for _, s := range specs {
		out = append(out, ttpSpec{Name: s.Name, Description: s.Description, Args: s.Args})
	}
	return out
}
