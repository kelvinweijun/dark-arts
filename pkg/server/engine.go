package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/tasking"
	"dark-arts/pkg/ttp"
)

var errNoSession = errors.New("server: unknown session")

type Session struct {
	ID        string    `json:"id"`
	AgentPub  string    `json:"agent_pub"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Beacons   uint64    `json:"beacons"`
}

type Event struct {
	Kind string          `json:"kind"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

func (h *Hub) Subscribe(ctx context.Context) (<-chan Event, func()) {
	ch := make(chan Event, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		h.mu.Lock()
		delete(h.subs, ch)
		close(ch)
		h.mu.Unlock()
	}()
	return ch, func() { close(done) }
}

func (h *Hub) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

type Engine struct {
	mu        sync.RWMutex
	stateMu   sync.Mutex
	ident     *crypto.Identity
	crypt     map[string]*crypto.Session
	meta      map[string]*Session
	queue     *tasking.Queue
	hub       *Hub
	statePath string
	startSend map[string]uint64
}

func NewEngine(ident *crypto.Identity) *Engine {
	return NewEngineWithState(ident, "")
}

func NewEngineWithState(ident *crypto.Identity, statePath string) *Engine {
	e := &Engine{
		ident:     ident,
		crypt:     make(map[string]*crypto.Session),
		meta:      make(map[string]*Session),
		queue:     tasking.NewQueue(),
		hub:       NewHub(),
		statePath: statePath,
		startSend: map[string]uint64{},
	}
	if statePath != "" {
		if b, err := os.ReadFile(statePath); err == nil {
			e.loadState(b)
		}
	}
	return e
}

type engineState struct {
	Send     map[string]uint64 `json:"send,omitempty"`
	Sessions map[string]string `json:"sessions,omitempty"`
}

func (e *Engine) loadState(b []byte) {
	var st engineState
	if err := json.Unmarshal(b, &st); err != nil || st.Send == nil {
		var legacy map[string]uint64
		if json.Unmarshal(b, &legacy) == nil {
			e.startSend = legacy
		}
		return
	}
	e.startSend = st.Send
	for sid, pubHex := range st.Sessions {
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			continue
		}
		e.replaySession(sid, pub)
	}
}

func (e *Engine) replaySession(sid string, agentPub []byte) {
	cs, err := crypto.NewSession(e.ident, agentPub, sid, crypto.RoleServer)
	if err != nil {
		return
	}
	cs.SkipSend(e.startSend[sid])
	now := time.Now().UTC()
	e.mu.Lock()
	e.crypt[sid] = cs
	e.meta[sid] = &Session{ID: sid, AgentPub: hex.EncodeToString(agentPub), FirstSeen: now, LastSeen: now}
	e.mu.Unlock()
}

func (e *Engine) SaveState() error {
	// Serialize state writes: Touch saves asynchronously while Encrypt saves
	// synchronously, and a stale async snapshot landing last would persist an
	// outdated send counter (Windows rename is replace-style, so last wins).
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.mu.RLock()
	st := engineState{
		Send:     make(map[string]uint64, len(e.crypt)),
		Sessions: make(map[string]string, len(e.meta)),
	}
	for sid, cs := range e.crypt {
		st.Send[sid] = cs.SendPos()
	}
	for sid, m := range e.meta {
		st.Sessions[sid] = m.AgentPub
	}
	e.mu.RUnlock()
	if e.statePath == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.statePath), 0o755); err != nil {
		return err
	}
	tmp := e.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.statePath)
}

func (e *Engine) Hub() *Hub             { return e.hub }
func (e *Engine) Queue() *tasking.Queue { return e.queue }

func (e *Engine) Touch(sid string, agentPub []byte) *Session {
	now := time.Now().UTC()
	pubHex := hex.EncodeToString(agentPub)
	e.mu.Lock()
	defer e.mu.Unlock()

	m := e.meta[sid]
	rotated := false
	if m == nil {
		m = &Session{ID: sid, AgentPub: pubHex, FirstSeen: now}
		e.meta[sid] = m
	} else if m.AgentPub != pubHex {
		m.AgentPub = pubHex
		rotated = true
	}
	m.LastSeen = now
	m.Beacons++

	if _, ok := e.crypt[sid]; !ok || rotated {
		if cs, err := crypto.NewSession(e.ident, agentPub, sid, crypto.RoleServer); err == nil {
			cs.SkipSend(e.startSend[sid])
			e.crypt[sid] = cs
		}
	}
	e.hub.Publish(Event{Kind: "session", Data: mustJSON(m)})
	go e.SaveState()
	return m
}

func (e *Engine) Sessions() []*Session {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Session, 0, len(e.meta))
	for _, m := range e.meta {
		out = append(out, m)
	}
	return out
}

func (e *Engine) Session(id string) (*Session, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.meta[id]
	return m, ok
}

func (e *Engine) RemoveSession(sid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.meta[sid]; !ok {
		return false
	}
	delete(e.meta, sid)
	delete(e.crypt, sid)
	delete(e.startSend, sid)
	e.queue.DropSession(sid)
	go e.SaveState()
	return true
}

func (e *Engine) IssueTask(opID, sid, taskType string, params map[string]string, signedBy string) (*tasking.Task, error) {
	if _, ok := e.Session(sid); !ok {
		return nil, fmt.Errorf("server: unknown session %q: register the session first", sid)
	}
	payload, err := ttp.Generate(taskType, params)
	if err != nil {
		return nil, err
	}
	t := &tasking.Task{
		OpID:      opID,
		SessionID: sid,
		Type:      taskType,
		Payload:   payload,
		SignedBy:  signedBy,
	}
	if err := e.queue.Enqueue(sid, t); err != nil {
		return nil, err
	}
	e.hub.Publish(Event{Kind: "task", Data: mustJSON(t)})
	return t, nil
}

func (e *Engine) Encrypt(sid string, t *tasking.Task) ([]byte, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	cs, err := e.cryptSession(sid)
	if err != nil {
		return nil, err
	}
	env, err := cs.Encrypt(raw)
	if err != nil {
		return nil, err
	}
	e.SaveState()
	return env.Marshal()
}

func (e *Engine) IngestEnvelope(sid string, envBytes []byte) error {
	env, err := crypto.UnmarshalEnvelope(envBytes)
	if err != nil {
		return err
	}
	cs, err := e.cryptSession(sid)
	if err != nil {
		return err
	}
	plain, err := cs.Decrypt(env)
	if err != nil {
		return err
	}
	var res tasking.Result
	if err := json.Unmarshal(plain, &res); err != nil {
		return err
	}
	if res.SessionID == "" {
		res.SessionID = sid
	}
	e.queue.Result(&res)
	e.hub.Publish(Event{Kind: "result", Data: mustJSON(&res)})
	return nil
}

func (e *Engine) DropSession(sid string) {
	e.queue.DropSession(sid)
}

func (e *Engine) cryptSession(sid string) (*crypto.Session, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cs, ok := e.crypt[sid]
	if !ok {
		return nil, errNoSession
	}
	return cs, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
