package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/mesh"
	"dark-arts/pkg/store"
)

var sidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

const maxBody = 1 << 20

type Options struct {
	MaxBody int64
	Retry   time.Duration
	Logger  *slog.Logger
	Client  *http.Client
}

type Relay struct {
	store  store.Store
	router *mesh.Router
	client *http.Client
	opts   Options
}

func New(st store.Store, upstreams []string, opts Options) *Relay {
	if opts.MaxBody <= 0 {
		opts.MaxBody = maxBody
	}
	if opts.Retry <= 0 {
		opts.Retry = 30 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Relay{
		store:  st,
		router: mesh.NewRouter(upstreams...),
		client: client,
		opts:   opts,
	}
}

func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", r.handleIngest)
	mux.HandleFunc("GET /tasks/{sid}", r.handleTasks)
	mux.HandleFunc("DELETE /tasks/{sid}/{counter}", r.handleDelete)
	mux.HandleFunc("GET /healthz", r.handleHealth)
	return mux
}

func (r *Relay) handleHealth(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "ok")
}

func (r *Relay) handleIngest(w http.ResponseWriter, req *http.Request) {
	flow, ok := flowName(req.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, r.opts.MaxBody+1))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > r.opts.MaxBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	env, err := crypto.UnmarshalEnvelope(body)
	if err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}
	if len(env.Nonce) != 12 || len(env.Ciphertext) == 0 {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return
	}
	if !sidRe.MatchString(env.SessionID) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	counter := binary.BigEndian.Uint64(env.Nonce[:8])
	key := fmt.Sprintf("%s/%s/%020d", env.SessionID, flow, counter)

	if !r.forward(req.Context(), http.MethodPost, "/ingest?f="+flow, body) {
		if err := r.store.Put(req.Context(), key, body); err != nil {
			r.opts.Logger.Error("relay: buffer failed", "key", key, "err", err)
			http.Error(w, "buffer failed", http.StatusInternalServerError)
			return
		}
		if err := r.store.Put(req.Context(), "pending/"+encodeKey(key), nil); err != nil {
			r.opts.Logger.Error("relay: pending marker failed", "key", key, "err", err)
		}
		r.opts.Logger.Warn("relay: upstream unreachable, buffered", "key", key)
	}
	r.opts.Logger.Info("relay: ingested", "sid", env.SessionID, "flow", flow, "counter", counter)
	w.WriteHeader(http.StatusAccepted)
}

func (r *Relay) handleDelete(w http.ResponseWriter, req *http.Request) {
	sid := req.PathValue("sid")
	if !sidRe.MatchString(sid) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	flow, ok := flowName(req.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	counter, err := strconv.ParseUint(req.PathValue("counter"), 10, 64)
	if err != nil {
		http.Error(w, "bad counter", http.StatusBadRequest)
		return
	}
	key := fmt.Sprintf("%s/%s/%020d", sid, flow, counter)
	path := fmt.Sprintf("/tasks/%s/%020d?f=%s", url.PathEscape(sid), counter, flow)
	if !r.forward(req.Context(), http.MethodDelete, path, nil) {
		r.opts.Logger.Warn("relay: upstream delete failed", "key", key)
	}
	r.store.Delete(req.Context(), key)
	r.store.Delete(req.Context(), "pending/"+encodeKey(key))
	r.opts.Logger.Info("relay: deleted", "key", key)
	w.WriteHeader(http.StatusNoContent)
}

func (r *Relay) handleTasks(w http.ResponseWriter, req *http.Request) {
	sid := req.PathValue("sid")
	if !sidRe.MatchString(sid) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	flow, ok := flowName(req.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	since := uint64(0)
	if q := req.URL.Query().Get("since"); q != "" {
		v, err := strconv.ParseUint(q, 10, 64)
		if err != nil {
			http.Error(w, "bad since", http.StatusBadRequest)
			return
		}
		since = v
	}

	local := r.localItems(req.Context(), sid, flow, since)
	upstream := r.forwardTasks(req.Context(), sid, flow, since)
	merged := mergeItems(local, upstream)
	if merged == nil {
		merged = local
	}

	out := make([]json.RawMessage, 0, len(merged))
	for _, it := range merged {
		out = append(out, it.raw)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (r *Relay) forward(ctx context.Context, method, path string, body []byte) bool {
	for attempts := 0; attempts < 2*len(r.router.List()); attempts++ {
		addr, ok := r.router.Next()
		if !ok {
			return false
		}
		if r.do(ctx, method, addr, path, body) {
			return true
		}
		r.router.MarkDown(addr, 30*time.Second)
	}
	return false
}

func (r *Relay) forwardAll(ctx context.Context, method, path string, body []byte) bool {
	for _, addr := range r.router.List() {
		if r.do(ctx, method, addr, path, body) {
			return true
		}
	}
	return false
}

func (r *Relay) do(ctx context.Context, method, addr, path string, body []byte) bool {
	u := addr + path
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

type item struct {
	counter uint64
	raw     json.RawMessage
}

func (r *Relay) localItems(ctx context.Context, sid, flow string, since uint64) []item {
	prefix := sid + "/" + flow + "/"
	keys, err := r.store.List(ctx, prefix)
	if err != nil {
		return nil
	}
	var items []item
	for _, k := range keys {
		c, ok := parseCounter(k, prefix)
		if !ok || c < since {
			continue
		}
		b, err := r.store.Get(ctx, k)
		if err != nil || !json.Valid(b) {
			continue
		}
		items = append(items, item{counter: c, raw: b})
	}
	return items
}

func (r *Relay) forwardTasks(ctx context.Context, sid, flow string, since uint64) []item {
	path := fmt.Sprintf("/tasks/%s?f=%s&since=%d", url.PathEscape(sid), flow, since)
	for i := 0; i < 2*len(r.router.List()); i++ {
		addr, ok := r.router.Next()
		if !ok {
			return nil
		}
		u := addr + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := r.client.Do(req)
		if err != nil {
			r.router.MarkDown(addr, 30*time.Second)
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			r.router.MarkDown(addr, 30*time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil
		}
		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			return nil
		}
		items := make([]item, 0, len(raws))
		for _, raw := range raws {
			env, err := crypto.UnmarshalEnvelope(raw)
			if err != nil || len(env.Nonce) < 8 {
				continue
			}
			c := binary.BigEndian.Uint64(env.Nonce[:8])
			items = append(items, item{counter: c, raw: raw})
		}
		return items
	}
	return nil
}

func mergeItems(a, b []item) []item {
	byCounter := make(map[uint64]json.RawMessage)
	for _, it := range a {
		byCounter[it.counter] = it.raw
	}
	for _, it := range b {
		if _, dup := byCounter[it.counter]; !dup {
			byCounter[it.counter] = it.raw
		}
	}
	merged := make([]item, 0, len(byCounter))
	for c, raw := range byCounter {
		merged = append(merged, item{counter: c, raw: raw})
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].counter < merged[j].counter })
	return merged
}

func (r *Relay) ForwardPending(ctx context.Context) error {
	keys, err := r.store.List(ctx, "pending/")
	if err != nil {
		return err
	}
	for _, marker := range keys {
		contentKey, err := decodeKey(strings.TrimPrefix(marker, "pending/"))
		if err != nil {
			r.store.Delete(ctx, marker)
			continue
		}
		parts := strings.Split(contentKey, "/")
		if len(parts) != 3 {
			r.store.Delete(ctx, marker)
			continue
		}
		body, err := r.store.Get(ctx, contentKey)
		if err != nil {
			r.store.Delete(ctx, marker)
			continue
		}
		flow := parts[1]
		if !r.forwardAll(ctx, http.MethodPost, "/ingest?f="+flow, body) {
			return nil
		}
		r.store.Delete(ctx, contentKey)
		r.store.Delete(ctx, marker)
		r.opts.Logger.Info("relay: pending forwarded", "key", contentKey)
	}
	return nil
}

func (r *Relay) ForwardPendingLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = r.opts.Retry
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.ForwardPending(ctx); err != nil {
				r.opts.Logger.Warn("relay: forward pending failed", "err", err)
			}
		}
	}
}

func flowName(v string) (string, bool) {
	if v == "" || v == "beacon" {
		return "beacon", true
	}
	if v == "server" {
		return "server", true
	}
	return "", false
}

func parseCounter(key, prefix string) (uint64, bool) {
	if len(key) <= len(prefix) {
		return 0, false
	}
	v, err := strconv.ParseUint(key[len(prefix):], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func encodeKey(k string) string { return hex.EncodeToString([]byte(k)) }
func decodeKey(k string) (string, error) {
	b, err := hex.DecodeString(k)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
